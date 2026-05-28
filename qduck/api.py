# Copyright 2026 Rick Harold
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#     http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

"""Public qduck API.

Application code should import from either:

    import qduck

or:

    from qduck.api import encrypt_blob, derive_key

The rest of the package is implementation detail.
"""

import base64
import binascii
import os
from pathlib import Path
from typing import Optional

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from .crypto import (
    AES_KEY_SIZE,
    PRIVATE_KEY_SIZE,
    PUBLIC_KEY_SIZE,
    aes_gcm_decrypt,
    aes_gcm_encrypt,
    derive_hybrid_key,
    generate_hybrid_keypair,
    recover_hybrid_key,
    validate_private_key,
    validate_public_key,
)
from .exceptions import DecryptionError, KeyFormatError, QDuckError
from .file_format import (
    BASE_NONCE_SIZE,
    CHUNK_LEN_FLAG_SIZE,
    DEFAULT_CHUNK_SIZE,
    MAX_CHUNK_SIZE,
    MIN_CHUNK_SIZE,
    build_chunk_aad,
    chunk_nonce,
    pack_chunk_prefix,
    pack_header,
    unpack_chunk_prefix,
    unpack_header,
    validate_chunk_size,
)

def generate_keypair() -> tuple[bytes, bytes]:
    """Generate a raw X25519 + ML-KEM-768 hybrid keypair.

    Returns:
        (public_key, private_key), both as raw bytes.
    """
    return generate_hybrid_keypair()


def _atomic_write(path: str, data: bytes, mode: int, overwrite: bool) -> None:
    """Write `data` to `path` atomically.

    Creates a sibling temp file with the requested `mode`, writes and fsyncs
    it, then renames it over the destination. On POSIX, rename is atomic
    within the same directory, so callers never observe a partial file.

    When `overwrite` is False, the destination is checked first and a
    FileExistsError is raised if it is already present. The check is
    advisory: there is still a small window where a parallel writer could
    create the file between the check and the rename. The rename itself is
    always atomic; the check just preserves the "refuse to clobber" intent.
    """
    def _writer(f):
        f.write(data)

    _atomic_write_stream(path, _writer, mode, overwrite)


def _atomic_write_stream(path, writer, mode: int, overwrite: bool) -> None:
    """Stream-write variant of _atomic_write.

    Opens a sibling temp file with the requested mode and hands a binary
    file object to ``writer(f)``. The caller is expected to write all
    output to ``f`` (it may call write() many times). The temp file is
    flushed and fsync'd, then atomically renamed over the destination.

    Used by encrypt_file / decrypt_file so multi-GB outputs do not have to
    be materialized in memory before the rename.
    """
    target = Path(path)
    if not overwrite and target.exists():
        raise FileExistsError(f"{path!r} already exists")

    directory = target.parent if str(target.parent) else Path(".")
    tmp_fd, tmp_name = _mkstemp_with_mode(directory, target.name, mode)
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            tmp_fd = -1
            writer(f)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp_name, target)
        tmp_name = None
    finally:
        if tmp_fd != -1:
            os.close(tmp_fd)
        if tmp_name is not None:
            try:
                os.unlink(tmp_name)
            except FileNotFoundError:
                pass


def _mkstemp_with_mode(directory: Path, base_name: str, mode: int) -> tuple[int, str]:
    """Create a unique temp file in `directory` with the requested mode.

    Returns (fd, path). Uses O_CREAT|O_EXCL with a randomized suffix so the
    file is created with the intended permissions in a single syscall.
    """
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    while True:
        suffix = os.urandom(8).hex()
        candidate = str(directory / f".{base_name}.{suffix}.tmp")
        try:
            fd = os.open(candidate, flags, mode)
            return fd, candidate
        except FileExistsError:
            continue


def save_keypair(public_path: str, private_path: str, force: bool = False) -> None:
    """Generate and write public/private raw key files.

    The private key is created atomically with 0o600 permissions. The public
    key is created atomically with 0o644 permissions. Existing files are
    refused unless force=True.

    If writing the private key fails, the public key written earlier in the
    call is removed so the caller does not end up with an orphan half-pair.
    """
    public_key, private_key = generate_keypair()

    _atomic_write(public_path, public_key, 0o644, overwrite=force)

    try:
        _atomic_write(private_path, private_key, 0o600, overwrite=force)
    except Exception:
        Path(public_path).unlink(missing_ok=True)
        raise


def _load_bytes_auto(path: str, expected_size: int, label: str) -> bytes:
    raw = Path(path).read_bytes()

    stripped = b"".join(raw.split())
    if stripped:
        try:
            decoded = base64.b64decode(stripped, validate=True)
            if len(decoded) == expected_size:
                return decoded
        except (binascii.Error, ValueError):
            pass

    if len(raw) == expected_size:
        return raw

    raise KeyFormatError(
        f"{label} at {path!r} is malformed: expected {expected_size} raw bytes "
        "or base64 text encoding exactly that many bytes"
    )


def load_public_key(path: str) -> bytes:
    """Load a public key from raw binary or base64 text."""
    public_key = _load_bytes_auto(path, PUBLIC_KEY_SIZE, "public key")
    validate_public_key(public_key)
    return public_key


def load_private_key(path: str) -> bytes:
    """Load a private key from raw binary or base64 text."""
    private_key = _load_bytes_auto(path, PRIVATE_KEY_SIZE, "private key")
    validate_private_key(private_key)
    return private_key


def derive_key(public_key: bytes) -> tuple[bytes, bytes]:
    """Client side: return (aes_key, key_block) for a recipient public key."""
    return derive_hybrid_key(public_key)


def recover_key(private_key: bytes, key_block: bytes) -> bytes:
    """Server side: recover the AES-256 key from private_key and key_block.

    Args:
        private_key: Raw qduck private key bytes.
        key_block: Public hybrid KEM handshake bytes produced by derive_key().

    Returns:
        The recovered 32-byte AES-256 session key.
    """
    return recover_hybrid_key(private_key, key_block)


def encrypt_blob(data: bytes, aes_key: bytes, aad: Optional[bytes] = None) -> bytes:
    """Encrypt bytes with AES-256-GCM as nonce(12) || ciphertext || tag(16).

    Args:
        data: Plaintext bytes.
        aes_key: 32-byte AES-256 key returned by derive_key()/recover_key().
        aad: Optional additional authenticated data. Use aad=key_block when you
            want each blob authenticated to the original session handshake.

    Notes:
        This function creates a fresh random 96-bit AES-GCM nonce per call.
        Never reuse a nonce with the same AES key.
    """
    return aes_gcm_encrypt(data, aes_key, aad=aad)


def decrypt_blob(
    ciphertext: bytes,
    aes_key: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    """Decrypt bytes produced by encrypt_blob.

    The aad value must exactly match the aad passed to encrypt_blob.
    """
    return aes_gcm_decrypt(ciphertext, aes_key, aad=aad)


def encrypt_file(
    src_path: str,
    dst_path: str,
    aes_key: bytes,
    aad: Optional[bytes] = None,
    overwrite: bool = False,
    chunk_size: int = DEFAULT_CHUNK_SIZE,
    key_block: Optional[bytes] = None,
) -> None:
    """Encrypt a file on disk with chunked AES-256-GCM (qduck file format v3).

    The plaintext is read in fixed-size chunks and each chunk is encrypted
    independently with AES-256-GCM. A small framing header records the
    format version, chunk size, and a random per-file base nonce; an
    optional key_block can be embedded so the file is self-contained.
    Memory use is bounded by ``chunk_size`` regardless of file size, so
    multi-GB and TB-scale files work without loading anything into RAM
    beyond one chunk.

    Args:
        src_path: Path to the plaintext file to read.
        dst_path: Path to write the encrypted output to.
        aes_key: 32-byte AES-256 key from derive_key()/recover_key().
        aad: Optional additional authenticated data, applied to every
            chunk. Decryption must supply the exact same value.
        overwrite: If False (the default), refuse to overwrite an existing
            destination. If True, replace any existing file at dst_path.
        chunk_size: Plaintext chunk size in bytes. Default is 1 MiB, which
            is a good balance for most machines. Tune down on memory-tight
            hosts (minimum 4 KiB) or up for higher throughput on big
            servers (maximum 64 MiB). The same chunk_size is recorded in
            the file header, so decrypt_file picks it up automatically.
        key_block: Optional KEM key block from derive_key(). When
            provided, it is embedded in the file header so the recipient
            can recover the AES key with just this file + their private
            key. When omitted, key distribution is the caller's problem.

    Notes:
        Per-chunk AAD binds each chunk to (header + counter + final flag
        + user aad), so an attacker cannot drop, reorder, splice, or move
        chunks between files without invalidating a GCM tag. In particular
        the file cannot be silently truncated: the real last chunk is the
        only one marked final.

        Output is written via a sibling temp file + atomic rename, so
        callers never observe a partial ciphertext.
    """
    if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_SIZE:
        raise KeyFormatError(f"aes_key must be {AES_KEY_SIZE} bytes")
    if aad is not None and not isinstance(aad, bytes):
        raise TypeError("aad must be bytes or None")
    validate_chunk_size(chunk_size)

    base_nonce = os.urandom(BASE_NONCE_SIZE)
    header_bytes = pack_header(chunk_size, base_nonce, key_block)
    aesgcm = AESGCM(aes_key)

    def _writer(out):
        out.write(header_bytes)
        with open(src_path, "rb") as src:
            counter = 0
            # Read one chunk ahead so we know whether the *current* chunk
            # is final before we encrypt it (the final flag is part of
            # the chunk's AAD).
            current = src.read(chunk_size)
            while True:
                nxt = src.read(chunk_size)
                is_final = not nxt
                chunk_aad = build_chunk_aad(header_bytes, counter, is_final, aad)
                nonce = chunk_nonce(base_nonce, counter)
                # AESGCM.encrypt returns ciphertext || tag.
                ct = aesgcm.encrypt(nonce, current, chunk_aad)
                # Nonce is recomputable from header + counter, so we do
                # not store it on disk. Only ct||tag goes after the
                # length prefix.
                out.write(pack_chunk_prefix(len(ct), is_final))
                out.write(ct)

                if is_final:
                    break
                current = nxt
                counter += 1
                if counter > 0xFFFFFFFF:
                    raise ValueError(
                        "file exceeds maximum chunk count for this chunk_size; "
                        "use a larger chunk_size"
                    )

    _atomic_write_stream(dst_path, _writer, 0o644, overwrite=overwrite)


def decrypt_file_with_private_key(
    src_path: str,
    dst_path: str,
    private_key: bytes,
    aad: Optional[bytes] = None,
    overwrite: bool = False,
) -> None:
    """Decrypt a self-contained qduck file using the recipient private key.

    This convenience API is for files created with::

        aes_key, key_block = derive_key(public_key)
        encrypt_file(src, dst, aes_key, key_block=key_block, aad=aad)

    The encrypted file must contain an embedded key_block in its header. This
    function reads that key_block, recovers the AES-256 file key with
    ``private_key``, then delegates to decrypt_file().

    Args:
        src_path: Path to the encrypted qduck file.
        dst_path: Path to write the recovered plaintext to.
        private_key: Raw qduck private key bytes.
        aad: Optional additional authenticated data. Must exactly match the aad
            passed to encrypt_file().
        overwrite: If False, refuse to overwrite an existing destination.

    Raises:
        DecryptionError: if the file has no embedded key_block, the key cannot
            be recovered, or chunk authentication fails.
    """
    validate_private_key(private_key)
    if aad is not None and not isinstance(aad, bytes):
        raise TypeError("aad must be bytes or None")

    with open(src_path, "rb") as src:
        _header_bytes, _chunk_size, _base_nonce, key_block = unpack_header(src)

    if key_block is None:
        raise DecryptionError(
            "qduck file does not contain an embedded key_block; "
            "use decrypt_file() with the AES key instead"
        )

    aes_key = recover_hybrid_key(private_key, key_block)
    decrypt_file(src_path, dst_path, aes_key, aad=aad, overwrite=overwrite)


def decrypt_file(
    src_path: str,
    dst_path: str,
    aes_key: bytes,
    aad: Optional[bytes] = None,
    overwrite: bool = False,
) -> None:
    """Decrypt a file produced by encrypt_file (qduck file format v3).

    Streams the file chunk by chunk, verifying each AES-GCM tag and
    writing decrypted output as it goes. Memory use is bounded by the
    file's recorded chunk size, not by the total file size.

    Args:
        src_path: Path to the encrypted file to read.
        dst_path: Path to write the recovered plaintext to.
        aes_key: 32-byte AES-256 key from derive_key()/recover_key().
        aad: Optional additional authenticated data. Must exactly match
            the aad passed to encrypt_file() when this file was produced.
        overwrite: If False (the default), refuse to overwrite an existing
            destination. If True, replace any existing file at dst_path.

    Raises:
        DecryptionError: bad magic, unsupported version, truncated file,
            missing final chunk, or any per-chunk AES-GCM tag failure.

    Notes:
        Output is written to a sibling temp file and only renamed into
        place after the final chunk authenticates. If any chunk fails
        verification the partial output is removed and no destination
        file is created.
    """
    if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_SIZE:
        raise DecryptionError(f"aes_key must be {AES_KEY_SIZE} bytes")
    if aad is not None and not isinstance(aad, bytes):
        raise TypeError("aad must be bytes or None")

    def _writer(out):
        with open(src_path, "rb") as src:
            header_bytes, chunk_size, base_nonce, _key_block = unpack_header(src)
            # chunk_size from the header is trusted only insofar as it
            # passed validate_chunk_size inside unpack_header. We do not
            # ever allocate based on attacker-controlled sizes without
            # that bound check, so this is safe.
            aesgcm = AESGCM(aes_key)
            counter = 0
            saw_final = False
            # Maximum on-disk ct||tag for one chunk: plaintext at most
            # chunk_size bytes, plus a 16-byte GCM tag.
            max_chunk_payload = chunk_size + 16
            while True:
                prefix = src.read(CHUNK_LEN_FLAG_SIZE)
                if not prefix:
                    raise DecryptionError(
                        "qduck file truncated: missing final chunk"
                    )
                ct_len, is_final = unpack_chunk_prefix(prefix)
                if ct_len < 16:
                    raise DecryptionError("chunk too short to contain GCM tag")
                if ct_len > max_chunk_payload:
                    raise DecryptionError(
                        f"qduck file declares oversized chunk ({ct_len} bytes)"
                    )

                ct_and_tag = src.read(ct_len)
                if len(ct_and_tag) != ct_len:
                    raise DecryptionError("qduck file truncated mid-chunk")

                nonce = chunk_nonce(base_nonce, counter)
                chunk_aad = build_chunk_aad(header_bytes, counter, is_final, aad)
                try:
                    pt = aesgcm.decrypt(nonce, ct_and_tag, chunk_aad)
                except InvalidTag as exc:
                    raise DecryptionError(
                        f"AES-GCM authentication failed on chunk {counter}"
                    ) from exc
                out.write(pt)

                if is_final:
                    saw_final = True
                    # Refuse trailing bytes after the final chunk.
                    trailing = src.read(1)
                    if trailing:
                        raise DecryptionError(
                            "qduck file has trailing bytes after final chunk"
                        )
                    break

                counter += 1
                if counter > 0xFFFFFFFF:
                    raise DecryptionError("qduck file has too many chunks")

            if not saw_final:  # pragma: no cover (loop guarantees this)
                raise DecryptionError("qduck file missing final chunk")

    _atomic_write_stream(dst_path, _writer, 0o600, overwrite=overwrite)


__all__ = [
    "QDuckError",
    "DecryptionError",
    "KeyFormatError",
    "generate_keypair",
    "save_keypair",
    "load_public_key",
    "load_private_key",
    "derive_key",
    "recover_key",
    "encrypt_blob",
    "decrypt_blob",
    "encrypt_file",
    "decrypt_file",
    "decrypt_file_with_private_key",
]
