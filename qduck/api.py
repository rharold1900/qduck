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

from .crypto import (
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
    target = Path(path)
    if not overwrite and target.exists():
        raise FileExistsError(f"{path!r} already exists")

    directory = target.parent if str(target.parent) else Path(".")
    # Temp file in the same directory so rename stays within one filesystem.
    tmp_fd, tmp_name = _mkstemp_with_mode(directory, target.name, mode)
    try:
        with os.fdopen(tmp_fd, "wb") as f:
            tmp_fd = -1
            f.write(data)
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
) -> None:
    """Encrypt a file on disk with AES-256-GCM.

    Reads `src_path`, encrypts the contents with encrypt_blob(), and writes
    the result atomically to `dst_path` with 0o644 permissions. Ciphertext
    is safe to share, so the default mode is world-readable; tighten it on
    the destination filesystem if your threat model requires it.

    Args:
        src_path: Path to the plaintext file to read.
        dst_path: Path to write the encrypted output to.
        aes_key: 32-byte AES-256 key from derive_key()/recover_key().
        aad: Optional additional authenticated data. Use aad=key_block when
            you want the ciphertext authenticated to the original handshake.
        overwrite: If False (the default), refuse to overwrite an existing
            destination. If True, replace any existing file at dst_path.

    Notes:
        This is a whole-file operation: src_path is loaded into memory.
        AES-GCM produces a single authentication tag over the entire input,
        so chunked streaming would require a different on-disk format. For
        multi-GB files where memory matters, encrypt in a higher layer that
        defines its own chunking.

        The destination is written via a sibling temp file + atomic rename,
        so callers never observe a partially written ciphertext.
    """
    plaintext = Path(src_path).read_bytes()
    ciphertext = aes_gcm_encrypt(plaintext, aes_key, aad=aad)
    _atomic_write(dst_path, ciphertext, 0o644, overwrite=overwrite)


def decrypt_file(
    src_path: str,
    dst_path: str,
    aes_key: bytes,
    aad: Optional[bytes] = None,
    overwrite: bool = False,
) -> None:
    """Decrypt a file produced by encrypt_file (or any encrypt_blob output).

    Reads `src_path`, decrypts the contents with decrypt_blob(), and writes
    the plaintext atomically to `dst_path` with 0o600 permissions. Plaintext
    on disk is treated as sensitive by default; relax the mode after the
    fact if the recovered file is not secret.

    Args:
        src_path: Path to the encrypted file to read.
        dst_path: Path to write the recovered plaintext to.
        aes_key: 32-byte AES-256 key from derive_key()/recover_key().
        aad: Optional additional authenticated data. Must exactly match the
            aad passed to encrypt_file()/encrypt_blob() when this was made.
        overwrite: If False (the default), refuse to overwrite an existing
            destination. If True, replace any existing file at dst_path.

    Raises:
        DecryptionError: AES-GCM tag failed, bad key, corrupt input, or
            mismatched aad.
    """
    ciphertext = Path(src_path).read_bytes()
    plaintext = aes_gcm_decrypt(ciphertext, aes_key, aad=aad)
    _atomic_write(dst_path, plaintext, 0o600, overwrite=overwrite)


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
]
