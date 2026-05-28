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

"""qduck chunked file format (v3).

On-disk layout
--------------

::

    +------------------------------------------------------------------+
    | HEADER                                                           |
    |------------------------------------------------------------------|
    |  magic        8B    b"QDUCKF\\x00\\x00"                          |
    |  version      1B    0x03                                         |
    |  flags        1B    bit0 = key_block present                     |
    |  header_len   2B    uint16 BE; total header bytes on disk        |
    |  alg_id       1B    0x01 = AES-256-GCM chunk encryption          |
    |  kem_id       1B    0x01 = ML-KEM-768 + X25519 hybrid KEM        |
    |  kdf_id       1B    0x01 = HKDF-SHA256 hybrid secret combiner    |
    |  reserved     1B    0x00                                         |
    |  chunk_size   4B    uint32 BE, plaintext chunk size              |
    |  base_nonce   8B    random; per-chunk nonce = base||ctr          |
    |  key_block    NB    present iff flags bit0 set                   |
    +------------------------------------------------------------------+
    | CHUNK 0 .. CHUNK N-1 (repeated)                                  |
    |------------------------------------------------------------------|
    |  ct_len_flag  4B    uint32 BE; high bit = final flag             |
    |  ciphertext   LB    AES-GCM ciphertext||tag                      |
    +------------------------------------------------------------------+

The nonce is not stored per chunk. It is recomputed as
``base_nonce || counter_be32``. The 8-byte random prefix keeps nonces unique
across files for the same key, and the 32-bit counter gives 2^32 chunks per
file (256 TiB at 64 KiB chunks, 4 PiB at 1 MiB chunks).

Each chunk is a standalone AES-256-GCM encryption of one plaintext slice.
Per-chunk AAD binds every chunk to its position in the file so an attacker
cannot drop, reorder, splice, truncate, or move chunks between files::

    aad = b"qduck-chunk-v3" || header_bytes || counter_be32 || final_byte || user_aad

``header_bytes`` is the exact on-disk header from byte 0 through
``header_len``. This includes ``key_block`` when present and any future header
extension bytes added by later versions. Flipping any header byte invalidates
every chunk. ``final_byte`` is 0x01 only on the last chunk: if a truncation
removes the real final chunk, the new last chunk was authenticated with 0x00
and decryption fails.

Versioning and expansion
------------------------

The v3 header has both a version and a total ``header_len``. Future versions can
append optional sections inside the header while old readers safely reject
unknown versions/flags instead of guessing where chunks begin. Algorithm IDs are
explicit so future qduck files can move beyond today's AES-256-GCM,
ML-KEM-768+X25519, or HKDF-SHA256 choices without overloading the version byte.
"""

import os
import struct
from typing import BinaryIO, Optional

from .crypto import AES_KEY_SIZE, KEY_BLOCK_SIZE, NONCE_SIZE, TAG_SIZE, validate_key_block
from .exceptions import DecryptionError

# --- Format constants ---------------------------------------------------

MAGIC = b"QDUCKF\x00\x00"
VERSION = 0x03
FLAG_HAS_KEY_BLOCK = 0x01

ALG_AES256_GCM = 0x01
KEM_MLKEM768_X25519 = 0x01
KDF_HKDF_SHA256 = 0x01

# Fixed-length prefix: magic(8) + version(1) + flags(1) + header_len(2) +
# alg_id(1) + kem_id(1) + kdf_id(1) + reserved(1) + chunk_size(4) + base_nonce(8).
# Key block, if present, follows inside the header and is counted by header_len.
HEADER_FIXED_LEN = 8 + 1 + 1 + 2 + 1 + 1 + 1 + 1 + 4 + 8  # = 28

BASE_NONCE_SIZE = 8
COUNTER_SIZE = 4
assert BASE_NONCE_SIZE + COUNTER_SIZE == NONCE_SIZE  # 12-byte AES-GCM nonce

# Per-chunk framing: 4-byte big-endian uint32; high bit is the final flag,
# low 31 bits are the ciphertext-plus-tag length on disk.
CHUNK_LEN_FLAG_SIZE = 4
CHUNK_FINAL_BIT = 0x80000000
CHUNK_LEN_MASK = 0x7FFFFFFF

# AAD domain separator. Bump this when the AAD layout or file format changes.
CHUNK_AAD_PREFIX = b"qduck-chunk-v3"

# --- Chunk-size policy --------------------------------------------------

DEFAULT_CHUNK_SIZE = 1 * 1024 * 1024
MIN_CHUNK_SIZE = 4 * 1024
MAX_CHUNK_SIZE = 64 * 1024 * 1024


def validate_chunk_size(chunk_size: int) -> None:
    """Reject chunk sizes outside the supported range."""
    if not isinstance(chunk_size, int):
        raise TypeError("chunk_size must be int")
    if chunk_size < MIN_CHUNK_SIZE or chunk_size > MAX_CHUNK_SIZE:
        raise ValueError(
            f"chunk_size must be between {MIN_CHUNK_SIZE} and "
            f"{MAX_CHUNK_SIZE} bytes, got {chunk_size}"
        )


# --- Header pack / unpack -----------------------------------------------

def pack_header(
    chunk_size: int,
    base_nonce: bytes,
    key_block: Optional[bytes],
) -> bytes:
    """Serialize the v3 file header.

    Returns the exact bytes that go on disk *and* that feed into every chunk's
    AAD. Callers must use this same byte string in both places.
    """
    validate_chunk_size(chunk_size)
    if len(base_nonce) != BASE_NONCE_SIZE:
        raise ValueError(f"base_nonce must be {BASE_NONCE_SIZE} bytes")

    flags = 0
    key_block_bytes = b""
    if key_block is not None:
        validate_key_block(key_block)
        flags |= FLAG_HAS_KEY_BLOCK
        key_block_bytes = key_block

    header_len = HEADER_FIXED_LEN + len(key_block_bytes)
    if header_len > 0xFFFF:
        raise ValueError("qduck header too large")

    # struct fmt: 8s magic, B version, B flags, H header_len,
    # B alg_id, B kem_id, B kdf_id, B reserved, I chunk_size, 8s base_nonce.
    fixed = struct.pack(
        ">8sBBHBBBBI8s",
        MAGIC,
        VERSION,
        flags,
        header_len,
        ALG_AES256_GCM,
        KEM_MLKEM768_X25519,
        KDF_HKDF_SHA256,
        0,                  # reserved
        chunk_size,
        base_nonce,
    )
    return fixed + key_block_bytes


def unpack_header(stream: BinaryIO) -> tuple[bytes, int, bytes, Optional[bytes]]:
    """Read and parse the v3 header from a binary stream positioned at byte 0.

    Returns ``(header_bytes, chunk_size, base_nonce, key_block_or_None)``.
    ``header_bytes`` is the exact byte string that was on disk, suitable for
    feeding back into per-chunk AAD.

    Raises DecryptionError on any malformed input.
    """
    fixed = _read_exact(stream, HEADER_FIXED_LEN, "header")
    try:
        (
            magic,
            version,
            flags,
            header_len,
            alg_id,
            kem_id,
            kdf_id,
            reserved,
            chunk_size,
            base_nonce,
        ) = struct.unpack(">8sBBHBBBBI8s", fixed)
    except struct.error as exc:
        raise DecryptionError("malformed qduck file header") from exc

    if magic != MAGIC:
        raise DecryptionError("not a qduck file (bad magic)")
    if version != VERSION:
        raise DecryptionError(
            f"unsupported qduck file version: {version} (this build understands {VERSION})"
        )
    if header_len < HEADER_FIXED_LEN:
        raise DecryptionError("malformed qduck file header (header_len too small)")
    if reserved != 0:
        raise DecryptionError("malformed qduck file header (reserved field nonzero)")
    if alg_id != ALG_AES256_GCM:
        raise DecryptionError(f"unsupported qduck encryption algorithm id: {alg_id}")
    if kem_id != KEM_MLKEM768_X25519:
        raise DecryptionError(f"unsupported qduck KEM id: {kem_id}")
    if kdf_id != KDF_HKDF_SHA256:
        raise DecryptionError(f"unsupported qduck KDF id: {kdf_id}")
    if chunk_size < MIN_CHUNK_SIZE or chunk_size > MAX_CHUNK_SIZE:
        raise DecryptionError(
            f"qduck file declares out-of-range chunk_size {chunk_size}"
        )

    extra_len = header_len - HEADER_FIXED_LEN
    extra = _read_exact(stream, extra_len, "header extension") if extra_len else b""

    unknown_flags = flags & ~FLAG_HAS_KEY_BLOCK
    if unknown_flags:
        raise DecryptionError(
            f"qduck file uses unknown flag bits 0x{unknown_flags:02x}"
        )

    key_block: Optional[bytes] = None
    expected_extra_len = 0
    if flags & FLAG_HAS_KEY_BLOCK:
        expected_extra_len += KEY_BLOCK_SIZE
        if len(extra) < KEY_BLOCK_SIZE:
            raise DecryptionError("qduck file header truncated in key_block")
        key_block = extra[:KEY_BLOCK_SIZE]
        validate_key_block(key_block)

    if len(extra) != expected_extra_len:
        raise DecryptionError("qduck file has unsupported header extension bytes")

    header_bytes = fixed + extra
    return header_bytes, chunk_size, base_nonce, key_block


def _read_exact(stream: BinaryIO, n: int, what: str) -> bytes:
    """Read exactly ``n`` bytes or raise DecryptionError on short read."""
    buf = stream.read(n)
    if len(buf) != n:
        raise DecryptionError(
            f"qduck file truncated while reading {what} "
            f"(needed {n} bytes, got {len(buf)})"
        )
    return buf


# --- Per-chunk AAD ------------------------------------------------------

def build_chunk_aad(
    header_bytes: bytes,
    counter: int,
    is_final: bool,
    user_aad: Optional[bytes],
) -> bytes:
    """Construct the AAD authenticated with one chunk."""
    if counter < 0 or counter > 0xFFFFFFFF:
        raise ValueError("chunk counter out of range")
    user = user_aad if user_aad is not None else b""
    return (
        CHUNK_AAD_PREFIX
        + header_bytes
        + struct.pack(">I", counter)
        + (b"\x01" if is_final else b"\x00")
        + user
    )


def chunk_nonce(base_nonce: bytes, counter: int) -> bytes:
    """Per-chunk AES-GCM nonce: 8-byte random base || 4-byte counter (BE)."""
    return base_nonce + struct.pack(">I", counter)


# --- Chunk framing ------------------------------------------------------

def pack_chunk_prefix(ct_len: int, is_final: bool) -> bytes:
    """Pack the 4-byte length+flag prefix that precedes each ciphertext chunk."""
    if ct_len < 0 or ct_len > CHUNK_LEN_MASK:
        raise ValueError(f"chunk ciphertext length {ct_len} out of range")
    word = ct_len | (CHUNK_FINAL_BIT if is_final else 0)
    return struct.pack(">I", word)


def unpack_chunk_prefix(prefix: bytes) -> tuple[int, bool]:
    """Return ``(ct_len, is_final)`` from a 4-byte prefix."""
    if len(prefix) != CHUNK_LEN_FLAG_SIZE:
        raise DecryptionError("malformed chunk length prefix")
    (word,) = struct.unpack(">I", prefix)
    return word & CHUNK_LEN_MASK, bool(word & CHUNK_FINAL_BIT)


# --- Minimum sane on-disk size for a v3 file ---------------------------

# Smallest legal v3 file: header(28) + one final chunk with empty plaintext
# (AES-GCM tag 16) + chunk prefix (4) = 48 bytes. No per-chunk nonce is stored.
MIN_FILE_SIZE = HEADER_FIXED_LEN + CHUNK_LEN_FLAG_SIZE + TAG_SIZE


__all__ = [
    "MAGIC",
    "VERSION",
    "FLAG_HAS_KEY_BLOCK",
    "ALG_AES256_GCM",
    "KEM_MLKEM768_X25519",
    "KDF_HKDF_SHA256",
    "HEADER_FIXED_LEN",
    "BASE_NONCE_SIZE",
    "DEFAULT_CHUNK_SIZE",
    "MIN_CHUNK_SIZE",
    "MAX_CHUNK_SIZE",
    "MIN_FILE_SIZE",
    "AES_KEY_SIZE",
    "validate_chunk_size",
    "pack_header",
    "unpack_header",
    "build_chunk_aad",
    "chunk_nonce",
    "pack_chunk_prefix",
    "unpack_chunk_prefix",
]
