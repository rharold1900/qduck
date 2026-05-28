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

"""Internal cryptography bindings for qduck.

This is intentionally the only qduck module that imports from cryptography.
The public API lives in qduck/api.py and is re-exported by qduck/__init__.py.
"""

import os
from typing import Optional

from cryptography.exceptions import InvalidTag, UnsupportedAlgorithm
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from .exceptions import DecryptionError, KeyFormatError, QDuckError

_MLKEM_UNAVAILABLE_MSG = (
    "qduck requires post-quantum (ML-KEM-768) support in the installed "
    "'cryptography' package. The cryptography wheels published on PyPI "
    "from version 47.0.0 onward ship with an OpenSSL build (>= 3.5) that "
    "should expose ML-KEM, so for most users 'pip install --upgrade "
    "cryptography' is enough. If you built cryptography from source against "
    "an older system OpenSSL (<3.5), rebuild against OpenSSL >= 3.5, "
    "AWS-LC, or BoringSSL."
)

try:
    from cryptography.hazmat.primitives.asymmetric import mlkem
except ImportError as _exc:
    raise QDuckError(_MLKEM_UNAVAILABLE_MSG) from _exc

MLKEM768_PUBLIC_SIZE = 1184
MLKEM768_PRIVATE_SEED_SIZE = 64
MLKEM768_CIPHERTEXT_SIZE = 1088
X25519_PUBLIC_SIZE = 32
X25519_PRIVATE_SIZE = 32

PUBLIC_KEY_SIZE = MLKEM768_PUBLIC_SIZE + X25519_PUBLIC_SIZE
PRIVATE_KEY_SIZE = MLKEM768_PRIVATE_SEED_SIZE + X25519_PRIVATE_SIZE
KEY_BLOCK_SIZE = MLKEM768_CIPHERTEXT_SIZE + X25519_PUBLIC_SIZE
AES_KEY_SIZE = 32
NONCE_SIZE = 12
IV_SIZE = NONCE_SIZE  # Backward-compatible alias.
TAG_SIZE = 16

_HKDF_INFO = b"qduck-v1 X25519+ML-KEM-768 hybrid KEM to AES-256 key"


def _require_bytes(value: bytes, name: str) -> None:
    if not isinstance(value, bytes):
        raise TypeError(f"{name} must be bytes")


def _hkdf_hybrid_secret(mlkem_secret: bytes, x25519_secret: bytes) -> bytes:
    # cryptography exposes ML-KEM and X25519 primitives here. qduck combines
    # the two shared secrets with a domain-separated HKDF to produce exactly
    # one AES-256 key. If cryptography later exposes a raw non-HPKE hybrid KEM
    # API, this module is the only place that should need to change.
    return HKDF(
        algorithm=hashes.SHA256(),
        length=AES_KEY_SIZE,
        salt=None,  # IKM is already uniformly random; zero salt is per RFC 5869 §2.2
        info=_HKDF_INFO,
    ).derive(mlkem_secret + x25519_secret)


def generate_hybrid_keypair() -> tuple[bytes, bytes]:
    try:
        mlkem_private = mlkem.MLKEM768PrivateKey.generate()
    except UnsupportedAlgorithm as exc:
        raise QDuckError(_MLKEM_UNAVAILABLE_MSG) from exc
    x_private = x25519.X25519PrivateKey.generate()

    public_key = (
        mlkem_private.public_key().public_bytes_raw()
        + x_private.public_key().public_bytes_raw()
    )
    private_key = mlkem_private.private_bytes_raw() + x_private.private_bytes_raw()
    return public_key, private_key


def validate_public_key(public_key: bytes) -> None:
    if not isinstance(public_key, bytes) or len(public_key) != PUBLIC_KEY_SIZE:
        raise KeyFormatError(
            f"public key must be {PUBLIC_KEY_SIZE} raw bytes "
            f"({MLKEM768_PUBLIC_SIZE} ML-KEM + {X25519_PUBLIC_SIZE} X25519)"
        )


def validate_private_key(private_key: bytes) -> None:
    if not isinstance(private_key, bytes) or len(private_key) != PRIVATE_KEY_SIZE:
        raise KeyFormatError(
            f"private key must be {PRIVATE_KEY_SIZE} raw bytes "
            f"({MLKEM768_PRIVATE_SEED_SIZE} ML-KEM seed + "
            f"{X25519_PRIVATE_SIZE} X25519 private key)"
        )


def validate_key_block(key_block: bytes) -> None:
    if not isinstance(key_block, bytes) or len(key_block) != KEY_BLOCK_SIZE:
        raise DecryptionError(
            f"key_block must be {KEY_BLOCK_SIZE} raw bytes "
            f"({MLKEM768_CIPHERTEXT_SIZE} ML-KEM ciphertext + "
            f"{X25519_PUBLIC_SIZE} X25519 ephemeral public key)"
        )


def derive_hybrid_key(public_key: bytes) -> tuple[bytes, bytes]:
    validate_public_key(public_key)

    mlkem_public_bytes = public_key[:MLKEM768_PUBLIC_SIZE]
    x_public_bytes = public_key[MLKEM768_PUBLIC_SIZE:]

    try:
        mlkem_public = mlkem.MLKEM768PublicKey.from_public_bytes(mlkem_public_bytes)
        x_public = x25519.X25519PublicKey.from_public_bytes(x_public_bytes)

        mlkem_secret, mlkem_ciphertext = mlkem_public.encapsulate()
        x_ephemeral_private = x25519.X25519PrivateKey.generate()
        x_ephemeral_public_bytes = x_ephemeral_private.public_key().public_bytes_raw()
        x_secret = x_ephemeral_private.exchange(x_public)
    except UnsupportedAlgorithm as exc:
        raise QDuckError(_MLKEM_UNAVAILABLE_MSG) from exc
    except Exception as exc:
        raise KeyFormatError("invalid public key") from exc

    aes_key = _hkdf_hybrid_secret(mlkem_secret, x_secret)
    key_block = mlkem_ciphertext + x_ephemeral_public_bytes
    return aes_key, key_block


def recover_hybrid_key(private_key: bytes, key_block: bytes) -> bytes:
    validate_private_key(private_key)
    validate_key_block(key_block)

    mlkem_seed = private_key[:MLKEM768_PRIVATE_SEED_SIZE]
    x_private_bytes = private_key[MLKEM768_PRIVATE_SEED_SIZE:]

    mlkem_ciphertext = key_block[:MLKEM768_CIPHERTEXT_SIZE]
    x_ephemeral_public_bytes = key_block[MLKEM768_CIPHERTEXT_SIZE:]

    try:
        mlkem_private = mlkem.MLKEM768PrivateKey.from_seed_bytes(mlkem_seed)
        x_private = x25519.X25519PrivateKey.from_private_bytes(x_private_bytes)
        x_ephemeral_public = x25519.X25519PublicKey.from_public_bytes(
            x_ephemeral_public_bytes
        )

        mlkem_secret = mlkem_private.decapsulate(mlkem_ciphertext)
        x_secret = x_private.exchange(x_ephemeral_public)
    except UnsupportedAlgorithm as exc:
        raise QDuckError(_MLKEM_UNAVAILABLE_MSG) from exc
    except Exception as exc:
        raise DecryptionError("failed to recover AES key from key_block") from exc

    return _hkdf_hybrid_secret(mlkem_secret, x_secret)


def _validate_aad(aad: Optional[bytes]) -> None:
    if aad is not None and not isinstance(aad, bytes):
        raise TypeError("aad must be bytes or None")


def aes_gcm_encrypt(data: bytes, aes_key: bytes, aad: Optional[bytes] = None) -> bytes:
    _require_bytes(data, "data")
    _validate_aad(aad)
    if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_SIZE:
        raise KeyFormatError(f"aes_key must be {AES_KEY_SIZE} bytes")

    nonce = os.urandom(NONCE_SIZE)
    ciphertext_and_tag = AESGCM(aes_key).encrypt(nonce, data, aad)
    return nonce + ciphertext_and_tag


def aes_gcm_decrypt(
    ciphertext: bytes,
    aes_key: bytes,
    aad: Optional[bytes] = None,
) -> bytes:
    _require_bytes(ciphertext, "ciphertext")
    _validate_aad(aad)
    if not isinstance(aes_key, bytes) or len(aes_key) != AES_KEY_SIZE:
        raise DecryptionError(f"aes_key must be {AES_KEY_SIZE} bytes")
    if len(ciphertext) < NONCE_SIZE + TAG_SIZE:
        raise DecryptionError("ciphertext is too short")

    nonce = ciphertext[:NONCE_SIZE]
    ciphertext_and_tag = ciphertext[NONCE_SIZE:]

    try:
        return AESGCM(aes_key).decrypt(nonce, ciphertext_and_tag, aad)
    except InvalidTag as exc:
        raise DecryptionError("AES-GCM authentication failed") from exc
    except Exception as exc:
        raise DecryptionError("AES-GCM decryption failed") from exc
