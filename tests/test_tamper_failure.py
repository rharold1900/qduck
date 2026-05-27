import os
import pytest
import qduck


def _make_encrypted(payload: bytes = b"attack at dawn"):
    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)
    ciphertext = qduck.encrypt_blob(payload, aes_key, aad=key_block)
    return aes_key, key_block, ciphertext


def test_tampered_ciphertext_fails():
    aes_key, key_block, ciphertext = _make_encrypted()

    tampered = bytearray(ciphertext)
    tampered[-1] ^= 0x01

    with pytest.raises(Exception):
        qduck.decrypt_blob(bytes(tampered), aes_key, aad=key_block)


def test_wrong_aad_fails():
    aes_key, key_block, ciphertext = _make_encrypted()

    wrong_aad = bytearray(key_block)
    wrong_aad[-1] ^= 0x01

    with pytest.raises(Exception):
        qduck.decrypt_blob(ciphertext, aes_key, aad=bytes(wrong_aad))


def test_wrong_key_fails():
    aes_key, key_block, ciphertext = _make_encrypted()

    wrong_key = bytearray(aes_key)
    wrong_key[-1] ^= 0x01

    with pytest.raises(Exception):
        qduck.decrypt_blob(ciphertext, bytes(wrong_key), aad=key_block)


def test_random_bytes_do_not_decrypt():
    aes_key, key_block, ciphertext = _make_encrypted()

    with pytest.raises(Exception):
        qduck.decrypt_blob(os.urandom(len(ciphertext)), aes_key, aad=key_block)
