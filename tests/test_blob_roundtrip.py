import os
import qduck


def _roundtrip(payload: bytes):
    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)

    ciphertext = qduck.encrypt_blob(payload, aes_key, aad=key_block)
    plaintext = qduck.decrypt_blob(ciphertext, aes_key, aad=key_block)

    assert plaintext == payload
    assert ciphertext != payload
    return ciphertext


def test_empty_blob_roundtrip():
    _roundtrip(b"")


def test_one_byte_blob_roundtrip():
    _roundtrip(b"x")


def test_text_blob_roundtrip():
    _roundtrip(b"hello qduck")


def test_random_binary_blob_roundtrip():
    _roundtrip(os.urandom(4096))


def test_repeated_encryptions_produce_different_ciphertexts():
    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)

    payload = b"same plaintext"
    ct1 = qduck.encrypt_blob(payload, aes_key, aad=key_block)
    ct2 = qduck.encrypt_blob(payload, aes_key, aad=key_block)

    assert ct1 != ct2
    assert qduck.decrypt_blob(ct1, aes_key, aad=key_block) == payload
    assert qduck.decrypt_blob(ct2, aes_key, aad=key_block) == payload
