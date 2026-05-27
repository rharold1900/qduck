import os
import qduck


def test_large_blob_5mb_roundtrip():
    payload = os.urandom(5 * 1024 * 1024)

    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)

    ciphertext = qduck.encrypt_blob(payload, aes_key, aad=key_block)
    plaintext = qduck.decrypt_blob(ciphertext, aes_key, aad=key_block)

    assert plaintext == payload
    assert ciphertext != payload
    assert len(ciphertext) > len(payload)
