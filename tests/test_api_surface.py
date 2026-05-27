import qduck


def test_expected_public_api_exists():
    assert callable(qduck.generate_keypair)
    assert callable(qduck.derive_key)
    assert callable(qduck.encrypt_blob)
    assert callable(qduck.decrypt_blob)
