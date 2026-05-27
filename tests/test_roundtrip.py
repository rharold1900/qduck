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

"""Roundtrip and tamper tests for qduck's blob and file APIs.

Run with pytest for the standard test runner:
    pytest tests/

Or run this file directly for a quick smoke check without pytest:
    python tests/test_roundtrip.py
"""

import pytest

import qduck


def test_blob_roundtrip():
    public_key, private_key = qduck.generate_keypair()

    client_aes_key, key_block = qduck.derive_key(public_key)
    ciphertext = qduck.encrypt_blob(b"test message", client_aes_key)

    server_aes_key = qduck.recover_key(private_key, key_block)
    plaintext = qduck.decrypt_blob(ciphertext, server_aes_key)

    assert plaintext == b"test message"
    assert client_aes_key == server_aes_key
    assert len(client_aes_key) == 32
    assert len(key_block) == 1120


def test_tampered_blob_fails():
    public_key, private_key = qduck.generate_keypair()
    client_aes_key, key_block = qduck.derive_key(public_key)
    ciphertext = bytearray(qduck.encrypt_blob(b"test message", client_aes_key))
    ciphertext[-1] ^= 1

    server_aes_key = qduck.recover_key(private_key, key_block)

    with pytest.raises(qduck.DecryptionError):
        qduck.decrypt_blob(bytes(ciphertext), server_aes_key)


def test_file_roundtrip(tmp_path):
    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)
    server_aes_key = qduck.recover_key(private_key, key_block)

    src = tmp_path / "message.txt"
    enc = tmp_path / "message.txt.enc"
    out = tmp_path / "message.recovered.txt"
    src.write_bytes(b"file roundtrip payload")

    qduck.encrypt_file(str(src), str(enc), aes_key)
    qduck.decrypt_file(str(enc), str(out), server_aes_key)

    assert out.read_bytes() == src.read_bytes()


def test_tampered_file_fails(tmp_path):
    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)
    server_aes_key = qduck.recover_key(private_key, key_block)

    src = tmp_path / "message.txt"
    enc = tmp_path / "message.txt.enc"
    out = tmp_path / "message.recovered.txt"
    src.write_bytes(b"file roundtrip payload")
    qduck.encrypt_file(str(src), str(enc), aes_key)

    tampered = bytearray(enc.read_bytes())
    tampered[-1] ^= 1
    enc.write_bytes(bytes(tampered))

    with pytest.raises(qduck.DecryptionError):
        qduck.decrypt_file(str(enc), str(out), server_aes_key)


if __name__ == "__main__":
    # Run all tests in this file directly without pytest. Standard usage
    # is `pytest tests/`; this fallback is here so the file can also be
    # invoked as `python tests/test_roundtrip.py` for a quick smoke check.
    import sys
    sys.exit(pytest.main([__file__, "-v"]))
