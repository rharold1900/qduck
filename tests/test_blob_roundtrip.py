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
