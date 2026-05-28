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


def test_large_blob_5mb_roundtrip():
    payload = os.urandom(5 * 1024 * 1024)

    public_key, private_key = qduck.generate_keypair()
    aes_key, key_block = qduck.derive_key(public_key)

    ciphertext = qduck.encrypt_blob(payload, aes_key, aad=key_block)
    plaintext = qduck.decrypt_blob(ciphertext, aes_key, aad=key_block)

    assert plaintext == payload
    assert ciphertext != payload
    assert len(ciphertext) > len(payload)
