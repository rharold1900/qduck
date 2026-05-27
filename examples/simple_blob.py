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

"""Simplest possible blob roundtrip with qduck.

The bare-minimum form: no aad, no files, just bytes in and bytes out.
For the recommended pattern that binds each ciphertext to its handshake,
see examples/roundtrip.py.
"""

import qduck


def main() -> None:
    public_key, private_key = qduck.generate_keypair()

    aes_key, key_block = qduck.derive_key(public_key)
    ciphertext = qduck.encrypt_blob(b"hello from qduck", aes_key)

    # In practice key_block is sent to the server during authentication.
    server_aes_key = qduck.recover_key(private_key, key_block)
    plaintext = qduck.decrypt_blob(ciphertext, server_aes_key)

    assert plaintext == b"hello from qduck"
    print("simple blob roundtrip ok")


if __name__ == "__main__":
    main()
