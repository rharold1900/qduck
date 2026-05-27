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

"""One-file qduck smoke example: keygen, derive, encrypt, recover, decrypt.

Uses aad=key_block to bind each ciphertext to its handshake (recommended).
See examples/simple_blob.py for the bare-minimum form without aad.
"""

import qduck


def main() -> None:
    public_key, private_key = qduck.generate_keypair()

    client_aes_key, key_block = qduck.derive_key(public_key)
    ciphertext = qduck.encrypt_blob(b"hello from qduck", client_aes_key, aad=key_block)

    # In practice key_block is sent to the server during authentication.
    server_aes_key = qduck.recover_key(private_key, key_block)
    plaintext = qduck.decrypt_blob(ciphertext, server_aes_key, aad=key_block)

    assert plaintext == b"hello from qduck"
    print("roundtrip ok")
    print(f"public key: {len(public_key)} bytes")
    print(f"private key: {len(private_key)} bytes")
    print(f"key block: {len(key_block)} bytes")


if __name__ == "__main__":
    main()
