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

"""One-file qduck smoke example for the on-disk file API.

Creates message.txt, encrypts it to message.txt.enc, decrypts it back
to message.recovered.txt, and verifies the result matches.

Uses aad=key_block to bind each ciphertext to its handshake (recommended).
See examples/simple_file.py for the bare-minimum form without aad.
"""

from pathlib import Path

import qduck


def main() -> None:
    public_key, private_key = qduck.generate_keypair()

    aes_key, key_block = qduck.derive_key(public_key)
    # In practice key_block is sent to the server during authentication.
    server_aes_key = qduck.recover_key(private_key, key_block)

    Path("message.txt").write_text("hello from qduck on disk\n", encoding="utf-8")

    qduck.encrypt_file("message.txt", "message.txt.enc", aes_key,
                       aad=key_block, overwrite=True)
    qduck.decrypt_file("message.txt.enc", "message.recovered.txt", server_aes_key,
                       aad=key_block, overwrite=True)

    assert Path("message.recovered.txt").read_bytes() == Path("message.txt").read_bytes()
    print("file roundtrip ok")
    print(f"plaintext:  {Path('message.txt').stat().st_size} bytes")
    print(f"ciphertext: {Path('message.txt.enc').stat().st_size} bytes")


if __name__ == "__main__":
    main()
