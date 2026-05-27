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

"""Simplest possible file roundtrip with qduck.

The bare-minimum form: no aad, just encrypt a file and decrypt it back.
For the recommended pattern that binds each ciphertext to its handshake,
see examples/file_roundtrip.py.
"""

from pathlib import Path

import qduck


def main() -> None:
    public_key, private_key = qduck.generate_keypair()

    aes_key, key_block = qduck.derive_key(public_key)
    # In practice key_block is sent to the server during authentication.
    server_aes_key = qduck.recover_key(private_key, key_block)

    Path("message.txt").write_text("hello from qduck on disk\n", encoding="utf-8")

    qduck.encrypt_file("message.txt", "message.txt.enc", aes_key, overwrite=True)
    qduck.decrypt_file("message.txt.enc", "message.recovered.txt", server_aes_key,
                       overwrite=True)

    assert Path("message.recovered.txt").read_bytes() == Path("message.txt").read_bytes()
    print("simple file roundtrip ok")


if __name__ == "__main__":
    main()
