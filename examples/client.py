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

"""Minimal client-side qduck example.

Demonstrates the on-disk file workflow using qduck.encrypt_file().

Inputs:
  public.key
  message.txt

Outputs:
  message.keyblock     (handshake bytes for the server)
  message.txt.enc      (encrypted file)
"""

from pathlib import Path

import qduck


PUBLIC_KEY_PATH = "public.key"
PLAINTEXT_PATH = "message.txt"
KEY_BLOCK_PATH = "message.keyblock"
CIPHERTEXT_PATH = "message.txt.enc"


def main() -> None:
    public_key = qduck.load_public_key(PUBLIC_KEY_PATH)
    aes_key, key_block = qduck.derive_key(public_key)

    qduck.encrypt_file(PLAINTEXT_PATH, CIPHERTEXT_PATH, aes_key,
                       aad=key_block, overwrite=True)
    Path(KEY_BLOCK_PATH).write_bytes(key_block)

    print(f"wrote {KEY_BLOCK_PATH}")
    print(f"wrote {CIPHERTEXT_PATH}")


if __name__ == "__main__":
    main()
