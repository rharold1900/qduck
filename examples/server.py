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

"""Minimal server-side qduck example.

Demonstrates the on-disk file workflow using qduck.decrypt_file().

Inputs:
  private.key
  message.keyblock
  message.txt.enc

Output:
  message.recovered.txt
"""

from pathlib import Path

import qduck


PRIVATE_KEY_PATH = "private.key"
KEY_BLOCK_PATH = "message.keyblock"
CIPHERTEXT_PATH = "message.txt.enc"
PLAINTEXT_PATH = "message.recovered.txt"


def main() -> None:
    private_key = qduck.load_private_key(PRIVATE_KEY_PATH)
    key_block = Path(KEY_BLOCK_PATH).read_bytes()

    aes_key = qduck.recover_key(private_key, key_block)
    qduck.decrypt_file(CIPHERTEXT_PATH, PLAINTEXT_PATH, aes_key,
                       aad=key_block, overwrite=True)

    size = Path(PLAINTEXT_PATH).stat().st_size
    print(f"wrote {PLAINTEXT_PATH} ({size} bytes)")


if __name__ == "__main__":
    main()
