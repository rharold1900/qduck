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

from .api import (
    DecryptionError,
    KeyFormatError,
    QDuckError,
    decrypt_blob,
    decrypt_file,
    derive_key,
    encrypt_blob,
    encrypt_file,
    generate_keypair,
    load_private_key,
    load_public_key,
    recover_key,
    save_keypair,
)

__all__ = [
    "QDuckError",
    "DecryptionError",
    "KeyFormatError",
    "generate_keypair",
    "save_keypair",
    "load_public_key",
    "load_private_key",
    "derive_key",
    "recover_key",
    "encrypt_blob",
    "decrypt_blob",
    "encrypt_file",
    "decrypt_file",
]
