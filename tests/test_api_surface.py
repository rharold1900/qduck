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

import qduck


def test_expected_public_api_exists():
    # Callable API
    assert callable(qduck.generate_keypair)
    assert callable(qduck.save_keypair)
    assert callable(qduck.load_public_key)
    assert callable(qduck.load_private_key)
    assert callable(qduck.derive_key)
    assert callable(qduck.recover_key)
    assert callable(qduck.encrypt_blob)
    assert callable(qduck.decrypt_blob)
    assert callable(qduck.encrypt_file)
    assert callable(qduck.decrypt_file)
    assert callable(qduck.decrypt_file_with_private_key)
    # Exception classes
    assert issubclass(qduck.QDuckError, Exception)
    assert issubclass(qduck.DecryptionError, qduck.QDuckError)
    assert issubclass(qduck.KeyFormatError, qduck.QDuckError)


def test_all_exports_present_in_dunder_all():
    expected = {
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
        "decrypt_file_with_private_key",
    }
    assert expected == set(qduck.__all__)
