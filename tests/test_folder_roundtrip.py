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

import sys
from pathlib import Path

# Make the project root importable so `from examples...` works whether this
# file is invoked via pytest (which auto-adds the root) or directly via
# `python tests/test_folder_roundtrip.py`.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from examples.folder_roundtrip import diff_folders, run_folder_roundtrip  # noqa: E402


def test_folder_roundtrip(tmp_path: Path):
    source = tmp_path / "source"
    encrypted = tmp_path / "encrypted"
    target = tmp_path / "target"

    (source / "subdir").mkdir(parents=True)
    (source / "a.txt").write_text("alpha\n", encoding="utf-8")
    (source / "subdir" / "b.bin").write_bytes(b"beta\x00gamma")

    run_folder_roundtrip(source, encrypted, target)

    assert diff_folders(source, target) == []


if __name__ == "__main__":
    import sys
    import pytest
    sys.exit(pytest.main([__file__, "-v"]))
