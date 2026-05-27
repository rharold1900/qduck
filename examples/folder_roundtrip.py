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

"""Encrypt/decrypt a whole folder tree using qduck primitives.

This is intentionally example code, not qduck library API. qduck itself only
handles bytes. This script shows how a caller can compose those primitives:

1. Enumerate source folder files.
2. Encrypt each file into a mirrored encrypted folder hierarchy.
3. Store a per-file .keyblock next to each encrypted file.
4. Decrypt into a mirrored target folder hierarchy.
5. Diff source vs target by relative path, size, and SHA-256 hash.

Usage:
  python examples/folder_roundtrip.py ./source ./encrypted ./decrypted
  python examples/folder_roundtrip.py ./source ./encrypted ./decrypted --verbose
"""

import argparse
import hashlib
import shutil
from pathlib import Path

import qduck


ENCRYPTED_SUFFIX = ".qduck"
KEYBLOCK_SUFFIX = ".keyblock"


def iter_files(root: Path):
    for path in sorted(root.rglob("*")):
        if path.is_file():
            yield path


def sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        for chunk in iter(lambda: f.read(1024 * 1024), b""):
            h.update(chunk)
    return h.hexdigest()


def ensure_clean_dir(path: Path) -> None:
    if path.exists():
        shutil.rmtree(path)
    path.mkdir(parents=True, exist_ok=True)


def encrypted_path_for(source_file: Path, source_root: Path, encrypted_root: Path) -> Path:
    relative = source_file.relative_to(source_root)
    return encrypted_root / relative.with_name(relative.name + ENCRYPTED_SUFFIX)


def keyblock_path_for(encrypted_file: Path) -> Path:
    return encrypted_file.with_name(encrypted_file.name + KEYBLOCK_SUFFIX)


def decrypted_path_for(encrypted_file: Path, encrypted_root: Path, target_root: Path) -> Path:
    relative = encrypted_file.relative_to(encrypted_root)
    if not relative.name.endswith(ENCRYPTED_SUFFIX):
        raise ValueError(f"not a qduck encrypted file: {encrypted_file}")
    original_name = relative.name[: -len(ENCRYPTED_SUFFIX)]
    return target_root / relative.with_name(original_name)


def encrypt_folder(
    source_root: Path,
    encrypted_root: Path,
    public_key: bytes,
    verbose: bool = False,
) -> int:
    count = 0
    for source_file in iter_files(source_root):
        aes_key, key_block = qduck.derive_key(public_key)

        encrypted_file = encrypted_path_for(source_file, source_root, encrypted_root)
        encrypted_file.parent.mkdir(parents=True, exist_ok=True)
        qduck.encrypt_file(
            str(source_file), str(encrypted_file), aes_key, aad=key_block, overwrite=True
        )
        keyblock_path_for(encrypted_file).write_bytes(key_block)
        count += 1
        if verbose and count % 100 == 0:
            print(f"encrypted {count} files")
    return count


def decrypt_folder(
    encrypted_root: Path,
    target_root: Path,
    private_key: bytes,
    verbose: bool = False,
) -> int:
    count = 0
    encrypted_files = [
        path
        for path in iter_files(encrypted_root)
        if path.name.endswith(ENCRYPTED_SUFFIX)
        and not path.name.endswith(ENCRYPTED_SUFFIX + KEYBLOCK_SUFFIX)
    ]

    for encrypted_file in encrypted_files:
        key_block = keyblock_path_for(encrypted_file).read_bytes()

        aes_key = qduck.recover_key(private_key, key_block)
        target_file = decrypted_path_for(encrypted_file, encrypted_root, target_root)
        target_file.parent.mkdir(parents=True, exist_ok=True)
        qduck.decrypt_file(
            str(encrypted_file), str(target_file), aes_key, aad=key_block, overwrite=True
        )
        count += 1
        if verbose and count % 100 == 0:
            print(f"decrypted {count} files")
    return count


def snapshot(root: Path) -> dict[str, tuple[int, str]]:
    return {
        str(path.relative_to(root)): (path.stat().st_size, sha256_file(path))
        for path in iter_files(root)
    }


def diff_folders(source_root: Path, target_root: Path) -> list[str]:
    source = snapshot(source_root)
    target = snapshot(target_root)
    problems: list[str] = []

    for relative in sorted(source.keys() - target.keys()):
        problems.append(f"missing from target: {relative}")
    for relative in sorted(target.keys() - source.keys()):
        problems.append(f"extra in target: {relative}")
    for relative in sorted(source.keys() & target.keys()):
        if source[relative] != target[relative]:
            problems.append(f"content mismatch: {relative}")
    return problems


def create_sample_source(source_root: Path) -> None:
    ensure_clean_dir(source_root)
    (source_root / "hello.txt").write_text("hello from qduck\n", encoding="utf-8")
    (source_root / "nested").mkdir()
    (source_root / "nested" / "data.bin").write_bytes(b"\x00\x01\x02 qduck data\n")
    (source_root / "nested" / "notes.md").write_text("# Notes\n\nSecret notes.\n", encoding="utf-8")


def run_folder_roundtrip(
    source_root: Path,
    encrypted_root: Path,
    target_root: Path,
    verbose: bool = False,
) -> None:
    if not source_root.exists():
        create_sample_source(source_root)
    ensure_clean_dir(encrypted_root)
    ensure_clean_dir(target_root)

    public_key, private_key = qduck.generate_keypair()

    encrypted_count = encrypt_folder(source_root, encrypted_root, public_key, verbose=verbose)
    decrypted_count = decrypt_folder(encrypted_root, target_root, private_key, verbose=verbose)
    problems = diff_folders(source_root, target_root)

    print(f"encrypted files: {encrypted_count}")
    print(f"decrypted files: {decrypted_count}")
    if problems:
        print("diff failed:")
        for problem in problems:
            print(f"  - {problem}")
        raise SystemExit(1)

    print("diff ok: source and target match")


def main() -> None:
    parser = argparse.ArgumentParser(description="qduck folder encrypt/decrypt/diff demo")
    parser.add_argument("source", nargs="?", default="demo-source")
    parser.add_argument("encrypted", nargs="?", default="demo-encrypted")
    parser.add_argument("target", nargs="?", default="demo-decrypted")
    parser.add_argument(
        "-v",
        "--verbose",
        action="store_true",
        help="print progress every 100 files",
    )
    args = parser.parse_args()

    run_folder_roundtrip(
        Path(args.source),
        Path(args.encrypted),
        Path(args.target),
        verbose=args.verbose,
    )


if __name__ == "__main__":
    main()
