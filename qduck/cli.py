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

import argparse

from .api import save_keypair


def main() -> None:
    parser = argparse.ArgumentParser(
        prog="qduck-keygen",
        description="Generate a qduck X25519 + ML-KEM-768 hybrid keypair.",
    )
    parser.add_argument("--public", default="public.key", help="public key output path")
    parser.add_argument("--private", default="private.key", help="private key output path")
    parser.add_argument(
        "--force",
        action="store_true",
        help="overwrite existing output files",
    )
    args = parser.parse_args()

    save_keypair(args.public, args.private, force=args.force)
    print(f"wrote public key:  {args.public}")
    print(f"wrote private key: {args.private}")


if __name__ == "__main__":
    main()
