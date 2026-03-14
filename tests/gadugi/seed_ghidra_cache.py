#!/usr/bin/env python3
import hashlib
import json
import sys
from pathlib import Path


def main() -> int:
    if len(sys.argv) != 3:
        print(
            "usage: seed_ghidra_cache.py <binary-path> <home-dir>",
            file=sys.stderr,
        )
        return 2

    binary_path = Path(sys.argv[1]).resolve()
    home_dir = Path(sys.argv[2]).resolve()

    digest = hashlib.sha256(binary_path.read_bytes()).hexdigest()
    cache_dir = home_dir / ".skwaq" / "cache" / "ghidra" / digest
    cache_dir.mkdir(parents=True, exist_ok=True)

    analysis = {
        "functions": [
            {
                "name": "main",
                "address": "00401000",
                "size": 64,
                "decompiled": (
                    "int main(int argc, char **argv) {\n"
                    "  char buffer[64];\n"
                    "  strcpy(buffer, argv[1]);\n"
                    "  return argc;\n"
                    "}"
                ),
                "calls": [],
                "called_by": [],
                "parameter_count": 2,
            }
        ],
        "strings": [],
        "imports": [],
    }

    (cache_dir / "analysis.json").write_text(json.dumps(analysis, indent=2))
    print(cache_dir / "analysis.json")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
