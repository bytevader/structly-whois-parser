#!/usr/bin/env python3
"""Fail when files contain bidirectional control characters."""

from __future__ import annotations

import sys
from pathlib import Path

BIDI_CODEPOINTS = tuple(range(0x202A, 0x202F)) + tuple(range(0x2066, 0x206A))
BIDI_CHARS = {chr(code) for code in BIDI_CODEPOINTS}
SKIP_DIRS = {
    ".git",
    ".idea",
    ".venv",
    "venv",
    "build",
    "dist",
    "__pycache__",
    ".mypy_cache",
    ".ruff_cache",
    ".pytest_cache",
}


def main() -> int:
    root = Path(__file__).resolve().parents[1]
    offenders: list[str] = []
    for path in iter_files(root):
        try:
            text = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            text = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        found = find_bidi_chars(text)
        if found:
            offenders.append(
                f"{path.relative_to(root)}: "
                + ", ".join(f"U+{ord(ch):04X}" for ch in found)
            )
    if offenders:
        print("Bidirectional control characters detected:", file=sys.stderr)
        for entry in offenders:
            print(f"  {entry}", file=sys.stderr)
        return 1
    return 0


def iter_files(root: Path):
    for path in root.rglob("*"):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.is_file():
            yield path


def find_bidi_chars(text: str) -> list[str]:
    return [ch for ch in text if ch in BIDI_CHARS]


if __name__ == "__main__":
    raise SystemExit(main())
