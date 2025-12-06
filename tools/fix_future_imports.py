#!/usr/bin/env python3
"""
Fixer: ensure `from __future__ import ...` statements appear at the
very beginning of a module (after shebang/encoding comment and optional
module docstring), as required by Python. Some annotators may insert
imports above future imports, causing SyntaxError at import time.

Usage:
  python3 tools/fix_future_imports.py <file_or_directory>

It will rewrite .py files in place. Best-effort and idempotent.
"""
from __future__ import annotations

import sys
from pathlib import Path
from typing import List


def split_header_body(lines: List[str]) -> tuple[List[str], List[str]]:
    """Split into (header, body) where header contains shebang, encoding comment,
    and top-level module docstring if present.
    """
    i = 0
    n = len(lines)
    header: List[str] = []

    # Shebang
    if i < n and lines[i].startswith("#!"):
        header.append(lines[i]); i += 1

    # Encoding comment (PEP 263)
    if i < n and ("coding" in lines[i] and lines[i].lstrip().startswith("#")):
        header.append(lines[i]); i += 1

    # Skip blank lines
    while i < n and lines[i].strip() == "":
        header.append(lines[i]); i += 1

    # Module docstring
    if i < n and lines[i].lstrip().startswith(("'"*3, '"'*3)):
        quote = lines[i].lstrip()[0] * 3
        header.append(lines[i]); i += 1
        # consume until closing triple quote
        while i < n:
            header.append(lines[i])
            if quote in lines[i]:
                i += 1
                break
            i += 1

    return header, lines[i:]


def fix_file(path: Path) -> bool:
    try:
        text = path.read_text(encoding="utf-8")
    except Exception:
        return False
    lines = text.splitlines(keepends=True)
    header, body = split_header_body(lines)

    future_idxs = []
    future_lines: List[str] = []
    for idx, line in enumerate(body):
        stripped = line.lstrip()
        # Only match clean future imports beginning of a statement
        if stripped.startswith("from __future__ import "):
            future_idxs.append(idx)
            future_lines.append(line)

    if not future_idxs:
        return False  # nothing to fix

    # Remove future imports from body
    new_body = [line for idx, line in enumerate(body) if idx not in future_idxs]

    # Avoid duplicates while preserving order
    seen = set()
    dedup_future: List[str] = []
    for fl in future_lines:
        if fl not in seen:
            dedup_future.append(fl)
            seen.add(fl)

    # Ensure there is exactly one blank line between header+futures and body if needed
    out_lines = []
    out_lines.extend(header)
    # If header doesn't already end with a newline linebreak, it will naturally as we kept ends
    # Insert future imports
    # Ensure there's a blank line before futures if header doesn't end with one and isn't empty
    if header and (len(header) == 0 or (header and header[-1].strip() != "")):
        out_lines.append("\n")
    out_lines.extend(dedup_future)
    if dedup_future and (len(new_body) and new_body[0].strip() != ""):
        out_lines.append("\n")
    out_lines.extend(new_body)

    new_text = "".join(out_lines)
    if new_text != text:
        path.write_text(new_text, encoding="utf-8")
        return True
    return False


def walk_and_fix(root: Path) -> int:
    count = 0
    if root.is_file() and root.suffix == ".py":
        if fix_file(root):
            count += 1
        return count
    for p in root.rglob("*.py"):
        try:
            if fix_file(p):
                count += 1
        except Exception:
            continue
    return count


def main() -> int:
    if len(sys.argv) < 2:
        print("Usage: fix_future_imports.py <file_or_directory>")
        return 2
    target = Path(sys.argv[1]).resolve()
    changed = walk_and_fix(target)
    print(f"Fixed __future__ imports in {changed} file(s) under {target}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
