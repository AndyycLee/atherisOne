#!/usr/bin/env python3
"""
Tidy the workspace by removing deprecated typing scripts and type-checker caches.
Keeps only pyrefly-based flows.
"""
import os
import shutil
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

DIRS = [
    ".pytype",
    ".pyre",
    ".mypy_cache",
    ".pytest_cache",
]
FILES = [
    "add_types.py",
    "add_types_repo.py",
    "add_types_repo_pyre.py",
    "test_pytype.py",
]

def rm_dir(p: Path) -> None:
    if p.is_dir():
        shutil.rmtree(p, ignore_errors=True)


def rm_file(p: Path) -> None:
    try:
        if p.is_file():
            p.unlink()
    except Exception:
        pass


def main() -> int:
    for d in DIRS:
        rm_dir(ROOT / d)
    for f in FILES:
        rm_file(ROOT / f)
    print("Tidied caches and deprecated files under:", ROOT)
    return 0

if __name__ == "__main__":
    raise SystemExit(main())
