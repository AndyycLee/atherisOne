#!/usr/bin/env python3
"""
add_types_repo.py - Bulk-add type annotations across a repo using PyType, then
merge them into source files. This is a pragmatic way to auto-annotate at scale
before running the Atheris harness generator.

Why PyType here instead of Pyre?
- PyType can infer and emit .pyi stubs directly from source, and merge them back
  via merge-pyi reliably. Pyre shines as a fast, large-scale type checker; it
  also has codemods, but end-to-end auto-annotation via Pyre is more bespoke.

Usage:
  python3 add_types_repo.py [--root .] [--include-tests] [--jobs N] [--dry-run]

Prereqs:
  pip install pytype
  # optional (for speed): pip install mypy_extensions

Notes:
  - This script runs PyType per file to keep paths simple, then uses merge-pyi
    to apply changes in-place. It skips common vendor/venv/build directories.
  - It only annotates .py files; it ignores already-generated .pyi files.
"""
from __future__ import annotations

import argparse
import os
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path
from typing import Iterable, List


SKIP_DIRS = {
    ".git",
    "__pycache__",
    ".mypy_cache",
    ".pytest_cache",
    ".pytype",
    ".venv",
    "venv",
    "env",
    "build",
    "dist",
    ".eggs",
}


def discover_python_files(root: Path, include_tests: bool) -> List[Path]:
    files: List[Path] = []
    for dirpath, dirnames, filenames in os.walk(root):
        # prune skip dirs
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for name in filenames:
            if not name.endswith(".py"):
                continue
            if name.endswith(".pyi"):
                continue
            if not include_tests and (name.startswith("test_") or name.endswith("_test.py")):
                continue
            files.append(Path(dirpath) / name)
    return files


def run_pytype_on_file(root: Path, file_path: Path) -> tuple[Path, Path | None, str | None]:
    """
    Run pytype on a single source file.
    Returns (file_path, pyi_path or None, error or None)
    """
    try:
        # Use the same Python exe that's running this script
        python_exe = sys.executable
        proc = subprocess.run(
            [python_exe, "-m", "pytype", str(file_path)],
            cwd=str(root),
            capture_output=True,
            text=True,
        )
        # PyType writes to .pytype/pyi/<module>.pyi. Compute relative path.
        rel = file_path.relative_to(root)
        pyi_path = root / ".pytype" / "pyi" / rel.with_suffix(".pyi")

        if pyi_path.exists():
            return (file_path, pyi_path, None)
        else:
            # Even if return code != 0, pytype may still emit stubs; report stderr if none.
            err = proc.stderr.strip() or proc.stdout.strip() or "No .pyi emitted"
            return (file_path, None, err)
    except Exception as e:
        return (file_path, None, f"Exception: {type(e).__name__}: {e}")


def merge_stub_into_source(source: Path, stub: Path, dry_run: bool) -> tuple[Path, bool, str | None]:
    """Apply merge-pyi to write annotations in-place."""
    try:
        if dry_run:
            return (source, True, None)
        proc = subprocess.run(
            ["merge-pyi", "-i", str(source), str(stub)],
            capture_output=True,
            text=True,
        )
        if proc.returncode == 0:
            return (source, True, None)
        else:
            return (source, False, proc.stderr.strip() or proc.stdout.strip())
    except FileNotFoundError:
        return (
            source,
            False,
            "merge-pyi not found. Install: pip install pytype && ensure merge-pyi on PATH",
        )
    except Exception as e:
        return (source, False, f"Exception: {type(e).__name__}: {e}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".", help="Project root (default: .)")
    ap.add_argument("--include-tests", action="store_true", help="Include test_*.py and *_test.py files")
    ap.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1), help="Parallel workers (default: CPU count)")
    ap.add_argument("--dry-run", action="store_true", help="Only run pytype, skip merge-pyi writes")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if not root.exists():
        print(f"Root not found: {root}", file=sys.stderr)
        return 2

    files = discover_python_files(root, include_tests=args.include_tests)
    if not files:
        print("No Python files discovered.")
        return 0

    print(f"Discovered {len(files)} Python files under {root}")

    # Run pytype in parallel
    results: List[tuple[Path, Path | None, str | None]] = []
    with ThreadPoolExecutor(max_workers=args.jobs) as ex:
        futures = [ex.submit(run_pytype_on_file, root, f) for f in files]
        for fut in as_completed(futures):
            results.append(fut.result())

    emit_count = sum(1 for _, pyi, _ in results if pyi is not None)
    print(f"PyType emitted stubs for {emit_count}/{len(files)} files")

    # Merge
    merged = 0
    failed: List[tuple[Path, str]] = []
    for src, pyi, err in results:
        if pyi is None:
            if err:
                failed.append((src, f"no-stub: {err}"))
            continue
        src_ok, ok, merge_err = merge_stub_into_source(src, pyi, args.dry_run)
        if ok:
            merged += 1
        else:
            failed.append((src_ok, merge_err or "merge failed"))

    print(("[DRY RUN] " if args.dry_run else "") + f"Annotated {merged} files via merge-pyi")
    if failed:
        print(f"\nSome files failed to annotate ({len(failed)}):")
        for path, msg in failed[:50]:
            print(f"  - {path}: {msg}")
        if len(failed) > 50:
            print(f"  ... and {len(failed)-50} more")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
