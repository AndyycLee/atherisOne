#!/usr/bin/env python3
"""
show_target_signature.py — Print the signature, evaluated type hints, and source for a target callable.

Usage:
  python3 show_target_signature.py module.path:callable

Notes:
  - Resolves dotted attributes after the colon (e.g., pkg.mod:Class.method).
  - Prints the file path and a small snippet if source is available.
  - Evaluates annotations via typing.get_type_hints (may import modules).
"""
from __future__ import annotations

import importlib
import inspect
import sys
from typing import get_type_hints


def resolve_target(spec: str):
    if ':' not in spec:
        raise SystemExit('Target must be module:callable (with optional dotted attributes)')
    module_name, callable_path = spec.split(':', 1)
    top_name = callable_path.split('.')[0]

    module = importlib.import_module(module_name)
    obj = getattr(module, top_name)
    rest = callable_path[len(top_name):].lstrip('.')
    for part in rest.split('.') if rest else []:
        obj = getattr(obj, part)
    return obj


def main() -> int:
    if len(sys.argv) < 2:
        print(__doc__)
        return 1
    target_spec = sys.argv[1]
    try:
        target = resolve_target(target_spec)
    except Exception as e:
        print(f"Failed to resolve target '{target_spec}': {type(e).__name__}: {e}")
        return 2

    print(f"Target: {target_spec}")
    try:
        sig = inspect.signature(target)
        print(f"Signature: {sig}")
    except Exception as e:
        print(f"Signature: <unavailable> ({type(e).__name__}: {e})")
        sig = None

    try:
        hints = get_type_hints(target)
        print("Type hints:")
        for k, v in hints.items():
            print(f"  {k}: {v}")
    except Exception as e:
        print(f"Type hints: <unavailable> ({type(e).__name__}: {e})")

    try:
        src_file = inspect.getsourcefile(target) or inspect.getfile(target)
        print(f"Source file: {src_file}")
        try:
            lines, start = inspect.getsourcelines(target)
            # show up to ~40 lines around the definition
            preview = ''.join(lines[:40])
            print("---- Source snippet (up to 40 lines) ----")
            print(preview.rstrip())
            print("----------------------------------------")
        except Exception as e:
            print(f"Source snippet: <unavailable> ({type(e).__name__}: {e})")
    except Exception as e:
        print(f"Source file: <unavailable> ({type(e).__name__}: {e})")

    return 0


if __name__ == '__main__':
    raise SystemExit(main())
