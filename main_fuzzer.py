#!/usr/bin/env python3
# Auto-generated harness for httpx._content:encode_content
import sys, os, inspect, atheris
from typing import get_type_hints
from fuzz_helpers import gen_by_type_hint

DEBUG_TRACE = os.environ.get("FUZZ_DEBUG", "0") == "1"

def debug_print(*args, **kwargs):
    if DEBUG_TRACE:
        print("[TRACE]", *args, **kwargs, flush=True)

# === Target import (instrument imports so coverage includes the target and its deps) ===
debug_print("=== INITIALIZING HARNESS ===")
try:
    with atheris.instrument_imports():
        module = __import__("httpx._content", fromlist=["*"])
        target = module
        for part in "encode_content".split("."):
            target = getattr(target, part)
    debug_print(f"Target resolved successfully: {target}")
except Exception as e:
    print(f"Failed to import target httpx._content:encode_content - {e}", flush=True)
    sys.exit(3)

# === Fuzz entrypoint ===
def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)
    debug_print("TestOneInput called")

    try:
        sig = inspect.signature(target)
        hints = get_type_hints(target)
    except Exception:
        sig, hints = None, {}

    # No parameters → call with raw bytes
    if not sig or not sig.parameters:
        try:
            target(data)
        except Exception as e:
            print(f"Crash: {type(e).__name__} - {e}", flush=True)
            raise
        return

    # Generate args
    args, kwargs = [], {}
    for pname, p in sig.parameters.items():
        if p.kind in (inspect.Parameter.VAR_POSITIONAL, inspect.Parameter.VAR_KEYWORD):
            continue
        hint = hints.get(pname, p.annotation if p.annotation is not inspect._empty else None)
        try:
            val = gen_by_type_hint(fdp, hint)
        except Exception:
            val = None
        if p.kind in (inspect.Parameter.POSITIONAL_ONLY, inspect.Parameter.POSITIONAL_OR_KEYWORD):
            args.append(val)
        else:
            kwargs[pname] = val

    try:
        target(*args, **kwargs)
    except Exception as e:
        print("\n=== CRASH DETECTED ===", flush=True)
        print(f"Target: httpx._content:encode_content", flush=True)
        print(f"Args: {args}", flush=True)
        print(f"Kwargs: {kwargs}", flush=True)
        print(f"Exception: {type(e).__name__}: {e}", flush=True)
        print("======================\n", flush=True)
        raise

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
