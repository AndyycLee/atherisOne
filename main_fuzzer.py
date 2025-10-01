#!/usr/bin/env python3
# Auto-generated harness for example_local_function_fuzz_gen:divide
import sys, os
sys.path.append(os.path.dirname(__file__))

import atheris, inspect
from typing import get_type_hints

# helper generator
from fuzz_helpers import gen_by_type_hint

# Import top-level symbol and resolve nested attributes at runtime
try:
    from example_local_function_fuzz_gen import divide as _top_sym
except Exception as e:
    # import might fail on host; will work when the container has packages installed
    _top_sym = None

_target = _top_sym
_rest = "".lstrip(".")

if _top_sym is not None and _rest:
    try:
        for part in _rest.split("."):
            _target = getattr(_target, part)
    except Exception:
        pass

def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)

    # if _target wasn't importable at generation time, try to import/rescue now
    global _target
    if _target is None:
        try:
            module = __import__("example_local_function_fuzz_gen", fromlist=["*"])
            _temp = getattr(module, "divide")
            rest = "".lstrip(".")
            if rest:
                for part in rest.split("."):
                    _temp = getattr(_temp, part)
            _target = _temp
        except Exception:
            # cannot resolve target; consume bytes and return
            _ = fdp.ConsumeRemainingBytes()
            return

    try:
        sig = inspect.signature(_target)
        hints = get_type_hints(_target)
    except Exception:
        sig = None
        hints = {}

    args = []
    kwargs = {}

    if sig is None or len(sig.parameters) == 0:
        # call with raw bytes if no params
        try:
            _target(fdp.ConsumeRemainingBytes())
        except Exception:
            raise
        return

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
        _target(*args, **kwargs)
    except Exception:
        # Print debug info only when there's an actual crash
        print("DEBUG ARGS (crash):", args, kwargs, flush=True)
        # re-raise unexpected exceptions so Atheris records them
        raise

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
