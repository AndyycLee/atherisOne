#!/usr/bin/env python3
"""
make_harness.py
Generates a harness file named `main_fuzzer.py` for a target specified as:
  module.path:callable

Examples:
  python3 make_harness.py ipaddress:ip_address
  python3 make_harness.py urllib.parse:urlparse
  python3 make_harness.py my_models:User.model_validate
"""
import sys, importlib, inspect, textwrap, os

if len(sys.argv) < 2:
    print(__doc__)
    sys.exit(1)

target = sys.argv[1]
out = "main_fuzzer.py"
# optional --out=filename
for a in sys.argv[2:]:
    if a.startswith("--out="):
        out = a.split("=",1)[1]

if ":" not in target:
    print("Target must be module:callable")
    sys.exit(2)

module_name, callable_path = target.split(":", 1)

# Attempt to import module to give early feedback (not strictly required)
try:
    importlib.import_module(module_name)
except Exception as e:
    print(f"Warning: unable to import module {module_name} in generator (it may be fine inside Docker): {e}")

top_name = callable_path.split(".")[0]

template = f'''#!/usr/bin/env python3
# Auto-generated harness for {module_name}:{callable_path}
import sys, os
sys.path.append(os.path.dirname(__file__))

import atheris, inspect
from typing import get_type_hints

# helper generator
from fuzz_helpers import gen_by_type_hint

# Import top-level symbol and resolve nested attributes at runtime
try:
    from {module_name} import {top_name} as _top_sym
except Exception as e:
    # import might fail on host; will work when the container has packages installed
    _top_sym = None

_target = _top_sym
_rest = "{callable_path[len(top_name):]}".lstrip(".")

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
            module = __import__("{module_name}", fromlist=["*"])
            _temp = getattr(module, "{top_name}")
            rest = "{callable_path[len(top_name):]}".lstrip(".")
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
        hints = {{}}

    args = []
    kwargs = {{}}

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

    print("DEBUG ARGS:", args, kwargs, flush=True)
    try:
        _target(*args, **kwargs)
    except Exception:
        # re-raise unexpected exceptions so Atheris records them
        raise

def main():
    atheris.instrument_all()
    atheris.Setup(sys.argv, TestOneInput)
    atheris.Fuzz()

if __name__ == "__main__":
    main()
'''
with open(out, "w") as f:
    f.write(textwrap.dedent(template))

print(f"Wrote harness to {out}. Run it under Atheris (no corpus for now):")
print("  python3 -m atheris", out)
print("Or build Docker and run: make build && make run")
