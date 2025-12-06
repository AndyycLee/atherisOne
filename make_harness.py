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
for a in sys.argv[2:]:
    if a.startswith("--out="):
        out = a.split("=", 1)[1]

if ":" not in target:
    print("Target must be module:callable")
    sys.exit(2)

module_name, callable_path = target.split(":", 1)
top_name = callable_path.split(".")[0]

template = f'''#!/usr/bin/env python3
# Auto-generated harness for {module_name}:{callable_path}
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
        module = __import__("{module_name}", fromlist=["*"])
        target = module
        for part in "{callable_path}".split("."):
            target = getattr(target, part)
    debug_print(f"Target resolved successfully: {{target}}")
except Exception as e:
    print(f"Failed to import target {module_name}:{callable_path} - {{e}}", flush=True)
    sys.exit(3)

# === Fuzz entrypoint ===
def TestOneInput(data: bytes):
    fdp = atheris.FuzzedDataProvider(data)
    debug_print("TestOneInput called")

    try:
        sig = inspect.signature(target)
        hints = get_type_hints(target)
    except Exception:
        sig, hints = None, {{}}

    # No parameters → call with raw bytes
    if not sig or not sig.parameters:
        try:
            target(data)
        except Exception as e:
            print(f"Crash: {{type(e).__name__}} - {{e}}", flush=True)
            raise
        return

    # Generate args
    args, kwargs = [], {{}}
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
        print("\\n=== CRASH DETECTED ===", flush=True)
        print(f"Target: {module_name}:{callable_path}", flush=True)
        print(f"Args: {{args}}", flush=True)
        print(f"Kwargs: {{kwargs}}", flush=True)
        print(f"Exception: {{type(e).__name__}}: {{e}}", flush=True)
        print("======================\\n", flush=True)
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

print(f"Wrote harness to {out}")
print(f"Run with: python3 -m atheris {out}")
