#!/usr/bin/env python3
"""
add_types_repo_pyre.py — Best-effort bulk annotation using Pyre + LibCST.

Strategy:
- For each Python file, ask Pyre for `types_in_file(path)` (JSON) and map spans → types.
- Parse the file with LibCST and collect, per function:
  - Parameters lacking annotations → find first usage in body and adopt that type.
  - Return type (if missing) → infer from return value expressions' types and unify.
- Apply annotations in-place, writing string-literal annotations ("...") to avoid
  import/runtime issues.

Requirements:
  - pyre-check installed and a .pyre_configuration at repo root (run `pyre init`).
  - libcst installed: `pip install libcst`.
  - Pyre server available (script will invoke `pyre query` and can auto-start).

Usage:
    # Query+codemod mode (default, safe best-effort)
    python3 add_types_repo_pyre.py --root . --jobs 8 [--include-tests] [--dry-run]
  
    # Infer mode (opt-in): let Pyre annotate in-place from existing stubs
    python3 add_types_repo_pyre.py --root . --mode infer [--use-existing-stubs] [--pyre-binary pyre]

Notes:
  - This is best-effort. It skips *args/**kwargs and leaves existing annotations.
  - It quotes annotations as strings (PEP 563 style) to avoid import problems.
  - If multiple return types are found, it writes a Union[...] when small, else Any.
"""
from __future__ import annotations

import argparse
import json
import os
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Dict, Iterable, List, Optional, Sequence, Tuple

import libcst as cst
from libcst import CSTNode
from libcst.metadata import PositionProvider, MetadataWrapper


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


@dataclass
class Span:
    start_line: int
    start_col: int
    end_line: int
    end_col: int

    def contains(self, line: int, col: int) -> bool:
        if (line < self.start_line) or (line > self.end_line):
            return False
        if line == self.start_line and col < self.start_col:
            return False
        if line == self.end_line and col > self.end_col:
            return False
        return True

    def size(self) -> Tuple[int, int]:
        return (self.end_line - self.start_line, self.end_col - self.start_col)


def pyre_types_in_file(pyre_bin: str, root: Path, file_path: Path) -> List[Tuple[Span, str]]:
    """Return list of (span, annotation) from Pyre for the file."""
    try:
        cmd = [pyre_bin, "query", "types_in_file(\"%s\")" % str(file_path), "--output=json"]
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True)
        if proc.returncode != 0:
            # Pyre may print useful info on stderr
            return []
        data = json.loads(proc.stdout)
        # Expected: { "response": [ {"location": {"path":..., "start": {"line":..,"column":..}, "stop": {...}}, "annotation": "..." }, ...] }
        raw = data.get("response") or data
        results: List[Tuple[Span, str]] = []
        for item in raw:
            loc = item.get("location") or {}
            start = loc.get("start") or {}
            stop = loc.get("stop") or {}
            span = Span(
                start_line=int(start.get("line", 0)),
                start_col=int(start.get("column", 0)),
                end_line=int(stop.get("line", 0)),
                end_col=int(stop.get("column", 0)),
            )
            ann = item.get("annotation") or "typing.Any"
            results.append((span, ann))
        return results
    except Exception:
        return []


def make_type_index(spans: List[Tuple[Span, str]]):
    """Create a callable that returns the most specific annotation covering (line,col)."""
    # Prefer smallest covering span.
    def find(line: int, col: int) -> Optional[str]:
        best: Optional[Tuple[Span, str]] = None
        for span, ann in spans:
            if span.contains(line, col):
                if best is None:
                    best = (span, ann)
                else:
                    # choose the more specific (smaller) span
                    bl, bc = best[0].size()
                    sl, sc = span.size()
                    if (sl, sc) < (bl, bc):
                        best = (span, ann)
        return best[1] if best else None
    return find


def is_good_type(ann: Optional[str]) -> bool:
    if not ann:
        return False
    lower = ann.lower()
    if lower in {"typing.any", "any", "unknown", "typing.unknown"}:
        return False
    return True


def unify_types(types: Sequence[str]) -> str:
    uniq = []
    seen = set()
    for t in types:
        if t not in seen:
            uniq.append(t)
            seen.add(t)
    if not uniq:
        return "typing.Any"
    if len(uniq) == 1:
        return uniq[0]
    if len(uniq) <= 4:
        inner = ", ".join(uniq)
        return f"typing.Union[{inner}]"
    return "typing.Any"


class _FuncUsageCollector(cst.CSTVisitor):
    METADATA_DEPENDENCIES = (PositionProvider,)

    def __init__(self, fn: cst.FunctionDef):
        self.fn = fn
        self.param_names = {p.name.value for p in fn.params.params}
        self.kwonly_names = {p.name.value for p in fn.params.kwonly_params}
        if fn.params.vararg:
            self.param_names.add(fn.params.vararg.name.value)
        if fn.params.kwarg:
            self.param_names.add(fn.params.kwarg.name.value)
        self.usages: Dict[str, List[Tuple[int, int]]] = {}
        self.return_positions: List[Tuple[int, int]] = []

    def visit_Return(self, node: cst.Return) -> None:
        if node.value is None:
            return
        pos = self.get_metadata(PositionProvider, node.value).start
        self.return_positions.append((pos.line, pos.column))

    def visit_Name(self, node: cst.Name) -> None:
        name = node.value
        # Skip the function name itself and attribute quals; only count names inside body
        if name in self.param_names or name in self.kwonly_names:
            pos = self.get_metadata(PositionProvider, node).start
            # Exclude the parameter declaration site by requiring position > def header
            def_pos_end = self.get_metadata(PositionProvider, self.fn).end
            if (pos.line, pos.column) <= (def_pos_end.line, def_pos_end.column):
                return
            self.usages.setdefault(name, []).append((pos.line, pos.column))


def annotate_file_with_pyre(pyre_bin: str, root: Path, path: Path, dry_run: bool) -> Tuple[Path, bool, str]:
    code = path.read_text(encoding="utf-8")
    try:
        mod = cst.parse_module(code)
    except Exception as e:
        return (path, False, f"parse error: {e}")

    wrapper = MetadataWrapper(mod)
    spans = pyre_types_in_file(pyre_bin, root, path)
    idx = make_type_index(spans)

    # Precompute decisions per function
    decisions: Dict[Tuple[int, int], Dict[str, Optional[str]]] = {}
    # key = function start position, value dict: {"return": type_str or None, param_name->type_str}

    fn_nodes: List[cst.FunctionDef] = []
    for fn in wrapper.tree.body:
        # Also handle nested functions via a walk
        pass

    class Gather(cst.CSTVisitor):
        METADATA_DEPENDENCIES = (PositionProvider,)

        def visit_FunctionDef(self, node: cst.FunctionDef) -> None:
            fn_nodes.append(node)

    wrapper.visit(Gather())

    for fn in fn_nodes:
        collector = _FuncUsageCollector(fn)
        MetadataWrapper(fn).visit(collector)  # local wrapper for metadata

        # Determine return type
        ret_types: List[str] = []
        for (line, col) in collector.return_positions:
            t = idx(line, col)
            if is_good_type(t):
                ret_types.append(t)  # type: ignore[arg-type]
        ret_ann = unify_types(ret_types) if ret_types else None

        # Determine param types
        param_types: Dict[str, str] = {}
        all_params: List[cst.Param] = list(fn.params.params) + list(fn.params.kwonly_params)
        if fn.params.vararg:
            all_params.append(fn.params.vararg)
        if fn.params.kwarg:
            all_params.append(fn.params.kwarg)

        for p in all_params:
            pname = p.name.value
            if p.annotation is not None:
                continue  # keep existing
            uses = collector.usages.get(pname) or []
            cand: Optional[str] = None
            for (line, col) in uses:
                t = idx(line, col)
                if is_good_type(t):
                    cand = t  # type: ignore[assignment]
                    break
            if cand:
                param_types[pname] = cand

        if ret_ann or param_types:
            pos = wrapper.resolve(PositionProvider)[fn].start
            decisions[(pos.line, pos.column)] = {"return": ret_ann, **param_types}

    if not decisions:
        return (path, True, "no-op")

    class Apply(cst.CSTTransformer):
        METADATA_DEPENDENCIES = (PositionProvider,)

        def leave_FunctionDef(self, original_node: cst.FunctionDef, updated_node: cst.FunctionDef) -> CSTNode:
            pos = self.get_metadata(PositionProvider, original_node).start
            dec = decisions.get((pos.line, pos.column))
            if not dec:
                return updated_node

            # Return annotation
            new_returns = updated_node.returns
            rtype = dec.get("return")
            if rtype and updated_node.returns is None:
                new_returns = cst.Annotation(cst.SimpleString(f'"{rtype}"'))

            # Parameter annotations
            def annotate_param(p: cst.Param) -> cst.Param:
                if p.annotation is not None:
                    return p
                t = dec.get(p.name.value)
                if not t:
                    return p
                return p.with_changes(annotation=cst.Annotation(cst.SimpleString(f'"{t}"')))

            new_params = updated_node.params
            new_params = new_params.with_changes(
                params=[annotate_param(p) for p in new_params.params],
                kwonly_params=[annotate_param(p) for p in new_params.kwonly_params],
                vararg=annotate_param(new_params.vararg) if new_params.vararg else None,
                kwarg=annotate_param(new_params.kwarg) if new_params.kwarg else None,
            )

            return updated_node.with_changes(params=new_params, returns=new_returns)

    new_mod = wrapper.visit(Apply())
    if dry_run:
        return (path, True, "dry-run")
    path.write_text(new_mod.code, encoding="utf-8")
    return (path, True, "ok")


def run_pyre_infer(pyre_bin: str, root: Path, use_existing_stubs: bool) -> Tuple[bool, str]:
    """Run 'pyre infer' once at the project level, optionally using existing stubs.
    This lets Pyre write annotations in-place. Returns (success, message)."""
    cmd = [pyre_bin, "infer", "-i"]  # in-place
    if use_existing_stubs:
        cmd.append("--annotate-from-existing-stubs")
    try:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True)
        if proc.returncode == 0:
            return True, (proc.stdout.strip() or "pyre infer completed")
        else:
            # include some stderr for diagnostics
            return False, (proc.stderr.strip() or proc.stdout.strip() or "pyre infer failed")
    except FileNotFoundError:
        return False, "pyre not found. Install: pip install pyre-check and ensure 'pyre' on PATH"
    except Exception as e:
        return False, f"Exception: {type(e).__name__}: {e}"


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--root", default=".")
    ap.add_argument("--include-tests", action="store_true")
    ap.add_argument("--jobs", type=int, default=max(1, os.cpu_count() or 1))
    ap.add_argument("--dry-run", action="store_true")
    ap.add_argument("--pyre-binary", default="pyre")
    ap.add_argument("--mode", choices=["query", "infer"], default="query", help="Query+codemod (default) or run 'pyre infer' in-place")
    ap.add_argument("--use-existing-stubs", action="store_true", help="With --mode infer, also pass --annotate-from-existing-stubs")
    args = ap.parse_args()

    root = Path(args.root).resolve()
    if args.mode == "infer":
        ok, msg = run_pyre_infer(args.pyre_binary, root, args.use_existing_stubs)
        print(("Success: " if ok else "Failure: ") + msg)
        return 0 if ok else 1

    # default: query mode
    files = discover_python_files(root, include_tests=args.include_tests)
    if not files:
        print("No Python files discovered.")
        return 0

    # Simple sequential processing keeps Pyre server load modest; adjust to your scale
    ok = 0
    changed = 0
    failures: List[Tuple[Path, str]] = []
    for f in files:
        path, success, msg = annotate_file_with_pyre(args.pyre_binary, root, f, args.dry_run)
        if success:
            ok += 1
            if msg not in {"no-op", "dry-run"}:
                changed += 1
        else:
            failures.append((path, msg))

    print(f"Pyre annotate success: {ok}/{len(files)} files; changed: {changed}")
    if failures:
        print(f"Failures ({len(failures)}):")
        for p, m in failures[:50]:
            print(f"  - {p}: {m}")
        if len(failures) > 50:
            print(f"  ... and {len(failures)-50} more")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
