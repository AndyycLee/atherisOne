#!/usr/bin/env python3
"""
add_types.py - PyType integration for adding types to untyped functions.

Usage: python3 add_types.py module:function
"""
import sys
import os
import importlib
import inspect
import subprocess
from typing import get_type_hints


def has_types(module_name, callable_path):
    """Check if function has type annotations."""
    try:
        module = importlib.import_module(module_name)
        func = module
        for part in callable_path.split("."):
            func = getattr(func, part)
        
        sig = inspect.signature(func)
        hints = get_type_hints(func)
        
        has_param_types = any(
            p.annotation != inspect.Parameter.empty 
            for p in sig.parameters.values()
        )
        
        return has_param_types or bool(hints)
    except Exception:
        return False


def run_pytype(module_name):
    """Run PyType to infer and apply types."""
    print(f"Running PyType on {module_name}...")
    
    # Get the source file path
    try:
        module = importlib.import_module(module_name)
        source_file = inspect.getsourcefile(module)
        if not source_file:
            print(f"Could not find source file for {module_name}")
            return False
    except Exception as e:
        print(f" Could not import {module_name}: {e}")
        return False
    
    # Run pytype to generate .pyi file
    print(f"Analyzing {source_file}...")
    
    # Use the same Python executable that's running this script
    python_exe = sys.executable
    
    result = subprocess.run(
        [python_exe, "-m", "pytype", source_file],
        capture_output=True,
        text=True
    )
    
    if result.returncode != 0:
        print(f" PyType analysis completed with warnings:\n{result.stderr}")
    
    # The .pyi file is in .pytype/pyi/module_name.pyi
    pyi_file = f".pytype/pyi/{module_name}.pyi"
    
    if not os.path.exists(pyi_file):
        print(f"No .pyi file generated at {pyi_file}")
        return False
    
    # Show the inferred types
    print("\nInferred types (.pyi file):")
    print("-" * 60)
    with open(pyi_file, "r") as f:
        print(f.read())
    print("-" * 60)
    
    # Merge types into source file using merge-pyi
    print(f"\nMerging types into {source_file}...")
    merge_result = subprocess.run(
        ["merge-pyi", "-i", source_file, pyi_file],
        capture_output=True,
        text=True
    )
    
    if merge_result.returncode == 0:
        print(f" Types applied to {source_file}")
        if merge_result.stdout:
            print(f"Output: {merge_result.stdout}")
        if merge_result.stderr:
            print(f"Warnings: {merge_result.stderr}")
        
        # Show what changed
        print("\nUpdated file:")
        print("-" * 60)
        with open(source_file, "r") as f:
            print(f.read())
        print("-" * 60)
        return True
    else:
        print(f" Failed to merge types: {merge_result.stderr}")
        return False


def main():
    if len(sys.argv) < 2:
        print("Usage: python3 add_types.py module:function")
        sys.exit(1)
    
    target = sys.argv[1]
    if ":" not in target:
        print("Error: Target must be module:function")
        sys.exit(1)
    
    module_name, callable_path = target.split(":", 1)
    
    if has_types(module_name, callable_path):
        print(f"✓ {module_name}:{callable_path} already has types, skipping")
    else:
        run_pytype(module_name)


if __name__ == "__main__":
    main()
