ATHERIS FUZZING HARNESS GENERATOR
==================================

OVERVIEW
--------
This is an automated fuzzing framework that generates Python fuzzing harnesses for any callable target using Google's Atheris fuzzer. The system can automatically create type-aware fuzz tests for Python functions, methods, or classes by analyzing their signatures and type hints.

QUICK START
-----------

1. BUILD THE CONTAINER:
   make build

2. GENERATE A FUZZER FOR A TARGET:
   make gen TARGET=urllib.parse:urlparse

3. RUN THE FUZZER:
   make run

That's it! The fuzzer will start generating random inputs and testing your target function.

DETAILED USAGE
--------------

STEP 1: PREPARE YOUR ENVIRONMENT
- If fuzzing third-party packages, add them to requirements.txt before building
- Example: Add "pydantic" to fuzz Pydantic models

STEP 2: BUILD THE DOCKER CONTAINER
  make build
  
This creates a Docker image with Python 3.10, Atheris fuzzer, and your dependencies.

STEP 3: GENERATE A FUZZING HARNESS
Basic syntax:
  make gen TARGET=module:function

Examples:
  make gen TARGET=ipaddress:ip_address          # Fuzz IP address parsing
  make gen TARGET=urllib.parse:urlparse         # Fuzz URL parsing  
  make gen TARGET=json:loads                    # Fuzz JSON parsing
  make gen TARGET=example_local_function_fuzz_gen:divide  # Fuzz local function

For class methods:
  make gen TARGET=my_models:User.model_validate

This creates main_fuzzer.py - the generated fuzzing harness.

STEP 4: RUN THE FUZZER
  make run

This executes the fuzzer inside Docker. You'll see output like:
  INFO: Instrumenting 2197 functions...
  INFO: Running with entropic power schedule
  #65536 pulse cov: 99 ft: 99 corp: 1/1b lim: 652 exec/s: 21845

When bugs are found, you'll see:
  === Uncaught Python exception: ===
  ZeroDivisionError: division by zero

ADDITIONAL COMMANDS:

Interactive debugging:
  make shell                    # Open bash shell in container
  
Clean up generated files:
  make clean                    # Remove main_fuzzer.py

Custom output file:
  python3 make_harness.py TARGET --out=custom_fuzzer.py

Run without Docker:
  python3 make_harness.py urllib.parse:urlparse
  python3 main_fuzzer.py

REAL EXAMPLES WITH EXPECTED RESULTS
-----------------------------------

EXAMPLE 1: Division by Zero Bug
  make gen TARGET=example_local_function_fuzz_gen:divide
  make run
  
Expected result:
  ZeroDivisionError: division by zero
  
This demonstrates finding a classic bug - the fuzzer generates b=0 which crashes divide(a,b).

EXAMPLE 2: URL Parsing Edge Cases  
  make gen TARGET=urllib.parse:urlparse
  make run
  
Expected result:
  ValueError: Invalid IPv6 URL
  
The fuzzer finds malformed URLs that crash the parser.

EXAMPLE 3: JSON Parsing (Manual Harness)
  python3 example_fuzz.py
  
This uses a hand-written harness to fuzz json.loads() with random byte strings.

UNDERSTANDING THE OUTPUT
------------------------

NORMAL FUZZING OUTPUT:
  #65536 pulse cov: 99 ft: 99 corp: 1/1b lim: 652 exec/s: 21845
  
  - #65536: Number of test cases run
  - cov: 99: Code coverage (lines hit)  
  - ft: 99: Feature coverage (branches hit)
  - corp: 1/1b: Corpus size (interesting inputs saved)
  - exec/s: Executions per second

BUG FOUND OUTPUT:
  === Uncaught Python exception: ===
  ZeroDivisionError: division by zero
  Traceback (most recent call last):
  ...
  artifact_prefix='./'; Test unit written to ./crash-abc123
  
The crash is saved to a file for later analysis.

DEBUG OUTPUT:
  DEBUG ARGS: [1, 0] {}
  
Shows the generated arguments that caused the crash (helpful for understanding the bug).

CORE COMPONENTS
--------------

1. HARNESS GENERATOR (make_harness.py)
   - Main entry point that generates fuzzing harnesses
   - Takes a target specification: "module.path:callable"
   - Creates a complete Atheris-compatible fuzzer file
   - Handles nested attribute resolution (e.g., "my_models:User.model_validate")
   - Provides early import validation with graceful fallbacks

2. TYPE-AWARE VALUE GENERATOR (fuzz_helpers.py)
   - Intelligent data generation based on Python type hints
   - Supports primitive types: int, float, bool, str, bytes
   - Handles complex types: List, Tuple, Dict, Union
   - Provides configurable limits (string length, list size)
   - Falls back to string generation for unknown types

3. GENERATED FUZZER (main_fuzzer.py - example output)
   - Auto-generated harness for specific targets
   - Uses runtime introspection to analyze target signatures
   - Generates appropriate arguments based on parameter types
   - Includes debug output for argument inspection
   - Handles import failures gracefully (useful in containerized environments)

4. CONTAINERIZATION (Dockerfile)
   - Python 3.10 base with build tools for native extensions
   - Installs Atheris and common dependencies
   - Non-root execution for security
   - Optimized Docker layer caching

HOW IT WORKS
------------

GENERATION PHASE:
1. Parse target specification (module:callable format)
2. Attempt early import validation (warns if fails)
3. Generate harness template with target resolution logic
4. Write complete fuzzer to output file

EXECUTION PHASE:
1. Import target function/method/class
2. Use Python's inspect module to get signature and type hints
3. For each parameter:
   - Determine type from hints or annotations
   - Generate appropriate test data using fuzz_helpers
   - Handle positional vs keyword arguments
4. Call target with generated arguments
5. Let Atheris handle crash detection and corpus management

TYPE GENERATION STRATEGY:
- Primitive types: Generate within reasonable bounds
- Collections: Recursive generation with size limits
- Unions: Randomly select one type from the union
- Unknown types: Fallback to string generation
- Complex nesting: Handles List[Dict[str, int]] etc.

RUNTIME TARGET RESOLUTION:
- Handles cases where imports fail during generation
- Resolves nested attributes at runtime (Class.method)
- Graceful degradation if target cannot be resolved

TYPICAL WORKFLOW
---------------
1. Identify Python function/method to fuzz
2. Add any required dependencies to requirements.txt
3. Run make build to create fuzzing environment
4. Run make gen TARGET=module:function to create harness
5. Run make run to start fuzzing
6. Analyze crashes and coverage reports from Atheris
7. Fix bugs found and repeat

TROUBLESHOOTING
--------------

"Module not found" during generation:
- This is usually fine - the module will be available in Docker
- Add missing packages to requirements.txt and rebuild

"Target cannot be resolved" at runtime:
- Check that the module:function specification is correct
- Ensure the target is importable in the Docker environment

Fuzzer finds no bugs:
- Try fuzzing for longer (Ctrl+C to stop)
- The function may be well-tested already
- Consider fuzzing edge cases or complex inputs

Low execution speed:
- Normal for complex functions
- Simpler functions fuzz faster
- Check if debug output is slowing things down

ARCHITECTURE BENEFITS
--------------------

1. AUTOMATIC HARNESS GENERATION
   - No manual fuzzer writing required
   - Type-aware argument generation
   - Handles complex signatures automatically

2. FLEXIBLE TARGET SPECIFICATION
   - Support for nested attributes
   - Runtime resolution for import issues
   - Works with functions, methods, and classes

3. ROBUST ERROR HANDLING
   - Graceful import failure handling
   - Runtime target resolution fallbacks
   - Debug output for troubleshooting

4. CONTAINERIZED EXECUTION
   - Consistent environment across systems
   - Proper dependency management
   - Security through non-root execution

5. EXTENSIBLE TYPE SYSTEM
   - Easy to add new type generators
   - Configurable generation parameters
   - Handles both typing module and built-in types

LIMITATIONS & FUTURE IMPROVEMENTS
--------------------------------

CURRENT LIMITATIONS:
- Limited to types defined in fuzz_helpers.py
- No support for complex custom classes (falls back to strings)
- Fixed generation limits (can be adjusted in fuzz_helpers.py)
- Requires Python 3.10+ for full type hint support
- No corpus management (starts fresh each time)

PLANNED IMPROVEMENTS:
- Better type inference from defaults and static analysis
- Corpus persistence between runs
- More sophisticated error handling (ignore expected exceptions)
- Support for more complex type hints
- Integration with mypy for better type information

The system is designed to make Python fuzzing accessible by automating the tedious parts of harness creation while providing intelligent, type-aware test data generation.
