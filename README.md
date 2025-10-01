# Atheris FuzzSlice

## Quick Start

1. **Build the Docker container**

    ```bash
    make build
    ```

2. **Generate a fuzzer for your target**

    ```bash
    make gen TARGET=urllib.parse:urlparse
    ```

3. **Run the fuzzer**
    ```bash
    make run
    ```

---

## Typical Workflow

1. Choose a Python function, method, or class to fuzz.
2. Add dependencies to `requirements.txt` if needed.
3. Build the fuzzing environment:
    ```bash
    make build
    ```
4. Generate the harness:
    ```bash
    make gen TARGET=your_module:your_function
    ```
5. Run the fuzzer:
    ```bash
    make run
    ```
6. Inspect crashes and review code coverage.
7. Fix issues and repeat.

---

## Examples

### Example 1 — Division by Zero

```bash
make gen TARGET=example_local_function_fuzz_gen:divide
make run
```

**Output (expected crash):**

```
=== Uncaught Python exception: ===
ZeroDivisionError: division by zero
DEBUG ARGS (crash): [42, 0] {}
artifact_prefix='./'; Test unit written to ./crash-abc123
```

### Example 2 — URL Parsing

```bash
make gen TARGET=urllib.parse:urlparse
make run
```

**Output (expected crash):**

```
ValueError: Invalid IPv6 URL
```


---

## Understanding Output

Example fuzzing log:

```
#65536  pulse  cov: 99 ft: 99 corp: 1/1b lim: 652 exec/s: 21845
```

-   **#65536** → Number of test cases executed
-   **cov** → Code coverage (lines hit)
-   **ft** → Feature coverage (branches hit)
-   **corp** → Corpus size (unique seeds)
-   **exec/s** → Executions per second

Crash log example:

```
=== Uncaught Python exception: ===
ZeroDivisionError: division by zero
DEBUG ARGS (crash): [42, 0] {}
artifact_prefix='./'; Test unit written to ./crash-abc123
```

The failing input is saved as a file (`crash-*`) for later replay.

---

## Reproducing Crashes

When a crash occurs, libFuzzer writes the failing input to a file (`./crash-*`).

To replay it:
```
docker run --rm -v /mnt/d/atherisOne:/app atheris-fuzz:latest python3 main_fuzzer.py ./crash-dd
```
replace `./crash-dd` with the actual crash file name. After building the harness

---

## Extra Commands

-   **Open a shell inside the container**:

    ```bash
    make shell
    ```

-   **Clean generated files**:

    ```bash
    make clean
    ```

-   **Generate a custom harness file**:

    ```bash
    python3 make_harness.py your_module:your_function --out custom_fuzzer.py
    ```

-   **Run outside Docker**:
    ```bash
    python3 make_harness.py urllib.parse:urlparse
    python3 main_fuzzer.py
    ```

---

## How It Works

-   **Harness Generator** → Creates a fuzzing harness from your target function.
-   **Type-Aware Generator** → Uses Python type hints to generate smarter test data.
-   **Fuzzer (libFuzzer + Atheris)** → Runs generated inputs and detects crashes.
-   **Containerization** → Ensures reproducibility and isolated dependencies.

### Phases

1. **Generation** → Parse target, validate imports, and create harness file.
2. **Execution** → Load target, generate arguments, call function, and detect crashes.

---

**To Do:**

-   Only supports types implemented in `fuzz_helpers.py`.
-   Complex classes default to string/byte inputs.
-   No persistent corpus (every run starts fresh).

-   Smarter type inference. (maybe mypy)?
-   Might fail for more custom classes?

-   Need to make either:
-   Bug bounty or VSCCode extension.
-   Also need to analyze results to see false positive rate

---

## Project Structure

```
.
├── Dockerfile
├── Makefile
├── make_harness.py
├── fuzz_helpers.py
├── requirements.txt
├── example_local_function_fuzz_gen.py
└── main_fuzzer.py   (auto-generated)
```