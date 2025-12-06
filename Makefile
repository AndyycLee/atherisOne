IMAGE := atheris-fuzz
TAG := latest

.PHONY: build run run-debug shell gen clean clone clone-src update-src type-src fuzz-src show-types-src tidy

build:
	docker build -t $(IMAGE):$(TAG) .

# Generate a harness file named main_fuzzer.py for TARGET=module:callable
# Example: make gen TARGET=ipaddress:ip_address
gen:
	python3 make_harness.py $(TARGET) --out main_fuzzer.py

# May add more optiosn liek pytype in future

# Run the fuzzer inside container
run:
	docker run --rm -v $(PWD):/app $(IMAGE):$(TAG)

# Run the fuzzer with debug tracing enabled
run-debug:
	docker run --rm -v $(PWD):/app -e FUZZ_DEBUG=1 $(IMAGE):$(TAG)

# Open interactive shell inside container
shell:
	docker run --rm -it -v $(PWD):/app --entrypoint /bin/bash $(IMAGE):$(TAG)

# Remove generated harness (if present)
clean:
	rm -f main_fuzzer.py

# (Removed) Pyre/Pyre-infer targets have been deprecated; use pyrefly-only flows

# One-shot: install a package and fuzz a single target (local venv by default)
slice:
	python3 slice_and_fuzz.py --package $(PKG) --target $(TARGET) --max-time $(TIME)

# Defaults for source-clone mode
SRC_DIR ?= work/src
SRC ?= $(SRC_DIR)/repo
ANNOTATE ?= pyrefly
TIME ?= 20
RUNS ?=
DEBUG ?=

# Clone a repository into SRC (e.g., make clone REPO_URL=https://github.com/psf/requests.git SRC=work/requests)
clone:
	git clone --depth 1 $(REPO_URL) $(SRC)

# Clone into standardized layout: work/src/$(NAME)
# Example: make clone-src REPO_URL=https://github.com/psf/requests.git NAME=requests
clone-src:
	python3 -c "import os,sys; os.makedirs(sys.argv[1], exist_ok=True)" $(SRC_DIR)
	bash -lc 'set -e; \
		DEST="$(SRC_DIR)/$(NAME)"; \
		TEMP="$(SRC_DIR)/.tmp_$(NAME)_$$$$"; \
		trap "rm -rf \"$$TEMP\"" EXIT; \
		if [ -n "$(FORCE)" ] && [ -e "$$DEST" ]; then \
			echo "[clone-src] Removing existing $$DEST (FORCE=1)"; \
			rm -rf "$$DEST" || rmdir "$$DEST" || true; \
		fi; \
		if [ -d "$$DEST/.git" ]; then \
			echo "[clone-src] $$DEST already exists (git repo). Skipping clone."; \
			exit 0; \
		fi; \
		if [ -e "$$DEST" ]; then \
			echo "[clone-src] $$DEST exists but is not a git repo. Use FORCE=1 to replace."; \
			exit 2; \
		fi; \
		git clone --depth 1 "$(REPO_URL)" "$$TEMP"; \
		rmdir "$$DEST" 2>/dev/null || true; \
		mv "$$TEMP" "$$DEST"'
# Update an existing cloned repo (fast-forward only)
# Example: make update-src NAME=markdown
update-src:
	bash -lc 'set -e; \
		DEST="$(SRC_DIR)/$(NAME)"; \
		if [ ! -d "$$DEST/.git" ]; then echo "[update-src] $$DEST is not a git repo. Run clone-src first."; exit 2; fi; \
		git -C "$$DEST" pull --ff-only || true'

# Type a cloned source directory with pyrefly (only)
# Example: make type-src SRC=work/src/requests
type-src:
	docker run --rm -v $(PWD):/app -v $(abspath $(SRC)):/repo $(IMAGE):$(TAG) bash -lc 'set -e; \
		pip install -e /repo; pip install pyrefly; pyrefly infer /repo; \
		python3 /app/tools/fix_future_imports.py /repo'

# Fuzz a target from the cloned source: make fuzz-src SRC=work/requests TARGET=requests:get TIME=20 DEBUG=1
fuzz-src:
	docker run --rm -v $(PWD):/app -v $(abspath $(SRC)):/repo -e FUZZ_DEBUG=$(DEBUG) $(IMAGE):$(TAG) bash -lc 'set -e; \
		export PYTHONPATH=/repo:/repo/lib:$$PYTHONPATH; \
		pip install -e /repo; \
		python3 /app/make_harness.py $(TARGET) --out /app/main_fuzzer.py; \
		FUZZ_ARGS="-max_total_time=$(TIME)"; if [ -n "$(RUNS)" ]; then FUZZ_ARGS="$$FUZZ_ARGS -runs=$(RUNS)"; fi; \
		python3 /app/main_fuzzer.py $$FUZZ_ARGS'

# Show signature and type hints for a target in the cloned source
show-types-src:
	docker run --rm -v $(PWD):/app -v $(abspath $(SRC)):/repo $(IMAGE):$(TAG) bash -lc 'set -e; \
		export PYTHONPATH=/repo:/repo/lib:$$PYTHONPATH; \
		pip install -e /repo; \
		python3 /app/show_target_signature.py $(TARGET)'

# Tidy repo: remove caches and deprecated files
tidy:
	python3 tools/tidy.py
