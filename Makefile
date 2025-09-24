IMAGE := atheris-fuzz
TAG := latest

.PHONY: build run shell gen clean

build:
	docker build -t $(IMAGE):$(TAG) .

# Generate a harness file named main_fuzzer.py for TARGET=module:callable
# Example: make gen TARGET=ipaddress:ip_address
gen:
	python3 make_harness.py $(TARGET) --out main_fuzzer.py

# Run the fuzzer inside container (no corpus)
run:
	docker run --rm -v $(PWD):/app $(IMAGE):$(TAG)

# Open interactive shell inside container
shell:
	docker run --rm -it -v $(PWD):/app --entrypoint /bin/bash $(IMAGE):$(TAG)

# Remove generated harness (if present)
clean:
	rm -f main_fuzzer.py
