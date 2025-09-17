IMAGE_NAME=atheris-fuzz

build:
	docker build -t $(IMAGE_NAME) .

run:
	docker run --rm -v $(PWD):/app $(IMAGE_NAME)

# Optional: build and run in one step
all: build run
