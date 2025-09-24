# Dockerfile
FROM python:3.10-slim

ENV DEBIAN_FRONTEND=noninteractive
ENV PYTHONUNBUFFERED=1

# System packages - good general coverage for Python packages & Atheris
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
      build-essential \
      clang \
      llvm \
      libclang-dev \
      python3-dev \
      git \
      ca-certificates \
      curl \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Copy requirements first to take advantage of Docker cache
COPY requirements.txt /app/requirements.txt

# Install Python deps (edit requirements.txt before build if you want extra packages)
RUN pip install --upgrade pip setuptools wheel && \
    pip install -r /app/requirements.txt

# Copy project files (my harness generator, helpers, and code to fuzz)
COPY . /app

# Create a non-root user and switch to it
RUN useradd --create-home --home-dir /home/fuzzer fuzzer && chown -R fuzzer:fuzzer /app
USER fuzzer

# Default command runs generated harness (you can override in `docker run`)
CMD ["python3", "main_fuzzer.py"]
