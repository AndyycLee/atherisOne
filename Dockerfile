FROM python:3.10-slim

# Install build tools and python dev headers ( cuz of atheris)
RUN apt-get update && \
    apt-get install -y build-essential python3-dev && \
    rm -rf /var/lib/apt/lists/*

# Set working directory
WORKDIR /app

# Copy your source code (adjust as needed)
COPY . /app

# Install atheris
RUN pip install --upgrade pip && pip install atheris

# Default command: run the example fuzzing script
CMD [ "python3", "example_fuzz.py" ]
