# Base image
FROM ubuntu:latest

# Update and install required tools
RUN apt-get update && apt-get install -y \
    bash \
    coreutils \
    curl \
    vim \
    && rm -rf /var/lib/apt/lists/*

# Set a working directory
WORKDIR /sandbox

# Default command (keep the container alive)
CMD ["bash"]
