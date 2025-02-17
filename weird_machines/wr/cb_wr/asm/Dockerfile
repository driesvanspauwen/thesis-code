FROM ubuntu:22.04

# Install required packages
RUN apt-get update && apt-get install -y \
    nasm \
    gcc \
    make \
    binutils \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

# Install unicorn for later testing
RUN pip3 install unicorn

WORKDIR /code

# Copy our assembly files and Makefile
COPY cache_reg.asm test.asm Makefile ./

# Default command - build and run tests
CMD ["make", "test"]