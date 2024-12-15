FROM ubuntu:22.04

# Install essential packages
RUN apt-get update && apt-get install -y \
    gdb \
    build-essential \
    python3 \
    python3-pip \
    python3-venv \
    git \
    vim \
    gcc \
    clang \
    make \
    wget \
    unzip \
    cargo \
    rustc \
    zstd \
    libgmp-dev

# Additional Python packages needed for LMTest
RUN pip3 install \
    recordclass==0.19.1 \
    pyyaml==5.4.1 \
    unicorn==2.0.1.post1 \
    pyelftools==0.29 \
    capstone==5.0.0 \
    pexpect==4.8.0 \
    ruamel.yaml==0.17.32 \
    bitstring==4.0.2 \
    hy==0.27.0 \
    hyrule==0.4.0 \
    iced-x86==1.19.0 \
    rich==13.4.2

# Create a working directory
WORKDIR /work

# Create a non-root user
RUN useradd -m -s /bin/bash dvp
RUN chown -R dvp:dvp /work

# Switch to non-root user
USER dvp

# Create and activate virtual environment
RUN python3 -m venv /work/venv
ENV PATH="/work/venv/bin:$PATH"

# Set default command
CMD ["/bin/bash"]