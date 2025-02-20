FROM ubuntu:latest
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    git \
    vim \
    wget \
    curl \
    gdb
WORKDIR /code