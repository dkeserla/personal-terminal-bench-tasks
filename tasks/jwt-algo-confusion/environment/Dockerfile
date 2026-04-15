FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

# Install PyJWT and cryptography so agents can inspect/decode JWT tokens
RUN pip3 install pyjwt cryptography --break-system-packages

WORKDIR /workspace
