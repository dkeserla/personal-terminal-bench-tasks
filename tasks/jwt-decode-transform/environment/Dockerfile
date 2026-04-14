FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    && rm -rf /var/lib/apt/lists/*

RUN pip3 install PyJWT==2.8.0 cryptography==42.0.5 --break-system-packages

RUN mkdir -p /app/tokens

COPY data/generate_tokens.py /tmp/generate_tokens.py
RUN python3 /tmp/generate_tokens.py

RUN chmod 444 /app/tokens/token_a.txt /app/tokens/token_b.txt /app/tokens/token_c.txt

WORKDIR /app

CMD ["sleep", "infinity"]
