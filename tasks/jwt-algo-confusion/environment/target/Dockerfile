FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt --break-system-packages

RUN mkdir -p /app/keys /shared

COPY app.py /app/app.py
COPY auth.py /app/auth.py
COPY db.json /shared/db.json

# Generate RSA-2048 key pair at build time
RUN python3 - <<'EOF'
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
priv_pem = private_key.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
)
pub_pem = private_key.public_key().public_bytes(
    serialization.Encoding.PEM,
    serialization.PublicFormat.SubjectPublicKeyInfo,
)
with open("/app/keys/private.pem", "wb") as f:
    f.write(priv_pem)
with open("/app/keys/public.pem", "wb") as f:
    f.write(pub_pem)
EOF

RUN chmod 600 /app/keys/private.pem && chmod 644 /app/keys/public.pem

WORKDIR /app

# Entrypoint: start Flask in foreground; delete source files in background after startup.
# Python caches loaded modules in memory, so Flask keeps running after .py files are removed.
RUN printf '#!/bin/bash\n(sleep 10 && rm -rf /app/app.py /app/auth.py /app/keys /app/__pycache__) &\nexec python3 /app/app.py\n' > /entrypoint.sh && chmod +x /entrypoint.sh

ENTRYPOINT ["/entrypoint.sh"]
