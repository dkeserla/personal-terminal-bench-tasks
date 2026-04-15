FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    python3 \
    python3-pip \
    curl \
    openssl \
    && rm -rf /var/lib/apt/lists/*

COPY data/requirements.txt /tmp/requirements.txt
RUN pip3 install -r /tmp/requirements.txt --break-system-packages

RUN mkdir -p /app/keys /logs/verifier

COPY data/app.py /app/app.py
COPY data/auth.py /app/auth.py
COPY data/db.json /app/db.json

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

# Record db.json baseline mtime so tests can confirm the file was modified at runtime
RUN stat -c %Y /app/db.json > /app/db_baseline_mtime.txt

WORKDIR /app

# Start Flask, wait for it to fully import all modules, then delete the source files.
# Python keeps loaded modules in memory, so Flask keeps running after the .py files
# are removed — the agent cannot read the application source code.
CMD python3 /app/app.py &>/app/flask.log & sleep 3 && rm -f /app/app.py /app/auth.py && sleep infinity
