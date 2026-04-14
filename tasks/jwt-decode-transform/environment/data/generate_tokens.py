"""
generate_tokens.py — run during Docker build to produce the three JWT token files.
"""
import base64
import json
import os

import jwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

os.makedirs("/app/tokens", exist_ok=True)

# ------------------------------------------------------------------
# Token A: HS256, process=true, sub=alice
# Has iat, exp (Unix timestamps) and an _internal_source field
# ------------------------------------------------------------------
payload_a = {
    "sub": "alice",
    "iat": 1700000000,
    "exp": 1700003600,
    "process": True,
    "role": "analyst",
    "_internal_source": "svc-a",
}
token_a = jwt.encode(payload_a, "secret_key_a_hs256", algorithm="HS256")
with open("/app/tokens/token_a.txt", "w") as f:
    f.write(token_a)

# ------------------------------------------------------------------
# Token B: RS256, process=false, sub=carol  (should be excluded)
# ------------------------------------------------------------------
private_key_b = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend(),
)
private_pem_b = private_key_b.private_bytes(
    serialization.Encoding.PEM,
    serialization.PrivateFormat.TraditionalOpenSSL,
    serialization.NoEncryption(),
)
payload_b = {
    "sub": "carol",
    "iat": 1700000000,
    "exp": 1700003600,
    "process": False,
    "role": "user",
}
token_b = jwt.encode(payload_b, private_pem_b, algorithm="RS256")
with open("/app/tokens/token_b.txt", "w") as f:
    f.write(token_b)

# ------------------------------------------------------------------
# Token C: alg:none, process=true, sub=bob
# Has nbf (Unix timestamp) and an _internal_trace field
# Constructed manually because PyJWT rejects alg=none by default
# ------------------------------------------------------------------
def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()

header_c = b64url_encode(json.dumps({"alg": "none", "typ": "JWT"}).encode())
payload_c_data = {
    "sub": "bob",
    "nbf": 1699999000,
    "process": True,
    "role": "viewer",
    "_internal_trace": "xyz789",
}
payload_c = b64url_encode(json.dumps(payload_c_data).encode())
token_c = f"{header_c}.{payload_c}."  # empty signature for alg:none
with open("/app/tokens/token_c.txt", "w") as f:
    f.write(token_c)

print("Tokens generated:")
print(f"  token_a.txt (HS256, alice, process=true)")
print(f"  token_b.txt (RS256, carol, process=false)")
print(f"  token_c.txt (none,  bob,   process=true)")
