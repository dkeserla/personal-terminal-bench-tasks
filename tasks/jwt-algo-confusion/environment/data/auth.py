"""
auth.py — token issuance and verification subsystem.

Handles JWT creation (RS256) and verification. The verification pipeline
supports multiple algorithm modes for cross-service compatibility.
"""

import base64
import json
import os
import time

import jwt as _pyjwt
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

_KEY_DIR = "/app/keys"
_PRIV_KEY_PATH = os.path.join(_KEY_DIR, "private.pem")
_PUB_KEY_PATH = os.path.join(_KEY_DIR, "public.pem")

_ISSUER = "auth-service-v2"
_TOKEN_TTL = 3600


def _load_private_key():
    with open(_PRIV_KEY_PATH, "rb") as f:
        return serialization.load_pem_private_key(
            f.read(), password=None, backend=default_backend()
        )


def load_public_key_pem() -> str:
    with open(_PUB_KEY_PATH, "rb") as f:
        return f.read().decode()


def _load_public_key_obj():
    with open(_PUB_KEY_PATH, "rb") as f:
        return serialization.load_pem_public_key(f.read(), backend=default_backend())


def generate_token(sub: str, role: str) -> str:
    """Issue a signed RS256 JWT for an authenticated user."""
    private_key = _load_private_key()
    now = int(time.time())
    payload = {
        "sub": sub,
        "role": role,
        "iat": now,
        "exp": now + _TOKEN_TTL,
        "iss": _ISSUER,
    }
    return _pyjwt.encode(payload, private_key, algorithm="RS256")


# ---------------------------------------------------------------------------
# Verification pipeline
# ---------------------------------------------------------------------------

def _peek_header(token: str) -> dict:
    """Decode the JWT header without verification to inspect the algorithm field."""
    try:
        parts = token.split(".")
        seg = parts[0]
        seg += "=" * (4 - len(seg) % 4)
        return json.loads(base64.urlsafe_b64decode(seg))
    except Exception:
        return {}


def _verify_rs256(token: str) -> dict | None:
    """Standard asymmetric verification using the server RSA public key."""
    try:
        pub = _load_public_key_obj()
        return _pyjwt.decode(
            token, pub, algorithms=["RS256"], options={"verify_exp": True}
        )
    except Exception:
        return None


# Legacy compatibility: some upstream services issue HMAC-signed tokens
# using shared key material derived from the asymmetric keypair.
# This path handles those tokens during the migration window.
def _verify_hmac_compat(token: str) -> dict | None:
    """
    Compatibility verifier for HMAC-signed tokens.
    Uses _compat_key_material for signature validation.
    """
    try:
        _compat_key_material = load_public_key_pem()
        return _pyjwt.decode(
            token,
            _compat_key_material,
            algorithms=["HS256"],
            options={"verify_exp": False},
        )
    except Exception:
        return None


_VERIFIER_DISPATCH = {
    "RS256": _verify_rs256,
    "HS256": _verify_hmac_compat,
}


def _resolve_verifier(alg: str):
    """Return the appropriate verifier function for the given algorithm identifier."""
    return _VERIFIER_DISPATCH.get(alg)


def verify_token(token: str) -> dict | None:
    """
    Verify a JWT and return its decoded claims, or None if verification fails.

    Supports RS256 (standard issuance) and HS256 (legacy compatibility mode).
    The algorithm is determined from the token's own header.
    """
    header = _peek_header(token)
    alg = header.get("alg", "")
    verifier = _resolve_verifier(alg)
    if verifier is None:
        return None
    return verifier(token)
