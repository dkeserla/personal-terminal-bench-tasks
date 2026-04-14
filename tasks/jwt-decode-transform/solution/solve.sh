#!/usr/bin/env bash
set -euo pipefail

python3 - <<'PYEOF'
import base64
import json
from datetime import datetime, timezone


def b64url_decode(segment: str) -> bytes:
    # Restore base64 padding
    padding = 4 - len(segment) % 4
    if padding != 4:
        segment += "=" * padding
    return base64.urlsafe_b64decode(segment)


def decode_payload(token_path: str) -> dict:
    with open(token_path) as f:
        token = f.read().strip()
    parts = token.split(".")
    raw = b64url_decode(parts[1])
    return json.loads(raw)


TIMESTAMP_FIELDS = {"iat", "exp", "nbf"}
TOKEN_PATHS = [
    "/app/tokens/token_a.txt",
    "/app/tokens/token_b.txt",
    "/app/tokens/token_c.txt",
]

results = []
for path in TOKEN_PATHS:
    payload = decode_payload(path)

    # Filter: only include tokens with process == True
    if not payload.get("process", False):
        continue

    # Transform
    transformed = {}
    for k, v in payload.items():
        if k.startswith("_internal_"):
            continue
        if k in TIMESTAMP_FIELDS and isinstance(v, int):
            dt = datetime.fromtimestamp(v, tz=timezone.utc)
            transformed[k] = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
        else:
            transformed[k] = v
    results.append(transformed)

# Sort by sub field alphabetically
results.sort(key=lambda x: x["sub"])

with open("/app/claims.json", "w") as f:
    json.dump(results, f, indent=2)

print(f"Done. Wrote {len(results)} entries to /app/claims.json")
PYEOF
