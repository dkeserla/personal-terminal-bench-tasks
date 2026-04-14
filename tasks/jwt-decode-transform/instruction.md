# JWT Decode and Transform

You are working on a data pipeline task. Three JWT tokens are stored at:

- `/app/tokens/token_a.txt`
- `/app/tokens/token_b.txt`
- `/app/tokens/token_c.txt`

Each token was issued by a different service using a different algorithm (HS256, RS256, and `alg: none`). **You do not need to verify signatures.** Your job is to process these tokens as follows:

## Steps

1. **Decode** the payload of each token by base64url-decoding the middle segment (between the first and second `.`) and parsing it as JSON.

2. **Filter**: only include tokens whose decoded payload contains the field `"process"` with the value `true` (boolean). Tokens where `"process"` is `false` or absent must be excluded.

3. **Transform** each included payload:
   - Convert any field whose name is exactly `iat`, `exp`, or `nbf` from a Unix timestamp integer to an ISO 8601 UTC string in the format `YYYY-MM-DDTHH:MM:SSZ` (e.g. `"2023-11-14T22:13:20Z"`). If the field is absent, leave it absent.
   - Remove any field whose name starts with `_internal_`. (These are internal metadata fields that must be stripped before export.)
   - Keep all other fields unchanged.

4. **Sort** the resulting list of transformed payloads by their `sub` field value, ascending alphabetically.

5. **Write** the result as a pretty-printed (2-space indent) JSON array to `/app/claims.json`.

## Constraints

- Do not install packages that require internet access.
- Python 3 and the `PyJWT` package are pre-installed.
- The output file `/app/claims.json` must be valid JSON.
- Do not modify the token files.
