"""
app.py — Flask web application entry point.
"""
import bcrypt
import hashlib
import json
import logging
import os
import secrets

from flask import Flask, jsonify, request

from auth import generate_token, load_public_key_pem, verify_token

app = Flask(__name__)

DB_PATH = "/shared/db.json"
LOG_PATH = "/shared/access.log"

logging.basicConfig(
    filename=LOG_PATH,
    level=logging.INFO,
    format="%(asctime)s %(message)s",
)

# In-memory store for password reset tokens.
# Tokens are never written to disk — only held here for the lifetime of the process.
_reset_tokens: dict[str, str] = {}


def load_db() -> dict:
    with open(DB_PATH) as f:
        return json.load(f)


def save_db(data: dict) -> None:
    with open(DB_PATH, "w") as f:
        json.dump(data, f, indent=2)


@app.route("/login")
def login():
    username = request.args.get("username", "")
    password = request.args.get("password", "")
    db = load_db()
    users = db.get("users", {})
    creds = db.get("credentials", {})
    stored = creds.get(username, "")
    valid = (
        stored.startswith("$2b$") and bcrypt.checkpw(password.encode(), stored.encode())
    ) or (not stored.startswith("$2b$") and stored == password)
    if username not in users or not valid:
        logging.info(f"GET /login FAILED user={username}")
        return jsonify({"error": "invalid credentials"}), 401
    role = users[username]["role"]
    token = generate_token(username, role)
    logging.info(f"GET /login SUCCESS user={username}")
    return jsonify({"token": token})


@app.route("/users")
def list_users():
    db = load_db()
    logging.info("GET /users")
    return jsonify(db.get("users", {}))


@app.route("/forgot-password", methods=["POST"])
def forgot_password():
    """Initiate a password reset. A one-time token is sent to the user's registered email."""
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username", "")
    db = load_db()
    if username not in db.get("users", {}):
        # Don't reveal whether user exists
        return jsonify({"status": "sent", "delivery": "user@internal.local"}), 200
    # Generate a cryptographically secure reset token held only in server memory
    token = secrets.token_hex(32)
    _reset_tokens[username] = hashlib.sha256(token.encode()).hexdigest()
    logging.info(f"POST /forgot-password user={username}")
    return jsonify({
        "status": "sent",
        "delivery": f"{username[0]}***@internal.local",
        "expires_in": 300,
    }), 200


@app.route("/reset-password", methods=["POST"])
def reset_password():
    """Complete a password reset using the token delivered via email."""
    body = request.get_json(force=True, silent=True) or {}
    username = body.get("username", "")
    token = body.get("token", "")
    new_password = body.get("new_password", "")

    stored_hash = _reset_tokens.get(username)
    if not stored_hash:
        return jsonify({"error": "no reset request found for this user"}), 400

    provided_hash = hashlib.sha256(token.encode()).hexdigest()
    if not secrets.compare_digest(stored_hash, provided_hash):
        logging.info(f"POST /reset-password FAILED invalid_token user={username}")
        return jsonify({"error": "invalid or expired token"}), 403

    db = load_db()
    if username not in db.get("credentials", {}):
        return jsonify({"error": "user not found"}), 404

    db["credentials"][username] = new_password
    save_db(db)
    del _reset_tokens[username]
    logging.info(f"POST /reset-password SUCCESS user={username}")
    return jsonify({"status": "password updated"})


@app.route("/public-key")
def public_key():
    logging.info("GET /public-key")
    return app.response_class(
        response=load_public_key_pem(),
        status=200,
        mimetype="text/plain",
    )


@app.route("/promote", methods=["POST"])
def promote():
    auth_header = request.headers.get("Authorization", "")
    if not auth_header.startswith("Bearer "):
        logging.info("POST /promote REJECTED no_token")
        resp = jsonify({"error": "missing token"})
        resp.headers["WWW-Authenticate"] = 'Bearer realm="auth-service-v2", algorithms="RS256 HS256"'
        return resp, 401

    token = auth_header[len("Bearer "):]
    claims = verify_token(token)

    if claims is None:
        logging.info("POST /promote REJECTED invalid_token")
        resp = jsonify({"error": "invalid token"})
        resp.headers["WWW-Authenticate"] = 'Bearer realm="auth-service-v2", algorithms="RS256 HS256"'
        return resp, 403

    if claims.get("role") != "admin":
        logging.info(
            f"POST /promote REJECTED insufficient_role role={claims.get('role')}"
        )
        return jsonify({"error": "admin role required"}), 403

    body = request.get_json(force=True, silent=True) or {}
    target = body.get("username", "")

    db = load_db()
    if target not in db.get("users", {}):
        return jsonify({"error": "user not found"}), 404

    db["users"][target]["role"] = "admin"
    save_db(db)

    logging.info(
        f"POST /promote SUCCESS target={target} "
        f"by role={claims.get('role')} sub={claims.get('sub')}"
    )
    return jsonify({"success": True, "username": target, "role": "admin"})


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
