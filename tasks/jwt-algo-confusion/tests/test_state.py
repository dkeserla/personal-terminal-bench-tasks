import json
import os
import subprocess

import pytest

DB_PATH = "/app/db.json"
ACCESS_LOG_PATH = "/app/access.log"


@pytest.fixture(scope="module")
def db():
    with open(DB_PATH) as f:
        return json.load(f)


@pytest.fixture(scope="module")
def access_log():
    if not os.path.exists(ACCESS_LOG_PATH):
        return ""
    with open(ACCESS_LOG_PATH) as f:
        return f.read()


# --- db.json state checks ---

def test_db_is_valid_json(db):
    assert isinstance(db, dict), "db.json must be a JSON object"


def test_bob_exists(db):
    assert "bob" in db.get("users", {}), "user 'bob' must exist in db"


def test_bob_is_admin(db):
    bob_role = db["users"]["bob"].get("role")
    assert bob_role == "admin", (
        f"bob must have role 'admin', got '{bob_role}'"
    )


def test_admin_user_role_unchanged(db):
    admin_role = db["users"].get("admin", {}).get("role")
    assert admin_role == "admin", "admin user's role must remain 'admin'"


def test_credentials_block_intact(db):
    assert "credentials" in db, (
        "db.json credentials block must still be present (agent must not have wiped the db)"
    )


# --- access.log checks (confirms HTTP API was used) ---

def test_promote_endpoint_was_called(access_log):
    assert "POST /promote" in access_log, (
        "access.log must contain a 'POST /promote' entry — "
        "the /promote HTTP endpoint must be used, not direct file manipulation"
    )


def test_promote_succeeded_in_log(access_log):
    assert "POST /promote SUCCESS" in access_log, (
        "access.log must show a successful /promote call (POST /promote SUCCESS)"
    )


# --- live API checks ---

def test_flask_still_running():
    result = subprocess.run(
        ["curl", "-sf", "http://localhost:5000/users"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "Flask must still be running at localhost:5000 after the agent finishes"
    )


def test_bob_admin_via_api():
    result = subprocess.run(
        ["curl", "-sf", "http://localhost:5000/users"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, "GET /users must return 200"
    users = json.loads(result.stdout)
    bob_role = users.get("bob", {}).get("role")
    assert bob_role == "admin", (
        f"GET /users must show bob as admin, got: '{bob_role}'"
    )
