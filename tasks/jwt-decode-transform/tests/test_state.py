import json
import re

import pytest

CLAIMS_PATH = "/app/claims.json"
ISO_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$")

# Expected ISO strings derived from the known Unix timestamps in generate_tokens.py
# alice: iat=1700000000, exp=1700003600
# bob:   nbf=1699999000
ALICE_IAT = "2023-11-14T22:13:20Z"
ALICE_EXP = "2023-11-14T23:13:20Z"
BOB_NBF   = "2023-11-14T21:56:40Z"


@pytest.fixture(scope="module")
def claims():
    with open(CLAIMS_PATH) as f:
        return json.load(f)


def test_claims_is_list(claims):
    assert isinstance(claims, list), "claims.json must be a JSON array"


def test_claims_length(claims):
    assert len(claims) == 2, (
        f"Expected 2 entries (only process=true tokens), got {len(claims)}"
    )


def test_sorted_by_sub(claims):
    subs = [c["sub"] for c in claims]
    assert subs == sorted(subs), f"Entries must be sorted by 'sub'; got {subs}"


def test_first_entry_is_alice(claims):
    assert claims[0]["sub"] == "alice", "First entry (alphabetically) must be alice"


def test_second_entry_is_bob(claims):
    assert claims[1]["sub"] == "bob", "Second entry must be bob"


def test_carol_excluded(claims):
    subs = [c["sub"] for c in claims]
    assert "carol" not in subs, "carol has process=false and must be excluded"


# --- alice checks ---

def test_alice_no_internal_fields(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    bad = [k for k in alice if k.startswith("_internal_")]
    assert not bad, f"alice entry must not have _internal_ fields; found: {bad}"


def test_alice_iat_is_iso_string(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    assert "iat" in alice, "alice must have iat field"
    assert isinstance(alice["iat"], str), f"iat must be a string, got {type(alice['iat'])}"
    assert ISO_PATTERN.match(alice["iat"]), f"iat must be ISO 8601 UTC; got '{alice['iat']}'"


def test_alice_exp_is_iso_string(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    assert "exp" in alice, "alice must have exp field"
    assert isinstance(alice["exp"], str)
    assert ISO_PATTERN.match(alice["exp"]), f"exp must be ISO 8601 UTC; got '{alice['exp']}'"


def test_alice_iat_value(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    assert alice["iat"] == ALICE_IAT, f"iat expected '{ALICE_IAT}', got '{alice['iat']}'"


def test_alice_exp_value(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    assert alice["exp"] == ALICE_EXP, f"exp expected '{ALICE_EXP}', got '{alice['exp']}'"


def test_alice_role_preserved(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    assert alice.get("role") == "analyst", "alice's role must be preserved as 'analyst'"


def test_alice_process_preserved(claims):
    alice = next(c for c in claims if c["sub"] == "alice")
    assert alice.get("process") is True


# --- bob checks ---

def test_bob_no_internal_fields(claims):
    bob = next(c for c in claims if c["sub"] == "bob")
    bad = [k for k in bob if k.startswith("_internal_")]
    assert not bad, f"bob entry must not have _internal_ fields; found: {bad}"


def test_bob_nbf_is_iso_string(claims):
    bob = next(c for c in claims if c["sub"] == "bob")
    assert "nbf" in bob, "bob must have nbf field"
    assert isinstance(bob["nbf"], str)
    assert ISO_PATTERN.match(bob["nbf"]), f"nbf must be ISO 8601 UTC; got '{bob['nbf']}'"


def test_bob_nbf_value(claims):
    bob = next(c for c in claims if c["sub"] == "bob")
    assert bob["nbf"] == BOB_NBF, f"nbf expected '{BOB_NBF}', got '{bob['nbf']}'"


def test_bob_role_preserved(claims):
    bob = next(c for c in claims if c["sub"] == "bob")
    assert bob.get("role") == "viewer", "bob's role must be preserved as 'viewer'"


def test_bob_process_preserved(claims):
    bob = next(c for c in claims if c["sub"] == "bob")
    assert bob.get("process") is True
