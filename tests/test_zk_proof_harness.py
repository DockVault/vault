"""The test-side client for key proofs (tests/zk_proof_harness.py).

Offline. The HTTP suite relies on this client for every request that changes a zero-knowledge vault's
keys, so the properties the suite depends on are pinned here rather than discovered through a live
failure: identity keys are derived and stable, every generated key can be found again from its public
key, the body is serialized once and those bytes are sent, and a server that issues no challenge gets
the request without a proof.
"""
import hashlib
import json
import re
from pathlib import Path

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import conftest
import zk_proof_harness as harness

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parent


class FakeResponse:
    def __init__(self, status_code=200, body=None):
        self.status_code = status_code
        self._body = body if body is not None else {}
        self.text = json.dumps(self._body)

    @property
    def ok(self):
        return self.status_code < 400

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise AssertionError(self.status_code)


class FakeClient:
    """Records every request; answers from a routing function."""

    def __init__(self, route, username="alice", user_id="9b2c1d5e-7a34-4c81-9f2b-1a2b3c4d5e6f"):
        self.calls = []
        self._route = route
        self._claims = {"username": username, "sub": user_id}
        self.user = {"id": user_id, "username": username}

    def _token_claims(self):
        return dict(self._claims)

    def _do(self, method, path, **kw):
        self.calls.append((method, path, kw))
        return self._route(method, path, kw)

    def get(self, path, **kw):
        return self._do("GET", path, **kw)

    def post(self, path, **kw):
        return self._do("POST", path, **kw)

    def put(self, path, **kw):
        return self._do("PUT", path, **kw)


def _old_server(method, path, kw):
    if path.endswith("/key-proof/challenge"):
        return FakeResponse(404, {"detail": "Not Found"})
    return FakeResponse(200, {"ok": True})


# ---------------------------------------------------------------------------------------- keys

def test_identity_keys_are_derived_from_the_username_and_stable():
    a1 = harness.identity_private_key("alice")
    a2 = harness.identity_private_key("alice")
    b = harness.identity_private_key("bob")
    assert harness.public_point(a1) == harness.public_point(a2)
    assert harness.public_point(a1) != harness.public_point(b)
    # Frozen: a long-lived stack keeps the keys an earlier run registered, so the derivation may never
    # change silently.
    assert hashlib.sha256(harness.public_point(a1)).hexdigest() == (
        "9b714dd34efbfcfd0e9763961c6b01dacc20ddf48049c7513955a4869a5123da"
    )


def test_a_remembered_key_is_found_from_any_encoding_of_its_public_key():
    key = harness.new_private_key()
    pem = harness.public_pem(key)
    assert harness.private_key_for(pem) is key
    assert harness.private_key_for(pem.replace("\n", "\r\n")) is key
    assert harness.private_key_for("\n  " + pem.strip() + "  \n") is key
    stranger = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    assert harness.private_key_for(stranger) is None
    assert harness.private_key_for("TEAMPUB-not-a-key") is None
    assert harness.private_key_for(None) is None


def test_team_public_key_is_a_remembered_p384_key():
    pem = harness.team_public_key()
    assert len(harness.public_point(pem)) == 97
    assert harness.private_key_for(pem) is not None
    assert harness.team_public_key() != pem


# -------------------------------------------------------------------------------------- routes

@pytest.mark.parametrize("method, path, body, expected", [
    ("POST", "/ecc/vaults/V/rekey", {"from_version": 1}, ("rekey", "V")),
    ("POST", "/ecc/vaults/V/rekey", {"owner_reset": True}, ("owner_reset", "V")),
    ("POST", "/ecc/vaults/V/members", {}, ("share", "V")),
    ("PUT", "/ecc/vaults/V/index-key", {}, ("index_key", "V")),
    ("PUT", "/ecc/vaults/V/key-proof", {}, ("bootstrap", "V")),
    ("POST", "/vaults", {"type": "zero_knowledge", "id": "I"}, ("create", "I")),
    ("POST", "/vaults", {"type": "zero_knowledge"}, ("create", None)),
    ("POST", "/vaults", {"type": "standard"}, None),
    ("POST", "/vaults", {"name": "x"}, None),
    ("GET", "/ecc/vaults/V/index-key", None, None),
    ("POST", "/ecc/vaults/V/members?x=1", {}, ("share", "V")),
    ("POST", "/ecc/vaults/V/retire-version", {}, None),
])
def test_guarded_operation_classifies_the_routes(method, path, body, expected):
    assert harness.guarded_operation(method, path, body) == expected


# ------------------------------------------------------------------------------------ requests

def test_post_zk_serializes_once_and_sends_those_bytes_to_an_old_server():
    client = FakeClient(_old_server)
    body = {"from_version": 1, "to_version": 2, "member_keys": [{"user_id": "u", "wrapped_dek": "é"}]}
    r = harness.post_zk(client, "/ecc/vaults/V/rekey", json=body)
    assert r.status_code == 200 and r.zk_challenge_status == 404
    (m1, p1, kw1), (m2, p2, kw2) = client.calls
    assert (m1, p1, kw1["json"]) == ("POST", "/ecc/vaults/V/key-proof/challenge", {"op": "rekey"})
    assert (m2, p2) == ("POST", "/ecc/vaults/V/rekey")
    assert kw2["data"] == harness.serialize(body).encode("utf-8")
    assert json.loads(kw2["data"].decode("utf-8")) == body
    assert kw2["headers"]["Content-Type"] == "application/json"
    assert harness.PROOF_HEADER not in kw2["headers"]
    assert "json" not in kw2, "the body must travel as the one serialized string, not be re-encoded"


def test_a_refused_challenge_sends_the_request_without_a_proof():
    def route(method, path, kw):
        if path.endswith("/key-proof/challenge"):
            return FakeResponse(403, {"detail": "No access to this vault's keys", "reason": "x"})
        return FakeResponse(403, {"detail": "route refusal"})
    client = FakeClient(route)
    r = harness.put_zk(client, "/ecc/vaults/V/index-key", json={"wraps": []})
    assert r.status_code == 403 and r.json()["detail"] == "route refusal"
    assert r.zk_challenge_status == 403
    method, path, kw = client.calls[-1]
    assert (method, path) == ("PUT", "/ecc/vaults/V/index-key")
    assert harness.PROOF_HEADER not in kw["headers"]


def test_a_standard_create_asks_for_no_challenge():
    client = FakeClient(_old_server)
    r = harness.post_zk(client, "/vaults", json={"name": "plain", "type": "standard"})
    assert r.zk_challenge_status is None
    assert [c[1] for c in client.calls] == ["/vaults"]


def test_a_zero_knowledge_create_without_an_id_is_sent_unchanged_to_an_old_server():
    client = FakeClient(_old_server)
    body = {"type": "zero_knowledge", "wrapped_dek": "w", "ephemeral_public_key": "e"}
    harness.post_zk(client, "/vaults", json=body)
    (_, challenge_path, challenge_kw), (_, _, kw) = client.calls
    assert re.fullmatch(r"/ecc/vaults/[0-9a-f-]{36}/key-proof/challenge", challenge_path)
    assert challenge_kw["json"] == {"op": "create"}
    assert json.loads(kw["data"]) == body, "no id or proof material is added when no challenge was issued"


def test_a_request_without_a_body_is_sent_without_one():
    client = FakeClient(_old_server)
    harness.post_zk(client, "/vaults", json=None)
    method, path, kw = client.calls[-1]
    assert (method, path) == ("POST", "/vaults") and "data" not in kw


# ---------------------------------------------------------------------------------- identities

def _registered(pem):
    def route(method, path, kw):
        if path == "/ecc/keys/public":
            return FakeResponse(200, {"has_keypair": pem is not None, "public_key": pem})
        return FakeResponse(200, {})
    return route


def test_the_harness_proves_only_for_an_account_whose_key_it_derived():
    mine = harness.public_pem(harness.identity_private_key("carol"))
    key = harness.identity_key_for(FakeClient(_registered(mine), username="carol"))
    assert harness.public_point(key) == harness.public_point(mine)

    other = harness.public_pem(ec.generate_private_key(ec.SECP384R1()))
    with pytest.raises(harness.HarnessError, match="not the test harness's derived key"):
        harness.identity_key_for(FakeClient(_registered(other), username="carol"))
    with pytest.raises(harness.HarnessError, match="no encryption key registered"):
        harness.identity_key_for(FakeClient(_registered(None), username="carol"))


def test_ensure_ecc_keypair_registers_the_derived_identity_key():
    server = ec.generate_private_key(ec.SECP384R1())
    server_pub = harness.public_pem(server)

    def route(method, path, kw):
        if path == "/ecc/keys/public":
            return FakeResponse(200, {"has_keypair": False})
        if path == "/ecc/keys/register/challenge":
            return FakeResponse(200, {"challenge_id": "c", "server_ephemeral_public_key": server_pub,
                                      "nonce": "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8="})
        return FakeResponse(201, {})

    client = FakeClient(route, username="dave")
    conftest.ensure_ecc_keypair(client)
    registered = [kw["json"] for m, p, kw in client.calls if p == "/ecc/keys/register"]
    assert len(registered) == 1
    assert harness.public_point(registered[0]["public_key"]) == harness.public_point(
        harness.identity_private_key("dave"))


# ------------------------------------------------------------------------------- the migration

_GUARDED_PATH = re.compile(
    r"""\.(post|put)\(\s*f?["'][^"']*/ecc/vaults/[^"']*/(rekey|members|index-key)["']""")


def _call_text(src, start):
    """The source of one call, from its opening parenthesis to the matching close."""
    depth, i = 0, src.index("(", start)
    for j in range(i, len(src)):
        if src[j] == "(":
            depth += 1
        elif src[j] == ")":
            depth -= 1
            if depth == 0:
                return src[i:j + 1]
    return src[i:]


def _unproven_sites(src):
    sites = []
    for m in _GUARDED_PATH.finditer(src):
        verb, route = m.group(1), m.group(2)
        if (verb, route) in (("post", "rekey"), ("post", "members"), ("put", "index-key")):
            sites.append(m.start())
    for m in re.finditer(r"""\.post\(\s*["']/vaults["']""", src):
        if "zero_knowledge" in _call_text(src, m.start()):
            sites.append(m.start())
    return sites


def test_every_api_test_changes_zero_knowledge_keys_through_the_harness():
    """A request that changes a zero-knowledge vault's keys must go through post_zk / put_zk, or it
    carries no proof and the suite tests a request no client sends. Browser tests are exempt: their
    requests come from the web app, and the keys their accounts hold were made in the browser, so the
    harness could not prove a setup request of theirs anyway."""
    offenders = []
    for path in sorted(TESTS.glob("test_*.py")):
        if path.name.startswith("test_ui_") or path.name == Path(__file__).name:
            continue
        src = path.read_text(encoding="utf-8")
        for at in _unproven_sites(src):
            offenders.append(f"{path.name}:{src.count(chr(10), 0, at) + 1}")
    assert offenders == [], f"guarded requests sent without the harness: {offenders}"


def test_the_unproven_request_detector_sees_one():
    """Guards the guard: each kind of guarded request, written the old way, is detected."""
    samples = [
        'admin.post(f"/ecc/vaults/{vid}/rekey", json={})',
        'admin.post(\n    f"/ecc/vaults/{vid}/members",\n    json={})',
        'admin.put(f"/ecc/vaults/{vid}/index-key", json={})',
        'admin.post("/vaults", json={"name": "z", "type": "zero_knowledge"})',
    ]
    for sample in samples:
        assert len(_unproven_sites(sample)) == 1, sample
    assert _unproven_sites('post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={})') == []
    assert _unproven_sites('admin.post("/vaults", json={"name": "s"})') == []
