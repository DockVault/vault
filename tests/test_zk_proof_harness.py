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
    assert challenge_kw["json"] == {"op": "create", "mode": "direct"}
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

# The path is a string literal quoted with " or ', and an f-string may hold the other quote inside it
# ({vault['id']}), so each quote style is matched up to its own closing quote.
_GUARDED_PATH = re.compile(
    r"""\.(post|put)\(\s*f?(?:"[^"]*/ecc/vaults/[^"]*/(rekey|members|index-key)\""""
    r"""|'[^']*/ecc/vaults/[^']*/(rekey|members|index-key)')""")


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
        verb, route = m.group(1), m.group(2) or m.group(3)
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
        # An f-string holding the other quote inside it.
        'owner.post(\n    f"/ecc/vaults/{vault[\'id\']}/members",\n    json={})',
        "admin.post(f'/ecc/vaults/{v[\"id\"]}/rekey', json={})",
    ]
    for sample in samples:
        assert len(_unproven_sites(sample)) == 1, sample
    assert _unproven_sites('post_zk(admin, f"/ecc/vaults/{vid}/rekey", json={})') == []
    assert _unproven_sites('admin.post("/vaults", json={"name": "s"})') == []


# ------------------------------------------------------------------------------ proofs it makes

class ProvingServer:
    """A stand-in server: issues challenges with the server module and checks the harness's proofs
    against the server module's transcript and MAC check."""

    def __init__(self, username, mode="direct", dek_epoch=3, team_epoch=1, verifier_pem=None):
        from app.services import zk_key_proof as kp
        self.kp = kp
        self.identity_pem = harness.public_pem(harness.identity_private_key(username))
        self.mode, self.de, self.te, self.verifier_pem = mode, dek_epoch, team_epoch, verifier_pem
        self.issued = {}
        self.sent = []

    def route(self, method, path, kw):
        if path == "/ecc/keys/public":
            return FakeResponse(200, {"has_keypair": True, "public_key": self.identity_pem})
        if path.endswith("/key-proof/challenge"):
            priv, pub, nonce = self.kp.generate_challenge()
            cid = "5d4c3b2a-1908-4f7e-8d6c-5b4a39281706"
            vid = path.split("/")[3]
            op = kw["json"]["op"]
            # As the server does: a create's vault does not exist yet, so its mode is the one asked for;
            # every other operation's mode is the vault's own, and a requested one is ignored.
            mode = (kw["json"].get("mode") or "direct") if op == "create" else self.mode
            if mode not in self.kp.MODES:
                return FakeResponse(400, {"detail": "mode must be direct or hierarchical",
                                          "reason": "zk-key-proof-malformed"})
            self.issued = {"priv": priv, "nonce": nonce, "cid": cid, "vid": vid, "op": op, "mode": mode}
            verifier = None
            if self.verifier_pem and op not in self.kp.OPS_WITHOUT_CURRENT_KEY:
                verifier = {"public_key": self.verifier_pem}
            return FakeResponse(200, {
                "challenge_id": cid, "server_ephemeral_public_key": pub, "nonce": nonce, "expires_in": 300,
                "mode": mode, "dek_epoch": self.de, "team_epoch": self.te, "verifier": verifier})
        self.sent.append((method, path, kw))
        return FakeResponse(200, {"ok": True})

    def check(self, user_id, current_pem, new_pem, mode=None):
        """Verify the last request's proof as the server would, in the mode the challenge was issued for
        unless `mode` says otherwise; return (body, {role: ok})."""
        method, path, kw = self.sent[-1]
        raw = kw["data"]
        header = self.kp.parse_header(kw["headers"][harness.PROOF_HEADER])
        i = self.issued
        digest = self.kp.transcript(
            op=i["op"], challenge_id=i["cid"], nonce_b64=i["nonce"], user_id=user_id,
            vault_id=i["vid"], mode=mode or i["mode"], dek_epoch=self.de, team_epoch=self.te,
            identity_public_key=self.identity_pem, current_public_key=current_pem,
            new_public_key=new_pem, body=raw)
        ok = {"identity": self.kp.verify_role("identity", i["priv"], self.identity_pem, digest, header.identity_mac)}
        if current_pem:
            ok["current-key"] = self.kp.verify_role("current-key", i["priv"], current_pem, digest,
                                                    header.current_key_mac)
        if new_pem:
            ok["new-key"] = self.kp.verify_role("new-key", i["priv"], new_pem, digest, header.new_key_mac)
        assert header.challenge_id == i["cid"]
        return json.loads(raw), ok


def test_a_direct_rotation_carries_new_material_and_all_three_proofs():
    from app.services import zk_key_proof as kp
    current = harness.new_private_key()
    server = ProvingServer("erin", verifier_pem=harness.public_pem(current))
    client = FakeClient(server.route, username="erin")
    harness.post_zk(client, "/ecc/vaults/0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9/rekey",
                    json={"from_version": 3, "to_version": 4, "member_keys": []})
    sent = json.loads(server.sent[-1][2]["data"])
    nkp = sent["next_key_proof"]
    body, ok = server.check(client.user["id"], harness.public_pem(current), nkp["public_key"])
    assert ok == {"identity": True, "current-key": True, "new-key": True}
    kp.validate_sealed_key(nkp["sealed_private_key"])
    kp.validate_mac32(nkp["dek_check"], "dek_check")
    kp.validate_mac32(body["lineage_tag"], "lineage_tag")
    assert harness.private_key_for(nkp["public_key"]) is not None, "the next epoch's key is remembered"


def test_a_create_carries_its_id_and_a_proof_for_the_key_it_installs():
    server = ProvingServer("frank", dek_epoch=1, team_epoch=1)
    client = FakeClient(server.route, username="frank")
    harness.post_zk(client, "/vaults", json={"type": "zero_knowledge", "wrapped_dek": "w",
                                             "ephemeral_public_key": "e"})
    sent = json.loads(server.sent[-1][2]["data"])
    assert sent["id"] == server.issued["vid"], "the body names the vault the challenge was issued for"
    assert _challenges_asked(client) == [{"op": "create", "mode": "direct"}]
    body, ok = server.check(client.user["id"], None, sent["key_proof"]["public_key"])
    assert ok == {"identity": True, "new-key": True}


def _challenges_asked(client):
    return [kw["json"] for _, path, kw in client.calls if path.endswith("/key-proof/challenge")]


def test_a_team_vault_create_asks_for_its_mode_and_proves_the_team_key():
    """A team vault does not exist when its create challenge is issued, so the challenge must name the
    mode the body creates it in: the proof then binds mode 2, and its new-key MAC is for the team public
    key the body installs."""
    team = harness.team_public_key()
    server = ProvingServer("kate", dek_epoch=1, team_epoch=1)
    client = FakeClient(server.route, username="kate")
    harness.post_zk(client, "/vaults", json={
        "type": "zero_knowledge", "key_wrapping_mode": "hierarchical", "team_public_key": team,
        "team_wrapped_dek": "w", "team_dek_ephemeral_public_key": "e", "wrapped_team_privkey": "p",
        "team_privkey_ephemeral_public_key": "q"})
    assert _challenges_asked(client) == [{"op": "create", "mode": "hierarchical"}]
    assert server.kp.MODES[server.issued["mode"]] == 2
    sent = json.loads(server.sent[-1][2]["data"])
    assert "key_proof" not in sent, "a team vault's verifier is its team key"
    body, ok = server.check(client.user["id"], None, team)
    assert ok == {"identity": True, "new-key": True}
    # The mode is bound: the same proof read as a direct create does not verify.
    _, as_direct = server.check(client.user["id"], None, team, mode="direct")
    assert as_direct == {"identity": False, "new-key": False}


def test_a_hierarchical_share_proves_with_the_remembered_team_key_and_adds_no_epoch():
    team = harness.team_public_key()
    server = ProvingServer("gina", mode="hierarchical", team_epoch=2, verifier_pem=team)
    client = FakeClient(server.route, username="gina")
    harness.post_zk(client, "/ecc/vaults/0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9/members",
                    json={"user_id": "u", "wrapped_team_privkey": "t", "team_ephemeral_public_key": "e"})
    body, ok = server.check(client.user["id"], team, None)
    assert ok == {"identity": True, "current-key": True}
    assert "dek_version" not in body


def test_a_direct_share_names_the_challenges_epoch_unless_the_test_sets_one():
    current = harness.new_private_key()
    server = ProvingServer("hank", verifier_pem=harness.public_pem(current))
    client = FakeClient(server.route, username="hank")
    path = "/ecc/vaults/0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9/members"
    harness.post_zk(client, path, json={"user_id": "u", "wrapped_dek": "w", "ephemeral_public_key": "e"})
    assert json.loads(server.sent[-1][2]["data"])["dek_version"] == 3
    harness.post_zk(client, path, json={"user_id": "u", "wrapped_dek": "w", "ephemeral_public_key": "e",
                                        "dek_version": 9})
    assert json.loads(server.sent[-1][2]["data"])["dek_version"] == 9
    harness.post_zk(client, path, json={"user_id": "u"}, augment=False)
    assert json.loads(server.sent[-1][2]["data"]) == {"user_id": "u"}
    body, ok = server.check(client.user["id"], harness.public_pem(current), None)
    assert ok["identity"] and ok["current-key"], "a body sent as given is still proved"


def test_a_key_the_harness_does_not_hold_gets_no_mac():
    stranger = ec.generate_private_key(ec.SECP384R1())
    server = ProvingServer("ivy", verifier_pem=harness.public_pem(stranger))
    client = FakeClient(server.route, username="ivy")
    harness.put_zk(client, "/ecc/vaults/0a1b2c3d-4e5f-4061-8273-8495a6b7c8d9/index-key", json={"wraps": []})
    header = server.kp.parse_header(server.sent[-1][2]["headers"][harness.PROOF_HEADER])
    assert header.current_key_mac is None and header.new_key_mac is None
    body, ok = server.check(client.user["id"], harness.public_pem(stranger), None)
    assert ok == {"identity": True, "current-key": False}


@pytest.mark.parametrize("given", ["", None])
def test_a_create_that_names_an_id_keeps_it_even_when_it_is_empty(given):
    server = ProvingServer("jill", dek_epoch=1, team_epoch=1)
    client = FakeClient(server.route, username="jill")
    harness.post_zk(client, "/vaults", json={"type": "zero_knowledge", "id": given})
    assert json.loads(server.sent[-1][2]["data"])["id"] == given


def test_a_create_whose_id_the_server_refuses_to_challenge_is_sent_as_given():
    def route(method, path, kw):
        if path.endswith("/key-proof/challenge"):
            return FakeResponse(400, {"detail": "the vault id is not a UUID", "reason": "zk-key-proof-malformed"})
        return FakeResponse(422, {"detail": "bad id"})
    client = FakeClient(route, username="jill")
    r = harness.post_zk(client, "/vaults", json={"type": "zero_knowledge", "id": "not-a-uuid"})
    assert r.status_code == 422 and r.zk_challenge_status == 400
    method, path, kw = client.calls[-1]
    assert json.loads(kw["data"])["id"] == "not-a-uuid" and harness.PROOF_HEADER not in kw["headers"]
