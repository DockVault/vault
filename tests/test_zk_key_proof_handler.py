"""The key proof in the handlers that change a zero-knowledge vault's keys: what each one checks, in what order,
and what it stores.

Rotating a vault's key (POST /ecc/vaults/{id}/rekey), sharing it (POST /ecc/vaults/{id}/members) and setting
its name-index key (PUT /ecc/vaults/{id}/index-key) each carry a proof in the X-ZK-Key-Proof header: MACs over
one server challenge and over the exact request body. This file drives the real handlers (without their
permission decorators, which the live tests cover) against the real tables in a throwaway SQLite database,
with challenges written straight into the challenge table and proofs made by the independent reference
(tests/zk_key_proof_reference.py). test_zk_key_proof_live.py drives the routes on a running deployment.

What is pinned here:
* a challenge is consumed whether or not the proof checks out, so a wrong answer cannot be followed by a
  right one on the same challenge; an expired one is refused;
* a malformed header or malformed key material is refused before anything is consumed;
* each role the operation needs is checked (identity always, the current key, the key a rotation installs);
* the vault must still be in the state the challenge was issued for;
* the proof binds the body's exact bytes;
* with enforcement on, no proof means 428; with it off, a request without one runs as before, is recorded,
  and stores no proof material, while a request with a proof is still checked in full;
* a proven rotation stores the new epoch's material; a team rotation that reinstalls the current team key
  is refused.
"""
import base64
import hashlib
import inspect
import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec
from sqlalchemy.orm import sessionmaker
from sqlalchemy.sql import sqltypes

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import zk_key_proof_reference as ref  # noqa: E402
from app.api import ecc_router as E  # noqa: E402
from app.core.key_wrap_algorithms import DIRECT_DEK_ALGO, TEAMPRIV_ALGO  # noqa: E402
from app.core.models import (  # noqa: E402
    RoleEnum, User, UserKeyPair, Vault, VaultKeyProof, VaultMemberIndexKey, VaultMemberKey,
    ZkKeyProofChallenge, vault_members,
)
from app.core.security import encrypt_secret  # noqa: E402
from app.services.zk_key_proof import KeyProofRefusal  # noqa: E402

pytestmark = pytest.mark.unit

REKEY = inspect.unwrap(E.rekey_vault)
GRANT = inspect.unwrap(E.grant_member_key)
PUT_INDEX_KEY = inspect.unwrap(E.put_vault_index_key)


# --------------------------------------------------------------------------------------- database

@pytest.fixture
def world(monkeypatch):
    """A SQLite database with the tables these handlers touch, the audit rows they write (collected here,
    not stored), and enforcement on unless a test turns it off."""
    original = sqltypes.Uuid.bind_processor

    def bind_processor(self, dialect):
        inner = original(self, dialect)
        if inner is None:
            return None

        def process(value):
            return inner(uuid.UUID(value) if isinstance(value, str) else value)
        return process

    monkeypatch.setattr(sqltypes.Uuid, "bind_processor", bind_processor)
    monkeypatch.setattr(E, "_ecc_rate_limit", lambda *a, **k: None)
    audit = []
    monkeypatch.setattr(E, "_audit_zk", lambda db, actor, action, **kw: audit.append((action, kw.get("details"))))
    state = {"enforce": True}
    monkeypatch.setattr(E.zk_key_proof, "enforcement_enabled", lambda: state["enforce"])
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'zk.db'}", connect_args={"check_same_thread": False})
        for table in (User.__table__, Vault.__table__, vault_members, VaultMemberKey.__table__,
                      UserKeyPair.__table__, VaultMemberIndexKey.__table__, VaultKeyProof.__table__,
                      ZkKeyProofChallenge.__table__):
            table.create(engine)
        yield World(sessionmaker(bind=engine, autocommit=False, autoflush=False), audit, state)
        engine.dispose()


class World:
    def __init__(self, Session, audit, state):
        self.Session = Session
        self.audit = audit
        self._state = state
        self.keys = {}          # user id -> identity private key

    def enforce(self, on: bool):
        self._state["enforce"] = on

    # ------------------------------------------------------------------ people and vaults
    def person(self, s, role=RoleEnum.USER):
        key = ec.generate_private_key(ec.SECP384R1())
        u = User(id=uuid.uuid4(), username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=role)
        s.add(u)
        s.flush()
        s.add(UserKeyPair(user_id=u.id, public_key=ref.public_pem(key), fingerprint=uuid.uuid4().hex))
        self.keys[u.id] = key
        return u.id

    def direct_vault(self, *, with_row=True):
        """A direct vault at epoch 1 whose owner and a Manager hold the key; with its epoch's proof row."""
        s = self.Session()
        owner, manager = self.person(s), self.person(s)
        vid = uuid.uuid4()
        s.add(Vault(id=vid, owner_id=owner, type="zero_knowledge", key_wrapping_mode="direct", dek_version=1))
        s.flush()
        s.execute(vault_members.insert().values(vault_id=vid, user_id=manager, read_permission=True,
                                                manage_permission=True))
        for u in (owner, manager):
            s.add(VaultMemberKey(vault_id=vid, user_id=u, wrapped_dek="w", ephemeral_public_key="e",
                                 wrapping_algorithm=DIRECT_DEK_ALGO, key_version=1))
        proof_key = None
        if with_row:
            proof_key = ec.generate_private_key(ec.SECP384R1())
            s.add(VaultKeyProof(vault_id=vid, dek_epoch=1, proof_public_key=ref.public_pem(proof_key),
                                sealed_private_key=_sealed_stub(), dek_check=_b64(os.urandom(32)),
                                source="create", created_by=owner))
        s.commit()
        s.close()
        return vid, owner, manager, proof_key

    def hier_vault(self):
        """A hierarchical vault whose owner and a Manager hold the team private key; returns the team key."""
        s = self.Session()
        owner, manager = self.person(s), self.person(s)
        team = ec.generate_private_key(ec.SECP384R1())
        vid = uuid.uuid4()
        s.add(Vault(id=vid, owner_id=owner, type="zero_knowledge", key_wrapping_mode="hierarchical",
                    dek_version=1, team_key_version=1, team_public_key=ref.public_pem(team),
                    team_key=json.dumps({"1": {"wrapped_dek": "d", "ephemeral_public_key": "e",
                                               "team_key_version": 1}})))
        s.flush()
        s.execute(vault_members.insert().values(vault_id=vid, user_id=manager, read_permission=True,
                                                manage_permission=True))
        for u in (owner, manager):
            s.add(VaultMemberKey(vault_id=vid, user_id=u, wrapped_dek="w", ephemeral_public_key="e",
                                 wrapping_algorithm=TEAMPRIV_ALGO, key_version=1))
        s.commit()
        s.close()
        return vid, owner, manager, team

    def new_person(self):
        s = self.Session()
        uid = self.person(s)
        s.commit()
        s.close()
        return uid

    # ------------------------------------------------------------------ challenges and proofs
    def challenge(self, user_id, vault_id, op, *, age_seconds=0, sealed=True):
        """Write a challenge row as the challenge route does, for the vault's current state."""
        s = self.Session()
        try:
            v = s.query(Vault).filter(Vault.id == vault_id).first()
            hier = v.key_wrapping_mode == "hierarchical"
            if hier:
                verifier = v.team_public_key
            else:
                row = s.query(VaultKeyProof).filter(VaultKeyProof.vault_id == vault_id,
                                                    VaultKeyProof.dek_epoch == v.dek_version).first()
                verifier = row.proof_public_key if row else None
            server = ec.generate_private_key(ec.SECP384R1())
            ch = ZkKeyProofChallenge(
                id=uuid.uuid4(), user_id=user_id, vault_id=vault_id, op=op,
                server_private_key_sealed=encrypt_secret(ref.private_pem(server)) if sealed else ref.private_pem(server),
                nonce=_b64(os.urandom(32)), mode="hierarchical" if hier else "direct",
                dek_epoch=v.dek_version or 1, team_epoch=v.team_key_version or 1,
                verifier_sha256=hashlib.sha256(ref.point(verifier)).hexdigest() if verifier else None,
                created_at=datetime.utcnow() - timedelta(seconds=age_seconds),
            )
            s.add(ch)
            s.commit()
            return {"challenge_id": str(ch.id), "server_ephemeral_public_key": ref.public_pem(server),
                    "nonce": ch.nonce, "mode": ch.mode, "dek_epoch": ch.dek_epoch, "team_epoch": ch.team_epoch,
                    "verifier": verifier}
        finally:
            s.close()

    def prove(self, ch, user_id, vault_id, op, body: str, *, current_key=None, new_pem=None, new_key=None,
              identity_key=None):
        """The header for `body`, proved with the caller's identity key and, when given, the current key and
        the key the request installs."""
        current_pem = None if op in ref.OPS_WITHOUT_CURRENT_KEY else ch["verifier"]
        digest = ref.transcript(
            op=op, challenge_id=ch["challenge_id"], nonce_b64=ch["nonce"], user_id=str(user_id),
            vault_id=str(vault_id), mode=ch["mode"], dek_epoch=ch["dek_epoch"], team_epoch=ch["team_epoch"],
            identity_pem=ref.public_pem(self.keys[user_id]), current_pem=current_pem, new_pem=new_pem,
            body=body.encode("utf-8"))
        server = ch["server_ephemeral_public_key"]
        return ref.proof_header(
            ch["challenge_id"],
            ref.role_mac("identity", identity_key or self.keys[user_id], server, digest),
            ref.role_mac("current-key", current_key, server, digest) if current_key else None,
            ref.role_mac("new-key", new_key, server, digest) if new_key else None,
        )

    def call(self, handler, caller, http_request, **kwargs):
        s = self.Session()
        try:
            user = s.query(User).filter(User.id == caller).first()
            return run_coroutine(handler(current_user=user, db=s, http_request=http_request, **kwargs))
        finally:
            s.close()

    def refused(self, handler, caller, http_request, **kwargs):
        with pytest.raises(Exception) as exc:
            self.call(handler, caller, http_request, **kwargs)
        return exc.value

    def challenges_left(self):
        s = self.Session()
        try:
            return s.query(ZkKeyProofChallenge).count()
        finally:
            s.close()

    def proof_rows(self, vault_id):
        s = self.Session()
        try:
            return {r.dek_epoch: (r.source, r.proof_public_key, r.lineage_tag)
                    for r in s.query(VaultKeyProof).filter(VaultKeyProof.vault_id == vault_id).all()}
        finally:
            s.close()

    def dek_version(self, vault_id):
        s = self.Session()
        try:
            return s.query(Vault).filter(Vault.id == vault_id).first().dek_version
        finally:
            s.close()

    def failures(self):
        return [d["reason"] for a, d in self.audit if a == "zk_key_proof_failed"]


class FakeRequest:
    """What the handlers read from the HTTP request: the header and the raw body."""

    def __init__(self, body: str, header=None):
        self._body = body.encode("utf-8")
        self.headers = {} if header is None else {"X-ZK-Key-Proof": header}

    async def body(self):
        return self._body


def _b64(raw: bytes) -> str:
    return base64.b64encode(raw).decode()


def _sealed_stub() -> str:
    return _b64(b"DVZ2\x02\x07\x00\x00" + os.urandom(60))


def _serialize(body: dict) -> str:
    return json.dumps(body, separators=(",", ":"))


def _direct_material():
    key = ec.generate_private_key(ec.SECP384R1())
    return key, {"public_key": ref.public_pem(key), "sealed_private_key": _sealed_stub(),
                 "dek_check": _b64(os.urandom(32))}


def _share_body(target, epoch=1):
    return {"user_id": str(target), "wrapped_dek": "w2", "ephemeral_public_key": "e2", "dek_version": epoch}


def _share(world, vid, caller, target, *, header=None, body=None, raw=None):
    body = body if body is not None else _share_body(target)
    raw = raw if raw is not None else _serialize(body)
    return world.call(GRANT, caller, FakeRequest(raw, header), vault_id=str(vid),
                      request=E.GrantMemberKeyRequest(**body))


def _proved_share(world, vid, caller, target, proof_key, **prove_kw):
    body = _share_body(target)
    raw = _serialize(body)
    ch = world.challenge(caller, vid, "share")
    header = world.prove(ch, caller, vid, "share", raw, current_key=proof_key, **prove_kw)
    return ch, body, raw, header


# ------------------------------------------------------------------------------ one-time challenges

def test_a_proven_share_stores_the_key_and_uses_up_its_challenge(world):
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    _, body, raw, header = _proved_share(world, vid, manager, target, proof_key)
    out = _share(world, vid, manager, target, header=header, body=body, raw=raw)
    assert out["status"] == "ok" and out["key_version"] == 1
    assert world.challenges_left() == 0
    granted = [d for a, d in world.audit if a == "zk_member_key_granted"]
    assert granted and granted[-1]["proof"] == "key"
    assert not [a for a, _ in world.audit if a == "zk_key_proof_absent"]


def test_a_wrong_proof_uses_up_the_challenge_so_the_right_one_then_fails(world):
    """Consumption never depends on the outcome: a guess costs a fresh, rate-limited challenge."""
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    ch, body, raw, good = _proved_share(world, vid, manager, target, proof_key)
    wrong = world.prove(ch, manager, vid, "share", raw, current_key=proof_key,
                        identity_key=ec.generate_private_key(ec.SECP384R1()))
    err = world.refused(GRANT, manager, FakeRequest(raw, wrong), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body))
    assert isinstance(err, KeyProofRefusal) and (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    err = world.refused(GRANT, manager, FakeRequest(raw, good), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body))
    assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    assert world.failures() == ["identity", "no_live_challenge"]


def test_an_expired_challenge_is_refused(world):
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    body = _share_body(target)
    raw = _serialize(body)
    ch = world.challenge(manager, vid, "share", age_seconds=301)
    header = world.prove(ch, manager, vid, "share", raw, current_key=proof_key)
    err = world.refused(GRANT, manager, FakeRequest(raw, header), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body))
    assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    assert world.failures() == ["expired"] and world.challenges_left() == 0


def test_a_challenge_whose_key_this_server_did_not_seal_never_verifies(world):
    """The one-time key is stored sealed with the deployment key. A row whose key was written in the clear
    -- by anyone who can write the table -- cannot be answered, even with a proof made against that key."""
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    body = _share_body(target)
    raw = _serialize(body)
    ch = world.challenge(manager, vid, "share", sealed=False)
    header = world.prove(ch, manager, vid, "share", raw, current_key=proof_key)
    err = world.refused(GRANT, manager, FakeRequest(raw, header), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body))
    assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")


def test_a_challenge_for_another_operation_or_vault_is_not_this_one(world):
    vid, owner, manager, proof_key = world.direct_vault()
    other_vid, *_ = world.direct_vault()
    target = world.new_person()
    body = _share_body(target)
    raw = _serialize(body)
    for ch in (world.challenge(manager, vid, "index_key"), world.challenge(manager, other_vid, "share")):
        header = world.prove(ch, manager, vid, "share", raw, current_key=proof_key)
        err = world.refused(GRANT, manager, FakeRequest(raw, header), vault_id=str(vid),
                            request=E.GrantMemberKeyRequest(**body))
        assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    assert world.failures() == ["no_live_challenge", "no_live_challenge"]


def test_malformed_headers_and_material_consume_nothing(world):
    """A request whose header or key material has the wrong shape is refused before its challenge is
    touched, so the honest client that sent it can still use the challenge."""
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    ch, body, raw, good = _proved_share(world, vid, manager, target, proof_key)
    for bad in ("v1", "v2" + good[2:], good + ".x", good.replace(good.split(".")[2], "!" * 43), ""):
        err = world.refused(GRANT, manager, FakeRequest(raw, bad), vault_id=str(vid),
                            request=E.GrantMemberKeyRequest(**body))
        assert (err.status_code, err.reason) == (400, "zk-key-proof-malformed"), bad
    # A direct share with a proof names its epoch.
    no_epoch = {k: v for k, v in body.items() if k != "dek_version"}
    err = world.refused(GRANT, manager, FakeRequest(_serialize(no_epoch), good), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**no_epoch))
    assert (err.status_code, err.reason) == (400, "zk-key-proof-malformed")
    assert world.challenges_left() == 1
    assert _share(world, vid, manager, target, header=good, body=body, raw=raw)["status"] == "ok"


def test_malformed_rotation_material_consumes_nothing(world):
    vid, owner, manager, proof_key = world.direct_vault()
    ch = world.challenge(owner, vid, "rekey")
    _, material = _direct_material()
    good_body = _rekey_body(owner, manager, material)
    for broken in ({"public_key": "not a key"}, {"sealed_private_key": _b64(b"DVZ2\x02\x06\x00\x00" + b"x" * 40)},
                   {"dek_check": _b64(b"x" * 31)}):
        bad = dict(good_body, next_key_proof=dict(material, **broken))
        raw = _serialize(bad)
        header = world.prove(ch, owner, vid, "rekey", raw, current_key=proof_key)
        err = world.refused(REKEY, owner, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**bad))
        assert (err.status_code, err.reason) == (400, "zk-key-proof-malformed"), broken
    for bad in ({k: v for k, v in good_body.items() if k != "next_key_proof"},
                {k: v for k, v in good_body.items() if k != "lineage_tag"},
                dict(good_body, lineage_tag=_b64(b"x" * 33))):
        raw = _serialize(bad)
        header = world.prove(ch, owner, vid, "rekey", raw, current_key=proof_key)
        err = world.refused(REKEY, owner, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**bad))
        assert (err.status_code, err.reason) == (400, "zk-key-proof-malformed")
    assert world.challenges_left() == 1
    assert world.dek_version(vid) == 1


# ------------------------------------------------------------------------------------- the roles

def test_each_role_the_operation_needs_is_checked(world):
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    # A share proves the current key: identity alone is not enough, nor is another key in its place.
    for current in (None, ec.generate_private_key(ec.SECP384R1())):
        body = _share_body(target)
        raw = _serialize(body)
        ch = world.challenge(manager, vid, "share")
        header = world.prove(ch, manager, vid, "share", raw, current_key=current)
        err = world.refused(GRANT, manager, FakeRequest(raw, header), vault_id=str(vid),
                            request=E.GrantMemberKeyRequest(**body))
        assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    # A rotation also proves the key it installs, which must be the one in its body.
    new_key, material = _direct_material()
    for installs in (None, ec.generate_private_key(ec.SECP384R1())):
        body = _rekey_body(owner, manager, material)
        raw = _serialize(body)
        ch = world.challenge(owner, vid, "rekey")
        header = world.prove(ch, owner, vid, "rekey", raw, current_key=proof_key,
                             new_pem=material["public_key"], new_key=installs)
        err = world.refused(REKEY, owner, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**body))
        assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    assert world.failures() == ["current_key", "current_key", "new_key", "new_key"]
    assert world.dek_version(vid) == 1 and _rows_for(world, vid, target) == 0


def test_the_proof_binds_the_exact_body_bytes(world):
    """The server hashes the bytes it received, not the parsed body: the same JSON with other whitespace,
    or a field the model ignores, is a different request."""
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    ch, body, raw, header = _proved_share(world, vid, manager, target, proof_key)
    for other in (json.dumps(body), _serialize(dict(body, ignored="x"))):
        again = world.challenge(manager, vid, "share")
        h = world.prove(again, manager, vid, "share", raw, current_key=proof_key)
        err = world.refused(GRANT, manager, FakeRequest(other, h), vault_id=str(vid),
                            request=E.GrantMemberKeyRequest(**body))
        assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    assert _share(world, vid, manager, target, header=header, body=body, raw=raw)["status"] == "ok"


def test_the_vault_must_still_be_in_the_state_the_challenge_was_issued_for(world):
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    ch, body, raw, header = _proved_share(world, vid, manager, target, proof_key)
    s = world.Session()
    s.query(Vault).filter(Vault.id == vid).update({"dek_version": 2})
    s.add(VaultMemberKey(vault_id=vid, user_id=manager, wrapped_dek="w", ephemeral_public_key="e",
                         wrapping_algorithm=DIRECT_DEK_ALGO, key_version=2))
    s.add(VaultKeyProof(vault_id=vid, dek_epoch=2, proof_public_key=ref.public_pem(proof_key),
                        sealed_private_key=_sealed_stub(), dek_check=_b64(os.urandom(32)), source="rotate"))
    s.commit()
    s.close()
    body2 = _share_body(target, epoch=2)
    raw2 = _serialize(body2)
    h2 = world.prove(ch, manager, vid, "share", raw2, current_key=proof_key)
    err = world.refused(GRANT, manager, FakeRequest(raw2, h2), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body2))
    assert (err.status_code, err.reason) == (409, "zk-key-proof-stale")
    assert _rows_for(world, vid, target) == 0


def test_a_direct_epoch_without_a_proof_key_needs_setting_up_first(world):
    vid, owner, manager, _ = world.direct_vault(with_row=False)
    target = world.new_person()
    body = _share_body(target)
    raw = _serialize(body)
    ch = world.challenge(manager, vid, "share")
    assert ch["verifier"] is None
    header = world.prove(ch, manager, vid, "share", raw)
    err = world.refused(GRANT, manager, FakeRequest(raw, header), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body))
    assert (err.status_code, err.reason) == (428, "zk-key-proof-setup-required")
    assert _rows_for(world, vid, target) == 0


# ------------------------------------------------------------------------------------ the switch

def _rows_for(world, vid, user_id):
    s = world.Session()
    try:
        return s.query(VaultMemberKey).filter(VaultMemberKey.vault_id == vid,
                                              VaultMemberKey.user_id == user_id).count()
    finally:
        s.close()


def _rekey_body(owner, manager, material, frm=1, lineage=True):
    body = {"from_version": frm, "to_version": frm + 1, "member_keys": [
        {"user_id": str(u), "wrapped_dek": "n", "ephemeral_public_key": "e"} for u in (owner, manager)],
        "next_key_proof": material}
    if lineage:
        body["lineage_tag"] = _b64(os.urandom(32))
    return body


def test_enforcing_a_request_without_a_proof_is_refused_with_428_and_changes_nothing(world):
    vid, owner, manager, _ = world.direct_vault()
    target = world.new_person()
    _, material = _direct_material()
    rk = _rekey_body(owner, manager, material)
    cases = (
        (GRANT, dict(request=E.GrantMemberKeyRequest(**_share_body(target))), _share_body(target)),
        (REKEY, dict(request=E.RekeyRequest(**rk)), rk),
        (PUT_INDEX_KEY, dict(body=E.IndexKeyPut(wraps=[E.IndexKeyWrap(
            user_id=str(owner), encrypted_index_key="k", ephemeral_public_key="e")])), None),
    )
    for handler, kwargs, body in cases:
        err = world.refused(handler, manager, FakeRequest(_serialize(body or {})), vault_id=str(vid), **kwargs)
        assert (err.status_code, err.reason) == (428, "zk-key-proof-required")
    assert world.dek_version(vid) == 1 and _rows_for(world, vid, target) == 0


def test_with_enforcement_off_a_request_without_a_proof_runs_as_before_and_stores_no_material(world):
    """Off, the operator has chosen to accept requests without a proof: each one is recorded, and
    material is stored only from a request whose proofs verified, so its epoch is set up later."""
    world.enforce(False)
    vid, owner, manager, _ = world.direct_vault()
    _, material = _direct_material()
    body = _rekey_body(owner, manager, material)
    out = world.call(REKEY, owner, FakeRequest(_serialize(body)), vault_id=str(vid), request=E.RekeyRequest(**body))
    assert out["dek_version"] == 2
    assert sorted(world.proof_rows(vid)) == [1], "a rotation without a proof stored proof material"
    absent = [d for a, d in world.audit if a == "zk_key_proof_absent"]
    assert absent == [{"op": "rekey", "mode": "direct"}]
    assert [d["proof"] for a, d in world.audit if a == "zk_vault_rekeyed"] == ["absent"]


def test_with_enforcement_off_a_request_with_a_bad_proof_is_still_refused(world):
    world.enforce(False)
    vid, owner, manager, proof_key = world.direct_vault()
    target = world.new_person()
    ch, body, raw, _ = _proved_share(world, vid, manager, target, proof_key)
    bad = world.prove(ch, manager, vid, "share", raw, current_key=ec.generate_private_key(ec.SECP384R1()))
    err = world.refused(GRANT, manager, FakeRequest(raw, bad), vault_id=str(vid),
                        request=E.GrantMemberKeyRequest(**body))
    assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")
    assert _rows_for(world, vid, target) == 0


# ------------------------------------------------------------------------------------- rotations

def test_a_proven_direct_rotation_stores_the_new_epochs_material(world):
    vid, owner, manager, proof_key = world.direct_vault()
    new_key, material = _direct_material()
    body = _rekey_body(owner, manager, material)
    raw = _serialize(body)
    ch = world.challenge(manager, vid, "rekey")
    header = world.prove(ch, manager, vid, "rekey", raw, current_key=proof_key,
                         new_pem=material["public_key"], new_key=new_key)
    out = world.call(REKEY, manager, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**body))
    assert out["dek_version"] == 2
    rows = world.proof_rows(vid)
    assert rows[2] == ("rotate", material["public_key"], body["lineage_tag"])
    assert [d["proof"] for a, d in world.audit if a == "zk_vault_rekeyed"] == ["key"]

    # The next change at epoch 2 proves with the new proof key; the old one no longer does.
    target = world.new_person()
    body2 = _share_body(target, epoch=2)
    raw2 = _serialize(body2)
    for key, expected in ((proof_key, 403), (new_key, 200)):
        ch2 = world.challenge(manager, vid, "share")
        h2 = world.prove(ch2, manager, vid, "share", raw2, current_key=key)
        if expected == 200:
            assert world.call(GRANT, manager, FakeRequest(raw2, h2), vault_id=str(vid),
                              request=E.GrantMemberKeyRequest(**body2))["key_version"] == 2
        else:
            err = world.refused(GRANT, manager, FakeRequest(raw2, h2), vault_id=str(vid),
                                request=E.GrantMemberKeyRequest(**body2))
            assert err.status_code == expected


def _team_body(owner, manager, new_team_pem, frm=1):
    return {"from_version": frm, "to_version": frm + 1,
            "member_keys": [{"user_id": str(u), "wrapped_dek": "tp", "ephemeral_public_key": "e"}
                            for u in (owner, manager)],
            "team_public_key": new_team_pem, "team_dek_wrapped": _b64(b"wrap" * 8),
            "team_dek_ephemeral_public_key": "e", "lineage_tag": _b64(os.urandom(32))}


def test_a_proven_team_rotation_makes_the_new_team_key_the_verifier(world):
    vid, owner, manager, team = world.hier_vault()
    new_team = ec.generate_private_key(ec.SECP384R1())
    body = _team_body(owner, manager, ref.public_pem(new_team))
    raw = _serialize(body)
    ch = world.challenge(owner, vid, "rekey")
    header = world.prove(ch, owner, vid, "rekey", raw, current_key=team,
                         new_pem=body["team_public_key"], new_key=new_team)
    out = world.call(REKEY, owner, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**body))
    assert (out["dek_version"], out["team_key_version"]) == (2, 2)
    assert world.proof_rows(vid)[2] == ("rotate", None, body["lineage_tag"])
    # The old team key no longer proves anything; the new one does.
    target = world.new_person()
    body2 = {"user_id": str(target), "wrapped_team_privkey": "w", "team_ephemeral_public_key": "e"}
    raw2 = _serialize(body2)
    for key, ok in ((team, False), (new_team, True)):
        ch2 = world.challenge(owner, vid, "share")
        h2 = world.prove(ch2, owner, vid, "share", raw2, current_key=key)
        if ok:
            assert world.call(GRANT, owner, FakeRequest(raw2, h2), vault_id=str(vid),
                              request=E.GrantMemberKeyRequest(**body2))["key_version"] == 2
        else:
            err = world.refused(GRANT, owner, FakeRequest(raw2, h2), vault_id=str(vid),
                                request=E.GrantMemberKeyRequest(**body2))
            assert (err.status_code, err.reason) == (403, "zk-key-proof-failed")


def test_a_team_rotation_that_reinstalls_the_current_team_key_is_refused(world):
    """Compared as points, not PEM text: a re-encoded copy of the current key is the same key, and a
    rotation to it would leave every removed member holding the team private key."""
    for enforce in (True, False):
        world.enforce(enforce)
        vid, owner, manager, team = world.hier_vault()
        der = team.public_key().public_bytes(serialization.Encoding.DER,
                                             serialization.PublicFormat.SubjectPublicKeyInfo)
        b64 = base64.b64encode(der).decode()
        reencoded = "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b64[i:i + 32] for i in range(0, len(b64), 32)) \
            + "\n-----END PUBLIC KEY-----\n"
        assert reencoded != ref.public_pem(team) and ref.point(reencoded) == ref.point(ref.public_pem(team))
        body = _team_body(owner, manager, reencoded)
        raw = _serialize(body)
        header = None
        if enforce:
            ch = world.challenge(owner, vid, "rekey")
            header = world.prove(ch, owner, vid, "rekey", raw, current_key=team, new_pem=reencoded, new_key=team)
        err = world.refused(REKEY, owner, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**body))
        assert (err.status_code, err.reason) == (400, "zk-key-proof-malformed")
        assert world.dek_version(vid) == 1


def test_a_team_key_that_is_not_a_p384_key_is_refused_before_anything_is_consumed(world):
    vid, owner, manager, team = world.hier_vault()
    ch = world.challenge(owner, vid, "rekey")
    other_curve = ec.generate_private_key(ec.SECP256R1())
    for bad in ("TEAMPUB", ref.public_pem(other_curve)):
        body = _team_body(owner, manager, bad)
        raw = _serialize(body)
        header = world.prove(ch, owner, vid, "rekey", raw, current_key=team)
        err = world.refused(REKEY, owner, FakeRequest(raw, header), vault_id=str(vid), request=E.RekeyRequest(**body))
        assert (err.status_code, err.reason) == (400, "zk-key-proof-malformed")
    assert world.challenges_left() == 1


def test_a_proven_index_key_mint_passes(world):
    vid, owner, manager, proof_key = world.direct_vault()
    body = {"wraps": [{"user_id": str(u), "encrypted_index_key": "k", "ephemeral_public_key": "e"}
                      for u in (owner, manager)]}
    raw = _serialize(body)
    ch = world.challenge(owner, vid, "index_key")
    header = world.prove(ch, owner, vid, "index_key", raw, current_key=proof_key)
    out = world.call(PUT_INDEX_KEY, owner, FakeRequest(raw, header), vault_id=str(vid), body=E.IndexKeyPut(**body))
    assert out["wraps"] == 2
    assert [d["proof"] for a, d in world.audit if a == "zk_index_key_wrapped"] == ["key"]
