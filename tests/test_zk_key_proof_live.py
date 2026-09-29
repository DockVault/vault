"""The key proof, live: changes to a zero-knowledge vault's keys need proof of the keys, not just an account.

Creating a zero-knowledge vault, sharing one, rotating its key and setting its name-index key each carry a
proof over one server challenge and the exact request body (tests/zk_proof_harness.py makes them the way the
web client does). This file drives those routes on a running deployment, which enforces proofs by default:

* a session without the account's identity key -- an account taken over, a stolen session -- changes no key,
  whatever else it holds, and each refusal is recorded;
* someone who knows the vault's key but not the key holder's identity key gets nowhere either;
* a proof authorizes exactly one request: a replay, or the same proof with any other body, is refused;
* a request that waited for the vault row lock while the key changed is told to prepare again;
* a rotation installs the new epoch's verifier, and the old one stops working;
* a create is proved before anything is built.

The handler-level rules (roles, shapes, the switch) are in test_zk_key_proof_handler.py.
"""
import base64
import concurrent.futures
import contextlib
import json
import os
import subprocess
import time
import uuid

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import zk_proof_harness as harness
from conftest import (
    ApiClient, ZK_ENC_NAME_STUB, ZK_EPHEMERAL_STUB, ZK_WRAPPED_DEK_STUB, create_zk_vault, ensure_ecc_keypair,
    post_zk, put_zk, team_public_key, unique,
)

pytestmark = pytest.mark.integration

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
FAILED = "zk-key-proof-failed"


def _psql(sql: str) -> str:
    result = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return (result.stdout or "").strip()


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


@pytest.fixture
def people(admin):
    """Make users on demand, each signed in and with a registered (derived) identity key; deleted after."""
    made = []

    def make(prefix="kp"):
        user = admin.create_user(username=unique(prefix))
        client = ApiClient()
        client.login(user["_username"], user["_password"])
        ensure_ecc_keypair(client)
        made.append(user)
        return user, client

    yield make
    for user in made:
        admin.delete_user(user["id"])


def _wrap(user_id):
    return {"user_id": str(user_id), "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}


def _index_wrap(user_id):
    return {"user_id": str(user_id), "encrypted_index_key": ZK_WRAPPED_DEK_STUB,
            "ephemeral_public_key": ZK_EPHEMERAL_STUB}


def _share_body(user_id):
    return {"user_id": str(user_id), "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}


def _rotation(frm, *remaining):
    return {"from_version": frm, "to_version": frm + 1, "member_keys": [_wrap(u) for u in remaining]}


def _state(vid):
    """What a refused change must leave exactly as it was."""
    return _psql(
        f"SELECT v.dek_version, v.team_key_version, coalesce(md5(v.team_public_key), '-'), "
        f"(SELECT count(*) FROM vault_member_keys k WHERE k.vault_id = v.id), "
        f"(SELECT count(*) FROM vault_member_index_keys i WHERE i.vault_id = v.id), "
        f"(SELECT count(*) FROM vault_key_proofs p WHERE p.vault_id = v.id) FROM vaults v WHERE v.id = '{vid}'")


def _failures(resource_id):
    return _psql("SELECT coalesce(string_agg(details->>'reason', ',' ORDER BY timestamp), '') FROM audit_logs "
                 f"WHERE action = 'zk_key_proof_failed' AND resource_id = '{resource_id}'")


def _refused(r, status=403, reason=FAILED):
    assert r.status_code == status, r.text
    assert r.json()["reason"] == reason, r.text
    return r


def _foreign():
    return ec.generate_private_key(ec.SECP384R1())


def _direct_vault(client, admin):
    with _zk_enabled(admin):
        return create_zk_vault(client)["id"]


def _team_vault(client, admin, team_pem=None):
    with _zk_enabled(admin):
        r = post_zk(client, "/vaults", json={
            "name": unique("kpteam"), "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB,
            "name_key_version": 1, "key_wrapping_mode": "hierarchical",
            "team_public_key": team_pem or team_public_key(), "team_wrapped_dek": ZK_WRAPPED_DEK_STUB,
            "team_dek_ephemeral_public_key": ZK_EPHEMERAL_STUB, "wrapped_team_privkey": ZK_WRAPPED_DEK_STUB,
            "team_privkey_ephemeral_public_key": ZK_EPHEMERAL_STUB,
        })
    assert r.status_code == 200, r.text
    return r.json()["id"]


def _create_body():
    return {"name": unique("kpnew"), "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB,
            "name_key_version": 1, "wrapped_dek": ZK_WRAPPED_DEK_STUB, "ephemeral_public_key": ZK_EPHEMERAL_STUB}


# ------------------------------------------------------------------------------ taken-over accounts

def test_a_session_without_the_identity_key_changes_no_key(admin, people):
    """An administrator who reset a key holder's password, or anyone with their session, acts as that
    account but does not have its identity private key. Even given every other key, each of the four
    changes is refused and recorded, and without a proof at all each one gets 428."""
    owner, oc = people("kpvic")
    target, _ = people("kptgt")
    vid = _direct_vault(oc, admin)
    try:
        before = _state(vid)
        foreign = {"identity": _foreign()}
        _refused(post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(target["id"]), roles=foreign))
        _refused(post_zk(oc, f"/ecc/vaults/{vid}/rekey", json=_rotation(1, owner["id"]), roles=foreign))
        _refused(put_zk(oc, f"/ecc/vaults/{vid}/index-key", json={"wraps": [_index_wrap(owner["id"])]}, roles=foreign))
        assert _state(vid) == before, "a change was stored from a session without the identity key"
        assert _failures(vid) == "identity,identity,identity"

        new_id = str(uuid.uuid4())
        with _zk_enabled(admin):
            _refused(post_zk(oc, "/vaults", json=dict(_create_body(), id=new_id), roles=foreign))
            assert _psql(f"SELECT count(*) FROM vaults WHERE id = '{new_id}'") == "0"
            assert _failures(new_id) == "identity"

            # No proof at all: 428, with a plain sentence and nobody signed out.
            for path, body, method in ((f"/ecc/vaults/{vid}/members", _share_body(target["id"]), "POST"),
                                       (f"/ecc/vaults/{vid}/rekey", _rotation(1, owner["id"]), "POST"),
                                       (f"/ecc/vaults/{vid}/index-key", {"wraps": [_index_wrap(owner["id"])]}, "PUT"),
                                       ("/vaults", dict(_create_body(), id=str(uuid.uuid4())), "POST")):
                prepared = harness.prepare_zk(oc, path, body, method=method)
                r = _refused(harness.send_prepared(oc, path, prepared, method=method, header=None), 428,
                             "zk-key-proof-required")
                assert isinstance(r.json()["detail"], str)
        assert _state(vid) == before
        assert oc.get("/ecc/keys/public").status_code == 200, "a refusal signed the person out"
    finally:
        oc.delete_vault(vid)


def test_knowing_the_key_is_not_enough_without_the_holders_identity(admin, people):
    """A member removed without a rotation still knows the vault's key and its proof key. Through a key
    holder's session they lack that holder's identity key; through their own they hold no current key."""
    owner, oc = people("kpown")
    removed, rc = people("kprem")
    vid = _direct_vault(oc, admin)
    try:
        post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(removed["id"])).raise_for_status()
        oc.post(f"/vaults/{vid}/permissions", json={"user_id": removed["id"], "level": "manage"}).raise_for_status()
        # Removed from the keys without a rotation (the key holder is told a rotation is owed).
        assert oc.delete(f"/ecc/vaults/{vid}/members/{removed['id']}").status_code == 200
        before = _state(vid)
        as_removed = {"identity": harness.identity_private_key(removed["_username"])}
        _refused(post_zk(oc, f"/ecc/vaults/{vid}/rekey", json=_rotation(1, owner["id"]), roles=as_removed))
        # Their own session gets no challenge (they hold no current key), so no proof can be made.
        r = rc.post(f"/ecc/vaults/{vid}/key-proof/challenge", json={"op": "rekey"})
        assert r.status_code == 403 and "holds this vault's key" in r.json()["detail"], r.text
        assert post_zk(rc, f"/ecc/vaults/{vid}/rekey", json=_rotation(1, owner["id"])).status_code == 428
        assert _state(vid) == before
    finally:
        oc.delete_vault(vid)


# -------------------------------------------------------------------------------- one request only

def test_a_proof_authorizes_exactly_one_request(admin, people):
    owner, oc = people("kpone")
    target, _ = people("kptg1")
    other, _ = people("kptg2")
    vid = _direct_vault(oc, admin)
    other_vid = _direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/members"
    try:
        prepared = harness.prepare_zk(oc, path, _share_body(target["id"]))
        assert harness.send_prepared(oc, path, prepared).status_code == 200
        # Replayed byte for byte: its challenge is gone.
        _refused(harness.send_prepared(oc, path, prepared))

        # The same proof with any other body: another recipient, or a field the server ignores.
        for edit in ({"user_id": target["id"]}, {"note": "ignored by the model"}):
            prepared = harness.prepare_zk(oc, path, _share_body(other["id"]))
            body = dict(json.loads(prepared["raw"]), **edit)
            _refused(harness.send_prepared(oc, path, dict(prepared, raw=harness.serialize(body))))
        assert _psql(f"SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vid}' "
                     f"AND user_id = '{other['id']}'") == "0"

        # A challenge for another vault, another operation, or another person is not this request's.
        for ch_vault, op, client in ((other_vid, "share", oc), (vid, "index_key", oc)):
            ch = client.post(f"/ecc/vaults/{ch_vault}/key-proof/challenge", json={"op": op}).json()
            raw, header = harness._prove(client, "share", vid, ch, _share_body(other["id"]))
            _refused(harness.send_prepared(oc, path, {"raw": raw, "header": header, "challenge_status": 200}))
        stranger, sc = people("kpstr")
        own_vault = _direct_vault(sc, admin)
        ch = sc.post(f"/ecc/vaults/{own_vault}/key-proof/challenge", json={"op": "share"}).json()
        raw, header = harness._prove(oc, "share", vid, ch, _share_body(other["id"]))
        _refused(harness.send_prepared(oc, path, {"raw": raw, "header": header, "challenge_status": 200}))
        sc.delete_vault(own_vault)
        assert _psql(f"SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vid}' "
                     f"AND user_id = '{other['id']}'") == "0"
    finally:
        oc.delete_vault(vid)
        oc.delete_vault(other_vid)


def test_the_proof_covers_the_exact_bytes_sent_through_the_whole_stack(admin, people):
    """The server hashes the body exactly as it arrives, after every middleware. A body with unusual but
    valid JSON -- spacing, escaped characters, keys in another order -- proves as sent."""
    owner, oc = people("kpraw")
    target, _ = people("kprtg")
    vid = _direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/members"
    try:
        ch = oc.post(f"/ecc/vaults/{vid}/key-proof/challenge", json={"op": "share"}).json()
        body = {"ephemeral_public_key": ZK_EPHEMERAL_STUB, "user_id": target["id"], "dek_version": 1,
                "wrapped_dek": ZK_WRAPPED_DEK_STUB, "label": "café ☃"}
        raw = json.dumps(body, indent=3, ensure_ascii=True).replace("\n", "\r\n")
        # Prove over exactly these bytes.
        digest_raw = raw
        identity = harness.identity_key_for(oc)
        verifier = ch["verifier"]["public_key"]
        digest = harness.reference.transcript(
            op="share", challenge_id=ch["challenge_id"], nonce_b64=ch["nonce"], user_id=harness.client_user_id(oc),
            vault_id=vid, mode="direct", dek_epoch=1, team_epoch=1, identity_pem=harness.public_pem(identity),
            current_pem=verifier, new_pem=None, body=digest_raw.encode("utf-8"))
        server = ch["server_ephemeral_public_key"]
        header = harness.reference.proof_header(
            ch["challenge_id"], harness.reference.role_mac("identity", identity, server, digest),
            harness.reference.role_mac("current-key", harness.private_key_for(verifier), server, digest), None)
        r = oc.post(path, data=raw.encode("utf-8"),
                    headers={"Content-Type": "application/json", harness.PROOF_HEADER: header})
        assert r.status_code == 200, r.text
    finally:
        oc.delete_vault(vid)


# -------------------------------------------------------------------------------------- the lock

_HOLD = 4


def _hold_vault_row(vid, before_commit=""):
    sql = (f"BEGIN; SELECT id FROM vaults WHERE id='{vid}' FOR KEY SHARE; "
           f"SELECT pg_sleep({_HOLD}); {before_commit} COMMIT;")
    holder = subprocess.Popen(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db",
                               "-v", "ON_ERROR_STOP=1", "-tAc", sql],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    time.sleep(1.0)
    return holder


def _rotate_from_outside(vid, owner_id, proof_pem):
    """SQL that moves the vault to epoch 2 as a rotation elsewhere would, with a proof key the harness holds."""
    sealed = base64.b64encode(b"DVZ2\x02\x07\x00\x00" + os.urandom(60)).decode()
    check = base64.b64encode(os.urandom(32)).decode()
    return (f"UPDATE vaults SET dek_version = 2 WHERE id = '{vid}'; "
            "INSERT INTO vault_member_keys (id, vault_id, user_id, encrypted_dek, ephemeral_public_key, "
            f"wrapping_algorithm, key_version, is_active, granted_at) SELECT gen_random_uuid(), '{vid}', "
            f"'{owner_id}', 'w', 'e', wrapping_algorithm, 2, true, now() FROM vault_member_keys "
            f"WHERE vault_id = '{vid}' AND user_id = '{owner_id}' AND key_version = 1; "
            "INSERT INTO vault_key_proofs (id, vault_id, dek_epoch, format, proof_public_key, sealed_private_key, "
            f"dek_check, source, created_at) VALUES (gen_random_uuid(), '{vid}', 2, 1, '{proof_pem}', "
            f"'{sealed}', '{check}', 'rotate', now());")


def test_a_change_that_waited_while_the_key_changed_is_told_to_prepare_again(admin, people):
    owner, oc = people("kprace")
    target, _ = people("kprt")
    vid = _direct_vault(oc, admin)
    try:
        share_path, index_path = f"/ecc/vaults/{vid}/members", f"/ecc/vaults/{vid}/index-key"
        share = harness.prepare_zk(oc, share_path, _share_body(target["id"]))
        index = harness.prepare_zk(oc, index_path, {"wraps": [_index_wrap(owner["id"])]}, method="PUT")
        proof_pem = harness.public_pem(harness.new_private_key())
        holder = _hold_vault_row(vid, _rotate_from_outside(vid, owner["id"], proof_pem))
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                a = pool.submit(harness.send_prepared, oc, share_path, share)
                b = pool.submit(harness.send_prepared, oc, index_path, index, method="PUT")
                results = (a.result(), b.result())
        finally:
            holder.wait(timeout=_HOLD + 10)
        assert holder.returncode == 0
        for r in results:
            _refused(r, 409, "zk-key-proof-stale")
        # Prepared again against the new state, both go through.
        assert post_zk(oc, share_path, json=_share_body(target["id"])).status_code == 200
        assert put_zk(oc, index_path, json={"wraps": [_index_wrap(owner["id"])]}).status_code == 200
    finally:
        oc.delete_vault(vid)


def test_two_rotations_at_once_one_wins_and_nothing_is_half_written(admin, people):
    owner, oc = people("kptwo")
    vid = _direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/rekey"
    try:
        first = harness.prepare_zk(oc, path, _rotation(1, owner["id"]))
        second = harness.prepare_zk(oc, path, _rotation(1, owner["id"]))
        holder = _hold_vault_row(vid)
        try:
            with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                futures = [pool.submit(harness.send_prepared, oc, path, p) for p in (first, second)]
                codes = sorted(f.result().status_code for f in futures)
        finally:
            holder.wait(timeout=_HOLD + 10)
        assert codes == [200, 409], codes
        assert _psql(f"SELECT dek_version FROM vaults WHERE id = '{vid}'") == "2"
        assert _psql(f"SELECT count(*) FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 2") == "1"
        assert _psql(f"SELECT count(*) FROM vault_member_keys WHERE vault_id = '{vid}' AND key_version = 2") == "1"
    finally:
        oc.delete_vault(vid)


# -------------------------------------------------------------------------------------- rotations

def test_a_rotation_installs_the_new_epochs_verifier_and_the_old_one_stops_working(admin, people):
    owner, oc = people("kprot")
    target, _ = people("kprtt")
    vid = _direct_vault(oc, admin)
    try:
        old_pem = _psql(f"SELECT proof_public_key FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 1")
        r = post_zk(oc, f"/ecc/vaults/{vid}/rekey", json=_rotation(1, owner["id"]))
        assert r.status_code == 200, r.text
        source, tag = _psql(f"SELECT source, coalesce(lineage_tag, '-') FROM vault_key_proofs "
                            f"WHERE vault_id = '{vid}' AND dek_epoch = 2").split("|")
        assert source == "rotate" and len(base64.b64decode(tag)) == 32
        assert _psql("SELECT details->>'proof' FROM audit_logs WHERE action = 'zk_vault_rekeyed' "
                     f"AND resource_id = '{vid}'") == "key"
        # The old proof key no longer proves the current key; the new one does.
        _refused(post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(target["id"]),
                         roles={"current": harness.private_key_for(old_pem)}))
        r = post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(target["id"]))
        assert r.status_code == 200 and r.json()["key_version"] == 2, r.text
        assert _psql("SELECT details->>'proof' FROM audit_logs WHERE action = 'zk_member_key_granted' "
                     f"AND resource_id = '{vid}' ORDER BY timestamp DESC LIMIT 1") == "key"
    finally:
        oc.delete_vault(vid)


def _team_rotation(owner_id, new_team_pem, frm=1):
    return {"from_version": frm, "to_version": frm + 1, "member_keys": [_wrap(owner_id)],
            "team_public_key": new_team_pem, "team_dek_wrapped": ZK_WRAPPED_DEK_STUB,
            "team_dek_ephemeral_public_key": ZK_EPHEMERAL_STUB}


def test_a_team_rotation_makes_the_new_team_key_the_verifier(admin, people):
    owner, oc = people("kptr")
    target, _ = people("kptrt")
    old_team = harness.new_private_key()
    vid = _team_vault(oc, admin, harness.public_pem(old_team))
    path = f"/ecc/vaults/{vid}/rekey"
    try:
        before = _state(vid)
        # The new-key proof must be for the key the body installs.
        _refused(post_zk(oc, path, json=_team_rotation(owner["id"], team_public_key()),
                         roles={"new": _foreign()}))
        # A team key that is not a P-384 key, or the current key re-encoded, is refused.
        for bad in ("TEAMPUB", _reencoded(old_team)):
            r = post_zk(oc, path, json=_team_rotation(owner["id"], bad))
            assert r.status_code == 400 and r.json()["reason"] == "zk-key-proof-malformed", r.text
        assert _state(vid) == before

        new_pem = team_public_key()
        r = post_zk(oc, path, json=_team_rotation(owner["id"], new_pem))
        assert r.status_code == 200 and r.json()["team_key_version"] == 2, r.text
        assert _psql(f"SELECT source || '|' || coalesce(proof_public_key, '-') FROM vault_key_proofs "
                     f"WHERE vault_id = '{vid}' AND dek_epoch = 2") == "rotate|-"
        share = {"user_id": target["id"], "wrapped_team_privkey": ZK_WRAPPED_DEK_STUB,
                 "team_ephemeral_public_key": ZK_EPHEMERAL_STUB}
        _refused(post_zk(oc, f"/ecc/vaults/{vid}/members", json=share, roles={"current": old_team}))
        assert post_zk(oc, f"/ecc/vaults/{vid}/members", json=share).status_code == 200
    finally:
        oc.delete_vault(vid)


def _reencoded(key):
    """The same public key as PEM with other line breaks: other text, the same point."""
    der = key.public_key().public_bytes(serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo)
    b64 = base64.b64encode(der).decode()
    return "-----BEGIN PUBLIC KEY-----\n" + "\n".join(b64[i:i + 40] for i in range(0, len(b64), 40)) \
        + "\n-----END PUBLIC KEY-----\n"


# ----------------------------------------------------------------------------------------- create

def test_a_create_is_proved_before_anything_is_built(admin, people):
    owner, oc = people("kpcr")
    with _zk_enabled(admin):
        # With a proof: the vault and its first epoch's proof row.
        vid = create_zk_vault(oc)["id"]
        try:
            assert _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 1") == "create"
        finally:
            oc.delete_vault(vid)

        # A proof made for another vault id is not this create's.
        body = dict(_create_body(), id=str(uuid.uuid4()))
        prepared = harness.prepare_zk(oc, "/vaults", body)
        moved = dict(json.loads(prepared["raw"]), id=str(uuid.uuid4()))
        _refused(harness.send_prepared(oc, "/vaults", dict(prepared, raw=harness.serialize(moved))))
        assert _psql(f"SELECT count(*) FROM vaults WHERE id IN ('{body['id']}', '{moved['id']}')") == "0"

        # A body in another mode than its challenge was issued for.
        team_body = {"name": unique("kpcrt"), "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB,
                     "name_key_version": 1, "key_wrapping_mode": "hierarchical", "team_public_key": team_public_key(),
                     "team_wrapped_dek": ZK_WRAPPED_DEK_STUB, "team_dek_ephemeral_public_key": ZK_EPHEMERAL_STUB,
                     "wrapped_team_privkey": ZK_WRAPPED_DEK_STUB,
                     "team_privkey_ephemeral_public_key": ZK_EPHEMERAL_STUB, "id": str(uuid.uuid4())}
        ch = oc.post(f"/ecc/vaults/{team_body['id']}/key-proof/challenge", json={"op": "create"}).json()
        assert ch["mode"] == "direct"
        raw, header = harness._prove(oc, "create", team_body["id"], ch, team_body)
        _refused(harness.send_prepared(oc, "/vaults", {"raw": raw, "header": header, "challenge_status": 200}),
                 409, "zk-key-proof-stale")
        assert _psql(f"SELECT count(*) FROM vaults WHERE id = '{team_body['id']}'") == "0"

        # A proven create names its vault id.
        ch_vault = str(uuid.uuid4())
        ch = oc.post(f"/ecc/vaults/{ch_vault}/key-proof/challenge", json={"op": "create"}).json()
        raw, header = harness._prove(oc, "create", ch_vault, ch, _create_body(), augment=False)
        r = harness.send_prepared(oc, "/vaults", {"raw": raw, "header": header, "challenge_status": 200})
        assert r.status_code == 400 and r.json()["reason"] == "zk-key-proof-malformed", r.text
        assert _psql(f"SELECT count(*) FROM zk_key_proof_challenges WHERE id = '{ch['challenge_id']}'") == "1", \
            "a malformed create consumed its challenge"


# ------------------------------------------------------------------------------------- bootstrap

def _legacy_direct_vault(client, admin):
    """A direct vault as one made before key proofs existed: its epoch has no proof key."""
    vid = _direct_vault(client, admin)
    _psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{vid}'")
    return vid


def _bootstrap_body(vid, epoch=1):
    _, material = harness.direct_proof_material(vid, epoch)
    return dict({"dek_epoch": epoch}, **material)


def test_a_legacy_epoch_is_set_up_once_by_a_manager_who_holds_its_key(admin, people):
    owner, oc = people("kpbo")
    target, _ = people("kpbt")
    vid = _legacy_direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/key-proof"
    try:
        # Until it is set up, a change that proves the current key cannot run.
        _refused(post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(target["id"])), 428,
                 "zk-key-proof-setup-required")
        body = _bootstrap_body(vid)
        first = harness.prepare_zk(oc, path, body, method="PUT")
        retry = harness.prepare_zk(oc, path, body, method="PUT")
        r = harness.send_prepared(oc, path, first, method="PUT")
        assert r.status_code == 200 and "unchanged" not in r.json(), r.text
        assert _psql(f"SELECT source || '|' || created_by FROM vault_key_proofs WHERE vault_id = '{vid}'") \
            == f"bootstrap|{owner['id']}"
        assert _psql("SELECT details->>'dek_epoch' FROM audit_logs WHERE action = 'zk_key_proof_bootstrapped' "
                     f"AND resource_id = '{vid}'") == "1"
        # The same material again from the same person, on a challenge taken before it was set up: a retry.
        r = harness.send_prepared(oc, path, retry, method="PUT")
        assert r.status_code == 200 and r.json()["unchanged"] is True, r.text
        # A new attempt is refused already at the challenge: the epoch has its row, and rows never change.
        r = put_zk(oc, path, json=_bootstrap_body(vid))
        assert r.zk_challenge_status == 409 and r.zk_challenge_refusal["reason"] == "zk-key-proof-exists"
        assert _psql(f"SELECT count(*) FROM vault_key_proofs WHERE vault_id = '{vid}'") == "1"
        # And the change that needed it now runs.
        assert post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(target["id"])).status_code == 200
    finally:
        oc.delete_vault(vid)


def test_bootstrap_is_refused_to_everyone_else(admin, people):
    owner, oc = people("kpbr")
    member, mc = people("kpbm")
    keyless, kc = people("kpbk")
    vid = _direct_vault(oc, admin)
    team_vid = _team_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/key-proof"
    try:
        post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(member["id"])).raise_for_status()
        oc.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "read"}).raise_for_status()
        oc.post(f"/vaults/{vid}/permissions", json={"user_id": keyless["id"], "level": "manage"}).raise_for_status()
        _psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{vid}'")   # as a vault made before key proofs
        # A plain member who holds the key.
        r = put_zk(mc, path, json=_bootstrap_body(vid))
        assert r.status_code == 403 and "manager" in r.json()["detail"], r.text
        # A manager who holds no key: no challenge, so no proof, and bootstrap exists only with one.
        r = put_zk(kc, path, json=_bootstrap_body(vid))
        assert r.zk_challenge_status == 403 and "holds this vault's key" in r.zk_challenge_refusal["detail"]
        _refused(r, 428, "zk-key-proof-required")
        # The owner, proving with a key that is not their identity key.
        _refused(put_zk(oc, path, json=_bootstrap_body(vid), roles={"identity": _foreign()}))
        # A temporary session, even of the owner's own account.
        cred = oc.post("/auth/temp-credentials", json={"note": unique("kpbtemp")}).json()
        temp = oc.clone_anonymous()
        temp.login(cred["temp_username"], cred["credential"])
        r = temp.put(path, json=_bootstrap_body(vid))
        assert r.status_code == 403, r.text
        # A team vault: its team public key is its verifier.
        r = put_zk(oc, f"/ecc/vaults/{team_vid}/key-proof", json=_bootstrap_body(team_vid))
        assert r.status_code == 400 and r.json()["reason"] == "zk-key-proof-malformed", r.text
        assert _psql(f"SELECT count(*) FROM vault_key_proofs WHERE vault_id = '{vid}'") == "0"
        assert _failures(vid) == "identity"
    finally:
        oc.delete_vault(vid)
        oc.delete_vault(team_vid)


def test_two_bootstraps_at_once_leave_exactly_one_row(admin, people):
    owner, oc = people("kpb2")
    vid = _legacy_direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/key-proof"
    try:
        a = harness.prepare_zk(oc, path, _bootstrap_body(vid), method="PUT")
        b = harness.prepare_zk(oc, path, _bootstrap_body(vid), method="PUT")
        with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
            codes = sorted(f.result().status_code for f in
                           [pool.submit(harness.send_prepared, oc, path, p, method="PUT") for p in (a, b)])
        assert codes == [200, 409], codes
        assert _psql(f"SELECT count(*) FROM vault_key_proofs WHERE vault_id = '{vid}'") == "1"
    finally:
        oc.delete_vault(vid)


# ----------------------------------------------------------------------------------- owner reset

def _damage(vid):
    """Replace the current epoch's proof key with one nobody holds, as a bad client or a database edit
    would: no current-key proof can pass any more."""
    stray = ec.generate_private_key(ec.SECP384R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    _psql(f"UPDATE vault_key_proofs SET proof_public_key = '{stray}' WHERE vault_id = '{vid}'")


def _reset(frm, *remaining):
    return dict(_rotation(frm, *remaining), owner_reset=True)


def test_the_owner_resets_damaged_key_material(admin, people):
    owner, oc = people("kpor")
    manager, gc = people("kporm")
    vid = _direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/rekey"
    try:
        post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(manager["id"])).raise_for_status()
        oc.post(f"/vaults/{vid}/permissions", json={"user_id": manager["id"], "level": "manage"}).raise_for_status()
        _damage(vid)
        # Nobody can rotate normally now.
        _refused(post_zk(oc, path, json=_rotation(1, owner["id"], manager["id"])))
        # A manager may not reset: only the owner gets a challenge for it.
        r = post_zk(gc, path, json=_reset(1, owner["id"], manager["id"]))
        assert r.zk_challenge_status == 403 and "owner" in r.zk_challenge_refusal["detail"]
        _refused(r, 428, "zk-key-proof-required")
        # The owner without their identity key.
        _refused(post_zk(oc, path, json=_reset(1, owner["id"], manager["id"]), roles={"identity": _foreign()}))
        assert _psql(f"SELECT dek_version FROM vaults WHERE id = '{vid}'") == "1"

        r = post_zk(oc, path, json=_reset(1, owner["id"], manager["id"]))
        assert r.status_code == 200 and r.json()["dek_version"] == 2, r.text
        assert _psql(f"SELECT source FROM vault_key_proofs WHERE vault_id = '{vid}' AND dek_epoch = 2") \
            == "owner_reset"
        assert _psql("SELECT details->>'dek_epoch' FROM audit_logs WHERE action = 'zk_owner_key_reset' "
                     f"AND resource_id = '{vid}'") == "2"
        assert _psql("SELECT details->>'proof' FROM audit_logs WHERE action = 'zk_vault_rekeyed' "
                     f"AND resource_id = '{vid}'") == "owner_reset"
        # The vault works again: the next change proves the new epoch's key.
        assert post_zk(gc, path, json=_rotation(2, owner["id"], manager["id"])).status_code == 200
    finally:
        oc.delete_vault(vid)


def test_an_owner_reset_asks_for_the_owners_second_factor_first_whatever_the_matrix_says(admin, people):
    """The step-up is fixed, not a matrix action: every catalogued action but two ships off. It is asked
    for before the challenge is consumed, so the web app's retry after the prompt finds it."""
    from _sf_helpers import enroll_totp, step_up_receipt
    owner, oc = people("kpsu")
    vid = _direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/rekey"
    try:
        actions = admin.get("/second-factor/actions").json()["actions"]
        assert "vault.owner_key_reset" not in {a["key"] for a in actions}
        assert actions and not [a["key"] for a in actions if a["require_otp"] or a["require_password"]
                                if a["key"] not in ("login", "account.second_factor")], "a matrix toggle is on"
        _damage(vid)
        _, codes = enroll_totp(owner, oc)
        prepared = harness.prepare_zk(oc, path, _reset(1, owner["id"]))
        r = harness.send_prepared(oc, path, prepared)
        assert r.status_code == 403, r.text
        detail = r.json()["detail"]
        assert detail["second_factor_required"] is True and detail["action"] == "vault.owner_key_reset"
        assert "recovery" in detail["methods"]
        assert _psql("SELECT count(*) FROM zk_key_proof_challenges "
                     f"WHERE id = '{prepared['challenge']['challenge_id']}'") == "1", "consumed before the step-up"
        receipt = step_up_receipt(oc, action="vault.owner_key_reset", recovery_codes=codes)
        r = harness.send_prepared(oc, path, prepared, headers={"X-Second-Factor": receipt})
        assert r.status_code == 200 and r.json()["dek_version"] == 2, r.text
    finally:
        oc.delete_vault(vid)


def test_a_temporary_session_cannot_reset_a_key(admin, people):
    owner, oc = people("kptr")
    vid = _direct_vault(oc, admin)
    try:
        cred = oc.post("/auth/temp-credentials", json={"note": unique("kprtemp")}).json()
        temp = oc.clone_anonymous()
        temp.login(cred["temp_username"], cred["credential"])
        r = temp.post(f"/ecc/vaults/{vid}/key-proof/challenge", json={"op": "owner_reset"})
        assert r.status_code == 403 and r.json()["reason"] == "zk-key-proof-interactive-only", r.text
        path = f"/ecc/vaults/{vid}/rekey"   # sent as is: a temporary session cannot make a proof
        r = temp.post(path, data=harness.serialize(_reset(1, owner["id"])), headers={"Content-Type": "application/json"})
        assert r.status_code == 403 and r.json()["reason"] == "zk-key-proof-interactive-only", r.text
    finally:
        oc.delete_vault(vid)


# ------------------------------------------------------------------------------ read side, retire

def test_key_holders_see_the_epochs_proof_material_and_only_managers_get_the_sealed_key(admin, people):
    owner, oc = people("kprd")
    member, mc = people("kprdm")
    stranger, sc = people("kprds")
    vid = _direct_vault(oc, admin)
    team_vid = _team_vault(oc, admin)
    try:
        post_zk(oc, f"/ecc/vaults/{vid}/members", json=_share_body(member["id"])).raise_for_status()
        oc.post(f"/vaults/{vid}/permissions", json={"user_id": member["id"], "level": "read"}).raise_for_status()
        row = _psql(f"SELECT proof_public_key, sealed_private_key, dek_check FROM vault_key_proofs "
                    f"WHERE vault_id = '{vid}' AND dek_epoch = 1").split("|")

        mine = oc.get(f"/ecc/vaults/{vid}/keys").json()["key_proof"]
        assert (mine["state"], mine["source"], mine["lineage_tag"]) == ("set", "create", None)
        assert mine["public_key"].strip() == row[0].strip() and mine["dek_check"] == row[2]
        assert mine["sealed_private_key"] == row[1] and mine["created_at"]
        theirs = mc.get(f"/ecc/vaults/{vid}/keys").json()["key_proof"]
        assert "sealed_private_key" not in theirs, "a plain member was given the sealed proof key"
        assert (theirs["state"], theirs["public_key"], theirs["dek_check"]) == ("set", mine["public_key"], row[2])
        assert sc.get(f"/ecc/vaults/{vid}/keys").status_code == 403

        # An epoch with no row, and a team vault, whose verifier is its team key.
        _psql(f"DELETE FROM vault_key_proofs WHERE vault_id = '{vid}'")
        assert oc.get(f"/ecc/vaults/{vid}/keys").json()["key_proof"] == {"state": "missing"}
        assert oc.get(f"/ecc/vaults/{team_vid}/keys").json()["key_proof"] == {
            "state": "team", "source": "create", "lineage_tag": None}
    finally:
        oc.delete_vault(vid)
        oc.delete_vault(team_vid)


def test_retiring_old_epochs_prunes_their_proof_rows_and_never_the_current_one(admin, people):
    owner, oc = people("kpret")
    with _zk_enabled(admin):
        vid = create_zk_vault(oc, seal_name=False)["id"]
    try:
        for frm in (1, 2):
            assert post_zk(oc, f"/ecc/vaults/{vid}/rekey", json=_rotation(frm, owner["id"])).status_code == 200
        epochs = lambda: _psql(f"SELECT string_agg(dek_epoch::text, ',' ORDER BY dek_epoch) "
                               f"FROM vault_key_proofs WHERE vault_id = '{vid}'")
        assert epochs() == "1,2,3"
        # Something claims an epoch above the current one: the floor it sets must not take the current row.
        _psql(f"UPDATE vaults SET enc_name = '{ZK_ENC_NAME_STUB}', name_key_version = 99 WHERE id = '{vid}'")
        r = oc.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200 and r.json()["proof_rows_deleted"] == 2, r.text
        assert epochs() == "3"
    finally:
        oc.delete_vault(vid)



# -------------------------------------------------------------------------------------------- audit

def test_no_audit_row_holds_any_part_of_a_proof(admin, people):
    owner, oc = people("kpau")
    target, _ = people("kpaut")
    vid = _direct_vault(oc, admin)
    path = f"/ecc/vaults/{vid}/members"
    try:
        refused = harness.prepare_zk(oc, path, _share_body(target["id"]), roles={"identity": _foreign()})
        _refused(harness.send_prepared(oc, path, refused))
        accepted = harness.prepare_zk(oc, path, _share_body(target["id"]))
        assert harness.send_prepared(oc, path, accepted).status_code == 200
        rows = _psql(f"SELECT coalesce(details::text, '') FROM audit_logs WHERE resource_id = '{vid}'")
        assert rows, "expected this vault's audit rows"
        for prepared in (refused, accepted):
            _, cid, *macs = prepared["header"].split(".")
            for secret in [cid, prepared["challenge"]["nonce"], *[m for m in macs if m != "-"]]:
                assert secret not in rows, "an audit row holds part of a key proof"
        assert _psql("SELECT details->>'reason' FROM audit_logs WHERE action = 'zk_key_proof_failed' "
                     f"AND resource_id = '{vid}'") == "identity"
        assert _psql("SELECT details->>'proof' FROM audit_logs WHERE action = 'zk_member_key_granted' "
                     f"AND resource_id = '{vid}' ORDER BY timestamp DESC LIMIT 1") == "key"
    finally:
        oc.delete_vault(vid)
