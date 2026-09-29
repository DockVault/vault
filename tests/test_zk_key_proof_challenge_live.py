"""The key-proof challenge route, live: who gets a challenge, what it says, and how it is stored.

A challenge is the first half of every request that changes a zero-knowledge vault's keys. Only someone who
could make the change gets one; a stranger is refused the same way whether or not the vault exists; the
answer carries the vault's state the proof will be checked against; and the server's one-time key is
stored sealed.
"""
import base64
import concurrent.futures
import contextlib
import hashlib
import os
import subprocess
import uuid

from cryptography.hazmat.primitives import serialization

from conftest import (
    ApiClient, ZK_ENC_NAME_STUB, create_zk_vault, ensure_ecc_keypair, post_zk, team_public_key, unique,
)

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
NO_ACCESS = "No access to this vault's keys"


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


def _client_for(admin, prefix="kpch"):
    user = admin.create_user(username=unique(prefix))
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return user, c


def _challenge(client, vault_id, op, **extra):
    return client.post(f"/ecc/vaults/{vault_id}/key-proof/challenge", json={"op": op, **extra})


def _stub(prefix):
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _create_team_vault(client):
    r = post_zk(client, "/vaults", json={
        "name": unique("kpteam"), "type": "zero_knowledge", "enc_name": ZK_ENC_NAME_STUB, "name_key_version": 1,
        "key_wrapping_mode": "hierarchical", "team_public_key": team_public_key(),
        "team_wrapped_dek": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
        "wrapped_team_privkey": _stub("tpriv"), "team_privkey_ephemeral_public_key": _stub("tpeph"),
    })
    r.raise_for_status()
    return r.json()


def _point_sha256(pem: str) -> str:
    key = serialization.load_pem_public_key(pem.encode())
    return hashlib.sha256(key.public_bytes(serialization.Encoding.X962,
                                           serialization.PublicFormat.UncompressedPoint)).hexdigest()


def test_a_holder_gets_a_challenge_carrying_the_vaults_state(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        r = _challenge(admin, vid, "share")
        assert r.status_code == 200, r.text
        body = r.json()
        assert set(body) == {"challenge_id", "server_ephemeral_public_key", "nonce", "expires_in", "mode",
                             "dek_epoch", "team_epoch", "verifier"}
        uuid.UUID(body["challenge_id"])
        assert len(base64.b64decode(body["nonce"])) == 32
        assert body["expires_in"] == 300
        assert (body["mode"], body["dek_epoch"], body["team_epoch"], body["verifier"]) == ("direct", 1, 1, None)
        assert serialization.load_pem_public_key(body["server_ephemeral_public_key"].encode()).curve.name == "secp384r1"

        row = _psql("SELECT op, mode, dek_epoch, team_epoch, coalesce(verifier_sha256, '-'), vault_id, "
                    f"server_private_key_sealed FROM zk_key_proof_challenges WHERE id = '{body['challenge_id']}'")
        op, mode, de, te, vsha, rvid, sealed = row.split("|")
        assert (op, mode, de, te, vsha, rvid) == ("share", "direct", "1", "1", "-", vid)
        assert sealed.startswith("gAAAA") and "BEGIN" not in sealed, "the one-time key is stored sealed"
        # No row in the table holds a key in the clear.
        assert _psql("SELECT count(*) FROM zk_key_proof_challenges "
                     "WHERE server_private_key_sealed LIKE '%BEGIN%'") == "0"
    finally:
        admin.delete_vault(vid)


def test_a_direct_epochs_verifier_is_its_row_and_bootstrap_is_refused_once_it_has_one(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        assert _challenge(admin, vid, "bootstrap").status_code == 200, "no row yet: bootstrap may run"
        proof_key = team_public_key()      # any remembered P-384 key will do as the verifier
        sealed = base64.b64encode(b"DVZ2\x02\x07\x00\x00" + os.urandom(60)).decode()
        check = base64.b64encode(os.urandom(32)).decode()
        _psql("INSERT INTO vault_key_proofs (id, vault_id, dek_epoch, format, proof_public_key, sealed_private_key, "
              f"dek_check, source, created_at) VALUES ('{uuid.uuid4()}', '{vid}', 1, 1, '{proof_key}', '{sealed}', "
              f"'{check}', 'bootstrap', now())")
        r = _challenge(admin, vid, "share")
        assert r.status_code == 200, r.text
        assert r.json()["verifier"] == {"public_key": proof_key, "source": "bootstrap", "sealed_private_key": sealed,
                                        "dek_check": check, "lineage_tag": None}
        vsha = _psql(f"SELECT verifier_sha256 FROM zk_key_proof_challenges WHERE id = '{r.json()['challenge_id']}'")
        assert vsha == _point_sha256(proof_key)

        again = _challenge(admin, vid, "bootstrap")
        assert again.status_code == 409 and again.json()["reason"] == "zk-key-proof-exists", again.text
        reset = _challenge(admin, vid, "owner_reset")
        assert reset.status_code == 200 and reset.json()["verifier"]["public_key"] == proof_key
    finally:
        admin.delete_vault(vid)


def test_a_team_vault_names_its_team_key_and_never_its_private_material(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        v = _create_team_vault(admin)
    vid = v["id"]
    try:
        team_key = _psql(f"SELECT team_public_key FROM vaults WHERE id = '{vid}'")
        r = _challenge(admin, vid, "share")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["mode"] == "hierarchical"
        verifier = body["verifier"]
        assert set(verifier) == {"public_key", "source", "lineage_tag"}, "no sealed or private material"
        assert verifier["public_key"].strip() == team_key.strip()           # psql drops the final newline
        assert (verifier["source"], verifier["lineage_tag"]) == (None, None)
        boot = _challenge(admin, vid, "bootstrap")
        assert boot.status_code == 400 and boot.json()["reason"] == "zk-key-proof-malformed", boot.text

        # A stored team key that is not a P-384 key cannot be proved against, so no challenge that needs it
        # is issued; the owner can still get one to reset the key.
        _psql(f"UPDATE vaults SET team_public_key = 'TEAMPUB-legacy' WHERE id = '{vid}'")
        bad = _challenge(admin, vid, "share")
        assert bad.status_code == 409 and bad.json()["reason"] == "zk-key-proof-verifier-unusable", bad.text
        assert _challenge(admin, vid, "owner_reset").status_code == 200
    finally:
        admin.delete_vault(vid)


def _give_key(admin, vid, user, level):
    r = post_zk(admin, f"/ecc/vaults/{vid}/members", json={
        "user_id": user["id"], "wrapped_dek": _stub("w"), "ephemeral_public_key": _stub("e")})
    assert r.status_code == 200, r.text
    r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": user["id"], "level": level})
    assert r.status_code in (200, 201), r.text


def test_only_a_manager_who_holds_the_key_gets_one_and_a_stranger_learns_nothing(admin):
    ensure_ecc_keypair(admin)
    stranger, sc = _client_for(admin, "kpstr")
    member, mc = _client_for(admin, "kpmem")
    manager, gc = _client_for(admin, "kpmgr")
    keyless_manager, kc = _client_for(admin, "kpkml")
    owner, oc = _client_for(admin, "kpown")
    for c in (mc, gc, kc, oc):
        ensure_ecc_keypair(c)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
        other = create_zk_vault(oc)["id"]
    try:
        # A stranger: the same 403 for a real vault, one that does not exist, and a malformed id.
        for target in (vid, str(uuid.uuid4()), "not-a-vault"):
            r = _challenge(sc, target, "share")
            assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS, (target, r.text)

        # A plain member who holds the key but does not manage the vault.
        _give_key(admin, vid, member, "read")
        r = _challenge(mc, vid, "share")
        assert r.status_code == 403 and "manager" in r.json()["detail"], r.text

        # An administrator with no relationship to a vault learns nothing about it either.
        r = _challenge(admin, other, "rekey")
        assert r.status_code == 403 and r.json()["detail"] == NO_ACCESS, r.text

        # A manager who holds no key to the vault.
        r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": keyless_manager["id"], "level": "manage"})
        assert r.status_code in (200, 201), r.text
        r = _challenge(kc, vid, "rekey")
        assert r.status_code == 403 and "holds this vault's key" in r.json()["detail"], r.text

        # A manager who holds the key gets one; only the owner may reset.
        _give_key(admin, vid, manager, "manage")
        assert _challenge(gc, vid, "share").status_code == 200
        r = _challenge(gc, vid, "owner_reset")
        assert r.status_code == 403 and "owner" in r.json()["detail"], r.text
        assert _challenge(admin, vid, "owner_reset").status_code == 200
    finally:
        admin.delete_vault(vid)
        oc.delete_vault(other)
        for u in (stranger, member, manager, keyless_manager, owner):
            admin.delete_user(u["id"])


def test_create_is_checked_as_creating_a_vault_is(admin):
    ensure_ecc_keypair(admin)
    keyless, kc = _client_for(admin, "kpnokey")
    try:
        fresh = str(uuid.uuid4())
        off = _challenge(admin, fresh, "create")
        assert off.status_code == 400 and "not enabled" in off.json()["detail"], off.text
        with _zk_enabled(admin):
            r = _challenge(admin, fresh, "create")
            assert r.status_code == 200, r.text
            assert (r.json()["mode"], r.json()["dek_epoch"], r.json()["team_epoch"], r.json()["verifier"]) == (
                "direct", 1, 1, None)
            team = _challenge(admin, str(uuid.uuid4()), "create", mode="hierarchical")
            assert team.status_code == 200 and team.json()["mode"] == "hierarchical"
            flat = _challenge(admin, str(uuid.uuid4()), "create", mode="flat")
            assert flat.status_code == 400 and flat.json()["reason"] == "zk-key-proof-malformed"
            garbage = _challenge(admin, "not-a-uuid", "create")
            assert garbage.status_code == 400 and garbage.json()["reason"] == "zk-key-proof-malformed"

            vid = create_zk_vault(admin)["id"]
            taken = _challenge(admin, vid, "create")
            assert taken.status_code == 409 and taken.json()["detail"] == "That vault id is already in use."
            assert admin.delete_vault(vid).status_code == 200
            retired = _challenge(admin, vid, "create")
            assert retired.status_code == 409 and retired.json()["detail"] == "That vault id is already in use."

            nokey = _challenge(kc, str(uuid.uuid4()), "create")
            assert nokey.status_code == 400 and "encryption key" in nokey.json()["detail"], nokey.text
    finally:
        admin.delete_user(keyless["id"])


def test_an_unknown_operation_is_malformed_and_costs_nothing(admin):
    r = _challenge(admin, str(uuid.uuid4()), "rotate")
    assert r.status_code == 400 and r.json()["reason"] == "zk-key-proof-malformed", r.text


def test_a_temporary_credential_cannot_ask_to_set_up_or_reset(admin):
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        vid = create_zk_vault(admin)["id"]
    try:
        body = admin.post("/auth/temp-credentials", json={"note": unique("kptemp")}).json()
        temp = admin.clone_anonymous()
        temp.login(body["temp_username"], body["credential"])
        for op in ("bootstrap", "owner_reset"):
            r = _challenge(temp, vid, op)
            assert r.status_code == 403 and r.json()["reason"] == "zk-key-proof-interactive-only", (op, r.text)
    finally:
        admin.delete_vault(vid)


def test_the_oldest_live_challenge_goes_when_the_33rd_is_issued_and_expired_ones_are_swept(admin):
    user, c = _client_for(admin, "kpcap")
    ensure_ecc_keypair(c)
    try:
        with _zk_enabled(admin):
            _psql("INSERT INTO zk_key_proof_challenges (id, user_id, vault_id, op, server_private_key_sealed, "
                  f"nonce, mode, dek_epoch, team_epoch, created_at) VALUES ('{uuid.uuid4()}', '{user['id']}', "
                  f"'{uuid.uuid4()}', 'create', 'sealed', 'n', 'direct', 1, 1, now() - interval '10 minutes')")
            ids = []
            for _ in range(33):
                r = _challenge(c, str(uuid.uuid4()), "create")
                assert r.status_code == 200, r.text
                ids.append(r.json()["challenge_id"])
        live = set(_psql(f"SELECT id FROM zk_key_proof_challenges WHERE user_id = '{user['id']}'").split())
        assert len(live) == 32
        assert ids[0] not in live and set(ids[1:]) == live, "the oldest went, the expired one too"
    finally:
        admin.delete_user(user["id"])


def test_concurrent_challenges_all_succeed_within_the_cap(admin):
    """A bulk share asks for one challenge per person, at once."""
    user, c = _client_for(admin, "kppar")
    ensure_ecc_keypair(c)
    try:
        with _zk_enabled(admin):
            def one(_):
                worker = ApiClient()
                worker.session.headers.update({"Authorization": f"Bearer {c.token}"})
                return _challenge(worker, str(uuid.uuid4()), "create").status_code
            with concurrent.futures.ThreadPoolExecutor(max_workers=10) as pool:
                codes = list(pool.map(one, range(20)))
        assert codes == [200] * 20, codes
        assert int(_psql(f"SELECT count(*) FROM zk_key_proof_challenges WHERE user_id = '{user['id']}'")) == 20
    finally:
        admin.delete_user(user["id"])


def test_the_challenge_budget_is_400_a_minute(admin):
    user, c = _client_for(admin, "kprate")
    try:
        target = str(uuid.uuid4())
        codes = [_challenge(c, target, "share").status_code for _ in range(401)]
        assert set(codes[:400]) == {403}, "a stranger is refused, and charged"
        assert codes[400] == 429
    finally:
        admin.delete_user(user["id"])
