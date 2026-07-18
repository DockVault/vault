"""Minting a temporary vault passcode at POST /auth/temp-credentials (STANDARD vaults only).

A passcode is a SECOND server-side access gate on a password-protected standard vault: the minter
proves the real vault password, then a passcode verifier is stored on the per-vault grant. These
tests pin generation, custom-with-policy, the fail-closed policy checks, the zero-knowledge
exclusion, and the one-time/same-for-all behavior. Redemption is covered separately — here we only
assert the stored grant + the once-shown plaintext. Exercised by a normal admin account AND a
temp-credential (delegated) session.
"""
import json
import os
import subprocess
import uuid

import pytest

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")

_POLICY_KEYS = [
    "temp_passcodes_enabled", "temp_passcode_allow_custom", "temp_passcode_one_time_default",
    "temp_passcode_single_vault_only", "temp_passcode_min_length",
    "temp_passcode_require_uppercase", "temp_passcode_require_lowercase",
    "temp_passcode_require_numbers", "temp_passcode_require_special",
    "temp_passcode_max_lifetime_minutes",
]


def _u(prefix):
    return f"{prefix}_{uuid.uuid4().hex[:8]}"


def _psql(sql):
    out = subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=20)
    return (out.stdout or "").strip()


def _grant(temp_username, vault_id):
    """(passcode_kind, passcode_max_uses, has_hash) for one temp-cred vault grant, or None."""
    q = ("SELECT tcva.passcode_kind, tcva.passcode_max_uses, (tcva.passcode_hash IS NOT NULL) "
         "FROM temp_credential_vault_access tcva "
         "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
         f"WHERE tc.temp_username = '{temp_username}' AND tcva.vault_id = '{vault_id}';")
    row = _psql(q)
    if not row:
        return None
    kind, max_uses, has_hash = row.split("|")
    return (kind or None, (int(max_uses) if max_uses else None), has_hash == "t")


def _passcode_hash(temp_username, vault_id):
    """The stored Argon2 verifier for a grant (raw), or None."""
    q = ("SELECT tcva.passcode_hash FROM temp_credential_vault_access tcva "
         "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
         f"WHERE tc.temp_username = '{temp_username}' AND tcva.vault_id = '{vault_id}';")
    return _psql(q) or None


def _passcode_expiry(temp_username, vault_id):
    """(passcode_expires_at, credential deactivate_at) as raw psql timestamp strings."""
    q = ("SELECT tcva.passcode_expires_at, tc.deactivate_at FROM temp_credential_vault_access tcva "
         "JOIN temporary_credentials tc ON tc.id = tcva.temp_credential_id "
         f"WHERE tc.temp_username = '{temp_username}' AND tcva.vault_id = '{vault_id}';")
    row = _psql(q)
    if not row:
        return (None, None)
    exp, deact = row.split("|")
    return (exp or None, deact or None)


def _cred_count():
    return int(_psql("SELECT count(*) FROM temporary_credentials;") or "0")


@pytest.fixture
def restore_policy(admin):
    before = admin.get("/settings").json()
    missing = [k for k in _POLICY_KEYS if k not in before]
    assert not missing, f"GET /settings did not overlay policy keys (restore would silently no-op): {missing}"
    yield
    admin.put("/settings", json={k: before[k] for k in _POLICY_KEYS})


def _set_policy(admin, **kw):
    admin.put("/settings", json=kw)


def _pw_vault(admin, pw="VaultPw-9x!secret"):
    v = admin.create_vault(name=_u("pcv"), password=pw)
    return v["id"], pw


def _mint(admin, vault_id, pw, **passcode_opts):
    """Mint a selected-scope cred granting download on one password vault, with passcode options."""
    caps = ["vault.see_files", "file.download"]
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False, "delegate": False}}
    sv = {"vault_id": vault_id, "caps": caps, "password": pw, **passcode_opts}
    return admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected", "selected_vaults": [sv],
    })


# --- generated passcode (default policy) ---------------------------------------------------------
# NB: the generator (app.core.security.generate_passcode) can't be imported in the host test venv
# (security.py pulls in argon2, which isn't installed here), so its policy-driven length + charset are
# asserted end-to-end through the mint response below rather than as a pure unit test.

def test_generated_passcode_minted_and_stored(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_min_length=16,
                temp_passcode_one_time_default=True)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw, issue_passcode=True)
        assert r.status_code == 200, r.text
        body = r.json()
        pcs = body["passcodes"]
        assert len(pcs) == 1 and pcs[0]["vault_id"] == vid
        assert pcs[0]["kind"] == "generated"
        assert len(pcs[0]["passcode"]) == 16 and pcs[0]["passcode"].isalnum()  # policy length + charset
        # stored: a hash exists, kind generated, one-time (max_uses=1) per policy default
        assert _grant(body["temp_username"], vid) == ("generated", 1, True)
        # the stored value is an Argon2 VERIFIER, never the plaintext (the whole point of the feature)
        h = _passcode_hash(body["temp_username"], vid)
        assert h and h.startswith("$argon2") and h != pcs[0]["passcode"]
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_generated_length_follows_policy_min_length(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_min_length=24)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw, issue_passcode=True)
        assert r.status_code == 200, r.text
        assert len(r.json()["passcodes"][0]["passcode"]) == 24  # generated length tracks the policy
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_no_passcode_requested_leaves_grant_null(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw)  # no issue_passcode
        assert r.status_code == 200
        assert r.json()["passcodes"] == []
        assert _grant(r.json()["temp_username"], vid) == (None, None, False)  # backward compatible
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_multi_use_override(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_one_time_default=True)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw, issue_passcode=True, one_time=False)
        assert r.status_code == 200
        assert _grant(r.json()["temp_username"], vid)[1] is None  # max_uses NULL = multi-use
    finally:
        admin.delete_vault(vid, vault_password=pw)


# --- custom passcode + complexity ----------------------------------------------------------------

def test_custom_rejected_when_not_allowed(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_allow_custom=False)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw, issue_passcode=True, passcode="MyCustomPass99")
        assert r.status_code == 400 and "custom" in r.text.lower()
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_custom_accepted_and_complexity_enforced(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_allow_custom=True,
                temp_passcode_min_length=10, temp_passcode_require_special=True)
    vid, pw = _pw_vault(admin)
    try:
        # missing a special char -> rejected
        bad = _mint(admin, vid, pw, issue_passcode=True, passcode="NoSpecial12")
        assert bad.status_code == 400, bad.text
        # satisfies min length + special -> accepted, kind custom
        good = _mint(admin, vid, pw, issue_passcode=True, passcode="Custom-9!code")
        assert good.status_code == 200, good.text
        assert good.json()["passcodes"][0]["kind"] == "custom"
        assert _grant(good.json()["temp_username"], vid)[0] == "custom"
    finally:
        admin.delete_vault(vid, vault_password=pw)


# --- fail-closed policy gates --------------------------------------------------------------------

def test_feature_disabled_rejects_passcode(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=False)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw, issue_passcode=True)
        assert r.status_code == 400 and "disabled" in r.text.lower()
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_no_password_vault_rejects_passcode(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True)
    v = admin.create_vault(name=_u("nopw"))  # no password
    try:
        caps = ["vault.see_files", "file.download"]
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": v["id"], "caps": caps, "issue_passcode": True}]})
        assert r.status_code == 400 and "no password" in r.text.lower()
    finally:
        admin.delete_vault(v["id"])


def test_zero_knowledge_vault_rejects_passcode(admin, restore_policy):
    """A zero-knowledge vault can never get a passcode — the server refuses it. We flip a vault's type
    in the DB (real ZK creation needs client crypto) to exercise the server guard directly."""
    _set_policy(admin, temp_passcodes_enabled=True)
    v = admin.create_vault(name=_u("zkflip"))  # no password; type check fires before the pw check
    vid = v["id"]
    try:
        _psql(f"UPDATE vaults SET type='zero_knowledge' WHERE id='{vid}';")
        caps = ["vault.see_files", "file.download"]
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": caps, "issue_passcode": True}]})
        assert r.status_code == 400 and "zero-knowledge" in r.text.lower()
    finally:
        _psql(f"UPDATE vaults SET type='standard' WHERE id='{vid}';")
        admin.delete_vault(vid)


def test_single_vault_only_rejects_multi(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_single_vault_only=True)
    v1, p1 = _pw_vault(admin)
    v2, p2 = _pw_vault(admin)
    try:
        caps = ["vault.see_files", "file.download"]
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "selected_vaults": [
                {"vault_id": v1, "caps": caps, "password": p1, "issue_passcode": True},
                {"vault_id": v2, "caps": caps, "password": p2, "issue_passcode": True}]})
        assert r.status_code == 400 and "single vault" in r.text.lower()
    finally:
        admin.delete_vault(v1, vault_password=p1)
        admin.delete_vault(v2, vault_password=p2)


def test_same_for_all_one_secret_many_grants(admin, restore_policy):
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_single_vault_only=False)
    v1, p1 = _pw_vault(admin)
    v2, p2 = _pw_vault(admin)
    try:
        caps = ["vault.see_files", "file.download"]
        scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps, "temp": {}}
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": scope, "vault_access_mode": "selected",
            "passcode_same_for_all": True,
            "selected_vaults": [
                {"vault_id": v1, "caps": caps, "password": p1, "issue_passcode": True},
                {"vault_id": v2, "caps": caps, "password": p2, "issue_passcode": True}]})
        assert r.status_code == 200, r.text
        pcs = {p["vault_id"]: p["passcode"] for p in r.json()["passcodes"]}
        assert len(pcs) == 2 and pcs[v1] == pcs[v2]  # one shared secret
        tu = r.json()["temp_username"]
        assert _grant(tu, v1)[2] and _grant(tu, v2)[2]  # both grants carry a verifier
    finally:
        admin.delete_vault(v1, vault_password=p1)
        admin.delete_vault(v2, vault_password=p2)


# --- temp-credential (delegated) session mints a passcode; proof does NOT inherit ----------------

def test_delegated_temp_session_mints_passcode_reproving_password(admin, restore_policy):
    """A temp session with create+delegate mints a CHILD carrying a passcode for a vault it holds,
    re-proving the real password at mint (proof never inherits). Exercises the changed mint endpoint
    from a temp-credential (delegated) session."""
    _set_policy(admin, temp_passcodes_enabled=True)
    vid, pw = _pw_vault(admin)
    try:
        pcaps = ["vault.see_files", "file.download"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": True}}
        parent = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": pscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps, "password": pw}]}).json()
        pc = admin.clone_anonymous()
        pc.login(parent["temp_username"], parent["credential"])
        # child WITHOUT the re-proof fails closed (proof does not inherit)
        cscope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": pcaps, "temp": {}}
        no_proof = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps, "issue_passcode": True}]})
        assert no_proof.status_code == 400  # password required at mint
        # child WITH the re-proof mints a passcode
        child = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps, "password": pw, "issue_passcode": True}]})
        assert child.status_code == 200, child.text
        assert child.json()["passcodes"][0]["kind"] == "generated"
        assert _grant(child.json()["temp_username"], vid)[2] is True
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_delegated_child_cannot_passcode_unreachable_vault(admin, restore_policy):
    """The scope guard: a delegated child cannot mint a passcode for a vault its parent does not hold
    (even when it supplies that vault's real password), while still minting for the in-scope vault."""
    _set_policy(admin, temp_passcodes_enabled=True)
    va, pa = _pw_vault(admin)   # parent holds A
    vb, pb = _pw_vault(admin)   # parent does NOT hold B
    try:
        pcaps = ["vault.see_files", "file.download"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": True}}
        parent = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": pscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": va, "caps": pcaps, "password": pa}]}).json()
        pc = admin.clone_anonymous()
        pc.login(parent["temp_username"], parent["credential"])
        cscope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": pcaps, "temp": {}}
        child = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [
                {"vault_id": va, "caps": pcaps, "password": pa},  # in scope, proven, no passcode
                {"vault_id": vb, "caps": pcaps, "password": pb, "issue_passcode": True}]})  # out of scope
        assert child.status_code == 200, child.text
        tu = child.json()["temp_username"]
        assert all(p["vault_id"] != vb for p in child.json()["passcodes"])  # no passcode revealed for B
        assert _grant(tu, vb) is None                                       # and no grant for B at all
    finally:
        admin.delete_vault(va, vault_password=pa)
        admin.delete_vault(vb, vault_password=pb)


def test_rejected_passcode_persists_nothing(admin, restore_policy):
    """Fail-closed: a rejected passcode mint (feature off) leaves NO credential behind."""
    _set_policy(admin, temp_passcodes_enabled=False)
    vid, pw = _pw_vault(admin)
    try:
        before = _cred_count()
        r = _mint(admin, vid, pw, issue_passcode=True)
        assert r.status_code == 400
        assert _cred_count() == before  # nothing was minted
    finally:
        admin.delete_vault(vid, vault_password=pw)


def test_max_lifetime_caps_passcode_expiry(admin, restore_policy):
    """An org max-lifetime shorter than the credential validity caps passcode_expires_at below the
    credential's deactivate_at (this asserts the stored expiry; the redemption check enforces it)."""
    _set_policy(admin, temp_passcodes_enabled=True, temp_passcode_max_lifetime_minutes=5)
    vid, pw = _pw_vault(admin)
    try:
        r = _mint(admin, vid, pw, issue_passcode=True)  # _mint uses validity_minutes=60
        assert r.status_code == 200
        exp, deact = _passcode_expiry(r.json()["temp_username"], vid)
        assert exp and deact and exp < deact  # ~now+5min, strictly before the credential's validity end
    finally:
        admin.delete_vault(vid, vault_password=pw)
