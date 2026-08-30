"""Per-user resource caps (findings F-R015-003 + F-R015-006): a per-user vault-count cap, a 50 GB
default per-account storage budget, and a cap on simultaneously-active temporary credentials. Regular
users are bounded; full admins are exempt."""
import json
import os
import subprocess

import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_GIB = 1024 ** 3

# The three per-user cap keys. When ABSENT from the settings blob (a fresh deployment), the server
# falls back to the shipped defaults 50 / 50 / 10 -- which is the fix under test.
_CAP_KEYS = ("default_user_quota", "max_vaults_per_user", "max_temp_creds_per_user")


def _user_client(admin):
    u = admin.create_user(role="user")
    c = ApiClient(BASE_URL)
    c.login(u["_username"], u["_password"])
    return u, c


def _psql(sql):
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    probe = subprocess.run(
        ["docker", "exec", container, "sh", "-c", "echo $POSTGRES_USER; echo $POSTGRES_DB"],
        capture_output=True, text=True, timeout=60)
    if probe.returncode != 0:
        pytest.skip("cannot reach the database container %s" % container)
    lines = [ln.strip() for ln in probe.stdout.splitlines() if ln.strip()]
    out = subprocess.run(
        ["docker", "exec", container, "psql", "-U", lines[0], "-d", lines[1], "-tAc", sql],
        capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, "psql failed: %s" % (out.stderr or "")[:300]
    return out.stdout.strip()


def _sql_literal(value):
    return "'" + value.replace("'", "''") + "'"


@pytest.fixture
def caps_defaults_absent():
    """Remove the three per-user cap keys from the settings blob (the fresh-deploy state), so a test
    exercises the server's fallback DEFAULTS rather than a value it set itself. Not `PUT {key: 50}` --
    that returns the value it stored and never touches the `.get(key, DEFAULT)` fallback under test.
    The whole blob is restored afterwards (the API cannot un-set a key, only set it)."""
    before = _psql("SELECT value FROM system_settings WHERE key = 'global'")
    if not before:
        _psql("INSERT INTO system_settings (key, value) VALUES ('global', '{}') "
              "ON CONFLICT (key) DO NOTHING")
        before = _psql("SELECT value FROM system_settings WHERE key = 'global'") or "{}"
    stripped = json.loads(before)
    for key in _CAP_KEYS:
        stripped.pop(key, None)
    _psql("UPDATE system_settings SET value = %s WHERE key = 'global'"
          % _sql_literal(json.dumps(stripped)))
    yield
    _psql("UPDATE system_settings SET value = %s WHERE key = 'global'" % _sql_literal(before))


def test_vault_count_cap_enforced_for_non_admin(admin):
    before = admin.get("/settings").json()
    # Small vault cap + unlimited storage, so the COUNT is the only bound under test.
    admin.put("/settings", json={"max_vaults_per_user": 2, "default_user_quota": 0})
    u, c = _user_client(admin)
    made = []
    try:
        made.append(c.create_vault(name=unique("cap1"))["id"])
        made.append(c.create_vault(name=unique("cap2"))["id"])
        third = c.post("/vaults", json={"name": unique("cap3")})
        assert third.status_code == 409, third.text
        # A full admin is EXEMPT: it can create MORE than the cap. A single admin create would pass via
        # the ordinary count<cap path (the admin usually owns 0-1 vaults here), so create cap+1 fresh
        # vaults as admin — a non-admin is refused at the (cap+1)th, so all succeeding proves the
        # exemption early-return actually fires.
        admin_made = []
        try:
            for i in range(3):  # cap is 2; the 3rd necessarily crosses the cap
                r = admin.post("/vaults", json={"name": unique(f"cap-admin{i}")})
                assert r.status_code in (200, 201), \
                    f"admin create #{i + 1} refused — exemption not firing: {r.text}"
                admin_made.append(r.json()["id"])
        finally:
            for vid in admin_made:
                admin.delete_vault(vid)
    finally:
        for vid in made:
            c.delete_vault(vid)
        admin.put("/settings", json={
            "max_vaults_per_user": before.get("max_vaults_per_user", 50),
            "default_user_quota": before.get("default_user_quota", 50)})
        admin.delete_user(u["id"])


def test_default_account_quota_is_50gb_for_non_admin(admin, caps_defaults_absent):
    # default_user_quota is ABSENT, so the 50 GB budget is the server's FALLBACK default (the actual
    # F-R015-003 fix: `_settings_blob(db).get("default_user_quota", _DEFAULT_ACCOUNT_QUOTA_GB)`), not a
    # value this test set. A non-admin's vaults are then bounded to that 50 GB aggregate.
    u, c = _user_client(admin)
    try:
        s = admin.get(f"/users/{u['id']}/storage").json()
        assert s["default_quota_bytes"] == 50 * _GIB, s
        # A 60 GB vault exceeds the fallback 50 GB account budget -> refused.
        big = c.post("/vaults", json={"name": unique("big"), "size_limit_gb": 60})
        assert big.status_code == 400, big.text
        # A 10 GB vault fits.
        ok = c.post("/vaults", json={"name": unique("okv"), "size_limit_gb": 10})
        assert ok.status_code in (200, 201), ok.text
        c.delete_vault(ok.json()["id"])
    finally:
        admin.delete_user(u["id"])


def test_temp_cred_cap_enforced_for_non_admin(admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"max_temp_creds_per_user": 1})
    u, c = _user_client(admin)
    made = []
    try:
        r1 = c.post("/auth/temp-credentials", json={"note": unique("tccap")})
        assert r1.status_code == 200, r1.text
        made.append(r1.json())
        r2 = c.post("/auth/temp-credentials", json={"note": unique("tccap")})
        # 409 Conflict — at the active-credential cap (matches the vault-count cap's status).
        assert r2.status_code == 409, r2.text
        # A full admin is exempt.
        ra = admin.post("/auth/temp-credentials", json={"note": unique("tccap-admin")})
        assert ra.status_code == 200, ra.text
        admin.post(f"/temp-creds/{ra.json()['temp_username']}/delete")
    finally:
        for cred in made:
            try:
                c.post(f"/temp-creds/{cred['temp_username']}/delete")
            except Exception:
                pass
        admin.put("/settings", json={
            "max_temp_creds_per_user": before.get("max_temp_creds_per_user", 10)})
        admin.delete_user(u["id"])


def test_temp_cred_cap_caps_non_admin_delegated_child(admin):
    # Symmetric to the admin-exemption test: a NON-admin account is capped for delegated child mints
    # too. The cap count includes children (same owning user_id) AND a non-admin never reaches the
    # exempt branch, so a delegated child on a non-admin account already at the cap is refused (409).
    # This pins the load-bearing invariant that delegation cannot amplify a non-admin past the cap.
    before = admin.get("/settings").json()
    admin.put("/settings", json={"max_temp_creds_per_user": 1})
    u, c = _user_client(admin)
    vid = c.create_vault(name=unique("tcndel"))["id"]
    made = []
    try:
        pcaps = ["vault.see_info"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True,
                           "delegate": True}}
        # The non-admin's first (direct) mint takes it to the cap of 1.
        parent = c.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": pscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]})
        assert parent.status_code == 200, parent.text
        made.append(parent.json())
        pc = c.clone_anonymous()
        pc.login(parent.json()["temp_username"], parent.json()["credential"])
        cscope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": pcaps, "temp": {}}
        # Delegated child on the non-admin account, already at the cap -> refused (409), NOT exempt.
        child = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]})
        assert child.status_code == 409, child.text
    finally:
        for cred in made:
            try:
                c.post(f"/temp-creds/{cred['temp_username']}/delete")
            except Exception:
                pass
        admin.put("/settings", json={
            "max_temp_creds_per_user": before.get("max_temp_creds_per_user", 10)})
        admin.delete_user(u["id"])


def test_temp_cred_cap_exempts_admin_delegated_child(admin):
    # An admin ACCOUNT is exempt from the temp-cred cap whether it mints directly OR through a
    # delegated child temp session (the child carries the same admin user_id). Regression: the cap
    # once keyed on 'direct mint only', so a delegated child on an admin account already at the cap
    # returned 409 instead of 200 (caught by the full suite once >cap creds had accumulated).
    before = admin.get("/settings").json()
    admin.put("/settings", json={"max_temp_creds_per_user": 1})
    vid = admin.create_vault(name=unique("tcdel"))["id"]
    made = []
    try:
        pcaps = ["vault.see_info"]
        pscope = {"v": 1, "pages": ["vaults", "temp_creds"], "caps": [], "vault_caps_default": pcaps,
                  "temp": {"view": True, "create": True, "invalidate": True, "clear": True,
                           "delegate": True}}
        # First (direct) admin mint — already at/over the cap of 1, but exempt.
        parent = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 60, "scope": pscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]})
        assert parent.status_code == 200, parent.text
        made.append(parent.json())
        pc = admin.clone_anonymous()
        pc.login(parent.json()["temp_username"], parent.json()["credential"])
        cscope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": pcaps, "temp": {}}
        # Delegated child on the admin account — exempt too (was 409 before the fix).
        child = pc.post("/auth/temp-credentials", json={
            "validity_minutes": 30, "scope": cscope, "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": vid, "caps": pcaps}]})
        assert child.status_code == 200, child.text
        made.append(child.json())
    finally:
        for cred in made:
            try:
                admin.post(f"/temp-creds/{cred['temp_username']}/delete")
            except Exception:
                pass
        admin.put("/settings", json={
            "max_temp_creds_per_user": before.get("max_temp_creds_per_user", 10)})
        admin.delete_vault(vid)


def test_cap_settings_report_effective_defaults(admin, caps_defaults_absent):
    # With the three keys ABSENT, /settings surfaces the shipped fallback defaults exactly (50 / 50 /
    # 10) -- not merely "some int". Reverting any default to 0/unlimited (or a wrong number) fails here.
    s = admin.get("/settings").json()
    assert s.get("max_vaults_per_user") == 50, s
    assert s.get("default_user_quota") == 50, s
    assert s.get("max_temp_creds_per_user") == 10, s


def test_cap_settings_validate(admin):
    assert admin.put("/settings", json={"max_vaults_per_user": -1}).status_code == 400
    assert admin.put("/settings", json={"max_vaults_per_user": True}).status_code == 400
    assert admin.put("/settings", json={"max_temp_creds_per_user": -1}).status_code == 400
