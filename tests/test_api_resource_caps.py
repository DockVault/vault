"""Per-user resource caps (findings F-R015-003 + F-R015-006): a per-user vault-count cap, a 50 GB
default per-account storage budget, and a cap on simultaneously-active temporary credentials. Regular
users are bounded; full admins are exempt."""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_GIB = 1024 ** 3


def _user_client(admin):
    u = admin.create_user(role="user")
    c = ApiClient(BASE_URL)
    c.login(u["_username"], u["_password"])
    return u, c


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
        # A full admin is exempt from the per-user cap.
        av = admin.create_vault(name=unique("cap-admin"))
        admin.delete_vault(av["id"])
    finally:
        for vid in made:
            c.delete_vault(vid)
        admin.put("/settings", json={
            "max_vaults_per_user": before.get("max_vaults_per_user", 50),
            "default_user_quota": before.get("default_user_quota", 50)})
        admin.delete_user(u["id"])


def test_default_account_quota_is_50gb_for_non_admin(admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"default_user_quota": 50, "max_vaults_per_user": 0})
    u, c = _user_client(admin)
    try:
        s = admin.get(f"/users/{u['id']}/storage").json()
        assert s["default_quota_bytes"] == 50 * _GIB, s
        # A 60 GB vault exceeds the 50 GB account budget -> refused.
        big = c.post("/vaults", json={"name": unique("big"), "size_limit_gb": 60})
        assert big.status_code == 400, big.text
        # A 10 GB vault fits.
        ok = c.post("/vaults", json={"name": unique("okv"), "size_limit_gb": 10})
        assert ok.status_code in (200, 201), ok.text
        c.delete_vault(ok.json()["id"])
    finally:
        admin.put("/settings", json={
            "default_user_quota": before.get("default_user_quota", 50),
            "max_vaults_per_user": before.get("max_vaults_per_user", 50)})
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


def test_cap_settings_report_effective_defaults(admin):
    s = admin.get("/settings").json()
    # The effective defaults are surfaced so the admin toggles reflect the shipped 50 / 50 / 10.
    assert isinstance(s.get("max_vaults_per_user"), int)
    assert isinstance(s.get("default_user_quota"), (int, float))
    assert isinstance(s.get("max_temp_creds_per_user"), int)


def test_cap_settings_validate(admin):
    assert admin.put("/settings", json={"max_vaults_per_user": -1}).status_code == 400
    assert admin.put("/settings", json={"max_vaults_per_user": True}).status_code == 400
    assert admin.put("/settings", json={"max_temp_creds_per_user": -1}).status_code == 400
