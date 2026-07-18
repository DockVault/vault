"""Admin Temporary Vault Passcode policy surface (settings only; no enforcement).

PUT /settings gains the temp_passcode_* + temp_cred_allow_zk_vaults keys (typed validation),
GET /settings overlays the EFFECTIVE policy (feature default OFF, allow-ZK default ON, min-length
floored at 8), and a NEW GET /temp-passcode-policy exposes the effective policy to any authenticated
user — including a temp-credential session — so the mint UI can shape the passcode controls without
the admin-only /settings store. These tests pin the policy surface and its validation. No passcode
is minted or redeemed here. (The fail-closed/decision defaults are pinned separately, and
independent of a live instance, in test_temp_passcode_policy_unit.py.)
"""
import uuid

import pytest


# the 9 boolean policy keys + the 2 integer keys the passcode policy adds (all overlaid onto GET /settings)
_BOOL_KEYS = [
    "temp_passcodes_enabled", "temp_cred_allow_zk_vaults", "temp_passcode_allow_custom",
    "temp_passcode_require_uppercase", "temp_passcode_require_lowercase",
    "temp_passcode_require_numbers", "temp_passcode_require_special",
    "temp_passcode_one_time_default", "temp_passcode_single_vault_only",
]
_INT_KEYS = ["temp_passcode_min_length", "temp_passcode_max_lifetime_minutes"]
_POLICY_KEYS = _BOOL_KEYS + _INT_KEYS


@pytest.fixture
def restore_passcode_settings(admin):
    """Snapshot the policy keys and restore them after the test so a run can't leave the shared
    deployment with a stray passcode policy."""
    before = admin.get("/settings").json()
    yield
    payload = {k: before[k] for k in _POLICY_KEYS if k in before}
    if payload:
        admin.put("/settings", json=payload)


def _temp_session(admin, **kw):
    """A logged-in temp-credential session client (admin-minted, unrestricted unless kw scopes it)."""
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60, **kw}).json()
    client = admin.clone_anonymous()
    client.login(body["temp_username"], body["credential"])
    return client


# --- GET /settings overlay: the keys are always present -----------------------------------------

def test_all_policy_keys_overlaid_on_settings(admin):
    data = admin.get("/settings").json()
    missing = [k for k in _POLICY_KEYS if k not in data]
    assert not missing, f"GET /settings is missing overlaid policy keys: {missing}"
    assert isinstance(data["temp_passcodes_enabled"], bool)
    assert isinstance(data["temp_cred_allow_zk_vaults"], bool)
    assert isinstance(data["temp_passcode_min_length"], int) and data["temp_passcode_min_length"] >= 8


# --- round-trips through PUT/GET /settings -------------------------------------------------------

def test_master_switch_round_trip(admin, restore_passcode_settings):
    assert admin.put("/settings", json={"temp_passcodes_enabled": True}).status_code == 200
    assert admin.get("/settings").json()["temp_passcodes_enabled"] is True
    assert admin.put("/settings", json={"temp_passcodes_enabled": False}).status_code == 200
    assert admin.get("/settings").json()["temp_passcodes_enabled"] is False


def test_allow_zk_vaults_round_trip(admin, restore_passcode_settings):
    assert admin.put("/settings", json={"temp_cred_allow_zk_vaults": False}).status_code == 200
    assert admin.get("/settings").json()["temp_cred_allow_zk_vaults"] is False
    assert admin.put("/settings", json={"temp_cred_allow_zk_vaults": True}).status_code == 200
    assert admin.get("/settings").json()["temp_cred_allow_zk_vaults"] is True


@pytest.mark.parametrize("key", _BOOL_KEYS)
def test_every_bool_key_accepts_true(admin, restore_passcode_settings, key):
    """Every bool key round-trips a True (catches a name typo in the server's key list/defaults)."""
    assert admin.put("/settings", json={key: True}).status_code == 200
    assert admin.get("/settings").json()[key] is True


def test_min_length_round_trip_and_floor(admin, restore_passcode_settings):
    assert admin.put("/settings", json={"temp_passcode_min_length": 24}).status_code == 200
    assert admin.get("/settings").json()["temp_passcode_min_length"] == 24
    # below the 8-char floor is accepted but the EFFECTIVE value is floored to 8
    assert admin.put("/settings", json={"temp_passcode_min_length": 4}).status_code == 200
    assert admin.get("/settings").json()["temp_passcode_min_length"] == 8
    # 0 => the default generated length (16)
    assert admin.put("/settings", json={"temp_passcode_min_length": 0}).status_code == 200
    assert admin.get("/settings").json()["temp_passcode_min_length"] == 16


def test_max_lifetime_round_trip(admin, restore_passcode_settings):
    assert admin.put("/settings", json={"temp_passcode_max_lifetime_minutes": 120}).status_code == 200
    assert admin.get("/settings").json()["temp_passcode_max_lifetime_minutes"] == 120
    assert admin.put("/settings", json={"temp_passcode_max_lifetime_minutes": 0}).status_code == 200
    assert admin.get("/settings").json()["temp_passcode_max_lifetime_minutes"] == 0


# --- validation: bad values are rejected 400 ----------------------------------------------------

@pytest.mark.parametrize("key", _BOOL_KEYS)
@pytest.mark.parametrize("bad", ["true", 1, 0, "yes", None])
def test_bool_keys_reject_non_bool(admin, restore_passcode_settings, key, bad):
    r = admin.put("/settings", json={key: bad})
    assert r.status_code == 400, f"expected 400 for {key}={bad!r}, got {r.status_code}: {r.text}"


@pytest.mark.parametrize("key", _INT_KEYS)
@pytest.mark.parametrize("bad", [-1, "16", 3.5, True])
def test_int_keys_reject_bad(admin, restore_passcode_settings, key, bad):
    r = admin.put("/settings", json={key: bad})
    assert r.status_code == 400, f"expected 400 for {key}={bad!r}, got {r.status_code}: {r.text}"


def test_unrelated_key_still_merges(admin, restore_passcode_settings):
    """Adding validation must not turn the generic store into a whitelist."""
    probe = "probe-" + uuid.uuid4().hex[:8]
    assert admin.put("/settings", json={"app_description": probe}).status_code == 200
    assert admin.get("/settings").json().get("app_description") == probe


# --- GET /temp-passcode-policy (the mint-UI subset) ---------------------------------------------

def _assert_policy_shape(policy):
    for k in _POLICY_KEYS:
        assert k in policy, f"policy missing {k}"
    assert isinstance(policy["temp_passcodes_enabled"], bool)
    assert isinstance(policy["temp_cred_allow_zk_vaults"], bool)
    assert isinstance(policy["temp_passcode_min_length"], int) and policy["temp_passcode_min_length"] >= 8


def test_policy_endpoint_normal_account(admin):
    r = admin.get("/temp-passcode-policy")
    assert r.status_code == 200, r.text
    _assert_policy_shape(r.json())


def test_policy_endpoint_temp_session(admin):
    """The policy endpoint is also reachable from a temporary-credential session (not just a full account)."""
    tclient = _temp_session(admin)
    r = tclient.get("/temp-passcode-policy")
    assert r.status_code == 200, r.text
    _assert_policy_shape(r.json())


def test_policy_endpoint_requires_auth(anon):
    assert anon.get("/temp-passcode-policy").status_code in (401, 403)


def test_policy_endpoint_reflects_saved_values(admin, restore_passcode_settings):
    """The subset the mint UI reads reflects a saved policy end to end."""
    admin.put("/settings", json={
        "temp_passcodes_enabled": True,
        "temp_passcode_allow_custom": True,
        "temp_passcode_min_length": 20,
        "temp_passcode_require_special": True,
        "temp_passcode_one_time_default": False,
        "temp_cred_allow_zk_vaults": False,
    })
    p = admin.get("/temp-passcode-policy").json()
    assert p["temp_passcodes_enabled"] is True
    assert p["temp_passcode_allow_custom"] is True
    assert p["temp_passcode_min_length"] == 20
    assert p["temp_passcode_require_special"] is True
    assert p["temp_passcode_one_time_default"] is False
    assert p["temp_cred_allow_zk_vaults"] is False


# --- admin-only guards: a temp session / anon must not read or write the org policy --------------

def test_temp_session_cannot_read_settings(admin):
    """The overlaid policy keys ride the admin-only GET /settings; a temp session must be refused."""
    tclient = _temp_session(admin)
    assert tclient.get("/settings").status_code in (401, 403)


def test_temp_session_cannot_write_settings(admin):
    tclient = _temp_session(admin)
    r = tclient.put("/settings", json={"temp_passcodes_enabled": True})
    assert r.status_code in (401, 403), f"a temp session must not rewrite org policy, got {r.status_code}"


def test_settings_write_is_admin_only(anon):
    assert anon.put("/settings", json={"temp_passcodes_enabled": True}).status_code in (401, 403)
