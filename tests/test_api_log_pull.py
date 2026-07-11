"""RO2-3 Phase 1 — the authenticated log-PULL endpoint + admin token management, over the
live HTTP chain.

The pure security logic (hashing, scope, filtering, redaction, the gate) is unit-tested in
tests/test_log_pull_helpers.py. These tests lock the WIRING: the admin mint/list/disable/flags
flow, that the list never leaks a hash/plaintext, that the audit row carries no plaintext, and
the auth negatives + ceiling behavior of GET /logs.

The env CEILING (PLAN_LOG_PULL) is read at process start, so a live vault built without it
returns 404 from GET /logs regardless of the token — the ON-path assertions are probe-skipped.
And the whole module skips if the running image predates the endpoint (GET /settings/logs 404).
"""
import uuid

import pytest
import requests

from conftest import BASE_URL, unique


@pytest.fixture(scope="module", autouse=True)
def _require_endpoint(admin):
    """Skip cleanly if the running vault image predates the log-pull endpoint."""
    r = admin.get("/settings/logs")
    if r.status_code == 404:
        pytest.skip("running vault image predates the RO2-3 log-pull endpoint (rebuild+redeploy)")


def _mint(admin, scope=("web",), name=None):
    r = admin.post("/settings/logs", json={"name": name or unique("tok"), "scope": list(scope)})
    assert r.status_code == 200, f"mint failed: {r.status_code} {r.text}"
    return r.json()


def _disable(admin, token_id):
    admin.post(f"/settings/logs/{token_id}/disable", json={})


# ---- admin view / mint / list-never-leaks / disable -----------------------------------------

def test_admin_view_shape(admin):
    body = admin.get("/settings/logs").json()
    assert set(["ceiling", "components", "serveable", "flags", "tokens"]).issubset(body)
    assert "web" in body["components"] and "sftp" in body["serveable"]
    assert isinstance(body["tokens"], list)


def test_mint_returns_plaintext_once_and_list_never_leaks_it(admin):
    minted = _mint(admin, scope=("web", "sftp"))
    try:
        assert minted["token"] and minted["token_prefix"] == minted["token"][:12]
        assert sorted(minted["scope"]) == ["sftp", "web"]
        listed = admin.get("/settings/logs").json()["tokens"]
        row = next(t for t in listed if t["id"] == minted["id"])
        # the list carries the public prefix, NEVER the plaintext or the hash
        assert row["token_prefix"] == minted["token_prefix"]
        assert "token" not in row and "token_hash" not in row
        assert minted["token"] not in str(row)
    finally:
        _disable(admin, minted["id"])


def test_mint_validates_name_and_scope(admin):
    assert admin.post("/settings/logs", json={"name": "", "scope": ["web"]}).status_code == 400
    assert admin.post("/settings/logs", json={"name": unique("t"), "scope": []}).status_code == 400
    assert admin.post("/settings/logs", json={"name": unique("t"), "scope": ["bogus"]}).status_code == 400
    # unknown scope entries are dropped, known kept
    m = _mint(admin, scope=("web", "bogus", "db-diag"))
    try:
        assert sorted(m["scope"]) == ["db-diag", "web"]
    finally:
        _disable(admin, m["id"])


def test_disable_is_idempotent_and_unknown_id_404(admin):
    m = _mint(admin)
    assert admin.post(f"/settings/logs/{m['id']}/disable", json={}).status_code == 200
    assert admin.post(f"/settings/logs/{m['id']}/disable", json={}).status_code == 200  # idempotent
    assert admin.post(f"/settings/logs/{uuid.uuid4()}/disable", json={}).status_code == 404
    assert admin.post("/settings/logs/not-a-uuid/disable", json={}).status_code == 404


def test_audit_row_has_no_plaintext_token(admin):
    m = _mint(admin, name=unique("audit"))
    try:
        rows = admin.get("/audit/log", params={"action": "log_token_generated", "limit": 50}).json()
        blob = str(rows)
        assert m["token"] not in blob, "plaintext token leaked into the audit log"
        assert m["token_prefix"] in blob, "audit row should record the prefix"
    finally:
        _disable(admin, m["id"])


# ---- flags round-trip -----------------------------------------------------------------------

@pytest.fixture
def restore_flags(admin):
    before = admin.get("/settings/logs").json().get("flags", {})
    yield
    admin.put("/settings/logs", json={"flags": before})


def test_flags_round_trip(admin, restore_flags):
    assert admin.put("/settings/logs", json={"flags": {"web": True}}).status_code == 200
    assert admin.get("/settings/logs").json()["flags"]["web"] is True
    assert admin.put("/settings/logs", json={"flags": {"web": False}}).status_code == 200
    assert admin.get("/settings/logs").json()["flags"]["web"] is False


def test_flags_rejects_empty_and_unknown_only(admin, restore_flags):
    assert admin.put("/settings/logs", json={}).status_code == 400
    assert admin.put("/settings/logs", json={"flags": {"bogus": True}}).status_code == 400


# ---- auth boundaries on the admin surface ---------------------------------------------------

def test_settings_logs_requires_admin(anon):
    assert anon.get("/settings/logs").status_code in (401, 403)
    assert anon.put("/settings/logs", json={"flags": {"web": True}}).status_code in (401, 403)
    assert anon.post("/settings/logs", json={"name": "x", "scope": ["web"]}).status_code in (401, 403)


# ---- GET /logs: auth + ceiling + (probe-skipped) ON path ------------------------------------

def _get_logs(token, service="web"):
    return requests.get(f"{BASE_URL}/logs", params={"service": service},
                        headers={"Authorization": f"Bearer {token}"}, timeout=15)


def test_logs_requires_a_token():
    # No token: 404 when the ceiling is off (no oracle), 401 when on. Never 200/500.
    r = requests.get(f"{BASE_URL}/logs", params={"service": "web"}, timeout=15)
    assert r.status_code in (401, 404), r.text


def test_logs_on_path_or_ceiling_off(admin, restore_flags):
    """If the ceiling is ON, a valid scoped token returns 200 and the auth/scope negatives hold.
    If OFF (the default build), GET /logs is 404 regardless of the token — assert that and skip
    the ON-path assertions."""
    admin.put("/settings/logs", json={"flags": {"web": True}})
    m = _mint(admin, scope=("web",))
    try:
        r = _get_logs(m["token"], "web")
        if r.status_code == 404:
            pytest.skip("ceiling PLAN_LOG_PULL is off on this build — ON-path not exercisable")
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["service"] == "web" and isinstance(body["lines"], list)
        assert "truncated" in body
        # a garbage token -> 401
        assert _get_logs("deadbeefdeadbeef-not-real", "web").status_code == 401
        # valid token, but not scoped for sftp -> 403 (only when sftp is enabled; else 404 first)
        admin.put("/settings/logs", json={"flags": {"web": True, "sftp": True}})
        assert _get_logs(m["token"], "sftp").status_code == 403
        # unknown component -> 404
        assert _get_logs(m["token"], "nonsense").status_code == 404
        # a db-diag scoped+enabled token still 404s in Phase 1 (no source yet)
        admin.put("/settings/logs", json={"flags": {"db-diag": True}})
        m2 = _mint(admin, scope=("db-diag",))
        try:
            assert _get_logs(m2["token"], "db-diag").status_code == 404
        finally:
            _disable(admin, m2["id"])
    finally:
        _disable(admin, m["id"])
