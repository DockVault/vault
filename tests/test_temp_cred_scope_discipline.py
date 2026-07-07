"""Regression tests for temporary-credential scope discipline.

Covers the hardening of the temp-credential subsystem:

* the parallel by-id management endpoints (`/api/user-management/temp-credentials/{id}`)
  must apply the SAME confinement a scoped delegate is subject to on the api_server twins
  — a scoped delegate may only touch credentials it created, and its listing is confined
  to those (no cross-user id enumeration);
* a create-but-not-delegate parent must NOT be able to mint create/delegate-capable
  children by omitting `scope` (the delegate gate applies to an inherited scope too);
* the advertised validity window (`deactivate_at`) is enforced at auth and per request,
  not just the hard expiry (`expires_at`);
* one-time use is an atomic claim — two concurrent logins can't both win;
* creating credentials for another user is interactive-admin only;
* the password endpoint carries the same ownership + confinement guard as its siblings.
"""
import shutil
import subprocess
import threading

import pytest

from conftest import ApiClient, BASE_URL, unique


# --------------------------------------------------------------------------- helpers
def _mint(client, **payload):
    r = client.post("/auth/temp-credentials", json=payload or None)
    assert r.status_code == 200, r.text
    return r.json()


def _login_temp(cred):
    c = ApiClient(BASE_URL)
    c.login(cred["temp_username"], cred["credential"])
    return c


def _cred_id(admin, temp_username):
    """Resolve a temp credential's row id from the admin listing."""
    r = admin.get("/temp-creds/list")
    assert r.status_code in (200, 304), r.text
    rows = r.json()
    rows = rows if isinstance(rows, list) else rows.get("items", rows.get("data", []))
    for row in rows:
        if row.get("temp_username") == temp_username:
            return row["id"], row.get("user_id")
    return None, None


# A scoped delegate that can view/create/invalidate/clear but NOT delegate.
SCOPE_NO_DELEGATE = {
    "pages": ["temp_creds"], "caps": [], "vault_caps_default": [],
    "temp": {"view": True, "create": True, "invalidate": True, "clear": True, "delegate": False},
}


@pytest.fixture
def cleanup(admin):
    """Delete every temp credential minted during a test (best effort)."""
    names = []
    yield names
    for tu in set(names):
        try:
            admin.post(f"/temp-creds/{tu}/delete")
        except Exception:  # noqa: BLE001
            pass


# --------------------------------------------------------------------------- delegate gate on an omitted scope
def test_omitting_scope_does_not_bypass_the_delegate_gate(admin, cleanup):
    """A create-but-not-delegate parent minting a child by OMITTING scope must produce a
    leaf child: create/delegate forced off, other inherited perms intact."""
    parent = _mint(admin, note=unique("delegate-parent"), scope=SCOPE_NO_DELEGATE, vault_access_mode="selected")
    cleanup.append(parent["temp_username"])
    p = _login_temp(parent)

    # Sanity: the parent itself holds create but not delegate.
    pperms = p.get("/auth/session").json().get("temp_perms") or {}
    assert pperms.get("create") is True and pperms.get("delegate") is False, pperms

    # Mint a child with NO scope field at all.
    r = p.post("/auth/temp-credentials", json={"note": unique("delegate-child")})
    assert r.status_code == 200, r.text
    child = r.json()
    cleanup.append(child["temp_username"])

    c = _login_temp(child)
    cperms = c.get("/auth/session").json().get("temp_perms") or {}
    assert cperms.get("create") is False, f"child inherited create by omitting scope: {cperms}"
    assert cperms.get("delegate") is False, f"child inherited delegate by omitting scope: {cperms}"
    # The strip must be surgical — inherited read perms survive.
    assert cperms.get("view") is True, f"child lost its inherited view perm: {cperms}"


# --------------------------------------------------------------------------- by-id endpoint confinement
def test_uma_by_id_endpoints_confine_a_scoped_delegate(admin, cleanup):
    """A scoped delegate may not deactivate/delete a credential it did not create via the
    parallel user_management_api by-id endpoints (parity with the api_server twins)."""
    victim = _mint(admin, note=unique("confine-victim"))       # created by the admin MAIN session
    cleanup.append(victim["temp_username"])
    v_id, _ = _cred_id(admin, victim["temp_username"])
    assert v_id, "could not resolve victim id"

    delegate = _mint(admin, note=unique("confine-delegate"), scope=SCOPE_NO_DELEGATE, vault_access_mode="selected")
    cleanup.append(delegate["temp_username"])
    d = _login_temp(delegate)

    assert d.post(f"/api/user-management/temp-credentials/{v_id}/deactivate").status_code == 403
    assert d.delete(f"/api/user-management/temp-credentials/{v_id}").status_code == 403

    # The victim must be untouched and still active.
    _, _ = _cred_id(admin, victim["temp_username"])
    rows = admin.get("/temp-creds/list").json()
    rows = rows if isinstance(rows, list) else rows.get("items", [])
    still = next((r for r in rows if r.get("temp_username") == victim["temp_username"]), None)
    assert still and still.get("is_active"), "blocked mutation must not have persisted"


# --------------------------------------------------------------------------- list scoping + interactive-admin-only mint
def test_uma_list_is_scoped_to_created_creds_for_a_delegate(admin, cleanup):
    """A scoped delegate listing another user's temp creds via the uma router sees only the
    ones IT created — not the target's full listing (whose ids feed the by-id endpoints)."""
    victim = _mint(admin, note=unique("listscope-victim"))
    cleanup.append(victim["temp_username"])
    _, admin_id = _cred_id(admin, victim["temp_username"])  # admin minted victim -> admin's id
    assert admin_id, "could not resolve admin user id"

    delegate = _mint(admin, note=unique("listscope-delegate"), scope=SCOPE_NO_DELEGATE, vault_access_mode="selected")
    cleanup.append(delegate["temp_username"])
    d = _login_temp(delegate)

    r = d.get(f"/api/user-management/users/{admin_id}/temp-credentials")
    assert r.status_code in (200, 304), r.text
    names = [c.get("temp_username") for c in r.json()] if r.status_code == 200 else []
    assert victim["temp_username"] not in names, "delegate enumerated a cred it did not create"


def test_uma_create_for_user_rejects_a_temp_session(admin, cleanup):
    """create_temp_credential_for_user is interactive-admin only — a temp session (even an
    admin-owned one) is refused, so it can't mint unscoped legacy creds for arbitrary users."""
    delegate = _mint(admin, note=unique("mintguard-delegate"), scope=SCOPE_NO_DELEGATE, vault_access_mode="selected")
    cleanup.append(delegate["temp_username"])
    _, admin_id = _cred_id(admin, delegate["temp_username"])
    d = _login_temp(delegate)
    assert d.post(f"/api/user-management/users/{admin_id}/temp-credentials", json={}).status_code == 403


# --------------------------------------------------------------------------- password-endpoint confinement
def test_password_endpoint_confines_a_scoped_delegate(admin, cleanup):
    """GET /temp-creds/{u}/password must apply the ownership + confinement guard its sibling
    mutations enforce: a scoped delegate reading a cred it did not create is denied (403),
    while the owner gets the inert 404 (passwords are one-way hashed, never retrievable)."""
    victim = _mint(admin, note=unique("pwguard-victim"))
    cleanup.append(victim["temp_username"])

    delegate = _mint(admin, note=unique("pwguard-delegate"), scope=SCOPE_NO_DELEGATE, vault_access_mode="selected")
    cleanup.append(delegate["temp_username"])
    d = _login_temp(delegate)

    assert d.get(f"/temp-creds/{victim['temp_username']}/password").status_code == 403
    # Owner path is inert (retrieve always None -> 404), never a password leak.
    assert admin.get(f"/temp-creds/{victim['temp_username']}/password").status_code == 404


# --------------------------------------------------------------------------- atomic one-time-use claim
def test_one_time_credential_is_an_atomic_claim(admin, cleanup):
    """Two concurrent logins with the same one-time credential: exactly one wins, the other
    is rejected as already-used. No second session is minted from a single one-time cred."""
    cred = _mint(admin, note=unique("onetime-race"))
    cleanup.append(cred["temp_username"])
    tu, cp = cred["temp_username"], cred["credential"]

    outcomes = []
    barrier = threading.Barrier(2)

    def racer():
        c = ApiClient(BASE_URL)  # distinct source IP -> own rate-limit bucket
        barrier.wait()
        r = c.session.post(f"{BASE_URL}/auth/login", json={"username": tu, "password": cp},
                           timeout=15)
        outcomes.append(r.status_code)

    threads = [threading.Thread(target=racer) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert outcomes.count(200) == 1, f"exactly one login must win: {outcomes}"


# --------------------------------------------------------------------------- validity-window (deactivate_at) enforcement
def _pg_ident():
    """(user, db) for the vault-db container, or None if docker/container is unavailable."""
    if not shutil.which("docker"):
        return None
    try:
        u = subprocess.run(["docker", "exec", "vault-db", "printenv", "POSTGRES_USER"],
                           capture_output=True, text=True, timeout=10)
        d = subprocess.run(["docker", "exec", "vault-db", "printenv", "POSTGRES_DB"],
                           capture_output=True, text=True, timeout=10)
    except Exception:  # noqa: BLE001
        return None
    if u.returncode != 0 or d.returncode != 0:
        return None
    return u.stdout.strip(), d.stdout.strip()


def _backdate_deactivate_at(temp_username):
    ident = _pg_ident()
    if not ident:
        return False
    user, db = ident
    r = subprocess.run(
        ["docker", "exec", "vault-db", "psql", "-U", user, "-d", db, "-c",
         "UPDATE temporary_credentials SET deactivate_at = NOW() - INTERVAL '5 minutes' "
         f"WHERE temp_username = '{temp_username}';"],
        capture_output=True, text=True, timeout=15)
    return r.returncode == 0 and "UPDATE 1" in r.stdout


def test_validity_window_deactivate_at_is_enforced(admin, cleanup):
    """A credential whose validity window (deactivate_at) has closed must stop authenticating
    even while its hard expiry (expires_at) is hours away — the advertised window is real."""
    cred = _mint(admin, note=unique("validity-window"), validity_minutes=60, total_lifetime_minutes=1440)
    cleanup.append(cred["temp_username"])
    if not _backdate_deactivate_at(cred["temp_username"]):
        pytest.skip("cannot backdate deactivate_at (docker/vault-db unavailable)")

    c = ApiClient(BASE_URL)
    r = c.session.post(f"{BASE_URL}/auth/login",
                       json={"username": cred["temp_username"], "password": cred["credential"]},
                       timeout=15)
    assert r.status_code == 401, f"login past deactivate_at must be rejected: {r.status_code}"


def test_validity_window_enforced_per_request_on_a_live_session(admin, cleanup):
    """Even an already-issued session token stops working once the credential's validity
    window closes (per-request bound, not just at login)."""
    cred = _mint(admin, note=unique("validity-perreq"), validity_minutes=60, total_lifetime_minutes=1440)
    cleanup.append(cred["temp_username"])
    c = _login_temp(cred)                       # a live session before backdating
    assert c.get("/auth/session").status_code == 200
    if not _backdate_deactivate_at(cred["temp_username"]):
        pytest.skip("cannot backdate deactivate_at (docker/vault-db unavailable)")
    assert c.get("/auth/session").status_code == 401, "live session must die past deactivate_at"
