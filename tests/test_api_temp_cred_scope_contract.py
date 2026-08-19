"""A temp-credential mint must not silently ignore a vault restriction list.

The no-scope mint path is legacy UNRESTRICTED. A caller that sends `selected_vaults` (a restriction)
without a `scope` used to have that list silently dropped and receive a credential reaching
everything the minting account can -- a delegation surprise. The mint now rejects that contradictory
shape 400 instead of returning an over-broad credential. The vault UI never produces it (it always
sends a scope alongside selected_vaults), so the two legitimate shapes -- unrestricted (nothing) and
scoped (scope + list) -- are unaffected.
"""
from conftest import ApiClient, unique


def _scope(caps=("vault.see_info",)):
    return {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": list(caps), "temp": {}}


def test_selected_vaults_without_scope_is_rejected(admin):
    """The bug: a restriction list with no scope must not mint an unrestricted credential."""
    v = admin.create_vault(name=unique("tcsc"))
    try:
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 30,
            "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": v["id"], "caps": ["vault.see_info"]}],
            # no "scope" -> legacy unrestricted path
        })
        assert r.status_code == 400, r.text
        assert "scope" in r.text.lower()
    finally:
        admin.delete_vault(v["id"])


def test_unrestricted_mint_still_works(admin):
    """Nothing sent = the legitimate legacy unrestricted credential; still allowed."""
    r = admin.post("/auth/temp-credentials", json={"validity_minutes": 30})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("scope") in (None, {})           # unrestricted
    # And it actually works as a credential.
    c = ApiClient()
    try:
        c.login(body["temp_username"], body["credential"])
        assert c.get("/vaults").status_code == 200
    finally:
        admin.post(f"/temp-creds/{body['temp_username']}/delete")


def test_scoped_mint_still_works_and_is_restricted(admin):
    """The legitimate scoped shape (scope + selected_vaults) is untouched and stays restricted."""
    v = admin.create_vault(name=unique("tcsc-ok"))
    try:
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 30,
            "scope": _scope(),
            "vault_access_mode": "selected",
            "selected_vaults": [{"vault_id": v["id"], "caps": ["vault.see_info"]}],
        })
        assert r.status_code == 200, r.text
        body = r.json()
        assert body.get("scope") is not None          # a real restriction was recorded, not dropped
        assert body.get("vault_access_mode") == "selected"
    finally:
        admin.delete_vault(v["id"])


def test_all_mode_with_selected_vaults_is_rejected(admin):
    """The symmetric contradiction: 'all' mode reaches every vault, so a restriction list sent with
    it would be silently dropped -- rejected the same way as the no-scope case."""
    v = admin.create_vault(name=unique("tcsc-all"))
    try:
        r = admin.post("/auth/temp-credentials", json={
            "validity_minutes": 30,
            "scope": _scope(),
            "vault_access_mode": "all",
            "selected_vaults": [{"vault_id": v["id"], "caps": ["vault.see_info"]}],
        })
        assert r.status_code == 400, r.text
        assert "all-vault" in r.text.lower() or "all vault" in r.text.lower()
    finally:
        admin.delete_vault(v["id"])


def test_all_mode_without_a_list_still_works(admin):
    """The legitimate all-vaults credential (all mode, empty/no list) is untouched."""
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30, "scope": _scope(), "vault_access_mode": "all", "selected_vaults": [],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    assert body.get("vault_access_mode") == "all"
    admin.post(f"/temp-creds/{body['temp_username']}/delete")


def test_empty_selected_vaults_without_scope_is_still_unrestricted(admin):
    """An empty list is not a restriction request, so the legacy unrestricted path is unchanged."""
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30, "vault_access_mode": "selected", "selected_vaults": [],
    })
    assert r.status_code == 200, r.text
    body = r.json()
    admin.post(f"/temp-creds/{body['temp_username']}/delete")
