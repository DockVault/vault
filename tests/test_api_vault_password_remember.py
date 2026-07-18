"""Vault-password remembering: the deployment-wide org floor + the per-user opt-out preference.

The org floor (a deployment setting) clamps every vault's EFFECTIVE unlock_remember_minutes to 0
on both reads (non-destructive overlay) and writes (persisted), so a user must re-enter a vault's
password each time. The per-user preference is a string enum ('on'/'off') that round-trips through
the preferences store, and the preferences read also surfaces the effective org floor so the account
UI can show the toggle as forced.
"""
import uuid

_PW = "Sup3r-Secret-PW-9!"


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _urm(client, vault_id):
    r = client.get(f"/vaults/{vault_id}")
    r.raise_for_status()
    return r.json().get("unlock_remember_minutes")


def _set_floor(admin, on):
    admin.put("/settings", json={"force_no_remember_vault_password": on}).raise_for_status()


def test_org_floor_clamps_unlock_remember_minutes(admin):
    _set_floor(admin, False)
    v = admin.create_vault(name=_u("rmb"), password=_PW)
    vid = v["id"]
    try:
        # floor OFF: a real unlock window persists and reads back
        admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 30}).raise_for_status()
        assert _urm(admin, vid) == 30
        # the list view reflects the same effective value
        row = next(x for x in admin.get("/vaults").json() if x["id"] == vid)
        assert row["unlock_remember_minutes"] == 30

        # floor ON: reads are clamped to 0 (overlay), but the stored value is untouched
        _set_floor(admin, True)
        assert _urm(admin, vid) == 0
        row = next(x for x in admin.get("/vaults").json() if x["id"] == vid)
        assert row["unlock_remember_minutes"] == 0

        # floor OFF again: the original stored value comes back -> the read overlay is non-destructive
        _set_floor(admin, False)
        assert _urm(admin, vid) == 30

        # floor ON: a WRITE is clamped and PERSISTS 0 (no-downgrade once the org forbids remembering)
        _set_floor(admin, True)
        admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 45}).raise_for_status()
        assert _urm(admin, vid) == 0
        _set_floor(admin, False)
        assert _urm(admin, vid) == 0  # the write clamp stuck
    finally:
        _set_floor(admin, False)
        admin.delete_vault(vid, vault_password=_PW)


def test_patch_echoes_clamped_unlock_window(admin):
    """The settings PATCH echoes the STORED (clamped) window so the client can't cache a password
    on a locally-submitted window the org floor forbids."""
    _set_floor(admin, False)
    v = admin.create_vault(name=_u("echo"), password=_PW)
    vid = v["id"]
    try:
        r = admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 60})
        r.raise_for_status()
        assert r.json()["unlock_remember_minutes"] == 60  # floor off -> as submitted

        _set_floor(admin, True)
        r = admin.patch(f"/vaults/{vid}/settings", json={"unlock_remember_minutes": 60})
        r.raise_for_status()
        assert r.json()["unlock_remember_minutes"] == 0   # floor on -> clamped in the echo
    finally:
        _set_floor(admin, False)
        admin.delete_vault(vid, vault_password=_PW)


def test_org_floor_rejects_non_bool(admin):
    r = admin.put("/settings", json={"force_no_remember_vault_password": "yes"})
    assert r.status_code == 400, r.text
    _set_floor(admin, False)


def test_never_remember_preference_round_trip(admin):
    try:
        # set the opt-out -> it round-trips as the 'on' string
        admin.put("/users/me/preferences", json={"never_remember_vault_password": "on"}).raise_for_status()
        assert admin.get("/users/me/preferences").json()["never_remember_vault_password"] == "on"

        # a bare bool is dropped by the sanitizer (string-enum whitelist), leaving the prior value
        admin.put("/users/me/preferences", json={"never_remember_vault_password": True})
        assert admin.get("/users/me/preferences").json()["never_remember_vault_password"] == "on"

        # an out-of-enum string is likewise dropped
        admin.put("/users/me/preferences", json={"never_remember_vault_password": "maybe"})
        assert admin.get("/users/me/preferences").json()["never_remember_vault_password"] == "on"

        # clear it
        admin.put("/users/me/preferences", json={"never_remember_vault_password": "off"}).raise_for_status()
        assert admin.get("/users/me/preferences").json()["never_remember_vault_password"] == "off"
    finally:
        admin.put("/users/me/preferences", json={"never_remember_vault_password": "off"})


def test_org_floor_surfaced_on_temp_passcode_policy(admin):
    """The account UI learns the effective floor from the non-admin /temp-passcode-policy read."""
    try:
        _set_floor(admin, False)
        assert admin.get("/temp-passcode-policy").json()["force_no_remember_vault_password"] is False
        _set_floor(admin, True)
        assert admin.get("/temp-passcode-policy").json()["force_no_remember_vault_password"] is True
    finally:
        _set_floor(admin, False)
