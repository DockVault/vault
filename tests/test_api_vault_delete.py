"""Vault deletion via the real POST /vaults/{id}/delete route.

The web UI used to send DELETE /vaults/{id} (no such route -> 405); the real route is
POST /vaults/{id}/delete. These lock the route in and, importantly, that a
password-protected vault can be deleted by proving the password through the
X-Vault-Password HEADER (the convention every other password-gated vault route uses),
not only the legacy ?vault_password= query string.
"""


def test_delete_plain_vault(admin):
    v = admin.create_vault()
    r = admin.post(f"/vaults/{v['id']}/delete")
    assert r.status_code == 200, r.text
    assert admin.get(f"/vaults/{v['id']}").status_code in (403, 404)


def test_delete_password_vault_without_password_is_refused(admin):
    v = admin.create_vault(password="DelPass!123long")
    try:
        r = admin.post(f"/vaults/{v['id']}/delete")  # no password proof at all
        assert r.status_code in (401, 403), r.text
        assert admin.get(f"/vaults/{v['id']}").status_code == 200  # survives
    finally:
        admin.delete_vault(v["id"], vault_password="DelPass!123long")


def test_delete_password_vault_via_header(admin):
    """The X-Vault-Password header proves the password — what the fixed frontend sends."""
    v = admin.create_vault(password="DelPass!123long")
    r = admin.post(
        f"/vaults/{v['id']}/delete",
        headers={"X-Vault-Password": "DelPass!123long"},
    )
    assert r.status_code == 200, r.text
    assert admin.get(f"/vaults/{v['id']}").status_code in (403, 404)


def test_delete_password_vault_wrong_header_rejected(admin):
    v = admin.create_vault(password="DelPass!123long")
    try:
        r = admin.post(
            f"/vaults/{v['id']}/delete",
            headers={"X-Vault-Password": "wrong-password"},
        )
        assert r.status_code in (401, 403), r.text
        # The header WAS read and the password was rejected as invalid — not merely
        # "password required" (which is what a route that ignores the header returns).
        assert "invalid" in r.text.lower(), r.text
        assert admin.get(f"/vaults/{v['id']}").status_code == 200  # survives
    finally:
        admin.delete_vault(v["id"], vault_password="DelPass!123long")
