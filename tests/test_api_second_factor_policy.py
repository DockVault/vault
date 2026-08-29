"""The admin second-factor policy matrix: it seeds at boot, renders in catalog order, is admin-only, and
each action carries the owner's two independent toggles (require_otp + require_password)."""


def test_matrix_seeded_and_togglable(admin):
    r = admin.get("/second-factor/actions")
    assert r.status_code == 200, r.text
    actions = {a["key"]: a for a in r.json()["actions"]}
    # the catalog is seeded; routes that don't exist yet are absent (they'd trip the boot contract)
    assert "login" in actions and "admin.user.manage" in actions and "vault.delete" in actions
    assert "receiver.create" not in actions
    # sensible seed defaults: admin management on, a low-risk vault password change off, password opt-in off
    assert actions["admin.user.manage"]["require_otp"] is True
    assert actions["vault.change_password"]["require_otp"] is False
    assert all(a["require_password"] is False for a in actions.values())

    # toggle require_password on an action (owner's second toggle), leaving require_otp untouched
    r = admin.put("/second-factor/actions/vault.delete", json={"require_password": True})
    assert r.status_code == 200 and r.json()["require_password"] is True
    actions = {a["key"]: a for a in admin.get("/second-factor/actions").json()["actions"]}
    assert actions["vault.delete"]["require_password"] is True
    assert actions["vault.delete"]["require_otp"] is True     # its seeded default, unchanged by the toggle

    # an unknown key is refused
    assert admin.put("/second-factor/actions/not.a.real.action", json={"require_otp": True}).status_code == 404
    # restore so the shared instance isn't left mutated
    admin.put("/second-factor/actions/vault.delete", json={"require_password": False}).raise_for_status()


def test_matrix_is_admin_only(temp_user_client):
    assert temp_user_client.get("/second-factor/actions").status_code in (401, 403)
    assert temp_user_client.put("/second-factor/actions/vault.delete",
                                json={"require_otp": True}).status_code in (401, 403)
