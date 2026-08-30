"""The admin second-factor policy matrix: it seeds at boot, renders in catalog order, is admin-only, and
each action carries the owner's two independent toggles (require_otp + require_password)."""


def test_matrix_seeded_and_read(admin):
    # Reading the matrix is not gated.
    r = admin.get("/second-factor/actions")
    assert r.status_code == 200, r.text
    actions = {a["key"]: a for a in r.json()["actions"]}
    # the catalog is seeded in catalog order; every guarded route is present (receiver.create is the
    # built POST /receivers step-up route).
    assert "login" in actions and "admin.user.manage" in actions and "vault.delete" in actions
    assert "receiver.create" in actions
    # Owner's model B: a fresh deploy forces MFA on NO ONE -- require_otp ships ON only for login +
    # manage-2FA (both never lock anyone out); admin management + every other action ship OFF (opt-in).
    assert actions["login"]["require_otp"] is True and actions["account.second_factor"]["require_otp"] is True
    assert actions["admin.user.manage"]["require_otp"] is False and actions["admin.settings.write"]["require_otp"] is False
    assert actions["vault.delete"]["require_otp"] is False and actions["vault.change_password"]["require_otp"] is False
    assert all(a["require_password"] is False for a in actions.values())
    # (Changing the matrix is gated by the account.second_factor step-up -- see test_api_second_factor_config.)


def test_matrix_is_admin_only(temp_user_client):
    assert temp_user_client.get("/second-factor/actions").status_code in (401, 403)
    assert temp_user_client.put("/second-factor/actions/vault.delete",
                                json={"require_otp": True}).status_code in (401, 403)
