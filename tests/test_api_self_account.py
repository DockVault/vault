"""Self-service account management via PATCH /users/me (usable by non-admins, blocked for temp creds)."""


def _client_for(admin, username, password):
    c = admin.clone_anonymous()
    c.login(username, password)
    return c


def test_non_admin_self_password_change_requires_current(admin):
    u = admin.create_user(role="user")  # conftest password: TestPassw0rd!123
    try:
        c = _client_for(admin, u["_username"], u["_password"])
        # a regular user CAN reach this endpoint (unlike PATCH /users/{id}, which needs USER_MANAGE)
        assert c.patch("/users/me", json={"new_password": "NewPassw0rd!456"}).status_code == 400  # no current
        assert c.patch("/users/me", json={"current_password": "wrong",
                                          "new_password": "NewPassw0rd!456"}).status_code == 400  # wrong current
        ok = c.patch("/users/me", json={"current_password": u["_password"], "new_password": "NewPassw0rd!456"})
        assert ok.status_code == 200, ok.text
        # the new password works; the old one doesn't
        fresh = admin.clone_anonymous()
        assert fresh.post("/auth/login", json={"username": u["_username"], "password": "NewPassw0rd!456"}).status_code == 200
        assert fresh.post("/auth/login", json={"username": u["_username"], "password": u["_password"]}).status_code != 200
    finally:
        admin.delete_user(u["id"])


def test_self_email_change_requires_current_password(admin):
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u["_username"], u["_password"])
        assert c.patch("/users/me", json={"email": "new@example.com"}).status_code == 400  # no current pw
        ok = c.patch("/users/me", json={"current_password": u["_password"], "email": "new@example.com"})
        assert ok.status_code == 200, ok.text
        assert ok.json()["email"] == "new@example.com"
        # a clash with another account's email is a clean 400, not a 500
        clash = c.patch("/users/me", json={"current_password": u["_password"], "email": admin.user["email"]})
        assert clash.status_code == 400, clash.text
    finally:
        admin.delete_user(u["id"])


def test_self_sftp_toggle_needs_no_password(admin):
    u = admin.create_user(role="user")
    try:
        c = _client_for(admin, u["_username"], u["_password"])
        r = c.patch("/users/me", json={"sftp_enabled": False})
        assert r.status_code == 200, r.text
        assert r.json()["sftp_enabled"] is False
    finally:
        admin.delete_user(u["id"])


def test_self_password_policy_enforced(admin):
    u = admin.create_user(role="user")
    try:
        admin.put("/settings", json={"password_min_length": 20})
        c = _client_for(admin, u["_username"], u["_password"])
        weak = c.patch("/users/me", json={"current_password": u["_password"], "new_password": "TooShort1!"})
        assert weak.status_code == 400, weak.text
    finally:
        admin.put("/settings", json={"password_min_length": 8})
        admin.delete_user(u["id"])


def test_temp_credential_cannot_change_account(admin):
    scope = {"v": 1, "pages": ["dashboard", "vaults"], "caps": [],
             "vault_caps_default": ["vault.see_info"], "temp": {}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 60, "scope": scope, "vault_access_mode": "all", "selected_vaults": []}).json()
    c = _client_for(admin, body["temp_username"], body["credential"])
    r = c.patch("/users/me", json={"current_password": "x", "new_password": "Whatever12!"})
    assert r.status_code == 403, r.text
