"""The admin password policy (min length + complexity) is enforced on account create + change."""
from conftest import unique


def _set(admin, **kw):
    r = admin.put("/settings", json=kw)
    assert r.status_code in (200, 204), r.text


def _reset(admin):
    _set(admin, password_min_length=8, require_uppercase=False, require_lowercase=False,
         require_numbers=False, require_special=False)


def _create(admin, password):
    return admin.post("/users", json={"username": unique("pp"), "email": unique("pp") + "@ex.com",
                                      "password": password, "role": "user"})


def test_policy_enforced_on_create(admin):
    # set the FULL policy (the shared instance's settings persist between tests/runs)
    _set(admin, password_min_length=14, require_uppercase=True, require_lowercase=False,
         require_numbers=True, require_special=False)
    made = []
    try:
        # long enough but no uppercase -> rejected with a policy message
        weak = _create(admin, "abcdefghijklmn1")
        assert weak.status_code == 400, weak.text
        assert "password must" in weak.text.lower()
        # too short even though complex
        short = _create(admin, "Abcd1")
        assert short.status_code in (400, 422), short.text  # 422 = the model's 8-char floor
        # satisfies min 14 + uppercase + number
        ok = _create(admin, "Abcdefghijklmn1")
        assert ok.status_code == 200, ok.text
        made.append(ok.json()["id"])
    finally:
        for uid in made:
            admin.delete_user(uid)
        _reset(admin)


def test_policy_enforced_on_password_change(admin):
    u = admin.create_user(role="user")
    try:
        _set(admin, password_min_length=8, require_uppercase=False, require_lowercase=False,
             require_numbers=False, require_special=True)
        weak = admin.patch(f"/users/{u['id']}", json={"password": "nospecials123X"})
        assert weak.status_code == 400, weak.text
        ok = admin.patch(f"/users/{u['id']}", json={"password": "withSpecial1!"})
        assert ok.status_code == 200, ok.text
    finally:
        _reset(admin)
        admin.delete_user(u["id"])


def test_settings_validation_rejects_bad_password_policy(admin):
    try:
        assert admin.put("/settings", json={"password_min_length": -1}).status_code == 400
        assert admin.put("/settings", json={"password_min_length": "abc"}).status_code == 400
        assert admin.put("/settings", json={"require_uppercase": "yes"}).status_code == 400
        assert admin.put("/settings", json={"password_min_length": 16, "require_special": True}).status_code in (200, 204)
    finally:
        _reset(admin)
