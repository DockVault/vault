"""Per-user UI preferences endpoints (GET/PUT /users/me/preferences).

These back the server-side theme/accent/background/skin sync so a user's look
follows their ACCOUNT across browsers and devices. The endpoints are self-only
(no user_id param) and whitelist every value on the way in and out.
"""


def test_preferences_default_is_empty(temp_user_client):
    """A user who has never saved a preference gets an empty object, not an error."""
    r = temp_user_client.get("/users/me/preferences")
    assert r.status_code == 200, r.text
    assert r.json() == {}


def test_preferences_put_then_get_roundtrip(temp_user_client):
    body = {"theme": "dark", "accent": "violet", "background": "navy", "ui": "v2"}
    r = temp_user_client.put("/users/me/preferences", json=body)
    assert r.status_code == 200, r.text
    assert r.json() == body
    # A subsequent GET returns the same stored set.
    r2 = temp_user_client.get("/users/me/preferences")
    assert r2.status_code == 200
    assert r2.json() == body


def test_preferences_partial_update_merges(temp_user_client):
    """A partial PUT changes only the provided keys; the rest are left intact."""
    temp_user_client.put("/users/me/preferences", json={"theme": "light", "accent": "teal"})
    r = temp_user_client.put("/users/me/preferences", json={"accent": "rose"})
    assert r.status_code == 200, r.text
    merged = r.json()
    assert merged.get("theme") == "light"   # untouched
    assert merged.get("accent") == "rose"    # updated


def test_preferences_reject_invalid_values(temp_user_client):
    """Values outside the whitelist are dropped; valid ones in the same call persist.

    The client writes these straight into DOM attributes/localStorage, so the server
    must never store a value the client wouldn't itself produce.
    """
    r = temp_user_client.put(
        "/users/me/preferences",
        json={"theme": "neon", "accent": "teal", "ui": "v9", "bogus": "x"},
    )
    assert r.status_code == 200, r.text
    out = r.json()
    assert out == {"accent": "teal"}          # only the one valid value survived
    assert "theme" not in out and "ui" not in out and "bogus" not in out


def test_preferences_require_auth(anon):
    # No Authorization header -> 403 (HTTPBearer); an invalid token -> 401.
    assert anon.get("/users/me/preferences").status_code in (401, 403)
    assert anon.put("/users/me/preferences", json={"theme": "dark"}).status_code in (401, 403)


def test_preferences_isolated_per_user(admin, temp_user, temp_user_client):
    """Two accounts keep entirely separate preference rows (no cross-leak)."""
    other = admin.create_user(role="user")
    try:
        c2 = admin.clone_anonymous()
        c2.login(other["_username"], other["_password"])
        temp_user_client.put("/users/me/preferences", json={"theme": "dark", "accent": "orange"})
        c2.put("/users/me/preferences", json={"theme": "light", "accent": "sky"})
        # Each account reads back exactly its own set — neither write clobbered the other.
        assert temp_user_client.get("/users/me/preferences").json() == {"theme": "dark", "accent": "orange"}
        assert c2.get("/users/me/preferences").json() == {"theme": "light", "accent": "sky"}
    finally:
        admin.delete_user(other["id"])
