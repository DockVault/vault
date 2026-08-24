"""Live API: public-note-link admin foundation — settings, note-link tag CRUD, and seeded defaults."""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration


@pytest.fixture
def restore_link_settings(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    yield
    admin.put("/settings", json=snap)


def test_seeded_default_tags_present(admin):
    tags = {t["name"]: t for t in admin.get("/note-link-tags").json()}
    for name in ("Open", "Restricted", "Confidential"):
        assert name in tags, f"{name} seed tag missing"
    assert tags["Open"]["min_token_len"] == 6
    assert tags["Confidential"]["require_secret"] == "password"
    assert tags["Confidential"]["max_uses_cap"] == 1


def test_settings_roundtrip_and_validation(admin, restore_link_settings):
    r = admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 25})
    assert r.status_code == 200, r.text
    s = admin.get("/settings").json()
    assert s["public_note_links_enabled"] is True
    assert s["public_note_link_user_cap"] == 25
    # Invalid values are refused and not persisted.
    for bad in ({"public_note_links_enabled": "yes"}, {"public_note_link_user_cap": 0},
                {"public_note_link_user_cap": -5}):
        assert admin.put("/settings", json=bad).status_code == 400, bad
    assert admin.get("/settings").json()["public_note_link_user_cap"] == 25


def test_tag_crud_admin(admin):
    name = unique("cfgtag")
    r = admin.post("/note-link-tags", json={"name": name, "min_token_len": 12,
                                            "require_secret": "pin", "min_pin_len": 6,
                                            "border_color": "indigo", "icon": "lock"})
    assert r.status_code == 200, r.text
    tid = r.json()["id"]
    assert r.json()["require_secret"] == "pin" and r.json()["min_pin_len"] == 6
    try:
        # Duplicate name → 400.
        assert admin.post("/note-link-tags", json={"name": name}).status_code == 400
        # Patch (only provided keys change).
        r = admin.patch(f"/note-link-tags/{tid}", json={"max_ttl_hours": 48, "description": "d"})
        assert r.status_code == 200 and r.json()["max_ttl_hours"] == 48
        assert r.json()["require_secret"] == "pin"   # unchanged
        # Deactivate.
        assert admin.delete(f"/note-link-tags/{tid}").status_code == 200
        assert any(t["id"] == tid and t["is_active"] is False
                   for t in admin.get("/note-link-tags").json())
    finally:
        pass  # soft-deactivated tags are left (no hard delete), harmless in a throwaway round


@pytest.mark.parametrize("payload", [
    {"name": "x", "min_token_len": 5},          # below the 6 floor
    {"name": "x", "require_secret": "otp"},     # bad secret kind
    {"name": "x", "min_pin_len": 5},            # not in {4,6,8}
    {"name": "x", "default_ttl_hours": 48, "max_ttl_hours": 24},  # default > max
    {"name": ""},                               # empty name
])
def test_tag_field_validation_400(admin, payload):
    assert admin.post("/note-link-tags", json=payload).status_code == 400, payload


def test_tag_management_requires_interactive_admin(admin):
    u = admin.create_user(role="user")
    c = admin.clone_anonymous(); c.login(u["_username"], u["_password"])
    tc = admin.post("/auth/temp-credentials", json={"validity_minutes": 30}).json()
    temp = ApiClient(BASE_URL); temp.login(tc["temp_username"], tc["credential"])
    try:
        for cl in (c, temp):
            assert cl.get("/note-link-tags").status_code == 403
            assert cl.post("/note-link-tags", json={"name": unique("x")}).status_code == 403
        # A non-admin also cannot flip the public-note-link settings.
        assert c.put("/settings", json={"public_note_links_enabled": True}).status_code == 403
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")
        admin.delete_user(u["id"])
