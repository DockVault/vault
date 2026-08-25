"""Live API: the admin-configurable max note size + the owner-facing link body snapshot."""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration


@pytest.fixture
def restore_note_max(admin):
    before = admin.get("/settings").json().get("note_max_chars")
    yield
    admin.put("/settings", json={"note_max_chars": before if before else 100000})


def test_note_max_chars_default_and_surfaced(admin):
    s = admin.get("/settings").json()
    assert "note_max_chars" in s and isinstance(s["note_max_chars"], int)


def test_note_max_chars_enforced_and_configurable(admin, restore_note_max):
    # Lower the cap, then a too-long note is refused and a short one is accepted.
    assert admin.put("/settings", json={"note_max_chars": 200}).status_code == 200
    over = admin.post("/notes", json={"title": unique("Big"), "body": "x" * 300})
    assert over.status_code == 400, over.text
    ok = admin.post("/notes", json={"title": unique("Ok"), "body": "x" * 150})
    assert ok.status_code == 200, ok.text
    # Raise the cap and the previously-too-long note now fits.
    assert admin.put("/settings", json={"note_max_chars": 1000}).status_code == 200
    assert admin.post("/notes", json={"title": unique("Now"), "body": "x" * 300}).status_code == 200


def test_note_max_chars_validation(admin, restore_note_max):
    for bad in ({"note_max_chars": 50}, {"note_max_chars": 2_000_000},
                {"note_max_chars": "x"}, {"note_max_chars": True}):
        assert admin.put("/settings", json=bad).status_code == 400, bad


def test_owner_link_list_has_body_admin_list_does_not(admin):
    before = admin.get("/settings").json().get("public_note_links_enabled")
    admin.put("/settings", json={"public_note_links_enabled": True})
    u = admin.create_user(role="user")
    user = admin.clone_anonymous(); user.login(u["_username"], u["_password"])
    try:
        note_id = user.post("/notes", json={"title": unique("T"), "body": "the secret snapshot body"}).json()["id"]
        tag = next(t for t in admin.get("/note-link-tags").json() if t["name"] == "Open")
        link = user.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
        # Owner sees the body snapshot on their own link (to recall its content).
        mine = next(x for x in user.get("/note-links").json()["links"] if x["id"] == link["id"])
        assert mine.get("body") == "the secret snapshot body"
        # Admin oversight list must NOT include the body.
        arow = next(x for x in admin.get("/admin/note-links").json()["links"] if x["id"] == link["id"])
        assert "body" not in arow
    finally:
        admin.delete_user(u["id"])
        admin.put("/settings", json={"public_note_links_enabled": bool(before)})
