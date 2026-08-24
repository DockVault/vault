"""UI — the anonymous public-note-link redemption page (/l/{token}).

No login: a visitor opens the link, is prompted for a secret only when the link needs one, and sees
the frozen snapshot rendered as TEXT (never markup)."""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


@pytest.fixture
def links_on(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in ("public_note_links_enabled", "public_note_link_user_cap")}
    admin.put("/settings", json={"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    yield
    admin.put("/settings", json=snap)


def _note(admin, title, body):
    return admin.post("/notes", json={"title": title, "body": body}).json()["id"]


def _open_tag(admin):
    return next(t for t in admin.get("/note-link-tags").json() if t["name"] == "Open")


def _pw_tag(admin):
    return admin.post("/note-link-tags", json={"name": unique("pwtag"), "min_token_len": 10,
                                               "require_secret": "password", "password_min_len": 8,
                                               "auto_enroll_new_users": True}).json()


def test_no_secret_link_renders_snapshot(page: Page, admin, links_on):
    note_id = _note(admin, "Public Title", "line one\nline two")
    tag = _open_tag(admin)
    link = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
    page.goto(f"/l/{link['token']}")
    expect(page.locator("#content")).to_be_visible(timeout=10000)
    expect(page.locator("#note-title")).to_have_text("Public Title")
    expect(page.locator("#note-body")).to_contain_text("line one")
    expect(page.locator("#note-body")).to_contain_text("line two")


def test_note_body_is_rendered_as_text_not_markup(page: Page, admin, links_on):
    payload = "<img src=x onerror=alert(1)><b>bolded</b>"
    note_id = _note(admin, "XSS <script>test</script>", payload)
    tag = _open_tag(admin)
    link = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"]}).json()
    errors = []
    page.on("pageerror", lambda e: errors.append(str(e)))
    page.goto(f"/l/{link['token']}")
    expect(page.locator("#content")).to_be_visible(timeout=10000)
    # The literal markup shows as text; no injected elements are created.
    expect(page.locator("#note-body")).to_contain_text("<img src=x")
    assert page.locator("#note-body b").count() == 0, "note body must not create real elements"
    assert page.locator("#note-body img").count() == 0
    expect(page.locator("#note-title")).to_contain_text("<script>")
    assert not errors, f"unexpected page errors: {errors}"


def test_password_link_prompts_then_unlocks(page: Page, admin, links_on):
    note_id = _note(admin, "Protected", "the protected body")
    tag = _pw_tag(admin)
    link = admin.post("/note-links", json={"note_id": note_id, "tag_id": tag["id"],
                                           "password": "hunter2x"}).json()
    page.goto(f"/l/{link['token']}")
    # Prompt appears (no content yet).
    expect(page.locator("#secret-form")).to_be_visible(timeout=10000)
    expect(page.locator("#content")).to_be_hidden()
    # Wrong secret -> inline error, still prompting.
    page.fill("#secret-input", "wrongpass1")
    page.click("#secret-submit")
    expect(page.locator("#secret-error")).to_be_visible(timeout=10000)
    expect(page.locator("#content")).to_be_hidden()
    # Correct secret -> content.
    page.fill("#secret-input", "hunter2x")
    page.click("#secret-submit")
    expect(page.locator("#content")).to_be_visible(timeout=10000)
    expect(page.locator("#note-body")).to_have_text("the protected body")


def test_unknown_token_shows_notice(page: Page, admin, links_on):
    page.goto("/l/nonexistenttoken99")
    expect(page.locator("#notice")).to_be_visible(timeout=10000)
    expect(page.locator("#content")).to_be_hidden()
