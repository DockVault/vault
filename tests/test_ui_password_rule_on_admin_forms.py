"""One password rule on the administrators' forms: Create User and Change User Password read the deployment's
policy (static/js/password-policy.js) instead of a number written into the form.

The server's rule is the one in Settings > Security (a minimum length floored at 8, and the complexity
switches), and the server applies it to every password it is given. The two administrator forms said
"Minimum 12 characters" and refused shorter ones themselves, whatever the rule was, while Settings said the floor
was 8 and the sign-up form read the real rule: three surfaces, three rules. Now the forms read the policy when
they open, show it in one sentence, set it as the fields' minimum, and refuse only what the server would refuse.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui


@pytest.fixture
def policy(admin):
    """The password rule set for the test and put back after it."""
    before = admin.get("/settings").json()
    keep = {k: before.get(k) for k in ("password_min_length", "require_uppercase", "require_lowercase",
                                       "require_numbers", "require_special")}

    def set_rule(**rule):
        r = admin.put("/settings", json=rule)
        assert r.status_code in (200, 204), r.text

    yield set_rule
    admin.put("/settings", json={k: (v if v is not None else 8 if k == "password_min_length" else False)
                                 for k, v in keep.items()})


def _login(page: Page, creds):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", creds["username"])
    page.fill("#password", creds["password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_users(page: Page):
    page.click('.sidebar-item[data-section="users"]')
    expect(page.locator("#users-section")).to_be_visible(timeout=10000)


def test_create_user_shows_the_rule_and_accepts_what_it_allows(page: Page, admin, admin_creds, policy):
    policy(password_min_length=10, require_uppercase=False, require_lowercase=False,
           require_numbers=False, require_special=False)
    _login(page, admin_creds)
    _open_users(page)
    page.click("#create-user-btn")
    expect(page.locator("#create-user-modal.active")).to_be_visible()
    expect(page.locator("#new-password-hint")).to_have_text("At least 10 characters.", timeout=10000)
    expect(page.locator("#new-password")).to_have_attribute("minlength", "10")
    name = unique("ten")
    page.fill("#new-username", name)
    page.fill("#new-password", "abcdefghij")  # ten: refused by a rule of twelve, allowed by this one
    page.click("#create-user-form button[type=submit]")
    expect(page.locator("#create-user-modal.active")).to_be_hidden(timeout=15000)
    made = [u for u in admin.get("/users").json() if u["username"] == name]
    assert made, "the ten-character password was not accepted"
    admin.delete_user(made[0]["id"])


def test_change_user_password_shows_the_rule_and_refuses_what_it_forbids(page: Page, admin, admin_creds, policy):
    policy(password_min_length=14, require_uppercase=True, require_lowercase=False,
           require_numbers=True, require_special=False)
    u = admin.create_user(role="user")
    try:
        _login(page, admin_creds)
        _open_users(page)
        page.click(f'#users-list .exp-row[data-id="{u["id"]}"] .exp-toggle')  # the actions sit in the row's details
        page.click(f'.change-password-btn[data-user-id="{u["id"]}"]')
        expect(page.locator("#change-password-modal.active")).to_be_visible()
        expect(page.locator("#change-password-hint")).to_have_text(
            "At least 14 characters, with an uppercase letter and a number.", timeout=10000)
        expect(page.locator("#change-password-new")).to_have_attribute("minlength", "14")
        expect(page.locator("#change-password-confirm")).to_have_attribute("minlength", "14")
        # Long enough for the form's minimum but missing the number: refused with the rule's own words, and
        # nothing is sent.
        sent = []
        page.on("request", lambda r: sent.append(r.url) if r.method == "PATCH" and f"/users/{u['id']}" in r.url else None)
        page.fill("#change-password-new", "Abcdefghijklmnop")
        page.fill("#change-password-confirm", "Abcdefghijklmnop")
        page.click("#change-password-form button[type=submit]")
        expect(page.locator(".toast-error", has_text="include a number")).to_be_visible(timeout=10000)
        page.wait_for_timeout(500)
        assert not sent, "a password the rule refuses was sent"
        # One that the rule allows goes through.
        page.fill("#change-password-new", "Abcdefghijklmno1")
        page.fill("#change-password-confirm", "Abcdefghijklmno1")
        page.click("#change-password-form button[type=submit]")
        expect(page.locator("#change-password-modal.active")).to_be_hidden(timeout=15000)
        assert len(sent) == 1, sent
    finally:
        admin.delete_user(u["id"])


def test_the_forms_carry_no_rule_of_their_own():
    """The number lives on the server: the two forms hold the floor and read the rest."""
    from pathlib import Path
    html = (Path(__file__).resolve().parents[1] / "static" / "index.html").read_text(encoding="utf-8")
    assert "Minimum 12 characters" not in html
    assert 'id="new-password-hint"' in html and 'id="change-password-hint"' in html
    assert 'id="new-password" class="form-control" required minlength="8"' in html
