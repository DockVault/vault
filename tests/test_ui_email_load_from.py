"""Settings → Email — the template editor's "Load From" dropdown.

Load From replaces the editor's subject + body with either a built-in DEFAULT template (to reset/start
from) or one of the admin's own templates (to fine-tune a copy). The default templates section is always
present; user templates appear below an underline. Selecting confirms first (it overwrites the editor).
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def _open_email_tab(page: Page):
    page.click('.sidebar-item[data-section="settings"]')
    page.click('.tab-btn[data-tab="email"]')
    expect(page.locator("#email-templates-grid")).to_be_visible(timeout=10000)


@pytest.fixture
def admin_page(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    return page


@pytest.fixture(autouse=True)
def _clean(admin):
    # Delete user templates (never the permanent defaults) so the fixed-name templates these tests
    # create don't accumulate across runs and trip Playwright strict-mode on a re-run.
    def wipe():
        for t in admin.get("/email/templates").json().get("templates", []):
            if not t.get("is_default"):
                admin.delete(f"/email/templates/{t['id']}")
    wipe()
    yield
    wipe()


def _new_template(page, *, name, subject, body):
    page.click("#email-template-add")
    expect(page.locator("#email-template-editor")).to_be_visible()
    page.fill("#et-name", name)
    page.fill("#et-subject", subject)
    page.fill("#et-body", body)


def test_load_from_menu_lists_defaults_and_own_templates(admin_page: Page, admin):
    # a user template to copy from
    admin.post("/email/templates", json={"name": "My Copy", "subject": "s", "body_html": "<p>mine</p>"})
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="LF", subject="orig", body="<p>orig</p>")
    page.click("#et-load-from")
    menu = page.locator("#et-loadfrom-menu")
    expect(menu).to_be_visible()
    # two sections: defaults (always) + your templates (below the underline)
    expect(menu.locator(".et-loadfrom-section")).to_have_count(2)
    expect(menu.locator('.et-loadfrom-section:has-text("Default templates")')).to_be_visible()
    expect(menu.locator('.et-loadfrom-section:has-text("Your templates")')).to_be_visible()
    # the built-in defaults are offered by name
    expect(menu.locator('.et-loadfrom-item:has-text("Welcome email")')).to_be_visible()
    expect(menu.locator('.et-loadfrom-item:has-text("Password reset")')).to_be_visible()
    # the admin's own template is offered too
    expect(menu.locator('.et-loadfrom-item:has-text("My Copy")')).to_be_visible()


def test_load_from_default_replaces_subject_and_body(admin_page: Page, admin):
    # what the "Welcome email" default should load
    dt = {p["key"]: p for p in admin.get("/email/default-templates").json()["templates"]}
    welcome = dt["account_welcome"]
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="LF2", subject="orig subject", body="<p>orig body</p>")
    page.click("#et-load-from")
    expect(page.locator("#et-loadfrom-menu")).to_be_visible()
    page.locator('.et-loadfrom-item:has-text("Welcome email")').first.click()
    page.click("#confirm-modal-confirm-btn")         # themed confirm for the destructive replace
    # subject + body now hold the default's content
    expect(page.locator("#et-subject")).to_have_value(welcome["subject"])
    expect(page.locator("#et-body")).to_have_value(welcome["body_html"])
    expect(page.locator("#et-loadfrom-menu")).to_be_hidden()   # menu closed after pick


def test_load_from_your_template_loads_its_body(admin_page: Page, admin):
    admin.post("/email/templates", json={"name": "Source Copy", "subject": "src subj",
                                         "body_html": "<p>source body {{user.username}}</p>"})
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="LF3", subject="x", body="<p>x</p>")
    page.click("#et-load-from")
    page.locator('.et-loadfrom-item:has-text("Source Copy")').first.click()
    page.click("#confirm-modal-confirm-btn")         # themed confirm for the destructive replace
    expect(page.locator("#et-subject")).to_have_value("src subj")
    expect(page.locator("#et-body")).to_have_value("<p>source body {{user.username}}</p>")
