"""Settings → Email — the template card grid + inline code/render/split editor + send flow."""
import os
import re
import time

import pytest
import requests
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


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
    def wipe():
        for t in admin.get("/email/templates").json().get("templates", []):
            admin.delete(f"/email/templates/{t['id']}")
        for r in admin.get("/email/resources").json().get("resources", []):
            admin.delete(f"/email/resources/{r['id']}")
        for p in admin.get("/email/profiles").json().get("profiles", []):
            admin.delete(f"/email/profiles/{p['id']}")
    wipe()
    yield
    wipe()


def _new_template(page, *, name, subject="Hello {{user.username}}", body="<p>Hi {{user.username}}</p>"):
    page.click("#email-template-add")
    expect(page.locator("#email-template-editor")).to_be_visible()
    page.fill("#et-name", name)
    page.fill("#et-subject", subject)
    page.fill("#et-body", body)


def test_templates_grid_and_create_card(admin_page: Page):
    _open_email_tab(admin_page)
    expect(admin_page.locator("#email-template-add")).to_be_visible()


def test_create_template_and_card_shows_profile_preview(admin_page: Page, admin):
    prof = admin.post("/email/profiles", json={"name": "P", "smtp_server": "smtp.example.com",
                                               "smtp_port": 587, "from_email": "from@example.com",
                                               "from_name": "Sender"}).json()
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Welcome")
    page.select_option("#et-profile", prof["id"])
    page.click("#et-save")
    card = page.locator('.email-profile-card:has-text("Welcome")')
    expect(card).to_be_visible(timeout=10000)
    expect(card.locator(".epc-meta")).to_contain_text("from@example.com")
    expect(card.locator(".epc-meta")).to_contain_text("smtp.example.com")
    assert len(admin.get("/email/templates").json()["templates"]) == 1


def test_editor_view_toggle_code_render_split(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Views")
    panes = page.locator("#et-panes")
    expect(page.locator("#et-body")).to_be_visible()          # code view: textarea shown
    page.click('.et-view[data-view="render"]')
    expect(panes).to_have_class(re.compile(r"et-view-render"))
    expect(page.locator("#et-body")).to_be_hidden()           # render view: iframe only
    expect(page.locator("#et-preview")).to_be_visible()
    page.click('.et-view[data-view="split"]')
    expect(panes).to_have_class(re.compile(r"et-view-split"))
    expect(page.locator("#et-body")).to_be_visible()          # split: both
    expect(page.locator("#et-preview")).to_be_visible()


def test_preview_renders_sanitized_and_personalized(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Prev",
                  body='<p>Hi <strong>{{user.username}}</strong></p><script>alert(1)</script>')
    page.click('.et-view[data-view="render"]')
    # the sandboxed iframe's srcdoc is the server-sanitized + personalized preview
    def srcdoc():
        return page.locator("#et-preview").get_attribute("srcdoc") or ""
    deadline = time.time() + 8
    while time.time() < deadline and "jsmith" not in srcdoc():
        page.wait_for_timeout(200)
    doc = srcdoc()
    assert "jsmith" in doc                                    # sample username substituted
    assert "<script" not in doc.lower()                       # script stripped by the server
    assert 'sandbox=""' in page.locator("#et-preview").evaluate("el => el.outerHTML")


def test_add_dynamic_action_inserts_token(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Dyn", body="")
    page.click("#et-add-dynamic")
    expect(page.locator("#et-dyn-menu")).to_be_visible()
    page.locator('#et-dyn-menu button:has-text("Recipient username")').click()
    expect(page.locator("#et-body")).to_have_value("{{user.username}}")


def test_add_image_inserts_data_resource_id(admin_page: Page, admin):
    res = admin.post("/email/resources", files={"file": ("logo.png", PNG, "application/octet-stream")}).json()
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Img", body="")
    page.click("#et-add-image")
    expect(page.locator("#email-image-modal")).to_have_class(re.compile(r"\bactive\b"))
    page.locator(f'.et-image-item:has-text("logo.png")').click()
    expect(page.locator("#et-body")).to_have_value(f'<img data-resource-id="{res["id"]}">')
    # the reference is a UUID; no path/URL appears in the source
    assert "/email/resources/" not in page.locator("#et-body").input_value()


def test_client_script_pre_check_blocks_save(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Evil", body="<p>hi</p><script>steal()</script>")
    page.click("#et-save")
    expect(page.locator("#et-editor-msg")).to_contain_text("not allowed")
    expect(page.locator("#email-template-editor")).to_be_visible()      # editor stays open
    assert admin.get("/email/templates").json()["templates"] == []      # nothing saved


def test_delete_template(admin_page: Page, admin):
    page = admin_page
    page.on("dialog", lambda d: d.accept())
    _open_email_tab(page)
    _new_template(page, name="Doomed")
    page.click("#et-save")
    expect(page.locator('.email-profile-card:has-text("Doomed")')).to_be_visible(timeout=10000)
    page.locator('.email-profile-card:has-text("Doomed") .etc-delete').click()
    expect(page.locator('.email-profile-card:has-text("Doomed")')).to_have_count(0, timeout=10000)


def test_edit_loads_full_body_and_saves_via_put(admin_page: Page, admin):
    # The card list omits body_html; the editor must fetch the full row. Editing then Saving must PUT
    # the same id (no duplicate), and the new body must persist.
    t = admin.post("/email/templates", json={"name": "Editable", "subject": "s",
                                             "body_html": "<p>original body</p>"}).json()
    page = admin_page
    _open_email_tab(page)
    expect(page.locator('.email-profile-card:has-text("Editable")')).to_be_visible(timeout=10000)
    page.locator('.email-profile-card:has-text("Editable") .etc-edit').click()
    expect(page.locator("#email-template-editor")).to_be_visible()
    expect(page.locator("#et-body")).to_have_value("<p>original body</p>")   # full body loaded
    page.fill("#et-body", "<p>edited body</p>")
    page.click("#et-save")
    expect(page.locator("#email-template-editor")).to_be_hidden(timeout=10000)
    rows = admin.get("/email/templates").json()["templates"]
    assert len(rows) == 1 and rows[0]["id"] == t["id"]                       # PUT, not a new row
    assert admin.get(f"/email/templates/{t['id']}").json()["body_html"] == "<p>edited body</p>"


def test_toolbar_bold_wraps_with_placeholder(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Fmt", body="")
    page.click('.et-toolbar [data-fmt="bold"]')
    expect(page.locator("#et-body")).to_have_value("<strong>bold text</strong>")


def test_code_view_hides_the_preview_iframe(admin_page: Page):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="CodeOnly")
    # default is Code view: textarea shown, iframe hidden.
    expect(page.locator("#et-body")).to_be_visible()
    expect(page.locator("#et-preview")).to_be_hidden()


def test_cancel_editor_saves_nothing(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Discarded")
    page.click("#et-cancel")
    expect(page.locator("#email-template-editor")).to_be_hidden()
    assert admin.get("/email/templates").json()["templates"] == []


def test_upload_via_file_input_adds_a_resource(admin_page: Page, admin):
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Uploader", body="")
    page.click("#et-add-image")
    expect(page.locator("#email-image-modal")).to_have_class(re.compile(r"\bactive\b"))
    page.set_input_files("#et-image-upload",
                         files=[{"name": "up.png", "mimeType": "image/png", "buffer": PNG}])
    # the upload posts to /email/resources; wait for the server to reflect the new row.
    deadline = time.time() + 10
    while time.time() < deadline and not admin.get("/email/resources").json().get("resources"):
        page.wait_for_timeout(200)
    res = admin.get("/email/resources").json()["resources"]
    assert len(res) == 1 and res[0]["content_type"] == "image/png"
    expect(page.locator(".et-image-item")).to_have_count(1, timeout=10000)   # thumb rendered


def test_send_modal_empty_recipient_is_guarded(admin_page: Page, admin):
    admin.post("/email/templates", json={"name": "Guarded", "subject": "s", "body_html": "<p>x</p>"})
    page = admin_page
    _open_email_tab(page)
    page.locator('.email-profile-card:has-text("Guarded") .etc-send').click()
    expect(page.locator("#email-send-modal")).to_have_class(re.compile(r"\bactive\b"))
    page.click("#et-send-go")   # no user selected, no address typed
    expect(page.locator("#et-send-results")).to_contain_text("at least one recipient")


def test_no_console_errors_across_the_template_flow(admin_page: Page):
    page = admin_page
    errors = []
    page.on("pageerror", lambda exc: errors.append(str(exc)))
    page.on("console", lambda m: errors.append(m.text) if m.type == "error"
            and "Failed to load resource" not in m.text else None)
    _open_email_tab(page)
    _new_template(page, name="Clean", body="<p>Hi {{user.username}}</p>")
    page.click('.et-view[data-view="split"]')
    page.wait_for_timeout(800)      # let the debounced preview fetch + render settle
    page.click("#et-save")
    expect(page.locator('.email-profile-card:has-text("Clean")')).to_be_visible(timeout=10000)
    assert errors == [], f"console/page errors during the flow: {errors}"


def test_toolbar_wired_once_after_renavigation(admin_page: Page):
    # initSettings()/attachSettingsListeners run on EVERY navigation to Settings; the editor wiring is
    # guarded so its arrow-wrapped listeners don't stack. Leave Settings and return, then a single
    # Bold click must wrap ONCE (a stacked listener would double-wrap <strong><strong>…).
    page = admin_page
    _open_email_tab(page)
    page.click('.sidebar-item[data-section="dashboard"]')
    page.wait_for_timeout(150)
    _open_email_tab(page)                              # attachSettingsListeners runs a second time
    _new_template(page, name="Once", body="")
    page.click('.et-toolbar [data-fmt="bold"]')       # exactly one user click
    expect(page.locator("#et-body")).to_have_value("<strong>bold text</strong>")


def test_edit_refuses_to_open_when_body_fetch_fails(admin_page: Page, admin):
    # If the detail-body GET fails, the editor must NOT open blank (a Save would overwrite the stored
    # body). Delete the template server-side after the card renders so the detail GET 404s.
    t = admin.post("/email/templates", json={"name": "Vanishing", "subject": "s",
                                             "body_html": "<p>b</p>"}).json()
    page = admin_page
    _open_email_tab(page)
    expect(page.locator('.email-profile-card:has-text("Vanishing")')).to_be_visible(timeout=10000)
    admin.delete(f"/email/templates/{t['id']}")       # card id is now stale
    with page.expect_response(lambda r: f"/email/templates/{t['id']}" in r.url) as resp:
        page.locator('.email-profile-card:has-text("Vanishing") .etc-edit').click()
    assert resp.value.status == 404
    expect(page.locator("#email-template-editor")).to_be_hidden()   # must not open blank


@pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST),
                    reason="no Mailpit sink (bring the round up WITH_MAILPIT)")
def test_send_flow_delivers_to_a_free_form_address(admin_page: Page, admin):
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
    admin.post("/email/profiles", json={"name": "MP", "smtp_server": MAILPIT_SMTP_HOST,
                                        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
                                        "from_email": "sender@example.com", "is_default": True})
    page = admin_page
    _open_email_tab(page)
    _new_template(page, name="Blast", subject="Hi {{user.username}}", body="<p>Hi {{user.username}}</p>")
    page.click("#et-save")
    card = page.locator('.email-profile-card:has-text("Blast")')
    expect(card).to_be_visible(timeout=10000)
    card.locator(".etc-send").click()
    expect(page.locator("#email-send-modal")).to_have_class(re.compile(r"\bactive\b"))
    page.fill("#et-send-addresses", "someone@example.com")
    page.click("#et-send-go")
    expect(page.locator("#et-send-results")).to_contain_text("Sent 1 of 1", timeout=15000)
    deadline, seen = time.time() + 15, False
    while time.time() < deadline and not seen:
        msgs = requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", [])
        seen = any("someone@example.com" in [a.get("Address", "").lower() for a in m.get("To", [])] for m in msgs)
        if not seen:
            time.sleep(0.5)
    assert seen, "the sent template never reached Mailpit"
