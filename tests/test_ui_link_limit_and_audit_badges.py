"""Two things a person reads on screen: why a link was refused, and whether an audit row is bad news.

The upload-link form used to show the server's raw refusal ("max_file_bytes 209715200 exceeds this
tag's cap of 104857600") for a size above the link type's cap. The form now says it in its own words
before sending anything, and the server's refusal, reached by a client that skips the form, reads
the same way.

The audit log painted every status other than "success" red, so a download's "authorized" row
(an allowed request) looked like a failure. Only failures and refusals are red now.
"""
import pytest
from playwright.sync_api import Page, expect

from conftest import unique

pytestmark = pytest.mark.ui

_MB = 1048576
SIZE_REFUSAL = "The size per file can be at most 100 MB for this link type."


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


@pytest.fixture
def size_capped_tag(admin):
    before = admin.get("/settings").json().get("public_receivers_enabled")
    admin.put("/settings", json={"public_receivers_enabled": True})
    r = admin.post("/receiver-tags", json={
        "name": unique("SizeCap"), "min_token_len": 10, "max_file_bytes_cap": 100 * _MB,
        "max_total_bytes_cap": 500 * _MB, "auto_enroll_new_users": True, "is_active": True,
    })
    assert r.status_code in (200, 201), r.text
    tag = r.json()
    yield tag
    admin.delete(f"/receiver-tags/{tag['id']}")
    admin.put("/settings", json={"public_receivers_enabled": bool(before)})


def test_a_file_size_over_the_cap_is_refused_in_the_forms_words(page: Page, admin, admin_creds,
                                                                size_capped_tag):
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(page.locator("#nav-uploadlinks")).to_be_visible(timeout=10000)
    page.locator("#nav-uploadlinks").click()
    expect(page.locator("#uploadlinks-section")).to_be_visible()

    posts = []
    page.on("request", lambda req: posts.append(req.url)
            if req.method == "POST" and req.url.rstrip("/").endswith("/receivers") else None)
    page.click("#receiver-new-btn")
    expect(page.locator("#receiver-create-modal")).to_be_visible()
    page.select_option("#rc-tag", label=size_capped_tag["name"])
    expect(page.locator("#rc-max-file-mb")).to_have_value("100")
    page.fill("#rc-max-file-mb", "200")
    page.click("#rc-create")
    expect(page.locator("#rc-error")).to_have_text(SIZE_REFUSAL)
    page.wait_for_timeout(500)
    assert posts == [], "the form sent a request it already knew would be refused"

    # A client that skips the form meets the same words from the server.
    r = admin.post("/receivers", json={"tag_id": size_capped_tag["id"], "max_file_bytes": 200 * _MB,
                                       "max_total_bytes": 500 * _MB})
    assert r.status_code == 400, r.text
    assert r.json()["detail"] == SIZE_REFUSAL


def test_link_limit_message_names_each_field_with_its_unit(page: Page, admin_creds):
    """The check behind all three link forms, driven with inputs shaped like theirs."""
    _login(page, admin_creds["username"], admin_creds["password"])
    said = page.evaluate("""() => {
        const field = (value, attrs) => {
            const el = document.createElement('input');
            el.type = 'number';
            Object.entries(attrs).forEach(([k, v]) => el.setAttribute(k, v));
            el.value = value;
            return el;
        };
        const off = field('9999', {max: '5'}); off.disabled = true;
        return {
            over: _linkLimitMessage([[field('48', {max: '24'}), 'The expiry', 'hours']]),
            under: _linkLimitMessage([[field('8', {min: '12'}), 'The link length', 'characters']]),
            one: _linkLimitMessage([[field('2', {max: '1'}), 'The retention period', 'days']]),
            count: _linkLimitMessage([[field('4', {max: '3'}), 'The number of views', '']]),
            inside: _linkLimitMessage([[field('24', {max: '24', min: '1'}), 'The expiry', 'hours']]),
            blank: _linkLimitMessage([[field('', {max: '24'}), 'The expiry', 'hours']]),
            disabled: _linkLimitMessage([[off, 'The expiry', 'hours']]),
            first: _linkLimitMessage([[field('1', {max: '5'}), 'A', ''], [field('9', {max: '5'}), 'B', ''],
                                      [field('9', {max: '5'}), 'C', '']]),
        };
    }""")
    assert said == {
        "over": "The expiry can be at most 24 hours for this link type.",
        "under": "The link length must be at least 12 characters for this link type.",
        "one": "The retention period can be at most 1 day for this link type.",
        "count": "The number of views can be at most 3 for this link type.",
        "inside": "", "blank": "", "disabled": "",
        "first": "B can be at most 5 for this link type.",
    }


def test_only_a_failure_or_a_refusal_is_red_in_the_audit_log(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    badges = page.evaluate("""() => Object.fromEntries(
        ['success', 'active', 'authorized', 'revoked', 'unconfirmed', 'failure', 'failed', 'error',
         'refused', 'something-new', undefined].map(s => [String(s), auditStatusBadge(s)]))""")
    assert badges == {
        "success": "success", "active": "success", "authorized": "info", "revoked": "secondary",
        "unconfirmed": "warning", "failure": "danger", "failed": "danger", "error": "danger",
        "refused": "danger", "something-new": "secondary", "undefined": "secondary",
    }


def test_an_authorized_download_row_is_not_painted_as_a_failure(page: Page, admin, admin_creds):
    """The reported case, as a person meets it: the audit page itself, both views."""
    rows = [
        {"id": 1, "timestamp": "2026-09-25T10:00:00Z", "action": "file_download", "status": "authorized",
         "username": "someone", "ip_address": "198.51.100.7", "resource_type": "file", "details": {}},
        {"id": 2, "timestamp": "2026-09-25T10:00:01Z", "action": "login", "status": "failure",
         "username": "someone", "ip_address": "198.51.100.7", "resource_type": "user", "details": {}},
    ]
    import json as _json

    def _fulfil(route):
        if route.request.method == "GET":
            route.fulfill(status=200, content_type="application/json", body=_json.dumps(rows))
        else:
            route.continue_()

    page.route(lambda url: "/audit/log" in url, _fulfil)
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("() => navigateToSection('settings')")
    page.wait_for_selector("#settings-section.active", timeout=15000)
    page.evaluate("""() => { const t = [...document.querySelectorAll('.tabs .tab-btn')]
                        .find(x => x.getAttribute('data-tab') === 'audit'); if (t) t.click(); }""")
    page.wait_for_selector("#settings-tab-audit.active", timeout=10000)
    page.click("#audit-search-btn")

    for view, scope in (("table", "#settings-tab-audit .data-table-wrapper"), ("cards", "#audit-log-cards")):
        page.click(f"#audit-view-{view}")
        authorized = page.locator(f"{scope} .badge", has_text="authorized").first
        expect(authorized).to_be_visible(timeout=10000)
        expect(authorized).to_have_class("badge badge-info")
        expect(page.locator(f"{scope} .badge", has_text="failure").first).to_have_class("badge badge-danger")
    # In the detailed view only the failure's card is marked as bad news.
    expect(page.locator("#audit-log-cards .audit-card.is-bad")).to_have_count(1)
