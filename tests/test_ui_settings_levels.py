"""UI — Settings levels (static/js/settings-levels.js), in both skins and at a phone's width.

Each Settings page shows its essential settings; "Show advanced settings (N)" reveals the advanced ones, each
marked Advanced, and a container left with no setting showing goes too (the rate limits, a whole card, the
groups of how long records are kept). A page whose every setting is advanced says so. "New" follows the
catalogue, and its mark leaves a field's label as it was for assistive technology. The settings the provider
has locked leave their place for one collapsed, read-only list at the foot of their page, "Set by your
provider (N)", with each one's value and reason, and the toggle's N leaves them out. What the marks say
reaches assistive technology as each field's description. Opening Settings again reads the catalogue again.
A search box above the tabs finds a setting by its label or its help text on any page (label hits first, at
most twelve listed) and goes to it, revealing it where it is advanced; it and N follow what the app shows or
hides. Hiding a setting never changes what "Save All Changes" sends. Nothing is wider than a phone. No console
error.

The catalogue is the server's (GET /settings/catalogue), or served with an edit (a lock, a "New") where a test
needs one the stack does not have. The tests sign in as a throwaway administrator, so a skin stored on the
shared account cannot change what they see.
"""
import json
import re
import uuid

import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui

WIDE = {"width": 1440, "height": 900}
PHONE = {"width": 390, "height": 844}


@pytest.fixture
def levels_admin(admin):
    u = admin.create_user(role="admin")
    yield u
    admin.delete_user(u["id"])


def _login(page: Page, user, skin="v2", viewport=WIDE):
    page.set_viewport_size(viewport)
    page.goto("/")
    page.evaluate("ui => localStorage.setItem('ui', ui)", skin)
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
    page.fill("#username", user["_username"])
    page.fill("#password", user["_password"])
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    applied = page.evaluate("() => document.documentElement.getAttribute('data-ui') || 'v1'")
    assert applied == skin, f"skin {skin!r} did not apply (got {applied!r})"


def _open(page: Page):
    """Settings, with the catalogue read and applied (the General page's toggle shows)."""
    drawer = page.locator("#mobile-nav-toggle")
    if drawer.is_visible():
        drawer.click()
        expect(page.locator('.sidebar-item[data-section="settings"]')).to_be_visible()
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    if drawer.is_visible():
        # The drawer slides out over .2s; wait for it before measuring or clicking anything.
        page.wait_for_function("() => getComputedStyle(document.getElementById('sidebar')).visibility === 'hidden'")
    expect(page.locator("#settings-tab-general .settings-advanced-toggle")).to_be_visible(timeout=15000)


def _tab(page: Page, name):
    page.locator(f'#settings-section .tab-btn[data-tab="{name}"]').click()
    expect(page.locator(f"#settings-tab-{name}")).to_be_visible()


def _setting(page: Page, key):
    return page.locator(f'#settings-section [data-setting="{key}"]').first


def _toggle(page: Page, name):
    return page.locator(f"#settings-tab-{name} .settings-advanced-toggle")


def _serve_catalogue(page: Page, edit):
    def handle(route):
        if route.request.method != "GET":
            return route.continue_()
        response = route.fetch()
        data = response.json()
        edit(data)
        route.fulfill(response=response, body=json.dumps(data))
    page.route(re.compile(r"/settings/catalogue$"), handle)


def _errors(page: Page):
    errors = []
    page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
    page.on("pageerror", lambda e: errors.append(str(e)))
    return errors


_VISIBLE_ADVANCED = """name => new Set([...document.querySelectorAll(`#settings-tab-${name} [data-setting].setting-advanced`)]
    .filter(n => n.offsetParent !== null).map(n => n.dataset.setting)).size"""


def _settled(page: Page):
    """Two animation frames: a change to the page has been applied (each pass runs in the next frame)."""
    page.evaluate("() => new Promise(r => requestAnimationFrame(() => requestAnimationFrame(r)))")


def _shown_count(page: Page, name):
    """N of a page's "Show advanced settings (N)", once the page's last change has been applied."""
    _settled(page)
    text = _toggle(page, name).inner_text().strip()
    found = re.fullmatch(r"Show advanced settings \((\d+)\)", text)
    assert found, text
    return int(found.group(1))


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_a_page_shows_its_essential_settings_and_reveals_the_advanced_ones(page: Page, levels_admin, skin):
    errors = _errors(page)
    _login(page, levels_admin, skin)
    _open(page)
    toggle = _toggle(page, "general")
    for key in ("app_name", "max_file_size"):
        expect(_setting(page, key)).to_be_visible()
        expect(_setting(page, key).locator(".setting-chip-advanced")).to_have_count(0)
    for key in ("app_description", "allowed_file_types"):
        expect(_setting(page, key)).to_be_hidden()
    expect(toggle).to_have_attribute("aria-pressed", "false")
    expect(page.locator("#settings-tab-general .settings-level-note")).to_be_hidden()   # it has essential ones
    count = re.fullmatch(r"Show advanced settings \((\d+)\)", toggle.inner_text().strip())
    assert count, toggle.inner_text()
    toggle.click()
    expect(toggle).to_have_text("Hide advanced settings")
    expect(toggle).to_have_attribute("aria-pressed", "true")
    expect(_setting(page, "app_description")).to_be_visible()
    expect(_setting(page, "app_description").locator(".setting-chip-advanced")).to_have_text("Advanced")
    assert page.evaluate(_VISIBLE_ADVANCED, "general") == int(count.group(1))
    toggle.click()
    expect(_setting(page, "app_description")).to_be_hidden()
    expect(toggle).to_be_focused()

    # A page whose every setting is advanced says so; a container holding only hidden settings goes too.
    _tab(page, "logs")
    logs = page.locator("#settings-tab-logs")
    expect(logs.locator(".settings-level-note")).to_have_text("Every setting on this page is advanced.")
    expect(logs.locator(".card", has=page.locator('[data-setting="log_components"]'))).to_be_hidden()
    expect(_setting(page, "log_tokens")).to_be_hidden()
    _toggle(page, "logs").click()
    expect(_setting(page, "log_components")).to_be_visible()
    expect(_setting(page, "log_tokens")).to_be_visible()
    expect(logs.locator(".settings-level-note")).to_be_hidden()

    # Rows the page's scripts draw: the rate limits, and how long records are kept.
    _tab(page, "security")
    expect(_setting(page, "mfa_mode")).to_be_visible()
    limits_card = page.locator("#settings-tab-security .card", has=page.locator("#rate-limit-settings"))
    expect(page.locator("#rate-limit-settings .rl-row").first).to_be_attached(timeout=10000)
    expect(limits_card).to_be_hidden()
    _toggle(page, "security").click()
    expect(limits_card).to_be_visible()
    expect(_setting(page, "rate_limit_vault_attempts")).to_be_visible()
    expect(_setting(page, "rate_limit_vault_attempts").locator(".setting-chip-advanced")).to_have_text("Advanced")

    _tab(page, "records")
    records = page.locator("#settings-tab-records")
    expect(page.locator('#retention-groups .retention-row[data-key="audit_max_days"]')).to_be_attached(timeout=10000)
    expect(_setting(page, "audit_max_days")).to_be_hidden()
    expect(page.locator("#retention-groups .retention-group").first).to_be_hidden()
    expect(page.locator("#retention-card h4", has_text="Changes waiting")).to_be_visible()
    expect(page.locator("#retention-storage-card")).to_be_visible()          # not a setting: always there
    expect(_setting(page, "audit_levels")).to_be_hidden()
    expect(records.locator(".settings-level-note")).to_be_visible()
    _toggle(page, "records").click()
    expect(_setting(page, "audit_max_days")).to_be_visible()
    expect(_setting(page, "audit_max_days").locator(".setting-chip-advanced")).to_have_text("Advanced")
    expect(page.locator("#recording-levels-card")).to_be_visible()
    assert not errors, errors


def test_the_new_marks_follow_the_catalogue_and_leave_labels_as_they_were(page: Page, levels_admin):
    errors = _errors(page)

    def mark(data):
        for e in data["entries"]:
            e["new"] = e["key"] in ("app_name", "app_description")
    _serve_catalogue(page, mark)
    _login(page, levels_admin)
    with page.expect_request(lambda r: r.url.endswith("/settings/catalogue/seen") and r.method == "POST"):
        _open(page)
    expect(_setting(page, "app_name").locator(".setting-chip-new")).to_have_text("New")
    expect(_setting(page, "max_file_size").locator(".setting-chip-new")).to_have_count(0)
    expect(page.locator("#setting-app-name")).to_have_accessible_name("Application Name")   # not in the name
    # What the marks say reaches assistive technology as the field's description.
    expect(page.locator("#setting-app-name")).to_have_accessible_description(re.compile(r"^New in \d+\.\d+\.\d+\.$"))
    expect(page.locator("#setting-max-file-size")).to_have_accessible_description("")
    # The note is read right after the label, outside it.
    note = _setting(page, "app_name").locator(".setting-marks-note")
    assert note.evaluate("n => [n.previousElementSibling.tagName, n.closest('label')]") == ["LABEL", None]
    _toggle(page, "general").click()
    chips = _setting(page, "app_description").locator(".setting-chip")
    expect(chips).to_have_text(["New", "Advanced"])
    expect(page.locator("#setting-app-description")).to_have_accessible_name("Application Description")
    expect(page.locator("#setting-app-description")).to_have_accessible_description(
        re.compile(r"^New in \d+\.\d+\.\d+\. An advanced setting\.$"))
    # A field that had a description keeps it, and the mark's is added beside it.
    _tab(page, "accounts")
    _toggle(page, "accounts").click()
    domains = page.locator("#setting-signup-domain-input")
    expect(domains).to_be_visible()
    assert "accounts-domain-help" in domains.get_attribute("aria-describedby").split()
    expect(domains).to_have_accessible_description(re.compile(r"^Type a domain .* An advanced setting\.$"))
    assert not errors, errors


def test_reopening_settings_reads_the_catalogue_again_and_says_seen_again(page: Page, levels_admin):
    """Each time Settings opens, the catalogue is read again (what is new may have changed) and the release is
    said to have been seen again; a mark the new read no longer gives goes, with what it said."""
    reads = []

    def mark(data):
        reads.append(1)
        for e in data["entries"]:
            e["new"] = e["key"] in ("app_name", "app_description") and len(reads) == 1
    _serve_catalogue(page, mark)
    _login(page, levels_admin)
    with page.expect_request(lambda r: r.url.endswith("/settings/catalogue/seen") and r.method == "POST"):
        _open(page)
    expect(_setting(page, "app_name").locator(".setting-chip-new")).to_have_text("New")
    expect(page.locator("#setting-app-name")).to_have_accessible_description(re.compile(r"^New in "))
    _toggle(page, "general").click()
    expect(page.locator("#setting-app-description")).to_have_accessible_description(
        re.compile(r"^New in \S+ An advanced setting\.$"))
    page.click('.sidebar-item[data-section="dashboard"]')
    expect(page.locator("#settings-section")).to_be_hidden()
    with page.expect_request(lambda r: r.url.endswith("/settings/catalogue/seen") and r.method == "POST"):
        page.click('.sidebar-item[data-section="settings"]')
    assert len(reads) == 2
    expect(_setting(page, "app_name").locator(".setting-chip-new")).to_have_count(0)
    expect(page.locator("#setting-app-name")).to_have_accessible_description("")
    expect(_setting(page, "app_name").locator(".setting-marks-note")).to_have_count(0)
    expect(page.locator("#setting-app-description")).to_have_accessible_description("An advanced setting.")


def test_a_setting_drawn_inside_another_is_described_by_its_own_marks_only(page: Page, levels_admin):
    """A setting a page's script draws inside another: each field is described by the marks of the setting that
    holds it most closely, never by an outer one's."""
    _login(page, levels_admin)
    _open(page)
    _toggle(page, "general").click()
    page.evaluate("""() => {
        const outer = document.querySelector('#settings-tab-general [data-setting="app_description"]');
        const inner = document.createElement('div');
        inner.dataset.setting = 'app_name';
        const label = document.createElement('label');
        label.htmlFor = 'levels-inner-field';
        label.textContent = 'Inner';
        const field = document.createElement('input');
        field.id = 'levels-inner-field';
        inner.append(label, field);
        outer.appendChild(inner);
    }""")
    _settled(page)
    expect(page.locator("#setting-app-description")).to_have_accessible_description("An advanced setting.")
    expect(page.locator("#levels-inner-field")).to_have_accessible_description("")


def test_the_new_marks_on_a_page_are_the_servers(page: Page, levels_admin, admin):
    _login(page, levels_admin)
    _open(page)
    _tab(page, "records")
    expect(page.locator('#retention-groups .retention-row[data-key="audit_max_days"]')).to_be_attached(timeout=10000)
    _toggle(page, "records").click()
    entries = page.evaluate("() => apiRequest('/settings/catalogue', {silent: true})")["entries"]
    on_page = [e for e in entries if e["page"] == "records" and not e["locked"]]
    assert on_page
    for e in on_page:
        nodes = page.locator(f'#settings-tab-records [data-setting="{e["key"]}"]')
        expect(nodes.first).to_be_attached()
        expect(nodes.locator(".setting-chip-new")).to_have_count(nodes.count() if e["new"] else 0)


def test_save_all_keeps_the_values_of_settings_it_hides(page: Page, levels_admin, admin):
    before = admin.get("/settings").json().get("app_description") or ""
    marker = f"levels {uuid.uuid4().hex[:8]}"
    assert admin.put("/settings", json={"app_description": marker}).status_code == 200
    try:
        _login(page, levels_admin)
        _open(page)
        page.wait_for_function("m => document.getElementById('setting-app-description').value === m", arg=marker,
                               timeout=15000)
        expect(_setting(page, "app_description")).to_be_hidden()
        with page.expect_response(lambda r: r.url.rstrip("/").endswith("/settings") and r.request.method == "PUT") \
                as response:
            page.click("#save-all-settings-btn")
        assert response.value.ok, response.value.status
        assert admin.get("/settings").json().get("app_description") == marker
    finally:
        admin.put("/settings", json={"app_description": before})


def _locked(data):
    for e in data["entries"]:
        if e["key"] in ("audit_hot_days", "audit_levels", "rate_limit_vault_attempts"):
            e.update(locked=True, value={"audit_hot_days": "120 days", "audit_levels": "Email addresses: none",
                                         "rate_limit_vault_attempts": "5 attempts"}[e["key"]],
                     reason=f"Set by your provider in the deployment's .env ({e['key'].upper()}) and locked "
                            f"there with SETTINGS_LOCKED_KEYS, so it cannot be changed here.")


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_locked_settings_fold_into_the_providers_list_on_their_page(page: Page, levels_admin, skin):
    errors = _errors(page)
    _serve_catalogue(page, _locked)
    _login(page, levels_admin, skin)
    _open(page)
    expect(page.locator("#settings-tab-general > .settings-provider-fold")).to_be_hidden()
    _tab(page, "records")
    expect(page.locator('#retention-groups .retention-row[data-key="audit_hot_days"]')).to_be_attached(timeout=10000)
    fold = page.locator("#settings-tab-records > .settings-provider-fold")
    expect(fold).to_be_visible()
    expect(fold.locator("summary")).to_have_text("Set by your provider (2)")
    assert fold.evaluate("d => d.open") is False
    item = fold.locator('.settings-provider-item[data-fold-key="audit_hot_days"]')
    expect(item).to_be_hidden()
    fold.locator("summary").click()
    expect(item).to_be_visible()
    expect(item).to_contain_text("Keep audit rows uncompressed for")
    expect(item.locator(".settings-provider-value")).to_have_text("120 days")
    expect(item.locator(".settings-provider-reason")).to_contain_text("Set by your provider")
    expect(item.locator(".settings-provider-reason")).to_contain_text("AUDIT_HOT_DAYS")
    expect(fold.locator('.settings-provider-item[data-fold-key="audit_levels"]')).to_contain_text("Recording levels")
    expect(fold.locator("input, select, textarea, button")).to_have_count(0)
    # Revealing the advanced settings shows the others, never a locked one; the toggle counts only those.
    count = _shown_count(page, "records")
    _toggle(page, "records").click()
    expect(_setting(page, "audit_max_days")).to_be_visible()
    expect(_setting(page, "audit_hot_days")).to_be_hidden()
    expect(page.locator("#recording-levels-card")).to_be_hidden()
    assert page.evaluate(_VISIBLE_ADVANCED, "records") == count
    _tab(page, "security")
    expect(page.locator("#settings-tab-security > .settings-provider-fold summary")).to_have_text(
        "Set by your provider (1)")
    expect(page.locator('#rate-limit-settings .rl-row[data-key="rate_limit_vault_attempts"]')).to_be_attached(
        timeout=10000)
    count = _shown_count(page, "security")
    _toggle(page, "security").click()
    expect(_setting(page, "rate_limit_api_default")).to_be_visible()
    expect(page.locator('#rate-limit-settings .rl-row[data-key="rate_limit_vault_attempts"]')).to_be_hidden()
    assert page.evaluate(_VISIBLE_ADVANCED, "security") == count
    assert not errors, errors


def test_the_fold_lists_what_the_deployment_locked(page: Page, levels_admin, admin):
    """On a stack started with SETTINGS_LOCKED_KEYS: the lists are the server's locked entries."""
    entries = admin.get("/settings/catalogue").json()["entries"]
    locked = [e for e in entries if e["locked"]]
    if not locked:
        pytest.skip("this stack locks no setting (SETTINGS_LOCKED_KEYS is empty)")
    _login(page, levels_admin)
    _open(page)
    for name in sorted({e["page"] for e in locked}):
        mine = [e for e in locked if e["page"] == name]
        _tab(page, name)
        if name == "records":
            expect(page.locator("#retention-groups .retention-row").first).to_be_attached(timeout=10000)
        fold = page.locator(f"#settings-tab-{name} > .settings-provider-fold")
        expect(fold.locator("summary")).to_have_text(f"Set by your provider ({len(mine)})")
        fold.locator("summary").click()
        toggle = _toggle(page, name)
        if toggle.is_visible() and toggle.inner_text().startswith("Show"):
            toggle.click()
        for e in mine:
            expect(fold.locator(f'.settings-provider-item[data-fold-key="{e["key"]}"] .settings-provider-reason')
                   ).to_have_text(e["reason"])
            for node in page.locator(f'#settings-tab-{name} [data-setting="{e["key"]}"]').all():
                expect(node).to_be_hidden()


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_the_search_finds_a_setting_on_any_page_and_goes_to_it(page: Page, levels_admin, skin):
    errors = _errors(page)
    _serve_catalogue(page, _locked)
    _login(page, levels_admin, skin)
    _open(page)
    box = page.locator("#settings-search")
    results = page.locator("#settings-search-results")
    expect(results).to_be_hidden()

    box.fill("tagline")
    hit = results.locator('.settings-search-hit[data-key="brand_tagline"]')
    expect(hit).to_contain_text("Tagline")
    expect(hit).to_contain_text("Branding · Advanced")
    hit.click()
    expect(page.locator('#settings-section .tab-btn[data-tab="branding"]')).to_have_class(re.compile(r"\bactive\b"))
    expect(page.locator("#setting-brand-tagline")).to_be_visible()
    expect(page.locator("#setting-brand-tagline")).to_be_focused()
    expect(results).to_be_hidden()
    expect(box).to_have_value("")

    # A word of a help text on the page finds its setting; Enter goes to the first.
    box.fill("MAX_FILE_SIZE_MB")
    expect(results.locator('.settings-search-hit[data-key="max_file_size"]')).to_be_visible()
    box.press("Enter")
    expect(page.locator("#setting-max-file-size")).to_be_focused()

    # A setting on a page not opened yet, drawn when it opens, advanced: its page, revealed.
    box.fill("keep audit rows for at most")
    expect(results.locator('.settings-search-hit[data-key="audit_max_days"]')).to_contain_text("Activity and records")
    box.press("Enter")
    row = _setting(page, "audit_max_days")
    expect(row).to_be_visible(timeout=10000)
    expect(row.locator("input")).to_be_focused()
    expect(_toggle(page, "records")).to_have_text("Hide advanced settings")

    # The catalogue's help text counts too.
    box.fill("daily blocks")
    expect(results.locator('.settings-search-hit[data-key="audit_hot_days"]')).to_contain_text("Set by your provider")
    results.locator('.settings-search-hit[data-key="audit_hot_days"]').click()
    fold = page.locator("#settings-tab-records > .settings-provider-fold")
    assert fold.evaluate("d => d.open") is True
    expect(fold.locator('.settings-provider-item[data-fold-key="audit_hot_days"]')).to_be_visible()

    # Arrows move through the results; Escape leaves them.
    box.fill("lifetime")
    expect(results.locator(".settings-search-hit").first).to_be_visible()
    box.press("ArrowDown")
    expect(results.locator(".settings-search-hit").first).to_be_focused()
    page.keyboard.press("Escape")
    expect(results).to_be_hidden()
    expect(box).to_be_focused()

    box.fill("zzzz nothing")
    expect(results).to_contain_text("No setting matches.")
    box.press("Escape")
    expect(results).to_be_hidden()
    assert not errors, errors


@pytest.mark.parametrize("skin", ["v1", "v2"])
def test_nothing_is_wider_than_a_phone(page: Page, levels_admin, skin):
    _serve_catalogue(page, _locked)
    _login(page, levels_admin, skin, PHONE)
    _open(page)
    wide = {}
    for name in ("general", "security", "records", "logs"):
        _tab(page, name)
        if name == "records":
            expect(page.locator("#retention-groups .retention-row").first).to_be_attached(timeout=10000)
        toggle = _toggle(page, name)
        expect(toggle).to_be_visible()
        box = toggle.bounding_box()
        assert box["x"] >= 0 and box["x"] + box["width"] <= PHONE["width"] + 1, (name, box)
        toggle.click()
        fold = page.locator(f"#settings-tab-{name} > .settings-provider-fold")
        if fold.is_visible():
            fold.locator("summary").click()
        page.wait_for_load_state("networkidle")
        width = page.evaluate("() => document.documentElement.scrollWidth")
        if width > PHONE["width"] + 1:
            wide[name] = width
    assert not wide, f"these pages scroll sideways at {PHONE['width']}px: {wide}"
    search = page.locator("#settings-search")
    search.scroll_into_view_if_needed()
    search.fill("limit")
    results = page.locator("#settings-search-results")
    expect(results.locator(".settings-search-hit").first).to_be_visible()
    for part in (search, results):
        b = part.bounding_box()
        assert b["x"] >= 0 and b["x"] + b["width"] <= PHONE["width"] + 1, b
    assert page.evaluate("() => document.documentElement.scrollWidth") <= PHONE["width"] + 1


def test_the_search_leaves_out_a_setting_the_app_hides(page: Page, levels_admin):
    """The update checks' controls show only while the checks are on; while they are off the search does not
    offer them (going to them would find nothing to show)."""
    status = {"enabled": False}
    page.route("**/api/update-status*", lambda route: route.fulfill(
        status=200, content_type="application/json",
        body=json.dumps({"enabled": status["enabled"], "managed": False, "current": "0.6.0", "latest": "0.6.0",
                         "update_available": False, "checked_at": 1700000000, "interval_minutes": 360})))
    _login(page, levels_admin)
    _open(page)
    expect(page.locator("#update-controls")).to_be_hidden()
    box = page.locator("#settings-search")
    hit = page.locator('#settings-search-results .settings-search-hit[data-key="update_check_interval"]')
    box.fill("update checks")
    expect(page.locator("#settings-search-results")).to_contain_text("No setting matches.")
    expect(hit).to_have_count(0)
    box.press("Escape")
    # On: the Settings pages read the status again when they open, and the search offers the checks.
    status["enabled"] = True
    page.click('.sidebar-item[data-section="dashboard"]')
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#update-controls")).to_be_attached()
    page.wait_for_function("() => document.getElementById('update-controls').style.display !== 'none'",
                           timeout=10000)
    box.fill("update checks")
    expect(hit).to_be_visible()
    hit.click()
    expect(page.locator("#update-controls")).to_be_visible()


def _update_status(enabled):
    return {"enabled": enabled, "managed": False, "current": "0.6.0", "latest": "0.6.0", "update_available": False,
            "checked_at": 1700000000, "interval_minutes": 360}


def test_the_count_and_the_search_follow_what_the_app_shows_or_hides_after_the_catalogue(page: Page, levels_admin):
    """The update checks' controls show while the checks are on. Once the catalogue has been applied, the app
    hides them by their style (the checks turned off) and shows them again: the General page's count and the
    search follow each time."""
    page.route("**/api/update-status*", lambda route: route.fulfill(
        status=200, content_type="application/json", body=json.dumps(_update_status(True))))
    _login(page, levels_admin)
    _open(page)
    page.wait_for_function("() => document.getElementById('update-controls').style.display !== 'none'",
                           timeout=10000)
    shown = _shown_count(page, "general")
    box = page.locator("#settings-search")
    results = page.locator("#settings-search-results")
    hit = results.locator('.settings-search-hit[data-key="update_check_interval"]')
    box.fill("update checks")
    expect(hit).to_be_visible()
    box.press("Escape")
    page.evaluate("us => renderUpdateStatus(us)", _update_status(False))
    expect(page.locator("#update-controls")).to_be_hidden()
    expect(_toggle(page, "general")).to_have_text(f"Show advanced settings ({shown - 1})")
    box.fill("update checks")
    expect(results).to_contain_text("No setting matches.")
    expect(hit).to_have_count(0)
    box.press("Escape")
    page.evaluate("us => renderUpdateStatus(us)", _update_status(True))
    expect(_toggle(page, "general")).to_have_text(f"Show advanced settings ({shown})")
    box.fill("update checks")
    expect(hit).to_be_visible()


def test_the_search_lists_label_hits_before_help_hits(page: Page, levels_admin):
    """A word in one setting's label and in another's help text: the label's setting comes first, though its page
    comes after the other's."""
    def edit(data):
        for e in data["entries"]:
            if e["key"] == "app_name":
                e["help"] = "Shown beside the zebrafish."
            elif e["key"] == "brand_tagline":
                e["label"] = "Zebrafish tagline"
    _serve_catalogue(page, edit)
    _login(page, levels_admin)
    _open(page)
    page.locator("#settings-search").fill("zebrafish")
    hits = page.locator("#settings-search-results .settings-search-hit")
    expect(hits).to_have_count(2)
    expect(hits.nth(0)).to_have_attribute("data-key", "brand_tagline")
    expect(hits.nth(1)).to_have_attribute("data-key", "app_name")


def test_the_search_lists_at_most_twelve_hits_and_says_how_many_more(page: Page, levels_admin):
    _login(page, levels_admin)
    _open(page)
    box = page.locator("#settings-search")
    results = page.locator("#settings-search-results")
    box.fill("a")
    expect(results.locator(".settings-search-hit")).to_have_count(12)
    total = page.evaluate("q => SettingsLevels.search(q).length", "a")
    assert total > 12, total
    expect(results.locator(".settings-search-more")).to_have_text(
        f"{total - 12} more: type more of the name to narrow them.")
    box.fill("tagline")
    expect(results.locator(".settings-search-hit")).to_have_count(1)
    expect(results.locator(".settings-search-more")).to_have_count(0)
