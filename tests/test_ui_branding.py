"""Branding / white-label end-to-end tests (A2).

Proves the app shell is data-driven from GET /branding via brand.js + data-brand-* hooks:
with a DB SystemSetting('brand') override the served page's <title>, header name, logo alt
and :root theme colours reflect it once brand.js runs; with no override the shell reflects
the /branding effective value (not a hardcoded literal). Hostile branding is neutralised
(name via textContent, asset URL scheme sanitised).

DB overrides are seeded via docker-exec psql and cleaned up; a test skips cleanly if
docker/psql is unavailable. Each test gets a fresh browser context (pytest-playwright), so
localStorage (brand.js's cache) starts clean.
"""
import base64
import contextlib
import json
import os
import re
import subprocess

import pytest
from playwright.sync_api import Page, expect

# a real 1x1 PNG (valid signature) for the A4 logo-upload e2e; base64 keeps the source ASCII.
_PNG_1x1 = base64.b64decode(
    "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAAC0lEQVR4nGNgYGAAAAAEAAH2FzhVAAAAAElFTkSuQmCC"
)

pytestmark = pytest.mark.ui

DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    try:
        proc = subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


def _delete_brand() -> None:
    _psql("DELETE FROM system_settings WHERE key='brand';")


def _delete_brand_quiet() -> None:
    """Best-effort teardown — never asserts/skips inside a finally."""
    try:
        subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-c", "DELETE FROM system_settings WHERE key='brand';"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except Exception:  # noqa: BLE001
        pass


@contextlib.contextmanager
def brand_override(overrides: dict):
    payload = json.dumps(overrides).replace("'", "''")
    _delete_brand()  # clean baseline (skips whole test if docker absent)
    _psql(
        "INSERT INTO system_settings (key, value, updated_at) "
        f"VALUES ('brand', '{payload}', now()) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();"
    )
    try:
        yield
    finally:
        _delete_brand_quiet()


def test_shell_reflects_brand_override(page: Page):
    """A DB brand override drives the served shell: header name, <title>, logo alt, :root colour."""
    with brand_override({"app_name": "AcmeBrand", "app_full_name": "Acme Secure",
                         "primary_color": "#abcdef"}):
        page.goto("/")
        # brand.js sets the login h1 text from /branding.app_name after the fetch resolves.
        expect(page.locator("#login-screen [data-brand-name]")).to_have_text("AcmeBrand", timeout=10000)
        expect(page).to_have_title("AcmeBrand - Acme Secure", timeout=10000)
        expect(page.locator("#login-screen [data-brand-logo]")).to_have_attribute("alt", "AcmeBrand")
        # applyHead() runs before the name is set, so the :root colour is applied by now.
        color = page.evaluate(
            "() => getComputedStyle(document.documentElement).getPropertyValue('--primary-color').trim()"
        )
        assert color == "#abcdef", f"--primary-color override not applied, got {color!r}"
        # the header NAME reflects the override (the persistent 'powered by DockVault'
        # footer legitimately still carries DockVault, so we don't scan the whole body).
        expect(page.locator("#login-screen [data-brand-name]")).not_to_have_text("DockVault")


def test_shell_default_is_data_driven_from_branding(page: Page):
    """With no override the shell name equals the /branding effective app_name — i.e. it is
    data-driven, not a hardcoded literal. The localStorage cache write is asserted as
    independent proof brand.js's fetch+apply path actually ran: without it, the name
    assertion would pass vacuously (against a broken/removed brand.js) as soon as A6 makes
    the env default app_name equal the static shell default (review finding)."""
    _delete_brand()  # ensure no override (skips if docker absent)
    page.goto("/")
    effective = page.evaluate("async () => { const r = await fetch('/branding'); return await r.json(); }")
    # brand.js writes its cache only AFTER apply(b) — a written cache proves the shell
    # was painted from /branding data, not left on the static default by a dead script.
    page.wait_for_function("() => !!window.localStorage.getItem('dv_branding')", timeout=10000)
    cached = json.loads(page.evaluate("() => window.localStorage.getItem('dv_branding')"))
    assert cached.get("app_name") == effective["app_name"], \
        f"brand.js cached {cached.get('app_name')!r} but /branding says {effective['app_name']!r}"
    expect(page.locator("#login-screen [data-brand-name]")).to_have_text(effective["app_name"], timeout=10000)


def test_hostile_brand_values_are_neutralised(page: Page):
    """Branding is admin-editable (A3) and could be hostile: the name must render as TEXT
    (not HTML) and a javascript: logo URL must be rejected — no script executes."""
    with brand_override({"app_name": "<img src=x onerror=window.__xss=1>",
                         "logo_url": "javascript:window.__xss=1",
                         "logo_small_url": "javascript:window.__xss=1"}):
        page.goto("/")
        h1 = page.locator("#login-screen [data-brand-name]")
        # textContent, so the payload shows as literal text and injects no element.
        expect(h1).to_have_text("<img src=x onerror=window.__xss=1>", timeout=10000)
        # the javascript: URL is rejected -> logo src stays the static same-origin default.
        logo_src = page.locator("#login-screen [data-brand-logo]").get_attribute("src")
        assert logo_src and logo_src.startswith("/static/"), f"logo src not sanitised: {logo_src!r}"
        assert page.evaluate("() => window.__xss === undefined"), "hostile branding executed script"


def test_settings_app_name_reflected_in_served_title(page: Page, admin):
    """The full A6 wiring lock, end to end: PUT /settings {app_name} -> mirrored into the
    brand override -> /branding -> brand.js -> the RENDERED shell <title> and header."""
    _delete_brand()  # clean brand baseline (skips if docker absent)
    before_global = admin.get("/settings").json().get("app_name")
    try:
        r = admin.put("/settings", json={"app_name": "TitleFromSettings"})
        assert r.status_code == 200, r.text
        page.goto("/")
        expect(page).to_have_title(re.compile(r"^TitleFromSettings\b"), timeout=10000)
        expect(page.locator("#login-screen [data-brand-name]")).to_have_text(
            "TitleFromSettings", timeout=10000)
    finally:
        admin.put("/settings", json={"app_name": before_global or ""})
        _delete_brand_quiet()


def test_default_rendered_shell_shows_dockvault(page: Page):
    """With no override, the default rendered shell shows the DockVault brand — the free /
    self-hosted default. Both the title and the header name are DockVault after brand.js runs."""
    _delete_brand()  # skips if docker absent
    page.goto("/")
    # wait for brand.js to have fetched + applied /branding so this covers the data-driven
    # render, not just the static shell
    page.wait_for_function("() => !!window.localStorage.getItem('dv_branding')", timeout=10000)
    assert "DockVault" in page.title(), f"default title is not DockVault: {page.title()!r}"
    expect(page.locator("#login-screen [data-brand-name]")).to_have_text("DockVault", timeout=10000)


def test_powered_by_persists_under_brand_override(page: Page):
    """The persistent 'powered by DockVault' stays even when a tenant fully rebrands the
    instance (header/name overridden) — a tenant cannot remove the attribution."""
    with brand_override({"app_name": "TenantCorp", "app_full_name": "Tenant Secure"}):
        page.goto("/")
        expect(page.locator("#login-screen [data-brand-name]")).to_have_text("TenantCorp", timeout=10000)
        pb = page.locator("#powered-by")
        expect(pb).to_be_visible()
        assert "DockVault" in pb.inner_text(), f"powered-by lost DockVault: {pb.inner_text()!r}"


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_admin_branding_editor_saves_live(page: Page, admin_creds, admin):
    """A3 end to end through the REAL admin form: log in, open Settings -> Branding, set a
    tagline + primary colour, click Save, and confirm the override lands in /branding —
    proving saveAllSettings actually wires the new brand inputs (not just that they render).
    The colour picker mirrors the text input, and the override is cleaned up afterwards."""
    _delete_brand()  # clean brand baseline (skips if docker absent)
    before_tagline = admin.get("/settings").json().get("app_tagline")
    try:
        # start from a clean 'global' so a residual brand field can't be re-mirrored
        admin.put("/settings", json={"app_tagline": "", "primary_color": ""})
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="settings"]')
        page.click('.tab-btn[data-tab="branding"]')
        tagline = page.locator("#setting-brand-tagline")
        expect(tagline).to_be_visible(timeout=10000)
        tagline.fill("Editor Wired Tagline")
        page.fill("#setting-brand-primary-color", "#abcdef")
        # the text input drives its <input type=color> companion
        assert page.input_value("#setting-brand-primary-color-pick") == "#abcdef", \
            "color picker did not mirror the text input"
        page.click("#save-all-settings-btn")
        # poll /branding until the save lands (avoids racing the async PUT + toast)
        page.wait_for_function(
            "async () => { const b = await (await fetch('/branding')).json();"
            " return b.app_tagline === 'Editor Wired Tagline'"
            " && b.colors['--primary-color'] === '#abcdef'; }",
            timeout=10000,
        )
    finally:
        admin.put("/settings", json={"app_tagline": before_tagline or "", "primary_color": ""})
        _delete_brand_quiet()


def test_admin_uploads_logo_via_form(page: Page, admin_creds, admin, tmp_path):
    """A4 e2e through the REAL admin form: log in, open Settings -> Branding, upload a logo
    via the file input + Upload button, and confirm /branding points every logo slot at the
    uploaded asset — proving wireBrandAssetUploads + uploadBrandAsset (the FormData fetch)
    actually work in a browser. Reset afterwards so the live app is left on the default."""
    admin.delete("/settings/brand/asset/logo")  # clean baseline
    png = tmp_path / "logo.png"
    png.write_bytes(_PNG_1x1)
    try:
        _login(page, admin_creds["username"], admin_creds["password"])
        page.click('.sidebar-item[data-section="settings"]')
        page.click('.tab-btn[data-tab="branding"]')
        expect(page.locator("#brand-logo-upload")).to_be_visible(timeout=10000)
        page.set_input_files("#brand-logo-file", str(png))
        page.click("#brand-logo-upload")
        # the client's uploadBrandAsset updates the on-page preview to the uploaded asset
        # (waiting on the preview proves the browser JS ran, not just that the server
        # committed — the /branding poll below could otherwise win a race with the commit)
        page.wait_for_function(
            "() => { const el = document.getElementById('brand-logo-preview');"
            " return el && (el.src || '').indexOf('/brand-assets/logo.') !== -1; }",
            timeout=10000,
        )
        # and /branding points the logo slot at it
        b = page.evaluate("async () => await (await fetch('/branding')).json()")
        assert b["logo_url"].startswith("/brand-assets/logo."), b["logo_url"]
    finally:
        admin.delete("/settings/brand/asset/logo")


def test_backslash_logo_url_rejected_as_cross_origin(page: Page):
    r"""Browsers normalise '\' to '/' when parsing URLs, so "/\host" resolves
    protocol-relative (cross-origin) like "//host" despite passing a naive
    leading-slash check. safeUrl's same-origin-path branch must reject it —
    the logo src must stay on the static same-origin default."""
    with brand_override({"logo_url": "/\\attacker.example/logo.png",
                         "logo_small_url": "/\\attacker.example/logo.png"}):
        page.goto("/")
        # Wait until brand.js has fetched + applied /branding (it writes its cache
        # after apply), so the src check below cannot race the fetch.
        page.wait_for_function("() => !!window.localStorage.getItem('dv_branding')", timeout=10000)
        logo_src = page.locator("#login-screen [data-brand-logo]").get_attribute("src")
        assert logo_src and logo_src.startswith("/static/"), \
            f"backslash URL not rejected, logo src: {logo_src!r}"
