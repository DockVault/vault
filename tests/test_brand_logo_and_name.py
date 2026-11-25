"""The logo, the name beside it and the privacy policy address, offline.

- /branding: an uploaded asset (under /brand-assets/) whose file is gone is replaced by the built-in default of its
  slot (logo, logo_dark, logo_small, favicon), with one warning per process per slot that names the slot and never
  the path. GET /settings says which upload (logo, favicon) is missing, and the Branding page says so beside it.
- show_name_beside_logo: a brand setting, on by default, kept in the brand override store (False included), carried
  by /branding, and edited on the Branding page as a switch. brand.js hides the name beside a logo that loaded when it
  is off, and shows it again when the logo cannot be loaded.
- privacy_policy_url: empty by default, edited on the Branding page under Links with the other links' address check,
  and GET /legal reports null while it is empty.
- brand.js: every [data-brand-logo] falls back once to the built-in logo and is hidden if that fails too.
- index.html: every link to /recording reads "Privacy".
"""
import re
import types
from pathlib import Path

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.config import effective  # noqa: E402
from app.config.branding import BrandingConfig  # noqa: E402
from app.routers import info  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
STATIC = ROOT / "static"


def _read(path: Path) -> str:
    return path.read_text(encoding="utf-8")


def _code(text: str) -> str:
    """Script text without its comments."""
    return re.sub(r"/\*.*?\*/|(?<![:\"'\\])//[^\n]*", "", text, flags=re.S)


def _default(field):
    return effective._field_default(field)


def _base(**values):
    """A config with the fields under test set explicitly, so a developer's .env cannot change the outcome."""
    fixed = dict(logo_url="/static/assets/logo.png", logo_dark_url="/static/assets/logo.png",
                 logo_small_url="/static/assets/logo-small.png", favicon_url="/static/assets/logo-small.png",
                 show_name_beside_logo=True, privacy_policy_url="")
    fixed.update(values)
    return BrandingConfig(**fixed)


@pytest.fixture
def warnings(monkeypatch):
    """The warnings effective.py writes, with the once-per-process memory emptied for the test."""
    seen = []
    monkeypatch.setattr(effective, "_missing_logged", set())
    monkeypatch.setattr(effective, "logger", types.SimpleNamespace(
        warning=lambda msg, *args, **kwargs: seen.append(msg % args if args else msg)))
    return seen


# --------------------------------------------------------------------------- a missing uploaded file

UPLOADS = {
    "logo_url": "/brand-assets/logo.0a1b2c3d.png",
    "logo_dark_url": "/brand-assets/logo.0a1b2c3d.png",
    "logo_small_url": "/brand-assets/logo.0a1b2c3d.png",
    "favicon_url": "/brand-assets/favicon.4e5f6a7b.png",
}


def test_a_missing_upload_falls_back_to_the_built_in_default_of_its_slot(tmp_path, warnings):
    (tmp_path / "favicon.4e5f6a7b.png").write_bytes(b"\x89PNG\r\n\x1a\n")    # the favicon is there, the logo is not
    cfg = effective.merge_branding(_base(), dict(UPLOADS))
    assets = effective.branding_public_payload(cfg, str(tmp_path))["assets"]
    assert assets["logo"] == _default("logo_url") == "/static/assets/logo.png"
    assert assets["logo_dark"] == _default("logo_dark_url")
    assert assets["logo_small"] == _default("logo_small_url") == "/static/assets/logo-small.png"
    assert assets["favicon"] == "/brand-assets/favicon.4e5f6a7b.png"
    # The top-level logo address follows the same rule.
    assert effective.branding_public_payload(cfg, str(tmp_path))["logo_url"] == "/static/assets/logo.png"


def test_the_warning_is_written_once_per_slot_and_names_the_slot_never_the_path(tmp_path, warnings):
    cfg = effective.merge_branding(_base(), dict(UPLOADS))
    for _ in range(3):
        effective.branding_public_payload(cfg, str(tmp_path))
    assert len(warnings) == 4, warnings
    for slot in ("logo", "logo_dark", "logo_small", "favicon"):
        assert sum(f"the {slot} slot" in w for w in warnings) == 1, (slot, warnings)
    for line in warnings:
        assert "/brand-assets" not in line and "0a1b2c3d" not in line and str(tmp_path) not in line


def test_present_files_and_built_in_or_outside_addresses_are_served_as_they_are(tmp_path, warnings):
    (tmp_path / "logo.0a1b2c3d.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    (tmp_path / "favicon.4e5f6a7b.png").write_bytes(b"\x89PNG\r\n\x1a\n")
    cfg = effective.merge_branding(_base(), dict(UPLOADS))
    assets = effective.branding_public_payload(cfg, str(tmp_path))["assets"]
    assert assets["logo"] == assets["logo_small"] == "/brand-assets/logo.0a1b2c3d.png"
    assert assets["favicon"] == "/brand-assets/favicon.4e5f6a7b.png"
    outside = _base(logo_url="https://cdn.example/logo.png", logo_small_url="/static/assets/logo-small.png")
    assets = effective.branding_public_payload(outside, str(tmp_path))["assets"]
    assert assets["logo"] == "https://cdn.example/logo.png" and assets["logo_small"] == "/static/assets/logo-small.png"
    assert warnings == []


@pytest.mark.parametrize("url", ["/brand-assets/", "/brand-assets/../secret.png", "/brand-assets/a/b.png",
                                 "/brand-assets/..\\x.png"])
def test_a_name_the_asset_route_would_refuse_counts_as_missing(tmp_path, url):
    assert effective.brand_asset_missing(url, str(tmp_path)) is True


def test_the_public_payload_checks_the_brand_asset_folder_by_default(tmp_path, monkeypatch, warnings):
    monkeypatch.setenv("BRAND_ASSET_DIR", str(tmp_path))
    assert effective.brand_asset_dir() == str(tmp_path)
    cfg = effective.merge_branding(_base(), {"favicon_url": "/brand-assets/favicon.4e5f6a7b.png"})
    assert effective.branding_public_payload(cfg)["assets"]["favicon"] == _default("favicon_url")
    (tmp_path / "favicon.4e5f6a7b.png").write_bytes(b"\x00\x00\x01\x00")
    assert effective.branding_public_payload(cfg)["assets"]["favicon"] == "/brand-assets/favicon.4e5f6a7b.png"


def test_the_server_and_the_payload_use_one_folder():
    source = _read(ROOT / "app" / "api" / "api_server.py")
    assert "BRAND_ASSET_DIR = brand_asset_dir()" in source
    assert 'os.environ.get("BRAND_ASSET_DIR", str(PROJECT_ROOT / "brand"))' in _read(ROOT / "app" / "config" / "effective.py")
    # /theme serves the same asset addresses as /branding.
    assert "urls = brand_asset_urls(cfg)" in _read(ROOT / "app" / "routers" / "info.py")


def test_settings_reports_which_upload_is_missing(tmp_path):
    (tmp_path / "favicon.4e5f6a7b.png").write_bytes(b"\x00\x00\x01\x00")
    assert effective.missing_brand_uploads(dict(UPLOADS), str(tmp_path)) == ["logo"]
    (tmp_path / "favicon.4e5f6a7b.png").unlink()
    assert effective.missing_brand_uploads(dict(UPLOADS), str(tmp_path)) == ["logo", "favicon"]
    # No upload stored: nothing is missing.
    assert effective.missing_brand_uploads({}, str(tmp_path)) == []
    source = _read(ROOT / "app" / "api" / "api_server.py")
    get_settings = source[source.index('@app.get("/settings")'):source.index('@app.put("/settings")')]
    assert 'data["brand_assets_missing"] = missing_brand_uploads(load_brand_overrides(db), BRAND_ASSET_DIR)' \
        in get_settings


def test_the_branding_page_says_which_upload_is_missing():
    html = _read(STATIC / "index.html")
    assert ('<span class="brand-asset-missing text-error text-sm" id="brand-logo-missing" role="status" hidden>'
            "The uploaded logo is missing from the server. Upload it again.</span>") in html
    assert ('<span class="brand-asset-missing text-error text-sm" id="brand-favicon-missing" role="status" hidden>'
            "The uploaded favicon is missing from the server. Upload it again.</span>") in html
    app = _read(STATIC / "js" / "app.js")
    assert "const missing = Array.isArray(settings.brand_assets_missing) ? settings.brand_assets_missing : [];" in app
    assert "['logo', 'favicon'].forEach(slot => _brandMissing(slot, missing.includes(slot)));" in app
    assert "if (el) el.hidden = !isMissing;" in app
    # A new upload or a reset clears the note.
    assert app.count("_brandMissing(slot, false);") == 2


# --------------------------------------------------------------------------- show the name beside the logo

class _Query:
    def __init__(self, db):
        self.db = db

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self.db.row


class _DB:
    """The one brand row, as set_brand_overrides and load_brand_overrides read and write it."""

    def __init__(self):
        self.row = None

    def query(self, model):
        return _Query(self)

    def add(self, row):
        self.row = row


def test_the_name_switch_is_on_by_default_with_an_env_twin():
    assert _default("show_name_beside_logo") is True
    env_prefix = getattr(BrandingConfig, "model_config", {}).get("env_prefix") \
        or getattr(getattr(BrandingConfig, "Config", None), "env_prefix", None)
    assert env_prefix == "BRAND_"
    assert "# BRAND_SHOW_NAME_BESIDE_LOGO=true" in _read(ROOT / ".env.example")
    payload = effective.branding_public_payload(_base())
    assert payload["show_name_beside_logo"] is True


def test_the_name_switch_round_trips_through_the_override_store_and_branding():
    db = _DB()
    effective.set_brand_overrides(db, updates={"show_name_beside_logo": False})
    assert effective.load_brand_overrides(db) == {"show_name_beside_logo": False}, "False is a value, not a blank"
    cfg = effective.merge_branding(_base(), effective.load_brand_overrides(db))
    assert effective.branding_public_payload(cfg)["show_name_beside_logo"] is False
    effective.set_brand_overrides(db, updates={"show_name_beside_logo": True})
    assert effective.load_brand_overrides(db) == {"show_name_beside_logo": True}
    # None clears it, as an empty field does: the deployment's value is back.
    effective.set_brand_overrides(db, updates={"show_name_beside_logo": None})
    assert effective.load_brand_overrides(db) == {}
    assert effective.branding_public_payload(
        effective.merge_branding(_base(), effective.load_brand_overrides(db)))["show_name_beside_logo"] is True
    # A non-boolean stored by hand never breaks a reader: it is dropped for the default.
    assert effective.merge_branding(_base(), {"show_name_beside_logo": "sometimes"}).show_name_beside_logo is True


def test_the_settings_save_takes_the_switch_and_checks_it():
    assert "show_name_beside_logo" in S._BRAND_FIELDS and "show_name_beside_logo" in S._BRAND_BOOL_FIELDS
    for bad in ("false", 0, None, "yes"):
        with pytest.raises(HTTPException) as caught:
            S._validate_brand_overrides({"show_name_beside_logo": bad})
        assert caught.value.status_code == 400
    S._validate_brand_overrides({"show_name_beside_logo": False})
    source = _read(ROOT / "app" / "api" / "api_server.py")
    put = source[source.index('@app.put("/settings")'):]
    put = put[:put.index("\n@app.")]
    # The deployment's own value keeps no override.
    assert "for key in _BRAND_BOOL_FIELDS & brand_keys:" in put
    assert "if brand_updates[key] == bool(getattr(_env_branding(), key)):" in put
    assert "set_brand_overrides(db, updates=brand_updates)" in put
    get = source[source.index('@app.get("/settings")'):source.index('@app.put("/settings")')]
    assert 'data["show_name_beside_logo"] = bool(get_effective_branding(db).show_name_beside_logo)' in get


def test_the_branding_page_has_the_switch_under_the_logo():
    html = _read(STATIC / "index.html")
    page = html[html.index('<div id="settings-tab-branding"'):html.index('<div id="settings-tab-security"')]
    logo = page.index('data-setting="brand_logo"')
    row = page.index('data-setting="brand_show_name"')
    assert logo < row < page.index('data-setting="brand_favicon"')
    switch = re.search(r'<button type="button" id="setting-brand-show-name"[^>]*>', page).group(0)
    assert 'role="switch"' in switch and 'aria-checked="true"' in switch
    assert 'aria-describedby="setting-brand-show-name-help"' in switch
    assert '<label for="setting-brand-show-name">Show the name beside the logo</label>' in page
    assert ('<small class="text-secondary block" id="setting-brand-show-name-help">Turn this off when your logo '
            "already shows the name. The name is still used for the browser tab, emails and screen readers, and "
            "shows on its own if the logo cannot be loaded.</small>") in page
    app = _read(STATIC / "js" / "app.js")
    assert "setBrandShowName(settings.show_name_beside_logo !== false);" in app
    assert "sw.addEventListener('click', () => setBrandShowName(!brandShowNameValue()));" in app
    assert "if (showName !== null) settings.show_name_beside_logo = showName;" in app


# --------------------------------------------------------------------------- the privacy policy address

def test_the_privacy_policy_address_is_empty_by_default():
    assert _default("privacy_policy_url") == ""
    assert "dockvault.io/privacy" not in _read(ROOT / "app" / "config" / "branding.py")


@pytest.mark.parametrize("value,reported", [("", None), ("   ", None),
                                            ("https://example.com/privacy", "https://example.com/privacy")])
def test_legal_reports_null_while_the_address_is_empty(monkeypatch, value, reported):
    monkeypatch.setattr(info, "get_effective_branding", lambda db: _base(privacy_policy_url=value))
    assert run_coroutine(info.get_legal_links(db=None))["privacy_policy"] == reported


def test_the_privacy_policy_address_is_an_editable_link():
    assert "privacy_policy_url" in S._BRAND_URL_FIELDS and "privacy_policy_url" in S._BRAND_FIELDS
    for bad in ("javascript:alert(1)", "//evil.example", "/\\evil.example", "data:text/html,x", "/\tevil", 5):
        with pytest.raises(HTTPException) as caught:
            S._validate_brand_overrides({"privacy_policy_url": bad})
        assert caught.value.status_code == 400, bad
    for good in ("https://example.com/privacy", "/privacy", ""):
        S._validate_brand_overrides({"privacy_policy_url": good})
    db = _DB()
    effective.set_brand_overrides(db, updates={"privacy_policy_url": " https://example.com/privacy "})
    cfg = effective.merge_branding(_base(), effective.load_brand_overrides(db))
    assert cfg.privacy_policy_url == "https://example.com/privacy"
    html = _read(STATIC / "index.html")
    links = html[html.index("<h3>Links</h3>"):html.index("<h3>Theme Colors</h3>")]
    assert 'data-setting="brand_privacy_policy_url"' in links
    assert '<label for="setting-brand-privacy-policy-url">Privacy policy URL</label>' in links
    assert re.search(r'<input type="url" id="setting-brand-privacy-policy-url" class="form-control" maxlength="500"',
                     links)
    assert "'setting-brand-privacy-policy-url': 'privacy_policy_url'," in _read(STATIC / "js" / "app.js")
    assert "# BRAND_PRIVACY_POLICY_URL=" in _read(ROOT / ".env.example")


# --------------------------------------------------------------------------- brand.js

BRAND = _read(STATIC / "js" / "brand.js")
BRAND_CODE = _code(BRAND)


def _function(code, head):
    start = code.index(head)
    end = code.index("\n    }\n", start)
    return code[start:end]


def test_a_logo_falls_back_once_to_the_built_in_logo_then_hides():
    assert "var FALLBACK_LOGO = '/static/assets/logo-small.png';" in BRAND_CODE
    on_error = _function(BRAND_CODE, "function onLogoError(img)")
    first = on_error.index("img.setAttribute('src', FALLBACK_LOGO);")
    hide = on_error.index("img.style.display = 'none';")
    assert "if (!img.hasAttribute('data-brand-fallback') && src !== FALLBACK_LOGO)" in on_error
    assert first < hide and "img.setAttribute('data-brand-fallback', '1');" in on_error
    assert on_error.rstrip().endswith("syncLogo(img);")
    # Every [data-brand-logo], from the first one parsed: the listeners capture on the document, in <head>.
    assert ("document.addEventListener('error', function (e) {\n        var t = e.target;\n"
            "        if (t && t.tagName === 'IMG' && t.hasAttribute('data-brand-logo')) onLogoError(t);\n"
            "    }, true);") in BRAND_CODE
    assert "document.addEventListener('load', function (e) {" in BRAND_CODE
    # An address that failed is not tried again on the same image.
    assert "if (img.getAttribute('data-brand-failed') === url) return;" in _function(BRAND_CODE, "function setLogoSrc(")


def test_the_name_hides_only_beside_a_brand_logo_that_loaded():
    assert "showName = b.show_name_beside_logo !== false;" in BRAND_CODE
    beside = _function(BRAND_CODE, "function nameBeside(img)")
    assert "parent.querySelector('[data-brand-name]')" in beside
    loaded = _function(BRAND_CODE, "function logoLoaded(img)")
    # The built-in fallback or a hidden image is not the brand's logo: the name shows.
    assert ("if (img.hasAttribute('data-brand-fallback') || img.hasAttribute('data-brand-logo-hidden')) "
            "return false;") in loaded
    sync = _function(BRAND_CODE, "function syncLogo(img)")
    assert "var logoOnly = !showName && logoLoaded(img);" in sync
    assert "name.style.display = logoOnly ? 'none' : '';" in sync
    # The image carries the name only when the name is hidden; alt="" while it shows.
    assert "img.setAttribute('alt', logoOnly ? label : '');" in sync
    # The markup ships alt="" beside the name, never alt text that could show next to it.
    html = _read(STATIC / "index.html")
    for tag in re.findall(r"<img [^>]*data-brand-logo[^>]*>", html):
        assert 'alt=""' in tag, tag


def test_brand_js_writes_no_markup_and_guards_its_storage():
    assert not re.search(r"innerHTML|outerHTML|insertAdjacentHTML|document\.write", BRAND_CODE)
    assert BRAND_CODE.count("localStorage") == 2
    for match in re.finditer(r"localStorage\.", BRAND_CODE):
        before = BRAND_CODE[:match.start()]
        opened = before.rfind("try {")
        # Inside a try block: one opened before it and not yet closed by its catch.
        assert opened != -1 and "catch" not in before[opened:]
        assert "catch" in BRAND_CODE[match.start():match.start() + 300]


def test_every_page_loads_the_same_brand_js():
    versions = {}
    for page in ("index.html", "upload-link.html", "public-link.html", "note-link.html", "recording.html"):
        found = re.findall(r'<script src="/static/js/brand\.js\?v=(\d{8}[a-z])"></script>', _read(STATIC / page))
        assert len(found) == 1, page
        versions[page] = found[0]
    assert versions["index.html"] == "20261125a"
    assert len(set(versions.values())) == 1, versions


# --------------------------------------------------------------------------- the Privacy links

def test_every_link_to_the_privacy_page_in_the_app_reads_privacy():
    html = _read(STATIC / "index.html")
    assert "What this vault records" not in html
    login = html[html.index('<div id="login-screen"'):html.index('<div id="boot-screen"')]
    invite = html[html.index('<div id="invite-screen"'):html.index('<div id="reset-screen"')]
    for part in (login, invite):
        link = re.search(r'<p class="[^"]*recording-link"[^>]*>\s*<a href="/recording" target="_blank" '
                         r'rel="noopener">([^<]+)</a>', part)
        assert link and link.group(1) == "Privacy"
    # The sign-up form shares the sign-in card's link, after both forms.
    assert login.index('id="signup-form"') < login.index("recording-link")
    menu = html[html.index('id="recording-notice-link"'):]
    assert menu[:menu.index("</a>")].rstrip().endswith("<span>Privacy</span>")
