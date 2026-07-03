"""Effective-branding endpoint tests (A1 — white-label wiring).

Exercises ``GET /branding`` (and ``/info``, which now routes through the same effective
branding) against the live container. The merge is: env ``BrandingConfig`` defaults with
DB ``SystemSetting('brand')`` overrides layered on top.

The pure-HTTP tests (shape / no-secrets / env default) need only a running container.
The A1/A2 override tests seed ``SystemSetting('brand')`` directly via ``docker exec
vault-db psql``; the A3 tests instead drive the real admin write path (``PUT /settings``
mirrors the brand fields into that row). Both always clean the row up and skip cleanly if
docker / psql is unavailable.
"""
import contextlib
import json
import os
import subprocess

import pytest

DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")

# The 8 theme colours are CSS custom properties keyed exactly like get_theme_css_vars().
THEME_VARS = [
    "--primary-color", "--secondary-color", "--accent-color", "--success-color",
    "--warning-color", "--error-color", "--text-color", "--background-color",
]
ASSET_KEYS = ["logo", "logo_dark", "logo_small", "favicon", "og_image"]

# The exact top-level key allow-list /branding may expose (to_public_dict() fields + the
# 'colors' and 'assets' maps). Asserting the payload is a subset of this catches a future
# to_public_dict() edit that leaks a new (possibly secret) field — a value-only scan can't.
ALLOWED_TOP_KEYS = {
    "app_name", "app_full_name", "app_tagline", "app_description", "app_version",
    "company_name", "company_url", "support_email", "website_url", "docs_url",
    "logo_url", "primary_color", "secondary_color", "copyright_notice",
    "colors", "assets", "powered_by",
}


# ---------------------------------------------------------------------------
# DB seeding helpers (mirror test_at_rest_crypto._db_run — skip if docker absent)
# ---------------------------------------------------------------------------
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
    """Best-effort brand-row cleanup for use in a `finally` — never asserts or skips, so a
    transient DB blip during teardown can't mask (or convert to a skip) the real assertion
    that failed inside the `with` block."""
    try:
        subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-c", "DELETE FROM system_settings WHERE key='brand';"],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except Exception:  # noqa: BLE001 — teardown must never raise
        pass


@contextlib.contextmanager
def brand_override(overrides: dict):
    """Seed ``SystemSetting('brand')`` with `overrides` for the block, then always delete
    the row so the global brand state is left clean for the next test."""
    payload = json.dumps(overrides).replace("'", "''")  # SQL-escape any single quotes
    _delete_brand()  # defend against a row left by a crashed prior run (skips if no docker)
    _psql(
        "INSERT INTO system_settings (key, value, updated_at) "
        f"VALUES ('brand', '{payload}', now()) "
        "ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value, updated_at = now();"
    )
    try:
        yield
    finally:
        _delete_brand_quiet()


def _all_keys(obj) -> set:
    """Every dict key anywhere in a nested JSON structure (lower-cased)."""
    keys = set()
    if isinstance(obj, dict):
        for k, v in obj.items():
            keys.add(str(k).lower())
            keys |= _all_keys(v)
    elif isinstance(obj, list):
        for v in obj:
            keys |= _all_keys(v)
    return keys


# ---------------------------------------------------------------------------
# Pure-HTTP tests (no DB seeding)
# ---------------------------------------------------------------------------
def test_branding_shape_and_no_secrets(anon):
    """/branding is public and returns the effective public dict: identity + company +
    URLs + copyright, the 8 theme colours (CSS vars), and asset URLs — and NO secrets."""
    r = anon.get("/branding")
    assert r.status_code == 200, r.text
    data = r.json()

    for k in ("app_name", "app_full_name", "app_tagline", "app_version",
              "company_name", "company_url", "support_email",
              "website_url", "docs_url", "logo_url", "copyright_notice"):
        assert k in data, f"missing public field {k!r}: {data}"

    colors = data.get("colors") or {}
    for var in THEME_VARS:
        assert var in colors, f"missing theme colour {var!r}: {colors}"

    assets = data.get("assets") or {}
    for a in ASSET_KEYS:
        assert a in assets, f"missing asset {a!r}: {assets}"

    # No secret-ish field may appear anywhere in the public payload...
    keys = _all_keys(data)
    for secret in ("smtp_password", "sentry_dsn", "mixpanel_token", "google_analytics_id",
                   "password", "secret", "token", "dsn", "api_key"):
        assert not any(secret in k for k in keys), f"secret-ish key {secret!r} leaked into /branding"

    # ...and, stronger than a name scan, the top-level payload must not grow NEW keys — a
    # future to_public_dict() edit that leaks a field (secret or otherwise) fails here.
    unexpected = set(data.keys()) - ALLOWED_TOP_KEYS
    assert not unexpected, f"/branding exposed unexpected top-level keys: {unexpected}"


def test_branding_env_default_no_override(anon):
    """With no override, /branding reflects the env BrandingConfig default — the DockVault
    brand (a fresh/self-hosted instance shows DockVault; overrides are opt-in)."""
    _delete_brand()  # ensure a clean baseline (skips if docker absent, which is fine)
    r = anon.get("/branding")
    assert r.status_code == 200, r.text
    assert r.json()["app_name"] == "DockVault"


# ---------------------------------------------------------------------------
# DB-override tests (seed SystemSetting('brand'); self-cleaning)
# ---------------------------------------------------------------------------
def test_branding_db_override_wins(anon):
    """A DB override of a branding field overrides the env default in /branding."""
    with brand_override({"app_name": "AcmeVault", "primary_color": "#123456"}):
        data = anon.get("/branding").json()
        assert data["app_name"] == "AcmeVault"
        assert data["colors"]["--primary-color"] == "#123456"
    # after the block the row is gone -> env default (DockVault) restored
    assert anon.get("/branding").json()["app_name"] == "DockVault"


def test_branding_unknown_key_falls_back(anon):
    """An unknown override key is ignored (never leaks), while a known key still wins."""
    with brand_override({"totally_bogus_field": "x", "app_name": "KnownWins"}):
        data = anon.get("/branding").json()
        assert data["app_name"] == "KnownWins"
        assert "totally_bogus_field" not in _all_keys(data)


def test_branding_invalid_value_falls_back_to_env(anon):
    """A stored override the validators reject (bad hex colour) reverts to the env default,
    without discarding the other valid overrides in the same row."""
    with brand_override({"primary_color": "not-a-hex", "app_name": "BadColorCo"}):
        data = anon.get("/branding").json()
        assert data["app_name"] == "BadColorCo"                      # valid override kept
        assert data["colors"]["--primary-color"] == "#2563eb"        # invalid one -> env default


def test_branding_metachar_color_rejected(anon):
    """A hex-SHAPED colour carrying CSS metacharacters (e.g. '#}body{', which the old
    length-only validator accepted and which would break out of a :root{} block in A2) is
    rejected by the strict validator and falls back to the env default — the read-time
    guard actually catches it, not just malformed-length values."""
    with brand_override({"primary_color": "#}body{", "app_name": "MetaCo"}):
        data = anon.get("/branding").json()
        assert data["app_name"] == "MetaCo"                          # valid override kept
        assert data["colors"]["--primary-color"] == "#2563eb"        # metachar colour -> env default


def test_branding_override_is_reversible(anon):
    """Setting then clearing an override returns /branding to its baseline (proves the
    endpoint re-reads the DB every call — edits are live, no restart)."""
    baseline = anon.get("/branding").json()["app_name"]
    with brand_override({"app_name": "TransientCo"}):
        assert anon.get("/branding").json()["app_name"] == "TransientCo"
    assert anon.get("/branding").json()["app_name"] == baseline


def test_info_endpoint_reflects_effective_override(anon):
    """/info now routes through the same effective branding, so a DB override shows there
    too (proves 'all readers go through get_effective_branding', not the env singleton)."""
    with brand_override({"app_name": "InfoBrand"}):
        info = anon.get("/info").json()
        assert info["app"]["name"] == "InfoBrand"
        assert info["branding"]["app_name"] == "InfoBrand"


# ---------------------------------------------------------------------------
# A2 — the served shell is data-driven (brand hooks + brand.js drive the chrome)
# ---------------------------------------------------------------------------
def test_index_shell_is_brand_driven(anon):
    """The served index shell drives its brand chrome from /branding via brand.js +
    data-brand-* hooks (A2 wiring), so a deployment can override it at deploy/runtime. The
    static HTML carries the DockVault DEFAULT that brand.js overwrites when an override
    exists — so the same shell serves a DockVault free instance and a rebranded paid one."""
    r = anon.get("/")
    assert r.status_code == 200, r.text
    html = r.text
    assert "/static/js/brand.js" in html, "brand.js is not wired into the shell <head>"
    for hook in ("data-brand-name", "data-brand-logo", "data-brand-tagline", "data-brand-template"):
        assert hook in html, f"missing brand hook {hook!r} in the served shell"
    assert "DockVault" in html, "the static shell should carry the DockVault default"


# ---------------------------------------------------------------------------
# DockVault-default brand + the /settings app_name wiring
# ---------------------------------------------------------------------------
def _all_strings(node):
    """Yield every string that appears anywhere in a JSON payload (keys + values)."""
    if isinstance(node, dict):
        for k, v in node.items():
            yield k
            yield from _all_strings(v)
    elif isinstance(node, list):
        for v in node:
            yield from _all_strings(v)
    elif isinstance(node, str):
        yield node


def test_branding_default_is_dockvault(anon):
    """Core lock: with NO override, the default /branding IS the DockVault brand — a fresh /
    self-hosted instance shows DockVault (name + identity), so the free product keeps the
    DockVault brand. A deployment overrides it via BRAND_* env or the admin editor."""
    _delete_brand()  # skips if docker absent
    data = anon.get("/branding").json()
    assert data["app_name"] == "DockVault"
    # the DockVault identity IS present by default (the inverse of the old neutral lock)
    assert any("dockvault" in s.lower() for s in _all_strings(data)), \
        "the default brand should carry the DockVault identity"
    # the persistent 'powered by' attribution defaults ON and to DockVault
    pb = data["powered_by"]
    assert pb["show"] is True
    assert pb["name"] == "DockVault"


def test_powered_by_is_not_editable_via_settings(admin, anon):
    """The 'powered by' attribution is NOT part of the admin-editable brand set, so a tenant
    can't remove/change it from /settings — it stays DockVault regardless."""
    _delete_brand()
    try:
        # try to tamper via the Settings editor -> ignored (not a brand override key)
        admin.put("/settings", json={"powered_by_name": "Tenant", "show_powered_by": False,
                                     "powered_by": {"show": False}})
        pb = anon.get("/branding").json()["powered_by"]
        assert pb["show"] is True and pb["name"] == "DockVault", \
            f"powered-by was tampered via /settings: {pb}"
    finally:
        _delete_brand_quiet()


def test_settings_app_name_drives_branding(admin, anon):
    """PUT /settings {app_name} is mirrored into the effective branding override, so the
    ONE existing admin brand field actually drives /branding (A6 wiring; A3 extends it).
    Clearing the field (empty string) drops the override -> back to the DockVault default."""
    _delete_brand()  # clean brand baseline (skips if docker absent)
    before_global = admin.get("/settings").json().get("app_name")
    try:
        r = admin.put("/settings", json={"app_name": "SettingsBrandCo"})
        assert r.status_code == 200, r.text
        assert anon.get("/branding").json()["app_name"] == "SettingsBrandCo"
        # the plain settings store still round-trips too
        assert admin.get("/settings").json().get("app_name") == "SettingsBrandCo"
        # clearing removes the brand override -> DockVault default returns
        assert admin.put("/settings", json={"app_name": ""}).status_code == 200
        assert anon.get("/branding").json()["app_name"] == "DockVault"
    finally:
        # restore the stored settings value and remove any brand residue
        admin.put("/settings", json={"app_name": before_global or ""})
        _delete_brand_quiet()


def test_settings_app_name_rejects_non_string(admin):
    """app_name now feeds the rendered shell brand — a non-string must 400, not persist."""
    r = admin.put("/settings", json={"app_name": 123})
    assert r.status_code == 400, r.text
    r = admin.put("/settings", json={"app_name": "x" * 101})
    assert r.status_code == 400, r.text


# ---------------------------------------------------------------------------
# A3 — admin Settings brand editor: the full brand set is editable + validated
# ---------------------------------------------------------------------------
_A3_BRAND = {
    "app_full_name": "Acme Full Platform",
    "app_tagline": "Ship files, not stress",
    "company_name": "Acme Inc.",
    "support_email": "help@acme.example",
    "company_url": "https://acme.example",
    "website_url": "https://acme.example",
    "docs_url": "/docs",
    "copyright_holder": "Acme Copyright Co.",
    "primary_color": "#123456",
    "secondary_color": "#abcdef",
    "accent_color": "#0a0b0c",
}


def _reset_global(admin, keys) -> None:
    """Best-effort: blank the 'global' brand keys a test wrote so it leaves no residue
    for the next one (the effective /branding reads the 'brand' row, cleaned separately)."""
    try:
        admin.put("/settings", json={k: "" for k in keys})
    except Exception:  # noqa: BLE001 — teardown must never raise
        pass


def test_settings_full_brand_set_drives_branding(admin, anon):
    """A3 core: PUT /settings with the full brand set mirrors into SystemSetting('brand') so
    /branding reflects every field (identity, company, key URLs, copyright + the theme
    colours). Clearing them (empty strings) reverts to the DockVault env defaults."""
    _delete_brand()  # clean baseline (skips if docker absent)
    try:
        assert admin.put("/settings", json=dict(_A3_BRAND)).status_code == 200
        data = anon.get("/branding").json()
        assert data["app_full_name"] == "Acme Full Platform"
        assert data["app_tagline"] == "Ship files, not stress"
        assert data["company_name"] == "Acme Inc."
        assert data["support_email"] == "help@acme.example"
        assert data["company_url"] == "https://acme.example"
        assert data["website_url"] == "https://acme.example"
        assert data["docs_url"] == "/docs"
        assert "Acme Copyright Co." in data["copyright_notice"]
        assert data["colors"]["--primary-color"] == "#123456"
        assert data["colors"]["--secondary-color"] == "#abcdef"
        assert data["colors"]["--accent-color"] == "#0a0b0c"
        # clear every override -> DockVault env defaults return
        assert admin.put("/settings", json={k: "" for k in _A3_BRAND}).status_code == 200
        after = anon.get("/branding").json()
        assert after["company_name"] == "DockVault"             # env default
        assert after["app_tagline"] != "Ship files, not stress"
        assert after["colors"]["--primary-color"] != "#123456"
    finally:
        _reset_global(admin, _A3_BRAND)
        _delete_brand_quiet()


def test_settings_brand_rejects_invalid_color(admin):
    """A3: an invalid hex colour is rejected (400) — including the ':root'-injection
    payload the strict regex exists to block — while a valid #rgb still saves."""
    _delete_brand()
    try:
        for bad in ("not-a-color", "#12", "#12345", "#}body{", "red", "#1234567"):
            r = admin.put("/settings", json={"primary_color": bad})
            assert r.status_code == 400, f"{bad!r} accepted: {r.status_code} {r.text[:200]}"
        assert admin.put("/settings", json={"primary_color": "#0af"}).status_code == 200
    finally:
        _reset_global(admin, ["primary_color"])
        _delete_brand_quiet()


def test_settings_brand_rejects_invalid_email(admin):
    """A3: a malformed support email is rejected with a 400 (reuses the model's email rule)."""
    _delete_brand()
    try:
        assert admin.put("/settings", json={"support_email": "not-an-email"}).status_code == 400
        assert admin.put("/settings", json={"support_email": "ok@acme.example"}).status_code == 200
    finally:
        _reset_global(admin, ["support_email"])
        _delete_brand_quiet()


def test_settings_brand_rejects_unsafe_url(admin, anon):
    """A3: brand URLs are scheme-validated server-side (mirrors brand.js safeUrl) —
    javascript:/data:, other schemes, protocol-relative //host, and a backslash
    cross-origin bypass are rejected; an https URL and a same-origin /path are accepted."""
    _delete_brand()
    try:
        # NOTE: internal control chars (e.g. "/\tevil") are the A2 attack shape and survive
        # .strip(); a merely LEADING-whitespace URL is stripped to a clean value and is safe.
        for bad in ("javascript:alert(1)", "//evil.example", "/\\evil.example",
                    "data:text/html,x", "ftp://evil.example", "/\tevil.example"):
            r = admin.put("/settings", json={"website_url": bad})
            assert r.status_code == 400, f"{bad!r} accepted: {r.status_code} {r.text[:200]}"
        assert admin.put("/settings", json={"website_url": "https://ok.example"}).status_code == 200
        assert anon.get("/branding").json()["website_url"] == "https://ok.example"
        assert admin.put("/settings", json={"website_url": "/status"}).status_code == 200
        assert anon.get("/branding").json()["website_url"] == "/status"
    finally:
        _reset_global(admin, ["website_url"])
        _delete_brand_quiet()


def test_settings_brand_rejects_overlong(admin):
    """A3: an over-length brand string is rejected (400); the field's cap is accepted."""
    _delete_brand()
    try:
        assert admin.put("/settings", json={"app_tagline": "x" * 201}).status_code == 400
        assert admin.put("/settings", json={"app_tagline": "x" * 200}).status_code == 200
    finally:
        _reset_global(admin, ["app_tagline"])
        _delete_brand_quiet()
