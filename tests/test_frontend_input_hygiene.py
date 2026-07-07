"""Frontend input-hygiene / output-encoding hardening.

Two complementary layers, both defence-in-depth against markup injection into operator/admin UIs
(the audit log, the dashboard activity feed, group chips):

1. Server-side: name fields (vault/user/group/file) reject angle brackets + control characters at
   the source, and group chip colours are constrained to a strict #hex or a named palette preset.
   These run against the live instance.
2. Client-side: the DOM render paths that were previously unescaped now pass their user-controlled
   values through escapeHtml() / a strict hex validator, and the login flow no longer logs the
   bearer token to the console. These are asserted against the shipped static/js/app.js source.
"""
from pathlib import Path

import pytest

from conftest import unique

STATIC = Path(__file__).resolve().parent.parent / "static"
APP_JS = (STATIC / "js" / "app.js").read_text(encoding="utf-8", errors="ignore")


# --------------------------------------------------------------------------------------------------
# Server-side name/colour validation (live)
# --------------------------------------------------------------------------------------------------
def test_vault_name_rejects_markup(admin):
    r = admin.post("/vaults", json={"name": "<img src=x onerror=alert(1)>"})
    assert r.status_code == 422, r.text


def test_vault_name_accepts_ordinary_name(admin):
    name = unique("hygiene-vault")
    r = admin.post("/vaults", json={"name": name})
    assert r.status_code in (200, 201), r.text
    vid = r.json()["id"]
    admin.delete_vault(vid)


def test_username_rejects_markup(admin):
    r = admin.post(
        "/users",
        json={"username": "ev<il", "email": f"{unique('e')}@example.com", "password": "TestPassw0rd!123"},
    )
    assert r.status_code == 422, r.text


def test_group_name_rejects_markup(admin):
    r = admin.post("/groups", json={"name": "<b>dept</b>"})
    assert r.status_code == 422, r.text


def test_file_rename_rejects_markup(admin):
    # A plaintext file rename to an angle-bracket name is rejected before it can reach the audit log
    # (control chars remain a separate concern, stripped by the sanitiser, not rejected here).
    v = admin.create_vault()
    try:
        up = admin.post(
            f"/vaults/{v['id']}/uploads",
            json={"file_name": "orig.txt", "total_size": 5, "total_chunks": 1, "chunk_size": 5},
        )
        sid = up.json().get("session_id") or up.json().get("id")
        admin.put(f"/vaults/{v['id']}/uploads/{sid}/chunks/0", data=b"hello")
        admin.post(f"/vaults/{v['id']}/uploads/{sid}/complete", json={})
        fid = next(x["id"] for x in admin.get(f"/vaults/{v['id']}/files").json()["items"]
                   if x.get("type") == "file")
        r = admin.put(f"/vaults/{v['id']}/files/{fid}/rename",
                      json={"new_name": "</pre><b>x</b>.txt"})
        assert r.status_code == 422, r.text
    finally:
        admin.delete_vault(v["id"])


def test_group_colour_rejects_attribute_breakout(admin):
    # A '#'-prefixed value carrying a double-quote would break out of the style="--chip:…" attribute.
    r = admin.post("/groups", json={"name": unique("grp"), "color": '#0" onmouseover=a('})
    assert r.status_code == 422, r.text


def test_group_colour_rejects_non_hex_garbage(admin):
    r = admin.post("/groups", json={"name": unique("grp"), "color": "not-a-colour"})
    assert r.status_code == 422, r.text


def test_group_colour_accepts_hex_and_preset(admin):
    for color in ("#14b8a6", "indigo"):
        r = admin.post("/groups", json={"name": unique("grp"), "color": color})
        assert r.status_code in (200, 201), f"{color}: {r.text}"
        admin.delete(f"/groups/{r.json()['id']}")


# --------------------------------------------------------------------------------------------------
# Response-header hardening (live)
# --------------------------------------------------------------------------------------------------
def test_legacy_xss_auditor_disabled(admin):
    r = admin.get("/")
    assert r.headers.get("X-XSS-Protection") == "0", r.headers.get("X-XSS-Protection")


def test_hostile_origin_gets_no_cors_grant(admin):
    r = admin.get("/health", headers={"Origin": "https://evil.example"})
    assert "access-control-allow-origin" not in {k.lower() for k in r.headers}, dict(r.headers)


# --------------------------------------------------------------------------------------------------
# Client-side output encoding (shipped app.js source)
# --------------------------------------------------------------------------------------------------
def test_audit_log_serialised_details_are_escaped():
    # The audit-log <pre> must escape the serialised details blob (low-priv name -> admin session).
    assert "escapeHtml(JSON.stringify(log.details" in APP_JS
    assert "<pre class=\"text-xs mt-sm\">${JSON.stringify(log.details" not in APP_JS


def test_dashboard_feed_username_and_action_escaped():
    assert "${escapeHtml(event.username || 'System')}" in APP_JS
    assert "${escapeHtml(event.description || event.action)}" in APP_JS
    # The whole feed template is uniformly escaped — the details branch too (no raw ${event.details}).
    assert "${escapeHtml(event.details)}" in APP_JS
    assert '<div class="event-details">${event.details}</div>' not in APP_JS


def test_chip_colour_is_strict_hex_validated():
    # chipColorValue must not hand a raw '#'-prefixed value straight into the style attribute.
    assert "CHIP_HEX_RE" in APP_JS
    assert "if (color.charAt(0) === '#') return color;" not in APP_JS


def test_login_flow_does_not_log_bearer_token():
    assert "console.log('Auth token:'" not in APP_JS
    assert "Auth token:" not in APP_JS
