"""Email Studio — built-in default templates (live).

Every automated-email action ships with a polished DEFAULT template, seeded as a real row and pre-bound
at boot. Defaults are permanent (undeletable) and recoverable: the "Load From → defaults" source stays
in code, so an admin can reset an edited default to its original. This exercises those invariants against
a running instance.
"""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

_ACTION_KEYS = {"email_change", "password_reset", "account_invite", "account_welcome",
                "login_alert", "share_created", "vault_member_added", "temp_credential_issued"}


def _defaults(admin):
    return {t["default_key"]: t for t in admin.get("/email/templates").json()["templates"] if t["is_default"]}


def test_defaults_are_seeded_as_rows_one_per_action(admin):
    by_key = _defaults(admin)
    # exactly one default template per action key
    assert set(by_key) == _ACTION_KEYS
    for key, t in by_key.items():
        assert t["is_default"] is True and t["default_key"] == key
        assert (t["name"] or "").strip()


def test_default_templates_endpoint_matches_the_code_catalog(admin):
    r = admin.get("/email/default-templates")
    assert r.status_code == 200
    payload = r.json()["templates"]
    assert {p["key"] for p in payload} == _ACTION_KEYS
    for p in payload:
        assert p["name"] and p["subject"] and p["body_html"]
        assert "<script" not in p["body_html"].lower()
    # the seeded row's stored body equals the endpoint's body (what "Load From" would restore)
    seeded = _defaults(admin)
    for p in payload:
        full = admin.get(f"/email/templates/{seeded[p['key']]['id']}").json()
        assert full["body_html"] == p["body_html"]


def test_a_default_template_cannot_be_deleted(admin):
    any_default = next(iter(_defaults(admin).values()))
    r = admin.delete(f"/email/templates/{any_default['id']}")
    assert r.status_code == 400
    assert "default" in r.json()["detail"].lower()
    # still there
    assert admin.get(f"/email/templates/{any_default['id']}").status_code == 200


def test_editing_a_default_keeps_it_default_and_load_from_restores_the_original(admin):
    d = _defaults(admin)["account_welcome"]
    original = admin.get(f"/email/templates/{d['id']}").json()
    try:
        edited = admin.put(f"/email/templates/{d['id']}", json={
            "name": original["name"], "subject": "CUSTOMIZED SUBJECT",
            "body_html": "<p>customized {{user.username}}</p>"})
        assert edited.status_code == 200
        body = edited.json()
        assert body["is_default"] is True and body["default_key"] == "account_welcome"  # still the default
        assert body["subject"] == "CUSTOMIZED SUBJECT"
        # the code default is unchanged — "Load From → defaults" restores the ORIGINAL, not the edit
        dt = {p["key"]: p for p in admin.get("/email/default-templates").json()["templates"]}
        assert dt["account_welcome"]["subject"] == original["subject"]
        assert dt["account_welcome"]["body_html"] == original["body_html"]
    finally:
        admin.put(f"/email/templates/{d['id']}",
                  json={"name": original["name"], "subject": original["subject"],
                        "body_html": original["body_html"]})


def test_default_templates_endpoint_requires_interactive_admin(admin):
    tc = admin.post("/auth/temp-credentials", json={"note": unique("dt")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    assert ct.get("/email/default-templates").status_code == 403
