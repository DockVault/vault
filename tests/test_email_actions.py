"""Email Studio — the automated-email action catalog (association + central delivery).

Actions are SEEDED and permanent (no create/delete): a `system` action always sends (with a built-in
default body until an admin binds a custom template) and its bound template is non-removable; an
`optional` action is opt-in via `enabled`. Delivery + dynamic-token injection run through one central
helper, exercised here via the per-action test-send (Mailpit).
"""
import os
import re
import time

import pytest
import requests

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")
_mailpit = pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST),
                              reason="no Mailpit sink (bring the round up WITH_MAILPIT)")

_SYSTEM_KEYS = {"email_change", "password_reset", "account_invite"}
_OPTIONAL_SAMPLE = "share_created"


def _actions(admin):
    return {a["key"]: a for a in admin.get("/email/actions").json()["actions"]}


def _new_template(admin, **over):
    body = {"name": unique("t"), "subject": "Hi {{user.username}}",
            "body_html": "<p>Hi {{user.username}}</p>"}
    body.update(over)
    return admin.post("/email/templates", json=body).json()


@pytest.fixture(autouse=True)
def _clean(admin):
    def reset():
        for a in admin.get("/email/actions").json().get("actions", []):
            admin.put(f"/email/actions/{a['key']}",
                      json={"template_id": None, "enabled": (a["category"] == "system")})
        for t in admin.get("/email/templates").json().get("templates", []):
            admin.delete(f"/email/templates/{t['id']}")
        # also drop any (Mailpit) profile a send test created, so a leftover default profile doesn't
        # make _smtp_configured true for the email-change tests that expect no SMTP.
        for p in admin.get("/email/profiles").json().get("profiles", []):
            admin.delete(f"/email/profiles/{p['id']}")
    reset()
    yield
    reset()


# -- seed / catalog ----------------------------------------------------------------------------

def test_seed_catalog_is_present_and_shaped(admin):
    acts = _actions(admin)
    assert _SYSTEM_KEYS <= set(acts), "system actions must be seeded"
    assert _OPTIONAL_SAMPLE in acts
    for k in _SYSTEM_KEYS:
        a = acts[k]
        assert a["category"] == "system"
        assert a["enabled"] is True                 # system actions are always on
    opt = acts[_OPTIONAL_SAMPLE]
    assert opt["category"] == "optional" and opt["enabled"] is False   # opt-in, off by default
    # seeded without a DB template (built-in default body) so the user template grid stays empty
    assert admin.get("/email/templates").json()["templates"] == []


def test_seed_created_exactly_the_catalog_no_duplicates(admin):
    # The seed runs on every boot (and this round has restarted many times). A non-idempotent seed
    # would accumulate duplicate rows; assert the count equals the catalog's distinct keys.
    from app.core.email_actions import ACTION_CATALOG
    rows = admin.get("/email/actions").json()["actions"]
    expected = {a["key"] for a in ACTION_CATALOG}
    assert {r["key"] for r in rows} == expected
    assert len(rows) == len(expected)                # no duplicate rows accreted across restarts


# -- association -------------------------------------------------------------------------------

def test_bind_template_and_toggle_optional_action(admin):
    t = _new_template(admin)
    try:
        r = admin.put(f"/email/actions/{_OPTIONAL_SAMPLE}",
                      json={"template_id": t["id"], "enabled": True})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["template_id"] == t["id"] and body["enabled"] is True
        assert body["template"]["name"] == t["name"]
        # turn it back off
        assert admin.put(f"/email/actions/{_OPTIONAL_SAMPLE}", json={"enabled": False}).json()["enabled"] is False
    finally:
        admin.put(f"/email/actions/{_OPTIONAL_SAMPLE}", json={"template_id": None, "enabled": False})
        admin.delete(f"/email/templates/{t['id']}")


def test_system_action_binds_and_resets_but_stays_enabled(admin):
    t = _new_template(admin)
    # bind a custom template to a system action
    assert admin.put("/email/actions/email_change", json={"template_id": t["id"]}).json()["template_id"] == t["id"]
    # a system action can't be disabled
    assert admin.put("/email/actions/email_change", json={"enabled": False}).json()["enabled"] is True
    # and can be RESET to its built-in default (unbind); it still sends
    assert admin.put("/email/actions/email_change", json={"template_id": None}).json()["template_id"] is None


def test_unknown_action_is_404(admin):
    assert admin.put("/email/actions/does_not_exist", json={"enabled": True}).status_code == 404


# -- non-removable templates (permission via the action) ---------------------------------------

def test_template_bound_to_system_action_cannot_be_deleted(admin):
    t = _new_template(admin)
    admin.put("/email/actions/password_reset", json={"template_id": t["id"]})
    # while bound to a SYSTEM action it is protected
    r = admin.delete(f"/email/templates/{t['id']}")
    assert r.status_code == 400 and "system" in r.json()["detail"].lower()
    # GET shows the binding so the UI can badge it + hide delete
    got = admin.get(f"/email/templates/{t['id']}").json()
    assert got["bound_action"]["key"] == "password_reset" and got["bound_action"]["category"] == "system"
    # reset the system action to its built-in default, then the template deletes
    admin.put("/email/actions/password_reset", json={"template_id": None})
    assert admin.delete(f"/email/templates/{t['id']}").status_code == 204


def test_template_bound_to_optional_action_blocks_delete_until_unbound(admin):
    t = _new_template(admin)
    admin.put(f"/email/actions/{_OPTIONAL_SAMPLE}", json={"template_id": t["id"], "enabled": True})
    r = admin.delete(f"/email/templates/{t['id']}")
    assert r.status_code == 400 and "automated email" in r.json()["detail"].lower()
    # unbind, then it deletes
    admin.put(f"/email/actions/{_OPTIONAL_SAMPLE}", json={"template_id": None, "enabled": False})
    assert admin.delete(f"/email/templates/{t['id']}").status_code == 204


# -- authz -------------------------------------------------------------------------------------

def test_actions_require_interactive_admin(admin):
    tc = admin.post("/auth/temp-credentials", json={"note": unique("a")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    assert ct.get("/email/actions").status_code == 403
    assert ct.put("/email/actions/email_change", json={"enabled": True}).status_code == 403
    assert ct.post("/email/actions/email_change/test", json={"to_addr": "x@example.com"}).status_code == 403


# -- central delivery (the send helper, via the per-action test send) --------------------------

@_mailpit
def test_action_test_send_delivers_rendered_default(admin):
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
    # a default profile pointed at Mailpit so system mail has an outbound path
    profs = admin.get("/email/profiles").json()["profiles"]
    for p in profs:
        admin.delete(f"/email/profiles/{p['id']}")
    admin.post("/email/profiles", json={"name": "MP", "smtp_server": MAILPIT_SMTP_HOST,
                                        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
                                        "from_email": "sender@example.com", "is_default": True})
    to = "action-rcpt@example.com"
    r = admin.post("/email/actions/email_change/test", json={"to_addr": to})
    assert r.status_code == 200, r.text
    # Mailpit received it, rendered from the built-in default (the sample code appears)
    deadline, msg = time.time() + 15, None
    while time.time() < deadline and msg is None:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if to in [a.get("Address", "").lower() for a in m.get("To", [])]:
                msg = m
                break
        if msg is None:
            time.sleep(0.5)
    assert msg is not None, "the action test email never reached Mailpit"
    body = requests.get(f"{MAILPIT_URL}/api/v1/message/{msg['ID']}", timeout=10).json()
    assert "482913" in (body.get("HTML", "") + body.get("Text", ""))   # the sample {{action.code}}


@_mailpit
def test_disabled_optional_action_test_send_force_delivers(admin):
    # An admin can preview a DISABLED optional action via the test-send (force): it must actually
    # deliver even though the action is off. (The normal-flow skip — send_action_email with
    # force=False returning False — has no wired trigger to exercise over HTTP; it's covered by the
    # helper's gate logic + the security review.)
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)
    for p in admin.get("/email/profiles").json()["profiles"]:
        admin.delete(f"/email/profiles/{p['id']}")
    admin.post("/email/profiles", json={"name": "MP", "smtp_server": MAILPIT_SMTP_HOST,
                                        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
                                        "from_email": "sender@example.com", "is_default": True})
    admin.put(f"/email/actions/{_OPTIONAL_SAMPLE}", json={"template_id": None, "enabled": False})
    to = "forced-rcpt@example.com"
    r = admin.post(f"/email/actions/{_OPTIONAL_SAMPLE}/test", json={"to_addr": to})
    assert r.status_code == 200, r.text
    deadline, seen = time.time() + 15, False
    while time.time() < deadline and not seen:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if to in [a.get("Address", "").lower() for a in m.get("To", [])]:
                seen = True
                break
        if not seen:
            time.sleep(0.5)
    assert seen, "the forced test send of a disabled optional action was not delivered"
