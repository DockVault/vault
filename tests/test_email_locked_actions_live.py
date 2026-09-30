"""Live: the code that releases an encryption key cannot be routed through an administrator's own template.

An administrator binds the release-code email to a template of their own, sent through a sending profile of
their own that carries the code in a link. The email a held session asks for still goes out with the built-in
text through the deployment's default sending profile, and Email Studio refuses the binding in the first place.
test_email_locked_actions.py pins the same offline.
"""
import re
import time

import pytest
import requests

from conftest import ApiClient, ensure_ecc_keypair, unique
from _account_change_helpers import MAILPIT_SMTP_HOST, MAILPIT_SMTP_PORT, MAILPIT_URL, mail_sink, psql

pytestmark = [pytest.mark.integration,
              pytest.mark.skipif(not MAILPIT_URL, reason="no mail sink (VAULT_MAILPIT_URL) for this run")]

NEW_PASSWORD = "Admin-Chosen-Pass-8x!"
ACTION = "encryption_key_release_code"


def _signed_in(username, password):
    c = ApiClient()
    c.login(username, password)
    return c


def _messages_to(address):
    return requests.get(f"{MAILPIT_URL}/api/v1/search", params={"query": f"to:{address}"},
                        timeout=10).json().get("messages", [])


def test_a_template_and_profile_bound_to_the_release_code_change_neither_sender_nor_body(admin):
    person = admin.create_user(username=unique("hold"))
    ensure_ecc_keypair(_signed_in(person["_username"], person["_password"]))
    address = f"{person['_username']}@example.com"
    bound_before = psql(f"SELECT coalesce(template_id::text, '') FROM email_actions WHERE key = '{ACTION}'")
    profile = template = None
    try:
        with mail_sink(admin) as real:
            assert real
            r = admin.post("/email/profiles", json={
                "name": unique("relay"), "smtp_server": MAILPIT_SMTP_HOST, "smtp_port": MAILPIT_SMTP_PORT,
                "smtp_username": "", "from_email": "relay-of-the-admin@example.com", "is_default": False})
            assert r.status_code in (200, 201), r.text
            profile = r.json()["id"]
            r = admin.post("/email/templates", json={
                "name": unique("tpl"), "profile_id": profile, "subject": "Your code",
                "body_html": '<p>Code {{action.code}}</p><p><a href="https://relay.example/c?k={{action.code}}">'
                             'Release your key</a></p>'})
            assert r.status_code in (200, 201), r.text
            template = r.json()["id"]

            # Email Studio refuses the binding; bound anyway (a direct database write, or a row from before),
            # it is ignored.
            refused = admin.put(f"/email/actions/{ACTION}", json={"template_id": template})
            psql(f"UPDATE email_actions SET template_id = '{template}' WHERE key = '{ACTION}'")
            listed = {a["key"]: a for a in admin.get("/email/actions").json()["actions"]}[ACTION]

            r = admin.patch(f"/users/{person['id']}", json={"password": NEW_PASSWORD})
            assert r.status_code == 200, r.text
            taker = _signed_in(person["_username"], NEW_PASSWORD)
            sent = taker.post("/ecc/keys/private/hold/code")
            assert sent.status_code == 200, sent.text

            found = []
            for _ in range(40):
                # Both the administrator's subject and the built-in one start so.
                found = [m for m in _messages_to(address) if (m.get("Subject") or "").startswith("Your code")]
                if found:
                    break
                time.sleep(0.5)
            assert found, "no release code reached the person"
            full = requests.get(f"{MAILPIT_URL}/api/v1/message/{found[0]['ID']}", timeout=10).json()
            sender = (full.get("From") or {}).get("Address", "")
            html = full.get("HTML") or ""
            assert sender == "vault-tests@example.com", f"sent from {sender}"
            assert found[0]["Subject"].startswith("Your code to open your encryption key"), found[0]["Subject"]
            assert "relay.example" not in html and re.search(r"\b[0-9a-f]{12}\b", full.get("Text") or "")

            assert refused.status_code == 400, refused.text
            assert listed["locked"] is True
    finally:
        psql(f"UPDATE email_actions SET template_id = "
             f"{repr(bound_before) if bound_before else 'NULL'} WHERE key = '{ACTION}'")
        if template:
            admin.delete(f"/email/templates/{template}")
        if profile:
            admin.delete(f"/email/profiles/{profile}")
        admin.delete_user(person["id"])
