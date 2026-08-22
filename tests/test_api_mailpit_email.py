"""End-to-end email delivery through a local Mailpit sink.

Runs only when the round exposes Mailpit (``VAULT_MAILPIT_URL`` set — see the ``WITH_MAILPIT`` round
harness); skips cleanly otherwise, so a normal round and CI are unaffected. These prove the one thing
the enumeration-safe stand-ins in test_api_email_change_verification.py cannot: that a real message
actually leaves the vault and lands in a mailbox, and that the one-time email-change code read back
from that mailbox completes the change.

The vault reaches Mailpit in-network at ``VAULT_MAILPIT_SMTP_HOST``:``VAULT_MAILPIT_SMTP_PORT`` (no
auth, plaintext — the send path skips login when no username is set and only STARTTLSes if offered);
the test reaches Mailpit's REST API from the host at ``VAULT_MAILPIT_URL``.
"""
import os
import re
import time

import pytest
import requests

from conftest import ApiClient, unique

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        not (MAILPIT_URL and MAILPIT_SMTP_HOST),
        reason="no Mailpit sink (bring the round up with WITH_MAILPIT=1 / MAILPIT_HTTP_PORT)"),
]


def _mp_clear():
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)


def _mp_messages():
    return requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", [])


def _mp_text(message_id):
    return requests.get(f"{MAILPIT_URL}/api/v1/message/{message_id}", timeout=10).json().get("Text", "")


def _wait_for_message(to_addr, subject_contains=None, timeout=20):
    """Poll Mailpit until a message addressed to `to_addr` (optionally matching a subject) appears."""
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in _mp_messages():
            recipients = [a.get("Address", "").lower() for a in m.get("To", [])]
            if to_addr.lower() in recipients and (
                    subject_contains is None or subject_contains in (m.get("Subject") or "")):
                return m
        time.sleep(0.5)
    return None


@pytest.fixture
def smtp_to_mailpit(admin):
    """Point the vault's SMTP at the round's Mailpit (no auth, plaintext); restore settings after."""
    keys = ("smtp_server", "smtp_port", "smtp_username", "from_email", "from_name",
            "email_change_requires_verification")
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in keys}
    r = admin.put("/settings", json={
        "smtp_server": MAILPIT_SMTP_HOST,
        "smtp_port": int(MAILPIT_SMTP_PORT),
        "smtp_username": "",
        "from_email": "vault@example.com",
        "from_name": "DockVault Test",
    })
    assert r.status_code == 200, r.text
    yield
    admin.put("/settings", json=snap)


def test_configured_smtp_reports_configured(admin, smtp_to_mailpit):
    # The pre-check the test-email and OTP flows gate on: once the server + From are stored, the
    # deployment counts as email-configured. (This is exactly what "must Save before Send Test" fixes:
    # test-email reads STORED settings, not the unsaved form.)
    assert admin.get("/settings").json()["smtp_server"] == MAILPIT_SMTP_HOST


def test_test_email_delivers_to_mailpit(admin, smtp_to_mailpit):
    _mp_clear()
    to = (admin.get("/users/me").json().get("email") or "vault@example.com")
    r = admin.post("/settings/test-email")
    assert r.status_code == 200, r.text
    assert _wait_for_message(to, subject_contains="test email") is not None, \
        "the test email never reached Mailpit"


def test_email_change_otp_delivers_and_confirms(admin, smtp_to_mailpit):
    # Verification requires SMTP configured first (smtp_to_mailpit did that); now enable the policy.
    assert admin.put("/settings", json={"email_change_requires_verification": True}).status_code == 200
    u = admin.create_user(role="user")
    new_email = unique("moved") + "@example.com"
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        _mp_clear()
        r = c.post("/users/me/request-email-change",
                   json={"new_email": new_email, "current_password": u["_password"]})
        assert r.status_code == 202, r.text
        msg = _wait_for_message(new_email, subject_contains="Confirm your new email")
        assert msg is not None, "the OTP email never reached Mailpit"
        codes = re.findall(r"\b[0-9a-f]{12}\b", _mp_text(msg["ID"]))
        assert codes, "no 12-hex verification code found in the email body"
        r2 = c.post("/users/me/confirm-email-change", json={"code": codes[0]})
        assert r2.status_code == 200, r2.text
        assert c.get("/users/me").json()["email"] == new_email
    finally:
        admin.delete_user(u["id"])
