"""Email Studio — sending profiles CRUD, test-send, and the system-mail repoint.

Admin-only. The password is write-only (never returned; an omitted value on update keeps it), a
single default profile is enforced, and the vault's own system mail (email-change verification) now
sends through the default profile — falling back to the legacy global SMTP config until one exists.

The Mailpit tests run only when the round exposes a Mailpit sink (WITH_MAILPIT); they skip cleanly
otherwise.
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


# -- helpers -----------------------------------------------------------------------------------

def _delete_all_profiles(admin):
    for p in admin.get("/email/profiles").json().get("profiles", []):
        admin.delete(f"/email/profiles/{p['id']}")


@pytest.fixture
def clean_profiles(admin):
    _delete_all_profiles(admin)
    yield
    _delete_all_profiles(admin)


def _valid_profile(**over):
    body = {"name": unique("prof"), "smtp_server": "smtp.example.com", "smtp_port": 587,
            "from_email": "noreply@example.com", "from_name": "Vault"}
    body.update(over)
    return body


def _mp_clear():
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)


def _wait_for_message(to_addr, subject_contains=None, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            recipients = [a.get("Address", "").lower() for a in m.get("To", [])]
            if to_addr.lower() in recipients and (
                    subject_contains is None or subject_contains in (m.get("Subject") or "")):
                return m
        time.sleep(0.5)
    return None


def _mp_text(mid):
    return requests.get(f"{MAILPIT_URL}/api/v1/message/{mid}", timeout=10).json().get("Text", "")


# -- CRUD --------------------------------------------------------------------------------------

def test_profile_crud_lifecycle(admin, clean_profiles):
    r = admin.post("/email/profiles", json=_valid_profile(name="Primary"))
    assert r.status_code == 201, r.text
    p = r.json()
    assert p["is_default"] is True                      # first profile is the default
    assert "smtp_password" not in p                     # password never serialized

    assert any(x["id"] == p["id"] for x in admin.get("/email/profiles").json()["profiles"])

    r2 = admin.put(f"/email/profiles/{p['id']}", json=_valid_profile(name="Renamed"))
    assert r2.status_code == 200, r2.text
    assert r2.json()["name"] == "Renamed"

    assert admin.delete(f"/email/profiles/{p['id']}").status_code == 204
    assert all(x["id"] != p["id"] for x in admin.get("/email/profiles").json()["profiles"])


def test_password_is_write_only(admin, clean_profiles):
    secret = "Sup3r-Secret-SMTP-Pw"
    r = admin.post("/email/profiles", json=_valid_profile(smtp_password=secret))
    assert r.status_code == 201, r.text
    p = r.json()
    assert secret not in r.text                          # not echoed on create
    assert p["has_password"] is True

    listing = admin.get("/email/profiles")
    assert secret not in listing.text                    # not echoed on list
    assert next(x for x in listing.json()["profiles"] if x["id"] == p["id"])["has_password"] is True

    # An update that omits the password keeps the stored one.
    r2 = admin.put(f"/email/profiles/{p['id']}", json=_valid_profile(name="Kept"))
    assert r2.status_code == 200 and r2.json()["has_password"] is True
    assert secret not in r2.text


def test_test_send_wont_pair_stored_password_with_a_new_host(admin, clean_profiles):
    """The write-only SMTP password must not be reusable against a caller-changed connection target:
    that would let an admin exfiltrate the stored credential to an attacker-controlled host."""
    p = admin.post("/email/profiles", json=_valid_profile(
        smtp_server="smtp.example.com", smtp_port=587, smtp_username="u@example.com",
        smtp_password="Stored-SMTP-Pw-99")).json()
    # Change the host, supply NO password -> refused before any connection is attempted.
    r = admin.post("/email/profiles/test", json={
        "profile_id": p["id"], "smtp_server": "attacker.example", "to_addr": "x@example.com"})
    assert r.status_code == 400, r.text
    assert "re-enter" in (r.json().get("detail") or "").lower()
    # Supplying a FRESH password passes the guard (then fails later as an ordinary transport error,
    # never the re-enter guard) — so a legitimate "test against a different server" still works.
    r2 = admin.post("/email/profiles/test", json={
        "profile_id": p["id"], "smtp_server": "attacker.invalid", "smtp_password": "fresh-pw",
        "to_addr": "x@example.com"})
    assert "re-enter" not in (r2.json().get("detail") or "").lower()


def test_smtp_password_is_encrypted_at_rest(admin, clean_profiles):
    """The stored SMTP password must be encrypted in the database, not plaintext."""
    import os
    import subprocess
    secret = "Encrypt-Me-At-Rest-77"
    p = admin.post("/email/profiles", json=_valid_profile(smtp_password=secret)).json()
    db = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    stored = subprocess.run(
        ["docker", "exec", db, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
         "SELECT smtp_password FROM email_profiles WHERE id = '%s'" % p["id"]],
        check=True, capture_output=True, text=True, timeout=20).stdout.strip()
    assert stored, "expected a stored password value"
    assert secret not in stored, "the SMTP password must NOT be stored in plaintext"
    assert stored.startswith("gAAAAA"), "the stored password should be a Fernet token (encrypted)"


def test_allow_insecure_tls_round_trips(admin, clean_profiles):
    """The per-profile insecure-TLS opt-out persists and defaults to secure (False)."""
    on = admin.post("/email/profiles", json=_valid_profile(name="Insecure", smtp_allow_insecure_tls=True)).json()
    assert on["smtp_allow_insecure_tls"] is True
    off = admin.post("/email/profiles", json=_valid_profile(name="Secure")).json()
    assert off["smtp_allow_insecure_tls"] is False, "verification must be ON by default"
    # An update can toggle it back off.
    r = admin.put("/email/profiles/%s" % on["id"],
                  json=_valid_profile(name="Insecure", smtp_allow_insecure_tls=False))
    assert r.status_code == 200 and r.json()["smtp_allow_insecure_tls"] is False


def test_single_default_is_enforced(admin, clean_profiles):
    a = admin.post("/email/profiles", json=_valid_profile(name="A")).json()
    b = admin.post("/email/profiles", json=_valid_profile(name="B", is_default=True)).json()
    profiles = {x["id"]: x for x in admin.get("/email/profiles").json()["profiles"]}
    assert profiles[b["id"]]["is_default"] is True
    assert profiles[a["id"]]["is_default"] is False
    assert sum(1 for x in profiles.values() if x["is_default"]) == 1

    # Promoting A demotes B.
    admin.put(f"/email/profiles/{a['id']}", json=_valid_profile(name="A", is_default=True))
    profiles = {x["id"]: x for x in admin.get("/email/profiles").json()["profiles"]}
    assert profiles[a["id"]]["is_default"] is True and profiles[b["id"]]["is_default"] is False
    assert sum(1 for x in profiles.values() if x["is_default"]) == 1


def test_non_admin_is_rejected(admin, clean_profiles):
    p = admin.post("/email/profiles", json=_valid_profile()).json()
    u = admin.create_user(role="user")
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        assert c.get("/email/profiles").status_code == 403
        assert c.post("/email/profiles", json=_valid_profile()).status_code == 403
        assert c.put(f"/email/profiles/{p['id']}", json=_valid_profile()).status_code == 403
        assert c.delete(f"/email/profiles/{p['id']}").status_code == 403
        assert c.post("/email/profiles/test", json={"profile_id": p["id"]}).status_code == 403
        assert c.get("/email/dynamic-actions").status_code == 403
    finally:
        admin.delete_user(u["id"])


def test_temp_credential_admin_is_rejected(admin, clean_profiles):
    # The router's distinctive gate: an admin acting through a TEMPORARY credential (not an
    # interactive session) must not manage sending identities.
    p = admin.post("/email/profiles", json=_valid_profile()).json()
    tc = admin.post("/auth/temp-credentials", json={"note": unique("em")}).json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    assert c.get("/email/profiles").status_code == 403
    assert c.post("/email/profiles", json=_valid_profile()).status_code == 403
    assert c.put(f"/email/profiles/{p['id']}", json=_valid_profile()).status_code == 403
    assert c.delete(f"/email/profiles/{p['id']}").status_code == 403
    assert c.post("/email/profiles/test", json={"profile_id": p["id"]}).status_code == 403


def test_has_password_false_without_password(admin, clean_profiles):
    p = admin.post("/email/profiles", json=_valid_profile()).json()   # no smtp_password
    assert p["has_password"] is False
    listed = next(x for x in admin.get("/email/profiles").json()["profiles"] if x["id"] == p["id"])
    assert listed["has_password"] is False


def test_deleting_default_promotes_oldest_remaining(admin, clean_profiles):
    a = admin.post("/email/profiles", json=_valid_profile(name="A")).json()   # first -> default
    b = admin.post("/email/profiles", json=_valid_profile(name="B")).json()   # non-default
    assert a["is_default"] is True and b["is_default"] is False
    assert admin.delete(f"/email/profiles/{a['id']}").status_code == 204
    profiles = admin.get("/email/profiles").json()["profiles"]
    assert [x["id"] for x in profiles] == [b["id"]]
    assert profiles[0]["is_default"] is True                         # B promoted, not stranded


def test_deleting_last_profile_leaves_none(admin, clean_profiles):
    a = admin.post("/email/profiles", json=_valid_profile()).json()
    assert admin.delete(f"/email/profiles/{a['id']}").status_code == 204
    assert admin.get("/email/profiles").json()["profiles"] == []


def test_test_send_rejects_control_chars_in_recipient(admin, clean_profiles):
    r = admin.post("/email/profiles/test", json={
        "smtp_server": "127.0.0.1", "smtp_port": 1, "from_email": "x@example.com",
        "to_addr": "a@example.com\r\nBcc: evil@example.com"})
    assert r.status_code == 400, r.text                              # rejected before any send


def test_test_send_is_rate_limited(admin, clean_profiles):
    # A FRESH admin so this consumes its own 30/60s budget and doesn't perturb the other test-sends.
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        codes = [c.post("/email/profiles/test", json={
            "smtp_server": "127.0.0.1", "smtp_port": 1,
            "from_email": "x@example.com", "to_addr": "y@example.com"}).status_code
            for _ in range(34)]                      # > the 30/60s courtesy cap
        # Pin the RAISED cap, not merely "some cap": the first 25 (well under 30) must pass, and the
        # limit must bite past 30. (25/30 leaves slack for the limiter's inclusive/exclusive edge.)
        assert 429 not in codes[:25], codes
        assert 429 in codes[30:], codes
    finally:
        admin.delete_user(fresh["id"])


@pytest.mark.parametrize("bad,expect", [
    ({"from_email": "not-an-email"}, 400),
    ({"from_name": "Ops\r\nBcc: attacker@evil.example"}, 400),
    ({"smtp_port": 0}, 422),
    ({"smtp_port": 70000}, 422),
    ({"name": ""}, 422),
    ({"smtp_server": ""}, 422),
])
def test_profile_validation_rejects_bad_input(admin, clean_profiles, bad, expect):
    assert admin.post("/email/profiles", json=_valid_profile(**bad)).status_code == expect


def test_test_send_is_clean_error_never_500_or_password(admin, clean_profiles):
    secret = "Do-Not-Echo-8823"
    # unsaved config pointing at a closed local port fails fast, not a 15s hang
    r = admin.post("/email/profiles/test", json={
        "smtp_server": "127.0.0.1", "smtp_port": 1,
        "from_email": "noreply@example.com", "smtp_password": secret, "to_addr": "x@example.com"})
    assert r.status_code != 500, r.text
    assert r.status_code in (400, 502), r.text
    assert secret not in r.text

    # no server configured -> clean 400
    r2 = admin.post("/email/profiles/test", json={"from_email": "x@example.com", "to_addr": "y@example.com"})
    assert r2.status_code == 400, r2.text


# -- Mailpit end-to-end ------------------------------------------------------------------------

@_mailpit
def test_profile_test_send_delivers_to_mailpit(admin, clean_profiles):
    _mp_clear()
    prof = admin.post("/email/profiles", json=_valid_profile(
        name="Mailpit", smtp_server=MAILPIT_SMTP_HOST, smtp_port=int(MAILPIT_SMTP_PORT),
        smtp_username="", from_email="profile-tester@example.com")).json()
    to = "recipient@example.com"
    r = admin.post("/email/profiles/test", json={"profile_id": prof["id"], "to_addr": to})
    assert r.status_code == 200, r.text
    assert _wait_for_message(to, subject_contains="test email") is not None, "test email never reached Mailpit"


@_mailpit
def test_default_profile_drives_system_mail(admin, clean_profiles):
    # Prove the repoint: with a default profile pointing at Mailpit and the legacy global SMTP
    # config CLEARED, the email-change verification (which uses _send_email) still delivers — so it
    # went through the profile, not the legacy config.
    snap = {k: admin.get("/settings").json().get(k)
            for k in ("smtp_server", "from_email", "email_change_requires_verification")}
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})   # legacy cannot send
    admin.post("/email/profiles", json=_valid_profile(
        name="System", smtp_server=MAILPIT_SMTP_HOST, smtp_port=int(MAILPIT_SMTP_PORT),
        smtp_username="", from_email="system-sender@example.com", is_default=True))
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
        assert msg is not None, "the OTP email never reached Mailpit — the default profile did not drive system mail"
        assert (msg.get("From") or {}).get("Address", "").lower() == "system-sender@example.com"
        codes = re.findall(r"\b[0-9a-f]{12}\b", _mp_text(msg["ID"]))
        assert codes, "no verification code in the email"
        assert c.post("/users/me/confirm-email-change", json={"code": codes[0]}).status_code == 200
    finally:
        admin.delete_user(u["id"])
        admin.put("/settings", json=snap)


@_mailpit
def test_only_the_default_profile_drives_system_mail(admin, clean_profiles):
    # With a default profile AND a non-default profile (distinct From), system mail must use the
    # DEFAULT one — never the non-default. Legacy is cleared so only a profile can deliver.
    snap = {k: admin.get("/settings").json().get(k)
            for k in ("smtp_server", "from_email", "email_change_requires_verification")}
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    admin.post("/email/profiles", json=_valid_profile(
        name="Default", smtp_server=MAILPIT_SMTP_HOST, smtp_port=int(MAILPIT_SMTP_PORT),
        smtp_username="", from_email="default-sender@example.com", is_default=True))
    admin.post("/email/profiles", json=_valid_profile(
        name="Other", smtp_server=MAILPIT_SMTP_HOST, smtp_port=int(MAILPIT_SMTP_PORT),
        smtp_username="", from_email="other-sender@example.com"))
    assert admin.put("/settings", json={"email_change_requires_verification": True}).status_code == 200
    u = admin.create_user(role="user")
    new_email = unique("moved") + "@example.com"
    c = admin.clone_anonymous()
    c.login(u["_username"], u["_password"])
    try:
        _mp_clear()
        assert c.post("/users/me/request-email-change",
                      json={"new_email": new_email, "current_password": u["_password"]}).status_code == 202
        msg = _wait_for_message(new_email, subject_contains="Confirm your new email")
        assert msg is not None, "OTP email never arrived"
        assert (msg.get("From") or {}).get("Address", "").lower() == "default-sender@example.com"
    finally:
        admin.delete_user(u["id"])
        admin.put("/settings", json=snap)


@_mailpit
def test_test_send_overlay_overrides_stored_from(admin, clean_profiles):
    _mp_clear()
    prof = admin.post("/email/profiles", json=_valid_profile(
        name="Ov", smtp_server=MAILPIT_SMTP_HOST, smtp_port=int(MAILPIT_SMTP_PORT),
        smtp_username="", from_email="stored@example.com")).json()
    to = "overlay-rcpt@example.com"
    r = admin.post("/email/profiles/test",
                   json={"profile_id": prof["id"], "from_email": "override@example.com", "to_addr": to})
    assert r.status_code == 200, r.text
    msg = _wait_for_message(to, subject_contains="test email")
    assert msg is not None
    assert (msg.get("From") or {}).get("Address", "").lower() == "override@example.com"  # overlay wins
