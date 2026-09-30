"""Live: the hold on the encryption-key envelope after an administrator changed an account's sign-in details.

After an administrator sets a person's password, the person's sessions get GET /ecc/keys/private refused with
`zk-envelope-hold` until they enter a code sent by email; the code releases that session only. The code goes to
the address the account had before the change: after an email change, the address before it, and after the
address was moved through the account's own settings, still the one it had. Without mail the request for a code says so, and the host
operator releases the account with `dockvault.py accounts`, which tells the person. The hold reads the change's
record, and ends 14 days after the change. A value above 14 stops the server starting.
test_zk_envelope_hold.py pins the same offline.
"""
import re
import subprocess

import pytest

from conftest import ApiClient, ensure_ecc_keypair, unique
from _account_change_helpers import API, MAILPIT_URL, in_api_container, mail_sink, mail_to, psql

pytestmark = pytest.mark.integration

needs_mailpit = pytest.mark.skipif(not MAILPIT_URL, reason="no mail sink (VAULT_MAILPIT_URL) for this run")
NEW_PASSWORD = "Admin-Chosen-Pass-8x!"


def _signed_in(username, password):
    c = ApiClient()
    c.login(username, password)
    return c


@pytest.fixture
def person(admin):
    """An account with an encryption key, whose password an administrator then sets (the change that holds
    its envelope). Yields (account, a session signed in with the new password)."""
    account = admin.create_user(username=unique("hold"))
    ensure_ecc_keypair(_signed_in(account["_username"], account["_password"]))
    try:
        yield account
    finally:
        admin.delete_user(account["id"])


def _set_password(admin, account):
    r = admin.patch(f"/users/{account['id']}", json={"password": NEW_PASSWORD})
    assert r.status_code == 200, r.text
    return _signed_in(account["_username"], NEW_PASSWORD)


def _held(client):
    r = client.get("/ecc/keys/private")
    if r.status_code == 200:
        return False
    assert r.status_code == 403 and r.json()["reason"] == "zk-envelope-hold", r.text
    assert isinstance(r.json()["detail"], str)
    return True


def test_an_account_no_administrator_changed_is_not_held(admin, person):
    client = _signed_in(person["_username"], person["_password"])
    assert _held(client) is False
    assert client.post("/ecc/keys/private/hold/code").json() == {"held": False}


@needs_mailpit
def test_the_emailed_code_releases_the_session_that_entered_it(admin, person):
    with mail_sink(admin):
        client = _set_password(admin, person)
        assert _held(client) is True
        sent = client.post("/ecc/keys/private/hold/code")
        assert sent.status_code == 200, sent.text
        body = sent.json()
        address = f"{person['_username']}@example.com"
        assert body["held"] is True and body["sent_to"] == f"{address[0]}***@example.com", body
        message = mail_to(address, subject_contains="Your code to open your encryption key")
        assert message, "no code reached the account's address"
        code = re.search(r"\b[0-9a-f]{12}\b", message["text"]).group(0)

        wrong = client.post("/ecc/keys/private/hold/release", json={"code": "0" * 12})
        assert wrong.status_code == 403 and wrong.json()["reason"] == "zk-envelope-hold-code-failed", wrong.text
        assert _held(client) is True
        ok = client.post("/ecc/keys/private/hold/release", json={"code": code.upper()})
        assert ok.status_code == 200 and ok.json() == {"released": True}, ok.text
        assert _held(client) is False
        assert client.get("/ecc/keys/private").json()["has_keypair"] is True

        # Another session of the same account is still held: the code released the one that entered it.
        assert _held(_signed_in(person["_username"], NEW_PASSWORD)) is True
        actions = psql("SELECT string_agg(action, ',' ORDER BY timestamp) FROM audit_logs "
                       f"WHERE resource_id = '{person['id']}' AND action LIKE 'zk_envelope_%'")
        assert actions == "zk_envelope_release_code_sent,zk_envelope_release_failed,zk_envelope_released", actions


@needs_mailpit
def test_after_an_email_change_the_code_goes_to_the_address_before(admin, person):
    with mail_sink(admin):
        old = f"{person['_username']}@example.com"
        new = f"{unique('moved')}@example.com"
        assert admin.patch(f"/users/{person['id']}", json={"email": new}).status_code == 200
        client = _signed_in(person["_username"], person["_password"])
        assert _held(client) is True
        body = client.post("/ecc/keys/private/hold/code").json()
        assert body["sent_to"] == f"{old[0]}***@example.com", body
        assert mail_to(old, subject_contains="Your code to open your encryption key"), "not sent to the address before"
        assert mail_to(new, subject_contains="Your code to open your encryption key", timeout=3) is None


@needs_mailpit
def test_the_code_does_not_follow_an_address_moved_through_the_accounts_own_settings(admin, person):
    """An administrator sets the password, signs in with it and moves the account's address through its own
    settings: a self-service change, not recorded as an administrator's. The code still goes to the address
    the account had when the password was set, so it reaches the person and the envelope stays held."""
    with mail_sink(admin):
        person_address = f"{person['_username']}@example.com"
        taker_address = f"{unique('taker')}@example.com"
        taker = _set_password(admin, person)
        assert _held(taker) is True
        moved = taker.patch("/users/me", json={"email": taker_address, "current_password": NEW_PASSWORD})
        if moved.status_code == 400 and "verification" in moved.text:
            r = taker.post("/users/me/request-email-change",
                           json={"new_email": taker_address, "current_password": NEW_PASSWORD})
            assert r.status_code in (200, 202), r.text
            m = mail_to(taker_address)
            code = re.search(r"\b\d{6}\b|\b[0-9a-f]{6,12}\b", m["text"]).group(0)
            moved = taker.post("/users/me/confirm-email-change", json={"code": code})
        assert moved.status_code == 200, moved.text
        assert admin.get(f"/users/{person['id']}").json()["email"] == taker_address

        sent = taker.post("/ecc/keys/private/hold/code")
        assert sent.status_code == 200, sent.text
        assert sent.json()["sent_to"] == f"{person_address[0]}***@example.com", sent.text
        assert mail_to(person_address, subject_contains="Your code to open your encryption key"),             "the code did not reach the person's address"
        assert mail_to(taker_address, subject_contains="Your code to open your encryption key", timeout=3) is None
        assert _held(taker) is True


def test_without_mail_the_host_operator_releases_the_account(admin, person):
    client = _set_password(admin, person)
    assert _held(client) is True
    # This stack has no sending profile unless a test adds one: no code can be sent.
    refused = client.post("/ecc/keys/private/hold/code")
    if refused.status_code == 200:
        pytest.skip("this stack can send mail; the case needs one that cannot")
    assert refused.status_code == 409 and refused.json()["reason"] == "zk-envelope-hold-no-mail", refused.text

    out = in_api_container(
        "from app.core.host_operator import run\n"
        f"run(['release-key-hold', '--username', {person['_username']!r}, "
        f"'--confirm-username', {person['_username']!r}])\n").stdout
    assert '"released": 1' in out and '"ok": true' in out, out[-400:]
    assert _held(client) is False
    titles = [n["title"] for n in client.get("/notifications").json()["notifications"]]
    assert "Your encryption key can be opened again" in titles
    assert psql("SELECT details->>'by' FROM audit_logs WHERE action = 'zk_envelope_released' "
                f"AND resource_id = '{person['id']}'") == "host operator"
    # A mistyped confirmation changes nothing.
    again = in_api_container(
        "from app.core.host_operator import run\n"
        f"run(['release-key-hold', '--username', {person['_username']!r}, '--confirm-username', 'nobody'])\n",
        check=False).stdout
    assert '"ok": false' in again


@pytest.mark.parametrize("days_ago,held", [(13, True), (15, False)])
def test_the_hold_ends_14_days_after_the_change(admin, person, days_ago, held):
    client = _set_password(admin, person)
    psql(f"UPDATE credential_changes SET applied_at = (now() AT TIME ZONE 'utc') - interval '{days_ago} days' "
         f"WHERE target_user_id = '{person['id']}'")
    assert _held(client) is held


def test_the_setting_cannot_be_changed_from_the_settings_page(admin):
    r = admin.put("/settings", json={"zk_envelope_hold_days": 0})
    assert r.status_code == 400 and "managed by the deployment environment" in r.text


def test_a_hold_longer_than_14_days_stops_the_server_starting():
    r = subprocess.run(["docker", "exec", "-e", "ZK_ENVELOPE_HOLD_DAYS=15", API, "python", "-c",
                        "from app.core.config import bootstrap_entrypoint\nbootstrap_entrypoint('hold-check')\n"
                        "print('started')\n"],
                       capture_output=True, text=True, timeout=120)
    assert r.returncode != 0 and "started" not in r.stdout, (r.returncode, r.stdout[-300:], r.stderr[-300:])
    assert "settings-invalid" in r.stderr, r.stderr[-400:]
