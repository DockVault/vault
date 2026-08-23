"""Email Studio — sending a template (POST /email/templates/{id}/send).

One personalized message per recipient (vault users + free-form addresses), images inlined as cid:
parts, sent through the template's profile. A stored body that is hostile (tampered directly in the
DB) is refused before send and raises a security event. Admin-only.

The Mailpit tests run only when the round exposes a Mailpit sink (WITH_MAILPIT).
"""

import os
import re
import subprocess
import time

import pytest
import requests

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

MAILPIT_URL = os.environ.get("VAULT_MAILPIT_URL")
MAILPIT_SMTP_HOST = os.environ.get("VAULT_MAILPIT_SMTP_HOST")
MAILPIT_SMTP_PORT = os.environ.get("VAULT_MAILPIT_SMTP_PORT", "1025")
DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_mailpit = pytest.mark.skipif(not (MAILPIT_URL and MAILPIT_SMTP_HOST),
                              reason="no Mailpit sink (bring the round up WITH_MAILPIT)")

PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32


# -- helpers -----------------------------------------------------------------------------------

def _mp_clear():
    requests.delete(f"{MAILPIT_URL}/api/v1/messages", timeout=10)


def _mp_wait(to_addr, timeout=20):
    deadline = time.time() + timeout
    while time.time() < deadline:
        for m in requests.get(f"{MAILPIT_URL}/api/v1/messages", timeout=10).json().get("messages", []):
            if to_addr.lower() in [a.get("Address", "").lower() for a in m.get("To", [])]:
                return requests.get(f"{MAILPIT_URL}/api/v1/message/{m['ID']}", timeout=10).json()
        time.sleep(0.5)
    return None


def _psql(sql):
    try:
        return subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
            capture_output=True, text=True, timeout=20)
    except (FileNotFoundError, subprocess.TimeoutExpired):
        return None   # no docker / slow exec -> the caller skips


@pytest.fixture
def studio(admin):
    """A mailpit-pointed profile + a template linked to it (with a token + an inline image), and a
    vault user with an email. Cleans everything up after."""
    made = {"profiles": [], "templates": [], "resources": [], "users": []}
    prof = admin.post("/email/profiles", json={
        "name": unique("p"), "smtp_server": MAILPIT_SMTP_HOST or "smtp.example.com",
        "smtp_port": int(MAILPIT_SMTP_PORT), "smtp_username": "",
        "from_email": "sender@example.com", "from_name": "Vault"}).json()
    made["profiles"].append(prof["id"])
    res = admin.post("/email/resources", files={"file": ("logo.png", PNG, "application/octet-stream")}).json()
    made["resources"].append(res["id"])
    tpl = admin.post("/email/templates", json={
        "name": unique("t"), "subject": "Hello {{user.username}}", "profile_id": prof["id"],
        "body_html": f'<p>Hi <strong>{{{{user.username}}}}</strong></p><img data-resource-id="{res["id"]}">'}).json()
    made["templates"].append(tpl["id"])
    user = admin.create_user(role="user")
    made["users"].append(user["id"])
    try:
        yield {"profile": prof, "resource": res, "template": tpl, "user": user}
    finally:
        for tid in made["templates"]:
            admin.delete(f"/email/templates/{tid}")
        for rid in made["resources"]:
            admin.delete(f"/email/resources/{rid}")
        for pid in made["profiles"]:
            admin.delete(f"/email/profiles/{pid}")
        for uid in made["users"]:
            admin.delete_user(uid)


# -- validation / errors (no Mailpit needed) ---------------------------------------------------

def test_send_requires_recipients(admin, studio):
    r = admin.post(f"/email/templates/{studio['template']['id']}/send", json={})
    assert r.status_code == 400


def test_send_unknown_template_404(admin):
    assert admin.post("/email/templates/11111111-1111-1111-1111-111111111111/send",
                      json={"addresses": ["a@b.example"]}).status_code == 404


def test_user_without_email_becomes_an_error_row(admin, studio):
    noemail = admin.create_user(role="user", email=None)   # account with no email
    try:
        r = admin.post(f"/email/templates/{studio['template']['id']}/send",
                       json={"user_ids": [noemail["id"]]})
        # no valid recipients -> 400 (the only recipient can't receive)
        assert r.status_code == 400
    finally:
        admin.delete_user(noemail["id"])


def test_invalid_free_form_address_is_error_row(admin, studio):
    r = admin.post(f"/email/templates/{studio['template']['id']}/send",
                   json={"addresses": ["not-an-email", "a@b.example\r\nBcc: x@y.example"]})
    assert r.status_code == 400   # both invalid -> no valid recipients


def test_send_with_no_profile_and_no_default_is_clean_400(admin):
    # A template with NO profile, and clear the legacy/default so nothing resolves.
    snap = {k: admin.get("/settings").json().get(k) for k in ("smtp_server", "from_email")}
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    _delete_all_profiles(admin)
    t = admin.post("/email/templates", json={"name": unique("np"), "subject": "s",
                                             "body_html": "<p>hi</p>"}).json()
    try:
        r = admin.post(f"/email/templates/{t['id']}/send", json={"addresses": ["a@b.example"]})
        assert r.status_code == 400 and "profile" in r.text.lower()
    finally:
        admin.delete(f"/email/templates/{t['id']}")
        admin.put("/settings", json=snap)


def _delete_all_profiles(admin):
    for p in admin.get("/email/profiles").json().get("profiles", []):
        admin.delete(f"/email/profiles/{p['id']}")


def test_tampered_body_is_refused_and_raises_event(admin, studio):
    # Simulate a direct-DB tamper: overwrite the stored (sanitized) body with a script, bypassing the
    # save-time sanitizer. The BEFORE-SEND check must refuse and raise a security event. Send as a
    # FRESH admin so the raised alert is attributable to a never-seen username (dedup can't fold it
    # into an earlier test's row).
    tid = studio["template"]["id"]
    res = _psql(f"update email_templates set body_html='<p>x</p><script>evil()</script>' where id='{tid}';")
    if res is None or res.returncode != 0 or "No such container" in (res.stderr or ""):
        pytest.skip("cannot reach the round DB to stage the tamper")
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        assert c.post(f"/email/templates/{tid}/send", json={"addresses": ["a@b.example"]}).status_code == 400
        alerts = admin.get("/api/security/alerts?limit=100").json()["alerts"]
        mine = [a for a in alerts if a["event_type"] == "malicious_email_content"
                and a["username"] == fresh["_username"]
                and (a.get("details") or {}).get("surface") == "email_template_send"]
        assert mine, "no attributable before-send tamper security event was raised"
    finally:
        admin.delete_user(fresh["id"])


@pytest.mark.parametrize("payload", [
    {"user_ids": ["11111111-1111-1111-1111-111111111111"] * 101},
    {"addresses": [f"a{i}@b.example" for i in range(101)]},
])
def test_too_many_recipients_is_422(admin, studio, payload):
    assert admin.post(f"/email/templates/{studio['template']['id']}/send", json=payload).status_code == 422


def test_send_is_rate_limited(admin):
    # A profile that fails to CONNECT instantly (a closed local port) so 33 rapid sends stay fast,
    # and a fresh admin so the 30/60s budget is isolated from the other send tests.
    prof = admin.post("/email/profiles", json={
        "name": unique("rl"), "smtp_server": "127.0.0.1", "smtp_port": 1,
        "from_email": "x@example.com"}).json()
    t = admin.post("/email/templates", json={
        "name": unique("rl"), "subject": "s", "profile_id": prof["id"], "body_html": "<p>hi</p>"}).json()
    fresh = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(fresh["_username"], fresh["_password"])
    try:
        codes = [c.post(f"/email/templates/{t['id']}/send", json={"addresses": ["a@b.example"]}).status_code
                 for _ in range(33)]
        assert 429 in codes, codes
    finally:
        admin.delete_user(fresh["id"])
        admin.delete(f"/email/templates/{t['id']}")
        admin.delete(f"/email/profiles/{prof['id']}")


def test_send_requires_interactive_admin(admin, studio):
    tid = studio["template"]["id"]
    u = admin.create_user(role="user")
    cu = admin.clone_anonymous()
    cu.login(u["_username"], u["_password"])
    tc = admin.post("/auth/temp-credentials", json={"note": unique("s")}).json()
    ct = ApiClient(BASE_URL)
    ct.login(tc["temp_username"], tc["credential"])
    try:
        for c in (cu, ct):
            assert c.post(f"/email/templates/{tid}/send", json={"addresses": ["a@b.example"]}).status_code == 403
    finally:
        admin.delete_user(u["id"])


# -- Mailpit end-to-end ------------------------------------------------------------------------

@_mailpit
def test_send_delivers_personalized_html_with_inline_image(admin, studio):
    _mp_clear()
    tid = studio["template"]["id"]
    user = studio["user"]
    free = "outside@example.com"
    r = admin.post(f"/email/templates/{tid}/send",
                   json={"user_ids": [user["id"]], "addresses": [free]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["sent"] == 2 and body["attempted"] == 2

    # The vault user's message: personalized subject + body, and the image as an inline part.
    user_email = user.get("email") or f"{user['_username']}@example.com"
    umsg = _mp_wait(user_email)
    assert umsg is not None, "the user's message never reached Mailpit"
    assert umsg["Subject"] == f"Hello {user['_username']}"
    assert f"Hi <strong>{user['_username']}</strong>" in umsg.get("HTML", "")
    inline = umsg.get("Inline") or []
    assert any((p.get("ContentType") or "").startswith("image/png") for p in inline), \
        "the inline image part is missing"

    # The free-form recipient's message: same image, empty username token.
    fmsg = _mp_wait(free)
    assert fmsg is not None
    assert fmsg["Subject"].strip() == "Hello"                # empty username token (transport trims the trailing space)
    assert user["_username"] not in fmsg.get("HTML", "")     # NOT personalized with the other recipient's name
    assert any((p.get("ContentType") or "").startswith("image/") for p in (fmsg.get("Inline") or []))


@_mailpit
def test_send_mixed_recipients_partitions_results(admin, studio):
    # One request mixing a valid user, a no-email user, an unknown id, a good address and a bad one.
    _mp_clear()
    tid = studio["template"]["id"]
    good_user = studio["user"]
    noemail = admin.create_user(role="user", email=None)
    good_addr, bad_addr = "ok@example.com", "not-an-email"
    try:
        r = admin.post(f"/email/templates/{tid}/send", json={
            "user_ids": [good_user["id"], noemail["id"], "11111111-1111-1111-1111-111111111111"],
            "addresses": [good_addr, bad_addr]})
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["sent"] == 2 and body["attempted"] == 2 and body["recipients"] == 2
        assert len(body["results"]) == 5
        errs = {row["error"] for row in body["results"] if not row["ok"]}
        assert errs == {"user has no email", "user not found", "invalid address"}
        oks = {row["recipient"] for row in body["results"] if row["ok"]}
        assert good_addr in oks
    finally:
        admin.delete_user(noemail["id"])


@_mailpit
def test_send_uses_default_profile_when_template_has_none(admin, studio):
    # A template with NO linked profile sends via the DEFAULT profile.
    snap = {k: admin.get("/settings").json().get(k) for k in ("smtp_server", "from_email")}
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    default = admin.post("/email/profiles", json={
        "name": unique("def"), "smtp_server": MAILPIT_SMTP_HOST, "smtp_port": int(MAILPIT_SMTP_PORT),
        "smtp_username": "", "from_email": "default-from@example.com", "is_default": True}).json()
    t = admin.post("/email/templates", json={
        "name": unique("np"), "subject": "s", "body_html": "<p>hi</p>"}).json()   # no profile_id
    to = "def-rcpt@example.com"
    try:
        _mp_clear()
        r = admin.post(f"/email/templates/{t['id']}/send", json={"addresses": [to]})
        assert r.status_code == 200 and r.json()["sent"] == 1, r.text
        msg = _mp_wait(to)
        assert msg is not None
        assert (msg.get("From") or {}).get("Address", "").lower() == "default-from@example.com"
    finally:
        admin.delete(f"/email/templates/{t['id']}")
        admin.delete(f"/email/profiles/{default['id']}")
        admin.put("/settings", json=snap)
