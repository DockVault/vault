"""The vault checks the mail server's certificate before it sends anything, on a running stack.

Live counterpart of test_settings_test_email_tls.py. A mail server runs inside the web container
(tests/_mail_tls_server.py, started with docker exec), so the vault's own sender reaches it on the
container's loopback and the test reads back how far each connection got: whether the TLS handshake
completed, and whether the server was sent a password (AUTH) or a message.

POST /settings/test-email sends through the stored settings, as system mail does when no sending
profile is the default. A certificate the vault cannot verify must end every such conversation before
AUTH; only a sending profile can turn the check off, for itself. A certificate the vault can verify is
accepted: the web process trusts only public authorities, so that case runs the route in a second
process inside the same container whose trust store also holds the test's authority.

The test sends go out as an administrator made for this module, so they never share the
five-a-minute test-send budget of the suite's administrator.
"""
import json
import os
import subprocess
import threading
from contextlib import contextmanager
from pathlib import Path
from types import SimpleNamespace

import pytest

from conftest import skip_if_container_absent, unique

pytestmark = pytest.mark.integration

API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
SERVER_SOURCE = Path(__file__).with_name("_mail_tls_server.py").read_text(encoding="utf-8")
PASSWORD = "relay-password-for-this-test"
SETTINGS = ("smtp_server", "smtp_port", "smtp_username", "from_email", "from_name",
            "smtp_allow_insecure_tls", "email_change_requires_verification")


def _first_line(proc, timeout):
    box = []
    reader = threading.Thread(target=lambda: box.append(proc.stdout.readline()), daemon=True)
    reader.start()
    reader.join(timeout)
    return box[0] if box else ""


@contextmanager
def mail_server(names, *, issuer="self", implicit_tls=False, port=0):
    """A mail server inside the web container. Yields an object with ``port`` and ``authority_pem``;
    once the block ends, its ``sessions`` say what each connection did."""
    spec = {"names": names, "issuer": issuer, "implicit_tls": implicit_tls, "port": port}
    script = SERVER_SOURCE + "\nserve_until_told(json.loads(" + repr(json.dumps(spec)) + "))\n"
    try:
        proc = subprocess.Popen(["docker", "exec", "-i", API, "python", "-c", script],
                                stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, text=True)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    first = _first_line(proc, 60)
    if not first.strip():
        proc.kill()
        out, err = proc.communicate(timeout=30)
        skip_if_container_absent(subprocess.CompletedProcess(proc.args, proc.returncode, out, err), API)
        pytest.fail(f"the mail server did not start in {API}: {(err or out)[-800:]}")
    started = json.loads(first)
    server = SimpleNamespace(port=started["port"], authority_pem=started["authority_pem"],
                             sessions=None)
    try:
        yield server
    finally:
        out, err = proc.communicate("stop\n", timeout=90)
        lines = [line for line in out.splitlines() if line.strip()]
        assert proc.returncode == 0 and lines, f"the mail server failed: {err[-800:]}"
        server.sessions = json.loads(lines[-1])


def assert_refused_before_auth(sessions):
    assert sessions, "the vault never connected to the mail server"
    for session in sessions:
        assert session["tls"] == "refused", sessions
        assert session["auth"] is None, f"the password went to a server the vault cannot verify: {sessions}"
        assert session["message"] is None, sessions


@pytest.fixture(scope="module")
def sender(admin):
    """An administrator of this module's own, signed in, and the stored settings put back afterwards."""
    before = admin.get("/settings").json()
    account = admin.create_user(role="admin")
    client = admin.clone_anonymous()
    client.login(account["_username"], account["_password"])
    try:
        yield SimpleNamespace(client=client, username=account["_username"])
    finally:
        restore = {k: before.get(k) for k in SETTINGS}
        restore["smtp_server"] = restore["smtp_server"] or ""
        restore["email_change_requires_verification"] = bool(restore["email_change_requires_verification"])
        restored = admin.put("/settings", json={**restore, "smtp_password": ""})
        admin.delete_user(account["id"])
        assert restored.status_code == 200, restored.text


def _store(client, port, **extra):
    r = client.put("/settings", json={
        "smtp_server": "127.0.0.1", "smtp_port": port, "smtp_username": "relay-user",
        "smtp_password": PASSWORD, "from_email": "vault@example.com", "from_name": "",
        "smtp_allow_insecure_tls": None, **extra})
    assert r.status_code == 200, r.text


def _profile_test(admin, port, insecure):
    return admin.post("/email/profiles/test", json={
        "smtp_server": "127.0.0.1", "smtp_port": port, "smtp_username": "relay-user",
        "smtp_password": PASSWORD, "from_email": "vault@example.com", "to_addr": "someone@example.com",
        "smtp_allow_insecure_tls": insecure})


def test_test_send_refuses_a_self_signed_certificate_over_starttls(sender):
    with mail_server(["mail.example.invalid"]) as server:
        _store(sender.client, server.port)
        r = sender.client.post("/settings/test-email")
    assert r.status_code in (400, 502), r.text
    assert PASSWORD not in r.text
    assert_refused_before_auth(server.sessions)


def test_test_send_refuses_a_self_signed_certificate_on_port_465(sender):
    with mail_server(["mail.example.invalid"], implicit_tls=True, port=465) as server:
        _store(sender.client, 465)
        r = sender.client.post("/settings/test-email")
    assert r.status_code in (400, 502), r.text
    assert_refused_before_auth(server.sessions)


def test_a_stored_opt_out_changes_nothing_while_a_profile_opt_out_applies_to_that_profile(admin, sender):
    """The stored settings have no opt-out of the check; a value stored under the profile field's name
    changes neither the test send nor system mail sent through those settings (an email change, here),
    while a sending profile's own opt-out reaches the same server, which shows the refusals are the
    certificate's."""
    profiles = admin.get("/email/profiles").json().get("profiles", [])
    assert not any(p.get("is_default") for p in profiles), \
        "a default sending profile would carry system mail instead of the stored settings"
    user = admin.create_user(role="user")
    person = admin.clone_anonymous()
    person.login(user["_username"], user["_password"])
    try:
        with mail_server(["mail.example.invalid"]) as server:
            _store(sender.client, server.port, smtp_allow_insecure_tls=True,
                   email_change_requires_verification=True)
            test_send = sender.client.post("/settings/test-email")
            change = person.post("/users/me/request-email-change", json={
                "new_email": unique("moved") + "@example.com", "current_password": user["_password"]})
        assert test_send.status_code in (400, 502), test_send.text
        assert change.status_code in (400, 502), change.text
        assert_refused_before_auth(server.sessions)

        with mail_server(["mail.example.invalid"]) as server:
            refused = _profile_test(admin, server.port, False)
            allowed = _profile_test(admin, server.port, True)
        assert refused.status_code in (400, 502), refused.text
        assert allowed.status_code == 200, allowed.text
        assert [s["tls"] for s in server.sessions] == ["refused", "ok"], server.sessions
        assert server.sessions[0]["auth"] is None and server.sessions[1]["auth"], server.sessions
    finally:
        admin.delete_user(user["id"])


_SEND_INSIDE = """
import asyncio, json, os, tempfile
from types import SimpleNamespace
handle, path = tempfile.mkstemp(suffix=".pem")
os.write(handle, AUTHORITY.encode())
os.close(handle)
os.environ["SSL_CERT_FILE"] = path
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("test-email-tls-test")
from fastapi import HTTPException
from app.api import api_server as api
from app.core.database import get_db_context
from app.core.models import User
with get_db_context() as db:
    user = db.query(User).filter(User.username == USERNAME).one()
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.11"))
    try:
        print(json.dumps({"answer": asyncio.run(api.send_test_email(request=request, current_user=user, db=db))}))
    except HTTPException as refused:
        print(json.dumps({"status": refused.status_code, "detail": refused.detail}))
"""


def test_test_send_accepts_a_certificate_the_vault_can_verify(sender):
    with mail_server(["127.0.0.1"], issuer="authority") as server:
        _store(sender.client, server.port)
        script = (f"AUTHORITY = {server.authority_pem!r}\nUSERNAME = {sender.username!r}\n"
                  + _SEND_INSIDE)
        try:
            ran = subprocess.run(["docker", "exec", "-i", API, "python", "-c", script],
                                 capture_output=True, text=True, timeout=120)
        except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
            pytest.skip(f"docker unavailable: {exc}")
        skip_if_container_absent(ran, API)
    assert ran.returncode == 0, (ran.stderr or ran.stdout)[-800:]
    result = json.loads(ran.stdout.strip().splitlines()[-1])
    assert result.get("answer", {}).get("message", "").startswith("Test email sent to"), result
    sent = [s for s in server.sessions if s["message"] and "DockVault test email" in s["message"]]
    assert len(sent) == 1 and sent[0]["tls"] == "ok" and sent[0]["auth"], server.sessions
