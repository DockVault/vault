"""Shared helpers for the live tests of the notices to vaults' owners: an SMTP server inside the stack's web
container that keeps every message it is handed, a way to keep the outbox's sender from sending for a while
(holding its advisory lock from another database session), and a vault owned by an account with an address.
Imported by the test modules that need them; holds no tests."""
import json
import subprocess
import time
from contextlib import contextmanager

import pytest

from _account_change_helpers import API, DB, psql, signed_in
from conftest import skip_if_container_absent, unique

SINK_PORT = 2525
SINK_DIR = "/tmp/owner-notice-sink"
# The outbox sender's advisory lock (app/core/owner_notices.py, SENDER_LOCK).
SENDER_LOCK = (0x6f62, 1)

_SINK = r"""
import os, socketserver, time, uuid
ROOT = %(root)r
os.makedirs(ROOT, exist_ok=True)

class Handler(socketserver.StreamRequestHandler):
    def handle(self):
        say = lambda text: (self.wfile.write((text + "\r\n").encode()), self.wfile.flush())
        say("220 sink ready")
        rcpt = []
        while True:
            line = self.rfile.readline()
            if not line:
                return
            cmd = line.decode("utf-8", "replace").strip()
            up = cmd.upper()
            if up.startswith("MAIL FROM"):
                rcpt = []
                say("250 ok")
            elif up.startswith("RCPT TO"):
                rcpt.append(cmd.split(":", 1)[1].strip().strip("<>"))
                say("250 ok")
            elif up == "DATA":
                say("354 go on")
                body = []
                while True:
                    part = self.rfile.readline()
                    if not part or part in (b".\r\n", b".\n"):
                        break
                    body.append(part[1:] if part.startswith(b"..") else part)
                name = "%%.6f-%%s.eml" %% (time.time(), uuid.uuid4().hex)
                tmp = os.path.join(ROOT, name + ".part")
                with open(tmp, "wb") as f:
                    f.write(("X-Sink-To: " + ",".join(rcpt) + "\r\n").encode() + b"".join(body))
                os.replace(tmp, os.path.join(ROOT, name))
                say("250 kept")
            elif up == "QUIT":
                say("221 bye")
                return
            else:
                say("250 ok")

class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True

Server(("127.0.0.1", %(port)d), Handler).serve_forever()
"""

_READ = r"""
import email, glob, json, os
from email import policy
out = []
for path in sorted(glob.glob(os.path.join(%(root)r, "*.eml"))):
    raw = open(path, "rb").read()
    head, _, rest = raw.partition(b"\r\n")
    msg = email.message_from_bytes(rest, policy=policy.default)
    text = msg.get_body(("plain",))
    out.append({"to": head.decode().split(":", 1)[1].strip().split(","), "subject": str(msg["subject"] or ""),
                "text": text.get_content() if text is not None else ""})
print(json.dumps(out))
"""


def _in_container(args):
    try:
        r = subprocess.run(["docker", "exec", *args], capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, API)
    return r


def sink_running() -> bool:
    probe = ("import socket\ns = socket.socket()\ns.settimeout(2)\n"
             f"print(s.connect_ex(('127.0.0.1', {SINK_PORT})) == 0)\n")
    return _in_container([API, "python", "-c", probe]).stdout.strip().endswith("True")


def start_sink() -> None:
    """Start the SMTP server in the web container unless it runs (a restart of the container stops it)."""
    if sink_running():
        return
    _in_container(["-d", API, "python", "-c", _SINK % {"root": SINK_DIR, "port": SINK_PORT}])
    for _ in range(40):
        if sink_running():
            return
        time.sleep(0.25)
    raise AssertionError("the SMTP sink did not start")


def messages():
    r = _in_container([API, "python", "-c", _READ % {"root": SINK_DIR}])
    assert r.returncode == 0, r.stderr[-400:]
    return json.loads(r.stdout.strip().splitlines()[-1])


def mail_to(address, subject_contains=None, *, timeout=60.0):
    """The messages to ``address`` (with a subject containing the text), waiting up to ``timeout`` for one."""
    deadline = time.time() + timeout
    while True:
        found = [m for m in messages() if address in m["to"]
                 and (subject_contains is None or subject_contains in m["subject"])]
        if found or time.time() >= deadline:
            return found
        time.sleep(1)


@contextmanager
def sending_to_sink(admin, *, port=SINK_PORT):
    """The vault's default sending profile points at the sink (or at ``port``, where nothing listens) for the
    duration; the previous default is restored."""
    if port == SINK_PORT:
        start_sink()
    before = admin.get("/email/profiles").json().get("profiles", [])
    previous_default = next((p for p in before if p.get("is_default")), None)
    r = admin.post("/email/profiles", json={"name": unique("owner notices"), "smtp_server": "127.0.0.1",
                                            "smtp_port": port, "smtp_username": "",
                                            "from_email": "vault-tests@example.com", "is_default": True})
    assert r.status_code in (200, 201), r.text
    made = r.json()["id"]
    try:
        yield
    finally:
        admin.delete(f"/email/profiles/{made}")
        if previous_default is not None:
            restore = {k: previous_default.get(k) for k in (
                "name", "description", "smtp_server", "smtp_port", "smtp_username", "from_email",
                "from_name", "smtp_allow_insecure_tls")}
            restore["is_default"] = True
            admin.put(f"/email/profiles/{previous_default['id']}",
                      json={k: v for k, v in restore.items() if v is not None})


def _sender_lock_held() -> bool:
    return psql("SELECT count(*) FROM pg_locks WHERE locktype = 'advisory' AND granted "
                f"AND classid = {SENDER_LOCK[0]} AND objid = {SENDER_LOCK[1]}") != "0"


@contextmanager
def sender_held():
    """No outbox sender sends while this runs: another database session holds the sender's advisory lock."""
    holder = subprocess.Popen(["docker", "exec", "-i", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
                               f"SELECT pg_advisory_lock({SENDER_LOCK[0]}, {SENDER_LOCK[1]}); "
                               "SELECT pg_sleep(900)"],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        for _ in range(120):
            if _sender_lock_held():
                break
            time.sleep(0.25)
        else:
            raise AssertionError("the sender's lock was not taken")
        yield
    finally:
        psql("SELECT count(pg_terminate_backend(pid)) FROM pg_locks WHERE locktype = 'advisory' AND granted "
             f"AND classid = {SENDER_LOCK[0]} AND objid = {SENDER_LOCK[1]} AND pid <> pg_backend_pid()")
        holder.kill()
        holder.wait(timeout=30)


def owner_with_vault(admin, *, email=None):
    """An account with an address (``email``, or a fresh one) that owns a vault: (account, client, vault id)."""
    user = admin.create_user(email=email or f"{unique('owner')}@example.com")
    client = signed_in(user)
    vault = client.create_vault(name=unique("owned"))
    return user, client, vault["id"]


def outbox(case_id):
    """The case's outbox rows, oldest first: [kind, status, attempts, user id]."""
    out = psql("SELECT kind || '|' || status || '|' || attempts || '|' || user_id FROM compliance_notice_outbox "
               f"WHERE case_id = '{case_id}' ORDER BY created_at, id")
    return [row.split("|") for row in out.splitlines() if row]


def wait_for(fn, *, timeout=90.0, every=1.0):
    deadline = time.time() + timeout
    while True:
        value = fn()
        if value or time.time() >= deadline:
            return value
        time.sleep(every)
