"""Live: each kind of probe on the SFTP port adds exactly one line to the container's log.

Scanners on the internet connect to a public SFTP port without speaking SSH. Each is refused, and each
used to add paramiko's error and traceback lines to the log, then the server's own event. This sends
each kind of probe to the stack's SFTP port -- a connection closed at once, an HTTP request, other
text, bytes that are not text, and silence until the sign-in grace period runs out -- and reads the
container's own log (stdout and stderr, where paramiko writes) after each: one new line, naming the
probe, and no traceback. A real SSH client that fails to sign in is still logged as a connection, and
its failure is still in the audit log.
"""
from __future__ import annotations

import os
import re
import shutil
import socket
import subprocess
import time
import uuid
from urllib.parse import urlsplit

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.sftp, pytest.mark.docker]

SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
TLS_HELLO = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xff\xfe\xfd\x0a"


def _host():
    from conftest import BASE_URL
    return urlsplit(BASE_URL).hostname or "127.0.0.1"


@pytest.fixture(scope="module")
def container():
    """The container whose log holds the SFTP server's lines: the SFTP container in the split shape,
    the one container otherwise."""
    if shutil.which("docker") is None:
        pytest.skip("reading the container's own log needs the docker CLI")
    for name in dict.fromkeys(c for c in (os.environ.get("VAULT_SFTP_CONTAINER"),
                                          os.environ.get("VAULT_API_CONTAINER"), "vault-sftp") if c):
        r = subprocess.run(["docker", "logs", name], capture_output=True, text=True,
                           encoding="utf-8", errors="replace", timeout=60)
        if r.returncode == 0 and "event server.listening" in r.stdout + r.stderr:
            return name
    pytest.skip("no container with the SFTP server's log on this host")


def _log_lines(name):
    r = subprocess.run(["docker", "logs", name], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=60)
    assert r.returncode == 0, r.stderr[-300:]
    return r.stdout.splitlines(), r.stderr.splitlines()


class _Log:
    def __init__(self, name):
        """Starts counting once the log has been quiet for a second, so a line a test before this
        one is still causing (a session ending) is not counted as the probe's."""
        self.name = name
        self.out, self.err = _log_lines(name)
        end = time.monotonic() + 15
        while time.monotonic() < end:
            time.sleep(1)
            out, err = _log_lines(name)
            if (len(out), len(err)) == (len(self.out), len(self.err)):
                break
            self.out, self.err = out, err

    def new(self):
        out, err = _log_lines(self.name)
        return out[len(self.out):] + err[len(self.err):]

    def wait_for(self, pattern, seconds):
        end = time.monotonic() + seconds
        while time.monotonic() < end:
            lines = self.new()
            if any(re.search(pattern, ln) for ln in lines):
                time.sleep(2)                    # anything logged just after it is counted too
                return self.new()
            time.sleep(0.5)
        pytest.fail(f"nothing matching {pattern!r} was logged within {seconds}s:\n" + "\n".join(self.new()))


def _probe(send, hold_seconds=0.0):
    sock = socket.create_connection((_host(), SFTP_PORT), timeout=10)
    try:
        if send:
            sock.sendall(send)
        if hold_seconds:
            sock.settimeout(hold_seconds)
            try:
                while sock.recv(4096):
                    pass
            except (socket.timeout, OSError):
                pass
    finally:
        sock.close()


@pytest.mark.parametrize("send, hold, kind, wait", [
    (None, 0.0, "closed", 15),
    (b"GET / HTTP/1.1\r\nHost: vault.example\r\n\r\n", 10.0, "http", 20),
    (b"HELLO THERE\r\n", 0.0, "text", 15),
    (TLS_HELLO, 5.0, "binary", 15),
    (None, 45.0, "silent", 60),
], ids=["closed-at-once", "http-request", "other-text", "bytes-not-text", "silent"])
def test_each_probe_adds_one_line_and_no_traceback(container, send, hold, kind, wait):
    log = _Log(container)
    _probe(send, hold)
    lines = log.wait_for(rf"event connection\.not-ssh\.{kind} ", wait)
    assert len(lines) == 1, "a probe added more than one line:\n" + "\n".join(lines)
    assert re.fullmatch(rf"(\[sftp\] )?event connection\.not-ssh\.{kind} peer=[0-9a-f.:]+", lines[0]), lines
    assert not any("Traceback" in ln or "Exception (server)" in ln for ln in lines)


def test_a_failed_ssh_sign_in_is_still_logged_as_a_connection(container, admin):
    paramiko = pytest.importorskip("paramiko")
    name = f"probe-{uuid.uuid4().hex[:10]}"
    log = _Log(container)
    transport = paramiko.Transport((_host(), SFTP_PORT))
    transport.banner_timeout = 30
    try:
        with pytest.raises(paramiko.AuthenticationException):
            transport.connect(username=name, password="not-the-password")
    finally:
        transport.close()
    lines = log.wait_for(r"event connection\.accepted ", 20)
    assert not any("not-ssh" in ln or "Traceback" in ln for ln in lines), lines

    deadline = time.monotonic() + 20
    while time.monotonic() < deadline:
        rows = admin.get("/audit/log", params={"action": "login_failure", "limit": 100}).json()
        entries = rows.get("logs", rows) if isinstance(rows, dict) else rows
        if any(isinstance(r, dict) and r.get("username") == name for r in entries):
            return
        time.sleep(1)
    pytest.fail("the failed SFTP sign-in is missing from the audit log")
