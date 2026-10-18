"""A peer that never speaks SSH is one line in the log; an SSH peer's failure keeps its detail, offline.

Scanners probe a public SFTP port all day. Each probe is refused correctly, and each used to be logged
as paramiko's "Exception (server): Error reading SSH protocol banner" and a traceback (two, chained,
for bytes that are not text), then the handler's own event -- which reads like a fault in the server.
Now a peer that never sends an SSH identification line is one line: the peer and what it sent instead.
A peer that did send one is an SSH connection, and everything about it is logged as before.

These run the real connection handler over a real loopback connection, with paramiko's real transport
on both ends: what paramiko logs is read from its logger, what the server logs from its output.
"""
from __future__ import annotations

import logging
import socket
import threading
import time

import paramiko
import pytest

from app.sftp import sftp_server as mod

pytestmark = pytest.mark.unit

PEER = ("203.0.113.9", 4242)


@pytest.fixture
def host_key(tmp_path):
    from app.sftp.host_key import generate_ed25519_host_key, load_host_key
    path = tmp_path / "host_key"
    generate_ed25519_host_key(path)
    return load_host_key(path)


@pytest.fixture
def connect(monkeypatch, host_key, caplog, capsys):
    """Run one connection through handle_sftp_client; `client` drives the peer's end.

    Returns the server's output lines for it and the paramiko records at WARNING or above."""
    from app.core import config
    monkeypatch.setattr(config.settings, "sftp_auth_grace_seconds", 2)
    # No limits, so this connection's admission release has nothing to give back.
    monkeypatch.setattr(mod, "_connection_admission", mod._ConnectionAdmission(0, 0))
    caplog.set_level(logging.DEBUG, logger="paramiko")

    def run(client):
        listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)
        peer_end = socket.create_connection(listener.getsockname())
        server_end, _ = listener.accept()
        listener.close()
        capsys.readouterr()
        caplog.clear()
        handler = threading.Thread(target=mod.handle_sftp_client, args=(server_end, PEER, host_key),
                                   daemon=True)
        handler.start()
        try:
            client(peer_end)
        finally:
            handler.join(timeout=20)
            try:
                peer_end.close()
            except OSError:
                pass
        assert not handler.is_alive(), "the connection was never closed"
        lines = [ln for ln in capsys.readouterr().out.splitlines() if ln.strip()]
        # The server's transport logs as "paramiko.transport"; a test's SSH client logs elsewhere.
        loud = [r for r in caplog.records
                if r.name == "paramiko.transport" and r.levelno >= logging.WARNING]
        return lines, loud

    return run


def _wait_for_close(sock, seconds=15):
    """Read (and drop) what the server sends -- its own banner -- until it closes the connection."""
    sock.settimeout(seconds)
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        try:
            if not sock.recv(4096):
                return
        except (socket.timeout, OSError):
            return


def _closes_at_once(sock):
    sock.close()


def _silent(sock):
    _wait_for_close(sock)


def _sends(data):
    def client(sock):
        sock.sendall(data)
        _wait_for_close(sock)
    return client


def _sends_and_closes(data):
    def client(sock):
        sock.sendall(data)
        sock.shutdown(socket.SHUT_WR)
        _wait_for_close(sock)
    return client


# A TLS ClientHello's first bytes, then bytes that are not UTF-8, then a line feed: what a TLS client
# that scans for HTTPS sends, read as a line.
TLS_HELLO = b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xff\xfe\xfd\x0a"


@pytest.mark.parametrize("client, event", [
    (_closes_at_once, "connection.not-ssh.closed"),
    (_silent, "connection.not-ssh.silent"),
    (_sends(b"GET / HTTP/1.1\r\nHost: vault.example\r\n\r\n"), "connection.not-ssh.http"),
    (_sends_and_closes(b"HELLO THERE\r\n"), "connection.not-ssh.text"),
    (_sends(TLS_HELLO), "connection.not-ssh.binary"),
], ids=["closed-at-once", "silent", "http-request", "other-text", "bytes-not-text"])
def test_a_peer_that_never_speaks_ssh_is_one_line(connect, client, event):
    lines, loud = connect(client)
    assert lines == [f"event {event} peer={PEER[0]}"], lines
    assert loud == [], [r.getMessage() for r in loud]


def test_a_tls_greeting_with_no_line_feed_is_a_closed_connection(connect):
    """The client gives up on the SSH banner it got back and closes: still one line."""
    lines, loud = connect(_sends_and_closes(b"\x16\x03\x01\x02\x00\x01\x00\x01\xfc\x03\x03\xff\xfe"))
    assert lines == [f"event connection.not-ssh.closed peer={PEER[0]}"] and loud == []


def _ssh_client(**transport_kwargs):
    def client(sock):
        transport = paramiko.Transport(sock, **transport_kwargs)
        transport.set_log_channel("paramiko.test-client")
        transport.banner_timeout = 5
        try:
            transport.start_client(timeout=10)
        except Exception:  # noqa: BLE001 -- the client's side of the failure is not under test
            pass
        finally:
            transport.close()
    return client


def test_an_ssh_client_that_fails_the_key_exchange_keeps_its_detail(connect):
    """Offering only ciphers the server refuses: a real SSH failure, after a valid banner."""
    only_cbc = _ssh_client(disabled_algorithms={"ciphers": [
        c for c in paramiko.Transport._preferred_ciphers if not c.endswith("-cbc")]})
    lines, loud = connect(only_cbc)
    assert lines[0] == f"event connection.accepted peer={PEER[0]}", lines
    assert lines[-1] == f"event client.handling.failed peer={PEER[0]} err=IncompatiblePeer", lines
    messages = [r.getMessage() for r in loud]
    assert any(m.startswith("Exception (server): Incompatible ssh ") for m in messages), messages
    assert any("Traceback" in m for m in messages), "the traceback of a real SSH failure was dropped"


def test_an_old_ssh_version_is_an_ssh_connection_with_its_detail(connect):
    lines, loud = connect(_sends(b"SSH-1.5-OldClient\r\n"))
    assert lines == [f"event connection.accepted peer={PEER[0]}",
                     f"event client.handling.failed peer={PEER[0]} err=IncompatiblePeer"], lines
    assert any("Incompatible version (1.5 instead of 2.0)" in r.getMessage() for r in loud)


def test_the_accept_loop_no_longer_logs_a_connection_before_it_speaks():
    """`connection.accepted` is logged once, by the transport, when the peer has said it speaks SSH."""
    import ast
    import inspect
    source = inspect.getsource(mod)
    tree = ast.parse(source)
    sites = []
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            for call in ast.walk(node):
                if (isinstance(call, ast.Call) and getattr(call.func, "id", None) == "safe_event"
                        and call.args and getattr(call.args[0], "value", None) == "connection.accepted"):
                    sites.append(node.name)
    assert sites == ["_check_banner"], sites
