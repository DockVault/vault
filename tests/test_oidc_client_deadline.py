"""A call to a provider is one deadline from the first address to the last byte (app/services/oidc_client.py).

The socket's timeout bounds one read. A provider that sent one byte of its status line or of a header just inside
that timeout, again and again, held the call, and the thread it runs in, for as long as it liked; so did a name with
many addresses that never answer, and a server that takes the connection and never starts TLS. Each is run here
against a real socket on this machine: a server that trickles, a listener that never speaks, and a good answer as the
control."""
import http.client
import socket
import ssl
import threading
import time
import urllib.request

import pytest

import _mail_tls_server as certs
from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

TRICKLE_SECONDS = 1.2      # how long the slow server keeps sending, a byte at a time
BYTE_EVERY = 0.05


def _oc():
    set_bare_api_env()
    from app.services import oidc_client as oc
    return oc


def _trickle(sock, head: bytes, finish: bytes):
    """Send ``head``, then one byte every BYTE_EVERY for TRICKLE_SECONDS, then ``finish``."""
    try:
        sock.sendall(head)
        until = time.monotonic() + TRICKLE_SECONDS
        while time.monotonic() < until:
            sock.sendall(b"a")
            time.sleep(BYTE_EVERY)
        sock.sendall(finish)
    except OSError:
        pass                                    # the reader gave up: what the test is about


def test_a_reply_trickled_inside_the_sockets_timeout_is_cut_off_at_the_calls_deadline():
    oc = _oc()

    def read_headers(wrap):
        ours, theirs = socket.socketpair()
        sender = threading.Thread(target=_trickle, args=(theirs, b"HTTP/1.1 200 OK\r\nX-Slow: ", b"\r\nContent-Length: 0\r\n\r\n"),
                                  daemon=True)
        sender.start()
        started = time.monotonic()
        try:
            ours.settimeout(0.4)
            response = http.client.HTTPResponse(wrap(ours))
            response.begin()
            return "read", time.monotonic() - started
        except TimeoutError:
            return "timed out", time.monotonic() - started
        finally:
            ours.close()
            sender.join(timeout=5)
            theirs.close()

    # The control: the socket's own timeout (0.4 s a read) never fires, and the whole trickle is read.
    how, took = read_headers(lambda sock: sock)
    assert how == "read" and took >= TRICKLE_SECONDS * 0.9, (how, took)
    # Under the call's deadline the same reply is cut off when the call's time is up.
    how, took = read_headers(lambda sock: oc._Deadlined(sock, time.monotonic() + 0.4))
    assert how == "timed out" and took < TRICKLE_SECONDS * 0.8, (how, took)


class _Server:
    """An https server on this machine: ``/ok`` answers a JSON object, ``/slow`` trickles its headers."""

    def __init__(self, tmp_path):
        authority = certs.authority("Test Provider Authority")
        cert, key = certs.server_certificate(["127.0.0.1"], issuer=authority)
        chain = certs.write_chain(str(tmp_path), key, cert)
        self.context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self.context.load_cert_chain(chain)
        self.trusting = ssl.create_default_context(cadata=certs.certificate_pem(authority[0]).decode())
        self.listener = socket.socket()
        self.listener.bind(("127.0.0.1", 0))
        self.listener.listen(8)
        self.port = self.listener.getsockname()[1]
        self.open = True
        threading.Thread(target=self._serve, daemon=True).start()

    def _serve(self):
        while self.open:
            try:
                plain, _ = self.listener.accept()
            except OSError:
                return
            threading.Thread(target=self._answer, args=(plain,), daemon=True).start()

    def _answer(self, plain):
        try:
            with self.context.wrap_socket(plain, server_side=True) as conn:
                asked = b""
                while b"\r\n\r\n" not in asked:
                    more = conn.recv(4096)
                    if not more:
                        return
                    asked += more
                if asked.startswith(b"GET /slow"):
                    _trickle(conn, b"HTTP/1.1 200 OK\r\nX-Slow: ", b"\r\nContent-Length: 2\r\n\r\n{}")
                else:
                    body = b'{"a": 1}'
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                                 b"Connection: close\r\n\r\n" % len(body) + body)
        except (OSError, ssl.SSLError):
            pass

    def opener(self, oc):
        return urllib.request.build_opener(oc._Https(context=self.trusting), oc._NoRedirects())

    def close(self):
        self.open = False
        self.listener.close()


@pytest.fixture
def server(tmp_path, monkeypatch):
    for name in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    made = _Server(tmp_path)
    yield made
    made.close()


def test_a_whole_call_ends_at_its_timeout_however_slowly_the_provider_sends_its_headers(server):
    oc = _oc()
    url = f"https://127.0.0.1:{server.port}"
    # The opener every call of the module uses holds its connections to the deadline.
    assert any(isinstance(handler, oc._Https) for handler in oc._opener.handlers)
    # The control: the connection the vault makes reads a good answer, and reads a slow one given the time.
    assert oc.fetch_json(url + "/ok", opener=server.opener(oc)) == {"a": 1}
    assert oc.fetch_json(url + "/slow", opener=server.opener(oc), timeout=10) == {}
    started = time.monotonic()
    with pytest.raises(oc.OidcError) as refused:
        oc.fetch_json(url + "/slow", opener=server.opener(oc), timeout=0.4)
    took = time.monotonic() - started
    assert refused.value.code == "temporarily_unavailable"
    assert took < TRICKLE_SECONDS * 0.8, took


def _certificate_refused(error) -> bool:
    """Whether a call failed because the certificate was not accepted (and not for any other reason)."""
    cause = error.__cause__
    return isinstance(getattr(cause, "reason", cause), ssl.SSLCertVerificationError)


def test_the_connection_still_checks_the_certificate_and_the_name_it_was_issued_for(server, tmp_path):
    """The connection is the vault's own; what the standard one checks, it checks. A certificate from an authority
    the trust store does not hold is refused, and so is a good one presented for another name."""
    oc = _oc()
    url = f"https://127.0.0.1:{server.port}/ok"
    assert oc.fetch_json(url, opener=server.opener(oc)) == {"a": 1}               # the control: trusted, right name
    with pytest.raises(oc.OidcError) as refused:
        oc.fetch_json(url)                                                       # the module's own opener: unknown authority
    assert refused.value.code == "temporarily_unavailable" and _certificate_refused(refused.value), refused.value
    with pytest.raises(oc.OidcError) as refused:
        oc.fetch_json(f"https://localhost:{server.port}/ok", opener=server.opener(oc))    # issued for 127.0.0.1 only
    assert refused.value.code == "temporarily_unavailable" and _certificate_refused(refused.value), refused.value
    conn = oc._DeadlineConnection("idp.example.com", timeout=5)
    assert conn._context.check_hostname is True and conn._context.verify_mode == ssl.CERT_REQUIRED


def test_a_server_that_never_starts_tls_holds_a_call_no_longer_than_its_timeout(monkeypatch):
    oc = _oc()
    for name in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    silent = socket.socket()
    silent.bind(("127.0.0.1", 0))
    silent.listen(4)                             # connections are taken by the system and never answered
    try:
        started = time.monotonic()
        with pytest.raises(oc.OidcError) as refused:
            oc.fetch_json(f"https://127.0.0.1:{silent.getsockname()[1]}/x", timeout=0.5)
        took = time.monotonic() - started
    finally:
        silent.close()
    assert refused.value.code == "temporarily_unavailable" and 0.4 <= took < 3, took


def _addresses(monkeypatch, oc, behaviour):
    """Three addresses for one name, a clock the test owns, and sockets that do what ``behaviour`` says of each
    address: "dead" lets the whole wait go by and fails, "answers" connects at once, a number lets that many
    seconds go by and fails. Returns the clock and the list of (address, wait given) tries."""
    clock = {"now": 1000.0}
    monkeypatch.setattr(oc.time, "monotonic", lambda: clock["now"])
    tried = []

    class _Socket:
        def __init__(self, *a):
            self.timeout = None

        def settimeout(self, seconds):
            self.timeout = seconds

        def connect(self, where):
            tried.append((where[0], round(self.timeout, 3)))
            what = behaviour[where[0]]
            if what == "answers":
                self.peer = where[0]
                return
            clock["now"] += self.timeout if what == "dead" else what
            raise TimeoutError("timed out")

        def setsockopt(self, *a):
            pass

        def close(self):
            pass
    addresses = [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (f"203.0.113.{n}", 443)) for n in (1, 2, 3)]
    monkeypatch.setattr(oc.socket, "getaddrinfo", lambda *a, **k: addresses)
    monkeypatch.setattr(oc.socket, "socket", _Socket)
    return clock, tried


def test_an_address_that_never_answers_leaves_time_for_the_next_and_all_share_the_one_deadline(monkeypatch):
    """A name with several addresses, as a provider reached over IPv4 and IPv6 has: each try gets an even share of
    what the call has left. An address that never answers (a route that drops IPv6, the usual case) leaves time
    for the next, which is taken when it answers; every address together takes no longer than the call's timeout;
    and once the call has no time left, no further address is tried."""
    oc = _oc()
    dead_then_alive = {"203.0.113.1": "dead", "203.0.113.2": "answers", "203.0.113.3": "answers"}
    clock, tried = _addresses(monkeypatch, oc, dead_then_alive)
    conn = oc._DeadlineConnection("idp.example.com", timeout=10)
    clock["now"] += 4                                    # four seconds of the call's ten went elsewhere
    sock = conn._connect_by_the_deadline(("idp.example.com", 443), 10)
    assert tried == [("203.0.113.1", 2.0), ("203.0.113.2", 2.0)], tried       # a third of six seconds, then half of four
    assert isinstance(sock, oc._Deadlined) and sock.plain.peer == "203.0.113.2"
    assert clock["now"] == 1006.0                        # the dead address cost its share, not the call
    # None answers: each had its share, and the whole took what the call had left, no more.
    clock, tried = _addresses(monkeypatch, oc, dict.fromkeys(dead_then_alive, "dead"))
    conn = oc._DeadlineConnection("idp.example.com", timeout=10)
    clock["now"] += 4
    with pytest.raises(TimeoutError):
        conn._connect_by_the_deadline(("idp.example.com", 443), 10)
    assert tried == [("203.0.113.1", 2.0), ("203.0.113.2", 2.0), ("203.0.113.3", 2.0)] and clock["now"] == 1010.0, tried
    # A try that overran the whole call (a connection that hung past its wait): nothing more is started.
    clock, tried = _addresses(monkeypatch, oc, {"203.0.113.1": 11, "203.0.113.2": "answers", "203.0.113.3": "answers"})
    conn = oc._DeadlineConnection("idp.example.com", timeout=10)
    with pytest.raises(TimeoutError):
        conn._connect_by_the_deadline(("idp.example.com", 443), 10)
    assert [where for where, _wait in tried] == ["203.0.113.1"], tried


def test_a_proxy_that_trickles_its_answer_to_connect_is_cut_off_at_the_calls_deadline():
    """Where the deployment reaches the provider through a proxy, the connection first asks the proxy for a tunnel.
    That exchange is on the bare connection, before TLS: it is held to the call's deadline as well."""
    oc = _oc()

    def through_a_slow_proxy(timeout):
        listener = socket.socket()
        listener.bind(("127.0.0.1", 0))
        listener.listen(1)

        def proxy():
            try:
                conn, _ = listener.accept()
                asked = b""
                while b"\r\n\r\n" not in asked:
                    more = conn.recv(4096)
                    if not more:
                        return
                    asked += more
                _trickle(conn, b"HTTP/1.1 200 Connection established\r\nX-Slow: ", b"\r\n\r\n")
                conn.close()
            except OSError:
                pass
        worker = threading.Thread(target=proxy, daemon=True)
        worker.start()
        conn = oc._DeadlineConnection("127.0.0.1", listener.getsockname()[1], timeout=timeout)
        conn.set_tunnel("idp.example.com", 443)
        started = time.monotonic()
        try:
            conn.connect()
            return "connected", time.monotonic() - started
        except TimeoutError:
            return "timed out", time.monotonic() - started
        except (OSError, ssl.SSLError):
            return "past the tunnel", time.monotonic() - started     # the proxy is no TLS server: the tunnel was made
        finally:
            conn.close()
            listener.close()
            worker.join(timeout=5)

    how, took = through_a_slow_proxy(0.4)
    assert how == "timed out" and took < TRICKLE_SECONDS * 0.8, (how, took)
    # The control: given the time, the same proxy's answer is read to its end.
    how, took = through_a_slow_proxy(10)
    assert how == "past the tunnel" and took >= TRICKLE_SECONDS * 0.9, (how, took)
