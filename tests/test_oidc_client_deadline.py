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
    """An https server on this machine: ``/ok`` answers a JSON object, ``/slow`` trickles its headers, and
    ``/redirect`` sends whoever asks to a plain-http listener beside it, which notes what reaches it."""

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
        self.elsewhere = socket.socket()
        self.elsewhere.bind(("127.0.0.1", 0))
        self.elsewhere.listen(8)
        self.elsewhere_port = self.elsewhere.getsockname()[1]
        self.reached_elsewhere = []
        self.accepted = 0
        self.open = True
        threading.Thread(target=self._serve, daemon=True).start()
        threading.Thread(target=self._serve_elsewhere, daemon=True).start()

    def _serve_elsewhere(self):
        while self.open:
            try:
                conn, _ = self.elsewhere.accept()
            except OSError:
                return
            try:
                conn.settimeout(5)
                asked = b""
                while b"\r\n\r\n" not in asked:
                    more = conn.recv(4096)
                    if not more:
                        break
                    asked += more
                self.reached_elsewhere.append(asked.decode("latin-1"))
                conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 2\r\n"
                             b"Connection: close\r\n\r\n{}")
            except OSError:
                pass
            finally:
                conn.close()

    def _serve(self):
        while self.open:
            try:
                plain, _ = self.listener.accept()
            except OSError:
                return
            self.accepted += 1
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
                elif b" /redirect " in asked.split(b"\r\n", 1)[0]:
                    head, _, body = asked.partition(b"\r\n\r\n")
                    lengths = [line.split(b":", 1)[1] for line in head.split(b"\r\n")
                               if line.lower().startswith(b"content-length:")]
                    while lengths and len(body) < int(lengths[0]):      # the whole request, before the answer
                        more = conn.recv(4096)
                        if not more:
                            break
                        body += more
                    conn.sendall(b"HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:%d/latest/meta-data\r\n"
                                 b"Content-Length: 0\r\nConnection: close\r\n\r\n" % self.elsewhere_port)
                else:
                    body = b'{"a": 1}'
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: %d\r\n"
                                 b"Connection: close\r\n\r\n" % len(body) + body)
        except (OSError, ssl.SSLError):
            pass

    def opener(self, oc):
        return oc._build_opener(self.trusting)          # the module's own opener, trusting this server

    def close(self):
        self.open = False
        self.listener.close()
        self.elsewhere.close()


@pytest.fixture
def server(tmp_path, monkeypatch):
    for name in ("https_proxy", "HTTPS_PROXY", "all_proxy", "ALL_PROXY"):
        monkeypatch.delenv(name, raising=False)
    monkeypatch.setenv("no_proxy", "127.0.0.1")
    made = _Server(tmp_path)
    yield made
    made.close()


def test_an_answer_that_points_elsewhere_is_refused_and_the_clients_credentials_go_nowhere(server):
    """A provider's endpoint (or whoever can make it answer) says 302, to a plain-http address inside. urllib's
    own handling would go there, as a GET that still carries the request's headers: the code exchange's
    ``Authorization: Basic`` with the client's secret. The address was never judged under the endpoint rule. The
    module's opener follows no redirect: the call is refused and nothing reaches the other address."""
    oc = _oc()
    url = f"https://127.0.0.1:{server.port}/redirect"
    headers = {"Authorization": "Basic Y2xpZW50OnNlY3JldA==", "Content-Type": "application/x-www-form-urlencoded"}
    # The opener the module's calls use, and the one this server hands out, come from the one place; every
    # redirect handler in them is the one that refuses.
    for opener in (oc._opener, server.opener(oc)):
        redirectors = [h for h in opener.handlers if isinstance(h, urllib.request.HTTPRedirectHandler)]
        assert redirectors and all(isinstance(h, oc._NoRedirects) for h in redirectors), redirectors
        assert any(isinstance(h, oc._Https) for h in opener.handlers)
    # The control: urllib's own redirect handling does follow this answer, and does carry the header along.
    following = urllib.request.build_opener(oc._Https(context=server.trusting))
    request = urllib.request.Request(url, data=b"grant_type=authorization_code", headers=headers, method="POST")
    with following.open(request, timeout=10) as answer:
        assert answer.status == 200
    assert len(server.reached_elsewhere) == 1 and server.reached_elsewhere[0].startswith("GET /latest/meta-data")
    assert "authorization: basic y2xpzw50onnly3jlda==" in server.reached_elsewhere[0].lower()
    server.reached_elsewhere.clear()
    with pytest.raises(oc.OidcError):
        oc.fetch_json(url, method="POST", data=b"grant_type=authorization_code", headers=headers,
                      opener=server.opener(oc))
    with pytest.raises(oc.OidcError):
        oc.fetch_json(url, opener=server.opener(oc))
    assert server.reached_elsewhere == []


def test_a_name_that_answers_inside_where_the_connection_is_made_reaches_nothing(server):
    """The endpoint rule looks a provider's name up before a call, and the connection looks it up again. Whoever
    answers for the name can say a public address first and one inside a moment later. The connection judges
    what it is given: for a provider not marked as inside it connects to nothing that is not public (this
    machine's own address here), and the call is refused as the rule refuses it; for one marked as inside, and
    through a proxy (which looks the name up itself), it connects as before."""
    import types
    oc = _oc()
    url = f"https://127.0.0.1:{server.port}/ok"

    def fetch(address, **kw):
        return oc.fetch_json(address, opener=server.opener(oc), **kw)

    inside, outside = types.SimpleNamespace(private_network=True), types.SimpleNamespace(private_network=False)
    assert oc._reach(inside, fetch, url) == {"a": 1} and server.accepted == 1
    with pytest.raises(oc.OidcError) as refused:
        oc._reach(outside, fetch, url)
    assert refused.value.code == oc.ENDPOINT_REFUSED and "private address" in refused.value.detail
    assert server.accepted == 1                                  # no connection was opened
    assert oc._PUBLIC_ONLY.get() is False                        # the rule ends with the call, failed or not
    assert oc._reach(inside, fetch, url) == {"a": 1} and server.accepted == 2
    # Through a proxy the connection is the proxy's to make: this one reaches the proxy as before.
    connection = oc._DeadlineConnection("127.0.0.1", server.port, timeout=5)
    token = oc._PUBLIC_ONLY.set(True)
    try:
        with pytest.raises(oc._NotPublic):
            connection._connect_by_the_deadline(("127.0.0.1", server.port))
        connection.set_tunnel("idp.example.com", 443)
        connection._connect_by_the_deadline(("127.0.0.1", server.port)).close()
    finally:
        oc._PUBLIC_ONLY.reset(token)
    waited = time.monotonic() + 5
    while server.accepted < 3 and time.monotonic() < waited:      # the server counts a moment after the connect
        time.sleep(0.01)
    assert server.accepted == 3
    # A name that answers both: only what is public is tried, in the order it was given.
    def entry(address):
        return (socket.AF_INET, socket.SOCK_STREAM, 6, "", (address, 443))

    answered = [entry("10.0.0.5"), entry("8.8.8.8"), entry("127.0.0.1"), entry("169.254.169.254"), entry("1.1.1.1"),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("::1", 443, 0, 0)),
                (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:4700:4700::1111", 443, 0, 0))]
    assert oc._addresses_allowed(answered, through_a_proxy=False) == answered        # no call is held: all of them
    token = oc._PUBLIC_ONLY.set(True)
    try:
        assert [found[4][0] for found in oc._addresses_allowed(answered, through_a_proxy=False)] == [
            "8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"]
        assert oc._addresses_allowed(answered, through_a_proxy=True) == answered
        with pytest.raises(oc._NotPublic):
            oc._addresses_allowed([entry("10.0.0.5"), entry("192.168.1.1")], through_a_proxy=False)
        with pytest.raises(oc._NotPublic):
            oc._addresses_allowed([], through_a_proxy=False)
    finally:
        oc._PUBLIC_ONLY.reset(token)


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
