"""A mail server for tests that speaks TLS the way a relay does, and certificates for it to present.

Standard library and ``cryptography`` only, with no import from the test suite, so a live test can
also run this file inside the web container, where the vault's own sender connects to it over the
container's loopback (tests/test_settings_test_email_tls_live.py). Holds no tests.

The server listens on 127.0.0.1 and answers one client at a time in a thread of its own. For each
connection it records how far the client got: whether the TLS handshake completed (``"ok"``) or the
client broke it off (``"refused"``), the AUTH command it sent, and the message it handed over. With
``implicit_tls`` it speaks TLS from the first byte, as port 465 does; otherwise it offers STARTTLS.
"""
import datetime
import ipaddress
import json
import os
import socket
import ssl
import sys
import tempfile
import threading

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def _name(common_name):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, common_name)])


def _alt_names(names):
    entries = []
    for name in names:
        try:
            entries.append(x509.IPAddress(ipaddress.ip_address(name)))
        except ValueError:
            entries.append(x509.DNSName(name))
    return x509.SubjectAlternativeName(entries)


def _window():
    now = datetime.datetime.now(datetime.timezone.utc)
    return now - datetime.timedelta(hours=1), now + datetime.timedelta(days=1)


def authority(common_name="Test Mail Authority"):
    """A certificate authority made for one test run: (certificate, private key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    start, end = _window()
    cert = (
        x509.CertificateBuilder()
        .subject_name(_name(common_name))
        .issuer_name(_name(common_name))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                     key_encipherment=False, data_encipherment=False,
                                     key_agreement=False, key_cert_sign=True, crl_sign=True,
                                     encipher_only=False, decipher_only=False), critical=True)
        .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False)
        .sign(key, hashes.SHA256())
    )
    return cert, key


def server_certificate(names, issuer=None):
    """A server certificate for ``names`` (host names or IP addresses), issued by ``issuer`` (a
    (certificate, key) pair from :func:`authority`), or signed by its own key when ``issuer`` is None.
    Returns (certificate, private key)."""
    key = ec.generate_private_key(ec.SECP256R1())
    start, end = _window()
    issuer_cert, issuer_key = issuer if issuer is not None else (None, key)
    builder = (
        x509.CertificateBuilder()
        .subject_name(_name(names[0]))
        .issuer_name(issuer_cert.subject if issuer_cert is not None else _name(names[0]))
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(start)
        .not_valid_after(end)
        .add_extension(_alt_names(names), critical=False)
        .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
        .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    )
    if issuer_cert is not None:
        builder = builder.add_extension(
            x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_cert.public_key()), critical=False)
    return builder.sign(issuer_key, hashes.SHA256()), key


def certificate_pem(*certs):
    return b"".join(c.public_bytes(serialization.Encoding.PEM) for c in certs)


def key_pem(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def write_chain(directory, key, *certs):
    """Write ``key`` and ``certs`` (the server's own first) to one PEM file in ``directory``; its path."""
    path = os.path.join(directory, "server-chain.pem")
    with open(path, "wb") as handle:
        handle.write(key_pem(key) + certificate_pem(*certs))
    return path


class MailServer:
    """An SMTP server on 127.0.0.1 presenting the chain in ``chain_file``. A context manager.

    ``sessions`` holds one record per connection: ``{"tls", "auth", "message"}``, None until reached.
    """

    def __init__(self, chain_file, *, implicit_tls=False, port=0):
        self._context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        self._context.load_cert_chain(chain_file)
        self.implicit_tls = implicit_tls
        self._listener = socket.create_server(("127.0.0.1", port))
        self._listener.settimeout(0.2)
        self.port = self._listener.getsockname()[1]
        self.sessions = []
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._serve, daemon=True)

    def __enter__(self):
        self._thread.start()
        return self

    def __exit__(self, *exc):
        self.close()

    def close(self):
        self._stop.set()
        self._thread.join(timeout=20)
        self._listener.close()

    def _serve(self):
        while not self._stop.is_set():
            try:
                conn, _ = self._listener.accept()
            except (TimeoutError, socket.timeout):
                continue
            except OSError:
                return
            session = {"tls": None, "auth": None, "message": None}
            self.sessions.append(session)
            conn.settimeout(15)
            try:
                self._converse(conn, session)
            except (OSError, ValueError) as exc:
                session["error"] = type(exc).__name__
            finally:
                conn.close()

    def _handshake(self, conn, session):
        try:
            stream = self._context.wrap_socket(conn, server_side=True)
        except (ssl.SSLError, OSError):
            session["tls"] = "refused"
            return None
        session["tls"] = "ok"
        return stream

    @staticmethod
    def _say(out, *lines):
        out.write("".join(line + "\r\n" for line in lines).encode())

    def _converse(self, conn, session):
        opened = []
        try:
            self._dialogue(conn, session, opened)
        finally:
            for thing in reversed(opened):
                try:
                    thing.close()
                except OSError:
                    pass

    def _dialogue(self, conn, session, opened):
        stream = self._handshake(conn, session) if self.implicit_tls else conn
        if stream is None:
            return
        opened.append(stream)
        out = stream.makefile("rwb", buffering=0)
        opened.append(out)
        self._say(out, "220 mail.example.test ESMTP")
        while True:
            raw = out.readline()
            if not raw:
                return
            command = raw.decode("utf-8", "replace").strip()
            verb = command.split(" ", 1)[0].upper()
            if verb in ("EHLO", "HELO"):
                offer_starttls = not self.implicit_tls and session["tls"] is None
                self._say(out, "250-mail.example.test",
                          *(["250-STARTTLS"] if offer_starttls else []), "250 AUTH PLAIN LOGIN")
            elif verb == "STARTTLS" and not self.implicit_tls and session["tls"] is None:
                self._say(out, "220 Ready to start TLS")
                out.close()
                stream = self._handshake(conn, session)
                if stream is None:
                    return
                opened.append(stream)
                out = stream.makefile("rwb", buffering=0)
                opened.append(out)
            elif verb == "AUTH":
                session["auth"] = command
                self._say(out, "235 Authentication successful")
            elif verb == "DATA":
                self._say(out, "354 End data with <CR><LF>.<CR><LF>")
                body = []
                while True:
                    line = out.readline()
                    if not line or line in (b".\r\n", b".\n"):
                        break
                    body.append(line.decode("utf-8", "replace"))
                session["message"] = "".join(body)
                self._say(out, "250 Queued")
            elif verb == "QUIT":
                self._say(out, "221 Bye")
                return
            elif verb in ("MAIL", "RCPT", "RSET", "NOOP"):
                self._say(out, "250 OK")
            else:
                self._say(out, "502 Not implemented")


def serve_until_told(spec):
    """For a live test: serve as ``spec`` says until a line arrives on stdin, then print the sessions.

    ``spec``: ``{"names": [...], "issuer": "self" | "authority", "implicit_tls": bool, "port": int}``.
    The first line printed is ``{"port": ..., "authority_pem": ...}`` (the authority's certificate when
    one was made, so the caller can trust it); the last is the list of sessions, both as JSON.
    """
    directory = tempfile.mkdtemp()
    issuer = authority() if spec.get("issuer") == "authority" else None
    cert, key = server_certificate(spec["names"], issuer)
    chain = write_chain(directory, key, cert)
    with MailServer(chain, implicit_tls=bool(spec.get("implicit_tls")), port=int(spec.get("port", 0))) as server:
        print(json.dumps({"port": server.port,
                          "authority_pem": certificate_pem(issuer[0]).decode() if issuer else None}),
              flush=True)
        sys.stdin.readline()
    print(json.dumps(server.sessions), flush=True)
