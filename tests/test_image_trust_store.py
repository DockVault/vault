"""The image refuses a certificate made with a disclosed eMudhra intermediate key.

In October 2026 the private keys of eight eMudhra intermediate authorities were found to be trivially
weak (Python's fix is CVE-2026-115557); one of them, EM OV TLS CA - G3C, has the secp384r1 scalar 4
for its key. The images up to 0.33.5 trusted emSign ECC Root CA - G3, which vouches for that
intermediate's issuer through a cross-certificate, and their Python had no list of keys to refuse. So
a certificate anyone could make with that key, for any name, was accepted by the vault's default TLS
context, and the vault's own mail sender sent the relay's password and the message to whoever
presented it.

Since 0.33.6 the image refuses that chain twice over: its Python refuses any chain that holds one of
the eight keys (verify code 28, certificate rejected), and its trust store no longer holds the root
(code 20, unable to get local issuer certificate). This test runs inside the image of the running
stack, with the two public certificates in tests/fixtures/tls/compromised-intermediate-chain.json: it
rebuilds the intermediate's key, makes a server certificate with it, and checks that the default
context and app.core.email_send.smtp_send both refuse it, with either code, before anything is sent.

The database driver (psycopg2's libpq) has a TLS library of its own, with no list of keys to refuse,
and a vault told to check its database's certificate against the system trust store
(sslrootcert=system) uses the image's trust store there. Up to 0.33.5 it accepted the chain and handed
the database password to whoever presented it; only the trust store stops it now. So the check also
connects the driver to a stand-in database server presenting the chain, and, as a control, to one
whose certificate comes from an authority named by file, which the driver must accept.
"""
import json
import os
import subprocess
from pathlib import Path

import pytest

from conftest import skip_if_container_absent

pytestmark = pytest.mark.unit

TESTS = Path(__file__).resolve().parent
FIXTURE = json.loads((TESTS / "fixtures" / "tls" / "compromised-intermediate-chain.json")
                     .read_text(encoding="utf-8"))
SERVER_SOURCE = (TESTS / "_mail_tls_server.py").read_text(encoding="utf-8")
REFUSED = {20, 28}

_CHECK = """
import datetime, json, socket, ssl, sys, tempfile, threading
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

intermediate = x509.load_pem_x509_certificate(CHAIN["intermediate"]["pem"].encode())
cross = x509.load_pem_x509_certificate(CHAIN["cross_certificate"]["pem"].encode())
weak_key = ec.derive_private_key(CHAIN["intermediate_private_scalar"], ec.SECP384R1())
result = {"python": sys.version.split()[0], "openssl": ssl.OPENSSL_VERSION,
          "key_matches": weak_key.public_key().public_numbers() == intermediate.public_key().public_numbers()}

server_key = ec.generate_private_key(ec.SECP384R1())
now = datetime.datetime.now(datetime.timezone.utc)
leaf = (
    x509.CertificateBuilder()
    .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")]))
    .issuer_name(intermediate.subject)
    .public_key(server_key.public_key())
    .serial_number(x509.random_serial_number())
    .not_valid_before(now - datetime.timedelta(hours=1))
    .not_valid_after(now + datetime.timedelta(hours=6))
    .add_extension(_alt_names(["localhost", "127.0.0.1"]), critical=False)
    .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
    .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
    .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(intermediate.public_key()),
                   critical=False)
    .sign(weak_key, hashes.SHA384())
)
chain = write_chain(tempfile.mkdtemp(), server_key, leaf, intermediate, cross)

def refusal(error):
    while error is not None and not isinstance(error, ssl.SSLCertVerificationError):
        error = error.__context__
    return None if error is None else {"code": error.verify_code, "reason": error.verify_message}

serving = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
serving.load_cert_chain(chain)
listener = socket.create_server(("127.0.0.1", 0))

def answer():
    conn, _ = listener.accept()
    try:
        with serving.wrap_socket(conn, server_side=True) as tls:
            tls.recv(1)
    except (ssl.SSLError, OSError):
        pass
    finally:
        conn.close()

threading.Thread(target=answer, daemon=True).start()
try:
    with socket.create_connection(("127.0.0.1", listener.getsockname()[1]), timeout=15) as raw:
        with ssl.create_default_context().wrap_socket(raw, server_hostname="localhost") as tls:
            tls.send(b"x")
    result["default_context"] = {"accepted": True}
except ssl.SSLCertVerificationError as error:
    result["default_context"] = {"accepted": False, "refusal": refusal(error)}

from app.core import email_send
with MailServer(chain) as mail:
    cfg = {"smtp_server": "127.0.0.1", "smtp_port": mail.port, "smtp_username": "relay-user",
           "smtp_password": "relay-password-for-this-test", "from_email": "vault@example.com"}
    message = email_send.build_message(cfg, to_addr="someone@example.com", subject="Reset your password",
                                       text_body="https://vault.example.com/?reset=not-a-real-token")
    try:
        email_send.smtp_send(cfg, message)
        result["smtp_send"] = {"sent": True}
    except email_send.EmailSendError as error:
        result["smtp_send"] = {"sent": False, "refusal": refusal(error)}
result["sessions"] = mail.sessions

# The database driver: psycopg2's libpq, with its own TLS library, against a stand-in PostgreSQL server
# that presents a chain, then asks for the password in clear text as a real server may. Told
# sslrootcert=system, libpq checks the server against the image's trust store.
import struct
import psycopg2

def recv_exact(sock, count):
    data = b""
    while len(data) < count:
        part = sock.recv(count - len(data))
        if not part:
            raise OSError("closed")
        data += part
    return data

def postgres_server(chain_file):
    seen = {"handshake": None, "startup": False, "password": None}
    context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    context.load_cert_chain(chain_file)
    sock = socket.create_server(("127.0.0.1", 0))
    sock.settimeout(30)

    def serve():
        try:
            conn, _ = sock.accept()
        except OSError:
            return
        try:
            conn.settimeout(30)
            length, code = struct.unpack("!II", recv_exact(conn, 8))
            if (length, code) != (8, 80877103):
                seen["handshake"] = "no TLS request"
                return
            conn.sendall(b"S")
            try:
                tls = context.wrap_socket(conn, server_side=True)
            except (ssl.SSLError, OSError):
                seen["handshake"] = "refused"
                return
            seen["handshake"] = "ok"
            size = struct.unpack("!I", recv_exact(tls, 4))[0]
            recv_exact(tls, size - 4)
            seen["startup"] = True
            tls.sendall(b"R" + struct.pack("!II", 8, 3))
            kind = recv_exact(tls, 1)
            size = struct.unpack("!I", recv_exact(tls, 4))[0]
            body = recv_exact(tls, size - 4)
            if kind == b"p":
                seen["password"] = body.rstrip(bytes(1)).decode(errors="replace")
            text = b"SFATAL" + bytes(1) + b"C28P01" + bytes(1) + b"Mstand-in server" + bytes(2)
            tls.sendall(b"E" + struct.pack("!I", len(text) + 4) + text)
        except (OSError, struct.error):
            pass
        finally:
            conn.close()
            sock.close()

    thread = threading.Thread(target=serve, daemon=True)
    thread.start()
    return sock.getsockname()[1], seen, thread

def connect_database(chain_file, root):
    port, seen, thread = postgres_server(chain_file)
    try:
        psycopg2.connect(host="localhost", hostaddr="127.0.0.1", port=port, user="vault_user",
                         password="database-password-for-this-test", dbname="vault_db",
                         sslmode="verify-full", sslrootcert=root, gssencmode="disable",
                         connect_timeout=15)
        error = None
    except psycopg2.OperationalError as exc:
        error = " ".join(str(exc).split())[:300]
    thread.join(20)
    return dict(seen, error=error)

control_authority = authority("Test Database Authority")
control_cert, control_key = server_certificate(["localhost", "127.0.0.1"], issuer=control_authority)
control_dir = tempfile.mkdtemp()
control_root = os.path.join(control_dir, "root.pem")
with open(control_root, "wb") as handle:
    handle.write(certificate_pem(control_authority[0]))
control_chain = write_chain(control_dir, control_key, control_cert)
result["database_control"] = connect_database(control_chain, control_root)
result["database"] = connect_database(chain, "system")
print(json.dumps(result))
"""


@pytest.fixture(scope="module")
def in_the_image():
    """What the check found inside the running stack's web container (one run for the module)."""
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    script = SERVER_SOURCE + "\nCHAIN = json.loads(" + repr(json.dumps(FIXTURE)) + ")\n" + _CHECK
    try:
        ran = subprocess.run(["docker", "exec", "-i", container, "python", "-c", script],
                             capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(ran, container)
    assert ran.returncode == 0, (ran.stderr or ran.stdout)[-1500:]
    return json.loads(ran.stdout.strip().splitlines()[-1])


def test_the_fixture_is_the_compromised_intermediate_and_its_cross_certificate():
    import datetime

    from cryptography import x509
    from cryptography.hazmat.primitives.asymmetric import ec

    intermediate = x509.load_pem_x509_certificate(FIXTURE["intermediate"]["pem"].encode())
    cross = x509.load_pem_x509_certificate(FIXTURE["cross_certificate"]["pem"].encode())
    weak = ec.derive_private_key(FIXTURE["intermediate_private_scalar"], ec.SECP384R1())
    assert weak.public_key().public_numbers() == intermediate.public_key().public_numbers()
    assert intermediate.issuer == cross.subject
    assert cross.issuer.rfc4514_string() == (
        "CN=emSign ECC Root CA - G3,O=eMudhra Technologies Limited,OU=emSign PKI,C=IN")
    # Both must still be within their validity, or the image would refuse the chain for its dates and
    # this test would no longer say anything about the keys or the root.
    now = datetime.datetime.now(datetime.timezone.utc)
    for cert in (intermediate, cross):
        assert cert.not_valid_before_utc <= now <= cert.not_valid_after_utc, cert.subject


@pytest.mark.docker
def test_the_image_refuses_a_certificate_made_with_the_disclosed_key(in_the_image):
    result = in_the_image
    assert result["key_matches"], result
    context = result["default_context"]
    assert not context["accepted"], f"the image's default context accepted the forged chain: {result}"
    assert context["refusal"]["code"] in REFUSED, result


@pytest.mark.docker
def test_the_mail_sender_refuses_it_before_sending_the_password_or_the_message(in_the_image):
    result = in_the_image
    send = result["smtp_send"]
    assert not send["sent"], f"smtp_send sent through the forged chain: {result}"
    assert send["refusal"] and send["refusal"]["code"] in REFUSED, result
    assert result["sessions"], result
    for session in result["sessions"]:
        assert session["tls"] == "refused" and session["auth"] is None and session["message"] is None, result


@pytest.mark.docker
def test_the_database_driver_refuses_it_from_the_system_trust_store(in_the_image):
    control = in_the_image["database_control"]
    # The same driver, server and password exchange with a certificate from an authority named by file:
    # the driver gets through and hands over the password, so a refusal below is the certificate's.
    assert control["handshake"] == "ok", control
    assert control["password"] == "database-password-for-this-test", control
    database = in_the_image["database"]
    assert database["handshake"] == "refused", (
        f"the database driver accepted the forged chain from the system trust store: {database}")
    assert database["startup"] is False and database["password"] is None, database
    assert "certificate verify failed" in (database["error"] or ""), database
