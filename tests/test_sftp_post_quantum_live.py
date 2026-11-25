"""SFTP on a running stack agrees its session keys with the hybrid post-quantum key exchange
(mlkem768x25519-sha256: ML-KEM-768 with X25519), with real clients.

  * an OpenSSH 10 client that offers only the hybrid exchange completes it: the server has it, in the image
    as it is built (a cryptography library without ML-KEM would make the SSH library fall back with no word);
  * left to choose, the same client and the server agree the hybrid exchange: it is the first choice of both;
  * a client that offers only a classical exchange still connects (SFTP_KEX_POLICY=pq-preferred, the default);
  * a client whose X25519 share is all zeros is refused by the server, and the same client with an honest share
    is not.

The OpenSSH client runs in a small container of its own (the host's client may be older than 10.0, which is
where the hybrid exchange became its default). No account is used: the key exchange is over before anybody
signs in, and the client's own log names what was agreed.

The negative control is run by hand when the library's pin changes: against a stack built with the pin before
(paramiko 5.0.0), the hybrid-only client finds no key exchange in common and the first test fails.

test_sftp_kex_policy.py holds the policy and the server's log line offline.
"""
import os
import re
import socket
import subprocess

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.sftp, pytest.mark.docker]

HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))
HYBRID = "mlkem768x25519-sha256"
IMAGE = "dockvault-test-openssh-client:1"
DOCKERFILE = "FROM alpine:3.23\nRUN apk add --no-cache openssh-client\n"


def _docker(*args, **kw):
    try:
        return subprocess.run(["docker", *args], capture_output=True, text=True, encoding="utf-8", errors="replace",
                              timeout=kw.pop("timeout", 120), **kw)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"docker did not finish within {exc.timeout} s")


@pytest.fixture(scope="module")
def openssh():
    """An OpenSSH client of version 10 or later, in a container on the host's network; built once."""
    if _docker("image", "inspect", IMAGE).returncode != 0:
        built = _docker("build", "-t", IMAGE, "-", input=DOCKERFILE, timeout=600)
        assert built.returncode == 0, (built.stderr or built.stdout)[-800:]
    said = _docker("run", "--rm", IMAGE, "ssh", "-V")
    version = re.search(r"OpenSSH_(\d+)\.(\d+)", said.stderr + said.stdout)
    assert version and int(version.group(1)) >= 10, said.stderr + said.stdout

    def connect(*options):
        """The client's own log of one connection that offers no way to sign in: the key exchange runs, and
        the sign-in is refused."""
        done = _docker("run", "--rm", "--network", "host", IMAGE, "ssh", "-vv", "-o", "BatchMode=yes",
                       "-o", "StrictHostKeyChecking=no", "-o", "UserKnownHostsFile=/dev/null",
                       "-o", "IdentitiesOnly=yes", "-o", "IdentityFile=/dev/null", "-o", "ConnectTimeout=15",
                       *options, "-p", str(PORT), f"nobody@{HOST}", "true")
        return done.stderr + done.stdout
    return connect


def _agreed(log: str):
    found = re.search(r"kex: algorithm: (\S+)", log)
    return found.group(1) if found else None


def _keys_were_agreed(log: str) -> bool:
    return "SSH2_MSG_NEWKEYS received" in log


def test_a_client_that_offers_only_the_hybrid_exchange_completes_it(openssh):
    log = openssh("-o", f"KexAlgorithms={HYBRID}")
    assert _agreed(log) == HYBRID, log[-1500:]
    assert _keys_were_agreed(log), log[-1500:]
    assert "no matching key exchange method" not in log


def test_left_to_choose_the_client_and_the_server_agree_the_hybrid_exchange(openssh):
    log = openssh()
    assert _agreed(log) == HYBRID and _keys_were_agreed(log), log[-1500:]


def test_a_client_that_offers_only_a_classical_exchange_still_connects(openssh):
    log = openssh("-o", "KexAlgorithms=curve25519-sha256@libssh.org")
    assert _agreed(log) == "curve25519-sha256@libssh.org" and _keys_were_agreed(log), log[-1500:]


def test_a_client_whose_x25519_share_is_all_zeros_is_refused_and_an_honest_one_is_not():
    """The hybrid exchange is as strong as its classical half against whoever sends a share of small order: the
    X25519 result would be all zeros, known to everybody. The server refuses such a share. Driven with the SSH
    library as the client, its own exchange changed only in the share it sends."""
    import paramiko
    from cryptography.hazmat.primitives.asymmetric import mlkem
    from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
    from paramiko import kex_mlkem
    from paramiko.message import Message
    from paramiko.ssh_exception import SSHException

    class ZeroShare(kex_mlkem.KexMLKEM768X25519):
        def start_kex(self):
            self.x25519_key = X25519PrivateKey.generate()
            self.mlkem_key = mlkem.MLKEM768PrivateKey.generate()
            m = Message()
            m.add_byte(kex_mlkem.c_MSG_KEX_HYBRID_INIT)
            m.add_string(self.mlkem_key.public_key().public_bytes_raw() + bytes(32))
            self.transport._send_message(m)
            self.transport._expect_packet(kex_mlkem._MSG_KEX_HYBRID_REPLY)

    def exchange(engine):
        sock = socket.create_connection((HOST, PORT), timeout=15)
        transport = paramiko.Transport(sock)
        try:
            transport._kex_info = dict(transport._kex_info)
            transport._kex_info[HYBRID] = engine
            transport.get_security_options().kex = (HYBRID,)
            try:
                transport.start_client(timeout=20)
            except (SSHException, EOFError) as refused:
                return "refused", type(refused).__name__
            return "agreed", transport.is_active()
        finally:
            transport.close()
    assert exchange(kex_mlkem.KexMLKEM768X25519) == ("agreed", True)
    outcome, _why = exchange(ZeroShare)
    assert outcome == "refused"
