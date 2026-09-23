"""The SFTP endpoint the server advertises is one a client can actually use.

A standard install publishes SFTP on a different host port than the one the server binds inside its
container. The desktop sync client dials exactly the host and port a device mint returns, so the mint
must name the port that answers. These tests dial what the server advertises and sign in with what it
minted, against the running deployment -- the same door a client uses.
"""

import paramiko
import pytest

from conftest import unique
from _device_boundary_helpers import SFTP_HOST, grant, mint_sync_cred, register_device

pytestmark = [pytest.mark.integration, pytest.mark.sftp]


def _signs_in(host, port, username, password):
    t = None
    try:
        t = paramiko.Transport((host, port))
        t.banner_timeout = 60
        t.auth_timeout = 60
        t.connect(username=username, password=password)
        return t.is_authenticated()
    except (paramiko.SSHException, EOFError, OSError):
        return False
    finally:
        if t is not None:
            t.close()


def test_a_device_signs_in_where_its_mint_says_sftp_is(admin, temp_vault, _sftp_service_health):
    dev = register_device(admin)
    grant(admin, dev["device_id"], temp_vault["id"])
    r = mint_sync_cred(dev["secret"], temp_vault["id"])
    assert r.status_code == 200, r.text
    body = r.json()
    # No public host is configured here, so the client uses the address it reached the API on.
    assert body["host"] is None
    assert body["port"] == _sftp_service_health["port"], (
        "the mint advertises port %r but SFTP answers on %r" % (body["port"], _sftp_service_health["port"]))
    assert _signs_in(SFTP_HOST, body["port"], body["temp_username"], body["credential"])


def test_a_temporary_credential_names_the_port_sftp_answers_on(admin, _sftp_service_health):
    tc = admin.post("/auth/temp-credentials", json={"note": unique("sftp-endpoint")}).json()
    assert tc["sftp_host"] is None
    assert tc["sftp_port"] == _sftp_service_health["port"]
