"""MFA SFTP-auth policy: with mfa_sftp_policy=temp_credential_only, a user whose second factor is IN
EFFECT (here: enrolled) may reach SFTP only via a temporary credential — direct password auth is refused
— while a user without the second factor in effect keeps normal password SFTP. Closes the SFTP
single-factor back door around MFA.
"""
import contextlib
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import pytest                                                      # noqa: E402

paramiko = pytest.importorskip("paramiko")

from _sf_helpers import enrolled_admin, enroll_totp, step_up_receipt   # noqa: E402

SFTP_HOST = os.environ.get("VAULT_SFTP_HOST", "127.0.0.1")
SFTP_PORT = int(os.environ.get("VAULT_SFTP_PORT", "2322"))

pytestmark = pytest.mark.sftp
_AUTH_ERR = (paramiko.SSHException, EOFError, OSError)


@contextlib.contextmanager
def _pw_conn(username, password):
    t = paramiko.Transport((SFTP_HOST, SFTP_PORT))
    t.banner_timeout = 30
    try:
        t.connect(username=username, password=password)
        yield t
    finally:
        t.close()


def _ls_root(transport):
    s = paramiko.SFTPClient.from_transport(transport)
    try:
        return s.listdir("/")
    finally:
        s.close()


def _set_sftp_policy(c, codes, value):
    r = c.put("/settings", json={"mfa_sftp_policy": value},
              headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                          recovery_codes=codes)})
    r.raise_for_status()


def test_temp_credential_only_refuses_enrolled_user_direct_sftp(admin):
    ta, c, _secret, codes = enrolled_admin(admin)
    enrolled = admin.create_user(role="user")
    plain = admin.create_user(role="user")
    ec = admin.clone_anonymous()
    ec.login(enrolled["_username"], enrolled["_password"])
    enroll_totp(enrolled, ec)   # enrolled -> second factor in effect (mfa_mode stays optional)
    try:
        _set_sftp_policy(c, codes, "temp_credential_only")
        # The enrolled user's direct password SFTP is refused (must use a temporary credential).
        with pytest.raises(_AUTH_ERR):
            with _pw_conn(enrolled["_username"], enrolled["_password"]):
                pass
        # A user whose second factor is NOT in effect is unaffected — normal password SFTP still works.
        with _pw_conn(plain["_username"], plain["_password"]) as t:
            _ls_root(t)
    finally:
        _set_sftp_policy(c, codes, "allow")
        admin.delete_user(enrolled["id"])
        admin.delete_user(plain["id"])
        admin.delete_user(ta["id"])
