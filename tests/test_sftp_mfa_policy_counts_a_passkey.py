"""The SFTP rule for an account with a second factor (mfa_sftp_policy = temp_credential_only: such an account
reaches SFTP through a temporary credential only) counts a passkey as the web does: an account whose one second
factor is a passkey is not let in with its password or its SSH key alone. Offline, on the SQLite copy of the model;
tests/test_sftp_mfa_policy.py holds the same on a running stack, at both doors and on an open connection."""
import ast
import inspect
import textwrap
import uuid
from datetime import datetime

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core.models import RoleEnum, SecondFactorEnrollment, SystemSetting, User, WebAuthnCredential  # noqa: E402
from app.sftp import sftp_server as S  # noqa: E402

pytestmark = pytest.mark.unit


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def _user(db, name):
    user = User(username=name, email=f"{name}@example.com", password_hash="x", role=RoleEnum.USER, is_active=True,
                is_locked=False)
    db.add(user)
    db.commit()
    return user


def _passkey(db, user, **extra):
    fields = dict(id=uuid.uuid4(), user_id=user.id, credential_id=uuid.uuid4().bytes, public_key_cose=b"pk",
                  cose_alg=-7, rp_id="vault.example.test", created_at=datetime.utcnow())
    fields.update(extra)
    db.add(WebAuthnCredential(**fields))
    db.commit()


def _policy(db, value):
    row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
    if row is None:
        db.add(SystemSetting(key="global", value={"mfa_sftp_policy": value}))
    else:
        row.value = {"mfa_sftp_policy": value}
    db.commit()


def test_a_passkey_is_a_second_factor_for_the_sftp_rule(db):
    _policy(db, "temp_credential_only")
    keyed, coded, plain = _user(db, "keyed"), _user(db, "coded"), _user(db, "plain")
    _passkey(db, keyed)
    db.add(SecondFactorEnrollment(user_id=coded.id, method="totp", status="active"))
    db.commit()
    for account in (keyed, coded):
        assert S._mfa_sftp_requires_temp_cred(db, account) is True, account.username
        assert S._user_requires_temp_cred_for_sftp(db, account, fail_closed=True) is True, account.username
    assert S._mfa_sftp_requires_temp_cred(db, plain) is False
    assert S._user_requires_temp_cred_for_sftp(db, plain, fail_closed=True) is False
    # Where the policy lets a password or a key in, nobody is held to a temporary credential.
    _policy(db, "allow")
    assert S._mfa_sftp_requires_temp_cred(db, keyed) is False and S._mfa_sftp_requires_temp_cred(db, coded) is False


def test_which_passkeys_count(db):
    """Every passkey that is not retired, whatever the vault's address: this process does not judge the address or
    the passkey switch, and refuses rather than guess. A retired key is no factor."""
    _policy(db, "temp_credential_only")
    elsewhere, retired, both = _user(db, "elsewhere"), _user(db, "retired"), _user(db, "both")
    _passkey(db, elsewhere, rp_id="old.example.test")
    _passkey(db, retired, retired_at=datetime.utcnow())
    _passkey(db, both, retired_at=datetime.utcnow())
    _passkey(db, both)
    assert S._mfa_sftp_requires_temp_cred(db, elsewhere) is True
    assert S._mfa_sftp_requires_temp_cred(db, retired) is False
    assert S._mfa_sftp_requires_temp_cred(db, both) is True


def test_an_account_whose_factor_was_reset_is_held_until_it_has_set_the_next_one_up(db):
    _policy(db, "temp_credential_only")
    reset = _user(db, "reset")
    assert S._mfa_sftp_requires_temp_cred(db, reset) is False
    reset.second_factor_reset_at = datetime.utcnow()
    db.commit()
    assert S._mfa_sftp_requires_temp_cred(db, reset) is True


def test_passkeys_that_cannot_be_read_refuse_the_sign_in_and_leave_an_open_connection(db, monkeypatch):
    _policy(db, "temp_credential_only")
    plain = _user(db, "plain")
    real = db.query

    def query(*what):
        if what and getattr(what[0], "class_", None) is WebAuthnCredential:
            raise RuntimeError("the passkeys cannot be read")
        return real(*what)

    monkeypatch.setattr(db, "query", query)
    with pytest.raises(S._PolicyUnreadable):
        S._mfa_sftp_requires_temp_cred(db, plain, fail_closed=True)
    assert S._mfa_sftp_requires_temp_cred(db, plain) is False


def test_both_doors_and_the_check_on_every_operation_ask_the_one_rule():
    """The password door, the key door and the check an open connection meets on every operation each ask
    _user_requires_temp_cred_for_sftp, which asks the rule above: none of them reads the factors by itself."""
    def calls(fn):
        tree = ast.parse(textwrap.dedent(inspect.getsource(fn)))
        return {node.func.id for node in ast.walk(tree)
                if isinstance(node, ast.Call) and isinstance(node.func, ast.Name)}

    for fn in (S.SFTPServer.check_auth_password, S.SFTPServer.check_auth_publickey,
               S.SFTPServerInterface._load_principal):
        assert "_user_requires_temp_cred_for_sftp" in calls(fn), fn.__name__
        assert "SecondFactorEnrollment" not in inspect.getsource(fn), fn.__name__
    assert "_mfa_sftp_requires_temp_cred" in calls(S._user_requires_temp_cred_for_sftp)
