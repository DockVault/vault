"""POST /settings/test-email checks the mail server's certificate before it sends the password, offline.

The route opens its own SMTP connection with the stored settings and logs in with the stored password.
It used to open that connection with smtplib's own TLS context, which verifies nothing: anyone able to
intercept the connection could present any certificate and receive the username and password. It now
uses the context system mail uses for the same stored settings (app.core.email_send), so a certificate
the vault cannot verify ends the conversation before AUTH, and one it can verify is accepted.

Each test drives the route against a real TLS mail server on 127.0.0.1 (tests/_mail_tls_server.py).
"Trusted" here means signed by a test authority added to the trust store the vault's own context loads.
test_settings_test_email_tls_live.py does the same against a running stack.
"""
import smtplib
import ssl
import tempfile
from pathlib import Path
from types import SimpleNamespace

import pytest
import sqlalchemy as sa
from fastapi import HTTPException
from sqlalchemy.orm import sessionmaker

import _mail_tls_server as mail
from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import email_send  # noqa: E402
from app.core.models import AuditLog, RoleEnum, SystemSetting, User  # noqa: E402

pytestmark = pytest.mark.unit

PASSWORD = "relay-password-for-this-test"


@pytest.fixture
def db():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'test-email.db'}")
        for model in (User, AuditLog, SystemSetting):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=False)()
        yield session
        session.close()
        engine.dispose()


@pytest.fixture
def admin(db):
    user = User(username="admin", email="admin@example.test", password_hash="x", role=RoleEnum.ADMIN,
                is_active=True, is_locked=False)
    db.add(user)
    db.commit()
    return user


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch):
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))


@pytest.fixture
def workdir():
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


def _store_settings(db, port, **extra):
    db.add(SystemSetting(key="global", value={
        "smtp_server": "127.0.0.1", "smtp_port": port, "smtp_username": "relay-user",
        "smtp_password": PASSWORD, "from_email": "vault@example.test", **extra}))
    db.commit()


def _trust(monkeypatch, authority_cert):
    """Add ``authority_cert`` to every default context made from here on, as an operator who adds an
    authority to the system's trust store would. Nothing else about the context changes."""
    made = ssl.create_default_context
    pem = mail.certificate_pem(authority_cert).decode()

    def trusting(*args, **kwargs):
        context = made(*args, **kwargs)
        context.load_verify_locations(cadata=pem)
        return context

    monkeypatch.setattr(ssl, "create_default_context", trusting)


def _send(db, admin):
    request = SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.10"))
    return run_coroutine(api.send_test_email(request=request, current_user=admin, db=db))


def _serve(workdir, names, *, issuer=None, implicit_tls=False):
    cert, key = mail.server_certificate(names, issuer)
    return mail.MailServer(mail.write_chain(workdir, key, cert), implicit_tls=implicit_tls)


def _port_for(monkeypatch, server, implicit_tls):
    """The port to store. Implicit TLS is chosen by port 465 alone, which a test cannot listen on, so
    the connection made for 465 is sent to the server's own port; the context it carries is untouched."""
    if not implicit_tls:
        return server.port
    connect = smtplib.SMTP_SSL

    def to_the_test_server(host, port, *args, **kwargs):
        return connect(host, server.port, *args, **kwargs)

    monkeypatch.setattr(smtplib, "SMTP_SSL", to_the_test_server)
    return 465


@pytest.mark.parametrize("implicit_tls", [False, True], ids=["starttls", "implicit-tls"])
def test_test_send_refuses_a_self_signed_certificate_for_another_name_before_the_password(
        db, admin, workdir, monkeypatch, implicit_tls):
    with _serve(workdir, ["mail.example.invalid"], implicit_tls=implicit_tls) as server:
        _store_settings(db, _port_for(monkeypatch, server, implicit_tls))
        with pytest.raises(HTTPException) as refused:
            _send(db, admin)
    assert refused.value.status_code in (400, 502)
    assert PASSWORD not in str(refused.value.detail)
    assert [s["tls"] for s in server.sessions] == ["refused"], server.sessions
    assert server.sessions[0]["auth"] is None, "the password was sent to a server the vault cannot verify"
    assert server.sessions[0]["message"] is None


@pytest.mark.parametrize("implicit_tls", [False, True], ids=["starttls", "implicit-tls"])
def test_test_send_accepts_a_certificate_from_a_trusted_authority(db, admin, workdir, monkeypatch,
                                                                 implicit_tls):
    authority = mail.authority()
    _trust(monkeypatch, authority[0])
    with _serve(workdir, ["127.0.0.1"], issuer=authority, implicit_tls=implicit_tls) as server:
        _store_settings(db, _port_for(monkeypatch, server, implicit_tls))
        answer = _send(db, admin)
    assert answer == {"message": "Test email sent to admin@example.test"}
    assert [s["tls"] for s in server.sessions] == ["ok"], server.sessions
    assert server.sessions[0]["auth"], "the trusted server was never asked to authenticate"
    assert "DockVault test email" in server.sessions[0]["message"]


def test_a_trusted_authority_does_not_excuse_a_certificate_for_another_name(db, admin, workdir,
                                                                           monkeypatch):
    authority = mail.authority()
    _trust(monkeypatch, authority[0])
    with _serve(workdir, ["mail.example.invalid"], issuer=authority) as server:
        _store_settings(db, server.port)
        with pytest.raises(HTTPException):
            _send(db, admin)
    assert [s["tls"] for s in server.sessions] == ["refused"], server.sessions
    assert server.sessions[0]["auth"] is None


@pytest.mark.parametrize("opt_out_stored", [True, False], ids=["opt-out-stored", "no-opt-out"])
def test_the_certificate_is_checked_as_system_mail_checks_it_for_the_same_settings(
        db, admin, workdir, monkeypatch, opt_out_stored):
    """System mail sends through these stored settings when no sending profile is the default
    (email_send.resolve_default_config falls back to _legacy_cfg), and only a sending profile can turn
    certificate checks off. A stored ``smtp_allow_insecure_tls`` in these settings, which no page
    writes, therefore changes neither: both refuse the same server. A profile's own opt-out still
    reaches that server, which shows the refusals are the certificate's."""
    with _serve(workdir, ["mail.example.invalid"]) as server:
        _store_settings(db, server.port,
                        **({"smtp_allow_insecure_tls": True} if opt_out_stored else {}))
        with pytest.raises(HTTPException):
            _send(db, admin)
        system_mail = email_send._legacy_cfg(db)
        with pytest.raises(email_send.EmailSendError):
            email_send.smtp_send(system_mail, email_send.build_message(
                system_mail, to_addr="someone@example.test", subject="s", text_body="b"))
        profile = {**system_mail, "smtp_allow_insecure_tls": True}
        email_send.smtp_send(profile, email_send.build_message(
            profile, to_addr="someone@example.test", subject="s", text_body="b"))
    assert [s["tls"] for s in server.sessions] == ["refused", "refused", "ok"], server.sessions
    assert [s["auth"] is None for s in server.sessions] == [True, True, False]
