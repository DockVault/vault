"""A mail server whose certificate the vault cannot verify is reported as exactly that, offline.

ssl.SSLCertVerificationError is also a ValueError, so it used to land in the sender's "configuration"
branch, and the administrator was told to check the server address and the From name and address: no
help to one whose mail server presents a certificate from an authority the vault no longer trusts. It
now has its own category ('certificate', answered 502 like the other failures of the server's side)
and a message that says the server's certificate could not be verified, with OpenSSL's reason, and that
neither the password nor the message was sent. The same text reaches every place a send failure does:
the sender's error (which the API answers, Email Studio and system mail use), the settings test send,
Email Studio's profile test, and the log.

Each test sends to a real TLS mail server on 127.0.0.1 (tests/_mail_tls_server.py).
"""
import smtplib
import ssl
import tempfile
import uuid
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

import _mail_tls_server as mail
from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import email_studio_router as studio  # noqa: E402
from app.core import email_send  # noqa: E402

pytestmark = pytest.mark.unit

PASSWORD = "relay-password-for-this-test"
CERTIFICATE = "The mail server's certificate could not be verified"
MISLEADING = "The SMTP configuration is invalid"


@pytest.fixture
def workdir():
    with tempfile.TemporaryDirectory() as tmp:
        yield tmp


@pytest.fixture(autouse=True)
def no_rate_limit(monkeypatch):
    from app.core import rate_limiter
    monkeypatch.setattr(rate_limiter.rate_limiter, "check_rate_limit", lambda **kw: (True, 0, 0))


def _cfg(port, **over):
    return {"smtp_server": "127.0.0.1", "smtp_port": port, "smtp_username": "relay-user",
            "smtp_password": PASSWORD, "from_email": "vault@example.test", "from_name": "", **over}


def _message(cfg):
    return email_send.build_message(cfg, to_addr="someone@example.test", subject="Reset your password",
                                    text_body="https://vault.example.test/?reset=not-a-real-token")


def _serve(workdir, names, *, issuer=None, implicit_tls=False):
    cert, key = mail.server_certificate(names, issuer)
    return mail.MailServer(mail.write_chain(workdir, key, cert), implicit_tls=implicit_tls)


def _send_465_to(monkeypatch, server):
    connect = smtplib.SMTP_SSL

    def to_the_test_server(host, port, *args, **kwargs):
        return connect(host, server.port, *args, **kwargs)

    monkeypatch.setattr(smtplib, "SMTP_SSL", to_the_test_server)


def _trust(monkeypatch, authority_cert):
    made = ssl.create_default_context
    pem = mail.certificate_pem(authority_cert).decode()

    def trusting(*args, **kwargs):
        context = made(*args, **kwargs)
        context.load_verify_locations(cadata=pem)
        return context

    monkeypatch.setattr(ssl, "create_default_context", trusting)


def _assert_nothing_sent(server):
    assert [s["tls"] for s in server.sessions] == ["refused"], server.sessions
    assert server.sessions[0]["auth"] is None and server.sessions[0]["message"] is None


@pytest.mark.parametrize("implicit_tls", [False, True], ids=["starttls", "implicit-tls"])
@pytest.mark.parametrize("batch", [False, True], ids=["one", "batch"])
def test_a_self_signed_certificate_is_reported_as_a_certificate_failure(workdir, monkeypatch, capsys,
                                                                        implicit_tls, batch):
    with _serve(workdir, ["mail.example.invalid"], implicit_tls=implicit_tls) as server:
        port = server.port
        if implicit_tls:
            _send_465_to(monkeypatch, server)
            port = 465
        cfg = _cfg(port)
        with pytest.raises(email_send.EmailSendError) as refused:
            if batch:
                email_send.smtp_send_batch(cfg, [_message(cfg)])
            else:
                email_send.smtp_send(cfg, _message(cfg))
    _assert_nothing_sent(server)
    error = refused.value
    assert error.category == "certificate"
    assert error.message.startswith(f"{CERTIFICATE}: self-signed certificate. "), error.message
    assert f"No password or message was sent to 127.0.0.1:{port}." in error.message
    assert MISLEADING not in error.message and PASSWORD not in error.message
    logged = capsys.readouterr().out
    assert f"the certificate of the mail server at 127.0.0.1:{port} could not be verified: " \
           "self-signed certificate (verify code 18)" in logged, logged
    assert PASSWORD not in logged


def test_an_authority_the_vault_does_not_trust_is_named_as_the_reason(workdir):
    """The case an installation meets when its mail server's certificate chains to a root the vault no
    longer trusts: the server's own authority is unknown to the vault."""
    authority = mail.authority()
    with _serve(workdir, ["127.0.0.1"], issuer=authority) as server:
        cfg = _cfg(server.port)
        with pytest.raises(email_send.EmailSendError) as refused:
            email_send.smtp_send(cfg, _message(cfg))
    _assert_nothing_sent(server)
    assert refused.value.category == "certificate"
    assert refused.value.message.startswith(
        f"{CERTIFICATE}: unable to get local issuer certificate. "), refused.value.message


def test_a_certificate_for_another_name_is_named_as_the_reason(workdir, monkeypatch):
    authority = mail.authority()
    _trust(monkeypatch, authority[0])
    with _serve(workdir, ["mail.example.invalid"], issuer=authority) as server:
        cfg = _cfg(server.port)
        with pytest.raises(email_send.EmailSendError) as refused:
            email_send.smtp_send(cfg, _message(cfg))
    _assert_nothing_sent(server)
    assert refused.value.category == "certificate"
    assert refused.value.message.startswith(
        f"{CERTIFICATE}: IP address mismatch, certificate is not valid for '127.0.0.1'. "), \
        refused.value.message


def test_a_verified_certificate_still_sends(workdir, monkeypatch):
    authority = mail.authority()
    _trust(monkeypatch, authority[0])
    with _serve(workdir, ["127.0.0.1"], issuer=authority) as server:
        cfg = _cfg(server.port)
        email_send.smtp_send(cfg, _message(cfg))
    assert [s["tls"] for s in server.sessions] == ["ok"]
    assert server.sessions[0]["auth"] and "not-a-real-token" in server.sessions[0]["message"]


def test_the_reason_is_one_printable_line():
    failure = ssl.SSLCertVerificationError(1, "certificate verify failed")
    failure.verify_code, failure.verify_message = 62, "Hostname mismatch,\r\ncertificate.\n"
    error = email_send.certificate_not_verified(failure, "mail\r\n.example.test", 25)
    assert "\r" not in error.message and "\n" not in error.message
    assert error.message.startswith(f"{CERTIFICATE}: Hostname mismatch,  certificate. ")
    assert "sent to mail  .example.test:25." in error.message


def test_the_settings_test_send_answers_with_the_same_message(workdir, monkeypatch):
    import sqlalchemy as sa
    from pathlib import Path
    from sqlalchemy.orm import sessionmaker

    from app.api import api_server as api
    from app.core.models import AuditLog, RoleEnum, SystemSetting, User

    engine = sa.create_engine(f"sqlite:///{Path(workdir) / 'settings.db'}")
    for model in (User, AuditLog, SystemSetting):
        model.__table__.create(engine)
    db = sessionmaker(bind=engine)()
    try:
        admin = User(username="admin", email="admin@example.test", password_hash="x",
                     role=RoleEnum.ADMIN, is_active=True, is_locked=False)
        db.add(admin)
        with _serve(workdir, ["mail.example.invalid"]) as server:
            db.add(SystemSetting(key="global", value=_cfg(server.port)))
            db.commit()
            with pytest.raises(HTTPException) as refused:
                run_coroutine(api.send_test_email(
                    request=SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.10")),
                    current_user=admin, db=db))
    finally:
        db.close()
        engine.dispose()
    _assert_nothing_sent(server)
    assert refused.value.status_code == 502
    assert refused.value.detail.startswith(f"{CERTIFICATE}: self-signed certificate. "), \
        refused.value.detail


def test_email_studio_profile_test_answers_with_the_same_message(workdir):
    with _serve(workdir, ["mail.example.invalid"]) as server:
        payload = studio.ProfileTestIn(
            smtp_server="127.0.0.1", smtp_port=server.port, smtp_username="relay-user",
            smtp_password=PASSWORD, from_email="vault@example.test", to_addr="someone@example.test")
        with pytest.raises(HTTPException) as refused:
            run_coroutine(studio.test_profile(
                payload=payload,
                request=SimpleNamespace(headers={}, client=SimpleNamespace(host="192.0.2.10")),
                admin=SimpleNamespace(id=uuid.uuid4(), email="admin@example.test"), db=None))
    _assert_nothing_sent(server)
    assert refused.value.status_code == 502
    assert refused.value.detail.startswith(f"{CERTIFICATE}: self-signed certificate. "), \
        refused.value.detail
