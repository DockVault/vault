"""Unit tests for app.core.email_send — the shared SMTP sender (no network, no DB).

A fake SMTP client captures how smtp_send drives the connection, so these prove the behaviors an
end-to-end Mailpit test can't easily reach without real TLS: the configured password is what gets
used to authenticate, the STARTTLS-strip defense refuses credentials over cleartext, and every
failure maps to a categorized EmailSendError with a GENERIC message (no exception detail/class name,
no password).
"""

import smtplib

import pytest

from app.core import email_send as es

pytestmark = pytest.mark.unit


class _FakeSMTP:
    """Records the connect/ehlo/starttls/login/send sequence. Configurable failure injection."""
    last = None

    def __init__(self, host, port, timeout=None, context=None):
        self.host, self.port = host, port
        self.tls_context = context          # SMTP_SSL now passes a verifying ssl context
        self.starttls_called = False
        self.logged_in = None
        self.sent = []
        self.extns = {"starttls"}          # advertise STARTTLS by default
        self.login_exc = None
        self.send_exc = None
        self._send_n = 0
        self.fail_send_indices = set()     # 0-based send_message calls that should fail
        _FakeSMTP.last = self

    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False

    def ehlo(self):
        pass

    def has_extn(self, name):
        return name in self.extns

    def starttls(self, *a, **k):
        self.starttls_called = True
        self.starttls_context = k.get("context")

    def login(self, user, password):
        if self.login_exc:
            raise self.login_exc
        self.logged_in = (user, password)

    def send_message(self, msg):
        i = self._send_n
        self._send_n += 1
        if self.send_exc:
            raise self.send_exc
        if i in self.fail_send_indices:
            raise smtplib.SMTPRecipientsRefused({})
        self.sent.append(msg)


@pytest.fixture
def fake_smtp(monkeypatch):
    # Patch BOTH constructors; configure the instance via _FakeSMTP.last after the call.
    monkeypatch.setattr(smtplib, "SMTP_SSL", _FakeSMTP)
    monkeypatch.setattr(smtplib, "SMTP", _FakeSMTP)
    _FakeSMTP.last = None
    return _FakeSMTP


def _cfg(**over):
    c = {"smtp_server": "smtp.example.com", "smtp_port": 587, "smtp_username": "",
         "smtp_password": "", "from_email": "from@example.com", "from_name": "V"}
    c.update(over)
    return c


def _msg(cfg, to="rcpt@example.com"):
    return es.build_message(cfg, to_addr=to, subject="s", text_body="hi")


def test_send_uses_configured_password_over_ssl(fake_smtp):
    cfg = _cfg(smtp_port=465, smtp_username="user@x", smtp_password="Stored-Pw-42")
    es.smtp_send(cfg, _msg(cfg))
    assert fake_smtp.last.logged_in == ("user@x", "Stored-Pw-42")   # the STORED password is used
    assert len(fake_smtp.last.sent) == 1
    assert fake_smtp.last.starttls_called is False                  # 465 is already encrypted


def test_starttls_used_then_login_when_advertised(fake_smtp):
    cfg = _cfg(smtp_port=587, smtp_username="u", smtp_password="p")
    es.smtp_send(cfg, _msg(cfg))
    assert fake_smtp.last.starttls_called is True
    assert fake_smtp.last.logged_in == ("u", "p")


def test_implicit_tls_uses_verifying_context(fake_smtp):
    import ssl as _ssl
    cfg = _cfg(smtp_port=465, smtp_username="u", smtp_password="p")
    es.smtp_send(cfg, _msg(cfg))
    ctx = fake_smtp.last.tls_context
    assert isinstance(ctx, _ssl.SSLContext), "SMTP_SSL must be given an ssl context"
    assert ctx.check_hostname is True and ctx.verify_mode == _ssl.CERT_REQUIRED, \
        "implicit-TLS (465) must verify the server certificate"


def test_starttls_uses_verifying_context(fake_smtp):
    import ssl as _ssl
    cfg = _cfg(smtp_port=587, smtp_username="u", smtp_password="p")
    es.smtp_send(cfg, _msg(cfg))
    ctx = getattr(fake_smtp.last, "starttls_context", None)
    assert isinstance(ctx, _ssl.SSLContext), "starttls() must be given an ssl context"
    assert ctx.check_hostname is True and ctx.verify_mode == _ssl.CERT_REQUIRED, \
        "STARTTLS must verify the server certificate"


def test_allow_insecure_tls_uses_unverified_context(fake_smtp):
    import ssl as _ssl
    # Implicit TLS (465) with the opt-out -> encrypted but NOT verifying.
    cfg = _cfg(smtp_port=465, smtp_username="u", smtp_password="p", smtp_allow_insecure_tls=True)
    es.smtp_send(cfg, _msg(cfg))
    ctx = fake_smtp.last.tls_context
    assert isinstance(ctx, _ssl.SSLContext)
    assert ctx.check_hostname is False and ctx.verify_mode == _ssl.CERT_NONE, \
        "smtp_allow_insecure_tls must skip certificate verification"
    # STARTTLS (587) with the opt-out -> same.
    cfg587 = _cfg(smtp_port=587, smtp_username="u", smtp_password="p", smtp_allow_insecure_tls=True)
    es.smtp_send(cfg587, _msg(cfg587))
    sctx = fake_smtp.last.starttls_context
    assert sctx.check_hostname is False and sctx.verify_mode == _ssl.CERT_NONE


def test_plaintext_no_auth_send_is_allowed(fake_smtp):
    # Mailpit-style: a plaintext port with NO STARTTLS and NO username sends fine and is never
    # blocked — the cleartext-credential guard only triggers when a username is set, and TLS
    # verification only applies to 465/STARTTLS (neither used here).
    cfg = _cfg(smtp_port=1025, smtp_username="", smtp_password="")
    import app.core.email_send as m
    def _plain(host, port, timeout=None, context=None):
        inst = _FakeSMTP(host, port, timeout)
        inst.extns = set()          # no STARTTLS advertised (like Mailpit's default)
        return inst
    m.smtplib.SMTP = _plain
    es.smtp_send(cfg, _msg(cfg))     # must not raise
    assert len(_FakeSMTP.last.sent) == 1
    assert _FakeSMTP.last.logged_in is None
    assert _FakeSMTP.last.starttls_called is False


def test_starttls_strip_defense_refuses_login_over_cleartext(fake_smtp):
    cfg = _cfg(smtp_port=587, smtp_username="u", smtp_password="p")
    # Server does NOT advertise STARTTLS -> credentials must not be sent.
    def _no_starttls(host, port, timeout=None, context=None):
        inst = _FakeSMTP(host, port, timeout)
        inst.extns = set()
        return inst
    import app.core.email_send as m
    m.smtplib.SMTP = _no_starttls
    with pytest.raises(es.EmailSendError) as ei:
        es.smtp_send(cfg, _msg(cfg))
    assert ei.value.category == "transport"
    assert _FakeSMTP.last.logged_in is None                         # never logged in


def test_no_login_without_username(fake_smtp):
    cfg = _cfg(smtp_port=587, smtp_username="", smtp_password="")
    es.smtp_send(cfg, _msg(cfg))
    assert fake_smtp.last.logged_in is None
    assert len(fake_smtp.last.sent) == 1


def test_auth_error_maps_to_auth_category(fake_smtp):
    cfg = _cfg(smtp_port=465, smtp_username="u", smtp_password="bad")
    orig = smtplib.SMTP_SSL
    def _mk(host, port, timeout=None, context=None):
        inst = orig(host, port, timeout)
        inst.login_exc = smtplib.SMTPAuthenticationError(535, b"nope")
        return inst
    smtplib.SMTP_SSL = _mk
    with pytest.raises(es.EmailSendError) as ei:
        es.smtp_send(cfg, _msg(cfg))
    assert ei.value.category == "auth"


def _transport_message_for(exc):
    cfg = _cfg(smtp_port=465)
    orig = smtplib.SMTP_SSL
    def _mk(host, port, timeout=None, context=None):
        inst = orig(host, port, timeout)
        inst.send_exc = exc
        return inst
    smtplib.SMTP_SSL = _mk
    try:
        with pytest.raises(es.EmailSendError) as ei:
            es.smtp_send(cfg, _msg(cfg))
        return ei.value
    finally:
        smtplib.SMTP_SSL = orig


def test_transport_error_message_leaks_no_detail_and_gives_no_oracle(fake_smtp):
    refused = _transport_message_for(ConnectionRefusedError("Connection refused to 10.0.0.1:22"))
    filtered = _transport_message_for(smtplib.SMTPServerDisconnected("service not available"))
    assert refused.category == "transport" and filtered.category == "transport"
    # The message may echo the admin's OWN configured host:port (helpful), but must not leak the
    # exception class/detail...
    for m in (refused.message, filtered.message):
        assert "ConnectionRefused" not in m and "SMTPServerDisconnected" not in m
        assert "10.0.0.1" not in m and "not available" not in m
    # ...and must be IDENTICAL across failure modes, so it can't be used to probe internal ports.
    assert refused.message == filtered.message


def test_missing_server_raises_config(fake_smtp):
    with pytest.raises(es.EmailSendError) as ei:
        es.smtp_send(_cfg(smtp_server=""), _msg(_cfg()))
    assert ei.value.category == "config"


def test_build_message_rejects_header_injection():
    with pytest.raises(es.EmailSendError) as ei:
        es.build_message(_cfg(), to_addr="a@x.example\r\nBcc: evil@x.example", subject="s", text_body="b")
    assert ei.value.category == "config"


def test_build_message_text_only_shape():
    msg = es.build_message(_cfg(from_name="Ops"), to_addr="r@x.example", subject="Hello", text_body="Body")
    assert msg["Subject"] == "Hello"
    assert msg["To"] == "r@x.example"
    assert "Ops" in msg["From"] and "from@example.com" in msg["From"]
    assert "Body" in msg.get_content()


def test_batch_sends_all_over_one_connection(fake_smtp):
    cfg = _cfg(smtp_port=465, smtp_username="u", smtp_password="p")
    msgs = [_msg(cfg, to=f"r{i}@x.example") for i in range(3)]
    out = es.smtp_send_batch(cfg, msgs)
    assert [o["ok"] for o in out] == [True, True, True]
    assert len(fake_smtp.last.sent) == 3            # one connection, three messages
    assert fake_smtp.last.logged_in == ("u", "p")   # authenticated once


def test_batch_per_message_failure_is_isolated(fake_smtp):
    cfg = _cfg(smtp_port=465)
    def _mk(host, port, timeout=None, context=None):
        inst = _FakeSMTP(host, port, timeout)
        inst.fail_send_indices = {1}                # only the 2nd recipient fails
        return inst
    smtplib.SMTP_SSL = _mk
    out = es.smtp_send_batch(cfg, [_msg(cfg, to=f"r{i}@x.example") for i in range(3)])
    assert out[0]["ok"] is True and out[2]["ok"] is True
    assert out[1]["ok"] is False and out[1]["error"] == "delivery failed"   # generic, no detail


def test_batch_connect_failure_raises(fake_smtp):
    cfg = _cfg(smtp_port=465)
    def _mk(host, port, timeout=None, context=None):
        raise ConnectionRefusedError("nope")
    smtplib.SMTP_SSL = _mk
    with pytest.raises(es.EmailSendError) as ei:
        es.smtp_send_batch(cfg, [_msg(cfg)])
    assert ei.value.category == "transport"


def test_build_message_html_with_inline_image():
    class _Img:
        cid = "img0"
        content_type = "image/png"
        data = b"\x89PNG"
    msg = es.build_message(_cfg(), to_addr="r@x.example", subject="s", text_body="alt",
                           html_body='<p>hi <img src="cid:img0"></p>', inline_images=[_Img()])
    assert msg.is_multipart()
    # the PNG rides along as a related part
    assert any(part.get_content_type() == "image/png" for part in msg.walk())
