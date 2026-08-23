"""Shared SMTP sending + sending-profile resolution.

Used by the Email Studio (profile test-sends and, later, template sends) AND by the vault's own
system mail (email-change verification). Centralizing the connect / STARTTLS-strip-defense /
login / send sequence keeps the two paths from drifting apart.

Failures are raised as a categorized :class:`EmailSendError` (never a bare SMTP exception and never
the password); callers map the category to an HTTP status. The module depends only on the standard
library + SQLAlchemy models, so it stays importable without FastAPI.
"""

from __future__ import annotations

import smtplib
import ssl
from email.message import EmailMessage
from typing import Optional

from sqlalchemy.orm import Session

# The single global settings blob that held the SMTP config before sending profiles existed. System
# mail falls back to it when no default profile is configured, so an already-running deployment keeps
# sending during and after the switch to profiles.
_LEGACY_SETTINGS_KEY = "global"


class EmailSendError(Exception):
    """A send failure classified as 'config' (400-worthy), 'auth', or 'transport' (502-worthy)."""

    def __init__(self, category: str, message: str):
        super().__init__(message)
        self.category = category
        self.message = message


def _profile_to_cfg(p) -> dict:
    return {
        "smtp_server": p.smtp_server or "",
        "smtp_port": p.smtp_port or 587,
        "smtp_username": p.smtp_username or "",
        "smtp_password": p.smtp_password or "",
        "from_email": p.from_email or "",
        "from_name": p.from_name or "",
    }


def _legacy_cfg(db: Session) -> dict:
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _LEGACY_SETTINGS_KEY).first()
    cfg = dict(row.value) if row and row.value else {}
    return {
        "smtp_server": cfg.get("smtp_server") or "",
        "smtp_port": cfg.get("smtp_port") or 587,
        "smtp_username": cfg.get("smtp_username") or "",
        "smtp_password": cfg.get("smtp_password") or "",
        "from_email": cfg.get("from_email") or "",
        "from_name": cfg.get("from_name") or "",
    }


def default_profile(db: Session):
    """The single default EmailProfile, or None. Deterministic order in case an old row ever slipped
    past the partial-unique-index backstop."""
    from app.core.models import EmailProfile
    return (db.query(EmailProfile)
            .filter(EmailProfile.is_default.is_(True))
            .order_by(EmailProfile.created_at, EmailProfile.id)
            .first())


def resolve_default_config(db: Session) -> Optional[dict]:
    """The config the vault's own system mail sends through: the default profile if there is one,
    otherwise the legacy global SMTP config. None when neither has both a server and a From address."""
    p = default_profile(db)
    cfg = _profile_to_cfg(p) if p else _legacy_cfg(db)
    if (cfg.get("smtp_server") or "").strip() and (cfg.get("from_email") or "").strip():
        return cfg
    return None


def smtp_configured(db: Session) -> bool:
    """True when system mail can send — i.e. resolve_default_config finds a usable config."""
    return resolve_default_config(db) is not None


def seed_default_profile(db: Session) -> bool:
    """One-time import: if NO profiles exist yet and the legacy global SMTP config has a server + From
    address, copy it into a default EmailProfile so system mail and the new UI start from the config
    the deployment already had. Idempotent — a no-op once any profile exists. Returns True if seeded."""
    from app.core.models import EmailProfile
    if db.query(EmailProfile.id).first() is not None:
        return False
    legacy = _legacy_cfg(db)
    if not ((legacy.get("smtp_server") or "").strip() and (legacy.get("from_email") or "").strip()):
        return False
    try:
        port = int(legacy.get("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    db.add(EmailProfile(
        name="Default",
        description="Imported from the previous Email settings.",
        smtp_server=legacy["smtp_server"].strip(),
        smtp_port=port,
        smtp_username=(legacy.get("smtp_username") or "").strip() or None,
        smtp_password=legacy.get("smtp_password") or None,
        from_email=legacy["from_email"].strip(),
        from_name=(legacy.get("from_name") or "").strip() or None,
        is_default=True,
    ))
    db.commit()
    return True


def build_message(cfg: dict, *, to_addr: str, subject: str, text_body: str,
                  html_body: Optional[str] = None, inline_images=None) -> EmailMessage:
    """Build an EmailMessage (rejects header injection via EmailMessage). Raises EmailSendError
    ('config') on a malformed From/subject/address. ``inline_images`` is an iterable of objects with
    ``.cid``, ``.content_type`` and ``.data`` attributes, embedded as multipart/related parts."""
    try:
        msg = EmailMessage()
        msg["Subject"] = subject
        from_email = (cfg.get("from_email") or "").strip()
        from_name = (cfg.get("from_name") or "").strip()
        msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
        msg["To"] = to_addr
        msg.set_content(text_body or "")
        if html_body is not None:
            msg.add_alternative(html_body, subtype="html")
            if inline_images:
                html_part = msg.get_payload()[-1]
                for img in inline_images:
                    maintype, _, subtype = (img.content_type or "image/png").partition("/")
                    html_part.add_related(img.data, maintype=maintype or "image",
                                          subtype=subtype or "png", cid=f"<{img.cid}>")
        return msg
    except (ValueError, UnicodeError) as e:
        # Log the detail server-side; return a generic message (never the exception class/detail).
        print(f"[email] message build failed: {type(e).__name__}: {e}")
        raise EmailSendError(
            "config", "The email could not be built — check the From name and address.")


def _smtp_tls_context(cfg: dict) -> "ssl.SSLContext":
    """The SSL context for the SMTP connection. Verifies the server certificate by default
    (check_hostname + CERT_REQUIRED). When the profile opts into insecure TLS
    (``smtp_allow_insecure_tls`` — e.g. an internal relay with a self-signed cert) the connection is
    still encrypted but the certificate is NOT verified."""
    ctx = ssl.create_default_context()
    if cfg.get("smtp_allow_insecure_tls"):
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    return ctx


def smtp_send(cfg: dict, msg: EmailMessage) -> None:
    """Send ``msg`` using ``cfg`` (server/port/username/password). Connect over SSL (465) or STARTTLS,
    NEVER send credentials over an unencrypted connection (STARTTLS-strip defense), and translate
    every failure into an EmailSendError — never leaking the password."""
    host = (cfg.get("smtp_server") or "").strip()
    from_email = (cfg.get("from_email") or "").strip()
    if not host or not from_email:
        raise EmailSendError("config", "SMTP is not configured")
    try:
        port = int(cfg.get("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    username = (cfg.get("smtp_username") or "").strip()
    password = cfg.get("smtp_password") or ""
    try:
        # Verify the server's TLS certificate on BOTH implicit-TLS (465) and STARTTLS (default), so an
        # active on-path attacker can't present a forged cert and capture the SMTP credentials / mail.
        # smtplib's default context does NOT verify; a profile may opt out via smtp_allow_insecure_tls.
        tls_ctx = _smtp_tls_context(cfg)
        server = (smtplib.SMTP_SSL(host, port, timeout=15, context=tls_ctx)
                  if port == 465 else smtplib.SMTP(host, port, timeout=15))
        with server:
            server.ehlo()
            encrypted = port == 465
            if port != 465 and server.has_extn("starttls"):
                server.starttls(context=tls_ctx)
                server.ehlo()
                encrypted = True
            if username and not encrypted:
                raise EmailSendError(
                    "transport",
                    "The SMTP server does not offer STARTTLS; refusing to send credentials over an unencrypted connection.")
            if username:
                server.login(username, password)
            server.send_message(msg)
    except EmailSendError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise EmailSendError("auth", "SMTP authentication failed — check the username and password.")
    except (ValueError, UnicodeError) as e:
        print(f"[email] send config invalid: {type(e).__name__}: {e}")
        raise EmailSendError(
            "config", "The SMTP configuration is invalid — check the server address and the From name/address.")
    except (smtplib.SMTPException, OSError) as e:
        # Log the detail server-side; return ONE generic message for every transport outcome so the
        # response cannot be used to distinguish a closed port / filtered host / non-SMTP service
        # (an internal-network probe oracle).
        print(f"[email] send failed: {type(e).__name__}: {e}")
        raise EmailSendError(
            "transport", "Could not send the email — check the SMTP server, port, and TLS settings.")


def smtp_send_batch(cfg: dict, messages: list) -> list:
    """Send several pre-built messages over ONE connection. Returns a list of
    ``{"ok": bool, "error": str|None}`` aligned with ``messages``.

    A connect/login/STARTTLS-strip failure raises EmailSendError (the whole batch cannot start). Once
    connected, a per-message failure marks only that message failed (with a GENERIC 'delivery failed'
    — never a leaked detail) and the loop continues, so one bad recipient doesn't sink the rest."""
    host = (cfg.get("smtp_server") or "").strip()
    from_email = (cfg.get("from_email") or "").strip()
    if not host or not from_email:
        raise EmailSendError("config", "SMTP is not configured")
    try:
        port = int(cfg.get("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    username = (cfg.get("smtp_username") or "").strip()
    password = cfg.get("smtp_password") or ""
    results = [{"ok": False, "error": "not attempted"} for _ in messages]
    try:
        # Verify the server's TLS certificate on both implicit-TLS (465) and STARTTLS (see smtp_send);
        # a profile may opt out via smtp_allow_insecure_tls.
        tls_ctx = _smtp_tls_context(cfg)
        server = (smtplib.SMTP_SSL(host, port, timeout=30, context=tls_ctx)
                  if port == 465 else smtplib.SMTP(host, port, timeout=30))
        with server:
            server.ehlo()
            encrypted = port == 465
            if port != 465 and server.has_extn("starttls"):
                server.starttls(context=tls_ctx)
                server.ehlo()
                encrypted = True
            if username and not encrypted:
                raise EmailSendError(
                    "transport",
                    "The SMTP server does not offer STARTTLS; refusing to send credentials over an unencrypted connection.")
            if username:
                server.login(username, password)
            for i, msg in enumerate(messages):
                try:
                    server.send_message(msg)
                    results[i] = {"ok": True, "error": None}
                except (smtplib.SMTPException, OSError, ValueError, UnicodeError) as e:
                    print(f"[email] per-recipient send failed: {type(e).__name__}: {e}")
                    results[i] = {"ok": False, "error": "delivery failed"}
    except EmailSendError:
        raise
    except smtplib.SMTPAuthenticationError:
        raise EmailSendError("auth", "SMTP authentication failed — check the username and password.")
    except (ValueError, UnicodeError) as e:
        print(f"[email] batch config invalid: {type(e).__name__}: {e}")
        raise EmailSendError(
            "config", "The SMTP configuration is invalid — check the server address and the From name/address.")
    except (smtplib.SMTPException, OSError) as e:
        print(f"[email] batch connect failed: {type(e).__name__}: {e}")
        raise EmailSendError(
            "transport", "Could not connect to the SMTP server — check the server, port, and TLS settings.")
    return results
