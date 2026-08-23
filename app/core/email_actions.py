"""The catalog of cases where the vault sends email, and the CENTRAL send helper for them.

An *email action* is a stable key (e.g. ``password_reset``) that application code references when a
flow needs to send mail. Each action is bound to an :class:`EmailTemplate`. A ``system`` action is
one the vault must be able to send — its bound template can't be deleted and it's always on. An
``optional`` action is opt-in per admin via a "notify by email" switch (``enabled``), the hook a
future trigger (file share, vault-member add, …) consults before sending.

Delivery and dynamic-token injection live in ONE place — :func:`send_action_email`. A trigger only
supplies the action key, the recipient, and any per-send context (a link / code / expiry). No trigger
builds SMTP config or renders HTML itself.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

SYSTEM = "system"
OPTIONAL = "optional"

# --------------------------------------------------------------------------------------------------
# The seeded catalog. `default_subject` / `default_body_html` seed a system action's template on first
# init and are the built-in fallback if a system action is ever left without one. Bodies use only
# allowlisted tags + dynamic tokens (no inline style — the sanitizer strips it).
# --------------------------------------------------------------------------------------------------
ACTION_CATALOG: tuple[dict, ...] = (
    {
        "key": "email_change",
        "name": "Email change verification",
        "description": "Sent to a new address when a user changes their email — carries the confirmation code.",
        "category": SYSTEM,
        "default_subject": "Confirm your new email address",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>Use this code to confirm your new email address for <strong>{{vault.name}}</strong>:</p>"
            "<h2>{{action.code}}</h2>"
            "<p>The code expires {{action.expires}}. If you didn't request this change, you can ignore this email.</p>"
        ),
    },
    {
        "key": "password_reset",
        "name": "Password reset",
        "description": "Sent when a user requests a password reset — carries the reset link.",
        "category": SYSTEM,
        "default_subject": "Reset your password",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>We received a request to reset your <strong>{{vault.name}}</strong> password.</p>"
            "<p><a href=\"{{action.link}}\">Reset your password</a></p>"
            "<p>This link expires {{action.expires}}. If you didn't request a reset, you can ignore this email.</p>"
        ),
    },
    {
        "key": "account_invite",
        "name": "Account invitation",
        "description": "Sent when an admin invites someone to create an account — carries the invitation link.",
        "category": SYSTEM,
        "default_subject": "You're invited to {{vault.name}}",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>You've been invited to create an account on <strong>{{vault.name}}</strong>.</p>"
            "<p><a href=\"{{action.link}}\">Accept your invitation</a></p>"
            "<p>This invitation expires {{action.expires}}.</p>"
        ),
    },
    {
        "key": "account_welcome",
        "name": "Welcome email",
        "description": "Optional — sent after an account is created.",
        "category": OPTIONAL,
        "default_subject": "Welcome to {{vault.name}}",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>Your account on <strong>{{vault.name}}</strong> is ready.</p>"
            "<p><a href=\"{{vault.url}}\">Open {{vault.name}}</a></p>"
        ),
    },
    {
        "key": "login_alert",
        "name": "New sign-in alert",
        "description": "Optional — notify a user when their account signs in.",
        "category": OPTIONAL,
        "default_subject": "New sign-in to your {{vault.name}} account",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>Your <strong>{{vault.name}}</strong> account was signed in to on {{current_datetime}} UTC.</p>"
            "<p>If this wasn't you, change your password.</p>"
        ),
    },
    {
        "key": "share_created",
        "name": "File / folder shared",
        "description": "Optional — notify a recipient when something is shared with them.",
        "category": OPTIONAL,
        "default_subject": "Something was shared with you on {{vault.name}}",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>Something was shared with you on <strong>{{vault.name}}</strong>.</p>"
            "<p><a href=\"{{action.link}}\">Open the share</a></p>"
        ),
    },
    {
        "key": "vault_member_added",
        "name": "Added to a vault",
        "description": "Optional — notify a user when they're added to a vault or team.",
        "category": OPTIONAL,
        "default_subject": "You were added to a vault on {{vault.name}}",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>You've been given access to a vault on <strong>{{vault.name}}</strong>.</p>"
            "<p><a href=\"{{vault.url}}\">Open {{vault.name}}</a></p>"
        ),
    },
    {
        "key": "temp_credential_issued",
        "name": "Temporary credential issued",
        "description": "Optional — notify a user when a temporary access credential is created for them.",
        "category": OPTIONAL,
        "default_subject": "A temporary access credential was issued",
        "default_body_html": (
            "<p>Hi {{user.username}},</p>"
            "<p>A temporary access credential was issued for your <strong>{{vault.name}}</strong> access.</p>"
            "<p>It expires {{action.expires}}.</p>"
        ),
    },
)

SPEC_BY_KEY: dict[str, dict] = {a["key"]: a for a in ACTION_CATALOG}


# --------------------------------------------------------------------------------------------------
# Small self-contained helpers (kept here to avoid importing the FastAPI router).
# --------------------------------------------------------------------------------------------------
def brand_name(db: Session) -> str:
    try:
        from app.config.effective import get_effective_branding
        return get_effective_branding(db).app_name or ""
    except Exception:
        return ""


def vault_url() -> str:
    """Best-effort public base URL for ``{{vault.url}}`` from the first ALLOWED_HOSTS entry; empty
    when nothing usable is configured. Never raises."""
    try:
        from app.core.config import settings
        raw = (settings.allowed_hosts or "").strip()
    except Exception:
        return ""
    for host in (h.strip() for h in raw.split(",")):
        if not host or host in ("*", "0.0.0.0") or host.startswith("."):
            continue
        if host.startswith("http://") or host.startswith("https://"):
            return host.rstrip("/")
        return f"https://{host}".rstrip("/")
    return ""


def _load_resource(db: Session, rid: str):
    from app.core.models import EmailResource
    import uuid as _uuid
    try:
        row = (db.query(EmailResource.content_type, EmailResource.data)
               .filter(EmailResource.id == _uuid.UUID(str(rid))).first())
    except (ValueError, TypeError):
        return None
    return (row[0], row[1]) if row else None


# --------------------------------------------------------------------------------------------------
# Seed
# --------------------------------------------------------------------------------------------------
def seed_email_actions(db: Session) -> int:
    """Idempotently ensure every cataloged action exists. Actions are seeded WITHOUT a bound template:
    a system action sends with its built-in default body until an admin binds a custom template, and
    an optional action is seeded disabled. This keeps the user-facing template grid empty by default
    (the built-in bodies live in code, not the DB, so there is nothing to accidentally delete). System
    actions are seeded enabled. Metadata is refreshed from the catalog; an admin's template/enabled
    choices are never overwritten. Returns the number of actions created."""
    from app.core.models import EmailAction

    created = 0
    changed = False
    for spec in ACTION_CATALOG:
        action = db.get(EmailAction, spec["key"])
        if action is None:
            db.add(EmailAction(key=spec["key"], name=spec["name"], description=spec["description"],
                               category=spec["category"], enabled=(spec["category"] == SYSTEM)))
            created += 1
            changed = True
        elif (action.name, action.description, action.category) != (spec["name"], spec["description"], spec["category"]):
            action.name, action.description, action.category = spec["name"], spec["description"], spec["category"]
            changed = True
    if changed:
        db.commit()
    return created


# --------------------------------------------------------------------------------------------------
# Central send helper
# --------------------------------------------------------------------------------------------------
def send_action_email(db: Session, key: str, *, recipient: dict,
                      action_context: Optional[dict] = None, force: bool = False,
                      raise_errors: bool = False) -> bool:
    """Send the email for a cataloged action. ``recipient`` = ``{email, username?, display_name?}``.
    Returns True if a message was handed to SMTP. By default NEVER raises for a delivery/config problem
    — it logs and returns False, so a caller flow (signup, share, …) isn't broken by mail trouble. A
    disabled optional action returns False unless ``force``. When ``raise_errors`` is set, an
    unconfigured/transport failure raises :class:`email_send.EmailSendError` instead (a critical flow
    like email-change verification maps it to a clean HTTP error). Delivery + token injection are
    centralized here."""
    from app.core.models import EmailAction, EmailProfile
    from app.core import email_sanitize, email_send

    to_addr = ((recipient or {}).get("email") or "").strip()
    if not to_addr:
        return False

    action = db.get(EmailAction, key)
    spec = SPEC_BY_KEY.get(key, {})
    if action is None and not spec:
        return False
    # An OPTIONAL action is off unless explicitly enabled — including the brief pre-seed window where
    # its DB row doesn't exist yet (default to the catalog category, disabled). System actions are on.
    category = action.category if action is not None else spec.get("category", OPTIONAL)
    enabled = action.enabled if action is not None else (category == SYSTEM)
    if category == OPTIONAL and not enabled and not force:
        return False

    template = action.template if action is not None else None
    if template is not None and (template.body_html or template.subject):
        subject_tpl = template.subject or spec.get("default_subject", "")
        body_tpl = template.body_html
    else:
        subject_tpl = spec.get("default_subject", "")
        body_tpl = spec.get("default_body_html", "")
    if not (subject_tpl or body_tpl):
        return False

    # Resolve the sending config: the template's profile if usable, else the default profile.
    cfg = None
    if template is not None and template.profile_id:
        p = db.get(EmailProfile, template.profile_id)
        if p is not None:
            cand = email_send._profile_to_cfg(p)          # decrypts the password
            if (cand.get("smtp_server") or "").strip() and (cand.get("from_email") or "").strip():
                cfg = cand
    if cfg is None:
        cfg = email_send.resolve_default_config(db)
    if cfg is None:                                        # no SMTP configured
        if raise_errors:
            raise email_send.EmailSendError(
                "config", "Email is not configured. Add a sending profile in Settings → Email first.")
        return False

    # Render AND send inside one try so a rendering error maps the same clean way as a send error
    # (a raw exception would otherwise become a 500 on the email-change flow instead of a 400/502).
    try:
        ctx = email_sanitize.token_context(
            recipient=recipient, brand_name=brand_name(db), vault_url=vault_url(),
            sender={"from_name": cfg.get("from_name") or "", "from_email": cfg.get("from_email") or ""},
            action=action_context or {})
        subject = email_sanitize.render_subject(subject_tpl, ctx)
        html, inline = email_sanitize.render_for_send(
            body_tpl, context=ctx, load_resource=lambda rid: _load_resource(db, rid))
        text = email_sanitize.render_plaintext_fallback(html)
        msg = email_send.build_message(cfg, to_addr=to_addr, subject=subject,
                                       text_body=text, html_body=html, inline_images=inline)
        email_send.smtp_send(cfg, msg)
    except email_send.EmailSendError as e:
        print(f"[email] action '{key}' send failed: {e.category}: {e.message}")
        if raise_errors:
            raise
        return False
    except Exception as e:                                  # never let mail trouble break a caller flow
        print(f"[email] action '{key}' unexpected error: {type(e).__name__}")
        if raise_errors:
            raise email_send.EmailSendError("transport", "The email could not be prepared or sent.")
        return False
    return True
