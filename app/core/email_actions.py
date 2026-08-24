"""The catalog of cases where the vault sends email, and the CENTRAL send helper for them.

An *email action* is a stable key (e.g. ``password_reset``) that application code references when a
flow needs to send mail. Each action is bound to an :class:`EmailTemplate`. A ``system`` action is
one the vault must be able to send — its bound template can't be deleted and it's always on. An
``optional`` action is opt-in per admin via a "notify by email" switch (``enabled``), the hook a
future trigger (file share, vault-member add, …) consults before sending.

Delivery and dynamic-token injection live in ONE place — :func:`send_action_email`. A trigger only
supplies the action key, the recipient, and any per-send context (a link / code / expiry). No trigger
builds SMTP config or renders HTML itself.

Each action also has a built-in DEFAULT TEMPLATE (:data:`DEFAULT_TEMPLATES`) — a polished, ready-to-send
HTML body using only allowlisted tags + dynamic tokens. :func:`seed_default_templates` materializes these
as real :class:`EmailTemplate` rows and pre-binds each action to its default on first boot, so the
Automated-emails grid ships usable out of the box. The same bodies remain in code as the send-time
fallback and as the "Load From → defaults" source, so a default is always recoverable.
"""
from __future__ import annotations

from typing import Optional

from sqlalchemy.orm import Session

SYSTEM = "system"
OPTIONAL = "optional"

# --------------------------------------------------------------------------------------------------
# Built-in default templates. `name`/`subject`/`body_html` seed a real EmailTemplate row per action
# (seed_default_templates) AND are the send-time fallback body when an action is left unbound. Bodies
# use ONLY allowlisted tags (h1-h2, p, strong, a, hr, small — no inline style/class; the sanitizer
# strips those) + dynamic tokens. A SYSTEM security action's body MUST carry its required token
# ({{action.code}} for email_change, {{action.link}} for password_reset/account_invite) — the send
# helper falls back to the built-in body if a customized template ever drops it.
# --------------------------------------------------------------------------------------------------
DEFAULT_TEMPLATES: dict[str, dict] = {
    "email_change": {
        "name": "Email change verification",
        "subject": "Confirm your new email address",
        "body_html": (
            "<h2>Confirm your new email address</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>Use this code to confirm your new email address for <strong>{{vault.name}}</strong>:</p>"
            "<h1>{{action.code}}</h1>"
            "<p>This code expires {{action.expires}}. If you didn't request this change, you can safely "
            "ignore this email — your address won't be changed.</p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "password_reset": {
        "name": "Password reset",
        "subject": "Reset your password",
        "body_html": (
            "<h2>Reset your password</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>We received a request to reset the password for your <strong>{{vault.name}}</strong> account.</p>"
            "<p><a href=\"{{action.link}}\">Choose a new password</a></p>"
            "<p>This link expires {{action.expires}} and can be used once. If you didn't request a reset, "
            "you can ignore this email — your password won't change.</p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "account_invite": {
        "name": "Account invitation",
        "subject": "You're invited to {{vault.name}}",
        "body_html": (
            "<h2>You're invited to {{vault.name}}</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>You've been invited to create an account on <strong>{{vault.name}}</strong>.</p>"
            "<p><a href=\"{{action.link}}\">Accept your invitation</a></p>"
            "<p>This invitation expires {{action.expires}}.</p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "account_welcome": {
        "name": "Welcome email",
        "subject": "Welcome to {{vault.name}}",
        "body_html": (
            "<h2>Welcome to {{vault.name}}</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>Your account on <strong>{{vault.name}}</strong> is ready to use.</p>"
            "<p><a href=\"{{vault.url}}\">Open {{vault.name}}</a></p>"
            "<p>If you have any questions, reply to this email or contact your administrator.</p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "login_alert": {
        "name": "New sign-in alert",
        "subject": "New sign-in to your {{vault.name}} account",
        "body_html": (
            "<h2>New sign-in to your account</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>Your <strong>{{vault.name}}</strong> account was signed in to on {{current_datetime}} (UTC).</p>"
            "<p>If this was you, no action is needed. If you don't recognize this sign-in, change your "
            "password right away.</p>"
            "<p><a href=\"{{vault.url}}\">Open {{vault.name}}</a></p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "share_created": {
        "name": "File / folder shared",
        "subject": "Something was shared with you on {{vault.name}}",
        "body_html": (
            "<h2>Something was shared with you</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>A file or folder was shared with you on <strong>{{vault.name}}</strong>.</p>"
            "<p><a href=\"{{action.link}}\">Open your shared items</a></p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "vault_member_added": {
        "name": "Added to a vault",
        "subject": "You were added to a vault on {{vault.name}}",
        "body_html": (
            "<h2>You were added to a vault</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>You've been given access to a vault on <strong>{{vault.name}}</strong>.</p>"
            "<p><a href=\"{{vault.url}}\">Open {{vault.name}}</a></p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
    "temp_credential_issued": {
        "name": "Temporary credential issued",
        "subject": "A temporary access credential was issued",
        "body_html": (
            "<h2>A temporary access credential was issued</h2>"
            "<p>Hi {{user.username}},</p>"
            "<p>A temporary access credential was issued for your <strong>{{vault.name}}</strong> access. "
            "It expires {{action.expires}}.</p>"
            "<p>If you didn't request this, contact your administrator.</p>"
            "<hr>"
            "<p><small>Sent by {{vault.name}}.</small></p>"
        ),
    },
}

# (key, name, description, category) for each cataloged action. Subject/body come from DEFAULT_TEMPLATES
# above, so the seeded template, the send-time fallback, and the "Load From" source are one and the same.
_ACTION_META: tuple[tuple[str, str, str, str], ...] = (
    ("email_change", "Email change verification",
     "Sent to a new address when a user changes their email — carries the confirmation code.", SYSTEM),
    ("password_reset", "Password reset",
     "Sent when a user requests a password reset — carries the reset link.", SYSTEM),
    ("account_invite", "Account invitation",
     "Sent when an admin invites someone to create an account — carries the invitation link.", SYSTEM),
    ("account_welcome", "Welcome email",
     "Optional — sent after an account is created.", OPTIONAL),
    ("login_alert", "New sign-in alert",
     "Optional — notify a user when their account signs in.", OPTIONAL),
    ("share_created", "File / folder shared",
     "Optional — notify a recipient when something is shared with them.", OPTIONAL),
    ("vault_member_added", "Added to a vault",
     "Optional — notify a user when they're added to a vault or team.", OPTIONAL),
    ("temp_credential_issued", "Temporary credential issued",
     "Optional — notify a user when a temporary access credential is created for them.", OPTIONAL),
)

ACTION_CATALOG: tuple[dict, ...] = tuple(
    {
        "key": key,
        "name": name,
        "description": description,
        "category": category,
        "default_subject": DEFAULT_TEMPLATES[key]["subject"],
        "default_body_html": DEFAULT_TEMPLATES[key]["body_html"],
        "default_template_name": DEFAULT_TEMPLATES[key]["name"],
    }
    for (key, name, description, category) in _ACTION_META
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
    """Idempotently ensure every cataloged action exists. Actions are seeded WITHOUT a bound template
    here; :func:`seed_default_templates` (called right after) materializes each action's default
    template and pre-binds it. System actions are seeded enabled; optional ones disabled. Metadata is
    refreshed from the catalog; an admin's template/enabled choices are never overwritten. Returns the
    number of actions created."""
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


def seed_default_templates(db: Session) -> int:
    """Idempotently materialize each action's built-in default template as an EmailTemplate row
    (identified by ``default_key``) and PRE-BIND the action to it when the action has no template yet.

    Runs after :func:`seed_email_actions` (the action rows must exist to bind). A default row is created
    only if one doesn't already exist for that key — so an admin's later customization of the default is
    never overwritten (the pristine code body stays available via "Load From"). Binding happens only at
    first creation and only when the action is currently unbound, so an admin's own template choice (or
    an explicit "none") is respected on every subsequent boot. Returns the number of templates created."""
    from sqlalchemy.exc import IntegrityError
    from app.core.models import EmailAction, EmailTemplate
    from app.core import email_sanitize

    created = 0
    for key, spec in DEFAULT_TEMPLATES.items():
        # A default row already exists (this boot or a prior one) -> leave it and its binding alone,
        # so an admin's later customization / "none" choice is never revived by a re-seed.
        if db.query(EmailTemplate).filter(EmailTemplate.default_key == key).first() is not None:
            continue
        tpl = EmailTemplate(
            name=spec["name"],
            description="Built-in default template.",
            subject=spec["subject"],
            body_html=email_sanitize.sanitize_email_html(spec["body_html"]),   # store only sanitized
            default_key=key,
        )
        try:
            # A SAVEPOINT so a conflict rolls back only this insert, not the templates already created
            # earlier in the loop. db.flush() assigns tpl.id for binding below.
            with db.begin_nested():
                db.add(tpl)
                db.flush()
        except IntegrityError:
            # A concurrent first boot won the partial-unique race on default_key; it will bind the
            # action — skip here so we don't double-bind.
            continue
        created += 1
        # Pre-bind the action to its brand-new default, but only when the admin hasn't already chosen a
        # template (or explicitly left it "none").
        action = db.get(EmailAction, key)
        if action is not None and action.template_id is None:
            action.template_id = tpl.id
    if created:
        db.commit()
    return created


def default_template_payloads() -> list[dict]:
    """The built-in default templates, sanitized, for the editor's "Load From → defaults" section.
    Returns one entry per action key in catalog order: ``{key, name, subject, body_html}`` where
    ``body_html`` is the sanitized default (byte-identical to the seeded row's stored body)."""
    from app.core import email_sanitize
    out: list[dict] = []
    for key, _n, _d, _c in _ACTION_META:
        spec = DEFAULT_TEMPLATES[key]
        out.append({
            "key": key,
            "name": spec["name"],
            "subject": spec["subject"],
            "body_html": email_sanitize.sanitize_email_html(spec["body_html"]),
        })
    return out


def _fallback_body_if_missing_required_token(category, body_tpl, spec):
    """A SYSTEM security action's built-in body carries a required token ({{action.code}} or
    {{action.link}}). If the chosen (admin-bound/customized) body OMITS it, return the built-in body
    instead, so a misconfigured template can never silently drop the verification code / reset or
    invite link. Non-system actions, or bodies that already carry the token, are returned unchanged.
    Matched on the token KEY, so a whitespace variant like ``{{ action.code }}`` still counts."""
    if category != SYSTEM or not body_tpl:
        return body_tpl
    default_body = (spec or {}).get("default_body_html", "") or ""
    for key_tok in ("action.code", "action.link"):
        if key_tok in default_body and key_tok not in body_tpl:
            return default_body
    return body_tpl


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
    # Defense in depth: an optional action with no bound template has nothing to send. The write paths
    # (update_action's force-off + the delete guard) already prevent enabling one, but guard at the point
    # of use too — so even a direct DB write that left (enabled=True, template_id=NULL) can't cause an
    # unexpected default-body send. A forced test send may still render the catalog default for preview.
    if category == OPTIONAL and template is None and not force:
        return False
    if template is not None and (template.body_html or template.subject):
        subject_tpl = template.subject or spec.get("default_subject", "")
        body_tpl = template.body_html
    else:
        subject_tpl = spec.get("default_subject", "")
        body_tpl = spec.get("default_body_html", "")
    if not (subject_tpl or body_tpl):
        return False

    # Fail-safe for SYSTEM security actions: the built-in body carries a required token
    # ({{action.code}} or {{action.link}}). If an admin binds/customizes a template that OMITS it,
    # the mail would send WITHOUT the verification code / reset or invite link — a silent security
    # drop that still reports success. Fall back to the built-in body so the payload is never lost.
    body_tpl = _fallback_body_if_missing_required_token(category, body_tpl, spec)

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
