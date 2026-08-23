"""Email Studio router — admin-authored SMTP profiles, HTML templates, and image resources.

All routes are gated by ``require_interactive_admin`` (the same surface as Settings): an admin-minted
temporary credential must not manage sending identities, templates, or the private resource folder.
Kept in its own module so the bulk of this feature stays out of api_server.py.

This module currently registers the router with the shared dynamic-action catalog; the profile,
template, resource, and sending endpoints fill in the rest of the CRUD.
"""

from __future__ import annotations

import base64
import hashlib
import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status
from fastapi.concurrency import run_in_threadpool
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, joinedload

from app.core.database import get_db
from app.core.models import EmailAction, EmailProfile, EmailResource, EmailTemplate, RoleEnum, User
from app.core import email_sanitize, email_send
from app.core.security import decrypt_secret, encrypt_secret
from app.core.rate_limiter import rate_limiter as _rate_limiter, RateLimiterUnavailable
from app.services.audit_logger import AuditLogger

security_scheme = HTTPBearer()


# --------------------------------------------------------------------------------------------------
# Auth dependencies (mirrors user_management_api: lazy-import the hardened chain to avoid a cycle —
# api_server imports THIS module at load time to mount the router). Defined BEFORE the router so it
# can carry a router-level dependency: every route on this router is then admin-gated by default,
# and no future CRUD/send route can accidentally ship unguarded.
# --------------------------------------------------------------------------------------------------

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security_scheme),
    db: Session = Depends(get_db),
) -> User:
    from app.api.api_server import get_current_user as _hardened_get_current_user
    return await _hardened_get_current_user(credentials, db)


async def require_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    if current_user.role != RoleEnum.ADMIN:
        from app.api.api_server import _audit_admin_denial
        _audit_admin_denial(db, current_user, "admin role required")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN, detail="Admin privileges required")
    return current_user


async def require_interactive_admin(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    """Admin, and NOT a temporary-credential session — the Email Studio is an org-policy surface."""
    if getattr(current_user, "_is_temp_session", False):
        from app.api.api_server import _audit_admin_denial
        _audit_admin_denial(db, current_user,
                            "interactive admin session required (temp credential rejected)")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an interactive admin session, not a temporary credential.",
        )
    return current_user


# Router-level gate: EVERY route below requires an interactive admin session. Individual routes that
# need the admin User object still add `Depends(require_interactive_admin)` as a parameter.
router = APIRouter(tags=["Email Studio"], dependencies=[Depends(require_interactive_admin)])


# --------------------------------------------------------------------------------------------------
# Shared catalog
# --------------------------------------------------------------------------------------------------

@router.get("/dynamic-actions")
async def list_dynamic_actions(
    _admin: User = Depends(require_interactive_admin),
):
    """The personalization tokens the template editor's 'Add Dynamic Action' dropdown offers.

    Server-owned so the accepted set and the UI list can never drift. Values are substituted per
    recipient at send time (see app.core.email_sanitize). Returns both a flat ``actions`` list (kept
    for compatibility) and a ``groups`` list for the two-level menu."""
    return {
        "actions": [
            {"token": a.token, "label": a.label, "sample": a.sample}
            for a in email_sanitize.DYNAMIC_ACTIONS
        ],
        "groups": email_sanitize.dynamic_action_groups(),
    }


# --------------------------------------------------------------------------------------------------
# Sending profiles
# --------------------------------------------------------------------------------------------------

# A control character in a header field is a header-injection vector; reject at save time (the
# message builder would also reject it, but a clean 400 on save is friendlier than a failed send).
_CTRL_RE = re.compile(r"[\r\n\x00-\x1f\x7f]")


class ProfileIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=255)
    smtp_server: str = Field(min_length=1, max_length=255)
    smtp_port: int = Field(default=587, ge=1, le=65535)
    smtp_username: Optional[str] = Field(default=None, max_length=255)
    # Write-only: on update, an omitted or empty value keeps the stored password.
    smtp_password: Optional[str] = None
    from_email: str = Field(min_length=3, max_length=255)
    from_name: Optional[str] = Field(default=None, max_length=120)
    is_default: Optional[bool] = None
    # Opt out of SMTP TLS certificate verification (e.g. an internal relay with a self-signed cert).
    smtp_allow_insecure_tls: bool = False


class ProfileTestIn(BaseModel):
    """Send a test WITHOUT saving. With profile_id, tests that saved profile (its stored password is
    used when the password field is left blank); the other fields overlay it, so an edited-but-unsaved
    profile can be tested. Without profile_id, tests a brand-new unsaved profile from these fields."""
    profile_id: Optional[uuid.UUID] = None
    smtp_server: Optional[str] = None
    smtp_port: Optional[int] = Field(default=None, ge=1, le=65535)
    smtp_username: Optional[str] = None
    smtp_password: Optional[str] = None
    from_email: Optional[str] = None
    from_name: Optional[str] = None
    to_addr: Optional[str] = None
    smtp_allow_insecure_tls: Optional[bool] = None


def _validate_profile_fields(p: ProfileIn) -> None:
    for label, value in (("name", p.name), ("From name", p.from_name),
                         ("From address", p.from_email), ("SMTP server", p.smtp_server),
                         ("SMTP username", p.smtp_username)):
        if value and _CTRL_RE.search(value):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"{label} contains invalid control characters.")
    if "@" not in (p.from_email or "") or (p.from_email or "").strip() != p.from_email:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="From address must be a valid email address.")


def _profile_out(p: EmailProfile) -> dict:
    """Serialize a profile — NEVER including the password (only a boolean 'has_password' hint)."""
    return {
        "id": str(p.id),
        "name": p.name,
        "description": p.description,
        "smtp_server": p.smtp_server,
        "smtp_port": p.smtp_port,
        "smtp_username": p.smtp_username,
        "from_email": p.from_email,
        "from_name": p.from_name,
        "is_default": p.is_default,
        "has_password": bool(p.smtp_password),
        "smtp_allow_insecure_tls": bool(p.smtp_allow_insecure_tls),
        "created_at": p.created_at.isoformat() if p.created_at else None,
        "updated_at": p.updated_at.isoformat() if p.updated_at else None,
    }


def _client_ip(request: Request) -> Optional[str]:
    from app.api.api_server import get_client_ip
    return get_client_ip(request)


def _audit(db: Session, request: Request, user: User, action: str, **details) -> None:
    try:
        AuditLogger(db).log_action(action=action, status="success", user=user,
                                   ip_address=_client_ip(request), details=details or None)
    except Exception:
        pass  # never fail the operation because the audit write did


def _rate_limit(admin_id, *, limit: int, window: int, prefix: str, detail: str) -> None:
    """Fail-closed rate limit for the outbound/side-effecting Email Studio routes. Raises 429 when
    the limit is hit, and a CLEAN 503 (not a 500) when the limiter itself is unavailable — matching
    the auth routes, so a Redis outage never proceeds AND never surfaces a stack."""
    try:
        allowed, _, reset = _rate_limiter.check_rate_limit(
            identifier=str(admin_id), limit=limit, window=window, prefix=prefix, fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                            detail="The rate limiter is temporarily unavailable; please try again shortly.")
    if not allowed:
        import time as _t
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail=detail,
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})


@router.get("/profiles")
async def list_profiles(db: Session = Depends(get_db)):
    """All sending profiles, default first then newest, passwords stripped."""
    rows = (db.query(EmailProfile)
            .order_by(EmailProfile.is_default.desc(), EmailProfile.created_at.desc())
            .all())
    return {"profiles": [_profile_out(p) for p in rows]}


@router.post("/profiles", status_code=status.HTTP_201_CREATED)
async def create_profile(payload: ProfileIn, request: Request,
                         admin: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    _validate_profile_fields(payload)
    # The first profile is always the default; otherwise honor the flag. Clearing any existing
    # default first keeps the partial-unique index satisfied within one transaction.
    make_default = bool(payload.is_default) or db.query(EmailProfile.id).first() is None
    if make_default:
        db.query(EmailProfile).filter(EmailProfile.is_default.is_(True)).update(
            {"is_default": False}, synchronize_session=False)
    p = EmailProfile(
        name=payload.name.strip(),
        description=(payload.description or "").strip() or None,
        smtp_server=payload.smtp_server.strip(),
        smtp_port=payload.smtp_port,
        smtp_username=(payload.smtp_username or "").strip() or None,
        smtp_password=(encrypt_secret(payload.smtp_password) or None),  # encrypted at rest
        from_email=payload.from_email.strip(),
        from_name=(payload.from_name or "").strip() or None,
        is_default=make_default,
        smtp_allow_insecure_tls=bool(payload.smtp_allow_insecure_tls),
    )
    db.add(p)
    try:
        db.commit()
    except IntegrityError:
        # Two admins set a default concurrently; the partial-unique index rejected the second.
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Another default profile was set at the same time; please retry.")
    db.refresh(p)
    _audit(db, request, admin, "email_profile_created", profile_id=str(p.id), name=p.name)
    return _profile_out(p)


@router.put("/profiles/{profile_id}")
async def update_profile(profile_id: uuid.UUID, payload: ProfileIn, request: Request,
                         admin: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    p = db.get(EmailProfile, profile_id)
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
    _validate_profile_fields(payload)
    p.name = payload.name.strip()
    p.description = (payload.description or "").strip() or None
    p.smtp_server = payload.smtp_server.strip()
    p.smtp_port = payload.smtp_port
    p.smtp_username = (payload.smtp_username or "").strip() or None
    p.from_email = payload.from_email.strip()
    p.from_name = (payload.from_name or "").strip() or None
    p.smtp_allow_insecure_tls = bool(payload.smtp_allow_insecure_tls)
    # Write-only password: overwrite (encrypted at rest) ONLY when a non-empty value is supplied.
    if payload.smtp_password:
        p.smtp_password = encrypt_secret(payload.smtp_password)
    if payload.is_default is True and not p.is_default:
        db.query(EmailProfile).filter(EmailProfile.is_default.is_(True),
                                      EmailProfile.id != p.id).update(
            {"is_default": False}, synchronize_session=False)
        p.is_default = True
    elif payload.is_default is False and p.is_default:
        p.is_default = False
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="Another default profile was set at the same time; please retry.")
    db.refresh(p)
    _audit(db, request, admin, "email_profile_updated", profile_id=str(p.id), name=p.name)
    return _profile_out(p)


@router.delete("/profiles/{profile_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_profile(profile_id: uuid.UUID, request: Request,
                         admin: User = Depends(require_interactive_admin),
                         db: Session = Depends(get_db)):
    p = db.get(EmailProfile, profile_id)
    if p is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
    name = p.name
    was_default = p.is_default
    db.delete(p)  # templates referencing it have profile_id set to NULL (FK ondelete=SET NULL)
    db.flush()    # apply the delete before choosing a replacement default (partial-index safe)
    promoted = None
    if was_default:
        # Don't strand system mail: promote the oldest remaining profile to default so a good
        # profile keeps driving system mail instead of silently falling back to the legacy config.
        promoted = (db.query(EmailProfile)
                    .order_by(EmailProfile.created_at, EmailProfile.id).first())
        if promoted is not None:
            promoted.is_default = True
    try:
        db.commit()
    except IntegrityError:
        # Two concurrent deletes of the default could each promote a different profile and collide on
        # the single-default partial index — same race the create/update paths guard.
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="The default profile changed at the same time; please retry.")
    _audit(db, request, admin, "email_profile_deleted", profile_id=str(profile_id), name=name,
           promoted_default=str(promoted.id) if promoted else None)


@router.post("/profiles/test")
async def test_profile(payload: ProfileTestIn, request: Request,
                       admin: User = Depends(require_interactive_admin),
                       db: Session = Depends(get_db)):
    """Send a one-off test email through a profile's config WITHOUT saving anything."""
    # Courtesy throttle only (this is admin-gated, not a security boundary): an admin iterating on a
    # profile legitimately clicks "Send test" several times in a row. 30/min matches the bulk-send cap.
    _rate_limit(admin.id, limit=30, window=60, prefix="email_profile_test",
                detail="Too many test emails; please wait a moment.")

    if payload.profile_id is not None:
        p = db.get(EmailProfile, payload.profile_id)
        if p is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
        cfg = {"smtp_server": p.smtp_server, "smtp_port": p.smtp_port,
               "smtp_username": p.smtp_username or "", "smtp_password": decrypt_secret(p.smtp_password),
               "from_email": p.from_email, "from_name": p.from_name or "",
               "smtp_allow_insecure_tls": bool(p.smtp_allow_insecure_tls)}
        stored_target = ((p.smtp_server or ""), int(p.smtp_port or 587), (p.smtp_username or ""))
        stored_has_password = bool(p.smtp_password)
    else:
        cfg = {"smtp_server": "", "smtp_port": 587, "smtp_username": "",
               "smtp_password": "", "from_email": "", "from_name": "", "smtp_allow_insecure_tls": False}
        stored_target = None
        stored_has_password = False
    # Overlay any fields the caller provided (edited-but-unsaved values); password only when non-empty.
    for field in ("smtp_server", "smtp_port", "smtp_username", "from_email", "from_name"):
        val = getattr(payload, field)
        if val is not None:
            cfg[field] = val
    if payload.smtp_allow_insecure_tls is not None:
        cfg["smtp_allow_insecure_tls"] = bool(payload.smtp_allow_insecure_tls)
    if payload.smtp_password:
        cfg["smtp_password"] = payload.smtp_password

    # SECURITY: never pair the STORED (write-only) SMTP password with a caller-CHANGED connection
    # target. Overlaying only smtp_server/port/username while reusing the saved password would let an
    # admin exfiltrate the profile's password (which no GET ever returns) to an attacker-chosen host.
    # If the target changed and no fresh password was supplied, refuse — the tester must re-enter it.
    if stored_target is not None and stored_has_password and not payload.smtp_password:
        try:
            eff_port = int(cfg.get("smtp_port") or 587)
        except (TypeError, ValueError):
            eff_port = 587
        eff_target = ((cfg.get("smtp_server") or ""), eff_port, (cfg.get("smtp_username") or ""))
        if eff_target != stored_target:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Re-enter the SMTP password to test against a different server, port, or username.")

    to_addr = (payload.to_addr or "").strip() or (admin.email or "").strip() or (cfg.get("from_email") or "").strip()
    if not to_addr:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No recipient address — set a From address or a recipient.")
    # The recipient and any overlaid header fields skip the create/update validation, so guard them
    # here too — a clean 400 rather than relying solely on the message builder (belt-and-suspenders).
    for label, value in (("Recipient", to_addr), ("From address", cfg.get("from_email")),
                         ("From name", cfg.get("from_name")), ("SMTP server", cfg.get("smtp_server"))):
        if value and _CTRL_RE.search(str(value)):
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                detail=f"{label} contains invalid control characters.")
    try:
        msg = email_send.build_message(
            cfg, to_addr=to_addr, subject="DockVault test email",
            text_body=("This is a test email from your vault's email configuration.\n"
                       "If you received it, outbound email delivery is working."))
        email_send.smtp_send(cfg, msg)
    except email_send.EmailSendError as e:
        code = status.HTTP_400_BAD_REQUEST if e.category == "config" else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(status_code=code, detail=e.message)
    _audit(db, request, admin, "email_profile_test_sent", to=to_addr,
           profile_id=str(payload.profile_id) if payload.profile_id else None)
    return {"message": f"Test email sent to {to_addr}"}


# --------------------------------------------------------------------------------------------------
# Templates
# --------------------------------------------------------------------------------------------------

# Cap the stored body so a single template cannot be used to exhaust memory/storage.
_MAX_BODY = 1_000_000


class TemplateIn(BaseModel):
    name: str = Field(min_length=1, max_length=120)
    description: Optional[str] = Field(default=None, max_length=255)
    profile_id: Optional[uuid.UUID] = None
    subject: str = Field(default="", max_length=255)
    body_html: str = Field(default="", max_length=_MAX_BODY)


class PreviewIn(BaseModel):
    subject: Optional[str] = Field(default="", max_length=255)
    body_html: str = Field(default="", max_length=_MAX_BODY)
    sample_username: Optional[str] = Field(default=None, max_length=255)
    sample_email: Optional[str] = Field(default=None, max_length=255)


def _resource_exists(db: Session, rid: str) -> bool:
    try:
        return db.query(EmailResource.id).filter(EmailResource.id == uuid.UUID(str(rid))).first() is not None
    except (ValueError, TypeError, AttributeError):
        return False


def _resource_data_uri(db: Session, rid: str) -> Optional[str]:
    """A self-contained data: URI for an image, so the editor's SANDBOXED preview iframe can render
    it (the iframe has an opaque origin and can't authenticate to the byte-serving route). The sent
    email uses cid: parts instead; only the live preview inlines the bytes."""
    try:
        row = (db.query(EmailResource.content_type, EmailResource.data)
               .filter(EmailResource.id == uuid.UUID(str(rid))).first())
    except (ValueError, TypeError):
        row = None
    if not row:
        return None
    content_type, data = row
    return f"data:{content_type};base64,{base64.b64encode(data).decode('ascii')}"


def _brand_name(db: Session) -> str:
    try:
        from app.config.effective import get_effective_branding
        return get_effective_branding(db).app_name or ""
    except Exception:
        return ""


def _vault_url() -> str:
    """Best-effort public base URL for the ``{{vault.url}}`` token, derived from the first configured
    ALLOWED_HOSTS entry. Empty when nothing usable is set (a wildcard or unset host) — the token then
    renders empty rather than guessing. Never raises."""
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


def _template_action_map(db: Session) -> dict:
    """{template_id(str): {key, name, category}} for templates bound to an automated email — so a card
    can badge a protected/system template and hide its Delete."""
    out: dict = {}
    for a in db.query(EmailAction).filter(EmailAction.template_id.isnot(None)).all():
        # a system binding wins over an optional one for the badge
        cur = out.get(str(a.template_id))
        if cur is None or (a.category == "system" and cur.get("category") != "system"):
            out[str(a.template_id)] = {"key": a.key, "name": a.name, "category": a.category}
    return out


def _template_out(t: EmailTemplate, *, include_body: bool = False, action_map: Optional[dict] = None) -> dict:
    d = {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "profile_id": str(t.profile_id) if t.profile_id else None,
        "subject": t.subject,
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }
    # Card preview of the linked sending profile (server / from), or None when unassigned.
    d["profile"] = ({"id": str(t.profile.id), "name": t.profile.name,
                     "smtp_server": t.profile.smtp_server, "from_email": t.profile.from_email,
                     "from_name": t.profile.from_name} if t.profile else None)
    # Which automated email this template is bound to (protected / non-removable when 'system').
    d["bound_action"] = (action_map or {}).get(str(t.id))
    if include_body:
        d["body_html"] = t.body_html
        d["referenced_resource_ids"] = email_sanitize.extract_resource_ids(t.body_html or "")
        d["unknown_tokens"] = email_sanitize.unknown_tokens(t.body_html or "")
    return d


def _guard_template_input(db: Session, request: Request, admin: User, payload: TemplateIn) -> None:
    """Reject a bad subject / missing profile, and — the security gate — raise a security event and
    reject when the RAW body contains clearly-malicious content (script/handler/js-uri/iframe)."""
    if payload.subject and _CTRL_RE.search(payload.subject):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Subject contains invalid control characters.")
    if payload.profile_id is not None and db.get(EmailProfile, payload.profile_id) is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="The selected sending profile does not exist.")
    # Only ACTUAL injection attempts (script/handler/js-uri/iframe/…) reject + raise a security
    # event; benign-but-unsupported markup (a <style> block, <meta>, <form>) is left for the
    # sanitizer to strip silently, so pasting ordinary marketing HTML isn't treated as an attack.
    reasons = email_sanitize.hostile_reasons(payload.body_html or "")
    if reasons:
        from app.services.security_monitor import get_security_monitor
        get_security_monitor(db).record_malicious_email_content(
            user_id=admin.id, username=admin.username, ip_address=_client_ip(request),
            surface="email_template", reasons=sorted(set(reasons)))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The template contains content that is not allowed (for example scripts or event handlers) and was blocked.")


@router.get("/templates")
async def list_templates(db: Session = Depends(get_db)):
    rows = (db.query(EmailTemplate)
            .options(joinedload(EmailTemplate.profile))   # avoid an N+1 for each card's profile
            .order_by(EmailTemplate.updated_at.desc()).all())
    amap = _template_action_map(db)
    return {"templates": [_template_out(t, action_map=amap) for t in rows]}


@router.get("/templates/{template_id}")
async def get_template(template_id: uuid.UUID, db: Session = Depends(get_db)):
    t = db.get(EmailTemplate, template_id)
    if t is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found.")
    return _template_out(t, include_body=True, action_map=_template_action_map(db))


@router.post("/templates", status_code=status.HTTP_201_CREATED)
async def create_template(payload: TemplateIn, request: Request,
                          admin: User = Depends(require_interactive_admin),
                          db: Session = Depends(get_db)):
    _guard_template_input(db, request, admin, payload)
    t = EmailTemplate(
        name=payload.name.strip(),
        description=(payload.description or "").strip() or None,
        profile_id=payload.profile_id,
        subject=payload.subject.strip(),
        body_html=email_sanitize.sanitize_email_html(payload.body_html),   # store only sanitized
        created_by=admin.id,
        updated_by=admin.id,
    )
    db.add(t)
    db.commit()
    db.refresh(t)
    _audit(db, request, admin, "email_template_created", template_id=str(t.id), name=t.name)
    return _template_out(t, include_body=True)


@router.put("/templates/{template_id}")
async def update_template(template_id: uuid.UUID, payload: TemplateIn, request: Request,
                          admin: User = Depends(require_interactive_admin),
                          db: Session = Depends(get_db)):
    t = db.get(EmailTemplate, template_id)
    if t is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found.")
    _guard_template_input(db, request, admin, payload)
    t.name = payload.name.strip()
    t.description = (payload.description or "").strip() or None
    t.profile_id = payload.profile_id
    t.subject = payload.subject.strip()
    t.body_html = email_sanitize.sanitize_email_html(payload.body_html)
    t.updated_by = admin.id
    db.commit()
    db.refresh(t)
    _audit(db, request, admin, "email_template_updated", template_id=str(t.id), name=t.name)
    return _template_out(t, include_body=True)


@router.delete("/templates/{template_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_template(template_id: uuid.UUID, request: Request,
                          admin: User = Depends(require_interactive_admin),
                          db: Session = Depends(get_db)):
    t = db.get(EmailTemplate, template_id)
    if t is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found.")
    # A template bound to an automated email is protected: a SYSTEM action's template is non-removable
    # (the vault must be able to send it); an OPTIONAL action's must be re-pointed first. This is what
    # makes the seeded system templates "non-removable" without adding a column to email_templates.
    refs = db.query(EmailAction).filter(EmailAction.template_id == template_id).all()
    sys_ref = next((a for a in refs if a.category == "system"), None)
    if sys_ref is not None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"This template is the system template for “{sys_ref.name}” and can't be "
                                   "deleted while it's in use; change or reset that action's template first.")
    if refs:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"This template is used by the “{refs[0].name}” automated email; "
                                   "change that action's template first.")
    name = t.name
    db.delete(t)
    db.commit()
    _audit(db, request, admin, "email_template_deleted", template_id=str(template_id), name=name)


@router.post("/templates/preview")
async def preview_template(payload: PreviewIn, request: Request,
                           admin: User = Depends(require_interactive_admin),
                           db: Session = Depends(get_db)):
    """Stateless: sanitize + personalize + resolve images to admin-only URLs, for the editor's
    render pane. Deliberately does NOT raise a security event (it runs live as the admin types) —
    it just shows the sanitized result, which visibly strips anything unsafe."""
    # Courtesy throttle: the render pane fires this on a debounce, so a real editing burst stays well
    # under the cap; the limit only bounds a scripted loop against the (now byte-inlining) preview.
    _rate_limit(admin.id, limit=120, window=60, prefix="email_preview",
                detail="Too many preview requests; please slow down.")
    # Preview uses SAMPLE values so the admin sees every token resolve, including the sender/branding
    # and the automated-action tokens (which are empty in a manual send but populated for invite/reset).
    ctx = email_sanitize.token_context(
        recipient={"username": payload.sample_username or "jsmith",
                   "email": payload.sample_email or "jsmith@example.com"},
        brand_name=_brand_name(db),
        vault_url=_vault_url() or "https://vault.example.com",
        sender={"from_name": _brand_name(db) or "Secure Vault", "from_email": "noreply@example.com"},
        action={"link": (_vault_url() or "https://vault.example.com") + "/invite/sample-token",
                "code": "482913", "expires": "in 24 hours"})
    # Bound the total bytes inlined into ONE preview: a template can reference many/large images and
    # base64 inflates ~33%, so without a budget a single request could build a multi-GB response and
    # OOM the worker. Each distinct image's bytes are loaded/encoded AT MOST ONCE (memoized), and once
    # the budget can't fit the next image we stop resolving entirely, so a body that references images
    # thousands of times can't force thousands of DB reads + base64 encodes either.
    state = {"bytes": 0, "stopped": False}
    uri_cache: dict[str, str] = {}

    def preview_src(rid: str) -> str:
        if state["stopped"]:
            return ""
        if rid not in uri_cache:
            uri_cache[rid] = _resource_data_uri(db, rid) or ""
        uri = uri_cache[rid]
        if not uri:
            return ""
        if state["bytes"] + len(uri) > _PREVIEW_INLINE_BUDGET:
            state["stopped"] = True      # budget exhausted — drop this and every later image
            return ""
        state["bytes"] += len(uri)       # count EVERY emission so repeats respect the budget too
        return uri

    html = email_sanitize.render_for_preview(
        payload.body_html, context=ctx,
        resource_exists=lambda rid: _resource_exists(db, rid),
        resource_url=preview_src)
    subject = email_sanitize.render_subject(payload.subject or "", ctx)   # header-safe (strips CR/LF)
    return {
        "html": html,
        "subject": subject,
        "unknown_tokens": email_sanitize.unknown_tokens(payload.body_html or ""),
        "referenced_resource_ids": email_sanitize.extract_resource_ids(
            email_sanitize.sanitize_email_html(payload.body_html)),
    }


# --------------------------------------------------------------------------------------------------
# Automated emails (the action catalog: bind a template to each send-case; toggle optional ones)
# --------------------------------------------------------------------------------------------------

class ActionUpdateIn(BaseModel):
    template_id: Optional[uuid.UUID] = None
    enabled: Optional[bool] = None


def _action_out(a: EmailAction) -> dict:
    tpl = a.template
    return {
        "key": a.key,
        "name": a.name,
        "description": a.description,
        "category": a.category,
        "enabled": bool(a.enabled),
        "template_id": str(a.template_id) if a.template_id else None,
        "template": ({"id": str(tpl.id), "name": tpl.name, "subject": tpl.subject} if tpl else None),
    }


@router.get("/actions")
async def list_actions(_admin: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    """The catalog of automated-email cases and their bound templates. Seeded + permanent (no create/
    delete): a ``system`` action always sends and keeps a non-removable template; an ``optional`` one
    is opt-in via ``enabled``."""
    rows = (db.query(EmailAction)
            .options(joinedload(EmailAction.template))   # avoid a lazy load per action for the card
            .order_by(EmailAction.category, EmailAction.name).all())
    return {"actions": [_action_out(a) for a in rows]}


@router.put("/actions/{key}")
async def update_action(key: str, payload: ActionUpdateIn, request: Request,
                        admin: User = Depends(require_interactive_admin),
                        db: Session = Depends(get_db)):
    """Bind a template to an action and (for optional actions) toggle it on/off. A system action can
    change its template or reset it to the built-in default (explicit null), and stays enabled either
    way. Delivery for the action then flows through the central send helper."""
    action = db.get(EmailAction, key)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown email action.")

    if payload.template_id is not None:
        tpl = db.get(EmailTemplate, payload.template_id)
        if tpl is None:
            raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="Template not found.")
        action.template_id = tpl.id
    elif "template_id" in payload.model_fields_set:      # explicit null = revert to the built-in default
        action.template_id = None                        # (a system action then sends its built-in body)

    if action.category == "system":
        action.enabled = True                            # system actions are always on
    elif payload.enabled is not None:
        action.enabled = bool(payload.enabled)

    db.commit()
    _audit(db, request, admin, "email_action_updated", action_key=key,
           template_id=str(action.template_id) if action.template_id else None, enabled=bool(action.enabled))
    return _action_out(action)


class ActionTestIn(BaseModel):
    to_addr: Optional[str] = None


@router.post("/actions/{key}/test")
async def test_action(key: str, payload: ActionTestIn, request: Request,
                      admin: User = Depends(require_interactive_admin),
                      db: Session = Depends(get_db)):
    """Send the action's email with SAMPLE token values to a chosen address, so an admin can preview an
    automated email through real delivery. Force-sends even a disabled optional action (it's a test)."""
    from app.core.email_actions import send_action_email
    action = db.get(EmailAction, key)
    if action is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Unknown email action.")
    _rate_limit(admin.id, limit=30, window=60, prefix="email_action_test",
                detail="Too many test emails; please wait a moment.")
    to_addr = (payload.to_addr or "").strip() or (admin.email or "").strip()
    if not _valid_address(to_addr):
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Enter a valid recipient address (or set one on your admin account).")
    sample = {"link": (_vault_url() or "https://vault.example.com") + "/sample-token",
              "code": "482913", "expires": "in 24 hours"}
    try:
        send_action_email(db, key, recipient={"email": to_addr, "username": admin.username or "admin"},
                          action_context=sample, force=True, raise_errors=True)
    except email_send.EmailSendError as e:
        code = status.HTTP_400_BAD_REQUEST if e.category == "config" else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(status_code=code, detail=e.message)
    _audit(db, request, admin, "email_action_test_sent", action_key=key, to=to_addr)
    return {"message": f"Test email for “{action.name}” sent to {to_addr}"}


# --------------------------------------------------------------------------------------------------
# Resource folder (private admin-only images embedded in templates by UUID)
# --------------------------------------------------------------------------------------------------

_MAX_RESOURCE_BYTES = 5 * 1024 * 1024   # 5 MB per image
_MAX_RESOURCE_COUNT = 1000              # ceiling on stored images, so the folder can't grow unbounded
# Per-preview cap on total inlined image bytes (base64 data: URIs) — bounds one preview's memory.
_PREVIEW_INLINE_BUDGET = 16 * 1024 * 1024

# Content type is decided by SNIFFING the bytes, never by trusting the client's Content-Type. Only
# raster formats — deliberately NO SVG (it can carry script and would execute if a browser rendered
# the served bytes).
_IMAGE_MAGIC = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def _sniff_image(data: bytes) -> Optional[str]:
    """Return the image content-type inferred from the magic bytes, or None if not a supported
    raster image. WebP is RIFF-container: 'RIFF'<size>'WEBP'."""
    for magic, ct in _IMAGE_MAGIC:
        if data.startswith(magic):
            return ct
    if len(data) >= 12 and data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "image/webp"
    return None


def _safe_filename(name: Optional[str]) -> str:
    """Display-only filename: strip any path, drop control chars, cap length."""
    base = (name or "image").replace("\\", "/").rsplit("/", 1)[-1]
    base = _CTRL_RE.sub("", base).strip() or "image"
    return base[:255]


def _resource_out(r: EmailResource) -> dict:
    """Metadata only — never the bytes (those come from the byte-serving route)."""
    return {
        "id": str(r.id),
        "filename": r.filename,
        "content_type": r.content_type,
        "byte_size": r.byte_size,
        "created_at": r.created_at.isoformat() if r.created_at else None,
    }


@router.get("/resources")
async def list_resources(db: Session = Depends(get_db)):
    # DEFER the LargeBinary `data` column: the list is metadata-only, so loading every image's bytes
    # (up to 5 MB each) into memory just to drop them would be a needless memory/DoS cost.
    rows = (db.query(EmailResource).options(defer(EmailResource.data))
            .order_by(EmailResource.created_at.desc()).all())
    return {"resources": [_resource_out(r) for r in rows]}


@router.post("/resources", status_code=status.HTTP_201_CREATED)
async def upload_resource(request: Request, file: UploadFile = File(...),
                          admin: User = Depends(require_interactive_admin),
                          db: Session = Depends(get_db)):
    # Throttle uploads (fail-closed, per admin) so the folder can't be filled rapidly, and cap the
    # total count so it can't grow without bound. (The multipart body is buffered by Starlette
    # before this handler runs — a pre-auth over-cap body is a known app-wide characteristic shared
    # with the brand-asset uploader; bounding it before parsing is deferred to a middleware change.)
    _rate_limit(admin.id, limit=60, window=60, prefix="email_resource_upload",
                detail="Too many uploads; please wait a moment.")
    if db.query(EmailResource.id).count() >= _MAX_RESOURCE_COUNT:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail=f"Resource limit reached ({_MAX_RESOURCE_COUNT}); delete some images first.")
    # read() bounds only the handler's in-memory copy; +1 lets an over-cap upload 413 cleanly.
    data = await file.read(_MAX_RESOURCE_BYTES + 1)
    if len(data) > _MAX_RESOURCE_BYTES:
        raise HTTPException(status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail=f"Image too large (max {_MAX_RESOURCE_BYTES // (1024 * 1024)} MB).")
    if not data:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST, detail="The uploaded file is empty.")
    content_type = _sniff_image(data)
    if content_type is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="Only PNG, JPEG, GIF, or WebP images are allowed.")
    r = EmailResource(
        filename=_safe_filename(file.filename),
        content_type=content_type,
        byte_size=len(data),
        sha256=hashlib.sha256(data).hexdigest(),
        data=data,
        uploaded_by=admin.id,
    )
    db.add(r)
    db.commit()
    db.refresh(r)
    _audit(db, request, admin, "email_resource_uploaded", resource_id=str(r.id),
           filename=r.filename, content_type=r.content_type, byte_size=r.byte_size)
    return _resource_out(r)


@router.get("/resources/{resource_id}")
async def get_resource_bytes(resource_id: uuid.UUID, db: Session = Depends(get_db)):
    """Serve the raw image bytes (admin-gated by the router dependency) for the editor preview.
    Content-Type is the SNIFFED type stored at upload; nosniff stops the browser guessing another."""
    r = db.get(EmailResource, resource_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
    return Response(
        content=r.data,
        media_type=r.content_type,
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Disposition": "inline",          # no filename -> no header-injection surface
            # NB: Cache-Control is set globally by the security-header middleware
            # (no-store, no-cache, must-revalidate, private), which is the right default for an
            # admin-only image, so we don't set our own here (it would be overridden anyway).
        },
    )


@router.delete("/resources/{resource_id}", status_code=status.HTTP_204_NO_CONTENT)
async def delete_resource(resource_id: uuid.UUID, request: Request,
                          admin: User = Depends(require_interactive_admin),
                          db: Session = Depends(get_db)):
    r = db.get(EmailResource, resource_id)
    if r is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Resource not found.")
    fn = r.filename
    db.delete(r)   # templates keep the data-resource-id; it simply stops resolving (dangling -> dropped)
    db.commit()
    _audit(db, request, admin, "email_resource_deleted", resource_id=str(resource_id), filename=fn)


# --------------------------------------------------------------------------------------------------
# Sending a template
# --------------------------------------------------------------------------------------------------

_MAX_RECIPIENTS = 100


def _valid_address(a: str) -> bool:
    """A LINEAR (no-backtracking) syntactic address check — deliberately not a regex, to avoid a
    polynomial-ReDoS on adversarial free-form input. Requires exactly one '@', a non-empty local
    part, and a dotted domain; rejects whitespace, control chars, and commas (send_message derives
    envelope RCPTs from the To header via getaddresses, which splits on commas). Real deliverability
    is decided by the SMTP server, which turns a bad address into a per-recipient error row."""
    if not a or len(a) > 254 or a.count("@") != 1:
        return False
    if _CTRL_RE.search(a) or any(c in a for c in (" ", "\t", ",")):
        return False
    local, _, domain = a.partition("@")
    return bool(local) and "." in domain and not domain.startswith(".") and not domain.endswith(".")


class SendIn(BaseModel):
    user_ids: list[uuid.UUID] = Field(default_factory=list, max_length=_MAX_RECIPIENTS)
    addresses: list[str] = Field(default_factory=list, max_length=_MAX_RECIPIENTS)


def _profile_cfg(p: EmailProfile) -> dict:
    return {"smtp_server": p.smtp_server, "smtp_port": p.smtp_port,
            "smtp_username": p.smtp_username or "", "smtp_password": decrypt_secret(p.smtp_password),
            "from_email": p.from_email, "from_name": p.from_name or "",
            "smtp_allow_insecure_tls": bool(p.smtp_allow_insecure_tls)}


@router.post("/templates/{template_id}/send")
async def send_template(template_id: uuid.UUID, payload: SendIn, request: Request,
                        admin: User = Depends(require_interactive_admin),
                        db: Session = Depends(get_db)):
    """Render + send a template to vault users and/or free-form addresses, one personalized message
    per recipient, images inlined as cid: parts. Refuses (and raises a security event) if the STORED
    body is hostile — the before-send tamper check."""
    _rate_limit(admin.id, limit=30, window=60, prefix="email_template_send",
                detail="Too many sends; please wait a moment.")

    t = db.get(EmailTemplate, template_id)
    if t is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found.")

    # BEFORE-SEND tamper defense: the stored body is normally already sanitized, so hostile content
    # here means the row was tampered with directly. Refuse the whole send and raise a security event.
    reasons = email_sanitize.hostile_reasons(t.body_html or "")
    if reasons:
        from app.services.security_monitor import get_security_monitor
        get_security_monitor(db).record_malicious_email_content(
            user_id=admin.id, username=admin.username, ip_address=_client_ip(request),
            surface="email_template_send", reasons=sorted(set(reasons)))
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="This template contains content that is not allowed and cannot be sent; re-save it first.")

    # Resolve the sending config: the template's profile (only if it has a usable server+From), else
    # the default profile. A blank/dangling profile falls through rather than erroring at send time.
    cfg = None
    if t.profile_id:
        p = db.get(EmailProfile, t.profile_id)
        if p is not None:
            candidate = _profile_cfg(p)
            if (candidate.get("smtp_server") or "").strip() and (candidate.get("from_email") or "").strip():
                cfg = candidate
    if cfg is None:
        cfg = email_send.resolve_default_config(db)
    if cfg is None:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No sending profile is configured. Assign one to the template or set a default.")

    # Build the recipient list; unresolvable recipients become error rows, not failures of the batch.
    recipients: list[dict] = []
    errors: list[dict] = []
    seen_emails: set = set()
    if payload.user_ids:
        found = {u.id: u for u in db.query(User).filter(User.id.in_(payload.user_ids)).all()}
        for uid in payload.user_ids:
            u = found.get(uid)
            if u is None:
                errors.append({"recipient": str(uid), "ok": False, "error": "user not found"})
            elif not (u.email or "").strip():
                errors.append({"recipient": u.username, "ok": False, "error": "user has no email"})
            elif u.email.strip().lower() not in seen_emails:      # dedupe: one message per address
                seen_emails.add(u.email.strip().lower())
                recipients.append({"email": u.email.strip(), "username": u.username})
    for addr in payload.addresses:
        a = (addr or "").strip()
        if not _valid_address(a):
            errors.append({"recipient": a[:120], "ok": False, "error": "invalid address"})
        elif a.lower() not in seen_emails:
            seen_emails.add(a.lower())
            recipients.append({"email": a, "username": ""})
    if not recipients:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail="No valid recipients to send to.")
    if len(recipients) > _MAX_RECIPIENTS:
        raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                            detail=f"Too many recipients (max {_MAX_RECIPIENTS} per send).")

    # Memoized resource loader so a shared image loads from the DB once, not once per recipient.
    _rc: dict = {}

    def load_resource(rid: str):
        if rid not in _rc:
            try:
                row = (db.query(EmailResource.content_type, EmailResource.data)
                       .filter(EmailResource.id == uuid.UUID(str(rid))).first())
            except (ValueError, TypeError):
                row = None
            _rc[rid] = (row[0], row[1]) if row else None
        return _rc[rid]

    brand = _brand_name(db)
    vault_url = _vault_url()
    sender = {"from_name": cfg.get("from_name") or "", "from_email": cfg.get("from_email") or ""}
    messages, prepared = [], []
    for rec in recipients:
        ctx = email_sanitize.token_context(recipient=rec, brand_name=brand,
                                           vault_url=vault_url, sender=sender)
        subject = email_sanitize.render_subject(t.subject, ctx)
        html, inline = email_sanitize.render_for_send(t.body_html, context=ctx, load_resource=load_resource)
        text = email_sanitize.render_plaintext_fallback(html)
        try:
            msg = email_send.build_message(cfg, to_addr=rec["email"], subject=subject,
                                           text_body=text, html_body=html, inline_images=inline)
        except email_send.EmailSendError:
            errors.append({"recipient": rec["email"], "ok": False, "error": "message build failed"})
            continue
        messages.append(msg)
        prepared.append(rec)

    try:
        # Offload the BLOCKING smtplib conversation to a worker thread so a bulk send doesn't stall
        # the async event loop for the whole worker.
        outcomes = await run_in_threadpool(email_send.smtp_send_batch, cfg, messages) if messages else []
    except email_send.EmailSendError as e:
        code = status.HTTP_400_BAD_REQUEST if e.category == "config" else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(status_code=code, detail=e.message)

    results = list(errors)
    sent = 0
    for rec, out in zip(prepared, outcomes):
        results.append({"recipient": rec["email"], "ok": out["ok"], "error": out["error"]})
        sent += 1 if out["ok"] else 0
    _audit(db, request, admin, "email_template_sent", template_id=str(t.id),
           sent=sent, failed=len(messages) - sent, errors=len(errors),
           attempted=len(messages), recipients=len(recipients))
    return {"template_id": str(t.id), "sent": sent, "attempted": len(messages),
            "recipients": len(recipients), "results": results}
