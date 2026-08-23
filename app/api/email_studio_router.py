"""Email Studio router — admin-authored SMTP profiles, HTML templates, and image resources.

All routes are gated by ``require_interactive_admin`` (the same surface as Settings): an admin-minted
temporary credential must not manage sending identities, templates, or the private resource folder.
Kept in its own module so the bulk of this feature stays out of api_server.py.

This module currently registers the router with the shared dynamic-action catalog; the profile,
template, resource, and sending endpoints fill in the rest of the CRUD.
"""

from __future__ import annotations

import hashlib
import re
import uuid
from typing import Optional

from fastapi import APIRouter, Depends, File, HTTPException, Request, Response, UploadFile, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from pydantic import BaseModel, Field
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session, defer, joinedload

from app.core.database import get_db
from app.core.models import EmailProfile, EmailResource, EmailTemplate, RoleEnum, User
from app.core import email_sanitize, email_send
from app.core.rate_limiter import rate_limiter as _rate_limiter
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
    recipient at send time (see app.core.email_sanitize)."""
    return {
        "actions": [
            {"token": a.token, "label": a.label, "sample": a.sample}
            for a in email_sanitize.DYNAMIC_ACTIONS
        ]
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
        smtp_password=(payload.smtp_password or None),
        from_email=payload.from_email.strip(),
        from_name=(payload.from_name or "").strip() or None,
        is_default=make_default,
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
    # Write-only password: overwrite ONLY when a non-empty value is supplied.
    if payload.smtp_password:
        p.smtp_password = payload.smtp_password
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
    db.commit()
    _audit(db, request, admin, "email_profile_deleted", profile_id=str(profile_id), name=name,
           promoted_default=str(promoted.id) if promoted else None)


@router.post("/profiles/test")
async def test_profile(payload: ProfileTestIn, request: Request,
                       admin: User = Depends(require_interactive_admin),
                       db: Session = Depends(get_db)):
    """Send a one-off test email through a profile's config WITHOUT saving anything."""
    allowed, _, reset = _rate_limiter.check_rate_limit(
        identifier=str(admin.id), limit=5, window=60, prefix="email_profile_test", fail_open=False)
    if not allowed:
        import time as _t
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many test emails; please wait a moment.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})

    if payload.profile_id is not None:
        p = db.get(EmailProfile, payload.profile_id)
        if p is None:
            raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Profile not found.")
        cfg = {"smtp_server": p.smtp_server, "smtp_port": p.smtp_port,
               "smtp_username": p.smtp_username or "", "smtp_password": p.smtp_password or "",
               "from_email": p.from_email, "from_name": p.from_name or ""}
    else:
        cfg = {"smtp_server": "", "smtp_port": 587, "smtp_username": "",
               "smtp_password": "", "from_email": "", "from_name": ""}
    # Overlay any fields the caller provided (edited-but-unsaved values); password only when non-empty.
    for field in ("smtp_server", "smtp_port", "smtp_username", "from_email", "from_name"):
        val = getattr(payload, field)
        if val is not None:
            cfg[field] = val
    if payload.smtp_password:
        cfg["smtp_password"] = payload.smtp_password

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


def _brand_name(db: Session) -> str:
    try:
        from app.config.effective import get_effective_branding
        return get_effective_branding(db).app_name or ""
    except Exception:
        return ""


def _template_out(t: EmailTemplate, *, include_body: bool = False) -> dict:
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
    return {"templates": [_template_out(t) for t in rows]}


@router.get("/templates/{template_id}")
async def get_template(template_id: uuid.UUID, db: Session = Depends(get_db)):
    t = db.get(EmailTemplate, template_id)
    if t is None:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Template not found.")
    return _template_out(t, include_body=True)


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
    name = t.name
    db.delete(t)
    db.commit()
    _audit(db, request, admin, "email_template_deleted", template_id=str(template_id), name=name)


@router.post("/templates/preview")
async def preview_template(payload: PreviewIn,
                           admin: User = Depends(require_interactive_admin),
                           db: Session = Depends(get_db)):
    """Stateless: sanitize + personalize + resolve images to admin-only URLs, for the editor's
    render pane. Deliberately does NOT raise a security event (it runs live as the admin types) —
    it just shows the sanitized result, which visibly strips anything unsafe."""
    ctx = email_sanitize.token_context(
        recipient={"username": payload.sample_username or "jsmith",
                   "email": payload.sample_email or "jsmith@example.com"},
        brand_name=_brand_name(db))
    html = email_sanitize.render_for_preview(
        payload.body_html, context=ctx,
        resource_exists=lambda rid: _resource_exists(db, rid),
        resource_url=lambda rid: f"/email/resources/{rid}")
    subject = email_sanitize.render_subject(payload.subject or "", ctx)   # header-safe (strips CR/LF)
    return {
        "html": html,
        "subject": subject,
        "unknown_tokens": email_sanitize.unknown_tokens(payload.body_html or ""),
        "referenced_resource_ids": email_sanitize.extract_resource_ids(
            email_sanitize.sanitize_email_html(payload.body_html)),
    }


# --------------------------------------------------------------------------------------------------
# Resource folder (private admin-only images embedded in templates by UUID)
# --------------------------------------------------------------------------------------------------

_MAX_RESOURCE_BYTES = 5 * 1024 * 1024   # 5 MB per image
_MAX_RESOURCE_COUNT = 1000              # ceiling on stored images, so the folder can't grow unbounded

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
    allowed, _, reset = _rate_limiter.check_rate_limit(
        identifier=str(admin.id), limit=60, window=60, prefix="email_resource_upload", fail_open=False)
    if not allowed:
        import time as _t
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many uploads; please wait a moment.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})
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
