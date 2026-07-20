# -*- coding: utf-8 -*-
"""
FastAPI application for management API.
Provides REST endpoints for user management, vault operations, and administration.

Performance: Key endpoints support ETag-based conditional responses to reduce traffic.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import uuid
import json

from fastapi import FastAPI, Depends, HTTPException, status, Request, File as FastAPIFile, UploadFile, Header, WebSocket, WebSocketDisconnect, Response
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler as fastapi_http_exception_handler
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request as StarletteRequest
from pydantic import BaseModel, EmailStr, Field, field_validator
from sqlalchemy.orm import Session
import io
import os
import shutil
import traceback
from pathlib import Path

from app.core.database import get_db, init_db, check_db_connection, check_redis_connection
from app.core.models import User, RoleEnum, PermissionEnum, VaultPermissionEnum, Vault, File, Folder, Group, user_groups, ChunkedUploadSession, UserPreference, ShareTag, Share, ShareClaim
from app.core import sharing_policy
# NOTE: auth_service and vault_service BOTH define a class named RateLimitExceededError
# (unrelated: one subclasses AuthenticationError, the other FileServiceError). Import the
# auth one under an alias so the later vault import below can't shadow it — otherwise the
# login throttle's `except` would bind the wrong class and a throttled login would surface
# as a 500 instead of a 429.
from app.services.auth_service import AuthService, InvalidCredentialsError, AccountLockedError, RateLimitExceededError as AuthRateLimitExceededError
from app.core.authorization import PermissionService, PermissionDeniedError, ResourceNotFoundError, AuthorizationError
from app.services.vault_service import VaultService, PasswordRequiredError, InvalidPasswordError, FileTooLargeError, RateLimitExceededError, FileNotFoundError, FileServiceError, VaultNotFoundError, FolderNotFoundError, DuplicateNameError, _name_match_filter
from app.services.vault_service import require_file_scope, require_folder_scope, require_item_scope, require_download_scope, folder_ancestry, filter_listing_for_scope
from app.core.id_scope import id_in_scope
from sqlalchemy.exc import IntegrityError
from app.services.audit_logger import AuditLogger
from app.services import log_pull  # pure helpers for the authenticated log-pull endpoint
from app.core.security import create_access_token, verify_access_token
from app.core.config import settings
from app.core.endpoint_permissions import require_endpoint_permission
from app.core.temp_scope import require_vault_cap
from app.api.user_management_api import router as user_management_router
from app.core.paths import PROJECT_ROOT
from app.core.response_hash_utils import handle_conditional_response, compute_response_hash, check_if_none_match, create_cached_response, create_not_modified_response

# Global tracking for active operations
import threading
active_operations_lock = threading.Lock()
active_operations = set()  # Set of operation IDs (upload/download in progress)

def start_operation(operation_id: str):
    """Track start of upload/download operation."""
    with active_operations_lock:
        active_operations.add(operation_id)
        print(f"[OPERATIONS] Started: {operation_id}, Total active: {len(active_operations)}")

def end_operation(operation_id: str):
    """Track end of upload/download operation."""
    with active_operations_lock:
        active_operations.discard(operation_id)
        print(f"[OPERATIONS] Ended: {operation_id}, Total active: {len(active_operations)}")

def get_active_operations_count() -> int:
    """Get current count of active operations."""
    with active_operations_lock:
        return len(active_operations)


# Initialize FastAPI app
# Security: Conditionally disable API docs in production
app = FastAPI(
    title="Secure SFTP Management API",
    description="Management API for secure SFTP server with vault system",
    version="1.0.0",
    # Disable interactive API docs in production to prevent endpoint enumeration
    docs_url="/docs" if settings.environment == "development" else None,
    redoc_url="/redoc" if settings.environment == "development" else None,
    openapi_url="/openapi.json" if settings.environment == "development" else None
)

@app.exception_handler(FileServiceError)
async def _file_service_error_handler(request: StarletteRequest, exc: FileServiceError):
    """Map vault/file domain errors to proper HTTP status codes.

    The per-endpoint try/except blocks catch authorization.ResourceNotFoundError,
    but VaultService raises vault_service.VaultNotFoundError (a FileServiceError),
    which is a different type. Without this handler those errors escape to the
    catch-all middleware and surface as 500s. Mapping them here fixes every
    endpoint at once.
    """
    if isinstance(exc, (PasswordRequiredError, InvalidPasswordError)):
        status_code = status.HTTP_401_UNAUTHORIZED
    elif isinstance(exc, (VaultNotFoundError, FolderNotFoundError, FileNotFoundError)):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, RateLimitExceededError):
        status_code = status.HTTP_429_TOO_MANY_REQUESTS
    elif isinstance(exc, FileTooLargeError):
        status_code = status.HTTP_413_REQUEST_ENTITY_TOO_LARGE
    else:
        status_code = status.HTTP_400_BAD_REQUEST
    return JSONResponse(status_code=status_code, content={"detail": str(exc)})


@app.exception_handler(AuthorizationError)
async def _authorization_error_handler(request: StarletteRequest, exc: AuthorizationError):
    """Map authorization domain errors to proper HTTP status codes so they
    don't escape uncaught endpoints as 500s."""
    if isinstance(exc, ResourceNotFoundError):
        status_code = status.HTTP_404_NOT_FOUND
    elif isinstance(exc, PermissionDeniedError):
        status_code = status.HTTP_403_FORBIDDEN
    else:
        status_code = status.HTTP_403_FORBIDDEN
    return JSONResponse(status_code=status_code, content={"detail": str(exc)})


@app.exception_handler(StarletteHTTPException)
async def _http_exception_handler(request: StarletteRequest, exc: StarletteHTTPException):
    """Render HTTPExceptions with FastAPI's default behaviour, EXCEPT sanitize any 500 detail.

    Many handlers wrap an underlying error as ``HTTPException(500, detail=f"…{str(e)}")``; that
    detail can embed SQL text, DB schema, or storage paths. Those responses are produced inside
    the ASGI exception layer and flow back out already-serialized, so the header middleware can't
    rewrite them. Intercept here: for a 500, emit a generic message + a server-side-logged
    correlation id and never the raw detail. Every other status renders exactly as before."""
    if exc.status_code == 500:
        error_id = str(uuid.uuid4())
        print(f"[ERROR] Sanitized HTTP 500 (ID: {error_id}): {exc.detail}")
        return JSONResponse(
            status_code=500,
            content={"detail": "An internal error occurred. Please contact support if the problem persists.",
                     "error_id": error_id},
            headers=getattr(exc, "headers", None),
        )
    return await fastapi_http_exception_handler(request, exc)


# Add CORS middleware. Bearer-token auth (no cookies anywhere) already makes credentialed
# cross-origin theft impossible, but don't bake a dev origin into a production image: read the
# allow-list from CORS_ALLOW_ORIGINS (comma-separated) and fall back to the localhost dev origin
# only in a development build (empty allow-list otherwise -> no cross-origin browser access).
_cors_env = os.getenv('CORS_ALLOW_ORIGINS', '').strip()
if _cors_env:
    _cors_origins = [o.strip() for o in _cors_env.split(',') if o.strip()]
elif settings.environment == 'development':
    _cors_origins = ["http://localhost:3000"]
else:
    _cors_origins = []
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

def _external_scheme(request: StarletteRequest) -> str:
    """The externally-visible request scheme, honouring X-Forwarded-Proto only from a trusted proxy.

    Behind a TLS-terminating reverse proxy (the common SaaS/orchestrator topology, and the dev
    compose) uvicorn sees plain HTTP even though the client spoke HTTPS, so the in-process
    request.url.scheme is 'http' and the strongest transport-security signals (HSTS +
    upgrade-insecure-requests) would never be emitted. Trust X-Forwarded-Proto ONLY when the
    immediate peer is a configured trusted proxy (reusing the net_utils trust set, empty/fail-closed
    by default), so a direct client can't influence it. Falls back to the in-process scheme — which
    is correctly 'https' in the standalone in-process-TLS (secure compose) deploy."""
    try:
        xfp = request.headers.get('x-forwarded-proto')
        if xfp:
            from app.core.net_utils import _is_trusted_peer
            peer = request.client.host if request.client else None
            if _is_trusted_peer(peer):
                return (xfp.split(',')[0].strip().lower() or request.url.scheme)
    except Exception:
        pass
    return request.url.scheme


# Comprehensive security headers middleware
# Absolute ceiling on a single request body (defense-in-depth vs a multipart/JSON DoS, on top of the
# starlette >=0.40 multipart-parser fix). Generous: it must exceed the largest legitimate direct upload
# (max_file_size_mb) plus multipart overhead, so it only trips on abusive multi-GB bodies — the
# per-endpoint upload checks still enforce the real file-size limit.
_MAX_REQUEST_BODY_BYTES = (settings.max_file_size_mb + 256) * 1024 * 1024


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """
    Security headers middleware addressing multiple OWASP findings:
    - Content Security Policy (CSP) - prevents XSS exploitation
    - X-Frame-Options - prevents clickjacking
    - X-Content-Type-Options - prevents MIME sniffing
    - Server header removal - reduces information disclosure
    - Cache control - prevents sensitive data caching
    - Global exception handling - prevents error information leakage
    """
    
    async def dispatch(self, request: StarletteRequest, call_next):
        # Defense-in-depth request-body cap on a DECLARED Content-Length. MULTIPART uploads are EXEMPT:
        # they are metered per-file in-stream and bounded by the target vault's own size limit (and the
        # multipart parser itself is bounded by starlette >=0.40), so an aggregate cap here would wrongly
        # reject a legitimate multi-file batch. A missing/chunked Content-Length is metered downstream.
        # The rejection is assigned to `response` (not returned early) so it still flows through the
        # hardening-header code below.
        _oversize_response = None
        _cl = request.headers.get("content-length")
        _ctype = request.headers.get("content-type", "").lower()
        if _cl is not None and not _ctype.startswith("multipart/"):
            try:
                if int(_cl) > _MAX_REQUEST_BODY_BYTES:
                    _oversize_response = JSONResponse(status_code=413, content={"detail": "Request body too large."})
            except ValueError:
                _oversize_response = JSONResponse(status_code=400, content={"detail": "Invalid Content-Length header."})
        try:
            response = _oversize_response if _oversize_response is not None else await call_next(request)
        except HTTPException:
            # Re-raise HTTPExceptions (they're handled by FastAPI)
            raise
        except (InvalidCredentialsError, AccountLockedError, RateLimitExceededError,
                AuthRateLimitExceededError, PasswordRequiredError, InvalidPasswordError,
                FileTooLargeError):
            # Re-raise custom exceptions that have specific handlers in endpoints
            raise
        except Exception as exc:
            # Global exception handler - prevents 500 errors from leaking information
            error_id = str(uuid.uuid4())
            print(f"[ERROR] Unhandled exception (ID: {error_id}): {exc}")
            print(traceback.format_exc())

            # Fall through to the header-setting code below so 500s carry the same hardening
            # headers (nosniff / XFO / no-store / Referrer-Policy / Permissions-Policy) as any
            # other response, rather than returning early bare-headed.
            response = JSONResponse(
                status_code=500,
                content={
                    "detail": "An internal error occurred. Please contact support if the problem persists.",
                    "error_id": error_id
                }
            )

        # Security Header: Prevent MIME type sniffing
        response.headers['X-Content-Type-Options'] = 'nosniff'
        
        # Security Header: Prevent clickjacking
        response.headers['X-Frame-Options'] = 'DENY'
        
        # Security Header: Remove server identification
        if 'server' in response.headers:
            del response.headers['server']
        
        # Security Header: disable the legacy XSS auditor (OWASP guidance is '0'; the enabled
        # value has historically been abusable for same-origin info leaks). CSP is the real control.
        response.headers['X-XSS-Protection'] = '0'
        
        # Security Header: Referrer policy
        response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
        
        # Security Header: Permissions policy (disable unnecessary features)
        response.headers['Permissions-Policy'] = 'geolocation=(), microphone=(), camera=()'
        
        # Externally-visible scheme (honours X-Forwarded-Proto from a trusted proxy) so the
        # transport-security signals below fire behind a TLS-terminating reverse proxy, not only
        # when uvicorn terminates TLS in-process.
        external_scheme = _external_scheme(request)

        # Content Security Policy (CSP) - for HTML responses only
        content_type = response.headers.get('content-type', '')
        if 'text/html' in content_type:
            csp_directives = [
                "default-src 'self'",  # Only load resources from same origin
                "script-src 'self'",  # Self-hosted scripts only (vendored under /static/js); NO inline scripts, no external CDN
                "style-src 'self' 'unsafe-inline'",  # Allow inline styles
                "img-src 'self' data: blob:",  # Allow images from same origin, data URIs, blob
                "media-src 'self' blob:",  # Audio/video previews from in-memory blobs
                "frame-src 'self' blob:",  # PDF/doc previews rendered in a blob iframe
                "object-src 'self' blob:",  # <object>/<embed> blob previews
                "font-src 'self'",  # Fonts from same origin only
                "connect-src 'self' ws: wss:",  # API calls and WebSocket
                "frame-ancestors 'none'",  # Prevent clickjacking (no iframes)
                "base-uri 'self'",  # Prevent base tag injection
                "form-action 'self'",  # Forms only submit to same origin
            ]
            
            # Add HTTPS upgrade directive if the external scheme is HTTPS
            if external_scheme == 'https':
                csp_directives.append("upgrade-insecure-requests")
            
            response.headers['Content-Security-Policy'] = '; '.join(csp_directives)
        
        # Cache control for sensitive responses
        path = request.url.path
        
        # Prevent caching of JS, CSS, HTML files (cache busting)
        if any(path.endswith(ext) for ext in ['.js', '.css', '.html']):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
            response.headers['Pragma'] = 'no-cache'
            response.headers['Expires'] = '0'
        
        # Prevent caching of API responses and non-static content
        elif not path.startswith('/static/') or path.startswith('/api/'):
            response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private'
            response.headers['Pragma'] = 'no-cache'
        
        # HSTS (HTTP Strict Transport Security) - only when the external scheme is HTTPS
        # (honours X-Forwarded-Proto from a trusted proxy, so it fires behind a TLS-terminating
        # reverse proxy too, not only for in-process TLS).
        if external_scheme == 'https':
            response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains'
        
        return response

# General API rate limiter. The sliding-window limiter in app/core/rate_limiter.py was fully implemented
# but never attached to the app, so the documented RATE_LIMIT_API_* knobs were inert and the whole
# API surface had no framework throttle (only the login path and /ecc/* self-throttled). Wire it
# here, gated on the config flag. It buckets by authenticated user when a bearer token is present,
# else by trusted-proxy-aware IP; excludes static assets / health / docs (one SPA page load pulls
# many static files); and fails OPEN on a Redis outage (availability over a brief throttling gap —
# the separate fail-CLOSED login throttle is unaffected). Registered BEFORE SecurityHeadersMiddleware
# so it sits inside it and a 429 response still carries the hardening headers on the way out.
if getattr(settings, 'rate_limit_api_enabled', True):
    from app.core.rate_limiter import RateLimitMiddleware, rate_limiter as _api_rate_limiter
    app.add_middleware(
        RateLimitMiddleware,
        rate_limiter=_api_rate_limiter,
        default_limit=settings.rate_limit_api_default,
        default_window=settings.rate_limit_api_default_window,
        exclude_paths=["/health", "/static", "/favicon.ico", "/brand-assets",
                       "/docs", "/redoc", "/openapi.json"],
    )

app.add_middleware(SecurityHeadersMiddleware)


class VaultPasscodeMiddleware:
    """Pure-ASGI middleware that captures the X-Vault-Passcode header into a request-scoped contextvar
    so VaultService.get_vault can redeem a temp-credential passcode at the single chokepoint without
    threading the header through every file endpoint (the vault password is threaded explicitly; the
    passcode rides the contextvar instead). Pure ASGI — NOT BaseHTTPMiddleware — so the contextvar
    reliably propagates into the sync route handler's threadpool call."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        from app.services.vault_service import set_current_vault_passcode, reset_current_vault_passcode
        value = None
        for k, v in (scope.get("headers") or []):
            if k == b"x-vault-passcode":
                try:
                    value = v.decode("latin-1")
                except Exception:
                    value = None
                break
        token = set_current_vault_passcode(value)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_current_vault_passcode(token)


app.add_middleware(VaultPasscodeMiddleware)

# Host-header allowlist (opt-in). Empty ALLOWED_HOSTS => permissive ['*'] (a self-hosted vault's
# served hostname is deployment-specific and unknown at build time), so this is inert unless the
# operator declares the served name(s) — then a forged Host / X-Forwarded-Host is rejected (a
# link-/cache-poisoning primitive). 'localhost'/'127.0.0.1' are always kept so the container's own
# /health probe still passes. Added last => OUTERMOST, so a bad Host is rejected before other work.
_allowed_hosts = [h.strip() for h in (getattr(settings, 'allowed_hosts', '') or '').split(',') if h.strip()]
if _allowed_hosts:
    for _h in ('localhost', '127.0.0.1'):
        if _h not in _allowed_hosts:
            _allowed_hosts.append(_h)
    from starlette.middleware.trustedhost import TrustedHostMiddleware
    app.add_middleware(TrustedHostMiddleware, allowed_hosts=_allowed_hosts)

# Include routers
app.include_router(user_management_router)

# Import and include dashboard router
from app.api.dashboard_api import router as dashboard_router
app.include_router(dashboard_router)

# Import and include info router (branding/public info)
from app.routers.info import router as info_router
app.include_router(info_router)

# Shared with the info router / effective-branding merge: the strict hex-colour
# pattern (so the admin brand write path validates identically to the model) and the
# SystemSetting key that holds the brand overrides (A3 mirrors the Settings brand
# fields into it so /branding + the rendered shell update live).
from app.config.branding import HEX_COLOR_RE
from app.config.effective import BRAND_SETTINGS_KEY, set_brand_overrides

# First-run gate for the ENTIRE setup surface. The setup wizard is UNAUTHENTICATED (it has
# to run before any admin exists), so it must become unreachable the moment an instance is
# set up — otherwise an anonymous request could reconfigure a live production instance
# (create/alter the admin, rewrite config). "Set up" = ANY admin user exists, which every
# production deploy has from startup (deploy/setup-secure.sh and the SaaS portal seed the admin
# from env). Queried WITHOUT the is_active filter on purpose: a deactivated admin still
# means the instance is set up and must NOT re-open the wizard. Setup is done by the
# provisioning script / portal, so the wizard is a first-run-only fallback for a bare deploy.
# Import and include ECC router (Elliptic Curve Cryptography)
from app.api.ecc_router import router as ecc_router
app.include_router(ecc_router, prefix="/ecc")

@app.get("/")
async def root():
    """Root endpoint - serve the SPA dashboard."""
    static_dir = str(PROJECT_ROOT / "static")
    index_path = os.path.join(static_dir, "index.html")
    if os.path.exists(index_path):
        response = FileResponse(index_path)
        # Prevent caching
        response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, max-age=0'
        response.headers['Pragma'] = 'no-cache'
        response.headers['Expires'] = '0'
        return response
    # If no HTML files found, return status
    return {
        "status": "running",
        "message": "Vault API Server",
        "endpoints": {"api_docs": "/docs"}
    }

# Security
security = HTTPBearer()


# Pydantic Models (Request/Response Schemas)

class LoginRequest(BaseModel):
    # Bound + markup-reject the attempted username the same way UserCreate does: it is echoed into
    # the failed-login SecurityAlert record that the admin API returns, so a hostile value must not
    # be able to carry markup into an admin surface. (Control characters are stripped defensively at
    # the alert/log sink too.)
    username: str = Field(..., max_length=254)
    password: str

    @field_validator('username')
    @classmethod
    def _clean_username(cls, v):
        return _reject_markup_chars(v, 'username')


class LoginResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    user: 'UserResponse'
    # True when this login used a temporary credential.
    is_temporary: bool = False
    # True only for a SCOPED temp credential (a legacy, scope-less temp cred is
    # intentionally unrestricted). Lets the frontend fail CLOSED — hide admin nav
    # up-front, before/without the GET /auth/session probe — for scoped creds only.
    is_scoped_temp: bool = False


# --- Name-field input hygiene (defence in depth) ---------------------------
# Names entered by low-privilege users (vault/file/group/user names) surface in operator and admin
# UIs — the audit log, the dashboard activity feed, group chips. Every client render path escapes
# them, but reject the HTML-markup characters ('<' and '>') at the source too so a hostile name can
# never become markup in another user's DOM even if a sink is ever added without escaping. Angle
# brackets are never legitimate in a display name. (Control characters are a separate concern,
# already stripped at the file sinks by the sanitiser, so they are not rejected here.)
def _reject_markup_chars(value: Optional[str], field: str) -> Optional[str]:
    if value is not None and ('<' in value or '>' in value):
        raise ValueError(f"{field} may not contain '<' or '>'")
    return value


# Group chip colours are interpolated into a CSS custom property on the client. Accept only a strict
# #hex or one of the fixed palette preset names (the swatches in index.html); anything else (a
# quote-carrying value, a CSS breakout) is rejected. Mirrors brand.js's colour validator.
_GROUP_COLOR_PRESETS = frozenset(
    {'teal', 'indigo', 'violet', 'rose', 'orange', 'sky', 'emerald', 'amber'}
)


def _validate_chip_color(value: Optional[str]) -> Optional[str]:
    if value is None or value == '':
        return value
    if value in _GROUP_COLOR_PRESETS:
        return value
    if value[0] == '#' and len(value) in (4, 7) and all(c in '0123456789abcdefABCDEF' for c in value[1:]):
        return value
    raise ValueError("color must be a #hex value or a named preset")


class UserCreate(BaseModel):
    username: str = Field(..., min_length=3, max_length=50)
    email: EmailStr
    password: str = Field(..., min_length=8)
    role: RoleEnum = RoleEnum.USER

    @field_validator('username')
    @classmethod
    def _clean_username(cls, v):
        return _reject_markup_chars(v, 'username')


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    role: Optional[RoleEnum] = None
    is_active: Optional[bool] = None
    is_locked: Optional[bool] = None
    # Per-account SFTP controls (settable by the user themselves or an admin).
    sftp_enabled: Optional[bool] = None
    sftp_password_auth: Optional[bool] = None


class SelfUpdate(BaseModel):
    """Self-service account update (PATCH /users/me). A credential-sensitive change (password or
    email) also requires the current password. Role / active / lock are deliberately absent — a user
    can never grant themselves privileges via this endpoint."""
    current_password: Optional[str] = None
    new_password: Optional[str] = Field(None, min_length=8)
    email: Optional[EmailStr] = None
    sftp_enabled: Optional[bool] = None
    sftp_password_auth: Optional[bool] = None


class GroupBrief(BaseModel):
    """Compact group reference embedded in user payloads."""
    id: uuid.UUID
    name: str
    color: Optional[str] = None

    class Config:
        from_attributes = True


class UserResponse(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: RoleEnum
    is_active: bool
    is_locked: bool
    sftp_enabled: bool = True
    sftp_password_auth: bool = True
    created_at: datetime
    last_login: Optional[datetime]
    groups: List[GroupBrief] = []

    class Config:
        from_attributes = True


class SSHKeyCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    public_key: str = Field(..., min_length=1)  # full OpenSSH public key line


class SSHKeyResponse(BaseModel):
    id: uuid.UUID
    name: str
    key_type: Optional[str] = None
    fingerprint: str
    created_at: datetime
    last_used: Optional[datetime] = None

    class Config:
        from_attributes = True


# LoginResponse declares `user: 'UserResponse'` as a forward reference before
# UserResponse exists. Pydantic v2 does not auto-resolve that during schema
# generation, so rebuild the model now that UserResponse is defined.
LoginResponse.model_rebuild()


# --- Organizational groups (departments) -----------------------------------
class GroupCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=20)
    parent_id: Optional[uuid.UUID] = None

    @field_validator('name')
    @classmethod
    def _clean_name(cls, v):
        return _reject_markup_chars(v, 'name')

    @field_validator('color')
    @classmethod
    def _clean_color(cls, v):
        return _validate_chip_color(v)


class GroupUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=20)
    parent_id: Optional[uuid.UUID] = None  # explicit null -> make it a root

    @field_validator('name')
    @classmethod
    def _clean_name(cls, v):
        return _reject_markup_chars(v, 'name')

    @field_validator('color')
    @classmethod
    def _clean_color(cls, v):
        return _validate_chip_color(v)


class GroupMemberRef(BaseModel):
    id: uuid.UUID
    username: str
    email: str
    role: RoleEnum
    group_role: str = 'member'

    class Config:
        from_attributes = True


class GroupResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str] = None
    color: Optional[str] = None
    parent_id: Optional[uuid.UUID] = None
    member_count: int = 0
    child_count: int = 0
    created_at: datetime

    class Config:
        from_attributes = True


class GroupDetailResponse(GroupResponse):
    members: List[GroupMemberRef] = []
    children: List[GroupResponse] = []


class GroupMembersAdd(BaseModel):
    user_ids: List[uuid.UUID]
    group_role: Optional[str] = 'member'


class VaultGroupAccessAdd(BaseModel):
    group_id: uuid.UUID
    permission: str = 'read'  # 'read' | 'write'


class ShareTagCreate(BaseModel):
    """Create a share tag (interactive-admin). Policy + create-allowlist. Ints are >= 1; a NULL cap or
    default means unlimited on that axis. Cross-field checks (default <= cap, default_lifetime <=
    ceiling, audiences subset, allowlist ids exist) run in the endpoint via _validate_share_tag_fields.
    The create-allowlist DEFAULTS FAIL-CLOSED (auto_enroll off + empty lists): a fresh tag grants no one
    until the admin allow-lists users/departments or enables auto-enroll."""
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=20)
    max_lifetime_minutes: int = Field(10080, ge=1)     # ceiling (7 days)
    default_lifetime_minutes: int = Field(1440, ge=1)  # default (1 day)
    max_recipients_cap: Optional[int] = Field(None, ge=1)
    max_recipients_default: Optional[int] = Field(None, ge=1)
    max_downloads_cap: Optional[int] = Field(None, ge=1)
    max_downloads_default: Optional[int] = Field(None, ge=1)
    allow_view_only: bool = True
    default_view_only: bool = False
    allow_custom: bool = True
    allowed_audiences: List[str] = Field(default_factory=lambda: list(sharing_policy.AUDIENCES))
    allowed_department_ids: List[uuid.UUID] = Field(default_factory=list)
    allowed_user_ids: List[uuid.UUID] = Field(default_factory=list)
    blocked_user_ids: List[uuid.UUID] = Field(default_factory=list)
    auto_enroll_new_users: bool = False

    @field_validator('name')
    @classmethod
    def _clean_name(cls, v):
        return _reject_markup_chars(v, 'name')

    @field_validator('color')
    @classmethod
    def _clean_color(cls, v):
        return _validate_chip_color(v)

    @field_validator('description')
    @classmethod
    def _clean_description(cls, v):
        # Strip HTML markup at the input boundary like every sibling free-text field (name/username/…),
        # so the Tags-manager UI can never render a stored-XSS payload from a tag description.
        return _reject_markup_chars(v, 'description') if v is not None else v


class ShareTagUpdate(BaseModel):
    """Patch a share tag (interactive-admin). All fields optional; only PROVIDED keys change (an
    explicit null on a cap/default clears it -> unlimited). is_active toggles soft-deactivate/reactivate."""
    name: Optional[str] = Field(None, min_length=1, max_length=120)
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=20)
    is_active: Optional[bool] = None
    max_lifetime_minutes: Optional[int] = Field(None, ge=1)
    default_lifetime_minutes: Optional[int] = Field(None, ge=1)
    max_recipients_cap: Optional[int] = Field(None, ge=1)
    max_recipients_default: Optional[int] = Field(None, ge=1)
    max_downloads_cap: Optional[int] = Field(None, ge=1)
    max_downloads_default: Optional[int] = Field(None, ge=1)
    allow_view_only: Optional[bool] = None
    default_view_only: Optional[bool] = None
    allow_custom: Optional[bool] = None
    allowed_audiences: Optional[List[str]] = None
    allowed_department_ids: Optional[List[uuid.UUID]] = None
    allowed_user_ids: Optional[List[uuid.UUID]] = None
    blocked_user_ids: Optional[List[uuid.UUID]] = None
    auto_enroll_new_users: Optional[bool] = None

    @field_validator('name')
    @classmethod
    def _clean_name(cls, v):
        return _reject_markup_chars(v, 'name') if v is not None else v

    @field_validator('color')
    @classmethod
    def _clean_color(cls, v):
        return _validate_chip_color(v)

    @field_validator('description')
    @classmethod
    def _clean_description(cls, v):
        return _reject_markup_chars(v, 'description') if v is not None else v


class ShareCreate(BaseModel):
    """Create a share of a file / folder / whole Standard vault. Standard-only; the chosen tag governs
    the limits + who may create. Limit overrides are honored only within the tag caps (and only if the
    tag permits customization). `with_link` mints the show-once claimable link token."""
    vault_id: uuid.UUID
    tag_id: uuid.UUID
    target_type: str = Field(..., pattern='^(vault|folder|file)$')
    target_folder_id: Optional[uuid.UUID] = None
    target_file_id: Optional[uuid.UUID] = None
    claim_audience: str = Field(..., pattern='^(users|departments|anyone_internal)$')
    audience_user_ids: List[uuid.UUID] = Field(default_factory=list)
    audience_department_ids: List[uuid.UUID] = Field(default_factory=list)
    lifetime_minutes: Optional[int] = Field(None, ge=1)
    max_recipients: Optional[int] = Field(None, ge=1)
    max_downloads: Optional[int] = Field(None, ge=1)
    view_only: Optional[bool] = None
    with_link: bool = True


class ShareClaimRequest(BaseModel):
    """Claim a share by its link token."""
    token: str = Field(..., min_length=1, max_length=512)


class TempCredentialCreate(BaseModel):
    # Optional overrides for the credential lifetime. When omitted, the server
    # falls back to the configured defaults (temp_cred_validity_minutes /
    # temp_cred_total_lifetime_minutes). Capped at 30 days (43200 minutes).
    validity_minutes: Optional[int] = Field(None, gt=0, le=43200)
    total_lifetime_minutes: Optional[int] = Field(None, gt=0, le=43200)
    note: Optional[str] = Field(None, max_length=500)
    can_create_temp_credentials: bool = False
    # Least-privilege scope (None = legacy/unrestricted). See app/core/temp_scope.py.
    scope: Optional[dict] = None
    vault_access_mode: Optional[str] = None          # 'all' | 'selected'
    # [{"vault_id":..., "caps":[...], "scope_ids":..., "password":..., "issue_passcode":bool,
    #   "passcode":"custom-or-omitted", "one_time":bool?}] — passcode fields are optional per vault.
    selected_vaults: Optional[list] = None
    # Issue ONE shared temporary passcode across all passcode-enabled selected vaults (a supplied
    # custom value if any, else a single generated one), stored as N verifiers.
    passcode_same_for_all: Optional[bool] = None


class TempCredentialResponse(BaseModel):
    temp_username: str
    credential: str
    created_at: str
    deactivate_at: str
    expires_at: str
    validity_minutes: int
    total_lifetime_minutes: int
    note: Optional[str] = None
    can_create_temp_credentials: bool = False
    scope: Optional[dict] = None
    vault_access_mode: Optional[str] = None
    # Temporary vault passcodes minted with this credential, shown ONCE. [{vault_id, passcode, kind}].
    passcodes: list = []


class VaultCreate(BaseModel):
    name: str = Field(..., min_length=1, max_length=255)
    description: Optional[str] = None
    password: Optional[str] = None
    expire_files_after_days: Optional[int] = Field(None, gt=0)
    # Per-vault maximum size in GB (absent => 1 GB, the model column default). Bounded at create
    # time by the admin per-vault ceiling and the owner's remaining account budget (see
    # _enforce_vault_size); a scoped temp cred / non-admin can never exceed its account quota.
    size_limit_gb: Optional[float] = Field(None, gt=0)
    # Confidentiality tier; the creation-policy hook resolves/validates it.
    # Defaults to 'standard' (today's only functional tier).
    type: Optional[str] = None
    # Zero-knowledge only: the vault DEK is generated AND wrapped in the BROWSER to
    # the owner's own public key; only the opaque wrapped form is sent here. The
    # server never sees the DEK.
    wrapped_dek: Optional[str] = None
    ephemeral_public_key: Optional[str] = None
    # Hierarchical ZK mode (large vaults): the browser also mints a per-vault TEAM keypair,
    # wraps the DEK to the team PUBLIC key (team_wrapped_dek/team_dek_ephemeral_public_key) and
    # wraps the team PRIVATE key to the owner's identity key (wrapped_team_privkey/
    # team_privkey_ephemeral_public_key). Set key_wrapping_mode='hierarchical' to use it.
    # Absent => 'direct' (the DEK is wrapped straight to the owner, as today).
    key_wrapping_mode: Optional[str] = None
    team_public_key: Optional[str] = None
    team_wrapped_dek: Optional[str] = None
    team_dek_ephemeral_public_key: Optional[str] = None
    wrapped_team_privkey: Optional[str] = None
    team_privkey_ephemeral_public_key: Optional[str] = None

    @field_validator('name')
    @classmethod
    def _clean_name(cls, v):
        # The vault's own display name is plaintext even for ZK vaults (only file/folder names are
        # client-encrypted), so this reject applies to it the same way and is regression-free.
        return _reject_markup_chars(v, 'name')


class VaultUpdate(BaseModel):
    name: Optional[str] = Field(None, min_length=1, max_length=255)
    description: Optional[str] = None
    password: Optional[str] = None
    expire_files_after_days: Optional[int] = Field(None, gt=0)

    @field_validator('name')
    @classmethod
    def _clean_name(cls, v):
        return _reject_markup_chars(v, 'name')


class FileRename(BaseModel):
    # Plaintext new name for Standard vaults. For ZERO-KNOWLEDGE vaults this is omitted and
    # the browser supplies the encrypted name + blind index instead (the server never sees
    # the new name). One of new_name (Standard) / enc_name+name_bi (ZK) must be present.
    new_name: Optional[str] = Field(None, min_length=1, max_length=255)
    enc_name: Optional[str] = None
    name_bi: Optional[str] = Field(None, max_length=64)  # stored in a VARCHAR(64) column
    # For ZK FOLDER renames: the DEK epoch the name was encrypted under (folders carry their
    # own name epoch). Ignored for files (a file's name epoch follows its content epoch).
    name_key_version: Optional[int] = None

    @field_validator('new_name')
    @classmethod
    def _clean_new_name(cls, v):
        # Only the Standard plaintext path sets new_name; ZK renames use enc_name (untouched).
        return _reject_markup_chars(v, 'new_name')


class VaultResponse(BaseModel):
    id: uuid.UUID
    name: str
    description: Optional[str]
    owner_id: uuid.UUID
    owner_username: Optional[str] = None
    has_password: bool
    expire_files_after_days: Optional[int]
    expire_files_unit: Optional[str]
    unlock_remember_minutes: Optional[int] = None
    size_limit: Optional[int]
    # Whole-vault aggregates. Null when the caller is a per-file/folder-scoped credential: the
    # denormalized counters cover the ENTIRE vault, so returning them would reveal the count/size
    # of files outside the credential's scope (an anti-enumeration leak).
    total_size_bytes: Optional[int]
    file_count: Optional[int]
    created_at: datetime
    updated_at: datetime
    last_accessed: Optional[datetime]
    is_active: bool
    type: str = 'standard'               # confidentiality tier: 'standard' | 'zero_knowledge'
    my_permission: Optional[str] = None  # owner | delete | write | read | none — caller's effective level
    is_favorite: bool = False            # starred by the caller

    class Config:
        from_attributes = True


class VaultMemberAdd(BaseModel):
    user_id: uuid.UUID
    read_permission: bool = True
    write_permission: bool = False
    delete_permission: bool = False


class PermissionGrant(BaseModel):
    user_id: uuid.UUID
    permission: PermissionEnum


class VaultPermissionAdd(BaseModel):
    user_id: uuid.UUID
    # 'manage' makes the member a vault Manager (read+write+delete + delegated
    # member/access administration). Only the owner or a global admin may assign it.
    level: str = Field(..., pattern="^(read|write|delete|manage)$")


class VaultPermissionResponse(BaseModel):
    user_id: uuid.UUID
    username: str
    email: str
    read_permission: bool
    write_permission: bool
    delete_permission: bool
    manage_permission: bool = False
    added_at: datetime

    class Config:
        from_attributes = True


class DashboardStats(BaseModel):
    total_users: int
    total_vaults: int
    total_files: int
    total_storage_bytes: int
    active_sessions: int


class EndpointPermissionGroupResponse(BaseModel):
    """Response model for functionality group info"""
    name: str
    display_name: str
    description: str
    ui_section: str
    default_for_roles: List[str]
    endpoint_count: int
    endpoints: List[dict]
    dependencies: List[str]


class UserPermissionsResponse(BaseModel):
    """Response model for user's permissions"""
    user_id: uuid.UUID
    username: str
    email: str
    role: str
    granted_groups: List[str]
    permissions: List[dict]


class GrantPermissionRequest(BaseModel):
    """Request model for granting permission group"""
    endpoint_group: str = Field(..., description="Name of functionality group to grant")


# Dependencies

async def get_current_user(
    credentials: HTTPAuthorizationCredentials = Depends(security),
    db: Session = Depends(get_db)
) -> User:
    """
    Dependency to get current authenticated user from JWT token.
    For temporary credentials, validates that the session is still active.
    """
    token = credentials.credentials
    
    payload = verify_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={
                "WWW-Authenticate": "Bearer",
                "Clear-Site-Data": '"cache", "cookies", "storage"'
            },
        )
    
    user_id = payload.get("sub")
    if not user_id:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload",
            headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
        )
    
    # Check if this is a temporary credential session
    session_token = payload.get("session_token")
    is_temporary = payload.get("is_temporary", False)
    temp_cred = None  # the TemporaryCredential row backing a temp session

    # Every token this server mints carries a session_token (login is the ONLY issuer —
    # app/api/api_server.py create_access_token call site). A token WITHOUT one can only be a forgery
    # or a stripped/legacy token, and it would bypass every revocation check below (all gated
    # on session_token). Reject it so leaked/forged tokens remain revocable.
    if not session_token:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid authentication credentials",
            headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
        )

    # Revocation: a logged-out token is denylisted until it expires. This revokes the token
    # for ALL users WITHOUT enforcing single-session (re-login denylists nothing), so
    # concurrent sessions still work. See auth_service.denylist_token.
    from app.services.auth_service import is_token_denylisted
    if session_token and is_token_denylisted(session_token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Session has been terminated. Please login again.",
            headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
        )

    # Durable revocation for REGULAR-user tokens: a logged-out / locked / deactivated session
    # is marked `revoked` in the DB (see logout + _revoke_sessions). Unlike the best-effort
    # Redis denylist above, this survives a Redis outage. We reject only an explicitly-revoked
    # session — a new login does NOT set `revoked`, so concurrent sessions keep working (no
    # single-session side effect). Temp sessions get a stricter is_active check below.
    if session_token and not is_temporary:
        from app.core.models import ActiveSession
        revoked_session = db.query(ActiveSession.revoked).filter(
            ActiveSession.session_token == session_token
        ).first()
        if revoked_session is not None and revoked_session[0]:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been terminated. Please login again.",
                headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
            )

    if is_temporary and session_token:
        # Validate that the session is still active
        from app.core.models import ActiveSession, TemporaryCredential
        from datetime import timedelta

        session = db.query(ActiveSession).filter(
            ActiveSession.session_token == session_token,
            ActiveSession.is_active == True
        ).first()

        if not session:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been terminated. Please login again.",
                headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
            )
        
        # Also check if session has expired based on grace period
        grace_minutes = int(os.getenv('TEMP_CRED_SESSION_GRACE_MINUTES', '65'))
        grace_cutoff = datetime.now(timezone.utc) - timedelta(minutes=grace_minutes)
        
        # ActiveSession.last_activity is stored naive (UTC); make it tz-aware so
        # this comparison doesn't raise "can't compare offset-naive and
        # offset-aware datetimes" — that was 500-ing every temp-credential request.
        last_activity = session.last_activity
        if last_activity is not None and last_activity.tzinfo is None:
            last_activity = last_activity.replace(tzinfo=timezone.utc)

        if last_activity is not None and last_activity < grace_cutoff:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has expired due to inactivity.",
                headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
            )

        # Load the credential row backing this session; its scope is attached below.
        temp_cred = db.query(TemporaryCredential).filter(
            TemporaryCredential.id == session.temp_credential_id
        ).first()

        # Fail CLOSED: an ACTIVE temp session whose backing credential row is missing (a broken DB
        # invariant — the FK is ON DELETE CASCADE and every deletion revokes the session in the same
        # commit, so this is not reachable via a normal app flow) must NOT run as an unrestricted
        # principal. Denying here is safer than proceeding as an unscoped session, which would no-op
        # is_scoped() and every per-vault capability gate.
        if temp_cred is None:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Session has been terminated. Please login again.",
                headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
            )

        # Bound the session by the credential's OWN stated lifetime, not just the
        # inactivity grace window above: a temp cred past its validity window
        # (deactivate_at) or hard expiry (expires_at) must stop authorizing requests
        # even while its session row is still nominally active. Stored naive (UTC).
        if temp_cred is not None:
            _now = datetime.now(timezone.utc)
            for _limit in (temp_cred.deactivate_at, temp_cred.expires_at):
                if _limit is None:
                    continue
                if _limit.tzinfo is None:
                    _limit = _limit.replace(tzinfo=timezone.utc)
                if _now > _limit:
                    raise HTTPException(
                        status_code=status.HTTP_401_UNAUTHORIZED,
                        detail="Temporary credential has expired. Please login again.",
                        headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
                    )

    user = db.query(User).filter(User.id == uuid.UUID(user_id)).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="User not found",
            headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
        )
    
    if not user.is_active:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is inactive",
            headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
        )

    # A locked account is rejected on every request (not just at login), so an admin
    # locking a user revokes their already-issued token immediately. A FAILED-LOGIN auto-lock
    # auto-expires (account_locked honours locked_until), so a brute-force on a victim's
    # username can't keep their valid session locked out beyond the TTL.
    from app.services.auth_service import account_locked
    if account_locked(user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="User account is locked",
            headers={"Clear-Site-Data": '"cache", "cookies", "storage"'}
        )

    # Surface the temp-session context (scope, vault mode, per-vault caps) so the
    # permission decorator and the data layer can enforce least privilege.
    # NULL scope = legacy credential = unrestricted (handled inside the helpers).
    if is_temporary and session_token and temp_cred is not None:
        from app.core.temp_scope import attach_scope
        attach_scope(db, user, temp_cred)
    else:
        # Fail SAFE: a temp session (is_temporary + session_token) whose scope row can't be loaded must
        # still be flagged, so it can never fall through require_interactive_admin as an interactive admin.
        user._is_temp_session = bool(is_temporary and session_token)
    return user


async def require_admin(current_user: User = Depends(get_current_user)) -> User:
    """Dependency to require admin role."""
    if current_user.role != RoleEnum.ADMIN:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


async def require_interactive_admin(current_user: User = Depends(require_admin)) -> User:
    """Admin dependency that ALSO rejects temporary-credential sessions.

    Org-policy writes — e.g. PUT /settings, which sets zero_knowledge_enabled /
    force_zero_knowledge / standard_vault_allowed_groups (the confidentiality boundary
    for the whole deployment) — must be performed by a real INTERACTIVE admin. An
    admin-minted temporary credential keeps the admin ROLE (get_current_user returns the
    real admin User and attach_scope does not downgrade role), so require_admin alone would
    let a tightly-scoped temp credential flip that boundary. Reject temp sessions here."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="This action requires an interactive admin session, not a temporary credential.",
        )
    return current_user


def get_client_ip(request: Request) -> str:
    """Get the client IP. Honours X-Forwarded-For ONLY from a trusted proxy peer, so a direct
    (untrusted) client can't spoof its IP to poison per-IP throttles or audit logs. See
    net_utils.client_ip (trusted set = settings.trusted_proxies, EMPTY by default => XFF ignored,
    peer used; the operator opts in by declaring their reverse-proxy network)."""
    from app.core.net_utils import client_ip
    return client_ip(request)


def get_current_metrics() -> dict:
    """
    Get current system metrics for broadcasting.
    Called by broadcast_event to include real-time metrics with each event.
    """
    from app.core.database import SessionLocal
    from sqlalchemy import func, distinct
    from app.core.models import ActiveSession, TemporaryCredential, AuditLog, File
    
    db = SessionLocal()
    try:
        grace_cutoff = datetime.now(timezone.utc) - timedelta(minutes=65)
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        
        # Active users
        active_users = db.query(func.count(distinct(ActiveSession.user_id))).filter(
            ActiveSession.is_active == True,
            ActiveSession.last_activity >= grace_cutoff
        ).scalar() or 0
        
        # Temp credentials
        total_temp_creds = db.query(func.count(TemporaryCredential.id)).filter(
            TemporaryCredential.expires_at > datetime.now(timezone.utc)
        ).scalar() or 0
        
        active_temp_creds = db.query(func.count(distinct(TemporaryCredential.id))).join(
            ActiveSession, ActiveSession.temp_credential_id == TemporaryCredential.id
        ).filter(
            TemporaryCredential.expires_at > datetime.now(timezone.utc),
            ActiveSession.is_active == True,
            ActiveSession.last_activity >= grace_cutoff
        ).scalar() or 0
        
        # Traffic (last hour)
        upload_count = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "upload",
            AuditLog.timestamp >= one_hour_ago
        ).scalar() or 0
        
        download_count = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "download",
            AuditLog.timestamp >= one_hour_ago
        ).scalar() or 0
        
        upload_traffic = upload_count * 1024 * 1024
        download_traffic = download_count * 1024 * 1024
        
        # Total files
        total_files = db.query(func.count(File.id)).scalar() or 0
        
        # Active operations (uploads/downloads currently in progress)
        active_ops = get_active_operations_count()
        
        return {
            "activeUsers": active_users,
            "tempCreds": total_temp_creds,
            "tempCredsActive": active_temp_creds,
            "uploadTraffic": upload_traffic,
            "downloadTraffic": download_traffic,
            "activeOperations": active_ops,
            "totalFiles": total_files
        }
    except Exception as e:
        print(f"Error getting metrics: {e}")
        return {}
    finally:
        db.close()


def broadcast_event(event_data: dict, include_metrics: bool = True) -> None:
    """
    Broadcast an event to all connected WebSocket clients via Redis pub/sub.
    Automatically includes current system metrics with each broadcast.
    
    Args:
        event_data: Dictionary containing event information:
            - event: Event object with type, title, description, user, ip, timestamp
            - traffic: Optional traffic data {upload: bytes, download: bytes}
            - operations: Optional active operations count
        include_metrics: If True, fetch and include current metrics (default: True)
    """
    from app.core.database import redis_client
    try:
        # Add current metrics to the broadcast
        if include_metrics:
            metrics = get_current_metrics()
            event_data['metrics'] = metrics
            
            # Extract data for graphs if not already provided
            if 'operations' not in event_data:
                event_data['operations'] = metrics.get('activeOperations', 0)
            
            if 'traffic' not in event_data:
                event_data['traffic'] = {
                    'upload': metrics.get('uploadTraffic', 0),
                    'download': metrics.get('downloadTraffic', 0)
                }
        
        # Publish to Redis channel that WebSocket endpoint subscribes to
        redis_client.publish("activity_events", json.dumps(event_data))
    except Exception as e:
        print(f"Error broadcasting event: {e}")


# API Endpoints

@app.get("/api")
async def api_root():
    """API information endpoint."""
    return {
        "message": "Secure SFTP Management API",
        "version": "1.0.0",
        "status": "operational"
    }


@app.get("/health")
async def health_check():
    """Health check endpoint."""
    db_ok = check_db_connection()
    redis_ok = check_redis_connection()
    
    return {
        "status": "healthy" if (db_ok and redis_ok) else "degraded",
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected"
    }


@app.get("/audit/events")
async def recent_audit_events(
    limit: int = 10,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Recent audit-log entries for the dashboard activity feed (admin only)."""
    from app.core.models import AuditLog
    limit = max(1, min(limit, 50))
    rows = db.query(AuditLog).order_by(AuditLog.timestamp.desc()).limit(limit).all()
    out = []
    for r in rows:
        level = 'success' if r.status == 'success' else ('error' if r.status in ('error', 'failure') else 'info')
        out.append({
            'action': r.action,
            'username': r.username,
            'description': (r.action or '').replace('_', ' '),
            'level': level,
            'timestamp': r.timestamp.isoformat() if r.timestamp else None,
            'details': None,
        })
    return out


# ---------------------------------------------------------------------------
# Audit log search + export (admin Audit page)
# ---------------------------------------------------------------------------

def _build_audit_query(db: Session, user_id=None, action=None, from_date=None, to_date=None):
    """Build the filtered AuditLog query shared by search + export."""
    from app.core.models import AuditLog
    q = db.query(AuditLog)
    if user_id:
        try:
            q = q.filter(AuditLog.user_id == uuid.UUID(str(user_id)))
        except (ValueError, AttributeError, TypeError):
            pass  # ignore an unparseable user id rather than 500
    if action:
        q = q.filter(AuditLog.action.ilike(f"%{action}%"))
    if from_date:
        try:
            q = q.filter(AuditLog.timestamp >= datetime.fromisoformat(from_date))
        except ValueError:
            pass
    if to_date:
        try:
            q = q.filter(AuditLog.timestamp < datetime.fromisoformat(to_date) + timedelta(days=1))
        except ValueError:
            pass
    return q


def _audit_row_to_dict(r):
    return {
        "timestamp": r.timestamp.isoformat() if r.timestamp else None,
        "username": r.username,
        "action": r.action,
        "status": r.status,
        "ip_address": r.ip_address,
        "resource_type": r.resource_type,
        "resource_id": r.resource_id,
        "details": r.details,
    }


@app.get("/audit/log")
async def search_audit_log(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    limit: int = 500,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Filtered audit-log search for the admin Audit page (admin only)."""
    from app.core.models import AuditLog
    limit = max(1, min(limit, 2000))
    rows = (
        _build_audit_query(db, user_id, action, from_date, to_date)
        .order_by(AuditLog.timestamp.desc())
        .limit(limit)
        .all()
    )
    return [_audit_row_to_dict(r) for r in rows]


def _csv_formula_safe(value):
    """Neutralise spreadsheet formula injection. A CSV cell that begins with =, +, -, @ (or a
    leading tab / carriage return) is interpreted as a FORMULA by Excel / Google Sheets. Audit
    cells carry attacker-influenced text (e.g. a failed-login username recorded verbatim), so a
    value like ``=cmd|'/c calc'!A1`` would execute when an admin opens the export. Prefix any such
    cell with a single quote so the spreadsheet treats it as literal text."""
    if isinstance(value, str) and value[:1] in ('=', '+', '-', '@', '\t', '\r'):
        return "'" + value
    return value


@app.get("/audit/export")
async def export_audit_log(
    user_id: Optional[str] = None,
    action: Optional[str] = None,
    from_date: Optional[str] = None,
    to_date: Optional[str] = None,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Export the filtered audit log as CSV (admin only)."""
    import csv
    from app.core.models import AuditLog
    rows = (
        _build_audit_query(db, user_id, action, from_date, to_date)
        .order_by(AuditLog.timestamp.desc())
        .limit(10000)
        .all()
    )
    buf = io.StringIO()
    writer = csv.writer(buf)
    writer.writerow(["Timestamp", "Username", "Action", "Status", "IP Address",
                     "Resource Type", "Resource ID", "Details"])
    for r in rows:
        writer.writerow([_csv_formula_safe(cell) for cell in (
            r.timestamp.isoformat() if r.timestamp else "",
            r.username or "",
            r.action or "",
            r.status or "",
            r.ip_address or "",
            r.resource_type or "",
            r.resource_id or "",
            json.dumps(r.details) if r.details else "",
        )])
    return Response(
        content=buf.getvalue(),
        media_type="text/csv",
        headers={"Content-Disposition": "attachment; filename=audit-log.csv"},
    )


# ---------------------------------------------------------------------------
# Global application settings (admin Settings page)
#
# Persistence only: settings are stored + returned so the page works end to
# end. Wiring each setting into actual enforcement (password policy, upload
# limits, SMTP send, quotas) is a separate follow-up.
# ---------------------------------------------------------------------------
_SETTINGS_KEY = "global"
_SETTINGS_SENSITIVE = {"smtp_password"}

# ---------------------------------------------------------------------------
# Brand fields: the settings keys that ALSO drive the effective branding.
# When present in a /settings PUT they are validated here and mirrored into the
# brand override row SystemSetting('brand') (see update_settings), so the admin
# Settings page edits /branding + the rendered shell (title/header/theme colours)
# live with no restart. Each maps 1:1 to a BrandingConfig field; the explicit
# allow-list keeps a Settings PUT from writing arbitrary keys into the brand row.
# An EMPTY/whitespace value clears that override -> reverts to the env default.
# ---------------------------------------------------------------------------
_BRAND_TEXT_FIELDS = {          # field -> max length of the stripped value
    "app_name": 100,
    "app_description": 500,
    "app_full_name": 150,
    "app_tagline": 200,
    "company_name": 120,
    "copyright_holder": 120,
}
_BRAND_EMAIL_FIELDS = {"support_email"}
_BRAND_URL_FIELDS = {"company_url", "website_url", "docs_url"}
_BRAND_COLOR_FIELDS = {
    "primary_color", "secondary_color", "accent_color", "success_color",
    "warning_color", "error_color", "text_color", "background_color",
}
_BRAND_FIELDS = (
    set(_BRAND_TEXT_FIELDS)
    | _BRAND_EMAIL_FIELDS
    | _BRAND_URL_FIELDS
    | _BRAND_COLOR_FIELDS
)
_BRAND_URL_MAX = 500


def _is_safe_brand_url(v: str) -> bool:
    """Server mirror of static/js/brand.js::safeUrl: allow ONLY a same-origin path
    ('/...' but not '//host') or an absolute http(s):// URL. Rejects javascript:/data:/
    other schemes, protocol-relative '//host', and any backslash or control char
    (browsers normalise '\\'->'/' and strip \\t/\\n/\\r, so '/\\host' or '/<TAB>/host'
    would resolve protocol-relative cross-origin past a naive leading-slash check)."""
    if any(ch == "\\" or ord(ch) < 0x20 for ch in v):
        return False
    if v[:1] == "/" and v[1:2] != "/":
        return True
    low = v.lower()
    return low.startswith("http://") or low.startswith("https://")


def _validate_brand_overrides(payload: dict) -> None:
    """Validate the brand fields present in a /settings payload before they are
    mirrored into the effective branding. A bad value would rebrand the rendered
    shell or (a colour) inject into the :root style block, so reject with a clear
    per-field 400. An empty/whitespace value is allowed — it clears the override.
    Reuses branding.py's HEX_COLOR_RE and the model's email rule so the write path
    matches the model validators and the read-time merge guard."""
    for field, cap in _BRAND_TEXT_FIELDS.items():
        if field not in payload:
            continue
        val = payload[field]
        if not isinstance(val, str):
            raise HTTPException(status_code=400, detail=f"{field} must be a string")
        if len(val.strip()) > cap:
            raise HTTPException(status_code=400, detail=f"{field} must be {cap} characters or fewer")

    for field in _BRAND_EMAIL_FIELDS:
        if field not in payload:
            continue
        val = payload[field]
        if not isinstance(val, str):
            raise HTTPException(status_code=400, detail=f"{field} must be a string")
        v = val.strip()
        if v and ("@" not in v or len(v) > 254):
            raise HTTPException(status_code=400, detail=f"{field} must be a valid email address")

    for field in _BRAND_URL_FIELDS:
        if field not in payload:
            continue
        val = payload[field]
        if not isinstance(val, str):
            raise HTTPException(status_code=400, detail=f"{field} must be a string")
        v = val.strip()
        if v and (len(v) > _BRAND_URL_MAX or not _is_safe_brand_url(v)):
            raise HTTPException(status_code=400, detail=f"{field} must be an http(s):// or /relative URL")

    for field in _BRAND_COLOR_FIELDS:
        if field not in payload:
            continue
        val = payload[field]
        if not isinstance(val, str):
            raise HTTPException(status_code=400, detail=f"{field} must be a string")
        v = val.strip()
        if v and not HEX_COLOR_RE.match(v):
            raise HTTPException(status_code=400, detail=f"{field} must be a hex colour like #2563eb")


def _validate_group_id_list(payload: dict, key: str, db: Session) -> None:
    """If `key` is present in payload, require it to be a list of EXISTING group
    ids — a typo'd id would otherwise sit in a policy doing nothing (the readers
    fail open on ids they can't resolve)."""
    if key not in payload:
        return
    groups = payload[key]
    if not isinstance(groups, list) or not all(isinstance(g, str) for g in groups):
        raise HTTPException(status_code=400, detail=f"{key} must be a list of group ids")
    try:
        wanted = {uuid.UUID(g) for g in groups}
    except (ValueError, AttributeError):
        raise HTTPException(status_code=400, detail=f"{key} contains an invalid group id")
    if wanted:
        from app.core.models import Group
        existing = {row[0] for row in db.query(Group.id).filter(Group.id.in_(wanted)).all()}
        missing = wanted - existing
        if missing:
            raise HTTPException(
                status_code=400,
                detail=f"Unknown group id(s): {', '.join(sorted(str(m) for m in missing))}",
            )


_DIRECTORY_SEARCH_SCOPES = ("deployment", "same_department")


def _directory_search_scope(db: Session) -> str:
    """Org policy governing GET /users/search breadth: 'deployment' (default — any active,
    non-EXTERNAL account is findable by a vault sharer) or 'same_department' (only accounts sharing
    at least one group/department with the caller). Unset/invalid -> 'deployment' (today's behavior)."""
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    val = (row.value or {}).get("directory_search_scope") if (row and row.value) else None
    return val if val in _DIRECTORY_SEARCH_SCOPES else "deployment"


_GIB = 1024 ** 3
_INT64_MAX = 2 ** 63 - 1  # the size_limit column is BigInteger; a larger value overflows it


def _quota_setting_bytes(db: Session, key: str) -> int:
    """A GB quota from the global settings blob -> bytes. Missing / non-positive / unparseable => 0,
    which means UNLIMITED on that axis (not enforced). So a fresh deployment that never set the value
    is unbounded, and an admin opts in by saving a positive number of GB."""
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    val = (row.value or {}).get(key) if (row and row.value) else None
    try:
        gb = float(val)
    except (TypeError, ValueError):
        return 0
    return int(gb * _GIB) if gb > 0 else 0


def _account_reserved_bytes(db: Session, owner_id, exclude_vault_id=None) -> int:
    """Sum of the declared per-vault size_limit across an owner's ACTIVE vaults — a RESERVATION
    (declared, not used), so a user can't oversubscribe their account budget by declaring large
    limits they may never fill. Optionally excludes one vault (when re-sizing it)."""
    from sqlalchemy import func as _f
    q = db.query(_f.coalesce(_f.sum(Vault.size_limit), 0)).filter(
        Vault.owner_id == owner_id, Vault.is_active == True)  # noqa: E712
    if exclude_vault_id is not None:
        q = q.filter(Vault.id != exclude_vault_id)
    return int(q.scalar() or 0)


def _max_allowed_vault_size_bytes(db: Session, owner: User, exclude_vault_id=None):
    """The largest size_limit (bytes) this owner may declare for ONE vault, bounded by the admin
    'Max Vault Size' per-vault ceiling AND — for non-admins — the remaining per-account budget
    ('Default User Storage Quota' minus what the owner's OTHER active vaults already reserve). Admins
    are still bounded by the per-vault ceiling but exempt from the account budget. Returns None when
    both axes are unlimited (nothing to enforce)."""
    caps = []
    ceiling = _quota_setting_bytes(db, "max_vault_size")
    if ceiling > 0:
        caps.append(ceiling)
    # "Full admin" = an interactive admin, NOT an admin-minted temp credential (which the codebase
    # deliberately does not treat as a full admin — mirrors the require_interactive_admin gate), so a
    # delegated credential can't over-consume the owner's account budget.
    is_full_admin = owner.role == RoleEnum.ADMIN and not getattr(owner, "_is_temp_session", False)
    if not is_full_admin:
        budget = _quota_setting_bytes(db, "default_user_quota")
        if budget > 0:
            caps.append(max(0, budget - _account_reserved_bytes(db, owner.id, exclude_vault_id)))
    return min(caps) if caps else None


def _enforce_vault_size(db: Session, owner: User, requested_bytes: int, exclude_vault_id=None) -> None:
    """Reject a requested per-vault size_limit that exceeds the owner's available headroom (the
    per-vault ceiling and/or the per-account budget). No-op when both are unlimited. The account
    budget is a best-effort reservation (a SELECT-then-write, not a lock), like the deployment-wide
    storage cap: two concurrent creates can overshoot by at most one vault's declared size — the
    per-upload guard remains the atomic backstop on ACTUAL bytes."""
    cap = _max_allowed_vault_size_bytes(db, owner, exclude_vault_id)
    if cap is not None and requested_bytes > cap:
        raise HTTPException(
            status_code=400,
            detail=(f"Requested vault size ({requested_bytes / _GIB:.2f} GB) exceeds the maximum size "
                    f"available to your account for this vault ({max(0, cap) / _GIB:.2f} GB)."),
        )


def _upload_policy(db: Session):
    """The current admin upload policy as (allowed_exts_set_or_None, effective_max_file_bytes) from
    ONE settings read. allowed=None means no file-type restriction. The max is the env per-file cap,
    lowered (never raised) by the admin 'max file size' setting."""
    from app.core import upload_policy
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    blob = (row.value or {}) if (row and row.value) else {}
    allowed = upload_policy.parse_allowed_exts(blob.get("allowed_file_types"))
    env_bytes = settings.max_file_size_mb * 1024 * 1024
    return allowed, upload_policy.effective_max_file_bytes(env_bytes, blob.get("max_file_size"))


def _enforce_file_type(filename: str, allowed_exts) -> None:
    """Reject (400) a filename whose extension isn't in the admin allowlist. No-op when allowed_exts
    is None (no restriction). ZK vaults are exempt at the call site (their names are encrypted, so
    the server can't see the extension). Takes a pre-read allowed set to avoid a per-file query."""
    from app.core import upload_policy
    if upload_policy.file_type_allowed(filename, allowed_exts):
        return
    ext = upload_policy.file_ext(filename)
    permitted = f" Allowed: {', '.join('.' + e for e in sorted(allowed_exts))}." if allowed_exts else ""
    raise HTTPException(
        status_code=400,
        detail=(f"File type '.{ext}' is not permitted here." if ext
                else "Files without an extension are not permitted here.") + permitted,
    )


def _setting_int(db: Session, key: str, default: int) -> int:
    """A positive-integer override from SystemSetting('global'), or `default` when absent / ≤0 /
    unparseable. Used to let the admin Settings UI tune the session-timeout without a redeploy."""
    from app.core.models import SystemSetting
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
        n = int((row.value or {}).get(key)) if (row and row.value) else 0
        return n if n > 0 else default
    except (TypeError, ValueError):
        return default


def _validate_password_policy(db: Session, password: str) -> None:
    """Enforce the admin account-password policy (min length + complexity) on a new account password.
    The API model already guarantees an 8-char floor; the stored policy can raise the minimum and add
    any complexity requirements the admin enabled. No-op when nothing beyond the floor is configured."""
    from app.core import password_policy
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    cfg = (row.value or {}) if (row and row.value) else {}
    errs = password_policy.password_policy_errors(password, cfg)
    if errs:
        raise HTTPException(status_code=400, detail="Password must " + "; ".join(errs) + ".")


# ---------------------------------------------------------------------------
# Temporary Vault Passcode policy. The effective values are resolved by the pure,
# unit-tested app/core/temp_passcode_policy module (mirrors password_policy.py);
# these thin wrappers just read the SystemSetting('global') blob and delegate. No
# PLAN_* env ceiling on this feature; no enforcement here (redemption
# reads them). Kept beside _zk_enabled/_directory_search_scope, NOT in
# app/config/effective.py (that resolver is branding-only).
# ---------------------------------------------------------------------------
def _global_settings_blob(db: Session) -> dict:
    """The raw SystemSetting('global') value dict, or {} on absence/error (so the passcode resolvers
    fail closed)."""
    from app.core.models import SystemSetting
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
        return (row.value or {}) if (row and row.value) else {}
    except Exception:
        return {}


def _temp_passcodes_enabled(db: Session) -> bool:
    """Master switch (FAIL-CLOSED: default False, and False for any non-bool stored value)."""
    from app.core import temp_passcode_policy
    return temp_passcode_policy.passcodes_enabled(_global_settings_blob(db))


def _sharing_enabled(db: Session) -> bool:
    """Sharing feature master switch (FAIL-CLOSED: default False, and False for any non-bool stored
    value). Mirrors _temp_passcodes_enabled / _zk_enabled; the per-tag policy lives in the share_tags
    table, this is only the deployment-wide on/off."""
    return sharing_policy.sharing_enabled(_global_settings_blob(db))


def _temp_cred_allow_zk_vaults(db: Session) -> bool:
    """May a zero-knowledge vault be included in a temporary credential's scope at all. Default True =
    today's behavior; only an explicit stored False denies (enforced fail-closed at the mint chokepoint)."""
    from app.core import temp_passcode_policy
    return temp_passcode_policy.allow_zk_vaults(_global_settings_blob(db))


def _temp_passcode_policy(db: Session) -> dict:
    """The effective Temporary Vault Passcode policy (INCLUDING temp_cred_allow_zk_vaults), keyed by the
    exact setting names so ONE call drives both the mint UI (GET /temp-passcode-policy) and the
    GET /settings overlay. No enforcement here — redemption reads this."""
    from app.core import temp_passcode_policy
    return temp_passcode_policy.effective_policy(_global_settings_blob(db))


def _force_no_remember_vault_password(db: Session) -> bool:
    """Org policy: when True, browser-remembering a vault password is forbidden deployment-wide, so
    every vault's EFFECTIVE unlock_remember_minutes is clamped to 0 (always re-ask). Default False."""
    return bool(_global_settings_blob(db).get("force_no_remember_vault_password", False))


def _zk_idle_lock_minutes(db: Session) -> int:
    """Org policy: auto-lock the in-memory zero-knowledge key (re-prompt for the passphrase) after N
    minutes of inactivity. 0 (default) = disabled. Enforced client-side; clamped to [0, 1440]."""
    v = _global_settings_blob(db).get("zk_idle_lock_minutes", 0)
    if isinstance(v, bool) or not isinstance(v, int):
        return 0
    return max(0, min(v, 1440))


def _validate_settings_payload(payload: dict, db: Session) -> None:
    """Validate the few settings keys that drive real enforcement so the admin UI
    can't silently persist values that later fail open. The store is otherwise
    generic: only keys PRESENT in the payload are checked, everything else passes
    through untouched.

    - zero_knowledge_enabled / force_zero_knowledge -> real booleans (a string
      "true" would otherwise coerce truthy and silently flip the policy).
    - sftp_require_temp_cred_groups / standard_vault_allowed_groups -> lists of
      EXISTING group ids (the SFTP gate and the force-ZK whitelist fail open on
      ids they can't resolve, so a typo would silently do nothing).
    """
    if not payload:
        return
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail="Settings payload must be an object")

    for bool_key in ("zero_knowledge_enabled", "force_zero_knowledge", "force_no_remember_vault_password",
                     "sharing_enabled"):
        if bool_key in payload and not isinstance(payload[bool_key], bool):
            raise HTTPException(status_code=400, detail=f"{bool_key} must be true or false")

    # Brand fields (app_name, tagline, company, support email, key URLs, the 8 theme
    # colours, copyright) are mirrored into the effective-branding override by
    # update_settings, so a bad value would rebrand the shell or inject into :root —
    # validate them here.
    _validate_brand_overrides(payload)

    _validate_group_id_list(payload, "sftp_require_temp_cred_groups", db)
    _validate_group_id_list(payload, "standard_vault_allowed_groups", db)

    if "directory_search_scope" in payload and payload["directory_search_scope"] not in _DIRECTORY_SEARCH_SCOPES:
        raise HTTPException(
            status_code=400,
            detail="directory_search_scope must be 'deployment' or 'same_department'",
        )

    # Storage quotas (GB). default_user_quota = per-account budget (sum of an owner's vault size
    # reservations); max_vault_size = the per-vault ceiling. Both are enforced at vault create/resize
    # (see _enforce_vault_size); 0 / absent means unlimited on that axis.
    for gb_key in ("default_user_quota", "max_vault_size"):
        if gb_key in payload and payload[gb_key] is not None:
            v = payload[gb_key]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise HTTPException(status_code=400, detail=f"{gb_key} must be a non-negative number of GB")

    # Upload policy: allowed_file_types (extension allowlist; empty = allow all) + max_file_size (MB).
    if "allowed_file_types" in payload and payload["allowed_file_types"] is not None:
        v = payload["allowed_file_types"]
        if not isinstance(v, list) or not all(isinstance(e, str) for e in v):
            raise HTTPException(status_code=400, detail="allowed_file_types must be a list of extension strings")
    if "max_file_size" in payload and payload["max_file_size"] is not None:
        v = payload["max_file_size"]
        if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
            raise HTTPException(status_code=400, detail="max_file_size must be a non-negative number of MB")

    # Account-password policy: minimum length + the four complexity toggles (enforced on user
    # create/password-change; the model keeps an 8-char hard floor the stored minimum can only raise).
    if "password_min_length" in payload and payload["password_min_length"] is not None:
        v = payload["password_min_length"]
        if isinstance(v, bool) or not isinstance(v, int) or v < 0:
            raise HTTPException(status_code=400, detail="password_min_length must be a non-negative integer")
    for bkey in ("require_uppercase", "require_lowercase", "require_numbers", "require_special"):
        if bkey in payload and not isinstance(payload[bkey], bool):
            raise HTTPException(status_code=400, detail=f"{bkey} must be true or false")

    # Auth limits (0/absent = keep the deployment env default). Enforced at login / token mint.
    # zk_idle_lock_minutes (0 = disabled) is a client-enforced ZK-key idle auto-lock.
    for int_key in ("max_login_attempts", "lockout_duration", "session_timeout", "zk_idle_lock_minutes"):
        if int_key in payload and payload[int_key] is not None:
            v = payload[int_key]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise HTTPException(status_code=400, detail=f"{int_key} must be a non-negative integer")

    # Temporary Vault Passcode policy. The master switch, the custom-passcode toggle + its complexity
    # toggles, the one-time/single-vault defaults, and whether ZK vaults may sit in a temp credential's
    # scope are all booleans; the length + max-lifetime are non-negative ints. No enforcement here —
    # redemption reads the effective policy via the helpers above.
    _TEMP_PASSCODE_BOOL_KEYS = (
        "temp_passcodes_enabled", "temp_cred_allow_zk_vaults", "temp_passcode_allow_custom",
        "temp_passcode_require_uppercase", "temp_passcode_require_lowercase",
        "temp_passcode_require_numbers", "temp_passcode_require_special",
        "temp_passcode_one_time_default", "temp_passcode_single_vault_only",
    )
    for bkey in _TEMP_PASSCODE_BOOL_KEYS:
        if bkey in payload and not isinstance(payload[bkey], bool):
            raise HTTPException(status_code=400, detail=f"{bkey} must be true or false")
    for int_key in ("temp_passcode_min_length", "temp_passcode_max_lifetime_minutes"):
        if int_key in payload and payload[int_key] is not None:
            v = payload[int_key]
            if isinstance(v, bool) or not isinstance(v, int) or v < 0:
                raise HTTPException(status_code=400, detail=f"{int_key} must be a non-negative integer")


@app.get("/settings")
async def get_settings(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Return stored global settings (sensitive fields stripped)."""
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    data = dict(row.value) if row and row.value else {}
    for k in _SETTINGS_SENSITIVE:
        data.pop(k, None)
    # Report the EFFECTIVE zero-knowledge state (plan ceiling + auto-enable), not the raw
    # stored flag: the admin toggle must reflect reality, or a settings save (which sends the
    # whole object) would persist the unchecked default and silently disable the auto-enabled
    # feature. An explicit admin off is preserved (_zk_enabled returns it verbatim).
    data["zero_knowledge_enabled"] = _zk_enabled(db)
    # Always report the EFFECTIVE directory-search policy so the admin toggle reflects the default
    # ('deployment') even when never explicitly saved.
    data["directory_search_scope"] = _directory_search_scope(db)
    # Overlay the EFFECTIVE Temporary Vault Passcode policy (incl. the ZK-in-scope toggle) so the
    # Settings card renders correct defaults even when never saved (feature default OFF, allow-ZK ON).
    data.update(_temp_passcode_policy(db))
    # Effective org floor for browser-remembering a vault password (default OFF).
    data["force_no_remember_vault_password"] = _force_no_remember_vault_password(db)
    # Effective ZK-key idle auto-lock (minutes; 0 = disabled).
    data["zk_idle_lock_minutes"] = _zk_idle_lock_minutes(db)
    # Effective Sharing master switch (default OFF) so the Settings -> Sharing toggle reflects reality.
    data["sharing_enabled"] = _sharing_enabled(db)
    return data


@app.put("/settings")
async def update_settings(
    payload: dict,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Persist global settings. Merges with the stored value so an omitted
    sensitive field (e.g. smtp_password) keeps its existing value.

    Gated by require_interactive_admin (NOT plain require_admin): a temporary credential —
    even one minted from an admin — must not rewrite the deployment's org policy
    (zero_knowledge_enabled / force_zero_knowledge / standard_vault_allowed_groups)."""
    _validate_settings_payload(payload, db)
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    existing = dict(row.value) if row and row.value else {}
    merged = {**existing, **(payload or {})}
    if row is None:
        db.add(SystemSetting(key=_SETTINGS_KEY, value=merged))
    else:
        row.value = merged  # reassign so SQLAlchemy flags the JSON column dirty
    # Mirror the BRAND fields into the effective-branding override row
    # SystemSetting('brand') (distinct from the 'global' settings row that
    # get_effective_branding merges over the env defaults) so the admin Settings
    # page drives /branding and the rendered shell <title>/header/theme colours live,
    # no restart. Each field is validated above; an empty/
    # whitespace value drops that override -> back to the env default.
    brand_keys = _BRAND_FIELDS & set((payload or {}).keys())
    if brand_keys:
        # shared writer (also used by the asset uploads + the setup wizard): non-empty sets, empty
        # clears -> env default. Values were validated by _validate_brand_overrides above.
        set_brand_overrides(db, updates={key: payload[key] for key in brand_keys})
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="settings_updated",
            status="success",
            user=current_user,
            ip_address=get_client_ip(request),
            details={"keys": sorted((payload or {}).keys())},
        )
    except Exception:
        pass  # never fail the save just because the audit write did
    return {"status": "ok"}


@app.post("/settings/test-email")
async def send_test_email(
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Send a test email to the requesting admin using the stored SMTP settings, to verify the
    Settings -> Email configuration end to end. Fails cleanly (not a 500) when SMTP isn't
    configured, and never echoes the stored SMTP password."""
    import smtplib
    from email.message import EmailMessage
    from app.core.rate_limiter import rate_limiter as _rl
    from app.core.models import SystemSetting

    # Sending mail is an outbound side effect — cap it per admin.
    allowed, _, reset = _rl.check_rate_limit(
        identifier=str(current_user.id), limit=5, window=60, prefix="test_email")
    if not allowed:
        import time as _t
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many test emails; please wait a moment.",
            headers={"Retry-After": str(max(1, reset - int(_t.time())))},
        )

    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    cfg = dict(row.value) if row and row.value else {}
    host = (cfg.get("smtp_server") or "").strip()
    from_email = (cfg.get("from_email") or "").strip()
    if not host or not from_email:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="SMTP is not configured. Set the SMTP server and From address in Settings → Email first.",
        )

    to_addr = (current_user.email or "").strip() or from_email
    try:
        port = int(cfg.get("smtp_port") or 587)
    except (TypeError, ValueError):
        port = 587
    username = (cfg.get("smtp_username") or "").strip()
    password = cfg.get("smtp_password") or ""
    from_name = (cfg.get("from_name") or "").strip()

    try:
        # EmailMessage encodes headers safely (rejects CRLF header injection). Building it INSIDE
        # the try means a control-char From name/address (saveable via PUT /settings, which doesn't
        # validate these fields) surfaces as a clean 400 below rather than an unhandled 500.
        msg = EmailMessage()
        msg["Subject"] = "DockVault test email"
        msg["From"] = f"{from_name} <{from_email}>" if from_name else from_email
        msg["To"] = to_addr
        msg.set_content(
            "This is a test email from your vault's SMTP configuration.\n"
            "If you received it, outbound email delivery is working."
        )

        if port == 465:
            server = smtplib.SMTP_SSL(host, port, timeout=15)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        with server:
            server.ehlo()
            encrypted = port == 465
            if port != 465 and server.has_extn("starttls"):
                server.starttls()
                server.ehlo()
                encrypted = True
            if username and not encrypted:
                # STARTTLS-strip defense: never send credentials over an unencrypted connection
                # (an on-path attacker can remove the STARTTLS advertisement from a plaintext EHLO).
                raise HTTPException(
                    status_code=status.HTTP_502_BAD_GATEWAY,
                    detail="The SMTP server does not offer STARTTLS; refusing to send credentials over an unencrypted connection.",
                )
            if username:
                server.login(username, password)
            server.send_message(msg)
    except smtplib.SMTPAuthenticationError:
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="SMTP authentication failed — check the username and password.",
        )
    except (ValueError, UnicodeError) as e:
        # Malformed From name/address (control chars) or SMTP host (bad IDNA) — a configuration
        # problem, returned cleanly instead of propagating as an unhandled 500.
        print(f"test-email config invalid: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="The SMTP configuration is invalid — check the server address and the From name/address.",
        )
    except (smtplib.SMTPException, OSError) as e:
        # Log the detail server-side; never surface it (or the password) to the client.
        print(f"test-email send failed: {type(e).__name__}: {e}")
        raise HTTPException(
            status_code=status.HTTP_502_BAD_GATEWAY,
            detail="Could not send the test email — check the SMTP server, port, and TLS settings.",
        )

    try:
        AuditLogger(db).log_action(
            action="test_email_sent", status="success", user=current_user,
            ip_address=get_client_ip(request), details={"to": to_addr},
        )
    except Exception:
        pass
    return {"message": f"Test email sent to {to_addr}"}


# ===========================================================================
# Authenticated, disableable log-PULL endpoint (GET /logs) + admin token mgmt.
# Two-layer gate: the env CEILING (settings.plan_log_pull, HARD, default off) AND a
# per-component DB flag in SystemSetting('logs'). A dedicated bearer dependency (NOT
# require_endpoint_permission, whose catalog-miss fails OPEN) validates a LogPullToken by
# peppered-HMAC constant-time compare. Every "off/unknown" path returns 404 so the feature is
# undetectable when disabled, and the response is redacted. See docs/ro2-3-phase1-build-plan.md.
# ===========================================================================
LOGS_SETTINGS_KEY = "logs"
_LOG_SINK_PATH = os.environ.get("LOG_PULL_SINK_PATH", "./logs/combined.log")


def _load_logs_settings(db) -> dict:
    """Per-component enable flags, in a DEDICATED SystemSetting('logs') row (like 'brand', not
    the shared 'global' row). Fail-closed to {} (feature off) on any read error."""
    try:
        from app.core.models import SystemSetting
        row = db.query(SystemSetting).filter(SystemSetting.key == LOGS_SETTINGS_KEY).first()
        return dict(row.value) if (row and row.value) else {}
    except Exception:  # noqa: BLE001
        return {}


def _set_logs_settings(db, updates: dict) -> None:
    """Merge per-component flags into SystemSetting('logs'). Reassigns row.value so SQLAlchemy
    flags the JSON column dirty. Caller commits."""
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == LOGS_SETTINGS_KEY).first()
    existing = dict(row.value) if (row and row.value) else {}
    merged = {**existing, **(updates or {})}
    if row is None:
        db.add(SystemSetting(key=LOGS_SETTINGS_KEY, value=merged))
    else:
        row.value = merged


def _log_ceiling_on() -> bool:
    """The EFFECTIVE log-pull ceiling: the plan must allow it (settings.plan_log_pull) AND a
    strong pepper must be configured. A weak/absent pepper DISABLES the endpoint (fail-safe)
    rather than bricking the vault, so the control plane can inject PLAN_LOG_PULL and the pepper
    in any order without a dead container in between."""
    return log_pull.effective_ceiling(settings.plan_log_pull, settings.log_token_pepper)


def _logs_pull_enabled(db, component: str) -> bool:
    """Env ceiling AND per-component DB flag. FAIL-CLOSED on error (unlike _zk_enabled, which
    fails toward the entitlement — for logs the unsafe direction is EXPOSURE)."""
    if not _log_ceiling_on():
        return False
    try:
        return log_pull.is_pull_enabled(True, _load_logs_settings(db), component)
    except Exception:  # noqa: BLE001
        return False


def _log_stealth_on(db) -> bool:
    """Stealth policy: when the admin turns this on, an auth failure on /logs returns 404 (not
    401) so the endpoint is indistinguishable from the feature being off — the vault never admits
    the endpoint exists to an unauthenticated caller. Default OFF (a plain 401 helps a tenant who
    is wiring up log collection); stealth is for deployments that want /logs fully undetectable.
    Fail to OFF on any read error (the 401 default reveals only existence, never access)."""
    try:
        return bool(_load_logs_settings(db).get("stealth_404", False))
    except Exception:  # noqa: BLE001
        return False


def _hash_log_token(token: str) -> str:
    return log_pull.hash_log_token(token, settings.log_token_pepper)


def _log_redaction_secrets() -> list:
    """The known-secret values scrubbed from any served log body (defense-in-depth on top of
    the header-only + scoped design). getattr so a missing config attr is just skipped."""
    return [getattr(settings, a, "") for a in
            ("jwt_secret_key", "encryption_key", "admin_password", "database_url",
             "redis_password", "log_token_pepper")]


def _read_sink_lines() -> list:
    """Read the active log-sink file (size-capped by run_combined). Best-effort -> [] if the
    sink is absent/unreadable (e.g. the split dev-stack, which does not run run_combined).

    Split ONLY on '\\n' — the sink writer (run_combined `_pump`) delimits records by '\\n' and a
    stored record can carry attacker-influenced content (an SFTP filename/username). str.splitlines()
    would ALSO break on \\v \\f \\x1c-\\x1e \\x85 \\u2028 \\u2029, so a content byte like '\\u2028[web] ...'
    inside an [sftp] record would be re-split into a fragment served under `?service=web`
    (within-tenant tag smuggling). Splitting on '\\n' makes the read match the write exactly."""
    try:
        with open(_LOG_SINK_PATH, "r", encoding="utf-8", errors="replace") as f:
            return f.read().split("\n")
    except Exception:  # noqa: BLE001
        return []


_log_bearer = HTTPBearer(auto_error=False)


async def require_log_pull_token(
    request: Request,
    credentials: Optional[HTTPAuthorizationCredentials] = Depends(_log_bearer),
    db: Session = Depends(get_db),
):
    """Validate a log-pull bearer token.

    - Ceiling-404 FIRST: when the feature is off, return 404 BEFORE inspecting the token, so a
      caller cannot use the endpoint as an oracle (feature-off is indistinguishable from a bad path).
    - Stealth: when the admin enables it, an auth failure returns a bodyless 404 (not 401) so an
      unauthenticated caller cannot even tell the endpoint exists. Default off (plain 401).
    - Header-only: HTTPBearer never reads a query param, so a token can't land in an access log.
    - Prefix-scoped lookup (indexed) then a constant-time peppered-hash compare. Fail-closed.
    """
    if not _log_ceiling_on():
        raise HTTPException(status_code=404)
    stealth = _log_stealth_on(db)

    def _deny(detail):
        # stealth -> bodyless 404 (same shape as ceiling-off); otherwise a helpful 401.
        return HTTPException(status_code=404) if stealth else HTTPException(status_code=401, detail=detail)

    if not credentials or not credentials.credentials:
        raise _deny("Log token required")
    try:
        from app.core.models import LogPullToken
        presented = credentials.credentials
        rows = db.query(LogPullToken).filter(
            LogPullToken.token_prefix == log_pull.token_prefix(presented),
            LogPullToken.disabled.is_(False),
        ).all()
        for r in rows:
            if log_pull.tokens_match(presented, settings.log_token_pepper, r.token_hash):
                return r
    except HTTPException:
        raise
    except Exception:  # noqa: BLE001
        raise _deny("Invalid log token")
    raise _deny("Invalid log token")


@app.get("/logs")
async def pull_logs(
    service: Optional[str] = None,
    tail: int = 500,
    token=Depends(require_log_pull_token),
    db: Session = Depends(get_db),
):
    """Authenticated per-component log pull. Returns JSON {service, lines, truncated}.

    `service` is optional in the signature (default None) so a missing value returns the same
    404 as an unknown one — no 422 that would reveal the endpoint exists when the ceiling is off.
    (`since` filtering is deferred to Phase 2 — the sink lines carry no uniform timestamp.)
    """
    # per-component DB enable (unknown/None service -> 404; no oracle beyond the already-passed ceiling)
    if not service or service not in log_pull.KNOWN_COMPONENTS or not _logs_pull_enabled(db, service):
        raise HTTPException(status_code=404)
    # valid token, but not scoped for this component
    if service not in log_pull.validate_scope(token.scope):
        raise HTTPException(status_code=403, detail="Token not scoped for this component")
    # Phase 1 serves only web/sftp (from the sink); db-diag/redis-diag arrive in Phase 2.
    if service not in log_pull.SERVEABLE_COMPONENTS:
        raise HTTPException(status_code=404, detail="Component logs not available in this phase")
    tail = max(1, min(int(tail or 500), 5000))
    svc_lines = log_pull.filter_service_lines(_read_sink_lines(), service)
    truncated = len(svc_lines) > tail
    svc_lines = svc_lines[-tail:]
    secretvals = _log_redaction_secrets()
    redacted = [log_pull.redact_log_text(ln, secretvals) for ln in svc_lines]
    try:
        token.last_used_at = datetime.utcnow()
        db.commit()
    except Exception:  # noqa: BLE001
        db.rollback()
    return {"service": service, "lines": redacted, "truncated": truncated}


@app.get("/settings/logs")
async def get_logs_settings(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Log-access admin view: the ceiling, per-component flags, and the token list. NEVER the
    token hash or plaintext."""
    from app.core.models import LogPullToken
    flags = _load_logs_settings(db)
    toks = db.query(LogPullToken).order_by(LogPullToken.created_at.desc()).all()
    return {
        "ceiling": _log_ceiling_on(),
        "components": list(log_pull.KNOWN_COMPONENTS),
        "serveable": list(log_pull.SERVEABLE_COMPONENTS),
        "flags": {c: bool(flags.get(c, False)) for c in log_pull.KNOWN_COMPONENTS},
        "stealth_404": bool(flags.get("stealth_404", False)),
        "tokens": [{
            "id": str(t.id), "name": t.name, "token_prefix": t.token_prefix,
            "scope": log_pull.validate_scope(t.scope), "disabled": bool(t.disabled),
            "last_used_at": t.last_used_at.isoformat() if t.last_used_at else None,
            "created_at": t.created_at.isoformat() if t.created_at else None,
        } for t in toks],
    }


@app.put("/settings/logs")
async def update_logs_settings(
    payload: dict,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Set per-component enable flags and/or the stealth-404 policy. require_interactive_admin —
    a temp-cred admin must not flip the exposure policy (mirrors PUT /settings)."""
    flags = payload.get("flags") if isinstance(payload, dict) else None
    updates = {}
    if isinstance(flags, dict):
        updates.update({c: bool(flags[c]) for c in log_pull.KNOWN_COMPONENTS if c in flags})
    if isinstance(payload, dict) and "stealth_404" in payload:
        updates["stealth_404"] = bool(payload["stealth_404"])
    if not updates:
        raise HTTPException(status_code=400, detail="no known components or stealth_404 in payload")
    _set_logs_settings(db, updates)
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="log_settings_updated", status="success", user=current_user,
            ip_address=get_client_ip(request), details={"keys": sorted(updates.keys())})
    except Exception:
        pass
    fresh = _load_logs_settings(db)
    return {"status": "ok",
            "flags": {c: bool(fresh.get(c, False)) for c in log_pull.KNOWN_COMPONENTS},
            "stealth_404": bool(fresh.get("stealth_404", False))}


@app.post("/settings/logs")
async def create_log_token(
    payload: dict,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Mint a log-pull token. Returns the plaintext EXACTLY ONCE (only the hash is stored). The
    audit row records the name/scope/prefix — NEVER the plaintext."""
    from app.core.models import LogPullToken
    name = (payload.get("name") or "").strip() if isinstance(payload, dict) else ""
    scope = log_pull.validate_scope(payload.get("scope") if isinstance(payload, dict) else None)
    if not name or len(name) > 100:
        raise HTTPException(status_code=400, detail="a token name (1-100 chars) is required")
    if not scope:
        raise HTTPException(status_code=400, detail="scope must include at least one known component")
    plaintext, prefix = log_pull.mint_token()
    tok = LogPullToken(name=name, token_prefix=prefix, token_hash=_hash_log_token(plaintext),
                       scope=scope, created_by=current_user.id)
    db.add(tok)
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="log_token_generated", status="success", user=current_user,
            ip_address=get_client_ip(request),
            details={"name": name, "scope": scope, "token_prefix": prefix})
    except Exception:
        pass
    return {"id": str(tok.id), "name": name, "scope": scope, "token_prefix": prefix, "token": plaintext}


@app.post("/settings/logs/{token_id}/disable")
async def disable_log_token(
    token_id: str,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Disable a token (rotation = mint a new one, then disable the old). require_interactive_admin."""
    from app.core.models import LogPullToken
    try:
        uuid.UUID(str(token_id))
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail="token not found")
    tok = db.query(LogPullToken).filter(LogPullToken.id == token_id).first()
    if not tok:
        raise HTTPException(status_code=404, detail="token not found")
    tok.disabled = True
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="log_token_disabled", status="success", user=current_user,
            ip_address=get_client_ip(request),
            details={"name": tok.name, "token_prefix": tok.token_prefix})
    except Exception:
        pass
    return {"status": "ok"}


# ---------------------------------------------------------------------------
# Brand asset uploads: admin-uploaded logo / favicon. Stored in a writable
# volume (/app/brand), served from /brand-assets/, and pointed at by the effective
# logo/favicon URLs via the 'brand' override row. Reset drops the override -> the
# baked default returns. Env-level URLs (BRAND_LOGO_URL) still win as a deploy default.
# ---------------------------------------------------------------------------
BRAND_ASSET_DIR = os.environ.get(
    "BRAND_ASSET_DIR", str(PROJECT_ROOT / "brand"))
BRAND_ASSET_MAX_BYTES = 2 * 1024 * 1024  # 2 MB
# slot -> the BrandingConfig override keys it drives. A single uploaded logo drives all
# three logo slots so it shows on the login screen, header AND sidebar at once.
_BRAND_ASSET_SLOTS = {
    "logo": ("logo_url", "logo_dark_url", "logo_small_url"),
    "favicon": ("favicon_url",),
}
_BRAND_ASSET_MEDIA = {
    "png": "image/png", "jpg": "image/jpeg", "gif": "image/gif",
    "webp": "image/webp", "ico": "image/x-icon", "svg": "image/svg+xml",
}


def _sniff_image_ext(data: bytes):
    """Return a safe file extension if `data` is an allowed image type — sniffed by
    MAGIC BYTES, never the client-supplied filename/Content-Type — else None. SVG is
    allowed but is served with a locked-down CSP + sandbox so it cannot execute script
    even if navigated to directly (a same-origin stored-XSS vector otherwise)."""
    if data[:8] == b"\x89PNG\r\n\x1a\n":
        return "png"
    if data[:3] == b"\xff\xd8\xff":
        return "jpg"
    if data[:6] in (b"GIF87a", b"GIF89a"):
        return "gif"
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return "webp"
    if data[:4] == b"\x00\x00\x01\x00":
        return "ico"
    head = data[:512].lstrip().lstrip(b"\xef\xbb\xbf").lstrip()  # skip UTF-8 BOM + whitespace
    if head[:5].lower() == b"<?xml" or head[:4].lower() == b"<svg":
        return "svg"
    return None


def _is_safe_asset_name(name: str) -> bool:
    """A served brand-asset name: a plain single-segment filename, no traversal."""
    return bool(name) and ".." not in name and "/" not in name and "\\" not in name \
        and all(c.isalnum() or c in "._-" for c in name)


def _update_brand_row(db, set_map=None, remove_keys=None) -> None:
    """Thin wrapper over the shared brand-override writer (app.config.effective) so the
    asset-upload path writes the same store as the Settings editor + wizard. Caller
    commits. (set_map values here are server-generated /brand-assets URLs, never empty.)"""
    set_brand_overrides(db, updates=set_map, remove_keys=remove_keys)


@app.get("/brand-assets/{name}")
async def get_brand_asset(name: str):
    """Serve an admin-uploaded brand asset from the writable brand volume. PUBLIC (a
    logo/favicon is public branding, like /static). Hardened: a strict name allow-list +
    a realpath-containment check block traversal; nosniff + a locked-down CSP/sandbox mean
    even an uploaded SVG cannot run script if navigated to directly."""
    if not _is_safe_asset_name(name):
        raise HTTPException(status_code=404, detail="Not found")
    base = os.path.realpath(BRAND_ASSET_DIR)
    real = os.path.realpath(os.path.join(BRAND_ASSET_DIR, name))
    if not (real == base or real.startswith(base + os.sep)) or not os.path.isfile(real):
        raise HTTPException(status_code=404, detail="Not found")
    ext = name.rsplit(".", 1)[-1].lower() if "." in name else ""
    return FileResponse(
        real,
        media_type=_BRAND_ASSET_MEDIA.get(ext, "application/octet-stream"),
        headers={
            "X-Content-Type-Options": "nosniff",
            "Content-Security-Policy": "default-src 'none'; style-src 'unsafe-inline'; sandbox",
            "Cache-Control": "public, max-age=300",
        },
    )


@app.post("/settings/brand/asset/{slot}")
async def upload_brand_asset(
    slot: str,
    request: Request,
    file: UploadFile = FastAPIFile(...),
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Admin-upload a brand logo or favicon. The type is sniffed by magic bytes (not the
    client name/type), size-capped, written into the brand volume under a content-hashed
    name, and the effective logo/favicon URL(s) are pointed at it via the 'brand' override
    row so /branding + the rendered shell use it live. Reset via DELETE."""
    import hashlib
    fields = _BRAND_ASSET_SLOTS.get(slot)
    if fields is None:
        raise HTTPException(status_code=404, detail="Unknown brand asset slot")
    # read with a hard cap — one extra byte distinguishes 'at cap' from 'over cap'
    data = await file.read(BRAND_ASSET_MAX_BYTES + 1)
    if len(data) > BRAND_ASSET_MAX_BYTES:
        raise HTTPException(
            status_code=413,
            detail=f"File too large (max {BRAND_ASSET_MAX_BYTES // (1024 * 1024)} MB)")
    if not data:
        raise HTTPException(status_code=400, detail="Empty file")
    ext = _sniff_image_ext(data)
    if ext is None:
        raise HTTPException(
            status_code=400,
            detail="Unsupported image type (allowed: png, jpg, gif, webp, ico, svg)")
    try:
        os.makedirs(BRAND_ASSET_DIR, exist_ok=True)
    except OSError:
        raise HTTPException(status_code=503, detail="Brand asset storage is not writable")
    fname = f"{slot}.{hashlib.sha256(data).hexdigest()[:8]}.{ext}"
    dest = os.path.join(BRAND_ASSET_DIR, fname)
    # keep one asset per slot: drop older files for this slot (different hash/ext)
    for existing in os.listdir(BRAND_ASSET_DIR):
        if existing.startswith(slot + ".") and existing != fname:
            try:
                os.remove(os.path.join(BRAND_ASSET_DIR, existing))
            except OSError:
                pass
    tmp = dest + ".tmp"
    with open(tmp, "wb") as fh:
        fh.write(data)
    os.replace(tmp, dest)  # atomic publish
    url = f"/brand-assets/{fname}"
    _update_brand_row(db, set_map={f: url for f in fields})
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="brand_asset_uploaded", status="success", user=current_user,
            ip_address=get_client_ip(request),
            details={"slot": slot, "type": ext, "bytes": len(data)})
    except Exception:
        pass
    return {"status": "ok", "slot": slot, "url": url}


@app.delete("/settings/brand/asset/{slot}")
async def reset_brand_asset(
    slot: str,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Reset a brand logo/favicon to the built-in default: drop the override key(s) from
    the 'brand' row and delete the uploaded file(s)."""
    fields = _BRAND_ASSET_SLOTS.get(slot)
    if fields is None:
        raise HTTPException(status_code=404, detail="Unknown brand asset slot")
    _update_brand_row(db, remove_keys=list(fields))
    db.commit()
    try:
        if os.path.isdir(BRAND_ASSET_DIR):
            for existing in os.listdir(BRAND_ASSET_DIR):
                if existing.startswith(slot + "."):
                    try:
                        os.remove(os.path.join(BRAND_ASSET_DIR, existing))
                    except OSError:
                        pass
    except OSError:
        pass
    try:
        AuditLogger(db).log_action(
            action="brand_asset_reset", status="success", user=current_user,
            ip_address=get_client_ip(request), details={"slot": slot})
    except Exception:
        pass
    return {"status": "ok", "slot": slot}


@app.get("/zk-enabled")
async def get_zk_enabled(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Zero-knowledge availability + org policy for the CURRENT user. Non-sensitive
    flags any authenticated user may read (the full /settings store is admin-only),
    so the vault-creation UI can offer/force the zero-knowledge option:
      - zero_knowledge_enabled: ZK creation is allowed on this deployment (effective:
          already factors in the plan ceiling below)
      - must_use_zk: this user may only create zero-knowledge vaults (force policy)
      - plan_zero_knowledge: whether the deployment's PLAN includes zero-knowledge at
          all — lets the UI show "not available on your plan" vs. "turned off".
      - max_zk_vaults / zk_vault_count: the plan's ZK-vault cap (-1 = unlimited) and
          how many already exist, so the UI can show "2 of 2 used" and pre-empt the
          create error.
      - allowed_vault_types: the operator-set, admin-irreversible allowlist of the
          types this deployment may create, so the UI can hide/disable a forbidden
          option instead of surfacing a create error."""
    allowed = _allowed_vault_types()
    zk_allowed = "zero_knowledge" in allowed
    return {
        # Effective creatable state: ZK is offered only when both the plan/toggle enable
        # it AND the allowlist permits it.
        "zero_knowledge_enabled": _zk_enabled(db) and zk_allowed,
        "must_use_zk": zk_allowed and _user_must_use_zk(db, current_user),
        "plan_zero_knowledge": bool(settings.plan_zero_knowledge),
        # Whether the PLAN itself mandates zero-knowledge (Enterprise tier) — distinct from
        # the local admin 'force_zero_knowledge' toggle. Lets the Settings page show that the
        # requirement is imposed by the plan (a floor the local toggle can't drop below),
        # instead of an unchecked box that looks contradictory when ZK is already forced.
        "plan_force_zero_knowledge": bool(settings.plan_force_zero_knowledge and settings.plan_zero_knowledge),
        "max_zk_vaults": settings.plan_max_zk_vaults,
        "zk_vault_count": _zk_vault_count(db),
        "allowed_vault_types": sorted(allowed),
        # Idle auto-lock for the in-memory ZK key (minutes; 0 = disabled). Enforced client-side.
        "zk_idle_lock_minutes": _zk_idle_lock_minutes(db),
    }


@app.get("/temp-passcode-policy")
async def get_temp_passcode_policy(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Effective Temporary Vault Passcode policy for the CURRENT user. Non-sensitive flags any
    authenticated user (including a temp session) may read — like /zk-enabled — so the temp-credential
    mint UI can shape the passcode controls without exposing the admin-only /settings store:
      - temp_passcodes_enabled: is the feature turned on (default off / fail-closed)
      - temp_passcode_allow_custom + the four temp_passcode_require_* toggles + temp_passcode_min_length:
          the custom-passcode complexity policy (generated passcodes are always high-entropy)
      - temp_passcode_one_time_default / temp_passcode_single_vault_only / temp_passcode_max_lifetime_minutes:
          mint defaults / ceilings
      - temp_cred_allow_zk_vaults: whether a zero-knowledge vault may be included in scope at all
      - force_no_remember_vault_password: deployment-wide floor forbidding the browser from
          remembering a vault password (lets the account UI show the per-user toggle as forced)
    No enforcement here — redemption reads the policy."""
    policy = dict(_temp_passcode_policy(db))
    policy["force_no_remember_vault_password"] = _force_no_remember_vault_password(db)
    return policy


@app.get("/zk/unsealed")
async def zk_unsealed_count(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Operator migration signal: how many zero-knowledge file/folder rows still carry an UNSEALED
    name — enc_name absent or not a client-sealed 'zk1:' blob — i.e. leftover cleartext metadata
    from before client-side name sealing was enforced on the write paths. A healthy deployment
    reports 0. The read guards already MASK such rows from being served, so this is a re-seal
    to-do list for owners, not a live leak. Admin-only (fleet-wide across all ZK vaults)."""
    from app.core.models import Vault, File, Folder
    from sqlalchemy import or_, not_, and_
    zk_ids = [r[0] for r in db.query(Vault.id).filter(Vault.type == 'zero_knowledge').all()]
    if not zk_ids:
        return {"zk_vaults": 0, "files_unsealed": 0, "folders_unsealed": 0, "vaults_affected": 0}

    def _unsealed(col):
        # NULL (never sealed) OR present-but-not a sealed blob. A sealed row is v1 (zk1:...) OR
        # v2 (zk2:..., obj-id-bound) — both are excluded from the "unsealed" count.
        return or_(col.is_(None), and_(not_(col.like('zk1:%')), not_(col.like('zk2:%'))))

    files_unsealed = db.query(File).filter(File.vault_id.in_(zk_ids), _unsealed(File.enc_name)).count()
    folders_unsealed = db.query(Folder).filter(Folder.vault_id.in_(zk_ids), _unsealed(Folder.enc_name)).count()
    affected = {r[0] for r in db.query(File.vault_id).filter(File.vault_id.in_(zk_ids), _unsealed(File.enc_name)).distinct()}
    affected |= {r[0] for r in db.query(Folder.vault_id).filter(Folder.vault_id.in_(zk_ids), _unsealed(Folder.enc_name)).distinct()}
    return {
        "zk_vaults": len(zk_ids),
        "files_unsealed": files_unsealed,
        "folders_unsealed": folders_unsealed,
        "vaults_affected": len(affected),
    }


@app.get("/sftp/host-key")
async def get_sftp_host_key(current_user: User = Depends(get_current_user)):
    """The SFTP server's public host-key SHA256 fingerprint, so a customer can verify it
    against their SFTP client's first-connect prompt (defends against MITM / blind TOFU).
    Read from the shared keys volume that the SFTP server generates on first boot. The
    fingerprint is a public value (any client sees it on connect), so any authenticated
    user may read it. Returns available=false until the SFTP server has created the key."""
    import hashlib
    import base64
    import paramiko
    key_path = settings.sftp_host_key_path
    try:
        if not os.path.exists(key_path):
            return {"available": False}
        host_key = paramiko.RSAKey.from_private_key_file(key_path)
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode().rstrip("=")
        return {"available": True, "algorithm": "ssh-rsa", "fingerprint_sha256": fp}
    except Exception as e:  # noqa: BLE001 — best-effort; never 500 on a missing/odd key file
        print(f"⚠️ host-key fingerprint read failed: {e}")
        return {"available": False}


# Authentication Endpoints

@app.post("/auth/login", response_model=LoginResponse)
async def login(
    login_request: LoginRequest,
    request: Request,
    db: Session = Depends(get_db)
):
    """
    Authenticate user and return access token.
    Supports both regular users and temporary credentials.
    """
    auth_service = AuthService(db)
    audit_logger = AuditLogger(db)
    client_ip = get_client_ip(request)
    
    try:
        # Check if this is a temporary credential (starts with "temp_")
        if login_request.username.startswith("temp_"):
            # Authenticate as temporary credential
            user, session_token = auth_service.authenticate_temporary_credential(
                temp_username=login_request.username,
                credential=login_request.password,
                ip_address=client_ip
            )
            is_temporary = True
        else:
            # Regular user authentication
            user, session_token = auth_service.authenticate_user(
                login_request.username,
                login_request.password,
                client_ip
            )
            is_temporary = False
        
        # Create JWT token (include session_token for session validation). A REGULAR session honours
        # the admin 'Session Timeout' setting (falling back to the env default); a temp credential
        # keeps the default token life — its own validity window is enforced separately.
        _expires = None
        if not is_temporary:
            _expires = timedelta(minutes=_setting_int(db, "session_timeout", settings.jwt_access_token_expire_minutes))
        access_token = create_access_token(
            data={
                "sub": str(user.id),
                "username": user.username,
                "session_token": session_token if session_token else None,
                "is_temporary": is_temporary
            },
            expires_delta=_expires,
        )
        
        audit_logger.log_login_success(user, client_ip, is_temporary=is_temporary)
        
        # Broadcast login event to monitoring. For a temp login, tag the event with
        # the owning account so its session can be notified (and so non-admins only
        # receive their own temp-login events — see the /ws/monitor filter).
        login_event = {
            "type": "login",
            "title": "User logged in",
            "description": f"{user.username} logged in" + (" (temporary)" if is_temporary else ""),
            "user": user.username,
            "ip": client_ip,
            "is_temporary": is_temporary,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
        if is_temporary:
            login_event["temp_username"] = login_request.username
            login_event["owner_user_id"] = str(user.id)
        broadcast_event({"event": login_event})
        
        from app.core.temp_scope import is_scoped as _is_scoped
        return LoginResponse(
            access_token=access_token,
            user=UserResponse.model_validate(user),
            is_temporary=is_temporary,
            is_scoped_temp=_is_scoped(user),
        )
    
    except (InvalidCredentialsError, AccountLockedError) as e:
        audit_logger.log_login_failure(login_request.username, client_ip, str(e))
        
        # Record failed login in security monitor for threat detection
        try:
            from app.services.security_monitor import get_security_monitor
            monitor = get_security_monitor(db)
            monitor.record_failed_login(login_request.username, client_ip, str(e))
        except Exception as monitor_error:
            # Don't fail the response if monitoring fails
            print(f"Warning: Failed to record security event: {monitor_error}")
        
        # A lock is only raised AFTER the password verified (verify-first ordering in
        # authenticate_user), so the caller has already proven they know the credential — telling
        # them the account is locked (and when it frees) reveals nothing an attacker couldn't
        # already determine, and unlike the generic message it tells a legitimate user why they're
        # stuck. Wrong password / nonexistent / inactive still get the uniform generic 401 so the
        # response body can't enumerate accounts or their state.
        if isinstance(e, AccountLockedError):
            locked_until = getattr(e, 'locked_until', None)
            if locked_until is not None:
                if locked_until.tzinfo is None:
                    locked_until = locked_until.replace(tzinfo=timezone.utc)
                secs = max(0, int((locked_until - datetime.now(timezone.utc)).total_seconds()))
                mins = max(1, (secs + 59) // 60)
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail=f"Your account is temporarily locked after too many failed attempts. "
                           f"Try again in about {mins} minute(s).",
                    headers={"Retry-After": str(secs)},
                )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Your account is locked. Contact your administrator to unlock it.",
            )
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid username or password"
        )

    except AuthRateLimitExceededError as e:
        # Log the rate limit event
        audit_logger.log_login_failure(
            login_request.username,
            client_ip,
            f"Rate limit exceeded: {str(e)}"
        )
        
        # Record in security monitor
        try:
            from app.services.security_monitor import get_security_monitor
            monitor = get_security_monitor(db)
            monitor.record_failed_login(login_request.username, client_ip, f"Rate limit exceeded: {str(e)}")
        except Exception as monitor_error:
            print(f"Warning: Failed to record security event: {monitor_error}")
        
        # Add rate limit headers to 429 response
        headers = {}
        if hasattr(e, 'limit') and e.limit:
            headers["X-RateLimit-Limit"] = str(e.limit)
        if hasattr(e, 'remaining'):
            headers["X-RateLimit-Remaining"] = str(e.remaining)
        if hasattr(e, 'retry_after') and e.retry_after:
            headers["Retry-After"] = str(e.retry_after)
        
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e),
            headers=headers
        )


@app.get("/auth/session")
async def get_session_access(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Nav-gating info for the CURRENT session.

    For a SCOPED temporary credential this returns exactly which UI sections its
    scope permits, so the sidebar can hide pages the credential cannot use
    (fail-closed) instead of showing empty, 403-ing pages. The check mirrors
    require_endpoint_permission for a temp session EXACTLY: a section is granted
    only if temp_session_allows_group() AND (the creating user is an admin OR the
    creating user actually holds that endpoint group) — otherwise the nav would
    advertise a page whose endpoints still 403. Only dashboard / vaults / temp-creds
    are ever grantable to a temp credential; monitor / users / groups / settings are
    admin surfaces (GROUP_PAGE '__deny__').

    Non-scoped sessions (regular users, admins, and legacy unscoped temp creds)
    return accessible_sections=null and keep their normal role/permission nav.
    """
    from app.core.temp_scope import is_scoped, temp_session_allows_group
    scoped = is_scoped(current_user)
    sections = None
    if scoped:
        # The creating user must also hold the group (unless admin) — same clamp
        # require_endpoint_permission applies at request time.
        creator_groups = None
        if current_user.role != RoleEnum.ADMIN:
            from app.core.models import UserEndpointPermission as UEP
            creator_groups = {
                row[0] for row in db.query(UEP.endpoint_group)
                .filter(UEP.user_id == current_user.id).all()
            }

        def _grants(group: str) -> bool:
            if not temp_session_allows_group(current_user, group, {}):
                return False
            return creator_groups is None or group in creator_groups

        sections = [
            section
            for section, group in (
                ("dashboard", "DASHBOARD_VIEW"),
                ("vaults", "VAULT_VIEW"),
                ("temp-creds", "TEMP_CREDS_VIEW"),
            )
            if _grants(group)
        ]
    resp = {
        "is_temp_session": bool(getattr(current_user, "_is_temp_session", False)),
        "is_scoped_temp": scoped,
        "role": current_user.role.value if current_user.role is not None else None,
        "accessible_sections": sections,
    }
    if scoped:
        # Effective capabilities, so the frontend can also hide ACTION controls the
        # scope forbids (not just nav) — matching require_cap / require_vault_cap:
        #   caps               = global caps (e.g. vault.create)
        #   temp_perms         = the temp-creds sub-permissions (view/create/…)
        #   vault_access_mode  = 'all' | 'selected'
        #   vault_caps_default = per-vault caps when mode is 'all'
        #   vault_caps         = {vault_id: [caps]} when mode is 'selected'
        # require_cap unions the per-vault caps with the global caps, so the client
        # must do the same when gating a per-vault button.
        sc = getattr(current_user, "_temp_scope", None) or {}
        resp["caps"] = list(sc.get("caps", []))
        resp["temp_perms"] = dict(sc.get("temp", {}))
        resp["vault_access_mode"] = getattr(current_user, "_temp_vault_mode", "selected")
        resp["vault_caps_default"] = list(sc.get("vault_caps_default", []))
        resp["vault_caps"] = dict(getattr(current_user, "_temp_vault_caps", {}) or {})
    return resp


@app.post("/auth/temp-credentials", response_model=TempCredentialResponse)
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def create_temp_credentials(
    payload: Optional[TempCredentialCreate] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Create temporary one-time credentials for the authenticated user.

    Accepts an optional validity_minutes / total_lifetime_minutes body to
    override the configured default lifetime. When omitted, the server defaults
    are used.
    """
    auth_service = AuthService(db)
    audit_logger = AuditLogger(db)
    client_ip = get_client_ip(request)

    is_temp = getattr(current_user, '_is_temp_session', False)
    scoped = getattr(current_user, '_temp_scope', None) is not None

    # Gate creation for temp sessions. A scoped cred needs the 'create' sub-perm;
    # a legacy cred falls back to the can_create flag. This stops someone given
    # vault access from minting and handing out more accounts.
    if is_temp:
        if scoped:
            from app.core.temp_scope import require_temp_perm
            require_temp_perm(current_user, 'create')
        elif not getattr(current_user, '_temp_can_create', False):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="This temporary account is not permitted to create credentials."
            )

    # Resolve the requested scope. A delegating temp session passes its own scope
    # as the parent so the child is intersected down to a subset.
    req_scope = payload.scope if payload else None
    req_mode = (payload.vault_access_mode if (payload and payload.vault_access_mode) else 'selected')
    req_vaults = payload.selected_vaults if payload else None
    parent_scope = parent_mode = parent_vault_ids = parent_vault_caps = parent_vault_scope = None
    # Stamp the creating temp session on every child (scoped OR legacy NULL-scope) so the child
    # lands in the creator's confinement subtree and stays visible/manageable by it. Without this a
    # legacy temp session would mint children with a NULL creator that its own confined list/guard
    # (which match created_by == this session's cred id) could never see or manage.
    created_by_temp_id = getattr(current_user, '_temp_cred_id', None) if is_temp else None
    if is_temp and scoped:
        actor_temp = (current_user._temp_scope or {}).get('temp', {})
        # A child may only receive create/delegate if THIS cred holds delegate. Force
        # both off UNCONDITIONALLY when the parent lacks delegate — including when the
        # caller OMITS scope. With req_scope=None, create_temporary_credential defaults
        # the child's requested scope to the FULL parent scope (create/delegate
        # included), so a create-but-not-delegate parent could otherwise mint
        # create-capable children simply by leaving scope out, bypassing the delegate
        # gate. Materialise the inherited scope first so the strip has something to write.
        if not actor_temp.get('delegate'):
            if req_scope is None:
                import copy
                req_scope = copy.deepcopy(current_user._temp_scope) or {}
            t = req_scope.setdefault('temp', {})
            t['create'] = False
            t['delegate'] = False
        parent_scope = current_user._temp_scope
        parent_mode = getattr(current_user, '_temp_vault_mode', 'selected')
        parent_vault_caps = getattr(current_user, '_temp_vault_caps', {}) or {}
        parent_vault_ids = list(parent_vault_caps.keys())
        parent_vault_scope = getattr(current_user, '_temp_vault_scope', {}) or {}

    temp_creds = auth_service.create_temporary_credential(
        current_user.id,
        validity_minutes=payload.validity_minutes if payload else None,
        total_lifetime_minutes=payload.total_lifetime_minutes if payload else None,
        note=payload.note if payload else None,
        can_create_temp_credentials=(payload.can_create_temp_credentials if payload else False),
        scope=req_scope,
        vault_access_mode=req_mode,
        selected_vaults=req_vaults,
        parent_scope=parent_scope,
        parent_vault_mode=parent_mode,
        parent_vault_ids=parent_vault_ids,
        parent_vault_caps=parent_vault_caps,
        parent_vault_scope=parent_vault_scope,
        created_by_temp_credential_id=created_by_temp_id,
        created_by_user_id=current_user.id,
        passcode_same_for_all=bool(payload.passcode_same_for_all) if payload else False,
    )

    audit_logger.log_temp_credential_created(
        current_user,
        temp_creds['temp_username'],
        client_ip
    )
    # A minted passcode is a second access door to a vault — record it (vault ids + kinds + count,
    # never the passcode plaintext) so a mint is auditable alongside its redemptions.
    if temp_creds.get('passcodes'):
        audit_logger.log_temp_passcode_minted(
            current_user, client_ip, temp_creds['passcodes'],
            same_for_all=bool(payload.passcode_same_for_all) if payload else False,
        )

    return TempCredentialResponse(**temp_creds)


@app.get("/temp-creds/list")
@require_endpoint_permission("TEMP_CREDS_VIEW")
async def list_temp_credentials(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Response:
    """
    List all temporary credentials for the current user (admin can see all).
    Now includes decrypted password for active credentials within validity window.
    Also includes active session information for each credential.
    
    Performance: Supports ETag caching to reduce redundant data transfer.
    Returns 304 Not Modified when data unchanged.
    """
    from app.core.models import TemporaryCredential, ActiveSession
    from datetime import datetime
    
    # A temp session (scoped OR legacy NULL-scope) sees only the credentials IT created —
    # never the whole deployment's, even though a NULL-scope temp cred keeps the admin role.
    # A degraded temp session whose cred id could not be loaded fails closed (empty).
    # Otherwise: admins see all, users see their own.
    if getattr(current_user, '_is_temp_session', False):
        _my_cred_id = getattr(current_user, '_temp_cred_id', None)
        temp_creds = (
            db.query(TemporaryCredential).filter(
                TemporaryCredential.created_by_temp_credential_id == _my_cred_id
            ).order_by(TemporaryCredential.created_at.desc()).all()
            if _my_cred_id is not None else []
        )
    elif current_user.role == RoleEnum.ADMIN:
        temp_creds = db.query(TemporaryCredential).order_by(TemporaryCredential.created_at.desc()).all()
    else:
        temp_creds = db.query(TemporaryCredential).filter(
            TemporaryCredential.user_id == current_user.id
        ).order_by(TemporaryCredential.created_at.desc()).all()
    
    result = []
    now = datetime.now(timezone.utc)  # Use timezone-naive to match database
    
    for cred in temp_creds:
        # Get active sessions for this credential (only those within grace period)
        from datetime import timedelta
        grace_minutes = int(os.getenv('TEMP_CRED_SESSION_GRACE_MINUTES', '65'))
        grace_cutoff = datetime.now(timezone.utc) - timedelta(minutes=grace_minutes)
        
        active_sessions = db.query(ActiveSession).filter(
            ActiveSession.temp_credential_id == cred.id,
            ActiveSession.is_active == True,
            ActiveSession.last_activity > grace_cutoff  # Only sessions active within grace period
        ).all()
        
        sessions_data = []
        for session in active_sessions:
            sessions_data.append({
                # NB: the raw session_token is deliberately NOT exposed here — it's a
                # live, reusable credential. The session 'id' identifies the row for the UI.
                'id': str(session.id),
                'ip_address': session.ip_address,
                'started_at': session.started_at.isoformat() + 'Z',
                'last_activity': session.last_activity.isoformat() + 'Z'
            })
        
        item = {
            'id': str(cred.id),
            'temp_username': cred.temp_username,
            'username': cred.user.username if cred.user else 'Unknown',
            'user_id': str(cred.user_id),
            # Append 'Z' to indicate UTC timezone for JavaScript
            'created_at': cred.created_at.isoformat() + 'Z',
            'expires_at': cred.expires_at.isoformat() + 'Z',
            'deactivate_at': cred.deactivate_at.isoformat() + 'Z',
            'is_used': cred.is_used,
            'is_active': cred.is_active,
            'used_at': (cred.used_at.isoformat() + 'Z') if cred.used_at else None,
            'active_sessions': sessions_data,
            'active_session_count': len(sessions_data),
            'note': cred.note,
            'can_create_temp_credentials': bool(getattr(cred, 'can_create_temp_credentials', False)),
            # Password available via dedicated endpoint for better security and caching
            'has_password': cred.encrypted_password is not None
        }
        
        # Note: Passwords are NOT decrypted in list endpoint for:
        # 1. Better security (passwords only retrieved when explicitly requested)
        # 2. Enables ETag caching (consistent response hashes)
        # 3. Reduced processing overhead
        # Use GET /temp-creds/{temp_username}/password to retrieve password
        
        result.append(item)
    
    # Use conditional response with ETag to reduce traffic
    from app.core.response_hash_utils import handle_conditional_response
    return handle_conditional_response(request, result)



@app.get("/temp-creds/{temp_username}/password")
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def get_temp_credential_password(
    temp_username: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
) -> Response:
    """
    Retrieve the password for a temporary credential.
    Only works within the 20-minute deactivation window.
    Admin only.
    
    Performance: Supports ETag caching (password doesn't change).
    """
    from app.core.models import TemporaryCredential
    temp_cred = db.query(TemporaryCredential).filter(
        TemporaryCredential.temp_username == temp_username
    ).first()
    if not temp_cred:
        raise HTTPException(
            status_code=404,
            detail="Password not available (expired, used, or not found)"
        )
    # Same ownership + confinement guard as the sibling temp-cred mutations: a
    # non-admin may only read its own credential; a scoped temp session only those it
    # created. Defense-in-depth — retrieve_temp_password currently always returns None,
    # but if that ever changes this endpoint must not become a cross-user password IDOR.
    if current_user.role != RoleEnum.ADMIN and temp_cred.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    _guard_temp_session_cred_mutation(current_user, temp_cred, 'view')

    auth_service = AuthService(db)
    password = auth_service.retrieve_temp_password(temp_username)

    if not password:
        raise HTTPException(
            status_code=404,
            detail="Password not available (expired, used, or not found)"
        )
    
    data = {
        "password": password,
        "warning": "This password expires 20 minutes after credential creation"
    }
    
    # Use conditional response with ETag (password doesn't change)
    from app.core.response_hash_utils import handle_conditional_response
    return handle_conditional_response(request, data)


def _guard_temp_session_cred_mutation(current_user, temp_cred, perm: str):
    """For a temp session (scoped OR legacy NULL-scope): limit the target to credentials
    THIS temp cred created — never the main account's or a sibling's. A scoped session
    additionally needs the temp.<perm> sub-permission; a legacy NULL-scope session keeps
    its broader in-subtree latitude (no sub-perm gate) but is still confined to its own
    subtree. No-op for normal (non-temp) sessions. Closes the admin-bypass leak: a temp
    session of an admin is still restricted here."""
    if not getattr(current_user, '_is_temp_session', False):
        return
    if getattr(current_user, '_temp_scope', None) is not None:
        from app.core.temp_scope import require_temp_perm
        require_temp_perm(current_user, perm)
    # Confine to credentials this temp session created. A degraded temp session whose cred id
    # could not be loaded (the fail-safe branch in get_current_user) has no subtree of its own,
    # so it fails closed rather than matching credentials with a NULL creator.
    _my_cred_id = getattr(current_user, '_temp_cred_id', None)
    if _my_cred_id is None or temp_cred.created_by_temp_credential_id != _my_cred_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="A temporary account may only manage credentials it created."
        )


def _revoke_sessions(db, *, user_id=None, temp_credential_id=None, actor_username="system",
                     durable=True):
    """Deactivate the matching active sessions AND publish a force-close signal to
    the 'session_terminations' Redis channel so the SFTP server tears down any live
    transport immediately — not just at the connection's next operation. This is
    the active counterpart to the per-request is_active/is_locked/cred-active
    re-checks on the web and SFTP paths. Returns the number of sessions revoked.

    durable=True (logout / lock / deactivate) ALSO sets ActiveSession.revoked so a regular-user
    web JWT is rejected per request even during a Redis outage. durable=False (e.g. disabling
    only SFTP) tears down live transports WITHOUT durably revoking the web token — the user's
    web session must keep working. Mutates session rows in `db` but does NOT commit."""
    from app.core.models import ActiveSession
    from app.core.database import redis_client
    q = db.query(ActiveSession).filter(ActiveSession.is_active == True)  # noqa: E712
    if user_id is not None:
        q = q.filter(ActiveSession.user_id == user_id)
    if temp_credential_id is not None:
        q = q.filter(ActiveSession.temp_credential_id == temp_credential_id)
    count = 0
    for s in q.all():
        s.is_active = False
        if durable:
            s.revoked = True  # durable revocation (web tokens rejected even if Redis is down)
        count += 1
        try:
            redis_client.publish('session_terminations', json.dumps({
                'session_token': s.session_token,
                'session_id': str(s.id),
                'terminated_by': actor_username,
            }))
            print(f"📢 Force-closed session {s.session_token[:8]}... ({actor_username})")
        except Exception as e:  # noqa: BLE001
            print(f"❌ Failed to publish termination signal: {e}")
    return count


@app.post("/temp-creds/{temp_username}/deactivate")
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def deactivate_temp_credential(
    temp_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Deactivate a temporary credential. This action cannot be reversed.
    The user loses access immediately: live SFTP sessions are force-closed.
    """
    from app.core.models import TemporaryCredential

    temp_cred = db.query(TemporaryCredential).filter(
        TemporaryCredential.temp_username == temp_username
    ).first()

    if not temp_cred:
        raise HTTPException(status_code=404, detail="Temporary credential not found")

    # Users can only deactivate their own, admins can deactivate any
    if current_user.role != RoleEnum.ADMIN and temp_cred.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    _guard_temp_session_cred_mutation(current_user, temp_cred, 'invalidate')

    # Deactivate the credential and force-close any live session for it.
    temp_cred.is_active = False
    revoked = _revoke_sessions(db, temp_credential_id=temp_cred.id,
                               actor_username=current_user.username)
    db.commit()

    return {
        "message": "Temporary credential deactivated successfully",
        "username": temp_username,
        "note": f"User has lost access; {revoked} live session(s) force-closed."
    }


@app.post("/temp-creds/{temp_username}/delete")
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def delete_temp_credential(
    temp_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a temporary credential.
    """
    from app.core.models import TemporaryCredential
    
    temp_cred = db.query(TemporaryCredential).filter(
        TemporaryCredential.temp_username == temp_username
    ).first()
    
    if not temp_cred:
        raise HTTPException(status_code=404, detail="Temporary credential not found")
    
    # Users can only delete their own, admins can delete any
    if current_user.role != RoleEnum.ADMIN and temp_cred.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    _guard_temp_session_cred_mutation(current_user, temp_cred, 'clear')

    # Force-close any live session before the row (and its cascaded sessions) go.
    _revoke_sessions(db, temp_credential_id=temp_cred.id, actor_username=current_user.username)
    db.delete(temp_cred)
    db.commit()

    return {"message": "Temporary credential deleted successfully"}


@app.post("/temp-creds/{temp_username}/terminate-sessions")
@require_endpoint_permission("TEMP_CREDS_MANAGE")
async def terminate_temp_credential_sessions(
    temp_username: str,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Terminate all active sessions for a temporary credential.
    This will forcibly disconnect any active SFTP/SSH sessions.
    """
    from app.core.models import TemporaryCredential, ActiveSession
    
    temp_cred = db.query(TemporaryCredential).filter(
        TemporaryCredential.temp_username == temp_username
    ).first()
    
    if not temp_cred:
        raise HTTPException(status_code=404, detail="Temporary credential not found")
    
    # Users can only terminate sessions for their own credentials, admins can terminate any
    if current_user.role != RoleEnum.ADMIN and temp_cred.user_id != current_user.id:
        raise HTTPException(status_code=403, detail="Access denied")
    _guard_temp_session_cred_mutation(current_user, temp_cred, 'invalidate')

    # Find and deactivate all active sessions for this credential
    active_sessions = db.query(ActiveSession).filter(
        ActiveSession.temp_credential_id == temp_cred.id,
        ActiveSession.is_active == True
    ).all()
    
    terminated_count = 0
    audit_logger = AuditLogger(db)
    
    # Get Redis connection for publishing termination signals
    from app.core.database import redis_client
    
    for session in active_sessions:
        session.is_active = False
        terminated_count += 1
        
        # Publish termination signal to Redis for SFTP server to close transport
        try:
            redis_client.publish('session_terminations', json.dumps({
                'session_token': session.session_token,
                'session_id': str(session.id),
                'temp_username': temp_username,
                'terminated_by': current_user.username
            }))
            print(f"📢 Published termination signal for session {session.session_token[:8]}...")
        except Exception as e:
            print(f"❌ Failed to publish termination signal: {e}")
        
        # Log the termination
        audit_logger.log_action(
            action="terminate_session",
            status="success",
            user_id=current_user.id,
            resource_type="temporary_credential",
            resource_id=str(temp_cred.id),
            details={
                "temp_username": temp_username,
                "session_id": str(session.id),
                "session_token": session.session_token,
                "ip_address": session.ip_address
            }
        )
    
    db.commit()
    
    return {
        "message": f"Terminated {terminated_count} active session(s)",
        "terminated_count": terminated_count
    }


@app.get("/monitor/stats")
async def monitor_stats(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Live-monitor headline counts: users and sessions active in the last hour."""
    from sqlalchemy import func, distinct
    from app.core.models import ActiveSession
    grace_cutoff = datetime.now(timezone.utc) - timedelta(minutes=65)
    active_filter = (
        ActiveSession.is_active == True,  # noqa: E712
        ActiveSession.last_activity >= grace_cutoff,
    )
    active_users = db.query(func.count(distinct(ActiveSession.user_id))).filter(*active_filter).scalar() or 0
    active_sessions = db.query(func.count(ActiveSession.id)).filter(*active_filter).scalar() or 0
    return {"active_users": active_users, "active_sessions": active_sessions}


@app.get("/storage/stats")
async def storage_stats(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Storage usage for this deployment: bytes stored across active vaults, plus the
    capacity of the underlying storage volume."""
    from app.services.vault_service import deployment_storage_used
    used = deployment_storage_used(db)
    total = available = 0
    try:
        usage = shutil.disk_usage(settings.file_storage_path)
        total, available = usage.total, usage.free
    except OSError as e:
        # Capacity is best-effort — never fail the panel if the path can't be stat'd.
        print(f"storage_stats: disk_usage unavailable: {e}")
    return {"total": total, "used": used, "available": available}


# ==============================================================================
# WebSocket Endpoint for Live Monitoring
# ==============================================================================

@app.websocket("/ws/monitor")
async def websocket_monitor_endpoint(websocket: WebSocket):
    """
    WebSocket endpoint for live activity monitoring.
    Requires valid JWT token in first message (not URL query parameter).
    
    Security: Token passed in first WebSocket message instead of URL to prevent:
    - Token leakage in server logs
    - Token exposure in browser history
    - Token leakage via Referer headers
    
    Client must send: {"type": "auth", "token": "JWT_TOKEN_HERE"}
    """
    import asyncio
    from app.core.database import redis_client
    
    # Accept the WebSocket connection
    await websocket.accept()
    
    try:
        # Wait for authentication message (timeout after 5 seconds)
        try:
            auth_message = await asyncio.wait_for(
                websocket.receive_json(),
                timeout=5.0
            )
        except asyncio.TimeoutError:
            await websocket.send_json({
                "type": "error",
                "message": "Authentication timeout - no auth message received"
            })
            await websocket.close(code=1008)
            return
        
        # Verify this is an auth message
        if auth_message.get("type") != "auth":
            await websocket.send_json({
                "type": "error",
                "message": "First message must be authentication message with type='auth'"
            })
            await websocket.close(code=1008)
            return
        
        # Extract token from auth message
        token = auth_message.get("token")
        if not token:
            await websocket.send_json({
                "type": "error",
                "message": "Authentication required - missing token in auth message"
            })
            await websocket.close(code=1008)
            return
        
        # Decode and verify token
        try:
            payload = verify_access_token(token)
            user_id = payload.get("sub")
            username = payload.get("username")
            
            if not user_id or not username:
                raise ValueError("Invalid token payload")

            # Parity with get_current_user: verify_access_token only checks
            # signature + exp, so without these a logged-out / revoked / locked / deactivated
            # token could open a live-monitor socket and stream events until its natural exp
            # (a revoked ADMIN token would stream the whole fleet feed).
            session_token = payload.get("session_token")
            is_temporary = payload.get("is_temporary", False)
            if not session_token:
                raise ValueError("Invalid token payload")
            from app.core.database import SessionLocal
            from app.services.auth_service import is_token_denylisted, account_locked
            from app.core.models import ActiveSession as _WsAS, User as _WsUser
            _wsdb = SessionLocal()
            try:
                if is_token_denylisted(session_token):
                    raise ValueError("Session terminated")
                if not is_temporary:
                    _rev = _wsdb.query(_WsAS.revoked).filter(
                        _WsAS.session_token == session_token
                    ).first()
                    if _rev is not None and _rev[0]:
                        raise ValueError("Session terminated")
                _wsuser = _wsdb.query(_WsUser).filter(_WsUser.id == uuid.UUID(user_id)).first()
                if not _wsuser or not _wsuser.is_active or account_locked(_wsuser):
                    raise ValueError("Account inactive or locked")
            finally:
                _wsdb.close()

        except ValueError as e:
            # Our own controlled auth-status messages (invalid payload / session terminated /
            # account inactive) are safe to surface to the client.
            await websocket.send_json({
                "type": "error",
                "message": str(e)
            })
            await websocket.close(code=1008)
            return
        except Exception as e:
            # Anything else (token-decode / DB / infra fault) must not leak internals over the
            # WebSocket — those frames bypass the HTTP 500-sanitizer. Log server-side, send generic.
            print(f"[WS] token validation failed: {e}")
            await websocket.send_json({
                "type": "error",
                "message": "Authentication failed"
            })
            await websocket.close(code=1008)
            return
        
        # Send connection success message
        await websocket.send_json({
            "type": "connected",
            "message": f"Connected to live monitor as {username}",
            "timestamp": datetime.now(timezone.utc).isoformat()
        })
        
        # Determine this connection's role so we can filter events: admins see all
        # activity (unchanged); everyone else receives only events they own (e.g.
        # the login of a temporary credential they created). This makes it safe to
        # open the socket app-wide for notifications without leaking others' activity.
        is_admin_conn = False
        try:
            from app.core.database import get_db_context
            from app.core.models import User as _WSUser, RoleEnum as _WSRole
            with get_db_context() as _wsdb:
                _wsu = _wsdb.query(_WSUser).filter(_WSUser.id == uuid.UUID(user_id)).first()
                # A temporary credential — even an admin's — is NOT a full admin here: it receives
                # only its OWN activity events, never the deployment-wide fleet feed (mirrors the
                # /api/dashboard confinement).
                is_admin_conn = bool(_wsu and _wsu.role == _WSRole.ADMIN and not is_temporary)
        except Exception:
            is_admin_conn = False

        def _event_visible_to_conn(ev):
            if is_admin_conn:
                return True
            inner = ev.get('event', ev) if isinstance(ev, dict) else {}
            owner = inner.get('owner_user_id')
            return owner is not None and str(owner) == str(user_id)

        # Subscribe to Redis pub/sub channel
        pubsub = redis_client.pubsub()
        await asyncio.get_event_loop().run_in_executor(
            None, pubsub.subscribe, "activity_events"
        )
        
        # Create tasks for sending and receiving
        async def send_events():
            """Forward Redis pub/sub events to WebSocket client."""
            while True:
                try:
                    # Get message from Redis (non-blocking with timeout)
                    message = await asyncio.get_event_loop().run_in_executor(
                        None, pubsub.get_message, True, 0.1
                    )
                    
                    if message and message['type'] == 'message':
                        # Parse and forward the event (filtered per connection)
                        event_data = json.loads(message['data'])
                        if _event_visible_to_conn(event_data):
                            await websocket.send_json(event_data)
                    
                    await asyncio.sleep(0.01)  # Small delay to prevent busy loop
                    
                except Exception as e:
                    print(f"Error forwarding event: {e}")
                    break
        
        async def receive_messages():
            """Receive messages from WebSocket client (for keepalive/commands)."""
            while True:
                try:
                    data = await websocket.receive_json()
                    
                    # Handle ping/pong for keepalive
                    if data.get("type") == "ping":
                        await websocket.send_json({
                            "type": "pong",
                            "timestamp": datetime.now(timezone.utc).isoformat()
                        })
                    
                except WebSocketDisconnect:
                    break
                except Exception as e:
                    print(f"Error receiving message: {e}")
                    break
        
        # Run both tasks concurrently
        send_task = asyncio.create_task(send_events())
        receive_task = asyncio.create_task(receive_messages())
        
        # Wait for either task to complete (usually due to disconnect)
        done, pending = await asyncio.wait(
            [send_task, receive_task],
            return_when=asyncio.FIRST_COMPLETED
        )
        
        # Cancel remaining tasks
        for task in pending:
            task.cancel()
        
    except WebSocketDisconnect:
        print(f"WebSocket disconnected for user {username if 'username' in locals() else 'unknown'}")
    except Exception as e:
        # str(e) can carry SQL/schema/host internals; log it server-side but never frame it to the
        # client (WebSocket frames don't pass through the HTTP 500-sanitizer).
        print(f"WebSocket error: {e}")
        try:
            await websocket.send_json({
                "type": "error",
                "message": "Internal error"
            })
        except:
            pass
    finally:
        # Cleanup
        try:
            if 'pubsub' in locals():
                await asyncio.get_event_loop().run_in_executor(
                    None, pubsub.unsubscribe, "activity_events"
                )
                await asyncio.get_event_loop().run_in_executor(
                    None, pubsub.close
                )
        except:
            pass
        
        try:
            await websocket.close()
        except:
            pass



# User Management Endpoints

@app.post("/users", response_model=UserResponse)
@require_endpoint_permission("USER_MANAGE")
async def create_user(
    user_create: UserCreate,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Create a new user (admin only).
    """
    auth_service = AuthService(db)
    audit_logger = AuditLogger(db)
    client_ip = get_client_ip(request)

    # Plan cap on the number of user accounts in this deployment.
    _enforce_user_cap(db)

    # Admin password policy (min length + complexity) beyond the model's 8-char floor.
    _validate_password_policy(db, user_create.password)

    try:
        new_user = auth_service.create_user(
            username=user_create.username,
            email=user_create.email,
            password=user_create.password,
            role=user_create.role,
            created_by=current_user.id
        )
        
        # Grant default permissions based on role
        from app.core.endpoint_permissions import grant_default_permissions_for_role
        grant_default_permissions_for_role(str(new_user.id), new_user.role, db)
        
        audit_logger.log_user_created(new_user, current_user, client_ip)
        
        return UserResponse.model_validate(new_user)
    
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )


@app.get("/users", response_model=List[UserResponse])
@require_endpoint_permission("USER_VIEW")
async def list_users(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    List all users (admin only).
    """
    users = db.query(User).all()
    return [UserResponse.model_validate(user) for user in users]


@app.get("/users/me", response_model=UserResponse)
async def get_current_user_info(current_user: User = Depends(get_current_user)):
    """
    Get current user information.
    """
    return UserResponse.model_validate(current_user)


@app.patch("/users/me", response_model=UserResponse)
async def update_own_account(
    body: SelfUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Self-service account update: change your OWN password, email, or SFTP toggles. Gated only by
    a valid session (no USER_MANAGE), so a regular user can manage their own account — but a
    TEMPORARY/external credential cannot touch the owning account, and a password/email change
    requires re-proving the current password so a hijacked live session can't take the account over."""
    from app.core.security import hash_password, verify_password
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="Temporary credentials cannot change account settings.")

    user = db.query(User).filter(User.id == current_user.id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")

    audit_logger = AuditLogger(db)
    changes = []
    changing_email = body.email is not None and body.email != user.email
    sensitive = body.new_password is not None or changing_email
    if sensitive:
        if not body.current_password or not user.password_hash or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="Your current password is required and must be correct.")

    if body.new_password is not None:
        _validate_password_policy(db, body.new_password)
        user.password_hash = hash_password(body.new_password)
        changes.append("password")
    if changing_email:
        # email is unique — reject a clash with a clean 400 instead of a commit-time 500.
        if db.query(User.id).filter(User.email == str(body.email), User.id != user.id).first():
            raise HTTPException(status_code=400, detail="That email address is already in use.")
        user.email = str(body.email)
        changes.append("email")
    if body.sftp_enabled is not None and body.sftp_enabled != user.sftp_enabled:
        user.sftp_enabled = body.sftp_enabled
        changes.append("sftp_enabled")
    if body.sftp_password_auth is not None and body.sftp_password_auth != user.sftp_password_auth:
        user.sftp_password_auth = body.sftp_password_auth
        changes.append("sftp_password_auth")

    if not changes:
        raise HTTPException(status_code=400, detail="No changes were provided.")
    db.commit()
    db.refresh(user)
    try:
        audit_logger.log_action(action="self_account_update", status="success", user=user,
                                ip_address=get_client_ip(request), details={"fields": changes})
    except Exception:  # noqa: BLE001
        pass
    return UserResponse.model_validate(user)


# -- Per-user UI preferences (theme / accent / background / skin) --------------
# Values mirror the client's ThemeManager (static/js/theme.js). Everything is
# whitelisted on the way in AND out, so a stored preference can never carry a value
# the client wouldn't itself produce (the client writes these straight into DOM
# attributes/localStorage, so an untrusted value there is a defensive concern).
_PREF_ALLOWED = {
    "theme": {"light", "dark"},
    "accent": {"teal", "indigo", "violet", "rose", "orange", "sky"},
    "background": {"slate", "graphite", "navy", "warm", "forest", "plum"},
    "ui": {"v1", "v2"},
    # Per-user opt-out of browser-remembering a vault password. Stored as a string enum ('on'/'off')
    # because _sanitize_preferences keeps only string values in the whitelist (a bare bool is dropped).
    "never_remember_vault_password": {"on", "off"},
}


def _sanitize_preferences(data) -> dict:
    """Keep only known keys whose value is in that key's whitelist; drop the rest."""
    if not isinstance(data, dict):
        return {}
    return {
        key: data[key]
        for key, allowed in _PREF_ALLOWED.items()
        if isinstance(data.get(key), str) and data[key] in allowed
    }


class PreferencesUpdate(BaseModel):
    """Partial update of the current user's UI preferences. Every field is
    optional — only the ones provided change; the rest are left as stored."""
    theme: Optional[str] = None
    accent: Optional[str] = None
    background: Optional[str] = None
    ui: Optional[str] = None
    never_remember_vault_password: Optional[str] = None


@app.get("/users/me/preferences")
async def get_my_preferences(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The current user's saved UI preferences (empty object if none set yet)."""
    row = db.query(UserPreference).filter(UserPreference.user_id == current_user.id).first()
    return _sanitize_preferences(row.preferences if row else {})


@app.put("/users/me/preferences")
async def update_my_preferences(
    update: PreferencesUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Merge the provided (whitelisted) preferences into the current user's saved
    set and return the merged result. Creates the row lazily on first use."""
    incoming = _sanitize_preferences(update.model_dump(exclude_none=True))
    # Lock the row for the read-modify-write so two concurrent partial updates can't
    # lose a field (last-writer-wins on the whole JSON blob).
    row = (db.query(UserPreference)
             .filter(UserPreference.user_id == current_user.id)
             .with_for_update().first())
    merged = dict(_sanitize_preferences(row.preferences) if row else {})
    merged.update(incoming)
    if row:
        row.preferences = merged  # reassign (not in-place mutate) so SQLAlchemy tracks the change
    else:
        db.add(UserPreference(user_id=current_user.id, preferences=merged))
    try:
        db.commit()
    except IntegrityError:
        # A concurrent first-write created the row — lock + merge onto it instead.
        db.rollback()
        row = (db.query(UserPreference)
                 .filter(UserPreference.user_id == current_user.id)
                 .with_for_update().first())
        merged = dict(_sanitize_preferences(row.preferences) if row else {})
        merged.update(incoming)
        if row:
            row.preferences = merged
        else:
            db.add(UserPreference(user_id=current_user.id, preferences=merged))
        db.commit()
    return merged


@app.get("/users/search")
async def search_users(
    q: str = "",
    group_id: str = "",
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Minimal user lookup so a vault sharer can find a recipient by username/email prefix.

    Deliberately NOT the admin directory listing, but note the boundary: the caller must be able
    to share SOME vault (own/manage one, or admin — a scoped temp credential only if it holds
    vault.change_permissions), which in practice is most active users, since creating a vault is
    self-service. The disclosure is bounded to id + username of active, non-EXTERNAL accounts, on a
    >=2-char prefix, LIKE-wildcards escaped, result set capped, and rate-limited (fail-closed). This
    matches the existing /ecc/users/{id}/public-key scoping and feeds the share/grant picker for
    non-admin owners (who cannot read the admin-only /users list). Scoping the search to the
    specific vault being shared (rather than the whole directory) is a possible future refinement."""
    from app.api.ecc_router import _manages_any_vault
    from app.core.rate_limiter import rate_limiter as _rl
    from app.core.rate_limiter import RateLimiterUnavailable
    from sqlalchemy import or_

    q = (q or "").strip()
    if len(q) < 2:
        return []  # require a real prefix — don't let 1 char / empty enumerate the directory

    # Fail CLOSED: a Redis outage must not silently disable the anti-enumeration throttle.
    try:
        allowed, _, reset = _rl.check_rate_limit(
            identifier=str(current_user.id), limit=60, window=60, prefix="user_search", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=status.HTTP_503_SERVICE_UNAVAILABLE, detail="Search is temporarily unavailable.")
    if not allowed:
        import time as _t
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail="Too many searches; please slow down.",
            headers={"Retry-After": str(max(1, reset - int(_t.time())))},
        )

    if not _manages_any_vault(db, current_user):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Only a vault owner or manager may search for users to share with.",
        )

    # Prefix match; escape the LIKE wildcards so a query like "%" can't sweep the directory.
    esc = q.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    like = esc + "%"
    query = db.query(User.id, User.username).filter(
        User.is_active == True,  # noqa: E712
        User.role != RoleEnum.EXTERNAL,
        or_(User.username.ilike(like, escape="\\"), User.email.ilike(like, escape="\\")),
    )

    # Org policy: 'same_department' limits discovery to accounts that share at least one group with
    # the caller (a caller in no groups therefore finds no one); 'deployment' (default) keeps the
    # whole-directory behavior. Applied uniformly — an interactive admin still has the /users list.
    # The optional group_id narrows to ONE department the caller belongs to (a foreign group id
    # yields no results — the join to the caller's memberships makes it fail closed either way).
    from app.core.models import user_groups
    from sqlalchemy import select as _select
    scope = _directory_search_scope(db)
    gid = None
    if group_id:
        try:
            gid = uuid.UUID(str(group_id))
        except (ValueError, TypeError):
            return []  # an unparseable group filter matches nothing rather than sweeping the directory
    if scope == "same_department" or gid is not None:
        caller_group_ids = _select(user_groups.c.group_id).where(user_groups.c.user_id == current_user.id)
        query = query.join(user_groups, User.id == user_groups.c.user_id)
        if scope == "same_department":
            query = query.filter(user_groups.c.group_id.in_(caller_group_ids))
        if gid is not None:
            # A specific-department filter is only honored for a group the caller belongs to, so it
            # can't be used to enumerate a department the caller isn't in.
            query = query.filter(
                user_groups.c.group_id == gid,
                user_groups.c.group_id.in_(caller_group_ids),
            )
        query = query.distinct()
    rows = query.order_by(User.username).limit(10).all()
    return [{"id": str(uid), "username": uname} for uid, uname in rows]


@app.get("/users/{user_id}", response_model=UserResponse)
@require_endpoint_permission("USER_VIEW")
async def get_user(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get user by ID (admin or self).
    """
    # Own-or-admin, checked BEFORE the existence lookup to avoid an enumeration oracle (mirrors
    # user_management_api.get_user_detail — a non-admin granted USER_VIEW must not distinguish an
    # existing from a nonexistent user id).
    if current_user.role != RoleEnum.ADMIN and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )

    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    return UserResponse.model_validate(user)


@app.patch("/users/{user_id}", response_model=UserResponse)
@require_endpoint_permission("USER_MANAGE")
async def update_user(
    user_id: uuid.UUID,
    user_update: UserUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Update user (admin or self for limited fields).
    """
    from app.core.security import hash_password
    
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Check permissions. A TEMP session keeps role==ADMIN but must not wield admin power here:
    # treat it as non-admin so the admin-only branch (role/is_active/is_locked) AND any
    # cross-user password reset are unreachable by a temp credential — a temp admin acting on
    # ANOTHER user then fails the is_admin/is_self gate below and gets 403.
    is_admin = current_user.role == RoleEnum.ADMIN and not getattr(current_user, "_is_temp_session", False)
    is_self = current_user.id == user_id

    if not (is_admin or is_self):
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Access denied"
        )
    
    # Track changes for audit log
    changes = {}
    
    # Non-admin users can only update their own email and password
    if user_update.email is not None:
        changes['email'] = {'old': user.email, 'new': user_update.email}
        user.email = user_update.email
    
    if user_update.password is not None:
        _validate_password_policy(db, user_update.password)
        user.password_hash = hash_password(user_update.password)
        changes['password'] = 'changed'

    # SFTP controls — a user may manage their own (or an admin, anyone's).
    if user_update.sftp_enabled is not None:
        changes['sftp_enabled'] = {'old': user.sftp_enabled, 'new': user_update.sftp_enabled}
        user.sftp_enabled = user_update.sftp_enabled
    if user_update.sftp_password_auth is not None:
        changes['sftp_password_auth'] = {'old': user.sftp_password_auth, 'new': user_update.sftp_password_auth}
        user.sftp_password_auth = user_update.sftp_password_auth

    # Turning SFTP off force-closes the user's live SFTP transports immediately. durable=False
    # so the user's WEB JWT session is NOT revoked (only SFTP is being disabled) — the SFTP
    # layer re-checks sftp_enabled every op, and the force-close signal tears down transports.
    if user_update.sftp_enabled is False:
        _revoke_sessions(db, user_id=user.id, actor_username=current_user.username, durable=False)

    # Admin-only fields
    if is_admin:
        if user_update.role is not None:
            changes['role'] = {'old': user.role.value, 'new': user_update.role.value}
            user.role = user_update.role
        
        if user_update.is_active is not None:
            # Reactivating a user consumes a seat, so enforce the plan's user cap on the
            # inactive->active transition too. create_user is otherwise the only
            # checkpoint, which an admin could sidestep by deactivating a user, creating
            # a replacement (allowed — a seat freed up), then reactivating the original
            # to land above the cap.
            if user_update.is_active and not user.is_active:
                _enforce_user_cap(db)
            changes['is_active'] = {'old': user.is_active, 'new': user_update.is_active}
            user.is_active = user_update.is_active
        
        if user_update.is_locked is not None:
            changes['is_locked'] = {'old': user.is_locked, 'new': user_update.is_locked}
            user.is_locked = user_update.is_locked

            if user_update.is_locked:
                # An ADMIN lock is permanent (no auto-unlock TTL) — locked_until NULL means
                # account_locked() treats it as a standing lock until an admin clears it.
                user.locked_until = None
            else:
                # Unlock: clear the failed-attempt counter and any auto-lock TTL.
                user.failed_login_attempts = 0
                user.locked_until = None

        # Locking or deactivating an account revokes its live sessions immediately:
        # force-close any open SFTP transport now (the per-request is_active/
        # is_locked re-checks would otherwise only catch it at the next op).
        if user_update.is_locked is True or user_update.is_active is False:
            revoked = _revoke_sessions(db, user_id=user.id, actor_username=current_user.username)
            if revoked:
                print(f"🔒 Revoked {revoked} live session(s) for locked/deactivated user {user.username}")

        # Deactivation also offboards the user's zero-knowledge key access — parity with the
        # user-management deactivate/toggle paths. Blacklist their active wrapped-DEK rows (owner
        # rows carved out) so the server can no longer hand them a ZK vault key; the affected
        # vaults surface 'rekey owed' to managers. Idempotent (only active rows), committed below.
        if user_update.is_active is False:
            from app.api.user_management_api import _blacklist_user_vault_keys
            n_bl = _blacklist_user_vault_keys(db, user.id, current_user.id)
            if n_bl:
                print(f"🔑 Blacklisted {n_bl} ZK key(s) for deactivated user {user.username}")

    user.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(user)
    
    # Audit log
    audit_logger = AuditLogger(db)
    audit_logger.log_user_updated(
        user, current_user, get_client_ip(request), changes
    )
    
    return UserResponse.model_validate(user)


def _parse_ssh_public_key(line: str):
    """Validate an OpenSSH public key line; return (key_type, normalized, fingerprint).
    normalized = 'type base64' (comment dropped) for canonical storage + matching."""
    import base64 as _b64
    import hashlib as _hl
    parts = (line or "").strip().split()
    if len(parts) < 2:
        raise HTTPException(status_code=400,
                            detail="Provide an OpenSSH public key, e.g. 'ssh-ed25519 AAAA... comment'")
    key_type, blob_b64 = parts[0], parts[1]
    if not (key_type.startswith("ssh-") or key_type.startswith("ecdsa-") or key_type.startswith("sk-")):
        raise HTTPException(status_code=400, detail=f"Unsupported SSH key type: {key_type}")
    try:
        blob = _b64.b64decode(blob_b64, validate=True)
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid base64 in public key")
    fingerprint = "SHA256:" + _b64.b64encode(_hl.sha256(blob).digest()).decode().rstrip("=")
    return key_type, f"{key_type} {blob_b64}", fingerprint


def _ssh_key_target_user(user_id, current_user, db, *, write=False):
    """Admin-or-self gate for SSH-key management; returns the target user.

    A stored SSH key is a persistent SFTP auth factor that outlives a temporary credential's
    time-box, so a temp session must not CREATE or REMOVE one — not on another account and not
    even on its own owning account (which would let the credential holder keep SFTP access after
    the credential expires). Reads (listing keys) stay allowed for self. An admin acting on
    another user must be an INTERACTIVE admin."""
    is_self = current_user.id == user_id
    is_temp = getattr(current_user, "_is_temp_session", False)
    if not is_self:
        if current_user.role != RoleEnum.ADMIN:
            raise HTTPException(status_code=403, detail="Access denied")
        if is_temp:
            raise HTTPException(
                status_code=403,
                detail="This action requires an interactive admin session, not a temporary credential.",
            )
    elif write and is_temp:
        raise HTTPException(
            status_code=403,
            detail="A temporary credential cannot manage SSH keys; use an interactive session.",
        )
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=404, detail="User not found")
    return user


@app.get("/users/{user_id}/ssh-keys", response_model=List[SSHKeyResponse])
async def list_ssh_keys(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List a user's authorized SSH public keys (admin or self)."""
    from app.core.models import UserSSHKey
    _ssh_key_target_user(user_id, current_user, db)
    keys = db.query(UserSSHKey).filter(UserSSHKey.user_id == user_id).order_by(UserSSHKey.created_at).all()
    return [SSHKeyResponse.model_validate(k) for k in keys]


@app.post("/users/{user_id}/ssh-keys", response_model=SSHKeyResponse)
async def add_ssh_key(
    user_id: uuid.UUID,
    body: SSHKeyCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add an SSH public key authorizing this user's SFTP access (admin or self)."""
    from app.core.models import UserSSHKey
    _ssh_key_target_user(user_id, current_user, db, write=True)
    key_type, normalized, fingerprint = _parse_ssh_public_key(body.public_key)
    if db.query(UserSSHKey).filter(
        UserSSHKey.user_id == user_id, UserSSHKey.fingerprint == fingerprint
    ).first():
        raise HTTPException(status_code=409, detail="This key is already registered for the user")
    key = UserSSHKey(
        user_id=user_id, name=body.name.strip(), key_type=key_type,
        public_key=normalized, fingerprint=fingerprint, created_by=current_user.id,
    )
    db.add(key)
    db.commit()
    db.refresh(key)
    try:
        AuditLogger(db).log_action(
            action="ssh_key_add", status="success", user=current_user,
            resource_type="user", resource_id=str(user_id),
            details={"fingerprint": fingerprint, "name": key.name},
            ip_address=get_client_ip(request),
        )
    except Exception:  # noqa: BLE001
        pass
    return SSHKeyResponse.model_validate(key)


@app.delete("/users/{user_id}/ssh-keys/{key_id}")
async def delete_ssh_key(
    user_id: uuid.UUID,
    key_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove an authorized SSH key (admin or self)."""
    from app.core.models import UserSSHKey
    _ssh_key_target_user(user_id, current_user, db, write=True)
    key = db.query(UserSSHKey).filter(
        UserSSHKey.id == key_id, UserSSHKey.user_id == user_id
    ).first()
    if not key:
        raise HTTPException(status_code=404, detail="SSH key not found")
    fp = key.fingerprint
    db.delete(key)
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="ssh_key_remove", status="success", user=current_user,
            resource_type="user", resource_id=str(user_id),
            details={"fingerprint": fp}, ip_address=get_client_ip(request),
        )
    except Exception:  # noqa: BLE001
        pass
    return {"message": "SSH key removed"}


@app.post("/users/{user_id}/delete")
@require_endpoint_permission("USER_MANAGE")
async def delete_user(
    user_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Delete user (admin only).
    """
    user = db.query(User).filter(User.id == user_id).first()
    
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )
    
    # Prevent deleting self
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot delete your own account"
        )

    # A user who still owns vaults can't be hard-deleted: Vault.owner_id is NOT NULL and the
    # vaults_owned relationship nullifies-the-FK-then-fails, so db.delete would raise IntegrityError
    # and surface as an opaque 500 (the delete is safely rolled back, but the admin gets no guidance).
    # Return a clear 409 so the admin reassigns/deletes those vaults first.
    owned_vaults = db.query(Vault).filter(Vault.owner_id == user.id).count()
    if owned_vaults:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"User owns {owned_vaults} vault(s); reassign or delete them before deleting the user.",
        )

    username = user.username
    db.delete(user)
    db.commit()
    
    # Audit log
    audit_logger = AuditLogger(db)
    audit_logger.log_user_deleted(
        username, user_id, current_user, get_client_ip(request)
    )
    
    return {"message": f"User {username} deleted successfully"}


@app.post("/users/{user_id}/terminate-sessions")
@require_endpoint_permission("USER_MANAGE")
async def terminate_user_sessions(
    user_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None
):
    """
    Terminate all active sessions for a user (admin only). Durably revokes the user's
    web tokens and force-closes any live web/SFTP transports immediately.
    """
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="User not found"
        )

    # Prevent self-termination (durable revocation would log the admin out mid-request);
    # mirrors delete_user's self-guard. An admin ends their own session via logout.
    if user.id == current_user.id:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Cannot terminate your own sessions; use logout instead."
        )

    terminated_count = _revoke_sessions(
        db, user_id=user_id, actor_username=current_user.username, durable=True
    )
    db.commit()

    audit_logger = AuditLogger(db)
    audit_logger.log_action(
        action="terminate_session",
        status="success",
        user_id=current_user.id,
        resource_type="user",
        resource_id=str(user_id),
        details={
            "username": user.username,
            "terminated_count": terminated_count,
            "ip_address": get_client_ip(request),
        }
    )

    return {
        "message": f"Terminated {terminated_count} active session(s)",
        "terminated_count": terminated_count
    }


# ============================================================================
# Organizational Groups (departments) — hierarchical, organizational-only.
# Admin-guarded. Membership writes go straight to the user_groups table (so we
# can record group_role + added_by); reads use the viewonly relationships.
# ============================================================================

def _group_counts(db: Session):
    """Return (member_count_by_group, child_count_by_group) maps in 2 queries."""
    from sqlalchemy import func as _func
    members = {
        gid: cnt
        for gid, cnt in db.query(
            user_groups.c.group_id, _func.count(user_groups.c.user_id)
        ).group_by(user_groups.c.group_id).all()
    }
    children = {
        pid: cnt
        for pid, cnt in db.query(
            Group.parent_id, _func.count(Group.id)
        ).filter(Group.parent_id.isnot(None)).group_by(Group.parent_id).all()
    }
    return members, children


def _group_to_response(g: Group, members_map: dict, children_map: dict) -> GroupResponse:
    return GroupResponse(
        id=g.id, name=g.name, description=g.description, color=g.color,
        parent_id=g.parent_id, created_at=g.created_at,
        member_count=members_map.get(g.id, 0),
        child_count=children_map.get(g.id, 0),
    )


@app.get("/groups", response_model=List[GroupResponse])
async def list_groups(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """List all organizational groups (admin only)."""
    groups = db.query(Group).order_by(Group.name).all()
    members_map, children_map = _group_counts(db)
    return [_group_to_response(g, members_map, children_map) for g in groups]


@app.post("/groups", response_model=GroupResponse)
async def create_group(
    payload: GroupCreate,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Create an organizational group (admin only)."""
    name = (payload.name or "").strip()
    if not name:
        raise HTTPException(status_code=400, detail="Group name is required")
    if payload.parent_id is not None and not db.query(Group).filter(Group.id == payload.parent_id).first():
        raise HTTPException(status_code=400, detail="Parent group not found")
    group = Group(
        name=name,
        description=(payload.description or None),
        color=(payload.color or None),
        parent_id=payload.parent_id,
        created_by=current_user.id,
    )
    db.add(group)
    db.commit()
    db.refresh(group)
    members_map, children_map = _group_counts(db)
    return _group_to_response(group, members_map, children_map)


@app.get("/groups/{group_id}", response_model=GroupDetailResponse)
async def get_group(
    group_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Group detail: members (with their per-group role) and direct sub-groups."""
    from sqlalchemy import select
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    members_map, children_map = _group_counts(db)
    rows = db.execute(
        select(User, user_groups.c.group_role)
        .join(user_groups, User.id == user_groups.c.user_id)
        .where(user_groups.c.group_id == group_id)
        .order_by(User.username)
    ).all()
    members = [
        GroupMemberRef(id=u.id, username=u.username, email=u.email, role=u.role, group_role=gr or 'member')
        for (u, gr) in rows
    ]
    children = [
        _group_to_response(c, members_map, children_map)
        for c in sorted(group.children, key=lambda x: x.name)
    ]
    base = _group_to_response(group, members_map, children_map)
    return GroupDetailResponse(**base.model_dump(), members=members, children=children)


@app.patch("/groups/{group_id}", response_model=GroupResponse)
async def update_group(
    group_id: uuid.UUID,
    payload: GroupUpdate,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Rename / re-describe / re-color / re-parent a group (admin only)."""
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    data = payload.model_dump(exclude_unset=True)
    if 'name' in data:
        nm = (data['name'] or "").strip()
        if not nm:
            raise HTTPException(status_code=400, detail="Group name cannot be empty")
        group.name = nm
    if 'description' in data:
        group.description = data['description'] or None
    if 'color' in data:
        group.color = data['color'] or None
    if 'parent_id' in data:
        new_parent = data['parent_id']
        if new_parent is not None:
            if new_parent == group_id:
                raise HTTPException(status_code=400, detail="A group cannot be its own parent")
            parent = db.query(Group).filter(Group.id == new_parent).first()
            if not parent:
                raise HTTPException(status_code=400, detail="Parent group not found")
            # Walk the proposed parent's ancestry to reject cycles.
            cur, seen = parent, set()
            while cur is not None and cur.id not in seen:
                if cur.id == group_id:
                    raise HTTPException(status_code=400, detail="Cannot move a group under one of its own descendants")
                seen.add(cur.id)
                cur = cur.parent
        group.parent_id = new_parent
    group.updated_at = datetime.now(timezone.utc)
    db.commit()
    db.refresh(group)
    members_map, children_map = _group_counts(db)
    return _group_to_response(group, members_map, children_map)


@app.delete("/groups/{group_id}")
async def delete_group(
    group_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Delete a group. Children are reparented to this group's parent so the
    tree stays connected; memberships cascade away via the FK."""
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    for child in list(group.children):
        child.parent_id = group.parent_id
    name = group.name
    db.delete(group)
    db.commit()
    return {"message": f"Group '{name}' deleted"}


# ---------------------------------------------------------------------------
# Sharing policy & tags. The Sharing feature's admin policy surface. The master
# switch lives in the SystemSetting('global') blob (validated in
# _validate_settings_payload, overlaid in get_settings, resolved by _sharing_enabled);
# the per-tag policy + create-allowlist live in the share_tags table (CRUD below,
# interactive-admin). GET /share-policy is the non-admin effective reader (like
# /zk-enabled) that shapes the share modal. No share creation or enforcement here.
# ---------------------------------------------------------------------------
# Tag fields whose columns are NOT NULL. A PATCH may OMIT them, but an explicit JSON null is rejected:
# ShareTagUpdate types everything Optional, so model_dump(exclude_unset=True) keeps an explicit null,
# which would otherwise violate the NOT-NULL column (500) or, for allowed_audiences, store an unusable
# empty-audiences tag. The caps (max_recipients_cap/max_downloads_cap) are nullable -> null clears them.
_SHARE_TAG_NOT_NULLABLE = frozenset({
    "name", "is_active", "max_lifetime_minutes", "default_lifetime_minutes",
    "allow_view_only", "default_view_only", "allow_custom", "auto_enroll_new_users", "allowed_audiences",
})


def _share_tag_dict(t: ShareTag) -> dict:
    """Full admin view of a share tag (includes the create-allowlist so the Tags manager can edit it).
    Id lists are stringified; this is the admin-only shape (GET /share-policy exposes far less)."""
    return {
        "id": str(t.id),
        "name": t.name,
        "description": t.description,
        "color": t.color,
        "is_active": t.is_active,
        "max_lifetime_minutes": t.max_lifetime_minutes,
        "default_lifetime_minutes": t.default_lifetime_minutes,
        "max_recipients_cap": t.max_recipients_cap,
        "max_recipients_default": t.max_recipients_default,
        "max_downloads_cap": t.max_downloads_cap,
        "max_downloads_default": t.max_downloads_default,
        "allow_view_only": t.allow_view_only,
        "default_view_only": t.default_view_only,
        "allow_custom": t.allow_custom,
        "allowed_audiences": list(t.allowed_audiences or []),
        "allowed_department_ids": [str(x) for x in (t.allowed_department_ids or [])],
        "allowed_user_ids": [str(x) for x in (t.allowed_user_ids or [])],
        "blocked_user_ids": [str(x) for x in (t.blocked_user_ids or [])],
        "auto_enroll_new_users": t.auto_enroll_new_users,
        "created_at": t.created_at.isoformat() if t.created_at else None,
    }


def _validate_ids_exist(db: Session, model, ids, field: str) -> None:
    """Reject a tag allowlist that references a user/group id that doesn't exist, so a typo can't
    silently do nothing (mirrors _validate_group_id_list's fail-loud philosophy)."""
    if not ids:
        return
    ids = [str(x) for x in ids]
    found = {str(r[0]) for r in db.query(model.id).filter(model.id.in_(ids)).all()}
    missing = [i for i in ids if i not in found]
    if missing:
        raise HTTPException(status_code=400, detail=f"{field} contains unknown id(s): {missing}")


def _validate_share_tag_fields(eff: dict, changed_keys: set, db: Session, existing: dict = None) -> None:
    """Cross-field + existence validation for a share tag. `eff` is the EFFECTIVE (post-merge) view so
    a PATCH that touches only one side of a pair is checked against the stored other side. Existence is
    only re-checked for id lists actually CHANGED, and (on PATCH) only for the NEWLY-ADDED ids vs
    `existing` — so an id that was valid when saved but whose user/group is later deleted can't block an
    unrelated edit, while a fresh typo still fails loud."""
    existing = existing or {}

    def _new_ids(key):
        prior = set(existing.get(key) or [])
        return [i for i in (eff.get(key) or []) if i not in prior]

    ml, dl = eff.get("max_lifetime_minutes"), eff.get("default_lifetime_minutes")
    if ml is not None and dl is not None and dl > ml:
        raise HTTPException(status_code=400, detail="default_lifetime_minutes cannot exceed max_lifetime_minutes")
    for cap_k, def_k in (("max_recipients_cap", "max_recipients_default"),
                         ("max_downloads_cap", "max_downloads_default")):
        cap, dv = eff.get(cap_k), eff.get(def_k)
        if cap is not None and dv is not None and dv > cap:
            raise HTTPException(status_code=400, detail=f"{def_k} cannot exceed {cap_k}")
    # A view-only DEFAULT is meaningless if view-only isn't even ALLOWED for the tag.
    if eff.get("default_view_only") and eff.get("allow_view_only") is False:
        raise HTTPException(status_code=400, detail="default_view_only requires allow_view_only")
    aud = eff.get("allowed_audiences")
    if aud is not None:
        bad = [a for a in aud if a not in sharing_policy.AUDIENCES]
        if bad:
            raise HTTPException(status_code=400,
                                detail=f"unknown audience(s) {bad}; allowed: {list(sharing_policy.AUDIENCES)}")
        if not sharing_policy.normalize_audiences(aud):
            raise HTTPException(status_code=400, detail="allowed_audiences must include at least one audience")
    if "allowed_department_ids" in changed_keys:
        _validate_ids_exist(db, Group, _new_ids("allowed_department_ids"), "allowed_department_ids")
    for uk in ("allowed_user_ids", "blocked_user_ids"):
        if uk in changed_keys:
            _validate_ids_exist(db, User, _new_ids(uk), uk)


def _audit_share_tag(db: Session, request: Request, user: User, action: str, tag: ShareTag) -> None:
    """Best-effort admin-config audit for a tag mutation (never fails the mutation). A tag NAME is an
    admin-authored classification label, not a file/folder name, so logging it is safe (cf. vault_name)."""
    try:
        AuditLogger(db).log_action(action=action, status="success", user=user,
                                   ip_address=get_client_ip(request),
                                   details={"tag_id": str(tag.id), "name": tag.name})
    except Exception:
        pass


@app.get("/share-tags")
async def list_share_tags(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """List all share tags (active AND inactive) for the admin Tags manager."""
    tags = db.query(ShareTag).order_by(ShareTag.name).all()
    return [_share_tag_dict(t) for t in tags]


@app.post("/share-tags")
async def create_share_tag(
    payload: ShareTagCreate,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Create a share tag (interactive-admin). Name is unique; policy + create-allowlist validated."""
    name = payload.name.strip()
    if not name:
        raise HTTPException(status_code=400, detail="Tag name is required")
    existing = db.query(ShareTag).filter(ShareTag.name == name).first()
    if existing:
        if not existing.is_active:
            raise HTTPException(status_code=400,
                                detail="A deactivated tag already uses this name — reactivate it or choose another")
        raise HTTPException(status_code=400, detail="A tag with that name already exists")
    data = payload.model_dump()
    data["name"] = name
    for k in ("allowed_department_ids", "allowed_user_ids", "blocked_user_ids"):
        data[k] = [str(x) for x in (data.get(k) or [])]
    _validate_share_tag_fields(data, set(data.keys()), db)
    data["allowed_audiences"] = sharing_policy.normalize_audiences(data.get("allowed_audiences"))
    tag = ShareTag(created_by=current_user.id, **data)
    db.add(tag)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # a concurrent create raced the same unique name -> clean 400, not a 500
        raise HTTPException(status_code=400, detail="A tag with that name already exists")
    db.refresh(tag)
    _audit_share_tag(db, request, current_user, "share_tag_created", tag)
    return _share_tag_dict(tag)


@app.patch("/share-tags/{tag_id}")
async def update_share_tag(
    tag_id: uuid.UUID,
    payload: ShareTagUpdate,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Update a share tag's policy / create-allowlist / active state (interactive-admin). Only PROVIDED
    keys change; editing does NOT retroactively alter existing shares (they snapshot the tag at create)."""
    tag = db.query(ShareTag).filter(ShareTag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    data = payload.model_dump(exclude_unset=True)
    # An explicit JSON null on a NOT-NULL field is rejected here (a PATCH may omit it, but must not blank
    # it): otherwise it would violate the column (500) or, for allowed_audiences, store an unusable tag.
    for k in _SHARE_TAG_NOT_NULLABLE:
        if k in data and data[k] is None:
            raise HTTPException(status_code=400, detail=f"{k} cannot be null")
    if "name" in data:
        nm = (data["name"] or "").strip()
        if not nm:
            raise HTTPException(status_code=400, detail="Tag name cannot be empty")
        if db.query(ShareTag).filter(ShareTag.name == nm, ShareTag.id != tag_id).first():
            raise HTTPException(status_code=400, detail="A tag with that name already exists")
        data["name"] = nm
    for k in ("allowed_department_ids", "allowed_user_ids", "blocked_user_ids"):
        if k in data:
            data[k] = [str(x) for x in (data[k] or [])]
    eff = _share_tag_dict(tag)
    stored = dict(eff)  # snapshot BEFORE the patch, so only newly-added ids are existence-checked
    eff.update(data)
    _validate_share_tag_fields(eff, set(data.keys()), db, existing=stored)
    if "allowed_audiences" in data:
        data["allowed_audiences"] = sharing_policy.normalize_audiences(data["allowed_audiences"])
    for k, v in data.items():
        setattr(tag, k, v)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # a concurrent rename raced the same unique name -> clean 400, not a 500
        raise HTTPException(status_code=400, detail="A tag with that name already exists")
    db.refresh(tag)
    _audit_share_tag(db, request, current_user, "share_tag_updated", tag)
    return _share_tag_dict(tag)


@app.delete("/share-tags/{tag_id}")
async def deactivate_share_tag(
    tag_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Soft-deactivate a share tag (interactive-admin) — NEVER a hard delete, so any shares that
    reference it keep their snapshot. Deactivating stops NEW creates with the tag; reactivate via PATCH
    is_active=true."""
    tag = db.query(ShareTag).filter(ShareTag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Tag not found")
    tag.is_active = False
    db.commit()
    _audit_share_tag(db, request, current_user, "share_tag_deactivated", tag)
    return {"message": f"Tag '{tag.name}' deactivated", "id": str(tag.id), "is_active": False}


@app.get("/share-policy")
async def get_share_policy(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Effective sharing policy for the CURRENT user — non-admin readable (like /zk-enabled), so the
    share modal can shape controls without exposing the admin-only /settings or /share-tags.
    Returns whether sharing is on + ONLY the tags this user may CREATE shares with, each carrying its
    effective limit envelope + allowed audiences.

    FAIL-CLOSED: sharing off -> no tags; a temp-credential session can never create a share -> no tags;
    a user not permitted by a tag's create-allowlist never sees that tag. The create-allowlist internals
    (who is allowed/blocked) are NEVER exposed here."""
    enabled = _sharing_enabled(db)
    if not enabled or getattr(current_user, "_is_temp_session", False):
        return {"sharing_enabled": enabled, "tags": []}
    user_gids = [
        str(r[0]) for r in db.query(user_groups.c.group_id)
        .filter(user_groups.c.user_id == current_user.id).all()
    ]
    creatable = []
    for t in db.query(ShareTag).filter(ShareTag.is_active.is_(True)).order_by(ShareTag.name).all():
        allowlist = {
            "is_active": t.is_active,
            "blocked_user_ids": t.blocked_user_ids,
            "allowed_user_ids": t.allowed_user_ids,
            "allowed_department_ids": t.allowed_department_ids,
            "auto_enroll_new_users": t.auto_enroll_new_users,
        }
        if not sharing_policy.user_can_create_with_tag(allowlist, current_user.id, user_gids):
            continue
        eff = sharing_policy.tag_effective_limits({
            "max_lifetime_minutes": t.max_lifetime_minutes,
            "default_lifetime_minutes": t.default_lifetime_minutes,
            "max_recipients_cap": t.max_recipients_cap,
            "max_recipients_default": t.max_recipients_default,
            "max_downloads_cap": t.max_downloads_cap,
            "max_downloads_default": t.max_downloads_default,
        })
        creatable.append({
            "id": str(t.id),
            "name": t.name,
            "color": t.color,
            "allowed_audiences": sharing_policy.normalize_audiences(t.allowed_audiences),
            "allow_view_only": t.allow_view_only,
            "default_view_only": t.default_view_only,
            "allow_custom": t.allow_custom,
            **eff,
        })
    return {"sharing_enabled": True, "tags": creatable}


# ---------------------------------------------------------------------------
# Shares (create + list-mine). A Share grants ONE item (file / folder / whole Standard vault) to
# authorized internal users, classified by a ShareTag whose limit policy is SNAPSHOTTED at creation.
# The link token is a bearer secret: stored HASHED and shown once at create.
# ---------------------------------------------------------------------------
def _user_group_ids(db: Session, user_id) -> list:
    return [str(r[0]) for r in db.query(user_groups.c.group_id).filter(user_groups.c.user_id == user_id).all()]


def _validate_share_audience_users(db: Session, current_user: User, aud_users: list) -> None:
    """A direct-push 'users' audience must be limited to recipients the creator could actually reach
    through the recipient picker (GET /users/search): active, non-EXTERNAL accounts, and — when the org
    sets directory_search_scope='same_department' — accounts sharing a department with the creator.
    Existence is already checked by _validate_ids_exist; this applies the SAME eligibility filter the
    picker applies, so a crafted POST /shares can't push a share to a user the picker would never
    surface (an out-of-scope, EXTERNAL, or inactive account). An interactive admin is NOT
    department-scoped — they have the unrestricted /users directory — mirroring /users/search. Fail-
    closed: any ineligible id is rejected with a non-enumerating 400 (the specific ids are not echoed)."""
    if not aud_users:
        return
    from sqlalchemy import select as _select
    q = db.query(User.id).filter(
        User.id.in_(aud_users),
        User.is_active == True,  # noqa: E712
        User.role != RoleEnum.EXTERNAL,
    )
    if getattr(current_user, "role", None) != RoleEnum.ADMIN and _directory_search_scope(db) == "same_department":
        caller_gids = _select(user_groups.c.group_id).where(user_groups.c.user_id == current_user.id)
        q = q.join(user_groups, User.id == user_groups.c.user_id).filter(
            user_groups.c.group_id.in_(caller_gids)).distinct()
    eligible = {str(r[0]) for r in q.all()}
    if any(str(u) not in eligible for u in aud_users):
        raise HTTPException(
            status_code=400,
            detail="One or more selected recipients aren't eligible to receive this share.")


def _share_effective_status(share: Share) -> str:
    """Lazy expiry: an active share past its expiry reads as 'expired' (a periodic sweep can flip the
    stored status later; correctness never depends on it)."""
    if share.status == "active" and share.expires_at and share.expires_at <= datetime.utcnow():
        return "expired"
    return share.status


def _share_dict(db: Session, share: Share, claim_counts: dict = None) -> dict:
    """Creator-facing view of a share ('Shared by me'). NEVER includes the link token (shown once at
    create); only whether a link exists. `claim_counts` is an optional precomputed {share_id: count} map
    so a list view avoids an N+1 COUNT per share."""
    if claim_counts is not None:
        claim_count = claim_counts.get(str(share.id), 0)
    else:
        claim_count = db.query(ShareClaim).filter(
            ShareClaim.share_id == share.id, ShareClaim.revoked.is_(False)).count()
    # Display names for the management cards. tag_name comes from the creation snapshot (survives a
    # later tag rename/deactivation); target_name is the folder/file name (Standard-vault plaintext
    # the creator authored). vault_name for the item label.
    tag_name = (share.tag_policy_snapshot or {}).get("tag_name") if isinstance(share.tag_policy_snapshot, dict) else None
    vault = db.query(Vault).filter(Vault.id == share.vault_id).first()
    target_name = None
    if share.target_type == "folder" and share.target_folder_id:
        f = db.query(Folder).filter(Folder.id == share.target_folder_id).first()
        target_name = f.name if f else None
    elif share.target_type == "file" and share.target_file_id:
        x = db.query(File).filter(File.id == share.target_file_id).first()
        target_name = x.original_name if x else None
    return {
        "id": str(share.id),
        "vault_id": str(share.vault_id),
        "vault_name": vault.name if vault else None,
        "tag_id": str(share.tag_id),
        "tag_name": tag_name,
        "target_name": target_name,
        "target_type": share.target_type,
        "target_folder_id": str(share.target_folder_id) if share.target_folder_id else None,
        "target_file_id": str(share.target_file_id) if share.target_file_id else None,
        "claim_audience": share.claim_audience,
        "audience_user_ids": [str(x) for x in (share.audience_user_ids or [])],
        "audience_department_ids": [str(x) for x in (share.audience_department_ids or [])],
        "has_link": bool(share.link_token_hash),
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "max_recipients": share.max_recipients,
        "max_downloads": share.max_downloads,
        "view_only": share.view_only,
        "status": _share_effective_status(share),
        "claim_count": claim_count,
        "created_at": share.created_at.isoformat() if share.created_at else None,
    }


@app.post("/shares")
async def create_share(
    payload: ShareCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a share of a file / folder / whole Standard vault. Fail-closed:
    a temporary session cannot create; sharing must be on; the creator must be able to READ the item;
    zero-knowledge and password-protected vaults are refused; the tag must be active and permit the
    creator (its create-allowlist); the audience must be one the tag allows; limit overrides are honored
    only within the tag caps. The tag's limits are snapshotted; a bearer link token is minted, stored
    HASHED, and returned ONCE."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary session cannot create shares.")
    if not _sharing_enabled(db):
        raise HTTPException(status_code=403, detail="Sharing is disabled on this deployment.")

    vault = db.query(Vault).filter(Vault.id == payload.vault_id, Vault.is_active.is_(True)).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found.")
    if not PermissionService(db).can_access_vault(current_user, vault.id, VaultPermissionEnum.READ):
        raise HTTPException(status_code=403, detail="You do not have access to this vault.")
    if getattr(vault, "type", "standard") == "zero_knowledge":
        raise HTTPException(status_code=400,
                            detail="Zero-knowledge vaults can't be shared — add the person as a member instead.")
    if vault.password_hash:
        raise HTTPException(status_code=400,
                            detail="Password-protected vaults can't be shared yet — remove the vault password or add the person as a member.")

    tag = db.query(ShareTag).filter(ShareTag.id == payload.tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Share tag not found.")
    if not tag.is_active:
        raise HTTPException(status_code=400, detail="That share tag is inactive.")
    allowlist = {
        "is_active": tag.is_active, "blocked_user_ids": tag.blocked_user_ids,
        "allowed_user_ids": tag.allowed_user_ids, "allowed_department_ids": tag.allowed_department_ids,
        "auto_enroll_new_users": tag.auto_enroll_new_users,
    }
    if not sharing_policy.user_can_create_with_tag(allowlist, current_user.id, _user_group_ids(db, current_user.id)):
        raise HTTPException(status_code=403, detail="You are not allowed to create shares with this tag.")

    # --- Target must be a real item in THIS vault ---
    tt = payload.target_type
    tf_folder = tf_file = None
    if tt == "vault":
        if payload.target_folder_id or payload.target_file_id:
            raise HTTPException(status_code=400, detail="A whole-vault share takes no folder/file target.")
    elif tt == "folder":
        if not payload.target_folder_id:
            raise HTTPException(status_code=400, detail="A folder share requires target_folder_id.")
        if payload.target_file_id:
            raise HTTPException(status_code=400, detail="A folder share takes no file target.")
        folder = db.query(Folder).filter(Folder.id == payload.target_folder_id, Folder.vault_id == vault.id).first()
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found in this vault.")
        # A folder can carry its OWN password gate (enforced on list/download); refuse to share it for the
        # same reason a password-protected vault is refused — a share would bypass that gate.
        if folder.password_hash:
            raise HTTPException(status_code=400,
                                detail="Password-protected folders can't be shared — remove the folder password or add the person as a member.")
        tf_folder = folder.id
    else:  # file
        if not payload.target_file_id:
            raise HTTPException(status_code=400, detail="A file share requires target_file_id.")
        if payload.target_folder_id:
            raise HTTPException(status_code=400, detail="A file share takes no folder target.")
        f = db.query(File).filter(File.id == payload.target_file_id, File.vault_id == vault.id).first()
        if not f:
            raise HTTPException(status_code=404, detail="File not found in this vault.")
        if f.password_hash:
            raise HTTPException(status_code=400,
                                detail="Password-protected files can't be shared — remove the file password or add the person as a member.")
        tf_file = f.id

    # --- Audience within the tag's allowed audiences ---
    if payload.claim_audience not in sharing_policy.normalize_audiences(tag.allowed_audiences):
        raise HTTPException(status_code=400, detail=f"This tag does not allow the '{payload.claim_audience}' audience.")
    aud_users = [str(x) for x in (payload.audience_user_ids or [])]
    aud_depts = [str(x) for x in (payload.audience_department_ids or [])]
    if payload.claim_audience == "users":
        if not aud_users:
            raise HTTPException(status_code=400, detail="Select at least one user for a user-audience share.")
        _validate_ids_exist(db, User, aud_users, "audience_user_ids")
        _validate_share_audience_users(db, current_user, aud_users)
        aud_depts = []
    elif payload.claim_audience == "departments":
        if not aud_depts:
            raise HTTPException(status_code=400, detail="Select at least one department for a department-audience share.")
        _validate_ids_exist(db, Group, aud_depts, "audience_department_ids")
        aud_users = []
    else:  # anyone_internal — bounded by the link token + limits, never anonymous
        aud_users = aud_depts = []

    # --- Limits within the tag caps (honoring allow_custom), then snapshot ---
    tag_limits = {
        "max_lifetime_minutes": tag.max_lifetime_minutes, "default_lifetime_minutes": tag.default_lifetime_minutes,
        "max_recipients_cap": tag.max_recipients_cap, "max_recipients_default": tag.max_recipients_default,
        "max_downloads_cap": tag.max_downloads_cap, "max_downloads_default": tag.max_downloads_default,
        "allow_view_only": tag.allow_view_only, "default_view_only": tag.default_view_only,
        "allow_custom": tag.allow_custom,
    }
    limits, err = sharing_policy.resolve_share_limits(tag_limits, {
        "lifetime_minutes": payload.lifetime_minutes, "max_recipients": payload.max_recipients,
        "max_downloads": payload.max_downloads, "view_only": payload.view_only,
    })
    if err:
        raise HTTPException(status_code=400, detail=err)
    try:
        expires_at = datetime.utcnow() + timedelta(minutes=limits["lifetime_minutes"])
    except OverflowError:  # an absurd admin-set tag ceiling; the creator can't reach this
        raise HTTPException(status_code=400, detail="The share lifetime is too large.")

    # --- Bearer link token: minted, stored HASHED, returned once ---
    link_token = link_token_hash = None
    if payload.with_link:
        import secrets as _secrets
        import hashlib as _hashlib
        link_token = _secrets.token_urlsafe(32)   # high-entropy bearer secret
        link_token_hash = _hashlib.sha256(link_token.encode()).hexdigest()  # only the hash is stored

    snapshot = dict(sharing_policy.tag_effective_limits(tag_limits))
    snapshot.update({"allow_view_only": tag.allow_view_only, "default_view_only": tag.default_view_only,
                     "allow_custom": tag.allow_custom, "tag_name": tag.name})
    share = Share(
        creator_id=current_user.id, vault_id=vault.id, tag_id=tag.id,
        target_type=tt, target_folder_id=tf_folder, target_file_id=tf_file,
        link_token_hash=link_token_hash, claim_audience=payload.claim_audience,
        audience_user_ids=aud_users, audience_department_ids=aud_depts,
        expires_at=expires_at, max_recipients=limits["max_recipients"], max_downloads=limits["max_downloads"],
        view_only=limits["view_only"], tag_policy_snapshot=snapshot, status="active",
    )
    db.add(share)
    db.commit()
    db.refresh(share)
    try:
        AuditLogger(db).log_action(
            action="share_created", status="success", user=current_user, ip_address=get_client_ip(request),
            details={"share_id": str(share.id), "vault_id": str(vault.id), "target_type": tt,
                     "tag_id": str(tag.id), "claim_audience": payload.claim_audience, "view_only": limits["view_only"]})
    except Exception:
        pass  # never fail the create on an audit-write error
    out = _share_dict(db, share)
    out["link_token"] = link_token  # SHOW ONCE — only the hash is stored; this is never returned again
    return out


@app.get("/shares")
async def list_my_shares(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The current user's own shares ('Shared by me'). Never returns the link token (shown once at
    create). A temp session owns no shares."""
    if getattr(current_user, "_is_temp_session", False):
        return []
    shares = db.query(Share).filter(Share.creator_id == current_user.id).order_by(Share.created_at.desc()).all()
    # One GROUP BY for all the creator's shares instead of a COUNT per row.
    from sqlalchemy import func as _func
    ids = [s.id for s in shares]
    counts = {}
    if ids:
        rows = db.query(ShareClaim.share_id, _func.count(ShareClaim.id)).filter(
            ShareClaim.share_id.in_(ids), ShareClaim.revoked.is_(False)).group_by(ShareClaim.share_id).all()
        counts = {str(sid): c for sid, c in rows}
    return [_share_dict(db, s, claim_counts=counts) for s in shares]


def _load_manageable_share(db: Session, share_id, current_user: User) -> Share:
    """Fetch a share the caller may MANAGE (revoke / kick): the creator or a global admin. A temp
    session can never manage a share. Raises the mapped HTTPException on any failure (fail-closed)."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary session cannot manage shares.")
    share = db.query(Share).filter(Share.id == share_id).first()
    if not share:
        raise HTTPException(status_code=404, detail="Share not found.")
    if share.creator_id != current_user.id and current_user.role != RoleEnum.ADMIN:
        raise HTTPException(status_code=403, detail="Only the share's creator or an admin can manage it.")
    return share


@app.post("/shares/{share_id}/revoke")
async def revoke_share(
    share_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke a whole share (creator or admin). Sets status='revoked'; every claimant loses access at
    the vault chokepoint on their next request (evaluated LIVE — there is no session to expire).
    Idempotent: revoking an already-revoked share is a no-op success."""
    share = _load_manageable_share(db, share_id, current_user)
    if share.status != "revoked":
        share.status = "revoked"
        share.revoked_at = datetime.utcnow()
        share.revoked_by = current_user.id
        db.commit()
        try:
            AuditLogger(db).log_action(
                action="share_revoked", status="success", user=current_user,
                ip_address=get_client_ip(request),
                details={"share_id": str(share.id), "vault_id": str(share.vault_id)})
        except Exception:
            db.rollback()
    return _share_dict(db, share)


@app.post("/shares/{share_id}/claims/{user_id}/revoke")
async def revoke_share_claim(
    share_id: uuid.UUID,
    user_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Kick a single recipient from a share (creator or admin) without revoking it for everyone. Sets
    that recipient's ShareClaim.revoked=True; they lose access LIVE at the chokepoint, other claimants
    keep theirs. Idempotent for an already-kicked recipient; 404 if that user never claimed."""
    share = _load_manageable_share(db, share_id, current_user)
    claim = db.query(ShareClaim).filter(
        ShareClaim.share_id == share.id, ShareClaim.user_id == user_id).first()
    if not claim:
        raise HTTPException(status_code=404, detail="That recipient has not claimed this share.")
    if not claim.revoked:
        claim.revoked = True
        db.commit()
        try:
            target = db.query(User).filter(User.id == user_id).first()
            AuditLogger(db).log_permission_revoked(
                target_user_id=user_id, target_username=(target.username if target else "?"),
                permission=f"share:{share.id}", revoked_by=current_user, ip_address=get_client_ip(request))
        except Exception:
            db.rollback()
    return {"share_id": str(share.id), "user_id": str(user_id), "revoked": True}


@app.get("/shares/{share_id}/claims")
async def list_share_claims(
    share_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The recipients who have claimed a share, for the creator's (or an admin's) management view —
    so they can see usage and kick a specific recipient. Creator/admin only (via _load_manageable_share,
    which also blocks temp sessions). Returns per-recipient id/username + download usage + revoked flag;
    no tokens."""
    share = _load_manageable_share(db, share_id, current_user)
    rows = (
        db.query(ShareClaim, User.username)
        .join(User, User.id == ShareClaim.user_id)
        .filter(ShareClaim.share_id == share.id)
        .order_by(ShareClaim.claimed_at.asc())
        .all()
    )
    return [{
        "user_id": str(c.user_id),
        "username": username,
        "download_count": c.download_count,
        "revoked": bool(c.revoked),
        "claimed_at": c.claimed_at.isoformat() if c.claimed_at else None,
        "last_access_at": c.last_access_at.isoformat() if c.last_access_at else None,
    } for c, username in rows]


def _share_claim_dict(claim: ShareClaim, share: Share) -> dict:
    """Recipient-facing view returned to a claimant. Describes WHAT was claimed (so the Shared tab can
    render a card); it does NOT itself grant access — the claim is authorized at the vault chokepoint on
    each access. No token, no creator/allowlist internals."""
    return {
        "claim_id": str(claim.id),
        "share_id": str(share.id),
        "vault_id": str(share.vault_id),
        "target_type": share.target_type,
        "target_folder_id": str(share.target_folder_id) if share.target_folder_id else None,
        "target_file_id": str(share.target_file_id) if share.target_file_id else None,
        "view_only": share.view_only,
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "claimed_at": claim.claimed_at.isoformat() if claim.claimed_at else None,
    }


@app.post("/shares/claim")
async def claim_share(
    payload: ShareClaimRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Claim a share by its link token. Fail-closed: a temporary session cannot claim; sharing must be
    on; the token must resolve to an ACTIVE, non-expired, non-revoked share; the claimant must satisfy
    the share's claim-audience; and the recipient limit must not be exceeded (an existing non-revoked
    claim is returned idempotently, a revoked one is denied). Creates a ShareClaim — this does NOT itself
    grant access to the shared item; the claim is authorized at the vault chokepoint on each access."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary session cannot claim shares.")
    if not _sharing_enabled(db):
        raise HTTPException(status_code=403, detail="Sharing is disabled on this deployment.")

    import hashlib as _hashlib
    token = (payload.token or "").strip()
    # 'surrogatepass' so an adversarial lone-surrogate token can't crash encode() (500); the resulting
    # hash matches no stored token and the request falls through to the clean 404 below.
    token_hash = _hashlib.sha256(token.encode("utf-8", "surrogatepass")).hexdigest()
    share = db.query(Share).filter(Share.link_token_hash == token_hash).first()
    if not share:
        raise HTTPException(status_code=404, detail="That share link is not valid.")
    return _claim_resolved_share(db, share, current_user, request)


def _claim_resolved_share(db: Session, share: Share, current_user: User, request: Request) -> dict:
    """Shared claim logic once the share is resolved (by token OR by id): status/expiry, defense-in-depth
    ZK/password refusal, the claim-audience check, idempotent re-open (revoked denied), the row-locked
    max_recipients guard, create the ShareClaim, audit. The caller has already checked the temp-session
    and sharing-enabled gates. Returns the recipient claim dict."""
    if share.status == "revoked":
        raise HTTPException(status_code=410, detail="That share has been revoked.")
    if _share_effective_status(share) == "expired":
        if share.status == "active":
            share.status = "expired"  # lazy expiry: flip the stored status for the UI
            db.commit()
            # Audit the active->expired transition (ids only, name-redacted). The status=='active' guard
            # above suppresses re-emit on any later claim of the already-flipped share, so sequential
            # claims emit once; a rare concurrent claim race could still write a duplicate benign audit
            # row (the flip is idempotent, so no data impact). Expiry is otherwise lazy (no periodic
            # sweep), so this claim-time flip is the transition event.
            try:
                AuditLogger(db).log_action(
                    action="share_expired", status="success", user=current_user,
                    ip_address=get_client_ip(request),
                    details={"share_id": str(share.id), "vault_id": str(share.vault_id)})
            except Exception:
                db.rollback()
        raise HTTPException(status_code=410, detail="That share has expired.")

    # Defense-in-depth: the vault must still be a shareable Standard, non-password vault (these are refused
    # at CREATE, but a vault password could be added afterwards — a claim must not open that gate).
    vault = db.query(Vault).filter(Vault.id == share.vault_id, Vault.is_active.is_(True)).first()
    if not vault or getattr(vault, "type", "standard") == "zero_knowledge" or vault.password_hash:
        raise HTTPException(status_code=403, detail="That share is no longer available.")

    if not sharing_policy.user_matches_claim_audience(
            share.claim_audience, share.audience_user_ids, share.audience_department_ids,
            current_user.id, _user_group_ids(db, current_user.id)):
        raise HTTPException(status_code=403, detail="You are not in the audience for this share.")

    existing = db.query(ShareClaim).filter(
        ShareClaim.share_id == share.id, ShareClaim.user_id == current_user.id).first()
    if existing:
        if existing.revoked:
            raise HTTPException(status_code=403, detail="Your access to this share was revoked.")
        return _share_claim_dict(existing, share)  # idempotent re-open

    # Serialize the recipient-limit check + insert against the share row, so concurrent claims by
    # DIFFERENT users cannot over-admit past max_recipients (a plain count-then-insert would race; the
    # unique (share,user) constraint only guards the same-user race). The lock releases on commit.
    locked = db.query(Share).filter(Share.id == share.id).with_for_update().first()
    if locked is not None and locked.max_recipients is not None:
        active = db.query(ShareClaim).filter(
            ShareClaim.share_id == share.id, ShareClaim.revoked.is_(False)).count()
        if active >= locked.max_recipients:
            db.rollback()  # release the FOR UPDATE lock
            raise HTTPException(status_code=409, detail="This share has reached its recipient limit.")

    claim = ShareClaim(share_id=share.id, user_id=current_user.id)
    db.add(claim)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()  # a concurrent claim by the same user raced the unique (share,user) -> idempotent
        existing = db.query(ShareClaim).filter(
            ShareClaim.share_id == share.id, ShareClaim.user_id == current_user.id).first()
        if existing and not existing.revoked:
            return _share_claim_dict(existing, share)
        raise HTTPException(status_code=409, detail="Could not claim this share.")
    db.refresh(claim)
    try:
        AuditLogger(db).log_action(
            action="share_claimed", status="success", user=current_user, ip_address=get_client_ip(request),
            details={"share_id": str(share.id), "vault_id": str(share.vault_id)})
    except Exception:
        pass
    return _share_claim_dict(claim, share)


@app.post("/shares/{share_id}/claim")
async def claim_pushed_share(
    share_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Claim a share you were DIRECTLY pushed to (a named users/departments audience) BY ID, without the
    link token — the audience check is the gate. anyone_internal shares are link-only (they carry no
    named recipients), so they must be claimed via POST /shares/claim with the token. Fail-closed: temp
    session denied; sharing must be on; the audience membership is verified in _claim_resolved_share."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary session cannot claim shares.")
    if not _sharing_enabled(db):
        raise HTTPException(status_code=403, detail="Sharing is disabled on this deployment.")
    share = db.query(Share).filter(Share.id == share_id).first()
    if not share:
        raise HTTPException(status_code=404, detail="Share not found.")
    if share.claim_audience not in ("users", "departments"):
        raise HTTPException(status_code=403, detail="This share can only be claimed through its link.")
    return _claim_resolved_share(db, share, current_user, request)


def _shared_with_me_dict(db: Session, claim: ShareClaim, share: Share) -> dict:
    """Recipient-facing card for the 'Shared with me' tab. Describes the shared item (vault name +
    target kind/name) + the effective status so an expired/revoked card can show its reason, and the
    recipient's own download usage. NEVER includes the link token or any creator/allowlist internals.
    Standard vaults only, so the target name is server-visible plaintext the recipient may already
    list."""
    if claim.revoked or share.status == "revoked":
        st = "revoked"
    elif _share_effective_status(share) == "expired":
        st = "expired"
    else:
        st = "active"
    # A recipient who has LOST access (revoked/expired) must not learn the item's CURRENT name — that
    # would be a live, post-access rename oracle. Resolve names ONLY for an active claim; an inactive
    # card shows just the kind + the reason.
    vault_name = target_name = None
    if st == "active":
        vault = db.query(Vault).filter(Vault.id == share.vault_id).first()
        vault_name = vault.name if vault else None
        if share.target_type == "folder" and share.target_folder_id:
            f = db.query(Folder).filter(Folder.id == share.target_folder_id).first()
            target_name = f.name if f else None
        elif share.target_type == "file" and share.target_file_id:
            x = db.query(File).filter(File.id == share.target_file_id).first()
            target_name = x.original_name if x else None
    return {
        "claim_id": str(claim.id),
        "share_id": str(share.id),
        "vault_id": str(share.vault_id),
        "vault_name": vault_name,
        "target_type": share.target_type,
        "target_folder_id": str(share.target_folder_id) if share.target_folder_id else None,
        "target_file_id": str(share.target_file_id) if share.target_file_id else None,
        "target_name": target_name,
        "view_only": share.view_only,
        "status": st,
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "max_downloads": share.max_downloads,
        "download_count": claim.download_count,
        "claimed_at": claim.claimed_at.isoformat() if claim.claimed_at else None,
    }


def _shared_available_dict(db: Session, share: Share) -> Optional[dict]:
    """A DIRECT-PUSH share addressed to the current user (named users/departments audience) that they
    have NOT claimed yet — an 'available' card they can claim in one click. Returns None if the vault is
    no longer shareable (deleted / zero-knowledge / password-protected), so a stale push isn't offered."""
    vault = db.query(Vault).filter(Vault.id == share.vault_id, Vault.is_active.is_(True)).first()
    if not vault or getattr(vault, "type", "standard") == "zero_knowledge" or vault.password_hash:
        return None
    # A share whose recipient cap is already full can never be claimed by a new recipient — don't offer
    # a dead-end 'Claim' card (the claim would just 409). First-come-first-served among the pushed set.
    if share.max_recipients is not None:
        active = db.query(ShareClaim).filter(
            ShareClaim.share_id == share.id, ShareClaim.revoked.is_(False)).count()
        if active >= share.max_recipients:
            return None
    target_name = None
    if share.target_type == "folder" and share.target_folder_id:
        f = db.query(Folder).filter(Folder.id == share.target_folder_id).first()
        target_name = f.name if f else None
    elif share.target_type == "file" and share.target_file_id:
        x = db.query(File).filter(File.id == share.target_file_id).first()
        target_name = x.original_name if x else None
    return {
        "claim_id": None,
        "share_id": str(share.id),
        "vault_id": str(share.vault_id),
        "vault_name": vault.name,
        "target_type": share.target_type,
        "target_folder_id": str(share.target_folder_id) if share.target_folder_id else None,
        "target_file_id": str(share.target_file_id) if share.target_file_id else None,
        "target_name": target_name,
        "view_only": share.view_only,
        "status": "available",   # pushed to you; claim to access
        "expires_at": share.expires_at.isoformat() if share.expires_at else None,
        "max_downloads": share.max_downloads,
        "download_count": 0,
        "claimed_at": None,
    }


@app.get("/shares/shared-with-me")
async def list_shared_with_me(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The current user's 'Shared with me' tab: shares they have CLAIMED (active/expired/revoked, so the
    UI can show a reason) PLUS shares they were directly pushed (named users/departments audience) but
    have not claimed yet ('available'). NEVER a token. A temp session owns nothing."""
    if getattr(current_user, "_is_temp_session", False):
        return []
    rows = (
        db.query(ShareClaim, Share)
        .join(Share, Share.id == ShareClaim.share_id)
        .filter(ShareClaim.user_id == current_user.id)
        .order_by(ShareClaim.claimed_at.desc())
        .all()
    )
    out = [_shared_with_me_dict(db, claim, share) for claim, share in rows]

    # Direct push: active named-audience shares addressed to this user that they haven't claimed appear
    # as 'available' cards. (Filtered in Python against the audience helper — the audience lists are
    # small; the recipient tab is not a hot poll.)
    claimed_ids = {r[1].id for r in rows}
    now = datetime.utcnow()
    gids = _user_group_ids(db, current_user.id)
    pushed = (
        db.query(Share)
        .filter(Share.status == "active", Share.expires_at > now,
                Share.claim_audience.in_(("users", "departments")))
        .order_by(Share.created_at.desc())
        .all()
    )
    for share in pushed:
        if share.id in claimed_ids:
            continue
        if sharing_policy.user_matches_claim_audience(
                share.claim_audience, share.audience_user_ids, share.audience_department_ids,
                current_user.id, gids):
            d = _shared_available_dict(db, share)
            if d is not None:
                out.append(d)
    return out


@app.post("/groups/{group_id}/members")
async def add_group_members(
    group_id: uuid.UUID,
    payload: GroupMembersAdd,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Add one or more users to a group (idempotent)."""
    group = db.query(Group).filter(Group.id == group_id).first()
    if not group:
        raise HTTPException(status_code=404, detail="Group not found")
    group_role = payload.group_role if payload.group_role in ('member', 'manager') else 'member'
    existing = {
        row[0] for row in db.query(user_groups.c.user_id).filter(user_groups.c.group_id == group_id).all()
    }
    added = 0
    for uid in payload.user_ids:
        if uid in existing:
            continue
        if not db.query(User).filter(User.id == uid).first():
            continue
        db.execute(user_groups.insert().values(
            user_id=uid, group_id=group_id, group_role=group_role,
            added_at=datetime.utcnow(), added_by=current_user.id,
        ))
        existing.add(uid)
        added += 1
    db.commit()
    return {"message": f"Added {added} member(s)", "added": added}


@app.delete("/groups/{group_id}/members/{user_id}")
async def remove_group_member(
    group_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Remove a user from a group."""
    if not db.query(Group).filter(Group.id == group_id).first():
        raise HTTPException(status_code=404, detail="Group not found")
    db.execute(user_groups.delete().where(
        (user_groups.c.group_id == group_id) & (user_groups.c.user_id == user_id)
    ))
    db.commit()
    return {"message": "Member removed"}


# Vault Endpoints

def _effective_vault_permission(vault, perms, user) -> str:
    """Collapse the {read,write,delete,manage} permission dict into a single level
    the UI can act on. Owner outranks everything; a member with 'manage' is a vault
    Manager (ranks above delete); admins without an explicit grant get 'none'
    because the write endpoints are owner/member-only anyway."""
    if vault.owner_id == user.id:
        return 'owner'
    if not perms:
        return 'none'
    if perms.get('manage'):
        return 'manage'
    if perms.get('delete'):
        return 'delete'
    if perms.get('write'):
        return 'write'
    if perms.get('read'):
        return 'read'
    return 'none'


# Confidentiality tiers we recognise. Only 'standard' (server-encrypted,
# SFTP-capable) is functional today; 'zero_knowledge' (browser crypto, web-only)
# is a later tier — see docs/vault-zero-trust-and-sftp-design.md §2.
VAULT_TYPES = {"standard", "zero_knowledge"}


def _allowed_vault_types() -> set:
    """The vault TYPES creatable on this deployment, per the operator-set,
    customer-admin-irreversible allowlist (settings.plan_allowed_vault_types, a
    comma-separated PLAN_* env). Entries are normalised and intersected with the
    recognised VAULT_TYPES; an EMPTY or all-unrecognised value means NO restriction —
    every recognised type is allowed (the permissive default). Never returns an empty
    set, so a mis-set env can't brick all vault creation."""
    raw = settings.plan_allowed_vault_types or ""
    wanted = {t.strip().lower() for t in raw.split(",") if t.strip()}
    allowed = wanted & VAULT_TYPES
    return allowed or set(VAULT_TYPES)


def _is_zk_vault(vault) -> bool:
    """True for zero-knowledge vaults (client-side crypto; server never holds the
    DEK). ZK sharing must be explicit per-user so the DEK can be wrapped to each
    recipient's key — group/department access can't deliver a key and is rejected."""
    return getattr(vault, "type", "standard") == "zero_knowledge"


def _require_zk_sealed_names(*tokens) -> None:
    """Reject any client-supplied ZK name blob that is not a sealed 'zk1:' ciphertext.
    The marker is a SERVER-enforced invariant: the model load events skip ZK blobs by it,
    the seal no-clobber guard keys on it, and enforcing it stops a buggy/hostile client from
    parking a plaintext (or otherwise non-conformant) name in the enc_name column."""
    from app.core.security import is_zk_sealed_name
    for t in tokens:
        if t is not None and not is_zk_sealed_name(t):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Encrypted name must be a sealed zero-knowledge blob.",
            )


def _zk_enabled(db) -> bool:
    """Whether zero-knowledge vaults may be created on this deployment.

    Plan ceiling first: if the deployment's plan does NOT include zero-knowledge, ZK is
    hard-off here regardless of any local toggle (a customer can't self-grant a feature
    their plan excludes). A plan that FORCES zero-knowledge necessarily enables it (and
    short-circuits before any DB read, so it holds even on error).

    When the plan GRANTS zero-knowledge, ZK is AUTO-ENABLED unless a local admin has
    explicitly turned it off. The local 'zero_knowledge_enabled' setting now acts only as an
    admin override: absent => on (the entitled tenant gets ZK without an undiscoverable
    manual click), explicitly False => off, explicitly True => on. get_settings() reports
    this EFFECTIVE value so a settings save can't silently clobber the auto-enable."""
    if not settings.plan_zero_knowledge:
        return False
    if settings.plan_force_zero_knowledge:
        return True
    try:
        from app.core.models import SystemSetting
        row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
        val = (row.value or {}) if (row and row.value) else {}
        override = val.get("zero_knowledge_enabled")
        return True if override is None else bool(override)
    except Exception:  # noqa: BLE001
        # Plan grants ZK; fail toward the entitlement (the confidentiality-safe direction),
        # matching the plan-force short-circuit above rather than silently disabling it.
        return True


def _user_must_use_zk(db, user) -> bool:
    """Org confidentiality policy (design §5): True when new vaults are forced to
    zero-knowledge AND this user is not in a whitelisted department.

    Force comes from EITHER the plan (an Enterprise plan mandates ZK — a floor the
    local toggle can't drop below) OR the local admin 'force_zero_knowledge' setting
    (which additionally requires the local 'zero_knowledge_enabled' toggle). The
    department whitelist (standard_vault_allowed_groups) exempts members of listed
    groups in both cases. On a read error, fails toward the plan-imposed floor:
    permissive (False) for non-forced plans, forced (True) for plan-forced ones —
    and _zk_enabled short-circuits ZK on for plan-forced deployments, so the user is
    never boxed into 'must use ZK but ZK is off'."""
    plan_force = settings.plan_force_zero_knowledge and settings.plan_zero_knowledge
    try:
        from app.core.models import SystemSetting, user_groups
        from sqlalchemy import select
        row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
        val = (row.value or {}) if (row and row.value) else {}
        setting_force = bool(val.get("force_zero_knowledge") and val.get("zero_knowledge_enabled"))
        if not (plan_force or setting_force):
            return False
        allowed = {str(g) for g in (val.get("standard_vault_allowed_groups") or [])}
        if not allowed:
            return True  # forced with no whitelist -> everyone must use ZK
        user_gids = {
            str(r[0]) for r in db.execute(
                select(user_groups.c.group_id).where(user_groups.c.user_id == user.id)
            ).fetchall()
        }
        return not (allowed & user_gids)
    except Exception:  # noqa: BLE001
        return bool(plan_force)


def _zk_vault_count(db) -> int:
    """Active zero-knowledge vaults in this deployment (one deployment = one customer
    org). Used to enforce the plan's per-deployment ZK-vault cap."""
    from app.core.models import Vault
    return db.query(Vault).filter(
        Vault.type == "zero_knowledge", Vault.is_active == True  # noqa: E712
    ).count()


def _enforce_deployment_storage_quota(db, additional_bytes: int) -> None:
    """Plan cap on TOTAL stored bytes across the deployment (settings.plan_max_storage_gb,
    GB; -1/0 => unlimited) — raises 413 if an upload would exceed it. Shares the check
    with the SFTP write path via vault_service.would_exceed_deployment_storage so a
    customer can't sidestep the per-vault size_limit by creating many vaults, on either
    transport. Permissive default (-1) leaves dev/un-gated deployments unrestricted."""
    from app.services.vault_service import would_exceed_deployment_storage
    exceeds, used, cap_bytes = would_exceed_deployment_storage(db, additional_bytes)
    if exceeds:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(f"Your plan's {cap_bytes // (1024 ** 3)} GB storage limit would be exceeded "
                    f"({used / (1024 ** 3):.2f} GB already used). Upgrade your plan or free up space."),
        )


def _enforce_user_cap(db) -> None:
    """Plan cap on the number of user accounts in this deployment (settings.plan_max_users).
    -1 (or None) = unlimited; 0 = block ALL new users (a 'freeze' an operator can set via
    the per-account override); N = up to N. Counts active users and rejects creation past
    the cap (matching the ZK-vault cap convention). The deployment's own admin counts
    toward it (so cap=1 = the owner only). Permissive default (-1) leaves dev/un-gated
    deployments unrestricted."""
    cap = settings.plan_max_users
    if cap is None or cap < 0:
        return  # unlimited (-1); cap==0 falls through and blocks every create (freeze)
    from app.core.models import User
    count = db.query(User).filter(User.is_active == True).count()  # noqa: E712
    if count >= cap:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=(f"Your plan allows up to {cap} user account(s) and you already have "
                    f"{count}. Upgrade your plan or deactivate a user."),
        )


def _enforce_zk_vault_cap(db) -> None:
    """Plan cap on the number of zero-knowledge vaults a deployment may hold
    (settings.plan_max_zk_vaults: -1 unlimited, 0 none, N capped). Rejects creation
    once the deployment is at the cap. Permissive default (-1) leaves dev/un-gated
    deployments unrestricted."""
    cap = settings.plan_max_zk_vaults
    if cap is None or cap < 0:
        return  # unlimited
    count = _zk_vault_count(db)
    if count >= cap:
        raise HTTPException(
            status_code=400,
            detail=(f"Your plan allows up to {cap} zero-knowledge vault(s) and you already "
                    f"have {count}. Upgrade your plan or delete an existing one."),
        )


def _resolve_vault_type_for_create(current_user: User, requested: Optional[str], db: Session) -> str:
    """Creation-time confidentiality-policy chokepoint (design sequencing item 2 + §5).

    Defaults to 'standard'. 'zero_knowledge' (client-side crypto; server stores
    only opaque ciphertext) is allowed only when the deployment opted in via
    'zero_knowledge_enabled' AND is under the plan's ZK-vault cap. When the org
    enforces 'force_zero_knowledge', a user who is not in a whitelisted department
    (standard_vault_allowed_groups) may not create 'standard' vaults.

    The operator-set, admin-irreversible allowed-vault-types allowlist
    (_allowed_vault_types) is the hard outer gate: a type the deployment's policy
    forbids is never creatable, whatever the local toggles say.
    """
    requested = (requested or "standard").strip().lower()
    if requested not in VAULT_TYPES:
        raise HTTPException(status_code=400, detail=f"Unknown vault type: {requested}")
    allowed = _allowed_vault_types()
    if requested not in allowed:
        raise HTTPException(
            status_code=400,
            detail=f"Vault type '{requested}' is not permitted on this deployment.",
        )
    if requested == "zero_knowledge":
        if not _zk_enabled(db):
            raise HTTPException(
                status_code=400,
                detail="Zero-knowledge vaults are not enabled on this deployment.",
            )
        _enforce_zk_vault_cap(db)
        return "zero_knowledge"
    # requested == 'standard'
    # Only force zero-knowledge when it is actually a permitted type — otherwise a
    # standard-only allowlist and a force-ZK policy would deadlock every create.
    if "zero_knowledge" in allowed and _user_must_use_zk(db, current_user):
        raise HTTPException(
            status_code=400,
            detail="This organization requires zero-knowledge vaults. Choose the Zero-knowledge type.",
        )
    return "standard"


@app.get("/account/storage")
async def account_storage(
    exclude_vault_id: Optional[uuid.UUID] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The current account's storage picture, so the UI can show how much a new/edited vault may
    declare. Bytes; a null bound means UNLIMITED on that axis. reserved = the SUM of the owner's
    declared vault size_limits; available = the largest size a vault may declare right now (pass
    exclude_vault_id when editing a vault, so its OWN current reservation doesn't count against it)."""
    budget = _quota_setting_bytes(db, "default_user_quota")
    ceiling = _quota_setting_bytes(db, "max_vault_size")
    is_full_admin = current_user.role == RoleEnum.ADMIN and not getattr(current_user, "_is_temp_session", False)
    return {
        "reserved_bytes": _account_reserved_bytes(db, current_user.id),
        "account_quota_bytes": (budget or None) if not is_full_admin else None,
        "per_vault_max_bytes": ceiling or None,
        "available_bytes": _max_allowed_vault_size_bytes(db, current_user, exclude_vault_id),
        "budget_exempt": is_full_admin,
    }


@app.post("/vaults", response_model=VaultResponse)
@require_endpoint_permission("VAULT_CREATE")
async def create_vault(
    vault_create: VaultCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Create a new vault.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)

    # Check permission
    permission_service.require_permission(current_user, PermissionEnum.VAULT_CREATE)

    # Confidentiality-policy hook (defaults to 'standard'; rejects unbuilt tiers).
    vault_type = _resolve_vault_type_for_create(current_user, vault_create.type, db)

    # A scoped temp credential may be restricted to a specific vault type (standard vs ZK).
    from app.core.temp_scope import require_create_vault_type
    require_create_vault_type(current_user, vault_type)

    # Per-vault size: default 1 GB. Reject a size that is out of range (a sub-nanogigabyte value
    # truncates to 0, which every upload guard reads as UNLIMITED; a huge value overflows the
    # BigInteger column and 500s) BEFORE the quota check, then enforce the ceiling / account budget.
    requested_size = int(vault_create.size_limit_gb * _GIB) if vault_create.size_limit_gb else _GIB
    if requested_size <= 0 or requested_size > _INT64_MAX:
        raise HTTPException(status_code=400,
                            detail=f"Vault size must be between 1 byte and {_INT64_MAX / _GIB:.0f} GB")
    _enforce_vault_size(db, current_user, requested_size)

    vault = vault_service.create_vault(
        name=vault_create.name,
        owner=current_user,
        description=vault_create.description,
        password=vault_create.password,
        expire_files_after_days=vault_create.expire_files_after_days,
        vault_type=vault_type,
        size_limit=requested_size,
    )

    # Zero-knowledge vaults: the DEK is generated AND wrapped IN THE BROWSER to the
    # owner's own public key; the owner's wrapped copy is supplied here. The server
    # stores only the opaque wrapped DEK + ephemeral public key and NEVER sees the
    # key — that is what makes it zero-knowledge. Reject (and roll back the vault) if
    # the owner has no keypair or the client didn't supply a wrapped DEK, since that
    # would leave a vault nobody can decrypt.
    if vault_type == 'zero_knowledge':
        from app.core.models import UserKeyPair, VaultMemberKey
        if not db.query(UserKeyPair).filter(UserKeyPair.user_id == current_user.id).first():
            db.delete(vault)
            db.commit()
            raise HTTPException(
                status_code=400,
                detail="Set up your encryption key before creating a zero-knowledge vault.",
            )
        hierarchical = (vault_create.key_wrapping_mode == 'hierarchical')
        if hierarchical:
            # Hierarchical: the DEK is wrapped to the TEAM public key (team_key map @ epoch 1),
            # and the owner gets the TEAM PRIVATE key wrapped to their identity key (a TEAMPRIV
            # row @ team epoch 1). The server stores only public keys + opaque wraps.
            missing = not (vault_create.team_public_key and vault_create.team_wrapped_dek
                           and vault_create.team_dek_ephemeral_public_key
                           and vault_create.wrapped_team_privkey
                           and vault_create.team_privkey_ephemeral_public_key)
            if missing:
                db.delete(vault)
                db.commit()
                raise HTTPException(
                    status_code=400,
                    detail="A hierarchical zero-knowledge vault requires the team public key, the "
                           "DEK wrapped to it, and the team private key wrapped to the owner.",
                )
            import json as _json
            vault.key_wrapping_mode = 'hierarchical'
            vault.team_public_key = vault_create.team_public_key
            vault.team_key_version = 1
            vault.team_key = _json.dumps({"1": {
                "wrapped_dek": vault_create.team_wrapped_dek,
                "ephemeral_public_key": vault_create.team_dek_ephemeral_public_key,
                "team_key_version": 1,
            }})
            db.add(VaultMemberKey(
                vault_id=vault.id,
                user_id=current_user.id,
                wrapped_dek=vault_create.wrapped_team_privkey,
                ephemeral_public_key=vault_create.team_privkey_ephemeral_public_key,
                wrapping_algorithm='ECDH-P384-AES-GCM-TEAMPRIV',
                key_version=1,  # team epoch 1
                granted_by=current_user.id,
                granted_at=datetime.now(timezone.utc),
            ))
            db.commit()
            db.refresh(vault)
        else:
            if not (vault_create.wrapped_dek and vault_create.ephemeral_public_key):
                db.delete(vault)
                db.commit()
                raise HTTPException(
                    status_code=400,
                    detail="A browser-wrapped vault key is required to create a zero-knowledge vault.",
                )
            db.add(VaultMemberKey(
                vault_id=vault.id,
                user_id=current_user.id,
                wrapped_dek=vault_create.wrapped_dek,
                ephemeral_public_key=vault_create.ephemeral_public_key,
                wrapping_algorithm='ECDH-P384-AES-KW',
                key_version=1,
                granted_by=current_user.id,
                granted_at=datetime.now(timezone.utc),
            ))
            vault.key_wrapping_mode = 'direct'
            db.commit()
            db.refresh(vault)

    audit_logger.log_vault_created(
        vault.id, vault.name, current_user, get_client_ip(request)
    )
    
    # Build response dict with has_password
    _fnr = _force_no_remember_vault_password(db)
    vault_dict = {
        'id': vault.id,
        'name': vault.name,
        'description': vault.description,
        'owner_id': vault.owner_id,
        'has_password': vault.password_hash is not None,
        'expire_files_after_days': vault.expire_files_after_days,
        'expire_files_unit': vault.expire_files_unit or 'days',
        'unlock_remember_minutes': (0 if _fnr else vault.unlock_remember_minutes),
        'size_limit': vault.size_limit,
        'total_size_bytes': vault.total_size_bytes,
        'file_count': vault.file_count,
        'created_at': vault.created_at,
        'updated_at': vault.updated_at,
        'last_accessed': vault.last_accessed,
        'is_active': vault.is_active,
        'type': vault.type,
        'my_permission': 'owner',  # creator owns it
        'is_favorite': False
    }
    return VaultResponse(**vault_dict)


@app.get("/vaults")
@require_endpoint_permission("VAULT_VIEW")
async def list_vaults(
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List vaults accessible to user.
    
    Performance: Supports ETag caching to reduce traffic.
    Returns 304 Not Modified if vault list unchanged since last request.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    
    vaults = vault_service.list_vaults(current_user)

    # Which of these vaults has the caller starred? (one query, not N)
    from app.core.models import vault_favorites
    from sqlalchemy import select as _select
    fav_ids = {
        r[0] for r in db.execute(
            _select(vault_favorites.c.vault_id).where(vault_favorites.c.user_id == current_user.id)
        ).fetchall()
    }

    from app.core.temp_scope import scope_ids as _scope_ids
    _fnr = _force_no_remember_vault_password(db)
    result = []
    for vault in vaults:
        perms = permission_service.get_vault_permissions(current_user, vault.id)
        # Suppress the whole-vault aggregates for a per-file/folder-scoped credential on this vault
        # (see get_vault) so it can't count/measure files outside its scope.
        _id_scoped = _scope_ids(current_user, vault.id) is not None
        vault_dict = {
            'id': vault.id,
            'name': vault.name,
            'description': vault.description,
            'owner_id': vault.owner_id,
            'has_password': vault.password_hash is not None,
            'expire_files_after_days': vault.expire_files_after_days,
            'expire_files_unit': vault.expire_files_unit or 'days',
            'unlock_remember_minutes': (0 if _fnr else vault.unlock_remember_minutes),
            'size_limit': vault.size_limit,
            'total_size_bytes': None if _id_scoped else vault.total_size_bytes,
            'file_count': None if _id_scoped else vault.file_count,
            'created_at': vault.created_at,
            'updated_at': vault.updated_at,
            'last_accessed': vault.last_accessed,
            'is_active': vault.is_active,
            'type': vault.type,
            'my_permission': _effective_vault_permission(vault, perms, current_user),
            'is_favorite': vault.id in fav_ids
        }
        result.append(vault_dict)
    
    # Use conditional response with ETag
    return handle_conditional_response(request, result)


@app.get("/vaults/{vault_id}", response_model=VaultResponse)
@require_endpoint_permission("VAULT_VIEW")
@require_vault_cap("vault.see_info")
async def get_vault(
    vault_id: uuid.UUID,
    request: Request,
    x_vault_password: Optional[str] = Header(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get vault details (metadata only - no password required).
    An optional X-Vault-Password HEADER soft-verifies the vault password (rate-limited). The password
    is taken from the header, never a URL query string (which would leak into access logs).
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)

    try:
        # require_password=False means we're just viewing metadata; a supplied X-Vault-Password is
        # soft-verified (and rate-limited) inside get_vault. allow_share=True: a recipient with an
        # active whole-vault share claim may open the vault (read-only). SFTP never passes this.
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password,
                                        require_password=False, allow_share=True)

        # Get owner username
        owner = db.query(User).filter(User.id == vault.owner_id).first()
        owner_username = owner.username if owner else None

        # A per-file/folder-scoped credential must not learn the whole-vault file count / size (it
        # would reveal how many files exist outside its scope). Suppress the denormalized aggregates.
        from app.core.temp_scope import scope_ids as _scope_ids
        _id_scoped = _scope_ids(current_user, vault_id) is not None
        _fnr = _force_no_remember_vault_password(db)

        # Effective permission for this caller. If they have no owner/member/group access but DID open
        # the vault, it was via an active share claim: reflect read-only in my_permission and audit the
        # open ONCE here (not on the polled file-list). base_perms is None only for a share-only caller.
        base_perms = permission_service.get_vault_permissions(current_user, vault.id)
        if base_perms is None:
            share_perms = permission_service.get_vault_permissions(current_user, vault.id, allow_share=True)
            if share_perms is not None:
                base_perms = share_perms
                try:
                    AuditLogger(db).log_action(
                        action="share_opened", status="success", user=current_user,
                        ip_address=get_client_ip(request), details={"vault_id": str(vault.id)})
                except Exception:
                    # A failed audit commit leaves the session in a pending-rollback state; roll it
                    # back so the same-request reads below (e.g. _is_vault_favorite) don't raise
                    # PendingRollbackError and turn an authorized open into a 500. Losing the audit
                    # row is acceptable; failing the open is not.
                    db.rollback()

        # Build response dict with has_password and owner_username
        vault_dict = {
            'id': vault.id,
            'name': vault.name,
            'description': vault.description,
            'owner_id': vault.owner_id,
            'owner_username': owner_username,
            'has_password': vault.password_hash is not None,
            'expire_files_after_days': vault.expire_files_after_days,
            'expire_files_unit': vault.expire_files_unit or 'days',
            'unlock_remember_minutes': (0 if _fnr else vault.unlock_remember_minutes),
            'size_limit': vault.size_limit,
            'total_size_bytes': None if _id_scoped else vault.total_size_bytes,
            'file_count': None if _id_scoped else vault.file_count,
            'created_at': vault.created_at,
            'updated_at': vault.updated_at,
            'last_accessed': vault.last_accessed,
            'is_active': vault.is_active,
            'type': vault.type,
            'my_permission': _effective_vault_permission(vault, base_perms, current_user),
            'is_favorite': _is_vault_favorite(db, current_user.id, vault.id)
        }
        return VaultResponse(**vault_dict)

    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )


def _is_vault_favorite(db: Session, user_id: uuid.UUID, vault_id: uuid.UUID) -> bool:
    from app.core.models import vault_favorites
    from sqlalchemy import select as _select
    return db.execute(
        _select(vault_favorites.c.vault_id).where(
            vault_favorites.c.user_id == user_id,
            vault_favorites.c.vault_id == vault_id,
        )
    ).first() is not None


@app.put("/vaults/{vault_id}/favorite")
@require_endpoint_permission("VAULT_VIEW")
async def set_vault_favorite(
    vault_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Star a vault for the current user (idempotent personal preference)."""
    from app.core.models import vault_favorites, Vault, VaultPermissionEnum
    from sqlalchemy import insert as _insert
    # require READ access before favoriting. Without this, favoriting is a cross-tenant
    # existence oracle (200-vs-404 on any vault_id) plus an unauthorized write on a vault the
    # caller cannot open. A uniform 404 for both "absent" and "exists-but-forbidden" keeps the
    # oracle closed. (This checks the underlying user's real READ access, not temp-cred scope —
    # a favorite is a personal bookmark keyed to the real user; temp-scope favorite discipline
    # is out of scope here.)
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault or not PermissionService(db).can_access_vault(current_user, vault_id, VaultPermissionEnum.READ):
        raise HTTPException(status_code=404, detail="Vault not found")
    if not _is_vault_favorite(db, current_user.id, vault_id):
        try:
            db.execute(_insert(vault_favorites).values(user_id=current_user.id, vault_id=vault_id))
            db.commit()
        except Exception:
            db.rollback()  # race: another request inserted it first — fine
    return {"vault_id": str(vault_id), "is_favorite": True}


@app.delete("/vaults/{vault_id}/favorite")
@require_endpoint_permission("VAULT_VIEW")
async def unset_vault_favorite(
    vault_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Un-star a vault for the current user."""
    from app.core.models import vault_favorites
    from sqlalchemy import delete as _delete
    db.execute(
        _delete(vault_favorites).where(
            vault_favorites.c.user_id == current_user.id,
            vault_favorites.c.vault_id == vault_id,
        )
    )
    db.commit()
    return {"vault_id": str(vault_id), "is_favorite": False}


@app.post("/vaults/{vault_id}/delete")
@require_endpoint_permission("VAULT_DELETE")
@require_vault_cap("vault.delete")
async def delete_vault(
    vault_id: uuid.UUID,
    request: Request,
    vault_password: Optional[str] = None,
    x_vault_password: Optional[str] = Header(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Delete a vault and all its contents.
    Requires vault password if vault is password-protected.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)

    # Accept the vault password via the X-Vault-Password header (the convention every other
    # password-gated vault route uses) OR the legacy query param, so a password never has to
    # ride the URL query string (where it would land in access logs).
    effective_vault_password = x_vault_password or vault_password

    # Get vault first to check permissions and validate password
    try:
        # require_password=True because we're deleting (destructive operation)
        vault = vault_service.get_vault(vault_id, current_user, effective_vault_password, require_password=True)
        vault_name = str(vault.name)  # Convert to string

        # SECURITY: deletion is owner-or-admin, mirroring update_vault_info /
        # change_vault_password. get_vault() above only checks READ, so without this guard a
        # read-only / group-access member could destroy the whole vault. NOTE: get_vault gates
        # READ first with no admin special-case, so the admin arm here only covers an admin who
        # is a MEMBER of the vault; a tenant-wide "admin deletes any vault" would need a
        # pre-get_vault admin bypass (a separate product decision, out of scope). Fails closed.
        if vault.owner_id != current_user.id and current_user.role != RoleEnum.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or an admin can delete this vault"
            )

        # Delete via the service so the on-disk encrypted blobs are removed too — the
        # route previously did a bare db.delete() that left {storage}/{vault_id}/ orphaned on
        # disk forever (disk-exhaustion DoS + broken secure-delete). The service re-checks
        # owner-or-admin and cascade-deletes the DB rows.
        vault_service.delete_vault(vault_id, current_user)

        audit_logger.log_vault_deleted(
            vault_id, vault_name, current_user, get_client_ip(request)
        )

        return {"message": f"Vault {vault_name} deleted successfully"}

    except HTTPException:
        raise
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except VaultNotFoundError as e:
        # A missing/already-deleted vault should be a clean 404, not a generic 500 (the
        # VaultNotFoundError subclasses FileServiceError, not ResourceNotFoundError).
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete vault: {str(e)}"
        )


@app.patch("/vaults/{vault_id}")
@require_endpoint_permission("VAULT_SETTINGS")
@require_vault_cap("vault.change_info")
async def update_vault_info(
    vault_id: uuid.UUID,
    vault_update: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update vault basic information (name, description).
    Only owner or admin can update vault info.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    try:
        # Get vault (no password required for metadata update)
        vault = vault_service.get_vault(vault_id, current_user, require_password=False)
        
        # SECURITY: Only vault owner or admin can edit info
        if vault.owner_id != current_user.id and current_user.role != RoleEnum.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only vault owner can edit vault information"
            )
        
        # Update fields if provided
        if 'name' in vault_update:
            new_name = vault_update['name']
            if not new_name or len(new_name.strip()) == 0:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Vault name cannot be empty"
                )
            if len(new_name) > 255:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Vault name too long (max 255 characters)"
                )
            vault.name = new_name.strip()
        
        if 'description' in vault_update:
            description = vault_update['description']
            if description and len(description) > 1000:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="Vault description too long (max 1000 characters)"
                )
            vault.description = description.strip() if description else None
        
        vault.updated_at = datetime.now(timezone.utc)
        db.commit()
        db.refresh(vault)
        
        # Log update in audit
        audit_logger.log_action(
            action="vault_info_updated",
            status="success",
            user=current_user,
            resource_type="vault",
            resource_id=str(vault_id),
            ip_address=get_client_ip(request),
            details={"updated_fields": list(vault_update.keys())}
        )
        
        # Return updated vault
        return {
            "id": str(vault.id),
            "name": vault.name,
            "description": vault.description,
            "size_limit": vault.size_limit,
            "current_size": vault.total_size_bytes,
            "has_password": vault.password_hash is not None,
            "owner_id": str(vault.owner_id),
            "created_at": vault.created_at.isoformat() if vault.created_at else None,
            "updated_at": vault.updated_at.isoformat() if vault.updated_at else None
        }
        
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update vault information: {str(e)}"
        )


@app.put("/vaults/{vault_id}/password")
@require_endpoint_permission("VAULT_SETTINGS")
@require_vault_cap("vault.change_password")
async def change_vault_password(
    vault_id: uuid.UUID,
    password_update: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Change vault password.
    Requires current password if vault is password-protected.
    Set new_password to null to remove password.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    current_password = password_update.get('current_password')
    new_password = password_update.get('new_password')
    
    try:
        # Get vault and verify current password if it has one
        vault = vault_service.get_vault(vault_id, current_user, current_password, require_password=True)
        
        # SECURITY: Only vault owner or admin can change password
        if vault.owner_id != current_user.id and current_user.role != RoleEnum.ADMIN:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only vault owner can change password"
            )
        
        # Update password
        if new_password:
            from app.core.security import hash_password
            vault.password_hash = hash_password(new_password)
        else:
            vault.password_hash = None
        
        vault.updated_at = datetime.now(timezone.utc)
        db.commit()
        
        action = 'set' if new_password else 'removed'
        
        # Log password change in audit
        audit_logger.log_action(
            action="vault_password_changed",
            status="success",
            user=current_user,
            resource_type="vault",
            resource_id=str(vault_id),
            ip_address=get_client_ip(request),
            details={"action": action}
        )
        
        return {"message": f"Vault password {action} successfully"}
        
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to change password: {str(e)}"
        )


@app.patch("/vaults/{vault_id}/settings")
@require_endpoint_permission("VAULT_SETTINGS")
@require_vault_cap("vault.change_expiry")
async def update_vault_settings(
    vault_id: uuid.UUID,
    settings_update: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Update vault settings (size_limit, expire_files_after_days, etc.).
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    try:
        # Get vault
        vault = vault_service.get_vault(vault_id, current_user, None, require_password=False)
        
        # Check if user is the owner (only owner can modify settings)
        if vault.owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only vault owner can modify settings"
            )
        
        # Update settings
        updated_fields = []
        
        if 'size_limit' in settings_update:
            size_limit = settings_update['size_limit']
            # A null would clear the cap to "unlimited", bypassing the per-vault ceiling AND the
            # account budget — reject it (the field is a bounded quota now, not a clearable option).
            if size_limit is None:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="size_limit is required (a positive number of bytes)")
            try:
                size_limit = int(size_limit)
            except (TypeError, ValueError):
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail="size_limit must be a number of bytes")
            if size_limit <= 0 or size_limit > _INT64_MAX:
                raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                    detail=f"size_limit must be between 1 byte and {_INT64_MAX / _GIB:.0f} GB")
            # Floor: can't shrink below what's already stored.
            current_size = vault.total_size_bytes or 0
            if size_limit < current_size:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail=f"Size limit ({size_limit} bytes) cannot be less than current usage ({current_size} bytes)"
                )
            # Ceiling: can't exceed the per-vault ceiling or the owner's remaining account budget
            # (excluding THIS vault's own current reservation). The owner is enforced above.
            _enforce_vault_size(db, current_user, size_limit, exclude_vault_id=vault_id)
            vault.size_limit = size_limit
            updated_fields.append('size_limit')
        
        if 'expire_files_after_days' in settings_update:
            vault.expire_files_after_days = settings_update['expire_files_after_days']
            updated_fields.append('expire_files_after_days')
        
        if 'expire_files_unit' in settings_update:
            unit = settings_update['expire_files_unit']
            if unit not in ['minutes', 'hours', 'days']:
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="expire_files_unit must be 'minutes', 'hours', or 'days'"
                )
            vault.expire_files_unit = unit
            updated_fields.append('expire_files_unit')

        if 'unlock_remember_minutes' in settings_update:
            urm = settings_update['unlock_remember_minutes']
            if urm is not None:
                try:
                    urm = int(urm)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="unlock_remember_minutes must be a number")
                urm = max(0, min(urm, 1440))  # 0 = always ask, cap at 24h
                if urm and _force_no_remember_vault_password(db):
                    urm = 0  # org policy forbids browser-remembering the vault password
            vault.unlock_remember_minutes = urm
            updated_fields.append('unlock_remember_minutes')

        vault.updated_at = datetime.now(timezone.utc)
        db.commit()

        # Echo the stored unlock window (already clamped to 0 when the org floor is set) so the
        # client bases its remember cache on the authoritative value, not the submitted one.
        return {"message": "Vault settings updated successfully",
                "unlock_remember_minutes": vault.unlock_remember_minutes}
        
    except ResourceNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to update settings: {str(e)}"
        )


# Vault Permission Endpoints
#
# Delegated administration ("Manager" role): the vault owner and global admins
# can always manage membership/access. In addition, a member granted
# manage_permission is a Manager who may add/remove members and grant/revoke
# access. To prevent privilege escalation, only the owner or a global admin may
# *assign* the 'manage' level or modify/revoke an existing Manager — a Manager
# cannot create or unseat peer Managers. Destructive/ownership actions (delete
# vault, rotate key, change password) remain owner-only at their own endpoints.

def _is_vault_owner_or_admin(vault, current_user) -> bool:
    return vault.owner_id == current_user.id or current_user.role == RoleEnum.ADMIN


def _vault_member_manages(db, vault_id, user_id) -> bool:
    """True if the given user is a Manager of the vault (member row with
    manage_permission set)."""
    from app.core.models import vault_members
    from sqlalchemy import select, and_
    row = db.execute(
        select(vault_members.c.manage_permission).where(and_(
            vault_members.c.vault_id == vault_id,
            vault_members.c.user_id == user_id,
        ))
    ).fetchone()
    return bool(row and row[0])


def _can_manage_vault(db, vault, current_user) -> bool:
    """True if current_user may administer this vault's membership/access:
    a global admin, the owner, or a Manager (member with manage_permission)."""
    if _is_vault_owner_or_admin(vault, current_user):
        return True
    return _vault_member_manages(db, vault.id, current_user.id)


@app.get("/vaults/{vault_id}/permissions")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.see_permissions")
async def list_vault_permissions(
    request: Request,
    vault_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    List all users who have access to this vault.
    Only vault owner can view permissions.
    
    Performance: Supports ETag caching to reduce traffic.
    """
    try:
        # Get vault directly from database
        from app.core.models import Vault
        vault = db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vault not found"
            )
        
        # Owner, global admin, or a Manager (member with manage_permission) can view.
        if not _can_manage_vault(db, vault, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or a manager can view permissions"
            )

        # Query vault_members table
        from app.core.models import vault_members
        from sqlalchemy import select

        stmt = select(
            vault_members.c.user_id,
            vault_members.c.read_permission,
            vault_members.c.write_permission,
            vault_members.c.delete_permission,
            vault_members.c.manage_permission,
            vault_members.c.added_at,
            User.username,
            User.email
        ).join(
            User, User.id == vault_members.c.user_id
        ).where(
            vault_members.c.vault_id == vault_id
        )

        result = db.execute(stmt).fetchall()

        permissions = []
        for row in result:
            permissions.append({
                "user_id": row.user_id,
                "username": row.username,
                "email": row.email,
                "read_permission": row.read_permission,
                "write_permission": row.write_permission,
                "delete_permission": row.delete_permission,
                "manage_permission": row.manage_permission,
                "added_at": row.added_at
            })
        
        # Use conditional response with ETag
        return handle_conditional_response(request, permissions)
        
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list permissions: {str(e)}"
        )


@app.post("/vaults/{vault_id}/permissions")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def grant_vault_permission(
    vault_id: uuid.UUID,
    permission: VaultPermissionAdd,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Grant vault access to a user.
    Only vault owner can grant permissions.
    """
    try:
        # Get vault directly from database
        from app.core.models import Vault
        vault = db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vault not found"
            )
        
        # Owner, global admin, or a Manager (member with manage_permission) can grant.
        if not _can_manage_vault(db, vault, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or a manager can grant permissions"
            )

        # NOTE: a per-user AUTHZ grant IS legitimate on a zero-knowledge vault — it records the
        # vault_members row (membership + read/write/delete/manage), while the wrapped DEK is
        # distributed separately through POST /ecc/vaults/{id}/members. A Manager, in particular,
        # may hold authz WITHOUT a decrypt key (they manage sharing, not necessarily read files),
        # and the normal member-share flow grants the key then this authz row. So — unlike the
        # GROUP path (grant_vault_group_access, which correctly 400s ZK because a group has no
        # keys) — the per-user grant is NOT blocked here. (A prior over-broad block was reverted:
        # it broke the ZK sharing flow; the "keyless membership" it targeted is the intended
        # authz-vs-key separation, and metadata is ZK-encrypted / deletion is a normal delete
        # grant, so there is no plaintext exposure to prevent.)

        # Check if user exists
        user = db.query(User).filter(User.id == permission.user_id).first()
        if not user:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User not found"
            )

        # Prevent owner from adding themselves
        if user.id == vault.owner_id:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Cannot grant permissions to vault owner"
            )

        # Privilege-escalation guard: assigning the Manager role, or modifying a
        # user who is already a Manager, is reserved for the owner / global admin.
        # A Manager cannot mint or alter peer Managers.
        is_owner_admin = _is_vault_owner_or_admin(vault, current_user)
        if permission.level == 'manage' and not is_owner_admin:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or an admin can assign the manager role"
            )
        if not is_owner_admin and _vault_member_manages(db, vault_id, permission.user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or an admin can modify a manager"
            )

        from app.core.models import vault_members
        from sqlalchemy.dialects.postgresql import insert as _pg_insert

        # Set permissions based on level. 'manage' implies full read/write/delete.
        manage_perm = permission.level == 'manage'
        read_perm = permission.level in ['read', 'write', 'delete', 'manage']
        write_perm = permission.level in ['write', 'delete', 'manage']
        delete_perm = permission.level in ['delete', 'manage']

        # Atomic upsert (race-safe): a concurrent double-grant for the same (vault, user) can no longer
        # create divergent duplicate rows — the uq_vault_members_vault_user constraint funnels both to
        # the same row. Replaces the previous non-atomic check-then-insert.
        _ins = _pg_insert(vault_members).values(
            vault_id=vault_id,
            user_id=permission.user_id,
            read_permission=read_perm,
            write_permission=write_perm,
            delete_permission=delete_perm,
            manage_permission=manage_perm,
            added_at=datetime.now(timezone.utc),
            added_by=current_user.id,
        )
        db.execute(_ins.on_conflict_do_update(
            index_elements=['vault_id', 'user_id'],
            set_={
                'read_permission': read_perm,
                'write_permission': write_perm,
                'delete_permission': delete_perm,
                'manage_permission': manage_perm,
            },
        ))
        db.commit()
        
        return {
            "message": f"Permission '{permission.level}' granted to user {user.username}",
            "user_id": str(permission.user_id),
            "level": permission.level
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to grant permission: {str(e)}"
        )


@app.delete("/vaults/{vault_id}/permissions/{user_id}")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def revoke_vault_permission(
    vault_id: uuid.UUID,
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Revoke vault access from a user.
    Only vault owner can revoke permissions.
    """
    try:
        # Get vault directly from database
        from app.core.models import Vault
        vault = db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vault not found"
            )
        
        # Owner, global admin, or a Manager (member with manage_permission) can revoke.
        if not _can_manage_vault(db, vault, current_user):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or a manager can revoke permissions"
            )

        # A Manager cannot unseat a peer Manager — that stays owner/admin-only.
        if not _is_vault_owner_or_admin(vault, current_user) and _vault_member_manages(db, vault_id, user_id):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only the vault owner or an admin can revoke a manager"
            )

        # Delete permission entry
        from app.core.models import vault_members
        from sqlalchemy import delete as sql_delete

        stmt = sql_delete(vault_members).where(
            vault_members.c.vault_id == vault_id,
            vault_members.c.user_id == user_id
        )
        result = db.execute(stmt)

        # Zero-knowledge: deactivate the user's wrapped DEK(s) in the SAME transaction as
        # the authz removal, so a usable crypto key is never left behind after access is
        # revoked. The forward-secrecy guarantee (a NEW DEK epoch the removed user never
        # gets) is the rekey flow's job — the web UI calls /ecc/.../rekey before this DELETE,
        # by which point these rows are already inactive (this becomes a no-op). For any
        # non-rekey caller (admin tooling, a direct API DELETE) this closes the window where
        # the removed user could still fetch their current-epoch DEK until the reconciler
        # swept it. Keeps the authz and crypto planes consistent on every revoke path.
        if getattr(vault, 'type', 'standard') == 'zero_knowledge':
            from app.core.models import VaultMemberKey
            now = datetime.now(timezone.utc)
            for mk in db.query(VaultMemberKey).filter(
                VaultMemberKey.vault_id == vault_id,
                VaultMemberKey.user_id == user_id,
                VaultMemberKey.is_active == True,  # noqa: E712
            ).all():
                mk.is_active = False
                mk.revoked_at = now
                mk.revoked_by = current_user.id

        db.commit()

        if result.rowcount == 0:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="User does not have access to this vault"
            )

        return {"message": "Permission revoked successfully"}
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to revoke permission: {str(e)}"
        )


# ----------------------------------------------------------------------------
# Vault group access (department whitelist). A vault is reachable by its owner,
# its direct members, AND members of any group granted access here.
# ----------------------------------------------------------------------------
def _require_vault_manager(vault, current_user, db):
    """Group-access management is open to the owner, global admins, and Managers
    (members with manage_permission)."""
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can manage access")


@app.get("/vaults/{vault_id}/group-access")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.see_permissions")
async def list_vault_group_access(
    vault_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """List departments (groups) granted access to a vault (owner/manager/admin)."""
    from app.core.models import Vault, Group, vault_group_access
    from sqlalchemy import select
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    # Match list_vault_permissions: only those who can administer the vault may
    # see who it's shared with (owner, global admin, or a Manager).
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(status_code=403, detail="Only the vault owner or a manager can view access")
    rows = db.execute(
        select(vault_group_access.c.group_id, vault_group_access.c.permission, Group.name, Group.color)
        .join(Group, Group.id == vault_group_access.c.group_id)
        .where(vault_group_access.c.vault_id == vault_id)
        .order_by(Group.name)
    ).all()
    return [{"group_id": str(r[0]), "permission": r[1], "name": r[2], "color": r[3]} for r in rows]


@app.post("/vaults/{vault_id}/group-access")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def grant_vault_group_access(
    vault_id: uuid.UUID,
    payload: VaultGroupAccessAdd,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Grant a department access to a vault (owner or admin)."""
    from app.core.models import Vault, Group, vault_group_access
    from sqlalchemy import select, insert, update
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    _require_vault_manager(vault, current_user, db)
    # Zero-knowledge vaults can't be shared to a department: a group has no key,
    # so members would gain a permission row but no wrapped DEK — access they
    # can't use. ZK sharing must be explicit per-user (the DEK is wrapped to each
    # recipient's key at grant time). Full group support would need a per-group
    # team key (backlog: VaultTeamKey).
    if _is_zk_vault(vault):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Zero-knowledge vaults can't be shared with a department. "
                   "Share with individual users instead so their key is provisioned.",
        )
    if not db.query(Group).filter(Group.id == payload.group_id).first():
        raise HTTPException(status_code=404, detail="Group not found")
    perm = 'write' if payload.permission == 'write' else 'read'
    existing = db.execute(
        select(vault_group_access).where(
            vault_group_access.c.vault_id == vault_id,
            vault_group_access.c.group_id == payload.group_id,
        )
    ).fetchone()
    if existing:
        db.execute(
            update(vault_group_access).where(
                vault_group_access.c.vault_id == vault_id,
                vault_group_access.c.group_id == payload.group_id,
            ).values(permission=perm)
        )
    else:
        db.execute(
            insert(vault_group_access).values(
                vault_id=vault_id, group_id=payload.group_id, permission=perm,
                added_at=datetime.now(timezone.utc), added_by=current_user.id,
            )
        )
    db.commit()
    return {"message": "Group access granted"}


@app.delete("/vaults/{vault_id}/group-access/{group_id}")
@require_endpoint_permission("VAULT_PERMISSIONS")
@require_vault_cap("vault.change_permissions")
async def revoke_vault_group_access(
    vault_id: uuid.UUID,
    group_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Revoke a department's access to a vault (owner or admin)."""
    from app.core.models import Vault, vault_group_access
    from sqlalchemy import delete as sql_delete
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if not vault:
        raise HTTPException(status_code=404, detail="Vault not found")
    _require_vault_manager(vault, current_user, db)
    db.execute(
        sql_delete(vault_group_access).where(
            vault_group_access.c.vault_id == vault_id,
            vault_group_access.c.group_id == group_id,
        )
    )
    db.commit()
    return {"message": "Group access revoked"}


# Vault Key Rotation Endpoints

@app.post("/vaults/{vault_id}/rotate-key")
@require_endpoint_permission("VAULT_SETTINGS")
@require_vault_cap("vault.rotate_key")
async def rotate_vault_encryption_key(
    vault_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Rotate a vault's encryption key to a new version.
    
    This operation:
    1. Archives the current key to VaultKeyHistory
    2. Generates a new random 32-byte encryption key
    3. Encrypts it with the master key
    4. Increments the vault's key_version
    
    After rotation:
    - New file uploads use the new key version
    - Old files remain readable using historical keys
    - No re-encryption of existing files is required
    
    Only vault owner can rotate keys.
    """
    try:
        from app.core.models import Vault
        from app.core.vault_key_utils import rotate_vault_key
        from app.core.config import settings
        
        # Get vault
        vault = db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vault not found"
            )
        
        # Only owner can rotate keys
        if vault.owner_id != current_user.id:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only vault owner can rotate encryption keys"
            )

        # server-side key rotation applies only to STANDARD vaults. A zero-knowledge
        # vault's content key is client-side (the server never holds it), so rotating the
        # server key here would touch an unused key and falsely report success — reject it.
        if getattr(vault, "type", "standard") == "zero_knowledge":
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Key rotation does not apply to zero-knowledge vaults; their keys are managed client-side (use the zero-knowledge rekey endpoint).",
            )

        # A password-protected Standard vault wraps its DEK under a password-derived KEK + salt.
        # rotate_vault_key can only re-wrap under the MASTER key (it has no password parameter), which
        # would write method='master_key' / key_salt=NULL while leaving password_hash set — an internally
        # inconsistent row. Re-wrap-with-password isn't supported here, so reject rather than corrupt the
        # row. (File content is keyed off the deployment secret, not this wrapped DEK, so no access change.)
        if getattr(vault, "password_hash", None):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Key rotation is not supported for password-protected vaults (the password-wrapped key cannot be re-wrapped here).",
            )

        # Perform key rotation
        master_key = settings.encryption_key.encode()
        old_version = vault.key_version
        new_version = rotate_vault_key(vault, master_key, db)
        
        return {
            "message": "Encryption key rotated successfully",
            "vault_id": str(vault_id),
            "old_key_version": old_version,
            "new_key_version": new_version,
            "note": "New file uploads will use the new key. Old files remain readable with historical keys."
        }
        
    except HTTPException:
        raise
    except Exception as e:
        db.rollback()
        print(f"ERROR: Key rotation failed for vault {vault_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Key rotation failed: {str(e)}"
        )


@app.get("/vaults/{vault_id}/key-history")
@require_endpoint_permission("VAULT_VIEW")
@require_vault_cap("vault.see_info")
async def get_vault_key_history(
    vault_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get the key rotation history for a vault.
    
    Returns a list of all key versions with their lifecycle information,
    useful for auditing and compliance.
    
    Only vault owner and members can view key history.
    """
    try:
        from app.core.models import Vault
        from app.core.vault_key_utils import get_vault_key_history
        
        # Get vault
        vault = db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vault not found"
            )
        
        # Check if user has access (owner or member)
        is_owner = vault.owner_id == current_user.id
        is_member = current_user in vault.members
        
        if not (is_owner or is_member):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="You don't have access to this vault"
            )
        
        # Get key history
        history = get_vault_key_history(vault_id, db)
        
        return {
            "vault_id": str(vault_id),
            "current_key_version": vault.key_version,
            "key_created_at": vault.key_created_at.isoformat() if vault.key_created_at else None,
            "history": [
                {
                    "key_version": entry["key_version"],
                    "created_at": entry["created_at"].isoformat(),
                    "retired_at": entry["retired_at"].isoformat() if entry["retired_at"] else None,
                    "active_duration_days": entry["active_duration_days"]
                }
                for entry in history
            ],
            "total_rotations": len(history)
        }
        
    except HTTPException:
        raise
    except Exception as e:
        print(f"ERROR: Failed to get key history for vault {vault_id}: {str(e)}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to retrieve key history: {str(e)}"
        )


# File Operation Endpoints

@app.get("/vaults/{vault_id}/files")
@require_endpoint_permission("FILE_VIEW")
@require_vault_cap("vault.see_files")
async def list_vault_files(
    request: Request,
    vault_id: uuid.UUID,
    folder_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """
    List files and folders in a vault or folder.
    Requires vault password if vault is password-protected (via X-Vault-Password header).
    
    Performance: CRITICAL OPTIMIZATION - Supports ETag caching.
    This endpoint is polled every 5 seconds, generating significant traffic.
    With ETag support, returns 304 Not Modified when file list unchanged,
    reducing bandwidth by 80-90% during idle periods.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    
    try:
        # Verify vault access and password (require_password=True for file access).
        # allow_share=True: a recipient with an active whole-vault share claim may list
        # the vault's contents (read-only). SFTP listing never passes this flag.
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password,
                                        require_password=True, allow_share=True)

        # Parse folder_id if provided
        folder_uuid = uuid.UUID(folder_id) if folder_id else None
        
        # Query folders in this location
        folder_query = db.query(Folder).filter(Folder.vault_id == vault_id)
        if folder_uuid:
            folder_query = folder_query.filter(Folder.parent_folder_id == folder_uuid)
        else:
            folder_query = folder_query.filter(Folder.parent_folder_id.is_(None))
        
        folders = folder_query.all()
        
        # Query files in this location
        file_query = db.query(File).filter(File.vault_id == vault_id)
        if folder_uuid:
            file_query = file_query.filter(File.folder_id == folder_uuid)
        else:
            file_query = file_query.filter(File.folder_id.is_(None))
        
        files = file_query.all()

        # A path-scoped temp credential sees only its in-scope files/folders (+ the ancestor folders
        # needed to navigate to them). This is the anti-enumeration gate (out-of-scope names/sizes
        # are never emitted); the @require_vault_cap("vault.see_files") above still gates listing at all.
        folders, files = filter_listing_for_scope(db, current_user, vault_id, folder_uuid, folders, files)

        # Build response
        items = []
        # Zero-knowledge vaults: names/MIME are encrypted client-side under the vault DEK,
        # so the server returns the opaque enc_* blobs + the name's DEK epoch for the
        # BROWSER to decrypt (the server holds no key). 'name'/'mime_type' are NULL for
        # sealed ZK rows (plaintext only for not-yet-migrated legacy rows). Standard vaults
        # are unchanged: 'name' is the server-decrypted plaintext, no enc_* fields sent.
        is_zk = _is_zk_vault(vault)
        # Read guard: the server must NEVER surface plaintext zero-knowledge metadata.
        # A SEALED row decrypts in the browser from enc_name (its plaintext name is already
        # NULL); a legacy/UNSEALED row (enc_name NULL but a plaintext name left over from
        # before client-side sealing was enforced on the write paths) gets masked with a
        # neutral placeholder so cleartext the ZK contract says we don't hold is never served.
        from app.core.security import is_zk_sealed_name as _zk_sealed
        _ZK_UNSEALED = "[encrypted - re-seal required]"

        # Add folders
        for folder in folders:
            entry = {
                'id': str(folder.id),
                'name': folder.name,
                'type': 'folder',
                'size': 0,
                'modified': folder.updated_at.isoformat(),
                'has_password': folder.password_hash is not None
            }
            if is_zk:
                entry['enc_name'] = folder.enc_name
                entry['name_key_version'] = folder.name_key_version or 1
                # Sealed -> browser decrypts from enc_name (name already NULL); unsealed
                # legacy -> mask the leftover plaintext instead of serving it.
                entry['name'] = None if _zk_sealed(folder.enc_name) else _ZK_UNSEALED
            items.append(entry)

        # Add files
        for file in files:
            meta = file.encryption_metadata if isinstance(file.encryption_metadata, dict) else None
            entry = {
                'id': str(file.id),
                'name': file.original_name,
                'type': 'file',
                'size': file.size_bytes,
                'mime_type': file.mime_type,
                'modified': file.updated_at.isoformat(),
                'has_password': file.password_hash is not None,
                # Zero-knowledge DEK epoch this file was encrypted under (forward-only
                # rotation). Absent/None => epoch 1; the browser uses it to fetch the
                # matching wrapped DEK on download AND to decrypt the name. Null for Standard.
                'key_version': (meta or {}).get('key_version') if meta else None,
            }
            if is_zk:
                entry['enc_name'] = file.enc_name
                entry['enc_mime'] = file.enc_mime
                # Sealed -> browser decrypts from enc_name/enc_mime; unsealed legacy ->
                # mask the leftover plaintext name + never serve a plaintext ZK mime.
                entry['name'] = None if _zk_sealed(file.enc_name) else _ZK_UNSEALED
                entry['mime_type'] = None
            items.append(entry)
        
        response_data = {'items': items}
        
        # Use conditional response with ETag - critical for 5s polling optimization
        response_hash = compute_response_hash(response_data)
        if check_if_none_match(request, response_hash):
            return create_not_modified_response()
        
        return create_cached_response(response_data, response_hash)
        
    except RateLimitExceededError as e:
        raise HTTPException(
            status_code=status.HTTP_429_TOO_MANY_REQUESTS,
            detail=str(e)
        )
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to list files: {str(e)}"
        )


def _has_vault_cap(user, vault_id, cap: str) -> bool:
    """Non-raising per-vault temp-credential capability check (True for normal
    users / legacy creds). Mirrors temp_scope.require_cap."""
    from app.core.temp_scope import is_scoped, effective_vault_caps
    if not is_scoped(user):
        return True
    scope = getattr(user, "_temp_scope", None) or {}
    return cap in (set(effective_vault_caps(user, vault_id)) | set(scope.get("caps", [])))


def _principal_can_replace_file(db, user, vault_id) -> bool:
    """True iff `user` may REPLACE (overwrite) an existing file in this vault. Replacing
    deletes the prior same-name row + its blob, so it requires the SAME authority as a
    delete: the file.delete temp-cred capability AND real vault DELETE permission (RBAC).

    _has_vault_cap alone is NOT sufficient — it returns True for every non-scoped user (it
    only models the temp-cred scope layer; RBAC is enforced separately by the service's
    require_vault_permission). The dedicated delete path (vault_service.delete_file) checks
    DELETE; the same-name-replace path must too, or a write-but-no-delete member (or any
    group member — group access never grants delete) could destroy another user's file via
    a same-name upload."""
    if not _has_vault_cap(user, vault_id, "file.delete"):
        return False
    return PermissionService(db).can_access_vault(user, vault_id, VaultPermissionEnum.DELETE)


def _file_name_match(db, vault, vault_id, filename, name_bi):
    """Build the SQLAlchemy same-name filter for a File in a vault. Zero-knowledge vaults
    match on the CLIENT-supplied blind index (the server has no plaintext to compare);
    Standard/legacy vaults match on the plaintext name (via the blind index or column)."""
    if name_bi is not None:
        return File.name_bi == name_bi
    return _name_match_filter(File, vault, filename)


def _reject_unreplaceable_upload(db, vault_id, folder_id, filename, user, name_bi=None):
    """Same-name upload policy = REPLACE. Pre-check before the bytes flow: if a
    file with this name already exists in the folder, the uploader must be able to
    delete it. A principal lacking file.delete (a scoped upload-only temp cred) is
    rejected (409) rather than silently creating a hidden duplicate. No-op when no
    clash or when the principal can replace. Matches the SFTP _open_write guard.

    Zero-knowledge vaults pass name_bi (the server has no plaintext name); the match then
    runs on the client blind index without the server ever seeing the name."""
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    clash = db.query(File).filter(
        File.vault_id == vault_id,
        File.folder_id == folder_id,
        _file_name_match(db, vault, vault_id, filename, name_bi),
    ).first()
    if clash is not None and not _principal_can_replace_file(db, user, vault_id):
        shown = f"'{filename}' " if filename else ""
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A file named {shown}already exists and you lack permission to replace it.",
        )


def _content_disposition(file_name: str) -> str:
    """Build an RFC 6266 Content-Disposition for a download. Includes an ASCII-only
    filename= fallback AND a UTF-8 filename* so non-Latin-1 names (any unicode name —
    now common since filenames round-trip through at-rest encryption) download correctly
    instead of raising a header-encoding error (the raw f'filename=\"{name}\"' form 500s
    on a non-Latin-1 character)."""
    from urllib.parse import quote
    name = file_name or 'download'
    # Strip control chars (incl. CR/LF, which ARE ASCII and survive the ascii encode) plus
    # quotes/backslashes, so a crafted filename can't inject header content, split the response,
    # or (on uvicorn) make the whole download 500 on a malformed header. The UTF-8 filename*
    # below is already safe (quote() percent-encodes control chars).
    ascii_fallback = ''.join(
        c for c in name.encode('ascii', 'ignore').decode('ascii')
        if 32 <= ord(c) < 127 and c not in '"\\'
    ).strip() or 'download'
    return f"attachment; filename=\"{ascii_fallback}\"; filename*=UTF-8''{quote(name)}"




# NOTE: same-name replace-on-clash moved INTO vault_service.finalize_streaming_upload
# (transactional delete-before-insert) so the old row never coexists with the new one
# under the (vault_id, folder_id, name_bi) unique index. The former post-commit
# _replace_same_name_files helper was removed; callers pass replace_same_name=<can-delete>.


@app.post("/vaults/{vault_id}/files")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def upload_file(
    vault_id: uuid.UUID,
    files: List[UploadFile],
    request: Request,
    folder_id: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """
    Upload one or more files to a vault with streaming support.
    Processes chunks in real-time, encrypts progressively, shows live progress.
    Requires vault password if vault is password-protected (via X-Vault-Password header).
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    from app.core.database import redis_client
    
    try:
        # Verify vault access and password (from header for security)
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        # A path-scoped temp credential may only upload INTO a folder within its scope
        # (uploading to the vault root, folder_id None, is denied for a scoped credential).
        require_folder_scope(db, current_user, vault_id, folder_id)

        # Zero-knowledge vaults cannot use this multipart path: the bytes (and the
        # multipart filename) arrive in the CLEAR, so the server would store plaintext
        # content + a plaintext name — breaking zero-knowledge. ZK uploads must use the
        # chunked uploader, which encrypts content + name in the browser first.
        if _is_zk_vault(vault):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Zero-knowledge vaults require the resumable (chunked) uploader; "
                       "direct multipart upload is not allowed.",
            )

        # Get vault's current size and limit
        vault_current_size = vault.total_size_bytes or 0
        vault_size_limit = vault.size_limit or 0
        
        # Get Content-Length from request to estimate total upload size
        content_length = request.headers.get('content-length')
        estimated_upload_size = int(content_length) if content_length else 0

        # Deployment-wide plan storage ceiling (aggregate across all vaults), enforced
        # before the per-vault reservation so a customer can't exceed their plan by
        # spreading data across many vaults.
        _enforce_deployment_storage_quota(db, estimated_upload_size)

        # the per-file ceiling is enforced IN-STREAM inside the per-file loop below (see the
        # bytes_uploaded check) — matching chunked-init — so an oversized single file is aborted
        # before it is fully buffered to transient disk, WITHOUT wrongly rejecting a legitimate
        # multi-file upload on its aggregate size. Read the admin upload policy (allowed types +
        # effective max) ONCE here; this multipart path is standard-only (ZK is rejected above), so
        # the file-type allowlist always applies.
        _allowed_exts, _max_upload_bytes = _upload_policy(db)

        # Parse folder_id if provided
        folder_uuid = uuid.UUID(folder_id) if folder_id else None
        
        uploaded_files = []
        
        # ATOMIC SPACE RESERVATION: Create reservation BEFORE processing files
        # This ensures parallel requests don't race
        reservation_key = None
        if vault_size_limit > 0 and estimated_upload_size > 0:
            # Create reservation key first (will be populated atomically)
            reservation_key = f"vault:{vault_id}:reservation:{uuid.uuid4()}"
            reservation_pattern = f"vault:{vault_id}:reservation:*"
            
            # Use Redis Lua script for atomic check-and-reserve
            # This prevents race conditions between check and set
            lua_script = """
            local vault_id = ARGV[1]
            local reservation_key = ARGV[2]
            local estimated_size = tonumber(ARGV[3])
            local vault_current_size = tonumber(ARGV[4])
            local vault_size_limit = tonumber(ARGV[5])
            local pattern = ARGV[6]
            
            -- Scan for existing reservations
            local cursor = "0"
            local current_reserved = 0
            repeat
                local result = redis.call('SCAN', cursor, 'MATCH', pattern, 'COUNT', 100)
                cursor = result[1]
                local keys = result[2]
                for i, key in ipairs(keys) do
                    local reserved_amount = redis.call('GET', key)
                    if reserved_amount then
                        current_reserved = current_reserved + tonumber(reserved_amount)
                    end
                end
            until cursor == "0"
            
            -- Calculate available space
            local total_used = vault_current_size + current_reserved
            local available_space = vault_size_limit - total_used
            
            -- Check if upload fits
            if estimated_size > available_space then
                return {0, current_reserved}  -- Rejected: return 0 and current reserved
            end
            
            -- Reserve space atomically
            redis.call('SET', reservation_key, estimated_size, 'EX', 300)
            return {1, current_reserved}  -- Success: return 1 and current reserved
            """
            
            try:
                # Execute atomic check-and-reserve
                result = redis_client.eval(
                    lua_script,
                    0,  # number of keys (we use ARGV only)
                    str(vault_id),
                    reservation_key,
                    str(estimated_upload_size),
                    str(vault_current_size),
                    str(vault_size_limit),
                    reservation_pattern
                )
                
                success = result[0]
                current_reserved = result[1]
                
                if not success:
                    # Reservation failed - not enough space
                    total_used = vault_current_size + current_reserved
                    available_space = vault_size_limit - total_used
                    
                    size_mb = f"{estimated_upload_size / (1024*1024):.2f} MB"
                    available_mb = f"{available_space / (1024*1024):.2f} MB"
                    current_mb = f"{vault_current_size / (1024*1024):.2f} MB"
                    reserved_mb = f"{current_reserved / (1024*1024):.2f} MB"
                    limit_mb = f"{vault_size_limit / (1024*1024):.2f} MB"
                    
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload rejected: File size ({size_mb}) exceeds available space ({available_mb}). Vault: {current_mb} used, {reserved_mb} reserved, {limit_mb} limit"
                    )
                
                # Success - space reserved
                current_mb = f"{vault_current_size / (1024*1024):.2f} MB"
                reserved_mb = f"{current_reserved / (1024*1024):.2f} MB"
                limit_mb = f"{vault_size_limit / (1024*1024):.2f} MB"
                print(f"📦 Space reserved atomically: {estimated_upload_size / (1024*1024):.2f} MB (Current: {current_mb}, Reserved: {reserved_mb}, Limit: {limit_mb})")
                
            except HTTPException:
                raise  # Re-raise HTTP exceptions
            except Exception as e:
                print(f"⚠️ Failed to create atomic reservation: {e}")
                # Fall back to simple check without reservation
                if vault_current_size + estimated_upload_size > vault_size_limit:
                    raise HTTPException(
                        status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                        detail=f"Upload rejected: Vault size limit would be exceeded"
                    )
        
        for upload_file in files:
            # Validate filename
            if not upload_file.filename:
                continue  # Skip files without names

            # Reject a disallowed file type up front (before any reservation/streaming work).
            _enforce_file_type(upload_file.filename, _allowed_exts)

            # Create operation ID for tracking
            operation_id = f"upload_{uuid.uuid4()}"
            
            # Track in local set
            start_operation(operation_id)
            
            # Track in Redis for cancellation and progress
            from app.services.activity_monitor import ProgressTracker
            tracker = ProgressTracker()
            tracker.start_operation(
                operation_id=operation_id,
                user_id=str(current_user.id),  # Convert UUID to string for JSON storage
                username=str(current_user.username),
                operation_type="upload",
                file_name=upload_file.filename,
                total_size=0  # Unknown at start for streaming uploads
            )
            _op_ok = False  # set True only after the file is fully committed (drives complete_operation)

            # Wrap entire upload in try-finally to ensure reservation cleanup
            try:
                # Same-name policy = replace; reject up front if the uploader can't.
                _reject_unreplaceable_upload(db, vault_id, folder_uuid, upload_file.filename, current_user)

                # Start streaming upload
                file_info, stream_ctx = vault_service.upload_file_streaming(
                    vault_id=vault_id,
                    file_name=upload_file.filename,
                    user=current_user,
                    folder_id=folder_uuid,
                    mime_type=upload_file.content_type
                )
                
                # Broadcast upload start IMMEDIATELY
                broadcast_event({
                    "event": {
                        "type": "upload",
                        "title": "Upload in progress",
                        "description": f"{upload_file.filename} - 0 bytes uploaded",
                        "user": current_user.username,
                        "ip": get_client_ip(request),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "operation_id": operation_id,
                        "file_name": upload_file.filename,
                        "bytes_uploaded": 0
                    }
                })
                
                # Stream chunks - process in real-time
                chunk_size = 5 * 1024 * 1024  # 5MB chunks
                bytes_uploaded = 0
                last_progress_broadcast = 0
                progress_broadcast_interval = 5 * 1024 * 1024  # Broadcast every 5MB for responsiveness
                
                with stream_ctx as ctx:
                    while True:
                        # Check if cancelled
                        if tracker.is_cancelled(operation_id):
                            broadcast_event({
                                "event": {
                                    "type": "upload",
                                    "title": "Upload cancelled",
                                    "description": f"{upload_file.filename} - cancelled by user",
                                    "user": current_user.username,
                                    "ip": get_client_ip(request),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "operation_id": operation_id,
                                    "file_name": upload_file.filename,
                                    "bytes_uploaded": bytes_uploaded,
                                    "completed": True,
                                    "cancelled": True  # Mark as cancelled
                                }
                            })
                            # Cleanup: partial file will be deleted by context manager __exit__
                            raise HTTPException(status_code=499, detail="Upload cancelled by user")
                        
                        # Read chunk from upload stream
                        chunk = await upload_file.read(chunk_size)
                        if not chunk:
                            break
                        
                        # SECURITY: Check if upload would exceed vault size limit BEFORE writing
                        if vault_size_limit > 0:
                            projected_total_size = vault_current_size + bytes_uploaded + len(chunk)
                            if projected_total_size > vault_size_limit:
                                # Format sizes for logging
                                bytes_up_str = f"{bytes_uploaded / (1024*1024):.2f} MB"
                                limit_str = f"{vault_size_limit / (1024*1024):.2f} MB"
                                
                                # Log security incident
                                audit_logger.log_action(
                                    action='size_limit_violation',
                                    status='failure',
                                    user=current_user,
                                    resource_type='vault',
                                    resource_id=str(vault_id),
                                    details={'file_name': upload_file.filename, 'bytes_uploaded': bytes_uploaded, 'chunk_size': len(chunk), 'limit': vault_size_limit},
                                    ip_address=get_client_ip(request)
                                )
                                
                                # Broadcast security event
                                broadcast_event({
                                    "event": {
                                        "type": "security_incident",
                                        "title": "Size limit violation detected",
                                        "description": f"{upload_file.filename} - Upload aborted after {bytes_up_str}. Would exceed vault limit.",
                                        "user": current_user.username,
                                        "ip": get_client_ip(request),
                                        "timestamp": datetime.now(timezone.utc).isoformat(),
                                        "operation_id": operation_id,
                                        "file_name": upload_file.filename,
                                        "severity": "medium"
                                    }
                                })
                                
                                # Abort upload - partial file will be deleted by context manager
                                raise HTTPException(
                                    status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                    detail=f"Upload aborted: File exceeds vault size limit. {bytes_up_str} uploaded before detection. Limit: {limit_str}"
                                )
                        
                        # enforce the per-file ceiling in-stream (per-file, via the
                        # per-file bytes_uploaded counter), aborting an oversized file before it
                        # is fully buffered — the chunked path enforces max_file_size at init.
                        if bytes_uploaded + len(chunk) > _max_upload_bytes:
                            raise HTTPException(
                                status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                                detail=f"File '{upload_file.filename}' exceeds the maximum size of {_max_upload_bytes // (1024 * 1024)}MB",
                            )

                        # Write and encrypt chunk immediately
                        ctx.write_chunk(chunk)
                        bytes_uploaded += len(chunk)
                        
                        # Broadcast progress every 5MB
                        if bytes_uploaded - last_progress_broadcast >= progress_broadcast_interval:
                            broadcast_event({
                                "event": {
                                    "type": "upload",
                                    "title": "Upload in progress",
                                    "description": f"{upload_file.filename} - {bytes_uploaded:,} bytes uploaded",
                                    "user": current_user.username,
                                    "ip": get_client_ip(request),
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "operation_id": operation_id,
                                    "file_name": upload_file.filename,
                                    "bytes_uploaded": bytes_uploaded
                                },
                                "traffic": {
                                    "upload": bytes_uploaded,
                                    "download": 0
                                }
                            })
                            last_progress_broadcast = bytes_uploaded
                    
                    # Get final checksum and size
                    final_checksum = ctx.get_checksum()
                    final_size = ctx.get_total_size()
                    # Re-gate the deployment storage ceiling with the TRUE size: the
                    # pre-check used Content-Length, which is 0/absent on a chunked-
                    # transfer stream. Inside the stream context so a 413 here unwinds
                    # the partial encrypted file (matches the per-vault abort pattern).
                    _enforce_deployment_storage_quota(db, final_size)

                # Broadcast final progress (100%)
                broadcast_event({
                    "event": {
                        "type": "upload",
                        "title": "Upload complete",
                        "description": f"{upload_file.filename} - {bytes_uploaded:,} bytes uploaded",
                        "user": current_user.username,
                        "ip": get_client_ip(request),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "operation_id": operation_id,
                        "file_name": upload_file.filename,
                        "bytes_uploaded": bytes_uploaded,
                        "completed": True
                    }
                })
                
                # Finalize upload - create database record. Replace-on-clash is done
                # transactionally inside finalize (old same-name row deleted in the same
                # commit as the new insert) so it never coexists with the new row under the
                # name unique index and a rollback preserves the old file. Gate replacement
                # on the principal's file.delete capability — matching the pre-check — so a
                # clash that appears after the pre-check can't let an upload-only cred
                # silently overwrite (it surfaces as a 409 via the unique index instead).
                file = vault_service.finalize_streaming_upload(
                    file_info=file_info,
                    total_size=final_size,
                    checksum=final_checksum,
                    replace_same_name=_principal_can_replace_file(db, current_user, vault_id),
                )

                uploaded_files.append({
                    'id': str(file.id),
                    'name': file.original_name,
                    'size': file.size_bytes,
                    'mime_type': file.mime_type
                })
                _op_ok = True  # fully committed -> complete_operation reports success in the finally

                # Audit log
                audit_logger.log_action(
                    action='file_upload',
                    status='success',
                    user=current_user,
                    resource_type='file',
                    resource_id=str(file.id),
                    details={'vault_id': str(vault_id), 'file_name': file.original_name},
                    ip_address=get_client_ip(request)
                )
                
                # Broadcast final completion event
                broadcast_event({
                    "event": {
                        "type": "upload",
                        "title": "Upload completed",
                        "description": f"{file.original_name} ({file.size_bytes:,} bytes) uploaded successfully",
                        "user": current_user.username,
                        "ip": get_client_ip(request),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                        "operation_id": operation_id,
                        "file_name": file.original_name,
                        "bytes_uploaded": file.size_bytes,
                        "completed": True
                    },
                    "traffic": {
                        "upload": file.size_bytes,
                        "download": 0
                    }
                })
                    
            except HTTPException:
                # Re-raise HTTP exceptions (size limit violations, cancellations, etc.)
                raise

            except DuplicateNameError as e:
                # Lost a same-name replace race against the name unique index — a clean 409.
                raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))

            except PermissionDeniedError as e:
                # A write-permission denial is a 403, not a 500 (the broad handler below).
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

            except Exception as e:
                # Log error
                print(f"Error during upload: {e}")
                audit_logger.log_action(
                    action='file_upload',
                    status='failure',
                    user=current_user,
                    resource_type='vault',
                    resource_id=str(vault_id),
                    details={'error': str(e), 'file_name': upload_file.filename},
                    ip_address=get_client_ip(request)
                )
                raise HTTPException(
                    status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                    detail=f"Upload failed: {str(e)}"
                )
                    
            finally:
                # CLEANUP: Release space reservation if it was created
                if reservation_key and vault_size_limit > 0:
                    try:
                        reserved_amount = redis_client.get(reservation_key)
                        redis_client.delete(reservation_key)
                        if reserved_amount:
                            print(f"🧹 Reservation cleanup: {int(reserved_amount) / (1024*1024):.2f} MB")
                    except Exception as e:
                        print(f"⚠️ Failed to cleanup reservation in finally: {e}")
                
                # Mark the Redis progress record complete + clear it (it was never completed before, so
                # every finished/failed upload used to leave a dangling operation:* record until TTL).
                # Best-effort: cleanup must never fail the request.
                try:
                    tracker.complete_operation(operation_id, success=_op_ok)
                except Exception:
                    pass

                # Always end operation tracking
                end_operation(operation_id)
        
        return {
            'message': f'Successfully uploaded {len(uploaded_files)} file(s)',
            'files': uploaded_files
        }
        
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except FileTooLargeError as e:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=str(e)
        )
    except HTTPException:
        # Deliberate HTTP errors raised inside (size reservation 413, same-name
        # replace 409, cancellations) must propagate as-is, not be re-wrapped to 500.
        raise
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        db.rollback()
        # Broadcast error event
        try:
            broadcast_event({
                "event": {
                    "type": "error",
                    "title": "Upload failed",
                    "description": f"Upload error: {str(e)[:100]}",
                    "user": current_user.username if current_user else "unknown",
                    "ip": get_client_ip(request),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            })
        except:
            pass  # Don't fail the error handler
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to upload file: {str(e)}"
        )


# ============================================================================
# Resumable chunked uploads
# ----------------------------------------------------------------------------
# Large files are uploaded as a sequence of independent chunk requests so they
# can be paused, cancelled and resumed — even across browser sessions or days.
# Raw chunks are buffered on the persistent storage volume under _uploads/<sid>/
# and are streamed through the SAME encryption pipeline as a normal upload only
# at /complete, so the at-rest file is byte-for-byte a regular vault file.
# ============================================================================

def _chunk_session_ttl_hours() -> int:
    """TTL (hours) before a chunked-upload session is considered abandoned and its
    buffered chunks become eligible for cleanup. Configurable via CHUNK_SESSION_TTL_HOURS
    (settings.chunk_session_ttl_hours). Floored at 1 so a mis-set 0/negative can't make a
    session expire the instant it is created (which would break every resumable upload)."""
    try:
        return max(1, int(settings.chunk_session_ttl_hours))
    except Exception:
        return 24


def _uploads_root() -> Path:
    """Single on-disk root holding every session's buffered chunks: <storage>/_uploads/.
    Session dirs live directly under it keyed by the (globally unique) session UUID, so a
    deployment-wide sweep only has to scan this one directory."""
    return Path(settings.file_storage_path) / "_uploads"


def _upload_session_dir(vault_service: VaultService, session_id: str):
    """Directory holding the buffered chunks for one upload session."""
    return vault_service.storage_path / "_uploads" / session_id


# Deployment-wide rowless-orphan reclaim grace: a chunk dir with no matching active-session
# row in our snapshot is only reclaimed once it has aged past this. init commits the session
# row and only THEN makes the dir, so a session that starts AFTER the sweep's row snapshot is
# briefly indistinguishable from a rowless orphan — the grace ensures its fresh, in-flight
# chunks are never swept out from under it. Genuinely abandoned orphans age in within a pass.
_ORPHAN_DIR_GRACE_MINUTES = 10


def _dir_size_bytes(path: Path) -> int:
    """Best-effort total size of the SETTLED chunk files under a session dir (for reclaim
    stats). Skips the in-flight atomic-write temp files (.chunk_*.part) so an actively
    uploading session's transient temp file doesn't inflate the reported totals."""
    total = 0
    try:
        for child in path.iterdir():
            try:
                if child.is_file() and not child.name.startswith('.'):
                    total += child.stat().st_size
            except OSError:
                continue
    except OSError:
        return total
    return total


def _sweep_orphaned_upload_chunks(db: Session, idle_minutes: Optional[int] = None,
                                  vault_id: Optional[uuid.UUID] = None) -> dict:
    """Reclaim disk + DB rows for chunked-upload sessions that no live upload still needs.

    A session's chunks buffer under _uploads/<sid>/ until /complete (or /cancel) removes
    them. Three classes leak and are reclaimed here:
      * terminal/expired rows — their chunk dir is removed (the periodic prune used to drop
        the ROW but leave the dir on disk until... nothing, so it lingered indefinitely);
      * truly orphaned dirs — a chunk dir with no DB row at all (e.g. a crash between the
        row delete and the rmtree in /complete) — reclaimed in deployment-wide mode;
      * idle-but-active sessions — only when an ``idle_minutes`` threshold is given: an
        active session whose last chunk landed longer than that ago is force-reclaimed
        (an operator clearing stalled uploads before the full TTL elapses). With
        ``idle_minutes=0`` every active session is reclaimed (a hard purge).

    Safety: an active session that is NOT past the idle threshold is always KEPT — its dir
    is never removed — so an in-flight upload is never destroyed by a sweep.

    Scope: pass ``vault_id`` to confine all of the above to one vault (only that vault's
    session rows are touched and only their dirs are removed; rowless orphan dirs, which
    can't be attributed to a vault, are left for a deployment-wide sweep). Omit it for a
    deployment-wide sweep (the periodic cleaner's mode).
    """
    now = datetime.utcnow()
    q = db.query(ChunkedUploadSession)
    if vault_id is not None:
        q = q.filter(ChunkedUploadSession.vault_id == vault_id)
    sessions = q.all()

    keep_sids: set = set()       # active+recent sessions whose dir must survive
    remove_rows = []             # session rows to delete (terminal/expired/idle-reclaimed)
    remove_sids: set = set()     # their session ids (for the scoped dir sweep)
    for s in sessions:
        sid = str(s.id)
        terminal = s.status in ('completed', 'failed', 'cancelled', 'expired')
        expired = bool(s.expires_at and s.expires_at < now)
        if s.status == 'active' and not terminal and not expired:
            if idle_minutes is not None:
                last = s.last_chunk_at or s.created_at or now
                idle = (now - last).total_seconds() / 60.0
                if idle >= idle_minutes:
                    remove_rows.append(s); remove_sids.add(sid); continue
            keep_sids.add(sid)
        else:
            remove_rows.append(s); remove_sids.add(sid)

    rows_pruned = 0
    for s in remove_rows:
        db.delete(s)
        rows_pruned += 1
    if rows_pruned:
        db.commit()

    scanned_dirs = 0
    dirs_removed = 0
    bytes_reclaimed = 0
    grace_cutoff = now - timedelta(minutes=_ORPHAN_DIR_GRACE_MINUTES)
    root = _uploads_root()
    if root.exists():
        for child in root.iterdir():
            if not child.is_dir():
                continue
            scanned_dirs += 1
            name = child.name
            if vault_id is None:
                # Deployment-wide reclaim.
                if name in keep_sids:
                    continue  # active+recent session — never touch
                if name not in remove_sids:
                    # Rowless dir (no session row) OR a session created AFTER our row
                    # snapshot. Only reclaim once it has aged past the grace window so a
                    # just-started, in-flight upload's chunks are never swept out from under
                    # it; positively-dead rows (in remove_sids) are reclaimed regardless.
                    try:
                        mtime = datetime.utcfromtimestamp(child.stat().st_mtime)
                    except OSError:
                        continue
                    if mtime >= grace_cutoff:
                        continue
            else:
                # Vault-scoped: only remove dirs for THIS vault's reclaimed sessions; leave
                # rowless/foreign dirs for a deployment-wide sweep.
                if name not in remove_sids:
                    continue
            bytes_reclaimed += _dir_size_bytes(child)
            shutil.rmtree(child, ignore_errors=True)
            dirs_removed += 1

    return {
        'scanned_dirs': scanned_dirs,
        'dirs_removed': dirs_removed,
        'bytes_reclaimed': bytes_reclaimed,
        'rows_pruned': rows_pruned,
        'active_sessions_kept': len(keep_sids),
        'idle_minutes': idle_minutes,
        'scope': f'vault:{vault_id}' if vault_id is not None else 'deployment',
    }


def _received_chunk_indices(session_dir) -> set:
    """Authoritative set of chunk indices present on disk (survives restarts)."""
    if not session_dir.exists():
        return set()
    indices = set()
    for p in session_dir.glob("chunk_*"):
        try:
            indices.add(int(p.name.split("_", 1)[1]))
        except (ValueError, IndexError):
            continue
    return indices


def _session_payload(session: ChunkedUploadSession, received: int) -> dict:
    total = session.total_chunks or 0
    return {
        'session_id': str(session.id),
        'file_name': session.filename,
        'total_size': session.total_size,
        'mime_type': session.mime_type,
        'total_chunks': total,
        'chunks_received': received,
        'folder_id': str(session.folder_id) if session.folder_id else None,
        'percent': round(received * 100 / total, 1) if total else 0,
        'created_at': session.created_at.isoformat() if session.created_at else None,
        'last_chunk_at': session.last_chunk_at.isoformat() if session.last_chunk_at else None,
    }


class ChunkedUploadInit(BaseModel):
    # Plaintext name for Standard vaults. For ZERO-KNOWLEDGE vaults this MUST be omitted
    # (the server must never see the plaintext name) — the client sends enc_name/name_bi.
    file_name: Optional[str] = None
    total_size: int
    total_chunks: int
    chunk_size: int = 5 * 1024 * 1024
    mime_type: Optional[str] = None
    folder_id: Optional[str] = None
    # Zero-knowledge only: the DEK epoch the client encrypted this file under. Carried to
    # finalize, where it is re-checked against the vault's current epoch under a row lock
    # (a mid-upload rotation => 409) and stamped onto the File. Omitted for Standard vaults.
    zk_key_version: Optional[int] = None
    # Zero-knowledge only: the file name + MIME encrypted IN THE BROWSER under the vault
    # DEK (security ZK marker + base64) and the client-computed blind index for same-name
    # matching. Required for ZK uploads; rejected for Standard ones. The server stores them
    # verbatim and never decrypts.
    enc_name: Optional[str] = None
    enc_mime: Optional[str] = None
    name_bi: Optional[str] = Field(None, max_length=64)  # stored in a VARCHAR(64) column


@app.post("/vaults/{vault_id}/uploads")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def init_chunked_upload(
    vault_id: uuid.UUID,
    body: ChunkedUploadInit,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Start (or resume) a chunked upload. Returns the session and the indices
    already received so the client can skip them."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    if body.total_size <= 0 or body.total_chunks <= 0:
        raise HTTPException(status_code=400, detail="Invalid upload size")
    # bound total_chunks so /complete's `range(total_chunks)` can't be forced to
    # materialize a multi-billion-element list (memory/CPU DoS). A chunk is >= 1 byte, so the
    # count can't exceed total_size; also cap it absolutely.
    if body.total_chunks > body.total_size or body.total_chunks > 200_000:
        raise HTTPException(status_code=400, detail="Invalid chunk count for the declared size")

    # Zero-knowledge name handling. ZK uploads must carry a browser-encrypted name + blind
    # index and MUST NOT carry a plaintext name/MIME (that would defeat zero-knowledge).
    # Standard uploads are the inverse: a plaintext name is required.
    is_zk = _is_zk_vault(vault)
    _allowed_exts, _max_file_bytes = _upload_policy(db)
    if is_zk:
        if not body.enc_name or not body.name_bi:
            raise HTTPException(
                status_code=400,
                detail="Zero-knowledge uploads require a client-encrypted name (enc_name + name_bi).",
            )
        if body.file_name or body.mime_type:
            raise HTTPException(
                status_code=400,
                detail="A zero-knowledge upload must not send a plaintext file name or MIME type.",
            )
        _require_zk_sealed_names(body.enc_name, body.enc_mime)
    else:
        if not body.file_name:
            raise HTTPException(status_code=400, detail="file_name is required")
        # strip control chars (CR/LF etc.) from the stored name. The download-header
        # sink is also defended, but keeping the at-rest name clean avoids log/listing
        # corruption from a crafted chunked-upload file_name (this path skips sanitize_filename).
        body.file_name = ''.join(c for c in body.file_name if ord(c) >= 32 and ord(c) != 127) or "download"
        # Standard (non-ZK) uploads carry a plaintext name — enforce the admin file-type allowlist.
        # ZK names are browser-encrypted (server-invisible), so ZK vaults are exempt.
        _enforce_file_type(body.file_name, _allowed_exts)

    if body.total_size > _max_file_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum size of {_max_file_bytes // (1024 * 1024)}MB")
    if vault.size_limit and (vault.total_size_bytes or 0) + body.total_size > vault.size_limit:
        raise HTTPException(status_code=413, detail="File would exceed the vault size limit")
    _enforce_deployment_storage_quota(db, body.total_size)   # plan aggregate storage ceiling

    folder_uuid = None
    if body.folder_id:
        try:
            folder_uuid = uuid.UUID(body.folder_id)
        except (ValueError, TypeError):
            raise HTTPException(status_code=400, detail="Invalid folder id")
        folder = db.query(Folder).filter(Folder.id == folder_uuid, Folder.vault_id == vault_id).first()
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found in vault")

    # A scoped credential may only start an upload into an in-scope folder (root => denied).
    require_folder_scope(db, current_user, vault_id, body.folder_id)

    now = datetime.utcnow()
    # Resume: reuse an active session for the same file if present. Standard vaults match
    # by plaintext name + size; ZK vaults match by the client blind index + size (the
    # server has no plaintext name to compare). Same (name, vault, epoch) -> same blind
    # index, so a re-init of the same file finds its in-flight session.
    resume_q = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
        ChunkedUploadSession.total_size == body.total_size,
        ChunkedUploadSession.total_chunks == body.total_chunks,
        ChunkedUploadSession.status == 'active',
        ChunkedUploadSession.expires_at > now,
    )
    # Match the requested destination too. user_id is shared between the minting admin and every
    # temp credential they mint, so without this a re-init would resume a session opened into a
    # DIFFERENT folder — reusing its stored target and ignoring body.folder_id (a correctness bug
    # for everyone, and it would let a scope-checked destination silently become another folder).
    if folder_uuid is None:
        resume_q = resume_q.filter(ChunkedUploadSession.folder_id.is_(None))
    else:
        resume_q = resume_q.filter(ChunkedUploadSession.folder_id == folder_uuid)
    if is_zk:
        resume_q = resume_q.filter(ChunkedUploadSession.name_bi == body.name_bi)
    else:
        resume_q = resume_q.filter(ChunkedUploadSession.filename == body.file_name)
    session = resume_q.order_by(ChunkedUploadSession.created_at.desc()).first()

    if session is None:
        # bound concurrent open sessions per user so N half-open sessions can't buffer
        # N*total_size of transient disk that the plan storage quota never counts. Resuming an
        # existing session (above) is unaffected — only a NEW session is capped.
        open_sessions = db.query(ChunkedUploadSession.id).filter(
            ChunkedUploadSession.user_id == current_user.id,
            ChunkedUploadSession.status == 'active',
            ChunkedUploadSession.expires_at > now,
        ).count()
        if open_sessions >= 25:
            raise HTTPException(
                status_code=429,
                detail="Too many concurrent uploads in progress; complete or cancel some before starting another.",
            )
        session = ChunkedUploadSession(
            vault_id=vault_id,
            user_id=current_user.id,
            # Standard: plaintext name/MIME. ZK: NULL plaintext, client-encrypted name in
            # enc_name/enc_mime + the blind index (server never sees the plaintext name).
            filename=body.file_name,
            mime_type=body.mime_type,
            enc_name=body.enc_name,
            enc_mime=body.enc_mime,
            name_bi=body.name_bi,
            total_size=body.total_size,
            total_chunks=body.total_chunks,
            chunks_received=0,
            bytes_received=0,
            folder_id=folder_uuid,
            created_at=now,
            last_chunk_at=now,
            expires_at=now + timedelta(hours=_chunk_session_ttl_hours()),
            status='active',
            # ZK only: remember the DEK epoch the client encrypted under (re-checked at
            # finalize). Recorded only on a fresh session; a resumed one keeps its original.
            zk_key_version=body.zk_key_version,
        )
        db.add(session)
        db.commit()
        db.refresh(session)

    sdir = _upload_session_dir(vault_service, str(session.id))
    sdir.mkdir(parents=True, exist_ok=True)
    if not session.temp_file_path:
        session.temp_file_path = str(sdir)
        db.commit()

    received = sorted(_received_chunk_indices(sdir))
    return {
        'session_id': str(session.id),
        'chunk_size': body.chunk_size,
        'total_chunks': session.total_chunks,
        'received_chunks': received,
        'expires_at': session.expires_at.isoformat() if session.expires_at else None,
    }


@app.put("/vaults/{vault_id}/uploads/{session_id}/chunks/{chunk_index}")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def upload_chunk(
    vault_id: uuid.UUID,
    session_id: uuid.UUID,
    chunk_index: int,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Store a single chunk. Idempotent: re-sending a chunk overwrites it."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    session = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session_id,
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
    ).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session not found")
    # A scoped credential may only write to a session whose target folder is in scope
    # (the session was created by the same shared user id, so re-check per surface).
    require_folder_scope(db, current_user, vault_id, session.folder_id)
    if session.status != 'active':
        raise HTTPException(status_code=409, detail=f"Upload session is {session.status}")
    if session.expires_at and session.expires_at <= datetime.utcnow():
        session.status = 'expired'
        db.commit()
        raise HTTPException(status_code=410, detail="Upload session expired")
    if chunk_index < 0 or chunk_index >= session.total_chunks:
        raise HTTPException(status_code=400, detail=f"Invalid chunk index (0-{session.total_chunks - 1})")

    sdir = _upload_session_dir(vault_service, str(session.id))
    sdir.mkdir(parents=True, exist_ok=True)
    chunk_path = sdir / f"chunk_{chunk_index:06d}"
    already = chunk_path.exists()
    # Size of this index if it is being re-sent, so the running total stays accurate
    # and an overwrite is not double-counted.
    try:
        existing_size = chunk_path.stat().st_size if already else 0
    except OSError:
        existing_size = 0
    # Bytes already buffered for this session EXCLUDING the index being written. Clamp at
    # 0: a crash between writing a chunk and committing the counter can leave bytes_received
    # undercounted, and base_bytes must never go negative (that would loosen the bound).
    base_bytes = max(0, (session.bytes_received or 0) - existing_size)
    remaining = session.total_size - base_bytes  # how many more bytes this index may add

    # Transient-disk-pressure guard. Raw chunks buffer on the persistent storage volume
    # until /complete streams them through the encryption pipeline. Bound the buffered
    # bytes for THIS session to the size declared (and quota-checked against max-file-size /
    # the vault size limit / the deployment storage quota) at init, so a client can't
    # balloon the _uploads/ buffer past what was approved by sending oversized chunks.
    # (This bounds a single session; aggregate transient disk across many concurrent
    # sessions is governed only by each session's own total_size — a known limitation.)
    # Fast path: reject an honestly-declared oversized body before reading anything.
    declared_len = request.headers.get("content-length")
    if declared_len is not None:
        try:
            clen = int(declared_len)
        except (TypeError, ValueError):
            clen = None
        if clen is not None and clen > remaining:
            raise HTTPException(status_code=413, detail="Chunk data exceeds the declared upload size")

    # Real bound: stream the body and abort as soon as it would exceed the remaining
    # budget, so a missing/understated Content-Length (chunked transfer-encoding, or a
    # lying header) can't force an arbitrarily large body into memory before we reject it.
    buf = bytearray()
    async for piece in request.stream():
        buf.extend(piece)
        if len(buf) > remaining:
            raise HTTPException(status_code=413, detail="Chunk data exceeds the declared upload size")
    data = bytes(buf)
    if not data:
        raise HTTPException(status_code=400, detail="Empty chunk")

    # Write atomically so a dropped connection can't leave a truncated chunk.
    tmp_path = sdir / f".chunk_{chunk_index:06d}.part"
    with open(tmp_path, 'wb') as f:
        f.write(data)
    os.replace(tmp_path, chunk_path)

    # Serialize the counter update per session (SELECT ... FOR UPDATE) and recompute the counters from
    # the AUTHORITATIVE on-disk chunk set, so concurrent PUTs — even a same-index re-send — converge to
    # the true total instead of racing a read-modify-write (a blind += double-counts a same-index race;
    # an absolute assignment clobbers a concurrent different-index write). Mirrors the disk-authoritative
    # /complete and the ZK-path locking.
    _total = session.total_chunks
    locked = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session.id
    ).with_for_update().first()
    _present = sorted(sdir.glob("chunk_*"))
    _bytes = 0
    for _p in _present:
        try:
            _bytes += _p.stat().st_size
        except OSError:
            pass
    received = len(_present)
    if locked is not None:
        locked.bytes_received = _bytes
        locked.chunks_received = received
        locked.last_chunk_at = datetime.utcnow()
    db.commit()

    return {
        'received': received,
        'total': _total,
        'bytes_received': _bytes,
        'percent': round(received * 100 / _total, 1) if _total else 0,
        'complete': received >= _total,
    }


@app.post("/vaults/{vault_id}/uploads/{session_id}/complete")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def complete_chunked_upload(
    vault_id: uuid.UUID,
    session_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Assemble buffered chunks through the real encryption pipeline and create
    the File record. Rejects with the missing indices if any chunk is absent."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    session = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session_id,
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
    ).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session not found")
    # A scoped credential may only finalize a session whose target folder is in scope.
    require_folder_scope(db, current_user, vault_id, session.folder_id)
    if session.status == 'completed' and session.file_id:
        return {'id': str(session.file_id), 'name': session.filename, 'already_completed': True}
    if session.status != 'active':
        raise HTTPException(status_code=409, detail=f"Upload session is {session.status}")
    # Mirror upload_chunk's expiry guard. Without it an expired-but-still-'active' session
    # could be finalized while the periodic/operator sweep concurrently reclaims (rmtree's)
    # its now-expired chunk dir — racing a FileNotFoundError into the streaming assembly and
    # losing the buffered upload. Reject a past-TTL finalize cleanly instead.
    if session.expires_at and session.expires_at <= datetime.utcnow():
        session.status = 'expired'
        db.commit()
        raise HTTPException(status_code=410, detail="Upload session expired")
    # Hold the session open for the (potentially long) assembly: push the TTL out so a
    # finalize that straddles the original expiry can't be classified 'expired' and swept
    # out from under the chunk reads. The row is deleted on success regardless.
    session.expires_at = datetime.utcnow() + timedelta(hours=_chunk_session_ttl_hours())
    db.commit()

    sdir = _upload_session_dir(vault_service, str(session.id))
    present = _received_chunk_indices(sdir)
    missing = [i for i in range(session.total_chunks) if i not in present]
    if missing:
        raise HTTPException(
            status_code=409,
            detail={
                'error': 'incomplete',
                'message': f'{len(missing)} chunk(s) still missing',
                'missing_chunks': missing[:100],
                'missing_count': len(missing),
            },
        )

    # Re-validate the destination folder still exists (may have been deleted).
    folder_uuid = session.folder_id
    if folder_uuid:
        folder = db.query(Folder).filter(Folder.id == folder_uuid, Folder.vault_id == vault_id).first()
        if not folder:
            folder_uuid = None  # fall back to vault root rather than failing the upload

    # Zero-knowledge: the name is client-encrypted (session.filename is NULL). Match
    # same-name on the client blind index, and feed the streaming context a placeholder
    # name (the on-disk blob is keyed by the file UUID, and finalize NULLs the plaintext
    # name anyway).
    is_zk = _is_zk_vault(vault)
    zk_name_bi = session.name_bi if is_zk else None

    # Same-name policy = replace; reject up front if the uploader can't replace.
    _reject_unreplaceable_upload(db, vault_id, folder_uuid, session.filename, current_user,
                                 name_bi=zk_name_bi)

    # Zero-knowledge v2 name binding: the client may supply the file id it sealed the name
    # under (so the sealed name binds the final row id and can't be transposed). Optional +
    # backward-compatible — absent means the server assigns the id (legacy v1). Reject a
    # collision cleanly (409) instead of a later 500.
    client_file_id = None
    try:
        _cbody = await request.json()
        if isinstance(_cbody, dict) and _cbody.get("file_id"):
            client_file_id = uuid.UUID(str(_cbody["file_id"]))
    except Exception:  # noqa: BLE001 — no/invalid body -> server assigns the id
        client_file_id = None
    if client_file_id is not None and db.query(File.id).filter(File.id == client_file_id).first():
        raise HTTPException(status_code=409, detail="File id already in use")

    # After a clean `with stream_ctx` exit the assembled blob PERSISTS; the post-assembly checks
    # (size-limit, deployment quota, ZK stale-epoch) and finalize below run OUTSIDE that block and can
    # raise, which would orphan a full-size ciphertext blob (the periodic sweep only touches _uploads/
    # chunk dirs, never the final blob). Best-effort remove it on ANY failure. No-op if never assembled.
    file_info = None

    def _remove_orphan_blob():
        try:
            if file_info and file_info.get('storage_path'):
                vault_service._remove_blobs([file_info['storage_path']])
        except Exception:
            pass

    try:
        file_info, stream_ctx = vault_service.upload_file_streaming(
            vault_id=vault_id,
            file_name=session.filename if not is_zk else '(encrypted)',
            user=current_user,
            folder_id=folder_uuid,
            mime_type=session.mime_type,
            file_id=client_file_id,
        )
        with stream_ctx as ctx:
            for i in range(session.total_chunks):
                with open(sdir / f"chunk_{i:06d}", 'rb') as cf:
                    while True:
                        buf = cf.read(1024 * 1024)
                        if not buf:
                            break
                        ctx.write_chunk(buf)
            final_checksum = ctx.get_checksum()
            final_size = ctx.get_total_size()

        # Final size-limit guard now that the true plaintext size is known.
        if vault.size_limit and (vault.total_size_bytes or 0) + final_size > vault.size_limit:
            raise HTTPException(status_code=413, detail="File would exceed the vault size limit")
        _enforce_deployment_storage_quota(db, final_size)   # plan aggregate storage ceiling

        # Zero-knowledge upload-vs-rekey race guard. Lock the vault row and confirm the
        # client encrypted under the CURRENT DEK epoch; if the vault was re-keyed during
        # the upload, reject (409) rather than commit a stale-epoch file that the
        # just-revoked member (who kept the old DEK) could still read. The lock is held
        # through finalize's commit so a concurrent rekey can't slip in between.
        zk_kv = None
        if getattr(vault, 'type', 'standard') == 'zero_knowledge':
            locked_vault = db.query(Vault).filter(Vault.id == vault_id).with_for_update().first()
            current_epoch = getattr(locked_vault, 'dek_version', 1) or 1
            declared = session.zk_key_version
            # Structured detail (code) so the client can distinguish this from a generic
            # failure and route the upload to a forced re-encrypt instead of a doomed resume.
            _stale = {
                "code": "stale_zk_epoch",
                "message": "The vault key changed during upload; re-encrypt with the current key and upload again.",
            }
            if declared is None:
                # An omitted epoch is only safe on a NEVER-rekeyed vault. After a rotation a
                # legacy/epoch-less client encrypted under the OLD DEK but can't declare it;
                # stamping it at the current epoch would leave it encrypted under the old DEK
                # and thus undecryptable. Reject rather than silently corrupt.
                if current_epoch != 1:
                    raise HTTPException(status_code=409, detail=_stale)
                declared = current_epoch
            if declared != current_epoch:
                raise HTTPException(status_code=409, detail=_stale)
            zk_kv = current_epoch

        file = vault_service.finalize_streaming_upload(
            file_info=file_info, total_size=final_size, checksum=final_checksum,
            zk_key_version=zk_kv,
            # ZK: stamp the browser-encrypted name/MIME + client blind index onto the File
            # (server stores them verbatim and decrypts nothing). NULL/no-op for Standard.
            zk_enc_name=session.enc_name if is_zk else None,
            zk_enc_mime=session.enc_mime if is_zk else None,
            zk_name_bi=zk_name_bi,
            # Replace-on-clash, transactionally inside finalize (see the multipart path).
            # Gated on the principal's real DELETE authority (cap + RBAC), not just the
            # temp-cred cap — a write-but-no-delete member must not overwrite via upload.
            replace_same_name=_principal_can_replace_file(db, current_user, vault_id),
        )
    except HTTPException:
        _remove_orphan_blob()
        raise
    except DuplicateNameError as e:
        _remove_orphan_blob()   # (finalize already removed it on this path; no-op safety net)
        # Lost a same-name replace race against the name unique index — a clean 409. finalize
        # already rolled back, but the session ROW survives intact (status='active') and for a
        # Standard vault still holds the plaintext filename/MIME as working state; the chunk
        # files are still on disk. Tear both down immediately (rather than leaving it for the
        # periodic sweep) so the conflict doesn't strand plaintext names + chunks on disk.
        try:
            db.delete(session)
            db.commit()
        except Exception:
            db.rollback()
        shutil.rmtree(sdir, ignore_errors=True)
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValueError as e:
        _remove_orphan_blob()
        # A client-supplied file id that collided (a fresh-UUID race that slipped past the
        # pre-check) -> a clean 409, not a 500. Any other ValueError keeps the generic handling.
        if "id already in use" in str(e):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="File id already in use")
        session.status = 'failed'
        session.error_message = str(e)[:500]
        db.commit()
        raise HTTPException(status_code=500, detail=f"Failed to finalize upload: {str(e)}")
    except PermissionDeniedError as e:
        # A permission denial is a 403, not a 500 — and it isn't a corrupt upload, so leave
        # the session/blob for the TTL cleanup rather than force-failing it here.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        _remove_orphan_blob()
        session.status = 'failed'
        session.error_message = str(e)[:500]
        db.commit()
        print(f"Error finalizing chunked upload: {e}")
        raise HTTPException(status_code=500, detail=f"Failed to finalize upload: {str(e)}")

    # Success: delete the upload session row entirely. It stored the plaintext
    # filename/MIME (working state during the transfer); keeping it as 'completed'
    # would leave those names at rest after the File's own name was sealed. The chunk
    # files are removed below; abandoned (failed/expired) sessions are pruned by
    # cleanup_expired_sessions.
    db.delete(session)
    db.commit()

    shutil.rmtree(sdir, ignore_errors=True)

    # For ZK files original_name is NULL by design (the name is client-encrypted). Use a
    # neutral label for the admin-facing audit/broadcast so nothing leaks and we don't
    # render "None". For Standard files original_name holds the (server-decrypted) name.
    disp_name = file.original_name or '(encrypted file)'

    audit_logger.log_action(
        action='file_upload',
        status='success',
        user=current_user,
        resource_type='file',
        resource_id=str(file.id),
        details={'vault_id': str(vault_id), 'file_name': file.original_name, 'chunked': True},
        ip_address=get_client_ip(request),
    )
    try:
        broadcast_event({
            "event": {
                "type": "upload",
                "title": "Upload completed",
                "description": f"{disp_name} ({file.size_bytes:,} bytes) uploaded (resumable)",
                "user": current_user.username,
                "ip": get_client_ip(request),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "file_name": disp_name,
                "bytes_uploaded": file.size_bytes,
                "completed": True,
            },
            "traffic": {"upload": file.size_bytes, "download": 0},
        })
    except Exception:
        pass

    return {
        'id': str(file.id),
        'name': file.original_name,
        'size': file.size_bytes,
        'mime_type': file.mime_type,
    }


@app.get("/vaults/{vault_id}/uploads")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def list_resumable_uploads(
    vault_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """List the caller's incomplete (resumable) upload sessions for this vault."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    now = datetime.utcnow()
    sessions = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
        ChunkedUploadSession.status == 'active',
        ChunkedUploadSession.expires_at > now,
    ).order_by(ChunkedUploadSession.created_at.desc()).all()

    # A scoped credential enumerates only its in-scope upload sessions: require_folder_scope
    # is a no-op for a whole-vault credential and raises for one whose scope excludes the
    # session's target folder (so out-of-scope filenames/folders are never listed).
    out = []
    for s in sessions:
        try:
            require_folder_scope(db, current_user, vault_id, s.folder_id)
        except PermissionDeniedError:
            continue
        received = len(_received_chunk_indices(_upload_session_dir(vault_service, str(s.id))))
        out.append(_session_payload(s, received))
    return out


@app.get("/vaults/{vault_id}/uploads/{session_id}")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def get_upload_session(
    vault_id: uuid.UUID,
    session_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Status of one session plus the exact indices already received (for resume)."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    session = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session_id,
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
    ).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session not found")
    # A scoped credential may only inspect a session whose target folder is in scope
    # (the payload carries the filename + folder id — do not reveal it out of scope).
    require_folder_scope(db, current_user, vault_id, session.folder_id)

    received = sorted(_received_chunk_indices(_upload_session_dir(vault_service, str(session.id))))
    payload = _session_payload(session, len(received))
    payload['status'] = session.status
    payload['received_chunks'] = received
    return payload


@app.delete("/vaults/{vault_id}/uploads/{session_id}")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def cancel_chunked_upload(
    vault_id: uuid.UUID,
    session_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Cancel a session and delete its buffered chunks."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    session = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session_id,
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
    ).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session not found")
    # A scoped credential may only cancel a session whose target folder is in scope.
    require_folder_scope(db, current_user, vault_id, session.folder_id)

    shutil.rmtree(_upload_session_dir(vault_service, str(session.id)), ignore_errors=True)
    if session.status == 'active':
        session.status = 'failed'
        session.error_message = 'Cancelled by user'
        db.commit()
    return {'message': 'Upload cancelled', 'session_id': str(session.id)}


# ----------------------------------------------------------------------------
# Operator maintenance: chunked-upload sessions
# ----------------------------------------------------------------------------
# /complete and /cancel remove a session's buffered chunks immediately, and a
# session row carries a TTL (CHUNK_SESSION_TTL_HOURS) after which it expires. But
# an abandoned upload's chunks sit under _uploads/<sid>/ until that TTL elapses
# (and historically the periodic prune dropped the expired ROW while leaving the
# chunk DIR on disk forever). These admin endpoints let an operator inspect that
# buffered disk and reclaim it on demand instead of waiting for the TTL.
# ----------------------------------------------------------------------------

@app.get("/api/maintenance/upload-sessions")
async def inspect_upload_sessions(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Operator view of resumable-upload disk usage across the deployment: how many
    sessions are active vs. terminal/expired, and how much chunk data is buffered on
    disk (including orphaned dirs with no live session). Admin only."""
    now = datetime.utcnow()
    sessions = db.query(ChunkedUploadSession).all()
    active_sids = set()
    active = 0
    terminal_or_expired = 0
    for s in sessions:
        expired = bool(s.expires_at and s.expires_at < now)
        if s.status == 'active' and not expired:
            active += 1
            active_sids.add(str(s.id))
        else:
            terminal_or_expired += 1

    root = _uploads_root()
    chunk_dirs = 0
    orphan_dirs = 0
    bytes_on_disk = 0
    if root.exists():
        for child in root.iterdir():
            if not child.is_dir():
                continue
            chunk_dirs += 1
            bytes_on_disk += _dir_size_bytes(child)
            if child.name not in active_sids:
                orphan_dirs += 1

    return {
        'ttl_hours': _chunk_session_ttl_hours(),
        'active_sessions': active,
        'terminal_or_expired_rows': terminal_or_expired,
        'chunk_dirs': chunk_dirs,
        'orphan_dirs': orphan_dirs,
        'bytes_on_disk': bytes_on_disk,
    }


@app.post("/api/maintenance/upload-sessions/cleanup")
async def cleanup_upload_sessions(
    request: Request,
    idle_minutes: Optional[int] = None,
    vault_id: Optional[uuid.UUID] = None,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Reclaim disk + rows for chunked-upload sessions no live upload needs.

    By default (no ``idle_minutes``) this is SAFE: it only removes terminal/expired session
    rows and their chunk dirs plus truly orphaned dirs — active, unexpired uploads are left
    untouched. Pass ``idle_minutes`` to also force-reclaim active sessions whose last chunk
    landed longer than that ago (``idle_minutes=0`` hard-purges every active session — use to
    clear stalled uploads before the full TTL). Pass ``vault_id`` to confine the sweep to one
    vault. Admin only; the operation is audited.
    """
    if idle_minutes is not None and idle_minutes < 0:
        raise HTTPException(status_code=400, detail="idle_minutes must be >= 0")

    result = _sweep_orphaned_upload_chunks(db, idle_minutes=idle_minutes, vault_id=vault_id)

    try:
        AuditLogger(db).log_action(
            action='upload_sessions_cleanup',
            status='success',
            user=current_user,
            resource_type='upload_session',
            details=result,
            ip_address=get_client_ip(request),
        )
    except Exception:
        pass  # never fail the reclaim on an audit hiccup

    return result


@app.get("/vaults/{vault_id}/files/{file_id}/download")
@require_endpoint_permission("FILE_DOWNLOAD")
@require_vault_cap("file.download")
async def download_file(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    request: Request,
    file_password: Optional[str] = None,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """
    Download a file from a vault.
    Requires vault password if vault is password-protected (via X-Vault-Password header).
    Requires file password if file is password-protected.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    try:
        # Verify vault access and password. allow_share=True: a recipient with an active
        # whole-vault share claim may open + download from the vault (read-only). SFTP
        # downloads never pass this flag.
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password,
                                        require_password=True, allow_share=True)
        # A path-scoped temp credential may only download a file within its file/folder scope.
        require_file_scope(db, current_user, vault_id, file_id)
        # A view-only share recipient may see the file but not download it (denied here).
        require_download_scope(db, current_user, vault_id, file_id)

        # Create operation ID for tracking downloads
        operation_id = f"download_{uuid.uuid4()}"
        start_operation(operation_id)
        
        try:
            # Get file info for size (before download for event broadcasting).
            # The file MUST belong to the vault it's requested through, so the vault
            # password/access gate above (checked against vault_id) actually covers
            # THIS file's vault — otherwise a member of a password-protected vault B
            # who lacks B's password could route through an own/unprotected vault A.
            file_record = db.query(File).filter(
                File.id == file_id, File.vault_id == vault_id
            ).first()
            if not file_record:
                raise HTTPException(
                    status_code=status.HTTP_404_NOT_FOUND,
                    detail="File not found"
                )

            # Per-recipient max_downloads: consume one download against the covering share claim(s)
            # BEFORE serving the bytes (an atomic conditional burn, so concurrent GETs can't exceed
            # the cap). Only for a share recipient (stamped a share scope on this vault by get_vault);
            # a no-op for owners/members/temp creds and for unlimited shares.
            if str(vault_id) in (getattr(current_user, '_share_vault_scope', None) or {}):
                if not permission_service.burn_share_download(
                        current_user, vault, file_record,
                        folder_ancestry(db, vault_id, file_record.folder_id)):
                    raise HTTPException(
                        status_code=status.HTTP_403_FORBIDDEN,
                        detail="This share has reached its download limit.")

            # Download file. allow_share=True so a whole-vault share claimant (read-only)
            # can download; SFTP downloads keep the default (False).
            file_content, file_name, mime_type = vault_service.download_file(
                file_id=file_id,
                user=current_user,
                file_password=file_password,
                allow_share=True,
            )

            # Zero-knowledge: the name is the client's secret. For a SEALED ZK file it's already
            # NULL; for a LEGACY (not-yet-migrated) ZK row the plaintext is still in the DB and
            # download_file returns it — so unconditionally use a neutral label for any
            # server-side surface (audit, monitoring broadcast, Content-Disposition). The
            # browser applies the real, decrypted name client-side. Standard vaults are unchanged.
            is_zk = _is_zk_vault(vault)
            disp_name = '(encrypted file)' if is_zk else (file_name or 'download')
            audit_name = None if is_zk else file_name

            # Audit log
            audit_logger.log_action(
                action='file_download',
                status='success',
                user=current_user,
                resource_type='file',
                resource_id=str(file_id),
                details={'vault_id': str(vault_id), 'file_name': audit_name},
                ip_address=get_client_ip(request)
            )

            # If this download came via a share claim (the recipient was stamped a share scope on this
            # vault by get_vault; owners/members are not), record a distinct share_downloaded event.
            if str(vault_id) in (getattr(current_user, '_share_vault_scope', None) or {}):
                try:
                    audit_logger.log_action(
                        action='share_downloaded', status='success', user=current_user,
                        resource_type='file', resource_id=str(file_id),
                        details={'vault_id': str(vault_id)}, ip_address=get_client_ip(request))
                except Exception:
                    db.rollback()

            # Broadcast event to monitoring WebSocket clients
            broadcast_event({
                "event": {
                    "type": "download",
                    "title": "File downloaded",
                    "description": f"{disp_name} ({file_record.size_bytes:,} bytes) downloaded from vault",
                    "user": current_user.username,
                    "ip": get_client_ip(request),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                    "operation_id": operation_id,
                    "completed": True
                },
                "traffic": {
                    "upload": 0,
                    "download": file_record.size_bytes
                }
            })
            
            # Use StreamingResponse for better download handling
            # Streams in chunks to avoid loading entire file in memory for large files
            import asyncio
            from fastapi.responses import StreamingResponse
            
            async def file_streamer():
                """Stream file content in chunks."""
                # Stream in reasonable chunks (64KB) for efficiency
                chunk_size = 65536
                offset = 0
                total_size = len(file_content)
                
                while offset < total_size:
                    chunk_end = min(offset + chunk_size, total_size)
                    chunk = file_content[offset:chunk_end]
                    yield chunk
                    offset = chunk_end
                    # Yield control to event loop
                    await asyncio.sleep(0)
            
            return StreamingResponse(
                file_streamer(),
                media_type=mime_type or 'application/octet-stream',
                headers={
                    'Content-Disposition': _content_disposition(disp_name),
                    'Content-Length': str(len(file_content)),
                    'Cache-Control': 'no-cache',
            }
        )
        
        finally:
            # Always end operation tracking
            end_operation(operation_id)
        
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except HTTPException:
        # Explicit HTTP errors (e.g. 404 file-not-found) must propagate as-is
        # rather than be re-wrapped into a generic 500 below.
        raise
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        # Broadcast error event
        try:
            broadcast_event({
                "event": {
                    "type": "error",
                    "title": "Download failed",
                    "description": f"Download error: {str(e)[:100]}",
                    "user": current_user.username if current_user else "unknown",
                    "ip": get_client_ip(request),
                    "timestamp": datetime.now(timezone.utc).isoformat()
                }
            })
        except:
            pass  # Don't fail the error handler
        import traceback
        print(f"[ERROR] Download failed - Exception type: {type(e).__name__}")
        print(f"[ERROR] Download failed - Exception message: {str(e)}")
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download file: {str(e)}"
        )


@app.post("/vaults/{vault_id}/files/{file_id}/delete")
@require_endpoint_permission("FILE_DELETE")
@require_vault_cap("file.delete")
async def delete_file(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """
    Delete a file from a vault.
    Requires vault password if vault is password-protected (via X-Vault-Password header).
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    try:
        # Verify vault access and password
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        # A path-scoped temp credential may only delete a file within its file/folder scope.
        require_file_scope(db, current_user, vault_id, file_id)

        # Get file info before deletion. The file MUST belong to the vault it's
        # deleted through, so the password/access gate above covers it (cross-vault
        # guard — otherwise B's file could be deleted by routing through vault A).
        file = db.query(File).filter(
            File.id == file_id, File.vault_id == vault_id
        ).first()
        if not file:
            raise HTTPException(status_code=404, detail="File not found")
        
        # ZK file names are NULL server-side (client-encrypted) — use a neutral label for
        # the user message; audit details file_name is redacted by AuditLogger regardless.
        file_name = file.original_name
        disp_name = file_name or '(encrypted file)'

        # Delete file
        vault_service.delete_file(file_id, current_user)

        # Audit log
        audit_logger.log_action(
            action='file_delete',
            status='success',
            user=current_user,
            resource_type='file',
            resource_id=str(file_id),
            details={'vault_id': str(vault_id), 'file_name': file_name},
            ip_address=get_client_ip(request)
        )

        # Feed the bulk-deletion detector (rapid single-file API deletions raise a BULK_FILE_DELETION
        # alert). Best-effort: monitoring must never fail the delete.
        try:
            from app.services.security_monitor import get_security_monitor
            get_security_monitor(db).record_file_deletion(str(current_user.id), str(vault_id), file_count=1)
        except Exception:
            pass

        return {'message': f'File "{disp_name}" deleted successfully'}
        
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except HTTPException:
        # Explicit HTTP errors (e.g. 404 cross-vault file) must propagate as-is
        # rather than be re-wrapped into a generic 500 below.
        raise
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to delete file: {str(e)}"
        )


@app.put("/vaults/{vault_id}/files/{file_id}/rename")
@require_endpoint_permission("FILE_DELETE")
@require_vault_cap("file.rename")
async def rename_file(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    rename_data: FileRename,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """
    Rename a file or folder in a vault.
    Requires vault password if vault is password-protected (via X-Vault-Password header).
    Requires WRITE permission on the vault.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    try:
        # Verify vault access and password
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        # A path-scoped temp credential may only rename a file/folder within its scope (this endpoint
        # is id-polymorphic — the id may be a file or a folder; rename keeps it in the same folder,
        # so the source check covers it).
        require_item_scope(db, current_user, vault_id, file_id)

        # Zero-knowledge: the new name must arrive ENCRYPTED (enc_name + name_bi) and never as
        # plaintext — mirror the upload/folder-create contract so all three write paths agree.
        if _is_zk_vault(vault):
            if rename_data.new_name:
                raise HTTPException(status_code=400, detail="A zero-knowledge rename must not send a plaintext name.")
            if not rename_data.enc_name or not rename_data.name_bi:
                raise HTTPException(status_code=400, detail="A zero-knowledge rename requires an encrypted name (enc_name + name_bi).")
            _require_zk_sealed_names(rename_data.enc_name)
            # A FOLDER rename carries the name's epoch (name_key_version); never let it pin the
            # name to a future DEK epoch no member holds yet (would make it undecryptable) —
            # same guard as create_folder/seal-names. Files send no name_key_version (their name
            # follows the content epoch, which a rename never changes).
            # Serialize the seal-epoch read+write against retire_dek_versions (which holds the SAME
            # Vault-row lock): without this a name (re)sealed at an old epoch could land in retire's
            # scan->delete window and lose its member key -> a permanently undecryptable name.
            # Same lock order as retire + upload-complete (Vault row first) -> no deadlock.
            locked_vault = db.query(Vault).filter(Vault.id == vault_id).with_for_update().first()
            _cur = getattr(locked_vault, 'dek_version', 1) or 1
            if rename_data.name_key_version is not None and int(rename_data.name_key_version) > _cur:
                raise HTTPException(status_code=400, detail="Folder name epoch is ahead of the vault's current key epoch.")

        # Renaming a FILE is a write path too: enforce the admin file-type allowlist on the new
        # name so a user can't upload an allowed type then rename it to a forbidden extension.
        # Standard vaults only (ZK renames carry an encrypted, server-invisible name); folders have
        # no file-type, so this only applies when the id resolves to a file.
        if rename_data.new_name and not _is_zk_vault(vault):
            _is_file = db.query(File.id).filter(File.id == file_id, File.vault_id == vault_id).first() is not None
            if _is_file:
                _enforce_file_type(rename_data.new_name, _upload_policy(db)[0])

        # Rename the file/folder. Scoped to the path vault: rename_file rejects an id
        # that belongs to a DIFFERENT vault (cross-vault guard, files + folders), so the
        # password/access gate above actually covers the renamed object. For ZK vaults the
        # new name arrives encrypted (enc_name + name_bi) and the server stores it verbatim.
        result = vault_service.rename_file(
            file_id, rename_data.new_name, current_user, vault_id=vault_id,
            zk_enc_name=rename_data.enc_name,
            zk_name_bi=rename_data.name_bi,
            zk_name_key_version=rename_data.name_key_version,
        )
        
        # Audit log
        audit_logger.log_action(
            action='file_rename',
            status='success',
            user=current_user,
            resource_type='file',
            resource_id=str(file_id),
            details={
                'vault_id': str(vault_id),
                'old_name': result['old_name'],
                'new_name': result['new_name'],
                'file_type': result['file_type']
            },
            ip_address=get_client_ip(request)
        )
        
        return {
            'message': f'{result["file_type"].capitalize()} renamed successfully',
            **result
        }
        
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e)
        )
    except FileNotFoundError as e:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e)
        )
    except PermissionDeniedError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e)
        )
    except IntegrityError:
        # Rename lost a race against the (vault, folder, name_bi) unique index after the
        # in-service uniqueness pre-check passed — surface it as a clean 409, not a 500.
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail="A file or folder with that name already exists in this location",
        )
    except HTTPException:
        # Deliberate 4xx (e.g. ZK plaintext-name / non-sealed-blob rejection) must
        # propagate as-is rather than be re-wrapped into a generic 500 below.
        raise
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to rename file: {str(e)}"
        )


@app.post("/vaults/{vault_id}/folders")
@require_endpoint_permission("FOLDER_MANAGE")
@require_vault_cap("folder.create")
async def create_folder(
    vault_id: uuid.UUID,
    folder_data: dict,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """
    Create a folder in a vault.
    Requires vault password if vault is password-protected (via X-Vault-Password header).
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    
    try:
        # Verify vault access and password
        vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        
        # Extract folder data
        folder_name = folder_data.get('name')
        parent_folder_id = folder_data.get('parent_folder_id')
        # A path-scoped temp credential may only create a folder INSIDE a folder within its scope
        # (creating at the vault root, parent None, is denied for a scoped credential).
        require_folder_scope(db, current_user, vault_id, parent_folder_id)

        # Zero-knowledge folders carry a browser-encrypted name + blind index (no plaintext);
        # Standard folders carry a plaintext name. Enforce the right shape per vault type.
        is_zk = _is_zk_vault(vault)
        zk_enc_name = folder_data.get('enc_name')
        zk_name_bi = folder_data.get('name_bi')
        zk_name_kv = folder_data.get('name_key_version')
        folder_client_id = None  # ZK v2: the client-supplied folder id (validated in the ZK branch)
        if is_zk:
            if not zk_enc_name or not zk_name_bi:
                raise HTTPException(
                    status_code=400,
                    detail="Zero-knowledge vaults require a client-encrypted folder name (enc_name + name_bi).",
                )
            if folder_name:
                raise HTTPException(
                    status_code=400,
                    detail="A zero-knowledge folder must not send a plaintext name.",
                )
            _require_zk_sealed_names(zk_enc_name)
            # Zero-knowledge v2 name binding: the client supplies the folder id it sealed the
            # name under (so the sealed name binds the final row id). Optional + backward-compat;
            # reject a bad/colliding id cleanly.
            if folder_data.get('id') is not None:
                try:
                    folder_client_id = uuid.UUID(str(folder_data.get('id')))
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="id must be a UUID")
                if db.query(Folder.id).filter(Folder.id == folder_client_id).first():
                    raise HTTPException(status_code=409, detail="Folder id already in use")
            # folder_data is a raw dict (untyped), so validate the client-supplied fields here
            # — a malformed value must be a clean 400, not a 500 (int()/DB DataError) below.
            if len(str(zk_name_bi)) > 64:
                raise HTTPException(status_code=400, detail="name_bi too long")
            if zk_name_kv is not None:
                try:
                    zk_name_kv = int(zk_name_kv)
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="name_key_version must be an integer")
            # A folder name must be sealed under an EXISTING epoch — never a future one (that
            # would pin it to a DEK no member holds yet, risking an undecryptable name).
            # Serialize the seal-epoch read+write against retire_dek_versions (which holds the SAME
            # Vault-row lock): without this a name sealed at an old epoch could land in retire's
            # scan->delete window and lose its member key -> a permanently undecryptable name.
            # Same lock order as retire + upload-complete (Vault row first) -> no deadlock.
            locked_vault = db.query(Vault).filter(Vault.id == vault_id).with_for_update().first()
            _cur = getattr(locked_vault, 'dek_version', 1) or 1
            if zk_name_kv is not None and zk_name_kv > _cur:
                raise HTTPException(status_code=400, detail="Folder name epoch is ahead of the vault's current key epoch.")
        elif not folder_name:
            raise HTTPException(status_code=400, detail="Folder name is required")

        # Parse parent folder ID if provided
        parent_uuid = uuid.UUID(parent_folder_id) if parent_folder_id else None

        # Create folder
        folder = vault_service.create_folder(
            vault_id=vault_id,
            name=folder_name,
            user=current_user,
            parent_folder_id=parent_uuid,
            zk_enc_name=zk_enc_name,
            zk_name_bi=zk_name_bi,
            zk_name_key_version=zk_name_kv,
            folder_id=folder_client_id,
        )
        
        # Audit log
        audit_logger.log_action(
            action='folder_create',
            status='success',
            user=current_user,
            resource_type='folder',
            resource_id=str(folder.id),
            details={'vault_id': str(vault_id), 'folder_name': folder_name},
            ip_address=get_client_ip(request)
        )
        
        return {
            # ZK folder names are NULL server-side (client-encrypted) — neutral label in the
            # message; the browser shows the real decrypted name after it reloads the listing.
            'message': f'Folder "{folder_name or "(encrypted folder)"}" created successfully',
            'folder': {
                'id': str(folder.id),
                'name': folder.name,
                'parent_folder_id': str(folder.parent_folder_id) if folder.parent_folder_id is not None else None
            }
        }
        
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e)
        )
    except DuplicateNameError as e:
        # Same-name folder already exists in this parent (pre-check or unique-index race).
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except ValueError as e:
        # A client-supplied folder id that collided (a fresh-UUID race past the pre-check) -> 409.
        if "id already in use" in str(e):
            raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail="Folder id already in use")
        raise
    except HTTPException:
        # Deliberate 4xx (e.g. ZK plaintext-name rejection, missing name) must propagate
        # as-is rather than be re-wrapped into a generic 500 below.
        raise
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to create folder: {str(e)}"
        )


@app.post("/vaults/{vault_id}/folders/{folder_id}/delete")
@require_endpoint_permission("FOLDER_MANAGE")
@require_vault_cap("folder.delete")
async def delete_folder(
    vault_id: uuid.UUID,
    folder_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """Delete a folder and everything inside it (recursive, secure file wipe)."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    try:
        vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        # A path-scoped temp credential may only delete a folder (subtree) within its scope.
        require_folder_scope(db, current_user, vault_id, folder_id)
        # folder deletion recursively wipes every file in the subtree — require DELETE
        # permission, not the mere READ that get_vault checks. Without this a read-only member
        # could destroy a whole folder tree (the per-file delete_file errors below were
        # swallowed, so the folder records were removed regardless). Owner/admin/delete-member.
        from app.core.models import VaultPermissionEnum
        if not permission_service.can_access_vault(current_user, vault_id, VaultPermissionEnum.DELETE):
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN,
                                detail="You do not have permission to delete folders in this vault")
        folder = db.query(Folder).filter(Folder.id == folder_id, Folder.vault_id == vault_id).first()
        if not folder:
            raise HTTPException(status_code=404, detail="Folder not found")
        folder_name = folder.name

        # Recurse: securely delete each file (storage + record + vault stats),
        # then remove sub-folders, then the folder itself. Returns the count of files deleted.
        def _purge(fid):
            n = 0
            for f in db.query(File).filter(File.folder_id == fid).all():
                try:
                    vault_service.delete_file(f.id, current_user)
                    n += 1
                except PermissionDeniedError:
                    # Never destroy a file the caller can't delete — abort the whole operation
                    # (defense-in-depth behind the vault-level DELETE gate above).
                    raise
                except Exception as ex:
                    print(f"Warning: failed to delete file {f.id} during folder delete: {ex}")
            for sub in db.query(Folder).filter(Folder.parent_folder_id == fid).all():
                n += _purge(sub.id)
                db.delete(sub)
            return n
        deleted_count = _purge(folder_id)
        db.delete(folder)
        db.commit()

        audit_logger.log_action(
            action='folder_delete', status='success', user=current_user,
            resource_type='folder', resource_id=str(folder_id),
            details={'vault_id': str(vault_id), 'folder_name': folder_name},
            ip_address=get_client_ip(request)
        )

        # A folder delete is the highest-throughput deletion vector — feed the whole subtree to the
        # bulk-deletion detector as ONE record (not per-file, to avoid hammering the alert row).
        # Best-effort: monitoring must never fail the delete.
        if deleted_count:
            try:
                from app.services.security_monitor import get_security_monitor
                get_security_monitor(db).record_file_deletion(str(current_user.id), str(vault_id), file_count=deleted_count)
            except Exception:
                pass

        return {'message': f'Folder "{folder_name}" deleted'}
    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail=str(e))
    except HTTPException:
        raise
    except PermissionDeniedError as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, detail=f"Failed to delete folder: {str(e)}")


# ============================================================================
# Zero-knowledge name migration (client-side sealing of legacy plaintext names)
# ----------------------------------------------------------------------------
# Existing zero-knowledge files/folders created before client-side name encryption
# still hold a PLAINTEXT name server-side. The server cannot encrypt them itself (it
# has no DEK), so a key-holding member seals them FROM THE BROWSER: it reads the
# plaintext from the listing, encrypts it under the right DEK epoch, and posts the
# blobs here. The server only ever swaps a plaintext name for the client's ciphertext
# (and NULLs the plaintext) — it never learns a name it didn't already store. Idempotent
# and convergent: the owner (who keeps every DEK epoch) seals everything on next open.
# ============================================================================

class ZkSealItem(BaseModel):
    id: uuid.UUID
    kind: str                         # 'file' | 'folder'
    enc_name: str                     # browser-encrypted name (ZK marker + base64)
    name_bi: str = Field(..., max_length=64)  # client blind index (stored in a VARCHAR(64))
    enc_mime: Optional[str] = None    # files only
    name_key_version: Optional[int] = None  # folders: the DEK epoch the name is sealed under


class ZkSealRequest(BaseModel):
    # Bound the batch so one request can't drive an unbounded per-item DB scan.
    items: List[ZkSealItem] = Field(..., max_length=1000)


@app.post("/vaults/{vault_id}/zk/seal-names")
@require_endpoint_permission("FILE_UPLOAD")
@require_vault_cap("file.upload")
async def zk_seal_names(
    vault_id: uuid.UUID,
    body: ZkSealRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Seal legacy plaintext names of EXISTING zero-knowledge objects with the client's
    ciphertext. Only converts a still-plaintext (unsealed) row to its encrypted form; an
    already-ZK-sealed row is left untouched (so this can't be used to overwrite a name).
    Requires WRITE on the vault; only valid for zero-knowledge vaults."""
    from app.core.security import is_zk_sealed_name
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
    if not _is_zk_vault(vault):
        raise HTTPException(status_code=400, detail="Name sealing applies only to zero-knowledge vaults")
    permission_service.require_vault_permission(current_user, vault_id, VaultPermissionEnum.WRITE)
    # Serialize the seal-epoch read + the seal writes against retire_dek_versions (which holds the SAME
    # Vault-row lock): without it a name sealed at an old epoch could land in retire's scan->delete
    # window and lose its member key -> a permanently undecryptable name. Same lock order (Vault row
    # first) as retire / rename / upload-complete -> no deadlock. Held through the commit below.
    locked_vault = db.query(Vault).filter(Vault.id == vault_id).with_for_update().first()
    # Fall back to the already-validated vault object if the row vanished between fetch and lock
    # (concurrent delete) so the epoch read keeps its original non-None semantics.
    current_epoch = getattr(locked_vault or vault, 'dek_version', 1) or 1

    sealed = 0
    for it in body.items:
        # A scoped credential may only seal names of in-scope objects (skip the rest, as with
        # any other non-applicable item). require_item_scope is a no-op for a whole-vault cred.
        try:
            require_item_scope(db, current_user, vault_id, it.id)
        except PermissionDeniedError:
            continue
        if not it.enc_name or not it.name_bi:
            continue
        # The blob must be a real sealed 'zk1:' ciphertext (server-enforced marker), and a
        # folder name must not be sealed under a future epoch (a DEK no member holds yet).
        if not is_zk_sealed_name(it.enc_name):
            continue
        if it.enc_mime and not is_zk_sealed_name(it.enc_mime):
            continue
        if it.kind == 'folder':
            kv = int(it.name_key_version) if it.name_key_version else 1
            if kv > current_epoch:
                continue
            obj = db.query(Folder).filter(Folder.id == it.id, Folder.vault_id == vault_id).first()
            if not obj or is_zk_sealed_name(obj.enc_name):
                continue  # gone, wrong vault, or already sealed — never overwrite a sealed name
            obj.enc_name = it.enc_name
            obj.name_bi = it.name_bi
            obj.name_key_version = kv
            obj.name = None
            sealed += 1
        elif it.kind == 'file':
            obj = db.query(File).filter(File.id == it.id, File.vault_id == vault_id).first()
            if not obj or is_zk_sealed_name(obj.enc_name):
                continue
            obj.enc_name = it.enc_name
            obj.name_bi = it.name_bi
            if it.enc_mime:
                obj.enc_mime = it.enc_mime
            obj.name = None
            obj.original_name = None
            obj.mime_type = None
            sealed += 1
    if sealed:
        db.commit()
    return {"status": "ok", "sealed": sealed}


@app.get("/dashboard/stats", response_model=DashboardStats)
async def get_dashboard_stats(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Get dashboard statistics (admin only).
    """
    from app.core.models import Vault, File, ActiveSession
    from sqlalchemy import func
    
    total_users = db.query(func.count(User.id)).scalar()
    total_vaults = db.query(func.count(Vault.id)).scalar()
    total_files = db.query(func.count(File.id)).scalar()
    total_storage = db.query(func.sum(File.size_bytes)).scalar() or 0
    active_sessions = db.query(func.count(ActiveSession.id)).filter(
        ActiveSession.is_active == True
    ).scalar()
    
    return DashboardStats(
        total_users=total_users,
        total_vaults=total_vaults,
        total_files=total_files,
        total_storage_bytes=total_storage,
        active_sessions=active_sessions
    )


@app.post("/api/logout")
async def logout(
    request: Request,
    response: Response,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Logout user and invalidate session."""
    from app.core.models import ActiveSession
    
    # Get JWT token from request
    token = request.headers.get('Authorization', '').replace('Bearer ', '')
    payload = verify_access_token(token)
    
    session_invalidated = False
    if payload:
        session_token = payload.get("session_token")
        if session_token:
            # Invalidate session in database
            session = db.query(ActiveSession).filter(
                ActiveSession.session_token == session_token
            ).first()
            if session:
                session.is_active = False
                # Durable revocation: rejected per-request even if the Redis denylist read
                # fails open during an outage (get_current_user checks ActiveSession.revoked).
                session.revoked = True
                db.commit()
                session_invalidated = True
                print(f"🔓 Session invalidated for user {current_user.username} (session_token: {session_token[:16]}...)")
            else:
                print(f"⚠️ Session not found in database for token {session_token[:16]}...")
            # Denylist the token so it stops working IMMEDIATELY for the rest of its life
            # (regular-user JWTs aren't re-validated against the session row each request).
            import time as _time
            from app.services.auth_service import denylist_token
            _ttl = int(payload.get("exp", 0) - _time.time())
            denylist_token(session_token, _ttl if _ttl > 0 else 1800)
        else:
            print(f"⚠️ No session_token in JWT payload for user {current_user.username}")
    
    # Clear all site data using Clear-Site-Data header
    response.headers["Clear-Site-Data"] = '"cache", "cookies", "storage"'
    
    # Delete auth cookies
    response.delete_cookie("dockvault_token")
    response.delete_cookie("dockvault_user")
    
    # Log logout event
    client_ip = get_client_ip(request)
    audit_logger = AuditLogger(db)
    audit_logger.log_logout(current_user, client_ip)
    
    broadcast_event({
        "event": {
            "type": "logout",
            "title": "User logged out",
            "description": f"{current_user.username} logged out",
            "user": current_user.username,
            "ip": client_ip,
            "timestamp": datetime.now(timezone.utc).isoformat()
        }
    })
    
    return {"message": "Logged out successfully", "session_invalidated": session_invalidated}


@app.get("/api/monitoring/metrics")
async def get_monitoring_metrics(
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Get real-time monitoring metrics for the live monitor dashboard.
    
    Performance: Supports ETag caching (polled every 10s as WebSocket backup).
    Returns 304 Not Modified when metrics unchanged, reducing polling overhead.
    """
    from app.core.models import ActiveSession, TemporaryCredential, File, AuditLog
    from sqlalchemy import func, distinct
    from datetime import datetime, timedelta
    
    try:
        # Grace period for active sessions (65 minutes)
        grace_cutoff = datetime.now(timezone.utc) - timedelta(minutes=65)
        
        # Active users (sessions active within grace period)
        active_users = db.query(func.count(distinct(ActiveSession.user_id))).filter(
            ActiveSession.is_active == True,
            ActiveSession.last_activity >= grace_cutoff
        ).scalar() or 0
        
        # Total temporary credentials
        total_temp_creds = db.query(func.count(TemporaryCredential.id)).filter(
            TemporaryCredential.expires_at > datetime.now(timezone.utc)
        ).scalar() or 0
        
        # Active temporary credentials (with active sessions)
        active_temp_creds = db.query(func.count(distinct(TemporaryCredential.id))).join(
            ActiveSession, ActiveSession.temp_credential_id == TemporaryCredential.id
        ).filter(
            TemporaryCredential.expires_at > datetime.now(timezone.utc),
            ActiveSession.is_active == True,
            ActiveSession.last_activity >= grace_cutoff
        ).scalar() or 0
        
        # Traffic in last hour (from audit logs)
        # Note: AuditLog doesn't have bytes_transferred field yet
        # For now, return 0 - will be implemented when field is added
        one_hour_ago = datetime.now(timezone.utc) - timedelta(hours=1)
        
        # Count upload/download actions as a proxy for traffic
        upload_count = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "upload",
            AuditLog.timestamp >= one_hour_ago
        ).scalar() or 0
        
        download_count = db.query(func.count(AuditLog.id)).filter(
            AuditLog.action == "download",
            AuditLog.timestamp >= one_hour_ago
        ).scalar() or 0
        
        # Return counts for now (can be converted to estimated bytes later)
        upload_traffic = upload_count * 1024 * 1024  # Estimate: 1MB per upload
        download_traffic = download_count * 1024 * 1024  # Estimate: 1MB per download
        
        # Active operations (for now, return 0 - will be implemented via WebSocket)
        active_operations = 0
        
        # Total files
        total_files = db.query(func.count(File.id)).scalar() or 0
        
        metrics_data = {
            "activeUsers": active_users,
            "tempCreds": total_temp_creds,
            "tempCredsActive": active_temp_creds,
            "uploadTraffic": upload_traffic,
            "downloadTraffic": download_traffic,
            "activeOperations": active_operations,
            "totalFiles": total_files
            # Timestamp removed: Including timestamp prevents ETag caching since it changes every request
            # Frontend can add timestamp when displaying if needed
        }
        
        # Use conditional response with ETag for 10s polling optimization
        return handle_conditional_response(request, metrics_data)
        
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching metrics: {str(e)}")


@app.post("/api/operations/{operation_id}/cancel")
async def cancel_operation(
    operation_id: str,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Cancel an active operation (upload/download).
    Requires authentication.
    """
    from app.services.activity_monitor import ProgressTracker

    tracker = ProgressTracker()
    # Only the operation's owner (or an admin) may cancel it — a leaked operation id must not
    # let one user abort another principal's transfer.
    if tracker.cancel_operation(
        operation_id,
        requester_id=str(current_user.id),
        # A temp credential is not a full admin: it may cancel only its own operations.
        is_admin=(current_user.role == RoleEnum.ADMIN and not getattr(current_user, "_is_temp_session", False)),
    ):
        # Broadcast cancellation event with operation_id
        broadcast_event({
            "event": {
                "type": "operation_cancelled",
                "title": "Operation cancelled",
                "description": f"Operation cancelled by {current_user.username}",
                "user": current_user.username,
                "ip": get_client_ip(request),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation_id": operation_id,  # Include operation_id
                "cancelled": True
            }
        })
        
        return {"message": "Operation cancelled successfully"}
    else:
        raise HTTPException(
            status_code=404,
            detail="Operation not found or already completed"
        )


# ============================================================================
# SECURITY MONITORING ENDPOINTS
# ============================================================================

@app.get("/api/security/metrics")
async def get_security_metrics(
    hours: int = 24,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Get security metrics for dashboard display.
    
    Returns:
        - Failed login count
        - Successful login count
        - Login success rate
        - Critical/warning alert counts
        - Top failed login IPs
    
    Requires admin privileges.
    """
    try:
        from app.services.security_monitor import get_security_monitor
        
        monitor = get_security_monitor(db)
        metrics = monitor.get_security_metrics(hours=hours)
        
        return metrics
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching security metrics: {str(e)}")


@app.get("/api/security/alerts")
async def get_security_alerts(
    limit: int = 50,
    severity: Optional[str] = None,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Get recent security alerts.
    
    Query Parameters:
        - limit: Maximum number of alerts (default 50)
        - severity: Filter by severity (info, warning, critical)
    
    Returns list of security alerts.
    Requires admin privileges.
    """
    try:
        from app.services.security_monitor import get_security_monitor
        
        monitor = get_security_monitor(db)

        # Opportunistically prune old RESOLVED alerts (throttled process-wide to once/hour, reads the
        # retention setting). Do it BEFORE fetching: cleanup commits, and expire_on_commit would
        # otherwise expire the fetched rows -> a just-deleted one raises ObjectDeletedError on
        # serialization. Best-effort: never let cleanup fail the alerts view.
        try:
            monitor.cleanup_old_alerts()
        except Exception:
            # A failed cleanup DELETE/commit aborts the transaction; roll back so the shared session
            # stays usable for the fetch below (mirrors _raise_alert's except pattern) -- else the
            # next SELECT raises "current transaction is aborted" and 500s the view.
            db.rollback()

        alerts = monitor.get_recent_alerts(limit=limit, severity=severity)

        # Convert to dict for JSON response
        return {
            "alerts": [
                {
                    "id": str(alert.id),
                    "event_type": alert.event_type,
                    "severity": alert.severity,
                    "message": alert.message,
                    "username": alert.username,
                    "ip_address": alert.ip_address,
                    "timestamp": alert.timestamp.isoformat(),
                    "resolved": alert.resolved,
                    "resolved_at": alert.resolved_at.isoformat() if alert.resolved_at is not None else None,
                    "resolved_by": alert.resolved_by,
                    "details": alert.details
                }
                for alert in alerts
            ]
        }
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error fetching security alerts: {str(e)}")


@app.post("/api/security/alerts/{alert_id}/resolve")
async def resolve_security_alert(
    alert_id: str,
    notes: Optional[str] = None,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Mark a security alert as resolved.
    
    Body:
        - notes: Optional resolution notes
    
    Requires admin privileges.
    """
    try:
        from app.services.security_monitor import get_security_monitor
        
        monitor = get_security_monitor(db)
        # Convert current_user.username from Column to string using getattr
        username = str(current_user.username) if hasattr(current_user, 'username') else 'unknown'
        monitor.resolve_alert(alert_id, username, notes)
        
        return {"message": "Alert resolved successfully"}
    except Exception as e:
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Error resolving security alert: {str(e)}")


@app.get("/api/security/user-activity/{user_id}")
async def get_user_security_activity(
    user_id: str,
    hours: int = 24,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Analyze a user's security activity for unusual patterns.
    
    Returns:
        - Total actions
        - Actions by type
        - Actions by hour
        - Failed actions count
        - IP addresses used
        - Vaults accessed
        - Detected anomalies
    
    Requires admin privileges.
    """
    # Coerce the path id to a UUID up front: the param is typed `str` (so FastAPI does not 422),
    # but it is compared against the UUID column audit_logs.user_id — a non-UUID string would cast
    # `::UUID` inside the query and psycopg2's error text (the full SELECT + schema) would surface
    # in the 500 detail below. Reject a malformed id with a 400 that carries no internal detail.
    try:
        user_id = str(uuid.UUID(str(user_id)))
    except (ValueError, AttributeError, TypeError):
        raise HTTPException(status_code=400, detail="Invalid user id")
    try:
        from app.services.security_monitor import get_security_monitor

        monitor = get_security_monitor(db)
        analysis = monitor.analyze_user_activity(user_id, hours=hours)

        return analysis
    except Exception as e:
        # Never echo str(e) — it can embed SQL / schema / storage paths. Log server-side, return generic.
        error_id = str(uuid.uuid4())
        print(f"[ERROR] user-activity analysis failed (ID: {error_id}): {e}")
        traceback.print_exc()
        raise HTTPException(status_code=500,
                            detail="An internal error occurred while analyzing user activity.")


# ============================================================================
# PERMISSION MANAGEMENT ENDPOINTS
# ============================================================================

@app.get("/permissions/groups", response_model=List[EndpointPermissionGroupResponse])
async def get_permission_groups(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Get all available functionality groups (admin only).
    Returns comprehensive list of all endpoint groups that can be granted to users.
    """
    from app.core.api_catalog import API_CATALOG, RoleRequirement
    
    groups = []
    for group_name, group in API_CATALOG.items():
        # Convert endpoints to dict format
        endpoints = [
            {
                'method': ep.method,
                'path': ep.path,
                'description': ep.description,
                'role_requirement': ep.role_requirement.value,
                'requires_ownership': ep.requires_ownership,
                'resource_type': ep.resource_type,
                'ui_widgets': ep.ui_widgets
            }
            for ep in group.endpoints
        ]
        
        groups.append(EndpointPermissionGroupResponse(
            name=group.name,
            display_name=group.display_name,
            description=group.description,
            ui_section=group.ui_section,
            default_for_roles=[role.value if hasattr(role, 'value') else str(role) for role in group.default_for_roles],
            endpoint_count=len(group.endpoints),
            endpoints=endpoints,
            dependencies=group.dependencies
        ))
    
    return groups


@app.get("/permissions/users/{user_id}", response_model=UserPermissionsResponse)
async def get_user_permissions(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get all permissions for a specific user.
    Users can access their own permissions, admins can access any user's permissions.
    For admin users, returns all permission groups as granted.
    """
    from app.core.endpoint_permissions import get_user_permissions as get_perms
    from app.core.api_catalog import API_CATALOG
    
    # Authorization: users see only their own permissions; a real (interactive) admin can see anyone's.
    # A temporary credential — even one owned by an admin — is treated as non-admin here, so it can
    # only read its OWN permission set (consistent with require_interactive_admin).
    _perms_is_admin = current_user.role == RoleEnum.ADMIN and not getattr(current_user, "_is_temp_session", False)
    if not _perms_is_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own permissions"
        )
    
    # Get target user
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )
    
    # Get user's permissions from database
    permissions = get_perms(str(user_id), db)
    
    # Group by endpoint_group to get granted groups
    granted_groups = list(set(perm['endpoint_group'] for perm in permissions))
    
    # If target user is admin, they have ALL permissions by role
    if target_user.role == RoleEnum.ADMIN:
        # Return all groups from API_CATALOG as granted for admins
        granted_groups = list(API_CATALOG.keys())
    
    return UserPermissionsResponse(
        user_id=target_user.id,
        username=target_user.username,
        email=target_user.email,
        role=str(target_user.role),
        granted_groups=granted_groups,
        permissions=permissions
    )


@app.post("/permissions/users/{user_id}/grant")
async def grant_user_permission(
    user_id: uuid.UUID,
    request: GrantPermissionRequest,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Grant a functionality group to a user (admin only).
    """
    from app.core.endpoint_permissions import grant_endpoint_permission
    from app.core.api_catalog import API_CATALOG
    
    # Validate user exists
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )
    
    # Validate group exists
    if request.endpoint_group not in API_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid endpoint group: {request.endpoint_group}"
        )
    
    try:
        # Grant permission
        grant_endpoint_permission(
            user_id=str(user_id),
            endpoint_group=request.endpoint_group,
            db=db,
            granted_by=str(current_user.id)
        )
        
        # Log the action
        audit_logger = AuditLogger(db)
        audit_logger.log_action(
            action='GRANT_PERMISSION',
            status='success',
            user=current_user,
            resource_type='permission',
            resource_id=str(user_id),
            details={
                'endpoint_group': request.endpoint_group,
                'target_user': target_user.username
            }
        )
        
        group = API_CATALOG[request.endpoint_group]
        return {
            'status': 'success',
            'message': f'Granted {group.display_name} permissions to {target_user.username}',
            'endpoint_group': request.endpoint_group,
            'endpoint_count': len(group.endpoints)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error granting permission: {str(e)}"
        )


@app.delete("/permissions/users/{user_id}/revoke/{group_name}")
async def revoke_user_permission(
    user_id: uuid.UUID,
    group_name: str,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """
    Revoke a functionality group from a user (admin only).
    """
    from app.core.endpoint_permissions import revoke_endpoint_permission
    from app.core.api_catalog import API_CATALOG
    
    # Validate user exists
    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found"
        )
    
    # Validate group exists
    if group_name not in API_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid endpoint group: {group_name}"
        )
    
    try:
        # Revoke permission
        revoke_endpoint_permission(
            user_id=str(user_id),
            endpoint_group=group_name,
            db=db
        )
        
        # Log the action
        audit_logger = AuditLogger(db)
        audit_logger.log_action(
            action='REVOKE_PERMISSION',
            status='success',
            user=current_user,
            resource_type='permission',
            resource_id=str(user_id),
            details={
                'endpoint_group': group_name,
                'target_user': target_user.username
            }
        )
        
        group = API_CATALOG[group_name]
        return {
            'status': 'success',
            'message': f'Revoked {group.display_name} permissions from {target_user.username}',
            'endpoint_group': group_name,
            'endpoint_count': len(group.endpoints)
        }
    
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Error revoking permission: {str(e)}"
        )


# ============================================================================
# STARTUP/SHUTDOWN & STATIC FILES
# ============================================================================

# Startup/Shutdown Events
from contextlib import asynccontextmanager
import asyncio

async def cleanup_expired_sessions():
    """Background task to periodically clean up expired sessions."""
    from app.core.models import ActiveSession, RateLimitRecord, User
    from app.core.database import get_db_context

    while True:
        try:
            # Run cleanup every 5 minutes
            await asyncio.sleep(300)

            grace_minutes = int(os.getenv('TEMP_CRED_SESSION_GRACE_MINUTES', '65'))
            grace_cutoff = datetime.now(timezone.utc) - timedelta(minutes=grace_minutes)

            with get_db_context() as db:
                # Auto-unlock accounts whose failed-login lockout TTL has elapsed (locked_until
                # in the past). authenticate_user also unlocks on the spot, but this clears the
                # flag proactively so the inline is_locked checks (SFTP key auth, etc.) see it.
                unlocked = db.query(User).filter(
                    User.is_locked == True,  # noqa: E712
                    User.locked_until.isnot(None),
                    User.locked_until < datetime.utcnow(),
                ).update(
                    {"is_locked": False, "failed_login_attempts": 0, "locked_until": None},
                    synchronize_session=False,
                )
                if unlocked:
                    db.commit()
                    print(f"🔓 Auto-unlocked {unlocked} account(s) past their lockout TTL")

                # Find sessions that are still marked active but have expired
                expired_sessions = db.query(ActiveSession).filter(
                    ActiveSession.is_active == True,
                    ActiveSession.last_activity < grace_cutoff
                ).all()

                if expired_sessions:
                    for session in expired_sessions:
                        session.is_active = False
                    db.commit()
                    print(f"🧹 Cleaned up {len(expired_sessions)} expired session(s)")

                # Prune stale DB-backed login-throttle rows (only written when Redis
                # is down). Their window is minutes; anything older than an hour is
                # dead and would otherwise accumulate one row per distinct
                # username/IP seen during an outage. Bounds the table's growth.
                rl_cutoff = datetime.utcnow() - timedelta(hours=1)
                pruned = db.query(RateLimitRecord).filter(
                    RateLimitRecord.window_start < rl_cutoff
                ).delete(synchronize_session=False)
                if pruned:
                    db.commit()
                    print(f"🧹 Pruned {pruned} stale rate-limit record(s)")

                # Prune abandoned chunked-upload sessions AND reclaim their buffered chunks
                # on disk. A terminal/expired session holds the plaintext filename/MIME as
                # transfer working state, and its raw chunks sit under _uploads/<sid>/. The
                # deployment-wide sweep deletes those rows and rmtrees the matching dirs
                # (including orphaned dirs left by a crash between row-delete and rmtree),
                # while always keeping active, unexpired sessions so an in-flight upload is
                # never destroyed. No idle threshold here — the periodic pass is the safe,
                # automatic backstop; the operator endpoint handles force-reclaim.
                try:
                    swept = _sweep_orphaned_upload_chunks(db)
                    if swept['rows_pruned'] or swept['dirs_removed']:
                        print(
                            f"🧹 Reclaimed {swept['rows_pruned']} chunked-upload row(s) and "
                            f"{swept['dirs_removed']} chunk dir(s) "
                            f"({swept['bytes_reclaimed']:,} bytes)"
                        )
                except Exception as sweep_err:
                    print(f"⚠ chunked-upload sweep failed: {sweep_err}")

        except Exception as e:
            print(f"❌ Error in session cleanup task: {e}")

def _seed_admin_user():
    """
    Bootstrap an admin user from ADMIN_USERNAME/ADMIN_PASSWORD when no users
    exist yet. This lets env-configured (Docker) deployments log in without
    running the interactive setup wizard. No-op if an admin already exists or
    no admin password is configured.
    """
    try:
        from app.core.database import get_db_context
        from app.services.auth_service import AuthService
        from app.core.models import RoleEnum, User

        # Match the app/core/config.py guard's emptiness definition: a whitespace-only value is "blank"
        # (the post-bootstrap no-op state), not a credential to seed.
        if not (settings.admin_password or "").strip():
            return
        with get_db_context() as db:
            if db.query(User).filter(User.username == settings.admin_username).first():
                return
            AuthService(db).create_user(
                username=settings.admin_username,
                email=settings.admin_email or "admin@local",
                password=settings.admin_password,
                role=RoleEnum.ADMIN,
            )
            print(f"[OK] Bootstrapped admin user '{settings.admin_username}' from environment")
    except Exception as e:
        print(f"⚠ Admin bootstrap skipped: {e}")


def _backfill_default_permissions():
    """Grant role-default endpoint permissions to existing non-admin users
    (idempotent). Picks up newly-added defaults such as temp-credential
    self-service for the 'user' role without needing the user to be recreated."""
    try:
        from app.core.database import get_db_context
        from app.core.endpoint_permissions import grant_default_permissions_for_role
        from app.core.models import RoleEnum, User
        with get_db_context() as db:
            users = db.query(User).filter(User.role != RoleEnum.ADMIN).all()
            for u in users:
                grant_default_permissions_for_role(str(u.id), u.role.value, db)
            print(f"[OK] Backfilled default permissions for {len(users)} non-admin user(s)")
    except Exception as e:
        print(f"⚠ Permission backfill skipped: {e}")


def _run_lightweight_migrations():
    """Idempotent column additions for existing tables. create_all() only creates
    missing TABLES, not missing COLUMNS, so new columns on existing tables must be
    added here (Postgres ADD COLUMN IF NOT EXISTS makes this safe to re-run)."""
    try:
        from app.core.database import get_db_context
        from sqlalchemy import text
        statements = [
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS unlock_remember_minutes INTEGER",
            # Per-vault confidentiality tier; 'standard' = today's server-encrypted,
            # SFTP-capable vault (zero-knowledge slots in later, web-only).
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS type VARCHAR(20) NOT NULL DEFAULT 'standard'",
            # Delegated vault administration: a member with manage_permission is a "Manager".
            "ALTER TABLE vault_members ADD COLUMN IF NOT EXISTS manage_permission BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS folder_id UUID",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS note VARCHAR(500)",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS can_create_temp_credentials BOOLEAN DEFAULT FALSE",
            # Least-privilege scope for temp credentials (the temp_credential_vault_access
            # TABLE itself is created by create_all; only new COLUMNS need an ALTER).
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS scope JSONB",
            # Optional per-file/folder ID scope on a selected-mode vault grant (NULL = whole vault).
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS scope_ids JSONB",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS vault_access_mode VARCHAR(10) DEFAULT 'selected'",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS created_by_temp_credential_id UUID",
            # Per-vault SFTP password proof: fingerprint of the vault password hash proven
            # when this grant was minted (re-checked on SFTP access; voided by a rotation).
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS vault_password_fingerprint VARCHAR(64)",
            # Temporary passcode verifier on a selected-mode standard-vault grant (a second access
            # gate; NULL = no passcode). Content is not re-encrypted — this is authorization only.
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS passcode_hash VARCHAR(255)",
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS passcode_kind VARCHAR(16)",
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS passcode_max_uses INTEGER",
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS passcode_use_count INTEGER NOT NULL DEFAULT 0",
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS passcode_expires_at TIMESTAMP",
            # Per-account SFTP controls (the user_ssh_keys TABLE is created by create_all).
            # Auth/session hardening: time-boxed account auto-unlock + durable session
            # revocation (web logout/lock survives a Redis outage). Both additive + idempotent.
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS locked_until TIMESTAMP",
            "ALTER TABLE active_sessions ADD COLUMN IF NOT EXISTS revoked BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS sftp_enabled BOOLEAN NOT NULL DEFAULT TRUE",
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS sftp_password_auth BOOLEAN NOT NULL DEFAULT TRUE",
            # DB-backed login throttle (RateLimitRecord, used when Redis is down):
            # first collapse any duplicate (identifier, action) rows, then add the
            # UNIQUE constraint the ON CONFLICT upsert relies on. create_all adds it
            # on a fresh DB; this backfills it on an existing one. Both idempotent.
            """DELETE FROM rate_limit_records WHERE id IN (
                   SELECT id FROM (
                       SELECT id, ROW_NUMBER() OVER (
                           PARTITION BY identifier, action
                           ORDER BY window_start DESC, id DESC) AS rn
                       FROM rate_limit_records) t
                   WHERE t.rn > 1)""",
            """DO $$ BEGIN
                   IF NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'uq_rate_limit_identifier_action') THEN
                       ALTER TABLE rate_limit_records
                           ADD CONSTRAINT uq_rate_limit_identifier_action
                           UNIQUE (identifier, action);
                   END IF;
               END $$;""",
            # Filename/MIME encryption at rest (Standard vaults). enc_* hold AES-GCM
            # blobs; name_bi is the per-vault HMAC blind index for lookups. The plaintext
            # name columns become NULLABLE (sealed rows NULL them). create_all adds the
            # columns/index on a fresh DB; these backfill them on an existing one. A
            # one-time eager backfill of existing rows runs in _backfill_encrypted_names.
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_name TEXT",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS enc_mime TEXT",
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS name_bi VARCHAR(64)",
            "CREATE INDEX IF NOT EXISTS ix_files_name_bi ON files (name_bi)",
            "ALTER TABLE files ALTER COLUMN name DROP NOT NULL",
            "ALTER TABLE files ALTER COLUMN original_name DROP NOT NULL",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS enc_name TEXT",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS name_bi VARCHAR(64)",
            "CREATE INDEX IF NOT EXISTS ix_folders_name_bi ON folders (name_bi)",
            "ALTER TABLE folders ALTER COLUMN name DROP NOT NULL",
            # Zero-knowledge DEK rotation (forward-only versioning). dek_version is the
            # vault's current ZK DEK epoch; backfills every existing vault to 1, matching
            # the existing key_version=1 member rows. Separate from vaults.key_version
            # (Standard Fernet counter). zk_key_version on a chunked session carries the
            # client-declared epoch through to finalize for the upload-vs-rekey race check.
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS dek_version INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS zk_key_version INTEGER",
            # Backfill any legacy NULL/0 per-vault size_limit to the 1 GB default: such a vault
            # reserves nothing in the account budget SUM yet is treated as UNLIMITED at every upload
            # guard (`if vault.size_limit`), so the reservation model would under-count it. Idempotent.
            "UPDATE vaults SET size_limit = 1073741824 WHERE size_limit IS NULL OR size_limit <= 0",
            # Hierarchical ZK key wrapping (VaultTeamKey). team_public_key = the per-vault team
            # public key; team_key_version = the team-KEYPAIR epoch, SEPARATE from dek_version
            # (bumps only on a team-keypair rotation, not a routine DEK rotation). team_key (the
            # DEK->team-pubkey wrap map) + key_wrapping_mode already exist. Additive; default
            # mode stays 'direct' so existing vaults are untouched. See docs/vault-zk-team-key-design.md.
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS team_public_key TEXT",
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS team_key_version INTEGER NOT NULL DEFAULT 1",
            # Zero-knowledge filename/MIME encryption (client-side, vault DEK). ZK file/folder
            # names are encrypted IN THE BROWSER and stored in the SAME enc_name/enc_mime/
            # name_bi columns as Standard names (distinguished by the security.ZK_NAME_PREFIX
            # marker); only NEW columns/nullability need backfilling here:
            #  - chunked sessions carry the client-encrypted name through to finalize, and
            #    their plaintext `filename` is NULL for ZK (so make it nullable);
            #  - folders gain name_key_version (the DEK epoch a ZK folder name is sealed under).
            "ALTER TABLE chunked_upload_sessions ALTER COLUMN filename DROP NOT NULL",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS enc_name TEXT",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS enc_mime TEXT",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS name_bi VARCHAR(64)",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS name_key_version INTEGER",
            # Harden vault_member_keys.key_version like dek_version: the version-aware
            # get_vault_keys read matches on key_version == epoch, so a NULL would make a row
            # unfetchable. Backfill any NULL to 1, then enforce default+NOT NULL. Must run
            # BEFORE the unique-constraint swap below (which keys on key_version).
            "UPDATE vault_member_keys SET key_version = 1 WHERE key_version IS NULL",
            "ALTER TABLE vault_member_keys ALTER COLUMN key_version SET DEFAULT 1",
            "ALTER TABLE vault_member_keys ALTER COLUMN key_version SET NOT NULL",
            # Widen the per-member-key uniqueness from (vault, user) to (vault, user,
            # key_version) so a member can hold one active wrapped row per DEK epoch they
            # still need to read old files. MUST be atomic with the index rebuild: every
            # existing row is key_version=1 and stays unique under the wider key, so the
            # swap is back-compat. One DO block = one transaction (no constraint gap).
            """DO $$ BEGIN
                   IF EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'uq_vault_member_key') THEN
                       ALTER TABLE vault_member_keys DROP CONSTRAINT uq_vault_member_key;
                   END IF;
                   IF NOT EXISTS (SELECT 1 FROM pg_constraint
                       WHERE conname = 'uq_vault_member_key_version') THEN
                       ALTER TABLE vault_member_keys
                           ADD CONSTRAINT uq_vault_member_key_version
                           UNIQUE (vault_id, user_id, key_version);
                   END IF;
                   DROP INDEX IF EXISTS idx_vault_member_key_active;
                   CREATE INDEX IF NOT EXISTS idx_vault_member_key_active
                       ON vault_member_keys (vault_id, user_id, key_version, is_active);
               END $$;""",
            # A member has at most one vault_members row per (vault, user). Dedup any pre-existing
            # duplicate rows (from a concurrent double-grant race) keeping one deterministically, then
            # add the composite unique so the grant upsert can funnel concurrent grants to a single row.
            # One DO block = one transaction (no constraint gap between the dedup and the ADD).
            """DO $$ BEGIN
                   DELETE FROM vault_members a USING vault_members b
                       WHERE a.ctid < b.ctid AND a.vault_id = b.vault_id AND a.user_id = b.user_id;
                   IF NOT EXISTS (SELECT 1 FROM pg_constraint WHERE conname = 'uq_vault_members_vault_user') THEN
                       ALTER TABLE vault_members
                           ADD CONSTRAINT uq_vault_members_vault_user UNIQUE (vault_id, user_id);
                   END IF;
               END $$;""",
        ]
        with get_db_context() as db:
            for stmt in statements:
                try:
                    db.execute(text(stmt))
                    db.commit()
                except Exception as e:
                    db.rollback()
                    print(f"⚠ Migration step skipped ({stmt}): {e}")
    except Exception as e:
        print(f"⚠ Lightweight migrations skipped: {e}")


def _backfill_encrypted_names():
    """One-time, idempotent eager encryption of existing plaintext file/folder names in
    STANDARD vaults (so names already on disk before this version stop being stored in
    the clear). Rows already sealed (enc_name set), zero-knowledge vaults, and rows with
    no plaintext name are skipped — safe to re-run. Runs after the columns exist."""
    try:
        from app.core.database import get_db_context
        from app.core.models import File, Folder, Vault
        from app.services.vault_service import _seal_named_object
        BATCH = 500
        with get_db_context() as db:
            # Only STANDARD vaults are sealed (ZK names are deferred). Load just those
            # vaults (few per deployment) and filter the row queries by their ids so the
            # batched loop makes progress (sealed rows drop out via enc_name IS NULL) and
            # never re-fetches a skipped non-standard row.
            vaults = {v.id: v for v in db.query(Vault).filter(Vault.type == 'standard').all()}
            if not vaults:
                return
            std_ids = list(vaults.keys())
            total = 0
            for model, is_file in ((File, True), (Folder, False)):
                plain_col = model.original_name if is_file else model.name
                while True:
                    rows = (db.query(model)
                            .filter(model.enc_name.is_(None),
                                    plain_col.isnot(None),
                                    model.vault_id.in_(std_ids))
                            .limit(BATCH).all())
                    if not rows:
                        break
                    for obj in rows:
                        _seal_named_object(vaults[obj.vault_id], obj, is_file=is_file)
                        total += 1
                    db.commit()  # bounded memory + a small transaction per batch
            if total:
                print(f"[OK] Backfilled encrypted names for {total} file/folder row(s)")
    except Exception as e:
        print(f"⚠ Encrypted-name backfill skipped: {e}")


# The fixed sentinel a NULL folder_id / parent_folder_id is folded to inside the name
# unique indexes, so two vault-ROOT items with the same name still collide (Postgres treats
# NULLs as distinct otherwise). MUST match app/core/models.py File/Folder __table_args__ exactly.
_NAME_UNIQ_NULL_FK = "'00000000-0000-0000-0000-000000000000'::uuid"


def _add_name_uniqueness():
    """Create the partial UNIQUE indexes that back-stop filename dedup at the DB layer:
      files   — UNIQUE (vault_id, COALESCE(folder_id, 0), name_bi)        WHERE name_bi NOT NULL
      folders — UNIQUE (vault_id, COALESCE(parent_folder_id, 0), name_bi) WHERE name_bi NOT NULL
    Idempotent (CREATE ... IF NOT EXISTS). create_all builds these from __table_args__ on a
    FRESH DB (no rows, no conflict); this adds them on an EXISTING one. Runs AFTER
    _backfill_encrypted_names so freshly-backfilled name_bi values are included.

    FILES: any pre-existing same-name duplicates in a folder (which the replace-on-clash
    upload path should already have prevented) are collapsed first — newest kept, older ones
    deleted (blob + stats + row) — so the index can be created. FOLDERS were never deduped at
    create time, so duplicate-name folders may legitimately exist and a folder delete CASCADES
    to its whole subtree; we therefore do NOT delete folder dupes. We try to create the folder
    index and, if duplicates block it, log a loud warning and leave folder uniqueness to the
    new create-time check until an operator resolves the duplicates."""
    try:
        from sqlalchemy import text
        from app.core.database import get_db_context
        from app.core.models import File, Vault
        from app.core.authorization import PermissionService

        # 1) Collapse pre-existing FILE duplicates (defensive; normally none exist). Isolated
        # so a de-dupe hiccup never prevents index creation below (if real dups remain, the
        # CREATE will simply fail and be reported — same as the folder path).
        try:
            with get_db_context() as db:
                dup_groups = db.execute(text(
                    f"SELECT array_agg(id ORDER BY created_at DESC, id DESC) AS ids "
                    f"FROM files WHERE name_bi IS NOT NULL "
                    f"GROUP BY vault_id, COALESCE(folder_id, {_NAME_UNIQ_NULL_FK}), name_bi "
                    f"HAVING count(*) > 1"
                )).fetchall()
                if dup_groups:
                    vs = VaultService(db, PermissionService(db))
                    stale_blobs, removed = [], 0
                    for grp in dup_groups:
                        for fid in list(grp.ids)[1:]:  # keep newest (index 0); delete the rest
                            f = db.query(File).filter(File.id == fid).first()
                            if f is None:
                                continue
                            vault = db.query(Vault).filter(Vault.id == f.vault_id).first()
                            if vault is not None:
                                vault.total_size_bytes = max(0, (vault.total_size_bytes or 0) - (f.size_bytes or 0))
                                vault.file_count = max(0, (vault.file_count or 0) - 1)
                            stale_blobs.append(f.storage_path)
                            db.delete(f)
                            removed += 1
                    db.commit()
                    vs._remove_blobs(stale_blobs)  # only after the rows are committed-deleted
                    print(f"[OK] Collapsed {removed} duplicate same-name file row(s) before adding the name unique index")
        except Exception as e:
            print(f"⚠ File duplicate-name collapse skipped: {e}")

        # 2) Create the indexes (idempotent). Files first (now de-duped, safe). Each index
        # is independent so a failure on one is reported without blocking the other.
        with get_db_context() as db:
            try:
                db.execute(text(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS uq_files_vault_folder_name_bi "
                    f"ON files (vault_id, COALESCE(folder_id, {_NAME_UNIQ_NULL_FK}), name_bi) "
                    f"WHERE name_bi IS NOT NULL"
                ))
                db.commit()
            except Exception as e:
                db.rollback()
                print("⚠ Could NOT create the files name unique index — duplicate same-name "
                      f"files remain in some folder. Resolve them, then restart. ({e})")
        # Folders: do NOT delete dupes (cascade risk). If pre-existing duplicate-name
        # folders block the unique index, surface it loudly and continue — the create-time
        # check still prevents NEW dupes.
        with get_db_context() as db:
            try:
                db.execute(text(
                    f"CREATE UNIQUE INDEX IF NOT EXISTS uq_folders_vault_parent_name_bi "
                    f"ON folders (vault_id, COALESCE(parent_folder_id, {_NAME_UNIQ_NULL_FK}), name_bi) "
                    f"WHERE name_bi IS NOT NULL"
                ))
                db.commit()
            except Exception as e:
                db.rollback()
                print("⚠ Could NOT create the folders name unique index — duplicate-name "
                      f"folders already exist in some parent. Resolve them, then restart. ({e})")
                # Surface the offending groups (vault, parent, ids) so an operator can resolve
                # them — folders are NOT auto-de-duped (a folder delete CASCADES to its subtree).
                # Until resolved, create_folder's same-name guard is only the (non-atomic)
                # pre-check, so concurrent same-name folder creates could slip a duplicate
                # through; this log makes the degraded state actionable rather than silent.
                try:
                    dups = db.execute(text(
                        f"SELECT vault_id, COALESCE(parent_folder_id, {_NAME_UNIQ_NULL_FK}) AS parent, "
                        f"name_bi, array_agg(id) AS ids FROM folders WHERE name_bi IS NOT NULL "
                        f"GROUP BY vault_id, COALESCE(parent_folder_id, {_NAME_UNIQ_NULL_FK}), name_bi "
                        f"HAVING count(*) > 1"
                    )).fetchall()
                    for d in dups:
                        print(f"   duplicate folder name: vault={d.vault_id} parent={d.parent} ids={list(d.ids)}")
                except Exception as diag_err:
                    db.rollback()
                    print(f"   (could not list duplicate folders: {diag_err})")
    except Exception as e:
        print(f"⚠ Name uniqueness index setup skipped: {e}")


@asynccontextmanager
async def lifespan(app: FastAPI):
    """Lifespan event handler for startup and shutdown."""
    # Startup
    init_db()
    print("Database initialized")
    _run_lightweight_migrations()
    _backfill_encrypted_names()
    _add_name_uniqueness()  # after backfill so freshly-sealed name_bi values are indexed
    _seed_admin_user()
    _backfill_default_permissions()
    
    # Start background task for session cleanup
    cleanup_task = asyncio.create_task(cleanup_expired_sessions())
    print("[OK] Session cleanup task started")
    
    yield
    
    # Shutdown - cancel background tasks
    cleanup_task.cancel()
    try:
        await cleanup_task
    except asyncio.CancelledError:
        print("Session cleanup task cancelled")
    pass

# Update app initialization
app.router.lifespan_context = lifespan


# Mount static files for web interface
static_dir = str(PROJECT_ROOT / "static")
if os.path.exists(static_dir):
    app.mount("/static", StaticFiles(directory=static_dir), name="static")


def _should_warn_plaintext_transport(use_https, environment, trusted_proxies):
    """True when serving plaintext HTTP on a reachable (non-development) deploy with no TLS-terminating
    proxy configured — the operator should enable TLS or front the app with an HTTPS proxy. A dev stack
    (ENVIRONMENT=development, loopback) is expected to run plaintext, so this stays False there."""
    return (not use_https
            and (environment or "").strip().lower() != "development"
            and not (trusted_proxies or "").strip())


if __name__ == "__main__":
    import uvicorn

    # Configure SSL if enabled
    ssl_config = {}
    if settings.api_use_https:
        ssl_config = {
            "ssl_keyfile": settings.api_ssl_keyfile,
            "ssl_certfile": settings.api_ssl_certfile,
        }
        print(f"🔒 HTTPS enabled")
        print(f"📁 Certificate: {settings.api_ssl_certfile}")
        print(f"🔑 Private Key: {settings.api_ssl_keyfile}")

    # --- Warn (do NOT brick) on a plaintext listener outside local development ---
    # The default/trial compose binds this to loopback, but a self-rolled `docker run`, or a compose
    # edited to publish on 0.0.0.0, could expose the plaintext API — login credentials and bearer
    # tokens would then cross the network in cleartext. Terminate TLS in-process (API_USE_HTTPS=true
    # + certs) or front the app with an HTTPS reverse proxy (set TRUSTED_PROXIES).
    if _should_warn_plaintext_transport(settings.api_use_https, settings.environment, settings.trusted_proxies):
        print("\n⚠️  WARNING: serving PLAINTEXT HTTP with ENVIRONMENT != development and no TRUSTED_PROXIES set.")
        print("   Login credentials and bearer tokens cross the network in cleartext if this port is")
        print("   reachable off-host. Enable TLS (API_USE_HTTPS=true) or front the app with an HTTPS")
        print("   reverse proxy (deploy/docker-compose.secure.yml / deploy/setup-secure.sh do this for you).")

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        **ssl_config
    )
