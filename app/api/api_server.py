# -*- coding: utf-8 -*-
"""
FastAPI application for management API.
Provides REST endpoints for user management, vault operations, and administration.

Performance: Key endpoints support ETag-based conditional responses to reduce traffic.
"""
from datetime import datetime, timedelta, timezone
from typing import List, Optional
import hashlib
import uuid
import json
import re
import logging

from fastapi import FastAPI, Depends, HTTPException, status, Request, File as FastAPIFile, UploadFile, Header, WebSocket, WebSocketDisconnect, Response, Query
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import StreamingResponse, FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from fastapi.exception_handlers import http_exception_handler as fastapi_http_exception_handler
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.requests import Request as StarletteRequest
from pydantic import BaseModel, EmailStr, Field, field_validator
import sqlalchemy
from sqlalchemy.orm import Session
import io
import os
import shutil
import traceback
from pathlib import Path

# Importing this module is itself the API launch contract (including ASGI import-string
# launchers), so runtime settings must be installed before the app or middleware captures them.
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("API")

from app.core.database import get_db, init_db, check_db_connection, check_redis_connection
from app.core.chunk_cleanup import fail_chunk_session
from app.core.session_hash_utils import hash_session_token
from app.core.models import User, RoleEnum, PermissionEnum, VaultPermissionEnum, Vault, File, Folder, Group, user_groups, ChunkedUploadSession, UserPreference, ShareTag, Share, ShareClaim, RetiredObjectId, VaultStorageGrant, SchemaStep, NoteLinkTag, NoteLink
from app.core import sharing_policy
from app.core import note_link_policy
from app.core import storage_quota
from app.core.email_identity import (
    EMAIL_LOWER_UNIQUE_INDEX, email_in_use, find_email_collisions, normalize_email,
)
from app.core.key_wrap_algorithms import DIRECT_DEK_ALGO, TEAMPRIV_ALGO
from app.config.branding import branding
# NOTE: auth_service and vault_service BOTH define a class named RateLimitExceededError
# (unrelated: one subclasses AuthenticationError, the other FileServiceError). Import the
# auth one under an alias so the later vault import below can't shadow it — otherwise the
# login throttle's `except` would bind the wrong class and a throttled login would surface
# as a 500 instead of a 429.
from app.services.auth_service import AuthService, InvalidCredentialsError, AccountLockedError, RateLimitExceededError as AuthRateLimitExceededError
from app.core.authorization import PermissionService, PermissionDeniedError, ResourceNotFoundError, AuthorizationError
from app.services.vault_service import VaultService, PasswordRequiredError, InvalidPasswordError, FileTooLargeError, RateLimitExceededError, FileNotFoundError, FileServiceError, VaultNotFoundError, FolderNotFoundError, DuplicateNameError, _name_match_filter, is_refundable_serve_failure
from app.services.vault_service import require_file_scope, require_folder_scope, require_item_scope, require_download_scope, folder_ancestry, filter_listing_for_scope
from app.core.id_scope import id_in_scope
from sqlalchemy.exc import IntegrityError
from app.services.audit_logger import AuditLogger
from app.services.streaming_upload import receive_bounded, ChunkTooLarge, EmptyBody
from app.core.upload_chunk_crypto import (
    seal_stream_to_file, sealed_plaintext_size, open_staged_chunk, StagedChunkError,
)
from app.services.download_stream import (
    ChecksumMismatch, UNSATISFIABLE, parse_byte_range,
)

#: How much of a range to decrypt per yield. Bounded for the same reason the whole-file
#: path is bounded: a client naming a two-gigabyte range must not turn into a
#: two-gigabyte allocation. The reader decrypts only the records a window touches.
_RANGE_WINDOW = 256 * 1024
from app.core import download_sink as _download_sink
from app.services import log_pull  # pure helpers for the authenticated log-pull endpoint
from app.core.security import (
    create_access_token, verify_access_token, EncryptionError, ObjectChangedDuringRead,
)
from app.core.config import initialize_runtime, settings
from app.core.endpoint_permissions import (
    require_endpoint_permission,
    validate_endpoint_permission_contract,
)
from app.core.temp_scope import require_vault_cap, scope_denials_as_filter
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


# The count above reports; this one decides. They are deliberately separate: the registry tracks
# every operation for the activity feed and cancellation, while admission governs only the two
# things that hold memory for a duration -- serving a download, and assembling an upload.
from app.core.transfer_admission import TransferAdmission, TransferBusy  # noqa: E402

transfer_admission = TransferAdmission(
    limit=settings.max_concurrent_transfers,
    max_waiting=settings.max_queued_transfers,
    wait_seconds=settings.transfer_queue_wait_seconds,
)


def _busy_response(exc: TransferBusy) -> HTTPException:
    """Turn a refusal into something a client can act on.

    503 with Retry-After, not 500: the deployment is working correctly and is momentarily full,
    which is a different thing from the file being unreadable. A client that cannot tell those
    apart either retries something hopeless or gives up on something that would have worked.
    """
    return HTTPException(
        status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
        detail=(f"The server is already handling {exc.limit} transfers. "
                f"Try again in a few seconds."),
        headers={"Retry-After": str(exc.retry_after)},
    )


# Initialize FastAPI app
# Security: Conditionally disable API docs in production
app = FastAPI(
    title="Secure SFTP Management API",
    description="Management API for secure SFTP server with vault system",
    version=branding.app_version,
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

    Behind a TLS-terminating reverse proxy (the common production topology, and the dev
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
# The largest a single resumable chunk may be. A chunk request stages to the transient _uploads/
# buffer BEFORE the per-session counter is committed, so without a per-request size bound K
# concurrent requests could each stage the whole file (K x total_size) -- uncounted transient disk,
# a cross-tenant DoS. Bounding each request to one chunk makes that transient independent of the
# file size (it no longer scales with max_file_size_mb). This is a SIZE cap per piece, not a rate
# limit: a client uploads as fast as its link allows, just in <= this-many-byte pieces.
_MAX_UPLOAD_CHUNK_BYTES = 64 * 1024 * 1024  # 64 MiB

# Absolute ceiling on a single NON-MULTIPART request body (defense-in-depth vs a JSON/octet-stream
# in-memory DoS, on top of the starlette >=0.40 multipart-parser fix). MULTIPART uploads are EXEMPT
# (metered per-file in-stream and bounded by the vault size limit), so this ceiling is DECOUPLED
# from max_file_size_mb: the largest legitimate non-multipart body is one resumable chunk PUT, so a
# few multiples of the chunk cap covers every real request while still tripping on an abusive body.
# Decoupling it keeps a large file cap (e.g. 10 GB) from widening this in-memory backstop.
_MAX_REQUEST_BODY_BYTES = 4 * _MAX_UPLOAD_CHUNK_BYTES  # 256 MiB


# The URL-secret redaction (invite/reset/share tokens in the path or landing-page query) lives in a
# small stdlib-only module so it is unit-testable offline and shared by the in-app sink AND the uvicorn
# access-log filter below. Add new secret-bearing routes in app/core/log_redaction.py.
from app.core.log_redaction import (  # noqa: E402
    redact_log_path as _redact_log_path,
    redact_access_path as _redact_access_path,
    AccessLogRedactFilter as _AccessLogRedactFilter,
)


def _public_base_url(request) -> str:
    """Absolute base URL for the tokened links we email (reset/invite). Delegates to
    ``email_actions.public_base_url`` (offline-testable): prefer the configured public host so a spoofed
    ``Host`` header can't poison an emailed token, else fall back to the request host."""
    from app.core.email_actions import public_base_url
    return public_base_url(request)


def _install_access_log_redaction() -> None:
    """Attach the access-log redaction filter once (idempotent), covering both run modes:
    `python -m app.api.api_server` and an ASGI server importing `app`."""
    lg = logging.getLogger("uvicorn.access")
    if not any(isinstance(f, _AccessLogRedactFilter) for f in lg.filters):
        lg.addFilter(_AccessLogRedactFilter())


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
        import time as _t
        _req_started = _t.monotonic()
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

        # Web log-pull access line. Only when the in-app sink is active (split/direct shape — under
        # run_combined it stays inactive and the launcher captures stdout instead, so no double-write).
        # Method + path + status + client IP + duration ONLY — never bodies, headers, or query strings
        # (the pull path also redacts on read, but we avoid logging secrets at the source).
        try:
            from app.services import log_sink
            if log_sink.is_active():
                _dur_ms = int((_t.monotonic() - _req_started) * 1000)
                log_sink.emit("web", f"{request.method} {_redact_log_path(request.url.path)} -> "
                                     f"{response.status_code} {get_client_ip(request)} {_dur_ms}ms")
        except Exception:  # noqa: BLE001 — logging must never affect the response
            pass

        return response

_RATE_LIMIT_API_CATEGORIES = ("default", "auth", "upload", "upload_chunk", "download", "poll")
_RATE_LIMIT_API_SETTING_KEYS = tuple(
    key
    for category in _RATE_LIMIT_API_CATEGORIES
    for key in (f"rate_limit_api_{category}", f"rate_limit_api_{category}_window")
)


def _api_rate_limit_deployment_defaults() -> dict:
    return {key: int(getattr(settings, key)) for key in _RATE_LIMIT_API_SETTING_KEYS}


def _load_stored_api_rate_limit_overrides() -> dict:
    from app.core.database import SessionLocal
    from app.core.models import SystemSetting

    db = SessionLocal()
    try:
        row = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
        return dict(row.value) if row and row.value else {}
    finally:
        db.close()


# The deployment flag is authoritative. When enabled, a five-second process-local cache
# avoids per-request PostgreSQL reads; Settings writes replace it immediately, while the
# bounded refresh propagates another worker's update. General API traffic preserves the
# documented Redis-outage fail-open policy; dedicated login/vault/SFTP throttles are separate.
_api_rate_limit_policy_cache = None
if getattr(settings, 'rate_limit_api_enabled', True):
    from app.core.rate_limiter import (
        ApiRateLimitPolicyCache,
        RateLimitMiddleware,
        RateLimitRule,
        rate_limiter as _api_rate_limiter,
    )
    deployment = _api_rate_limit_deployment_defaults()
    deployment_rules = {
        category: RateLimitRule(
            deployment[f"rate_limit_api_{category}"],
            deployment[f"rate_limit_api_{category}_window"],
        )
        for category in _RATE_LIMIT_API_CATEGORIES
    }
    _api_rate_limit_policy_cache = ApiRateLimitPolicyCache(
        deployment_rules,
        _load_stored_api_rate_limit_overrides,
        ttl_seconds=5,
    )
    app.add_middleware(
        RateLimitMiddleware,
        rate_limiter=_api_rate_limiter,
        default_limit=settings.rate_limit_api_default,
        default_window=settings.rate_limit_api_default_window,
        auth_limit=settings.rate_limit_api_auth,
        auth_window=settings.rate_limit_api_auth_window,
        upload_limit=settings.rate_limit_api_upload,
        upload_window=settings.rate_limit_api_upload_window,
        upload_chunk_limit=settings.rate_limit_api_upload_chunk,
        upload_chunk_window=settings.rate_limit_api_upload_chunk_window,
        download_limit=settings.rate_limit_api_download,
        download_window=settings.rate_limit_api_download_window,
        poll_limit=settings.rate_limit_api_poll,
        poll_window=settings.rate_limit_api_poll_window,
        policy_provider=_api_rate_limit_policy_cache.get,
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


class ClientIPMiddleware:
    """Pure-ASGI middleware that resolves the trusted-proxy client IP once per request into a
    contextvar, so any code -- notably the permission-denial audit helpers -- can record it
    without the endpoint having to declare a `request` parameter. Pure ASGI (NOT
    BaseHTTPMiddleware) so the contextvar reliably propagates into the route handler."""

    def __init__(self, app):
        self.app = app

    async def __call__(self, scope, receive, send):
        if scope.get("type") != "http":
            await self.app(scope, receive, send)
            return
        from app.core.net_utils import client_ip, set_client_ip, reset_client_ip
        from starlette.requests import Request as _Request
        try:
            ip = client_ip(_Request(scope))
        except Exception:  # noqa: BLE001 — never fail a request over IP resolution
            ip = None
        token = set_client_ip(ip)
        try:
            await self.app(scope, receive, send)
        finally:
            reset_client_ip(token)


app.add_middleware(ClientIPMiddleware)

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

# Import and include ECC router (Elliptic Curve Cryptography)
from app.api.ecc_router import router as ecc_router
app.include_router(ecc_router, prefix="/ecc")

# Import and include Email Studio router (SMTP profiles / HTML templates / image resources)
from app.api.email_studio_router import router as email_studio_router
app.include_router(email_studio_router, prefix="/email")

@app.get("/download-sw.js", include_in_schema=False)
async def download_service_worker():
    """The streaming-download sink, served from the ORIGIN ROOT rather than /static/js/.

    A service worker's default scope is the directory it was served from, so the same file under
    /static/js/ could only ever intercept /static/js/... and would never see the sink URL. Serving
    it here gives it the whole origin without needing a Service-Worker-Allowed header, which is the
    simpler of the two ways to get there.

    Registered by the page only when the resolved download sink is `streaming` -- a worker is an
    origin-wide, persistent thing, and one should not be installed on everybody's browser to
    support a mode most deployments will not use.
    """
    path = PROJECT_ROOT / "static" / "js" / "download-sw.js"
    if not path.exists():
        raise HTTPException(status_code=404, detail="Not found")
    response = FileResponse(str(path), media_type="application/javascript")
    # A stale worker is worse than no worker: it would keep answering the sink URL with old
    # framing after the page had moved on. Revalidate every time; the file is small.
    response.headers["Cache-Control"] = "no-cache"
    response.headers["Service-Worker-Allowed"] = "/"
    return response


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


def _validate_new_username(v):
    """The rules a newly-created username must satisfy, shared by account creation and invitations so
    they cannot drift. Rejects '<'/'>' markup and '@' — a username that looked like an email would,
    under an 'either' login policy (username tried first), shadow the real owner of that address.
    NOT applied to LoginRequest, where an email is a legitimate identifier in email/either mode."""
    v = _reject_markup_chars(v, 'username')
    if v is not None and '@' in v:
        raise ValueError("username may not contain '@'")
    return v


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
    # Optional at the schema layer so an omitted address is a policy question, not a 422 schema
    # dump. EmailStr still applies to anything actually supplied, so "no email" and "a bad email"
    # stay distinguishable. The org policy that can make an address mandatory arrives with the
    # Accounts & Access settings; until then an omitted email is simply accepted.
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=8)
    role: RoleEnum = RoleEnum.USER

    @field_validator('username')
    @classmethod
    def _clean_username(cls, v):
        return _validate_new_username(v)


class InviteCreate(BaseModel):
    # Mirrors UserCreate's username/email rules (an invitation pre-assigns the account's username);
    # there is no password here — the invitee sets it at acceptance.
    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    role: RoleEnum = RoleEnum.USER

    @field_validator('username')
    @classmethod
    def _clean_username(cls, v):
        return _validate_new_username(v)


class InviteAccept(BaseModel):
    # Mass-assignment defense: the ONLY fields an invitee may supply. Username and role come from the
    # invitation ROW, never the request body — so role/is_active/is_locked/quota are structurally
    # unrepresentable here. `email` is used only when the invitation carries no address.
    password: str = Field(..., min_length=8)
    email: Optional[EmailStr] = None


class SignupRequest(BaseModel):
    # Public self-signup. Mass-assignment defense: the ONLY fields a visitor may supply. Any
    # role/is_active/is_locked/storage_quota/created_by key in the body is IGNORED by the schema
    # (pydantic's default extra='ignore') and the handler forces the safe values itself
    # (role=user, created_by=NULL, active/unlocked column defaults) — it never reads those keys.
    # `email` is EmailStr so a multiple-'@' address is rejected at the schema edge (the domain gate
    # rsplit('@')s and would otherwise treat everything after the last '@' as the domain).
    username: str = Field(..., min_length=3, max_length=50)
    email: Optional[EmailStr] = None
    password: str = Field(..., min_length=8)

    @field_validator('username')
    @classmethod
    def _clean_username(cls, v):
        return _validate_new_username(v)


class UserUpdate(BaseModel):
    email: Optional[EmailStr] = None
    password: Optional[str] = Field(None, min_length=8)
    role: Optional[RoleEnum] = None
    is_active: Optional[bool] = None
    is_locked: Optional[bool] = None
    # Per-account SFTP controls (settable by the user themselves or an admin).
    sftp_enabled: Optional[bool] = None
    sftp_password_auth: Optional[bool] = None
    # Per-account storage budget, in GB, ADMIN-ONLY (a user raising their own would make the
    # deployment default meaningless). Three shapes, because "unset" and "unlimited" are
    # genuinely different states: omit the field to leave it alone, send the string "inherit"
    # (or "default") to fall back to the deployment default, send "unlimited" to exempt the
    # account, or send a number >= 0 for an exact budget. JSON null is read as "inherit" too,
    # since that is what a cleared field in the admin UI means.
    storage_quota_gb: Optional[object] = None


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
    email: Optional[str] = None
    role: RoleEnum
    is_active: bool
    is_locked: bool
    sftp_enabled: bool = True
    sftp_password_auth: bool = True
    # The account's storage override in bytes: null = inherits the deployment default,
    # -1 = exempt, otherwise an exact budget. The effective number (and what the account has
    # already allocated) comes from /users/{id}/storage.
    storage_quota_bytes: Optional[int] = None
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
    email: Optional[str] = None
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


# Postgres INTEGER (int4) ceiling. The share limit/lifetime fields map to int4 columns, so bound the
# Pydantic validators here: a larger value would pass validation and then raise an uncaught DataError
# (HTTP 500 — only IntegrityError is caught) on INSERT/UPDATE. le= turns it into a clean 422 at the edge.
_INT4_MAX = 2147483647


class ShareTagCreate(BaseModel):
    """Create a share tag (interactive-admin). Policy + create-allowlist. Ints are >= 1; a NULL cap or
    default means unlimited on that axis. Cross-field checks (default <= cap, default_lifetime <=
    ceiling, audiences subset, allowlist ids exist) run in the endpoint via _validate_share_tag_fields.
    The create-allowlist DEFAULTS FAIL-CLOSED (auto_enroll off + empty lists): a fresh tag grants no one
    until the admin allow-lists users/departments or enables auto-enroll."""
    name: str = Field(..., min_length=1, max_length=120)
    description: Optional[str] = None
    color: Optional[str] = Field(None, max_length=20)
    max_lifetime_minutes: int = Field(10080, ge=1, le=_INT4_MAX)     # ceiling (7 days)
    default_lifetime_minutes: int = Field(1440, ge=1, le=_INT4_MAX)  # default (1 day)
    max_recipients_cap: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_recipients_default: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_downloads_cap: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_downloads_default: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    allow_view_only: bool = True
    default_view_only: bool = False
    force_view_only: bool = False
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
    max_lifetime_minutes: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    default_lifetime_minutes: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_recipients_cap: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_recipients_default: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_downloads_cap: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_downloads_default: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    allow_view_only: Optional[bool] = None
    default_view_only: Optional[bool] = None
    force_view_only: Optional[bool] = None
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
    lifetime_minutes: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_recipients: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
    max_downloads: Optional[int] = Field(None, ge=1, le=_INT4_MAX)
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
    # Optional so a zero-knowledge client can send only its non-secret LABEL (or nothing) here while
    # the real name travels sealed in enc_name. A standard vault still requires a real name -- the
    # handler enforces that. Blank/whitespace is normalized to None below.
    name: Optional[str] = Field(None, max_length=255)
    # Optionally the id to create this vault under. A zero-knowledge client needs the id
    # before it locks the vault key -- the newer lock format stamps the key with its vault,
    # and the key travels in this same request, so waiting for the server to assign one is
    # too late. Absent, the server assigns it as before.
    id: Optional[uuid.UUID] = None
    description: Optional[str] = None
    # Zero-knowledge: the vault name/description sealed IN THE BROWSER (zk2: markers). The server
    # stores them and cannot read them; `name` then carries only the non-secret label.
    enc_name: Optional[str] = None
    enc_description: Optional[str] = None
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
    # Bound the client-supplied sealed name (ZK). A sealed 255-char filename is ~1.4 KB, so 8 KB is
    # generous headroom while stopping unbounded metadata from being parked in a Text column that
    # the storage quota does not count. (Standard-vault at-rest enc_name is set server-side, not here.)
    enc_name: Optional[str] = Field(None, max_length=8192)
    name_bi: Optional[str] = Field(None, max_length=64)  # stored in a VARCHAR(64) column
    # Extra blind-index values to MATCH the new name against (every epoch's candidate), so a rename
    # INTO a name that already exists at an OLD epoch is detected as a clash rather than silently
    # creating a duplicate. Bounded; absent falls back to matching the single name_bi.
    name_bi_candidates: Optional[List[str]] = Field(None, max_length=64)
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
    # Optional: a zero-knowledge vault may carry only a non-secret label here (or nothing), with the
    # real name sealed in enc_name. A standard vault's decrypted name is always present.
    name: Optional[str] = None
    description: Optional[str]
    # Zero-knowledge: browser-sealed name/description for the client to decrypt (None for standard).
    enc_name: Optional[str] = None
    enc_description: Optional[str] = None
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
    # When the CALLER last opened this vault, or null if they never have. Personal to the
    # requester and never anyone else's activity — distinct from last_accessed above, which is
    # the last access by any member.
    last_viewed_at: Optional[datetime] = None

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
    email: Optional[str] = None
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
    email: Optional[str] = None
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
            ActiveSession.session_token == hash_session_token(session_token)
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
            ActiveSession.session_token == hash_session_token(session_token),
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

        # A DEACTIVATED credential must stop authorizing IMMEDIATELY, even while its session row is
        # still nominally active. Deactivation (admin or self revoke) flips the credential's
        # is_active flag but does not necessarily revoke every backing session row in the same
        # commit, so the session-level checks above are not sufficient on their own. Re-read
        # is_active here every request — mirroring the SFTP path, which does the same on every
        # operation for exactly this case — so a revoke takes effect on the very next request
        # instead of surviving until the session's inactivity/hard-expiry window closes.
        if not temp_cred.is_active:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Temporary credential has been deactivated. Please login again.",
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


def _audit_admin_denial(db, user, reason: str) -> None:
    """Record an admin-plane access denial in the audit log. require_admin /
    require_interactive_admin are resolved by FastAPI as dependencies BEFORE the
    @require_endpoint_permission decorator on the handler runs, so a non-admin (or an
    admin-minted temp-credential session) turned away here otherwise leaves NO audit trail —
    the highest-signal probe (a non-admin reaching for an admin function) went unrecorded, while
    endpoint-permission and vault-capability denials already are. Mirrors _audit_endpoint_denial.
    Best-effort by contract: a failure here must never turn the 403 the caller is already getting
    into a 500, so everything is swallowed."""
    try:
        from app.core.net_utils import current_client_ip
        AuditLogger(db).log_action(
            action="admin_access_denied",
            status="failure",
            user=user,
            resource_type="admin_function",
            resource_id="admin_plane",
            ip_address=current_client_ip(),
            details={"reason": reason},
        )
    except Exception:  # noqa: BLE001 — a lost audit row must never mask the 403
        pass


async def require_admin(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> User:
    """Dependency to require admin role."""
    if current_user.role != RoleEnum.ADMIN:
        _audit_admin_denial(db, current_user, "admin role required")
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Admin privileges required"
        )
    return current_user


async def require_interactive_admin(
    current_user: User = Depends(require_admin),
    db: Session = Depends(get_db),
) -> User:
    """Admin dependency that ALSO rejects temporary-credential sessions.

    Org-policy writes — e.g. PUT /settings, which sets zero_knowledge_enabled /
    force_zero_knowledge / standard_vault_allowed_groups (the confidentiality boundary
    for the whole deployment) — must be performed by a real INTERACTIVE admin. An
    admin-minted temporary credential keeps the admin ROLE (get_current_user returns the
    real admin User and attach_scope does not downgrade role), so require_admin alone would
    let a tightly-scoped temp credential flip that boundary. Reject temp sessions here."""
    if getattr(current_user, "_is_temp_session", False):
        _audit_admin_denial(db, current_user,
                            "interactive admin session required (temp credential rejected)")
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


def _vault_activity_fields(vault=None, current_user=None) -> dict:
    """Enrichment fields for Live Monitor activity events.

    The base upload/download broadcasts only carried actor + IP + file, so the operator could not
    tell WHICH vault an event touched or whether it was a Standard vs zero-knowledge vault, nor
    whether a temporary credential acted. This returns those fields to spread into an event dict
    (``{**event, **_vault_activity_fields(vault, current_user)}``). All lookups are getattr-guarded
    so a partially-bound caller (e.g. an error path where the vault was never fetched) is safe.
    """
    fields: dict = {}
    if vault is not None:
        vid = getattr(vault, "id", None)
        fields["vault_id"] = str(vid) if vid else None
        fields["vault_name"] = getattr(vault, "name", None)
        # Raw column value: "standard" | "zero_knowledge". The UI maps this to a badge.
        fields["vault_type"] = getattr(vault, "type", "standard")
    if current_user is not None and getattr(current_user, "_is_temp_session", False):
        # A temporary session IS the account; surface it so the feed shows main-vs-temp actor.
        fields["is_temporary"] = True
        tcid = getattr(current_user, "_temp_cred_id", None)
        if tcid:
            fields["temp_credential_id"] = str(tcid)
    return fields


# API Endpoints

@app.get("/api")
async def api_root():
    """API information endpoint."""
    return {
        "message": "Secure SFTP Management API",
        "version": branding.app_version,
        "status": "operational"
    }


_UPDATE_SETTINGS_KEY = "update_check"


def _effective_update_interval_minutes(db) -> int:
    """The effective update-check interval: a live DB override (SystemSetting 'update_check') if set,
    else the env default (settings.update_check_interval_minutes) — ALWAYS clamped to the
    rate-limit-safe range. Fail-safe to the clamped env default on any read error."""
    from app.services import update_check
    default = update_check.clamp_interval_minutes(settings.update_check_interval_minutes)
    try:
        from app.core.models import SystemSetting
        row = db.query(SystemSetting).filter(SystemSetting.key == _UPDATE_SETTINGS_KEY).first()
        val = (row.value or {}).get("interval_minutes") if (row and row.value) else None
        return update_check.clamp_interval_minutes(val) if val is not None else default
    except Exception:  # noqa: BLE001
        return default


@app.get("/api/update-status")
def get_update_status_endpoint(force: bool = False,
                               current_user: User = Depends(require_interactive_admin),
                               db: Session = Depends(get_db)):
    """Admin-only: whether a newer DockVault release exists (opt-in, default off).

    Deliberately a SYNC endpoint: the (cached) update check does a BLOCKING urllib request, so
    FastAPI runs this in a threadpool instead of stalling the async event loop. A real request goes
    out at most once per the admin-set interval (the shared cache protects GitHub's rate limit no
    matter how often the UI polls). `force=1` is a manual "check now" that bypasses the interval but
    is still throttled server-side (never spammable into the rate limit).

    Gated behind an interactive admin so the (mildly fingerprint-aiding) 'outdated?' signal is
    not exposed publicly like /version is. Returns {enabled, managed, current, latest,
    update_available, url, notes, checked_at, interval_minutes}; the check itself is
    fail-closed-silent and only ever runs when UPDATE_CHECK_ENABLED is set (never when managed)."""
    from app.services import update_check
    interval = _effective_update_interval_minutes(db)
    status = update_check.get_update_status(
        current_version=branding.app_version,
        enabled=settings.update_check_enabled,
        managed=settings.managed_deployment,
        force=bool(force),
        interval_seconds=interval * 60,
    )
    status["interval_minutes"] = interval
    return status


@app.put("/api/update-settings")
def set_update_settings_endpoint(payload: dict, request: Request,
                                 current_user: User = Depends(require_interactive_admin),
                                 db: Session = Depends(get_db)):
    """Admin-only: set the LIVE update-check interval (minutes), clamped to the rate-limit-safe
    range (a mis-set value snaps into range). Stored in SystemSetting('update_check'); takes effect
    without a restart. Does NOT enable the check — that stays the UPDATE_CHECK_ENABLED env flag."""
    from app.services import update_check
    from app.core.models import SystemSetting
    raw = payload.get("interval_minutes") if isinstance(payload, dict) else None
    if raw is None:
        raise HTTPException(status_code=400, detail="interval_minutes is required")
    minutes = update_check.clamp_interval_minutes(raw)
    row = db.query(SystemSetting).filter(SystemSetting.key == _UPDATE_SETTINGS_KEY).first()
    if row is None:
        db.add(SystemSetting(key=_UPDATE_SETTINGS_KEY, value={"interval_minutes": minutes}))
    else:
        row.value = {**(dict(row.value) if row.value else {}), "interval_minutes": minutes}
    db.commit()
    try:
        AuditLogger(db).log_action(action="update_settings_updated", status="success", user=current_user,
                                   ip_address=get_client_ip(request), details={"interval_minutes": minutes})
    except Exception:
        pass
    return {"interval_minutes": minutes}


@app.get("/health")
async def health_check():
    """Health check endpoint.

    Reports each subsystem separately, because a vault can be half-broken: the API answering
    while its database is gone is a different problem from the API being down, and the two need
    different responses. `status` stays the one-word summary a container healthcheck reads.

    Unauthenticated, so every value comes from a short fixed vocabulary — see
    `app/core/health.py`. No paths, capacities or error text.
    """
    from app.core.health import (check_schema_state, check_sftp_status,
                                 check_storage_status)

    db_ok = check_db_connection()
    redis_ok = check_redis_connection()
    sftp = check_sftp_status()
    storage = check_storage_status()
    schema = check_schema_state()

    # SFTP is opt-in, so `disabled` is a healthy state, and so is `external` (a split deployment
    # serves SFTP from its own container, which this process cannot and should not answer for) —
    # only a vault that was meant to serve SFTP from HERE and is not counts against the summary.
    # Storage that cannot be written to is degraded even while the API answers: uploads will
    # fail, and nothing else would have said so.
    degraded = ((not db_ok) or (not redis_ok) or sftp == "unreachable"
                or storage != "writable" or schema != "complete")

    body = {
        "status": "degraded" if degraded else "healthy",
        "database": "connected" if db_ok else "disconnected",
        "redis": "connected" if redis_ok else "disconnected",
        "sftp": sftp,
        "storage": storage,
        # `complete` | `incomplete` | `partial` | `unknown`. A one-word summary and nothing else:
        # this endpoint is unauthenticated, so it says THAT the schema is wrong, never what is
        # wrong with it. The detail is in schema_steps, for someone with database access.
        "schema": schema,
    }

    # An incomplete schema is the one state here that answers non-2xx, and the asymmetry is
    # deliberate.
    #
    # It is the only condition that cannot resolve itself. A database or Redis that is down comes
    # back, and storage that is unwritable becomes writable, without the container being replaced --
    # so reporting those as hard failures would have Docker restart a vault that was about to
    # recover, and would make `dockvault.py`'s health-wait fail an upgrade that actually worked. A
    # step that did not apply stays not-applied until something changes and the process restarts,
    # and every request needing that column fails meanwhile.
    #
    # This is also what carries the signal outward for free: the container healthcheck calls this
    # endpoint with urlopen, which raises on a non-2xx, so Docker marks the container unhealthy and
    # the tool that waits on Docker's verdict sees it. Neither of them needed changing.
    if schema == "incomplete":
        return JSONResponse(status_code=503, content=body)
    return body


@app.get("/audit/events")
async def recent_audit_events(
    limit: int = 10,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Recent audit-log entries for the dashboard activity feed (admin only)."""
    from app.core.models import AuditLog
    limit = max(1, min(limit, 50))
    # Opportunistically prune audit rows past the retention window (throttled once/hour; a no-op
    # unless an operator set a positive audit_log_retention_days). Do it BEFORE the fetch: the prune
    # commits, and a failed DELETE must not leave the shared session aborted and 500 the feed.
    try:
        from app.services.audit_logger import AuditLogger
        AuditLogger(db).cleanup_old_audit_logs()
    except Exception:
        db.rollback()
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

def _like_escape(value: str) -> str:
    r"""Escape LIKE/ILIKE wildcards so a user-supplied filter matches its characters
    literally (use with ``.ilike(pattern, escape="\")``). Without it, ``%`` and ``_`` in
    the input silently become pattern metacharacters -- e.g. the ``_`` in a filter like
    "file_download" matches ANY character, returning actions the caller never asked for."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


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
        q = q.filter(AuditLog.action.ilike(f"%{_like_escape(action)}%", escape="\\"))
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
        # The ACCOUNT is always the username, because a temporary session is the account.
        # This is the only field that says which credential acted, so an admin can answer
        # "what did the one I issued to that contractor actually do?" -- and so a credential
        # misbehaving is not recorded as the owner doing it.
        "temp_credential_id": str(r.temp_credential_id) if r.temp_credential_id else None,
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
    action: Optional[str] = Query(None, max_length=128),
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
    writer.writerow(["Timestamp", "Username", "Temp Credential", "Action", "Status",
                     "IP Address", "Resource Type", "Resource ID", "Details"])
    for r in rows:
        writer.writerow([_csv_formula_safe(cell) for cell in (
            r.timestamp.isoformat() if r.timestamp else "",
            r.username or "",
            str(r.temp_credential_id) if r.temp_credential_id else "",
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


def _settings_blob(db: Session) -> dict:
    """The global settings blob as a plain dict (empty when never saved)."""
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    return dict(row.value) if (row and row.value) else {}


def _is_budget_exempt(user: User) -> bool:
    """Whether this identity is exempt from the per-account storage budget.

    "Full admin" = an interactive admin, NOT an admin-minted temp credential (which the codebase
    deliberately does not treat as a full admin — mirrors the require_interactive_admin gate), so a
    delegated credential can't over-consume the owner's account budget."""
    return user.role == RoleEnum.ADMIN and not getattr(user, "_is_temp_session", False)


def _account_quota_bytes(db: Session, user: User):
    """This account's EFFECTIVE storage budget in bytes, or None when it has none.

    Per-account override first (users.storage_quota_bytes: NULL inherits, -1 exempts, >= 0 is an
    exact budget), otherwise the deployment default. A budget-exempt identity has no budget at
    all — the per-vault ceiling still applies to them."""
    if _is_budget_exempt(user):
        return None
    return storage_quota.account_quota_bytes(
        getattr(user, "storage_quota_bytes", None), _settings_blob(db).get("default_user_quota"))


def _account_allocated_bytes(db: Session, user_id, exclude_vault_id=None) -> int:
    """How much of an account's budget is currently ALLOCATED: the sum of that person's storage
    grants across ACTIVE vaults — including storage they contributed to vaults somebody else owns.
    Optionally excludes one vault, so re-sizing a vault doesn't count its own current allocation
    against the person changing it."""
    from sqlalchemy import func as _f
    q = (db.query(_f.coalesce(_f.sum(VaultStorageGrant.granted_bytes), 0))
         .join(Vault, Vault.id == VaultStorageGrant.vault_id)
         .filter(VaultStorageGrant.user_id == user_id, Vault.is_active == True))  # noqa: E712
    if exclude_vault_id is not None:
        q = q.filter(VaultStorageGrant.vault_id != exclude_vault_id)
    return int(q.scalar() or 0)


def _max_allowed_vault_size_bytes(db: Session, owner: User, exclude_vault_id=None):
    """The largest total size_limit (bytes) this person may put on ONE vault they are the sole
    contributor to, bounded by the admin 'Max Vault Size' per-vault ceiling AND their remaining
    account budget. Returns None when both axes are unlimited (nothing to enforce)."""
    ceiling = storage_quota.quota_setting_bytes(_settings_blob(db).get("max_vault_size"))
    headroom = storage_quota.account_headroom_bytes(
        _account_quota_bytes(db, owner), _account_allocated_bytes(db, owner.id, exclude_vault_id))
    return storage_quota.max_vault_total_bytes(ceiling, headroom)


def _vault_grant_rows(db: Session, vault, commit: bool = True) -> list:
    """This vault's storage-allocation ledger, repaired if it ever drifts from the vault's
    declared size_limit.

    The ledger's SUM is the vault's limit. A vault created before the ledger existed (or a
    size_limit edited straight in the database) leaves an unexplained difference, and that
    difference belongs to the OWNER — that is precisely what the historical single-owner model
    meant. A NEGATIVE difference (contributions adding up to more than the recorded limit) is
    resolved the other way, by raising the limit to what people actually contributed, because
    silently deleting somebody's contribution is never the right repair.
    """
    rows = db.query(VaultStorageGrant).filter(VaultStorageGrant.vault_id == vault.id).all()
    total = sum(int(r.granted_bytes or 0) for r in rows)
    limit = int(vault.size_limit or 0)
    if total == limit:
        return rows
    if total < limit:
        # Storage the ledger cannot account for: a vault that predates the ledger, or one whose
        # contributor's account was deleted. It belongs to the owner. The reverse case is NOT
        # symmetrical and deliberately touches nobody's row — contributions adding up to more
        # than the recorded limit means the limit is what is stale, and "repairing" it by
        # subtracting from a row would delete storage somebody actually allocated.
        owner_row = next((r for r in rows if r.user_id == vault.owner_id), None)
        if owner_row is None:
            owner_row = VaultStorageGrant(vault_id=vault.id, user_id=vault.owner_id, granted_bytes=0)
            db.add(owner_row)
            rows.append(owner_row)
        owner_row.granted_bytes = int(owner_row.granted_bytes or 0) + (limit - total)
    vault.size_limit = sum(int(r.granted_bytes or 0) for r in rows)
    # A read path has no other work in flight, so it persists the repair itself. A write path
    # passes commit=False: it is holding a row lock that its own commit will release, and
    # committing here would drop that lock halfway through the allocation.
    try:
        if commit:
            db.commit()
        else:
            db.flush()
    except IntegrityError:
        # Two unlocked reads repairing the same vault at once: both insert the owner's row and
        # the (vault_id, user_id) constraint rejects the loser. The winner's row is the answer,
        # so re-read it rather than turning a self-healing path into a 500.
        db.rollback()
        return db.query(VaultStorageGrant).filter(VaultStorageGrant.vault_id == vault.id).all()
    return rows


def _lock_vault_for_allocation(db: Session, vault) -> None:
    """Serialize allocation changes on ONE vault by taking a row lock on it.

    Every allocation is read-modify-write across two tables (the contributor's row, then the
    vault's derived size_limit), so two contributors writing at the same moment could each
    compute a total that omitted the other's row. Locking the vault makes the ledger and the
    limit it derives agree without a global lock: writes to different vaults never contend.
    Released by the caller's commit/rollback.

    populate_existing() is not optional. The handler has already loaded this vault on the way in,
    and SQLAlchemy's identity map would hand back that same instance — lock emitted, attributes
    unchanged — so the stored-bytes figure the allocation is then checked against would predate
    the lock that was taken to make it trustworthy."""
    db.query(Vault).filter(Vault.id == vault.id).populate_existing().with_for_update().first()


def _vault_storage_state(db: Session, vault, commit: bool = True) -> dict:
    """The vault's allocation ledger as {user_id: bytes} plus the resulting total."""
    rows = _vault_grant_rows(db, vault, commit=commit)
    by_user = {r.user_id: int(r.granted_bytes or 0) for r in rows}
    return {"by_user": by_user, "total": sum(by_user.values())}


def _write_vault_grant(db: Session, vault, user_id, new_grant: int) -> int:
    """Set one contributor's allocation on a vault to an absolute value and re-derive the
    vault's size_limit from the ledger. Returns the vault's new total.

    Absolute, not a delta, so a retried request converges instead of stacking. A zero
    allocation keeps its row: the history of "this person contributed here" is worth more than
    the row it costs, and it makes the reclaim path a plain update."""
    row = db.query(VaultStorageGrant).filter(
        VaultStorageGrant.vault_id == vault.id, VaultStorageGrant.user_id == user_id).first()
    if row is None:
        row = VaultStorageGrant(vault_id=vault.id, user_id=user_id, granted_bytes=0)
        db.add(row)
    row.granted_bytes = int(new_grant)
    row.updated_at = datetime.now(timezone.utc)
    db.flush()
    from sqlalchemy import func as _f
    total = int(db.query(_f.coalesce(_f.sum(VaultStorageGrant.granted_bytes), 0))
                .filter(VaultStorageGrant.vault_id == vault.id).scalar() or 0)
    vault.size_limit = total
    vault.updated_at = datetime.now(timezone.utc)
    return total


def _apply_vault_total(db: Session, vault, actor: User, requested_total: int) -> None:
    """Move a vault's TOTAL size limit to `requested_total` by adjusting the actor's own
    allocation — the owner-facing spelling of the same ledger operation.

    Growing spends the actor's budget; shrinking refunds it, but only down to what the actor
    personally contributed. The remainder belongs to other contributors and is theirs to
    reclaim, so an owner cannot shrink a shared vault by cancelling somebody else's storage.
    """
    _lock_vault_for_allocation(db, vault)
    state = _vault_storage_state(db, vault, commit=False)
    mine = state["by_user"].get(actor.id, 0)
    others = state["total"] - mine
    new_grant = int(requested_total) - others
    if new_grant < 0:
        raise HTTPException(
            status_code=400,
            detail=(f"Other contributors have allocated {storage_quota.format_bytes(others)} to this "
                    f"vault, so its limit cannot go below that. You can reclaim up to your own "
                    f"{storage_quota.format_bytes(mine)}."),
        )
    _enforce_grant(db, vault, actor, new_grant, current_grant=mine, other_grants=others)
    _write_vault_grant(db, vault, actor.id, new_grant)


def _enforce_grant(db: Session, vault, actor: User, new_grant: int, *, current_grant: int,
                   other_grants: int) -> None:
    """Reject (400) an allocation the actor's budget, the vault's stored bytes or the admin's
    per-vault ceiling does not allow."""
    reason = storage_quota.check_grant(
        new_grant,
        current_grant=current_grant,
        other_grants=other_grants,
        stored_bytes=vault.total_size_bytes or 0,
        per_vault_ceiling=storage_quota.quota_setting_bytes(_settings_blob(db).get("max_vault_size")),
        account_quota=_account_quota_bytes(db, actor),
        allocated_elsewhere=_account_allocated_bytes(db, actor.id, exclude_vault_id=vault.id),
    )
    if reason:
        raise HTTPException(status_code=400, detail=reason)


def _enforce_vault_size(db: Session, owner: User, requested_bytes: int, exclude_vault_id=None) -> None:
    """Reject a requested per-vault size_limit that exceeds the owner's available headroom (the
    per-vault ceiling and/or the per-account budget). No-op when both are unlimited. The account
    budget is a best-effort allocation (a SELECT-then-write, not a lock): two concurrent creates
    can overshoot by at most one vault's declared size — the per-upload guard remains the atomic
    backstop on ACTUAL bytes."""
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


def _password_policy_view(db: Session) -> dict:
    """The enforced password policy in a shape safe to hand an unauthenticated client (the invite
    acceptance form) so it can show the requirements. Same source + clamps as _validate_password_policy,
    so the displayed rules can never drift from the enforced ones."""
    from app.core import password_policy
    from app.core.models import SystemSetting
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    cfg = (row.value or {}) if (row and row.value) else {}
    return password_policy.password_policy_view(cfg)


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


def _admin_can_email_login(db: Session, admin) -> bool:
    """Whether this admin could actually sign in under email-only login. Judged by RESOLUTION, not
    just "has a non-blank email": email login goes through find_user_by_email, which fails closed on
    a case-insensitive duplicate (the legacy broken-index install), so a colliding email that can't
    resolve to exactly this account does NOT count — otherwise the lockout guard would wave through a
    total lockout it exists to prevent."""
    from app.core.email_identity import find_user_by_email
    if not (admin.email or "").strip():
        return False
    resolved = find_user_by_email(db, admin.email)
    return resolved is not None and resolved.id == admin.id


def _active_admins(db: Session):
    """Active ADMIN accounts, ordered for a stable display list."""
    from app.core.models import User, RoleEnum
    return db.query(User).filter(
        User.role == RoleEnum.ADMIN, User.is_active.isnot(False),
    ).order_by(User.username).all()


def _admins_without_email(db: Session):
    """Usernames of every active ADMIN who could NOT sign in under email-only login — no email, or an
    email that doesn't resolve uniquely to them (a case-insensitive duplicate). The complete list for
    the warning, and the basis for the total-lockout check."""
    return [a.username for a in _active_admins(db) if not _admin_can_email_login(db, a)]


def _active_admin_with_email_exists(db: Session) -> bool:
    """True if at least one active ADMIN could actually sign in by email — i.e. someone can still get
    in under email-only login (resolution, not mere presence of a non-blank address)."""
    return any(_admin_can_email_login(db, a) for a in _active_admins(db))


def _email_login_would_lock_out_all_admins(db: Session) -> bool:
    """True only if email-only login would strand EVERY admin: no active ADMIN has an email, so no
    administrator could present a valid identifier and there would be no way back in. (A partial
    lockout — some admins lack email but at least one has one — is allowed and only warned about.)"""
    return not _active_admin_with_email_exists(db)


def _clearing_email_locks_out_all_admins(db: Session, target_user) -> bool:
    """True if REMOVING target_user's email would leave no active admin able to sign in by email — a
    total, unrecoverable lockout. The switch-time guard (_email_login_would_lock_out_all_admins) only
    fires when the policy is set to 'email'; this covers the other half — an admin's email being
    cleared AFTER the switch. Only meaningful under login_identifier='email' (under 'username'/'either'
    a username still resolves). Computed as-if-applied: an admin can email-login afterward only if it
    isn't the target (whose email is going away) and it currently resolves by email."""
    if _login_identifier(db) != "email":
        return False
    tid = getattr(target_user, "id", None)
    return not any(a.id != tid and _admin_can_email_login(db, a) for a in _active_admins(db))


def _users_without_email_count(db: Session) -> int:
    """How many active NON-admin accounts have no email — the population that would lose access under
    email-only login. Returned as a count only (there can be many)."""
    from app.core.models import User, RoleEnum
    from sqlalchemy import or_, func
    return db.query(User.id).filter(
        User.role != RoleEnum.ADMIN,
        User.is_active.isnot(False),
        or_(User.email.is_(None), func.length(func.trim(User.email)) == 0),
    ).count()


def _login_identifier_readiness(db: Session, current_user) -> dict:
    """What the admin needs to see before switching Sign-in method to 'email': who would be locked
    out. Admins are few, so the COMPLETE list is returned (serious); users can be many, so only a
    COUNT. `blocks` is the hard-stop condition (no admin has an email — the save will be refused)."""
    admins_no_email = _admins_without_email(db)
    cur = getattr(current_user, "username", None)
    return {
        "blocks": not _active_admin_with_email_exists(db),
        "admins_without_email": admins_no_email,
        "current_user_without_email": cur in admins_no_email,
        "users_without_email_count": _users_without_email_count(db),
    }


def _username_email_collision(db: Session):
    """A sample (username, email) pair where one account's username equals another account's email,
    case-insensitively, or None.

    This is the legacy-data hazard behind 'either' login: email-as-username was historically allowed
    (only NEW usernames are barred from containing '@' now), so a pre-existing username can equal a
    different account's email. Under 'either' the username is tried first, so that username shadows
    the real email owner's login identifier and locks them out. Pure 'email' mode is unaffected (the
    username is never consulted), so this only gates switching TO 'either'. Mirrors
    find_email_collisions: raw lower() on both sides, the same fold the resolver uses.
    """
    from sqlalchemy import text
    row = db.execute(text(
        """
        SELECT u.username, v.email
          FROM users u
          JOIN users v ON lower(u.username) = lower(v.email)
         WHERE u.id <> v.id AND v.email IS NOT NULL AND v.email <> ''
         ORDER BY u.username
         LIMIT 1
        """
    )).fetchone()
    return (row[0], row[1]) if row else None


def _smtp_configured(db: Session) -> bool:
    """True when the deployment can send mail — the default sending profile (or, until a profile
    exists, the legacy global SMTP config) has an SMTP server and a From address. Gates turning ON
    email-change verification, which relies on emailing a one-time code."""
    from app.core import email_send
    return email_send.smtp_configured(db)


def _fire_action_email_bulk(db: Session, key: str, recipients, action_context=None) -> None:
    """Best-effort trigger for an OPTIONAL automated email to one or more recipients.

    Uses the request ``db`` ONLY for a fast enabled-check, so a disabled action (the default) costs a
    single indexed lookup on the hot path and spawns nothing. When the action is on and bound, the
    render + SMTP fan-out runs on a daemon thread in its OWN session, so mail latency never delays the
    triggering request (a sign-in, a share, a member add …) and a mail failure can't touch its
    transaction. ``recipients`` is an iterable of ``(email, username)``. Never raises."""
    try:
        from app.core.models import EmailAction
        a = db.get(EmailAction, key)
        # An optional action only sends when explicitly enabled AND bound to a template.
        if not (a is not None and a.enabled and a.template_id is not None):
            return
        pairs = [((e or "").strip(), u) for (e, u) in recipients if (e or "").strip()]
        if not pairs:
            return
        ctx = dict(action_context or {})

        def _run(k, pp, c):
            try:
                from app.core.database import get_db_context
                from app.core.email_actions import send_action_email
                with get_db_context() as s:
                    for em, un in pp:
                        send_action_email(s, k, recipient={"email": em, "username": un}, action_context=c)
            except Exception:  # noqa: BLE001 — a courtesy notification must never surface anywhere
                pass

        threading.Thread(target=_run, args=(key, pairs, ctx), daemon=True).start()
    except Exception:  # noqa: BLE001
        pass


def _fire_action_email(db: Session, key: str, *, email, username=None, action_context=None) -> None:
    """Single-recipient convenience wrapper over :func:`_fire_action_email_bulk`."""
    _fire_action_email_bulk(db, key, [(email, username)], action_context)


def _email_change_requires_verification(db: Session) -> bool:
    """Effective org policy: does a self-service email change require an emailed one-time code?"""
    from app.core.models import SystemSetting
    from app.core.account_policy import effective_account_policy
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    return bool(effective_account_policy(row.value if row else None)["email_change_requires_verification"])


def _email_change_otp_ttl_minutes(db: Session) -> int:
    """Configured lifetime (minutes) of the email-change verification code; effective policy default 5."""
    from app.core.models import SystemSetting
    from app.core.account_policy import effective_account_policy
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    return int(effective_account_policy(row.value if row else None)["email_change_otp_ttl_minutes"])


def _login_identifier(db: Session) -> str:
    """Effective org policy: which identifier the login form accepts — 'username', 'email', or
    'either'. Always resolved through effective_account_policy so a settings hiccup or a hand-edited
    blob fails safe to 'username' and never breaks login or silently switches modes."""
    from app.core.models import SystemSetting
    from app.core.account_policy import effective_account_policy
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    return effective_account_policy(row.value if row else None)["login_identifier"]


def _account_policy(db: Session) -> dict:
    """The full effective account-onboarding policy block. Always read through
    effective_account_policy so defaults fill in and the domain list is leniently normalized — never
    read the raw stored blob."""
    from app.core.models import SystemSetting
    from app.core.account_policy import effective_account_policy
    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    return effective_account_policy(row.value if row else None)


def _invite_pepper() -> str:
    """The HMAC pepper for invitation tokens: the dedicated INVITE_TOKEN_PEPPER when set, else the
    JWT secret so invitations work with no extra configuration. Either way it is a strong secret
    (the JWT secret is required and long), so pepper_ok holds in a normal deployment."""
    return (settings.invite_token_pepper or "").strip() or settings.jwt_secret_key


def _send_email(db: Session, *, to_addr: str, subject: str, body: str) -> None:
    """Send one plaintext email through the default sending profile (or the legacy global SMTP
    config until a profile exists), raising a CLEAN HTTPException (400/502) on any failure — never a
    500, never surfacing the SMTP password. The connect / STARTTLS-strip-defense / login / send
    sequence lives in app.core.email_send, shared with the Email Studio."""
    from app.core import email_send
    cfg = email_send.resolve_default_config(db)
    if not cfg:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Email is not configured. Add a sending profile in Settings → Email first.")
    try:
        msg = email_send.build_message(cfg, to_addr=to_addr, subject=subject, text_body=body)
        email_send.smtp_send(cfg, msg)
    except email_send.EmailSendError as e:
        code = status.HTTP_400_BAD_REQUEST if e.category == "config" else status.HTTP_502_BAD_GATEWAY
        raise HTTPException(status_code=code, detail=e.message)


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

    for managed_key in ("rate_limit_api_enabled", "rate_limit_api_deployment_defaults"):
        if managed_key in payload:
            raise HTTPException(
                status_code=400,
                detail=f"{managed_key} is managed by the deployment environment",
            )

    from app.core.rate_limiter import (
        API_RATE_LIMIT_MAX_REQUESTS,
        API_RATE_LIMIT_MAX_WINDOW_SECONDS,
    )
    for category in _RATE_LIMIT_API_CATEGORIES:
        for key, maximum in (
            (f"rate_limit_api_{category}", API_RATE_LIMIT_MAX_REQUESTS),
            (f"rate_limit_api_{category}_window", API_RATE_LIMIT_MAX_WINDOW_SECONDS),
        ):
            if key not in payload:
                continue
            value = payload[key]
            if (
                isinstance(value, bool)
                or not isinstance(value, int)
                or value < 0
                or value > maximum
            ):
                raise HTTPException(
                    status_code=400,
                    detail=f"{key} must be an integer from 0 to {maximum}",
                )

    for bool_key in ("zero_knowledge_enabled", "force_zero_knowledge", "force_no_remember_vault_password",
                     "sharing_enabled"):
        if bool_key in payload and not isinstance(payload[bool_key], bool):
            raise HTTPException(status_code=400, detail=f"{bool_key} must be true or false")

    # Public note-link settings (feature toggle + the per-user active-link cap).
    try:
        note_link_policy.validate_settings(payload)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))

    # Max note size (chars).
    if "note_max_chars" in payload:
        v = payload["note_max_chars"]
        if isinstance(v, bool) or not isinstance(v, int) or not (_NOTE_BODY_MAX_FLOOR <= v <= _NOTE_BODY_MAX_CEILING):
            raise HTTPException(status_code=400,
                                detail=f"note_max_chars must be an integer {_NOTE_BODY_MAX_FLOOR}..{_NOTE_BODY_MAX_CEILING}")

    # Where a decrypted download is written. Refused here rather than tolerated, because the read
    # path deliberately falls back on anything it cannot parse -- so a typo would silently mean
    # "user_choice" and an administrator would believe they had required something.
    if "download_sink_policy" in payload:
        value = payload["download_sink_policy"]
        if not isinstance(value, str) or value not in _download_sink.ORG_POLICIES:
            raise HTTPException(
                status_code=400,
                detail="download_sink_policy must be one of: "
                       + ", ".join(sorted(_download_sink.ORG_POLICIES)),
            )

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

    # Storage quotas (GB). default_user_quota = the per-account budget an account spends by
    # ALLOCATING storage to vaults; max_vault_size = the per-vault ceiling. Both are enforced at
    # vault create/resize (see _enforce_vault_size); 0 / absent means unlimited on that axis.
    for gb_key in ("default_user_quota", "max_vault_size"):
        if gb_key in payload and payload[gb_key] is not None:
            v = payload[gb_key]
            if isinstance(v, bool) or not isinstance(v, (int, float)) or v < 0:
                raise HTTPException(status_code=400, detail=f"{gb_key} must be a non-negative number of GB")

    # Deployment-wide limit on STORED bytes (GB). Unlike the two quotas above, 0 is a real value
    # here (accept no further bytes) and null clears the override so the deployment runs at its
    # configured maximum — the admin panel offers a bounded 0..MAX_STORAGE_GB range rather than a
    # magic "unlimited" number. Refused when it exceeds that maximum or falls below what is
    # already stored, both of which the message names outright.
    if "deployment_storage_limit_gb" in payload and payload["deployment_storage_limit_gb"] is not None:
        from app.services.vault_service import deployment_storage_used
        reason = storage_quota.validate_deployment_limit(
            payload["deployment_storage_limit_gb"], settings.max_storage_gb,
            deployment_storage_used(db))
        if reason:
            raise HTTPException(status_code=400, detail=reason)

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

    # Account-onboarding policy (email requirement, invitation/signup switches, invite TTL, domain
    # gate, login identifier). Validated by a pure helper so the same rules are unit-testable; the one
    # DB-derived fact it can't know is whether email-only login would lock out an admin.
    from app.core.account_policy import (
        ACCOUNT_POLICY_KEYS, validate_account_policy, AccountPolicyError)
    if any(k in payload for k in ACCOUNT_POLICY_KEYS):
        try:
            normalized = validate_account_policy(
                payload,
                email_login_locks_out_all_admins=_email_login_would_lock_out_all_admins(db),
                smtp_configured=_smtp_configured(db),
                username_email_collision=_username_email_collision(db))
        except AccountPolicyError as exc:
            raise HTTPException(status_code=400, detail=str(exc))
        # Persist the canonical form (deduped/lowercased domains), not the raw input. Mutating the
        # payload here carries the normalized value into the merge in update_settings.
        payload.update(normalized)


@app.get("/settings/login-identifier-readiness")
async def get_login_identifier_readiness(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Who would lose access if Sign-in method were switched to 'email', so the settings UI can warn
    BEFORE the save. Admin-only (the same surface as the settings it informs). Returns the hard-block
    flag, the complete list of admins with no email, whether the requesting admin is one of them, and
    a count of non-admin users with no email."""
    return _login_identifier_readiness(db, current_user)


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
    # Storage limits render as a bounded range, so the panel needs the deployment's hard maximum
    # (null = none configured) and the limit currently in force alongside the raw stored value —
    # a blank field could otherwise not tell "not set" from "unlimited".
    from app.services.vault_service import deployment_storage_used, deployment_storage_limit_bytes
    data["deployment_storage_max_gb"] = (settings.max_storage_gb
                                         if (settings.max_storage_gb or 0) > 0 else None)
    data["deployment_storage_limit_bytes"] = deployment_storage_limit_bytes(db)
    data["deployment_storage_used_bytes"] = deployment_storage_used(db)
    # Overlay the EFFECTIVE Temporary Vault Passcode policy (incl. the ZK-in-scope toggle) so the
    # Settings card renders correct defaults even when never saved (feature default OFF, allow-ZK ON).
    data.update(_temp_passcode_policy(db))
    # Effective org floor for browser-remembering a vault password (default OFF).
    data["force_no_remember_vault_password"] = _force_no_remember_vault_password(db)
    # Effective ZK-key idle auto-lock (minutes; 0 = disabled).
    data["zk_idle_lock_minutes"] = _zk_idle_lock_minutes(db)
    # Effective Sharing master switch (default OFF) so the Settings -> Sharing toggle reflects reality.
    data["sharing_enabled"] = _sharing_enabled(db)
    # Public note-link master switch (default OFF) + the per-user active-link cap (anti-abuse).
    _blob = _global_settings_blob(db)
    data["public_note_links_enabled"] = note_link_policy.public_note_links_enabled(_blob)
    data["public_note_link_user_cap"] = note_link_policy.public_note_link_user_cap(_blob)
    data["note_max_chars"] = _note_max_chars(db)
    # Effective account-onboarding policy (email requirement, invitation + signup switches, domain
    # gate, login identifier) with defaults filled in, so the Accounts & Access tab renders the real
    # posture and a whole-object save can't persist an unchecked default.
    from app.core.account_policy import effective_account_policy
    data.update(effective_account_policy(row.value if row else None))
    # Stored zero means "use deployment default"; expose those defaults separately so the UI
    # can explain the effective fallback without persisting it on an unrelated save.
    for key in _RATE_LIMIT_API_SETTING_KEYS:
        data.setdefault(key, 0)
    data["rate_limit_api_enabled"] = bool(settings.rate_limit_api_enabled)
    data["rate_limit_api_deployment_defaults"] = _api_rate_limit_deployment_defaults()
    # Whether the deployment can send mail — the default sending profile (or the legacy global SMTP
    # config) is usable. The Accounts tab gates email-change verification on this rather than on the
    # now-removed inline SMTP fields.
    data["smtp_configured"] = _smtp_configured(db)
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
        # Shared writer (also used by asset uploads): non-empty sets, empty
        # clears -> env default. Values were validated by _validate_brand_overrides above.
        set_brand_overrides(db, updates={key: payload[key] for key in brand_keys})
    db.commit()
    if (
        _api_rate_limit_policy_cache is not None
        and any(key in (payload or {}) for key in _RATE_LIMIT_API_SETTING_KEYS)
    ):
        _api_rate_limit_policy_cache.replace(merged)
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
# per-component DB flag in SystemSetting('logs'). A dedicated bearer dependency (rather
# than a user endpoint-permission group) validates a LogPullToken by
# peppered-HMAC constant-time compare. Every "off/unknown" path returns 404 so the feature is
# undetectable when disabled, and the response is redacted.
# ===========================================================================
LOGS_SETTINGS_KEY = "logs"
_LOG_SINK_PATH = os.environ.get("LOG_PULL_SINK_PATH", "./logs/combined.log")


def _log_sink_components() -> set:
    """Which components are actually being WRITTEN to the log sink this API reads.

    Only run_combined.py writes it, and it names the components it spawned (see mark_sink_active
    there). That answers a question the API cannot answer for itself, in two parts: every other
    deployment shape — the dev stack and both `split` profiles — starts app.api.api_server
    directly, so nothing is written at all; and even under the launcher the SFTP child is spawned
    only when RUN_SFTP is set, which the shipped default leaves empty.

    Without this, a pull is indistinguishable from a component that merely has no lines yet: both
    are HTTP 200 with an empty list, forever. The admin panel uses it to stop offering a command
    that cannot succeed.
    """
    if str(os.environ.get("VAULT_LOG_SINK_ACTIVE", "")).strip().lower() not in ("1", "true", "yes", "on"):
        return set()
    raw = str(os.environ.get("VAULT_LOG_SINK_COMPONENTS", "")).strip()
    named = {c.strip() for c in raw.split(",") if c.strip()}
    # An older launcher that set the active marker without naming components still wrote `web`.
    return (named or {"web"}) & set(log_pull.SERVEABLE_COMPONENTS)


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
    rather than bricking the vault, so a managing operator can inject PLAN_LOG_PULL and the pepper
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
    (`since` filtering is not implemented yet — only its parsing/filtering; each sink line now
    carries a uniform ISO-8601 UTC timestamp right after its [service] tag to key it on.)
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
        # Per SERVEABLE component: is anything actually writing its lines into the sink? False in
        # every shape that starts the API directly instead of through run_combined.py, false when
        # the sink could not be opened, and false for `sftp` when RUN_SFTP is unset — the shipped
        # default — because the launcher then never spawns that child. Per component rather than a
        # single flag precisely because that last case differs between the two.
        "sink_available": {c: (c in _log_sink_components())
                           for c in log_pull.SERVEABLE_COMPONENTS},
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
# Account invitations (admin-minted). Mint / list / revoke; acceptance is a
# separate, unauthenticated flow (a later phase). Only the peppered HMAC of the
# token is stored; the plaintext invite link is returned exactly ONCE at mint.
# ---------------------------------------------------------------------------
def _invite_status(inv, now):
    """Status derived from the lifecycle timestamps, in precedence order."""
    if inv.revoked_at:
        return "revoked"
    if inv.accepted_at:
        return "accepted"
    if inv.expires_at <= now:
        return "expired"
    return "pending"


@app.post("/invites")
@require_endpoint_permission("USER_MANAGE")
async def create_invite(
    payload: InviteCreate,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Mint an account invitation (interactive admin only — a temp-cred admin is refused). The
    plaintext invite link is returned ONCE; only its peppered HMAC is stored."""
    from app.core.models import AccountInvitation
    from app.core.account_policy import email_allowed_by_domain_gate, signup_email_is_ascii
    from app.core import invitations
    from sqlalchemy.exc import IntegrityError

    pol = _account_policy(db)
    if not pol.get("invite_enabled"):
        raise HTTPException(status_code=400, detail="Invitations are disabled for this deployment.")
    pepper = _invite_pepper()
    if not invitations.pepper_ok(pepper):
        raise HTTPException(status_code=503,
                            detail="Invitations are unavailable: the invite-token secret is not configured.")

    username = payload.username  # markup/@-validated by the schema
    role = payload.role.value if hasattr(payload.role, "value") else str(payload.role)
    now = datetime.utcnow()

    # The username must be free the same way account creation requires: no existing account, no
    # account whose EMAIL equals it (an 'either'-login impersonation vector), and no live invite.
    if db.query(User.id).filter(User.username == username).first():
        raise HTTPException(status_code=400, detail=f"Username '{username}' already exists.")
    if email_in_use(db, username):
        raise HTTPException(status_code=400,
                            detail=f"Username '{username}' conflicts with an existing account's email.")
    if db.query(AccountInvitation.id).filter(
            AccountInvitation.username == username,
            AccountInvitation.revoked_at.is_(None),
            AccountInvitation.accepted_at.is_(None),
            AccountInvitation.expires_at > now).first():
        raise HTTPException(status_code=400, detail=f"Username '{username}' already has a pending invitation.")

    # Email: optional or required per policy, domain-gated, unique.
    email = normalize_email(payload.email)
    if pol.get("email_requirement") == "required" and not email:
        raise HTTPException(status_code=400, detail="An email address is required for new accounts.")
    if email:
        # ASCII-only, same as self-signup: the domain-gate config is ASCII/punycode, so a unicode IDN
        # domain (or a homograph of a denylisted one) would otherwise slip the allow/deny check.
        if not signup_email_is_ascii(email):
            raise HTTPException(status_code=400, detail="That email domain is not permitted.")
        if not email_allowed_by_domain_gate(email, pol.get("signup_email_domain_mode"),
                                            pol.get("signup_email_domains")):
            raise HTTPException(status_code=400, detail="That email domain is not permitted.")
        if email_in_use(db, email):
            raise HTTPException(status_code=400, detail="That email address is already in use.")
        # Symmetric with the username guard: don't let two LIVE invitations claim one address (the
        # "two accounts, one email" impersonation risk email_identity.py exists to prevent). Folded
        # case-insensitively, the same way email_in_use decides "same address".
        from sqlalchemy import func as _func
        if db.query(AccountInvitation.id).filter(
                _func.lower(AccountInvitation.email) == email.lower(),
                AccountInvitation.revoked_at.is_(None),
                AccountInvitation.accepted_at.is_(None),
                AccountInvitation.expires_at > now).first():
            raise HTTPException(status_code=400, detail="That email address already has a pending invitation.")

    # effective_account_policy always fills invite_ttl_hours (validated 1..720); the fallback mirrors
    # the policy DEFAULT (24) only for the pathological empty-blob case, never the shipped 72.
    expires_at = now + timedelta(hours=int(pol.get("invite_ttl_hours") or 24))
    plaintext, prefix = invitations.mint_invite()
    inv = AccountInvitation(
        username=username, email=email, role=role,
        token_prefix=prefix, token_hash=invitations.hash_invite_token(plaintext, pepper),
        expires_at=expires_at, created_by=current_user.id)
    db.add(inv)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="Could not create the invitation; please try again.")
    db.refresh(inv)

    try:
        AuditLogger(db).log_action(
            action="account_invitation_created", status="success", user=current_user,
            ip_address=get_client_ip(request) if request is not None else None,
            details={"username": username, "email": email, "role": role, "token_prefix": prefix})
    except Exception:
        pass

    base = _public_base_url(request) if request is not None else ""
    invite_url = f"{base}/?invite={plaintext}"

    # Send the invitation email carrying the freshly-minted link (the {{action.link}} token). This is
    # the SYSTEM "account_invite" action (always on), so it sends whenever the invite carries an email
    # and SMTP is configured. The link is ALSO returned below for the admin to copy, so a mail failure
    # (or an invite with no email) never blocks the invite — email_sent just tells the UI which to show.
    email_sent = False
    if email:
        try:
            from app.core.email_actions import send_action_email
            _ttl_h = int(pol.get("invite_ttl_hours") or 24)
            email_sent = bool(send_action_email(
                db, "account_invite", recipient={"email": email, "username": username},
                action_context={"link": invite_url, "expires": f"in {_ttl_h} hours"}))
        except Exception:  # noqa: BLE001 — the link is still returned; never fail the mint on mail trouble
            email_sent = False

    return {
        "id": str(inv.id), "username": username, "email": email, "role": role,
        "status": "pending", "expires_at": inv.expires_at.isoformat(), "token_prefix": prefix,
        "token": plaintext,                       # shown ONCE — never stored, never re-returned
        "invite_url": invite_url,
        "email_sent": email_sent,
    }


@app.get("/invites")
@require_endpoint_permission("USER_VIEW")
async def list_invites(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """List invitations with server-derived status. Never returns the token hash or plaintext."""
    from app.core.models import AccountInvitation
    now = datetime.utcnow()
    rows = db.query(AccountInvitation).order_by(AccountInvitation.created_at.desc()).all()
    return [{
        "id": str(i.id), "username": i.username, "email": i.email, "role": i.role,
        "token_prefix": i.token_prefix, "status": _invite_status(i, now),
        "expires_at": i.expires_at.isoformat(),
        "accepted_at": i.accepted_at.isoformat() if i.accepted_at else None,
        "revoked_at": i.revoked_at.isoformat() if i.revoked_at else None,
        "created_at": i.created_at.isoformat() if i.created_at else None,
    } for i in rows]


@app.delete("/invites/{invite_id}")
@require_endpoint_permission("USER_MANAGE")
async def revoke_invite(
    invite_id: str,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
    request: Request = None,
):
    """Revoke an invitation (soft — a revoked invite can never be accepted). Idempotent: a second
    revoke is a no-op success."""
    from app.core.models import AccountInvitation
    try:
        iid = uuid.UUID(str(invite_id))
    except (ValueError, TypeError):
        raise HTTPException(status_code=404, detail="Invitation not found.")
    inv = db.query(AccountInvitation).filter(AccountInvitation.id == iid).first()
    if not inv:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    if inv.revoked_at is None:
        inv.revoked_at = datetime.utcnow()
        db.commit()
        try:
            AuditLogger(db).log_action(
                action="account_invitation_revoked", status="success", user=current_user,
                ip_address=get_client_ip(request) if request is not None else None,
                details={"username": inv.username, "email": inv.email, "token_prefix": inv.token_prefix})
        except Exception:
            pass
    return {"ok": True, "id": str(inv.id), "status": "revoked"}


# ---------------------------------------------------------------------------
# Public invitation acceptance (UNAUTHENTICATED). GET renders the form's inputs;
# POST creates the account. Both fail closed and non-enumerating: an invalid,
# expired, revoked, or already-accepted token — and a globally disabled feature —
# all return the SAME generic 404, so the surface can't be probed for valid tokens.
# ---------------------------------------------------------------------------
def _resolve_valid_invite(db: Session, token: str):
    """Return the AccountInvitation iff it is presently claimable (pending — not revoked, not
    accepted, not expired), else None. Fail CLOSED: any exception, disabled feature, unusable pepper,
    wrong prefix, no match, or non-pending lifecycle -> None, so callers have ONE generic branch and
    the surface is not an enumeration oracle. Mirrors require_log_pull_token: match the hash FIRST
    (constant-time), evaluate lifecycle in Python AFTER — never filter lifecycle in SQL (an expired
    row's absence would otherwise be distinguishable from a never-existed token)."""
    from app.core.models import AccountInvitation
    from app.core import invitations
    try:
        if not _account_policy(db).get("invite_enabled"):
            return None
        pepper = _invite_pepper()
        if not invitations.pepper_ok(pepper):
            return None
        now = datetime.utcnow()
        rows = db.query(AccountInvitation).filter(
            AccountInvitation.token_prefix == invitations.token_prefix(token)
        ).all()
        for r in rows:
            if invitations.invite_tokens_match(token, pepper, r.token_hash):
                if r.revoked_at is not None or r.accepted_at is not None or r.expires_at <= now:
                    return None
                return r
        return None
    except Exception:  # noqa: BLE001 — fail closed, like require_log_pull_token
        return None


def _audit_accept_failure(db: Session, prefix: str, ip: str, reason: str) -> None:
    """Record a failed acceptance attempt (anonymous — no user yet). Never carries the raw token,
    only its public prefix; never raises."""
    try:
        AuditLogger(db).log_action(
            action="account_invitation_accept_failed", status="failure", user=None,
            ip_address=ip, resource_type="account_invitation",
            details={"token_prefix": prefix, "reason": reason})
    except Exception:
        pass


@app.get("/invites/{token}")
async def get_invite(token: str, request: Request, db: Session = Depends(get_db)):
    """PUBLIC: what the acceptance form needs for a claimable token (the claimed username, whether an
    email is still required, the password policy). Every non-usable state returns the same 404."""
    import time as _t
    from app.core import invitations
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    client_ip = get_client_ip(request)
    try:
        allowed, _, reset = _rl.check_rate_limit(
            identifier=client_ip, limit=settings.rate_limit_api_auth,
            window=settings.rate_limit_api_auth_window, prefix="invite_lookup", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})
    if not invitations.pepper_ok(_invite_pepper()):
        raise HTTPException(status_code=503,
                            detail="Invitations are unavailable: the invite-token secret is not configured.")
    inv = _resolve_valid_invite(db, token)
    if inv is None:
        raise HTTPException(status_code=404, detail="Invitation not found.")
    pol = _account_policy(db)
    return {
        "username": inv.username,
        "email": inv.email,
        "email_required": (pol.get("email_requirement") == "required") and not inv.email,
        "password_policy": _password_policy_view(db),
        "expires_at": inv.expires_at.isoformat(),
    }


@app.post("/invites/{token}/accept")
async def accept_invite(token: str, payload: InviteAccept, request: Request,
                        db: Session = Depends(get_db)):
    """PUBLIC: redeem an invitation into a new account. Single-use under concurrency, mass-assignment
    proof (identity comes from the invite row, never the body), rate-limited per IP and per token
    prefix, audited on every outcome. The account is NOT signed in — success lands at the login page."""
    import time as _t
    from app.core.models import AccountInvitation, RoleEnum, User
    from app.core import invitations
    from app.core.email_identity import normalize_email, email_in_use
    from app.core.account_policy import email_allowed_by_domain_gate, signup_email_is_ascii
    from app.core.security import hash_password
    from app.core.endpoint_permissions import grant_default_permissions_for_role
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    from sqlalchemy import update as _sa_update
    from sqlalchemy.exc import IntegrityError

    client_ip = get_client_ip(request)
    prefix = invitations.token_prefix(token)

    # (a) Rate limit — per IP AND per token prefix, both fail-closed (this is an unauthenticated
    # account-creation surface; it must throttle even during a Redis outage).
    for ident, pfx, lim in ((client_ip, "invite_accept_ip", settings.rate_limit_api_auth),
                            (prefix, "invite_accept_prefix", 5)):
        try:
            allowed, _, reset = _rl.check_rate_limit(identifier=ident, limit=lim, window=60,
                                                     prefix=pfx, fail_open=False)
        except RateLimiterUnavailable:
            raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many requests.",
                                headers={"Retry-After": str(max(1, reset - int(_t.time())))})

    # A global config error (pepper unset) is a 503 on BOTH public endpoints, consistent with GET —
    # not a per-token oracle (same answer for every token).
    if not invitations.pepper_ok(_invite_pepper()):
        raise HTTPException(status_code=503,
                            detail="Invitations are unavailable: the invite-token secret is not configured.")

    generic_miss = HTTPException(status_code=404, detail="Invitation not found.")

    # (b) Resolve (also re-checks invite_enabled + pepper). A disabled-after-mint token is no longer
    # acceptable — the master switch is the org's current intent.
    inv = _resolve_valid_invite(db, token)
    if inv is None:
        _audit_accept_failure(db, prefix, client_ip, reason="unresolved")
        raise generic_miss

    # (c)-(e) Post-resolution validation. A rejection here is a legitimate-but-invalid submission on an
    # already-valid token; audit each outcome (the accept contract logs EVERY outcome) with a distinct
    # reason, then re-raise unchanged. Nothing is written to the session yet, so the audit commit is
    # clean. (c) Password policy (beyond the model's 8-char floor):
    try:
        _validate_password_policy(db, payload.password)
    except HTTPException:
        _audit_accept_failure(db, prefix, client_ip, reason="weak_password")
        raise

    # (d) Email: the invite's address if it has one (validated + reserved at mint); otherwise per
    # current policy, domain-gated and unique.
    pol = _account_policy(db)
    if inv.email:
        # The invite's address was validated + reserved at mint. Re-run the application-level
        # uniqueness guard anyway (defense-in-depth for a legacy install lacking the lower(email)
        # unique index, where the flush below would NOT catch a duplicate) so a collision surfaces as
        # a clear audited reason rather than a raw IntegrityError — mirroring the body-email branch.
        if email_in_use(db, inv.email):
            _audit_accept_failure(db, prefix, client_ip, reason="email_in_use")
            raise HTTPException(status_code=409, detail="This invitation cannot be completed.")
        acct_email = inv.email
    else:
        body_email = normalize_email(payload.email)
        if pol.get("email_requirement") == "required" and not body_email:
            _audit_accept_failure(db, prefix, client_ip, reason="email_required")
            raise HTTPException(status_code=400, detail="An email address is required.")
        if body_email:
            # ASCII-only, same as self-signup (uniform across all three account-creation surfaces):
            # a unicode IDN domain would otherwise slip the ASCII/punycode allow/deny gate.
            if not signup_email_is_ascii(body_email):
                _audit_accept_failure(db, prefix, client_ip, reason="email_non_ascii")
                raise HTTPException(status_code=400, detail="That email domain is not permitted.")
            if not email_allowed_by_domain_gate(body_email, pol.get("signup_email_domain_mode"),
                                                pol.get("signup_email_domains")):
                _audit_accept_failure(db, prefix, client_ip, reason="email_domain")
                raise HTTPException(status_code=400, detail="That email domain is not permitted.")
            if email_in_use(db, body_email):
                _audit_accept_failure(db, prefix, client_ip, reason="email_in_use")
                raise HTTPException(status_code=400, detail="That email address is already in use.")
        acct_email = body_email

    # (e) Plan cap — invited accounts count too. Genericize the count-bearing cap message the same way
    # self_signup does: this is a public surface and an invitee has no need for the exact cap/count.
    try:
        _enforce_user_cap(db)
    except HTTPException:
        _audit_accept_failure(db, prefix, client_ip, reason="user_cap")
        raise HTTPException(status_code=503, detail="This invitation cannot be completed right now.")

    # (f) Build the user inline + flush (NO commit) so it lives in the same transaction as the claim.
    # The username==existing-email impersonation guard has no DB backstop, so re-run it here; the
    # username/email UNIQUE constraints cover the other collisions via IntegrityError on flush.
    if email_in_use(db, inv.username):
        _audit_accept_failure(db, prefix, client_ip, reason="username_email_conflict")
        raise HTTPException(status_code=409, detail="This invitation cannot be completed.")
    try:
        role = RoleEnum(inv.role)
    except ValueError:
        _audit_accept_failure(db, prefix, client_ip, reason="bad_role")
        raise HTTPException(status_code=400, detail="This invitation cannot be completed.")
    user = User(username=inv.username, email=acct_email,
                password_hash=hash_password(payload.password),
                role=role, created_by=inv.created_by)
    db.add(user)
    try:
        db.flush()  # surfaces users.username/email UNIQUE conflicts before we claim the invite
    except IntegrityError:
        db.rollback()
        _audit_accept_failure(db, prefix, client_ip, reason="race_conflict")
        raise HTTPException(status_code=409, detail="This invitation cannot be completed.")

    # (g) Atomic single-use claim: the invite must still be pending. rowcount==1, or nothing happened
    # and the flushed user is discarded — so a lost race or a mid-window revoke leaves NO half-account.
    now = datetime.utcnow()
    res = db.execute(
        _sa_update(AccountInvitation)
        .where(AccountInvitation.id == inv.id,
               AccountInvitation.accepted_at.is_(None),
               AccountInvitation.revoked_at.is_(None),
               AccountInvitation.expires_at > now)
        .values(accepted_at=now, accepted_user_id=user.id))
    if res.rowcount != 1:
        db.rollback()
        _audit_accept_failure(db, prefix, client_ip, reason="claim_lost")
        raise generic_miss

    # (h) Grant the role's default permissions inside this same transaction (commit=False).
    grant_default_permissions_for_role(str(user.id), user.role, db, commit=False)

    # (i) One commit for the whole accept.
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        _audit_accept_failure(db, prefix, client_ip, reason="commit_conflict")
        raise HTTPException(status_code=409, detail="This invitation cannot be completed.")

    try:
        AuditLogger(db).log_action(
            action="account_invitation_accepted", status="success", user=user, ip_address=client_ip,
            resource_type="account_invitation", resource_id=str(inv.id),
            details={"username": inv.username, "role": str(user.role), "token_prefix": prefix})
    except Exception:
        pass

    # Optionally welcome the freshly-created account by email (opt-in). Best-effort.
    _fire_action_email(db, "account_welcome", email=user.email, username=user.username)

    # Deliberately NOT auto-logged-in and NO token returned: an invitation link sitting in a mail
    # client's history must not become a live session.
    return {"ok": True, "username": inv.username}


@app.get("/auth/policy")
async def auth_policy(db: Session = Depends(get_db)):
    """PUBLIC, unauthenticated: the MINIMAL policy the login screen needs to render itself and to
    decide whether to offer self-signup. Deliberately a small allowlist of keys — it must NOT leak the
    signup domain lists, invite settings, email-change policy, SMTP/brand config, or anything else
    from the settings blob (PUT /settings merges freely, so a future key could otherwise ride along;
    test_api_signup pins the absent keys). Reuses the fail-safe helpers, so it never 500s the login
    page even on a corrupted settings row."""
    pol = _account_policy(db)
    return {
        "signup_enabled": bool(pol.get("signup_enabled")),
        "password_reset_enabled": bool(pol.get("password_reset_enabled")),
        "login_identifier": pol.get("login_identifier"),
        "email_requirement": pol.get("email_requirement"),
        "password_policy": _password_policy_view(db),
    }


def _email_has_pending_invite(db: Session, email: str) -> bool:
    """Is this email reserved by a LIVE (pending, unrevoked, unexpired) account invitation?

    create_invite reserves an invited address against existing users AND other live invites to avoid
    the 'two accounts, one email' impersonation risk. The other creation paths must honor the same
    reservation, or a squatter could claim an invited address before the invitee accepts. Folded the
    same way email_in_use decides 'same address'. Blank/None never matches."""
    if not email:
        return False
    from app.core.models import AccountInvitation
    from sqlalchemy import func as _func
    now = datetime.utcnow()
    return db.query(AccountInvitation.id).filter(
        _func.lower(AccountInvitation.email) == email.strip().lower(),
        AccountInvitation.revoked_at.is_(None),
        AccountInvitation.accepted_at.is_(None),
        AccountInvitation.expires_at > now).first() is not None


def _audit_signup_failure(db: Session, username: str, ip: str, reason: str) -> None:
    """Record a failed self-signup attempt (anonymous — no account yet). Never carries the password;
    the attempted username is truncated. Never raises."""
    try:
        AuditLogger(db).log_action(
            action="account_self_signup_failed", status="failure", user=None,
            ip_address=ip, resource_type="user",
            details={"username": (username or "")[:64], "reason": reason})
    except Exception:
        pass


# ============ Password reset (self-service, gated OFF by default, + admin-triggered) ============
class ForgotPasswordRequest(BaseModel):
    identifier: str          # a username or an email address


class ResetPasswordRequest(BaseModel):
    # min_length mirrors the sibling password models (the server also enforces HARD_FLOOR=8); max_length
    # bounds the input so a pathologically large body can't be hashed.
    new_password: str = Field(..., min_length=8, max_length=1024)


def _password_reset_policy(db: Session):
    """(enabled, ttl_minutes) — self-service switch + link lifetime, from effective account policy."""
    pol = _account_policy(db)
    return bool(pol.get("password_reset_enabled")), int(pol.get("password_reset_ttl_minutes") or 5)


def _reset_pepper() -> str:
    from app.core.password_reset import reset_pepper
    return reset_pepper(settings.jwt_secret_key)


def _resolve_reset_user(db: Session, identifier: str):
    """Resolve a username OR email to an ACTIVE user, or None. Case-insensitive."""
    ident = (identifier or "").strip()
    if not ident:
        return None
    from sqlalchemy import func as _f
    from app.core.email_identity import find_user_by_email
    u = db.query(User).filter(User.is_active.is_(True),
                              _f.lower(User.username) == ident.lower()).first()
    if u is None and "@" in ident:
        # Reuse the canonical email resolver (SQL-folds both sides, exactly like the unique index), then
        # honour the active-only rule.
        cand = find_user_by_email(db, ident)
        if cand is not None and getattr(cand, "is_active", True):
            u = cand
    return u


def _mint_and_send_reset(db: Session, user, base_url: str, *, created_by_id) -> bool:
    """Mint a single-use reset token (invalidating any prior unconsumed one), email it through the
    password_reset action with the freshly-minted {{action.link}}, and return whether it was sent.
    Never raises — the caller (public or admin) must not fail on mail trouble."""
    from app.core.password_reset import mint_reset_token, hash_reset_token, pepper_ok
    from app.core.models import PasswordResetToken
    from app.core.email_actions import send_action_email
    pepper = _reset_pepper()
    email = (getattr(user, "email", "") or "").strip()
    if not pepper_ok(pepper) or not email:
        return False
    _, ttl = _password_reset_policy(db)
    try:
        db.query(PasswordResetToken).filter(
            PasswordResetToken.user_id == user.id,
            PasswordResetToken.consumed_at.is_(None)).delete(synchronize_session=False)
        plaintext, prefix = mint_reset_token()
        db.add(PasswordResetToken(
            user_id=user.id, token_prefix=prefix, token_hash=hash_reset_token(plaintext, pepper),
            expires_at=datetime.utcnow() + timedelta(minutes=ttl), created_by=created_by_id))
        db.commit()
    except Exception:
        db.rollback()
        return False
    link = f"{(base_url or '').rstrip('/')}/?reset={plaintext}"
    try:
        return bool(send_action_email(db, "password_reset",
                                      recipient={"email": email, "username": user.username},
                                      action_context={"link": link, "expires": f"in {ttl} minutes"}))
    except Exception:
        return False


def _mint_and_send_reset_async(user_id, base_url: str) -> None:
    """Fire-and-forget the self-service reset mint+send on a daemon thread in its OWN session, so a
    resolved identifier doesn't respond measurably slower than an unknown one (a timing enumeration
    oracle). The 202 has already been returned by the time this runs."""
    def _run():
        try:
            from app.core.database import get_db_context
            with get_db_context() as s:
                u = s.query(User).filter(User.id == user_id).first()
                if u is not None:
                    _mint_and_send_reset(s, u, base_url, created_by_id=None)
        except Exception:  # noqa: BLE001
            pass
    try:
        threading.Thread(target=_run, daemon=True).start()
    except Exception:  # noqa: BLE001
        pass


def _resolve_valid_reset_token(db: Session, token: str):
    """The valid, unconsumed, unexpired PasswordResetToken for a presented token, or None. Fails closed
    and never enumerates: lifecycle is checked in Python AFTER a constant-time hash match, so an
    expired/consumed token is indistinguishable from one that never existed."""
    from app.core.password_reset import token_prefix, reset_tokens_match, pepper_ok
    from app.core.models import PasswordResetToken
    try:
        pepper = _reset_pepper()
        if not pepper_ok(pepper):
            return None
        now = datetime.utcnow()
        for r in db.query(PasswordResetToken).filter(
                PasswordResetToken.token_prefix == token_prefix(token)).all():
            if reset_tokens_match(token, pepper, r.token_hash):
                return r if (r.consumed_at is None and r.expires_at > now) else None
    except Exception:
        return None
    return None


@app.post("/auth/forgot-password")
async def forgot_password(body: ForgotPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Public self-service password-reset request. ALWAYS returns 202 (enumeration-safe). A link is
    minted+sent only when self-service is enabled AND the identifier resolves to an active account with
    an email AND SMTP is configured. Rate-limited fail-closed per client IP."""
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    ip = get_client_ip(request)
    try:
        allowed, _, reset = _rl.check_rate_limit(
            identifier=ip, limit=settings.rate_limit_api_auth, window=settings.rate_limit_api_auth_window,
            prefix="forgot_password_ip", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable. Please try again shortly.")
    if not allowed:
        import time as _t
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many requests; please wait a few minutes.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})
    enabled, _ttl = _password_reset_policy(db)
    if enabled and _smtp_configured(db):
        user = _resolve_reset_user(db, body.identifier)
        if user is not None:
            # Background the mint+send so a resolved identifier can't be told apart from an unknown one
            # by response timing (both do only the resolution query on the request path). The link base
            # prefers the configured public host so a spoofed Host header can't poison the emailed token.
            _mint_and_send_reset_async(user.id, _public_base_url(request))
    try:
        AuditLogger(db).log_action(action="password_reset_requested", status="success", user=None,
                                   ip_address=ip, details={})
    except Exception:  # noqa: BLE001
        pass
    return JSONResponse(status_code=202, content={
        "message": "If an account matches and self-service reset is enabled, a reset link has been sent."})


@app.post("/users/{user_id}/send-reset-link")
@require_endpoint_permission("USER_MANAGE")
async def admin_send_reset_link(user_id: uuid.UUID, request: Request,
                                current_user: User = Depends(get_current_user), db: Session = Depends(get_db)):
    """Admin action: email a password-reset link to a user. Always available (independent of the public
    self-service switch), interactive-admin only."""
    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="Temporary credentials cannot manage users.")
    user = db.query(User).filter(User.id == user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not (user.email or "").strip():
        raise HTTPException(status_code=400, detail="That user has no email address to send a reset link to.")
    if not _smtp_configured(db):
        raise HTTPException(status_code=400,
                            detail="Email is not configured. Add a sending profile in Settings -> Email first.")
    sent = _mint_and_send_reset(db, user, _public_base_url(request), created_by_id=current_user.id)
    try:
        AuditLogger(db).log_action(action="password_reset_link_sent", status="success", user=current_user,
                                   ip_address=get_client_ip(request),
                                   details={"target_user_id": str(user_id), "email_sent": bool(sent)})
    except Exception:  # noqa: BLE001
        pass
    return {"email_sent": bool(sent)}


@app.get("/reset/{token}")
async def get_reset(token: str, request: Request, db: Session = Depends(get_db)):
    """Public: validate a reset token and return the minimal info the reset form needs. Generic 404 for
    any unusable token (no enumeration). Rate-limited fail-closed per IP."""
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    ip = get_client_ip(request)
    try:
        allowed, _, _ = _rl.check_rate_limit(
            identifier=ip, limit=settings.rate_limit_api_auth, window=settings.rate_limit_api_auth_window,
            prefix="reset_lookup_ip", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
    if not allowed:
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS, detail="Too many requests; please wait.")
    r = _resolve_valid_reset_token(db, token)
    if r is None:
        raise HTTPException(status_code=404, detail="This reset link is invalid or has expired.")
    user = db.query(User).filter(User.id == r.user_id).first()
    return {"username": (user.username if user else None)}


@app.post("/reset/{token}")
async def do_reset(token: str, body: ResetPasswordRequest, request: Request, db: Session = Depends(get_db)):
    """Public: set a new password using a valid reset token. Single-use (atomic claim); revokes the
    user's sessions so a stolen session can't outlive the reset. Rate-limited fail-closed per IP AND
    per token-prefix."""
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    from app.core.password_reset import token_prefix
    from app.core.security import hash_password
    from app.core.models import PasswordResetToken
    ip = get_client_ip(request)
    prefix = token_prefix(token)
    # Two fail-closed limits: a generous per-IP cap (many users can share one address) and a tight
    # per-token-prefix cap that bounds repeated attempts against ONE known prefix (e.g. a leaked one).
    # Whole-space brute force is already infeasible against the 256-bit token and bounded by the per-IP cap.
    try:
        for ident, pfx, lim, win in (
                (ip, "reset_do_ip", settings.rate_limit_api_auth, settings.rate_limit_api_auth_window),
                (prefix or "none", "reset_do_prefix", 5, 60)):
            allowed, _, reset = _rl.check_rate_limit(identifier=ident, limit=lim, window=win, prefix=pfx, fail_open=False)
            if not allowed:
                import time as _t
                raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                                    detail="Too many attempts; please wait.",
                                    headers={"Retry-After": str(max(1, reset - int(_t.time())))})
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
    r = _resolve_valid_reset_token(db, token)
    if r is None:
        raise HTTPException(status_code=404, detail="This reset link is invalid or has expired.")
    _validate_password_policy(db, body.new_password)     # 400 on a weak password BEFORE the token is burned
    user = db.query(User).filter(User.id == r.user_id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="This reset link is invalid or has expired.")
    # Atomic single-use claim: only the request that flips consumed_at proceeds.
    claimed = db.query(PasswordResetToken).filter(
        PasswordResetToken.id == r.id, PasswordResetToken.consumed_at.is_(None)).update(
        {"consumed_at": datetime.utcnow()}, synchronize_session=False)
    if not claimed:
        db.rollback()
        raise HTTPException(status_code=404, detail="This reset link is invalid or has expired.")
    user.password_hash = hash_password(body.new_password)
    db.commit()
    try:
        # _revoke_sessions mutates session rows but does NOT commit — commit it ourselves so the durable
        # DB-level revocation persists (a hijacked session must not outlive the reset).
        _revoke_sessions(db, user_id=user.id, actor_username="password-reset")   # force re-login everywhere
        db.commit()
    except Exception:  # noqa: BLE001
        try:
            db.rollback()
        except Exception:
            pass
    try:
        AuditLogger(db).log_action(action="password_reset_completed", status="success", user=user,
                                   ip_address=ip, details={})
    except Exception:  # noqa: BLE001
        pass
    return {"ok": True}


@app.post("/auth/signup")
async def self_signup(payload: SignupRequest, request: Request, db: Session = Depends(get_db)):
    """PUBLIC: create an account from the login screen when self-signup is enabled. Mass-assignment
    proof (role forced to 'user', created_by NULL — neither is representable in the body),
    rate-limited per IP AND per attempted username (both fail-closed), email domain-gated + ASCII-only,
    audited on every processed outcome (throttle 429/503 rejections are deliberately not audited, to
    avoid audit-row amplification during an attack). The account is NOT signed in — success returns to
    the login page (mirrors invitation accept)."""
    import time as _t
    from app.core.models import RoleEnum, User
    from app.core.email_identity import normalize_email, email_in_use
    from app.core.account_policy import email_allowed_by_domain_gate, signup_email_is_ascii
    from app.core.security import hash_password
    from app.core.endpoint_permissions import grant_default_permissions_for_role
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable
    from sqlalchemy.exc import IntegrityError

    client_ip = get_client_ip(request)
    uname = payload.username

    # (a) Rate limit — per IP AND per attempted username, both fail-closed (unauthenticated
    # account-creation surface; it must throttle even during a Redis outage). Distinct prefixes so the
    # budgets don't collide with login (rate_limit:login:*) or invites (invite_accept_*). The username
    # key is the raw submitted value (lowered), so even a never-existing name is throttled.
    for ident, pfx, lim in ((client_ip, "signup_ip", settings.rate_limit_api_auth),
                            (uname.strip().lower(), "signup_identifier", 5)):
        try:
            allowed, _, reset = _rl.check_rate_limit(identifier=ident, limit=lim, window=60,
                                                     prefix=pfx, fail_open=False)
        except RateLimiterUnavailable:
            raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
        if not allowed:
            raise HTTPException(status_code=429, detail="Too many requests.",
                                headers={"Retry-After": str(max(1, reset - int(_t.time())))})

    pol = _account_policy(db)

    # (b) Master switch. When self-signup is off the endpoint does not exist as far as a caller can
    # tell — a 404 (not 403), matching the stealth of GET /invites/{token} on a disabled feature.
    if not pol.get("signup_enabled"):
        _audit_signup_failure(db, uname, client_ip, reason="disabled")
        raise HTTPException(status_code=404, detail="Not found.")

    # (c) Password policy (beyond the model's 8-char floor).
    try:
        _validate_password_policy(db, payload.password)
    except HTTPException:
        _audit_signup_failure(db, uname, client_ip, reason="weak_password")
        raise

    # (d) Email per policy. Required when the org requires it OR when login is by email/either (an
    # account with no email could never sign in under those identifiers). ASCII-only: the domain-gate
    # config is ASCII/punycode, so a unicode IDN domain would silently slip the allow/deny check.
    body_email = normalize_email(payload.email)
    email_required = (pol.get("email_requirement") == "required"
                      or pol.get("login_identifier") in ("email", "either"))
    if email_required and not body_email:
        _audit_signup_failure(db, uname, client_ip, reason="email_required")
        raise HTTPException(status_code=400, detail="An email address is required.")
    if body_email:
        if not signup_email_is_ascii(body_email):
            _audit_signup_failure(db, uname, client_ip, reason="email_non_ascii")
            raise HTTPException(status_code=400, detail="This email provider is not allowed to sign up.")
        if not email_allowed_by_domain_gate(body_email, pol.get("signup_email_domain_mode"),
                                            pol.get("signup_email_domains")):
            _audit_signup_failure(db, uname, client_ip, reason="email_domain")
            raise HTTPException(status_code=400, detail="This email provider is not allowed to sign up.")
        # An already-registered address, OR one reserved by a live invitation, cannot self-sign-up.
        # BOTH return the SAME generic message as the domain gate above — on this anonymous surface a
        # distinct "already in use" would confirm whether a given address holds an account (an
        # enumeration oracle), and rejecting an invited address stops a squatter from claiming the
        # identity an admin reserved for someone else (the invitee's later accept would 409). Distinct
        # audit reasons keep operator visibility; the HTTP response is uniform.
        if email_in_use(db, body_email):
            _audit_signup_failure(db, uname, client_ip, reason="email_in_use")
            raise HTTPException(status_code=400, detail="This email provider is not allowed to sign up.")
        if _email_has_pending_invite(db, body_email):
            _audit_signup_failure(db, uname, client_ip, reason="email_invited")
            raise HTTPException(status_code=400, detail="This email provider is not allowed to sign up.")

    # (e) Plan cap. _enforce_user_cap's message names the exact user count and plan cap — fine for an
    # authenticated admin, but on this PUBLIC surface it would hand anonymous visitors a recon oracle.
    # Swap it for a generic answer.
    try:
        _enforce_user_cap(db)
    except HTTPException:
        _audit_signup_failure(db, uname, client_ip, reason="user_cap")
        raise HTTPException(status_code=503, detail="Sign-ups are not available right now.")

    # (f) Uniqueness + impersonation guard, then build the account in ONE transaction. Role is FORCED
    # to USER and created_by is NULL — a self-signed account can never be an admin or claim a creator.
    if db.query(User.id).filter(User.username == uname).first():
        _audit_signup_failure(db, uname, client_ip, reason="username_taken")
        raise HTTPException(status_code=400, detail="That username is already taken.")
    # A username that equals an existing account's email would, under 'either' login (username tried
    # first), shadow that owner. The model already bans '@' in a username, so this is belt-and-braces.
    if email_in_use(db, uname):
        _audit_signup_failure(db, uname, client_ip, reason="username_email_conflict")
        raise HTTPException(status_code=400, detail="That username is already taken.")

    user = User(username=uname, email=body_email,
                password_hash=hash_password(payload.password),
                role=RoleEnum.USER, created_by=None)
    db.add(user)
    try:
        db.flush()  # surfaces users.username/email UNIQUE conflicts (a race with a concurrent signup)
    except IntegrityError:
        db.rollback()
        _audit_signup_failure(db, uname, client_ip, reason="race_conflict")
        raise HTTPException(status_code=400, detail="That username or email is already in use.")

    grant_default_permissions_for_role(str(user.id), user.role, db, commit=False)

    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        _audit_signup_failure(db, uname, client_ip, reason="commit_conflict")
        raise HTTPException(status_code=409, detail="Account could not be created. Please try again.")

    try:
        AuditLogger(db).log_action(
            action="account_self_signup", status="success", user=user, ip_address=client_ip,
            resource_type="user", resource_id=str(user.id), details={"username": uname})
    except Exception:
        pass

    # Optionally welcome the freshly-created account by email (opt-in). Best-effort.
    _fire_action_email(db, "account_welcome", email=user.email, username=user.username)

    # Not auto-logged-in and no token returned — success returns the visitor to the sign-in form.
    return {"ok": True, "username": uname}


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


def _resolved_download_sink(request: Request, db: Session, user: User) -> dict:
    """Organisation policy, the user's preference, and what the browser can actually do.

    The secure-context question is answered from the externally-visible scheme, honouring
    X-Forwarded-Proto from a trusted proxy -- the same helper the security headers use -- because
    a deployment behind a TLS-terminating proxy IS a secure context to the browser even though
    uvicorn saw plain HTTP. Loopback counts too: browsers treat it as trustworthy.
    """
    from app.core.models import SystemSetting, UserPreference

    row = db.query(SystemSetting).filter(SystemSetting.key == _SETTINGS_KEY).first()
    org_policy = (row.value or {}).get("download_sink_policy") if row else None

    pref_row = db.query(UserPreference).filter(UserPreference.user_id == user.id).first()
    user_pref = (pref_row.preferences or {}).get("download_sink") if pref_row else None

    host = (request.url.hostname or "").lower()
    secure = _external_scheme(request) == "https" or host in ("localhost", "127.0.0.1", "::1")

    return _download_sink.describe_download_sink(org_policy, user_pref, secure_context=secure)


@app.get("/zk-enabled")
async def get_zk_enabled(
    request: Request,
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
        # Where this user's decrypted downloads go, already resolved: organisation policy, the
        # user's preference when the organisation delegates, and whether the browser can register
        # a service worker here at all. Resolved server-side so the client has one answer to act
        # on rather than three inputs to combine -- and so the three ways of arriving at
        # "buffered" stay distinguishable in the UI.
        "download_sink": _resolved_download_sink(request, db, current_user),
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
    from app.sftp.host_key import load_host_key
    key_path = settings.sftp_host_key_path
    try:
        if not os.path.exists(key_path):
            return {"available": False}
        # Ed25519 on new installs, RSA on ones that predate it -- report whichever this is.
        host_key = load_host_key(key_path)
        fp = "SHA256:" + base64.b64encode(hashlib.sha256(host_key.asbytes()).digest()).decode().rstrip("=")
        return {"available": True, "algorithm": host_key.get_name(), "fingerprint_sha256": fp}
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
            # Regular user authentication. The org policy decides whether the submitted value is
            # resolved as a username, an email, or either — the temp_ branch above stays first and
            # policy-independent (temp usernames are their own namespace, never an email).
            user, session_token = auth_service.authenticate_user(
                login_request.username,
                login_request.password,
                client_ip,
                login_identifier=_login_identifier(db),
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

        # Persist the owner-facing "your temporary credential just signed in" as an in-app
        # notification too (the WS toast is transient; this is the durable bell/history record). No
        # dedup key — every temp-credential sign-in is a distinct, notable event. Best-effort.
        if is_temporary:
            _notify_users(
                [str(user.id)], "temp_login",
                title="Temporary credential signed in",
                body=f"{login_request.username} signed in" + (f" from {client_ip}" if client_ip else ""),
                target="#temp-creds",
            )
        else:
            # A real account sign-in optionally emails the owner a "New sign-in alert" (opt-in; the
            # default template uses {{current_datetime}}, so no action_context is required). Best-effort.
            _fire_action_email(db, "login_alert", email=user.email, username=user.username)

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

    # Optionally email the account owner that a temporary credential was issued for their access
    # (opt-in). NEVER include the credential plaintext — only that one exists + when it expires.
    _lifetime = temp_creds.get('total_lifetime_minutes')
    _fire_action_email(db, "temp_credential_issued", email=current_user.email, username=current_user.username,
                       action_context={"expires": f"in {_lifetime} minutes"} if _lifetime else {})

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
            # A temp password is show-once at creation and never stored for re-reveal, so there is
            # never a retrievable password to fetch (the reveal endpoint always 404s).
            'has_password': False
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

    # Release any chunked upload the credential had open. Those sessions are bound to the
    # principal that started them, so once the credential is gone nobody can finish them and
    # nobody but a deployment administrator could clear them -- while they keep occupying the
    # account's session budget until they expire. The buffered chunks are swept with the row.
    #
    # Marked cancelled rather than deleted, so the ordinary sweeper reclaims the bytes on its
    # own schedule rather than this request doing filesystem work. The row leaves the active
    # listing immediately and the sweep removes it shortly after; what survives for auditing
    # is the audit row, not this one.
    if temp_credential_id is not None:
        for up in db.query(ChunkedUploadSession).filter(
            ChunkedUploadSession.temp_credential_id == temp_credential_id,
            ChunkedUploadSession.status == 'active',
        ).all():
            up.status = 'cancelled'

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
    # A temporary credential is single-login: once its session is gone it cannot log back in,
    # so terminating its sessions ends it as surely as deactivating it does. Release the
    # uploads it left open, the same as the other two paths -- otherwise they stay active,
    # finishable by nobody, and count against the account's session budget until they expire.
    for _up in db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.temp_credential_id == temp_cred.id,
        ChunkedUploadSession.status == 'active',
    ).all():
        _up.status = 'cancelled'

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
    """Storage usage for this deployment: bytes stored across active vaults, the capacity of the
    underlying storage volume, and the limit picture the admin panel renders.

    `limit_bytes` is what is actually enforced on stored bytes (null = unlimited); `max_bytes` is
    the deployment's hard ceiling from MAX_STORAGE_GB, which the panel shows as the top of the
    range an admin may choose from. `allocated_bytes` is the sum of every active vault's declared
    limit — reported so an operator can see how much has been promised, NOT enforced against this
    limit: an empty vault costs nothing until files land in it."""
    from sqlalchemy import func as _f
    from app.services.vault_service import deployment_storage_used, deployment_storage_limit_bytes
    used = deployment_storage_used(db)
    total = available = 0
    try:
        usage = shutil.disk_usage(settings.file_storage_path)
        total, available = usage.total, usage.free
    except OSError as e:
        # Capacity is best-effort — never fail the panel if the path can't be stat'd.
        print(f"storage_stats: disk_usage unavailable: {e}")
    allocated = int(db.query(_f.coalesce(_f.sum(Vault.size_limit), 0)).filter(
        Vault.is_active == True).scalar() or 0)  # noqa: E712
    limit = deployment_storage_limit_bytes(db)
    return {
        "total": total,
        "used": used,
        "available": available,
        "allocated_bytes": allocated,
        "limit_bytes": limit,
        "max_bytes": storage_quota.env_ceiling_bytes(settings.max_storage_gb),
        "vault_count": int(db.query(_f.count(Vault.id)).filter(
            Vault.is_active == True).scalar() or 0),  # noqa: E712
    }


# ==============================================================================
# WebSocket Endpoint for Live Monitoring
# ==============================================================================

def _ws_session_invalid(session_token: str, user_id: str, is_temporary: bool) -> bool:
    """Re-check, on a LIVE /ws/monitor socket, whether the session has since been revoked, so the
    socket can be closed promptly (the handshake only validates at CONNECT). Covers logout, admin
    terminate-sessions, account lock/deactivate, and temp-credential invalidation -- all of which
    either denylist the token or flip the session/account state. Returns True when the socket should
    be torn down. Fails OPEN (returns False) on a transient error so a DB blip can't drop every live
    socket at once; the next cycle re-checks."""
    try:
        from app.core.database import SessionLocal
        from app.services.auth_service import is_token_denylisted, account_locked
        from app.core.models import ActiveSession as _AS, User as _U
        if is_token_denylisted(session_token):
            return True
        db = SessionLocal()
        try:
            row = db.query(_AS.revoked, _AS.is_active).filter(
                _AS.session_token == hash_session_token(session_token)).first()
            if row is None:
                return True  # session row gone -> treat as terminated
            revoked, is_active = row
            if revoked:
                return True
            if is_temporary and not is_active:
                return True  # temp credential invalidated (_revoke_sessions flips is_active)
            u = db.query(_U).filter(_U.id == uuid.UUID(user_id)).first()
            if not u or not u.is_active or account_locked(u):
                return True
        finally:
            db.close()
    except Exception as e:
        print(f"[WS] periodic session re-check error (ignored): {e}")
        return False
    return False


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
                        _WsAS.session_token == hash_session_token(session_token)
                    ).first()
                    if _rev is not None and _rev[0]:
                        raise ValueError("Session terminated")
                else:
                    # Temp sessions: full parity with get_current_user, which bounds a temp session
                    # by an ACTIVE session row, the inactivity grace window, AND the credential's own
                    # deactivate_at/expires_at lifetime -- and fails CLOSED if the backing credential
                    # row is gone. Invalidating/deleting the credential flips ActiveSession.is_active
                    # to False (see _revoke_sessions); a credential minted with a validity window
                    # shorter than the token's life is refused past deactivate_at even while its
                    # session row is still nominally active. None of this denylists the token, so the
                    # handshake must re-derive it here rather than trust signature+exp alone.
                    from app.core.models import TemporaryCredential as _WsTC
                    from datetime import timedelta as _wstd
                    _sess = _wsdb.query(_WsAS.last_activity, _WsAS.temp_credential_id).filter(
                        _WsAS.session_token == hash_session_token(session_token),
                        _WsAS.is_active == True,  # noqa: E712
                    ).first()
                    if _sess is None:
                        raise ValueError("Session terminated")
                    _grace = int(os.getenv("TEMP_CRED_SESSION_GRACE_MINUTES", "65"))
                    _cutoff = datetime.now(timezone.utc) - _wstd(minutes=_grace)
                    _la = _sess[0]
                    if _la is not None and _la.tzinfo is None:
                        _la = _la.replace(tzinfo=timezone.utc)
                    if _la is not None and _la < _cutoff:
                        raise ValueError("Session terminated")
                    # Fail closed: an active session whose backing credential row is gone must not
                    # authorize (it would otherwise run unscoped).
                    _tc = _wsdb.query(_WsTC.deactivate_at, _WsTC.expires_at).filter(
                        _WsTC.id == _sess[1]
                    ).first()
                    if _tc is None:
                        raise ValueError("Session terminated")
                    _now = datetime.now(timezone.utc)
                    for _lim in (_tc[0], _tc[1]):
                        if _lim is None:
                            continue
                        if _lim.tzinfo is None:
                            _lim = _lim.replace(tzinfo=timezone.utc)
                        if _now > _lim:
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
            inner = ev.get('event', ev) if isinstance(ev, dict) else {}
            # A temp / scoped-temp connection must NEVER receive notification nudges: they belong to
            # the PARENT account, and a scoped credential (handed to an external party) has no business
            # seeing the owner's live notification metadata. The JS client already ignores them; this
            # keeps them off the wire too. (Checked before the admin short-circuit: an admin acting via
            # a temp credential is not a full admin here.)
            if is_temporary and inner.get('type') == 'notification':
                return False
            if is_admin_conn:
                return True
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
            # The handshake validates the session once; this socket is now app-wide and long-lived
            # (its whole session, up to the token's exp), so re-check revocation periodically and tear
            # it down promptly when the session is logged out / terminated / locked. Without this a
            # revoked session (an admin's, streaming the whole fleet feed) would keep receiving events
            # until natural expiry, and the "terminate sessions" control would not cut the live socket.
            loops = 0
            while True:
                try:
                    loops += 1
                    if loops >= 45:  # each loop ~0.11s -> re-check about every 5s
                        loops = 0
                        revoked = await asyncio.get_event_loop().run_in_executor(
                            None, _ws_session_invalid, session_token, user_id, is_temporary)
                        if revoked:
                            print("[WS] session revoked/terminated; closing live socket")
                            break
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

        # Optionally send the new account a welcome email (opt-in). Best-effort.
        _fire_action_email(db, "account_welcome", email=new_user.email, username=new_user.username)

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
    # Omitting "email" and sending it explicitly as null are DIFFERENT requests: the first leaves
    # the address alone, the second clears it. `Optional[EmailStr] = None` collapses both to None,
    # so ask pydantic which fields the client actually sent. Without this a user could never remove
    # their own address — the request would be indistinguishable from one that never mentioned it.
    email_supplied = "email" in body.model_fields_set
    new_email = normalize_email(body.email) if email_supplied else None
    changing_email = email_supplied and new_email != user.email
    sensitive = body.new_password is not None or changing_email
    if sensitive:
        if not body.current_password or not user.password_hash or not verify_password(body.current_password, user.password_hash):
            raise HTTPException(status_code=400, detail="Your current password is required and must be correct.")

    if body.new_password is not None:
        _validate_password_policy(db, body.new_password)
        user.password_hash = hash_password(body.new_password)
        changes.append("password")
    if changing_email:
        # When the organization requires it, a self email CHANGE must be proved with a code sent to
        # the new address (request-email-change / confirm-email-change below). A direct change here is
        # refused so the verification can't be bypassed. Clearing the address (new_email is None) has
        # nothing to verify and still goes direct.
        if new_email is not None and _email_change_requires_verification(db):
            raise HTTPException(
                status_code=400,
                detail="Changing your email requires verification. Request a code sent to the new "
                       "address from account settings.")
        # Case-insensitive, so a clash cannot be slipped through by changing only the case. The
        # previous check compared against str(body.email), which would have matched the literal
        # string "None" once an address could legitimately be absent.
        if new_email is not None and email_in_use(db, new_email, exclude_user_id=user.id):
            raise HTTPException(status_code=400, detail="That email address is already in use.")
        # An address reserved by a live invitation belongs to whoever was invited — don't let a
        # different account claim it via an email change (generic message: don't reveal it's invited).
        if new_email is not None and _email_has_pending_invite(db, new_email):
            raise HTTPException(status_code=400, detail="That email address is already in use.")
        # Under email-only login the address IS the sign-in identifier. Clearing it used to be allowed
        # unconditionally (a username still identified the account) — but that let an admin remove the
        # last email-resolvable admin's address AFTER the policy switch, reaching the exact total
        # lockout the switch-time guard prevents. Refuse the clear in that case.
        if new_email is None and _clearing_email_locks_out_all_admins(db, user):
            raise HTTPException(
                status_code=400,
                detail="Your email is the sign-in identifier for this deployment and can't be removed: "
                       "it would lock every administrator out. Give another admin an email, or change "
                       "the sign-in method first.")
        user.email = new_email
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


# -- Verified self-service email change (request a code, then confirm it) -------
# When the org policy requires it, changing your OWN email is proved by a one-time code sent to the
# NEW address, so an account is never moved to an address the requester does not control. The
# current-password re-auth still applies (a hijacked live session cannot start the flow); admin
# create/set of an email is a separate, already-trusted act and is exempt.
class EmailChangeRequest(BaseModel):
    new_email: EmailStr
    current_password: str


class EmailChangeConfirm(BaseModel):
    code: str


@app.post("/users/me/request-email-change")
async def request_email_change(
    body: EmailChangeRequest,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Start a verified change of the caller's OWN email: re-prove the current password, then send a
    one-time code to the NEW address. The account email is not touched until the code is confirmed.
    Enumeration-safe: an address already in use (or unchanged) gets the same 202 and no usable code."""
    from app.core.security import verify_password
    from app.core import otp_service
    from app.core.rate_limiter import rate_limiter as _rl

    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="Temporary credentials cannot change account settings.")
    user = db.query(User).filter(User.id == current_user.id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    if not _email_change_requires_verification(db):
        raise HTTPException(status_code=400, detail="Email-change verification is not enabled for this deployment.")
    if not _smtp_configured(db):
        raise HTTPException(status_code=400, detail="Email is not configured, so a verification code cannot be sent.")
    # Re-prove the current password before starting the flow (a hijacked live session must not be
    # able to move the account to an attacker's address).
    if not user.password_hash or not verify_password(body.current_password, user.password_hash):
        raise HTTPException(status_code=400, detail="Your current password is required and must be correct.")
    # Cap the outbound-email request per user — the code lands in a requester-chosen inbox.
    allowed, _, reset = _rl.check_rate_limit(identifier=str(user.id), limit=3, window=300,
                                             prefix="email_change_code")
    if not allowed:
        import time as _t
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many email-change requests; please wait a few minutes.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})
    new_email = normalize_email(body.new_email)
    # Mint + send only for a genuinely new, unused address; otherwise return the same 202 with no
    # usable code, so this endpoint can't be used to probe which addresses are registered.
    if new_email and new_email != user.email and not email_in_use(db, new_email, exclude_user_id=user.id):
        # Mint a one-time code bound to (email_change, this user, the new address). Redis-primary with a
        # durable DB fallback; issuing invalidates any prior code (one pending change at a time). TTL is
        # org-configurable (default 5 minutes).
        ttl = _email_change_otp_ttl_minutes(db)
        code = otp_service.issue(db, purpose="email_change", user_id=user.id, destination=new_email,
                                 ttl_minutes=ttl, pepper=settings.jwt_secret_key)
        # Route through the central action helper so this uses the admin-customizable "email_change"
        # template (its {{action.code}} / {{action.expires}} tokens). raise_errors preserves the prior
        # behavior: a clean 400/502 on a config/transport failure rather than a silent miss.
        from app.core.email_actions import send_action_email
        from app.core import email_send as _es
        try:
            send_action_email(
                db, "email_change",
                recipient={"email": new_email, "username": user.username},
                action_context={"code": code, "expires": f"in {ttl} minutes"},
                raise_errors=True)
        except _es.EmailSendError as e:
            code_status = (status.HTTP_400_BAD_REQUEST if e.category == "config"
                           else status.HTTP_502_BAD_GATEWAY)
            raise HTTPException(status_code=code_status, detail=e.message)
    try:
        AuditLogger(db).log_action(action="email_change_requested", status="success", user=user,
                                   ip_address=get_client_ip(request), details={})
    except Exception:  # noqa: BLE001
        pass
    return JSONResponse(status_code=202, content={
        "message": "If that address can receive mail, a verification code has been sent to it."})


@app.post("/users/me/confirm-email-change", response_model=UserResponse)
async def confirm_email_change(
    body: EmailChangeConfirm,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Complete a verified email change by presenting the code sent to the new address. On success
    the account's email becomes the new address and the code is consumed (single-use)."""
    from app.core import otp_service
    from app.core.rate_limiter import rate_limiter as _rl

    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="Temporary credentials cannot change account settings.")
    user = db.query(User).filter(User.id == current_user.id).first()
    if user is None:
        raise HTTPException(status_code=404, detail="User not found")
    # Cap confirm attempts — an OUTER brute-force guard on the code space (the OTP service also
    # invalidates the code after 3 wrong tries).
    allowed, _, reset = _rl.check_rate_limit(identifier=str(user.id), limit=10, window=300,
                                             prefix="email_change_confirm")
    if not allowed:
        import time as _t
        raise HTTPException(status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                            detail="Too many attempts; please wait a few minutes.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})
    result = otp_service.verify(db, purpose="email_change", user_id=user.id, code=body.code,
                                pepper=settings.jwt_secret_key)
    if not result.ok or not result.destination:
        raise HTTPException(status_code=400, detail="That code is invalid or has expired.")
    new_email = result.destination
    # Re-check uniqueness at apply time — the address may have been taken since the request.
    if email_in_use(db, new_email, exclude_user_id=user.id):
        raise HTTPException(status_code=400, detail="That email address is now in use.")
    old_email = user.email
    user.email = new_email
    db.commit()
    db.refresh(user)
    try:
        AuditLogger(db).log_action(action="email_change_confirmed", status="success", user=user,
                                   ip_address=get_client_ip(request),
                                   details={"old": old_email, "new": new_email})
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
    "background": {"slate", "graphite", "navy", "ocean",
                   "forest", "warm", "ember", "plum"},
    "ui": {"v1", "v2"},
    # Per-user opt-out of browser-remembering a vault password. Stored as a string enum ('on'/'off')
    # because _sanitize_preferences keeps only string values in the whitelist (a bare bool is dropped).
    "never_remember_vault_password": {"on", "off"},
    # How the vault list is ordered. Kept here rather than in localStorage so the ordering follows
    # the account across browsers and devices, the way the theme already does. String enums,
    # because _sanitize_preferences only keeps whitelisted strings.
    "vault_sort": {"name", "size", "files", "created", "viewed"},
    "vault_sort_dir": {"asc", "desc"},
    "vault_fav_group": {"first", "last", "mixed"},
    # Where this user's decrypted downloads are written, when the organisation delegates the
    # choice. Consulted only then -- see app/core/download_sink.py for the precedence.
    "download_sink": {"buffered", "streaming"},
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
    vault_sort: Optional[str] = None
    vault_sort_dir: Optional[str] = None
    vault_fav_group: Optional[str] = None
    download_sink: Optional[str] = None


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


@app.get("/users/{user_id}/storage")
@require_endpoint_permission("USER_VIEW")
async def get_user_storage(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """One account's storage budget and what it has spent, for the admin user editor.

    Returns the EFFECTIVE quota (null = none) alongside the raw override and where the number
    came from, so the editor can show "inherits the 10 GB default" rather than a bare figure an
    administrator would have to guess the origin of."""
    # Own-or-admin, checked BEFORE the existence lookup to avoid an enumeration oracle (mirrors
    # get_user above).
    if current_user.role != RoleEnum.ADMIN and current_user.id != user_id:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Access denied")
    user = db.query(User).filter(User.id == user_id).first()
    if not user:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="User not found")

    override = user.storage_quota_bytes
    quota = _account_quota_bytes(db, user)
    allocated = _account_allocated_bytes(db, user.id)
    return {
        "user_id": str(user.id),
        "username": user.username,
        "storage_quota_bytes": override,
        "effective_quota_bytes": quota,
        "allocated_bytes": allocated,
        "available_bytes": storage_quota.account_headroom_bytes(quota, allocated),
        "default_quota_bytes": storage_quota.quota_setting_bytes(
            _settings_blob(db).get("default_user_quota")),
        "budget_exempt": _is_budget_exempt(user),
        "quota_source": ("exempt" if _is_budget_exempt(user) else
                         "account" if override is not None else
                         "default" if quota is not None else "unlimited"),
    }


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

    # Own-or-admin, checked BEFORE the existence lookup to avoid a user-enumeration oracle (mirrors
    # get_user / user_management.get_user_detail — a non-admin granted USER_MANAGE must not be able
    # to distinguish an existing user id from a nonexistent one via a 403-vs-404 split). A TEMP
    # session keeps role==ADMIN but must not wield admin power here: treat it as non-admin so the
    # admin-only branch (role/is_active/is_locked) AND any cross-user password reset are unreachable
    # by a temp credential — a temp admin acting on ANOTHER user fails this gate and gets 403.
    is_admin = current_user.role == RoleEnum.ADMIN and not getattr(current_user, "_is_temp_session", False)
    is_self = current_user.id == user_id

    if not (is_admin or is_self):
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

    # Track changes for audit log
    changes = {}
    
    # Non-admin users can only update their own email and password.
    # "email" omitted leaves the address alone; sent as an explicit null clears it.
    if "email" in user_update.model_fields_set:
        new_email = normalize_email(user_update.email)
        # Changing your OWN email here would sidestep the re-proof its sibling requires. Exactly like
        # the password field just below, the id form refuses a self change and points at /users/me,
        # which demands the current password (and, when the org requires it, an emailed verification
        # code). An admin changing SOMEONE ELSE's email is a different, already-trusted act and still
        # allowed. A no-op resave of one's own address is not a change and falls through.
        if is_self and new_email != user.email:
            raise HTTPException(
                status_code=400,
                detail="Change your own email from account settings, which requires your "
                       "current password.",
            )
        # This path previously assigned the address with NO uniqueness check at all, so an exact
        # duplicate reached the database and surfaced as an uncaught IntegrityError 500.
        if new_email is not None and email_in_use(db, new_email, exclude_user_id=user.id):
            raise HTTPException(status_code=400, detail="That email address is already in use.")
        # Don't let an admin assign an address a live invitation already reserved for someone else.
        if new_email is not None and _email_has_pending_invite(db, new_email):
            raise HTTPException(status_code=400, detail="That email address is already in use.")
        # Removing an admin's email under email-only login can strand every admin — the total lockout
        # the policy-switch guard prevents, reachable here by clearing an email afterward. Refuse it.
        if new_email is None and _clearing_email_locks_out_all_admins(db, user):
            raise HTTPException(
                status_code=400,
                detail="This admin's email is the sign-in identifier for the deployment and can't be "
                       "removed: it would lock every administrator out.")
        changes['email'] = {'old': user.email, 'new': new_email}
        user.email = new_email
    
    if user_update.password is not None:
        # Setting your OWN password here would sidestep the re-proof its sibling requires.
        # PATCH /users/me demands the current password before a password or email change,
        # precisely so a hijacked live session cannot take the account over -- and addressing
        # the same account by id instead of "me" reached the same field with no proof at all.
        # That is the whole of the control, so the id form refuses and says where to go.
        #
        # An admin resetting SOMEONE ELSE's password is a different act and still allowed: it is
        # a reset, performed by a party who is already trusted with the account, and no password
        # of the target's exists to re-prove.
        if is_self:
            raise HTTPException(
                status_code=400,
                detail="Change your own password from account settings, which requires your "
                       "current password.",
            )
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

        # Per-account storage budget. Admin-only and deliberately outside the self-service
        # branch above: a user who could raise their own quota would make the deployment
        # default advisory. Absent = leave as-is, which is why model_fields_set is consulted
        # rather than the value (an explicit null means "inherit the default").
        if "storage_quota_gb" in user_update.model_fields_set:
            try:
                new_quota = storage_quota.parse_account_quota_input(user_update.storage_quota_gb)
            except ValueError as exc:
                raise HTTPException(status_code=400, detail=str(exc))
            changes['storage_quota_bytes'] = {'old': user.storage_quota_bytes, 'new': new_quota}
            user.storage_quota_bytes = new_quota

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
    "allow_view_only", "default_view_only", "force_view_only", "allow_custom", "auto_enroll_new_users",
    "allowed_audiences",
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
        "force_view_only": t.force_view_only,
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
        # Report only a COUNT, never the ids themselves: echoing the submitted-but-unknown ids back
        # would turn this into an existence oracle for arbitrary user/group ids.
        raise HTTPException(status_code=400, detail=f"{field} contains {len(missing)} unknown id(s).")


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
    # Forcing view-only implies view-only is permitted; the contradictory combo is rejected.
    if eff.get("force_view_only") and eff.get("allow_view_only") is False:
        raise HTTPException(status_code=400, detail="force_view_only requires allow_view_only")
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


# ---------------------------------------------------------------------------
# Note-link tags — admin policy templates for PUBLIC note links ("Links"). A
# tag is a security FLOOR; a user creating a link may only tighten it (enforced
# in a later phase). Anonymous, so the tag governs how hard the link is to reach.
# ---------------------------------------------------------------------------
_NOTE_LINK_TAG_NOT_NULLABLE = (
    "name", "is_active", "min_token_len", "require_secret", "min_pin_len",
    "password_min_len", "password_require_alnum",
    "allowed_department_ids", "allowed_user_ids", "blocked_user_ids", "auto_enroll_new_users",
)


class NoteLinkTagCreate(BaseModel):
    name: str
    description: Optional[str] = None
    is_active: bool = True
    border_color: Optional[str] = None
    icon: Optional[str] = None
    min_token_len: int = 10
    default_ttl_hours: Optional[int] = None
    max_ttl_hours: Optional[int] = None
    require_secret: str = "none"
    min_pin_len: int = 4
    password_min_len: int = 8
    password_require_alnum: bool = False
    max_uses_cap: Optional[int] = None
    allowed_department_ids: list = Field(default_factory=list)
    allowed_user_ids: list = Field(default_factory=list)
    blocked_user_ids: list = Field(default_factory=list)
    auto_enroll_new_users: bool = False


class NoteLinkTagUpdate(BaseModel):
    name: Optional[str] = None
    description: Optional[str] = None
    is_active: Optional[bool] = None
    border_color: Optional[str] = None
    icon: Optional[str] = None
    min_token_len: Optional[int] = None
    default_ttl_hours: Optional[int] = None
    max_ttl_hours: Optional[int] = None
    require_secret: Optional[str] = None
    min_pin_len: Optional[int] = None
    password_min_len: Optional[int] = None
    password_require_alnum: Optional[bool] = None
    max_uses_cap: Optional[int] = None
    allowed_department_ids: Optional[list] = None
    allowed_user_ids: Optional[list] = None
    blocked_user_ids: Optional[list] = None
    auto_enroll_new_users: Optional[bool] = None


def _note_link_tag_dict(t: NoteLinkTag) -> dict:
    return {
        "id": str(t.id), "name": t.name, "description": t.description, "is_active": bool(t.is_active),
        "border_color": t.border_color, "icon": t.icon,
        "min_token_len": t.min_token_len,
        "default_ttl_hours": t.default_ttl_hours, "max_ttl_hours": t.max_ttl_hours,
        "require_secret": t.require_secret, "min_pin_len": t.min_pin_len,
        "password_min_len": t.password_min_len, "password_require_alnum": bool(t.password_require_alnum),
        "max_uses_cap": t.max_uses_cap,
        "allowed_department_ids": t.allowed_department_ids or [],
        "allowed_user_ids": t.allowed_user_ids or [],
        "blocked_user_ids": t.blocked_user_ids or [],
        "auto_enroll_new_users": bool(t.auto_enroll_new_users),
        "created_at": t.created_at.isoformat() if t.created_at else None,
        "updated_at": t.updated_at.isoformat() if t.updated_at else None,
    }


def _audit_note_link_tag(db, request, user, action, tag):
    try:
        AuditLogger(db).log_action(action=action, status="success", user=user,
                                   resource_type="note_link_tag", resource_id=str(tag.id),
                                   details={"name": tag.name}, ip_address=get_client_ip(request))
    except Exception:
        pass


@app.get("/note-link-tags")
async def list_note_link_tags(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """List all note-link tags (active AND inactive) for the admin manager."""
    tags = db.query(NoteLinkTag).order_by(NoteLinkTag.name).all()
    return [_note_link_tag_dict(t) for t in tags]


@app.post("/note-link-tags")
async def create_note_link_tag(
    payload: NoteLinkTagCreate,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Create a note-link tag (interactive-admin). Name unique; policy validated against the floor rules."""
    data = payload.model_dump()
    data["name"] = (data.get("name") or "").strip()
    for k in ("allowed_department_ids", "allowed_user_ids", "blocked_user_ids"):
        data[k] = [str(x) for x in (data.get(k) or [])]
    try:
        note_link_policy.validate_tag_fields(data)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    existing = db.query(NoteLinkTag).filter(NoteLinkTag.name == data["name"]).first()
    if existing:
        raise HTTPException(status_code=400,
                            detail="A note-link tag with that name already exists"
                            if existing.is_active else
                            "A deactivated tag already uses this name — reactivate it or choose another")
    tag = NoteLinkTag(created_by=current_user.id, **data)
    db.add(tag)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="A note-link tag with that name already exists")
    db.refresh(tag)
    _audit_note_link_tag(db, request, current_user, "note_link_tag_created", tag)
    return _note_link_tag_dict(tag)


@app.patch("/note-link-tags/{tag_id}")
async def update_note_link_tag(
    tag_id: uuid.UUID,
    payload: NoteLinkTagUpdate,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Update a note-link tag (interactive-admin). Only PROVIDED keys change."""
    tag = db.query(NoteLinkTag).filter(NoteLinkTag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Note-link tag not found")
    data = payload.model_dump(exclude_unset=True)
    for k in _NOTE_LINK_TAG_NOT_NULLABLE:
        if k in data and data[k] is None:
            raise HTTPException(status_code=400, detail=f"{k} cannot be null")
    if "name" in data:
        data["name"] = (data["name"] or "").strip()
        if not data["name"]:
            raise HTTPException(status_code=400, detail="Tag name cannot be empty")
        if db.query(NoteLinkTag).filter(NoteLinkTag.name == data["name"], NoteLinkTag.id != tag_id).first():
            raise HTTPException(status_code=400, detail="A note-link tag with that name already exists")
    for k in ("allowed_department_ids", "allowed_user_ids", "blocked_user_ids"):
        if k in data:
            data[k] = [str(x) for x in (data[k] or [])]
    eff = _note_link_tag_dict(tag)
    eff.update(data)
    try:
        note_link_policy.validate_tag_fields(eff)
    except ValueError as e:
        raise HTTPException(status_code=400, detail=str(e))
    for k, v in data.items():
        setattr(tag, k, v)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=400, detail="A note-link tag with that name already exists")
    db.refresh(tag)
    _audit_note_link_tag(db, request, current_user, "note_link_tag_updated", tag)
    return _note_link_tag_dict(tag)


@app.delete("/note-link-tags/{tag_id}")
async def deactivate_note_link_tag(
    tag_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Soft-deactivate a note-link tag (interactive-admin) — stops NEW links; existing links keep
    their snapshot policy. Reactivate via PATCH is_active=true."""
    tag = db.query(NoteLinkTag).filter(NoteLinkTag.id == tag_id).first()
    if not tag:
        raise HTTPException(status_code=404, detail="Note-link tag not found")
    tag.is_active = False
    db.commit()
    _audit_note_link_tag(db, request, current_user, "note_link_tag_deactivated", tag)
    return {"message": f"Note-link tag '{tag.name}' deactivated", "id": str(tag.id), "is_active": False}


# ============================ PUBLIC NOTE LINKS (anonymous snapshot links) =========================
# A NoteLink is an anonymous, tokenized SNAPSHOT of one note, governed by a NoteLinkTag floor that the
# owner may only TIGHTEN. Creation is authenticated + feature-gated + allowlisted + per-user-capped;
# redemption is PUBLIC, rate-limited, optionally secret-gated with a per-link lockout, and audited.

_NOTELINK_TOKEN_ALPHABET = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"  # base62
_NOTELINK_REDEEM_LIMIT = 10          # redemption requests / minute / IP (and / token)
_NOTELINK_REDEEM_WINDOW = 60
_NOTELINK_FAIL_MAX = 5               # wrong-secret attempts before a lockout
_NOTELINK_FAIL_WINDOW = 900          # 15-minute lockout window
_NOTELINK_TOKEN_MAX_INPUT = 128      # reject absurd tokens before they touch redis/db
_NOTELINK_SECRET_MAX = note_link_policy.PASSWORD_MAX_LEN   # cap the redeem secret before argon2


def _notelink_gen_token(n: int) -> str:
    import secrets as _secrets
    return "".join(_secrets.choice(_NOTELINK_TOKEN_ALPHABET) for _ in range(int(n)))


def _notelink_status(link, now=None) -> str:
    now = now or datetime.utcnow()
    if link.revoked:
        return "revoked"
    if link.expires_at and link.expires_at <= now:
        return "expired"
    if link.max_uses is not None and link.use_count >= link.max_uses:
        return "exhausted"
    return "active"


def _notelink_public_dict(link, tag=None) -> dict:
    """Owner-facing view of a link. Includes the frozen title + body SNAPSHOT so the owner can recall
    what a link contains from the Shared tab (it is their OWN note's content). The admin-oversight
    variant (_notelink_admin_dict) strips body + token — an admin must not read others' content."""
    return {
        "id": str(link.id),
        "token": link.token,
        "url_path": f"/l/{link.token}",
        "title": link.title_snapshot or "",
        "body": link.body_snapshot or "",
        "tag_id": str(link.tag_id) if link.tag_id else None,
        "tag_name": getattr(tag, "name", None),
        "tag_border_color": getattr(tag, "border_color", None),
        "tag_icon": getattr(tag, "icon", None),
        "secret_kind": link.secret_kind,
        "expires_at": link.expires_at.isoformat() if link.expires_at else None,
        "max_uses": link.max_uses,
        "use_count": link.use_count,
        "view_count": link.view_count,
        "last_viewed_at": link.last_viewed_at.isoformat() if link.last_viewed_at else None,
        "revoked": bool(link.revoked),
        "status": _notelink_status(link),
        "created_at": link.created_at.isoformat() if link.created_at else None,
    }


def _notelink_fail_key(token: str) -> str:
    return f"notelink:fail:{token}"


def _notelink_locked(token: str) -> bool:
    """True if this link is in failed-secret lockout. Raises on a Redis outage so the caller fails
    CLOSED (503) — a link's lockout must never silently lift because the store is unreachable."""
    from app.core.rate_limiter import rate_limiter as _rl
    r = getattr(_rl, "redis", None)
    if r is None:
        raise RuntimeError("rate-limit store unavailable")
    n = r.get(_notelink_fail_key(token))
    return n is not None and int(n) >= _NOTELINK_FAIL_MAX


def _notelink_record_fail(token: str) -> int:
    """Count one wrong-secret attempt; returns the running count. Best-effort — a store outage is
    handled by the redemption rate-limit gate (which fails closed) before we get here."""
    from app.core.rate_limiter import rate_limiter as _rl
    r = getattr(_rl, "redis", None)
    if r is None:
        return _NOTELINK_FAIL_MAX
    try:
        n = int(r.incr(_notelink_fail_key(token)))
        if n == 1:
            r.expire(_notelink_fail_key(token), _NOTELINK_FAIL_WINDOW)
        return n
    except Exception:
        return _NOTELINK_FAIL_MAX


def _notelink_clear_fails(token: str) -> None:
    from app.core.rate_limiter import rate_limiter as _rl
    r = getattr(_rl, "redis", None)
    if r is not None:
        try:
            r.delete(_notelink_fail_key(token))
        except Exception:
            pass


class NoteLinkCreate(BaseModel):
    note_id: uuid.UUID
    tag_id: uuid.UUID
    token_len: Optional[int] = None
    secret_kind: Optional[str] = None
    pin: Optional[str] = None
    password: Optional[str] = None
    ttl_hours: Optional[int] = None
    max_uses: Optional[int] = None


class NoteLinkRedeem(BaseModel):
    secret: Optional[str] = None


@app.post("/note-links")
async def create_note_link(
    payload: NoteLinkCreate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Create a PUBLIC snapshot link for one of MY notes, under a note-link tag I'm allowed to use.
    The tag is a security FLOOR; my overrides may only TIGHTEN it (note_link_policy.resolve_link_policy).
    The title/body are FROZEN here. Feature-gated, allowlisted, per-user capped, audited."""
    from sqlalchemy import func as _f, or_ as _or
    from app.core.security import hash_password
    from app.core.models import Note

    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    if not note_link_policy.public_note_links_enabled(_global_settings_blob(db)):
        raise HTTPException(status_code=403, detail="Public note links are disabled on this deployment.")

    note = db.query(Note).filter(Note.id == payload.note_id, Note.owner_id == current_user.id).first()
    if not note:
        raise HTTPException(status_code=404, detail="Note not found")

    tag = db.query(NoteLinkTag).filter(NoteLinkTag.id == payload.tag_id).first()
    if not tag or not tag.is_active:
        raise HTTPException(status_code=404, detail="Note-link tag not found")

    # Create-allowlist (same engine as vault share tags): fail closed.
    user_gids = [str(r[0]) for r in db.query(user_groups.c.group_id)
                 .filter(user_groups.c.user_id == current_user.id).all()]
    allowlist = {"is_active": tag.is_active, "blocked_user_ids": tag.blocked_user_ids,
                 "allowed_user_ids": tag.allowed_user_ids,
                 "allowed_department_ids": tag.allowed_department_ids,
                 "auto_enroll_new_users": tag.auto_enroll_new_users}
    if not sharing_policy.user_can_create_with_tag(allowlist, current_user.id, user_gids):
        raise HTTPException(status_code=403, detail="You are not permitted to create links with this tag.")

    # Per-user active-link cap (anti-abuse). "Active" = not revoked, not expired, not exhausted.
    now = datetime.utcnow()
    cap = note_link_policy.public_note_link_user_cap(_global_settings_blob(db))
    active = db.query(_f.count(NoteLink.id)).filter(
        NoteLink.owner_id == current_user.id, NoteLink.revoked.is_(False),
        _or(NoteLink.expires_at.is_(None), NoteLink.expires_at > now),
        _or(NoteLink.max_uses.is_(None), NoteLink.use_count < NoteLink.max_uses)).scalar() or 0
    if active >= cap:
        raise HTTPException(status_code=409,
                            detail=f"You have reached your limit of {cap} active links. Revoke one first.")

    # Merge the tag floor with my overrides (tighten-only). resolve_link_policy raises on any loosen.
    overrides = payload.model_dump(exclude_unset=True)
    for k in ("note_id", "tag_id"):
        overrides.pop(k, None)
    try:
        pol = note_link_policy.resolve_link_policy(tag, overrides)
    except note_link_policy.PolicyViolation as e:
        raise HTTPException(status_code=400, detail=str(e))

    password_hash = hash_password(pol["secret_value"]) if pol["secret_value"] is not None else None
    expires_at = (now + timedelta(hours=pol["ttl_hours"])) if pol["ttl_hours"] else None

    # Allocate a unique token (high entropy; the unique index is the real backstop).
    token = None
    for _ in range(8):
        cand = _notelink_gen_token(pol["token_len"])
        if not db.query(NoteLink.id).filter(NoteLink.token == cand).first():
            token = cand
            break
    if token is None:
        raise HTTPException(status_code=500, detail="Could not allocate a link token; try again.")

    link = NoteLink(
        owner_id=current_user.id, tag_id=tag.id, token=token, token_len=pol["token_len"],
        title_snapshot=note.title or "", body_snapshot=note.body or "",
        secret_kind=pol["secret_kind"], password_hash=password_hash,
        expires_at=expires_at, max_uses=pol["max_uses"])
    db.add(link)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=409, detail="Link token collision; please try again.")
    db.refresh(link)
    try:
        AuditLogger(db).log_action(
            action="note_link_create", status="success", user=current_user,
            resource_type="note_link", resource_id=str(link.id),
            details={"note_id": str(note.id), "tag": tag.name, "secret_kind": link.secret_kind,
                     "token_len": link.token_len, "has_expiry": bool(expires_at),
                     "max_uses": link.max_uses},
            ip_address=get_client_ip(request))
    except Exception:
        pass
    return _notelink_public_dict(link, tag)


@app.get("/note-links")
async def list_note_links(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """List MY public note links (newest first) with each tag's tile colour/icon."""
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    links = db.query(NoteLink).filter(NoteLink.owner_id == current_user.id)\
        .order_by(NoteLink.created_at.desc()).all()
    tag_ids = {l.tag_id for l in links if l.tag_id}
    tags = {t.id: t for t in db.query(NoteLinkTag).filter(NoteLinkTag.id.in_(tag_ids)).all()} if tag_ids else {}
    return {"links": [_notelink_public_dict(l, tags.get(l.tag_id)) for l in links]}


@app.get("/note-link-policy")
async def get_note_link_policy(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Effective PUBLIC-note-link policy for the CURRENT user — non-admin readable (like /share-policy),
    so the Share modal's Public tile can shape its controls without the admin-only /note-link-tags.
    Returns whether public links are enabled, the per-user active-link cap, and ONLY the tags this user
    may create links with — each carrying its FLOOR fields + tile colour/icon so the UI can render the
    floor and permit tightening. The create-allowlist internals are NEVER exposed.

    FAIL-CLOSED: feature off -> no tags; a temp-credential session can't create links -> no tags; a
    user not permitted by a tag's create-allowlist never sees that tag."""
    blob = _global_settings_blob(db)
    enabled = note_link_policy.public_note_links_enabled(blob)
    cap = note_link_policy.public_note_link_user_cap(blob)
    if not enabled or _notes_denied_for_temp(current_user):
        return {"enabled": enabled, "user_cap": cap, "tags": []}
    user_gids = [str(r[0]) for r in db.query(user_groups.c.group_id)
                 .filter(user_groups.c.user_id == current_user.id).all()]
    tags = []
    for t in db.query(NoteLinkTag).filter(NoteLinkTag.is_active.is_(True)).order_by(NoteLinkTag.name).all():
        allowlist = {"is_active": t.is_active, "blocked_user_ids": t.blocked_user_ids,
                     "allowed_user_ids": t.allowed_user_ids,
                     "allowed_department_ids": t.allowed_department_ids,
                     "auto_enroll_new_users": t.auto_enroll_new_users}
        if not sharing_policy.user_can_create_with_tag(allowlist, current_user.id, user_gids):
            continue
        tags.append({
            "id": str(t.id), "name": t.name, "description": t.description,
            "border_color": t.border_color, "icon": t.icon,
            "min_token_len": t.min_token_len,
            "default_ttl_hours": t.default_ttl_hours, "max_ttl_hours": t.max_ttl_hours,
            "require_secret": t.require_secret, "min_pin_len": t.min_pin_len,
            "password_min_len": t.password_min_len,
            "password_require_alnum": bool(t.password_require_alnum),
            "max_uses_cap": t.max_uses_cap,
        })
    return {"enabled": True, "user_cap": cap, "tags": tags}


@app.post("/note-links/{link_id}/revoke")
async def revoke_note_link(
    link_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Revoke one of MY links (immediate; the snapshot stops being reachable)."""
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    link = db.query(NoteLink).filter(NoteLink.id == link_id, NoteLink.owner_id == current_user.id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if not link.revoked:
        link.revoked = True
        db.commit()
        try:
            AuditLogger(db).log_action(
                action="note_link_revoke", status="success", user=current_user,
                resource_type="note_link", resource_id=str(link.id),
                ip_address=get_client_ip(request))
        except Exception:
            pass
    return {"ok": True, "id": str(link.id), "revoked": True}


@app.delete("/note-links/{link_id}")
async def delete_note_link(
    link_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Delete one of MY links (removes the snapshot row entirely)."""
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    link = db.query(NoteLink).filter(NoteLink.id == link_id, NoteLink.owner_id == current_user.id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    db.delete(link)
    db.commit()
    try:
        AuditLogger(db).log_action(
            action="note_link_delete", status="success", user=current_user,
            resource_type="note_link", resource_id=str(link_id),
            ip_address=get_client_ip(request))
    except Exception:
        pass
    return {"ok": True}


# --- Admin oversight of public note links (the review-flagged gap: admins had no way to see or stop
# OTHER users' public links besides the feature kill-switch). ---------------------------------------
def _notelink_admin_dict(link, tag, owner) -> dict:
    d = _notelink_public_dict(link, tag)
    # Admin oversight must not expose others' note CONTENT or a redeemable token: drop the body
    # snapshot, the token, and the URL. Admins see owner/title/status metadata only; revoke uses the id.
    d.pop("body", None)
    d.pop("token", None)
    d.pop("url_path", None)
    d["owner_id"] = str(link.owner_id)
    d["owner"] = (getattr(owner, "username", None) or getattr(owner, "email", None)) if owner else None
    return d


@app.get("/admin/note-links")
async def admin_list_note_links(
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """List ALL public note links across every user (interactive-admin), so an admin can audit and
    revoke exposures. Newest first, capped; each row carries the owner + tag + status (NEVER the body
    snapshot)."""
    _CAP = 1000
    links = db.query(NoteLink).order_by(NoteLink.created_at.desc()).limit(_CAP).all()
    tag_ids = {l.tag_id for l in links if l.tag_id}
    owner_ids = {l.owner_id for l in links}
    tags = {t.id: t for t in db.query(NoteLinkTag).filter(NoteLinkTag.id.in_(tag_ids)).all()} if tag_ids else {}
    owners = {u.id: u for u in db.query(User).filter(User.id.in_(owner_ids)).all()} if owner_ids else {}
    active = sum(1 for l in links if _notelink_status(l) == "active")
    return {"links": [_notelink_admin_dict(l, tags.get(l.tag_id), owners.get(l.owner_id)) for l in links],
            "active_count": active, "total": len(links), "capped": len(links) >= _CAP}


@app.post("/admin/note-links/{link_id}/revoke")
async def admin_revoke_note_link(
    link_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Admin-revoke ANY user's public link (immediate)."""
    link = db.query(NoteLink).filter(NoteLink.id == link_id).first()
    if not link:
        raise HTTPException(status_code=404, detail="Link not found")
    if not link.revoked:
        link.revoked = True
        db.commit()
        try:
            AuditLogger(db).log_action(
                action="note_link_admin_revoke", status="success", user=current_user,
                resource_type="note_link", resource_id=str(link.id),
                details={"owner_id": str(link.owner_id)}, ip_address=get_client_ip(request))
        except Exception:
            pass
    return {"ok": True, "id": str(link.id), "revoked": True}


@app.post("/admin/note-links/revoke-all")
async def admin_revoke_all_note_links(
    request: Request,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db),
):
    """Admin bulk-revoke: revoke EVERY currently-active public link (a surgical stop that leaves the
    feature enabled, unlike the settings kill-switch). Returns how many were revoked."""
    from sqlalchemy import update as _sa_update, or_ as _or
    now = datetime.utcnow()
    stmt = (_sa_update(NoteLink)
            .where(NoteLink.revoked.is_(False),
                   _or(NoteLink.expires_at.is_(None), NoteLink.expires_at > now),
                   _or(NoteLink.max_uses.is_(None), NoteLink.use_count < NoteLink.max_uses))
            .values(revoked=True))
    res = db.execute(stmt)
    db.commit()
    n = res.rowcount or 0
    try:
        AuditLogger(db).log_action(
            action="note_link_admin_revoke_all", status="success", user=current_user,
            resource_type="note_link", details={"revoked_count": n}, ip_address=get_client_ip(request))
    except Exception:
        pass
    return {"ok": True, "revoked_count": n}


@app.get("/l/{token}")
async def note_link_page(token: str):
    """PUBLIC: serve the anonymous redemption page. It reads the token from the URL and POSTs to
    /note-links/{token}/redeem (prompting for a PIN/password only if the link needs one)."""
    static_dir = str(PROJECT_ROOT / "static")
    page = os.path.join(static_dir, "note-link.html")
    if not os.path.exists(page):
        raise HTTPException(status_code=404, detail="Not found")
    resp = FileResponse(page)
    resp.headers["Cache-Control"] = "no-store, no-cache, must-revalidate, max-age=0"
    resp.headers["X-Robots-Tag"] = "noindex, nofollow"
    return resp


@app.post("/note-links/{token}/redeem")
async def redeem_note_link(
    token: str,
    payload: NoteLinkRedeem,
    request: Request,
    db: Session = Depends(get_db),
):
    """PUBLIC: redeem a snapshot link. Rate-limited per IP AND per token (fail-closed); a secret-gated
    link prompts for its PIN/password with a per-link lockout after repeated wrong attempts; expiry,
    max-uses and revocation are enforced atomically; every outcome is audited. Returns the frozen
    snapshot on success."""
    import time as _t
    from sqlalchemy import update as _sa_update, or_ as _or
    from app.core.security import verify_password
    from app.core.rate_limiter import rate_limiter as _rl, RateLimiterUnavailable

    client_ip = get_client_ip(request)
    if not token or len(token) > _NOTELINK_TOKEN_MAX_INPUT:
        raise HTTPException(status_code=404, detail="This link is not available.")

    # (1) Redemption rate limit — 10 requests / minute per (IP, link), fail-closed (anonymous
    # surface). Keying on IP+token means one IP may open many different links, but is throttled on
    # any single one; the global middleware caps a single IP's overall rate, and the per-token
    # lockout below stops distributed secret-guessing on one link.
    try:
        allowed, _, reset = _rl.check_rate_limit(
            identifier=f"{client_ip}:{token}", limit=_NOTELINK_REDEEM_LIMIT,
            window=_NOTELINK_REDEEM_WINDOW, prefix="notelink_redeem", fail_open=False)
    except RateLimiterUnavailable:
        raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
    if not allowed:
        raise HTTPException(status_code=429, detail="Too many requests.",
                            headers={"Retry-After": str(max(1, reset - int(_t.time())))})

    def _audit(status, reason=None, link_id=None):
        try:
            AuditLogger(db).log_action(
                action="note_link_redeem", status=status, resource_type="note_link",
                resource_id=str(link_id) if link_id else None,
                details={"reason": reason} if reason else None, ip_address=client_ip)
        except Exception:
            pass

    # Disabling the feature is a KILL SWITCH for the anonymous read path, not just for creation: an
    # admin turning it off (e.g. abuse response) must stop already-minted links from serving too.
    # Same generic 404 as any other unavailable state (no oracle).
    if not note_link_policy.public_note_links_enabled(_global_settings_blob(db)):
        _audit("failure", reason="feature_disabled")
        raise HTTPException(status_code=404, detail="This link is not available.")

    link = db.query(NoteLink).filter(NoteLink.token == token).first()
    # A missing OR unusable link returns the SAME 404 (no revoked/expired/exhausted oracle).
    if not link or _notelink_status(link) != "active":
        _audit("failure", reason="not_available", link_id=(link.id if link else None))
        raise HTTPException(status_code=404, detail="This link is not available.")

    if link.secret_kind != "none":
        # Lockout peek first — a locked link refuses everything, including the correct secret.
        try:
            locked = _notelink_locked(token)
        except Exception:
            raise HTTPException(status_code=503, detail="Service temporarily unavailable.")
        if locked:
            _audit("failure", reason="locked_out", link_id=link.id)
            raise HTTPException(status_code=429, detail="Too many incorrect attempts. Try again later.",
                                headers={"Retry-After": str(_NOTELINK_FAIL_WINDOW)})
        raw = (payload.secret if payload else None) or ""
        if not raw.strip():
            # The page needs to know which prompt to show; no consume, no failure recorded.
            raise HTTPException(status_code=401,
                                detail={"error": "secret_required", "secret_kind": link.secret_kind})
        # A PIN carries no meaningful whitespace (and is stored stripped); a password is verbatim, so
        # the two ends agree. Bound the length before argon2 on this anonymous surface — an over-long
        # secret is simply treated as wrong (never hashed).
        secret = raw.strip() if link.secret_kind == "pin" else raw
        if len(secret) > _NOTELINK_SECRET_MAX or not link.password_hash \
                or not verify_password(secret, link.password_hash):
            n = _notelink_record_fail(token)
            _audit("failure", reason="wrong_secret", link_id=link.id)
            if n >= _NOTELINK_FAIL_MAX:
                raise HTTPException(status_code=429, detail="Too many incorrect attempts. Try again later.",
                                    headers={"Retry-After": str(_NOTELINK_FAIL_WINDOW)})
            raise HTTPException(status_code=401,
                                detail={"error": "wrong_secret", "secret_kind": link.secret_kind})
        _notelink_clear_fails(token)

    # (2) Atomically consume one use under a WHERE guard so max-uses/expiry/revoke can't be raced.
    now = datetime.utcnow()
    stmt = (_sa_update(NoteLink)
            .where(NoteLink.id == link.id, NoteLink.revoked.is_(False),
                   _or(NoteLink.max_uses.is_(None), NoteLink.use_count < NoteLink.max_uses),
                   _or(NoteLink.expires_at.is_(None), NoteLink.expires_at > now))
            .values(use_count=NoteLink.use_count + 1, view_count=NoteLink.view_count + 1,
                    last_viewed_at=now))
    res = db.execute(stmt)
    db.commit()
    if res.rowcount == 0:
        _audit("failure", reason="not_available", link_id=link.id)
        raise HTTPException(status_code=404, detail="This link is not available.")
    _audit("success", link_id=link.id)
    return {"title": link.title_snapshot or "", "body": link.body_snapshot or "",
            "secret_kind": link.secret_kind}


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
            "force_view_only": t.force_view_only,
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
        # A folder may carry its own password_hash; refuse to share such a folder (defense-in-depth, for
        # the same reason a password-protected vault is refused).
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
        "force_view_only": tag.force_view_only, "allow_custom": tag.allow_custom,
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
                     "force_view_only": tag.force_view_only, "allow_custom": tag.allow_custom,
                     "tag_name": tag.name})
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
    # Notify the concrete recipients of a directly-addressed share (users / departments) that
    # something is now waiting for them. anyone_internal has no recipients at create time. Fail-soft
    # (each write in its own session) so a notification failure never fails the share create.
    try:
        recipient_ids = list(aud_users)  # "users" audience: concrete user-ids (already validated)
        if aud_depts:                    # "departments": expand to member user-ids
            recipient_ids += [
                str(r[0]) for r in db.query(user_groups.c.user_id)
                .filter(user_groups.c.group_id.in_([str(d) for d in aud_depts])).all()
            ]
        recipient_ids = [u for u in recipient_ids if str(u) != str(current_user.id)]  # not myself
        if recipient_ids:
            item = out.get("target_name") or out.get("vault_name") or "an item"
            _notify_users(
                recipient_ids, "share_received",
                title=f"{current_user.username} shared a {tt} with you",
                body=f'"{item}" in {out.get("vault_name") or "a vault"}',
                target="#shared",
                dedup_prefix=f"share:{share.id}",
            )
            # Optionally ALSO email each recipient the "File / folder shared" notice (opt-in). Resolve
            # addresses now (one query), then fan the SMTP out on a background thread. NEVER email the
            # link_token (the bearer secret for anyone_internal shares) — link into "Shared with me".
            from app.core.email_actions import vault_url as _email_vault_url
            _base = (_email_vault_url() or str(request.base_url).rstrip("/"))
            _share_ctx = {"link": (_base.rstrip("/") + "/#shared") if _base else "",
                          "expires": (f"until {share.expires_at.strftime('%Y-%m-%d')} UTC" if share.expires_at else "")}
            _share_pairs = [(u.email, u.username) for u in
                            db.query(User).filter(User.id.in_([str(x) for x in recipient_ids])).all()]
            _fire_action_email_bulk(db, "share_created", _share_pairs, _share_ctx)
    except Exception as e:
        print(f"⚠ share notification skipped: {e}")
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
    # Audience FIRST — before any status/expiry/vault check — so a caller who holds a share id/token but
    # is NOT in the audience is denied uniformly and cannot fingerprint the share's lifecycle state
    # (active vs revoked vs expired vs vault-gone) from the distinct error codes below.
    if not sharing_policy.user_matches_claim_audience(
            share.claim_audience, share.audience_user_ids, share.audience_department_ids,
            current_user.id, _user_group_ids(db, current_user.id)):
        raise HTTPException(status_code=403, detail="You are not in the audience for this share.")
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

    existing = db.query(ShareClaim).filter(
        ShareClaim.share_id == share.id, ShareClaim.user_id == current_user.id).first()
    if existing:
        if existing.revoked:
            raise HTTPException(status_code=403, detail="Your access to this share was revoked.")
        return _share_claim_dict(existing, share)  # idempotent re-open

    # Serialize the recipient-limit check + insert against the share row, so concurrent claims by
    # DIFFERENT users cannot over-admit past max_recipients (a plain count-then-insert would race; the
    # unique (share,user) constraint only guards the same-user race). The lock releases on commit.
    # Relies on READ COMMITTED (the engine default) so the post-lock count re-reads the committed
    # winner; REPEATABLE READ would use a stale snapshot and could reintroduce over-admit.
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
    # as 'available' cards. Narrowed SERVER-SIDE via JSONB @> containment (GIN-indexed) so we fetch only
    # the shares addressed to THIS user, instead of scanning every active named-audience share in the
    # deployment. The Python user_matches_claim_audience check below stays as the authoritative filter.
    from sqlalchemy import or_, and_
    claimed_ids = {r[1].id for r in rows}
    now = datetime.utcnow()
    gids = [str(g) for g in _user_group_ids(db, current_user.id)]
    uid = str(current_user.id)
    audience_or = [and_(Share.claim_audience == "users", Share.audience_user_ids.contains([uid]))]
    for g in gids:
        audience_or.append(and_(Share.claim_audience == "departments",
                                Share.audience_department_ids.contains([g])))
    pushed = (
        db.query(Share)
        .filter(Share.status == "active", Share.expires_at > now, or_(*audience_or))
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


# ---------------------------------------------------------------------------
# In-app notifications — the bell (every page) + the Dashboard "What's waiting
# for you" lane. Personal data: every query is scoped to the requesting user,
# and a temporary-credential session owns none (it must never see or touch the
# owner account's notifications).
# ---------------------------------------------------------------------------

def _notify_users(user_ids, ntype: str, title: str, body: str = None,
                  target: str = None, dedup_prefix: str = None) -> None:
    """Best-effort: create an in-app notification for each user in a SEPARATE session, so a failure
    or a dedup collision can never affect the caller's request/transaction. When dedup_prefix is
    given, each row's dedup_key is f"{dedup_prefix}:{user_id}" and a UNIQUE(user_id, dedup_key)
    collision is silently skipped (that user was already notified for this event)."""
    from app.core.database import get_db_context
    from app.core.models import Notification
    ids = [str(u) for u in dict.fromkeys(user_ids) if u]  # de-dup + drop falsy, preserve order
    if not ids:
        return
    notified = []
    try:
        with get_db_context() as db:
            for uid in ids:
                dedup = f"{dedup_prefix}:{uid}" if dedup_prefix else None
                try:
                    with db.begin_nested():
                        db.add(Notification(user_id=uid, type=ntype, title=title, body=body,
                                            target=target, dedup_key=dedup))
                    notified.append(uid)
                except IntegrityError:
                    pass  # dedup collision -> this user was already notified for this event
        # Live nudge over the activity socket so the recipient's bell (and an open target section,
        # e.g. Notes) updates WITHOUT a page refresh. One event per recipient, owner_user_id set to
        # them, so the /ws/monitor per-user filter delivers it only to that recipient. The nudge
        # carries NO title/body — the client re-fetches via its authenticated endpoints — so it is
        # safe even on the admin-visible feed. Best-effort: a broadcast failure never affects callers.
        for uid in notified:
            try:
                broadcast_event({"event": {"type": "notification", "notification_type": ntype,
                                           "target": target, "owner_user_id": str(uid)}},
                                include_metrics=False)
            except Exception:
                pass
    except Exception as e:
        print(f"⚠ notification write skipped: {e}")


def _notification_dict(n) -> dict:
    return {
        "id": str(n.id),
        "type": n.type,
        "title": n.title,
        "body": n.body,
        "target": n.target,
        "is_read": n.is_read,
        "created_at": n.created_at.isoformat() if n.created_at else None,
    }


def _notifications_denied_for_temp(current_user) -> bool:
    return bool(getattr(current_user, "_is_temp_session", False))


@app.get("/notifications")
async def list_notifications(
    limit: int = 30,
    unread_only: bool = False,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """The caller's in-app notifications, newest first, plus their unread count. Scoped to the
    requesting user; a temp session owns none (must not see the owner account's notifications)."""
    from app.core.models import Notification
    if _notifications_denied_for_temp(current_user):
        return {"notifications": [], "unread_count": 0}
    limit = max(1, min(limit, 100))
    base = db.query(Notification).filter(Notification.user_id == current_user.id)
    q = base.filter(Notification.is_read.is_(False)) if unread_only else base
    rows = q.order_by(Notification.created_at.desc()).limit(limit).all()
    unread = (db.query(Notification)
              .filter(Notification.user_id == current_user.id, Notification.is_read.is_(False))
              .count())
    return {"notifications": [_notification_dict(n) for n in rows], "unread_count": unread}


@app.get("/notifications/unread-count")
async def notifications_unread_count(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from app.core.models import Notification
    if _notifications_denied_for_temp(current_user):
        return {"count": 0}
    count = (db.query(Notification)
             .filter(Notification.user_id == current_user.id, Notification.is_read.is_(False))
             .count())
    return {"count": count}


@app.post("/notifications/{notification_id}/read")
async def mark_notification_read(
    notification_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from app.core.models import Notification
    if _notifications_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Not available for temporary sessions")
    n = (db.query(Notification)
         .filter(Notification.id == notification_id, Notification.user_id == current_user.id)
         .first())
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    if not n.is_read:
        n.is_read = True
        n.read_at = datetime.utcnow()
        db.commit()
    return {"ok": True}


@app.post("/notifications/read-all")
async def mark_all_notifications_read(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from app.core.models import Notification
    if _notifications_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Not available for temporary sessions")
    updated = (db.query(Notification)
               .filter(Notification.user_id == current_user.id, Notification.is_read.is_(False))
               .update({Notification.is_read: True, Notification.read_at: datetime.utcnow()},
                       synchronize_session=False))
    db.commit()
    return {"ok": True, "updated": updated}


@app.delete("/notifications/{notification_id}")
async def dismiss_notification(
    notification_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from app.core.models import Notification
    if _notifications_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Not available for temporary sessions")
    n = (db.query(Notification)
         .filter(Notification.id == notification_id, Notification.user_id == current_user.id)
         .first())
    if not n:
        raise HTTPException(status_code=404, detail="Notification not found")
    db.delete(n)
    db.commit()
    return {"ok": True}


# ---------------------------------------------------------------------------
# Notes — personal server-side notes (title + text). "Send note" is a snapshot
# COPY to another user (no live share, no cascade): the recipient gets their own
# row and can adopt it into their notes. Personal data: every query is scoped to
# the requesting account (owner_id); a temporary-credential session is excluded.
# ---------------------------------------------------------------------------
_NOTE_TITLE_MAX = 255
_NOTE_BODY_MAX = 100_000


class NoteIn(BaseModel):
    title: str = ""
    body: str = ""


class NoteUpdate(BaseModel):
    title: Optional[str] = None
    body: Optional[str] = None
    is_favorite: Optional[bool] = None


class NoteSend(BaseModel):
    recipient_user_id: uuid.UUID


def _notes_denied_for_temp(current_user) -> bool:
    # Notes belong to the underlying account; a least-privilege temp session must not read or write
    # them (matches the notification bell). The temp-account note model is a deferred follow-up.
    return bool(getattr(current_user, "_is_temp_session", False))


_NOTE_BODY_MAX_FLOOR = 100         # smallest an admin may set the note-size cap to
_NOTE_BODY_MAX_CEILING = 1_000_000  # largest (guards memory / payload size)


def _note_max_chars(db) -> int:
    """The admin-configured maximum note-body length (chars). Defaults to _NOTE_BODY_MAX; clamped to
    a sane range so a bad stored value can't disable or explode the limit."""
    try:
        raw = _global_settings_blob(db).get("note_max_chars", _NOTE_BODY_MAX)
        v = int(raw)
    except (TypeError, ValueError):
        return _NOTE_BODY_MAX
    return v if _NOTE_BODY_MAX_FLOOR <= v <= _NOTE_BODY_MAX_CEILING else _NOTE_BODY_MAX


def _clean_note_fields(title, body, max_body=_NOTE_BODY_MAX):
    title = (title or "").strip()
    # Drop control chars (CR/LF etc.): the title also lands in a notification title on send.
    title = ''.join(c for c in title if ord(c) >= 32 and ord(c) != 127)
    if len(title) > _NOTE_TITLE_MAX:
        raise HTTPException(status_code=400, detail=f"Title is too long (max {_NOTE_TITLE_MAX} characters)")
    body = body or ""
    if len(body) > max_body:
        raise HTTPException(status_code=400,
                            detail=f"Note is too long (max {max_body} characters)")
    return title, body


def _note_dict(n) -> dict:
    return {
        "id": str(n.id),
        "title": n.title or "",
        "body": n.body or "",
        "is_favorite": bool(n.is_favorite),
        "adopted": bool(n.adopted),
        "sent_from": n.sent_from_name if n.sent_from_user_id else None,
        "created_at": n.created_at.isoformat() if n.created_at else None,
        "updated_at": n.updated_at.isoformat() if n.updated_at else None,
    }


def _get_owned_note(db, current_user, note_id):
    from app.core.models import Note
    n = db.query(Note).filter(Note.id == note_id, Note.owner_id == current_user.id).first()
    if not n:
        raise HTTPException(status_code=404, detail="Note not found")
    return n


@app.get("/notes")
async def list_notes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """My notes: the ones I authored plus received copies I have adopted. Favourites first."""
    from app.core.models import Note
    if _notes_denied_for_temp(current_user):
        return {"notes": []}
    rows = (db.query(Note)
            .filter(Note.owner_id == current_user.id, Note.adopted.is_(True))
            .order_by(Note.is_favorite.desc(), Note.updated_at.desc())
            .all())
    return {"notes": [_note_dict(n) for n in rows]}


@app.get("/notes/received")
async def list_received_notes(
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Notes other users sent me that I have not adopted yet ("sent to me")."""
    from app.core.models import Note
    if _notes_denied_for_temp(current_user):
        return {"notes": []}
    rows = (db.query(Note)
            .filter(Note.owner_id == current_user.id, Note.adopted.is_(False))
            .order_by(Note.created_at.desc())
            .all())
    return {"notes": [_note_dict(n) for n in rows]}


@app.post("/notes")
async def create_note(
    body: NoteIn,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    from app.core.models import Note
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    title, text = _clean_note_fields(body.title, body.body, _note_max_chars(db))
    if not title and not text:
        raise HTTPException(status_code=400, detail="A note needs a title or some text")
    n = Note(owner_id=current_user.id, title=title, body=text, adopted=True)
    db.add(n)
    db.commit()
    db.refresh(n)
    return _note_dict(n)


@app.get("/notes/{note_id}")
async def get_note(
    note_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    return _note_dict(_get_owned_note(db, current_user, note_id))


@app.patch("/notes/{note_id}")
async def update_note(
    note_id: uuid.UUID,
    body: NoteUpdate,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    n = _get_owned_note(db, current_user, note_id)
    if body.title is not None or body.body is not None:
        title, text = _clean_note_fields(
            n.title if body.title is None else body.title,
            n.body if body.body is None else body.body,
            _note_max_chars(db))
        n.title = title
        n.body = text
    if body.is_favorite is not None:
        n.is_favorite = bool(body.is_favorite)
    db.commit()
    db.refresh(n)
    return _note_dict(n)


@app.delete("/notes/{note_id}")
async def delete_note(
    note_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    n = _get_owned_note(db, current_user, note_id)
    db.delete(n)
    db.commit()
    return {"ok": True}


@app.post("/notes/{note_id}/adopt")
async def adopt_note(
    note_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Add a received note to my own notes (it becomes a normal, editable note of mine)."""
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    n = _get_owned_note(db, current_user, note_id)
    n.adopted = True
    db.commit()
    db.refresh(n)
    return _note_dict(n)


@app.post("/notes/{note_id}/send")
async def send_note(
    note_id: uuid.UUID,
    body: NoteSend,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Send a SNAPSHOT COPY of my note to another user. They get their own editable copy under
    "sent to me" (no live link, no cascade) and an in-app notification."""
    from app.core.models import Note
    if _notes_denied_for_temp(current_user):
        raise HTTPException(status_code=403, detail="Notes are not available for temporary sessions")
    src = _get_owned_note(db, current_user, note_id)
    if str(body.recipient_user_id) == str(current_user.id):
        raise HTTPException(status_code=400, detail="You cannot send a note to yourself")
    recipient = db.query(User).filter(User.id == body.recipient_user_id).first()
    if not recipient or not recipient.is_active or recipient.role == RoleEnum.EXTERNAL:
        raise HTTPException(status_code=404, detail="Recipient not found")
    sender_name = current_user.username or (current_user.email or "Someone")
    copy = Note(owner_id=recipient.id, title=src.title, body=src.body,
                sent_from_user_id=current_user.id, sent_from_name=sender_name, adopted=False)
    db.add(copy)
    db.commit()
    # Best-effort in-app notification (separate session; never fails the send).
    _notify_users([str(recipient.id)], "note_received", f"{sender_name} sent you a note",
                  body=(src.title or "Untitled note"), target="#notes")
    try:
        AuditLogger(db).log_action(
            action='note_send', status='success', user=current_user, resource_type='note',
            resource_id=str(note_id),
            details={'recipient_user_id': str(recipient.id)},
            ip_address=get_client_ip(request))
    except Exception:
        pass
    return {"ok": True}


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
# is web-only because the server never receives the browser-held decryption keys.
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
    """Reject any client-supplied ZK name blob that is not sealed AND bound to its object.

    The marker is a SERVER-enforced invariant: the model load events skip ZK blobs by it, the
    seal no-clobber guard keys on it, and enforcing it stops a buggy or hostile client from
    parking a plaintext name in the enc_name column.

    Writes require the v2 ('zk2:') form specifically. v1 binds vault, field and epoch but NOT the
    row, so a v1 blob can be lifted onto another row and still authenticate -- the transposition
    v2 exists to prevent. Accepting v1 here left that binding opt-out at the one boundary that
    could require it: every shipped client already seals with an object id, so nothing legitimate
    still produces v1, and a party holding the DEK could choose to.

    READS stay tolerant of v1, deliberately: rows sealed before v2 exist and must remain
    readable. The asymmetry is the point -- strict on the way in, forgiving on the way out.
    """
    from app.core.security import is_zk_object_bound_name
    for t in tokens:
        if t is not None and not is_zk_object_bound_name(t):
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Encrypted name must be a sealed zero-knowledge blob bound to its object.",
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
    """Deployment-wide limit on TOTAL stored bytes (MAX_STORAGE_GB, narrowed by the admin
    panel) — raises 413 if an upload would exceed it. Shares the check with the SFTP write
    path via vault_service.would_exceed_deployment_storage so a customer can't sidestep the
    per-vault size_limit by creating many vaults, on either transport. Permissive default
    (-1, no admin limit saved) leaves un-gated deployments unrestricted."""
    from app.services.vault_service import would_exceed_deployment_storage
    exceeds, used, cap_bytes = would_exceed_deployment_storage(db, additional_bytes)
    if exceeds:
        raise HTTPException(
            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            detail=(f"This deployment's {storage_quota.format_bytes(cap_bytes)} storage limit would "
                    f"be exceeded ({storage_quota.format_bytes(used)} already stored). Free up space "
                    f"or ask an administrator to raise the limit."),
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
    declare. Bytes; a null bound means UNLIMITED on that axis. reserved = the storage this account
    has ALLOCATED (to its own vaults and to shared vaults it helps fund); available = the largest
    size a vault may declare right now (pass exclude_vault_id when editing a vault, so its OWN
    current allocation doesn't count against it).

    quota_source names where the budget came from, so the UI can say "set for your account" rather
    than implying every account has the same one."""
    ceiling = storage_quota.quota_setting_bytes(_settings_blob(db).get("max_vault_size"))
    is_full_admin = _is_budget_exempt(current_user)
    quota = _account_quota_bytes(db, current_user)
    override = getattr(current_user, "storage_quota_bytes", None)
    return {
        "reserved_bytes": _account_allocated_bytes(db, current_user.id),
        "account_quota_bytes": quota,
        "per_vault_max_bytes": ceiling,
        "available_bytes": _max_allowed_vault_size_bytes(db, current_user, exclude_vault_id),
        "budget_exempt": is_full_admin,
        "quota_source": ("exempt" if is_full_admin else
                         "account" if override is not None else
                         "default" if quota is not None else "unlimited"),
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

    if vault_create.id is not None:
        # Only a zero-knowledge vault has a reason to choose its own id: its key is locked
        # before the vault exists, and the lock is stamped with the id. A Standard vault's id
        # feeds at-rest key derivation and names a directory on disk, so there is no reason to
        # let a caller pick it and every reason not to.
        if vault_type != 'zero_knowledge':
            raise HTTPException(
                status_code=400,
                detail="A vault id may only be supplied when creating a zero-knowledge vault.",
            )
        # Reject a taken id before anything is built. Note what actually guarantees uniqueness:
        # the primary key. This check turns that constraint violation into a clear answer, and
        # two simultaneous requests for one id still race past it -- hence the guard below.
        # "In use" includes "was in use". A retired vault id is the most valuable one to refuse:
        # the server never generates a zero-knowledge vault key, it stores a wrap the browser
        # supplies, so an old key holder could otherwise recreate the vault under its own id,
        # re-supply that same wrap, and read whatever survived the delete.
        if (db.query(Vault.id).filter(Vault.id == vault_create.id).first()
                or db.query(RetiredObjectId.id).filter(
                    RetiredObjectId.id == vault_create.id).first()):
            raise HTTPException(status_code=409, detail="That vault id is already in use.")

    # Name / seal validation. A standard vault needs a real plaintext name. A zero-knowledge vault
    # seals its name (and optionally its description) in the BROWSER and sends only its non-secret
    # label (or nothing) as `name`; a sealed blob MUST carry the ZK marker so the server never
    # mistakes a browser seal for one it can decrypt, and the plaintext description is dropped (the
    # real one rides in enc_description).
    _name = (vault_create.name or '').strip() or None
    _enc_name = vault_create.enc_name
    _enc_description = vault_create.enc_description
    _description = vault_create.description
    if vault_type == 'zero_knowledge':
        from app.core.security import is_zk_sealed_name
        if _enc_name is not None and not is_zk_sealed_name(_enc_name):
            raise HTTPException(status_code=400,
                                detail="A zero-knowledge vault name must be sealed in the browser.")
        if _enc_description is not None and not is_zk_sealed_name(_enc_description):
            raise HTTPException(status_code=400,
                                detail="A zero-knowledge vault description must be sealed in the browser.")
        _description = None                       # the real description is sealed in enc_description
    else:
        if _name is None:
            # 422 (not 400): a missing required field is a validation error, matching the status the
            # schema returned before `name` became optional (so a ZK vault can send only enc_name).
            raise HTTPException(status_code=422, detail="Vault name is required.")
        _enc_name = None                          # a standard vault never carries browser seals
        _enc_description = None

    try:
        vault = vault_service.create_vault(
            vault_id=vault_create.id,
            name=_name,
            owner=current_user,
            description=_description,
            password=vault_create.password,
            expire_files_after_days=vault_create.expire_files_after_days,
            vault_type=vault_type,
            size_limit=requested_size,
            enc_name=_enc_name,
            enc_description=_enc_description,
        )
    except (ValueError, IntegrityError) as exc:
        # Losing the race between the check above and this insert should look to a caller
        # exactly like losing the check -- a taken id -- and not like a server fault.
        #
        # Narrowly, though. Key setup raises ValueError too when a deployment has no
        # encryption key, and answering that with "id already in use" would diagnose a
        # misconfiguration as a client mistake and hide it from error monitoring.
        db.rollback()
        taken = isinstance(exc, IntegrityError) or 'id already in use' in str(exc)
        if vault_create.id is not None and taken:
            raise HTTPException(status_code=409,
                                detail="That vault id is already in use.") from exc
        raise

    # Open the vault's storage-allocation ledger: the creator funds the whole initial size out
    # of their own budget, and is therefore the one who can later reclaim it.
    _write_vault_grant(db, vault, current_user.id, requested_size)
    db.commit()

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
                wrapping_algorithm=TEAMPRIV_ALGO,
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
                wrapping_algorithm=DIRECT_DEK_ALGO,
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

    # When did the CALLER last open each of these? One query, like fav_ids above — never per row.
    view_times = _vault_view_times(db, current_user)

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
            # An id-scoped (file/folder share or scoped temp-cred) caller sees only their subtree; the
            # owner-authored vault description may reference items outside that scope, so mask it too
            # (same rationale as suppressing the whole-vault aggregates).
            'description': None if _id_scoped else vault.description,
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
            # Zero-knowledge: the browser-sealed name/description, so the client can decrypt them
            # once unlocked (the server can't). For a ZK vault `name`/`description` above carry only
            # the non-secret label / NULL. Omitted for standard vaults (nothing to client-decrypt);
            # enc_description masked for an id-scoped caller like the plaintext description is.
            'enc_name': vault.enc_name if vault.type == 'zero_knowledge' else None,
            'enc_description': (None if _id_scoped
                                else (vault.enc_description if vault.type == 'zero_knowledge' else None)),
            'my_permission': _effective_vault_permission(vault, perms, current_user),
            'is_favorite': vault.id in fav_ids,
            'last_viewed_at': view_times.get(vault.id),
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
    x_access_check: Optional[str] = Header(None),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Get vault details (metadata only - no password required).
    An optional X-Vault-Password HEADER soft-verifies the vault password (rate-limited). The password
    is taken from the header, never a URL query string (which would leak into access logs).

    X-Access-Check marks a background liveness probe rather than a person opening the vault. The
    client polls this endpoint every 20 seconds while a vault view is on screen, so it can notice
    revoked access; counting those as views would make a vault left open in a background tab
    permanently the "most recently viewed" one, and would rewrite the same row three times a minute
    for as long as the tab lived. A caller can only ever suppress their OWN bookmark by sending it,
    so a header needs no stronger guarantee than this.
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
            # An id-scoped (file/folder share or scoped temp-cred) caller sees only their subtree; the
            # owner-authored vault description may reference items outside that scope, so mask it too
            # (same rationale as suppressing the whole-vault aggregates).
            'description': None if _id_scoped else vault.description,
            # Zero-knowledge: browser-sealed name/description for the client to decrypt once unlocked
            # (None for standard; enc_description masked for an id-scoped caller like description is).
            'enc_name': vault.enc_name if vault.type == 'zero_knowledge' else None,
            'enc_description': (None if _id_scoped
                                else (vault.enc_description if vault.type == 'zero_knowledge' else None)),
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
            'is_favorite': _is_vault_favorite(db, current_user.id, vault.id),
            'last_viewed_at': _vault_view_times(db, current_user, vault.id).get(vault.id),
        }
        # Opening the detail view IS the view. Stamped after the payload is built, so the value
        # returned is the PREVIOUS visit rather than the current instant — otherwise every read
        # would report "just now" and the ordering would be useless. A background access-check
        # poll is not a view (see the X-Access-Check note above).
        if not x_access_check:
            _stamp_vault_view(db, current_user, vault.id)
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


def _stamp_vault_view(db: Session, user: User, vault_id: uuid.UUID) -> None:
    """Record that THIS user opened this vault, for the "last viewed by me" ordering.

    Called from the HTTP vault-detail handler, deliberately NOT from VaultService.get_vault():
    that runs for downloads, file operations and SFTP too, so stamping there would record a
    "view" for things nobody looked at.

    A temporary credential never stamps. It authenticates AS the owning account, so the row it
    would write is the owner's — attributing activity to a person who did not act, and leaking the
    credential holder's movements into the owner's ordering.

    Best-effort: a failure here must never turn a successful vault read into an error, so it is
    committed in its own transaction and rolled back on any problem.
    """
    if getattr(user, "_is_temp_session", False):
        return
    from app.core.models import vault_views
    from sqlalchemy.dialects.postgresql import insert as _pg_insert
    try:
        now = datetime.utcnow()
        stmt = _pg_insert(vault_views).values(
            user_id=user.id, vault_id=vault_id, viewed_at=now
        ).on_conflict_do_update(
            index_elements=[vault_views.c.user_id, vault_views.c.vault_id],
            set_={"viewed_at": now},
        )
        db.execute(stmt)
        db.commit()
    except Exception:  # noqa: BLE001 — never fail a read because the bookmark write failed
        db.rollback()


def _vault_view_times(db: Session, user: User, vault_id: uuid.UUID = None) -> dict:
    """{vault_id: viewed_at} for ONE user, in a single query (not N+1).

    Returns nothing for a temporary credential. A temp session authenticates AS the owning
    account, so `current_user.id` here is the OWNER's id and an unguarded read would hand the
    credential holder the owner's viewing history — a continuously updating record of when the
    owner last opened each vault, for the life of the credential. That is the mirror image of the
    write guard in _stamp_vault_view: the write must not be attributed to the owner, and the read
    must not be disclosed to the holder.
    """
    if getattr(user, "_is_temp_session", False):
        return {}
    from app.core.models import vault_views
    from sqlalchemy import select as _select
    stmt = _select(vault_views.c.vault_id, vault_views.c.viewed_at).where(
        vault_views.c.user_id == user.id
    )
    # The single-vault path needs one row; without this it pulled the caller's whole history on
    # every vault-detail request, which the client issues on a 20-second timer.
    if vault_id is not None:
        stmt = stmt.where(vault_views.c.vault_id == vault_id)
    return {r[0]: r[1] for r in db.execute(stmt).fetchall()}


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
        
        # Update fields if provided. A plaintext name/description is a STANDARD-vault concern only:
        # a zero-knowledge vault's real name/description are sealed in the browser (enc_name/
        # enc_description below), and the server -- the enforcement boundary for the ZK guarantee --
        # must REFUSE a plaintext one so a naive/buggy/hostile caller can never store the real value
        # in the clear (its label is set at creation).
        if 'name' in vault_update and vault_update['name'] is not None:
            if vault.type == 'zero_knowledge':
                raise HTTPException(
                    status_code=status.HTTP_400_BAD_REQUEST,
                    detail="A zero-knowledge vault name must be sealed in the browser (send enc_name)."
                )
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
            # Seal the name at rest (Standard vaults); the db.refresh() below restores the
            # plaintext into vault.name so the response echoes it correctly.
            from app.services.vault_service import _seal_vault_name
            _seal_vault_name(vault, new_name.strip())

        if 'description' in vault_update:
            if vault.type == 'zero_knowledge':
                # A ZK vault never stores a plaintext description. A truthy one is refused; an empty
                # /null value is accepted only to CLEAR it (the sealed enc_description carries the
                # real one).
                if vault_update['description']:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="A zero-knowledge vault description must be sealed in the browser (send enc_description)."
                    )
                vault.description = None
            else:
                description = vault_update['description']
                if description and len(description) > 1000:
                    raise HTTPException(
                        status_code=status.HTTP_400_BAD_REQUEST,
                        detail="Vault description too long (max 1000 characters)"
                    )
                vault.description = description.strip() if description else None

        # Zero-knowledge rename: the browser sends the sealed name/description (zk2: blobs the server
        # cannot read). Store them and leave the non-secret label (vault.name) untouched; the
        # plaintext description stays NULL. Only ever acts on a ZK vault, and only on the sealed
        # fields, so a plaintext name can never overwrite a ZK vault's seal.
        if vault.type == 'zero_knowledge' and ('enc_name' in vault_update or 'enc_description' in vault_update):
            from app.core.security import is_zk_sealed_name
            if 'enc_name' in vault_update:
                _en = vault_update['enc_name']
                if _en is not None and not is_zk_sealed_name(_en):
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                        detail="A zero-knowledge vault name must be sealed in the browser.")
                if _en:
                    # Legacy re-seal: a ZK vault whose name was still plaintext (enc_name NULL) is
                    # being sealed for the first time -> drop the now-redundant plaintext name so the
                    # server no longer holds it (it becomes a label-less encrypted vault). A rename of
                    # an already-sealed vault keeps its label.
                    _was_legacy = vault.enc_name is None
                    vault.enc_name = _en
                    if _was_legacy:
                        vault.name = None
            if 'enc_description' in vault_update:
                _ed = vault_update['enc_description']
                if _ed is not None and not is_zk_sealed_name(_ed):
                    raise HTTPException(status_code=status.HTTP_400_BAD_REQUEST,
                                        detail="A zero-knowledge vault description must be sealed in the browser.")
                vault.enc_description = _ed        # None clears a removed description
                vault.description = None           # a ZK vault never stores a plaintext description

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
            # Ceiling: can't exceed the per-vault ceiling or the owner's remaining account budget.
            # Applied through the allocation ledger, so the difference is charged to (or refunded
            # from) the owner's own budget and any storage other contributors added to this shared
            # vault stays theirs.
            _apply_vault_total(db, vault, current_user, size_limit)
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


class VaultStorageUpdate(BaseModel):
    """Set the caller's OWN storage allocation on a vault, in bytes (absolute, not a delta)."""
    granted_bytes: int = Field(..., ge=0, le=storage_quota.INT64_MAX)

    @field_validator("granted_bytes", mode="before")
    @classmethod
    def _reject_bool(cls, v):
        # bool is a subclass of int, so pydantic would happily read `true` as a 1-byte
        # allocation and silently shrink the vault to one byte.
        if isinstance(v, bool):
            raise ValueError("granted_bytes must be a number of bytes")
        return v


def _vault_storage_payload(db: Session, vault, current_user: User) -> dict:
    """The vault's storage picture for one viewer: the totals everyone may see, the viewer's own
    allocation and how far they could raise it, and — only for people who administer the vault —
    the itemised contributor list. A plain member has no business knowing whose budget paid for
    the vault, so they get the totals and their own row and nothing else."""
    state = _vault_storage_state(db, vault)
    mine = state["by_user"].get(current_user.id, 0)
    others = state["total"] - mine
    ceiling = storage_quota.quota_setting_bytes(_settings_blob(db).get("max_vault_size"))
    quota = _account_quota_bytes(db, current_user)
    allocated_elsewhere = _account_allocated_bytes(db, current_user.id, exclude_vault_id=vault.id)
    headroom = storage_quota.account_headroom_bytes(quota, allocated_elsewhere)
    max_total = storage_quota.max_vault_total_bytes(ceiling, headroom, others)
    manages = _can_manage_vault(db, vault, current_user)

    payload = {
        "vault_id": str(vault.id),
        "size_limit": int(vault.size_limit or 0),
        "used_bytes": int(vault.total_size_bytes or 0),
        "my_grant_bytes": mine,
        "others_grant_bytes": others,
        # The largest TOTAL this viewer could set the vault to right now (None = unbounded), and
        # the largest allocation of their own that implies.
        "max_total_bytes": max_total,
        "my_max_grant_bytes": None if max_total is None else max(0, max_total - others),
        "per_vault_max_bytes": ceiling,
        "account_quota_bytes": quota,
        "account_allocated_bytes": allocated_elsewhere + mine,
        "budget_exempt": _is_budget_exempt(current_user),
        "can_contribute": manages and not getattr(current_user, "_is_temp_session", False),
    }
    if manages:
        names = {u.id: u.username for u in db.query(User).filter(
            User.id.in_(list(state["by_user"].keys()) or [vault.owner_id])).all()}
        payload["contributors"] = sorted(
            ({"user_id": str(uid),
              "username": names.get(uid, "(removed account)"),
              "granted_bytes": granted,
              "is_owner": uid == vault.owner_id,
              "is_you": uid == current_user.id}
             for uid, granted in state["by_user"].items()),
            key=lambda c: (-c["granted_bytes"], c["username"]),
        )
    return payload


@app.get("/vaults/{vault_id}/storage")
@require_endpoint_permission("VAULT_VIEW")
@require_vault_cap("vault.see_info")
async def get_vault_storage(
    vault_id: uuid.UUID,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """This vault's storage: how much it may hold, how much it holds, and who allocated it."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    try:
        vault = vault_service.get_vault(vault_id, current_user, None, require_password=False)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    return _vault_storage_payload(db, vault, current_user)


@app.put("/vaults/{vault_id}/storage")
@require_endpoint_permission("VAULT_SETTINGS")
@require_vault_cap("vault.change_expiry")
async def set_vault_storage(
    vault_id: uuid.UUID,
    payload: VaultStorageUpdate,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Set the caller's own storage allocation on this vault, out of their account quota.

    Open to the owner and to Managers, so a shared vault can be funded by the people who run it
    — each of them adding storage from their own budget and reclaiming exactly what they added,
    never anybody else's. A temporary credential is refused outright: spending an account's
    storage budget outlives the credential's time-box, so it needs an interactive session.
    """
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    try:
        vault = vault_service.get_vault(vault_id, current_user, None, require_password=False)
    except ResourceNotFoundError as e:
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail=str(e))
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))

    if getattr(current_user, "_is_temp_session", False):
        raise HTTPException(
            status_code=403,
            detail="A temporary credential cannot change storage allocation; use an interactive session.",
        )
    if not _can_manage_vault(db, vault, current_user):
        raise HTTPException(
            status_code=403,
            detail="Only the vault owner or a vault manager can change this vault's storage.",
        )

    # Take the vault's row lock first, so a second contributor writing at the same moment cannot
    # compute a total that omits this one. Held until the commit below.
    _lock_vault_for_allocation(db, vault)
    state = _vault_storage_state(db, vault, commit=False)
    mine = state["by_user"].get(current_user.id, 0)
    others = state["total"] - mine
    _enforce_grant(db, vault, current_user, payload.granted_bytes,
                   current_grant=mine, other_grants=others)
    total = _write_vault_grant(db, vault, current_user.id, payload.granted_bytes)
    db.commit()

    try:
        AuditLogger(db).log_action(
            action="vault_storage_allocated",
            status="success",
            user=current_user,
            ip_address=get_client_ip(request),
            details={"vault_id": str(vault.id), "granted_bytes": payload.granted_bytes,
                     "previous_bytes": mine, "size_limit": total},
        )
    except Exception:
        pass  # never fail the allocation just because the audit write did

    db.refresh(vault)
    return _vault_storage_payload(db, vault, current_user)


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

        # For a zero-knowledge vault, surface each member's encryption-key status so the UI can show
        # "Pending encryption key setup" for a member granted access before they created their key
        # (allowed: the authz membership row exists, but no wrapped DEK can be issued until they have a
        # keypair). Standard vaults have no per-member keys, so the flag is not applicable there.
        is_zk = _is_zk_vault(vault)
        keyed_user_ids = set()
        if is_zk and result:
            from app.core.models import UserKeyPair
            member_ids = [row.user_id for row in result]
            keyed_user_ids = {
                uid for (uid,) in db.query(UserKeyPair.user_id).filter(
                    UserKeyPair.user_id.in_(member_ids)).all()
            }

        permissions = []
        for row in result:
            has_key = row.user_id in keyed_user_ids
            permissions.append({
                "user_id": row.user_id,
                "username": row.username,
                "email": row.email,
                "read_permission": row.read_permission,
                "write_permission": row.write_permission,
                "delete_permission": row.delete_permission,
                "manage_permission": row.manage_permission,
                "added_at": row.added_at,
                # ZK encryption-key status: null for a standard vault; for a ZK vault, whether the
                # member has set up their key, and whether they're still pending it.
                "has_encryption_key": (has_key if is_zk else None),
                "pending_key_setup": (is_zk and not has_key),
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

        # Was this user already a member? The upsert below is idempotent (on_conflict_do_update), so a
        # re-grant that only changes a permission level must NOT fire the "added to a vault" email.
        _already_member = db.query(vault_members).filter(
            vault_members.c.vault_id == vault_id,
            vault_members.c.user_id == permission.user_id).first() is not None

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

        # Optionally email a genuinely-new member that they were added to a vault (opt-in). Best-effort;
        # the default template uses {{vault.name}}/{{vault.url}}, so no action_context is required.
        if not _already_member:
            _fire_action_email(db, "vault_member_added", email=user.email, username=user.username)

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
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """
    Refuse to rotate a Standard vault's encryption key, and say why.

    This endpoint used to archive the stored key, generate a new one, bump `key_version` and
    answer "Encryption key rotated successfully — new file uploads will use the new key."

    None of that was true of the content. A Standard vault's file bytes are encrypted under a key
    derived from the DEPLOYMENT secret — HKDF over `settings.encryption_key`, salted per file with
    the vault and file ids — and no read path consults `encrypted_vault_key` or `key_version` at
    all. Rotating them changed a key nothing uses, then reported a completed security operation.

    That is the worst possible failure mode for this particular endpoint. An operator reaches for
    it precisely when they believe a key is compromised; a success message tells them the content
    is now protected under a new key, and they stop. The honest answer is that this server cannot
    re-key Standard content today, so it says so, and changes nothing.

    Zero-knowledge vaults are unaffected: their content key never reaches the server, and their
    rekey endpoint is a different mechanism that genuinely works.
    """
    try:
        from app.core.models import Vault
        audit_logger = AuditLogger(db)
        
        # Get vault
        vault = db.query(Vault).filter(Vault.id == vault_id).first()
        
        if not vault:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="Vault not found"
            )
        
        # Only owner can rotate keys
        if vault.owner_id != current_user.id:
            # A non-owner reaching for another account's key rotation is worth recording:
            # it is both an access denial and a possible probe of someone else's vault.
            audit_logger.log_access_denied(
                user=current_user, resource_type='vault', resource_id=str(vault_id),
                ip_address=get_client_ip(request), reason='rotate-key: not vault owner',
            )
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail="Only vault owner can rotate encryption keys"
            )

        # server-side key rotation applies only to STANDARD vaults. A zero-knowledge
        # vault's content key is client-side (the server never holds it), so rotating the
        # server key here would touch an unused key and falsely report success — reject it.
        if getattr(vault, "type", "standard") == "zero_knowledge":
            audit_logger.log_action(
                action='vault_key_rotation', status='refused', user=current_user,
                resource_type='vault', resource_id=str(vault_id),
                ip_address=get_client_ip(request), details={'reason': 'zero_knowledge'},
            )
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="Key rotation does not apply to zero-knowledge vaults; their keys are managed client-side (use the zero-knowledge rekey endpoint).",
            )

        # ONE refusal for every Standard vault, whatever its password state or key vintage.
        #
        # Rotating here would archive the stored key, mint a replacement and bump key_version --
        # all of it invisible to the content, which is encrypted under a key derived from the
        # deployment secret and never consults these columns. The old response claimed otherwise.
        #
        # It is deliberately a REFUSAL rather than a quieter success or a no-op 200: a caller
        # asking to rotate a key needs to learn that the key did not rotate. Nothing external
        # depends on the old response -- no frontend, tool or documented flow calls this route;
        # only this repository's own tests did.
        #
        # Record the attempt before refusing. An operator reaches for key rotation when they
        # believe a key is compromised -- one of the highest-signal events the product can
        # capture -- and until now a defender reviewing the log after an incident saw nothing.
        # This writes ONE audit row; it still changes no vault key state (nothing is archived,
        # minted or version-bumped), so the refuse-before-any-key-mutation property holds.
        audit_logger.log_action(
            action='vault_key_rotation', status='refused', user=current_user,
            resource_type='vault', resource_id=str(vault_id),
            ip_address=get_client_ip(request), details={'reason': 'standard_not_supported'},
        )
        raise HTTPException(
            status_code=status.HTTP_501_NOT_IMPLEMENTED,
            detail=(
                "Key rotation is not implemented for standard vaults. File contents are "
                "encrypted with a key derived from this deployment's encryption secret, not "
                "from the vault key, so rotating the vault key would not re-encrypt anything. "
                "Nothing was changed. To re-key stored content you must first download it, "
                "then upload it to a deployment created with a new encryption secret: rotating "
                "this deployment's secret in place makes every existing file permanently "
                "undecryptable, including anything not yet downloaded. Zero-knowledge vaults are "
                "the supported way to rotate content keys, because those keys are client-side."
            ),
        )
        
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
            "total_rotations": len(history),
            # The server-side key rotation this history would record is not supported: a
            # Standard vault's content is encrypted under a key derived from the deployment
            # secret, which this version never rotates, so the list cannot become non-empty.
            # Stated so a reader does not mistake a permanently-empty history for a fault.
            "rotation_supported": False,
            "note": ("Server-side key rotation is not supported; this history tracks a key version no read path uses. Zero-knowledge vaults rotate their content key by a separate client-side mechanism."),
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
                # UNIMPLEMENTED: folder passwords are not wired end-to-end — no endpoint sets one
                # and no access path enforces one — so this flag is cosmetic today (always False in
                # practice). See VaultService.get_folder for the full state.
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


def _file_name_match(db, vault, vault_id, filename, name_bi, name_bi_candidates=None):
    """Build the SQLAlchemy same-name filter for a File in a vault. Zero-knowledge vaults
    match on the CLIENT-supplied blind index (the server has no plaintext to compare);
    Standard/legacy vaults match on the plaintext name (via the blind index or column).

    `name_bi_candidates`, when given, is the SET a zero-knowledge name may match under. A ZK name
    index is keyed per (DEK, epoch), so a file sealed before a rotation carries an index at an old
    epoch that the uploader's single current-epoch `name_bi` cannot equal -- and the clash goes
    unseen. The client therefore sends every epoch's candidate (plus, once the vault has one, the
    rotation-independent index-key value); this matches the union with `IN`. It is a superset of
    the single-value match -- `name_bi` itself is expected to be among the candidates -- so it never
    matches FEWER rows, only the older ones the single value missed. Absent/empty preserves the
    exact prior behaviour for an old client."""
    if name_bi_candidates:
        # De-duplicated, and any stray non-string dropped so a malformed element cannot turn the
        # IN into a type error on the query.
        vals = [c for c in dict.fromkeys(name_bi_candidates) if isinstance(c, str)]
        if vals:
            return File.name_bi.in_(vals)
    if name_bi is not None:
        return File.name_bi == name_bi
    return _name_match_filter(File, vault, filename)


def _reject_unreplaceable_upload(db, vault_id, folder_id, filename, user, name_bi=None,
                                name_bi_candidates=None):
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
        _file_name_match(db, vault, vault_id, filename, name_bi, name_bi_candidates),
    ).first()
    if clash is not None and not _principal_can_replace_file(db, user, vault_id):
        shown = f"'{filename}' " if filename else ""
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=f"A file named {shown}already exists and you lack permission to replace it.",
        )


_MEDIA_TOKEN_CHARS = frozenset(
    "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!#$%&'*+.^_`|~-")


def _is_media_token(text: str) -> bool:
    return bool(text) and all(c in _MEDIA_TOKEN_CHARS for c in text)


def _safe_media_type(value: Optional[str]) -> str:
    """A stored MIME type reduced to something that can be put in a header.

    A MIME type is whatever the client said it was and is stored verbatim, so this cannot assume it
    is well formed. Two ways a stored string breaks the response: anything outside Latin-1 raises
    while the header is being encoded, and a control character -- CR and LF are ASCII, so they
    survive any encode -- would let it inject header content. What passes is a conservative
    type/subtype with optional parameters; anything else becomes the generic type, which is always
    safe to serve. The filename beside it is guarded the same way, in _content_disposition.
    """
    text = (value or "").strip()
    if not text or len(text) > 255:
        return "application/octet-stream"
    if any(not (32 <= ord(c) <= 126) for c in text):
        return "application/octet-stream"

    essence, _, rest = text.partition(";")
    kind, slash, subtype = essence.strip().partition("/")
    if not slash or not _is_media_token(kind) or not _is_media_token(subtype):
        return "application/octet-stream"

    while rest:
        parameter, _, rest = rest.partition(";")
        name, equals, raw = parameter.strip().partition("=")
        # An empty segment is not a parameter. Passing "text/plain;" through unchanged leaves the
        # framework to render it as "text/plain;; charset=utf-8".
        if not equals or not _is_media_token(name.strip()):
            return "application/octet-stream"
        raw = raw.strip()
        if raw.startswith('"'):
            if (not raw.endswith('"') or len(raw) < 2
                    or "\\" in raw or '"' in raw[1:-1]):
                return "application/octet-stream"
        elif not _is_media_token(raw):
            return "application/octet-stream"

    return text


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
    
    # One transfer slot for the request, not one per file. A request carrying several files is
    # one transfer as far as memory goes -- the files are read and encrypted one after another --
    # and taking a slot per file would let a request commit its first file and then be refused
    # partway through, which is a worse answer than either accepting or refusing the whole thing.
    transfer_slot = None

    # Bound here, not where they are first used, because the teardown at the end of this function
    # reads them on EVERY path out -- including the ones that raise before the vault has even been
    # looked up. Left to be bound later, an authorization denial raises past them and the teardown
    # fails with an unbound name, turning a clean 403 into a 500.
    reservation_key = None
    vault_size_limit = 0

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
        
        # Admitted on the same ceiling as a download: reading the submitted bytes and pushing
        # them through the encryption pipeline holds memory for a duration in the same way, and a
        # deployment's capacity is the two together rather than each apart.
        #
        # Taken once for the request rather than once per file -- a request carrying several files
        # is one transfer as far as memory goes, and admitting each file separately would let a
        # request commit its first file and then be refused partway through. Taken before the
        # operation is registered, so a refusal leaves nothing in the registry, and returned by the
        # request-level finally on every path out -- which also returns the space reservation taken
        # above, the one thing that does precede admission.
        if files:
            try:
                transfer_slot = await transfer_admission.acquire()
            except TransferBusy as busy:
                raise _busy_response(busy)

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
                total_size=0,  # Unknown at start for streaming uploads
                temp_credential_id=getattr(current_user, "_temp_cred_id", None),
                vault_id=str(vault_id),
            )

            _op_ok = False  # set True only after the file is fully committed (drives complete_operation)

            # Per-file teardown: the progress record and the operation entry. The transfer slot
            # and the space reservation belong to the request, and are released at the end of it.
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
                        "bytes_uploaded": 0,
                        **_vault_activity_fields(vault, current_user)
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
                                    "cancelled": True,  # Mark as cancelled
                                    **_vault_activity_fields(vault, current_user)
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
                                        "severity": "medium",
                                        **_vault_activity_fields(vault, current_user)
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
                                    "bytes_uploaded": bytes_uploaded,
                                    **_vault_activity_fields(vault, current_user)
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

                    # And the PER-VAULT ceiling, on the same terms and for the same two
                    # reasons. Both guards above it consume `vault_current_size`, read once
                    # before the stream began: stale the moment another upload commits. And
                    # the atomic reservation is only taken when Content-Length gave a size,
                    # so a client that omits the header -- which any streaming client does by
                    # default -- had no reservation and only that stale number standing
                    # between it and the limit. Measured: two concurrent requests from ONE
                    # ordinary account put 250% of a vault's ceiling into it, and sixteen put
                    # 400%, every one of them returning success. Sequentially the same
                    # uploads are refused correctly, which is why it survived.
                    #
                    # Read fresh, like the resumable path's guard. This does not make the
                    # check atomic -- see the note there -- but it removes the two holes that
                    # make this path bypassable without any timing skill at all.
                    _vault_now = (db.query(Vault.total_size_bytes)
                                  .filter(Vault.id == vault_id).scalar() or 0)
                    if vault_size_limit and _vault_now + final_size > vault_size_limit:
                        raise HTTPException(
                            status_code=status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
                            detail="Upload rejected: Vault size limit would be exceeded")

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
                        "completed": True,
                        **_vault_activity_fields(vault, current_user)
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
                        "completed": True,
                        **_vault_activity_fields(vault, current_user)
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
    finally:
        # Every path out of the request returns the slot, including the ones that raise before a
        # single file is read (where there is nothing to return and this is a no-op). A slot lost
        # here does not fail loudly: it shrinks the ceiling permanently, one leak at a time, until
        # the deployment refuses every transfer.
        if transfer_slot is not None:
            transfer_admission.release(transfer_slot)

        # The space reservation goes back on the same terms, and for the same reason: held after
        # the request is over it counts against the vault for its full five-minute life, so a
        # refused or abandoned upload makes the vault look fuller than it is.
        if reservation_key and vault_size_limit > 0:
            try:
                reserved_amount = redis_client.get(reservation_key)
                redis_client.delete(reservation_key)
                if reserved_amount:
                    print(f"🧹 Reservation cleanup: {int(reserved_amount) / (1024*1024):.2f} MB")
            except Exception as exc:
                print(f"⚠️ Failed to cleanup reservation in finally: {exc}")


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


def _session_visible(current_user):
    """Sessions this caller may SEE and CANCEL.

    Wider than `_session_principal`, and only in the direction that is safe. A person signed in
    directly may look at, and get rid of, any upload sitting on their own account -- including one
    a temporary credential started. It is their storage, their quota and their session budget.

    They still may not WRITE to or COMPLETE such a session; those keep the strict rule, because
    that is where the tampering and the misattribution live.

    Without this, binding a session to its opener hid a credential's uploads from the only party
    entitled to clear them: a few credentials could fill the account's session budget, the owner
    would see an empty list beside a 429, and nothing short of a deployment administrator could
    resolve it. Revoking the credential made it permanent rather than better.
    """
    # Branching on the credential id alone was wrong: a temporary session that somehow lacks
    # one would land in the owner branch and get see-and-cancel over the whole account --
    # exactly the shape the strict predicate below refuses, made unreachable by returning
    # first. Anything that is temporary in any way goes through the strict rule.
    if (getattr(current_user, '_is_temp_session', False)
            or getattr(current_user, '_temp_cred_id', None) is not None):
        return _session_principal(current_user)
    return ChunkedUploadSession.user_id == current_user.id


def _session_principal(current_user):
    """Restrict a chunked-upload session query to the principal that opened it.

    `user_id` alone cannot do this. A temporary credential acts AS the account that minted it and
    carries the same `user_id`, so every session surface -- write a chunk, list, inspect, complete,
    cancel -- was reachable by any credential holding `file.upload` on the vault, for uploads it
    had never started. A credential could overwrite chunks of somebody else's in-flight upload and
    the owner's own completion would then succeed, storing a file made partly of the credential's
    bytes, with a checksum computed over the tampered assembly. On a zero-knowledge vault that is
    destruction rather than tampering: one replaced chunk fails the whole-file tag, and the browser
    released the only plaintext copy when it encrypted.

    Applied as a query filter rather than a post-fetch check, so a session belonging to another
    principal is simply not found -- the same answer as one that does not exist, which is also the
    right answer to give.

    A credential must not match NULL: an interactive session belongs to the person, not to
    "whoever is acting as them".
    """
    cred_id = getattr(current_user, '_temp_cred_id', None)
    if cred_id is None:
        # A temporary session with no credential id should be impossible -- authentication rejects
        # it well before here -- but the whole point of this predicate is that the SHAPE of the
        # caller decides what they reach, and defaulting a temp session to the owner's predicate
        # would be this defect over again. Match nothing instead of guessing.
        if getattr(current_user, '_is_temp_session', False):
            return sqlalchemy.false()
        return ChunkedUploadSession.temp_credential_id.is_(None)
    return ChunkedUploadSession.temp_credential_id == cred_id


def _chunk_hash_path(session_dir, index: int):
    """Where the digest of chunk `index` lives.

    Beside the chunk rather than in the database, for two reasons. The received-chunk set is read
    from disk precisely so it survives a restart, and a digest kept anywhere else could disagree
    with the bytes it describes. And they are removed together: the session directory is deleted
    wholesale on completion and by the sweeper, so a digest cannot outlive its chunk.

    Named `hash_*` rather than `chunk_*.sha256` so it cannot be mistaken for a chunk by the glob
    below -- that would depend on an integer parse failing, which is not a thing to rely on.
    """
    return session_dir / f"hash_{index:06d}"


def _chunk_hashes(session_dir) -> dict:
    """Digest per stored chunk, for a resuming client to check its local copy against.

    A resumed upload sends only the indices the server says it is missing. If the file changed
    since the interrupted attempt -- edited to the same length, so nothing else notices -- the
    result is the old attempt's chunks joined to the new file's, stored with no error. These let
    the client find out which of its own chunks no longer match and send those too.
    """
    if not session_dir.exists():
        return {}
    out = {}
    for p in session_dir.glob("hash_*"):
        try:
            out[int(p.name.split("_", 1)[1])] = p.read_text(encoding="ascii").strip()
        except (ValueError, IndexError, OSError):
            continue
    return out


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
        # Which principal opened it. The owner may cancel any session on their account, and
        # cancelling a zero-knowledge upload destroys the only copy of those bytes -- so a
        # list they cannot tell apart is a list they cannot safely act on.
        'temp_credential_id': (str(session.temp_credential_id)
                               if session.temp_credential_id else None),
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
    # The object id the client will encrypt against. REQUIRED for a zero-knowledge upload (see
    # the check below); optional here so a Standard upload, which binds nothing to it, is
    # unaffected.
    file_id: Optional[uuid.UUID] = None
    # Zero-knowledge only: 32 lowercase hex characters naming this ENCRYPTION ATTEMPT. Required
    # for a zero-knowledge upload. The server never interprets the value -- it compares it, so
    # that a second encryption of the same file cannot inherit the first's buffered chunks.
    blob_id: Optional[str] = Field(None, pattern=r'^[0-9a-f]{32}$')
    # The session this upload means to continue. Absent means "start a new one", and that is
    # the whole point: resuming used to be inferred from the request looking like one already
    # in flight, which is not something a server can tell apart from a second upload of the
    # same file.
    resume_session_id: Optional[uuid.UUID] = None
    # Zero-knowledge only: the file name + MIME encrypted IN THE BROWSER under the vault
    # DEK (security ZK marker + base64) and the client-computed blind index for same-name
    # matching. Required for ZK uploads; rejected for Standard ones. The server stores them
    # verbatim and never decrypts.
    enc_name: Optional[str] = Field(None, max_length=8192)   # bound sealed metadata (see FileRename)
    enc_mime: Optional[str] = Field(None, max_length=8192)
    name_bi: Optional[str] = Field(None, max_length=64)  # stored in a VARCHAR(64) column
    # Zero-knowledge only: extra blind-index values to MATCH this name against, beyond the single
    # `name_bi` stored on the finished row. A ZK name index is per (DEK, epoch); after a rotation a
    # pre-existing file's index sits at an old epoch that the uploader's current-epoch `name_bi`
    # cannot equal, so a same-name clash goes unseen and the replace/reject guard stops firing. The
    # client sends every epoch's candidate (and the rotation-independent index-key value once the
    # vault has one). Bounded so a client cannot make the server hold an unbounded list; each is a
    # 64-char blind index. Absent falls back to matching the single `name_bi`.
    name_bi_candidates: Optional[List[str]] = Field(None, max_length=64)


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
    # Each chunk must fit within _MAX_UPLOAD_CHUNK_BYTES so a single chunk request cannot stage more
    # than one piece to the transient buffer (see the constant). Require enough chunks that each
    # stays within the cap; the per-chunk write enforces it as a backstop. Reject here for a clean
    # error at session creation rather than a mid-upload 413.
    _min_chunks = (body.total_size + _MAX_UPLOAD_CHUNK_BYTES - 1) // _MAX_UPLOAD_CHUNK_BYTES
    if body.total_chunks < _min_chunks:
        raise HTTPException(
            status_code=400,
            detail=(f"Too few chunks: each chunk may be at most "
                    f"{_MAX_UPLOAD_CHUNK_BYTES // (1024 * 1024)} MB, so declare at least "
                    f"{_min_chunks} chunk(s) for a {body.total_size}-byte upload."),
        )

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
        # And it must not carry the fields that only mean something for an encrypted upload,
        # mirroring the guard above. Accepting them is not harmless: a session opened while
        # carrying one of them then refuses every ordinary re-init of that same file, for the whole
        # session lifetime, because the plain client sends none.
        #
        # `file_id` is deliberately NOT in this list, and the reasoning is worth recording because
        # it changed. A session opened carrying an id refuses every re-init of that file that
        # declares none, for the whole session lifetime -- and the shipped client declares none for
        # a standard upload, so the field looked like the same lockout this guard exists to
        # prevent. What made that worth acting on was that a temporary credential could inflict it
        # on the account owner. It no longer can: a session is now bound to the principal that
        # opened it, so a credential's session is invisible to the owner and cannot collide with
        # theirs. What remains is one principal colliding with itself, recoverable from the
        # refusal, which names the session to discard.
        #
        # Against that, refusing it would remove a capability that exists on purpose: an API client
        # may choose its own object id, and the completion honours it.
        forbidden = [name for name, value in (
            ('blob_id', body.blob_id),
            ('zk_key_version', body.zk_key_version),
        ) if value is not None]
        if forbidden:
            raise HTTPException(
                status_code=400,
                detail=("An upload to a standard vault must not send "
                        + ", ".join(forbidden) + "."),
            )

    if body.total_size > _max_file_bytes:
        raise HTTPException(status_code=413, detail=f"File exceeds maximum size of {_max_file_bytes // (1024 * 1024)}MB")
    if vault.size_limit and (vault.total_size_bytes or 0) + body.total_size > vault.size_limit:
        raise HTTPException(status_code=413, detail="File would exceed the vault size limit")
    _enforce_deployment_storage_quota(db, body.total_size)   # deployment-wide stored-bytes limit

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
        _session_principal(current_user),
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
    # Resuming is something a client ASKS for. It used to be inferred: a new upload matching an
    # existing session on vault, folder, name, size and chunk count was handed that session and
    # its already-received chunks. Nothing in that set distinguishes a genuine resume from a
    # second upload of the same file -- so editing a file without changing its length and
    # uploading it again stored the OLD content, or a mixture, with no error and a 200.
    #
    # A different length was always safe, because the length is part of the match. This closes
    # the one case where it is not doing that work.
    #
    # The cost of asking is a client that relied on the inference now re-uploads instead of
    # continuing: slower, never wrong.
    if body.resume_session_id is None:
        session = None
    else:
        session = resume_q.filter(
            ChunkedUploadSession.id == body.resume_session_id).first()
        if session is None:
            # Named a session that does not exist, belongs to another principal, has expired,
            # or describes a different file. Refusing beats silently starting a new upload the
            # caller did not ask for and will not know to look for.
            raise HTTPException(status_code=409, detail={
                "code": "resume_target_gone",
                "message": ("That upload can no longer be continued. Start it again."),
            })

    # This session's buffered chunks, and its stored encrypted name, belong to the object id,
    # the key epoch and the encryption attempt it was opened with. Resuming under any different
    # one would assemble a file out of two encryptions and commit it under bindings its own
    # bytes do not match -- an entry that will never open again.
    #
    # Refused HERE rather than at the end. Silently keeping the session's own values meant the
    # caller re-uploaded the whole file to be told no, and each attempt pushed the session's
    # expiry out by another TTL.
    #
    # The three are not interchangeable and all three are needed:
    #   - the attempt token is the only one that separates two encryptions of the SAME object,
    #     because the object id is deliberately stable across a resume (the name is sealed
    #     against it) and can legitimately be equal on both attempts;
    #   - the object id catches a resume that adopted the wrong object entirely;
    #   - the key epoch catches an attempt encrypted after a rekey meeting one from before it.
    #
    # The epoch needs no vault-type conditioning: a standard upload is refused above if it carries
    # one at all, so both sides are always absent there and the comparison is a no-op. An earlier
    # draft conditioned it on the vault type, which read as though it were load-bearing.
    #
    # Both sides absent still compares equal, which now only reaches Standard uploads: an
    # encrypted one cannot open a session without declaring all three.
    if session is not None:
        for code, mine, theirs in (
            ("upload_attempt_mismatch", body.blob_id, session.blob_id),
            ("object_id_mismatch", body.file_id, session.client_object_id),
            ("key_epoch_mismatch", body.zk_key_version, session.zk_key_version),
        ):
            if mine == theirs:
                continue
            # The session id travels with the refusal because it is the handle on the thing the
            # caller has to act on, and it is the caller's own session -- the resume query above
            # is filtered to this user, and the listing endpoint already returns more about it.
            #
            # The message does NOT say to cancel. For an encrypted upload the buffered
            # ciphertext is the only copy -- the plaintext handle was released at encryption
            # time -- so cancelling is the one irreversible option, and it was the only one the
            # old wording offered.
            raise HTTPException(status_code=409, detail={
                "code": code,
                "session_id": str(session.id),
                "message": ("An earlier attempt at this file is still in progress. Resume "
                            "that one, or discard it before starting again."),
            })

    if session is None:
        if is_zk:
            # A zero-knowledge upload must say what its encrypted material is bound to, and it
            # must say it HERE rather than at the end.
            #
            # At the end the server can only guess, and guessing costs the file: the name is
            # sealed against the object id, and the coming content format derives its key from
            # the object id, the epoch and the attempt (today's does not -- the token is an
            # opaque label the server only ever compares). Worse, a session that declared
            # nothing was
            # indistinguishable from any OTHER session that declared nothing -- so a second,
            # independent encryption of the same file matched the first one's session and
            # inherited its buffered chunks. The stored object came out as one attempt's first
            # chunk followed by another attempt's rest, committed with a 200 and no error.
            #
            # Required only when OPENING a session, deliberately. A session opened before these
            # fields existed still has a browser holding its ciphertext as the only copy, and
            # refusing its resume would strand exactly the bytes this rule exists to protect. Such
            # a session declares nothing on both sides, compares equal above, and continues; it
            # ages out with its own expiry, and nothing new can be created in that shape.
            missing = [name for name, value in (
                ('file_id', body.file_id),
                ('zk_key_version', body.zk_key_version),
                ('blob_id', body.blob_id),
            ) if value is None]
            if missing:
                raise HTTPException(status_code=400, detail={
                    "code": "upload_declaration_missing",
                    "missing": missing,
                    "message": ("This upload could not be started because the browser did not "
                                "say which encryption produced it. Add the file again."),
                })

        # bound concurrent open sessions per user so N half-open sessions can't buffer
        # N*total_size of transient disk that the plan storage quota never counts. Resuming an
        # existing session (above) is unaffected — only a NEW session is capped.
        open_sessions = db.query(ChunkedUploadSession.id).filter(
            ChunkedUploadSession.user_id == current_user.id,
            _session_principal(current_user),
            ChunkedUploadSession.status == 'active',
            ChunkedUploadSession.expires_at > now,
        ).count()
        if open_sessions >= 25:
            raise HTTPException(
                status_code=429,
                detail="Too many concurrent uploads in progress; complete or cancel some before starting another.",
            )
        # The cap above now counts only the caller's OWN sessions, which is the fix: it used to
        # count every session on the account, so a credential scoped to one vault could fill it and
        # lock the owner out of uploading to every OTHER vault for the whole session lifetime --
        # a scope escape, since the point of scoping is to bound the blast radius to the vaults
        # granted.
        #
        # Per-principal counting alone would multiply the buffered-chunk disk by the number of
        # live credentials, so the account keeps an overall ceiling too. Four credentials at
        # their own limit reach it, which is ordinary use rather than abuse -- so reaching it
        # must stay recoverable, and it is: the owner can list and cancel every session on
        # the account, and revoking a credential releases the ones it opened.
        account_sessions = db.query(ChunkedUploadSession.id).filter(
            ChunkedUploadSession.user_id == current_user.id,
            ChunkedUploadSession.status == 'active',
            ChunkedUploadSession.expires_at > now,
        ).count()
        if account_sessions >= 100:
            raise HTTPException(
                status_code=429,
                detail="This account has too many uploads in progress; complete or cancel some before starting another.",
            )
        # Refuse a doomed id BEFORE a byte moves. The completion checks this too and must
        # keep doing so -- an id can be retired while an upload is in flight -- but without a
        # check here the client transfers the entire file, the server writes every chunk to disk,
        # and only then does /complete answer 409. The comment on that check justified itself by
        # avoiding exactly this, which was true of the assembly and not of the transfer.
        if body.file_id is not None and (
                db.query(File.id).filter(File.id == body.file_id).first()
                or db.query(RetiredObjectId.id).filter(
                    RetiredObjectId.id == body.file_id).first()):
            raise HTTPException(status_code=409, detail="File id already in use")
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
            name_bi_candidates=body.name_bi_candidates or None,
            total_size=body.total_size,
            total_chunks=body.total_chunks,
            chunks_received=0,
            bytes_received=0,
            folder_id=folder_uuid,
            client_object_id=body.file_id,
            # Recorded only on a fresh session, like the epoch below; a resumed one keeps its
            # original and the comparison above is what enforces that.
            blob_id=body.blob_id,
            # Whose session this is. NULL for a person signed in directly.
            temp_credential_id=getattr(current_user, '_temp_cred_id', None),
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
        # What the server holds for each of those indices, so the client can tell whether its
        # local copy still matches before skipping them.
        'chunk_checksums': _chunk_hashes(sdir),
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
        _session_principal(current_user),
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
    # PLAINTEXT size of this index if it is being re-sent, so the running total stays accurate and
    # an overwrite is not double-counted. A sealed chunk carries its plaintext length in its header
    # (a legacy plaintext chunk is its own on-disk size); using that -- not the on-disk ciphertext
    # size -- keeps the byte accounting in the same plaintext units as `total_size`, so the
    # encryption framing overhead is never charged against the declared file size.
    existing_size = sealed_plaintext_size(chunk_path) if already else 0
    # Bytes already buffered for this session EXCLUDING the index being written. Clamp at
    # 0: a crash between writing a chunk and committing the counter can leave bytes_received
    # undercounted, and base_bytes must never go negative (that would loosen the bound).
    base_bytes = max(0, (session.bytes_received or 0) - existing_size)
    # Bound each request to ONE chunk, not the whole remaining file. base_bytes is read before the
    # per-session row lock, so a stale (low) read would otherwise let K concurrent requests each
    # stage up to total_size into the _uploads/ buffer -- uncounted transient disk, a cross-tenant
    # DoS. min() caps the stream to the smaller of "bytes left in the file" and one chunk; a body
    # larger than that is refused (413 below). This is a size cap per piece, not a rate limit.
    remaining = min(session.total_size - base_bytes, _MAX_UPLOAD_CHUNK_BYTES)  # bytes this index may add

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

    # Staged under a name unique to this REQUEST, not to the chunk index. The body is streamed
    # into this file across the whole transfer rather than written to it in one call at the end,
    # so an index-derived name would be one two concurrent requests hold open at once: the second
    # `open(..., 'wb')` truncates the first one's file, both then write at their own offsets, and
    # either one's cleanup deletes the other's work. Re-sending a chunk is the documented retry,
    # so two requests at one index are ordinary traffic rather than an attack.
    tmp_path = sdir / f".chunk_{chunk_index:06d}.{uuid.uuid4().hex}.part"

    # Straight to disk as it arrives, with the digest taken in passing. Nothing downstream wants
    # the whole body -- it is written, hashed, and checked for emptiness, all of which stream --
    # so nothing larger than one piece is held, whatever chunk size the client declared. See
    # `receive_bounded` for what holding it used to cost.
    #
    # The bound is still `remaining`, what is left of the declared file, checked per piece so an
    # absent or understated Content-Length cannot get past it. As a per-request bound it is
    # generous, but it is the only size the session actually promises, and it now bounds transient
    # disk rather than memory.
    try:
        # The byte count is not needed here: the counters below are recomputed from what is
        # actually on disk, which is what stays right under a concurrent re-send. The chunk is
        # sealed as it streams (each 1 MiB record AES-GCM-encrypted under a per-session key, bound
        # to this session+index) so no raw chunk is ever readable on the staging volume; `remaining`
        # still bounds PLAINTEXT bytes and `chunk_digest` is still over the plaintext, so the
        # ChunkTooLarge/EmptyBody contract and the resume digest are unchanged.
        _written, chunk_digest = await seal_stream_to_file(
            request.stream(), tmp_path, remaining, session.id, chunk_index)
    except ChunkTooLarge:
        # The body reached disk before it could be measured, which is the trade for not holding it
        # in memory. It is bounded by `remaining` -- disk this session was already approved to
        # buffer -- and `receive_bounded` has removed it.
        raise HTTPException(status_code=413, detail="Chunk data exceeds the declared upload size")
    except EmptyBody:
        raise HTTPException(status_code=400, detail="Empty chunk")

    # Everything from here is under the per-session row lock (SELECT ... FOR UPDATE). It already
    # existed to serialize the counter update; publishing the chunk needs it for the same reason.
    # A chunk and its digest are two filesystem operations, so two requests at one index can
    # otherwise finish them interleaved and leave one request's bytes under the other's digest --
    # which tells a resuming client that a copy the server no longer holds still matches. Holding
    # the lock across the rename makes the pair atomic against the only writers that can collide,
    # which are other requests in this same session. The counters are then recomputed from the
    # AUTHORITATIVE on-disk chunk set, so concurrent PUTs -- even a same-index re-send -- converge
    # to the true total instead of racing a read-modify-write (a blind += double-counts a
    # same-index race; an absolute assignment clobbers a concurrent different-index write).
    # Mirrors the disk-authoritative /complete and the ZK-path locking.
    _total = session.total_chunks
    locked = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session.id
    ).with_for_update().first()

    hash_path = _chunk_hash_path(sdir, chunk_index)
    # A previous attempt's digest goes first. The lock keeps another request out, but a crash still
    # lands somewhere, and this order leaves a resuming client with no digest, so it re-sends. The
    # other order leaves the new bytes under the old digest.
    try:
        hash_path.unlink()
    except OSError:
        pass
    try:
        # Renamed only once it is whole, so a dropped connection cannot leave a truncated chunk
        # under the name the assembler reads.
        os.replace(tmp_path, chunk_path)
    except OSError:
        try:
            tmp_path.unlink()
        except OSError:
            pass
        raise
    # From what was actually written rather than from anything the client asserted, accumulated
    # while the body streamed past. Best effort: a missing digest makes a resuming client re-send
    # that chunk, which is slower and never wrong.
    try:
        hash_path.write_text(chunk_digest, encoding='ascii')
    except Exception:  # noqa: BLE001 -- a missing digest costs a re-send, never the upload
        pass

    _present = sorted(sdir.glob("chunk_*"))
    _bytes = 0
    for _p in _present:
        # PLAINTEXT bytes (sealed chunks report it from their header; legacy plaintext chunks report
        # their on-disk size), so `bytes_received` stays comparable to the plaintext `total_size`.
        _bytes += sealed_plaintext_size(_p)
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
    the File record. Rejects with the missing indices if any chunk is absent.

    Admitted on the transfer ceiling. This is the assembling half of an upload -- it reads the
    staged chunks and pushes them through the encryption pipeline -- so it holds memory for a
    duration in the same way a download does, and it is the path the product's own client takes.
    The chunk writes before it are not admitted: each streams straight to disk and holds nothing.
    """
    transfer_slot = None

    async def admit():
        """Take the transfer slot. Called by the body once the request has earned one."""
        nonlocal transfer_slot
        try:
            transfer_slot = await transfer_admission.acquire()
        except TransferBusy as busy:
            raise _busy_response(busy)

    try:
        return await _complete_chunked_upload(
            vault_id, session_id, request, current_user, db, x_vault_password, admit)
    finally:
        if transfer_slot is not None:
            transfer_admission.release(transfer_slot)


async def _complete_chunked_upload(vault_id, session_id, request, current_user, db,
                                   x_vault_password, admit):
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    vault = vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)

    session = db.query(ChunkedUploadSession).filter(
        ChunkedUploadSession.id == session_id,
        ChunkedUploadSession.vault_id == vault_id,
        ChunkedUploadSession.user_id == current_user.id,
        _session_principal(current_user),
    ).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session not found")
    # A scoped credential may only finalize a session whose target folder is in scope.
    require_folder_scope(db, current_user, vault_id, session.folder_id)
    # Unreachable: nothing writes `file_id` (see the column), and a session is deleted once it
    # completes. Left in place rather than removed with an unrelated change.
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

    # Everything above is authorization and validation, and costs nothing to answer. From here the
    # request reads the staged chunks and encrypts them, which is what the ceiling governs -- so
    # this is where it is applied, and a caller who is going to be told 403, 404, 409 or 410 is
    # told that instead of being made to queue for a slot they were never going to use.
    await admit()

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
    # The full set a ZK name may match under (all epochs' candidates + the index-key value),
    # stored at init. Used for BOTH the reject pre-check and the replace at finalize, so an
    # existing file sealed before a rotation is found and not silently duplicated. NULL for a
    # Standard upload or an old client that sent none.
    zk_name_bi_candidates = session.name_bi_candidates if is_zk else None

    # Same-name policy = replace; reject up front if the uploader can't replace.
    _reject_unreplaceable_upload(db, vault_id, folder_uuid, session.filename, current_user,
                                 name_bi=zk_name_bi, name_bi_candidates=zk_name_bi_candidates)

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
    # A session that declared an id at the start must finish with that id. Silently substituting
    # a different one is the failure this whole mechanism exists to prevent: the client encrypted
    # against what it declared, so anything else produces material that will not open.
    declared_object_id = session.client_object_id
    if declared_object_id is not None:
        if client_file_id is None:
            raise HTTPException(
                status_code=400,
                detail=("This upload declared an object id when it started and must supply the "
                        "same one to finish. Encrypted material is bound to it."),
            )
        if client_file_id != declared_object_id:
            raise HTTPException(
                status_code=400,
                detail=("The object id supplied does not match the one this upload declared when "
                        "it started."),
            )
    # Not the enforcement boundary -- that is in the service, which every upload path goes
    # through -- but leaving this one liveness-only would turn a clean 409 into a ValueError
    # surfacing after the whole blob had been streamed and assembled.
    if client_file_id is not None and (
            db.query(File.id).filter(File.id == client_file_id).first()
            or db.query(RetiredObjectId.id).filter(
                RetiredObjectId.id == client_file_id).first()):
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
                # Each staged chunk was sealed on arrival; unseal it in order (memory-bounded,
                # one record at a time) and hand the plaintext to the at-rest codec. A chunk
                # staged as plaintext by a pre-upgrade release streams through verbatim.
                for buf in open_staged_chunk(sdir / f"chunk_{i:06d}", session.id, i):
                    if buf:
                        ctx.write_chunk(buf)
            final_checksum = ctx.get_checksum()
            final_size = ctx.get_total_size()

        # A short delivery must not commit. Every other size check in this path is a one-sided
        # upper bound, so a session that declared N bytes and delivered fewer was assembled and
        # stored without complaint.
        #
        # Under whole-file encryption that surfaces loudly on the first read. Under chunk
        # framing it surfaces LAST: every chunk that did arrive authenticates correctly, and
        # only the missing end-of-stream marker reveals the truncation -- which is no help to a
        # reader that has already handed those bytes onward. The server knows at commit time and
        # can simply refuse.
        #
        # Every vault, not only encrypted ones. `final_size` counts the RAW bytes handed to
        # the codec -- `write_chunk` adds `len(chunk)` before encrypting, and the accessor
        # says so -- so a codec that prepends a header and expands each chunk does not move
        # it. An earlier draft scoped this to encrypted vaults on the assumption that it did,
        # which would have left a Standard upload able to declare 11 bytes, send 5, and store
        # the truncation with a 200.
        if final_size != session.total_size:
            raise HTTPException(status_code=409, detail={
                "code": "size_mismatch",
                "message": ("This upload delivered " + str(final_size) + " bytes but declared "
                            + str(session.total_size) + ". Nothing has been stored."),
            })

        # Final size-limit guard now that the true plaintext size is known.
        #
        # The stored total is read FRESH, and that is the whole fix. `vault` was loaded when this
        # request began, before any overlapping upload committed, so its copy is stale by exactly
        # the amount being checked against: three consecutive completions were observed all seeing
        # the same total and each concluding there was room. Five accounts sharing one vault,
        # released together, put 120 MB into a 64 MB vault that way, with all five returning
        # success.
        #
        # Two heavier answers were built and discarded, each disproved by the tests that cover
        # this. A row lock around the check is held while the file is encrypted, so concurrent
        # uploads then exceed the client's timeout. An atomic Redis reservation is no better than
        # the total it is handed -- with a stale read it still admits everyone, and with a fresh
        # read it changes nothing. Measured both ways before being removed.
        stored_now = db.query(Vault.total_size_bytes).filter(Vault.id == vault_id).scalar() or 0
        if vault.size_limit and stored_now + final_size > vault.size_limit:
            raise HTTPException(status_code=413, detail="File would exceed the vault size limit")
        _enforce_deployment_storage_quota(db, final_size)   # deployment-wide stored-bytes limit

        # Zero-knowledge upload-vs-rekey race guard. Lock the vault row and confirm the
        # client encrypted under the CURRENT DEK epoch; if the vault was re-keyed during
        # the upload, reject (409) rather than commit a stale-epoch file that the
        # just-revoked member (who kept the old DEK) could still read. The lock is held
        # through finalize's commit so a concurrent rekey can't slip in between.
        zk_kv = None
        if getattr(vault, 'type', 'standard') == 'zero_knowledge':
            # populate_existing() is what makes the lock mean anything: this session already
            # holds the vault from the checks above, and without it the epoch compared below
            # would be the one read before the lock -- so the rotation this guard exists to
            # catch would sail straight past it.
            locked_vault = (db.query(Vault).populate_existing()
                            .filter(Vault.id == vault_id).with_for_update().first())
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
            zk_name_bi_candidates=zk_name_bi_candidates,
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
        # Genuine finalize failure: fail the session and clear its plaintext name/MIME + staged
        # chunks now, rather than leaving the plaintext name + chunks on disk until the TTL sweep.
        fail_chunk_session(db, session, sdir, e)
        raise HTTPException(status_code=500, detail=f"Failed to finalize upload: {str(e)}")
    except PermissionDeniedError as e:
        # A permission denial is a 403, not a 500 — and it isn't a corrupt upload, so leave
        # the session/blob for the TTL cleanup rather than force-failing it here.
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        _remove_orphan_blob()
        # Genuine finalize failure: fail the session and clear its plaintext name/MIME + staged
        # chunks now, rather than leaving the plaintext name + chunks on disk until the TTL sweep.
        fail_chunk_session(db, session, sdir, e)
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
                **_vault_activity_fields(vault, current_user),
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
        _session_visible(current_user),
        ChunkedUploadSession.status == 'active',
        ChunkedUploadSession.expires_at > now,
    ).order_by(ChunkedUploadSession.created_at.desc()).all()

    # A scoped credential enumerates only its in-scope upload sessions: require_folder_scope
    # is a no-op for a whole-vault credential and raises for one whose scope excludes the
    # session's target folder (so out-of-scope filenames/folders are never listed).
    out = []
    for s in sessions:
        try:
            with scope_denials_as_filter():  # per-session listing filter, not a denial to record
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
        _session_visible(current_user),
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
    # The client checks its own copy of each received index against these before skipping it.
    payload['chunk_checksums'] = _chunk_hashes(
        _upload_session_dir(vault_service, str(session.id)))
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
        _session_visible(current_user),
    ).first()
    if session is None:
        raise HTTPException(status_code=404, detail="Upload session not found")
    # A scoped credential may only cancel a session whose target folder is in scope.
    require_folder_scope(db, current_user, vault_id, session.folder_id)

    shutil.rmtree(_upload_session_dir(vault_service, str(session.id)), ignore_errors=True)
    if session.status == 'active':
        # 'cancelled', matching what revoking a credential records. Two words for one outcome
        # meant a query for cancelled uploads found half of them.
        session.status = 'cancelled'
        session.error_message = (
            'Cancelled by the account owner' if session.temp_credential_id
            and getattr(current_user, '_temp_cred_id', None) is None else 'Cancelled by user')
        db.commit()
        # The one destructive cross-principal action here. On a zero-knowledge vault it
        # destroys the only copy of the buffered bytes, so it does not go unrecorded in a
        # change whose subject is attribution.
        try:
            AuditLogger(db).log_action(
                action='upload_session_cancelled', status='success', user=current_user,
                resource_type='vault', resource_id=str(vault_id),
                details={'session_id': str(session.id),
                         'opened_by_temp_credential_id': (
                             str(session.temp_credential_id)
                             if session.temp_credential_id else None)},
            )
        except Exception:  # noqa: BLE001 -- never fail the cancellation over its own record
            pass
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
    file_password: Optional[str] = Header(None, alias="X-File-Password"),
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None)
):
    """Download a file while exposing a cancellable, principal-bound operation."""
    from app.services.activity_monitor import ProgressTracker

    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    operation_id = None
    tracker = None
    tracker_started = False
    streaming_response = None
    download = None
    transfer_slot = None
    # The exact share-claim ids the burn below consumed, so a later server-side failure can return
    # those and no others. Empty for a non-share or unlimited-share download (nothing was burned).
    burned_share_claim_ids = []

    try:
        # Verify vault access and password. allow_share=True: a recipient with an active
        # whole-vault share claim may open + download from the vault (read-only). SFTP
        # downloads never pass this flag.
        vault = vault_service.get_vault(
            vault_id,
            current_user,
            x_vault_password,
            require_password=True,
            allow_share=True,
        )
        require_file_scope(db, current_user, vault_id, file_id)
        require_download_scope(db, current_user, vault_id, file_id)

        # The file must belong to the vault used for the access/password gate. Resolved before the
        # transfer slot is taken: naming a file that is not there costs nothing to answer, and a
        # caller who is going to be told 404 should not first be made to queue behind real
        # transfers -- nor should the attempt show up as load the deployment shed.
        file_record = db.query(File).filter(
            File.id == file_id, File.vault_id == vault_id
        ).first()
        if not file_record:
            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail="File not found",
            )

        operation_id = f"download_{uuid.uuid4()}"
        try:
            transfer_slot = await transfer_admission.acquire()
        except TransferBusy as busy:
            raise _busy_response(busy)
        start_operation(operation_id)

        # Atomically consume a capped share download before serving bytes. This one stays AFTER
        # admission on purpose: it spends one of the recipient's downloads, and a transfer that was
        # refused for want of a slot must not be charged for.
        share_authorized = str(vault_id) in (
            getattr(current_user, '_share_vault_scope', None) or {})
        if share_authorized:
            allowed, burned_share_claim_ids = permission_service.burn_share_download(
                current_user,
                vault,
                file_record,
                folder_ancestry(db, vault_id, file_record.folder_id),
            )
            if not allowed:
                raise HTTPException(
                    status_code=status.HTTP_403_FORBIDDEN,
                    detail="This share has reached its download limit.",
                )

        # Opened, not read. The walk inside this authenticates the terminal and settles
        # truncation, a missing terminal, trailing bytes, a dropped record and a substituted blob
        # -- so those now fail HERE, with no response body yet, instead of part-way through one.
        download = vault_service.open_download_stream(
            file_id=file_id,
            user=current_user,
            file_password=file_password,
            allow_share=True,
        )
        file_name, mime_type = download.name, download.mime_type

        if download.total_length == 0:
            # The hold-back signals a failed checksum by leaving the client short of a promised
            # length. A zero-length response cannot be made shorter, so a mismatch raised inside
            # the body arrives after the headers and the client sees a complete success. Settle it
            # here, where it can still be an error status.
            try:
                download.verify_now()
            except ChecksumMismatch:
                download.close()
                raise FileServiceError("File integrity check failed")

        # Never expose a zero-knowledge file name on a server-side surface.
        is_zk = _is_zk_vault(vault)
        disp_name = '(encrypted file)' if is_zk else (file_name or 'download')
        audit_name = None if is_zk else file_name

        # Started BEFORE the response headers, which already carry the operation id. Starting it at
        # the first byte instead would open a window where a cancel issued against the published id
        # finds no tracker entry and fails silently.
        tracker = ProgressTracker()
        tracker_started = tracker.start_operation(
            operation_id=operation_id,
            user_id=str(current_user.id),
            username=str(current_user.username),
            operation_type="download",
            file_name=disp_name,
            total_size=download.total_length,
            temp_credential_id=getattr(current_user, "_temp_cred_id", None),
            vault_id=str(vault_id),
        ) is not None

        # Access was granted: that is the fact this row records, and it is true now. Whether the
        # transfer then completed is a different fact, recorded at the end of the response by
        # `file_streamer`. Writing 'success' here was how a failed or cancelled download came to be
        # logged as a successful one.
        audit_logger.log_action(
            action='file_download',
            status='authorized',
            user=current_user,
            resource_type='file',
            resource_id=str(file_id),
            details={'vault_id': str(vault_id), 'file_name': audit_name},
            ip_address=get_client_ip(request),
        )

        if str(vault_id) in (getattr(current_user, '_share_vault_scope', None) or {}):
            try:
                audit_logger.log_action(
                    action='share_downloaded',
                    status='success',
                    user=current_user,
                    resource_type='file',
                    resource_id=str(file_id),
                    details={'vault_id': str(vault_id)},
                    ip_address=get_client_ip(request),
                )
            except Exception:
                db.rollback()

        request_ip = get_client_ip(request)
        broadcast_event({
            "event": {
                "type": "download",
                "title": "Download in progress",
                "description": f"{disp_name} ({file_record.size_bytes:,} bytes)",
                "user": current_user.username,
                "ip": request_ip,
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "operation_id": operation_id,
                "completed": False,
                **_vault_activity_fields(vault, current_user),
            }
        })

        import asyncio
        from fastapi.responses import StreamingResponse

        async def file_streamer():
            """Stream the file, holding the last piece back until the checksum has been checked.

            The response length below comes from the authenticated terminal, so it is the writer's
            sealed statement of the size rather than the server's opinion of it. That is what makes
            a late failure visible: stopping early delivers fewer bytes than promised, and a
            conforming client reports a truncated response. Completing the body and then deciding
            the file was wrong would give the client a clean success instead.
            """
            served = 0
            total_size = download.total_length
            cancellation_observed = False
            disconnected = False
            terminal_success = False
            failure = None
            try:
                try:
                    for piece in download.chunks():
                        if tracker_started and tracker.is_cancelled(operation_id):
                            cancellation_observed = True
                            break
                        # Asked before each piece, because `served` counts bytes handed to the
                        # server, not bytes that reached anyone: writes after a disconnect are
                        # discarded silently, so a generator that only counts what it yielded runs
                        # to the end and reports a client that left as having received everything.
                        # Whether that happens at all depends on the file size against the socket
                        # buffer, which is not a distinction an audit log should be making.
                        if await request.is_disconnected():
                            disconnected = True
                            break
                        yield piece
                        served += len(piece)
                        await asyncio.sleep(0)
                    terminal_success = (not cancellation_observed and not disconnected
                                        and served == total_size)
                except ChecksumMismatch as exc:
                    # Raised by the hold-back with the final piece still owed, so the client is
                    # left short of the promised length rather than given a complete response for
                    # a file that did not match what was stored for it.
                    failure = exc
                except ObjectChangedDuringRead as exc:
                    # A delete or a same-name replacement racing this read. Not an integrity
                    # failure, and recorded as itself so an operator is not sent looking for an
                    # attacker who is not there.
                    failure = exc
                except EncryptionError as exc:
                    failure = exc
            finally:
                download.close()
                # Held for the whole response, not just the endpoint: the slot is what the transfer
                # occupies, and the transfer is still happening while this generator runs.
                transfer_admission.release(transfer_slot)

                # The completion record, written here rather than before the first byte. What the
                # audit row above states is that access was granted; what this one states is what
                # the transfer actually did.
                try:
                    audit_logger.log_action(
                        action='file_download_completed',
                        status='success' if terminal_success else 'failed',
                        user=current_user,
                        resource_type='file',
                        resource_id=str(file_id),
                        details={
                            'vault_id': str(vault_id),
                            'file_name': audit_name,
                            'bytes_sent': served,
                            'total_bytes': total_size,
                            'outcome': (
                                'completed' if terminal_success
                                else 'cancelled' if cancellation_observed
                                else 'disconnected' if disconnected
                                else type(failure).__name__ if failure is not None
                                else 'incomplete'
                            ),
                        },
                        ip_address=request_ip,
                    )
                except Exception:      # noqa: BLE001 - a lost audit row must not mask the transfer
                    try:
                        db.rollback()
                    except Exception:  # noqa: BLE001
                        pass

                # A share grant is burned at authorization, because it is a cap on grants
                # exercised and must be atomic before serving, and it stays burned when the client
                # abandons or cancels -- refunding those would make a capped share uncapped for
                # anyone willing to disconnect. A SERVER-side integrity failure discovered here (the
                # checksum hold-back, or a per-record decrypt failure) is different: the client is
                # left short of the promised length and received no usable file, and cannot induce
                # the failure, so the burned downloads are returned -- exactly the claims the burn
                # consumed, once. Not ObjectChangedDuringRead: a same-name replacement is a race, not
                # a corrupt blob, and a colluding writer could otherwise trigger refunds at will.
                if burned_share_claim_ids and is_refundable_serve_failure(failure):
                    try:
                        permission_service.refund_share_download(burned_share_claim_ids)
                    except Exception:      # noqa: BLE001 - a failed refund must not mask the transfer
                        try:
                            db.rollback()
                        except Exception:  # noqa: BLE001
                            pass

                transition = None
                if tracker_started and not cancellation_observed:
                    transition = tracker.complete_operation(
                        operation_id,
                        success=terminal_success,
                    )

                if transition is not None:
                    broadcast_event({
                        "event": {
                            "type": "download",
                            "title": (
                                "File downloaded" if terminal_success else "Download interrupted"
                            ),
                            "description": (
                                f"{disp_name} ({served:,} of {total_size:,} bytes transferred)"
                            ),
                            "user": current_user.username,
                            "ip": request_ip,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "operation_id": operation_id,
                            "completed": terminal_success,
                            **_vault_activity_fields(vault, current_user),
                        },
                        "traffic": {
                            "upload": 0,
                            "download": served,
                        },
                    })
                elif tracker_started and tracker.is_cancelled(operation_id):
                    # The cancellation endpoint emitted the terminal cancellation event.
                    # This worker event confirms that the transfer loop observed it.
                    broadcast_event({
                        "event": {
                            "type": "download",
                            "title": "Download cancelled",
                            "description": f"{disp_name} stopped after {served:,} bytes",
                            "user": current_user.username,
                            "ip": request_ip,
                            "timestamp": datetime.now(timezone.utc).isoformat(),
                            "operation_id": operation_id,
                            "completed": True,
                            "cancelled": True,
                            "worker_stopped": True,
                            **_vault_activity_fields(vault, current_user),
                        }
                    })
                end_operation(operation_id)

        # The teardown below asks whether this exists rather than reading a flag someone has to
        # remember to set in the right place. Building a response can fail -- it encodes the
        # headers -- and a flag set a line too early skipped the teardown entirely, holding the
        # transfer slot, the open blob and the operation entry for the life of the process.
        # --- ranged response ------------------------------------------------------------------
        #
        # Offered only where a range is genuinely cheap: `read_range` is None for the
        # client-encrypted blob and for the legacy format, so those fall through to the whole-file
        # path without a special case here.
        #
        # It is also withheld from a share-authorized download, and that is not conservatism for
        # its own sake. A capped share spends one download per request, burned above. Honouring a
        # range would either charge a resumed transfer a second time -- so a flaky link could
        # exhaust a three-download share on one file -- or skip the burn for ranged requests,
        # which makes the cap bypassable by sending a header. Neither is acceptable, and refusing
        # to resume is the only option that leaves the cap meaning what it says.
        rangeable = download.read_range is not None and not share_authorized

        # A KEYED tag over the content, as the entity tag -- NOT the plaintext checksum, which would
        # let anyone who can request the file confirm whether it holds specific known content (hash
        # a candidate, compare the ETag). content_mac is HMAC of the checksum under a per-file key,
        # so it is still stable and unique per version but cannot be reproduced without the key.
        #
        # Resuming across two requests is only safe if the second one is reading the same bytes as
        # the first, and nothing else here establishes that: a same-name replacement between the two
        # would let a client splice two different files together and notice nothing, because each
        # half authenticates perfectly well on its own. A replacement changes the file id and/or the
        # checksum, so the tag changes and the If-Range below mismatches. Per-record AEAD proves a
        # record belongs to this file; it cannot prove both requests saw the same version of it.
        etag = f'"{download.content_mac}"' if download.content_mac else None

        if_range = request.headers.get('if-range')
        stale_resume = False
        if if_range is not None:
            # Only the entity-tag form is honoured. The date form is accepted syntax we cannot
            # answer accurately -- last-modified is not tracked to the second here -- and guessing
            # would defeat the check, so it counts as a mismatch and costs the client a restart
            # rather than risking a splice.
            stale_resume = etag is None or if_range.strip() != etag

        wanted = (parse_byte_range(request.headers.get('range'), download.total_length)
                  if rangeable and not stale_resume else None)

        if wanted is UNSATISFIABLE:
            # Nothing released or closed here on purpose. No response object exists yet, so the
            # teardown below owns the slot, the open blob and the operation entry -- which is the
            # same contract every other pre-handoff failure on this path follows.
            raise HTTPException(
                status_code=status.HTTP_416_REQUESTED_RANGE_NOT_SATISFIABLE,
                detail="Requested range not satisfiable",
                headers={'Content-Range': f'bytes */{download.total_length}'},
            )

        # A range that covers the whole representation is not a range in any useful sense, and
        # taking the ranged path for it costs the stored-checksum check that the whole-file path
        # runs. `bytes=0-` is the ordinary way to write it, so this is one header away from being
        # the normal case rather than an exotic one.
        #
        # It matters most where the checksum is not redundant with per-record AEAD: the retained
        # v1 chunk stream has no terminal, so a truncated blob reports its truncated total and
        # every layer agrees with itself; and a zero-knowledge blob is copied verbatim, where the
        # stored digest over the ciphertext is the only integrity statement the server can make
        # at all.
        if wanted is not None and wanted.start == 0 and wanted.last == download.total_length - 1:
            wanted = None

        if wanted is not None:
            async def range_streamer(span):
                """Serve one span, a window at a time.

                No checksum hold-back: it works by leaving the client short of a promised length,
                and it covers the whole file, which a range by definition is not. Integrity here
                is the per-record AEAD that `read_range` verifies as it decrypts the records the
                span touches -- the same guarantee SFTP has always relied on for seeks.
                """
                served_bytes = 0
                cancelled = False
                try:
                    at = span.start
                    while at <= span.last:
                        # Cancellation is checked here for the same reason the whole-file path
                        # checks it: an operator can stop a transfer, and a ranged one is still a
                        # transfer. Without this, Cancel would appear to do nothing.
                        if tracker_started and tracker.is_cancelled(operation_id):
                            cancelled = True
                            break
                        if await request.is_disconnected():
                            break
                        piece = download.read_range(at, min(_RANGE_WINDOW, span.last - at + 1))
                        if not piece:
                            # The reader clamps rather than raising, so an empty answer inside the
                            # span means the file is shorter than the length the walk reported.
                            # Stopping leaves the client short of Content-Length, which is how
                            # every other failure on this path announces itself.
                            break
                        yield piece
                        served_bytes += len(piece)
                        at += len(piece)
                        await asyncio.sleep(0)
                finally:
                    download.close()
                    transfer_admission.release(transfer_slot)

                    # The operation was started before this branch was chosen, and only the
                    # whole-file generator's teardown completes one. Without this a ranged
                    # download leaves an in_progress record in Redis that nothing ever closes,
                    # and the transfer shows as running for as long as the key survives.
                    transition = None
                    if tracker_started and not cancelled:
                        try:
                            transition = tracker.complete_operation(
                                operation_id,
                                success=(served_bytes == span.length),
                            )
                        except Exception:      # noqa: BLE001 - a bookkeeping write, not the body
                            transition = None

                    # Emitted for the same reason the whole-file path emits one: this is where
                    # bytes served are counted. Leaving it out would make ranged transfers
                    # invisible in the activity feed and absent from traffic accounting, so a
                    # resuming client would move real bytes that nothing added up.
                    if transition is not None:
                        try:
                            broadcast_event({
                                "event": {
                                    "type": "download",
                                    "title": ("File downloaded (range)"
                                              if served_bytes == span.length
                                              else "Ranged download interrupted"),
                                    "description": (
                                        f"{disp_name} (bytes {span.start}-{span.last} of "
                                        f"{span.total}, {served_bytes:,} transferred)"
                                    ),
                                    "user": current_user.username,
                                    "ip": request_ip,
                                    "timestamp": datetime.now(timezone.utc).isoformat(),
                                    "operation_id": operation_id,
                                    "completed": served_bytes == span.length,
                                    **_vault_activity_fields(vault, current_user),
                                },
                                "traffic": {"upload": 0, "download": served_bytes},
                            })
                        except Exception:      # noqa: BLE001 - telemetry must not kill a response
                            pass

                    try:
                        audit_logger.log_action(
                            user_id=current_user.id,
                            action="file.download.range",
                            resource_type="file",
                            resource_id=str(file_id),
                            details=(f"{disp_name}: bytes {span.start}-{span.last} of "
                                     f"{span.total}, {served_bytes} served"),
                            ip_address=request_ip,
                        )
                    except Exception:      # noqa: BLE001 - an audit write must not kill a response
                        pass
                    end_operation(operation_id)

            # Assigned to the name the teardown checks. It keys on whether a response exists,
            # not on the slot -- so a response held in any other variable would be torn down
            # while the generator serving it was still running.
            range_headers = {
                'Content-Disposition': _content_disposition(disp_name),
                'Content-Length': str(wanted.length),
                'Content-Range': wanted.content_range(),
                'Accept-Ranges': 'bytes',
                'Cache-Control': 'no-cache',
                'X-Operation-ID': operation_id,
            }
            if etag:
                # Conditional, because a row stored without a checksum has no tag to send and a
                # None here would fail header encoding -- turning a served range into a 500. Such
                # a client simply cannot detect a replacement mid-resume, which is a weaker
                # position than an ETag buys but not a worse one than it had before ranges.
                range_headers['ETag'] = etag

            streaming_response = StreamingResponse(
                range_streamer(wanted),
                status_code=status.HTTP_206_PARTIAL_CONTENT,
                media_type=_safe_media_type(mime_type),
                headers=range_headers,
            )
            # `transfer_slot` deliberately NOT cleared. The generator's teardown reads the
            # variable, not a captured value, so nulling it here would leave the real token
            # unreleased and shrink the transfer ceiling by one on every ranged download.
            return streaming_response

        headers = {
            'Content-Disposition': _content_disposition(disp_name),
            # From the terminal the walk authenticated, so a stream that stops
            # early is a short body the client can detect.
            'Content-Length': str(download.total_length),
            'Cache-Control': 'no-cache',
            'X-Operation-ID': operation_id,
        }
        if rangeable:
            # Advertised only where it is true. Claiming it for a file that would answer a range
            # by decrypting all of itself invites exactly the request that costs the most.
            headers['Accept-Ranges'] = 'bytes'
            if etag:
                # Sent with the whole-file response too, because that is where a client learns
                # the tag it will quote back in If-Range when it comes to resume.
                headers['ETag'] = etag

        streaming_response = StreamingResponse(
            file_streamer(),
            media_type=_safe_media_type(mime_type),
            headers=headers,
        )
        return streaming_response

    except (PasswordRequiredError, InvalidPasswordError) as e:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail=str(e),
        )
    except FileNotFoundError as e:
        if burned_share_claim_ids:
            try:
                permission_service.refund_share_download(burned_share_claim_ids)
                burned_share_claim_ids = []
            except Exception:      # noqa: BLE001 - a failed refund must not mask the 404
                try:
                    db.rollback()
                except Exception:  # noqa: BLE001
                    pass
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=str(e),
        )
    except HTTPException:
        raise
    except PermissionDeniedError as e:
        raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=str(e))
    except Exception as e:
        # Anything reaching this handler failed BEFORE the response was handed off, so zero bytes
        # were served -- whether the cause was a stored-byte integrity failure (a rejected walk, a
        # failed record tag, the zero-length checksum), a blob that vanished in a TOCTOU race, or an
        # infrastructure hiccup starting the tracker or writing the authorized-access audit row. A
        # capped recipient who received nothing must not be charged, so the burn is returned
        # unconditionally here. Client and auth failures never reach this point -- the specific
        # clauses above answer them (and deliberately keep those burned, so a wrong file password
        # can't be retried for free). No-op off the share path (empty list). The stricter,
        # integrity-only classification lives at the mid-stream guard, where a prefix may already
        # have been served and a delete/replacement race must NOT refund.
        if burned_share_claim_ids:
            try:
                permission_service.refund_share_download(burned_share_claim_ids)
                burned_share_claim_ids = []
            except Exception:      # noqa: BLE001 - a failed refund must not mask the download error
                try:
                    db.rollback()
                except Exception:  # noqa: BLE001
                    pass
        try:
            broadcast_event({
                "event": {
                    "type": "error",
                    "title": "Download failed",
                    "description": f"Download error: {str(e)[:100]}",
                    "user": current_user.username if current_user else "unknown",
                    "ip": get_client_ip(request),
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            })
        except Exception:
            pass
        import traceback
        print(f"[ERROR] Download failed - Exception type: {type(e).__name__}")
        print(f"[ERROR] Download failed - Exception message: {str(e)}")
        traceback.print_exc()
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to download file: {str(e)}",
        )
    finally:
        # Before response handoff, this function owns cleanup. Afterwards the
        # streaming generator owns the terminal transition, the open blob, and the local active
        # set. The blob is now opened before the handoff, so anything that fails in between --
        # every early failure the walk exists to produce -- would otherwise leak its descriptor
        # for the life of the process.
        # No response object means the request never got as far as handing anything over, so
        # this owns the cleanup. Once it exists, the streaming generator's own teardown does --
        # the one exception being a connection that dies before the framework starts iterating,
        # which is not reachable through the middleware stack in front of this.
        if streaming_response is None:
            transfer_admission.release(transfer_slot)
            if download is not None:
                download.close()
            if operation_id:
                if tracker_started:
                    tracker.complete_operation(operation_id, success=False)
                end_operation(operation_id)

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
            locked_vault = (db.query(Vault).populate_existing()
                            .filter(Vault.id == vault_id).with_for_update().first())
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
            zk_name_bi_candidates=rename_data.name_bi_candidates,
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


class ItemMoveCopy(BaseModel):
    """Destination for a file move/copy. dest_folder_id None means the destination vault root."""
    dest_vault_id: uuid.UUID
    dest_folder_id: Optional[uuid.UUID] = None
    replace_same_name: bool = False


class FolderMoveCopy(BaseModel):
    """Destination for a folder move/copy. dest_parent_folder_id None means the vault root."""
    dest_vault_id: uuid.UUID
    dest_parent_folder_id: Optional[uuid.UUID] = None


def _gate_move_copy_destination(db, vault_service, current_user, dest_vault_id, dest_folder_id,
                                dest_password, caps):
    """Shared destination gate for move/copy: prove access + password to the destination vault, the
    scoped-temp caps hold on the destination, and (for a scoped temp) the destination folder — INCLUDING
    the vault root — is in scope. Returns the destination vault."""
    from app.core.temp_scope import require_cap
    dest_vault = vault_service.get_vault(dest_vault_id, current_user, dest_password,
                                         require_password=True)
    for cap in caps:
        require_cap(current_user, dest_vault_id, cap)
    # Unconditional (NOT `if dest_folder_id is not None`): require_folder_scope denies the vault ROOT
    # (folder_id None) for an id-scoped principal — a scoped temp must not deposit an item at the root,
    # outside its granted subtree — and is a no-op for a non-scoped / whole-vault principal.
    require_folder_scope(db, current_user, dest_vault_id, dest_folder_id)
    return dest_vault


@app.post("/vaults/{vault_id}/files/{file_id}/copy")
@require_endpoint_permission("FILE_DOWNLOAD")
@require_vault_cap("file.download")
async def copy_file_endpoint(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    body: ItemMoveCopy,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
    x_dest_vault_password: Optional[str] = Header(None),
    x_file_password: Optional[str] = Header(None),
):
    """Copy a file to another folder/vault, leaving the original. Standard vaults only (the server
    cannot re-encrypt a zero-knowledge blob). Requires read on the source and write on the
    destination; each vault's password is gated when it is password-protected."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    try:
        # Source: access + password on the path vault, the file belongs to it, item in scope.
        vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        if not db.query(File.id).filter(File.id == file_id, File.vault_id == vault_id).first():
            raise HTTPException(status_code=404, detail="File not found in this vault")
        require_item_scope(db, current_user, vault_id, file_id)
        # Destination: access + password + the write cap + folder scope.
        _gate_move_copy_destination(db, vault_service, current_user, body.dest_vault_id,
                                    body.dest_folder_id, x_dest_vault_password, ["file.upload"])
        # Overwriting a same-name file in the destination DELETES it, so it needs delete authority on
        # the DESTINATION vault — the client flag alone must not let an upload-only principal destroy
        # another user's file (same rule as every other replace path, _principal_can_replace_file).
        replace = body.replace_same_name and _principal_can_replace_file(db, current_user, body.dest_vault_id)
        new_file = vault_service.copy_file(
            file_id, current_user, body.dest_vault_id, body.dest_folder_id,
            source_file_password=x_file_password, replace_same_name=replace)
        audit_logger.log_action(
            action='file_copy', status='success', user=current_user, resource_type='file',
            resource_id=str(file_id),
            details={'source_vault_id': str(vault_id), 'dest_vault_id': str(body.dest_vault_id),
                     'dest_folder_id': str(body.dest_folder_id) if body.dest_folder_id else None,
                     'new_file_id': str(new_file.id)},
            ip_address=get_client_ip(request))
        return {'message': 'File copied', 'id': str(new_file.id)}
    except DuplicateNameError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except HTTPException:
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="A file with that name already exists in the destination")


@app.post("/vaults/{vault_id}/files/{file_id}/move")
@require_endpoint_permission("FILE_DELETE")
@require_vault_cap("file.delete")
async def move_file_endpoint(
    vault_id: uuid.UUID,
    file_id: uuid.UUID,
    body: ItemMoveCopy,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
    x_dest_vault_password: Optional[str] = Header(None),
    x_file_password: Optional[str] = Header(None),
):
    """Move a file. Within one vault this is a reparent (no re-encryption); across vaults it
    re-encrypts into the destination (Standard↔Standard) and deletes the source. Requires the delete
    capability on the source and the upload capability on the destination."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    try:
        vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        if not db.query(File.id).filter(File.id == file_id, File.vault_id == vault_id).first():
            raise HTTPException(status_code=404, detail="File not found in this vault")
        require_item_scope(db, current_user, vault_id, file_id)
        _gate_move_copy_destination(db, vault_service, current_user, body.dest_vault_id,
                                    body.dest_folder_id, x_dest_vault_password, ["file.upload"])
        # Same rule as copy: overwriting a same-name file in the destination needs delete authority
        # there, not just the client flag.
        replace = body.replace_same_name and _principal_can_replace_file(db, current_user, body.dest_vault_id)
        new_file = vault_service.move_file(
            file_id, current_user, body.dest_vault_id, body.dest_folder_id,
            source_file_password=x_file_password, replace_same_name=replace)
        audit_logger.log_action(
            action='file_move', status='success', user=current_user, resource_type='file',
            resource_id=str(file_id),
            details={'source_vault_id': str(vault_id), 'dest_vault_id': str(body.dest_vault_id),
                     'dest_folder_id': str(body.dest_folder_id) if body.dest_folder_id else None,
                     'new_file_id': str(new_file.id)},
            ip_address=get_client_ip(request))
        return {'message': 'File moved', 'id': str(new_file.id)}
    except DuplicateNameError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except HTTPException:
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="A file with that name already exists in the destination")


@app.post("/vaults/{vault_id}/folders/{folder_id}/move")
@require_endpoint_permission("FOLDER_MANAGE")
@require_vault_cap("folder.create")
async def move_folder_endpoint(
    vault_id: uuid.UUID,
    folder_id: uuid.UUID,
    body: FolderMoveCopy,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Move a folder within its vault (a reparent). Cross-vault folder moves are not supported yet."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    try:
        vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        if not db.query(Folder.id).filter(Folder.id == folder_id, Folder.vault_id == vault_id).first():
            raise HTTPException(status_code=404, detail="Folder not found in this vault")
        require_item_scope(db, current_user, vault_id, folder_id)
        # Unconditional: denies the vault ROOT for an id-scoped temp (a no-op otherwise).
        require_folder_scope(db, current_user, vault_id, body.dest_parent_folder_id)
        folder = vault_service.move_folder(
            folder_id, current_user, body.dest_vault_id, body.dest_parent_folder_id)
        audit_logger.log_action(
            action='folder_move', status='success', user=current_user, resource_type='folder',
            resource_id=str(folder_id),
            details={'vault_id': str(vault_id),
                     'dest_parent_folder_id': str(body.dest_parent_folder_id) if body.dest_parent_folder_id else None},
            ip_address=get_client_ip(request))
        return {'message': 'Folder moved', 'id': str(folder.id)}
    except DuplicateNameError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except HTTPException:
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="A folder with that name already exists in the destination")


@app.post("/vaults/{vault_id}/folders/{folder_id}/copy")
@require_endpoint_permission("FOLDER_MANAGE")
@require_vault_cap("folder.create")
async def copy_folder_endpoint(
    vault_id: uuid.UUID,
    folder_id: uuid.UUID,
    body: FolderMoveCopy,
    request: Request,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db),
    x_vault_password: Optional[str] = Header(None),
):
    """Recursively copy a folder (its files + subfolders) within its vault. Standard vaults only;
    cross-vault folder copies are not supported yet."""
    permission_service = PermissionService(db)
    vault_service = VaultService(db, permission_service)
    audit_logger = AuditLogger(db)
    try:
        from app.core.temp_scope import require_cap
        vault_service.get_vault(vault_id, current_user, x_vault_password, require_password=True)
        if not db.query(Folder.id).filter(Folder.id == folder_id, Folder.vault_id == vault_id).first():
            raise HTTPException(status_code=404, detail="Folder not found in this vault")
        require_item_scope(db, current_user, vault_id, folder_id)
        # Unconditional: denies the vault ROOT for an id-scoped temp (a no-op otherwise).
        require_folder_scope(db, current_user, vault_id, body.dest_parent_folder_id)
        # A recursive copy reads every descendant file and writes a duplicate, so a scoped temp needs
        # the read + write caps too (all within the one vault).
        require_cap(current_user, vault_id, "file.download")
        require_cap(current_user, vault_id, "file.upload")
        folder = vault_service.copy_folder(
            folder_id, current_user, body.dest_vault_id, body.dest_parent_folder_id)
        audit_logger.log_action(
            action='folder_copy', status='success', user=current_user, resource_type='folder',
            resource_id=str(folder_id),
            details={'vault_id': str(vault_id), 'new_folder_id': str(folder.id),
                     'dest_parent_folder_id': str(body.dest_parent_folder_id) if body.dest_parent_folder_id else None},
            ip_address=get_client_ip(request))
        return {'message': 'Folder copied', 'id': str(folder.id)}
    except DuplicateNameError as e:
        raise HTTPException(status_code=status.HTTP_409_CONFLICT, detail=str(e))
    except HTTPException:
        raise
    except IntegrityError:
        db.rollback()
        raise HTTPException(status_code=status.HTTP_409_CONFLICT,
                            detail="A folder with that name already exists in the destination")


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

    NOTE: folder passwords are an UNIMPLEMENTED feature. This endpoint intentionally does not
    read or forward a folder `password` (the VaultService.create_folder `password` parameter
    stays None), because no access path enforces a folder password yet. Wiring a setter here
    WITHOUT first implementing nearest-protected-ancestor enforcement on every file/folder
    access path (REST + SFTP) and at share time would ship folders that appear protected but are
    not. See VaultService.get_folder for the full state and requirements.
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
        zk_name_bi_candidates = folder_data.get('name_bi_candidates')
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
            # Bound the sealed name — this endpoint takes a raw dict, so the cap the Pydantic paths
            # (upload/rename) apply must be applied by hand; stops unbounded metadata in a Text
            # column the storage quota does not count. A sealed 255-char name is ~1.4 KB.
            if len(str(zk_enc_name)) > 8192:
                raise HTTPException(status_code=400, detail="enc_name too long")
            _require_zk_sealed_names(zk_enc_name)
            # Zero-knowledge v2 name binding: the client supplies the folder id it sealed the
            # name under (so the sealed name binds the final row id). Optional + backward-compat;
            # reject a bad/colliding id cleanly.
            if folder_data.get('id') is not None:
                try:
                    folder_client_id = uuid.UUID(str(folder_data.get('id')))
                except (TypeError, ValueError):
                    raise HTTPException(status_code=400, detail="id must be a UUID")
                # Live OR spent, matching the vault and file pre-checks. The service refuses
                # a retired id regardless, so this only changes where the refusal happens -- but
                # reaching the service means taking a row lock on the vault first.
                if (db.query(Folder.id).filter(Folder.id == folder_client_id).first()
                        or db.query(RetiredObjectId.id).filter(
                            RetiredObjectId.id == folder_client_id).first()):
                    raise HTTPException(status_code=409, detail="Folder id already in use")
            # folder_data is a raw dict (untyped), so validate the client-supplied fields here
            # — a malformed value must be a clean 400, not a 500 (int()/DB DataError) below.
            if len(str(zk_name_bi)) > 64:
                raise HTTPException(status_code=400, detail="name_bi too long")
            # Bound the same-name candidate set here, the way the Pydantic-validated paths (rename,
            # upload) bound it with max_length=64. This endpoint takes a raw dict, so the cap has to
            # be applied by hand: without it a client could send tens of thousands of candidates,
            # which SQLAlchemy expands to one bind parameter each in the `name_bi.in_(...)` clash
            # query and Postgres rejects past 65535 -- a 500 and a per-request amplification lever
            # instead of the clean 400 the other paths give. Each element is also a blind index, so
            # anything longer than the column can never match; drop it rather than store a giant.
            if zk_name_bi_candidates is not None:
                if not isinstance(zk_name_bi_candidates, list) or len(zk_name_bi_candidates) > 64:
                    raise HTTPException(
                        status_code=400,
                        detail="name_bi_candidates must be a list of at most 64 blind indices")
                if any(not isinstance(c, str) or len(c) > 64 for c in zk_name_bi_candidates):
                    raise HTTPException(
                        status_code=400,
                        detail="each name_bi_candidate must be a string of at most 64 characters")
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
            locked_vault = (db.query(Vault).populate_existing()
                            .filter(Vault.id == vault_id).with_for_update().first())
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
            zk_name_bi_candidates=zk_name_bi_candidates if isinstance(zk_name_bi_candidates, list) else None,
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
    enc_name: str = Field(..., max_length=8192)  # browser-encrypted name (ZK marker + base64)
    name_bi: str = Field(..., max_length=64)  # client blind index (stored in a VARCHAR(64))
    enc_mime: Optional[str] = Field(None, max_length=8192)    # files only
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
    locked_vault = (db.query(Vault).populate_existing()
                    .filter(Vault.id == vault_id).with_for_update().first())
    # Fall back to the already-validated vault object if the row vanished between fetch and lock
    # (concurrent delete) so the epoch read keeps its original non-None semantics.
    current_epoch = getattr(locked_vault or vault, 'dek_version', 1) or 1

    sealed = 0
    for it in body.items:
        # A scoped credential may only seal names of in-scope objects (skip the rest, as with
        # any other non-applicable item). require_item_scope is a no-op for a whole-vault cred.
        try:
            with scope_denials_as_filter():  # per-item batch filter, not a denial to record
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
@require_endpoint_permission("DASHBOARD_VIEW")
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
                ActiveSession.session_token == hash_session_token(session_token)
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
        
        # What the deployment is actually carrying, and what the transfer ceiling has done about
        # it. The docs tell an operator to size MAX_CONCURRENT_TRANSFERS against their memory, and
        # they cannot do that without seeing how close to it they run: a refusal otherwise leaves
        # no trace but a 503 in the access log.
        active_operations = get_active_operations_count()
        transfers = transfer_admission.stats()
        
        # Total files
        total_files = db.query(func.count(File.id)).scalar() or 0
        
        metrics_data = {
            "activeUsers": active_users,
            "tempCreds": total_temp_creds,
            "tempCredsActive": active_temp_creds,
            "uploadTraffic": upload_traffic,
            "downloadTraffic": download_traffic,
            "activeOperations": active_operations,
            "transfersInFlight": transfers["in_flight"],
            "transfersWaiting": transfers["waiting"],
            "transferLimit": transfers["limit"],
            "transfersPeak": transfers["peak_in_flight"],
            "transfersAdmitted": transfers["admitted"],
            "transfersRefused": transfers["refused"],
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
        requester_temp_credential_id=getattr(current_user, "_temp_cred_id", None),
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
    """Return the functionality groups an administrator can actually grant."""
    from app.core.api_catalog import GRANTABLE_API_CATALOG

    groups = []
    for group in GRANTABLE_API_CATALOG.values():
        endpoints = [
            {
                "method": endpoint.method,
                "path": endpoint.path,
                "description": endpoint.description,
                "role_requirement": endpoint.role_requirement.value,
                "requires_ownership": endpoint.requires_ownership,
                "resource_type": endpoint.resource_type,
                "ui_widgets": endpoint.ui_widgets,
            }
            for endpoint in group.endpoints
        ]
        groups.append(EndpointPermissionGroupResponse(
            name=group.name,
            display_name=group.display_name,
            description=group.description,
            ui_section=group.ui_section,
            default_for_roles=[
                role.value if hasattr(role, "value") else str(role)
                for role in group.default_for_roles
            ],
            endpoint_count=len(group.endpoints),
            endpoints=endpoints,
            dependencies=group.dependencies,
        ))
    return groups


@app.get("/permissions/users/{user_id}", response_model=UserPermissionsResponse)
async def get_user_permissions(
    user_id: uuid.UUID,
    current_user: User = Depends(get_current_user),
    db: Session = Depends(get_db)
):
    """Return grantable permissions for the current user or an admin-selected user."""
    from app.core.api_catalog import GRANTABLE_API_CATALOG
    from app.core.endpoint_permissions import get_user_permissions as get_perms

    is_interactive_admin = (
        current_user.role == RoleEnum.ADMIN
        and not getattr(current_user, "_is_temp_session", False)
    )
    if not is_interactive_admin and current_user.id != user_id:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="You can only view your own permissions",
        )

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )

    permissions = get_perms(str(user_id), db)
    granted_groups = sorted({
        permission["endpoint_group"]
        for permission in permissions
    })
    if target_user.role == RoleEnum.ADMIN:
        granted_groups = list(GRANTABLE_API_CATALOG)

    return UserPermissionsResponse(
        user_id=target_user.id,
        username=target_user.username,
        email=target_user.email,
        role=str(target_user.role),
        granted_groups=granted_groups,
        permissions=permissions,
    )


@app.post("/permissions/users/{user_id}/grant")
async def grant_user_permission(
    user_id: uuid.UUID,
    request: GrantPermissionRequest,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Atomically grant a functionality group and its dependencies."""
    from app.core.api_catalog import GRANTABLE_API_CATALOG
    from app.core.endpoint_permissions import grant_endpoint_permission

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    if request.endpoint_group not in GRANTABLE_API_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid endpoint group: {request.endpoint_group}",
        )

    try:
        granted_groups = grant_endpoint_permission(
            user_id=str(user_id),
            endpoint_group=request.endpoint_group,
            db=db,
            granted_by=str(current_user.id),
            commit=False,
        )

        AuditLogger(db).log_action(
            action="GRANT_PERMISSION",
            status="success",
            user=current_user,
            resource_type="permission",
            resource_id=str(user_id),
            details={
                "endpoint_group": request.endpoint_group,
                "granted_groups": granted_groups,
                "target_user": target_user.username,
            },
        )

        group = GRANTABLE_API_CATALOG[request.endpoint_group]
        return {
            "status": "success",
            "message": f"Granted {group.display_name} permissions to {target_user.username}",
            "endpoint_group": request.endpoint_group,
            "endpoint_count": len(group.endpoints),
            "granted_groups": granted_groups,
        }
    except Exception as exc:
        db.rollback()
        error_id = str(uuid.uuid4())
        print(f"[ERROR] permission grant failed (ID: {error_id}): {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Permission update failed (reference: {error_id})",
        )


@app.delete("/permissions/users/{user_id}/revoke/{group_name}")
async def revoke_user_permission(
    user_id: uuid.UUID,
    group_name: str,
    current_user: User = Depends(require_interactive_admin),
    db: Session = Depends(get_db)
):
    """Atomically revoke a group and every group that depends on it."""
    from app.core.api_catalog import GRANTABLE_API_CATALOG
    from app.core.endpoint_permissions import revoke_endpoint_permission

    target_user = db.query(User).filter(User.id == user_id).first()
    if not target_user:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"User {user_id} not found",
        )
    if group_name not in GRANTABLE_API_CATALOG:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Invalid endpoint group: {group_name}",
        )

    try:
        revoked_groups = revoke_endpoint_permission(
            user_id=str(user_id),
            endpoint_group=group_name,
            db=db,
            commit=False,
        )

        AuditLogger(db).log_action(
            action="REVOKE_PERMISSION",
            status="success",
            user=current_user,
            resource_type="permission",
            resource_id=str(user_id),
            details={
                "endpoint_group": group_name,
                "revoked_groups": revoked_groups,
                "target_user": target_user.username,
            },
        )

        group = GRANTABLE_API_CATALOG[group_name]
        return {
            "status": "success",
            "message": f"Revoked {group.display_name} permissions from {target_user.username}",
            "endpoint_group": group_name,
            "endpoint_count": len(group.endpoints),
            "revoked_groups": revoked_groups,
        }
    except Exception as exc:
        db.rollback()
        error_id = str(uuid.uuid4())
        print(f"[ERROR] permission revoke failed (ID: {error_id}): {exc}")
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Permission update failed (reference: {error_id})",
        )


# All imported routers and monolithic routes have now applied their guards.
# Refuse to construct an application whose grant UI and runtime gates diverge.
validate_endpoint_permission_contract()

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

def _seed_admin_user(db=None):
    """Bootstrap the FIRST admin from ADMIN_USERNAME/ADMIN_PASSWORD, exactly ONCE per deployment.

    The logic lives in app.core.admin_bootstrap (side-effect-free, so it is unit-testable against a
    throwaway database). Seed-once is enforced by an ``admin_bootstrap`` marker in ``system_settings``:
    once bootstrapped, or once any admin exists, this refuses to seed again - so a later ADMIN_USERNAME
    change in ``.env`` can no longer mint a new admin. No-op if already bootstrapped / an admin exists
    / no password is configured. ``db`` is an injection seam for tests; production passes None and a
    session is opened here.
    """
    try:
        from app.core.admin_bootstrap import bootstrap_admin

        if db is not None:
            return bootstrap_admin(db)
        from app.core.database import get_db_context
        with get_db_context() as session:
            return bootstrap_admin(session)
    except Exception as e:
        print(f"⚠ Admin bootstrap skipped: {e}")
        return "error"


# Starter share-tag set seeded onto a FRESH deployment so sharing is usable out of the box. The
# create-allowlist is fail-closed (auto_enroll off + empty lists => grants no one), so each seed tag
# sets auto_enroll_new_users=True to grant every internal user create rights; an admin can tighten
# the allowlist per tag afterwards. Names are the owner-chosen set; the policy is a sensible default an
# admin can edit. Lifetime/cap fields fall to the model defaults (7-day ceiling, 1-day default, no
# recipient/download cap). Colors are drawn from the UI's chip palette (unknown names fall back).
_DEFAULT_SHARE_TAGS = [
    {
        "name": "Normal", "color": "sky",
        "description": "Everyday sharing with the standard limits.",
        "allowed_audiences": ["anyone_internal", "users", "departments"],
        "allow_view_only": True, "default_view_only": False, "force_view_only": False,
        "allow_custom": True, "auto_enroll_new_users": True,
    },
    {
        "name": "Internal", "color": "indigo",
        "description": "For anyone inside the organisation who holds the link.",
        "allowed_audiences": ["anyone_internal", "users", "departments"],
        "allow_view_only": True, "default_view_only": False, "force_view_only": False,
        "allow_custom": True, "auto_enroll_new_users": True,
    },
    {
        "name": "Confidential", "color": "amber",
        "description": "Sensitive — share only with named people or departments.",
        "allowed_audiences": ["users", "departments"],
        "allow_view_only": True, "default_view_only": False, "force_view_only": False,
        "allow_custom": True, "auto_enroll_new_users": True,
    },
    {
        "name": "Confidential (Read)", "color": "rose",
        "description": "Sensitive, view-only — recipients can read but not download.",
        "allowed_audiences": ["users", "departments"],
        "allow_view_only": True, "default_view_only": True, "force_view_only": True,
        "allow_custom": True, "auto_enroll_new_users": True,
    },
]


def _seed_default_share_tags():
    """Seed the starter share-tag set on a FRESH deployment so sharing works out of the box.

    Guarded by _should_seed_default_tags: runs only when the share_tags table is empty AND sharing is
    not already enabled — so it never re-adds a removed tag and never silently widens sharing on an
    existing deployment that had already opted in. The seed tags reference the bootstrap admin as
    creator when one exists (else NULL). Best-effort: a failure logs and is swallowed so it can never
    brick startup.
    """
    try:
        from app.core.database import get_db_context
        from app.core.models import ShareTag, User, RoleEnum
        with get_db_context() as db:
            has_tags = db.query(ShareTag).first() is not None
            if not sharing_policy.should_seed_default_tags(has_tags, _sharing_enabled(db)):
                return
            admin = db.query(User).filter(User.role == RoleEnum.ADMIN).first()
            created_by = admin.id if admin else None
            for spec in _DEFAULT_SHARE_TAGS:
                db.add(ShareTag(created_by=created_by, **spec))
            print(f"[OK] Seeded {len(_DEFAULT_SHARE_TAGS)} default share tags")
    except Exception as e:
        print(f"⚠ Default share-tag seeding skipped: {e}")


def _seed_default_note_link_tags():
    """Seed the starter public-note-link tags (Open / Restricted / Confidential) on a fresh deployment
    only — no tags AND public links not already enabled — mirroring the share-tag seed. Inert until an
    admin turns public note links on. Best-effort; never bricks startup."""
    try:
        from app.core.database import get_db_context
        from app.core.models import NoteLinkTag, User, RoleEnum
        with get_db_context() as db:
            has_tags = db.query(NoteLinkTag).first() is not None
            enabled = note_link_policy.public_note_links_enabled(_global_settings_blob(db))
            if not note_link_policy.should_seed_default_note_link_tags(has_tags, enabled):
                return
            admin = db.query(User).filter(User.role == RoleEnum.ADMIN).first()
            created_by = admin.id if admin else None
            for spec in note_link_policy.DEFAULT_NOTE_LINK_TAGS:
                db.add(NoteLinkTag(created_by=created_by, **spec))
            print(f"[OK] Seeded {len(note_link_policy.DEFAULT_NOTE_LINK_TAGS)} default note-link tags")
    except Exception as e:
        print(f"⚠ Default note-link-tag seeding skipped: {e}")


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


def _seed_default_email_profile():
    """Import the legacy global SMTP config into a default sending profile on first boot after this
    feature lands (idempotent — a no-op once any profile exists), so system mail and the Email Studio
    start from the config the deployment already had."""
    try:
        from app.core.database import get_db_context
        from app.core import email_send
        from app.core.email_actions import seed_email_actions, seed_default_templates
        with get_db_context() as db:
            if email_send.seed_default_profile(db):
                print("[OK] Seeded default email sending profile from legacy SMTP config")
            n = seed_email_actions(db)
            if n:
                print(f"[OK] Seeded {n} automated-email action(s)")
            # Materialize each action's built-in default template and pre-bind it (idempotent; never
            # overwrites an admin's own template choice). Runs after the actions exist so it can bind,
            # and self-heals an unbound SYSTEM action against an existing default (see seed_default_templates).
            t = seed_default_templates(db)
            if t:
                print(f"[OK] Seeded {t} default email template(s)")
    except Exception as e:
        print(f"⚠ Default email profile seed skipped: {e}")


def _app_version():
    """The running version, or None. Never raises: this is provenance on a bookkeeping row."""
    try:
        from app.config.branding import branding
        return (branding.app_version or None)
    except Exception:
        return None


class _SchemaStepRecorder:
    """Writes what each boot-time DDL step did, so an incomplete schema stops being invisible.

    Every write is best-effort and swallowed. That looks like the very habit this phase exists to
    end, and it is the opposite: this is BOOKKEEPING about the schema, not the schema. A recorder
    that could abort a boot would make honest health strictly more dangerous than silence, which is
    not a trade worth making to know about a failure. When recording itself fails, `/health` reports
    the schema state as unknown rather than claiming it is fine.

    Each write commits on its own. The steps it describes have already committed independently, so
    holding these to the end would mean losing the whole record to one late error -- including the
    record of the failure that caused it.
    """

    def __init__(self, db):
        self.db = db
        self.seen = set()
        self.broken = False

    @staticmethod
    def step_id(statement):
        return hashlib.sha256(statement.encode("utf-8")).hexdigest()[:32]

    @staticmethod
    def _summary(statement):
        """One readable line, for an operator scanning the table."""
        collapsed = " ".join(statement.split())
        return collapsed[:197] + "..." if len(collapsed) > 200 else collapsed

    @staticmethod
    def _safe_detail(detail):
        """The error's first line only, capped.

        A Postgres error carries a DETAIL: section, and for a constraint violation that section is
        the offending ROW -- every column of it. The statements replayed here include data
        migrations over `users`, so a failure could put real addresses into this table, where they
        would then travel in every database backup. The first line names the constraint and the
        relation, which is what a person debugging this needs; the row is not.
        """
        if not detail:
            return None
        return str(detail).strip().splitlines()[0][:500] or None

    def record(self, statement, outcome, detail=None):
        identifier = self.step_id(statement)
        self.seen.add(identifier)
        try:
            existing = self.db.get(SchemaStep, identifier)
            if existing is None:
                self.db.add(SchemaStep(
                    step_id=identifier, summary=self._summary(statement), outcome=outcome,
                    detail=self._safe_detail(detail), app_version=_app_version(),
                    recorded_at=datetime.utcnow()))
            else:
                existing.outcome = outcome
                existing.detail = self._safe_detail(detail)
                existing.app_version = _app_version()
                existing.recorded_at = datetime.utcnow()
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            self.broken = True
            print(f"⚠ Could not record the outcome of a schema step: {exc}")

    def forget_steps_no_longer_declared(self):
        """Drop rows for statements that are no longer in the list.

        Without this, a step that failed and was then fixed by EDITING its SQL would leave its old
        row behind reporting failure for good -- the hash changes, so the fix records a new row and
        never touches the old one -- and health would never recover. The table describes the
        current list and nothing else.
        """
        if self.broken or not self.seen:
            return
        try:
            self.db.query(SchemaStep).filter(
                SchemaStep.step_id.notin_(self.seen)).delete(synchronize_session=False)
            self.db.commit()
        except Exception as exc:
            self.db.rollback()
            self.broken = True
            print(f"⚠ Could not prune stale schema-step records: {exc}")


def _run_lightweight_migrations():
    """Idempotent column additions for existing tables. create_all() only creates
    missing TABLES, not missing COLUMNS, so new columns on existing tables must be
    added here (Postgres ADD COLUMN IF NOT EXISTS makes this safe to re-run).

    Returns True when the outcome of every step was recorded, False when the record is
    untrustworthy. The caller passes that to the health state: rows left from an earlier boot would
    otherwise let a deployment whose recording failed report a complete schema, which is the exact
    reassurance this machinery exists to stop giving.
    """
    recording_failed = False
    try:
        from app.core.database import get_db_context
        from sqlalchemy import text
        # Retired object ids. `create_all` builds the TABLE on a fresh database but knows nothing
        # about triggers, and an existing deployment has neither -- so both are declared here, and
        # a startup self-test below refuses to serve if the triggers did not land. That check is
        # not belt-and-braces: every statement in this list is wrapped in try/except and a failure
        # only PRINTS, so without it a skipped step quietly returns the deployment to the
        # liveness-only behaviour this replaces, while every id check keeps answering "not spent".
        _retire_ddl = ["""
            CREATE TABLE IF NOT EXISTS retired_object_ids (
                id       UUID      PRIMARY KEY,
                kind     INTEGER   NOT NULL,
                vault_id UUID      NULL,
                spent_at TIMESTAMP NOT NULL DEFAULT (now() AT TIME ZONE 'utc')
            )""",
            "CREATE INDEX IF NOT EXISTS idx_retired_object_vault "
            "ON retired_object_ids (vault_id)",
            # For a database where create_all already built this table from an earlier model that
            # carried only the Python-side default. Harmless when the default is already right.
            "ALTER TABLE retired_object_ids ALTER COLUMN spent_at "
            "SET DEFAULT (now() AT TIME ZONE 'utc')"]
        # One function + one statement-level trigger per table holding a client-choosable id.
        #
        # Statement-level with a transition table, not row-level: a cascade deleting N rows then
        # costs one INSERT rather than N. And AFTER DELETE fires for rows removed by an
        # `ON DELETE CASCADE` foreign key, which is the whole reason this lives in the database --
        # those deletions have no Python site to patch, now or in future.
        for _tbl, _kind, _vault_expr in (("files", 1, "d.vault_id"),
                                         ("folders", 2, "d.vault_id"),
                                         ("vaults", 3, "NULL::uuid")):
            _retire_ddl.append(f"""
                CREATE OR REPLACE FUNCTION dv_retire_{_tbl}_ids() RETURNS trigger
                LANGUAGE plpgsql AS $dv$
                BEGIN
                    INSERT INTO retired_object_ids (id, kind, vault_id)
                    SELECT d.id, {_kind}, {_vault_expr} FROM deleted d
                    ON CONFLICT (id) DO NOTHING;
                    RETURN NULL;
                END $dv$""")
            # CREATE OR REPLACE, not DROP-then-CREATE. Those were two separately committed
            # statements, so every single boot dropped the protection and re-added it ~20ms
            # later -- and the SFTP server is a different container that keeps serving across an
            # API restart, so a delete landing in that window retired nothing and freed the id
            # permanently. If the CREATE had then failed, the window never closed.
            _retire_ddl.append(f"""
                CREATE OR REPLACE TRIGGER trg_{_tbl}_retire AFTER DELETE ON {_tbl}
                REFERENCING OLD TABLE AS deleted FOR EACH STATEMENT
                EXECUTE FUNCTION dv_retire_{_tbl}_ids()""")
            # ENABLE ALWAYS, not the default ORIGIN. An ORIGIN trigger does not fire when
            # `session_replication_role = 'replica'` -- which is what a logical-replication apply
            # worker runs as, and what `pg_restore --disable-triggers` sets. A promoted replica or
            # a restore would otherwise free every id it touched, silently, while the trigger row
            # still existed for the check below to find.
            _retire_ddl.append(
                f"ALTER TABLE {_tbl} ENABLE ALWAYS TRIGGER trg_{_tbl}_retire")

        statements = _retire_ddl + [
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS unlock_remember_minutes INTEGER",
            # Per-vault confidentiality tier; 'standard' = today's server-encrypted,
            # SFTP-capable vault (zero-knowledge slots in later, web-only).
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS type VARCHAR(20) NOT NULL DEFAULT 'standard'",
            # Delegated vault administration: a member with manage_permission is a "Manager".
            "ALTER TABLE vault_members ADD COLUMN IF NOT EXISTS manage_permission BOOLEAN NOT NULL DEFAULT FALSE",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS folder_id UUID",
            # Notes are sealed at rest (a marker + ciphertext); a title that once fit String(255)
            # no longer does, so widen it (and the public-link title snapshot) to TEXT. Idempotent.
            "ALTER TABLE notes ALTER COLUMN title TYPE TEXT",
            "ALTER TABLE note_public_links ALTER COLUMN title_snapshot TYPE TEXT",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS note VARCHAR(500)",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS can_create_temp_credentials BOOLEAN DEFAULT FALSE",
            # Least-privilege scope for temp credentials (the temp_credential_vault_access
            # TABLE itself is created by create_all; only new COLUMNS need an ALTER).
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS scope JSONB",
            # Optional per-file/folder ID scope on a selected-mode vault grant (NULL = whole vault).
            "ALTER TABLE temp_credential_vault_access ADD COLUMN IF NOT EXISTS scope_ids JSONB",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS vault_access_mode VARCHAR(10) DEFAULT 'selected'",
            # Converge these two on the model, which declares both NOT NULL.
            #
            # ADD COLUMN alone did not, and could not: on a database where the column already
            # exists the statement is a no-op, so every deployment that had already upgraded kept a
            # nullable column while a fresh install -- built by create_all from the model -- got a
            # NOT NULL one. Two installs of one release with two different physical schemas, and
            # nothing compared them.
            #
            # Backfill first. SET NOT NULL cannot apply while a NULL remains, and on an upgraded
            # deployment the rows written before the column existed hold exactly that. The values
            # match the column defaults, which is what those rows have been read as all along.
            "UPDATE temporary_credentials SET can_create_temp_credentials = FALSE "
            "WHERE can_create_temp_credentials IS NULL",
            "ALTER TABLE temporary_credentials "
            "ALTER COLUMN can_create_temp_credentials SET NOT NULL",
            "UPDATE temporary_credentials SET vault_access_mode = 'selected' "
            "WHERE vault_access_mode IS NULL",
            "ALTER TABLE temporary_credentials ALTER COLUMN vault_access_mode SET NOT NULL",
            "ALTER TABLE temporary_credentials ADD COLUMN IF NOT EXISTS created_by_temp_credential_id UUID",
            # Drop the long-deprecated encrypted_password column: it held a retrievable copy of the temp
            # password and has been NULL for every row since the password became show-once-at-creation.
            # Removing it takes the column (and its SQL-readable data) out of the schema. Idempotent - a
            # fresh install (whose model never declared the column) is a clean no-op.
            "ALTER TABLE temporary_credentials DROP COLUMN IF EXISTS encrypted_password",
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
            # Keyed content MAC used as the file's ETag (HMAC of checksum_sha256 under a per-file
            # key), so the plaintext checksum is never handed to a client. create_all adds it on a
            # fresh DB; this adds it on an existing one. No backfill: for a row whose column is still
            # NULL the value is derived on read (deterministic from id + checksum_sha256).
            "ALTER TABLE files ADD COLUMN IF NOT EXISTS content_mac VARCHAR(64)",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS enc_name TEXT",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS name_bi VARCHAR(64)",
            "CREATE INDEX IF NOT EXISTS ix_folders_name_bi ON folders (name_bi)",
            # Vault name sealed at rest (Standard vaults): enc_name holds the AES-GCM blob and the
            # plaintext `name` becomes NULLABLE (a sealed row NULLs it; the load event restores it on
            # read). create_all adds these on a fresh DB; these backfill them on an existing one. A
            # one-time eager backfill of existing rows runs in _backfill_encrypted_names.
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS enc_name TEXT",
            "ALTER TABLE vaults ALTER COLUMN name DROP NOT NULL",
            # Zero-knowledge vault description sealed in the browser (server stores, never reads).
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS enc_description TEXT",
            # Sharing: a tag can FORCE view-only on every share it mints (independent of allow_custom).
            # create_all adds the column on a fresh DB; this backfills it on a vault that already ran an
            # earlier sharing build. Idempotent + additive.
            "ALTER TABLE share_tags ADD COLUMN IF NOT EXISTS force_view_only BOOLEAN NOT NULL DEFAULT FALSE",
            # Sharing: the Share audience id-arrays are queried with JSONB @> containment so the
            # "shared with me" scan filters server-side + is GIN-indexed (was an unbounded Python scan).
            # Convert JSON->JSONB only if still json (idempotent; avoids a table rewrite every startup),
            # then add the GIN indexes. create_all makes them JSONB + GIN on a fresh DB.
            """DO $$ BEGIN
                   IF EXISTS (SELECT 1 FROM information_schema.columns
                              WHERE table_name='shares' AND column_name='audience_user_ids'
                                AND data_type='json') THEN
                       ALTER TABLE shares ALTER COLUMN audience_user_ids TYPE JSONB
                           USING audience_user_ids::jsonb;
                   END IF;
                   IF EXISTS (SELECT 1 FROM information_schema.columns
                              WHERE table_name='shares' AND column_name='audience_department_ids'
                                AND data_type='json') THEN
                       ALTER TABLE shares ALTER COLUMN audience_department_ids TYPE JSONB
                           USING audience_department_ids::jsonb;
                   END IF;
               END $$;""",
            "CREATE INDEX IF NOT EXISTS idx_share_aud_users ON shares USING GIN (audience_user_ids)",
            "CREATE INDEX IF NOT EXISTS idx_share_aud_depts ON shares USING GIN (audience_department_ids)",
            "ALTER TABLE folders ALTER COLUMN name DROP NOT NULL",
            # Zero-knowledge DEK rotation (forward-only versioning). dek_version is the
            # vault's current ZK DEK epoch; backfills every existing vault to 1, matching
            # the existing key_version=1 member rows. Separate from vaults.key_version
            # (Standard Fernet counter). zk_key_version on a chunked session carries the
            # client-declared epoch through to finalize for the upload-vs-rekey race check.
            "ALTER TABLE vaults ADD COLUMN IF NOT EXISTS dek_version INTEGER NOT NULL DEFAULT 1",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS zk_key_version INTEGER",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS client_object_id UUID",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS blob_id VARCHAR(32)",
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS temp_credential_id UUID",
            "ALTER TABLE audit_logs ADD COLUMN IF NOT EXISTS temp_credential_id UUID",
            # Backfill any legacy NULL/0 per-vault size_limit to the 1 GB default: such a vault
            # reserves nothing in the account budget SUM yet is treated as UNLIMITED at every upload
            # guard (`if vault.size_limit`), so the reservation model would under-count it. Idempotent.
            "UPDATE vaults SET size_limit = 1073741824 WHERE size_limit IS NULL OR size_limit <= 0",
            # Hierarchical ZK key wrapping (VaultTeamKey). team_public_key = the per-vault team
            # public key; team_key_version = the team-KEYPAIR epoch, SEPARATE from dek_version
            # (bumps only on a team-keypair rotation, not a routine DEK rotation). team_key (the
            # DEK->team-pubkey wrap map) + key_wrapping_mode already exist. Additive; default
            # mode stays 'direct' so existing vaults retain their direct member wraps.
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
            # The per-epoch/index-key candidate set a ZK upload matches its name against, so a
            # same-name file sealed before a rotation is found rather than silently duplicated.
            # create_all adds it on a fresh DB; this backfills it on an in-place upgrade. Additive
            # and nullable — an old session row simply has none and falls back to single-value match.
            "ALTER TABLE chunked_upload_sessions ADD COLUMN IF NOT EXISTS name_bi_candidates JSON",
            "ALTER TABLE folders ADD COLUMN IF NOT EXISTS name_key_version INTEGER",
            # Per-account storage budget (NULL inherits the deployment default, -1 exempts).
            "ALTER TABLE users ADD COLUMN IF NOT EXISTS storage_quota_bytes BIGINT",
            # Email becomes optional. This ALTER is what makes an UPGRADED install match a fresh
            # one: create_all() only ever creates tables, so without this line the model would say
            # nullable while every existing deployment kept NOT NULL -- and creating an email-less
            # user would fail at the database for every self-hoster while the suite stayed green,
            # because the suite installs fresh. The case-insensitive uniqueness index is NOT here:
            # it needs a collision check first, so it lives in code after this loop.
            "ALTER TABLE users ALTER COLUMN email DROP NOT NULL",
            # Storage-allocation ledger. create_all builds the table on a fresh database; these
            # cover a database that already has vaults, and seed one owner-held grant per vault so
            # the ledger's invariant (SUM(granted_bytes) == vaults.size_limit) holds from the first
            # request after an update. The INSERT is guarded by NOT EXISTS, so re-running it on a
            # deployment whose contributions have since changed cannot resurrect the old figure.
            """CREATE TABLE IF NOT EXISTS vault_storage_grants (
                   id            UUID      PRIMARY KEY,
                   vault_id      UUID      NOT NULL REFERENCES vaults(id) ON DELETE CASCADE,
                   user_id       UUID      NOT NULL REFERENCES users(id) ON DELETE CASCADE,
                   granted_bytes BIGINT    NOT NULL DEFAULT 0,
                   created_at    TIMESTAMP,
                   updated_at    TIMESTAMP,
                   CONSTRAINT uq_vault_storage_grant_vault_user UNIQUE (vault_id, user_id),
                   CONSTRAINT ck_vault_storage_grant_non_negative CHECK (granted_bytes >= 0)
               )""",
            "CREATE INDEX IF NOT EXISTS idx_vault_storage_grant_vault "
            "ON vault_storage_grants (vault_id)",
            "CREATE INDEX IF NOT EXISTS idx_vault_storage_grant_user "
            "ON vault_storage_grants (user_id)",
            """INSERT INTO vault_storage_grants
                   (id, vault_id, user_id, granted_bytes, created_at, updated_at)
               SELECT gen_random_uuid(), v.id, v.owner_id, GREATEST(COALESCE(v.size_limit, 0), 0),
                      (now() AT TIME ZONE 'utc'), (now() AT TIME ZONE 'utc')
                 FROM vaults v
                WHERE NOT EXISTS (SELECT 1 FROM vault_storage_grants g
                                   WHERE g.vault_id = v.id)""",
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
            # Email Studio: the per-profile "allow insecure TLS" opt-out. email_profiles is a whole
            # new table (create_all builds it with this column on a fresh DB), but a deployment that
            # created email_profiles on an INTERMEDIATE build before the column was added would not
            # get it from create_all (which never ALTERs) — so back it in here on upgrade. Additive +
            # idempotent; the table always exists by now because init_db()/create_all ran first.
            "ALTER TABLE email_profiles ADD COLUMN IF NOT EXISTS "
            "smtp_allow_insecure_tls BOOLEAN NOT NULL DEFAULT FALSE",
            # Email Studio: mark a template as the built-in default for an action key (NULL = user
            # template). Additive + idempotent; create_all builds it on a fresh DB, this ADDs it on an
            # INTERMEDIATE deployment that created email_templates before the column existed.
            "ALTER TABLE email_templates ADD COLUMN IF NOT EXISTS default_key VARCHAR(64)",
            # Partial unique: at most one default template per action key (NULLs — user templates —
            # unconstrained). Safe to create on upgrade: the column is brand-new (all NULL) until the
            # boot seed, which runs after migrations, so no duplicate can exist at index-creation time.
            "CREATE UNIQUE INDEX IF NOT EXISTS idx_email_template_default_key "
            "ON email_templates (default_key) WHERE default_key IS NOT NULL",
        ]
        with get_db_context() as db:
            recorder = _SchemaStepRecorder(db)
            for stmt in statements:
                try:
                    db.execute(text(stmt))
                    db.commit()
                    recorder.record(stmt, SchemaStep.OUTCOME_APPLIED)
                except Exception as e:
                    db.rollback()
                    print(f"⚠ Migration step skipped ({stmt}): {e}")
                    # The point of the record: the failure now survives the print. Without it
                    # /health has nothing to consult, and a deployment missing a column reports
                    # itself well until an endpoint that needed the column returns a 500.
                    recorder.record(stmt, SchemaStep.OUTCOME_FAILED, str(e))

            # Case-insensitive uniqueness on users.email. Deliberately NOT a string in the list
            # above, because it is conditional: a deployment that already holds two addresses
            # differing only in case cannot build this index at all.
            #
            # Such a deployment BOOTS anyway, with a warning naming the accounts.
            # Refusing to start would take a self-hosted vault down in the middle of an unattended
            # update and keep it down until someone hand-edited the database; nulling the newer
            # duplicate would silently destroy an address that may be that person's only way in.
            #
            # The consequence has to be stated plainly, because it is load-bearing: on a colliding
            # install this index does NOT exist, so the application check in
            # app/core/email_identity.py is the only guard there is. It is not belt-and-braces and
            # must not be deleted as redundant with the index.
            email_index_step = "conditional: users.email case-insensitive unique index"
            try:
                collisions = find_email_collisions(db)
                if collisions:
                    # Recorded, not merely printed. This is the conditional degradation the phase
                    # exists to surface: the deployment boots correctly and serves, but it is
                    # running without a uniqueness index that a fresh install has.
                    recorder.record(
                        email_index_step, SchemaStep.OUTCOME_SKIPPED,
                        f"{len(collisions)} address(es) held by more than one account differing "
                        "only in case; resolve them and restart to build the index")
                    print(
                        f"⚠ users.email: {len(collisions)} address(es) are held by more than one "
                        f"account differing only in case, so the case-insensitive unique index "
                        f"({EMAIL_LOWER_UNIQUE_INDEX}) was NOT created. Uniqueness is still enforced "
                        f"by the application, but two concurrent requests could still race. "
                        f"Resolve these accounts and restart:"
                    )
                    for normalized, usernames in collisions:
                        print(f"    {normalized}  ->  {usernames}")
                else:
                    # Canonicalize what is already there before indexing it. Rows written by an
                    # older release kept whatever case the caller typed, so without this an
                    # upgraded install holds a mix of folded and unfolded addresses. Uses the
                    # DATABASE's lower(), the same function the index and every lookup use, so
                    # there is one definition of "lowercase" everywhere. Safe to run only in this
                    # branch: the preflight has just proven no two rows collide under lower(), so
                    # this cannot violate the plain unique constraint.
                    db.execute(text(
                        "UPDATE users SET email = lower(email) "
                        "WHERE email IS NOT NULL AND email <> lower(email)"
                    ))
                    db.execute(text(
                        f"CREATE UNIQUE INDEX IF NOT EXISTS {EMAIL_LOWER_UNIQUE_INDEX} "
                        f"ON users (lower(email))"
                    ))
                    db.commit()
                    recorder.record(email_index_step, SchemaStep.OUTCOME_APPLIED)
            except Exception as e:
                # Own try/except so a failure here cannot abort anything else; every statement in
                # the loop above already committed independently.
                db.rollback()
                print(f"⚠ users.email case-insensitive index skipped: {e}")
                recorder.record(email_index_step, SchemaStep.OUTCOME_FAILED, str(e))

            recorder.forget_steps_no_longer_declared()
            recording_failed = recorder.broken
    except Exception as e:
        print(f"⚠ Lightweight migrations skipped: {e}")
        # The whole block fell over, so whatever is in schema_steps describes an earlier boot.
        recording_failed = True

    # OUTSIDE that try, deliberately, and this is the whole point of the check.
    #
    # It used to be the last line inside it -- where the `except Exception: print(...)` above
    # caught the RuntimeError it raises and carried on serving. The check that exists to stop a
    # deployment without the triggers reported its own failure in the same "⚠ … skipped" format
    # its docstring dismisses as nothing anyone reads. A fresh session, because the one above
    # belongs to a context manager that has already closed.
    from app.core.database import get_db_context as _ctx
    with _ctx() as _db:
        _verify_retired_object_id_triggers(_db)

    return not recording_failed


def _verify_retired_object_id_triggers(db) -> None:
    """Refuse to run without the triggers that record retired object ids.

    Every statement above is wrapped in try/except and reports a failure by PRINTING. That is the
    right call for a column addition -- one that does not apply is usually one that already
    exists. It is the wrong call here, because the failure is silent in the direction that matters:
    with no trigger, ids are never recorded, every "has this id been spent" check keeps answering
    no, and the deployment is back to the liveness-only guard with nothing in the logs anyone reads
    to say so. A client could then re-claim the id of a deleted object and read a blob that
    outlived its row.

    So this is a hard stop rather than a warning. A deployment that cannot record retired ids must
    not serve, because the property it would be advertising is not one it has.
    """
    from sqlalchemy import text as _text

    expected = {"trg_files_retire": "files",
                "trg_folders_retire": "folders",
                "trg_vaults_retire": "vaults"}
    try:
        # Name alone is not enough, and both extra conditions were demonstrated to matter:
        # a trigger of the same name on ANY table satisfied a name-only lookup, and
        # `ALTER TABLE ... DISABLE TRIGGER` left the row in place so the check passed while
        # nothing was recorded. Join the relation, and reject a disabled one.
        rows = db.execute(_text(
            "SELECT t.tgname, c.relname, t.tgenabled FROM pg_trigger t "
            "JOIN pg_class c ON c.oid = t.tgrelid "
            "WHERE t.tgname = ANY(:names) AND NOT t.tgisinternal"
        ), {"names": sorted(expected)}).fetchall()
    except Exception as e:  # noqa: BLE001 - a database that cannot answer is not a pass
        raise RuntimeError(
            "Could not verify the retired-object-id triggers, so the re-claim guard cannot be "
            f"trusted: {e}"
        ) from e
    usable = {name for name, relation, enabled in rows
              if relation == expected.get(name) and enabled != "D"}
    missing = set(expected) - usable
    if missing:
        raise RuntimeError(
            "Retired-object-id triggers are missing: " + ", ".join(sorted(missing)) + ". Object "
            "ids of deleted files, folders or vaults would silently become re-claimable. Check "
            "the migration output above for the step that was skipped."
        )


def _rehash_plaintext_session_tokens():
    """Hash any legacy plaintext session token at rest (idempotent, no forced logout). Best-effort:
    never block boot. The logic lives in app.core.session_migrations so it is unit-testable."""
    try:
        from app.core.database import get_db_context
        from app.core.session_migrations import rehash_plaintext_session_tokens
        with get_db_context() as db:
            rehashed = rehash_plaintext_session_tokens(db)
            if rehashed:
                db.commit()
                print(f"[OK] Rehashed {rehashed} plaintext session token(s) at rest")
    except Exception as e:  # noqa: BLE001 — best-effort hardening migration, never block boot
        print(f"⚠ session-token rehash skipped: {e}")


def _backfill_note_content():
    """Seal any legacy plaintext note/link content at rest (idempotent). Best-effort: never block
    boot. Runs after the widen DDL. The logic lives in app.core.note_migrations so it is testable."""
    try:
        from app.core.database import get_db_context
        from app.core.note_migrations import backfill_note_content
        with get_db_context() as db:
            sealed = backfill_note_content(db)
            if sealed:
                db.commit()
                print(f"[OK] Sealed {sealed} note/link row(s) with plaintext content at rest")
    except Exception as e:  # noqa: BLE001 — best-effort hardening migration, never block boot
        print(f"⚠ note-content backfill skipped: {e}")


def _backfill_encrypted_names():
    """One-time, idempotent eager encryption of existing plaintext file/folder names in
    STANDARD vaults (so names already on disk before this version stop being stored in
    the clear). Rows already sealed (enc_name set), zero-knowledge vaults, and rows with
    no plaintext name are skipped — safe to re-run. Runs after the columns exist."""
    try:
        from app.core.database import get_db_context
        from app.core.models import File, Folder, Vault
        from app.services.vault_service import _seal_named_object, _seal_vault_name
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
            # Seal the vault NAMES themselves in place (the load event restores them on read).
            # Idempotent: a row already sealed has enc_name set and is skipped. NULLing a vault's
            # name does not affect the file/folder loop below (it keys off vault.id, not the name).
            # Isolated in its own try/except so a hiccup here can never skip the proven file/folder
            # name backfill that follows; it just retries next boot. On failure the in-memory vault
            # objects may be partly mutated (name NULLed without a commit), so re-fetch them for the
            # file/folder loop rather than trusting the dict.
            try:
                vname = 0
                for _v in vaults.values():
                    if getattr(_v, 'enc_name', None) is None and _v.name is not None:
                        _seal_vault_name(_v, _v.name)
                        vname += 1
                if vname:
                    db.commit()
                    print(f"[OK] Sealed {vname} vault name(s) at rest")
            except Exception as _ve:  # noqa: BLE001 — never block the file/folder backfill
                db.rollback()
                vaults = {v.id: v for v in db.query(Vault).filter(Vault.type == 'standard').all()}
                print(f"⚠ Vault-name backfill skipped this boot (retries next boot): {_ve}")
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
    initialize_runtime()
    init_db()
    print("Database initialized")
    recorded = _run_lightweight_migrations()
    # After the replay, so the remembered value describes what this boot actually achieved.
    from app.core.health import refresh_schema_state
    print(f"Schema state: {refresh_schema_state(recorded=recorded)}")
    _rehash_plaintext_session_tokens()  # hash any legacy plaintext session tokens at rest (no logout)
    _backfill_note_content()            # seal any legacy plaintext note/link content at rest
    _backfill_encrypted_names()
    _add_name_uniqueness()  # after backfill so freshly-sealed name_bi values are indexed
    _seed_admin_user()
    _seed_default_share_tags()  # after the admin exists, so seed tags can record it as creator
    _seed_default_note_link_tags()  # public-note-link starter tags (inert until enabled)
    _backfill_default_permissions()
    _seed_default_email_profile()

    # Start background task for session cleanup
    cleanup_task = asyncio.create_task(cleanup_expired_sessions())
    print("[OK] Session cleanup task started")

    # Keep the single-use invite/share tokens (which ride the URL) out of uvicorn's access log — they
    # would otherwise be written on every invite lookup/accept and the ?invite= landing hit.
    _install_access_log_redaction()

    # Web log-pull sink: when NOT running under run_combined (i.e. the API was started directly — the
    # split-container / dev shape), self-write the [web] access lines so GET /logs?service=web works
    # in every run shape. Under run_combined the launcher already captures this child's stdout as
    # [web]; its VAULT_LOG_SINK_OWNER marker makes us stand down here so we never double-write.
    if not str(os.environ.get("VAULT_LOG_SINK_OWNER", "")).strip():
        from app.services import log_sink
        if log_sink.init_sink():
            os.environ["VAULT_LOG_SINK_ACTIVE"] = "1"
            os.environ["VAULT_LOG_SINK_COMPONENTS"] = "web"
            print("[OK] Web log sink active (in-app)")
        else:
            # Sink couldn't init (e.g. read-only logs dir). CLEAR any stale markers a hand-edited
            # .env may carry, so the admin panel reports web log-pull as unavailable rather than
            # advertising it and then serving an empty list (mirrors run_combined.mark_sink_active).
            os.environ.pop("VAULT_LOG_SINK_ACTIVE", None)
            os.environ.pop("VAULT_LOG_SINK_COMPONENTS", None)

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
        print("   reverse proxy (deploy/docker-compose.secure.yml / 'python3 dockvault.py setup' do this for you).")

    uvicorn.run(
        app,
        host=settings.api_host,
        port=settings.api_port,
        log_level=settings.log_level.lower(),
        **ssl_config
    )
