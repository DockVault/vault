"""
Enhanced rate limiting system with Redis-backed sliding window algorithm.

Features:
- Sliding window algorithm (more accurate than fixed window)
- Rate limit headers (X-RateLimit-Limit, X-RateLimit-Remaining, X-RateLimit-Reset)
- Retry-After header for 429 responses
- Per-IP and per-user rate limiting
- Configurable limits and windows
- FastAPI middleware for automatic application
"""
import time
import threading
import uuid
from dataclasses import dataclass
from types import MappingProxyType
from typing import Callable, Dict, Mapping, Optional, Tuple

from functools import wraps

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import JSONResponse

from app.core.database import redis_client

import logging

logger = logging.getLogger(__name__)

API_RATE_LIMIT_CLASSES = ("default", "auth", "upload", "download")
API_RATE_LIMIT_MAX_REQUESTS = 1_000_000
API_RATE_LIMIT_MAX_WINDOW_SECONDS = 86_400


@dataclass(frozen=True)
class RateLimitRule:
    limit: int
    window: int


def classify_api_rate_limit(method: str, path: str) -> str:
    """Return one general-API class with auth > upload > download > default precedence.

    Auth covers every /auth route plus logout. Upload covers direct file POSTs and
    chunk-init/chunk-write/complete routes. Download covers the file-content GET route.
    Everything else is default; method checks prevent lookalike paths changing class.
    """
    method = (method or "").upper()
    path = (path or "/").rstrip("/") or "/"
    if path == "/auth" or path.startswith("/auth/") or path == "/api/logout":
        return "auth"

    parts = path.strip("/").split("/")
    if parts[:1] == ["vaults"]:
        if method == "POST" and len(parts) == 3 and parts[2] in {"files", "uploads"}:
            return "upload"
        if (
            method == "PUT"
            and len(parts) == 6
            and parts[2] == "uploads"
            and parts[4] == "chunks"
        ):
            return "upload"
        if (
            method == "POST"
            and len(parts) == 5
            and parts[2] == "uploads"
            and parts[4] == "complete"
        ):
            return "upload"
        if (
            method == "GET"
            and len(parts) == 5
            and parts[2] == "files"
            and parts[4] == "download"
        ):
            return "download"
    return "default"


def resolve_api_rate_limit_policy(
    defaults: Mapping[str, RateLimitRule],
    overrides: Mapping[str, object] | None,
) -> Mapping[str, RateLimitRule]:
    """Apply positive stored fields; zero/invalid fields retain deployment defaults."""
    overrides = overrides if isinstance(overrides, Mapping) else {}
    resolved = {}
    for category in API_RATE_LIMIT_CLASSES:
        fallback = defaults[category]
        limit = overrides.get(f"rate_limit_api_{category}", 0)
        window = overrides.get(f"rate_limit_api_{category}_window", 0)
        resolved[category] = RateLimitRule(
            limit
            if (
                isinstance(limit, int)
                and not isinstance(limit, bool)
                and 0 < limit <= API_RATE_LIMIT_MAX_REQUESTS
            )
            else fallback.limit,
            window
            if (
                isinstance(window, int)
                and not isinstance(window, bool)
                and 0 < window <= API_RATE_LIMIT_MAX_WINDOW_SECONDS
            )
            else fallback.window,
        )
    return MappingProxyType(resolved)


class ApiRateLimitPolicyCache:
    """Bounded DB refresh plus immediate same-process replacement after Settings writes."""

    def __init__(
        self,
        defaults: Mapping[str, RateLimitRule],
        loader: Callable[[], Mapping[str, object]],
        *,
        ttl_seconds: float = 5.0,
        clock: Callable[[], float] = time.monotonic,
    ):
        if ttl_seconds <= 0:
            raise ValueError("ttl_seconds must be positive")
        self._defaults = MappingProxyType(dict(defaults))
        self._loader = loader
        self._ttl_seconds = ttl_seconds
        self._clock = clock
        self._lock = threading.RLock()
        self._policy = resolve_api_rate_limit_policy(self._defaults, {})
        self._expires_at = 0.0

    def get(self) -> Mapping[str, RateLimitRule]:
        now = self._clock()
        with self._lock:
            if now < self._expires_at:
                return self._policy
            try:
                loaded = self._loader()
            except Exception:  # noqa: BLE001 - keep serving the last known bounded policy
                logger.warning("Could not refresh the API rate-limit policy; using last known values")
            else:
                self._policy = resolve_api_rate_limit_policy(self._defaults, loaded)
            self._expires_at = now + self._ttl_seconds
            return self._policy

    def replace(self, overrides: Mapping[str, object]) -> None:
        with self._lock:
            self._policy = resolve_api_rate_limit_policy(self._defaults, overrides)
            self._expires_at = self._clock() + self._ttl_seconds


class RateLimitExceeded(Exception):
    """Exception raised when rate limit is exceeded."""
    def __init__(self, message: str, retry_after: int, limit: int, remaining: int = 0):
        self.message = message
        self.retry_after = retry_after
        self.limit = limit
        self.remaining = remaining
        super().__init__(self.message)


class RateLimiterUnavailable(Exception):
    """Raised when the Redis backing store is unavailable AND the caller asked to
    fail closed (``fail_open=False``).

    General API traffic fails OPEN on a Redis outage (availability over a brief
    throttling gap). Security-sensitive auth paths must NOT silently stop
    throttling, so they pass ``fail_open=False`` and catch this to fall back to a
    durable DB-backed throttle instead of waving the request through."""
    pass


# --- Redis circuit breaker -------------------------------------------------
# Even with a short Redis connect timeout, paying it on EVERY request during a sustained
# outage makes logins crawl — and the timeout doesn't even bound DNS resolution (a dead
# Redis host can stall getaddrinfo for several seconds per call). After the first
# Redis failure we OPEN the breaker and skip Redis entirely for a cooldown —
# so the fail-closed auth path drops to its DB fallback instantly, and general (fail-open)
# traffic isn't delayed at all. After the cooldown the next call probes Redis again
# (half-open); a success resets, a failure re-opens. The cooldown is comfortably longer than
# any burst of requests so the breaker stays open through an outage instead of re-probing
# (and re-stalling) every few requests. Process-local state — fine for our single worker.
_CB_FAIL_THRESHOLD = 1
# Cooldown the breaker stays open before a half-open probe. Long enough to outlast any burst of
# requests during an outage (so it stays open instead of re-probing/re-stalling every few
# requests), short enough that rate limiting resumes quickly after Redis recovers. A half-open
# probe may pay one resolver delay, so the breaker re-opens immediately on failure.
_CB_COOLDOWN_SECONDS = 10
_cb_consecutive_failures = 0
_cb_open_until = 0.0


def _cb_is_open(now: float) -> bool:
    return now < _cb_open_until


def redis_circuit_open() -> bool:
    """Return whether this process recently observed a Redis backend failure."""
    return _cb_is_open(time.time())


def _cb_record_success() -> None:
    global _cb_consecutive_failures, _cb_open_until
    _cb_consecutive_failures = 0
    _cb_open_until = 0.0


def _cb_record_failure(now: float) -> None:
    global _cb_consecutive_failures, _cb_open_until
    _cb_consecutive_failures += 1
    if _cb_consecutive_failures >= _CB_FAIL_THRESHOLD:
        _cb_open_until = now + _CB_COOLDOWN_SECONDS


class RateLimiter:
    """
    Unified rate limiter with sliding window algorithm.
    
    Sliding window is more accurate than fixed window:
    - Fixed window: Can get 2x limit at window boundary
    - Sliding window: Smooth, accurate limit enforcement
    """

    _SLIDING_WINDOW_SCRIPT = """
local key = KEYS[1]
local window_start = tonumber(ARGV[1])
local now = tonumber(ARGV[2])
local limit = tonumber(ARGV[3])
local ttl = tonumber(ARGV[4])
local entry_id = ARGV[5]
local window = tonumber(ARGV[6])

redis.call('ZREMRANGEBYSCORE', key, '-inf', window_start)
local current_count = redis.call('ZCARD', key)
if current_count >= limit then
    local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
    local reset_at = math.ceil(now + window)
    if oldest[2] then
        reset_at = math.ceil(tonumber(oldest[2]) + window)
    end
    return {0, 0, tostring(reset_at)}
end

redis.call('ZADD', key, now, entry_id)
redis.call('EXPIRE', key, ttl)
local oldest = redis.call('ZRANGE', key, 0, 0, 'WITHSCORES')
local reset_at = math.ceil(now + window)
if oldest[2] then
    reset_at = math.ceil(tonumber(oldest[2]) + window)
end
return {1, limit - current_count - 1, tostring(reset_at)}
"""

    def __init__(self, redis_client):
        self.redis = redis_client
    
    def _sliding_window_check(
        self,
        key: str,
        limit: int,
        window: int,
        fail_open: bool = True
    ) -> Tuple[bool, int, int]:
        """
        Check rate limit using sliding window algorithm.

        Args:
            key: Redis key for rate limiting
            limit: Maximum requests allowed
            window: Time window in seconds
            fail_open: Behaviour when the Redis backend errors. True (default) ->
                allow the request (suits general API traffic, where a Redis blip
                shouldn't take the whole service down). False -> raise
                RateLimiterUnavailable so a security-sensitive caller (auth) can
                deny or fall back to a durable throttle instead of silently
                disabling rate limiting.

        Returns:
            (allowed, remaining, reset_time)
        """
        now = time.time()
        window_start = now - window

        # Circuit breaker: skip Redis during a known outage so we don't pay the connect
        # timeout per request. Open => behave exactly as a Redis failure would (fail
        # closed -> raise so auth drops to its DB fallback; fail open -> allow).
        if _cb_is_open(now):
            if not fail_open:
                raise RateLimiterUnavailable("rate limiter circuit open (Redis recently unavailable)")
            return True, limit, int(now + window)

        try:
            # Prune, count, decide, and insert as one Redis-side operation. A pipeline
            # alone cannot stop concurrent requests from all observing the same count.
            results = self.redis.eval(
                self._SLIDING_WINDOW_SCRIPT,
                1,
                key,
                window_start,
                now,
                limit,
                window + 1,
                str(uuid.uuid4()),
                window,
            )
            _cb_record_success()  # Redis is healthy — reset the breaker
            allowed = bool(int(results[0]))
            remaining = max(0, int(results[1]))
            reset_time = int(results[2])
            return allowed, remaining, reset_time
            
        except Exception as e:
            _cb_record_failure(time.time())  # trip the breaker after repeated failures
            logger.error(f"Rate limit check failed: {e}", exc_info=True)
            if not fail_open:
                # Fail closed: signal the caller so it can deny the request or
                # fall back to a durable throttle. Never silently allow
                # security-sensitive traffic when Redis is down.
                raise RateLimiterUnavailable(str(e)) from e
            # Fail open (default): on a Redis error, allow the request so a Redis
            # blip doesn't take down general API traffic.
            return True, limit, int(now + window)
    
    def check_rate_limit(
        self,
        identifier: str,
        limit: int,
        window: int,
        prefix: str = "rate_limit",
        fail_open: bool = True
    ) -> Tuple[bool, int, int]:
        """
        Check if rate limit is exceeded for an identifier.

        Args:
            identifier: Unique identifier (IP, user ID, etc.)
            limit: Maximum requests allowed
            window: Time window in seconds
            prefix: Redis key prefix
            fail_open: See _sliding_window_check. Default True. Auth paths pass
                False so a Redis outage raises RateLimiterUnavailable instead of
                silently allowing the request.

        Returns:
            (allowed, remaining, reset_time)
        """
        key = f"{prefix}:{identifier}"
        return self._sliding_window_check(key, limit, window, fail_open=fail_open)
    
    def get_rate_limit_headers(
        self,
        limit: int,
        remaining: int,
        reset_time: int
    ) -> Dict[str, str]:
        """
        Generate standard rate limit headers.
        
        Headers:
            X-RateLimit-Limit: Maximum requests allowed
            X-RateLimit-Remaining: Requests remaining in current window
            X-RateLimit-Reset: Unix timestamp when the limit resets
        """
        return {
            "X-RateLimit-Limit": str(limit),
            "X-RateLimit-Remaining": str(remaining),
            "X-RateLimit-Reset": str(reset_time)
        }
    
    def check_and_raise(
        self,
        identifier: str,
        limit: int,
        window: int,
        prefix: str = "rate_limit",
        message: str = "Rate limit exceeded"
    ):
        """
        Check rate limit and raise HTTPException if exceeded.
        
        This is a convenience method for use in endpoints.
        """
        allowed, remaining, reset_time = self.check_rate_limit(
            identifier, limit, window, prefix
        )
        
        if not allowed:
            retry_after = reset_time - int(time.time())
            raise RateLimitExceeded(
                message=message,
                retry_after=retry_after,
                limit=limit,
                remaining=0
            )
        
        return remaining, reset_time


class RateLimitMiddleware(BaseHTTPMiddleware):
    """
    FastAPI middleware for automatic rate limiting.
    
    Applies rate limiting to all API endpoints with customizable limits.
    Adds rate limit headers to all responses.
    """
    
    def __init__(
        self,
        app,
        rate_limiter: RateLimiter,
        default_limit: int = 100,
        default_window: int = 60,
        auth_limit: Optional[int] = None,
        auth_window: Optional[int] = None,
        upload_limit: Optional[int] = None,
        upload_window: Optional[int] = None,
        download_limit: Optional[int] = None,
        download_window: Optional[int] = None,
        policy_provider: Optional[Callable[[], Mapping[str, RateLimitRule]]] = None,
        exclude_paths: Optional[list] = None,
    ):
        super().__init__(app)
        self.rate_limiter = rate_limiter
        self.default_limit = default_limit
        self.default_window = default_window
        self.policy_provider = policy_provider
        self._static_policy = MappingProxyType({
            "default": RateLimitRule(default_limit, default_window),
            "auth": RateLimitRule(
                auth_limit if auth_limit is not None else default_limit,
                auth_window if auth_window is not None else default_window,
            ),
            "upload": RateLimitRule(
                upload_limit if upload_limit is not None else default_limit,
                upload_window if upload_window is not None else default_window,
            ),
            "download": RateLimitRule(
                download_limit if download_limit is not None else default_limit,
                download_window if download_window is not None else default_window,
            ),
        })
        self.exclude_paths = exclude_paths or ["/docs", "/openapi.json", "/redoc", "/health"]
    
    def _get_client_identifier(self, request: Request) -> str:
        """
        Extract client identifier from request.

        Priority:
        1. User ID from request.state (if some earlier layer set it)
        2. User ID decoded from the bearer token (best-effort, no DB hit)
        3. IP address

        Preferring the authenticated user means one user's traffic doesn't consume another's
        budget just because they share a NAT / proxy egress IP; anonymous traffic (login, static)
        still buckets by trusted-proxy-aware IP. The token decode is best-effort — a missing or
        invalid token silently falls through to the IP bucket (the request will be rejected by the
        real auth dependency downstream anyway).
        """
        # 1. Explicit request.state (kept for forward-compat with an auth middleware).
        if hasattr(request.state, "user_id") and request.state.user_id:
            return f"user:{request.state.user_id}"

        # 2. Best-effort identity from the bearer token (HS256 decode is cheap; no DB lookup).
        auth = request.headers.get("Authorization") or request.headers.get("authorization")
        if auth and auth.lower().startswith("bearer "):
            try:
                from app.core.security import verify_access_token
                payload = verify_access_token(auth.split(" ", 1)[1].strip())
                sub = payload.get("sub") if payload else None
                if sub:
                    return f"user:{sub}"
            except Exception:
                pass  # fall through to IP

        # 3. Fall back to IP — trusted-proxy aware (a direct client can't spoof X-Forwarded-For).
        from app.core.net_utils import client_ip
        return f"ip:{client_ip(request)}"
    
    def _should_rate_limit(self, path: str) -> bool:
        """Check if path should be rate limited."""
        # Exclude health checks and documentation
        for excluded in self.exclude_paths:
            if path.startswith(excluded):
                return False
        return True
    
    async def dispatch(self, request: Request, call_next):
        """Process request with rate limiting."""
        path = request.url.path
        
        # Skip rate limiting for excluded paths
        if not self._should_rate_limit(path):
            return await call_next(request)
        
        # Resolve one deterministic class, then one rule. The provider is a bounded
        # cache; no request performs an unconditional PostgreSQL query.
        category = classify_api_rate_limit(request.method, path)
        policy = self._static_policy
        if self.policy_provider is not None:
            try:
                candidate = self.policy_provider()
                if category in candidate:
                    policy = candidate
            except Exception:  # noqa: BLE001 - retain deployment defaults on provider failure
                logger.warning("Could not resolve the live API rate-limit policy; using deployment defaults")
        rule = policy.get(category, self._static_policy["default"])
        identifier = self._get_client_identifier(request)

        # Class prefixes isolate budgets: traffic in one class cannot consume another.
        allowed, remaining, reset_time = self.rate_limiter.check_rate_limit(
            identifier,
            rule.limit,
            rule.window,
            prefix=f"rate_limit:api:{category}",
        )
        headers = self.rate_limiter.get_rate_limit_headers(
            rule.limit,
            remaining,
            reset_time,
        )

        if not allowed:
            retry_after = max(1, reset_time - int(time.time()))
            headers["Retry-After"] = str(retry_after)
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "retry_after": retry_after,
                },
                headers=headers,
            )

        response = await call_next(request)
        for header_name, header_value in headers.items():
            response.headers[header_name] = header_value
        
        return response


def rate_limit(
    limit: int,
    window: int = 60,
    per: str = "ip",
    key_prefix: str = "rate_limit:custom"
):
    """
    Decorator for endpoint-specific rate limiting.
    
    Usage:
        @app.get("/api/expensive-operation")
        @rate_limit(limit=10, window=60, per="user")
        async def expensive_operation():
            ...
    
    Args:
        limit: Maximum requests allowed
        window: Time window in seconds
        per: Rate limit per "ip" or "user"
        key_prefix: Redis key prefix
    """
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, **kwargs):
            # Find the Request object in kwargs
            request = kwargs.get("request") or next(
                (arg for arg in args if isinstance(arg, Request)), None
            )
            
            if not request:
                logger.warning(f"No request object found for rate limiting in {func.__name__}")
                return await func(*args, **kwargs)
            
            # Get identifier based on 'per' parameter (trusted-proxy-aware client IP).
            from app.core.net_utils import client_ip as _client_ip
            if per == "user" and hasattr(request.state, "user_id") and request.state.user_id:
                identifier = f"user:{request.state.user_id}"
            else:
                identifier = f"ip:{_client_ip(request)}"
            
            # Initialize rate limiter
            rate_limiter = RateLimiter(redis_client)
            
            # Check rate limit
            allowed, remaining, reset_time = rate_limiter.check_rate_limit(
                identifier,
                limit,
                window,
                prefix=key_prefix
            )
            
            if not allowed:
                retry_after = reset_time - int(time.time())
                headers = rate_limiter.get_rate_limit_headers(limit, 0, reset_time)
                headers["Retry-After"] = str(retry_after)
                
                raise HTTPException(
                    status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                    detail=f"Rate limit exceeded for {func.__name__}. Try again in {retry_after} seconds.",
                    headers=headers
                )
            
            # Call the original function
            return await func(*args, **kwargs)
        
        return wrapper
    return decorator


# Global rate limiter instance
rate_limiter = RateLimiter(redis_client)
