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

from app.core.database import redis_client, redis_probe_ping

import logging

logger = logging.getLogger(__name__)

API_RATE_LIMIT_CLASSES = ("default", "auth", "upload", "upload_chunk", "download", "poll")
API_RATE_LIMIT_MAX_REQUESTS = 1_000_000
API_RATE_LIMIT_MAX_WINDOW_SECONDS = 86_400


@dataclass(frozen=True)
class RateLimitRule:
    limit: int
    window: int


# GET endpoints the UI POLLS on a timer (or fetches in bursts) — security events, notifications,
# audit, monitor stats. They get their own lenient bucket so normal polling + browsing never trips
# the shared "default" bucket. Matched exactly (path already stripped of any trailing slash).
POLL_GET_PATHS = frozenset({
    "/audit/events", "/audit/log",
    "/notifications", "/notifications/unread-count",
    "/monitor/stats",
    "/api/security/metrics", "/api/security/alerts", "/api/monitoring/metrics",
})


def classify_api_rate_limit(method: str, path: str) -> str:
    """Return one general-API class with auth > upload(_chunk) > download > poll > default precedence.

    Auth covers every /auth route plus logout. A resumable upload's per-CHUNK PUTs go to their own
    high-limit `upload_chunk` bucket (one upload is dozens–thousands of requests, so they must NOT
    share the small operation-level `upload` bucket used for init/complete — that throttled large
    files mid-transfer). Download covers the file-content GET. Poll covers the timer-polled read
    endpoints. Everything else is default; method checks prevent lookalike paths changing class.
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
            return "upload_chunk"   # each chunk PUT — high-volume, its own bucket
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
    if method == "GET" and path in POLL_GET_PATHS:
        return "poll"
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
# Paying the Redis socket timeout on EVERY request during an outage makes the whole server crawl (and
# the timeout does not even bound DNS: a dead host can stall getaddrinfo for seconds per call). So
# after the first failure we OPEN the breaker and skip Redis entirely: the fail-closed auth path
# drops to its DB fallback at once, and fail-open traffic is not delayed. That FIRST failing call
# still pays one socket timeout to discover the outage -- the unavoidable one: it is paid ONCE PER
# OUTAGE (at discovery), not once per cooldown, which is the recurring stall this design removes.
#
# Closing it must NOT be a timer. If the breaker simply lapsed after a cooldown, the first foreground
# caller to touch Redis afterwards -- typically RateLimitMiddleware.dispatch's synchronous check, ON
# the event loop, on every route -- would pay the socket timeout again to rediscover an ongoing
# outage, freezing the server for ~one timeout every cooldown, for everyone. Instead a single
# BACKGROUND daemon thread heals the breaker: while open it waits a cooldown, pings Redis on its own
# short-timeout connection, and closes the breaker only on success (else it stays open and tries
# again). No foreground request ever pays the discovery stall; the server recovers while idle rather
# than on a victim request; and a plain sleep is enough for a caller to wait the breaker out. It is a
# thread (not an event-loop task) so the API and the SFTP process behave the same, one per process
# (guarded by a lock), and a daemon so process shutdown never waits on it. Process-local state.
_CB_FAIL_THRESHOLD = 1
# Cooldown the breaker stays open before each health probe. Long enough to outlast a burst, short
# enough that rate limiting resumes promptly once Redis recovers.
_CB_COOLDOWN_SECONDS = 10
# The probe's own timeout, kept short so the background thread never lingers -- independent of the
# main client's (longer) socket timeout for real work.
_CB_PROBE_TIMEOUT_SECONDS = 1.0
_cb_consecutive_failures = 0
_cb_open = False                 # True while the breaker is skipping Redis
_cb_lock = threading.Lock()      # guards the open flag, the failure count and the single probe thread
_cb_probe_thread = None          # the one background probe thread while open, else None/dead
_cb_last_attempt_at = 0.0        # when a probe last tried (or the breaker last opened); staleness stamp
# The breaker has no timer and the probe is its only closer, and while open no foreground caller
# records failures -- so ANY state of "open with no working probe" is permanent, not transient. That
# can arise three ways: a Thread.start() that raised (thread exhaustion), a probe hung inside a
# connect whose DNS lookup the socket timeout does not bound, or a failure racing the probe's exit.
# The exit race is fixed structurally (see _cb_probe_loop); the other two are covered by a STATE
# backstop rather than a patch per path: every probe attempt stamps _cb_last_attempt_at, and if the
# breaker is open with no attempt in a long while, _cb_is_open unwedges it. Kept well above the
# cooldown so a healthy probe (which stamps every cooldown, even against a down Redis) never trips it.
_CB_PROBE_STALE_SECONDS = 6 * _CB_COOLDOWN_SECONDS


def _cb_is_open(now: float) -> bool:
    """Whether to skip Redis right now.

    Fast path: the background probe, not the caller, closes the breaker, so no foreground request
    touches the socket to rediscover an outage. But an "open with no working probe" state would be
    permanent (see the module note), so when the breaker has been open with no probe attempt for
    longer than ``_CB_PROBE_STALE_SECONDS`` this unwedges it: it restarts a probe that has died or
    never started (and stays skipping), or -- if a probe is alive but stuck (a hung connect) -- lets
    THIS one caller re-probe Redis directly (returns False), a bounded once-per-stale-period stall
    that is the price of never wedging. The stamp is reset so only one caller pays it per period."""
    global _cb_probe_thread, _cb_last_attempt_at
    if not _cb_open:
        return False
    if now - _cb_last_attempt_at <= _CB_PROBE_STALE_SECONDS:
        return True
    with _cb_lock:
        if not _cb_open:
            return False
        if now - _cb_last_attempt_at <= _CB_PROBE_STALE_SECONDS:
            return True  # another caller refreshed the stamp while we waited on the lock
        _cb_last_attempt_at = now  # only one caller acts per stale period
        if _cb_probe_thread is None or not _cb_probe_thread.is_alive():
            # The probe died or never started: restart it (start errors are swallowed inside
            # _cb_ensure_probe_locked, which leaves the slot None to retry) and keep skipping.
            _cb_probe_thread = None
            _cb_ensure_probe_locked()
            return True
        # A probe is alive but has not attempted in a stale period -- it is stuck (e.g. a hung DNS
        # lookup). Let this one caller re-probe Redis the old way so recovery is not hostage to it.
        logger.warning("rate-limiter breaker probe appears stuck; allowing one foreground re-probe")
        return False


def redis_circuit_open() -> bool:
    """Return whether this process is currently skipping Redis after a backend failure."""
    return _cb_is_open(time.time())


def _cb_record_success() -> None:
    """Redis is proven healthy (a live op, or the background probe, succeeded): close the breaker."""
    global _cb_consecutive_failures, _cb_open
    with _cb_lock:
        _cb_consecutive_failures = 0
        _cb_open = False


def _cb_record_failure(now: float) -> None:
    """Record a Redis failure; open the breaker and start the background probe once the threshold is
    hit. Stamps the staleness clock on opening so the backstop starts counting even if the probe
    never runs (a start that raised); `now` otherwise does not drive recovery -- the probe does."""
    global _cb_consecutive_failures, _cb_open, _cb_last_attempt_at
    with _cb_lock:
        _cb_consecutive_failures += 1
        if _cb_consecutive_failures >= _CB_FAIL_THRESHOLD:
            if not _cb_open:
                _cb_last_attempt_at = now
            _cb_open = True
            _cb_ensure_probe_locked()


def _cb_ensure_probe_locked() -> None:
    """Start the single background probe thread if the slot is empty. The caller holds ``_cb_lock``.

    Keys on the slot being None -- which only a cleanly exiting probe sets, under this same lock --
    NOT on ``is_alive()``. A thread stays alive for a moment after it has decided to exit; a failure
    racing into that window must still get a probe, and the None slot (set atomically with the exit
    decision) is the one consistent signal for "no probe is running or about to"."""
    global _cb_probe_thread
    if _cb_probe_thread is not None:
        return
    thread = threading.Thread(target=_cb_probe_loop, name="redis-cb-probe", daemon=True)
    try:
        thread.start()
    except Exception:  # noqa: BLE001 — thread exhaustion must not escape into the request path
        # Leave the slot None so this never wedges: the next failure, or the staleness backstop in
        # _cb_is_open, retries the start rather than the breaker sitting open with no probe.
        logger.warning("rate-limiter breaker probe thread could not be started; will retry")
        return
    _cb_probe_thread = thread


def _cb_ping() -> None:
    """Ping Redis on the dedicated short-timeout connection; raise on failure. A seam for tests."""
    redis_probe_ping(_CB_PROBE_TIMEOUT_SECONDS)


def _cb_probe_sleep(seconds: float) -> None:
    """The probe's wait between attempts. A seam so a test can drive the loop without real time."""
    time.sleep(seconds)


def _cb_probe_post_success() -> None:
    """Runs right after a probe records success, before the loop re-checks the breaker. A no-op in
    production; a seam so a test can inject a failure into the exact window this design closes."""


def _cb_probe_attempt() -> bool:
    """One probe attempt: ping Redis; on success close the breaker and return True, else return
    False (the breaker stays open). Split out from the loop so a test can drive one attempt.

    Stamps the staleness clock before the ping, so a probe that then hangs inside the ping (a connect
    whose DNS lookup the socket timeout does not bound) still lets _cb_is_open notice it went stale."""
    global _cb_last_attempt_at
    with _cb_lock:
        _cb_last_attempt_at = time.time()
    try:
        _cb_ping()
    except Exception:
        return False
    _cb_record_success()
    _cb_probe_post_success()
    return True


def _cb_probe_loop() -> None:
    """Background: while the breaker is open, wait a cooldown then probe Redis; close on success and
    exit, else stay open and try again. One per process, daemon.

    The exit decision and the thread slot move together under ``_cb_lock``: the loop leaves ONLY by
    finding the breaker closed while holding the lock, and clears the slot in the same critical
    section. So a failure that races in just after a probe's success re-opened the breaker either (a)
    runs before this check and finds the slot still set (no duplicate probe) while this thread, seeing
    the breaker open again, keeps looping; or (b) runs after it and finds the slot None, and starts a
    fresh probe. Without that, a probe could decide to exit while a racing failure re-opened the
    breaker and started nothing -- leaving it open forever, since no foreground caller touches the
    socket to record another failure. Sleeping before the probe also means a breaker a live success
    closed during the wait exits without a ping."""
    global _cb_probe_thread
    while True:
        with _cb_lock:
            if not _cb_open:
                _cb_probe_thread = None
                return
        _cb_probe_sleep(_CB_COOLDOWN_SECONDS)
        _cb_probe_attempt()


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
        upload_chunk_limit: Optional[int] = None,
        upload_chunk_window: Optional[int] = None,
        download_limit: Optional[int] = None,
        download_window: Optional[int] = None,
        poll_limit: Optional[int] = None,
        poll_window: Optional[int] = None,
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
            "upload_chunk": RateLimitRule(
                upload_chunk_limit if upload_chunk_limit is not None else default_limit,
                upload_chunk_window if upload_chunk_window is not None else default_window,
            ),
            "download": RateLimitRule(
                download_limit if download_limit is not None else default_limit,
                download_window if download_window is not None else default_window,
            ),
            "poll": RateLimitRule(
                poll_limit if poll_limit is not None else default_limit,
                poll_window if poll_window is not None else default_window,
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
