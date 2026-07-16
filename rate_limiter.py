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
import uuid
from typing import Tuple, Optional, Dict
from datetime import datetime, timedelta
from functools import wraps

from fastapi import Request, HTTPException, status
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import Response, JSONResponse

from database import redis_client
from config import settings
import logging

logger = logging.getLogger(__name__)


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
# Redis host can stall getaddrinfo for several seconds per call). After a couple of
# consecutive Redis failures we OPEN the breaker and skip Redis entirely for a cooldown —
# so the fail-closed auth path drops to its DB fallback instantly, and general (fail-open)
# traffic isn't delayed at all. After the cooldown the next call probes Redis again
# (half-open); a success resets, a failure re-opens. The cooldown is comfortably longer than
# any burst of requests so the breaker stays open through an outage instead of re-probing
# (and re-stalling) every few requests. Process-local state — fine for our single worker.
_CB_FAIL_THRESHOLD = 2
# Cooldown the breaker stays open before a half-open probe. Long enough to outlast any burst of
# requests during an outage (so it stays open instead of re-probing/re-stalling every few
# requests), short enough that rate limiting resumes quickly after Redis recovers. With DNS now
# bounded to ~1s (RES_OPTIONS), a re-probe is cheap, so this can be modest.
_CB_COOLDOWN_SECONDS = 10
_cb_consecutive_failures = 0
_cb_open_until = 0.0


def _cb_is_open(now: float) -> bool:
    return now < _cb_open_until


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
            # Use pipeline for atomic operations
            pipe = self.redis.pipeline()

            # Remove old entries outside the window
            pipe.zremrangebyscore(key, 0, window_start)

            # Count current entries in the window
            pipe.zcard(key)

            # Execute pipeline
            results = pipe.execute()
            _cb_record_success()  # Redis is healthy — reset the breaker
            current_count = results[1]
            
            # Calculate remaining and reset time
            remaining = max(0, limit - current_count)
            reset_time = int(now + window)
            
            if current_count >= limit:
                # Rate limit exceeded
                return False, 0, reset_time
            
            # Add new entry with current timestamp as score
            entry_id = str(uuid.uuid4())
            self.redis.zadd(key, {entry_id: now})
            
            # Set expiration (cleanup)
            self.redis.expire(key, window + 1)
            
            remaining -= 1  # Account for the request we just added
            return True, remaining, reset_time
            
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
        exclude_paths: Optional[list] = None
    ):
        super().__init__(app)
        self.rate_limiter = rate_limiter
        self.default_limit = default_limit
        self.default_window = default_window
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
                from security import verify_access_token
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
        
        # Get client identifier
        identifier = self._get_client_identifier(request)
        
        # Check rate limit
        allowed, remaining, reset_time = self.rate_limiter.check_rate_limit(
            identifier,
            self.default_limit,
            self.default_window,
            prefix="rate_limit:api"
        )
        
        # Add rate limit headers
        headers = self.rate_limiter.get_rate_limit_headers(
            self.default_limit,
            remaining,
            reset_time
        )
        
        if not allowed:
            # Rate limit exceeded - return 429
            retry_after = reset_time - int(time.time())
            headers["Retry-After"] = str(retry_after)
            
            return JSONResponse(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                content={
                    "detail": "Rate limit exceeded. Please try again later.",
                    "retry_after": retry_after
                },
                headers=headers
            )
        
        # Process request
        response = await call_next(request)
        
        # Add rate limit headers to response
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
