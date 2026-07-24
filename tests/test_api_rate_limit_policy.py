"""Pure contracts for the general API rate-limit classifier and policy cache."""

import pytest
from starlette.requests import Request

from app.core.rate_limiter import (
    API_RATE_LIMIT_MAX_REQUESTS,
    API_RATE_LIMIT_MAX_WINDOW_SECONDS,
    ApiRateLimitPolicyCache,
    RateLimitMiddleware,
    RateLimitRule,
    classify_api_rate_limit,
    resolve_api_rate_limit_policy,
)


pytestmark = pytest.mark.unit


@pytest.mark.parametrize(
    ("method", "path", "expected"),
    [
        ("POST", "/auth/login", "auth"),
        ("GET", "/auth/session", "auth"),
        ("POST", "/auth/temp-credentials", "auth"),
        ("POST", "/api/logout", "auth"),
        ("POST", "/vaults/v/files", "upload"),
        ("POST", "/vaults/v/uploads", "upload"),
        ("PUT", "/vaults/v/uploads/s/chunks/0", "upload"),
        ("POST", "/vaults/v/uploads/s/complete", "upload"),
        ("GET", "/vaults/v/files/f/download", "download"),
        ("GET", "/vaults/v/files", "default"),
        ("DELETE", "/vaults/v/uploads/s", "default"),
        ("GET", "/api/dashboard/stats", "default"),
    ],
)
def test_classifier_has_one_deterministic_class(method, path, expected):
    assert classify_api_rate_limit(method, path) == expected


def test_classifier_precedence_and_method_are_explicit():
    assert classify_api_rate_limit("POST", "/auth/files/f/download") == "auth"
    assert classify_api_rate_limit("POST", "/vaults/v/files/f/download") == "default"
    assert classify_api_rate_limit("GET", "/vaults/v/uploads") == "default"


def _defaults():
    return {
        "default": RateLimitRule(100, 60),
        "auth": RateLimitRule(10, 60),
        "upload": RateLimitRule(20, 60),
        "download": RateLimitRule(50, 60),
    }


def test_zero_and_invalid_stored_values_fall_back_per_field():
    policy = resolve_api_rate_limit_policy(
        _defaults(),
        {
            "rate_limit_api_default": 7,
            "rate_limit_api_default_window": 0,
            "rate_limit_api_auth": True,
            "rate_limit_api_auth_window": "5",
            "rate_limit_api_upload": -1,
            "rate_limit_api_upload_window": 9,
            "rate_limit_api_download": API_RATE_LIMIT_MAX_REQUESTS + 1,
            "rate_limit_api_download_window": API_RATE_LIMIT_MAX_WINDOW_SECONDS + 1,
        },
    )
    assert policy["default"] == RateLimitRule(7, 60)
    assert policy["auth"] == RateLimitRule(10, 60)
    assert policy["upload"] == RateLimitRule(20, 9)
    assert policy["download"] == RateLimitRule(50, 60)


def test_policy_cache_is_bounded_and_replace_is_immediate():
    now = [100.0]
    loads = []
    stored = {"rate_limit_api_default": 9}

    def load():
        loads.append(now[0])
        return dict(stored)

    cache = ApiRateLimitPolicyCache(
        _defaults(),
        load,
        ttl_seconds=5,
        clock=lambda: now[0],
    )
    assert cache.get()["default"].limit == 9
    assert cache.get()["default"].limit == 9
    assert loads == [100.0]

    cache.replace({"rate_limit_api_default": 4, "rate_limit_api_auth_window": 12})
    assert cache.get()["default"].limit == 4
    assert cache.get()["auth"].window == 12
    assert loads == [100.0]

    stored["rate_limit_api_default"] = 11
    now[0] += 6
    assert cache.get()["default"].limit == 11
    assert loads == [100.0, 106.0]


def test_policy_cache_keeps_last_known_policy_when_reload_fails():
    now = [0.0]
    fail = [False]

    def load():
        if fail[0]:
            raise RuntimeError("database unavailable")
        return {"rate_limit_api_download": 3}

    cache = ApiRateLimitPolicyCache(
        _defaults(),
        load,
        ttl_seconds=2,
        clock=lambda: now[0],
    )
    assert cache.get()["download"].limit == 3
    fail[0] = True
    now[0] = 3.0
    assert cache.get()["download"].limit == 3


def _request(*, authorization=None):
    headers = []
    if authorization is not None:
        headers.append((b"authorization", authorization.encode()))
    return Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/users/me",
            "headers": headers,
            "client": ("192.0.2.10", 1234),
            "scheme": "https",
            "server": ("vault.example", 443),
        }
    )


def test_identity_uses_authenticated_user_and_unauthenticated_ip(monkeypatch):
    middleware = object.__new__(RateLimitMiddleware)
    monkeypatch.setattr("app.core.security.verify_access_token", lambda _token: {"sub": "user-123"})
    monkeypatch.setattr("app.core.net_utils.client_ip", lambda _request: "198.51.100.9")

    assert middleware._get_client_identifier(_request(authorization="Bearer valid")) == "user:user-123"
    assert middleware._get_client_identifier(_request()) == "ip:198.51.100.9"
