"""Shared helpers for the tests of POST /auth/sign-out (the API's and the web app's): a token's claims, the session
row a token names, a token the server signs with the claims a test chooses (an expired copy of a session's token
among them), the sign-outs recorded for an account, the cache's entries, and the auth requests' rate limit at the
value a vault ships with. Imported by the test modules that need them; holds no tests."""
import hashlib
import json
import subprocess
from contextlib import contextmanager

import jwt
import pytest

from _account_change_helpers import REDIS, in_api_container, psql
from conftest import skip_if_container_absent

# The auth requests' limit a vault ships with (RATE_LIMIT_API_AUTH in .env.example, app/core/config.py), a minute
# each; the test stacks raise it, so that the suite's own sign-ins are not refused.
SHIPPED_AUTH_LIMIT = 10


def claims(token):
    return jwt.decode(token, options={"verify_signature": False})


def session_digest(token):
    """The hash the server keeps of the session a token names."""
    return hashlib.sha256(claims(token)["session_token"].encode()).hexdigest()


def session_row(token):
    """(is_active, revoked) of the session a token names, as psql prints it: "t|f" is signed in."""
    return psql(f"SELECT is_active, revoked FROM active_sessions WHERE session_token = '{session_digest(token)}'")


def signed_by_the_server(chosen, minutes):
    """A token the server signs with the claims `chosen`, valid for `minutes` from now (negative: expired)."""
    out = in_api_container(
        "import json\n"
        "from datetime import timedelta\n"
        "from app.core.security import create_access_token\n"
        f"print(create_access_token(json.loads({json.dumps(json.dumps(chosen))}), timedelta(minutes={int(minutes)})))\n")
    return out.stdout.strip().splitlines()[-1]


def expired_copy(token):
    """The same session's token, signed by the server, expired five minutes ago."""
    return signed_by_the_server({k: v for k, v in claims(token).items() if k not in ("exp", "iat")}, -5)


def sign_outs_recorded(user_id):
    return int(psql(f"SELECT count(*) FROM audit_logs WHERE user_id = '{user_id}' AND action = 'logout'"))


def redis_cli(*args):
    """One redis-cli command in the stack's cache, its output stripped."""
    try:
        r = subprocess.run(["docker", "exec", REDIS, "redis-cli", *args], capture_output=True, text=True, timeout=30)
    except FileNotFoundError as exc:
        pytest.skip(f"docker unavailable: {exc}")
    except subprocess.TimeoutExpired as exc:
        pytest.fail(f"the command did not finish within {exc.timeout} s")
    skip_if_container_absent(r, REDIS)
    assert r.returncode == 0, r.stderr[:300]
    return r.stdout.strip()


def reset_auth_request_buckets():
    """Empty the auth requests' rate-limit buckets (the sign-out's among them), so that a test counts only its own."""
    r = subprocess.run(["docker", "exec", REDIS, "sh", "-c",
                        "redis-cli --scan --pattern 'rate_limit:api:auth*' | xargs -r redis-cli del"],
                       capture_output=True, text=True, timeout=30)
    skip_if_container_absent(r, REDIS)
    assert r.returncode == 0, r.stderr[:300]


@contextmanager
def shipped_auth_limit(admin):
    """The auth requests' limit set to the shipped one, a minute, through the administrators' override, with its
    buckets empty; put back as it was, and emptied again, after."""
    before = admin.get("/settings").json()
    restore = {key: before.get(key, 0) for key in ("rate_limit_api_auth", "rate_limit_api_auth_window")}
    r = admin.put("/settings", json={"rate_limit_api_auth": SHIPPED_AUTH_LIMIT, "rate_limit_api_auth_window": 60})
    assert r.status_code == 200, r.text
    reset_auth_request_buckets()
    try:
        yield SHIPPED_AUTH_LIMIT
    finally:
        put_back = admin.put("/settings", json=restore)
        reset_auth_request_buckets()
        assert put_back.status_code == 200, put_back.text
