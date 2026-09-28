"""Cache keys that count failed sign-ins by name carry a keyed stand-in for the name, never the name,
offline.

A name typed at sign-in can be anything, a password typed into the name box included, and the cache
has no password by default. The stand-in is an HMAC-SHA256 under the deployment's pepper
(LOG_TOKEN_PEPPER, else a key derived from JWT_SECRET_KEY): stable, so the counts still match, and not
reversible or confirmable without the secret."""
import hashlib

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import name_keys, sign_in_lockout as L  # noqa: E402
from app.core.config import settings  # noqa: E402
from app.services import auth_service as A  # noqa: E402

pytestmark = pytest.mark.unit

TYPED = "Hunter2!Pass-typed-in-the-name-box"


def test_the_stand_in_is_stable_keyed_and_never_the_name(monkeypatch):
    monkeypatch.setattr(settings, "log_token_pepper", "p" * 40)
    first = name_keys.name_key(TYPED)
    assert first == name_keys.name_key(TYPED) and len(first) == 32
    assert TYPED not in first
    assert first != name_keys.name_key("hunter2!pass-typed-in-the-name-box"), "names differ by case"
    assert first not in (hashlib.sha256(TYPED.encode()).hexdigest()[:32], hashlib.md5(TYPED.encode()).hexdigest())
    monkeypatch.setattr(settings, "log_token_pepper", "q" * 40)
    assert name_keys.name_key(TYPED) != first, "another deployment's secret gives another stand-in"


def test_without_a_log_pepper_the_jwt_secret_keys_it(monkeypatch):
    monkeypatch.setattr(settings, "log_token_pepper", "")
    monkeypatch.setattr(settings, "jwt_secret_key", "j" * 40)
    one = name_keys.name_key(TYPED)
    monkeypatch.setattr(settings, "jwt_secret_key", "k" * 40)
    assert name_keys.name_key(TYPED) != one


def test_no_sign_in_cache_key_carries_the_typed_name():
    keys = list(L._phantom_keys(TYPED, "203.0.113.9")) + [A.login_user_key(TYPED, "203.0.113.9"),
                                                          A.login_user_key(TYPED, "203.0.113.9", prefixed=False)]
    for key in keys:
        assert TYPED not in key and name_keys.name_key(TYPED) in key, key
    assert keys[0].endswith("|" + name_keys.name_key(TYPED)) and "203.0.113.9" in keys[0]


def test_a_known_temporary_name_is_throttled_under_its_stand_in(monkeypatch):
    from app.core import rate_limiter as rl

    seen = []

    class _Limiter:
        def check_rate_limit(self, key, *a, **k):
            seen.append(key)
            return True, 1, 0

    monkeypatch.setattr(rl, "rate_limiter", _Limiter())
    monkeypatch.setattr(A.rate_limit_settings, "effective", lambda name: 5 if "attempts" in name else 60)
    A.AuthService.__new__(A.AuthService)._check_username_rate_limit(TYPED)
    assert seen == [f"login_user:{name_keys.name_key(TYPED)}"]


def test_the_security_monitors_counter_key_carries_no_name(monkeypatch):
    from app.services import security_monitor as sm
    keys = []
    mon = sm.SecurityMonitor.__new__(sm.SecurityMonitor)
    mon.failed_login_window_minutes = 10
    mon.failed_login_threshold_critical = 1000
    mon.failed_login_threshold_warning = 1000
    mon._login_attempts = __import__("collections").defaultdict(list)
    monkeypatch.setattr(mon, "_windowed_count", lambda key, window, trail: keys.append(key) or 1, raising=False)
    mon.record_failed_login(TYPED, "203.0.113.9", "bad password")
    assert keys and TYPED not in keys[0] and name_keys.name_key(TYPED) in keys[0]
