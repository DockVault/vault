"""The audit as a contract: every on-loop Redis call site in app/ is classified and guarded.

During a Redis outage a synchronous Redis op on the event loop pays the socket timeout on the loop.
The sweep put every such site behind one of five treatments; this test walks app/ for Redis call
sites and fails if any site sits in a function that is not in the classification registry below --
so a NEW `<client>.<op>(` line (a new feature, or the next counter landing unthrottled by accident)
fails the suite until it is deliberately classified. Definition files (the client and the breaker)
and the helper modules are exempt: they ARE the guard.

Classes: A security counter (Redis->DB fallback, fail-closed); B anonymous lockout/grant (raise or
return the locked/absent value BEFORE the socket while open); C OTP store (routes to its DB path via
_resolve_redis when open); D best-effort (read-through guard, skip while open); E already correct
(guarded before the sweep, or skip-to-fallback), and the dead verify_session kept only for a
source-text security pin.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

# The raw client and the breaker live here; the read-through guard and the vault-attempt helper ARE
# the guard. All exempt from the walk.
_EXEMPT_FILES = {"database.py", "rate_limiter.py", "redis_guard.py", "vault_attempt_throttle.py"}

_CLIENTS = r"(?:redis_client|self\.redis|_redis_probe_client|\bredis\b|\br\b|\bpipe\b)"
_OPS = (r"(?:get|set|setex|setnx|incr|incrby|expire|delete|publish|eval|evalsha|exists|mget|scan|"
        r"pipeline|ping|hget|hset|hdel|ttl|persist|execute)")
_CALL = re.compile(rf"{_CLIENTS}\.{_OPS}\(")

# module (relative to app/) -> { enclosing function : class letter }. This IS the audit; a Redis
# site whose function is absent here fails the test.
_CLASSIFIED = {
    "api/api_server.py": {
        "_device_reuse_alert": "D",            # best-effort dedup, guard (fail-open)
        "_guarded_publish": "E", "_guarded_publish_force": "E",
        "_notelink_locked": "B", "_notelink_record_fail": "B", "_notelink_clear_fails": "B",
        "_publiclink_locked": "B", "_publiclink_record_fail": "B", "_publiclink_clear_fails": "B",
        "_publiclink_issue_grant": "B", "_publiclink_consume_grant": "B",
        "_receiver_locked": "B", "_receiver_record_fail": "B", "_receiver_clear_fails": "B",
        "upload_file": "E",                    # space reservation: skip the eval when open -> fallback
    },
    "core/otp_service.py": {
        "_redis_put": "C", "_redis_delete": "C", "_redis_consume_verify": "C",
    },
    "services/activity_monitor.py": {
        "broadcast_sync": "D", "start_operation": "D", "complete_operation": "D",
        "is_cancelled": "D", "cancel_operation": "D",
    },
    "services/auth_service.py": {
        "_create_session": "E", "_terminate_session": "E", "create_temporary_credential": "E",
        "mint_device_sync_credential": "E", "denylist_token": "E", "is_token_denylisted": "E",
        "verify_session": "E",                 # dead (no production caller); source-text security pin
    },
    "services/security_monitor.py": {
        "_broadcast_alert": "E", "_windowed_count": "E",
    },
    "sftp/sftp_server.py": {
        "_sftp_key_clear": "D",
    },
}


def _sites():
    found = []
    for path in sorted(APP.glob("**/*.py")):
        if path.name in _EXEMPT_FILES or "__pycache__" in path.parts:
            continue
        rel = path.relative_to(APP).as_posix()
        func = "<module>"
        for lineno, line in enumerate(path.read_text(encoding="utf-8").split("\n"), 1):
            m = re.match(r"\s*(?:async def|def)\s+(\w+)", line)
            if m:
                func = m.group(1)
            if _CALL.search(line):
                found.append((rel, func, lineno))
    return found


def test_every_redis_call_site_in_app_is_classified():
    unclassified = [
        f"{rel}:{lineno} in {func}()"
        for rel, func, lineno in _sites()
        if func not in _CLASSIFIED.get(rel, {})
    ]
    assert not unclassified, (
        "unclassified on-loop Redis call site(s) — put each behind the breaker/guard/helper and add "
        "its function to _CLASSIFIED with a class letter (A-E):\n  " + "\n  ".join(unclassified))


def test_the_registry_has_no_stale_entries():
    # A function listed here must still contain a Redis site, or the registry has rotted.
    live = {(rel, func) for rel, func, _ in _sites()}
    stale = [f"{rel}::{func}" for rel, funcs in _CLASSIFIED.items() for func in funcs
             if (rel, func) not in live]
    assert not stale, f"registry lists functions with no Redis site any more: {stale}"
