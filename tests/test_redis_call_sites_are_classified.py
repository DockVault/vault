"""The audit as a contract: every on-loop Redis call site in app/ is classified, guarded, and counted.

A synchronous Redis op on the event loop pays the socket timeout on the loop during an outage. The
sweep put every such site behind one of five treatments; this test walks app/ and fails if any site
sits in a function not in the registry below, OR if a registered function's site COUNT changes -- so
a NEW `<client>.<op>(` line, whether in a new function or added inside an already-classified one (the
exact place the next counter would land unthrottled by accident), fails the suite until it is
deliberately classified. Definition/helper files (the client, the breaker, the guard, the
vault-attempt helper) are exempt: they ARE the guard.

Detection matches ANY attribute call on a client handle (rather than a verb allow-list, which missed
hgetall/hincrby/pubsub), minus a short list of non-command plumbing (pipeline/execute, the Lua
redis.call/pcall, and .read which is an HTTP-response method a bare `r` handle also has). Each site is
attributed to its OUTERMOST def (module function or class method), so a redis call inside a closure
counts against the function that owns it.

Classes: A security counter (Redis->DB fallback, fail-closed; its sites call the helper, so none
appear here); B anonymous lockout/grant (raise or return the locked/absent value BEFORE the socket
while open); C OTP store (routes to its DB path via _resolve_redis when open); D best-effort
(read-through guard, skip while open); E already-correct (guarded before the sweep, skip-to-fallback,
off-loop pubsub/listener, or the dead verify_session kept only for a source-text security pin).
"""
import ast
import re
from collections import Counter
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = ROOT / "app"

_EXEMPT_FILES = {"database.py", "rate_limiter.py", "redis_guard.py", "vault_attempt_throttle.py"}
_CALL = re.compile(
    r"(?:redis_client|self\.redis|_redis_probe_client|\bredis\b|\br\b|\bpipe\b)\.([a-z_]+)\(")
# Not Redis commands that touch the socket in their own right: the pipeline constructor and its flush
# (the queued commands are counted individually), the Lua redis.call/pcall inside script strings, and
# .read (a bare `r` handle is also used for urllib HTTP responses, which have .read()).
_NON_OPS = {"pipeline", "execute", "call", "pcall", "read"}

# module (relative to app/) -> { outermost function : (class letter, expected site count) }.
_REGISTRY = {
    "api/api_server.py": {
        "_device_reuse_alert": ("D", 2),
        "_guarded_publish": ("E", 1), "_guarded_publish_force": ("E", 1),
        "_notelink_locked": ("B", 1), "_notelink_record_fail": ("B", 2), "_notelink_clear_fails": ("B", 1),
        "_publiclink_locked": ("B", 1), "_publiclink_record_fail": ("B", 2), "_publiclink_clear_fails": ("B", 1),
        "_publiclink_issue_grant": ("B", 1), "_publiclink_consume_grant": ("B", 2),
        "_receiver_locked": ("B", 1), "_receiver_record_fail": ("B", 2), "_receiver_clear_fails": ("B", 1),
        "upload_file": ("E", 3),                 # space reservation: skip the eval when open -> fallback
        "websocket_monitor_endpoint": ("E", 1),  # .pubsub() off-loop (subscribe/get via run_in_executor)
    },
    "core/otp_service.py": {
        "_redis_put": ("C", 4), "_redis_load": ("C", 1),
        "_redis_delete": ("C", 1), "_redis_consume_verify": ("C", 2),
    },
    "services/activity_monitor.py": {
        "broadcast_sync": ("D", 1), "start_operation": ("D", 1), "complete_operation": ("D", 1),
        "is_cancelled": ("D", 1), "cancel_operation": ("D", 1),
    },
    "services/auth_service.py": {
        "_create_session": ("E", 1), "_terminate_session": ("E", 1),
        "create_temporary_credential": ("E", 1), "mint_device_sync_credential": ("E", 1),
        "denylist_token": ("E", 1), "is_token_denylisted": ("E", 1),
        "verify_session": ("E", 2),              # dead (no production caller); source-text security pin
    },
    "services/security_monitor.py": {
        "_broadcast_alert": ("E", 1), "_windowed_count": ("E", 2),
    },
    "sftp/sftp_server.py": {
        "_sftp_key_clear": ("D", 1),
        "listen_for_terminations": ("E", 1),     # the termination listener's own client, off-loop thread
    },
}


def _outer_defs(src):
    """(start, end, name) for every module-level function and class method -- the OUTERMOST defs; a
    site inside a nested closure maps to whichever of these contains it."""
    out = []
    for node in ast.parse(src).body:
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            out.append((node.lineno, node.end_lineno, node.name))
        elif isinstance(node, ast.ClassDef):
            for child in node.body:
                if isinstance(child, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    out.append((child.lineno, child.end_lineno, child.name))
    return out


def _site_counts():
    counts = Counter()
    for path in sorted(APP.glob("**/*.py")):
        if path.name in _EXEMPT_FILES or "__pycache__" in path.parts:
            continue
        src = path.read_text(encoding="utf-8")
        defs = _outer_defs(src)
        rel = path.relative_to(APP).as_posix()
        for lineno, line in enumerate(src.split("\n"), 1):
            for m in _CALL.finditer(line):
                if m.group(1) in _NON_OPS:
                    continue
                func = next((n for s, e, n in defs if s <= lineno <= e), "<module>")
                counts[(rel, func)] += 1
    return counts


def test_every_redis_call_site_is_classified_with_the_expected_count():
    counts = _site_counts()
    problems = []
    for (rel, func), n in sorted(counts.items()):
        entry = _REGISTRY.get(rel, {}).get(func)
        if entry is None:
            problems.append(f"{rel}::{func} — {n} Redis site(s), UNCLASSIFIED (add it with a class A-E)")
        elif entry[1] != n:
            problems.append(f"{rel}::{func} — {n} Redis site(s), registry expects {entry[1]} "
                            f"(class {entry[0]}): a line was added/removed; re-check the guard and the count")
    assert not problems, "Redis call-site audit failed:\n  " + "\n  ".join(problems)


def test_the_registry_has_no_stale_entries():
    live = _site_counts()
    stale = [f"{rel}::{func}" for rel, funcs in _REGISTRY.items() for func in funcs
             if (rel, func) not in live]
    assert not stale, f"registry lists functions with no Redis site any more: {stale}"
