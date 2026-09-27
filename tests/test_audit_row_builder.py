"""AuditLogger.build_row gives the row log_action writes, without adding or committing it.

log_action commits on its own. An automatic account lock and the file-expiry sweep record their audit
rows in the transaction that makes their change, so the change and its record commit together or not
at all. They build the row with build_row and add it to their own session, and it must be exactly the
row log_action would have stored for the same arguments: names stripped from `details`, the acting
user's name and temporary credential, and the request's channel, method, route, user agent and address.
"""
import uuid
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core import net_utils
from app.core import request_context as rc
from app.core.models import AuditLog
from app.services.audit_logger import REDACTED_NAME_KEYS, AuditLogger

pytestmark = pytest.mark.unit

# Every stored column but the two that differ by construction: the id (set on insert) and the time.
COLUMNS = [c.name for c in AuditLog.__table__.columns if c.name not in ("id", "timestamp")]


class _Session:
    """Records what is added and committed, and answers the username lookup for the ids it knows."""

    def __init__(self, users=None):
        self.added, self.commits, self.users, self.asked = [], 0, users or {}, []

    def add(self, obj):
        self.added.append(obj)

    def commit(self):
        self.commits += 1

    def query(self, *_cols):
        db = self

        class _Q:
            def filter(self, cond):
                db.asked.append(cond.right.value)
                return self

            def scalar(self):
                return db.users.get(db.asked[-1])
        return _Q()


class _Route:
    path = "/auth/login"


def _columns(row):
    return {c: getattr(row, c) for c in COLUMNS}


def _both(users=None, **kwargs):
    """(the row log_action stores, the row build_row returns) for the same arguments."""
    logged = AuditLogger(_Session(users)).log_action(**kwargs)
    built = AuditLogger(_Session(users)).build_row(**kwargs)
    return logged, built


def test_during_a_web_request_the_built_row_is_the_logged_row():
    user = SimpleNamespace(id=uuid.uuid4(), username="maria", _temp_cred_id=uuid.uuid4())
    details = {"reason": "wrong password", **{k: "secret name" for k in REDACTED_NAME_KEYS}}
    ctx = rc.set_request_context(rc.RequestContext("POST", "/auth/login", "Mozilla/5.0", "web",
                                                   {"route": _Route()}))
    ip = net_utils.set_client_ip("198.51.100.23")
    try:
        logged, built = _both(action="login_failure", status="failure", user=user,
                              resource_type="user", resource_id="1", details=details,
                              error_message="Invalid username or password")
    finally:
        net_utils.reset_client_ip(ip)
        rc.reset_request_context(ctx)

    assert _columns(built) == _columns(logged)
    # What they agree on is what the logger applies, not a pair of empty rows.
    assert (built.channel, built.method, built.endpoint, built.user_agent, built.ip_address) == (
        "web", "POST", "/auth/login", "Mozilla/5.0", "198.51.100.23")
    assert (built.user_id, built.username, built.temp_credential_id) == (
        user.id, "maria", user._temp_cred_id)
    assert built.details == {"reason": "wrong password"}
    assert set(details) > {"reason"}, "the caller's own dict is left as it was"


def test_in_the_sftp_process_with_only_an_id_the_built_row_is_the_logged_row():
    uid = uuid.uuid4()
    try:
        rc.set_process_default_channel("sftp")
        logged, built = _both(users={uid: "nikos"}, action="account_auto_locked", status="success",
                              user_id=uid, resource_type="user", resource_id=str(uid),
                              ip_address="203.0.113.7", details={"failed_attempts": 5})
    finally:
        rc.set_process_default_channel(None)

    assert _columns(built) == _columns(logged)
    assert (built.channel, built.username, built.ip_address) == ("sftp", "nikos", "203.0.113.7")
    assert (built.method, built.endpoint, built.user_agent) == (None, None, None)


def test_outside_any_request_the_built_row_is_the_logged_row():
    logged, built = _both(action="file_expired", status="success", resource_type="file",
                          resource_id="f1", details={"vault_id": "v1", "expires_at": "2026-09-26T11:00:00"})
    assert _columns(built) == _columns(logged)
    assert (built.channel, built.user_id, built.username, built.ip_address) == (None, None, None, None)


def test_building_a_row_neither_adds_nor_commits_it():
    db = _Session()
    row = AuditLogger(db).build_row(action="file_expired", status="success")
    assert isinstance(row, AuditLog)
    assert (db.added, db.commits) == ([], 0)

    logged = AuditLogger(db).log_action(action="file_expired", status="success")
    assert (db.added, db.commits) == ([logged], 1), "log_action is the same row, added and committed"


def test_a_built_row_is_timed_now_unless_the_caller_gives_the_time():
    before = datetime.now(timezone.utc)
    row = AuditLogger(_Session()).build_row(action="file_expired", status="success")
    assert before <= row.timestamp <= datetime.now(timezone.utc) + timedelta(seconds=1)

    at = datetime(2026, 9, 26, 12, 0)
    assert AuditLogger(_Session()).build_row(action="file_expired", status="success",
                                             timestamp=at).timestamp == at
