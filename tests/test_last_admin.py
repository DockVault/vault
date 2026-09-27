"""The deployment always keeps one administrator who can act.

Only an administrator can make another administrator, unlock an account or reactivate one, so a
change that removes the last administrator who can still sign in leaves nobody able to undo it. Two
rules now hold on every route that can make such a change:

  * an administrator cannot change their own role, deactivate or lock themselves -- the dedicated
    role, activate and lock endpoints already refused this, but PATCH /users/{id} and
    PUT /api/user-management/users/{id} did not;
  * demoting, deactivating, locking or deleting an administrator is refused when no other active,
    unlocked administrator would remain, counted under a lock on the administrator rows.

This file drives the shared rule (app/core/last_admin.py) against the real users table in a
throwaway SQLite database, pins that each route asks it before it changes anything, and calls each
of the six routes with the rule answering yes, expecting a refusal and no write.
test_last_admin_live.py drives the routes against a running deployment.
"""
import re
import tempfile
import types
import uuid
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import last_admin as L  # noqa: E402
from app.core.models import RoleEnum, User  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
API = ROOT / "app" / "api" / "api_server.py"
USER_MGMT = ROOT / "app" / "api" / "user_management_api.py"


def _now():
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _person(role=RoleEnum.ADMIN, **kw):
    base = dict(id=uuid.uuid4(), role=role, is_active=True, is_locked=False, locked_until=None)
    base.update(kw)
    return types.SimpleNamespace(**base)


# --------------------------------------------------------------------------- who can act

# A timed lock is given as minutes from now and built when the test runs: a deadline computed at
# collection has already passed by the time a long suite reaches this test.
@pytest.mark.parametrize("fields,lock_minutes,able", [
    ({}, None, True),
    ({"role": RoleEnum.USER}, None, False),
    ({"role": RoleEnum.EXTERNAL}, None, False),
    ({"is_active": False}, None, False),
    ({"is_locked": True}, None, False),        # an admin's lock
    ({"is_locked": True}, 5, False),           # a running timed lock
    ({"is_locked": True}, -5, True),           # one that ran out
])
def test_who_can_administer(fields, lock_minutes, able):
    if lock_minutes is not None:
        fields = dict(fields, locked_until=_now() + timedelta(minutes=lock_minutes))
    assert L.can_administer(_person(**fields)) is able


def test_the_last_able_admin_is_the_only_one_who_can_act():
    a, b = _person(), _person()
    assert L.is_last_able_admin([a, b], a.id) is False
    assert L.is_last_able_admin([a, _person(id=b.id, is_active=False)], a.id) is True
    assert L.is_last_able_admin([a, _person(id=b.id, is_locked=True)], a.id) is True
    # Someone who cannot act is never "the last": removing them removes nobody who could.
    locked = _person(is_locked=True)
    assert L.is_last_able_admin([locked, a], locked.id) is False
    assert L.is_last_able_admin([locked], locked.id) is False
    assert L.is_last_able_admin([], a.id) is False


# --------------------------------------------------------------------------- against the table

@pytest.fixture
def Session():
    """A file-backed database, so two sessions can see each other's commits."""
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'admins.db'}")
        User.__table__.create(engine)
        yield sessionmaker(bind=engine, autocommit=False, autoflush=False)
        engine.dispose()


def _add(Session, role=RoleEnum.ADMIN, **kw):
    s = Session()
    u = User(username=f"u_{uuid.uuid4().hex[:8]}", password_hash="x", role=role, **kw)
    s.add(u)
    s.commit()
    uid = u.id
    s.close()
    return uid


def _removes(Session, uid):
    s = Session()
    try:
        return L.removes_last_admin(s, s.query(User).filter(User.id == uid).first())
    finally:
        s.close()


def test_counts_the_other_administrators_who_can_act(Session):
    a = _add(Session)
    b = _add(Session)
    user = _add(Session, role=RoleEnum.USER)
    assert _removes(Session, a) is False
    assert _removes(Session, user) is False, "a regular user is not an administrator to remove"

    s = Session()
    s.query(User).filter(User.id == b).update({"is_locked": True})
    s.commit()
    s.close()
    assert _removes(Session, a) is True, "a locked administrator cannot take over"
    assert _removes(Session, b) is False, "removing a locked administrator removes nobody who could act"


@pytest.mark.parametrize("change", [{"is_active": False}, {"is_locked": True}, {"role": RoleEnum.USER}])
def test_the_count_reads_the_rows_as_they_stand_not_as_this_session_loaded_them(Session, change):
    """The race the lock is for: two administrators deactivate, lock or demote each other at the same
    moment. The one that runs second has already loaded both as able administrators; when it counts,
    it must see the other change, which has committed meanwhile. Without populate_existing() the
    count would read the stale copies it holds for the first two."""
    a = _add(Session)
    b = _add(Session)
    second = Session()
    try:
        target = second.query(User).filter(User.id == a).first()
        other = second.query(User).filter(User.id == b).first()   # loaded before the other commit
        assert L.can_administer(other)

        first = Session()
        first.query(User).filter(User.id == b).update(change)
        first.commit()
        first.close()

        assert L.removes_last_admin(second, target) is True
    finally:
        second.close()


def test_the_rule_locks_every_administrator_row_in_a_fixed_order():
    src = (ROOT / "app" / "core" / "last_admin.py").read_text(encoding="utf-8")
    body = src[src.index("def removes_last_admin"):]
    assert re.search(r"\.filter\(User\.role == RoleEnum\.ADMIN\)\.order_by\(User\.id\)\s*"
                     r"\.populate_existing\(\)\.with_for_update\(\)\.all\(\)", body)


# --------------------------------------------------------------------------- the routes ask first

def _route(path, marker, nxt=r"^@(app|router)\.[a-z]+\("):
    src = path.read_text(encoding="utf-8")
    assert src.count(marker) == 1, marker
    start = src.index(marker)
    rest = re.search(nxt, src[start + len(marker):], re.M)
    return src[start:start + len(marker) + (rest.start() if rest else len(src))]


def _before(body, first, then):
    assert body.count(first) == 1, f"expected {first!r} exactly once"
    assert body.index(first) < body.index(then), f"{first!r} must come before {then!r}"


def test_patch_refuses_self_changes_and_asks_before_writing():
    body = _route(API, '@app.patch("/users/{user_id}", response_model=UserResponse)')
    self_guard = body.index("if is_admin and is_self:")
    for message in ("Cannot change your own role", "Cannot deactivate your own account",
                    "Cannot lock your own account"):
        assert self_guard < body.index(message) < body.index("removes_last_admin(db, user)")
    assert "user_update.role != user.role" in body, "resaving your own unchanged role is allowed"
    _before(body, "removes_last_admin(db, user)", "changes = {}")
    _before(body, "removes_last_admin(db, user)", "user.role = user_update.role")


def test_put_refuses_self_changes_and_asks_before_writing():
    body = _route(USER_MGMT, '@router.put("/users/{user_id}", response_model=UserDetailResponse)')
    for message in ("Cannot change your own role", "Cannot deactivate your own account"):
        assert body.index(message) < body.index("removes_last_admin(db, user)")
    _before(body, "removes_last_admin(db, user)", "user.email = new_email")
    _before(body, "removes_last_admin(db, user)", "user.role = update_data.role")


@pytest.mark.parametrize("path,marker,check,write", [
    (USER_MGMT, '@router.post("/users/{user_id}/toggle-active")',
     "user.is_active and user.role == RoleEnum.ADMIN and removes_last_admin(db, user)",
     "user.is_active = not user.is_active"),
    (USER_MGMT, '@router.post("/users/{user_id}/toggle-locked")',
     "not user.is_locked and user.role == RoleEnum.ADMIN and removes_last_admin(db, user)",
     "user.is_locked = new_locked"),
    (USER_MGMT, '@router.patch("/users/{user_id}/role", response_model=ChangeRoleResponse)',
     "removes_last_admin(db, target_user)", "target_user.role = request.new_role"),
    (API, '@app.post("/users/{user_id}/delete")',
     "user.role == RoleEnum.ADMIN and removes_last_admin(db, user)", "db.delete(user)"),
])
def test_each_other_route_asks_before_it_writes(path, marker, check, write):
    body = _route(path, marker)
    _before(body, check, write)
    assert "LAST_ADMIN_DETAIL" in body[body.index(check):body.index(write)]


def test_no_other_route_changes_a_role_activity_lock_or_deletes_a_user():
    """Every place that writes one of these is one of the routes above (or the automatic,
    time-limited failed-login lock, which is not an administrator's act)."""
    writers = []
    for path in sorted((ROOT / "app").rglob("*.py")):
        if "__pycache__" in str(path):
            continue
        for lineno, ln in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\b(user|target_user)\.(role|is_active|is_locked) = |db\.delete\(user\)", ln):
                writers.append(f"{path.relative_to(ROOT).as_posix()}: {ln.strip()}")
    assert sorted(writers) == sorted([
        "app/api/api_server.py: user.role = user_update.role",
        "app/api/api_server.py: user.is_active = user_update.is_active",
        "app/api/api_server.py: user.is_locked = user_update.is_locked",
        "app/api/api_server.py: db.delete(user)",
        "app/api/user_management_api.py: user.role = update_data.role",
        "app/api/user_management_api.py: user.is_active = update_data.is_active",
        "app/api/user_management_api.py: user.is_active = not user.is_active",
        "app/api/user_management_api.py: user.is_locked = new_locked",
        "app/api/user_management_api.py: target_user.role = request.new_role",
        "app/services/auth_service.py: user.is_locked = True",
    ]), writers


# --------------------------------------------------------------------------- the routes refuse
#
# The pins above check that each route ASKS; a route could keep the text and still ignore the answer.
# So each of the six routes is also called here, with the rule answering that the change would leave
# no administrator who can act: it must refuse with 400 before it changes anything.

from _async_run import run_coroutine  # noqa: E402
from fastapi import HTTPException  # noqa: E402

import app.api.api_server as S  # noqa: E402
import app.api.user_management_api as UM  # noqa: E402


class _Rows:
    """Any db.query(...) chain: first() is the account the route looks up, and nothing else exists."""

    def __init__(self, found):
        self.found = found

    def __getattr__(self, name):          # filter, order_by, with_for_update, ...
        return lambda *a, **k: self

    def first(self):
        return self.found

    def all(self):
        return []

    def count(self):
        return 0

    def update(self, *a, **k):
        return 0


class _RecordingDB:
    """Records every call that would change the database."""

    def __init__(self, target):
        self.target = target
        self.writes = []

    def query(self, model, *more):
        return _Rows(self.target if model is User else None)

    def __getattr__(self, name):
        if name in ("add", "delete", "merge", "execute", "flush", "commit"):
            return lambda *a, **k: self.writes.append(name)
        if name in ("refresh", "rollback", "expire", "expire_all"):
            return lambda *a, **k: None
        raise AttributeError(name)


def _admin_account():
    return types.SimpleNamespace(
        id=uuid.uuid4(), username="the_last_admin", email=None, role=RoleEnum.ADMIN, is_active=True,
        is_locked=False, locked_until=None, failed_login_attempts=0, sftp_enabled=True,
        sftp_password_auth=True, storage_quota_bytes=None, updated_at=None)


# name -> how to call the route on `target`, as `actor`
_ROUTES = {
    "PATCH /users/{id} role": lambda t, a, db: S.update_user(
        user_id=t.id, user_update=S.UserUpdate(role=RoleEnum.USER), current_user=a, db=db, request=None),
    "PATCH /users/{id} deactivate": lambda t, a, db: S.update_user(
        user_id=t.id, user_update=S.UserUpdate(is_active=False), current_user=a, db=db, request=None),
    "PATCH /users/{id} lock": lambda t, a, db: S.update_user(
        user_id=t.id, user_update=S.UserUpdate(is_locked=True), current_user=a, db=db, request=None),
    "PUT /api/user-management/users/{id} role": lambda t, a, db: UM.update_user(
        user_id=t.id, update_data=UM.UserUpdateRequest(role=RoleEnum.USER), request=None,
        current_user=a, db=db),
    "PUT /api/user-management/users/{id} deactivate": lambda t, a, db: UM.update_user(
        user_id=t.id, update_data=UM.UserUpdateRequest(is_active=False), request=None,
        current_user=a, db=db),
    "toggle-active": lambda t, a, db: UM.toggle_user_active(
        user_id=t.id, current_user=a, db=db, request=None),
    "toggle-locked": lambda t, a, db: UM.toggle_user_locked(
        user_id=t.id, current_user=a, db=db, request=None),
    "PATCH /api/user-management/users/{id}/role": lambda t, a, db: UM.change_user_role(
        user_id=t.id, request=UM.ChangeRoleRequest(new_role=RoleEnum.USER), current_user=a, db=db,
        http_request=None),
    "POST /users/{id}/delete": lambda t, a, db: S.delete_user(
        user_id=t.id, current_user=a, db=db, request=None),
}


@pytest.fixture
def the_rule_says(monkeypatch):
    """Make removes_last_admin answer `verdict`, and record whom each route asked about."""
    asked = []

    def answer(verdict):
        def removes_last_admin(db, target):
            asked.append(target)
            return verdict
        monkeypatch.setattr(S, "removes_last_admin", removes_last_admin)
        monkeypatch.setattr(UM, "removes_last_admin", removes_last_admin)
        return asked

    return answer


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_each_route_refuses_before_it_writes_when_no_admin_would_remain(route, the_rule_says):
    asked = the_rule_says(True)
    target, actor = _admin_account(), _admin_account()
    before = dict(vars(target))
    db = _RecordingDB(target)

    with pytest.raises(HTTPException) as refused:
        run_coroutine(_ROUTES[route](target, actor, db))

    assert refused.value.status_code == 400
    assert refused.value.detail == L.LAST_ADMIN_DETAIL
    assert asked == [target], "the route must ask about the account it changes"
    assert db.writes == [], f"{route} wrote before refusing: {db.writes}"
    assert vars(target) == before, f"{route} changed the account before refusing"


@pytest.mark.parametrize("route", sorted(_ROUTES))
def test_the_same_call_goes_ahead_when_another_admin_remains(route, the_rule_says):
    """The control for the test above: with the rule answering no, the same call reaches the account
    (whatever the stand-in database then does to the rest of the route), so a refusal above is the
    rule's doing and not the stand-in's."""
    the_rule_says(False)
    target, actor = _admin_account(), _admin_account()
    before = dict(vars(target))
    db = _RecordingDB(target)

    try:
        run_coroutine(_ROUTES[route](target, actor, db))
    except HTTPException as e:
        assert e.detail != L.LAST_ADMIN_DETAIL, route
    except Exception:  # noqa: BLE001 -- the stand-in cannot carry every later step; the change is made
        pass
    assert vars(target) != before or "delete" in db.writes, f"{route} did not reach the account"
