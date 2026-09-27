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
throwaway SQLite database, and pins that each route asks it before it changes anything.
test_last_admin_live.py drives the routes.
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

@pytest.mark.parametrize("person,able", [
    (_person(), True),
    (_person(role=RoleEnum.USER), False),
    (_person(role=RoleEnum.EXTERNAL), False),
    (_person(is_active=False), False),
    (_person(is_locked=True), False),                                            # an admin's lock
    (_person(is_locked=True, locked_until=_now() + timedelta(minutes=5)), False),  # a running timed lock
    (_person(is_locked=True, locked_until=_now() - timedelta(minutes=5)), True),   # one that ran out
])
def test_who_can_administer(person, able):
    assert L.can_administer(person) is able


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
