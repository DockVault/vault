"""Nobody gives themselves access to another person's vault.

An administrator may manage any vault's access, and could grant it to anyone, themselves included.
So any admin could open any Standard vault in two clicks, with no second person involved, although
administrators are not members of every vault. Now whoever administers a vault's access may still
grant it to OTHER people, but a change that would widen the caller's own access is refused on each
of the three paths that could widen it:

  * a per-person grant to yourself (POST /vaults/{id}/permissions);
  * a grant to a department you belong to (POST /vaults/{id}/group-access);
  * adding yourself to a department that has access (POST /groups/{id}/members).

The owner or another administrator can still grant the admin access, so such a grant always has a
second person behind it. Every refusal is written to the audit log with status "refused".

This file drives the shared rule (_gains_own_access and its helpers) directly, and pins that each
route asks it before it writes. test_no_self_granted_access_live.py drives the routes.
"""
import re
import types
import uuid
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402

pytestmark = pytest.mark.unit

API = Path(__file__).resolve().parent.parent / "app" / "api" / "api_server.py"

NONE = {"read": False, "write": False, "delete": False, "manage": False}
READ = {"read": True, "write": False, "delete": False, "manage": False}
WRITE = {"read": True, "write": True, "delete": False, "manage": False}
MANAGE = {"read": True, "write": True, "delete": True, "manage": True}


def test_each_person_level_includes_the_ones_below_it():
    assert S._person_grant_permissions("read") == READ
    assert S._person_grant_permissions("write") == WRITE
    assert S._person_grant_permissions("delete") == {**WRITE, "delete": True}
    assert S._person_grant_permissions("manage") == MANAGE


def test_a_department_grant_never_carries_delete_or_manage():
    assert S._department_grant_permissions("read") == READ
    assert S._department_grant_permissions("write") == WRITE


@pytest.fixture
def held(monkeypatch):
    """Set what PermissionService says the caller holds on each vault (absent = nothing)."""
    table = {}

    class _Permissions:
        def __init__(self, db):
            pass

        def get_vault_permissions(self, user, vault_id, allow_share=False):
            assert allow_share is False, "a share claim must not count as the caller's own access"
            return table.get(vault_id)

    monkeypatch.setattr(S, "PermissionService", _Permissions)
    return table


def _vault(owner_id=None, kind="standard"):
    return types.SimpleNamespace(id=uuid.uuid4(), owner_id=owner_id or uuid.uuid4(), type=kind)


def _user():
    return types.SimpleNamespace(id=uuid.uuid4())


@pytest.mark.parametrize("holds,grant,widens", [
    (None, READ, True),        # no access at all: any grant widens it
    (None, WRITE, True),
    (READ, READ, False),       # restating what you hold is not a widening
    (READ, WRITE, True),       # read to write is
    (WRITE, READ, False),      # lowering is not
    (MANAGE, MANAGE, False),   # a Manager already holds everything a grant can carry
    (MANAGE, WRITE, False),
])
def test_a_grant_widens_only_what_the_caller_does_not_hold(held, holds, grant, widens):
    user, vault = _user(), _vault()
    if holds is not None:
        held[vault.id] = holds
    assert S._gains_own_access(None, vault, user, grant) is widens


def test_nothing_widens_the_owner(held):
    user = _user()
    vault = _vault(owner_id=user.id)
    assert S._gains_own_access(None, vault, user, MANAGE) is False


class _GrantsDB:
    """A department's vault grants, and the vaults they point at."""

    def __init__(self, grants, vaults):
        self.grants = grants
        self.vaults = {v.id: v for v in vaults}

    def query(self, first, *more):
        return self._ById(self.vaults) if first is S.Vault else self._All(self.grants)

    class _All:
        def __init__(self, rows):
            self.rows = rows

        def filter(self, *args):
            return self

        def all(self):
            return list(self.rows)

    class _ById:
        def __init__(self, vaults):
            self.vaults, self.vault_id = vaults, None

        def filter(self, expr):
            self.vault_id = expr.right.value      # Vault.id == <id>
            return self

        def first(self):
            return self.vaults.get(self.vault_id)


def test_joining_names_exactly_the_vaults_it_would_open(held):
    user = _user()
    opens = _vault()                        # no access today
    already_read = _vault()                 # already read, joined for read
    widens_to_write = _vault()              # already read, the department holds write
    own = _vault(owner_id=user.id)
    zero_knowledge = _vault(kind="zero_knowledge")   # a department never opens one
    held[already_read.id] = READ
    held[widens_to_write.id] = READ
    grants = [(opens.id, "read"), (already_read.id, "read"), (widens_to_write.id, "write"),
              (own.id, "write"), (zero_knowledge.id, "write"), (uuid.uuid4(), "read")]  # last: gone
    db = _GrantsDB(grants, [opens, already_read, widens_to_write, own, zero_knowledge])
    assert S._vaults_opened_by_joining(db, user, uuid.uuid4()) == [str(opens.id), str(widens_to_write.id)]


def test_joining_a_department_with_no_vault_access_opens_nothing(held):
    assert S._vaults_opened_by_joining(_GrantsDB([], []), _user(), uuid.uuid4()) == []


# --------------------------------------------------------------------------- the routes ask first
#
# Each route must ask before it writes, lock the department row before asking where a department is
# involved (so a concurrent grant and join cannot both pass), and record the refusal.

def _endpoint_body(verb, path):
    src = API.read_text(encoding="utf-8")
    marker = f'@app.{verb}("{path}")'
    assert src.count(marker) == 1, marker
    start = src.index(marker)
    nxt = re.search(r"^@app\.[a-z]+\(", src[start + len(marker):], re.M)
    return src[start:start + len(marker) + (nxt.start() if nxt else len(src))]


def _once(body, needle):
    assert body.count(needle) == 1, f"expected {needle!r} exactly once, found {body.count(needle)}"
    return body.index(needle)


def _refusal_is_recorded(body, via):
    call = body.index('"vault_self_access_refused"')
    rest = body[call:]
    assert f'"via": "{via}"' in rest[:rest.index("raise HTTPException")], (
        f"the {via} refusal must be recorded before the request is refused")
    assert 'status="refused"' in rest[:rest.index("raise HTTPException")]


def test_a_grant_to_yourself_is_checked_before_the_member_row_is_written():
    body = _endpoint_body("post", "/vaults/{vault_id}/permissions")
    check = _once(body, "_gains_own_access(")
    assert check < _once(body, "_pg_insert(vault_members)")
    assert "user.id == current_user.id and _gains_own_access(" in body, "only a grant to yourself is limited"
    _refusal_is_recorded(body, "grant_to_self")


def test_a_grant_to_your_department_is_checked_under_the_department_lock():
    body = _endpoint_body("post", "/vaults/{vault_id}/group-access")
    lock = _once(body, "db.query(Group).filter(Group.id == payload.group_id).with_for_update().first()")
    check = _once(body, "_gains_own_access(")
    assert lock < check < _once(body, "insert(vault_group_access)")
    _refusal_is_recorded(body, "department_access")


def test_joining_a_department_is_checked_under_the_department_lock():
    body = _endpoint_body("post", "/groups/{group_id}/members")
    lock = _once(body, "db.query(Group).filter(Group.id == group_id).with_for_update().first()")
    check = _once(body, "_vaults_opened_by_joining(")
    assert lock < check < _once(body, "user_groups.insert()")
    _refusal_is_recorded(body, "department_membership")
