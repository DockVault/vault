"""Nobody gives themselves access to another person's vault.

An administrator may manage any vault's access, and could grant it to anyone, themselves included.
So any admin could open any Standard vault in two clicks, with no second person involved, although
administrators are not members of every vault. Now whoever administers a vault's access may still
grant it to OTHER people, but a change that would widen the caller's own access is refused on each
of the three paths that could widen it:

  * a per-person grant to yourself (POST /vaults/{id}/permissions);
  * a grant to a department you belong to (POST /vaults/{id}/group-access);
  * adding yourself to a department that has access (POST /groups/{id}/members), whether the
    department was granted the vault or is the audience of a share of something in it;
  * removing your own member row (DELETE /vaults/{id}/permissions/{your id}) when your departments
    hold more on that vault than the row gave you: a member row overrides department access.

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
from fastapi import HTTPException

from _async_run import run_coroutine
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


# --------------------------------------------------------------------------- shares to a department
#
# A share addressed to a department can be claimed by anyone in that department at claim time, so
# joining it reaches the shared item. Which shares are live (active, not expired, naming this
# department) is the query's to decide and is driven live; what is decided here is which of those
# would open something the joiner cannot read today.

class _SharesDB:
    """The live shares naming the department, the joiner's current departments, and the vaults."""

    def __init__(self, shares, vaults, groups_now=()):
        self.shares = shares
        self.vaults = {v.id: v for v in vaults}
        self.groups_now = [(g,) for g in groups_now]

    def query(self, first, *more):
        if first is S.Share:
            return _GrantsDB._All(self.shares)
        if first is S.Vault:
            return _GrantsDB._ById(self.vaults)
        return _GrantsDB._All(self.groups_now)          # user_groups.c.group_id


def _share(vault, *departments):
    return types.SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, claim_audience="departments",
                                 audience_user_ids=[],
                                 audience_department_ids=[str(d) for d in departments])


def test_joining_names_exactly_the_shares_it_would_let_you_claim(held):
    user, dept, other_dept = _user(), uuid.uuid4(), uuid.uuid4()
    unreadable, readable = _vault(), _vault()
    own, zero_knowledge = _vault(owner_id=user.id), _vault(kind="zero_knowledge")
    held[readable.id] = READ
    opens = _share(unreadable, dept)
    shares = [
        opens,
        _share(readable, dept),                  # you read the vault already
        _share(own, dept),                       # nothing widens the owner
        _share(zero_knowledge, dept),            # never shared
        _share(unreadable, dept, other_dept),    # you can claim it already, through another department
        _share(_vault(), dept),                  # its vault is gone
    ]
    db = _SharesDB(shares, [unreadable, readable, own, zero_knowledge], groups_now=[other_dept])
    assert S._shares_opened_by_joining(db, user, dept) == [str(opens.id)]


def test_being_in_other_departments_does_not_stop_a_share_from_counting(held):
    user, dept = _user(), uuid.uuid4()
    vault = _vault()
    share = _share(vault, dept)
    db = _SharesDB([share], [vault], groups_now=[uuid.uuid4()])
    assert S._shares_opened_by_joining(db, user, dept) == [str(share.id)]


def test_no_share_naming_the_department_opens_nothing(held):
    assert S._shares_opened_by_joining(_SharesDB([], []), _user(), uuid.uuid4()) == []


# --------------------------------------------------------------------------- joining, end to end

class _JoinDB:
    """What POST /groups/{id}/members reads before it adds anyone: the department, its members (none)
    and each person to add. Records the inserts."""

    def __init__(self):
        self.executed = []

    def query(self, first, *more):
        if first is S.Group or first is S.User:
            found = types.SimpleNamespace(id=uuid.uuid4())
        else:
            found = None                                    # user_groups.c.user_id: no members yet

        class _Q:
            def filter(self, *a, **k):
                return self

            def with_for_update(self, *a, **k):
                return self

            def first(self):
                return found

            def all(self):
                return []

        return _Q()

    def execute(self, statement, *a, **k):
        self.executed.append(statement)

    def commit(self):
        pass


@pytest.fixture
def join(monkeypatch):
    """Call the real route, with what joining would open set by the test."""
    audited = []
    monkeypatch.setattr(S, "_audit_access_change",
                        lambda db, actor, action, rtype, rid, details=None, status="success":
                        audited.append((action, details, status)))

    def run(vaults, shares, *, include_self=True):
        monkeypatch.setattr(S, "_vaults_opened_by_joining", lambda db, user, gid: list(vaults))
        monkeypatch.setattr(S, "_shares_opened_by_joining", lambda db, user, gid: list(shares))
        me, colleague = _user(), _user()
        ids = [colleague.id] + ([me.id] if include_self else [])
        db = _JoinDB()
        try:
            result = run_coroutine(S.add_group_members(
                group_id=uuid.uuid4(), payload=S.GroupMembersAdd(user_ids=ids), current_user=me, db=db))
        except HTTPException as e:
            result = e
        return result, db, audited

    return run


def test_a_share_to_the_department_refuses_the_whole_self_join(join):
    result, db, audited = join([], ["share-1"])
    assert isinstance(result, HTTPException) and result.status_code == 403
    assert db.executed == [], "a refused request added someone"
    assert audited == [("vault_self_access_refused",
                        {"via": "department_membership", "vault_ids": [], "share_ids": ["share-1"]},
                        "refused")]


def test_a_grant_to_the_department_still_refuses_it(join):
    result, db, audited = join(["vault-1"], [])
    assert isinstance(result, HTTPException) and result.status_code == 403
    assert db.executed == []
    assert audited == [("vault_self_access_refused",
                        {"via": "department_membership", "vault_ids": ["vault-1"], "share_ids": []},
                        "refused")]


def test_joining_a_department_that_opens_nothing_goes_ahead(join):
    result, db, audited = join([], [])
    assert not isinstance(result, HTTPException), result
    assert len(db.executed) == 2, "both people are added"


def test_adding_only_other_people_is_not_limited(join):
    result, db, audited = join(["vault-1"], ["share-1"], include_self=False)
    assert not isinstance(result, HTTPException), result
    assert len(db.executed) == 1
    assert not [a for a in audited if a[0] == "vault_self_access_refused"]


# --------------------------------------------------------------------------- removing your own row

class _MemberRowDB:
    """Answers the member-row lookup with `row` (or no row)."""

    def __init__(self, row):
        self.row = row

    def execute(self, statement, *a, **k):
        return types.SimpleNamespace(fetchone=lambda: self.row)


def _member_row(level):
    perms = S._person_grant_permissions(level)
    return types.SimpleNamespace(read_permission=perms["read"], write_permission=perms["write"],
                                 delete_permission=perms["delete"], manage_permission=perms["manage"])


@pytest.fixture
def departments_hold(monkeypatch):
    """Set what the caller's departments hold on the vault (None = nothing)."""
    box = {"perms": None}

    class _Permissions:
        def __init__(self, db):
            pass

        def _group_vault_permission(self, user, vault_id):
            return box["perms"]

    monkeypatch.setattr(S, "PermissionService", _Permissions)
    return box


@pytest.mark.parametrize("row,departments,widens", [
    ("read", WRITE, True),        # the owner held the admin to read; the department writes
    ("read", READ, False),
    ("read", None, False),        # no department access: removing the row only narrows
    ("write", WRITE, False),
    ("manage", WRITE, False),     # a department never holds delete or manage
    (None, WRITE, False),         # no row to remove
], ids=["read-dept-writes", "read-dept-reads", "read-no-dept", "write-dept-writes", "manage-dept-writes",
        "no-row"])
def test_removing_your_own_row_widens_only_when_a_department_holds_more(departments_hold, row,
                                                                        departments, widens):
    departments_hold["perms"] = departments
    db = _MemberRowDB(_member_row(row) if row else None)
    assert S._removing_own_row_widens(db, _vault(), _user()) is widens


def test_neither_the_owner_nor_a_zero_knowledge_vault_can_widen(departments_hold):
    departments_hold["perms"] = WRITE
    user = _user()
    db = _MemberRowDB(_member_row("read"))
    assert S._removing_own_row_widens(db, _vault(owner_id=user.id), user) is False
    assert S._removing_own_row_widens(db, _vault(kind="zero_knowledge"), user) is False


class _RevokeDB:
    """What DELETE /vaults/{id}/permissions/{user id} reads: the vault. Records the statements."""

    def __init__(self, vault):
        self.vault = vault
        self.executed = []

    def query(self, first, *more):
        vault = self.vault

        class _Q:
            def filter(self, *a, **k):
                return self

            def first(self):
                return vault

        return _Q()

    def execute(self, statement, *a, **k):
        self.executed.append(statement)
        return types.SimpleNamespace(rowcount=1)

    def commit(self):
        pass

    def rollback(self):
        pass


@pytest.fixture
def revoke(monkeypatch):
    """Call the real route as an administrator, with what removing the row would do set by the test."""
    audited = []
    monkeypatch.setattr(S, "_audit_access_change",
                        lambda db, actor, action, rtype, rid, details=None, status="success":
                        audited.append((action, details, status)))

    def run(widens, *, own_row=True):
        monkeypatch.setattr(S, "_removing_own_row_widens", lambda db, vault, user: widens)
        me = types.SimpleNamespace(id=uuid.uuid4(), role=S.RoleEnum.ADMIN)
        vault = _vault()
        db = _RevokeDB(vault)
        try:
            result = run_coroutine(S.revoke_vault_permission(
                vault_id=vault.id, user_id=me.id if own_row else uuid.uuid4(), current_user=me, db=db))
        except HTTPException as e:
            result = e
        return result, db, audited

    return run


def test_removing_your_own_row_is_refused_when_it_widens(revoke):
    result, db, audited = revoke(True)
    assert isinstance(result, HTTPException) and result.status_code == 403
    assert "ask its owner or another administrator" in result.detail
    assert db.executed == [], "the row was removed anyway"
    assert audited == [("vault_self_access_refused", {"via": "remove_own_member_row"}, "refused")]


def test_removing_your_own_row_is_allowed_when_it_only_narrows(revoke):
    result, db, audited = revoke(False)
    assert not isinstance(result, HTTPException), result
    assert len(db.executed) == 1
    assert [a[0] for a in audited] == ["vault_permission_revoked"]


def test_removing_someone_elses_row_is_not_limited(revoke):
    result, db, audited = revoke(True, own_row=False)
    assert not isinstance(result, HTTPException), result
    assert len(db.executed) == 1


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
    shares = _once(body, "_shares_opened_by_joining(")
    assert lock < check < _once(body, "user_groups.insert()")
    assert lock < shares < _once(body, "user_groups.insert()")
    _refusal_is_recorded(body, "department_membership")
