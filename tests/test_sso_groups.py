"""Groups from the provider into departments and roles at each sign-in (app/services/sso_groups.py), and the held
administrator requests (app/api/sso_admin_router.py): joins and leaves per mapping with every other department left
alone; a token without group information changing nothing but telling the administrators; a user or external role
applied once and never demoting an administrator; the administrator request opened once and granted only by another
administrator's approval through the promotion path under the approver rules; the demotion of an administrator
made that way who left the group, except the last one able to act; the list and its lazy expiry. Offline."""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from test_sso_resolution import Resolving, _sign_in
from test_sso_sign_in import _call, _h, _identity, _provider, _user

pytestmark = pytest.mark.unit


class Grouping(Resolving):
    """The resolution harness plus departments, mappings, and the promotion machinery observed rather than run."""

    def __init__(self, monkeypatch, users, providers, identities=(), **kw):
        super().__init__(monkeypatch, users, providers, identities=identities, **kw)
        S = self.S
        from app.core import access_notices, admin_grants
        from app.api import sso_admin_router
        from app.services import sso_groups
        self.watched, self.role_sets, self.lost, self.forgotten, self.status_notices = [], [], [], [], []
        self.grants_recorded, self.announced, self.handed, self.step_ups = [], [], [], []
        self.last_admin = False
        self.reach_of = {}
        harness = self

        class Reach:
            def __init__(self, db, granter):
                harness.watched.append(("reach", granter.username))

            def watch(self, vault, user_ids, *, via, department=None):
                harness.watched.append(("watch", via, department, [str(u) for u in user_ids]))

            def watch_share(self, share, vault, user_ids, *, department=None):
                harness.watched.append(("share", department))

            def tell(self, *, now=None):
                harness.watched.append(("tell",))
                return 0
        monkeypatch.setattr(access_notices, "Reach", Reach)
        monkeypatch.setattr(sso_groups, "_reach_of", lambda db, gid: self.reach_of.get(str(gid), ([], [])))

        def set_role(db, user, new_role, *, actor):
            self.role_sets.append((user.username, new_role.value, getattr(actor, "username", None)))
            user.role = new_role
            return ["old-permission"]
        monkeypatch.setattr(S, "_set_role", set_role)
        monkeypatch.setattr(S, "removes_last_admin", lambda db, user: self.last_admin)
        monkeypatch.setattr(S, "_account_lost_standing",
                            lambda db, user, *, actor, because: self.lost.append((user.username, because, actor)) or "lost")
        monkeypatch.setattr(S, "_announce_lost_standing", lambda db, told, request=None: self.lost.append(("told", told)))
        monkeypatch.setattr(admin_grants, "forget", lambda db, user_id: self.forgotten.append(str(user_id)))
        monkeypatch.setattr(S, "_notify_account_status_changes",
                            lambda db, user, *, by_name, locked=None, active=None, role=None, sign_in_locks_cleared=0,
                            permissions_removed=(): self.status_notices.append((user.username, by_name, role, list(permissions_removed))))
        monkeypatch.setattr(S, "_record_admin_grant",
                            lambda db, user, *, by, by_name=None, inherited=None: self.grants_recorded.append((user.username, by.username)))
        monkeypatch.setattr(S, "_take_back_password_at_promotion", lambda db, user, *, by: {"user_id": user.id})
        monkeypatch.setattr(S, "_hand_over_promotion_reset", lambda db, taken, *, by, request=None: self.handed.append(taken) or None)
        monkeypatch.setattr(S, "_announce_admin_granted",
                            lambda db, user, *, by_name, how: self.announced.append((user.username, by_name, how)))
        monkeypatch.setattr(sso_admin_router, "_step_up", lambda db, user, request: self.step_ups.append(user.username))

    def department(self, name, *members):
        """A department; ``members`` are filed in the association table as an administrator's add files them."""
        from app.core.models import Group, user_groups
        group = types.SimpleNamespace(id=uuid.uuid4(), name=name)
        self.db.rows_of(Group).append(group)
        for user in members:
            self.db.rows_of(user_groups).append(types.SimpleNamespace(user_id=user.id, group_id=group.id, group_role="member"))
            user.groups.append(group)
        return group

    def membership_rows(self, user):
        from app.core.models import user_groups
        return sorted(str(r.group_id) for r in self.db.rows_of(user_groups) if r.user_id == user.id)

    def mapping(self, provider, group, department=None, role=None):
        from app.core.models import SsoGroupMapping
        row = types.SimpleNamespace(id=uuid.uuid4(), provider_id=provider.id, provider_group=group,
                                    department_id=department.id if department is not None else None, role=role)
        self.db.rows_of(SsoGroupMapping).append(row)
        return row

    def requests(self):
        from app.core.models import SsoAdminRequest
        return self.db.rows_of(SsoAdminRequest)

    def membership_audits(self):
        return [a for a in self.audits if a[0] in ("group_members_added", "group_member_removed")]


def _names(groups):
    return sorted(g.name for g in groups)


# --------------------------------------------------------------------------- departments

def test_the_mappings_move_the_person_between_departments_and_touch_nothing_else(monkeypatch):
    alice, root, p = _user(), _user("root", role="admin"), _provider()
    h = Grouping(monkeypatch, [alice, root], [p], identities=[_identity(alice, p)])
    finance, legal, board = h.department("Finance"), h.department("Legal", alice), h.department("Board", alice)
    h.mapping(p, "fin", finance)
    h.mapping(p, "legal", legal)
    h.reach_of[str(finance.id)] = (["vault-1"], [])
    location, _ = _sign_in(h, p, groups=["fin", "other"])
    assert location.startswith("/#sso="), location
    assert _names(alice.groups) == ["Board", "Finance"]                     # joined Finance, left Legal, Board kept
    # Written through the association table, as the groups routes write it (the relationship is read-only).
    assert h.membership_rows(alice) == sorted([str(board.id), str(finance.id)])
    assert ("execute", "insert user_groups", alice.id, finance.id) in h.db.log and ("execute", "delete user_groups", 1) in h.db.log
    assert ("commit",) in h.db.log
    added = [a for a in h.audits if a[0] == "group_members_added"]
    removed = [a for a in h.audits if a[0] == "group_member_removed"]
    assert len(added) == 1 and added[0][2]["via"] == "single_sign_on" and added[0][2]["user_ids"] == [str(alice.id)]
    assert len(removed) == 1 and removed[0][2]["user_id"] == str(alice.id) and removed[0][2]["provider_id"] == str(p.id)
    # The owners of what Finance reaches were told, as an administrator's add tells them.
    assert ("reach", "single sign-on") in h.watched and ("watch", "joined_department", "Finance", [str(alice.id)]) in h.watched
    assert ("tell",) in h.watched
    # The same token again: nothing moves, nothing is recorded twice.
    before = len(h.membership_audits())
    _sign_in(h, p, groups=["fin", "other"])
    assert _names(alice.groups) == ["Board", "Finance"] and len(h.membership_audits()) == before
    # Leaving a department takes nobody else out of it.
    from app.core.models import User
    dave = _user("dave")
    h.db.rows_of(User).append(dave)
    legal2 = h.department("Legal 2", alice, dave)
    h.mapping(p, "legal2", legal2)
    _sign_in(h, p, groups=["fin"])
    assert _names(alice.groups) == ["Board", "Finance"] and _names(dave.groups) == ["Legal 2"]
    assert h.membership_rows(dave) == [str(legal2.id)]
    # A department two mappings name, one group present: the person is in it.
    h.mapping(p, "fin2", finance)
    _sign_in(h, p, groups=["fin"])
    assert "Finance" in _names(alice.groups)
    # Departments no mapping names are never touched, even when the token names no group at all.
    _sign_in(h, p, groups=[])
    assert _names(alice.groups) == ["Board"]


def test_a_token_without_group_information_changes_nothing_and_tells_the_administrators(monkeypatch):
    alice, root, p = _user(), _user("root", role="admin"), _provider()
    h = Grouping(monkeypatch, [alice, root], [p], identities=[_identity(alice, p)])
    legal = h.department("Legal", alice)
    h.mapping(p, "legal", legal)
    h.mapping(p, "fin", h.department("Finance"))
    # A list beside the marker would move alice to Finance if it were trusted; it is partial, so nothing moves.
    for claims in ({"groups": ...}, {"groups": ..., "_claim_names": {"groups": "src1"}},
                   {"groups": ["fin"], "_claim_names": {"groups": "src1"}}):
        location, _ = _sign_in(h, p, **claims)
        assert location.startswith("/#sso="), location
        assert _names(alice.groups) == ["Legal"] and h.membership_rows(alice) == [str(legal.id)] and h.membership_audits() == []
    assert [a for a in h.audits if a[0] == "sso_groups_missing" and a[1] == "failure"]
    assert ([str(root.id)], "A provider sent no group information") in h.notices
    # A provider with no mappings has nothing to miss.
    q = _provider(name="plain")
    h2 = Grouping(monkeypatch, [alice, root], [q], identities=[_identity(alice, q)])
    _sign_in(h2, q, groups=...)
    assert not [a for a in h2.audits if a[0] == "sso_groups_missing"] and h2.notices == []


# --------------------------------------------------------------------------- roles

def test_a_user_or_external_role_follows_the_group_and_never_demotes_an_administrator(monkeypatch):
    alice, root, p = _user(), _user("root", role="admin"), _provider()
    h = Grouping(monkeypatch, [alice, root], [p], identities=[_identity(alice, p), _identity(root, p, subject="root-subject")])
    h.mapping(p, "ext", role="external")
    h.mapping(p, "staff", role="user")
    from app.core.models import RoleEnum
    _sign_in(h, p, groups=["ext"])
    assert h.role_sets == [("alice", "external", None)] and alice.role == RoleEnum.EXTERNAL
    assert ("sso_role_changed", "success", {"provider_id": str(p.id), "from_role": "user", "to_role": "external", "demoted": False}) in h.audits
    assert h.status_notices == [("alice", "single sign-on", ("user", "external"), ["old-permission"])]
    # The same again: applied once.
    _sign_in(h, p, groups=["ext"])
    assert len(h.role_sets) == 1
    # Both groups: the wider role.
    _sign_in(h, p, groups=["ext", "staff"])
    assert h.role_sets[-1] == ("alice", "user", None) and alice.role == RoleEnum.USER
    # No role group in the token: the role stays as it is.
    _sign_in(h, p, groups=["nothing"])
    assert len(h.role_sets) == 2
    # An administrator in the external group keeps the role.
    _sign_in(h, p, sub="root-subject", groups=["ext"])
    assert root.role == RoleEnum.ADMIN and len(h.role_sets) == 2


def test_an_administrator_group_opens_one_held_request_and_grants_nothing(monkeypatch):
    alice, root = _user(), _user("root", role="admin")
    p = _provider(policy={"sso_admin_mapping": True})
    off = _provider(name="off", policy={"sso_admin_mapping": False})
    h = Grouping(monkeypatch, [alice, root], [p, off], identities=[_identity(alice, p), _identity(alice, off, subject="s-off")])
    h.mapping(p, "admins", role="admin")
    h.mapping(off, "admins", role="admin")
    from app.core.models import RoleEnum
    # The setting off: a mapping to the administrator role does nothing.
    _sign_in(h, off, sub="s-off", groups=["admins"])
    assert h.requests() == [] and alice.role == RoleEnum.USER
    # On: one held request, seven days, told to the administrators and the person; the role untouched.
    _sign_in(h, p, groups=["admins"])
    (request,) = h.requests()
    assert request.state == "held" and request.provider_group == "admins" and request.user_id == alice.id
    assert timedelta(days=6, hours=23) < request.expires_at - request.requested_at <= timedelta(days=7)
    assert alice.role == RoleEnum.USER and h.role_sets == [] and h.grants_recorded == []
    assert any(a[0] == "sso_admin_requested" and a[2]["provider_group"] == "admins" for a in h.audits)
    assert ([str(root.id)], "An administrator request is waiting") in h.notices
    assert ([str(alice.id)], "Your administrator role waits for approval") in h.notices
    # An account that signs in only through its provider raises no request: it could never type the password.
    carol = _user("carol", sso_only=True)
    from app.core.models import ExternalIdentity, RoleEnum, User
    h.db.rows_of(User).append(carol)
    h.db.rows_of(ExternalIdentity).append(_identity(carol, p, subject="s-carol"))
    _sign_in(h, p, sub="s-carol", email="carol@example.test", groups=["admins"])
    assert len(h.requests()) == 1 and carol.role == RoleEnum.USER
    # Signing in again while it waits: no second request, no second notice.
    _sign_in(h, p, groups=["admins"])
    assert len(h.requests()) == 1
    assert [n for n in h.notices if n[1] == "An administrator request is waiting"] == [([str(root.id)], "An administrator request is waiting")]
    # Denied: no new request for as long as one would have waited; after that, a sign-in may ask again.
    request.state, request.decided_at = "denied", datetime.utcnow() - timedelta(days=2)
    _sign_in(h, p, groups=["admins"])
    assert len(h.requests()) == 1
    request.decided_at = datetime.utcnow() - timedelta(days=8)
    _sign_in(h, p, groups=["admins"])
    assert len(h.requests()) == 2 and h.requests()[-1].state == "held"


def test_an_approvals_grant_stamped_a_second_before_the_decision_is_still_the_approvals(monkeypatch):
    bob, root = _user("bob", role="admin"), _user("root", role="admin")
    p = _provider(policy={"sso_admin_mapping": True})
    h = Grouping(monkeypatch, [bob, root], [p], identities=[_identity(bob, p)])
    h.mapping(p, "admins", role="admin")
    h.mapping(p, "staff", role="user")
    from app.core.models import RoleEnum
    decided = datetime.utcnow() - timedelta(days=10)
    _request_for(h, p, bob, state="approved", decided_by=root.id, decided_at=decided)
    _grant(h, bob, decided - timedelta(seconds=1), granted_by_id=root.id)
    _sign_in(h, p, groups=["staff"])
    assert bob.role == RoleEnum.USER and len(h.role_sets) == 1


def test_the_lazy_expiry_touches_only_a_row_still_held():
    """The memory store runs no two sessions at once: the guard is pinned in the source. The expiry is one UPDATE
    whose WHERE repeats the state and the time, so a decision that landed meanwhile is never overwritten."""
    import inspect
    from app.services import sso_groups
    source = inspect.getsource(sso_groups.requests)
    update = source[source.index(".update("):]
    where = source[source.index("filter(SsoAdminRequest.id == r.id"):source.index(".update(")]
    assert "SsoAdminRequest.state == HELD" in where and "SsoAdminRequest.expires_at <= now" in where
    assert "synchronize_session=False" in update


def test_a_decision_reads_the_request_locked_after_the_step_up():
    """The memory store shows no row lock; the decision's read is pinned in the source: the request row is read
    again, locked, after the step-up, so two decisions cannot both pass."""
    import inspect
    from app.api import sso_admin_router
    source = inspect.getsource(sso_admin_router._decide)
    assert source.index("_step_up(db, current_user, request)") < source.index("_request_or_404(db, request_id, lock=True)")
    assert inspect.getsource(sso_admin_router._request_or_404).count("with_for_update()") == 1


def test_a_test_sign_in_syncs_nothing(monkeypatch):
    """A test sign-in by an administrator reports and changes nothing: no membership moves, no role changes, no
    administrator request is opened, whatever the mappings say."""
    root, p = _user("root", role="admin"), _provider(state="tested", policy={"sso_admin_mapping": True})
    h = Grouping(monkeypatch, [root], [p])
    finance = h.department("Finance")
    legal = h.department("Legal", root)
    h.mapping(p, "fin", finance)
    h.mapping(p, "legal", legal)
    h.mapping(p, "admins", role="admin")
    h.mapping(p, "ext", role="external")
    from app.core import sso_state
    from app.services import sso_sign_in as sso
    url = sso.start(p, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    h.claims_override = {"groups": ["fin", "admins", "ext"]}
    status, location, _ = h.callback(p, state)
    assert location.startswith("/#sso-test="), location
    assert h.finish_test(p, location)[0] == 200
    from app.core.models import RoleEnum
    assert _names(root.groups) == ["Legal"] and h.membership_rows(root) == [str(legal.id)]
    assert root.role == RoleEnum.ADMIN and h.role_sets == [] and h.requests() == [] and h.membership_audits() == []
    assert p.last_test["groups"] == ["admins", "ext", "fin"]


# --------------------------------------------------------------------------- the decision

def _request_for(h, p, user, **extra):
    from app.core.models import SsoAdminRequest
    now = datetime.utcnow()
    fields = dict(id=uuid.uuid4(), user_id=user.id, provider_id=p.id, provider_group="admins", requested_at=now,
                  expires_at=now + timedelta(days=7), state="held", decided_by=None, decided_by_name=None, decided_at=None)
    fields.update(extra)
    row = types.SimpleNamespace(**fields)
    h.db.rows_of(SsoAdminRequest).append(row)
    return row


def _grant(h, admin, granted_at, lineage=(), granted_by_id=None):
    from app.core.models import AdminGrant
    h.db.rows_of(AdminGrant).append(types.SimpleNamespace(user_id=admin.id, granted_at=granted_at, lineage=list(lineage),
                                                           granted_by_id=granted_by_id, granted_by_name="x"))


def test_the_request_is_decided_by_another_administrator_under_the_approver_rules(monkeypatch):
    bob, root = _user("bob", password_set_by_other_at=None), _user("root", role="admin", password_set_by_other_at=None)
    p = _provider(policy={"sso_admin_mapping": True})
    h = Grouping(monkeypatch, [bob, root], [p])
    h.current_user = root                               # the administrator at the keyboard
    h.mapping(p, "admins", role="admin")
    request = _request_for(h, p, bob)
    S = h.S
    from app.core.models import RoleEnum
    status, body, _ = _call(S, "GET", "/admin/sso/admin-requests")
    assert status == 200, body
    (held,) = body["held"]
    assert held["username"] == "bob" and held["state"] == "held" and held["you_may_decide"] is True and held["refusal"] is None
    assert held["provider"] == "Sign in with Contoso" and body["decided"] == []
    # A new administrator may not decide; the list says why.
    _grant(h, root, datetime.utcnow() - timedelta(days=2))
    status, body, _ = _call(S, "GET", "/admin/sso/admin-requests")
    assert body["held"][0]["you_may_decide"] is False and "less than 14 days" in body["held"][0]["refusal"]
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "new" and h.step_ups == [] and request.state == "held"
    from app.core.models import AdminGrant
    h.db.rows_of(AdminGrant).clear()
    # One who changed the account's sign-in details lately may not either.
    from app.core.models import CredentialChange
    from app.core import credential_changes as cc
    change = types.SimpleNamespace(target_user_id=bob.id, requested_by_id=root.id, decided_by_id=None,
                                   status=sorted(cc.APPLIED)[0], applied_at=datetime.utcnow() - timedelta(days=1))
    h.db.rows_of(CredentialChange).append(change)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "changed"
    h.db.rows_of(CredentialChange).clear()
    # A locked administrator cannot act; one whose password someone else set may not decide.
    root.is_locked = True
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "cannot_act", body
    root.is_locked = False
    root.password_set_by_other_at = datetime.utcnow()
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "password", body
    root.password_set_by_other_at = None
    # The account the request is about must be able to sign in.
    bob.is_active = False
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "account_unusable", body
    bob.is_active = True
    # ... with a password of its own, and under the promotion rules; both judged before the step-up is spent.
    bob.sso_only = True
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "sso_only" and h.step_ups == [], body
    bob.sso_only = False
    from app.core import auditor_rights
    monkeypatch.setattr(auditor_rights, "promotion_refusal", lambda db, user: "bob holds the auditor right")
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "auditor_right" and h.step_ups == [], body
    assert body["detail"]["message"] == "bob holds the auditor right"
    monkeypatch.setattr(auditor_rights, "promotion_refusal", lambda db, user: None)
    # A held request past its time is refused as expired even when nothing marked it yet.
    request.expires_at = datetime.utcnow() - timedelta(seconds=1)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "expired", body
    request.expires_at = datetime.utcnow() + timedelta(days=6)
    # The mapping, the setting and the provider must still stand.
    p.policy = {"sso_admin_mapping": False}
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "mapping_off", body
    p.policy = {"sso_admin_mapping": True}
    p.state = "disabled"
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "provider_gone", body
    p.state = "enabled"
    from app.core.models import SsoGroupMapping
    h.db.rows_of(SsoGroupMapping)[0].provider_group = "other"
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "mapping_gone", body
    h.db.rows_of(SsoGroupMapping)[0].provider_group = "admins"
    assert h.step_ups == []
    # A request about an administrator (their own account included) has nothing to grant.
    own = _request_for(h, p, root)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{own.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "already_admin", body
    # A request decided while the step-up was being proved is not decided twice.
    def deciding_step_up(db, user, http_request):
        h.step_ups.append(user.username)
        request.state = "denied"
    from app.api import sso_admin_router
    monkeypatch.setattr(sso_admin_router, "_step_up", deciding_step_up)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "changed" and h.step_ups == ["root"] and bob.role == RoleEnum.USER
    request.state = "held"
    h.step_ups.clear()
    monkeypatch.setattr(sso_admin_router, "_step_up", lambda db, user, http_request: h.step_ups.append(user.username))
    # Approved: the step-up, then the promotion path with the approver as the grantor, the announcements; the
    # decision takes the grant record's moment, so the demotion rule finds exactly this grant.
    from app.core.models import AdminGrant
    grant_moment = datetime.utcnow() - timedelta(seconds=3)

    def record_grant(db, user, *, by, by_name=None, inherited=None):
        h.grants_recorded.append((user.username, by.username))
        h.db.rows_of(AdminGrant).append(types.SimpleNamespace(user_id=user.id, granted_at=grant_moment,
                                                              granted_by_id=by.id, lineage=[]))
    monkeypatch.setattr(S, "_record_admin_grant", record_grant)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/approve")
    assert status == 200, body
    assert request.decided_at == grant_moment
    assert h.step_ups == ["root"] and h.grants_recorded == [("bob", "root")] and bob.role == RoleEnum.ADMIN
    assert h.role_sets == [("bob", "admin", "root")] and h.announced == [("bob", "root", "promoted")] and h.handed == [{"user_id": bob.id}]
    assert h.status_notices == [("bob", "root", ("user", "admin"), ["old-permission"])]
    assert request.state == "approved" and request.decided_by == root.id and request.decided_by_name == "root"
    assert request.decided_at is not None
    assert body["request"]["state"] == "approved" and body["username"] == "bob"
    assert any(a[0] == "sso_admin_approved" and a[1] == "success" for a in h.audits)
    # Decided once: a second decision is refused.
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{request.id}/deny")
    assert status == 409 and body["detail"]["reason"] == "decided"
    # Denied: the account unchanged, the person told.
    carol = _user("carol")
    from app.core.models import User
    h.db.rows_of(User).append(carol)
    denied = _request_for(h, p, carol)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{denied.id}/deny")
    assert status == 200 and denied.state == "denied" and carol.role == RoleEnum.USER and len(h.role_sets) == 1
    # The approval's notice names the role the account really had.
    carol.role = RoleEnum.EXTERNAL
    again = _request_for(h, p, carol)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{again.id}/approve")
    assert status == 200 and h.status_notices[-1] == ("carol", "root", ("external", "admin"), ["old-permission"])
    assert ([str(carol.id)], "Your administrator role was not granted") in h.notices
    assert any(a[0] == "sso_admin_denied" and a[1] == "success" for a in h.audits)
    # Expired: marked as it is read, and undecidable.
    stale = _request_for(h, p, carol, requested_at=datetime.utcnow() - timedelta(days=8), expires_at=datetime.utcnow() - timedelta(days=1))
    status, body, _ = _call(S, "GET", "/admin/sso/admin-requests")
    assert stale.state == "expired" and any(r["id"] == str(stale.id) and r["state"] == "expired" for r in body["decided"])
    assert any(a[0] == "sso_admin_expired" for a in h.audits)
    status, body, _ = _call(S, "POST", f"/admin/sso/admin-requests/{stale.id}/approve")
    assert status == 409 and body["detail"]["reason"] == "decided", body
    assert _call(S, "POST", f"/admin/sso/admin-requests/{uuid.uuid4()}/approve")[0] == 404
    assert _call(S, "POST", "/admin/sso/admin-requests/not-an-id/approve")[0] == 404


def test_an_administrator_made_by_the_mapping_is_demoted_when_the_group_is_gone_except_the_last_one(monkeypatch):
    bob, root = _user("bob", role="admin"), _user("root", role="admin")
    p = _provider(policy={"sso_admin_mapping": True})
    h = Grouping(monkeypatch, [bob, root], [p], identities=[_identity(bob, p), _identity(root, p, subject="root-subject")])
    h.mapping(p, "admins", role="admin")
    h.mapping(p, "staff", role="user")
    decided = datetime.utcnow() - timedelta(days=10)
    approval = _request_for(h, p, bob, state="approved", decided_by=root.id, decided_at=decided)
    _grant(h, bob, decided + timedelta(seconds=1), granted_by_id=root.id)      # the approval's own grant record
    from app.core.models import RoleEnum
    # Still in the group: nothing.
    _sign_in(h, p, groups=["admins", "staff"])
    assert bob.role == RoleEnum.ADMIN and h.role_sets == []
    # Out of it, but the last administrator able to act: the role is kept, the administrators told.
    h.last_admin = True
    _sign_in(h, p, groups=["staff"])
    assert bob.role == RoleEnum.ADMIN and h.lost == [] and ([str(bob.id), str(root.id)], "An administrator kept the role") in h.notices
    assert any(a[0] == "sso_role_changed" and a[1] == "failure" and a[2]["reason"] == "last_administrator" for a in h.audits)
    # Another administrator can act: demoted to the mapped role, as the Users page would do it.
    h.last_admin = False
    _sign_in(h, p, groups=["staff"])
    assert bob.role == RoleEnum.USER and h.role_sets == [("bob", "user", None)] and h.forgotten == [str(bob.id)]
    assert h.lost[0] == ("bob", "demoted", None) and ("told", "lost") in h.lost
    assert ("sso_role_changed", "success", {"provider_id": str(p.id), "from_role": "admin", "to_role": "user", "demoted": True}) in h.audits
    assert h.status_notices[-1] == ("bob", "single sign-on", ("admin", "user"), ["old-permission"])
    assert approval.state == "demoted"                                           # the approval is spent
    # An administrator made by hand (no approved request) keeps the role whatever the token says.
    _sign_in(h, p, sub="root-subject", groups=["staff"])
    assert root.role == RoleEnum.ADMIN and len(h.role_sets) == 1


def test_a_stale_approval_demotes_nobody_made_an_administrator_since(monkeypatch):
    bob, root = _user("bob", role="admin"), _user("root", role="admin")
    p, q = _provider(policy={"sso_admin_mapping": True}), _provider(name="other", policy={"sso_admin_mapping": True})
    h = Grouping(monkeypatch, [bob, root], [p, q], identities=[_identity(bob, p), _identity(bob, q, subject="s-q")])
    h.mapping(p, "admins", role="admin")
    h.mapping(q, "admins-q", role="admin")
    from app.core.models import AdminGrant, RoleEnum
    decided = datetime.utcnow() - timedelta(days=30)
    _request_for(h, p, bob, state="approved", decided_by=root.id, decided_at=decided)
    # Promoted by hand since (a fresh grant by root, after the approval was spent): the mapping takes nothing.
    _grant(h, bob, datetime.utcnow() - timedelta(days=1), granted_by_id=root.id)
    _sign_in(h, p, groups=["staff"])
    assert bob.role == RoleEnum.ADMIN and h.role_sets == [] and h.lost == []
    # A grant by another administrator at the approval's moment is not the approval's either ...
    other = _user("other", role="admin")
    h.db.rows_of(AdminGrant).clear()
    _grant(h, bob, decided + timedelta(seconds=1), granted_by_id=other.id)
    _sign_in(h, p, groups=["staff"])
    assert bob.role == RoleEnum.ADMIN and h.role_sets == []
    # ... nor one by the approver seconds or minutes later.
    for later in (timedelta(seconds=10), timedelta(minutes=5)):
        h.db.rows_of(AdminGrant).clear()
        _grant(h, bob, decided + later, granted_by_id=root.id)
        _sign_in(h, p, groups=["staff"])
        assert bob.role == RoleEnum.ADMIN and h.role_sets == []
    # The approval of another provider's mapping does not count for this one.
    h.db.rows_of(AdminGrant).clear()
    _grant(h, bob, decided + timedelta(seconds=1), granted_by_id=root.id)
    _request_for(h, q, bob, state="approved", decided_by=root.id, decided_at=decided)
    _sign_in(h, q, sub="s-q", groups=["nothing"])            # q's approval, q's token lacks the group: q demotes
    assert bob.role == RoleEnum.USER and len(h.role_sets) == 1
    # An external mapping present and no user mapping: the demotion lands on external.
    carol = _user("carol", role="admin")
    from app.core.models import User
    h.db.rows_of(User).append(carol)
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(_identity(carol, p, subject="s-carol"))
    h.mapping(p, "ext", role="external")
    _request_for(h, p, carol, state="approved", decided_by=root.id, decided_at=decided)
    _grant(h, carol, decided + timedelta(seconds=1), granted_by_id=root.id)
    _sign_in(h, p, sub="s-carol", groups=["ext"])
    assert carol.role == RoleEnum.EXTERNAL and h.role_sets[-1] == ("carol", "external", None)
