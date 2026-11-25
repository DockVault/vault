"""A role's passkey requirement lifted for one account by the server's operator (app/core/webauthn_settings.py:
lifting_refusal, lift_requirement, end_lifting, lifted_for, tell_of_a_lifting; app/core/host_operator.py).

The break-glass for a person whose browser cannot make a passkey. It was permanent, nobody was told, and no
administrator could see it: a user later made an administrator stayed exempt from what administrators must hold,
and an account lifted while no requirement named its role was exempt from whatever was required later. Now only a
requirement that names the account's role is lifted; it ends when the account adds a passkey or its role changes;
the operator can put it back; the person and the administrators are told of each; and administrators see who it
is lifted for.
"""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _memory_db import MemoryDB
# The route harness sets the application's overrides itself: cleared after every test here, as in its own file.
from test_passkey_routes import Harness as RouteHarness, _clean_overrides  # noqa: F401
from test_passkey_settings import _mod, _resolving
from test_passkey_settings import _the_vault_has_an_address  # noqa: F401  (a fixture, used by every test here)
from test_passkey_sign_in import _call, _user
from test_passkeys_that_never_verified import _settings_route

pytestmark = pytest.mark.unit

LIFTED_AT = datetime(2026, 11, 20, 9, 30)


def _person(name, role="user", lifted=None, **kw):
    return _user(name, role=role, passkey_required_since=None, passkey_requirement_cleared_at=lifted, **kw)


def test_only_a_requirement_that_names_the_accounts_role_is_lifted_and_it_can_be_put_back(monkeypatch):
    registry, wss = _mod()
    from app.core.models import User, WebAuthnCredential
    alice, root = _person("alice"), _person("root", role="admin")
    db = MemoryDB({User: [alice, root], WebAuthnCredential: []})
    # No requirement at all, or one that names another role: nothing to lift, in words.
    _resolving(monkeypatch, registry, {wss.MODE: "optional", wss.REQUIRED_ROLES: ["user"]})
    assert "not required to hold a passkey" in wss.lifting_refusal(alice)
    _resolving(monkeypatch, registry, {wss.MODE: "off", wss.REQUIRED_ROLES: ["user"]})
    assert "not required to hold a passkey" in wss.lifting_refusal(alice)
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["admin"]})
    assert "nothing to lift" in wss.lifting_refusal(alice) and wss.lifting_refusal(root) is None
    # The requirement names her role: lifted, and from then on it does not apply to her.
    _resolving(monkeypatch, registry, {wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["user"]})
    assert wss.lifting_refusal(alice) is None and wss.requirement(db, alice).required is True
    wss.lift_requirement(alice, now=LIFTED_AT)
    assert alice.passkey_requirement_cleared_at == LIFTED_AT
    need = wss.requirement(db, alice)
    assert need.required is False and need.cleared is True and wss.must_hold(alice) is False
    assert wss.lifting_refusal(alice) == "The passkey requirement is already lifted for this account."
    # Put back: it applies again; put back twice changes nothing.
    assert wss.end_lifting(alice) is True and alice.passkey_requirement_cleared_at is None
    assert wss.requirement(db, alice).required is True and wss.must_hold(alice) is True
    assert wss.end_lifting(alice) is False
    wss.lift_requirement(alice)
    assert datetime.utcnow() - alice.passkey_requirement_cleared_at < timedelta(seconds=5)


def test_the_lifting_ends_with_the_role_it_was_for(monkeypatch):
    """A user the operator exempted is made an administrator: what was lifted was the users' requirement, and
    the administrators' applies to the account like to any other."""
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    from app.api import api_server as api
    from app.core import endpoint_permissions
    from app.core.models import RoleEnum
    rows = []
    monkeypatch.setattr(endpoint_permissions, "reset_to_role_defaults",
                        lambda user_id, role, db: {"removed": [], "added": [], "kept": []})
    monkeypatch.setattr(api.AuditLogger, "build_row", lambda self, **kw: kw)
    db = types.SimpleNamespace(add=rows.append)
    root = types.SimpleNamespace(id=uuid.uuid4(), username="root")
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice", role=RoleEnum.USER,
                                  passkey_requirement_cleared_at=LIFTED_AT)
    # The same role again is no change of role: the lifting stands.
    api._set_role(db, alice, RoleEnum.USER, actor=root)
    assert alice.passkey_requirement_cleared_at == LIFTED_AT and rows == []
    api._set_role(db, alice, RoleEnum.ADMIN, actor=root)
    assert alice.passkey_requirement_cleared_at is None
    (row,) = rows
    assert row["action"] == "passkey_requirement_restored" and row["user"] is root
    assert row["resource_id"] == str(alice.id) and row["details"] == {
        "target_username": "alice", "reason": "role_changed", "old_role": "user", "new_role": "admin"}
    # An account it was never lifted for: a change of role writes no such row.
    del rows[:]
    bob = types.SimpleNamespace(id=uuid.uuid4(), username="bob", role=RoleEnum.USER, passkey_requirement_cleared_at=None)
    api._set_role(db, bob, RoleEnum.EXTERNAL, actor=root)
    assert rows == [] and bob.passkey_requirement_cleared_at is None


def test_the_lifting_ends_when_the_account_adds_a_passkey(monkeypatch):
    """The browser that could make no passkey was replaced: the account adds one, meets the requirement like
    anyone, and owes it again should that key go."""
    registry, wss = _mod()
    alice = _person("alice", lifted=LIFTED_AT)
    h = RouteHarness(monkeypatch, alice)
    status, body, _auth = h.register(label="new laptop")
    assert status == 201, body
    assert alice.passkey_requirement_cleared_at is None


def test_administrators_see_who_the_requirement_is_lifted_for(monkeypatch):
    registry, wss = _mod()
    from app.core.models import User, WebAuthnCredential
    root = _person("root", role="admin")
    zoe, adam, bob = _person("zoe", lifted=LIFTED_AT), _person("Adam", role="external", lifted=LIFTED_AT), _person("bob")
    db = MemoryDB({User: [root, zoe, adam, bob], WebAuthnCredential: []})
    listed = wss.lifted_for(db)
    assert listed == [{"username": "Adam", "role": "external", "lifted_at": "2026-11-20T09:30:00Z"},
                      {"username": "zoe", "role": "user", "lifted_at": "2026-11-20T09:30:00Z"}]
    assert wss.lifted_for(db, limit=1) == listed[:1]
    S, _told, _in_force = _settings_route(monkeypatch, db, root, registry, wss)
    status, body = _call(S, "GET", "/settings/sign-in")
    assert status == 200 and body["requirement_lifted_for"] == listed
    # The Users page's rows carry it too.
    assert "passkey_requirement_cleared_at" in S.UserResponse.model_fields
    assert S.UserResponse.model_fields["passkey_requirement_cleared_at"].default is None


@pytest.mark.parametrize("what", ["lifted", "put_back"])
def test_the_person_and_the_other_administrators_are_told(monkeypatch, what):
    registry, wss = _mod()
    from app.api import api_server as api
    from app.core.models import User
    root, ada = _person("root", role="admin"), _person("ada", role="admin")
    gone = _person("gone", role="admin", is_active=False)
    alice = _person("alice", role="admin")
    db = MemoryDB({User: [root, ada, gone, alice]})
    told = []
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
        told.append((sorted(ids), ntype, title, body, target, dedup_prefix)) or list(ids)))
    wss.tell_of_a_lifting(db, alice, what, by="The server's operator")
    day = datetime.utcnow().date().isoformat()
    (mine, theirs) = told
    assert mine[0] == [str(alice.id)] and mine[1] == "security" and mine[4] == "#profile"
    assert theirs[0] == sorted([str(root.id), str(ada.id)]) and theirs[4] == "#settings"      # not the person, not the inactive
    assert mine[5] == f"passkey_requirement_{what}:{day}"
    assert theirs[5] == f"passkey_requirement_{what}:{alice.id}:{day}"
    if what == "lifted":
        assert mine[2] == "The passkey requirement was lifted for your account"
        assert mine[3] == ("The server's operator lifted the requirement that your role hold a passkey, for your "
                           "account. You sign in without one. It applies again when you add a passkey or your role "
                           "changes, or when it is put back.")
        assert theirs[2] == "The passkey requirement was lifted for alice"
        assert theirs[3] == ("The server's operator lifted the requirement that the role admin hold a passkey, for "
                             "alice. It applies again when the account adds a passkey or its role changes, or when "
                             "the server's operator puts it back (dockvault.py accounts, "
                             "restore-passkey-requirement). Settings, Sign-in lists the accounts it is lifted for.")
    else:
        assert mine[2] == "The passkey requirement applies to your account again"
        assert mine[3] == ("The server's operator put back the requirement that your role hold a passkey. You are "
                           "given the usual time to add one, from your next sign-in.")
        assert theirs[2] == "The passkey requirement applies to alice again"
        assert theirs[3] == ("The server's operator put back the requirement that the role admin hold a passkey, "
                             "for alice.")
    # The only administrator is the person: nobody else to tell. A failure to tell raises nothing.
    del told[:]
    wss.tell_of_a_lifting(MemoryDB({User: [alice]}), alice, what, by="The server's operator")
    assert len(told) == 1

    def broken(*a, **k):
        raise RuntimeError("the notices are down")
    monkeypatch.setattr(api, "_notify_users", broken)
    wss.tell_of_a_lifting(db, alice, what, by="The server's operator")


def test_the_host_tool_lifts_only_what_stands_tells_and_puts_back():
    """The two actions of the tool in the container, as it is written: the refusal is asked before anything is
    set, the people are told after the commit, and putting back writes its own record only when something was
    lifted."""
    from _bare_api_env import set_bare_api_env
    set_bare_api_env()
    import inspect
    from app.core import host_operator
    source = inspect.getsource(host_operator)
    assert "restore-passkey-requirement" in host_operator.ACTIONS
    lift = source[source.index('if args.action == "clear-passkey-requirement":'):
                  source.index('if args.action == "restore-passkey-requirement":')]
    assert lift.index("webauthn_settings.lifting_refusal(user)") < lift.index("return _refuse(why)") \
        < lift.index("webauthn_settings.lift_requirement(user)") < lift.index("db.commit()") \
        < lift.index('action="passkey_requirement_cleared"') \
        < lift.index("webauthn_settings.tell_of_a_lifting(db, user, webauthn_settings.LIFTED")
    back = source[source.index('if args.action == "restore-passkey-requirement":'):
                  source.index('if args.action == "reset-second-factor":')]
    assert back.index("was_lifted = webauthn_settings.end_lifting(user)") < back.index("db.commit()") \
        < back.index("if was_lifted:") < back.index('action="passkey_requirement_restored"') \
        < back.index("webauthn_settings.tell_of_a_lifting(db, user, webauthn_settings.PUT_BACK")
    assert '"was_lifted": was_lifted' in back
    # What the tool shows of an account names the moment it was lifted.
    described = inspect.getsource(host_operator._describe)
    assert '"passkey_requirement_cleared_at"' in described and '"passkeys": passkeys' in described
