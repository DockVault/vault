"""A provider's Identities page (GET /admin/sso/providers/{id}/identities, app/api/sso_admin_router.py): the accounts
linked to one provider, each with its username and id, how and when it was linked, its last sign-in there, and where
it stands (linked, refused or held, lapsed) with the dates the vault keeps. For an interactive administrator only,
as the provider list is; a read that asks no step-up and records nothing; one provider's accounts never under
another's; nothing of what the provider said about the person beyond that. And every sentence that sends an
administrator there names the page. Offline, through the ASGI app against the in-memory store."""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from test_sso_providers_routes import Admin
from test_sso_sign_in import _call, _identity, _provider, _user

pytestmark = pytest.mark.unit

NOW = datetime.utcnow()
POLICY = {"sso_freshness_days": 30, "sso_lapse_ends_sign_in": True}
FIELDS = {"id", "user_id", "username", "linked_by", "linked_at", "last_sign_in_at", "state", "refused_at", "due_at",
          "holds_sign_in", "after_lift", "own"}


def _t(value):
    return value.isoformat() + "Z"


def _world(monkeypatch, *, state="enabled", policy=None):
    p = _provider(state=state, policy=dict(policy or POLICY), created_at=None, updated_at=None)
    q = _provider(name="fabrikam", label="Fabrikam", policy=dict(POLICY), created_at=None, updated_at=None)
    alice, bob, carol, dave = _user("alice"), _user("Bob"), _user("carol"), _user("dave")
    erin = _user("erin", role="admin")
    fresh = _identity(alice, p, subject="s-alice", linked_by="invitation", linked_at=NOW - timedelta(days=60),
                      last_sign_in_at=NOW - timedelta(days=2), refused_at=None,
                      tenant_id="tenant-1", email_at_link="alice@corp.example", display_name="Alice Corp")
    gone = _identity(bob, p, subject="s-bob", linked_by="email", linked_at=NOW - timedelta(days=90),
                     last_sign_in_at=NOW - timedelta(days=40), refused_at=None)
    refused = _identity(carol, p, subject="s-carol", linked_by="self", linked_at=NOW - timedelta(days=20),
                        last_sign_in_at=NOW - timedelta(days=5), refused_at=NOW - timedelta(days=1))
    # A refusal the person answered since: a sign-in the provider admitted came after it.
    answered = _identity(dave, p, subject="s-dave", linked_by="jit", linked_at=NOW - timedelta(days=20),
                         last_sign_in_at=NOW - timedelta(days=1), refused_at=NOW - timedelta(days=3))
    admin_lapsed = _identity(erin, p, subject="s-erin", linked_by="self", linked_at=NOW - timedelta(days=80),
                             last_sign_in_at=NOW - timedelta(days=35), refused_at=None)
    elsewhere = _identity(alice, q, subject="s-alice-q", linked_by="self", last_sign_in_at=None, refused_at=None)
    h = Admin(monkeypatch, [p, q], users=[alice, bob, carol, dave, erin],
              identities=[fresh, gone, refused, answered, admin_lapsed, elsewhere])
    return types.SimpleNamespace(h=h, p=p, q=q, alice=alice, bob=bob, carol=carol, dave=dave, erin=erin, fresh=fresh,
                                 gone=gone, refused=refused, answered=answered, admin_lapsed=admin_lapsed,
                                 elsewhere=elsewhere)


def _list(h, provider_id, query=""):
    return h.call("GET", f"/admin/sso/providers/{provider_id}/identities{query}")


def test_the_page_lists_a_providers_accounts_with_where_each_stands_and_its_dates(monkeypatch):
    w = _world(monkeypatch)
    status, out = _list(w.h, w.p.id)
    assert status == 200, out
    assert out["provider_id"] == str(w.p.id) and out["total"] == 5 and out["skip"] == 0 and out["limit"] == 50
    assert out["counts"] == {"linked": 2, "refused": 1, "lapsed": 2}
    rows = out["identities"]
    # Refused first, then lapsed, then linked; by username (whatever its case) within each.
    assert [(r["username"], r["state"]) for r in rows] == [
        ("carol", "refused"), ("Bob", "lapsed"), ("erin", "lapsed"), ("alice", "linked"), ("dave", "linked")]
    by_name = {r["username"]: r for r in rows}
    assert all(set(r) == FIELDS for r in rows)
    carol = by_name["carol"]
    assert carol == {"id": str(w.refused.id), "user_id": str(w.carol.id), "username": "carol", "linked_by": "self",
                     "linked_at": _t(w.refused.linked_at), "last_sign_in_at": _t(w.refused.last_sign_in_at),
                     "state": "refused", "refused_at": _t(w.refused.refused_at),
                     "due_at": _t(w.refused.last_sign_in_at + timedelta(days=30)), "holds_sign_in": True,
                     "after_lift": {"state": "linked", "holds_sign_in": False}, "own": False}
    bob = by_name["Bob"]
    assert bob["state"] == "lapsed" and bob["refused_at"] is None and bob["linked_by"] == "email"
    assert bob["due_at"] == _t(w.gone.last_sign_in_at + timedelta(days=30)) and bob["holds_sign_in"] is True
    # What a lift would leave is said for a refused or held account only.
    assert all(r["after_lift"] is None for r in rows if r["state"] != "refused")
    # The days have run out for an administrator too, but an administrator keeps the password as the way in.
    assert by_name["erin"]["state"] == "lapsed" and by_name["erin"]["holds_sign_in"] is False
    # An answered refusal holds nobody: the account is linked, and the old stamp is not shown as a refusal.
    dave = by_name["dave"]
    assert dave["state"] == "linked" and dave["refused_at"] is None and dave["holds_sign_in"] is False
    alice = by_name["alice"]
    assert alice["state"] == "linked" and alice["linked_by"] == "invitation" and alice["holds_sign_in"] is False


def test_one_providers_accounts_are_never_listed_under_another(monkeypatch):
    w = _world(monkeypatch)
    status, out = _list(w.h, w.q.id)
    assert status == 200
    assert [(r["id"], r["username"]) for r in out["identities"]] == [(str(w.elsewhere.id), "alice")]
    assert out["total"] == 1 and out["counts"] == {"linked": 1, "refused": 0, "lapsed": 0}
    assert out["identities"][0]["last_sign_in_at"] is None
    listed = {r["id"] for r in _list(w.h, w.p.id)[1]["identities"]}
    assert str(w.elsewhere.id) not in listed


def test_the_page_says_nothing_of_the_persons_identifier_address_or_name_at_the_provider(monkeypatch):
    w = _world(monkeypatch)
    status, out = _list(w.h, w.p.id)
    text = str(out)
    for kept in ("s-alice", "s-bob", "tenant-1", "alice@corp.example", "Alice Corp", w.p.issuer, w.p.client_id):
        assert kept not in text, kept


def test_the_page_pages_and_keeps_one_state(monkeypatch):
    w = _world(monkeypatch)
    status, first = _list(w.h, w.p.id, "?skip=0&limit=2")
    assert status == 200 and [r["username"] for r in first["identities"]] == ["carol", "Bob"]
    assert first["total"] == 5 and first["limit"] == 2
    second = _list(w.h, w.p.id, "?skip=2&limit=2")[1]
    third = _list(w.h, w.p.id, "?skip=4&limit=2")[1]
    assert [r["username"] for r in second["identities"]] == ["erin", "alice"]
    assert [r["username"] for r in third["identities"]] == ["dave"]
    assert _list(w.h, w.p.id, "?skip=10")[1]["identities"] == []
    lapsed = _list(w.h, w.p.id, "?state=lapsed")[1]
    assert [r["username"] for r in lapsed["identities"]] == ["Bob", "erin"] and lapsed["total"] == 2
    # The counts are the provider's, whatever the page shows.
    assert lapsed["counts"] == {"linked": 2, "refused": 1, "lapsed": 2}
    for query in ("?limit=0", "?limit=201", "?skip=-1", "?state=held", "?state=", "?limit=x"):
        assert _list(w.h, w.p.id, query)[0] == 422, query


def test_an_unknown_provider_is_not_found(monkeypatch):
    w = _world(monkeypatch)
    assert _list(w.h, uuid.uuid4())[0] == 404
    assert _list(w.h, "not-an-id")[0] == 404


def test_the_read_asks_no_step_up_and_records_nothing(monkeypatch):
    w = _world(monkeypatch)
    assert _list(w.h, w.p.id)[0] == 200
    assert w.h.order == [] and w.h.audits == [] and w.h.told == [] and w.h.notices == []
    assert w.h.step_ups == []


def test_an_administrators_own_identity_is_marked_for_another_administrator_to_lift(monkeypatch):
    w = _world(monkeypatch)
    w.admin_lapsed.refused_at = NOW
    w.h.current_user = w.erin
    rows = {r["username"]: r for r in _list(w.h, w.p.id)[1]["identities"]}
    assert rows["erin"]["own"] is True and rows["erin"]["state"] == "refused"
    assert all(r["own"] is False for name, r in rows.items() if name != "erin")


def test_a_hold_written_when_the_provider_was_turned_off_is_listed_with_its_date_and_lifted_here(monkeypatch):
    """Turning a provider off holds the accounts whose days there had already run out: the identity keeps the date,
    as a provider's refusal does, and the turn-off records only how many. The page lists each such account as
    refused or held, with that date, and the existing route lifts it."""
    w = _world(monkeypatch)
    status, out = w.h.call("POST", f"/admin/sso/providers/{w.p.id}/state", {"state": "disabled"})
    assert status == 200 and out["held"] == 2, out
    rows = {r["username"]: r for r in _list(w.h, w.p.id)[1]["identities"]}
    assert rows["Bob"]["state"] == "refused" and rows["Bob"]["refused_at"] == _t(w.gone.refused_at)
    assert rows["erin"]["state"] == "refused"
    # The provider is off: its days close no other way in, but what held an account before goes on holding it.
    assert rows["Bob"]["holds_sign_in"] is True and rows["carol"]["holds_sign_in"] is True
    assert rows["alice"]["state"] == "linked"
    from app.api import sso_admin_router as A
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: w.h.order.append("step_up"))
    status, out = w.h.call("POST", f"/admin/sso/identities/{w.gone.id}/clear-refusal")
    assert status == 200 and out == {"cleared": True}
    rows = {r["username"]: r for r in _list(w.h, w.p.id)[1]["identities"]}
    # Lifted: the days still count as they stand, but while the provider is off they close no password.
    assert rows["Bob"]["state"] == "lapsed" and rows["Bob"]["refused_at"] is None
    assert rows["Bob"]["holds_sign_in"] is False


@pytest.mark.parametrize("ends_sign_in", [True, False], ids=["days end sign-in", "days pause keys only"])
@pytest.mark.parametrize("how", ["on", "off from the start", "turned off"])
def test_where_each_account_stands_is_what_the_sign_in_and_the_keys_hold_it_to(monkeypatch, ends_sign_in, how):
    """The page says what the vault enforces: an account is shown refused or lapsed exactly when its keys are paused
    for this provider (sso_freshness.lapsed), and its password and passkeys are said not to sign it in exactly when
    the sign-in holds it to this provider (sso_freshness.held_to_a_provider). The provider's own switch decides the
    second: with "missed days end sign-in" off, a refused or lapsed account still signs in with its password."""
    from app.services import sso_freshness
    w = _world(monkeypatch, state="disabled" if how == "off from the start" else "enabled",
               policy={"sso_freshness_days": 30, "sso_lapse_ends_sign_in": ends_sign_in})
    if how == "turned off":
        status, out = w.h.call("POST", f"/admin/sso/providers/{w.p.id}/state", {"state": "disabled"})
        assert status == 200 and out["held"] == 2, out
    rows = _list(w.h, w.p.id)[1]["identities"]
    users = {str(u.id): u for u in (w.alice, w.bob, w.carol, w.dave, w.erin)}
    for row in rows:
        user = users[row["user_id"]]
        missed = sso_freshness.lapsed(w.h.db, user.id)
        held = sso_freshness.held_to_a_provider(w.h.db, user)
        assert (row["state"] != "linked") == (missed is not None and missed.provider_id == str(w.p.id)), row
        assert row["holds_sign_in"] == (held is not None and held.provider_id == str(w.p.id)), row
    by_name = {r["username"]: r for r in rows}
    assert by_name["carol"]["state"] == "refused" and by_name["Bob"]["state"] != "linked"
    assert by_name["carol"]["holds_sign_in"] is ends_sign_in
    assert by_name["Bob"]["holds_sign_in"] is (ends_sign_in and how != "off from the start")
    assert by_name["erin"]["holds_sign_in"] is False                # an administrator keeps the password


@pytest.mark.parametrize("status, held", [("proposed", True), ("suspended", True), ("active", False)])
def test_only_an_auditor_right_in_force_keeps_an_account_out_of_the_hold_here_as_at_the_sign_in(
        monkeypatch, status, held):
    """The sign-in holds every account but one that keeps a password of its own in use now: an administrator, or the
    holder of an auditor right in force. A proposal for the right, or a right that is suspended, keeps nobody out of
    the hold. The page says the password and passkeys do not sign an account in, and what a lift would leave, by the
    same rule (sso_freshness.held_to_a_provider)."""
    from app.core.models import AuditorGrant
    from app.services import sso_freshness
    w = _world(monkeypatch)
    w.gone.refused_at = NOW - timedelta(days=1)          # refused after the days had run out: a lift leaves it lapsed
    for user in (w.bob, w.carol):
        w.h.db.rows_of(AuditorGrant).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=user.id, status=status))
    rows = {r["username"]: r for r in _list(w.h, w.p.id)[1]["identities"]}
    for name, user in (("Bob", w.bob), ("carol", w.carol)):
        assert (sso_freshness.held_to_a_provider(w.h.db, user) is not None) is held, name
        assert rows[name]["state"] == "refused" and rows[name]["holds_sign_in"] is held, (name, rows[name])
    assert rows["Bob"]["after_lift"] == {"state": "lapsed", "holds_sign_in": held}
    assert rows["carol"]["after_lift"] == {"state": "linked", "holds_sign_in": False}


def test_a_refusal_on_a_provider_that_counts_no_days_has_no_date_for_its_days(monkeypatch):
    """With the days at 0 only a refusal holds anybody, and its deadline is the refusal itself: the page gives the
    refusal's date, and no date for days that are not counted."""
    w = _world(monkeypatch, policy={"sso_freshness_days": 0, "sso_lapse_ends_sign_in": True})
    status, out = _list(w.h, w.p.id)
    assert status == 200 and out["counts"] == {"linked": 4, "refused": 1, "lapsed": 0}
    rows = {r["username"]: r for r in out["identities"]}
    carol = rows["carol"]
    assert carol["state"] == "refused" and carol["refused_at"] == _t(w.refused.refused_at)
    assert carol["due_at"] is None and carol["holds_sign_in"] is True
    assert all(r["due_at"] is None and r["state"] == "linked" for name, r in rows.items() if name != "carol")
    # No days to run out: lifting the refusal leaves the account linked and its password signing it in.
    assert carol["after_lift"] == {"state": "linked", "holds_sign_in": False}


@pytest.mark.parametrize("ends_sign_in", [True, False], ids=["days end sign-in", "days pause keys only"])
@pytest.mark.parametrize("how", ["on", "turned off"])
def test_what_a_lift_would_leave_is_where_the_account_stands_once_lifted(monkeypatch, ends_sign_in, how):
    """For each refused or held account the page says where a lift leaves it, and it is where the account stands once
    the lift is made. A refusal the provider made before the days ran out leaves the account linked; a hold (or a
    refusal) after they ran out leaves it lapsed, its keys paused, and held to the provider's sign-in while the
    provider is on and says so."""
    from app.api import sso_admin_router as A
    w = _world(monkeypatch, policy={"sso_freshness_days": 30, "sso_lapse_ends_sign_in": ends_sign_in})
    if how == "turned off":
        status, out = w.h.call("POST", f"/admin/sso/providers/{w.p.id}/state", {"state": "disabled"})
        assert status == 200 and out["held"] == 2, out
    else:
        w.gone.refused_at = NOW - timedelta(days=1)      # refused after the days had run out
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: w.h.order.append("step_up"))
    said = {r["username"]: r["after_lift"] for r in _list(w.h, w.p.id)[1]["identities"] if r["state"] == "refused"}
    assert set(said) >= {"carol", "Bob"}
    assert said["carol"] == {"state": "linked", "holds_sign_in": False}
    assert said["Bob"] == {"state": "lapsed", "holds_sign_in": ends_sign_in and how == "on"}
    ids = {"carol": w.refused.id, "Bob": w.gone.id, "erin": w.admin_lapsed.id}
    for name, after in said.items():
        status, out = w.h.call("POST", f"/admin/sso/identities/{ids[name]}/clear-refusal")
        assert status == 200 and out == {"cleared": True}, (name, out)
        now = {r["username"]: r for r in _list(w.h, w.p.id)[1]["identities"]}[name]
        assert {"state": now["state"], "holds_sign_in": now["holds_sign_in"]} == after, name
        assert now["after_lift"] is None


def _refused_for(monkeypatch, w, user):
    """The real administrator check, for ``user`` (None: no session at all)."""
    from app.api import user_management_api as um
    w.h.S.app.dependency_overrides.pop(um.require_interactive_admin, None)
    if user is None:
        w.h.S.app.dependency_overrides.pop(um.get_current_user, None)
    w.h.current_user = user
    status, out = _list(w.h, w.p.id)
    assert "identities" not in str(out)
    return status


@pytest.mark.parametrize("who", ["user", "external"])
def test_an_account_that_is_not_an_administrator_is_refused(monkeypatch, who):
    w = _world(monkeypatch)
    assert _refused_for(monkeypatch, w, _user("someone", role=who)) == 403
    assert ("admin_access_denied", "failure", {"reason": "admin role required"}) in w.h.audits


def test_an_auditor_is_refused(monkeypatch):
    from app.core import privileged_accounts
    from app.core.models import AuditorGrant
    w = _world(monkeypatch)
    auditor = _user("auditor")
    w.h.db.rows_of(AuditorGrant).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=auditor.id, status="active"))
    assert privileged_accounts.kind(w.h.db, auditor) == privileged_accounts.AUDITOR_RIGHT
    assert _refused_for(monkeypatch, w, auditor) == 403


def test_an_administrators_temporary_credential_is_refused(monkeypatch):
    w = _world(monkeypatch)
    temp = _user("root-temp", role="admin", _is_temp_session=True)
    assert _refused_for(monkeypatch, w, temp) == 403


def test_no_session_is_refused(monkeypatch):
    w = _world(monkeypatch)
    assert _refused_for(monkeypatch, w, None) == 401


def test_the_route_is_an_interactive_administrators():
    from _route_walk import served_routes
    from app.api import sso_admin_router as A
    from app.api.user_management_api import require_interactive_admin
    from test_sso_sign_in import _api
    found = [route for path, route in served_routes(_api().app.routes)
             if path == "/admin/sso/providers/{provider_id}/identities"]
    assert len(found) == 1 and found[0].methods == {"GET"}
    assert require_interactive_admin in {d.call for d in found[0].dependant.dependencies}
    assert found[0].endpoint is A.list_provider_identities


def test_every_sentence_that_sends_an_administrator_to_the_identities_names_the_page(monkeypatch):
    """The turn-off's notice, the removal's refusal and the rule's own account of itself say where the page is: a
    provider's Identities page, under Settings, Sign-in."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    for path in ("app/api/sso_providers_router.py", "app/services/sso_providers.py", "app/services/sso_freshness.py",
                 "app/api/sso_admin_router.py"):
        assert "under Identities" not in (root / path).read_text(encoding="utf-8"), path
    # The removal refused while a refusal holds an account says where to lift it.
    w = _world(monkeypatch, state="disabled")
    status, out = w.h.call("DELETE", f"/admin/sso/providers/{w.p.id}")
    assert status == 409 and out["detail"]["reason"] == "refusals_in_force"
    assert "on this provider's Identities page first" in out["detail"]["message"]
    # The turn-off's notice to the administrators, where it holds accounts.
    w = _world(monkeypatch)
    status, out = w.h.call("POST", f"/admin/sso/providers/{w.p.id}/state", {"state": "disabled"})
    assert status == 200 and out["held"] == 2
    said = w.h.told[-1][2]
    assert "lifted on the provider's Identities page (Settings, Sign-in)" in said
    assert "lift each on the provider's Identities page (Settings, Sign-in) when it should have its keys back" in said
