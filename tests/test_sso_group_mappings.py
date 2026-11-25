"""A provider's groups mapped to departments and roles, as an administrator keeps them: the routes under
``/admin/sso/providers/{id}/group-mappings`` (app/api/sso_providers_router.py) and their rules
(app/services/sso_group_mappings.py), through the ASGI app against an in-memory database. Offline.

What a sign-in does with a mapping is in test_sso_groups.py. Here: the order every write keeps (the deployment's
lock, the judgement, the step-up, the provider's row held, the change with its record, the notice), what each route
answers, and the rule for the administrator role: it is mapped only while the provider may raise administrator
requests and its people can hold a password. That rule asks the provider's own rule for passwords, never an
account's flag, so a provider whose accounts are made at their first sign-in can still have its administrators'
group mapped.
"""
import types
import uuid

import pytest

from test_sso_providers_routes import Admin
from test_sso_sign_in import _provider

pytestmark = pytest.mark.unit

ADMIN_ON = {"sso_admin_mapping": True}


class Mappings(Admin):
    def __init__(self, monkeypatch, provider=None, **kw):
        self.provider = provider if provider is not None else _provider(created_at=None, updated_at=None)
        super().__init__(monkeypatch, [self.provider], **kw)
        self.path = f"/admin/sso/providers/{self.provider.id}/group-mappings"
        self.locks = []
        real = self.R._row_or_404

        def row_or_404(db, provider_id, *, lock=False):
            if lock:
                self.order.append("row held")
            return real(db, provider_id, lock=False)        # the memory store holds no row locks
        monkeypatch.setattr(self.R, "_row_or_404", row_or_404)

    def department(self, name, parent=None):
        from app.core.models import Group
        group = types.SimpleNamespace(id=uuid.uuid4(), name=name, parent_id=getattr(parent, "id", None))
        self.db.rows_of(Group).append(group)
        return group

    def stored(self):
        from app.core.models import SsoGroupMapping
        return [(m.provider_group, m.department_id, m.role) for m in self.db.rows_of(SsoGroupMapping)]

    def add(self, **body):
        return self.call("POST", self.path, body)


def _refused(out, reason):
    return out["detail"]["reason"] == reason


def test_the_list_gives_the_page_everything_it_draws(monkeypatch):
    provider = _provider(created_at=None, updated_at=None, claims={"groups": "roles"},
                         last_test={"outcome": "ok", "groups": ["finance", "staff"]})
    h = Mappings(monkeypatch, provider)
    finance, backend = h.department("Finance"), h.department("backend", parent=None)
    assert h.add(provider_group="staff", role="user")[0] == 201
    assert h.add(provider_group="Finance-Team", department_id=str(finance.id))[0] == 201
    h.order.clear()
    status, out = h.call("GET", h.path)
    assert status == 200, out
    assert out["provider"] == {"id": str(provider.id), "name": "contoso", "label": "Sign in with Contoso",
                               "state": "enabled"}
    assert [(m["provider_group"], m["department"], m["role"], m["does_nothing"]) for m in out["mappings"]] == [
        ("Finance-Team", {"id": str(finance.id), "name": "Finance"}, None, None),
        ("staff", None, "user", None)]                                          # by the group's name
    assert out["departments"] == [{"id": str(backend.id), "name": "backend", "parent_id": None},
                                  {"id": str(finance.id), "name": "Finance", "parent_id": None}]
    assert out["roles"] == ["user", "external", "admin"] and out["limit"] == 200
    assert out["groups_claim"] == "roles" and out["seen_at_last_test"] == ["finance", "staff"]
    assert out["admin_role"]["allowed"] is False and out["admin_role"]["why_not"]["reason"] == "admin_mapping_off"
    assert out["locked"] is False and out["step_up"] == "admin.auth_policy.write"
    assert h.order == []                                                        # a read asks no step-up
    assert h.call("GET", f"/admin/sso/providers/{uuid.uuid4()}/group-mappings")[0] == 404
    assert h.call("GET", "/admin/sso/providers/not-an-id/group-mappings")[0] == 404


def test_before_any_test_sign_in_the_list_names_no_groups_and_the_default_claim(monkeypatch):
    h = Mappings(monkeypatch)
    out = h.call("GET", h.path)[1]
    assert out["seen_at_last_test"] is None and out["groups_claim"] == "groups" and out["mappings"] == []
    h.provider.last_test = {"outcome": "ok", "groups": []}                       # a token that named no group
    assert h.call("GET", h.path)[1]["seen_at_last_test"] == []


def test_a_mapping_is_judged_then_stepped_up_then_written_under_the_providers_row_and_recorded(monkeypatch):
    h = Mappings(monkeypatch)
    finance = h.department("Finance")
    for body, field, said in (
            ({}, "provider_group", "Name the provider's group."),
            ({"provider_group": "   "}, "provider_group", "Between 1 and 255 characters, without control characters."),
            ({"provider_group": "x" * 256}, "provider_group", "Between 1 and 255 characters, without control characters."),
            ({"provider_group": "a\x00b"}, "provider_group", "Between 1 and 255 characters, without control characters."),
            ({"provider_group": 7}, "provider_group", "A text is expected."),
            ({"provider_group": "staff"}, "role", "Choose a department, a role, or both: a mapping with neither does nothing."),
            ({"provider_group": "staff", "role": "owner"}, "role", "One of user, external or admin, or none."),
            ({"provider_group": "staff", "role": ["user"]}, "role", "One of user, external or admin, or none."),
            ({"provider_group": "staff", "department_id": "nope"}, "department_id", "Unknown department."),
            ({"provider_group": "staff", "department_id": str(uuid.uuid4())}, "department_id", "Unknown department."),
            ({"provider_group": "staff", "role": "user", "made_up": 1}, "made_up", "Unknown field.")):
        status, out = h.add(**body)
        assert status == 400 and out["detail"]["reason"] == "invalid", (body, out)
        assert out["detail"]["field"] == field and out["detail"]["message"].endswith(said), (body, out)
    assert h.order == [] and h.stored() == [] and h.told == []          # judged before anything is asked
    status, out = h.add(provider_group="Finance-Team", department_id=str(finance.id), role="external")
    assert status == 201, out
    shown = out["mapping"]
    assert shown == {"id": shown["id"], "provider_group": "Finance-Team",
                     "department": {"id": str(finance.id), "name": "Finance"}, "role": "external",
                     "does_nothing": None}
    assert h.order == ["step_up", "row held"] and h.stored() == [("Finance-Team", finance.id, "external")]
    assert h.audit("sso_group_mapping_added") == [("sso_group_mapping_added", "success", {
        "provider_id": str(h.provider.id), "name": "contoso", "mapping_id": shown["id"],
        "provider_group": "Finance-Team", "group_id": str(finance.id), "department": "Finance", "role": "external"})]
    assert h.told == [("root", "A single sign-on group was mapped", (
        "root mapped the group Finance-Team of the single sign-on provider contoso to the department Finance and "
        "the role external. It applies from each person's next sign-in through the provider."))]


def test_a_group_is_mapped_once_and_as_the_provider_spells_it(monkeypatch):
    h = Mappings(monkeypatch)
    assert h.add(provider_group="staff", role="user")[0] == 201
    h.order.clear()
    status, out = h.add(provider_group="staff", role="external")
    assert status == 409 and _refused(out, "group_mapped") and h.order == []    # refused before the step-up
    # The provider's spelling is the group: another case is another group.
    assert h.add(provider_group="Staff", role="external")[0] == 201
    assert sorted(h.stored()) == [("Staff", None, "external"), ("staff", None, "user")]


def test_what_is_judged_in_the_providers_row_is_read_again_from_the_database(monkeypatch):
    """A session keeps the values of a row it loaded. Each write loads the mappings before it asks for the
    step-up and waits for the provider's row: judged on those values, a change another administrator committed
    meanwhile would not be seen. Every read of the mappings made while the row is held asks for them as they
    are."""
    h = Mappings(monkeypatch)
    from _memory_db import MemoryQuery
    from app.core.models import SsoGroupMapping
    reads = []
    real_fresh, real_all, real_first = MemoryQuery.populate_existing, MemoryQuery.all, MemoryQuery.first

    def fresh(self):
        self.asked_fresh = True
        return real_fresh(self)

    def note(self):
        if self.model is SsoGroupMapping:
            reads.append(("row held" in h.order, getattr(self, "asked_fresh", False)))

    monkeypatch.setattr(MemoryQuery, "populate_existing", fresh)
    monkeypatch.setattr(MemoryQuery, "all", lambda self: (note(self), real_all(self))[1])
    monkeypatch.setattr(MemoryQuery, "first", lambda self: (note(self), real_first(self))[1])

    def of_the_write():
        seen = sorted(set(reads))
        reads.clear()
        h.order.clear()
        return seen
    status, out = h.add(provider_group="staff", role="user")
    assert status == 201 and of_the_write() == [(False, False), (True, True)]
    path = f"{h.path}/{out['mapping']['id']}"
    assert h.call("PATCH", path, {"role": "external"})[0] == 200 and of_the_write() == [(False, False), (True, True)]
    assert h.call("DELETE", path)[0] == 200 and of_the_write() == [(False, False), (True, True)]


def test_the_same_group_sent_twice_at_once_is_refused_in_the_row(monkeypatch):
    """Two saves judged before either wrote: the second is judged again once it holds the provider's row."""
    h = Mappings(monkeypatch)
    from app.services import sso_group_mappings as M
    real, calls = M.judge, []

    def judge(db, row, **kw):
        calls.append(1)
        if len(calls) == 1:              # the first judgement of this save passes; another save lands before its write
            out = real(db, row, **kw)
            M.create(db, row, provider_group="staff", role="user")
            return out
        return real(db, row, **kw)
    monkeypatch.setattr(M, "judge", judge)
    status, out = h.add(provider_group="staff", role="external")
    assert status == 409 and _refused(out, "group_mapped"), out
    assert h.audit("sso_group_mapping_added") == [] and h.told == []


def test_the_administrator_role_is_mapped_only_while_the_provider_can_raise_requests(monkeypatch):
    h = Mappings(monkeypatch)
    status, out = h.add(provider_group="vault-admins", role="admin")
    assert status == 409 and _refused(out, "admin_mapping_off") and h.order == [] and h.stored() == []
    assert out["detail"]["message"] == ("Sign in with Contoso may not raise administrator requests. Turn on "
                                         "“Administrator group” on its Access page first.")
    h.provider.policy = dict(ADMIN_ON)
    assert h.call("GET", h.path)[1]["admin_role"] == {"allowed": True, "why_not": None}
    status, out = h.add(provider_group="vault-admins", role="admin")
    assert status == 201 and out["mapping"]["role"] == "admin" and out["mapping"]["does_nothing"] is None
    assert h.told[-1][2] == ("root mapped the group vault-admins of the single sign-on provider contoso to a request "
                             "for the administrator role, which another administrator decides. It applies from each "
                             "person's next sign-in through the provider.")


def test_a_provider_whose_people_hold_no_password_cannot_have_its_administrators_group_mapped(monkeypatch):
    """An administrator needs a password, and a sign-in through such a provider raises no request: the save says
    what to change and keeps nothing that would do nothing."""
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None,
                                        policy={**ADMIN_ON, "sso_password_login": "disabled"}))
    status, out = h.add(provider_group="vault-admins", role="admin")
    assert status == 409 and _refused(out, "provider_holds_no_passwords") and h.order == [] and h.stored() == []
    assert out["detail"]["message"] == (
        "People of Sign in with Contoso hold no password, which an administrator needs, so a sign-in through it "
        "raises no administrator request. Allow password sign-in for it on its Access page first.")
    assert h.call("GET", h.path)[1]["admin_role"]["why_not"]["reason"] == "provider_holds_no_passwords"
    # The lesser roles and the departments are mapped there as anywhere.
    assert h.add(provider_group="staff", role="user")[0] == 201


def test_a_provider_that_makes_accounts_with_no_password_can_have_its_administrators_group_mapped(monkeypatch):
    """Held to no password only because the account was made at its first sign-in: the approval of its request
    ends that and hands over a link. The rule asks whether the provider lets anybody hold a password, not whether
    an account has one."""
    from app.core import sso_only
    provider = _provider(created_at=None, updated_at=None,
                         policy={**ADMIN_ON, "sso_account_creation": "jit", "sso_jit_password": False})
    assert sso_only.made_here_holds_no_password(provider) and not sso_only.password_less(provider)
    h = Mappings(monkeypatch, provider)
    status, out = h.add(provider_group="vault-admins", role="admin")
    assert status == 201 and out["mapping"]["does_nothing"] is None, out


def test_a_mapping_saved_before_the_providers_rule_changed_says_that_it_does_nothing(monkeypatch):
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    finance = h.department("Finance")
    mapping_id = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    assert h.add(provider_group="staff", role="user")[0] == 201
    h.provider.policy = {**ADMIN_ON, "sso_password_login": "disabled"}
    shown = {m["provider_group"]: m["does_nothing"] for m in h.call("GET", h.path)[1]["mappings"]}
    assert shown["staff"] is None and shown["vault-admins"]["reason"] == "provider_holds_no_passwords"
    h.provider.policy = {}
    shown = {m["provider_group"]: m["does_nothing"] for m in h.call("GET", h.path)[1]["mappings"]}
    assert shown["staff"] is None and shown["vault-admins"]["reason"] == "admin_mapping_off"
    # It can still be given a department, or lose the role; it cannot be pointed at another group meanwhile.
    path = f"{h.path}/{mapping_id}"
    status, out = h.call("PATCH", path, {"department_id": str(finance.id)})
    assert status == 200 and out["changed"] == ["department"] and out["mapping"]["role"] == "admin"
    status, out = h.call("PATCH", path, {"provider_group": "other-admins"})
    assert status == 409 and _refused(out, "admin_mapping_off")
    status, out = h.call("PATCH", path, {"role": None})
    assert status == 200 and out["changed"] == ["role"] and out["mapping"]["does_nothing"] is None
    status, out = h.call("PATCH", path, {"role": "admin"})                       # and not taken up again
    assert status == 409 and _refused(out, "admin_mapping_off")


def test_a_change_is_judged_stepped_up_written_and_recorded_with_what_it_was(monkeypatch):
    h = Mappings(monkeypatch)
    finance, sales = h.department("Finance"), h.department("Sales")
    mapping_id = h.add(provider_group="staff", department_id=str(finance.id), role="user")[1]["mapping"]["id"]
    path = f"{h.path}/{mapping_id}"
    h.order.clear()
    h.told.clear()
    for body, field in (({}, "provider_group"), ({"made_up": 1}, "made_up"), ({"role": "owner"}, "role"),
                        ({"department_id": "nope"}, "department_id"), ({"provider_group": ""}, "provider_group")):
        status, out = h.call("PATCH", path, body)
        assert status == 400 and out["detail"]["field"] == field, (body, out)
    status, out = h.call("PATCH", path, {"department_id": None, "role": None})
    assert status == 400 and out["detail"]["field"] == "role"                    # a mapping keeps one of the two
    assert h.order == []
    # Nothing would change: no step-up, no record, no notice.
    status, out = h.call("PATCH", path, {"role": "user", "department_id": str(finance.id), "provider_group": "staff"})
    assert status == 200 and out["changed"] == [] and h.order == [] and h.told == []
    assert h.audit("sso_group_mapping_changed") == []
    status, out = h.call("PATCH", path, {"provider_group": "all-staff", "department_id": str(sales.id), "role": None})
    assert status == 200, out
    assert out["changed"] == ["department", "provider_group", "role"]
    assert out["mapping"] == {"id": mapping_id, "provider_group": "all-staff",
                              "department": {"id": str(sales.id), "name": "Sales"}, "role": None, "does_nothing": None}
    assert h.order == ["step_up", "row held"] and h.stored() == [("all-staff", sales.id, None)]
    assert h.audit("sso_group_mapping_changed") == [("sso_group_mapping_changed", "success", {
        "provider_id": str(h.provider.id), "name": "contoso", "mapping_id": mapping_id, "provider_group": "all-staff",
        "group_id": str(sales.id), "department": "Sales", "role": None,
        "changed": ["department", "provider_group", "role"],
        "changes": {"provider_group": {"old": "staff", "new": "all-staff"},
                    "department": {"old": "Finance", "new": "Sales"}, "role": {"old": "user", "new": None}}})]
    assert h.told == [("root", "A single sign-on group mapping was changed", (
        "root changed how the group all-staff of the single sign-on provider contoso is mapped: it now gives the "
        "department Sales. It applies from each person's next sign-in through the provider."))]
    # Renamed onto another mapping's group: refused.
    assert h.add(provider_group="guests", role="external")[0] == 201
    status, out = h.call("PATCH", path, {"provider_group": "guests"})
    assert status == 409 and _refused(out, "group_mapped")


def test_a_mapping_is_removed_after_the_step_up_and_recorded_as_it_was(monkeypatch):
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    finance = h.department("Finance")
    first = h.add(provider_group="staff", department_id=str(finance.id))[1]["mapping"]["id"]
    second = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    h.order.clear()
    h.told.clear()
    assert h.call("DELETE", f"{h.path}/{uuid.uuid4()}")[0] == 404
    assert h.call("DELETE", f"{h.path}/not-an-id")[0] == 404
    assert h.order == []                                                         # an unknown mapping asks nothing
    status, out = h.call("DELETE", f"{h.path}/{first}")
    assert status == 200 and out["removed"] is True and out["mapping"]["provider_group"] == "staff"
    assert h.order == ["step_up", "row held"] and h.stored() == [("vault-admins", None, "admin")]
    assert h.audit("sso_group_mapping_removed") == [("sso_group_mapping_removed", "success", {
        "provider_id": str(h.provider.id), "name": "contoso", "mapping_id": first, "provider_group": "staff",
        "group_id": str(finance.id), "department": "Finance", "role": None})]
    assert h.told == [("root", "A single sign-on group mapping was removed", (
        "root removed the mapping of the group staff of the single sign-on provider contoso (it gave the department "
        "Finance). Nobody's department or role was changed by that."))]
    status, out = h.call("DELETE", f"{h.path}/{second}")
    assert status == 200 and h.stored() == []
    # No request was waiting through the group: nothing more is said.
    assert out["requests_ended"] == 0
    assert h.told[-1][2].endswith("(it gave a request for the administrator role, which another administrator "
                                  "decides). Nobody's department or role was changed by that.")
    assert h.call("DELETE", f"{h.path}/{second}")[0] == 404


def test_a_mapping_of_another_provider_is_not_this_providers(monkeypatch):
    other = _provider(name="fabrikam", label="Fabrikam", created_at=None, updated_at=None)
    h = Mappings(monkeypatch)
    from app.core.models import SsoProvider
    h.db.rows_of(SsoProvider).append(other)
    mapping_id = h.add(provider_group="staff", role="user")[1]["mapping"]["id"]
    h.order.clear()
    elsewhere = f"/admin/sso/providers/{other.id}/group-mappings/{mapping_id}"
    assert h.call("PATCH", elsewhere, {"role": "external"})[0] == 404
    assert h.call("DELETE", elsewhere)[0] == 404
    assert h.order == [] and h.stored() == [("staff", None, "user")]
    assert h.call("GET", f"/admin/sso/providers/{other.id}/group-mappings")[1]["mappings"] == []
    # The provider's own shape counts its mappings, for the list of providers.
    assert h.call("GET", f"/admin/sso/providers/{h.provider.id}")[1]["provider"]["group_mappings"] == 1
    assert h.call("GET", f"/admin/sso/providers/{other.id}")[1]["provider"]["group_mappings"] == 0


def test_every_write_is_refused_while_the_deployment_has_locked_single_sign_on(monkeypatch):
    h = Mappings(monkeypatch)
    mapping_id = h.add(provider_group="staff", role="user")[1]["mapping"]["id"]
    h.order.clear()
    h.is_locked = True
    for method, path, body in (("POST", h.path, {"provider_group": "guests", "role": "external"}),
                               ("PATCH", f"{h.path}/{mapping_id}", {"role": "external"}),
                               ("DELETE", f"{h.path}/{mapping_id}", None)):
        status, out = h.call(method, path, body)
        assert status == 409 and _refused(out, "locked"), (method, out)
    assert h.order == [] and h.stored() == [("staff", None, "user")]
    assert h.call("GET", h.path)[1]["locked"] is True                           # the page is still shown them


def test_only_an_administrator_reaches_these_routes(monkeypatch):
    h = Mappings(monkeypatch)
    mapping_id = h.add(provider_group="staff", role="user")[1]["mapping"]["id"]
    h.order.clear()
    from fastapi import HTTPException
    from app.api.user_management_api import require_interactive_admin

    def _no():
        raise HTTPException(status_code=403, detail="Administrators only.")
    monkeypatch.setitem(h.S.app.dependency_overrides, require_interactive_admin, _no)
    for method, path, body in (("GET", h.path, None), ("POST", h.path, {"provider_group": "guests", "role": "user"}),
                               ("PATCH", f"{h.path}/{mapping_id}", {"role": "external"}),
                               ("DELETE", f"{h.path}/{mapping_id}", None)):
        assert h.call(method, path, body)[0] == 403, (method, path)
    assert h.order == [] and h.stored() == [("staff", None, "user")]
    # Each is behind the interactive-administrator dependency itself, and each write asks the fixed step-up of
    # the sign-in settings.
    found = {}
    for route in h.R.router.routes:
        if "group-mappings" in route.path:
            deps = {getattr(d.call, "__name__", "") for d in route.dependant.dependencies}
            assert "require_interactive_admin" in deps, route.path
            for method in route.methods:
                found[(method, route.path)] = route.endpoint
    base = "/admin/sso/providers/{provider_id}/group-mappings"
    assert set(found) == {("GET", base), ("POST", base), ("PATCH", base + "/{mapping_id}"),
                          ("DELETE", base + "/{mapping_id}")}
    import inspect
    for (method, _path), endpoint in found.items():
        source = inspect.getsource(endpoint)
        assert ("_step_up(db, current_user, request)" in source) is (method != "GET"), method
        if method != "GET":
            steps = ["_refuse_locked()", "_step_up(db, current_user, request)",
                     "_row_or_404(db, provider_id, lock=True)", "_record(db, ", "db.commit()"]
            order = [source.index(step) for step in steps]
            assert order == sorted(order), (method, order)


def test_a_provider_holds_at_most_its_limit_of_mappings(monkeypatch):
    h = Mappings(monkeypatch)
    from app.services import sso_group_mappings as M
    monkeypatch.setattr(M, "MAX_MAPPINGS", 2)
    assert h.add(provider_group="a", role="user")[0] == 201 and h.add(provider_group="b", role="user")[0] == 201
    h.order.clear()
    status, out = h.add(provider_group="c", role="user")
    assert status == 409 and _refused(out, "too_many_mappings") and h.order == []
    # One that exists is still changed at the limit, and above it (a limit lowered since): the limit is for new
    # mappings only.
    mapping_id = h.call("GET", h.path)[1]["mappings"][0]["id"]
    assert h.call("PATCH", f"{h.path}/{mapping_id}", {"role": "external"})[0] == 200
    monkeypatch.setattr(M, "MAX_MAPPINGS", 1)
    assert h.call("PATCH", f"{h.path}/{mapping_id}", {"role": "user"})[0] == 200
    assert h.call("DELETE", f"{h.path}/{mapping_id}")[0] == 200


def test_a_record_that_cannot_be_written_keeps_the_mapping_from_being_saved(monkeypatch):
    h = Mappings(monkeypatch)
    from app.services import audit_logger

    class Broken:
        def __init__(self, db):
            pass

        def build_row(self, **kw):
            raise RuntimeError("the audit log is gone")
    monkeypatch.setattr(audit_logger, "AuditLogger", Broken)
    status, out = h.add(provider_group="staff", role="user")
    assert status == 503 and "its audit record could not be written" in out["detail"]
    assert h.stored() == [] and h.told == []


def test_the_rules_ask_the_providers_own_rule_for_passwords_and_no_accounts_flag():
    """The provider's rule, read from its policy: nothing here reads an account or its sso_only flag."""
    import inspect
    from app.services import sso_group_mappings as M
    source = inspect.getsource(M.admin_refusal)
    assert "sso_only.password_less(row)" in source and '["sso_admin_mapping"]' in source
    code = "\n".join(line.split("#")[0] for line in inspect.getsource(M).splitlines()
                     if not line.lstrip().startswith(('"', "*")))
    assert "User" not in code and ".sso_only" not in code and "held_by_a_password_less_provider" not in code


def test_a_department_says_how_many_mappings_name_it_and_its_deletion_how_many_went(monkeypatch):
    """A department that is deleted takes the mappings that name it with it, of every provider, a role on the
    same mapping included. Its page is given the number before, its deletion answers it and records it."""
    other = _provider(name="fabrikam", label="Fabrikam", created_at=None, updated_at=None)
    h = Mappings(monkeypatch)
    from app.core.models import SsoGroupMapping, SsoProvider
    from app.services import sso_group_mappings as M
    h.db.rows_of(SsoProvider).append(other)
    finance, sales = h.department("Finance"), h.department("Sales")
    assert M.naming(h.db, finance.id) == 0
    assert h.add(provider_group="finance", department_id=str(finance.id))[0] == 201
    assert h.add(provider_group="controllers", department_id=str(finance.id), role="user")[0] == 201
    assert h.add(provider_group="staff", role="user")[0] == 201
    elsewhere = types.SimpleNamespace(id=uuid.uuid4(), provider_id=other.id, provider_group="fin",
                                      department_id=finance.id, role=None)
    h.db.rows_of(SsoGroupMapping).append(elsewhere)
    assert M.naming(h.db, finance.id) == 3 and M.naming(h.db, sales.id) == 0
    # The two routes of a department ask it: the detail gives the number, the deletion counts before it deletes.
    import inspect
    detail, delete = inspect.getsource(h.S.get_group), inspect.getsource(h.S.delete_group)
    assert "sso_group_mappings=sso_group_mappings.naming(db, group.id))" in detail
    assert h.S.GroupDetailResponse.model_fields["sso_group_mappings"].default == 0
    steps = ("mapped = sso_group_mappings.naming(db, group.id)", "db.delete(group)", "db.commit()",
             '"sso_group_mappings": mapped})', '"sso_group_mappings_removed": mapped}')
    assert all(step in delete for step in steps), [step for step in steps if step not in delete]
    order = [delete.index(step) for step in steps]
    assert order == sorted(order), order
    from app.core import audit_privacy
    assert audit_privacy.kind_of("sso_group_mappings") == audit_privacy.IDENTIFIER


def test_the_three_records_are_catalogued_with_the_other_provider_changes():
    from app.core import audit_catalog, audit_privacy
    provider_change = audit_catalog.lookup("sso_provider_updated")
    for name in ("sso_group_mapping_added", "sso_group_mapping_changed", "sso_group_mapping_removed"):
        entry = audit_catalog.lookup(name)
        assert entry is not None and entry[1:2] == provider_change[1:2] == ("administration",), name
        assert entry[3] == provider_change[3] == "warning", name
    for key in ("mapping_id", "department", "provider_group", "group_id", "role", "name", "provider_id", "changed"):
        assert audit_privacy.kind_of(key) == audit_privacy.IDENTIFIER, key
    assert audit_privacy.kind_of("changes.department") == audit_privacy.IDENTIFIER


def _members(monkeypatch, counts):
    """``counts``: department id -> how many accounts linked to the provider are in it."""
    from app.services import sso_groups
    asked = []

    def linked_members(db, row, department_id):
        asked.append(department_id)
        return counts.get(department_id, 0)
    monkeypatch.setattr(sso_groups, "linked_members", linked_members)
    return asked


def test_a_mapping_added_to_a_department_with_members_says_how_many_may_leave_it(monkeypatch):
    """An administrator put people in Finance by hand. A group of the provider is then mapped to Finance: from now
    on the department follows the provider's groups, and a linked account in it leaves at its next sign-in unless
    the token names the group. The route said only "it applies from each person's next sign-in"."""
    h = Mappings(monkeypatch)
    finance, legal = h.department("Finance"), h.department("Legal")
    asked = _members(monkeypatch, {finance.id: 3})
    status, out = h.add(provider_group="fin", department_id=str(finance.id))
    assert status == 201 and out["may_leave"] == [
        {"department": {"id": str(finance.id), "name": "Finance"}, "accounts": 3}], out
    assert asked == [finance.id]
    assert h.told[-1][2] == (
        "root mapped the group fin of the single sign-on provider contoso to the department Finance. It applies "
        "from each person's next sign-in through the provider. 3 account(s) linked to contoso are in the department "
        "Finance now: each leaves it at its next sign-in through the provider unless that sign-in names a group "
        "mapped to it.")
    # Nobody linked in it, or a role alone: nothing to say.
    status, out = h.add(provider_group="law", department_id=str(legal.id))
    assert status == 201 and out["may_leave"] == [] and h.told[-1][2].endswith("next sign-in through the provider.")
    status, out = h.add(provider_group="staff", role="user")
    assert status == 201 and out["may_leave"] == [] and h.told[-1][2].endswith("next sign-in through the provider.")


def test_a_removal_says_who_may_leave_a_department_another_mapping_still_names(monkeypatch):
    """Finance is mapped from two groups. One mapping is removed. "Nobody's department was changed by that" holds
    for the removal, and no further: the department is still mapped, so a linked member whose next sign-in names
    only the removed group leaves it. Said nowhere, the notice promised that nobody would move."""
    h = Mappings(monkeypatch)
    finance = h.department("Finance")
    first = h.add(provider_group="fin", department_id=str(finance.id))[1]["mapping"]["id"]
    second = h.add(provider_group="fin-contractors", department_id=str(finance.id))[1]["mapping"]["id"]
    _members(monkeypatch, {finance.id: 5})
    status, out = h.call("DELETE", f"{h.path}/{first}")
    assert status == 200 and out["may_leave"] == [
        {"department": {"id": str(finance.id), "name": "Finance"}, "accounts": 5}], out
    assert h.told[-1][2] == (
        "root removed the mapping of the group fin of the single sign-on provider contoso (it gave the department "
        "Finance). Nobody's department or role was changed by that. Another group is still mapped to the "
        "department. 5 account(s) linked to contoso are in the department Finance now: each leaves it at its next "
        "sign-in through the provider unless that sign-in names a group mapped to it.")
    # The last mapping that names the department: a sign-in no longer touches it, and nobody is counted.
    status, out = h.call("DELETE", f"{h.path}/{second}")
    assert status == 200 and out["may_leave"] == []
    assert h.told[-1][2].endswith("(it gave the department Finance). Nobody's department or role was changed by that.")


def test_a_change_says_who_may_leave_the_department_it_had_and_the_one_it_has(monkeypatch):
    h = Mappings(monkeypatch)
    finance, legal = h.department("Finance"), h.department("Legal")
    mapping = h.add(provider_group="fin", department_id=str(finance.id))[1]["mapping"]["id"]
    h.add(provider_group="fin-2", department_id=str(finance.id))
    asked = _members(monkeypatch, {finance.id: 4, legal.id: 2})
    # The group is renamed: the department follows the new name.
    status, out = h.call("PATCH", f"{h.path}/{mapping}", {"provider_group": "finance"})
    assert status == 200 and out["changed"] == ["provider_group"]
    assert out["may_leave"] == [{"department": {"id": str(finance.id), "name": "Finance"}, "accounts": 4}]
    assert asked == [finance.id]                       # one department touched, counted once
    assert h.told[-1][2].endswith("4 account(s) linked to contoso are in the department Finance now: each leaves it "
                                  "at its next sign-in through the provider unless that sign-in names a group mapped "
                                  "to it.")
    # Moved to another department: the one it had is still named by another mapping, and the one it has is named now.
    status, out = h.call("PATCH", f"{h.path}/{mapping}", {"department_id": str(legal.id)})
    assert status == 200 and out["may_leave"] == [
        {"department": {"id": str(finance.id), "name": "Finance"}, "accounts": 4},
        {"department": {"id": str(legal.id), "name": "Legal"}, "accounts": 2}], out
    # Nothing changed: nothing is counted or said.
    del asked[:]
    told = len(h.told)
    status, out = h.call("PATCH", f"{h.path}/{mapping}", {"department_id": str(legal.id)})
    assert status == 200 and out["changed"] == [] and "may_leave" not in out and asked == [] and len(h.told) == told


def test_a_count_that_cannot_be_made_holds_up_no_change(monkeypatch):
    from app.services import sso_groups
    h = Mappings(monkeypatch)
    finance = h.department("Finance")

    def down(db, row, department_id):
        raise RuntimeError("down")
    monkeypatch.setattr(sso_groups, "linked_members", down)
    status, out = h.add(provider_group="fin", department_id=str(finance.id))
    assert status == 201 and out["may_leave"] == [] and len(h.stored()) == 1


def _held_request(h, group, username="bob", state="held"):
    from datetime import datetime, timedelta
    from app.core.models import SsoAdminRequest
    now = datetime.utcnow()
    row = types.SimpleNamespace(id=uuid.uuid4(), user_id=uuid.uuid4(), provider_id=h.provider.id, provider_group=group,
                                requested_at=now, expires_at=now + timedelta(days=7), state=state, decided_by=None,
                                decided_by_name=None, decided_at=None)
    h.db.rows_of(SsoAdminRequest).append(row)
    return row


def _notices(h, monkeypatch):
    sent = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, *, title, body, target=None, dedup_prefix=None:
                        sent.append((list(ids), title, body, dedup_prefix)), raising=False)
    return sent


def test_removing_an_administrator_mapping_ends_the_requests_its_group_opened(monkeypatch):
    """Bob's request for the administrator role waits, opened through the group vault-admins. The mapping is
    removed. The request could no longer be approved, nor denied, and for seven days it kept Bob from asking again
    through another group. It is ended with the mapping, in the same transaction, with its record, and Bob is
    told; a request another group opened is left as it is."""
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    sent = _notices(h, monkeypatch)
    first = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    h.add(provider_group="it-admins", role="admin")
    waiting, other = _held_request(h, "vault-admins"), _held_request(h, "it-admins")
    decided = _held_request(h, "vault-admins", state="denied")
    h.told.clear()
    status, out = h.call("DELETE", f"{h.path}/{first}")
    assert status == 200 and out["requests_ended"] == 1, out
    assert waiting.state == "expired" and waiting.decided_at is not None
    assert other.state == "held" and decided.state == "denied"
    assert h.audit("sso_admin_expired") == [("sso_admin_expired", "success", {
        "provider_id": str(h.provider.id), "user_id": str(waiting.user_id), "reason": "mapping_gone"})]
    assert h.told[-1][2].endswith(
        "Nobody's department or role was changed by that. 1 request(s) for the administrator role that the group "
        "had opened were ended with nothing decided, and the people told.")
    (to, title, body, dedup), = sent
    assert to == [str(waiting.user_id)] and title == "Your request for the administrator role ended"
    assert "is no longer mapped to the administrator role" in body and "Your account is unchanged" in body
    assert dedup == f"sso_admin_ended:{waiting.id}"


@pytest.mark.parametrize("change, ends", [
    ({"provider_group": "dv-admins"}, True),          # the group is renamed
    ({"role": "user"}, True),                         # the role is taken from the mapping
    ({"role": None, "department_id": "FINANCE"}, True),
    ({"department_id": "FINANCE"}, False),            # the role and the group stay: the request stands
])
def test_a_change_that_takes_the_role_from_a_group_ends_its_requests(monkeypatch, change, ends):
    """The organisation renames its administrators' group, and an administrator renames the mapping to match.
    Bob's request, opened through the old name, could be neither approved nor denied afterwards, and no new one
    was opened for seven days: he could not be made an administrator through the provider at all."""
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    sent = _notices(h, monkeypatch)
    finance = h.department("Finance")
    mapping = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    waiting = _held_request(h, "vault-admins")
    body = {k: (str(finance.id) if v == "FINANCE" else v) for k, v in change.items()}
    status, out = h.call("PATCH", f"{h.path}/{mapping}", body)
    assert status == 200 and out["requests_ended"] == (1 if ends else 0), out
    assert waiting.state == ("expired" if ends else "held")
    assert len(h.audit("sso_admin_expired")) == (1 if ends else 0) and len(sent) == (1 if ends else 0)
    assert ("were ended with nothing decided" in h.told[-1][2]) is ends


def test_a_groups_name_is_kept_letter_for_letter_as_the_sign_in_compares_it(monkeypatch):
    """The provider sends a group with a space after its name, another with a no-break space in it, another with
    an invisible mark. The save trimmed the first, so the stored name never matched what the provider sends, and
    refused the other two as "control characters". A mapping keeps the name as it was given; only a control
    character, a name of nothing but spaces, and a name too long are refused."""
    from app.services import sso_group_mappings as M
    h = Mappings(monkeypatch)
    finance = h.department("Finance")
    kept = ["vault-users ", " leading", "Finance\u00a0Team", "ops\u200b", "r\u00e9sum\u00e9", "x" * 255]
    assert kept[2][7] == chr(0xA0) and kept[3][-1] == chr(0x200B)
    for name in kept:
        assert M._group(name) == name
        status, out = h.add(provider_group=name, department_id=str(finance.id))
        assert status == 201 and out["mapping"]["provider_group"] == name, (name, out)
    assert [stored[0] for stored in h.stored()] == kept
    for refused in ("", "   ", "\t", "line\nbreak", "bell\x07", "c1\x85", "x" * 256, 7, None, ["a"]):
        status, out = h.add(provider_group=refused, department_id=str(finance.id))
        assert status == 400 and out["detail"]["field"] == "provider_group", (refused, out)
    # The same name with and without the space are two groups, as they are two to the provider.
    assert h.add(provider_group="vault-users", department_id=str(finance.id))[0] == 201


KEPT = ("administrator(s) were approved through the group vault-admins and keep the role. Leaving that group no "
        "longer takes it from them at a sign-in through contoso: where an account should lose the role, take it "
        "under Users.")


@pytest.mark.parametrize("change, taken", [
    ({"provider_group": "dv-admins"}, True),          # the group is renamed
    ({"role": "user"}, True),                         # the role is taken from the mapping
    ({"role": None, "department_id": "FINANCE"}, True),
    ({"department_id": "FINANCE"}, False),            # the role and the group stay
])
def test_a_change_that_takes_the_role_from_a_group_says_who_keeps_it(monkeypatch, change, taken):
    """The organisation renames its administrators' group and an administrator renames the mapping to match. The
    people approved through the old name keep the role, and from that save on leaving the group at the provider
    takes it from none of them: until then it did, at their next sign-in. Nothing told the administrator who
    made the change. The answer and the notice say how many such administrators there are, asked of the group the
    mapping had."""
    from app.services import sso_groups
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    finance = h.department("Finance")
    mapping = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    asked = []
    monkeypatch.setattr(sso_groups, "kept_by_the_end_of_a_mapping",
                        lambda db, row, group: asked.append((row.id, group)) or 2)
    body = {k: (str(finance.id) if v == "FINANCE" else v) for k, v in change.items()}
    status, out = h.call("PATCH", f"{h.path}/{mapping}", body)
    assert status == 200 and out["administrators_kept"] == (2 if taken else 0), out
    assert asked == ([(h.provider.id, "vault-admins")] if taken else [])
    assert h.told[-1][2].endswith(" 2 " + KEPT) is taken and (KEPT in h.told[-1][2]) is taken


def test_removing_an_administrator_mapping_says_who_keeps_the_role(monkeypatch):
    """The removal says that nobody's role was changed by it. It did not say that the administrators approved
    through the group are, from then on, administrators no sign-in demotes."""
    from app.services import sso_groups
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    first = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    second = h.add(provider_group="staff", role="user")[1]["mapping"]["id"]
    asked = []
    monkeypatch.setattr(sso_groups, "kept_by_the_end_of_a_mapping",
                        lambda db, row, group: asked.append((row.id, group)) or 3)
    status, out = h.call("DELETE", f"{h.path}/{first}")
    assert status == 200 and out["administrators_kept"] == 3 and asked == [(h.provider.id, "vault-admins")], out
    assert h.told[-1][2].endswith("Nobody's department or role was changed by that. 3 " + KEPT)
    # A mapping that gave another role: nobody is asked about, and nothing is said.
    status, out = h.call("DELETE", f"{h.path}/{second}")
    assert status == 200 and out["administrators_kept"] == 0 and len(asked) == 1, out
    assert "keep the role" not in h.told[-1][2]
    # None approved through the group: the count is given, and no sentence.
    third = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    monkeypatch.setattr(sso_groups, "kept_by_the_end_of_a_mapping", lambda db, row, group: 0)
    status, out = h.call("DELETE", f"{h.path}/{third}")
    assert status == 200 and out["administrators_kept"] == 0 and "keep the role" not in h.told[-1][2]


def test_the_count_of_who_keeps_the_role_is_read_once_the_mapping_is_gone(monkeypatch):
    """Through the route with the count itself: read after the removal is committed, so the group it asks about is
    mapped to the role no more, and the administrator approved through it is counted."""
    from app.core.models import SsoAdminRequest, User
    from app.services import sso_groups
    from test_sso_sign_in import _user
    bob = _user("bob", role="admin")
    h = Mappings(monkeypatch, _provider(created_at=None, updated_at=None, policy=dict(ADMIN_ON)))
    h.db.rows_of(User).append(bob)
    mapping = h.add(provider_group="vault-admins", role="admin")[1]["mapping"]["id"]
    approval = _held_request(h, "vault-admins", state="approved")
    approval.user_id = bob.id
    assert approval in h.db.rows_of(SsoAdminRequest)
    monkeypatch.setattr(sso_groups, "approved_through", lambda db, user, row: "vault-admins")
    assert sso_groups.kept_by_the_end_of_a_mapping(h.db, h.provider, "vault-admins") == 0     # while it is mapped
    status, out = h.call("DELETE", f"{h.path}/{mapping}")
    assert status == 200 and out["administrators_kept"] == 1, out
    assert h.told[-1][2].endswith("Nobody's department or role was changed by that. 1 " + KEPT)
