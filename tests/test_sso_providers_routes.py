"""The provider administration routes (app/api/sso_providers_router.py, the test start in app/api/sso_router.py)
through the ASGI app against an in-memory database: the order every write keeps (the deployment's lock, the
judgement, the step-up, the change, its audit row, the notice), the answers of each route, a test sign-in's start,
and the buttons the sign-in page is given. Offline."""
import types
import uuid

import pytest

from test_sso_sign_in import BASE, DB, Harness, _call, _h, _identity, _provider, _user

pytestmark = pytest.mark.unit

ISSUER_2 = "https://login.example.org/tenant/v2.0"


class _Rows(DB):
    """Rows get their id when they are added, as a flush would give it, and can be deleted."""

    def add(self, obj):
        if getattr(obj, "id", None) is None and hasattr(type(obj), "id"):
            obj.id = uuid.uuid4()
        super().add(obj)

    def delete(self, obj):
        for rows in self.tables.values():
            if any(row is obj for row in rows):
                rows[:] = [row for row in rows if row is not obj]
        self.log.append(("delete", getattr(obj, "name", None)))


class Admin(Harness):
    """The sign-in harness with an administrator signed in, the step-up, the notices and the lock observed."""

    def __init__(self, monkeypatch, providers=(), users=(), identities=()):
        root = _user("root", role="admin")
        super().__init__(monkeypatch, [root, *users], list(providers), identities=identities)
        from app.api import sso_providers_router as R
        from app.core import security, sso_settings
        from app.core.database import get_db
        self.R, self.root = R, root
        tables = dict(self.db.tables)
        self.db = _Rows(tables)
        monkeypatch.setitem(self.S.app.dependency_overrides, get_db, lambda: self.db)
        self.order, self.told, self.is_locked = [], [], False
        self.accounts_told = []            # what account owners were told: (usernames, title, text)
        monkeypatch.setattr(R, "_tell_accounts", lambda users, title, change: users and self.accounts_told.append(
            (sorted(name for _id, name, _email in users), title, change)))
        monkeypatch.setattr(R, "_step_up", lambda db, user, request: self.order.append("step_up"))
        monkeypatch.setattr(R, "_tell_administrators", lambda by, title, body: self.told.append((by, title, body)))
        monkeypatch.setattr(sso_settings, "locked", lambda settings=None: self.is_locked)
        monkeypatch.setattr(security, "encrypt_secret", lambda value: "enc(" + "*" * len(value) + ")")
        monkeypatch.setattr(self.S, "_account_policy", lambda db: {})

    def rows(self):
        from app.core.models import SsoProvider
        return self.db.rows_of(SsoProvider)

    def audit(self, action):
        return [a for a in self.audits if a[0] == action]

    def call(self, method, path, body=None):
        status, out, _headers = _call(self.S, method, path, body)
        return status, out


def _tested(row):
    from app.services import sso_providers
    row.last_test = {"outcome": "ok", "auth_time_present": True, "config": sso_providers.fingerprint(row)}
    return row


def test_the_list_gives_the_page_everything_it_draws(monkeypatch):
    a = _provider(name="zeta", label=None, sort_order=2, state="draft", created_at=None, updated_at=None)
    b = _provider(name="alpha", label="Company sign-in", sort_order=1, created_at=None, updated_at=None)
    h = Admin(monkeypatch, [a, b])
    status, out = h.call("GET", "/admin/sso/providers")
    assert status == 200, out
    assert [p["name"] for p in out["providers"]] == ["alpha", "zeta"]          # the sign-in page's order
    assert out["address"] == {"usable": True, "base": BASE, "why_not": None}
    assert out["locked"] is False and out["limit"] == 20 and out["step_up"] == "admin.auth_policy.write"
    assert [p["id"] for p in out["presets"]][0] == "entra" and "microsoft" in out["icons"]
    assert "client_secret_enc" not in str(out) and out["providers"][0]["has_client_secret"] is True
    assert h.order == []                                                        # a read asks no step-up
    status, one = h.call("GET", f"/admin/sso/providers/{b.id}")
    assert status == 200 and one["provider"]["id"] == str(b.id)
    assert h.call("GET", f"/admin/sso/providers/{uuid.uuid4()}")[0] == 404
    assert h.call("GET", "/admin/sso/providers/not-an-id")[0] == 404


def test_without_an_address_the_list_says_what_to_change(monkeypatch):
    h = Admin(monkeypatch, [_provider(created_at=None, updated_at=None)])
    from app.core import public_url
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    monkeypatch.setattr(public_url, "why_not_usable", lambda: "Set ALLOWED_HOSTS in .env.")
    out = h.call("GET", "/admin/sso/providers")[1]
    assert out["address"] == {"usable": False, "base": None,
                              "why_not": "Single sign-on needs the vault's public address. Set ALLOWED_HOSTS in .env."}
    assert out["providers"][0]["addresses"] is None


def test_a_draft_is_made_after_the_step_up_and_recorded(monkeypatch):
    h = Admin(monkeypatch)
    # Judged before anything is asked of the administrator.
    assert h.call("POST", "/admin/sso/providers", {"name": "x", "preset": "made-up"}) == (
        400, {"detail": {"reason": "invalid", "field": "preset", "message": "Provider: Unknown preset."}})
    assert h.order == [] and h.rows() == []
    status, out = h.call("POST", "/admin/sso/providers", {"name": " Entra ", "preset": "entra"})
    assert status == 201, out
    shown = out["provider"]
    assert (shown["name"], shown["state"], shown["icon"], shown["configured"]) == ("Entra", "draft", "microsoft", False)
    assert shown["addresses"]["redirect_uri"] == f"{BASE}/auth/sso/{shown['id']}/callback"
    assert h.order == ["step_up"] and len(h.rows()) == 1 and h.rows()[0].created_by_name == "root"
    assert h.audit("sso_provider_created") == [("sso_provider_created", "success", {
        "provider_id": shown["id"], "name": "Entra", "preset": "entra"})]
    assert h.told == [("root", "A single sign-on provider was added",
                       "root added the single sign-on provider Entra. It is off until it is tested and turned on.")]
    status, out = h.call("POST", "/admin/sso/providers", {"name": "entra"})
    assert status == 409 and out["detail"]["reason"] == "name_taken" and h.order == ["step_up"]


def test_a_change_is_judged_then_stepped_up_then_written_and_recorded_by_field_name(monkeypatch):
    row = _provider(state="draft", issuer=None, client_id=None, client_secret_enc=None, label=None,
                    created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    path = f"/admin/sso/providers/{row.id}"
    for body, field, said in (
            ({"issuer": "http://plain.example.org"}, "issuer", "Issuer: The endpoint must use https."),
            ({"made_up": 1}, "made_up", "Unknown field."),
            ({"policy": {"sso_freshness_days": 999}}, "policy.sso_freshness_days",
             "Days without signing in: A whole number from 0 to 365.")):
        status, out = h.call("PATCH", path, body)
        assert status == 400 and out["detail"] == {"reason": "invalid", "field": field, "message": said}, out
    status, out = h.call("PATCH", path, {"policy": {"sso_account_creation": "jit"}})
    assert status == 409 and out["detail"]["reason"] == "needs_restriction"
    assert h.order == [] and row.issuer is None and h.audits == []
    # Nothing to change: answered as it is, nothing asked.
    status, out = h.call("PATCH", path, {})
    assert status == 200 and out["changed"] == [] and h.order == []
    status, out = h.call("PATCH", path, {"issuer": ISSUER_2, "client_id": "client-1", "client_secret": "s3cret",
                                         "label": "Company sign-in", "policy": {"sso_freshness_days": 7}})
    assert status == 200, out
    assert out["changed"] == ["label", "issuer", "client_id", "client_secret", "policy.sso_freshness_days"]
    assert out["connection_changed"] is True and out["provider"]["configured"] is True
    assert h.order == ["step_up"]
    assert row.issuer == ISSUER_2 and row.client_secret_enc == "enc(******)" and row.policy == {"sso_freshness_days": 7}
    assert "s3cret" not in str(out) and "enc(" not in str(out)
    (audit,) = h.audit("sso_provider_updated")
    assert audit[2] == {"provider_id": str(row.id), "name": row.name, "made_sso_only": 0, "restored": 0,
                        "changed": ["label", "issuer", "client_id", "client_secret", "policy.sso_freshness_days"]}
    assert "s3cret" not in str(h.audits) and ISSUER_2 not in str(h.audits)     # names of fields, never a value
    assert len(h.told) == 1 and "s3cret" not in str(h.told) and "client_secret" in h.told[0][2]
    # The same values again: the step-up is asked (a change was sent), nothing is recorded or told.
    status, out = h.call("PATCH", path, {"label": "Company sign-in"})
    assert status == 200 and out["changed"] == [] and len(h.audit("sso_provider_updated")) == 1 and len(h.told) == 1


def test_turning_password_sign_in_off_names_the_accounts_and_says_so_to_the_administrators(monkeypatch):
    row = _provider(created_at=None, updated_at=None)
    alice, bob = _user("alice"), _user("bob")
    h = Admin(monkeypatch, [row], users=[alice, bob], identities=[_identity(alice, row), _identity(bob, row, subject="s-2")])
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_password_login": "disabled"}})
    assert status == 200, out
    assert out["made_sso_only"] == ["alice", "bob"] and out["restored"] == [] and alice.sso_only is True
    assert out["provider"]["sso_only_accounts"] == 2
    assert h.audit("sso_provider_updated")[0][2]["made_sso_only"] == 2
    assert h.told[0][2].endswith("2 linked account(s) now sign in only through it.")
    # A change another person made to how an account signs in is told to its owner.
    label = row.label or row.name
    assert h.accounts_told == [(["alice", "bob"], "Your password no longer works on this vault", (
        f"An administrator turned password sign-in off for {label}. Your account now signs in only through {label}: "
        "its password and its SFTP password sign-in no longer work."))]
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_password_login": "allowed"}})
    assert status == 200 and out["restored"] == ["alice", "bob"] and alice.sso_only is False
    assert "reset" not in str(out).lower() and h.told[1][2].endswith("2 linked account(s) may hold a password again.")
    assert len(h.accounts_told) == 2 and h.accounts_told[1][:2] == (["alice", "bob"], "You can set a password again")
    assert "Forgot password" in h.accounts_told[1][2] and f"still sign in through {label}" in h.accounts_told[1][2]
    # An administrator linked to it keeps the setting from being turned off at all.
    h.db.rows_of(type(_identity(h.root, row))).clear()
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(_identity(h.root, row, subject="s-root"))
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_password_login": "disabled"}})
    assert status == 409 and out["detail"]["reason"] == "privileged_linked" and "root" in out["detail"]["message"]


def test_a_provider_is_turned_on_only_tested_and_off_at_once(monkeypatch):
    row = _provider(state="draft", created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    path = f"/admin/sso/providers/{row.id}/state"
    assert h.call("POST", path, {"state": "tested"})[0] == 400
    status, out = h.call("POST", path, {"state": "enabled"})
    assert status == 409 and out["detail"]["reason"] == "not_tested" and h.order == [] and row.state == "draft"
    _tested(row)
    status, out = h.call("POST", path, {"state": "enabled"})
    assert status == 200 and out["changed"] is True and row.state == "enabled" and h.order == ["step_up"]
    assert h.audit("sso_provider_updated")[0][2] == {"provider_id": str(row.id), "name": row.name,
                                                     "changed": ["state"], "state": "enabled"}
    assert h.told[0][1] == "A single sign-on provider was turned on"
    # Already so: nothing asked, nothing recorded.
    status, out = h.call("POST", path, {"state": "enabled"})
    assert status == 200 and out["changed"] is False and h.order == ["step_up"]
    # Off is never refused, whatever depends on the provider.
    row.last_test = None
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and row.state == "disabled" and h.order == ["step_up", "step_up"]
    assert h.told[1][1] == "A single sign-on provider was turned off"
    # Without an address the provider can send a browser back to, nothing is turned on.
    _tested(row)
    from app.core import public_url
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    monkeypatch.setattr(public_url, "why_not_usable", lambda: "Set ALLOWED_HOSTS in .env.")
    status, out = h.call("POST", path, {"state": "enabled"})
    assert status == 409 and out["detail"]["reason"] == "no_public_address" and row.state == "disabled"
    assert out["detail"]["message"] == "Single sign-on needs the vault's public address. Set ALLOWED_HOSTS in .env."


def test_a_provider_is_removed_with_its_links_only_when_nothing_depends_on_it(monkeypatch):
    row = _provider(created_at=None, updated_at=None)
    alice = _user("alice")
    h = Admin(monkeypatch, [row], users=[alice], identities=[_identity(alice, row)])
    path = f"/admin/sso/providers/{row.id}"
    status, out = h.call("DELETE", path)
    assert status == 409 and out["detail"]["reason"] == "still_on" and h.order == [] and h.rows() == [row]
    row.state = "disabled"
    row.policy = {"sso_password_login": "disabled"}          # its people hold no password because of it
    alice.sso_only = True
    status, out = h.call("DELETE", path)
    assert out["detail"]["reason"] == "only_way_in" and "Allow password sign-in for this provider first" in out["detail"]["message"]
    row.policy = None                                           # allowed again (the save settles the accounts)
    alice.sso_only = False
    status, out = h.call("DELETE", path)
    assert status == 200 and out == {"removed": True} and h.rows() == [] and h.order == ["step_up"]
    # Each account that was linked is told it lost a way to sign in.
    assert h.accounts_told == [(["alice"], "A sign-in method was removed from your account", (
        f"An administrator removed {row.label or row.name} from this vault: your account can no longer sign in through it."))]
    assert h.audit("sso_provider_deleted") == [("sso_provider_deleted", "success", {
        "provider_id": str(row.id), "name": row.name, "identities": 1})]
    assert h.told == [("root", "A single sign-on provider was removed",
                       f"root removed the single sign-on provider {row.name}, with the links of 1 account(s) to it.")]
    assert h.call("DELETE", path)[0] == 404


def test_a_locked_deployment_changes_nothing_and_asks_nothing(monkeypatch):
    row = _tested(_provider(state="draft", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    h.is_locked = True
    locked = {"detail": {"reason": "locked", "message": "Single sign-on is set by your provider on this deployment: "
                                                         "nothing can be changed here."}}
    path = f"/admin/sso/providers/{row.id}"
    for method, where, body in (("POST", "/admin/sso/providers", {"name": "new"}), ("PATCH", path, {"label": "x"}),
                                ("POST", path + "/state", {"state": "enabled"}), ("DELETE", path, None)):
        assert h.call(method, where, body) == (409, locked), (method, where)
    assert h.order == [] and h.audits == [] and h.told == [] and h.rows() == [row] and row.state == "draft"
    # It is still listed, and says it is locked.
    status, out = h.call("GET", "/admin/sso/providers")
    assert status == 200 and out["locked"] is True and len(out["providers"]) == 1


def test_only_an_administrator_reaches_these_routes(monkeypatch):
    row = _provider(created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    from fastapi import HTTPException
    from app.api.user_management_api import require_interactive_admin

    def _no():
        raise HTTPException(status_code=403, detail="Administrators only.")
    monkeypatch.setitem(h.S.app.dependency_overrides, require_interactive_admin, _no)
    path = f"/admin/sso/providers/{row.id}"
    for method, where, body in (("GET", "/admin/sso/providers", None), ("GET", path, None),
                                ("POST", "/admin/sso/providers", {"name": "new"}), ("PATCH", path, {"label": "x"}),
                                ("POST", path + "/state", {"state": "disabled"}), ("DELETE", path, None),
                                ("POST", path + "/test/start", {"verifier_hash": _h("v")})):
        assert h.call(method, where, body)[0] == 403, (method, where)
    assert h.order == [] and row.state == "enabled" and row.label != "x"


def test_every_write_asks_the_fixed_step_up_of_the_sign_in_settings():
    from app.api import sso_providers_router as R
    from app.core import fixed_step_up
    assert R.STEP_UP_ACTION == "admin.auth_policy.write" and R._step_up.action == R.STEP_UP_ACTION
    assert R.STEP_UP_ACTION in fixed_step_up.GUARDED


# --------------------------------------------------------------------------- a test sign-in's start

def test_a_test_sign_in_starts_for_a_provider_that_is_filled_in_whatever_its_state(monkeypatch):
    from urllib.parse import parse_qs, urlsplit
    row = _provider(state="draft", created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/test/start", {"verifier_hash": _h("tab")})
    assert status == 200, out
    query = parse_qs(urlsplit(out["authorization_url"]).query)
    assert query["redirect_uri"] == [f"{BASE}/auth/sso/{row.id}/callback"] and query["client_id"] == [row.client_id]
    assert out["expires_in"] > 0 and h.order == []                       # a test asks no step-up
    from app.core import sso_state
    state = sso_state.take(query["state"][0])
    assert (state.purpose, state.provider_id, state.user_id) == ("test", str(row.id), str(h.root.id))
    assert state.verifier_hash == _h("tab") and state.session_hash == h.session_hash
    assert row.state == "draft" and row.last_test is None                # nothing written by a start
    assert h.call("POST", f"/admin/sso/providers/{uuid.uuid4()}/test/start", {"verifier_hash": _h("tab")})[0] == 404
    assert h.call("POST", f"/admin/sso/providers/{row.id}/test/start", {})[0] == 422


def test_a_test_sign_in_needs_the_connection_and_an_address(monkeypatch):
    row = _provider(state="draft", client_secret_enc=None, created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    path = f"/admin/sso/providers/{row.id}/test/start"
    assert h.call("POST", path, {"verifier_hash": _h("tab")}) == (409, {"detail": {
        "reason": "not_configured", "message": "Enter the issuer, the client id and the client secret first."}})
    row.client_secret_enc = "enc"
    from app.core import public_url
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    status, out = h.call("POST", path, {"verifier_hash": _h("tab")})
    assert status == 409 and out["detail"]["reason"] == "no_public_address"
    assert h.redis.rows == {} if hasattr(h.redis, "rows") else True      # no state was made


def test_a_finished_test_keeps_the_connections_fingerprint_with_its_summary(monkeypatch):
    from app.services import sso_providers, sso_sign_in
    row = _provider(state="draft", created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    answer = sso_sign_in.ProviderAnswer(claims={"sub": "s-1"}, subject="s-1", issuer=row.issuer, tenant_id=None,
                                        email=None, email_verified=False, display_name=None, auth_time=None)
    summary = sso_sign_in.test_summary(h.db, row, answer, h.root)
    assert summary["config"] == sso_providers.fingerprint(row) and summary["outcome"] == "ok"
    row.last_test = summary
    assert sso_providers.tested(row)
    assert "config" not in sso_providers.public(h.db, row)["last_test"]


# --------------------------------------------------------------------------- the sign-in page's buttons

def test_the_sign_in_page_gets_a_button_for_each_provider_that_is_on_and_shown(monkeypatch):
    on = _provider(name="b-on", label="Company sign-in", sort_order=2, icon="microsoft")
    first = _provider(name="a-first", label=None, sort_order=1, icon=None)
    hidden = _provider(name="hidden", show_on_sign_in=False)
    off = _provider(name="off", state="disabled")
    draft = _provider(name="draft", state="draft")
    half = _provider(name="half", client_secret_enc=None)
    h = Admin(monkeypatch, [on, first, hidden, off, draft, half])
    assert h.S._sign_in_providers(h.db) == [
        {"id": str(first.id), "label": "a-first", "kind": "oidc", "icon": "generic", "order": 1},
        {"id": str(on.id), "label": "Company sign-in", "kind": "oidc", "icon": "microsoft", "order": 2}]
    methods = h.S._sign_in_methods(h.db)
    assert methods["providers"] == h.S._sign_in_providers(h.db) and set(methods) == {"password", "passkeys", "providers", "origin"}
    # Never an issuer, a client id or anything of the connection.
    assert not {"issuer", "client_id", "name", "state"} & set(methods["providers"][0])
    # No address a provider can send the browser back to: no button, since no sign-in could start.
    from app.core import public_url
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    assert h.S._sign_in_providers(h.db) == []


def test_a_database_that_cannot_be_read_leaves_the_sign_in_page_its_form(monkeypatch):
    h = Admin(monkeypatch, [_provider()])

    class Broken:
        def query(self, *a, **kw):
            raise RuntimeError("down")
    assert h.S._sign_in_providers(Broken()) == []
    assert h.S._sign_in_providers(types.SimpleNamespace(get_bind=lambda: (_ for _ in ()).throw(RuntimeError("down")))) == []


def test_what_changed_while_the_administrator_confirmed_is_judged_again(monkeypatch):
    """The step-up takes a moment and may commit; each write judges once more on the row as it then stands."""
    row = _tested(_provider(state="draft", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    path = f"/admin/sso/providers/{row.id}"

    def meanwhile(change):
        def step_up(db, user, request):
            h.order.append("step_up")
            change()
        monkeypatch.setattr(h.R, "_step_up", step_up)

    # Turned on: the connection moved on from its test meanwhile.
    meanwhile(lambda: setattr(row, "client_id", "client-9"))
    status, out = h.call("POST", path + "/state", {"state": "enabled"})
    assert status == 409 and out["detail"]["reason"] == "not_tested" and row.state == "draft"
    # Removed: turned on meanwhile.
    meanwhile(lambda: setattr(row, "state", "enabled"))
    status, out = h.call("DELETE", path)
    assert status == 409 and out["detail"]["reason"] == "still_on" and h.rows() == [row]
    # Renamed: the name taken meanwhile.
    row.state = "disabled"
    meanwhile(lambda: h.rows().append(_provider(name="Taken", created_at=None, updated_at=None)))
    status, out = h.call("PATCH", path, {"name": "taken"})
    assert status == 409 and out["detail"]["reason"] == "name_taken" and row.name == "contoso"
    assert h.order == ["step_up"] * 3 and h.audits == [] and h.told == []


# --------------------------------------------------------------------------- Your account

def test_your_account_lists_the_providers_it_is_linked_to_or_could_link(monkeypatch):
    shown = _provider(name="b-shown", label="Company sign-in", sort_order=2, icon="microsoft")
    first = _provider(name="a-first", label=None, sort_order=1, icon=None,
                      last_test={"outcome": "ok", "auth_time_present": True})
    hidden = _provider(name="hidden", show_on_sign_in=False)
    hidden_linked = _provider(name="hidden-linked", label=None, show_on_sign_in=False, sort_order=3)
    off = _provider(name="off", state="disabled")
    off_linked = _provider(name="off-linked", label=None, state="disabled")
    half = _provider(name="half", client_secret_enc=None)
    h = Admin(monkeypatch, [shown, first, hidden, hidden_linked, off, off_linked, half])
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).extend([_identity(h.root, first), _identity(h.root, hidden_linked, subject="s-2"),
                                           _identity(h.root, off_linked, subject="s-3"),
                                           _identity(_user("someone"), shown, subject="s-4")])
    status, out = h.call("GET", "/users/me/identities")
    assert status == 200, out
    assert sorted(i["provider"] for i in out["identities"]) == ["a-first", "hidden-linked", "off-linked"]
    assert out["providers"] == [
        # An administrator confirms with a password of its own: no provider stands in for it.
        {"id": str(first.id), "label": "a-first", "icon": "generic", "linked": True, "ends_password": False, "reauth": False},
        {"id": str(shown.id), "label": "Company sign-in", "icon": "microsoft", "linked": False, "ends_password": False,
         "reauth": False},
        {"id": str(hidden_linked.id), "label": "hidden-linked", "icon": "generic", "linked": True, "ends_password": False,
         "reauth": False}]
    # A provider whose people hold no password: the page is told before the link that linking ends the password.
    shown.policy = {"sso_password_login": "disabled"}
    status, out = h.call("GET", "/users/me/identities")
    assert [(p["label"], p["ends_password"]) for p in out["providers"]] == [
        ("a-first", False), ("Company sign-in", True), ("hidden-linked", False)]
    shown.policy = None
    # Nothing of a provider's connection rides along.
    assert not {"issuer", "client_id", "name", "state"} & set(out["providers"][0])
    # Without an address a provider can send the browser back to, nothing can be linked: none is offered.
    from app.core import public_url
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    out = h.call("GET", "/users/me/identities")[1]
    assert out["providers"] == [] and len(out["identities"]) == 3


# --------------------------------------------------------------------------- a provider that is on, changed or turned off

def _watch_turn_off(monkeypatch, h, ended=3, held=2):
    """What turning a provider off does beside the state, observed: (the state the row had when the lapsed accounts
    were held, the provider whose sessions were ended)."""
    from app.services import sso_providers
    seen = []
    monkeypatch.setattr(sso_providers, "hold_lapsed", lambda db, row, now=None: seen.append(("held", row.state)) or held)
    monkeypatch.setattr(h.R, "_end_sessions_of", lambda db, provider_id: seen.append(("ended", str(provider_id))) or ended)
    return seen


def test_a_change_to_the_connection_of_a_provider_that_is_on_turns_it_off_until_tested_again(monkeypatch):
    """One administrator points a provider that is on at another discovery address. It does not go on signing people
    in on a connection nobody tested: the change turns it off, ends the sessions that came through it, holds the
    lapsed accounts, and drops the stored secret, which was never entered for that address. It comes on again only
    after the secret is entered and a test sign-in passes."""
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    seen = _watch_turn_off(monkeypatch, h)
    path = f"/admin/sso/providers/{row.id}"
    status, out = h.call("PATCH", path, {"discovery_url": "https://elsewhere.example.net/.well-known/openid-configuration"})
    assert status == 200, out
    assert out["turned_off"] is True and out["secret_cleared"] is True and out["sessions_ended"] == 3 and out["held"] == 2
    assert row.state == "disabled" and row.client_secret_enc is None
    assert out["provider"]["state"] == "disabled" and out["provider"]["has_client_secret"] is False
    assert seen == [("held", "enabled"), ("ended", str(row.id))]       # held while it still read as on, then ended
    said = h.told[-1][2]
    assert "turned off until a test sign-in passes again" in said and "3 session(s)" in said
    assert "must be entered again" in said
    # It does not come back on by itself: no secret, then no test of the connection as it is now.
    status, out = h.call("POST", f"{path}/state", {"state": "enabled"})
    assert status == 409 and out["detail"]["reason"] == "not_configured" and row.state == "disabled"
    status, out = h.call("PATCH", path, {"client_secret": "entered-again"})
    assert status == 200 and out["turned_off"] is False and row.client_secret_enc
    status, out = h.call("POST", f"{path}/state", {"state": "enabled"})
    assert status == 409 and out["detail"]["reason"] == "not_tested" and row.state == "disabled"
    # A connection field that does not say where the provider is turns it off as well, and keeps the secret.
    _tested(row)
    row.state = "enabled"
    seen.clear()
    status, out = h.call("PATCH", path, {"client_id": "another-client"})
    assert status == 200 and out["turned_off"] is True and out["secret_cleared"] is False and row.state == "disabled"
    assert row.client_secret_enc and seen == [("held", "enabled"), ("ended", str(row.id))]
    # What is not the connection leaves a provider that is on as it is.
    _tested(row)
    row.state = "enabled"
    seen.clear()
    status, out = h.call("PATCH", path, {"label": "Staff sign-in", "policy": {"sso_freshness_days": 14}})
    assert status == 200 and out["turned_off"] is False and row.state == "enabled" and seen == []
    # And a provider that is off is not turned off again by a change.
    row.state = "disabled"
    status, out = h.call("PATCH", path, {"client_id": "a-third-client"})
    assert status == 200 and out["turned_off"] is False and seen == []


def test_turning_a_provider_off_ends_its_sessions_and_holds_the_lapsed_accounts(monkeypatch):
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    seen = _watch_turn_off(monkeypatch, h, ended=4, held=1)
    path = f"/admin/sso/providers/{row.id}/state"
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is True and out["sessions_ended"] == 4 and out["held"] == 1, out
    assert row.state == "disabled" and seen == [("held", "enabled"), ("ended", str(row.id))]
    audit = h.audit("sso_provider_updated")[-1][2]
    assert audit["state"] == "disabled" and audit["sessions"] == 4 and audit["identities"] == 1
    said = h.told[-1][2]
    assert "4 session(s) that came through it were ended" in said and "1 account(s) whose sign-in there had lapsed stay held" in said
    # Turning it on ends nothing and holds nobody, and its answer says nothing of either.
    seen.clear()
    status, out = h.call("POST", path, {"state": "enabled"})
    assert status == 200 and out["changed"] is True and "sessions_ended" not in out and "held" not in out and seen == []
    # Off when it is off already: nothing happens.
    row.state = "disabled"
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is False and seen == []


def test_the_sessions_of_a_provider_are_ended_under_each_owners_turn(monkeypatch):
    """Every session recorded for the provider, and none of another provider's: each owner's turn at their sessions
    is taken first (a renewal moves the provider's session to its new row under the same turn), then they are ended
    for good. A failure ends none and does not raise: the provider stays off."""
    from app.api import sso_router
    from app.core.models import SsoSession
    row, other = _provider(created_at=None, updated_at=None), _provider(name="other", created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row, other])
    mine = [types.SimpleNamespace(session_id=uuid.uuid4(), provider_id=row.id) for _ in range(2)]
    theirs = types.SimpleNamespace(session_id=uuid.uuid4(), provider_id=other.id)
    h.db.tables.setdefault(SsoSession, []).extend(mine + [theirs])
    order = []
    monkeypatch.setattr(sso_router, "_owners_of", lambda db, ids: order.append(("owners", sorted(map(str, ids)))) or ["u1", "u2"])
    monkeypatch.setattr(h.S, "_sessions_turn", lambda db, owner: order.append(("turn", owner)))
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, session_ids=None, actor_username=None, durable=False: (
        order.append(("revoke", sorted(map(str, session_ids)), actor_username, durable)) or len(session_ids)))
    wanted = sorted(str(s.session_id) for s in mine)
    assert h.R._end_sessions_of(h.db, row.id) == 2
    assert order == [("owners", wanted), ("turn", "u1"), ("turn", "u2"), ("revoke", wanted, "provider turned off", True)]
    order.clear()
    assert h.R._end_sessions_of(h.db, uuid.uuid4()) == 0 and order == []        # a provider with none

    def broken(db, session_ids=None, actor_username=None, durable=False):
        raise RuntimeError("down")
    monkeypatch.setattr(h.S, "_revoke_sessions", broken)
    assert h.R._end_sessions_of(h.db, row.id) == 0


def test_a_test_sign_in_speaks_for_the_connection_it_was_made_with(monkeypatch):
    """A connection saved while the provider is answering a test sign-in was not tested by it. The summary carries
    the fingerprint of the provider as the sign-in was made with it, so the provider with the newer connection does
    not read as tested and cannot be turned on with it."""
    from app.core import sso_state
    from app.services import oidc_client as oc
    from app.services import sso_providers
    from app.services import sso_sign_in as sso
    row = _provider(state="draft", created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    before = sso_providers.fingerprint(row)
    url = sso.start(row, purpose=sso_state.TEST, source="s", client_ip="203.0.113.9", verifier_hash=_h("test-tab"),
                    user_id=h.root.id, session_hash="sess-hash")
    state, _ = h.state_of(url)
    answered = oc.fetch_json

    def while_the_provider_answers(*a, **kw):
        row.scopes = "openid email"                    # another administrator's save lands meanwhile
        return answered(*a, **kw)
    monkeypatch.setattr(oc, "fetch_json", while_the_provider_answers)
    status, location, _ = h.callback(row, state)
    assert location.startswith("/#sso-test="), location
    status, body = h.finish_test(row, location)
    assert status == 200, body
    assert row.last_test["config"] == before != sso_providers.fingerprint(row)
    assert sso_providers.tested(row) is False


def test_the_client_secret_is_in_no_text_made_of_the_provider():
    from app.services import oidc_client as oc
    provider = oc.ProviderConfig(id="p", issuer="https://login.example.org", client_id="client-1", client_secret="s3cret-value")
    assert "s3cret-value" not in repr(provider) and "s3cret-value" not in str(provider) and "s3cret-value" not in f"{provider}"
    assert provider.client_secret == "s3cret-value" and "client-1" in repr(provider)
