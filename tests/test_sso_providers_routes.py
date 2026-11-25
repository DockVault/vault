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
             "Days without signing in: A whole number from 0 to 365."),
            # A box left empty: refused, and never taken for 0 (which turns the rule off).
            ({"policy": {"sso_freshness_days": None}}, "policy.sso_freshness_days",
             "Days without signing in: Type a whole number from 0 to 365: an empty box is not 0."),
            ({"policy": {"sso_freshness_days": ""}}, "policy.sso_freshness_days",
             "Days without signing in: Type a whole number from 0 to 365: an empty box is not 0.")):
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
                        "secret_cleared": False, "owners_told": 0,
                        "changed": ["label", "issuer", "client_id", "client_secret", "policy.sso_freshness_days"],
                        # What each was and is: none of them is a secret, and an auditor reads who changed what.
                        "changes": {"label": {"old": None, "new": "Company sign-in"},
                                    "issuer": {"old": None, "new": ISSUER_2},
                                    "client_id": {"old": None, "new": "client-1"},
                                    "client_secret": {"old": None, "new": "(set)"},      # only that one was set
                                    "sso_freshness_days": {"old": 30, "new": 7}}}
    assert "s3cret" not in str(h.audits) and "enc(" not in str(h.audits)       # never the secret, in any form
    # Recorded in the transaction that made the change: added before its commit.
    assert [step[0] for step in h.db.log if step[0] in ("add", "commit")][-2:] == ["add", "commit"]
    assert len(h.told) == 1 and "s3cret" not in str(h.told) and "client_secret" in h.told[0][2]
    # The same values again: the step-up is asked (a change was sent), nothing is recorded or told.
    status, out = h.call("PATCH", path, {"label": "Company sign-in"})
    assert status == 200 and out["changed"] == [] and len(h.audit("sso_provider_updated")) == 1 and len(h.told) == 1


def test_turning_a_provider_off_and_on_says_what_its_days_do_to_passwords(monkeypatch):
    """Off: the administrators are told that the days stop no password while it is off, and that what was held
    before stays held. On again: how many linked accounts its days hold to the provider's sign-in from now."""
    from datetime import datetime, timedelta
    row = _provider(created_at=None, updated_at=None)
    alice, bob = _user("alice"), _user("bob")
    long_ago = datetime.utcnow() - timedelta(days=40)
    bobs = _identity(bob, row, subject="s-2", last_sign_in_at=datetime.utcnow())
    h = Admin(monkeypatch, [row], users=[alice, bob],
              identities=[_identity(alice, row, last_sign_in_at=datetime.utcnow()), bobs])
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "disabled"})
    assert status == 200 and out["held"] == 0 and "due" not in out, out
    assert "While it is off, its days stop no password: only an account that was held before" in h.told[-1][2]
    # Nobody could sign in through it meanwhile: bob's days ran out while it was off.
    bobs.last_sign_in_at = long_ago
    from app.services import sso_providers as providers
    monkeypatch.setattr(providers, "enable_refusal", lambda db, row: None)
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "enabled"})
    assert status == 200 and out["due"] == 1, out
    assert h.told[-1][2].endswith("1 linked account(s) have not signed in through it within its days: their "
                                  "password and passkeys do not sign them in until they have.")
    # A provider that only pauses keys says neither.
    row.policy = {"sso_lapse_ends_sign_in": False}
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "disabled"})
    assert status == 200 and "its days stop no password" not in h.told[-1][2]
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "enabled"})
    assert status == 200 and out["due"] == 0 and "have not signed in through it" not in h.told[-1][2]


def test_the_setting_for_accounts_made_at_a_first_sign_in_tells_them_in_its_own_words(monkeypatch):
    """A save that changes only what an account made at a first sign-in may hold settles those accounts, and tells
    each what changed for it: not that password sign-in was turned off for the provider, which it was not."""
    from app.core import password_origin, security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    row = _provider(created_at=None, updated_at=None)
    made, linked = _user("made", sso_only=True, password_hash="r1"), _user("linked")
    made.password_set_by, made.password_set_by_other_at = None, None
    password_origin.mark_nobody_knows(made)
    h = Admin(monkeypatch, [row], users=[made, linked],
              identities=[_identity(made, row, linked_by="jit"), _identity(linked, row, subject="s-2")])
    label = row.label or row.name
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_jit_password": True}})
    assert status == 200 and out["restored"] == ["made"] and out["made_sso_only"] == [] and made.sso_only is False, out
    assert out["changed"] == ["policy.sso_jit_password"]
    assert h.accounts_told == [(["made"], "You can set a password", h.accounts_told[0][2])]
    assert h.accounts_told[0][2].startswith(
        f"An administrator now lets accounts made at their first sign-in through {label} set a password. ")
    assert "Forgot password" in h.accounts_told[0][2]
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_jit_password": False}})
    assert status == 200 and out["made_sso_only"] == ["made"] and made.sso_only is True and linked.sso_only is False
    assert h.accounts_told[1][:2] == (["made"], f"Your account signs in only through {label}")
    assert h.accounts_told[1][2].startswith(
        f"An administrator no longer lets accounts made at their first sign-in through {label} set a password. ")
    assert "turned password sign-in off" not in str(h.accounts_told)
    # The other setting settles nobody and tells no account anything.
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_lapse_ends_sign_in": False}})
    assert status == 200 and out["changed"] == ["policy.sso_lapse_ends_sign_in"] and len(h.accounts_told) == 2


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
                                                     "changed": ["state"], "state": "enabled",
                                                     "changes": {"state": {"old": "draft", "new": "enabled"}}}
    assert [step[0] for step in h.db.log if step[0] in ("add", "commit")][-2:] == ["add", "commit"]
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


def test_a_removal_tells_an_account_left_with_no_way_in_how_to_get_a_password(monkeypatch):
    """A provider is removed. An account linked to it that has a password is told it lost a way to sign in. One
    whose password nobody knows, linked to no other provider that is on, has nothing left that signs it in (its
    passkey signs in after a provider only): it is told how to get a password, as an account that may hold one
    again is. With another provider that is on it is told what the first is told; where that other provider has
    refused it, nothing would sign it in there either, and it is told how to get a password. An account another
    provider still holds to no password, that provider being off, cannot use a reset link (none is made or taken
    for it): it is told to ask an administrator, not to do what would be refused."""
    from datetime import datetime
    from app.api import sso_providers_router as router
    from app.core import password_origin, sso_only
    row, other = _provider(created_at=None, updated_at=None, state="disabled"), _provider(name="Fabrikam")
    no_password = _provider(name="Northwind", state="disabled")
    no_password.policy = {"sso_password_login": "disabled"}
    alice, dana, erin, frank, gina = _user("alice"), _user("dana"), _user("erin"), _user("frank"), _user("gina")
    for marked in (dana, erin, gina):
        marked.sso_only, marked.password_hash, marked.password_nobody_knows = False, "argon2:of-random-bytes", None
        password_origin.mark_nobody_knows(marked)
    frank.sso_only, frank.password_hash, frank.password_nobody_knows = True, "argon2:of-random-bytes", None
    password_origin.mark_nobody_knows(frank)
    h = Admin(monkeypatch, [row, other, no_password], users=[alice, dana, erin, frank, gina],
              identities=[_identity(alice, row), _identity(dana, row), _identity(erin, row), _identity(erin, other),
                          _identity(frank, row), _identity(frank, no_password),
                          _identity(gina, row),
                          _identity(gina, other, refused_at=datetime.utcnow(), last_sign_in_at=None)])
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200 and out == {"removed": True}, out
    removed = f"An administrator removed {row.label or row.name} from this vault: your account can no longer sign in through it."
    told = {tuple(names): text for names, _title, text in h.accounts_told}
    assert told[("alice", "erin")] == removed
    assert told[("dana", "gina")] == f"{removed} {router.SET_A_PASSWORD}"
    assert told[("frank",)] == f"{removed} {sso_only.NO_PROVIDER_ON}" and frank.sso_only is True
    assert "Ask your administrator" in sso_only.NO_PROVIDER_ON and len(told) == 3


def test_a_removal_first_holds_the_people_whose_days_ran_out_while_the_provider_was_off(monkeypatch):
    """A removed provider has no identities left to count days for. A person whose days ran out while it was off
    would get their keys back for good, unseen. Where the days only pause keys, the removal holds them first, the
    hold is kept whatever becomes of the request, and the removal is refused until an administrator has cleared
    it."""
    from datetime import datetime, timedelta
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    alice, bob = _user("alice"), _user("bob")
    now = datetime.utcnow()
    lapsed = _identity(alice, row, last_sign_in_at=now - timedelta(days=30), linked_at=now - timedelta(days=60),
                       refused_at=None)
    inside = _identity(bob, row, last_sign_in_at=now - timedelta(days=1), linked_at=now - timedelta(days=60),
                       refused_at=None)
    h = Admin(monkeypatch, [row], users=[alice, bob], identities=[lapsed, inside])
    # A step-up that does not pass: no account is changed by a click that goes no further.
    from fastapi import HTTPException

    def no_step_up(db, user, request):
        raise HTTPException(status_code=403, detail="step-up required")
    monkeypatch.setattr(h.R, "_step_up", no_step_up)
    assert h.call("DELETE", f"/admin/sso/providers/{row.id}")[0] == 403
    assert lapsed.refused_at is None and ("commit",) not in h.db.log and h.audits == [] and h.told == []
    monkeypatch.setattr(h.R, "_step_up", lambda db, user, request: h.order.append("step_up"))
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["reason"] == "refusals_in_force", out
    assert out["detail"]["message"] == (
        "1 account has not signed in through this provider within its days. It is held now, so that removing the "
        "provider does not give it its SSH keys, temporary credentials and devices back unseen. Clear it under "
        "Identities when it should have them back, then remove the provider again.")
    assert lapsed.refused_at is not None and inside.refused_at is None and h.rows() == [row]
    assert h.order == ["step_up"]                               # held after the step-up, and not before
    # Recorded in the transaction that wrote the hold, and told: the administrators and the person held.
    assert h.audit("sso_provider_updated") == [("sso_provider_updated", "success", {
        "provider_id": str(row.id), "name": row.name, "changed": [], "identities": 1, "reason": "held_before_removal"})]
    recorded = next(i for i, step in enumerate(h.db.log) if step[0] == "add")
    assert recorded < h.db.log.index(("commit",))
    assert h.told[0][1] == "Accounts were held before a provider's removal" and "1 account(s)" in h.told[0][2]
    assert h.accounts_told == [(["alice"], "Your keys stay paused on this vault", (
        f"You have not signed in through {row.label or row.name} within the time your organisation allows, and "
        f"{row.label or row.name} is being removed from this vault. Your SSH keys, temporary credentials and devices "
        "stay paused until an administrator lifts that. Your password signs you in as before."))]
    # Tried again while she is held: the recorded refusal stands in the way, and nothing is held or told twice.
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["reason"] == "refusals_in_force" and "Clear it under Identities first" in out["detail"]["message"]
    assert len(h.audit("sso_provider_updated")) == 1 and len(h.accounts_told) == 1
    lapsed.refused_at = None                                    # cleared, and signed in since
    lapsed.last_sign_in_at = now
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200 and out == {"removed": True}, out


def test_a_removal_holds_a_turned_off_account_and_tells_it_nothing(monkeypatch):
    """The organisation turns leavers' accounts off and leaves them linked. A removal held such an account and
    told it, in the app and by email to the address it holds, that its keys stay paused and that "your password
    signs you in as before": neither is true of an account that signs in nowhere. The hold is kept (the removal
    still waits for each to be cleared); the account is told nothing, and the administrators how many such there
    are."""
    from datetime import datetime, timedelta
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    alice, leaver = _user("alice"), _user("leaver")
    leaver.is_active = False
    now = datetime.utcnow()
    links = [_identity(who, row, subject=f"s-{who.username}", last_sign_in_at=now - timedelta(days=30),
                       linked_at=now - timedelta(days=60), refused_at=None) for who in (alice, leaver)]
    h = Admin(monkeypatch, [row], users=[alice, leaver], identities=links)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and "2 accounts have not" in out["detail"]["message"]
    assert all(link.refused_at is not None for link in links)             # both held: both must be cleared
    assert [names for names, _title, _body in h.accounts_told] == [["alice"]]
    assert h.told[0][2].endswith("the provider can be removed then. 1 of them are turned off: held as the others "
                                 "are, and not told.")
    assert h.audit("sso_provider_updated")[0][2]["identities"] == 2
    # With nobody turned off among them, nothing more is said.
    for link in links:
        link.refused_at = None
    leaver.is_active = True
    del h.told[:]
    assert h.call("DELETE", f"/admin/sso/providers/{row.id}")[0] == 409
    assert h.told[0][2].endswith("the provider can be removed then.")


def test_a_removal_goes_through_once_an_administrator_has_lifted_the_holds_it_made(monkeypatch):
    """The removal holds the people whose days ran out and says: clear each under Identities, then remove again.
    Clearing gave the identity no new deadline (nobody signs in through a provider that is off), so the next
    removal held the same people again, recorded and told again, and refused again, for as long as anyone tried.
    The lift is remembered against the deadline it answered, and the identity is not held again for that one."""
    from datetime import datetime, timedelta
    from app.api import sso_admin_router as A
    from app.core import owner_notices
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    alice, bob = _user("alice"), _user("bob")
    now = datetime.utcnow()
    last = now - timedelta(days=30)
    lapsed = _identity(alice, row, last_sign_in_at=last, linked_at=now - timedelta(days=60), refused_at=None,
                       hold_lifted_for=None)
    other = _identity(bob, row, last_sign_in_at=last, linked_at=now - timedelta(days=60), refused_at=None,
                      hold_lifted_for=None)
    h = Admin(monkeypatch, [row], users=[alice, bob], identities=[lapsed, other])
    monkeypatch.setattr(A, "_step_up", lambda db, user, request: None)
    monkeypatch.setattr(owner_notices, "notify_in_transaction", lambda db, ids, *, title, body, ntype, target: None)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["reason"] == "refusals_in_force" and "2 accounts have not" in out["detail"]["message"]
    assert lapsed.refused_at is not None and other.refused_at is not None
    told, recorded = len(h.accounts_told), len(h.audit("sso_provider_updated"))
    # One of the two is lifted, through the route: the other still stands in the way, and nothing is held or told again.
    status, out = h.call("POST", f"/admin/sso/identities/{lapsed.id}/clear-refusal")
    assert status == 200 and out == {"cleared": True}, out
    assert lapsed.refused_at is None and lapsed.hold_lifted_for == last + timedelta(days=7)
    assert lapsed.last_sign_in_at == last                       # the lift gives no sign-in
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and "Clear it under Identities first" in out["detail"]["message"], out
    assert lapsed.refused_at is None and len(h.accounts_told) == told and len(h.audit("sso_provider_updated")) == recorded
    # Both lifted: the removal goes through, and nobody is held, recorded or told again.
    status, out = h.call("POST", f"/admin/sso/identities/{other.id}/clear-refusal")
    assert status == 200, out
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200 and out == {"removed": True}, out
    # Nobody is held again or told of a hold again: what is told now is the removal itself.
    assert [t[1] for t in h.accounts_told].count("Your keys stay paused on this vault") == 1
    assert len(h.audit("sso_provider_updated")) == recorded


def test_a_lift_answers_the_deadline_it_was_given_for_and_no_later_one():
    """The lift says nothing of a deadline the identity gets afterwards: signed in since and past the days
    again, it is held as anyone is. A provider that asks no days gives a lift nothing to answer."""
    from datetime import datetime, timedelta
    from app.services import sso_freshness as F
    from app.services import sso_providers
    now = datetime.utcnow()
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    alice = _user("alice")
    first = now - timedelta(days=30)
    identity = _identity(alice, row, last_sign_in_at=first, linked_at=now - timedelta(days=60), refused_at=now,
                         hold_lifted_for=None)
    identity.refused_at = None
    F.note_the_lift(identity, row)
    assert identity.hold_lifted_for == first + timedelta(days=7)
    assert F.lift_answers(identity, F.deadline_of(identity, row)) is True

    class DB:
        def query(self, model):
            return self

        def filter(self, *a):
            return self

        def all(self):
            return [identity]
    held = []
    assert sso_providers.hold_lapsed(DB(), row, into=held) == 0 and identity.refused_at is None and held == []
    # Signed in since, and past the days again: another deadline, which the lift does not answer.
    identity.last_sign_in_at = now - timedelta(days=10)
    assert F.lift_answers(identity, F.deadline_of(identity, row)) is False
    assert sso_providers.hold_lapsed(DB(), row, into=held) == 1 and identity.refused_at is not None and held == [alice.id]
    # No days asked: the lift has no deadline to answer, and none is kept.
    identity.refused_at = None
    row.policy = {"sso_freshness_days": 0}
    F.note_the_lift(identity, row)
    assert identity.hold_lifted_for is None and F.lift_answers(identity, None) is False


def test_a_removal_that_is_refused_ends_nobodys_password(monkeypatch):
    """A provider that closes the other ways in after its days: while it is off, its days end no password (nobody
    could sign in through it). A hold does, so the removal writes none there: it is refused, with the two ways on,
    and the people whose days ran out while it was off go on signing in as they did. It held each of them before
    it refused, ahead of any step-up, and nobody was told."""
    from datetime import datetime, timedelta
    from app.services import sso_freshness as F
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7}                      # the other setting as it stands: on
    alice, bob = _user("alice"), _user("bob")
    now = datetime.utcnow()
    lapsed = _identity(alice, row, last_sign_in_at=now - timedelta(days=30), linked_at=now - timedelta(days=60),
                       refused_at=None)
    inside = _identity(bob, row, last_sign_in_at=now - timedelta(days=1), linked_at=now - timedelta(days=60),
                       refused_at=None)
    h = Admin(monkeypatch, [row], users=[alice, bob], identities=[lapsed, inside])
    before = F.held_to_a_provider(h.db, alice)
    assert before is None or not F.closes_now(before, now)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["reason"] == "days_ran_out", out
    assert out["detail"]["message"] == (
        "1 account has not signed in through this provider within its days, so its SSH keys, temporary credentials "
        "and devices are paused. Removing the provider would lift that unseen. The ways on: turn the provider on so "
        "that it signs in through it again; unlink it under the provider's Identities; or delete the account. Or "
        "turn off “After those days, or a refusal, the account signs in only through a provider” for it (Access) "
        "and remove it again: it is then held, to be lifted under Identities, and nobody's password stops.")
    # For several accounts it is said in the plural.
    from app.services import sso_providers
    also = _identity(bob, row, subject="s-9", last_sign_in_at=now - timedelta(days=40), linked_at=now - timedelta(days=60),
                     refused_at=None)
    carol = _user("carol")
    also.user_id = carol.id
    from app.core.models import ExternalIdentity
    h.db.rows_of(ExternalIdentity).append(also)
    said = str(sso_providers.remove_refusal(h.db, row))
    assert said.startswith("2 accounts have not signed in through this provider within its days, so their SSH keys")
    assert "so that they sign in through it again; unlink each under the provider's Identities; or delete the accounts." in said
    assert "they are then held, to be lifted under Identities" in said
    # A way it names works: unlinked under Identities, that account no longer stands in the way.
    h.db.rows_of(ExternalIdentity).remove(also)
    assert sso_providers.days_ran_out(h.db, row) == 1
    assert lapsed.refused_at is None and inside.refused_at is None and h.rows() == [row] and h.order == []
    after = F.held_to_a_provider(h.db, alice)
    assert after is None or not F.closes_now(after, now)        # her password signs in as before
    assert ("commit",) not in h.db.log
    # The second way on: the setting turned off, the removal holds her (keys only) and waits for it to be cleared.
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["reason"] == "refusals_in_force", out
    assert h.order == ["step_up"]
    held = F.held_to_a_provider(h.db, alice)
    assert lapsed.refused_at is not None and (held is None or not F.closes_now(held, now))
    # The first way on, instead: turned on, she signs in through it, and it is turned off and removed.
    lapsed.refused_at, lapsed.last_sign_in_at = None, now
    row.policy = {"sso_freshness_days": 7}
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200 and out == {"removed": True}, out


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
    assert not [key for key in h.redis.rows if key.startswith("sso:state:")]      # no state was made


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
    # The form stays in view while a provider lets its people keep a password; it goes behind a link once every
    # provider that is on holds its people to none (one that is off, or hidden, does not count).
    assert methods["password"] == "visible"
    for row in (on, first, hidden):
        row.policy = {"sso_password_login": "disabled"}
    assert h.S._sign_in_methods(h.db)["password"] == "link"
    first.policy = None
    assert h.S._sign_in_methods(h.db)["password"] == "visible"
    for row in (on, first, hidden):
        row.policy = None
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
    monkeypatch.setattr(h.R, "_end_sessions_of", lambda db, provider_id, **record: (
        seen.append(("ended", str(provider_id))) or ended))
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
    assert out["owners_told"] == 0 and h.accounts_told == []           # nobody is linked to it here
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


@pytest.mark.parametrize("state", ["enabled", "disabled"])
@pytest.mark.parametrize("change", [{"discovery_url": "https://elsewhere.example.net/.well-known/openid-configuration"},
                                    {"issuer": ISSUER_2}, {"private_network": True},
                                    {"issuer": ISSUER_2, "client_secret": "their-own"}])
def test_the_people_linked_to_a_provider_are_told_when_it_is_pointed_somewhere_else(monkeypatch, state, change):
    """Where a provider is found says who vouches for a linked account's sign-in. One administrator can change it
    (to a provider they run, with their own secret), test it and turn it on again. The other administrators are
    told; so is every person linked to it, who is the one it would be used against. Turning it off first hides
    nothing: the people are told whichever state it was in. The administrator who made the change is not told of
    their own change, an account that is off is told nothing, and a change that points it nowhere else (another
    client, a new secret, its label) tells nobody."""
    row = _tested(_provider(state=state, created_at=None, updated_at=None))
    other = _provider(name="other", label="Other", created_at=None, updated_at=None)
    alice, bob, gone, carol = _user("alice"), _user("bob", email=None), _user("gone", is_active=False), _user("carol")
    linked = [(alice, row), (bob, row), (gone, row), (carol, other)]
    h = Admin(monkeypatch, [row, other], users=[alice, bob, gone, carol],
              identities=[_identity(user, provider, subject=f"subject-{n}") for n, (user, provider) in enumerate(linked)])
    from app.core.models import ExternalIdentity
    h.db.tables[ExternalIdentity].append(_identity(h.root, row, subject="subject-root"))
    _watch_turn_off(monkeypatch, h)
    path = f"/admin/sso/providers/{row.id}"
    status, out = h.call("PATCH", path, change)
    assert status == 200 and out["owners_told"] == 2, out
    (names, title, text), = h.accounts_told
    assert names == ["alice", "bob"] and title == "Sign in with Contoso was pointed somewhere else"
    assert "changed where this vault finds Sign in with Contoso" in text and "tested it again" in text
    assert "stop and tell an administrator" in text
    said = h.told[-1][2]
    assert "pointed somewhere else" in said and "The 2 account(s) linked to it were told." in said
    assert ("must be entered again" in said) is ("client_secret" not in change)
    # What points it nowhere else tells nobody linked to it.
    h.accounts_told.clear()
    for quiet in ({"client_id": "another-client"}, {"client_secret": "rotated"}, {"label": "Staff sign-in"},
                  {"scopes": "openid email"}):
        status, out = h.call("PATCH", path, quiet)
        assert status == 200 and out["owners_told"] == 0 and h.accounts_told == [], (quiet, out)
        assert "pointed somewhere else" not in h.told[-1][2]


def test_turning_a_provider_off_ends_its_sessions_and_holds_the_lapsed_accounts(monkeypatch):
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    seen = _watch_turn_off(monkeypatch, h, ended=4, held=1)
    path = f"/admin/sso/providers/{row.id}/state"
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is True and out["sessions_ended"] == 4 and out["held"] == 1, out
    assert row.state == "disabled" and seen == [("held", "enabled"), ("ended", str(row.id))]
    audit = h.audit("sso_provider_updated")[-1][2]
    # The sessions are ended after this commit and recorded where they are ended (the test of that ending).
    assert audit["state"] == "disabled" and audit["identities"] == 1 and "sessions" not in audit
    assert audit["changes"] == {"state": {"old": "enabled", "new": "disabled"}}
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
    assert h.audits == []                                    # nobody named to record it for: nothing is written
    order.clear()
    # Ended for an administrator's change: how many is recorded with the ending, in its transaction.
    del h.db.log[:]
    assert h.R._end_sessions_of(h.db, row.id, by=h.root, ip="203.0.113.9", name=row.name) == 2
    assert h.audit("sso_provider_updated") == [("sso_provider_updated", "success", {
        "provider_id": str(row.id), "name": row.name, "changed": [], "sessions": 2, "reason": "sessions_ended"})]
    assert [step[0] for step in h.db.log if step[0] in ("add", "commit")] == ["add", "commit"]
    del h.audits[:]
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


def _linked_every_way(monkeypatch):
    """A provider that is on, with seven accounts linked: one with a password of its own, and six with none they
    can type, of which one is signed in by another provider that is on. Four are held to a provider and two were
    made at a first sign-in, so the accounts held to a provider and the accounts it is the only way in for are
    different sets, of different sizes."""
    from datetime import datetime
    from app.core import password_origin
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    other = _provider(name="other", label="Other", created_at=None, updated_at=None)
    off = _provider(name="off", label="Off", state="disabled", created_at=None, updated_at=None)
    own = _user("own")                                             # a password of her own
    held = _user("held", sso_only=True)                            # signs in only through a provider
    made = _user("made", password_hash="argon2:of-random-bytes")   # made at its first sign-in here
    password_origin.mark_nobody_knows(made)
    also_made = _user("alsomade", password_hash="argon2:of-random-bytes")
    password_origin.mark_nobody_knows(also_made)
    two = _user("two", sso_only=True)                              # another provider that is on signs it in
    two_off = _user("twooff", sso_only=True)                       # its other provider is off
    refused = _user("refused", sso_only=True)                      # its other provider has refused it
    users = [own, held, made, also_made, two, two_off, refused]
    identities = [_identity(u, row, subject="s-" + u.username) for u in users]
    identities += [_identity(two, other, subject="o-two"), _identity(two_off, off, subject="x-two"),
                   _identity(refused, other, subject="o-refused", refused_at=datetime.utcnow())]
    return Admin(monkeypatch, [row, other, off], users=users, identities=identities), row


def test_turning_a_provider_off_says_for_how_many_accounts_it_is_the_only_way_in(monkeypatch):
    """Counted for what it is: an account with no password it can type (held to its provider, or made at its first
    sign-in with a password nobody knows) and no other identity that lets it in. Not an account with a password of
    its own, nor one that another provider signs in. The answer carries the count, and the administrators' notice
    of the turn-off says it."""
    from app.core import sso_only
    from app.services import sign_in, sso_providers
    h, row = _linked_every_way(monkeypatch)
    shown = sso_providers.public(h.db, row)
    assert (shown["identities"], shown["sso_only_accounts"], shown["only_way_in_accounts"]) == (7, 4, 5), shown
    # The count is the rule the unlink goes by, account by account.
    from app.core.models import ExternalIdentity, User
    by_rule = 0
    for identity in [i for i in h.db.rows_of(ExternalIdentity) if i.provider_id == row.id]:
        user = next(u for u in h.db.rows_of(User) if u.id == identity.user_id)
        by_rule += (not sign_in.has_a_password_it_can_type(user)
                    and not sso_only.another_way_in(h.db, user, without=identity))
    assert by_rule == 5
    _watch_turn_off(monkeypatch, h, ended=0, held=0)
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "disabled"})
    assert status == 200 and out["provider"]["only_way_in_accounts"] == 5, out
    assert h.told[-1][2].endswith("5 account(s) linked to it have no other way to sign in: nothing signs them in "
                                  "while it is off."), h.told[-1]
    # Turned on again: nothing of the kind is said.
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "enabled"})
    assert status == 200 and "no other way to sign in" not in h.told[-1][2]


def test_a_turn_off_that_strands_nobody_says_nothing_of_it(monkeypatch):
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    own = _user("own")
    h = Admin(monkeypatch, [row], users=[own], identities=[_identity(own, row)])
    _watch_turn_off(monkeypatch, h, ended=0, held=0)
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "disabled"})
    assert status == 200 and out["provider"]["only_way_in_accounts"] == 0
    assert "no other way to sign in" not in h.told[-1][2]


def test_the_page_asks_before_a_turn_off_that_leaves_accounts_no_way_in():
    """The administrator's page confirms a turn-off by the count of accounts it leaves no way in, not by the
    count of accounts held to a provider (one of those may have another provider; an account made at its first
    sign-in is held to none and still has no other way in)."""
    from pathlib import Path
    page = (Path(__file__).resolve().parents[1] / "static" / "js" / "settings-sso.js").read_text(encoding="utf-8")
    assert "if (state === 'disabled' && open.only_way_in_accounts) {" in page
    assert "open.sso_only_accounts" not in page
    assert "have no other way " in page and "nothing signs them in while " in page


@pytest.mark.parametrize("state", ["enabled", "disabled"])
def test_an_account_is_told_of_the_password_rule_as_its_provider_stands(monkeypatch, state):
    """Password sign-in turned off, then allowed again, for a provider: each linked account is told. Where the
    provider is turned off at that moment, nothing signs in through it, and the account is not told that it does."""
    row = _provider(state=state, created_at=None, updated_at=None)
    alice = _user("alice")
    h = Admin(monkeypatch, [row], users=[alice], identities=[_identity(alice, row)])
    from app.core import security
    monkeypatch.setattr(security, "hash_password", lambda secret: "argon2:" + secret)
    label = row.label or row.name
    while_off = f" {label} is turned off at the moment: ask an administrator."
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_password_login": "disabled"}})
    assert status == 200 and out["made_sso_only"] == ["alice"], out
    told = h.accounts_told[-1][2]
    assert told.startswith(f"An administrator turned password sign-in off for {label}. Your account now signs in "
                           f"only through {label}: its password and its SFTP password sign-in no longer work.")
    assert told.endswith(while_off) is (state == "disabled") and (while_off in told) is (state == "disabled")
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_password_login": "allowed"}})
    assert status == 200 and out["restored"] == ["alice"], out
    told = h.accounts_told[-1][2]
    assert (f"You can still sign in through {label}." in told) is (state == "enabled")
    assert told.endswith(while_off) is (state == "disabled")


def test_the_account_page_does_not_point_here_for_a_factor_it_cannot_set_up_here():
    from pathlib import Path
    page = (Path(__file__).resolve().parents[1] / "static" / "js" / "sso.js").read_text(encoding="utf-8")
    assert "set one up '" in page and "(email.factor_here === false ? '' : 'here ') + 'first if you have none.'" in page


def test_what_changes_a_provider_takes_its_row_with_the_key_left_free(monkeypatch):
    """A save, a turn-off and a removal take the provider's row for themselves, so they come one at a time and
    none while a sign-in through the provider is being written. The row's key is left free: the record of a
    session that "Stay signed in" moves is written in the account's turn and refers to the provider, and a save
    settles accounts in their turns while it holds the row. Taken with its key, the two waited for each other."""
    row = _provider(created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    seen, through = [], h.db.query

    def query(*entities):
        made = through(*entities)
        lock = made.with_for_update

        def with_for_update(**kw):
            seen.append(kw)
            return lock(**kw)
        made.with_for_update = with_for_update
        return made
    monkeypatch.setattr(h.db, "query", query)
    assert h.R._row_or_404(h.db, str(row.id), lock=True) is row and seen == [{"key_share": True}]
    del seen[:]
    assert h.R._row_or_404(h.db, str(row.id)) is row and seen == []


def test_the_accounts_a_change_settles_are_taken_by_their_id_however_they_were_linked(monkeypatch):
    """A save and a removal settle every account linked to the provider, each in its turn. Two changes that
    settle the same accounts take those turns in one order, by the account's id, as a logout and a turn-off do."""
    from app.core import sso_only
    row = _provider(state="disabled", created_at=None, updated_at=None)
    users = [_user(f"user{i}") for i in range(6)]
    by_id = sorted(users, key=lambda u: str(u.id))
    linked = [_identity(u, row, subject="s-" + u.username) for u in reversed(by_id)]
    linked[0], linked[3] = linked[3], linked[0]                    # linked in no order at all
    h = Admin(monkeypatch, [row], users=users, identities=linked)
    assert [u.username for u in sso_only.linked_accounts(h.db, row)] == [u.username for u in by_id]
    settled = []
    monkeypatch.setattr(sso_only, "settle", lambda db, user, **kw: settled.append(user.username))
    sso_only.apply_password_login(h.db, row)
    assert settled == [u.username for u in by_id]
    del settled[:]
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200, out
    assert settled == [u.username for u in by_id]


def test_a_save_and_a_removal_hash_one_unknown_password_before_they_take_the_providers_row(monkeypatch):
    """Sign-ins through the provider wait for its row, and hashing is slow on purpose: what settles the linked
    accounts while it holds the row makes its one unknown password before, and writes that to each."""
    from app.core import password_origin, security, sso_only
    row = _provider(created_at=None, updated_at=None)
    people = [_user(name) for name in ("alice", "bob", "carol")]
    h = Admin(monkeypatch, [row], users=people,
              identities=[_identity(person, row, subject="s-" + person.username) for person in people])
    made = []

    def hash_password(secret):
        h.order.append("hash")
        made.append("argon2:" + secret)
        return made[-1]
    monkeypatch.setattr(security, "hash_password", hash_password)
    find = h.R._row_or_404
    monkeypatch.setattr(h.R, "_row_or_404", lambda db, provider_id, *, lock=False: (
        h.order.append("the row, taken" if lock else "the row, read"), find(db, provider_id, lock=lock))[1])
    path = f"/admin/sso/providers/{row.id}"
    # Off for all three: one hashing, before the row is taken, and the three accounts hold what it made.
    status, out = h.call("PATCH", path, {"policy": {"sso_password_login": "disabled"}})
    assert status == 200 and out["made_sso_only"] == ["alice", "bob", "carol"], out
    assert h.order == ["the row, read", "step_up", "hash", "the row, taken"], h.order
    assert [person.password_hash for person in people] == made * 3 and len(made) == 1
    assert all(password_origin.nobody_knows(person) for person in people)
    # Allowed again: the same.
    del h.order[:]
    status, out = h.call("PATCH", path, {"policy": {"sso_password_login": "allowed"}})
    assert status == 200 and out["restored"] == ["alice", "bob", "carol"], out
    assert h.order == ["the row, read", "step_up", "hash", "the row, taken"], h.order
    assert [person.password_hash for person in people] == made[1:] * 3 and len(made) == 2
    assert all(password_origin.nobody_knows(person) for person in people)
    # A change that settles nobody (a name) hashes nothing.
    del h.order[:]
    assert h.call("PATCH", path, {"label": "Contoso 2"})[0] == 200
    assert h.order == ["the row, read", "step_up", "the row, taken"], h.order
    # A removal: made before the row is taken, and handed to every account it settles.
    row.state = "disabled"
    del h.order[:]
    handed = []
    settle = sso_only.settle
    monkeypatch.setattr(sso_only, "settle", lambda db, user, **kw: (handed.append(kw.get("unknown_hash")),
                                                                    settle(db, user, **kw))[1])
    status, out = h.call("DELETE", path)
    assert status == 200, out
    assert h.order[:4] == ["the row, read", "step_up", "hash", "the row, taken"] and h.order.count("hash") == 1, h.order
    assert handed == [made[-1]] * 3 and len(made) == 3


def test_an_unknown_password_made_beforehand_is_what_is_written_and_one_is_made_without_it(monkeypatch):
    from app.core import password_origin, security, sso_only
    made = []
    monkeypatch.setattr(security, "hash_password", lambda secret: (made.append("argon2:" + secret), made[-1])[1])
    monkeypatch.setattr(sso_only, "end_sessions_no_provider_made", lambda db, user, keep=None: 0)
    monkeypatch.setattr(sso_only.privileged_accounts, "kind", lambda db, user: None)
    ready = sso_only.a_password_nobody_knows()
    assert made == [ready] and len(ready) > 40
    alice, bob = _user("alice"), _user("bob")
    sso_only.make_sso_only(None, alice, unknown_hash=ready)
    assert alice.password_hash == ready and alice.sso_only is True and password_origin.nobody_knows(alice)
    sso_only.allow_password_sign_in(None, alice, unknown_hash=ready)
    assert alice.password_hash == ready and alice.sso_only is False and len(made) == 1
    # Without one, each makes its own (one account settled by itself, in its own turn).
    sso_only.make_sso_only(None, bob)
    assert bob.password_hash == made[1] != ready and password_origin.nobody_knows(bob)
    sso_only.allow_password_sign_in(None, bob)
    assert bob.password_hash == made[2] and len(made) == 3
    # A privileged account met flagged keeps its password: nothing is written, with or without one.
    before = bob.password_hash
    sso_only.allow_password_sign_in(None, bob, keep_password=True, unknown_hash=ready)
    assert bob.password_hash == before


def test_a_change_that_turns_a_provider_off_records_what_it_did(monkeypatch):
    """One save points a provider that is on somewhere else. Its record says more than the fields: the provider
    went off, how many lapsed accounts were held, that the stored secret was dropped, and how many linked people
    were told."""
    alice = _user("alice")
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row], users=[alice], identities=[_identity(alice, row)])
    _watch_turn_off(monkeypatch, h, ended=3, held=2)
    was = row.issuer
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"issuer": ISSUER_2})
    assert status == 200 and out["turned_off"] is True, out
    (audit,) = h.audit("sso_provider_updated")
    assert audit[2] == {"provider_id": str(row.id), "name": row.name, "changed": ["issuer"],
                        "changes": {"issuer": {"old": was, "new": ISSUER_2},
                                    "client_secret": {"old": "(set)", "new": None}},
                        "made_sso_only": 0, "restored": 0, "secret_cleared": True, "owners_told": 1,
                        "state": "disabled", "identities": 2}


def test_no_change_of_a_provider_without_its_record(monkeypatch):
    """The record is written with the change or the change is not made: a provider added, changed, turned on or
    removed with nothing in the audit log saying who did it is the one thing an investigator cannot work with."""
    import app.services.audit_logger as al
    row = _tested(_provider(state="disabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])

    class Broken:
        def __init__(self, db):
            pass

        def build_row(self, **kw):
            raise RuntimeError("the audit log cannot be written")
    monkeypatch.setattr(al, "AuditLogger", Broken)
    path = f"/admin/sso/providers/{row.id}"
    for method, where, body in (("POST", "/admin/sso/providers", {"name": "another"}),
                                ("PATCH", path, {"label": "Another button"}),
                                ("POST", path + "/state", {"state": "enabled"}), ("DELETE", path, None)):
        del h.db.log[:]
        row.state = "disabled"          # (the stand-in database rolls no field back; a real one does)
        status, out = h.call(method, where, body)
        assert status == 503 and "its audit record could not be written. Nothing was changed" in out["detail"], out
        assert ("commit",) not in h.db.log and ("rollback",) in h.db.log, (method, where)
    assert h.told == [] and h.rows()[0] is row


def test_what_a_providers_record_keeps_of_its_settings():
    from app.services import sso_providers
    row = _provider(created_at=None, updated_at=None, policy={"sso_freshness_days": 7})
    before = sso_providers.recorded_values(row)
    assert before["client_secret"] == "(set)" and before["issuer"] == row.issuer and before["sso_freshness_days"] == 7
    assert before["sso_trust_idp_mfa"] is False                 # a setting never saved is recorded as what applies
    assert "client_secret_enc" not in before and row.client_secret_enc not in str(before)
    row.label, row.policy, row.client_secret_enc = "Staff", {"sso_freshness_days": 7, "sso_trust_idp_mfa": True}, "enc(new)"
    changes = sso_providers.recorded_changes(before, row, ["label", "client_secret", "policy.sso_trust_idp_mfa"])
    assert changes == {"label": {"old": before["label"], "new": "Staff"},
                       "client_secret": {"old": "(set)", "new": "(replaced)"},
                       "sso_trust_idp_mfa": {"old": False, "new": True}}
    # A secret dropped by the change, with no new one entered: said, though no field of that name was sent.
    row.client_secret_enc = None
    assert sso_providers.recorded_changes(before, row, ["issuer"])["client_secret"] == {"old": "(set)", "new": None}
    # A long value is kept as the caller shortens it.
    long = sso_providers.recorded_changes(before, row, ["label"], shorten=lambda field, value: f"{field}:{len(str(value))}")
    assert long["label"] == {"old": f"label:{len(str(before['label']))}", "new": "label:5"}


def test_a_providers_records_are_kept_with_the_other_settings_records():
    """Who may sign in through whom is an administrator's setting. Its records are in the category the size cap
    never deletes and the administrators' minimum protects."""
    from app.core import audit_catalog, audit_retention
    by_name = {a.name: a for a in audit_catalog.ACTIONS} if hasattr(audit_catalog, "ACTIONS") else None
    for name in ("sso_provider_created", "sso_provider_updated", "sso_provider_deleted", "sso_provider_tested"):
        category = by_name[name].category if by_name else audit_catalog.category_of(name)
        assert category == "administration" and category in audit_retention.PROTECTED_CATEGORIES, name


def _sessions_through(h, row, *, standing=2, ended=1, others=1, idle=0, over=0):
    """Sessions recorded for ``row``: some in use, some ended already, some of another provider, some that sat
    idle (marked inactive, never ended: their token works) and some whose time is over."""
    from datetime import datetime, timedelta
    from app.core.models import ActiveSession, SsoSession
    made = []

    def add(provider_id, **state):
        session = types.SimpleNamespace(id=uuid.uuid4(), user_id=uuid.uuid4(), **{"is_active": True, "revoked": False, **state})
        h.db.tables.setdefault(ActiveSession, []).append(session)
        h.db.tables.setdefault(SsoSession, []).append(types.SimpleNamespace(session_id=session.id, provider_id=provider_id))
        made.append(session)
        return session
    for _ in range(standing):
        add(row.id)
    for index in range(ended):
        add(row.id, is_active=index % 2 == 1, revoked=True)
    for _ in range(idle):
        add(row.id, is_active=False, expires_at=datetime.utcnow() + timedelta(days=30))
    for _ in range(over):
        add(row.id, expires_at=datetime.utcnow() - timedelta(minutes=1))
    for _ in range(others):
        add(uuid.uuid4())
    return made


def test_the_sessions_of_a_provider_that_still_stand_are_counted(monkeypatch):
    row = _provider(created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    assert h.R._sessions_standing(h.db, row.id) == 0                     # none recorded
    _sessions_through(h, row, standing=2, ended=3, others=2)
    assert h.R._sessions_standing(h.db, row.id) == 2                     # in use and not ended, of this provider
    assert h.R._sessions_standing(h.db, uuid.uuid4()) == 0
    # A session that sat idle is marked inactive and its token works all the same: it stands. One whose time is
    # over does not, whatever its marks say.
    _sessions_through(h, row, standing=0, ended=0, others=0, idle=3, over=2)
    assert h.R._sessions_standing(h.db, row.id) == 5
    from datetime import datetime, timedelta, timezone
    now = datetime.utcnow()
    ticking = types.SimpleNamespace(revoked=False, is_active=False, expires_at=now + timedelta(seconds=30))
    assert h.R._still_works(ticking, now) is True
    assert h.R._still_works(types.SimpleNamespace(revoked=False, expires_at=now), now) is False     # over at its time
    assert h.R._still_works(types.SimpleNamespace(revoked=False, expires_at=None), now) is True     # no time on record
    assert h.R._still_works(types.SimpleNamespace(revoked=True, is_active=True, expires_at=None), now) is False
    # A time read with its zone is compared as the same moment.
    aware = types.SimpleNamespace(revoked=False, expires_at=(now + timedelta(seconds=30)).replace(tzinfo=timezone.utc))
    assert h.R._still_works(aware, now) is True
    # It could not be counted: said as that, never as "none".
    rolled = []

    class Down:
        def query(self, *a):
            raise RuntimeError("down")

        def rollback(self):
            rolled.append(1)
    assert h.R._sessions_standing(Down(), row.id) is None and rolled == [1]
    assert h.R._said_of_sessions_standing(0) == ""
    assert h.R._said_of_sessions_standing(2) == (
        " 2 session(s) that came through it could not be ended and stand until they run out: turn it off again to "
        "end them, or sign those accounts out.")
    assert h.R._said_of_sessions_standing(None).startswith(" Sessions that came through it could not be ended")


def test_a_turn_off_that_could_not_end_the_sessions_says_so_and_asked_again_ends_them(monkeypatch):
    """An administrator turns a provider off in an incident while a long save holds the turn of one of its
    people. The sessions are ended in a transaction of their own, which failed and ended none: the provider was
    off, every session through it stood until it ran out, and the answer and the notice said nothing. Both say
    how many still stand. Turning it off again, which did nothing, ends them, behind the same proof."""
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    sessions = _sessions_through(h, row, standing=2, ended=1, others=1)
    path = f"/admin/sso/providers/{row.id}/state"
    works = [False]

    def end(db, provider_id, **record):
        if not works[0]:
            return 0                                  # the turn of an owner was held: none ended, none raised
        for session in sessions[:2]:
            session.is_active, session.revoked = False, True
        return 2
    monkeypatch.setattr(h.R, "_end_sessions_of", end)
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is True and row.state == "disabled", out
    assert out["sessions_ended"] == 0 and out["sessions_not_ended"] == 2
    said = h.told[-1][2]
    assert "2 session(s) that came through it could not be ended and stand until they run out" in said
    assert "turn it off again to end them" in said
    # Asked again: the same proof, the sessions ended, nothing else changed, and the administrators told.
    del h.order[:], h.told[:]
    works[0] = True
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is False and out["sessions_ended"] == 2 and out["sessions_not_ended"] == 0
    assert h.order == ["step_up"] and row.state == "disabled"
    (by, title, body), = h.told
    assert title == "Sessions of a single sign-on provider were ended" and "2 session(s) were ended." in body
    assert "could not be ended" not in body
    # None stands now: off again is nothing, and asks for no proof.
    del h.order[:], h.told[:]
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out == {"provider": out["provider"], "changed": False} and h.order == [] and h.told == []
    # On when it is on is nothing either, whatever sessions there are.
    row.state = "enabled"
    sessions[0].is_active, sessions[0].revoked = True, False
    status, out = h.call("POST", path, {"state": "enabled"})
    assert status == 200 and out == {"provider": out["provider"], "changed": False} and h.order == []


def test_a_turn_off_that_could_not_end_sessions_that_sat_idle_says_so_and_asked_again_ends_them(monkeypatch):
    """Every session through the provider is older than an hour: the cleanup marked each inactive, and each
    token works until its session is ended. The turn-off's ending failed. Counted as the sessions in use lately,
    none stood: the answer and the notice said nothing, and turning the provider off again was "no change" and
    ended nothing, while every one of them went on working."""
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    sessions = _sessions_through(h, row, standing=0, ended=1, others=1, idle=2)
    idle = [s for s in sessions if not s.is_active and not s.revoked]
    assert len(idle) == 2
    path = f"/admin/sso/providers/{row.id}/state"
    works = [False]

    def end(db, provider_id, **record):
        if not works[0]:
            return 0
        for session in idle:
            session.revoked = True
        return 2
    monkeypatch.setattr(h.R, "_end_sessions_of", end)
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is True and out["sessions_ended"] == 0, out
    assert out["sessions_not_ended"] == 2
    assert "2 session(s) that came through it could not be ended and stand until they run out" in h.told[-1][2]
    del h.order[:], h.told[:]
    works[0] = True
    status, out = h.call("POST", path, {"state": "disabled"})
    assert status == 200 and out["changed"] is False and out["sessions_ended"] == 2 and out["sessions_not_ended"] == 0
    assert h.order == ["step_up"] and all(s.revoked for s in idle)


def test_a_turn_off_that_ended_every_session_says_nothing_of_sessions_left(monkeypatch):
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    sessions = _sessions_through(h, row, standing=2, ended=0, others=1)

    def end(db, provider_id, **record):
        for session in sessions[:2]:
            session.is_active, session.revoked = False, True
        return 2
    monkeypatch.setattr(h.R, "_end_sessions_of", end)
    status, out = h.call("POST", f"/admin/sso/providers/{row.id}/state", {"state": "disabled"})
    assert status == 200 and out["sessions_ended"] == 2 and out["sessions_not_ended"] == 0
    assert "could not be ended" not in h.told[-1][2] and "2 session(s) that came through it were ended." in h.told[-1][2]


def test_a_change_that_turns_a_provider_off_says_which_sessions_still_stand(monkeypatch):
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None))
    h = Admin(monkeypatch, [row])
    _sessions_through(h, row, standing=3, ended=0, others=0)
    monkeypatch.setattr(h.R, "_end_sessions_of", lambda db, provider_id, **record: 0)
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"client_id": "another-client"})
    assert status == 200 and out["turned_off"] is True and out["sessions_ended"] == 0, out
    assert out["sessions_not_ended"] == 3
    assert "3 session(s) that came through it could not be ended" in h.told[-1][2]
    # A change that turns nothing off counts nothing and says nothing.
    _tested(row)
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"label": "Staff"})
    assert status == 200 and out["turned_off"] is False and out["sessions_not_ended"] == 0
    assert "could not be ended" not in h.told[-1][2]


def _linked_since(monkeypatch, days_ago, *, policy=None):
    """A provider that is on and three accounts linked to it, signed in through it ``days_ago`` each."""
    from datetime import datetime, timedelta
    row = _tested(_provider(state="enabled", created_at=None, updated_at=None, policy=policy))
    people = [_user(name) for name in ("ann", "ben", "cy")]
    links = [_identity(person, row, subject=f"s-{person.username}",
                       last_sign_in_at=datetime.utcnow() - timedelta(days=ago))
             for person, ago in zip(people, days_ago)]
    h = Admin(monkeypatch, [row], users=people, identities=links)
    return h, row, people


def test_a_save_that_shortens_a_providers_days_says_whom_it_holds_and_tells_them(monkeypatch):
    """An administrator saves a provider with 7 days where it had 30. Every linked account whose last sign-in
    through it is older than 7 days is held from that moment: its password and passkeys sign it in to nothing.
    They had no warning (the warning counts down to the days as they were), and the administrators' notice did
    not say how many stopped. The answer, the record and the notice say it, and each of those people is told."""
    h, row, (ann, ben, cy) = _linked_since(monkeypatch, [1, 10, 40])
    path = f"/admin/sso/providers/{row.id}"
    from app.services import sso_providers as providers
    assert [u.username for u in providers.held_by_its_days(h.db, row)] == ["cy"]       # 40 days against 30
    # A turned-off account past the days signs in nowhere: it is not among the accounts the days hold, so it is
    # neither counted nor told that its password stopped.
    cy.is_active = False
    assert providers.held_by_its_days(h.db, row) == []
    cy.is_active = True
    # An account the provider refused is held by the refusal, whatever the days are: it is not among these.
    from datetime import datetime, timedelta
    from app.core.models import ExternalIdentity, User
    dee = _user("dee")
    h.db.rows_of(User).append(dee)
    h.db.rows_of(ExternalIdentity).append(_identity(dee, row, subject="s-dee", refused_at=datetime.utcnow(),
                                                    last_sign_in_at=datetime.utcnow() - timedelta(days=40)))
    assert [u.username for u in providers.held_by_its_days(h.db, row)] == ["cy"]
    status, out = h.call("PATCH", path, {"policy": {"sso_freshness_days": 7}})
    assert status == 200 and out["changed"] == ["policy.sso_freshness_days"], out
    assert out["held_by_its_days"] == 2 and out["newly_held"] == 1                      # ben, since this save
    assert out["held_by_a_refusal"] == 1                                                # dee, before and after
    (told,) = h.accounts_told
    assert told[0] == ["ben"] and told[1].startswith("Sign in through ")
    assert "your password and passkeys do not sign you in to this vault until you have signed in through" in told[2]
    said = h.told[-1][2]
    assert ("1 more linked account(s) have not signed in through it within its days as they are now: their password "
            "and passkeys do not sign them in until they have. They were told. 3 account(s) are held so in all.") in said
    # Recorded after the change's own record, which was written with the change before this could be counted.
    change, count = h.audit("sso_provider_updated")
    assert change[2]["changed"] == ["policy.sso_freshness_days"] and "newly_held" not in change[2]
    assert count[2] == {"provider_id": str(row.id), "name": row.name, "changed": [], "reason": "held_by_its_days",
                        "held_by_its_days": 2, "held_by_a_refusal": 1, "newly_held": 1}
    # A change of something else, while two accounts are held: nobody is counted, nobody told again.
    del h.accounts_told[:], h.audits[:]
    status, out = h.call("PATCH", path, {"label": "Staff sign-in"})
    assert status == 200 and out["held_by_its_days"] == 0 and out["newly_held"] == 0 and h.accounts_told == []
    assert "have not signed in through it within its days" not in h.told[-1][2]
    # Longer days hold fewer: nobody new, nobody told, and the notice says nothing of it.
    del h.accounts_told[:], h.audits[:]
    status, out = h.call("PATCH", path, {"policy": {"sso_freshness_days": 60}})
    assert status == 200 and out["held_by_its_days"] == 0 and out["newly_held"] == 0
    assert h.accounts_told == [] and "have not signed in through it within its days" not in h.told[-1][2]
    # A change that is not of the days counts nobody.
    status, out = h.call("PATCH", path, {"label": "Staff"})
    assert status == 200 and out["held_by_its_days"] == 0 and out["newly_held"] == 0 and h.accounts_told == []
    # Nothing new held, nothing recorded of it: one record for each of the two changes since.
    assert [a[2]["changed"] for a in h.audit("sso_provider_updated")] == [["policy.sso_freshness_days"], ["label"]]


def test_a_save_that_turns_on_that_the_days_end_sign_in_says_whom_it_holds(monkeypatch):
    h, row, (ann, ben, cy) = _linked_since(monkeypatch, [1, 40, 50], policy={"sso_lapse_ends_sign_in": False})
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_lapse_ends_sign_in": True}})
    assert status == 200 and out["changed"] == ["policy.sso_lapse_ends_sign_in"], out
    assert out["held_by_its_days"] == 2 and out["newly_held"] == 2
    (told,) = h.accounts_told
    assert sorted(told[0]) == ["ben", "cy"]
    assert "2 more linked account(s) have not signed in through it within its days" in h.told[-1][2]
    # Turned off again: the days hold nobody, and nobody is told that they are held.
    del h.accounts_told[:]
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_lapse_ends_sign_in": False}})
    assert status == 200 and out["held_by_its_days"] == 0 and out["newly_held"] == 0 and h.accounts_told == []


def test_a_provider_that_is_off_holds_nobody_by_its_days_at_a_save(monkeypatch):
    """Turned off, a provider's days hold nobody: nothing is counted and nobody told at a save, and the count is
    given when it is turned on. The same for a save that turns the provider off by changing its connection."""
    h, row, people = _linked_since(monkeypatch, [40, 40, 40])
    row.state = "disabled"
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_freshness_days": 7}})
    assert status == 200 and out["held_by_its_days"] == 0 and out["newly_held"] == 0 and h.accounts_told == []
    row.state = "enabled"
    _tested(row)
    _watch_turn_off(monkeypatch, h, ended=0, held=0)
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}",
                         {"client_id": "another-client", "policy": {"sso_freshness_days": 3}})
    assert status == 200 and out["turned_off"] is True and out["held_by_its_days"] == 0 and out["newly_held"] == 0
    assert not [t for t in h.accounts_told if t[1].startswith("Sign in through ")]


def test_the_accounts_a_providers_days_hold_are_never_counted_while_its_row_is_held():
    """The count reads every account linked to the provider. Sign-ins through the provider wait for its row a
    short time and are refused as busy after it: so the count before the change is taken before the row is, and
    the count after it once the change is committed."""
    import inspect
    from app.api import sso_providers_router as R
    source = inspect.getsource(R.update_provider)
    steps = ('held_before = {u.id for u in providers.held_through(db, row)} if "policy" in changes else set()',
             "row = _row_or_404(db, provider_id, lock=True)",
             "        db.commit()",
             "held_now, by_days = (_held_after(db, row, by=current_user, ip=api.get_client_ip(request), held_before=held_before)")
    order = [source.index(step) for step in steps]
    assert order == sorted(order), order
    assert source.count("held_through(db, row)") == 1 and source.count("_held_after(") == 1
    assert "held_by_its_days(db, row)" not in source


def _held_for_keys_only_by_a_removal(monkeypatch):
    """Contoso is off, asks 7 days and only pauses keys. Alice last signed in 30 days ago. A removal is tried:
    she is held, and told that her password signs her in as before."""
    from datetime import datetime, timedelta
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    alice = _user("alice")
    now = datetime.utcnow()
    link = _identity(alice, row, last_sign_in_at=now - timedelta(days=30), linked_at=now - timedelta(days=60),
                     refused_at=None, hold_lifted_for=None, keys_only_hold_at=None)
    h = Admin(monkeypatch, [row], users=[alice], identities=[link])
    assert h.call("DELETE", f"/admin/sso/providers/{row.id}")[0] == 409
    assert link.refused_at is not None and link.keys_only_hold_at == link.refused_at
    assert h.accounts_told[-1][2].endswith("Your password signs you in as before.")
    return h, row, alice, link


def test_a_hold_written_for_keys_only_closes_no_password_while_its_provider_is_off(monkeypatch):
    """Later an administrator turns on "after those days, or a refusal, the account signs in only through a
    provider" for Contoso, still off (the removal's own advice leads there). A hold on record closes the password
    wherever a provider says so, whatever the provider's state: Alice's password, passkeys and SFTP password were
    refused from that save on, with nobody able to sign in through Contoso, the save answering that it held
    nobody, and nobody told. The hold was written for her keys and closes no more than that while Contoso is off."""
    from app.services import sso_freshness as F
    h, row, alice, link = _held_for_keys_only_by_a_removal(monkeypatch)
    del h.accounts_told[:]
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_lapse_ends_sign_in": True}})
    assert status == 200 and out["newly_held"] == 0 and out["held_by_a_refusal"] == 0 and out["held_by_its_days"] == 0, out
    assert F.held_to_a_provider(h.db, alice) is None                    # her password signs her in as she was told
    assert F.lapsed(h.db, alice.id) is not None                         # her keys stay paused, as she was told
    assert h.accounts_told == []
    standing = F.deadline_of(link, row)
    assert standing.refused and standing.keys_only_hold and not F.a_hold_closes(standing)
    assert F.closes_the_other_ways_in(h.db, alice, standing) is False
    # Turned on again: people can sign in through it, its days have run out, and the hold closes as any does.
    row.state = "enabled"
    standing = F.deadline_of(link, row)
    assert F.a_hold_closes(standing) and F.held_to_a_provider(h.db, alice) is not None


def test_a_providers_own_refusal_and_a_hold_from_days_that_ended_sign_in_close_whatever_its_state(monkeypatch):
    """What stays as it was: a refusal the provider made holds the account while the provider is off (turning a
    provider off in an incident hands nothing back), and so does a hold written at a turn-off for days that
    already ended sign-in (those people's passwords were closed before the turn-off)."""
    from datetime import datetime, timedelta
    from app.services import sso_freshness as F
    from app.services import sso_providers
    now = datetime.utcnow()
    row = _provider(state="disabled", created_at=None, updated_at=None)
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": True}
    alice = _user("alice")
    refused = _identity(alice, row, last_sign_in_at=now - timedelta(days=30), refused_at=now - timedelta(days=1),
                        keys_only_hold_at=None)
    assert F.a_hold_closes(F.deadline_of(refused, row)) is True
    # A mark from an earlier hold says nothing of a refusal made since: the refusal is the provider's own.
    refused.keys_only_hold_at = now - timedelta(days=9)
    assert F.deadline_of(refused, row).keys_only_hold is False and F.a_hold_closes(F.deadline_of(refused, row)) is True
    # Written by a turn-off while the days ended sign-in: no mark, and it closes while the provider is off.
    row.state = "enabled"
    lapsed = _identity(alice, row, last_sign_in_at=now - timedelta(days=30), refused_at=None, hold_lifted_for=None,
                       keys_only_hold_at=now - timedelta(days=90))

    class DB:
        def query(self, model):
            return self

        def filter(self, *a):
            return self

        def all(self):
            return [lapsed]
    assert sso_providers.hold_lapsed(DB(), row) == 1 and lapsed.refused_at is not None and lapsed.keys_only_hold_at is None
    row.state = "disabled"
    assert F.a_hold_closes(F.deadline_of(lapsed, row)) is True
    # No hold in force: nothing to close, marked or not.
    plain = _identity(alice, row, last_sign_in_at=now, refused_at=None, keys_only_hold_at=now)
    assert F.deadline_of(plain, row).keys_only_hold is False and F.a_hold_closes(F.deadline_of(plain, row)) is False


def test_a_save_that_makes_a_missed_sign_in_end_the_password_counts_whom_a_refusal_holds(monkeypatch):
    """Contoso is on and only pauses keys. It refused Cy at his last sign-in. An administrator makes a missed
    sign-in end the password too: Cy's password stops at that save. The count read only the accounts the days
    hold, so the save answered that nobody was newly held, and Cy was told nothing."""
    from datetime import datetime, timedelta
    h, row, (ann, ben, cy) = _linked_since(monkeypatch, [1, 2, 3], policy={"sso_freshness_days": 30,
                                                                         "sso_lapse_ends_sign_in": False})
    from app.core.models import ExternalIdentity
    link = next(i for i in h.db.rows_of(ExternalIdentity) if i.user_id == cy.id)
    link.refused_at = datetime.utcnow() - timedelta(hours=1)             # refused since his last sign-in
    link.last_sign_in_at = datetime.utcnow() - timedelta(days=3)
    from app.services import sso_providers as providers
    assert providers.held_through(h.db, row) == [] and providers.held_by_its_days(h.db, row) == []
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_lapse_ends_sign_in": True}})
    assert status == 200, out
    assert (out["newly_held"], out["held_by_a_refusal"], out["held_by_its_days"]) == (1, 1, 0), out
    assert [u.username for u in providers.held_through(h.db, row)] == ["cy"] and providers.held_by_its_days(h.db, row) == []
    label = row.label or row.name
    assert h.accounts_told == [(["cy"], f"Sign in through {label} to keep signing in here", (
        f"An administrator changed what a sign-in that {label} did not admit stops. Your account is held to a "
        f"sign-in through {label}: its password and passkeys do not sign it in to this vault until {label} has "
        "admitted it again. If it does not, ask your administrator."))]
    count = [a for a in h.audit("sso_provider_updated") if a[2].get("reason") == "held_by_its_days"]
    assert count[0][2] == {"provider_id": str(row.id), "name": row.name, "changed": [], "reason": "held_by_its_days",
                           "held_by_its_days": 0, "held_by_a_refusal": 1, "newly_held": 1}
    assert ("1 more linked account(s) that it had not admitted are held to a sign-in through it now: their password "
            "and passkeys do not sign them in until it admits them. They were told. 1 account(s) are held so in "
            "all.") in h.told[-1][2]
    # Saved again with nothing changed in what the days hold: nobody is held anew.
    del h.accounts_told[:]
    status, out = h.call("PATCH", f"/admin/sso/providers/{row.id}", {"policy": {"sso_freshness_days": 31}})
    assert status == 200 and out["newly_held"] == 0 and out["held_by_a_refusal"] == 1 and h.accounts_told == []


def test_a_provider_is_not_removed_while_sessions_that_came_through_it_still_stand(monkeypatch):
    """Contoso was turned off, and two of its sessions could not be ended: the notice said to turn it off again
    to end them. Another administrator removed it first. The removal took what names those sessions with it: they
    went on working until they ran out, turning it off again answered 404, and nothing said whom to sign out. The
    removal is refused, before anything is asked or changed, until none stands."""
    row = _provider(state="disabled", created_at=None, updated_at=None)
    h = Admin(monkeypatch, [row])
    sessions = _sessions_through(h, row, standing=1, ended=1, others=2, idle=1)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"] == {"reason": "sessions_standing", "message": (
        "2 session(s) that came through this provider still stand. Turn it off again to end its sessions first: "
        "removed now, nothing would name them any more.")}, out
    assert h.order == [] and h.rows() == [row] and h.audits == []          # no step-up asked, nothing written
    # They cannot be counted: not taken for none.
    real = h.R._sessions_standing
    monkeypatch.setattr(h.R, "_sessions_standing", lambda db, provider_id: None)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["message"].startswith("Sessions that came through this provider still stand.")
    monkeypatch.setattr(h.R, "_sessions_standing", real)
    # Ended meanwhile, after the step-up was given: read again in the row, and refused there too.
    for session in sessions:
        session.revoked = True
    seen = []

    def standing_again(db, provider_id):
        seen.append(1)
        return 0 if len(seen) == 1 else 3
    monkeypatch.setattr(h.R, "_sessions_standing", standing_again)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 409 and out["detail"]["reason"] == "sessions_standing" and h.order == ["step_up"] and h.rows() == [row]
    # None stands: removed.
    monkeypatch.setattr(h.R, "_sessions_standing", real)
    status, out = h.call("DELETE", f"/admin/sso/providers/{row.id}")
    assert status == 200 and out == {"removed": True} and h.rows() == []
