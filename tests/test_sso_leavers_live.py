"""A person who has left, on a running stack's Postgres (a throwaway database of its own, tests/_throwaway_db.py),
with the application's own functions: the real password check and its turn, the real sign-in pipeline, the real
rows.

- An account whose sign-in through its provider has lapsed, or that the provider refused, where the provider closes
  the other ways in: the right password is refused on the web and over SFTP with no session written, a passkey by
  itself is refused, "Stay signed in" is refused, an open SFTP connection goes no further; the password as a step
  of a provider's own sign-in goes on, and a sign-in through the provider restores everything.
- The same account on a provider that only pauses the keys: everything but the keys goes on.
- An administrator: never held.
- An account made at its first sign-in: provider-only whatever the provider's password setting, until the provider
  lets such accounts set a password, and back when it no longer does; made an administrator, it loses the flag and
  its password is taken back.

The last two tests go through the stack's own doors, over HTTP and SFTP, on an account of the stack linked to a
provider row of the test's own: the sign-in form, an SFTP sign-in with the password and with a key, connections
that are already open, and a passkey by itself; with the provider closing the other ways in, and only pausing keys.

test_sso_leavers.py holds the same rules offline.
"""
import json
import uuid

import pytest
import requests

from _account_change_helpers import psql
from _throwaway_db import PREAMBLE, run_in, throwaway_database
from conftest import ApiClient, BASE_URL
from test_sign_in_channels_live import (_REFUSED, _key_connection, _password_connection, _works,  # noqa: F401
                                        person)

pytestmark = pytest.mark.integration


SCENARIO = PREAMBLE + r'''
from app.api import api_server as api
from app.core import password_origin, privileged_accounts, sso_only
from app.core.models import ActiveSession, ExternalIdentity, RoleEnum, SsoProvider, User
from app.core.security import hash_password
from app.services import auth_service as auth_mod, sign_in, sso_freshness

PASSWORD, IP = "Leaver-Password-8x!", "192.0.2.61"
LONG_AGO = now - timedelta(days=40)
# What is not the database stands still: no live-monitor signal, no notice, no email, no throttle.
sign_in._record = lambda *a, **k: None
api._fire_action_email = lambda *a, **k: None
api._notify_users = lambda *a, **k: None
auth_mod.AuthService._check_rate_limit = lambda self, *a, **k: None
auth_mod.AuthService._give_back = lambda self, *a, **k: None


def provider(name, **policy):
    with SessionLocal() as s:
        row = SsoProvider(id=uuid.uuid4(), kind="oidc", state="enabled", name=name, label="Sign in with " + name,
                          show_on_sign_in=True, policy=policy or None)
        s.add(row)
        s.commit()
        return row.id


def account(name, pid, *, role=RoleEnum.USER, signed_in=LONG_AGO, refused=None, linked_by="self", made_here=False):
    with SessionLocal() as s:
        u = User(username=name + "-" + uuid.uuid4().hex[:6], email=None, password_hash=hash_password(PASSWORD),
                 role=role, is_active=True, is_locked=False, sso_only=True if made_here else None)
        if made_here:
            password_origin.set_by_other(u, None)
            password_origin.mark_nobody_knows(u)
        s.add(u)
        s.flush()
        s.add(ExternalIdentity(id=uuid.uuid4(), user_id=u.id, provider_id=pid, issuer="https://idp.example",
                               subject="subject-" + u.username, subject_source="oidc:sub",
                               linked_at=LONG_AGO - timedelta(days=30), linked_by=linked_by,
                               last_sign_in_at=signed_in, refused_at=refused))
        s.commit()
        return u.id, u.username


def outcome(fn):
    try:
        return ["ok", fn()]
    except Exception as exc:  # noqa: BLE001
        said = getattr(exc, "detail", None) or getattr(exc, "message", None) or str(exc)
        return ["refused", type(exc).__name__, getattr(exc, "status_code", None), str(said)[:200]]


def password(name, channel="web", through_provider=False):
    def run():
        with SessionLocal() as s:
            auth_mod.AuthService(s).authenticate_user(name, PASSWORD, IP, channel=channel,
                                                      through_provider=through_provider)
            return "signed in"
    return outcome(run)


def passkey(uid):
    def run():
        with SessionLocal() as s:
            user = s.get(User, uid)
            result = sign_in.SignInResult(user, [sign_in.HARDWARE_KEY], IP, user_verified=True,
                                          passwordless_allowed=True)
            return type(sign_in.finish(s, result)).__name__
    return outcome(run)


def stay_signed_in(uid):
    def run():
        with SessionLocal() as s:
            sign_in.refuse_renewal_by_the_sign_in_rules(s, s.get(User, uid), {"amr": ["pwd"]})
            return "kept going"
    return outcome(run)


def open_connection(uid):
    with SessionLocal() as s:
        user = s.get(User, uid)
        return {"a password's": sso_freshness.closes_a_connection(s, user, by_password=True),
                "a key's": sso_freshness.closes_a_connection(s, user, by_password=False)}


def sessions(uid):
    with SessionLocal() as s:
        return s.query(ActiveSession).filter(ActiveSession.user_id == uid).count()


def every_door(uid, name):
    return {"web": password(name), "sessions after the web door": sessions(uid), "sftp": password(name, "sftp"),
            "passkey": passkey(uid), "stay signed in": stay_signed_in(uid), "open connection": open_connection(uid)}


out = {}
closing, pausing = provider("Contoso"), provider("Fabrikam", sso_lapse_ends_sign_in=False)

# 1. The days ran out on a provider that closes the other ways in.
uid, name = account("held", closing)
out["held"] = every_door(uid, name)
out["held, the password as a step of the provider's sign-in"] = password(name, through_provider=True)
with SessionLocal() as s:                       # a sign-in the provider admits stamps the identity
    s.query(ExternalIdentity).filter(ExternalIdentity.user_id == uid).update({"last_sign_in_at": now})
    s.commit()
out["held, after a sign-in through the provider"] = every_door(uid, name)

# 2. The same on a provider that only pauses the keys.
uid, name = account("paused", pausing)
out["keys only"] = every_door(uid, name)

# 3. Refused by the provider well inside its days.
uid, name = account("refused", closing, signed_in=now - timedelta(days=1), refused=now - timedelta(hours=1))
out["refused"] = {"web": password(name), "passkey": passkey(uid)}

# 4. An administrator keeps the password as the way in; the keys pause as anybody's.
uid, name = account("root", closing, role=RoleEnum.ADMIN)
out["administrator"] = {"web": password(name), "open connection": open_connection(uid)}
with SessionLocal() as s:
    out["administrator"]["kind"] = privileged_accounts.kind(s, s.get(User, uid))

# 5. An account made at its first sign-in.
made_by = provider("Northwind")
uid, name = account("made", made_by, linked_by="jit", made_here=True, signed_in=now)
other, _ = account("linked", made_by, signed_in=now)


def settle_all():
    with SessionLocal() as s:
        row = s.get(SsoProvider, made_by)
        changed = sso_only.apply_password_login(s, row)
        s.commit()
        return changed


def flags():
    with SessionLocal() as s:
        made, linked = s.get(User, uid), s.get(User, other)
        return {"made": bool(made.sso_only), "linked": bool(linked.sso_only),
                "made holds a password nobody knows": password_origin.nobody_knows(made),
                "made may sign in to SFTP with a password": bool(made.sftp_password_auth)}


def set_policy(**policy):
    with SessionLocal() as s:
        s.get(SsoProvider, made_by).policy = policy or None
        s.commit()


out["made here"] = {"as made": [settle_all(), flags()], "web": password(name)}
set_policy(sso_jit_password=True)
out["made here"]["the provider lets it set a password"] = [settle_all(), flags()]
set_policy(sso_jit_password=False)
out["made here"]["the provider no longer does"] = [settle_all(), flags()]


def promote():
    with SessionLocal() as s:
        admin = s.query(User).filter(User.role == RoleEnum.ADMIN).first()
        user = s.get(User, uid)
        api._record_admin_grant(s, user, by=admin)
        taken = api._take_back_password_at_promotion(s, user, by=admin)
        api._set_role(s, user, RoleEnum.ADMIN, actor=admin)
        s.commit()
        return {"password taken back": bool(taken)}


out["made here"]["promoted"] = [outcome(promote), flags()]
with SessionLocal() as s:
    user = s.get(User, uid)
    out["made here"]["after the promotion"] = {"role": user.role.value, "kind": privileged_accounts.kind(s, user),
                                               "settled": sso_only.settle(s, user)}
print(json.dumps(out))
'''


@pytest.fixture(scope="module")
def out():
    for name in throwaway_database():
        yield run_in(name, SCENARIO)


THROUGH = "Sign in through Contoso: your account has not signed in there within the time your organisation allows"


def test_a_held_account_is_refused_at_every_door_that_goes_through_no_provider(out):
    held = out["held"]
    assert held["web"][:3] == ["refused", "SignInThroughProviderError", None] and held["web"][3].startswith(THROUGH)
    assert held["sessions after the web door"] == 0
    assert held["sftp"][:2] == ["refused", "SignInThroughProviderError"]
    assert held["passkey"][:3] == ["refused", "ProviderOnly", 403] and held["passkey"][3].startswith(THROUGH)
    assert held["stay signed in"][:3] == ["refused", "HTTPException", 403]
    assert held["open connection"] == {"a password's": True, "a key's": True}


def test_the_password_as_a_step_of_the_providers_sign_in_goes_on_and_that_sign_in_restores_everything(out):
    assert out["held, the password as a step of the provider's sign-in"] == ["ok", "signed in"]
    after = out["held, after a sign-in through the provider"]
    assert after["web"] == ["ok", "signed in"] and after["sftp"] == ["ok", "signed in"]
    assert after["passkey"] == ["ok", "SignedIn"] and after["stay signed in"] == ["ok", "kept going"]
    assert after["open connection"] == {"a password's": False, "a key's": False}


def test_a_provider_that_only_pauses_the_keys_leaves_every_other_way_in(out):
    keys_only = out["keys only"]
    assert keys_only["web"] == ["ok", "signed in"] and keys_only["sftp"] == ["ok", "signed in"]
    assert keys_only["passkey"] == ["ok", "SignedIn"] and keys_only["stay signed in"] == ["ok", "kept going"]
    assert keys_only["open connection"] == {"a password's": False, "a key's": True}


def test_a_refusal_holds_at_once_and_says_so(out):
    refused = out["refused"]
    assert refused["web"][:2] == ["refused", "SignInThroughProviderError"]
    assert refused["web"][3].startswith("Contoso did not admit your account")
    assert refused["passkey"][:3] == ["refused", "ProviderOnly", 403]


def test_an_administrator_is_never_held(out):
    root = out["administrator"]
    assert root["kind"] == "administrator" and root["web"] == ["ok", "signed in"]
    assert root["open connection"] == {"a password's": False, "a key's": True}


def test_an_account_made_at_a_first_sign_in_follows_the_providers_setting_and_a_promotion(out):
    made = out["made here"]
    nothing = {"made_sso_only": [], "restored": []}
    assert made["as made"][0] == nothing and made["as made"][1]["made"] is True and made["as made"][1]["linked"] is False
    assert made["web"][:2] == ["refused", "InvalidCredentialsError"]          # its password is nobody's
    changed, flags = made["the provider lets it set a password"]
    assert changed["made_sso_only"] == [] and len(changed["restored"]) == 1 and changed["restored"][0].startswith("made-")
    assert flags["made"] is False and flags["made holds a password nobody knows"] is True
    changed, flags = made["the provider no longer does"]
    assert len(changed["made_sso_only"]) == 1 and changed["restored"] == []
    assert flags["made"] is True and flags["linked"] is False
    assert flags["made may sign in to SFTP with a password"] is False
    promoted, flags = made["promoted"]
    assert promoted == ["ok", {"password taken back": True}], promoted
    assert flags["made"] is False and flags["made holds a password nobody knows"] is True
    assert made["after the promotion"] == {"role": "admin", "kind": "administrator", "settled": None}


# --------------------------------------------------------------------------- through the stack's own doors

UTC_NOW = "(now() at time zone 'utc')"


def _link(account_id, *, days_ago, **policy):
    """A provider row of the test's own, on (so the person is told to use it) with no button on the sign-in page,
    and an identity of the account on it whose last sign-in there was ``days_ago`` days ago. Its id and name."""
    pid, name = str(uuid.uuid4()), "leavers-" + uuid.uuid4().hex[:8]
    psql("INSERT INTO sso_providers (id, kind, state, name, label, policy) VALUES "
         f"('{pid}', 'oidc', 'enabled', '{name}', 'Sign in with {name}', '{json.dumps(policy)}')")
    psql("INSERT INTO external_identities (id, user_id, provider_id, issuer, subject, subject_source, linked_at, "
         "linked_by, last_sign_in_at) VALUES "
         f"('{uuid.uuid4()}', '{account_id}', '{pid}', 'https://idp.example', 'subject-{name}', 'oidc:sub', "
         f"{UTC_NOW} - interval '90 days', 'self', {UTC_NOW} - interval '{int(days_ago)} days')")
    return pid, name


def _signed_in_there(pid, days_ago):
    psql(f"UPDATE external_identities SET last_sign_in_at = {UTC_NOW} - interval '{int(days_ago)} days' "
         f"WHERE provider_id = '{pid}'")


def _policy(pid, **policy):
    psql(f"UPDATE sso_providers SET policy = '{json.dumps(policy)}' WHERE id = '{pid}'")


def _form(name, password):
    return requests.post(f"{BASE_URL}/auth/login", json={"username": name, "password": password}, timeout=20)


def test_the_form_and_sftp_refuse_a_held_account_and_its_open_connections_go_no_further(person):  # noqa: F811
    name, password = person["name"], person["password"]
    pid, provider = _link(person["id"], days_ago=1)
    try:
        # Inside the provider's days: the form signs in, and a connection each way is open.
        assert _form(name, password).status_code == 200
        t, by_password = _password_connection(name, password)
        person["opened"].append(t)
        t, by_key = _key_connection(name, person["pkey"])
        person["opened"].append(t)
        assert _works(by_password) and _works(by_key)
        # The days run out.
        _signed_in_there(pid, 40)
        r = _form(name, password)
        assert r.status_code == 403 and r.json()["detail"].startswith(f"Sign in through {provider}: "), r.text
        assert r.json()["detail"].endswith("Use the sign-in link your organisation gave you.")
        wrong = _form(name, "not-the-password-1!")
        assert wrong.status_code == 401 and wrong.json()["detail"] == "Invalid username or password"
        with pytest.raises(_REFUSED):
            _password_connection(name, password)
        with pytest.raises(_REFUSED):
            _key_connection(name, person["pkey"])
        assert not _works(by_password) and not _works(by_key)
        # The provider only pauses the keys: the password signs in again, on the web and over SFTP; the key not.
        _policy(pid, sso_lapse_ends_sign_in=False)
        assert _form(name, password).status_code == 200
        t, again = _password_connection(name, password)
        person["opened"].append(t)
        assert _works(again)
        with pytest.raises(_REFUSED):
            _key_connection(name, person["pkey"])
        # It closes the other ways in again, and the connection the password just made goes no further.
        _policy(pid)
        assert not _works(again) and _form(name, password).status_code == 403
        # A sign-in the provider admits (its stamp on the identity) restores everything.
        _signed_in_there(pid, 0)
        assert _form(name, password).status_code == 200
        t, key_again = _key_connection(name, person["pkey"])
        person["opened"].append(t)
        assert _works(key_again)
    finally:
        psql(f"DELETE FROM sso_providers WHERE id = '{pid}'")


def test_a_passkey_by_itself_is_refused_for_a_held_account_and_signs_in_where_the_provider_only_pauses_keys(admin):
    from test_api_passkeys_live import _public_url, _register
    user = admin.create_user(role="user")
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    client.username, client.password = user["_username"], user["_password"]
    pid = None
    try:
        made, auth = _register(client, "leaver key")
        assert made.status_code == 201, made.text
        pid, provider = _link(user["id"], days_ago=40)

        def by_itself(count):
            anon = ApiClient()
            body = anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/options", json={}, timeout=15).json()
            credential = auth.get_assertion(body["options"], _public_url(), sign_count=count)
            return anon.session.post(f"{anon.base_url}/auth/passkeys/sign-in/verify",
                                     json={"challenge_id": body["challenge_id"], "credential": credential}, timeout=15)

        r = by_itself(1)
        assert r.status_code == 403 and r.json()["detail"].startswith(f"Sign in through {provider}: "), r.text
        _policy(pid, sso_lapse_ends_sign_in=False)
        r = by_itself(2)
        assert r.status_code == 200 and r.json()["user"]["username"] == client.username, r.text
    finally:
        if pid:
            psql(f"DELETE FROM sso_providers WHERE id = '{pid}'")
        admin.delete_user(user["id"])
