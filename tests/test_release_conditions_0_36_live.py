"""The detect queries kept for the 0.36.0 conditions (tests/_release_conditions_0_36.py), run on real Postgres: on a
throwaway database of the stack's server, with the schema the app's start builds, each query finds nothing on the
new database but what the start itself made, and once rows are seeded counts exactly those it is about: accounts held
to a provider, with self-service reset off and then on; passwords nobody knows, beside one whose hash changed since
and one held to its provider; accounts with a passkey or an identity on a provider that trusts its second factor and
no authenticator app, beside one with an app, a retired passkey, a provider that does not trust it and one that is
off; identities refused since their last sign-in or whose days ran out, on a provider that is on or off, beside one
refused before a later sign-in, one within its days and one on a provider whose days are 0, counted as the freshness
code itself counts them; the passkey mode with no roles, with roles, and optional; a held confirmation of an address
beside a held change of address and an applied confirmation; and the audit rows of a password sign-in given back. The
query that tells a database was on 0.36 finds 0.36's tables. test_release_conditions_0_36.py checks the queries
offline.
"""
import json

import pytest

import _release_conditions_0_36 as rc
from _throwaway_db import PREAMBLE, run_in, throwaway_database

pytestmark = pytest.mark.integration

SCRIPT = PREAMBLE + r'''
from app.core.models import (AuditLog, CredentialChange, ExternalIdentity, ManagedSetting, RoleEnum,
                             SecondFactorEnrollment, SsoProvider, SystemSetting, User, WebAuthnCredential)
from app.core import password_origin
from app.services import sso_freshness
QUERIES = json.loads(__QUERIES__)

def run(*only):
    out = {}
    with engine.begin() as c:
        for cid, sql in QUERIES.items():
            if only and cid not in only:
                continue
            rows = c.execute(text(sql)).mappings().all()
            out[cid] = [{k: (str(v) if v is not None else None) for k, v in r.items()} for r in rows]
    return out

out = {"before": run()}
ago = lambda days: now - timedelta(days=days)
db = SessionLocal()

def account(name, **kw):
    user = User(id=uuid.uuid4(), username="cond-" + name, email=name + "@example.com", password_hash="hash-" + name,
                role=RoleEnum.USER, is_active=True, **kw)
    db.add(user)
    db.flush()
    return user

def provider(name, state, policy):
    row = SsoProvider(id=uuid.uuid4(), name="cond-" + name, kind="oidc", state=state, policy=policy)
    db.add(row)
    db.flush()
    return row

def identity(user, on, linked, last=None, refused=None):
    db.add(ExternalIdentity(id=uuid.uuid4(), user_id=user.id, provider_id=on.id, issuer="https://idp.example",
                            subject="sub-" + user.username, subject_source="oidc:sub", linked_at=linked,
                            linked_by="admin", last_sign_in_at=last, refused_at=refused))

def passkey(user, retired=None):
    db.add(WebAuthnCredential(id=uuid.uuid4(), user_id=user.id, credential_id=uuid.uuid4().bytes,
                              public_key_cose=b"k", cose_alg=-7, retired_at=retired))

def app_factor(user, status):
    db.add(SecondFactorEnrollment(id=uuid.uuid4(), user_id=user.id, method="totp", status=status))

def nobody_knows(user):
    password_origin.mark_nobody_knows(user)
    db.flush()

# Held to a provider: two (true), beside one false and one never set.
for name, held in (("only-1", True), ("only-2", True), ("not-only", False), ("unset", None)):
    account("provider-" + name, sso_only=held)
# Passwords nobody knows: one not held to a provider and one never set, counted; one whose hash changed since, and
# one held to its provider, not.
nobody_knows(account("nobody-1", sso_only=False))
nobody_knows(account("nobody-2"))
changed = account("nobody-changed", sso_only=False)
nobody_knows(changed)
changed.password_hash = "another"
nobody_knows(account("nobody-held", sso_only=True))
# Second factors: a passkey and no app, a passkey and an app not yet confirmed, an identity on a provider that is on
# and trusts its factor: counted. A retired passkey, a passkey beside an active app, an identity on a provider that
# does not trust its factor, or that trusts it but is off: not.
trusting = provider("trusting", "enabled", {"sso_trust_idp_mfa": True})
distrusting = provider("distrusting", "enabled", {})
trusting_off = provider("trusting-off", "disabled", {"sso_trust_idp_mfa": True})
passkey(account("factor-passkey"))
unconfirmed = account("factor-unconfirmed")
passkey(unconfirmed)
app_factor(unconfirmed, "unconfirmed")
identity(account("factor-trusted"), trusting, linked=now)
passkey(account("factor-retired"), retired=ago(1))
with_app = account("factor-with-app")
passkey(with_app)
app_factor(with_app, "active")
identity(account("factor-distrusted"), distrusting, linked=now)
identity(account("factor-off"), trusting_off, linked=now)
# People a provider no longer admits, on a provider that is on with the default days, one that is off with the default
# days, and one that is off with none: refused since the last sign-in, never signed in and linked 31 days ago, signed
# in 31 days ago, refused with no sign-in, linked 40 days ago on the provider that is off: counted. Refused before a
# later sign-in, signed in 29 days ago, linked 100 days ago where the days are 0: not.
off = provider("off", "disabled", {})
no_days = provider("no-days", "disabled", {"sso_freshness_days": 0})
identity(account("left-refused"), distrusting, linked=ago(60), last=ago(5), refused=ago(1))
identity(account("left-answered"), distrusting, linked=ago(60), last=ago(1), refused=ago(5))
identity(account("left-never"), distrusting, linked=ago(31))
identity(account("left-29"), distrusting, linked=ago(60), last=ago(29))
identity(account("left-31"), distrusting, linked=ago(60), last=ago(31))
identity(account("left-refused-no-days"), no_days, linked=ago(100), refused=ago(1))
identity(account("left-no-days"), no_days, linked=ago(100))
identity(account("left-off"), off, linked=ago(40))
# Held changes: a confirmation of an address, counted; a held change of address, an applied confirmation and a held
# password change, not.
target = account("held-target")
for kind, status, payload in (("email", "held", {"email": "held-target@example.com", "confirm": True}),
                              ("email", "held", {"email": "elsewhere@example.com"}),
                              ("email", "made", {"email": "held-target@example.com", "confirm": True}),
                              ("password", "held", None)):
    db.add(CredentialChange(target_user_id=target.id, kind=kind, status=status, requested_by_name="admin",
                            requested_at=now, payload=payload, applied_at=now if status == "made" else None))
# Two password sign-ins given back at a start, beside another action.
for action in ("sso_password_sign_in_restored", "sso_password_sign_in_restored", "file_upload"):
    db.add(AuditLog(id=uuid.uuid4(), action=action, status="success", timestamp=now, resource_id=str(target.id)))
db.commit()
out["after"], out["target"] = run(), str(target.id)
# What the freshness code says of the same identities: those whose deadline is a refusal or has passed.
out["by_the_code"] = 0
for row in db.query(ExternalIdentity).all():
    found = sso_freshness.deadline_of(row, db.query(SsoProvider).filter(SsoProvider.id == row.provider_id).first())
    out["by_the_code"] += found is not None and (found.refused or found.due <= now)

# Self-service reset on.
policy = db.query(SystemSetting).filter(SystemSetting.key == "global").first()
if policy is None:
    db.add(SystemSetting(key="global", value={"password_reset_enabled": True}))
else:
    policy.value = dict(policy.value or {}, password_reset_enabled=True)
db.commit()
out["reset_on"] = run("provider-only-accounts")

# The passkey mode: required for roles with no roles, then with a role, then optional with that role.
mode = ManagedSetting(key="webauthn_mode", value="required_for_roles", version=1, updated_at=now)
roles = ManagedSetting(key="webauthn_required_roles", value=[], version=2, updated_at=now)
db.add_all([mode, roles])
db.commit()
out["no_roles"] = run("role-must-hold-a-passkey")
roles.value, roles.version = ["admin"], 3
db.commit()
out["a_role"] = run("role-must-hold-a-passkey")
mode.value, mode.version = "optional", 4
db.commit()
out["optional"] = run("role-must-hold-a-passkey")
print(json.dumps(out))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_each_detect_query_finds_what_was_seeded_and_only_that(throwaway):
    out = run_in(throwaway, SCRIPT.replace("__QUERIES__", repr(json.dumps(rc.DETECT))))
    before, after = out["before"], out["after"]
    assert set(before) == set(after) == set(rc.DETECT)

    # On the new database: no row where a count is not asked for, a count of none where it is, and 0.36's tables.
    for cid in ("provider-only-accounts", "role-must-hold-a-passkey", "privileged-accounts-keep-a-password"):
        assert before[cid] == [], cid
    for cid in ("passwords-nobody-knows", "second-factors-an-earlier-release-does-not-know",
                "people-a-provider-no-longer-admits", "held-address-confirmations"):
        assert before[cid] == [{"count": "0"}], cid
    assert len(before["back-on-0-36-after-an-earlier-release"]) == 1

    # The two held to a provider, and the one among the passwords nobody knows that is held to its provider.
    assert after["provider-only-accounts"] == [{"provider_only": "3", "self_service_reset": "false"}]
    assert out["reset_on"]["provider-only-accounts"] == [{"provider_only": "3", "self_service_reset": "true"}]
    assert after["passwords-nobody-knows"] == [{"count": "2"}]
    assert after["second-factors-an-earlier-release-does-not-know"] == [{"count": "3"}]
    assert after["people-a-provider-no-longer-admits"] == [{"count": "5"}]
    assert out["by_the_code"] == 5
    assert out["no_roles"]["role-must-hold-a-passkey"] == []
    assert len(out["a_role"]["role-must-hold-a-passkey"]) == 1
    assert out["optional"]["role-must-hold-a-passkey"] == []
    assert after["held-address-confirmations"] == [{"count": "1"}]
    assert [row["resource_id"] for row in after["privileged-accounts-keep-a-password"]] == [out["target"]] * 2
