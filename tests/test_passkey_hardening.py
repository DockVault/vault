"""What the hostile review of the passkey routes asked to pin: a retired key refused at sign-in; the lockout read
before anything is counted and a key named against another account's challenge never counted against its owner; a
counter that went backwards told to the owner; the throttle charged per address and given back on success; an
auditor-right holder (suspended too) always adding the password; the provider's sign-in finished by a passkey; the
compliance rule for every non-administrator; a provisional key confirmed only by something older than it; the
second step counting an unusable challenge and another account's registered key; the same credential on another
account refused at registration; hostile browser answers refused rather than crashing; the retired-key pruner."""
import time
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env
from _webauthn_softauth import FLAG, SoftAuthenticator
from test_passkey_second_factor import Harness, _call_h
from test_passkey_sign_in import ORIGIN, RP_ID, _call, _claims, _user

pytestmark = pytest.mark.unit


def _other_key(user):
    """A registered key of ``user`` made by a fresh authenticator, for a harness's in-memory table."""
    from app.core.models import WebAuthnCredential
    from fido2 import cbor
    auth = SoftAuthenticator()
    auth.user_handle = user.id.bytes
    cose = auth.cose_public_key
    row = WebAuthnCredential(id=uuid.uuid4(), user_id=user.id, credential_id=auth.credential_id,
                             public_key_cose=cbor.encode(dict(cose)), cose_alg=cose.ALGORITHM, sign_count=0,
                             transports=["internal"], aaguid=None, backup_eligible=False, backup_state=False,
                             uv_initialized=True, discoverable=True, label="other", created_at=datetime.utcnow(),
                             last_used_at=None, created_by_session=None, provisional_until=None, retired_at=None,
                             prf_slot_id=None)
    return auth, row


# --------------------------------------------------------------------------- signing in

def test_a_retired_key_never_signs_in(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    row.retired_at = datetime.utcnow()
    status, body = h.sign_in(auth)
    assert status == 401 and h.failures == [("", "unknown passkey", "passkey")]
    assert h.counted == [] and row.last_used_at is None


def test_a_key_named_against_another_accounts_challenge_is_never_counted_against_its_owner(monkeypatch):
    alice, bob = _user(), _user("bob")
    h = Harness(monkeypatch, [alice, bob])
    auth, row = h.enroll(alice)
    bauth, brow = h.enroll(bob)
    status, body = h.options("bob")                    # bob's challenge...
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=1)   # ...answered with alice's public id
    status, out = _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 401 and h.failures[-1] == ("alice", "passkey of another account", "passkey")
    assert h.counted == []                              # the address paid, not alice


def test_a_lockout_is_read_before_anything_is_counted(monkeypatch):
    from app.core.sign_in_lockout import Lock
    alice, bob = _user(), _user("bob")
    h = Harness(monkeypatch, [alice, bob], lock=Lock("account", datetime(2999, 1, 1), "s"))
    auth, row = h.enroll(alice)
    h.enroll(bob)
    status, body = h.options("bob")
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=1)
    status, out = _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": body["challenge_id"], "credential": credential})
    assert status == 403 and h.counted == [] and h.failures == []
    # A real signature failure under a lock: refused by the lock too, counted nowhere.
    status, body = h.sign_in(auth, username="alice", bad_signature=True)
    assert status == 403 and h.counted == []


def test_a_counter_that_went_backwards_tells_the_owner(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    notices = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None: (
        notices.append((list(ids), title)) or list(ids)))
    auth, row = h.enroll(alice, sign_count=9)
    status, body = h.sign_in(auth, username="alice", sign_count=3)
    assert status == 401 and h.counted == ["alice"]
    assert ("action", "passkey_sign_count_regressed") in h.audits
    assert notices and notices[-1] == ([str(alice.id)], "A passkey may have been copied")
    assert row.sign_count == 9 and row.last_used_at is None


def test_the_throttle_is_charged_per_address_and_given_back_on_success(monkeypatch):
    from app.services.auth_service import AuthService, RateLimitExceededError
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    charges, given_back = [], []
    monkeypatch.setattr(AuthService, "_check_rate_limit", lambda self, identifier, ip: charges.append((identifier, ip)) or {"charges": [("cache", "k", "v")]})
    monkeypatch.setattr(AuthService, "_give_back", classmethod(lambda cls, throttle: given_back.append(throttle)))
    status, body = h.sign_in(auth, username="alice", sign_count=1)
    assert status == 200 and len(charges) == 1 and charges[0][0].startswith("passkey:") and len(given_back) == 1
    # A failure keeps its charge.
    status, body = h.sign_in(auth, username="alice", sign_count=1)          # the counter did not move: refused
    assert status == 401 and len(charges) == 2 and len(given_back) == 1
    # Over the limit: 429 before any challenge is spent.
    def _over(self, identifier, ip):
        raise RateLimitExceededError("too many", retry_after=30)
    monkeypatch.setattr(AuthService, "_check_rate_limit", _over)
    status, body = h.options("alice")
    status, out = _call(h.S, "POST", "/auth/passkeys/sign-in/verify", {"challenge_id": body["challenge_id"], "credential": {}})
    assert status == 429 and "sign_in" in [__import__("json").loads(v)["purpose"] for v in h.redis.rows.values()]


def test_a_suspended_auditor_right_still_means_the_password_step(monkeypatch):
    from app.core import auditor_rights
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: types.SimpleNamespace(status="suspended"))
    status, body = h.sign_in(auth, username="alice", sign_count=1)
    assert status == 200 and body.get("stage") == "password", body
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: types.SimpleNamespace(status="proposed"))
    status, body = h.sign_in(auth, username="alice", sign_count=2)
    assert status == 200 and "access_token" in body and "stage" not in body


def test_the_counters_do_not_move_when_the_pipeline_refuses(monkeypatch):
    alice = _user(is_active=False)
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice, sign_count=1)
    status, body = h.sign_in(auth, username="alice", sign_count=9)
    assert status == 401 and row.sign_count == 1 and row.last_used_at is None


def test_a_providers_sign_in_is_finished_by_a_passkey_like_a_code():
    set_bare_api_env()
    from app.services import sign_in
    user = types.SimpleNamespace(role=None)
    done = sign_in.second_factor_due(user, ["hwk"], factor_in_effect=True, enrollment_pending=False, provider_id="okta",
                                     user_verified=True)
    assert done == sign_in.DONE
    assert sign_in.second_factor_due(user, ["totp"], factor_in_effect=True, enrollment_pending=False, provider_id="okta") == sign_in.DONE
    # Without a provider the passkey rules stand.
    assert sign_in.second_factor_due(user, ["hwk"], factor_in_effect=True, enrollment_pending=False) == sign_in.STAGE_PASSWORD


# --------------------------------------------------------------------------- the second step and the step-up

def test_the_second_step_counts_an_unusable_challenge_and_another_accounts_key(monkeypatch):
    alice, bob = _user(), _user("bob")
    h = Harness(monkeypatch, [alice, bob])
    auth, row = h.enroll(alice)
    bauth, brow = h.enroll(bob)
    pending, headers = h.pending_for(alice)
    # A made-up challenge id.
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify", {"challenge_id": "0" * 32, "credential": {}}, headers)
    assert status == 400 and pending.attempts == 1
    # Bob's registered key at alice's second step.
    status, body = _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)
    credential = bauth.get_assertion(body["options"], ORIGIN, sign_count=1)
    status, out = _call_h(h.S, "POST", "/auth/second-factor/passkey/verify",
                          {"challenge_id": body["challenge_id"], "credential": credential}, headers)
    assert status == 401 and pending.attempts == 2
    # The cap: at five wrong answers the pending login is spent.
    pending.attempts = 5
    assert _call_h(h.S, "POST", "/auth/second-factor/passkey/options", None, headers)[0] == 401
    assert _call_h(h.S, "POST", "/auth/second-factor/passkey/verify", {"challenge_id": "0" * 32, "credential": {}}, headers)[0] == 401


def test_a_step_up_challenge_of_another_account_is_refused(monkeypatch):
    alice, bob = _user(), _user("bob")
    h = Harness(monkeypatch, [alice, bob])
    auth, row = h.enroll(alice)
    h.enroll(bob)
    status, body = _call(h.S, "POST", "/auth/passkeys/step-up/options")           # alice's challenge
    h.current_user = bob
    credential = auth.get_assertion(body["options"], ORIGIN, sign_count=1)
    status, out = _call(h.S, "POST", "/auth/second-factor/step-up",
                        {"action": "account.second_factor", "method": "passkey", "challenge_id": body["challenge_id"],
                         "credential": credential})
    assert status in (400, 403) and not h.receipts


def test_the_compliance_rule_binds_every_non_administrator_to_the_approved_keys(monkeypatch):
    from app.core import auditor_rights
    alice = _user()
    h = Harness(monkeypatch, [alice])
    auth, row = h.enroll(alice)
    grant = types.SimpleNamespace(approved_credential_ids=[])
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: grant)
    status, body = h.step_up_with_passkey(auth, "compliance.hold.place")
    assert status == 403 and "approved with" in body["detail"]
    grant.approved_credential_ids = [str(row.id)]
    assert h.step_up_with_passkey(auth, "compliance.hold.place", sign_count=4)[0] == 200
    # An administrator holds no grant and needs none.
    root = _user("root", role="admin")
    h2 = Harness(monkeypatch, [root])
    rauth, rrow = h2.enroll(root)
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id, **kw: None)
    assert h2.step_up_with_passkey(rauth, "compliance.hold.place")[0] == 200


def test_a_provisional_key_is_confirmed_only_by_something_older_than_it(monkeypatch):
    alice = _user()
    h = Harness(monkeypatch, [alice])
    from app.core.models import SecondFactorEnrollment
    h.db.rows_of(SecondFactorEnrollment).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=alice.id, method="totp", status="active"))
    auth1, p1 = h.enroll(alice, provisional=True, label="p1")
    auth2, p2 = h.enroll(alice, provisional=True, label="p2")
    p2.created_at = p1.created_at + timedelta(seconds=5)
    # A receipt earned with the other provisional key confirms nothing.
    status, body = h.step_up_with_passkey(auth2, "account.second_factor")
    assert status == 200
    status, out = _call_h(h.S, "POST", f"/users/me/passkeys/{p1.id}/confirm", None, {"X-Second-Factor": body["receipt"]})
    assert status == 409 and "older than it" in out["detail"] and p1.provisional_until is not None
    # Nor a receipt whose factor part is unknown or an email code.
    for marker in ("", "email"):
        h.receipts["rx"] = (str(alice.id), "account.second_factor", "sess-1", marker)
        status, out = _call_h(h.S, "POST", f"/users/me/passkeys/{p1.id}/confirm", None, {"X-Second-Factor": "rx"})
        assert status == 409, marker
    # The authenticator app does.
    h.receipts["rt"] = (str(alice.id), "account.second_factor", "sess-1", "totp")
    status, out = _call_h(h.S, "POST", f"/users/me/passkeys/{p1.id}/confirm", None, {"X-Second-Factor": "rt"})
    assert status == 200 and p1.provisional_until is None
    # And now p1, ordinary and older, vouches for p2.
    status, body = h.step_up_with_passkey(auth1, "account.second_factor", sign_count=2)
    status, out = _call_h(h.S, "POST", f"/users/me/passkeys/{p2.id}/confirm", None, {"X-Second-Factor": body["receipt"]})
    assert status == 200 and p2.provisional_until is None


# --------------------------------------------------------------------------- registration

def test_the_same_credential_on_another_account_is_refused_at_registration(monkeypatch):
    from test_passkey_routes import Harness as RouteHarness, _call as _rcall
    alice, bob = _user(), _user("bob")
    h = RouteHarness(monkeypatch, alice)
    status, shown, auth = h.register(label="alice's")
    assert status == 201
    from app.core.models import User
    h.db.rows_of(User).append(bob)
    monkeypatch.setitem(h.S.app.dependency_overrides, h.S.get_current_user, lambda: bob)
    monkeypatch.setitem(h.S.app.dependency_overrides, h.S.get_enrolling_principal, lambda: (bob, None))
    monkeypatch.setitem(h.S.app.dependency_overrides, h.S.require_interactive_admin, lambda: bob)
    status, body = _rcall(h.S, "POST", "/users/me/passkeys/register/options", {"current_password": "pw"})
    assert status == 200
    credential = auth.make_credential(body["options"], ORIGIN)
    status, out = _rcall(h.S, "POST", "/users/me/passkeys/register/verify",
                         {"challenge_id": body["challenge_id"], "credential": credential, "label": "bob's"})
    assert status == 409 and out["detail"]["reason"] == "already_registered"
    assert [r.user_id for r in h.rows()] == [alice.id]


def test_hostile_browser_answers_are_refused_not_crashes():
    set_bare_api_env()
    from fido2.utils import websafe_encode
    from fido2.webauthn import AttestationObject, AuthenticatorData
    from app.services import webauthn_service as ws
    rp = ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name="x")
    policy = ws.PasskeyPolicy()
    challenge = b"c" * 32
    options = ws.registration_options(rp, policy, challenge=challenge, user_id=b"u" * 16, username="alice", display_name=None)
    auth = SoftAuthenticator()
    # Odd extension and transport types.
    for spoil in ({"extensions": {"credProps": 5}}, {"transports": 5}, {"transports": "usb"}, {"extensions": {"credProps": {"rk": "yes"}}}):
        credential = auth.make_credential(options, ORIGIN, **spoil)
        key = ws.verify_registration(rp, policy, challenge=challenge, credential=credential)
        assert key.discoverable is None or isinstance(key.discoverable, bool)
        assert all(isinstance(t, str) for t in key.transports) and "u" not in key.transports
    # An attestation whose authenticator data carries no credential: refused as malformed, not an AssertionError.
    credential = auth.make_credential(options, ORIGIN)
    auth_data = AuthenticatorData.create(SoftAuthenticator.rp_id_hash(RP_ID), FLAG.UP | FLAG.UV, 0)
    credential["response"]["attestationObject"] = websafe_encode(AttestationObject.create("none", auth_data, {}))
    with pytest.raises(ws.Refused) as e:
        ws.verify_registration(rp, policy, challenge=challenge, credential=credential)
    assert e.value.code == "malformed"
    # A credential id outside the standard's bounds.
    short = SoftAuthenticator()
    short.credential_id = b"ab"
    with pytest.raises(ws.Refused) as e:
        ws.verify_registration(rp, policy, challenge=challenge, credential=short.make_credential(options, ORIGIN))
    assert e.value.code == "malformed"


# --------------------------------------------------------------------------- the pruner

def test_retired_passkeys_are_pruned_after_thirty_days():
    set_bare_api_env()
    from app.core import retention, working_records
    from app.core.models import WebAuthnCredential
    assert any(j.name == "retired_passkeys" for j in retention.JOBS)
    now = datetime(2026, 11, 9, 12, 0, 0)
    (cond,) = working_records.retired_passkey_conditions(WebAuthnCredential, now)
    assert "retired_at <" in str(cond)
    deleted = []

    class _Pass:
        def delete_in_batches(self, model, conditions, order):
            deleted.append((model, len(conditions), str(order)))
            return "done"
    p = _Pass()
    p.now = now
    assert working_records.prune_retired_passkeys(p) == "done"
    assert deleted[0][0] is WebAuthnCredential and "retired_at" in deleted[0][2]
