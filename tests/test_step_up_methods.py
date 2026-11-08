"""The active-factors helper and the step-up methods table: one answer to "what second factors does this
account hold", and one table of the ways a step-up can be met, read by every gate. Offline."""
import types
import uuid

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


def _mods():
    set_bare_api_env()
    from app.core import active_factors, step_up_methods
    return active_factors, step_up_methods


def test_the_factors_an_account_holds():
    af, _ = _mods()
    from app.core.models import SecondFactorEnrollment
    uid = uuid.uuid4()
    db = MemoryDB({SecondFactorEnrollment: [
        types.SimpleNamespace(user_id=uid, status="active", method="totp"),
        types.SimpleNamespace(user_id=uuid.uuid4(), status="active", method="totp"),     # someone else's
        types.SimpleNamespace(user_id=uid, status="pending", method="email"),            # not confirmed
    ]})
    f = af.active_factors(db, uid)
    assert f == af.ActiveFactors(code_method="totp", passkeys=0) and f.code and f.any
    none = af.active_factors(db, uuid.uuid4())
    assert none == af.ActiveFactors() and not none.code and not none.any
    # A passkey alone is a factor too (the store arrives with passkeys; the shape is ready for it).
    assert af.ActiveFactors(passkeys=1).any and not af.ActiveFactors(passkeys=1).code


def _req(otp=False, password=False, must_enroll=False):
    return {"otp": otp, "password": password, "must_enroll": must_enroll}


def test_todays_accounts_are_offered_what_they_always_were():
    af, sm = _mods()
    totp = af.ActiveFactors(code_method="totp")
    none = af.ActiveFactors()
    assert sm.offered(_req(otp=True, password=True), totp) == ["totp", "recovery", "password"]
    assert sm.offered(_req(otp=True), totp) == ["totp", "recovery"]
    assert sm.offered(_req(password=True), totp) == ["password"]
    assert sm.offered(_req(), totp) == []
    assert sm.offered(_req(password=True), none) == ["password"]
    # A factor asked of an account with none: nothing to offer for that part (the caller enrolls them first).
    assert sm.offered(_req(otp=True, password=True), none) == ["password"]
    assert sm.offered(_req(otp=True, password=True, must_enroll=True), totp) == []
    # An email enrollment offers the email code in the authenticator's place.
    assert sm.offered(_req(otp=True), af.ActiveFactors(code_method="email")) == ["email", "recovery"]


def test_new_methods_appear_only_when_the_policy_allows_them():
    af, sm = _mods()
    passkeys = af.ActiveFactors(passkeys=2)
    both = af.ActiveFactors(code_method="totp", passkeys=1)
    # A passkey meets the factor part once the passkey policy says so; never the password part.
    assert sm.offered(_req(otp=True, password=True), passkeys) == ["password"]
    assert sm.offered(_req(otp=True, password=True), passkeys, sm.Context(passkey_step_up=True)) == ["passkey", "password"]
    assert sm.offered(_req(otp=True), both, sm.Context(passkey_step_up=True)) == ["totp", "recovery", "passkey"]
    # A fresh sign-in at the provider meets the password part only, beside the password.
    ctx = sm.Context(idp_reauth=True)
    assert sm.offered(_req(password=True), af.ActiveFactors(), ctx) == ["idp_reauth", "password"]
    assert sm.offered(_req(otp=True), af.ActiveFactors(code_method="totp"), ctx) == ["totp", "recovery"]


def test_each_method_meets_exactly_the_part_the_table_says():
    _, sm = _mods()
    for name in ("totp", "email", "recovery", "passkey"):
        assert sm.meets_factor(name) and not sm.meets_password(name), name
    for name in ("password", "idp_reauth"):
        assert sm.meets_password(name) and not sm.meets_factor(name), name
    assert not sm.meets_factor("unknown") and not sm.meets_password("") and sm.meets_factor("TOTP")


def test_every_gate_reads_the_one_helper():
    """The gates that used to ask the enrollment table themselves now ask active_factors, so a passkey counts
    wherever a code counted; a direct read in one of them would silently leave passkey holders unenrolled."""
    from pathlib import Path
    root = Path(__file__).resolve().parent.parent
    api = (root / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    fixed = (root / "app" / "core" / "fixed_step_up.py").read_text(encoding="utf-8")

    def body(src, name, until="\ndef ", start="\ndef "):
        begin = src.index(f"{start}{name}(")
        end = src.index(until, begin + 1)
        return src[begin:end]

    for name in ("_sf_requirement_for", "_sf_step_up_methods", "_second_factor_effective", "_sf_login_methods"):
        text = body(api, name)
        assert "active_factors(" in text, name
        assert "SecondFactorEnrollment" not in text, name
    text = body(fixed, "requirement")
    assert "active_factors(" in text and "SecondFactorEnrollment" not in text
    # The step-up route tells the factor part from the password part by the table, not by name.
    route = api[api.index('@app.post("/auth/second-factor/step-up")'):]
    route = route[:route.index("\n@app.")]
    assert "meets_factor(m)" in route and 'if m != "password"' not in route
