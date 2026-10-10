"""Step-ups an administrator cannot switch off: one helper, with a policy per action.

The admin's step-up matrix decides what most actions ask for, and every action but signing in and managing
your own second factor ships asking for nothing. An action listed in
second_factor_actions.FIXED_STEP_UP_ACTIONS instead has a policy fixed in code
(second_factor_policy.FIXED_POLICIES), and nothing in the matrix weakens it:

    compliance        the password and a TOTP or recovery code; never an email code; refused outright for an
                      account with no active TOTP enrollment;
    password_always   the password every time, plus any second factor the account has enrolled, email codes
                      included; an account without one gives the password alone.

A route guards such an action by calling the function guard() returns, inside its body, before it changes
anything: guard() is not a decorator, so it serves a plain-``def`` route as well as an ``async`` one. The
person earns a receipt at POST /auth/second-factor/step-up, which asks for exactly what the policy
demands, and sends it back in X-Second-Factor. The receipt is bound to the action and to the session that
earned it, and is used once. The refusal is the usual 403 (``second_factor_required``, with the reason and
the methods to offer), so the web app's step-up prompt and retry work unchanged. A temporary credential is
refused outright.

guard() records the action. The boot contract refuses to start while a fixed action is guarded by no
route, or a guarded one is not in FIXED_STEP_UP_ACTIONS.
"""
from fastapi import HTTPException

from app.core import second_factor_actions as acts
from app.core import second_factor_policy as pol

# Every fixed action a route guards, filled by guard() as the route modules are imported.
GUARDED: set = set()


def requirement(db, user, action):
    """(requirement, has_active_enrollment) for ``user`` and the fixed ``action``: what its policy demands of
    the enrollment the account has now. The matrix is never read."""
    from app.core.models import SecondFactorEnrollment
    policy = acts.fixed_policy(action)
    if policy is None:
        raise LookupError(f"{action} is not a fixed step-up")
    enrollment = db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.user_id == user.id, SecondFactorEnrollment.status == "active").first()
    method = enrollment.method if enrollment is not None else None
    return pol.resolve_fixed_requirement(policy, active_method=method), enrollment is not None


def enforce(db, user, request, action) -> None:
    """Raise the step-up 403 unless ``request`` carries a receipt this session earned for ``action`` under
    its fixed policy. Refuses a temporary credential, and an account the policy needs to enroll first."""
    from app.api.api_server import _current_session_hash, _sf_step_up_methods
    from app.core import second_factor as sf
    if getattr(user, "_is_temp_session", False):
        raise HTTPException(status_code=403, detail="A temporary credential cannot do this.")
    req, has_active = requirement(db, user, action)
    if req["must_enroll"]:
        raise HTTPException(status_code=403, detail={
            "second_factor_required": True, "action": action, "reason": "enroll_required", "methods": []})
    if not (req["password"] or req["otp"]):
        return
    receipt = request.headers.get("X-Second-Factor")
    if not (receipt and sf.consume_step_up_receipt(db, user=user, action=action, receipt=receipt,
                                                   session_hash=_current_session_hash(request))):
        raise HTTPException(status_code=403, detail={
            "second_factor_required": True, "action": action, "reason": "step_up_required",
            "methods": _sf_step_up_methods(db, user, req, has_active)})


def guard(action):
    """The check a route calls, as ``check(db, user, request)``, for the fixed ``action``. Call it once, at
    the route module's import, so the boot contract sees the action guarded."""
    if acts.fixed_policy(action) is None:
        raise LookupError(f"{action} is not a fixed step-up")
    GUARDED.add(action)

    def check(db, user, request) -> None:
        enforce(db, user, request, action)

    check.action = action
    return check


def compliance_step_up(action):
    """The check a compliance route calls inside its body, as ``check(db, user, request)``: guard() for an action
    whose policy is the compliance one (the password and a TOTP or recovery code; never an email code; an
    account with no TOTP enrollment is refused). Raises LookupError for any other action, so a compliance route
    cannot be guarded by a weaker policy by mistake. Call it once, at the route module's import."""
    if acts.fixed_policy(action) != pol.POLICY_COMPLIANCE:
        raise LookupError(f"{action} is not a compliance step-up")
    return guard(action)


# What each policy asks for, in the words the step-up matrix shows beside the action (read-only).
REQUIRES = {
    pol.POLICY_COMPLIANCE: "Always: your password and an authenticator or recovery code (never an email code)",
    pol.POLICY_PASSWORD_ALWAYS: "Always: your password, and your second factor when you have one",
    pol.POLICY_FACTOR_WHEN_ENROLLED: "Your second factor, when you have one",
}


def describe() -> list:
    """The fixed step-ups as the matrix lists them, read-only: key, name, policy and what it asks for."""
    return [{"key": key, "name": name, "policy": policy, "requires": REQUIRES.get(policy, ""), "fixed": True}
            for key, (name, policy) in acts.FIXED_STEP_UP_ACTIONS.items()]


def contract_problems() -> list:
    """What breaks the rule that every fixed action is guarded by a route, and only those are."""
    listed = set(acts.FIXED_STEP_UP_ACTIONS)
    problems = []
    for key, (_name, policy) in sorted(acts.FIXED_STEP_UP_ACTIONS.items()):
        if policy not in pol.FIXED_POLICIES:
            problems.append(f"{key} has an unknown policy {policy!r}")
    if listed - GUARDED:
        problems.append(f"fixed step-ups no route guards: {sorted(listed - GUARDED)}")
    if GUARDED - listed:
        problems.append(f"guarded as fixed step-ups but not listed: {sorted(GUARDED - listed)}")
    return problems
