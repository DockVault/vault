"""Shared second-factor test helpers.

Note the TOTP replay rule: a 30-second code can be spent only once, so a test that needs MORE than one
step-up in the same window must use recovery codes (single-use, ten available) -- `step_up_receipt` does.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor as sf   # noqa: E402


def totp(secret, step_offset=0):
    return sf._totp_at_step(secret, sf.current_totp_step() + step_offset)


def enroll_totp(user, client):
    """Enroll `client` (logged in as `user`) in TOTP. Returns (secret, recovery_codes[list])."""
    secret = client.post("/users/me/second-factor/totp/enroll",
                         json={"current_password": user["_password"]}).json()["secret"]
    codes = client.post("/users/me/second-factor/totp/confirm",
                        json={"code": totp(secret)}).json()["recovery_codes"]
    client.post("/users/me/second-factor/recovery/acknowledge").raise_for_status()
    return secret, codes


def enrolled_admin(admin):
    """A throwaway role=admin account, logged in and TOTP-enrolled. Returns (user, client, secret, codes).
    Creating it is deliberately NOT gated (admin.* default require_otp off, model B)."""
    ta = admin.create_user(role="admin")
    c = admin.clone_anonymous()
    c.login(ta["_username"], ta["_password"])
    secret, codes = enroll_totp(ta, c)
    return ta, c, secret, codes


def step_up_receipt(client, *, action, recovery_codes):
    """Mint a step-up receipt using a FRESH recovery code (single-use), so repeated step-ups in one test
    don't collide on the one-TOTP-per-30s-window rule."""
    code = recovery_codes.pop(0)
    r = client.post("/auth/second-factor/step-up",
                    json={"action": action, "method": "recovery", "code": code})
    r.raise_for_status()
    return r.json()["receipt"]


def set_action_require_otp(admin, action, value):
    """Turn an action's require_otp on/off for test setup, satisfying the account.second_factor gate on the
    matrix via a throwaway enrolled admin. Self-cleaning (the throwaway admin is deleted)."""
    ta, c, _secret, codes = enrolled_admin(admin)
    try:
        r = c.put(f"/second-factor/actions/{action}", json={"require_otp": value},
                  headers={"X-Second-Factor": step_up_receipt(c, action="account.second_factor",
                                                              recovery_codes=codes)})
        r.raise_for_status()
    finally:
        admin.delete_user(ta["id"])
