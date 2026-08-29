"""Pure second-factor policy resolution: the admin policy (settings blob) + the per-user effective state
+ what a given action requires of a given user. DB-derived facts (has_active_enrollment, the user's
group ids, save-time admin-email/SMTP facts) are passed in, like account_policy / sharing_policy.

Owner's model (a deliberate divergence from the design spec's single `require_otp`): each action carries
TWO independent admin toggles, `require_otp` and `require_password`. `require_password` on = re-enter the
account password (a re-auth, applies to everyone, independent of MFA). `require_otp` on = present the OTP
second factor; if the user has no enrollment they are BLOCKED with "enroll to continue" (progressive
enrollment) rather than the spec's silent no-op. `admin.*` management actions are NEVER a no-op: an
enrolled admin satisfies them with OTP, an un-enrolled admin re-authenticates with the account password.
"""
from typing import Optional

_MODES = ("optional", "required")
_METHODS = ("totp", "email")
_SFTP = ("allow", "temp_credential_only")

DEFAULTS = {
    "mfa_mode": "optional",
    "mfa_required_group_ids": [],
    "mfa_required_user_ids": [],
    "mfa_allowed_methods": ["totp"],
    "mfa_email_code_ttl_minutes": 5,
    "mfa_sftp_policy": "allow",
}


class SecondFactorPolicyError(ValueError):
    """A settings save that would be an invalid or lockout-inducing MFA policy."""


def effective_policy(blob: Optional[dict]) -> dict:
    """The MFA policy with defaults filled in, leniently (a corrupt/hand-edited value degrades to its
    default rather than raising — validation happens at save time, not on every read)."""
    blob = blob or {}
    out = dict(DEFAULTS)
    if blob.get("mfa_mode") in _MODES:
        out["mfa_mode"] = blob["mfa_mode"]
    if isinstance(blob.get("mfa_required_group_ids"), list):
        out["mfa_required_group_ids"] = [str(x) for x in blob["mfa_required_group_ids"]]
    if isinstance(blob.get("mfa_required_user_ids"), list):
        out["mfa_required_user_ids"] = [str(x) for x in blob["mfa_required_user_ids"]]
    methods = blob.get("mfa_allowed_methods")
    if isinstance(methods, list):
        cleaned = [m for m in methods if m in _METHODS]
        if cleaned:
            out["mfa_allowed_methods"] = cleaned
    ttl = blob.get("mfa_email_code_ttl_minutes")
    if isinstance(ttl, int) and 1 <= ttl <= 60:
        out["mfa_email_code_ttl_minutes"] = ttl
    if blob.get("mfa_sftp_policy") in _SFTP:
        out["mfa_sftp_policy"] = blob["mfa_sftp_policy"]
    return out


def effective_second_factor(*, mode, required_group_ids, required_user_ids,
                            user_group_ids, user_id, has_active_enrollment) -> dict:
    """The user's effective second-factor state — computed, never stored. `required` if the mode is
    `required` OR the user is in a required department OR the user is on the per-user required list;
    `state` is setup / pending / not_setup; `in_effect` gates whether login demands a factor and the
    matrix rows bite for this user."""
    required, source = (mode == "required"), None
    if required:
        source = "global"
    if not required and user_id is not None and str(user_id) in {str(x) for x in (required_user_ids or [])}:
        required, source = True, "user"
    if not required and (set(str(g) for g in (user_group_ids or []))
                         & set(str(g) for g in (required_group_ids or []))):
        required, source = True, "department"
    state = "setup" if has_active_enrollment else ("pending" if required else "not_setup")
    return {"required": required, "source": source, "state": state,
            "in_effect": bool(required or has_active_enrollment)}


def resolve_action_requirement(*, require_otp, require_password, has_active_enrollment,
                               is_admin_action) -> dict:
    """What a step-up action demands of a specific user. Returns {password, otp, must_enroll}.

    - `require_password` on -> always re-enter the password (a re-auth, MFA-independent).
    - `require_otp` on -> present OTP if enrolled; if NOT enrolled, `must_enroll` (owner's block/enroll
      model — the action walks the user through enrollment rather than being a silent no-op).
    - `admin.*` action -> never a no-op: enrolled admin uses OTP, un-enrolled admin re-auths with password.
    `login` is NOT resolved here — its factor is presented in the login flow, and forced enrollment for
    login is governed by the effective `pending` state, not by an action requirement."""
    need_password = bool(require_password)
    need_otp = False
    must_enroll = False
    if require_otp:
        if has_active_enrollment:
            need_otp = True
        else:
            must_enroll = True
    if is_admin_action:
        if has_active_enrollment:
            need_otp = True
        else:
            need_password = True
            must_enroll = False   # an un-enrolled admin re-auths with the password, not by enrolling
    return {"password": need_password, "otp": need_otp, "must_enroll": must_enroll}


def validate_policy(blob: dict, *, active_admins_without_email: int, smtp_configured: bool) -> dict:
    """Shape/bounds + lockout guards for a proposed MFA policy. DB-derived facts are passed in (the
    number of active admins with no email, whether SMTP is configured). Returns the normalized policy or
    raises SecondFactorPolicyError. Group-id list membership is validated by the caller (the DB-bound
    _validate_group_id_list), matching the account-policy pattern."""
    if not isinstance(blob, dict):
        raise SecondFactorPolicyError("MFA policy must be an object.")
    out = effective_policy(blob)   # fills defaults + drops obviously-bad values leniently first
    # Then reject the values that must be an outright error rather than silently defaulted.
    if "mfa_mode" in blob and blob["mfa_mode"] not in _MODES:
        raise SecondFactorPolicyError("mfa_mode must be 'optional' or 'required'.")
    if "mfa_allowed_methods" in blob:
        methods = blob["mfa_allowed_methods"]
        if not isinstance(methods, list) or not methods or any(m not in _METHODS for m in methods):
            raise SecondFactorPolicyError("mfa_allowed_methods must be a non-empty subset of ['totp','email'].")
    if "mfa_email_code_ttl_minutes" in blob:
        ttl = blob["mfa_email_code_ttl_minutes"]
        if not isinstance(ttl, int) or not (1 <= ttl <= 60):
            raise SecondFactorPolicyError("mfa_email_code_ttl_minutes must be an integer 1..60.")
    if "mfa_sftp_policy" in blob and blob["mfa_sftp_policy"] not in _SFTP:
        raise SecondFactorPolicyError("mfa_sftp_policy must be 'allow' or 'temp_credential_only'.")
    # Lockout guards: an email-only policy needs SMTP and needs every active admin to have an email,
    # else the admins can never receive their own code (the login_identifier='email' reasoning).
    if out["mfa_allowed_methods"] == ["email"]:
        if not smtp_configured:
            raise SecondFactorPolicyError("An email-only second factor needs SMTP configured first.")
        if active_admins_without_email > 0:
            raise SecondFactorPolicyError(
                "An email-only second factor is refused while an active admin has no email address.")
    return out
