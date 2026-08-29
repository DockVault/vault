"""Organizational account-onboarding policy.

One coherent, validated block of settings that governs how accounts get into a deployment:
the email requirement (applied uniformly to admin-create, invitation acceptance, and self-signup),
the two master switches for invitations and self-signup, the invitation lifetime, the domain gate
for signup/invite acceptance, and which identifier people log in with.

These helpers are PURE so the validation is unit-testable offline; the API layer supplies the
DB-derived facts a pure function cannot know (e.g. whether switching to email-only login would lock
out an admin who has no email address). Every default preserves today's behaviour exactly:
email required, invitations and signup off, username login.
"""
from __future__ import annotations

import re

EMAIL_REQUIREMENT_VALUES = ("required", "optional")
LOGIN_IDENTIFIER_VALUES = ("username", "email", "either")
DOMAIN_MODE_VALUES = ("off", "allowlist", "denylist")

MIN_INVITE_TTL_HOURS = 1
MAX_INVITE_TTL_HOURS = 720          # 30 days
MIN_OTP_TTL_MINUTES = 1
MAX_OTP_TTL_MINUTES = 60            # a verification code is meant to be short-lived
MAX_SIGNUP_DOMAINS = 100
MAX_DOMAIN_LENGTH = 253             # RFC 1035 total length ceiling
# Hard ceiling on the RAW list length, checked before the per-entry loop so a pathologically large
# input can't be fully walked. Generous vs MAX_SIGNUP_DOMAINS so a list padded with duplicates
# (which dedup below) still passes.
_MAX_RAW_DOMAINS = 10 * MAX_SIGNUP_DOMAINS

# Defaults are conservative EXCEPT admin invite-by-link, which now defaults ON for self-host
# convenience: it is admin-only (only admins mint invitation links) and exposes nothing until a link
# is created, so on-by-default is low risk. Self-signup stays OFF (open registration is a bigger call).
DEFAULTS = {
    "email_requirement": "required",
    "invite_enabled": True,
    "invite_ttl_hours": 24,
    "signup_enabled": False,
    "signup_email_domain_mode": "off",
    "signup_email_domains": [],
    "login_identifier": "username",
    # A self-service email change proves ownership of the NEW address with a one-time code emailed
    # to it. That needs SMTP, so this can only be turned on once email sending is configured (the
    # PUT /settings handler supplies that fact). Off by default. Admin-set emails are exempt.
    "email_change_requires_verification": False,
    # How long the email-change verification code stays valid, in minutes (bounded 1..60). Short by
    # default so a code read from an inbox can't be replayed hours later.
    "email_change_otp_ttl_minutes": 5,
    # Public self-service "forgot password" flow. OFF by default — an admin can always send a reset
    # link (a separate, permission-gated action); this switch only opens the unauthenticated endpoint.
    "password_reset_enabled": False,
    # How long a password-reset link stays valid, in minutes (bounded 1..60). Short by default.
    "password_reset_ttl_minutes": 5,
}
ACCOUNT_POLICY_KEYS = tuple(DEFAULTS.keys())

# One DNS label: 1..63 chars, alphanumeric, internal hyphens allowed, no leading/trailing hyphen.
_LABEL = r"(?!-)[a-z0-9-]{1,63}(?<!-)"
_DOMAIN_RE = re.compile(rf"^{_LABEL}(?:\.{_LABEL})+$")


class AccountPolicyError(ValueError):
    """A policy value failed validation. The message is safe to show the admin (no internals)."""


def effective_account_policy(stored: dict | None) -> dict:
    """The seven keys with defaults filled in for anything unset.

    GET /settings must report EFFECTIVE values so a whole-object save cannot silently persist an
    unchecked default (the same reason zero_knowledge_enabled / directory_search_scope are overlaid).
    The domain list is normalized on read too, so a legacy or hand-edited raw value renders clean.

    A non-dict stored value (a corrupted or hand-edited row holding a list/scalar) is treated as
    absent and falls back to defaults, rather than raising: this reader is on the pre-auth login path
    (which identifier the login form resolves) and the unauthenticated login-policy read, so it must
    fail safe to the defaults, never 500 login. Every other settings reader coerces the same way.
    """
    stored = stored if isinstance(stored, dict) else {}
    out = {}
    for key, default in DEFAULTS.items():
        out[key] = stored[key] if key in stored else default
    # Read path: LENIENT. A legacy or hand-edited stored row may hold invalid entries; drop them and
    # render clean rather than 500 the whole settings page. The write path stays strict.
    out["signup_email_domains"] = normalize_domains_lenient(out.get("signup_email_domains"))
    return out


def email_allowed_by_domain_gate(email, mode, domains) -> bool:
    """Is this email's domain permitted by the signup-domain policy?

    The two modes are DELIBERATELY asymmetric, both failing toward more restriction:

    * ``allowlist`` — the domain must EXACTLY equal a listed domain. A subdomain of a listed domain is
      NOT allowed (``sub.acme.com`` is not covered by ``acme.com``).
    * ``denylist`` — the domain is blocked if it equals a listed domain OR is a subdomain of one
      (``x.evil.com`` is blocked by ``evil.com``).

    ``off`` allows everything. A blank/`@`-less candidate has no domain: allowlist denies it (nothing
    to match), denylist allows it (nothing blocks it) — consistent with each mode's default lean. The
    ``domains`` list is assumed already normalized (lowercased, ``@``-stripped) by the settings write
    path; the candidate's domain is lowercased here to match.
    """
    domain = (email or "").rsplit("@", 1)[-1].strip().lower() if "@" in (email or "") else ""
    listed = {d.strip().lower() for d in (domains or [])}
    if mode == "allowlist":
        return domain in listed
    if mode == "denylist":
        return not any(domain == d or domain.endswith("." + d) for d in listed)
    return True  # "off" or any unknown mode: no domain restriction


def signup_email_is_ascii(email) -> bool:
    """Is this candidate signup email pure ASCII (local part AND domain)?

    Self-signup requires it, deliberately. The domain-gate config (normalize_domains) accepts
    ASCII/punycode labels only, but pydantic EmailStr hands the gate the UNICODE form of an IDN
    domain -- so a unicode 'evіl.com' (Cyrillic i) would neither match an ASCII allowlist entry
    (wrongly denied) nor be caught by an ASCII denylist entry (wrongly allowed). Rejecting any
    non-ASCII address at the signup edge closes BOTH mismatches, plus the SMTPUTF8 non-ASCII-local
    case (which has no ASCII form at all). A blank/None candidate is 'acceptable' here -- its absence
    is handled by the email-requirement check, not by this ASCII gate.
    """
    if not email:
        return True
    try:
        str(email).encode("ascii")
        return True
    except (UnicodeEncodeError, UnicodeDecodeError):
        return False


def normalize_domains(value) -> list[str]:
    """Validate and normalize a signup-domain list; raise AccountPolicyError on any bad entry.

    Each entry is trimmed, has a single leading '@' stripped, is lowercased, and must be a
    syntactically valid multi-label domain (no scheme, path, spaces, or wildcard). The result is
    deduplicated preserving first-seen order and bounded in count; each entry is bounded in length.
    """
    if not isinstance(value, list):
        raise AccountPolicyError("signup_email_domains must be a list of domain strings")
    if len(value) > _MAX_RAW_DOMAINS:
        raise AccountPolicyError(f"at most {MAX_SIGNUP_DOMAINS} signup domains are allowed")
    seen: set[str] = set()
    out: list[str] = []
    for raw in value:
        if not isinstance(raw, str):
            raise AccountPolicyError("each signup domain must be a string")
        d = raw.strip()
        if d.startswith("@"):
            d = d[1:]
        d = d.strip().lower()
        if not d:
            raise AccountPolicyError("a signup domain is empty")
        if len(d) > MAX_DOMAIN_LENGTH:
            raise AccountPolicyError(f"a signup domain exceeds {MAX_DOMAIN_LENGTH} characters")
        if not _DOMAIN_RE.match(d):
            raise AccountPolicyError(f"'{raw}' is not a valid domain")
        if d in seen:
            continue
        seen.add(d)
        out.append(d)
    if len(out) > MAX_SIGNUP_DOMAINS:
        raise AccountPolicyError(f"at most {MAX_SIGNUP_DOMAINS} signup domains are allowed")
    return out


def normalize_domains_lenient(value) -> list[str]:
    """Read-path normalization: keep the valid domains and DROP anything malformed, never raising.

    A legacy or hand-edited stored row (a non-list, a bad domain, a non-string entry) must render
    clean rather than 500 the settings page on load; the write path (normalize_domains /
    validate_account_policy) stays strict and rejects the same input. Bounded and deduped.
    """
    if not isinstance(value, list):
        return []
    seen: set[str] = set()
    out: list[str] = []
    for raw in value[:_MAX_RAW_DOMAINS]:
        if not isinstance(raw, str):
            continue
        d = raw.strip()
        if d.startswith("@"):
            d = d[1:]
        d = d.strip().lower()
        if not d or len(d) > MAX_DOMAIN_LENGTH or not _DOMAIN_RE.match(d):
            continue
        if d not in seen:
            seen.add(d)
            out.append(d)
    return out[:MAX_SIGNUP_DOMAINS]


def validate_account_policy(payload: dict, *, email_login_locks_out_all_admins: bool = False,
                            smtp_configured: bool = False,
                            username_email_collision: tuple | None = None) -> dict:
    """Validate only the account-policy keys PRESENT in `payload`; pass everything else through.

    Returns a dict of the NORMALIZED values for the keys it handled (e.g. deduped/lowercased
    domains), so the caller can persist the canonical form. Raises AccountPolicyError with an
    admin-safe message on the first invalid value.

    Two DB-derived facts the pure validator cannot know are supplied by the caller:
    - `email_login_locks_out_all_admins`: refuse login_identifier='email' ONLY when it would strand
      EVERY admin (no active admin has an email) — a total lockout with no way back in. If at least
      one admin can still sign in by email the save is allowed; the caller warns (out of band) about
      the individual admins/users who lack an email.
    - `smtp_configured`: refuse turning ON email-change verification unless the deployment can send
      the one-time code (email-change verification is gated behind email-client setup).
    - `username_email_collision`: a sample (username, email) pair where one account's username equals
      another's email. Refuse switching to 'either' login when one exists, or that username would
      shadow the real email owner (username is tried first). Pure 'email' mode is unaffected.
    """
    if not isinstance(payload, dict):
        raise AccountPolicyError("Settings payload must be an object")
    normalized: dict = {}

    if "email_requirement" in payload:
        v = payload["email_requirement"]
        if v not in EMAIL_REQUIREMENT_VALUES:
            raise AccountPolicyError("email_requirement must be 'required' or 'optional'")
        normalized["email_requirement"] = v

    for bool_key in ("invite_enabled", "signup_enabled", "password_reset_enabled"):
        if bool_key in payload and not isinstance(payload[bool_key], bool):
            raise AccountPolicyError(f"{bool_key} must be true or false")

    if "invite_ttl_hours" in payload:
        v = payload["invite_ttl_hours"]
        # bool is an int subclass; reject it explicitly so True can't pass as 1.
        if isinstance(v, bool) or not isinstance(v, int) or not (MIN_INVITE_TTL_HOURS <= v <= MAX_INVITE_TTL_HOURS):
            raise AccountPolicyError(
                f"invite_ttl_hours must be an integer from {MIN_INVITE_TTL_HOURS} to {MAX_INVITE_TTL_HOURS}")

    if "email_change_otp_ttl_minutes" in payload:
        v = payload["email_change_otp_ttl_minutes"]
        if isinstance(v, bool) or not isinstance(v, int) or not (MIN_OTP_TTL_MINUTES <= v <= MAX_OTP_TTL_MINUTES):
            raise AccountPolicyError(
                f"email_change_otp_ttl_minutes must be an integer from {MIN_OTP_TTL_MINUTES} to {MAX_OTP_TTL_MINUTES}")

    if "password_reset_ttl_minutes" in payload:
        v = payload["password_reset_ttl_minutes"]
        if isinstance(v, bool) or not isinstance(v, int) or not (MIN_OTP_TTL_MINUTES <= v <= MAX_OTP_TTL_MINUTES):
            raise AccountPolicyError(
                f"password_reset_ttl_minutes must be an integer from {MIN_OTP_TTL_MINUTES} to {MAX_OTP_TTL_MINUTES}")

    if "signup_email_domain_mode" in payload:
        v = payload["signup_email_domain_mode"]
        if v not in DOMAIN_MODE_VALUES:
            raise AccountPolicyError("signup_email_domain_mode must be 'off', 'allowlist', or 'denylist'")

    if "signup_email_domains" in payload:
        normalized["signup_email_domains"] = normalize_domains(payload["signup_email_domains"])

    if "login_identifier" in payload:
        v = payload["login_identifier"]
        if v not in LOGIN_IDENTIFIER_VALUES:
            raise AccountPolicyError("login_identifier must be 'username', 'email', or 'either'")
        if v == "email" and email_login_locks_out_all_admins:
            raise AccountPolicyError(
                "Refusing to set email-only login: no administrator has an email address, so every "
                "admin would be locked out with no way back in. Give at least one admin an email "
                "first, or use 'either'.")
        # 'either' tries the username first, so a username equal to another account's email would
        # shadow that email owner's login and lock them out. Refuse the switch until the collision is
        # resolved. (Only 'either' is affected — 'email' never consults the username.)
        if v == "either" and username_email_collision:
            uname, email = username_email_collision
            raise AccountPolicyError(
                f"Refusing to enable 'either' login: the username {uname!r} matches another account's "
                f"email {email!r} and would shadow that owner's email login. Rename the username first.")

    if "email_change_requires_verification" in payload:
        v = payload["email_change_requires_verification"]
        if not isinstance(v, bool):
            raise AccountPolicyError("email_change_requires_verification must be true or false")
        if v and not smtp_configured:
            raise AccountPolicyError(
                "Cannot require email-change verification until SMTP is configured: the deployment "
                "must be able to send the one-time code. Set up Settings -> Email first.")

    return normalized
