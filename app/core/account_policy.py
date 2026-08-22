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
MAX_SIGNUP_DOMAINS = 100
MAX_DOMAIN_LENGTH = 253             # RFC 1035 total length ceiling
# Hard ceiling on the RAW list length, checked before the per-entry loop so a pathologically large
# input can't be fully walked. Generous vs MAX_SIGNUP_DOMAINS so a list padded with duplicates
# (which dedup below) still passes.
_MAX_RAW_DOMAINS = 10 * MAX_SIGNUP_DOMAINS

# Defaults chosen so an install that never opens this tab behaves exactly as it did before it existed.
DEFAULTS = {
    "email_requirement": "required",
    "invite_enabled": False,
    "invite_ttl_hours": 24,
    "signup_enabled": False,
    "signup_email_domain_mode": "off",
    "signup_email_domains": [],
    "login_identifier": "username",
    # A self-service email change proves ownership of the NEW address with a one-time code emailed
    # to it. That needs SMTP, so this can only be turned on once email sending is configured (the
    # PUT /settings handler supplies that fact). Off by default. Admin-set emails are exempt.
    "email_change_requires_verification": False,
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


def validate_account_policy(payload: dict, *, email_login_locks_out_admin: bool = False,
                            smtp_configured: bool = False,
                            username_email_collision: tuple | None = None) -> dict:
    """Validate only the account-policy keys PRESENT in `payload`; pass everything else through.

    Returns a dict of the NORMALIZED values for the keys it handled (e.g. deduped/lowercased
    domains), so the caller can persist the canonical form. Raises AccountPolicyError with an
    admin-safe message on the first invalid value.

    Two DB-derived facts the pure validator cannot know are supplied by the caller:
    - `email_login_locks_out_admin`: refuse login_identifier='email' when an active admin has no
      email, or they could never log in again.
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

    for bool_key in ("invite_enabled", "signup_enabled"):
        if bool_key in payload and not isinstance(payload[bool_key], bool):
            raise AccountPolicyError(f"{bool_key} must be true or false")

    if "invite_ttl_hours" in payload:
        v = payload["invite_ttl_hours"]
        # bool is an int subclass; reject it explicitly so True can't pass as 1.
        if isinstance(v, bool) or not isinstance(v, int) or not (MIN_INVITE_TTL_HOURS <= v <= MAX_INVITE_TTL_HOURS):
            raise AccountPolicyError(
                f"invite_ttl_hours must be an integer from {MIN_INVITE_TTL_HOURS} to {MAX_INVITE_TTL_HOURS}")

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
        if v == "email" and email_login_locks_out_admin:
            raise AccountPolicyError(
                "Refusing to set email-only login: an active administrator has no email address and "
                "would be locked out. Give every admin an email first, or use 'either'.")
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
