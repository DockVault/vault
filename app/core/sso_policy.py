"""A single sign-on provider's policy (the ``policy`` JSON on its row): who the provider admits, whether it makes
accounts, whether its people keep a password, whether a verified email may link an existing account.

Everything is read through :func:`effective`, which fills the defaults and drops a value of the wrong shape, so a
hand-edited or older row never crashes a sign-in. The restriction (:func:`restriction`) tells *excluded* apart from
*indeterminate*: a claim that is present and leaves the person out is ``restricted``; a claim a rule needs that the
token does not carry, or Entra's overage marker standing in for the groups, is ``restriction_claim_missing``. Both
refuse the sign-in; only the first may ever count as a refusal that ends access (the freshness item's rule).
"""
from __future__ import annotations

from typing import Optional

ACCOUNT_CREATION_VALUES = ("invite_only", "jit")
PASSWORD_LOGIN_VALUES = ("allowed", "disabled")
DEFAULT_ROLE_VALUES = ("user", "external")

DEFAULTS = {
    "sso_account_creation": "invite_only",
    "sso_default_role": "user",
    "sso_password_login": "allowed",
    "sso_link_by_email": False,
    "sso_use_signup_domains": False,      # the account policy's sign-up domain list as a restriction too
    "sso_allowed_tenants": [],            # Entra: the token's tid must be one of these
    "sso_allowed_domains": [],            # Google Workspace: hd, else the verified email's domain
    "sso_required_groups": [],            # at least one of these in the groups claim
}
_ENUMS = {"sso_account_creation": ACCOUNT_CREATION_VALUES, "sso_default_role": DEFAULT_ROLE_VALUES,
          "sso_password_login": PASSWORD_LOGIN_VALUES}
_BOOLS = ("sso_link_by_email", "sso_use_signup_domains")
_LISTS = ("sso_allowed_tenants", "sso_allowed_domains", "sso_required_groups")
MAX_LIST_ITEMS = 200
MAX_ITEM_LENGTH = 255

RESTRICTED = "restricted"
RESTRICTION_CLAIM_MISSING = "restriction_claim_missing"


def _clean_list(value, *, lower: bool = False) -> list:
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:MAX_LIST_ITEMS]:
        if isinstance(item, str):
            item = item.strip()
            if item and len(item) <= MAX_ITEM_LENGTH:
                out.append(item.lower() if lower else item)
    return out


def effective(stored) -> dict:
    """The policy with every default filled and every value of a wrong shape replaced by its default. Domains
    are lowered (a host name has no case); tenants and groups are kept as given."""
    policy = {k: (list(v) if isinstance(v, list) else v) for k, v in DEFAULTS.items()}
    if not isinstance(stored, dict):
        return policy
    for key, values in _ENUMS.items():
        if stored.get(key) in values:
            policy[key] = stored[key]
    for key in _BOOLS:
        if isinstance(stored.get(key), bool):
            policy[key] = stored[key]
    for key in _LISTS:
        policy[key] = _clean_list(stored.get(key), lower=(key == "sso_allowed_domains"))
    return policy


def signup_domain_gate(account_policy: Optional[dict]) -> tuple:
    """``(mode, domains)`` of the account policy's sign-up domain list, as the sign-up forms read it."""
    pol = account_policy if isinstance(account_policy, dict) else {}
    mode = pol.get("signup_email_domain_mode")
    domains = pol.get("signup_email_domains")
    return (mode if mode in ("allowlist", "denylist") else "off",
            [d for d in domains if isinstance(d, str)] if isinstance(domains, list) else [])


def is_restricted(policy: dict, account_policy: Optional[dict] = None) -> bool:
    """A restricted provider admits a named set of people: a tenant list, a domain list, a required group, or the
    sign-up domain allow-list when the administrator ticked it. A deny-list bars some and admits the rest, so it
    does not count; neither does a list that is empty. Account creation at the first sign-in and linking by email
    are only ever meant for a restricted provider."""
    if policy["sso_allowed_tenants"] or policy["sso_allowed_domains"] or policy["sso_required_groups"]:
        return True
    if policy["sso_use_signup_domains"]:
        mode, domains = signup_domain_gate(account_policy)
        return mode == "allowlist" and bool(domains)
    return False


def restriction(policy: dict, *, tenant_id, email, email_verified: bool, hosted_domain, groups,
                groups_overage: bool, account_policy: Optional[dict] = None) -> Optional[str]:
    """Why the restriction keeps this person out (``RESTRICTED`` or ``RESTRICTION_CLAIM_MISSING``), or None when
    it admits them or there is none. Every rule that is set is judged; a claim that excludes the person outright
    wins over one that is missing, since an exclusion is definite and a missing claim is not."""
    missing = False
    tenants = policy["sso_allowed_tenants"]
    if tenants:
        if not isinstance(tenant_id, str) or not tenant_id.strip():
            missing = True
        elif tenant_id.strip().lower() not in {t.lower() for t in tenants}:
            return RESTRICTED
    domains = policy["sso_allowed_domains"]
    if domains:
        domain = _domain_of(hosted_domain, email, email_verified)
        if domain is None:
            missing = True
        elif domain not in set(domains):
            return RESTRICTED
    required = policy["sso_required_groups"]
    if required:
        if groups_overage or not isinstance(groups, list):
            missing = True
        elif not set(required) & {str(g) for g in groups}:
            return RESTRICTED
    if policy["sso_use_signup_domains"]:
        mode, listed = signup_domain_gate(account_policy)
        if mode != "off":
            from app.core.account_policy import email_allowed_by_domain_gate
            if not (email_verified and isinstance(email, str) and "@" in email):
                missing = True
            elif not email_allowed_by_domain_gate(email, mode, listed):
                return RESTRICTED
    return RESTRICTION_CLAIM_MISSING if missing else None


def _domain_of(hosted_domain, email, email_verified) -> Optional[str]:
    """The domain a domain rule judges: the hosted-domain claim when the provider sends one, else the verified
    email's; a consumer account has neither, or an address whose domain the list does not name."""
    if isinstance(hosted_domain, str) and hosted_domain.strip():
        return hosted_domain.strip().lower()
    if email_verified and isinstance(email, str) and "@" in email:
        return email.rsplit("@", 1)[1].strip().lower() or None
    return None
