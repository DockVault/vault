"""A single sign-on provider's policy (the ``policy`` JSON on its row): who the provider admits, whether it makes
accounts, whether its people keep a password, whether a verified email may link an existing account.

Everything is read through :func:`effective`, which fills the defaults and drops a value of the wrong shape, so a
hand-edited or older row never crashes a sign-in. The restriction (:func:`restriction`) tells *excluded* apart from
*indeterminate*: a claim that is present and leaves the person out is ``restricted``; a claim a rule needs that the
token does not carry, or Entra's overage marker standing in for the groups, is ``restriction_claim_missing``. Both
refuse the sign-in; only the first may ever count as a refusal that ends access (the freshness item's rule).
"""
from __future__ import annotations

import re
from typing import Optional

ACCOUNT_CREATION_VALUES = ("invite_only", "jit")
PASSWORD_LOGIN_VALUES = ("allowed", "disabled")
DEFAULT_ROLE_VALUES = ("user", "external")

DEFAULTS = {
    "sso_account_creation": "invite_only",
    "sso_default_role": "user",
    "sso_password_login": "allowed",
    "sso_link_by_email": False,
    "sso_admin_mapping": False,           # a group may raise an administrator request (never the role itself)
    "sso_use_signup_domains": False,      # the account policy's sign-up domain list as a restriction too
    "sso_backchannel_logout": True,       # a provider's back-channel logout token ends the sessions it names
    "sso_idp_logout": False,              # a vault sign-out also sends the browser to the provider's logout
    "sso_trust_idp_mfa": False,           # a token with an accepted amr or acr value counts as the second factor
    "sso_accepted_amr": [],
    "sso_accepted_acr": [],
    "sso_requested_acr": "",              # sent as acr_values when set
    "sso_allowed_tenants": [],            # Entra: the token's tid must be one of these
    "sso_allowed_domains": [],            # Google Workspace: hd, else the verified email's domain
    "sso_required_groups": [],            # at least one of these in the groups claim
    "sso_freshness_days": 30,             # an account linked here keeps its SSH keys and temporary credentials only
                                          # while its last sign-in here is younger than this; 0 = off
    "sso_refusal_ends_access": True,      # a verified token that excludes a known identity ends the account's access
}
_ENUMS = {"sso_account_creation": ACCOUNT_CREATION_VALUES, "sso_default_role": DEFAULT_ROLE_VALUES,
          "sso_password_login": PASSWORD_LOGIN_VALUES}
_BOOLS = ("sso_link_by_email", "sso_admin_mapping", "sso_use_signup_domains", "sso_trust_idp_mfa",
          "sso_backchannel_logout", "sso_idp_logout", "sso_refusal_ends_access")
FRESHNESS_DAYS_MAX = 365
_INTS = {"sso_freshness_days": (0, FRESHNESS_DAYS_MAX)}
_LISTS = ("sso_allowed_tenants", "sso_allowed_domains", "sso_required_groups", "sso_accepted_amr", "sso_accepted_acr")
_STRS = ("sso_requested_acr",)
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
    for key, (low, high) in _INTS.items():
        value = stored.get(key)
        if isinstance(value, int) and not isinstance(value, bool) and low <= value <= high:
            policy[key] = value
    for key in _LISTS:
        policy[key] = _clean_list(stored.get(key), lower=(key == "sso_allowed_domains"))
    for key in _STRS:
        value = stored.get(key)
        policy[key] = value.strip()[:MAX_ITEM_LENGTH] if isinstance(value, str) else ""
    return policy


# ``amr`` values that name one knowledge factor (RFC 8176): a password, a PIN, a question. A sign-in that shows
# only one of them proved one factor; none is a second one, whatever a list says.
SINGLE_FACTOR_AMR = frozenset({"pwd", "pin", "kba"})


def mfa_trusted(policy: dict, amr, acr) -> bool:
    """Whether the token's ``amr`` values or ``acr`` value count as the second factor under this policy: trust on, and
    an accepted value present. Nothing is trusted by default, and a value that names a single knowledge factor
    (``pwd``, ``pin``, ``kba``) never counts, also when a stored list holds it."""
    if not policy["sso_trust_idp_mfa"]:
        return False
    values = {str(v) for v in amr} if isinstance(amr, (list, tuple, set)) else set()
    accepted = {a for a in policy["sso_accepted_amr"] if str(a).strip().lower() not in SINGLE_FACTOR_AMR}
    if values & accepted:
        return True
    return isinstance(acr, str) and acr in set(policy["sso_accepted_acr"])


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
                groups_overage: bool, account_policy: Optional[dict] = None,
                hosted_domain_only: bool = False) -> Optional[str]:
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
        domain = _domain_of(hosted_domain, email, email_verified, claim_only=hosted_domain_only)
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
            if hosted_domain_only:
                # Where the provider has a hosted-domain claim, the list is asked about that claim, as the
                # provider's own list is: a consumer account's verified address proves nothing, whichever list
                # the address is on.
                domain = _domain_of(hosted_domain, email, email_verified, claim_only=True)
                if domain is None:
                    missing = True
                elif not email_allowed_by_domain_gate("someone@" + domain, mode, listed):
                    return RESTRICTED
            elif not (email_verified and isinstance(email, str) and email.count("@") == 1):
                missing = True
            elif not email_allowed_by_domain_gate(email, mode, listed):
                return RESTRICTED
    return RESTRICTION_CLAIM_MISSING if missing else None


def address_admitted(policy: dict, email: str) -> bool:
    """Whether an address may be stored on, or link, an account under this provider: when a domain list is set, the
    address's own domain must be on it (the hosted-domain claim admits the sign-in, not another domain's address)."""
    domains = policy["sso_allowed_domains"]
    if not domains or not isinstance(email, str) or email.count("@") != 1:
        return not domains
    return email.rsplit("@", 1)[1].strip().lower() in set(domains)


def _domain_of(hosted_domain, email, email_verified, *, claim_only: bool = False) -> Optional[str]:
    """The domain a domain rule judges: the hosted-domain claim when the provider sends one, else the verified
    email's. ``claim_only`` is for a provider that has such a claim (Google's ``hd``): there the claim alone says
    that an account belongs to the organisation. A consumer account at the same provider carries no claim and may
    carry any verified address, a former employee's work address among them, so its address proves nothing and a
    token without the claim is missing what the rule needs."""
    if isinstance(hosted_domain, str) and hosted_domain.strip():
        return hosted_domain.strip().lower()
    if claim_only:
        return None
    if email_verified and isinstance(email, str) and email.count("@") == 1:
        return email.rsplit("@", 1)[1].strip().lower() or None
    return None


# --------------------------------------------------------------------------- an administrator's save

class PolicyInvalid(ValueError):
    """A policy value an administrator's save may not hold; ``key`` names the setting."""

    def __init__(self, key: str, message: str):
        super().__init__(message)
        self.key = key


_DOMAIN = re.compile(r"^[a-z0-9]([a-z0-9-]*[a-z0-9])?(\.[a-z0-9]([a-z0-9-]*[a-z0-9])?)+$")


def _plain(text: str) -> bool:
    """No control character, and nothing a browser or a log would not show as itself."""
    return all(ch.isprintable() for ch in text)


def _saved_list(key: str, value) -> list:
    if not isinstance(value, list):
        raise PolicyInvalid(key, "A list is expected.")
    if len(value) > MAX_LIST_ITEMS:
        raise PolicyInvalid(key, f"At most {MAX_LIST_ITEMS} entries.")
    out, seen = [], set()
    for item in value:
        if not isinstance(item, str):
            raise PolicyInvalid(key, "Every entry is a text.")
        item = item.strip()
        if not item:
            continue
        if len(item) > MAX_ITEM_LENGTH or not _plain(item):
            raise PolicyInvalid(key, f"An entry is at most {MAX_ITEM_LENGTH} characters, without control characters.")
        if key == "sso_allowed_domains":
            item = item.lower()
            if not _DOMAIN.match(item):
                raise PolicyInvalid(key, f"“{item}” is not a domain name (write it like example.org).")
        elif key != "sso_required_groups" and any(ch.isspace() for ch in item):
            raise PolicyInvalid(key, "An entry holds no spaces.")
        if key == "sso_accepted_amr" and item.lower() in SINGLE_FACTOR_AMR:
            raise PolicyInvalid(key, (
                f"“{item}” says that a password, a PIN or a question was used: one factor, not a second one. With "
                "it on the list, every sign-in with a password alone would count as the second factor. List a value "
                "that names a second kind, such as mfa."))
        mark = item.lower() if key in ("sso_allowed_domains", "sso_allowed_tenants") else item
        if mark not in seen:
            seen.add(mark)
            out.append(item)
    return out


def validate(changes) -> dict:
    """An administrator's policy changes, checked strictly: where :func:`effective` forgives a stored value of the
    wrong shape, a save is refused. Only known settings, each of its own type and within its bounds; lists trimmed,
    without empty or repeated entries, domains lowered. Returns the values to store; raises :class:`PolicyInvalid`."""
    if not isinstance(changes, dict):
        raise PolicyInvalid("policy", "The policy is a set of named settings.")
    out = {}
    for key, value in changes.items():
        if key not in DEFAULTS:
            raise PolicyInvalid(str(key)[:80], "Unknown setting.")
        if key in _ENUMS:
            if value not in _ENUMS[key]:
                raise PolicyInvalid(key, "One of: " + ", ".join(_ENUMS[key]) + ".")
            out[key] = value
        elif key in _BOOLS:
            if not isinstance(value, bool):
                raise PolicyInvalid(key, "On or off.")
            out[key] = value
        elif key in _INTS:
            low, high = _INTS[key]
            if not isinstance(value, int) or isinstance(value, bool) or not low <= value <= high:
                raise PolicyInvalid(key, f"A whole number from {low} to {high}.")
            out[key] = value
        elif key in _LISTS:
            out[key] = _saved_list(key, value)
        else:
            if not isinstance(value, str) or len(value.strip()) > MAX_ITEM_LENGTH or not _plain(value.strip()):
                raise PolicyInvalid(key, f"A text of at most {MAX_ITEM_LENGTH} characters.")
            out[key] = value.strip()
    return out
