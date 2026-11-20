"""The single sign-on providers an administrator configures (the ``sso_providers`` rows): what a save may hold,
what the pages are shown, and the rules of testing a provider, turning it on or off and removing it.

A provider starts as a draft, so its two addresses exist before the provider's own console is touched. It is
turned on only when the vault has an address the provider can send a browser back to, and a test sign-in passed
with the connection settings as they stand now (a fingerprint of them is kept with the test's summary). The client
secret is written, encrypted, and never read back. Turning a provider off is never refused: an incident may need
it at once. Removing one is refused while it is on, while an account still signs in only through it, and while a
refusal it recorded is in force, so that nothing a rule depends on is deleted along with it.

Nothing here commits and nothing here asks for a step-up: the routes do both (app/api/sso_providers_router.py).
"""
from __future__ import annotations

import hashlib
import json
import re
from typing import Optional

from app.core import sso_policy, sso_presets
from app.services import oidc_client as oc

DRAFT, ENABLED, DISABLED = "draft", "enabled", "disabled"
KIND_OIDC = "oidc"
ICONS = ("generic", "microsoft", "google", "okta", "keycloak", "authentik")
TOKEN_AUTH_VALUES = (oc.TOKEN_AUTH_BASIC, oc.TOKEN_AUTH_POST)
CLAIM_KEYS = ("username", "email", "email_verified", "name", "tenant", "domain", "groups")
MAX_PROVIDERS = 20
NAME_MAX = LABEL_MAX = 60
URL_MAX = CLIENT_ID_MAX = SCOPES_MAX = 255
SECRET_MAX = 2048
SORT_MAX = 999
# The settings of the connection: a change to any of them makes the last test sign-in a test of something else.
CONNECTION_FIELDS = ("issuer", "discovery_url", "private_network", "client_id", "client_secret", "token_auth",
                     "scopes", "claims")
FIELDS = ("name", "label", "icon", "sort_order", "show_on_sign_in", *CONNECTION_FIELDS, "policy")

NOT_TESTED = "not_tested"
NOT_CONFIGURED = "not_configured"
STILL_ON = "still_on"
ONLY_WAY_IN = "only_way_in"
REFUSALS_IN_FORCE = "refusals_in_force"
TOO_MANY = "too_many_providers"
NAME_TAKEN = "name_taken"
NEEDS_RESTRICTION = "needs_restriction"
PRIVILEGED_LINKED = "privileged_linked"

_SCOPE = re.compile(r"^[\x21\x23-\x5B\x5D-\x7E]+$")        # a scope token (RFC 6749): no space, quote or backslash
_CLAIM = re.compile(r"^[A-Za-z0-9_.:/-]{1,120}$")


# What each field is called on the page, so that a refusal reads on its own wherever it is shown.
LABELS = {
    "name": "Name", "preset": "Provider", "label": "Button text", "icon": "Icon", "sort_order": "Order",
    "show_on_sign_in": "Button on the sign-in page", "issuer": "Issuer", "discovery_url": "Discovery address",
    "private_network": "Inside the network", "client_id": "Client ID", "client_secret": "Client secret",
    "token_auth": "How the secret is sent", "scopes": "Scopes", "claims": "Claim names",
    "policy.sso_account_creation": "Accounts", "policy.sso_default_role": "Role of the accounts made",
    "policy.sso_password_login": "Password sign-in", "policy.sso_link_by_email": "Link by email",
    "policy.sso_admin_mapping": "Administrator group", "policy.sso_use_signup_domains": "Sign-up domain list",
    "policy.sso_backchannel_logout": "Back-channel logout", "policy.sso_idp_logout": "Provider logout",
    "policy.sso_trust_idp_mfa": "Second factor at the provider", "policy.sso_accepted_amr": "Accepted methods (amr)",
    "policy.sso_accepted_acr": "Accepted levels (acr)", "policy.sso_requested_acr": "Level to ask for (acr_values)",
    "policy.sso_allowed_tenants": "Tenants", "policy.sso_allowed_domains": "Domains",
    "policy.sso_required_groups": "Required groups", "policy.sso_freshness_days": "Days without signing in",
    "policy.sso_refusal_ends_access": "A refusal ends access",
}


class Invalid(ValueError):
    """A value a save may not hold; ``field`` names it for the form."""

    def __init__(self, field: str, message: str):
        super().__init__(message)
        self.field = field

    @property
    def said(self) -> str:
        """The refusal as a sentence that names its field: ``Issuer: The endpoint must use https.``"""
        label = LABELS.get(self.field)
        return f"{label}: {self}" if label else str(self)


class Conflict(ValueError):
    """A change the state of things does not allow now; ``reason`` is a code for the page."""

    def __init__(self, reason: str, message: str):
        super().__init__(message)
        self.reason = reason


def _plain(text: str) -> bool:
    return all(ch.isprintable() for ch in text)


def _text(field: str, value, *, most: int, least: int = 1) -> str:
    if not isinstance(value, str):
        raise Invalid(field, "A text is expected.")
    value = value.strip()
    if not least <= len(value) <= most or not _plain(value):
        raise Invalid(field, (f"Between {least} and {most} characters" if least else f"At most {most} characters")
                      + ", without control characters.")
    return value


def _address(field: str, value, *, private_network: bool) -> str:
    value = _text(field, value, most=URL_MAX)
    problem = oc.endpoint_problem(value, private_network=private_network)
    if problem:
        raise Invalid(field, problem[0].upper() + problem[1:] + ".")
    if "#" in value or "?" in value:
        raise Invalid(field, "The address has no query and no fragment.")
    return value


def _scopes(value) -> str:
    value = _text("scopes", value, most=SCOPES_MAX)
    tokens = []
    for token in value.split():
        if not _SCOPE.match(token):
            raise Invalid("scopes", f"“{token}” is not a scope.")
        if token not in tokens:
            tokens.append(token)
    if "openid" not in tokens:
        raise Invalid("scopes", "The scope openid is always asked for.")
    return " ".join(tokens)


def _claims(value) -> Optional[dict]:
    if value is None:
        return None
    if not isinstance(value, dict):
        raise Invalid("claims", "The claim names are a set of named texts.")
    out = {}
    for key, name in value.items():
        if key not in CLAIM_KEYS:
            raise Invalid("claims", f"Unknown claim setting: {str(key)[:40]}.")
        if name is None or (isinstance(name, str) and not name.strip()):
            continue                                            # empty: the default name
        if not isinstance(name, str) or not _CLAIM.match(name.strip()):
            raise Invalid("claims", f"The claim name for {key} is letters, digits and . _ : / - only.")
        out[key] = name.strip()
    return out or None


def clean(body: dict, *, row=None) -> dict:
    """The fields of ``body`` an administrator may set, each checked on its own. ``policy`` comes back as the
    changes to make (:func:`sso_policy.validate`); the client secret under ``client_secret``, still in the clear,
    for :func:`apply` to encrypt. Addresses are judged with the private-network choice as it will stand."""
    if not isinstance(body, dict):
        raise Invalid("body", "A set of named fields is expected.")
    unknown = [key for key in body if key not in FIELDS]
    if unknown:
        raise Invalid(str(unknown[0])[:40], "Unknown field.")
    out = {}
    if "name" in body:
        out["name"] = _text("name", body["name"], most=NAME_MAX)
    if "label" in body:
        label = body["label"]
        out["label"] = None if label is None or (isinstance(label, str) and not label.strip()) else _text(
            "label", label, most=LABEL_MAX)
    if "icon" in body:
        if body["icon"] is not None and body["icon"] not in ICONS:
            raise Invalid("icon", "One of: " + ", ".join(ICONS) + ".")
        out["icon"] = body["icon"]
    if "sort_order" in body:
        order = body["sort_order"]
        if not isinstance(order, int) or isinstance(order, bool) or not 0 <= order <= SORT_MAX:
            raise Invalid("sort_order", f"A whole number from 0 to {SORT_MAX}.")
        out["sort_order"] = order
    for flag in ("show_on_sign_in", "private_network"):
        if flag in body:
            if not isinstance(body[flag], bool):
                raise Invalid(flag, "On or off.")
            out[flag] = body[flag]
    private = out.get("private_network", bool(getattr(row, "private_network", False)))
    if "issuer" in body:
        out["issuer"] = _address("issuer", body["issuer"], private_network=private)
    if "discovery_url" in body:
        url = body["discovery_url"]
        out["discovery_url"] = None if url is None or (isinstance(url, str) and not url.strip()) else _address(
            "discovery_url", url, private_network=private)
    if "private_network" in out and not private and row is not None:
        # Turned off: what is already stored must still be allowed without it.
        for field in ("issuer", "discovery_url"):
            stored = getattr(row, field, None) if field not in out else None
            if stored and oc.endpoint_problem(stored, private_network=False):
                raise Invalid("private_network", f"The {field.replace('_', ' ')} is inside the network: it needs "
                                                 "this setting.")
    if "client_id" in body:
        out["client_id"] = _text("client_id", body["client_id"], most=CLIENT_ID_MAX)
    if "client_secret" in body and body["client_secret"] not in (None, ""):
        secret = body["client_secret"]
        if not isinstance(secret, str) or not 1 <= len(secret) <= SECRET_MAX or secret != secret.strip() \
                or not _plain(secret):
            raise Invalid("client_secret", f"At most {SECRET_MAX} characters, without spaces around it.")
        out["client_secret"] = secret
    if "token_auth" in body:
        if body["token_auth"] not in TOKEN_AUTH_VALUES:
            raise Invalid("token_auth", "One of: " + ", ".join(TOKEN_AUTH_VALUES) + ".")
        out["token_auth"] = body["token_auth"]
    if "scopes" in body:
        out["scopes"] = _scopes(body["scopes"])
    if "claims" in body:
        out["claims"] = _claims(body["claims"])
    if "policy" in body:
        try:
            out["policy"] = sso_policy.validate(body["policy"])
        except sso_policy.PolicyInvalid as exc:
            raise Invalid(f"policy.{exc.key}", str(exc)) from exc
    return out


# --------------------------------------------------------------------------- what the pages are shown

def fingerprint(row) -> str:
    """The connection settings of ``row`` as one short value: equal while a test sign-in still speaks for them.
    The secret enters as a digest of its stored form, never as itself."""
    secret = getattr(row, "client_secret_enc", None) or ""
    parts = [getattr(row, "kind", None) or "", getattr(row, "issuer", None) or "",
             getattr(row, "discovery_url", None) or "", bool(getattr(row, "private_network", False)),
             getattr(row, "client_id", None) or "", getattr(row, "token_auth", None) or oc.TOKEN_AUTH_BASIC,
             getattr(row, "scopes", None) or "", getattr(row, "claims", None) or {},
             hashlib.sha256(secret.encode("utf-8")).hexdigest()]
    return hashlib.sha256(json.dumps(parts, sort_keys=True, separators=(",", ":")).encode("utf-8")).hexdigest()[:32]


def configured(row) -> bool:
    """Whether ``row`` holds what a sign-in needs: the issuer, the client id and the client secret."""
    return bool(getattr(row, "kind", None) == KIND_OIDC and row.issuer and row.client_id and row.client_secret_enc)


def tested(row) -> bool:
    """Whether a test sign-in passed with the connection settings as they are now."""
    last = getattr(row, "last_test", None)
    return (isinstance(last, dict) and last.get("outcome") == "ok" and bool(last.get("config"))
            and last.get("config") == fingerprint(row))


def addresses(row) -> Optional[dict]:
    """The two addresses the provider's own console asks for, on the vault's configured address; None when the
    vault has none to give (see :func:`app.services.sso_sign_in.address_refusal`)."""
    from app.core.public_url import public_base_url
    base = public_base_url()
    if not base:
        return None
    return {"redirect_uri": f"{base}/auth/sso/{row.id}/callback",
            "backchannel_logout_uri": f"{base}/auth/sso/{row.id}/backchannel-logout",
            "sign_in_link": f"{base}/?sso={row.id}"}


def _counts(db, row) -> dict:
    """How many accounts are linked to ``row``, how many of them sign in only through a provider, and how many
    identities carry a refusal."""
    from app.core.models import ExternalIdentity, User
    identities = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all()
    only = 0
    for identity in identities:
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is not None and getattr(user, "sso_only", False):
            only += 1
    return {"identities": len(identities), "sso_only_accounts": only,
            "refusals": sum(1 for i in identities if getattr(i, "refused_at", None) is not None)}


def public(db, row) -> dict:
    """``row`` as an administrator's page is shown it. Never the client secret, in any form: only whether one is
    stored."""
    from app.services import sso_sign_in

    def _t(value):
        return value.isoformat() + "Z" if value else None
    last = row.last_test if isinstance(getattr(row, "last_test", None), dict) else None
    return {
        "id": str(row.id), "kind": row.kind, "state": row.state, "name": row.name, "label": row.label,
        "icon": row.icon, "sort_order": row.sort_order or 0, "show_on_sign_in": bool(row.show_on_sign_in),
        "issuer": row.issuer, "discovery_url": row.discovery_url, "private_network": bool(row.private_network),
        "client_id": row.client_id, "has_client_secret": bool(row.client_secret_enc),
        "token_auth": row.token_auth or oc.TOKEN_AUTH_BASIC, "scopes": row.scopes or "openid profile email",
        "claims": dict(row.claims) if isinstance(row.claims, dict) else {},
        "policy": sso_policy.effective(row.policy),
        "configured": configured(row), "tested": tested(row),
        "last_test": {k: v for k, v in last.items() if k != "config"} if last else None,
        "reauth_offered": sso_sign_in.reauth_offered(row),
        "addresses": addresses(row),
        "created_at": _t(getattr(row, "created_at", None)), "updated_at": _t(getattr(row, "updated_at", None)),
        "created_by": getattr(row, "created_by_name", None),
        **_counts(db, row),
    }


# --------------------------------------------------------------------------- the changes

def _name_taken(db, name: str, *, but=None) -> bool:
    from app.core.models import SsoProvider
    for other in db.query(SsoProvider).all():
        if (but is None or other.id != but.id) and (other.name or "").strip().lower() == name.lower():
            return True
    return False


def new(db, *, name, preset_id=None) -> tuple:
    """Judge a new provider, changing nothing: its name as it would be stored and its preset (or None)."""
    from app.core.models import SsoProvider
    name = _text("name", name, most=NAME_MAX)
    preset = sso_presets.get(preset_id) if preset_id is not None else None
    if preset_id is not None and preset is None:
        raise Invalid("preset", "Unknown preset.")
    if len(db.query(SsoProvider).all()) >= MAX_PROVIDERS:
        raise Conflict(TOO_MANY, f"A vault holds at most {MAX_PROVIDERS} providers. Remove one first.")
    if _name_taken(db, name):
        raise Conflict(NAME_TAKEN, "Another provider already has this name.")
    return name, preset


def create(db, *, name, preset_id=None, by=None):
    """A new draft provider named ``name``, filled in from ``preset_id`` when one is given. Added to the session,
    not committed."""
    from app.core.models import SsoProvider
    name, preset = new(db, name=name, preset_id=preset_id)
    row = SsoProvider(kind=KIND_OIDC, state=DRAFT, name=name, label=None,
                      icon=(preset or {}).get("icon") or "generic", sort_order=0, show_on_sign_in=True,
                      token_auth=oc.TOKEN_AUTH_BASIC, scopes=(preset or {}).get("scopes") or "openid profile email",
                      claims=dict((preset or {}).get("claims") or {}) or None, policy=None,
                      created_by=getattr(by, "id", None), created_by_name=getattr(by, "username", None))
    db.add(row)
    return row


def check(db, row, changes: dict, *, account_policy=None) -> dict:
    """Judge ``changes`` (from :func:`clean`) against the row and the rest of the vault, changing nothing: the name
    is free, the policy as it would stand keeps its rules, and password sign-in is not turned off over a linked
    account that must keep a password. Returns the policy as it would be stored (or None when it is not changed)."""
    from app.core import sso_only
    if "name" in changes and _name_taken(db, changes["name"], but=row):
        raise Conflict(NAME_TAKEN, "Another provider already has this name.")
    if "policy" not in changes:
        return None
    stored = {**(row.policy if isinstance(row.policy, dict) else {}), **changes["policy"]}
    policy = sso_policy.effective(stored)
    restricted = sso_policy.is_restricted(policy, account_policy)
    if policy["sso_account_creation"] == "jit" and not restricted:
        raise Conflict(NEEDS_RESTRICTION, (
            "Accounts are made at the first sign-in only for a provider that says who may sign in. Set a tenant, a "
            "domain or a required group first."))
    if policy["sso_link_by_email"] and not restricted:
        raise Conflict(NEEDS_RESTRICTION, (
            "An account is linked by its verified email address only for a provider that says who may sign in. Set a "
            "tenant, a domain or a required group first."))
    was = sso_policy.effective(row.policy)["sso_password_login"]
    if policy["sso_password_login"] == "disabled" and was != "disabled":
        why = sso_only.disabled_refusal(db, row)
        if why:
            raise Conflict(PRIVILEGED_LINKED, why)
    return stored


def apply(db, row, changes: dict, stored_policy) -> dict:
    """Write ``changes`` to ``row`` (already judged by :func:`check`). Returns what happened beside the row itself:
    the fields that changed, whether the connection did (the last test no longer speaks for it), and the accounts
    whose password sign-in was turned off or allowed again."""
    from app.core import sso_only
    from app.core.security import encrypt_secret
    changed = []
    before = fingerprint(row)
    for field, value in changes.items():
        if field == "policy":
            continue
        if field == "client_secret":
            row.client_secret_enc = encrypt_secret(value)
            changed.append("client_secret")
        elif getattr(row, field) != value:
            setattr(row, field, value)
            changed.append(field)
    accounts = {"made_sso_only": [], "restored": []}
    if stored_policy is not None:
        was = sso_policy.effective(row.policy)
        now = sso_policy.effective(stored_policy)
        keys = sorted(key for key in now if now[key] != was[key])
        if keys:
            row.policy = stored_policy
            changed.extend("policy." + key for key in keys)
        if now["sso_password_login"] != was["sso_password_login"]:
            accounts = sso_only.apply_password_login(db, row, now["sso_password_login"])
    return {"changed": changed, "connection_changed": fingerprint(row) != before, **accounts}


def enable_refusal(db, row) -> Optional[Conflict]:
    """Why ``row`` may not be turned on now, or None."""
    from app.core import sso_only
    from app.services import sso_sign_in
    if not configured(row):
        return Conflict(NOT_CONFIGURED, "Enter the issuer, the client id and the client secret first.")
    address = sso_sign_in.address_refusal()
    if address:
        return Conflict(sso_sign_in.NO_PUBLIC_ADDRESS, address)
    if not tested(row):
        return Conflict(NOT_TESTED, (
            "Run a test sign-in first: a provider is turned on only after one passed with its settings as they are "
            "now."))
    if sso_policy.effective(row.policy)["sso_password_login"] == "disabled":
        why = sso_only.disabled_refusal(db, row)
        if why:
            return Conflict(PRIVILEGED_LINKED, why)
    return None


def remove_refusal(db, row) -> Optional[Conflict]:
    """Why ``row`` may not be removed now, or None."""
    if row.state == ENABLED:
        return Conflict(STILL_ON, "Turn the provider off before removing it.")
    counts = _counts(db, row)
    if counts["sso_only_accounts"]:
        n = counts["sso_only_accounts"]
        return Conflict(ONLY_WAY_IN, (
            f"{n} account{'s' if n != 1 else ''} sign{'s' if n == 1 else ''} in only through a provider and "
            f"{'is' if n == 1 else 'are'} linked to this one. Allow password sign-in for this provider first (Access)."))
    if counts["refusals"]:
        n = counts["refusals"]
        return Conflict(REFUSALS_IN_FORCE, (
            f"{n} account{'s are' if n != 1 else ' is'} held by a refusal this provider recorded. Clear "
            f"{'each' if n != 1 else 'it'} under Identities first: removing the provider would lift "
            f"{'them' if n != 1 else 'it'} unseen."))
    return None
