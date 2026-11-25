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
DAYS_RAN_OUT = "days_ran_out"
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
    "policy.sso_jit_password": "Password for accounts made at a first sign-in",
    "policy.sso_lapse_ends_sign_in": "Other ways in after the days run out",
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

# The fields that say where the provider is. The client secret was entered for the place they named then, and is
# kept only for it: pointing the provider somewhere else drops the secret, to be entered again by whoever knows it.
WHERE_IT_IS = ("issuer", "discovery_url", "private_network")

# What the audit log keeps of a provider's settings: every field but the client secret.
_RECORDED = ("name", "label", "icon", "sort_order", "show_on_sign_in", "issuer", "discovery_url", "private_network",
             "client_id", "token_auth", "scopes", "claims")
SECRET_STORED = "(set)"
SECRET_REPLACED = "(replaced)"


def recorded_values(row) -> dict:
    """A provider's settings as the audit log keeps them, by the field's name (a policy setting by its own): each
    as it is. None of them is a secret. Of the client secret only whether one is stored is kept."""
    out = {field: getattr(row, field, None) for field in _RECORDED}
    out.update(sso_policy.effective(getattr(row, "policy", None)))
    out["client_secret"] = SECRET_STORED if getattr(row, "client_secret_enc", None) else None
    return out


def recorded_changes(before: dict, row, changed, *, shorten=None) -> dict:
    """``{field: {"old": ..., "new": ...}}`` for the fields a save changed (``changed``, as :func:`apply` names
    them), from the values before it (``before``, :func:`recorded_values`) and the row as it is now. A new client
    secret is said as set or replaced, a dropped one as gone; ``shorten(field, value)`` may stand a long value in
    by its digest."""
    after = recorded_values(row)
    keep = shorten or (lambda field, value: value)
    out = {}
    for name in changed:
        field = name[len("policy."):] if name.startswith("policy.") else name
        if field == "client_secret":
            out[field] = {"old": before.get(field), "new": SECRET_REPLACED if before.get(field) else SECRET_STORED}
        else:
            out[field] = {"old": keep(field, before.get(field)), "new": keep(field, after.get(field))}
    if "client_secret" not in out and before.get("client_secret") != after.get("client_secret"):
        out["client_secret"] = {"old": before.get("client_secret"), "new": after.get("client_secret")}
    return out


def hold_lapsed(db, row, *, now=None, into=None) -> int:
    """Before ``row`` is turned off, and again before it is removed, in the caller's transaction: every identity
    of it whose freshness window has already run out is recorded as held (``refused_at``). The window goes on
    counting while a provider is off, but a removed provider has no identities left to count for: without this
    the people who stopped signing in there (the ones the window is for) would get their SSH keys, temporary
    credentials and devices back for good once it is removed. A held identity is lifted as a refusal is: by a
    later sign-in the provider admits, or by another administrator; and a provider is not removed while it holds
    one. Returns how many were held. An identity whose hold an administrator lifted is not held again for the
    deadline that lift answered (app/services/sso_freshness.py, lift_the_hold): the removal that asked for the
    lift then goes through.

    Nothing is written for a provider that is off and closes the other ways in after its days
    (``sso_lapse_ends_sign_in``). There a hold also ends the person's password, and while a provider is off its
    days end no password: nobody could sign in through it. A removal that was then refused had ended the
    password of everybody whose days ran out while the provider was off, and told nobody. Such a provider is not
    removed while days have run out (:func:`remove_refusal` says how it can be).

    ``into``: a list the held accounts' ids are added to, for the caller to tell them after its commit."""
    from datetime import datetime
    from app.core.models import ExternalIdentity
    from app.services import sso_freshness
    now = now or datetime.utcnow()
    if getattr(row, "state", None) != ENABLED and sso_policy.effective(getattr(row, "policy", None))["sso_lapse_ends_sign_in"]:
        return 0
    held = 0
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all():
        standing = sso_freshness.deadline_of(identity, row)
        if sso_freshness.lift_answers(identity, standing):
            continue
        if standing is not None and not standing.refused and standing.due <= now:
            identity.refused_at = now
            # Written while the days only pause keys: marked so, with the hold's own moment. It closes no
            # password while the provider is off, whatever its settings become (sso_freshness.a_hold_closes).
            identity.keys_only_hold_at = None if standing.ends_sign_in else now
            held += 1
            if into is not None:
                into.append(identity.user_id)
    return held


def held_by_the_removal(n: int) -> Conflict:
    """What a removal answers when it has just held ``n`` accounts whose days had run out (:func:`hold_lapsed`):
    the removal waits until an administrator has cleared each, knowingly."""
    return Conflict(REFUSALS_IN_FORCE, (
        f"{n} account{'s have' if n != 1 else ' has'} not signed in through this provider within its days. "
        f"{'They are' if n != 1 else 'It is'} held now, so that removing the provider does not give "
        f"{'them their' if n != 1 else 'it its'} SSH keys, temporary credentials and devices back unseen. Clear "
        f"{'each' if n != 1 else 'it'} under Identities when {'they' if n != 1 else 'it'} should have them back, "
        "then remove the provider again."))


def days_ran_out(db, row, *, now=None) -> int:
    """How many identities of ``row`` are past its days and not held by a refusal. Nothing is written."""
    from datetime import datetime
    from app.core.models import ExternalIdentity
    from app.services import sso_freshness
    now = now or datetime.utcnow()
    count = 0
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all():
        standing = sso_freshness.deadline_of(identity, row)
        if standing is not None and not standing.refused and standing.due <= now:
            count += 1
    return count


# The settings of a provider that say when its days hold an account to a sign-in through it.
WHAT_ITS_DAYS_HOLD = ("policy.sso_freshness_days", "policy.sso_lapse_ends_sign_in")


def _held(db, row, now=None) -> list:
    """(account, its deadline) for each account that can sign in and that ``row`` holds to a provider's sign-in
    right now: its password and passkeys sign it in to nothing until the provider admits it again."""
    from datetime import datetime
    from app.core.models import ExternalIdentity, User
    from app.services import sso_freshness
    now = now or datetime.utcnow()
    held = []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all():
        standing = sso_freshness.deadline_of(identity, row)
        if standing is None or not sso_freshness.closes_now(standing, now):
            continue
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is not None and user.is_active and sso_freshness.closes_the_other_ways_in(db, user, standing):
            held.append((user, standing))
    return held


def held_by_its_days(db, row, *, now=None) -> list:
    """The accounts linked to ``row`` (which is on) that its days hold to a provider's sign-in right now: their
    last sign-in through it is older than its days, and their password and passkeys sign them in to nothing until
    they have signed in through it again. Not the ones it refused: those are held by the refusal, whatever the
    days are. And not an account that is turned off: it signs in nowhere whatever the days are, so it is neither
    counted among the accounts a save holds nor told that its password stopped (the address on such an account
    is often a former employee's own)."""
    return [user for user, standing in _held(db, row, now) if not standing.refused]


def held_through(db, row, *, now=None) -> list:
    """Every account that can sign in and that ``row`` holds to a provider's sign-in right now, whatever holds
    it: its days (:func:`held_by_its_days`), or a refusal or hold on record. What a save that changes what the
    days hold is measured by: counted by the days alone, a save that makes a missed sign-in end the password
    closed it for everybody a refusal held, and said that it held nobody."""
    return [user for user, _standing in _held(db, row, now)]


def due_at_turn_on(db, row, *, now=None) -> int:
    """How many accounts linked to ``row`` (which is on) its days hold to a provider's sign-in right now: what an
    administrator is told when a provider is turned on after a time in which nobody could sign in through it."""
    return len(held_by_its_days(db, row, now=now))


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
    """The addresses the provider's own console asks for, on the vault's configured address: where it sends the
    browser back after a sign-in, where it reports a logout, where it sends the browser back after its own logout
    (asked for only when signing out here also signs out there; a provider refuses an address it was not given),
    and the link an organisation hands out. None when the vault has none to give (see
    :func:`app.services.sso_sign_in.address_refusal`)."""
    from app.core.public_url import public_base_url
    base = public_base_url()
    if not base:
        return None
    return {"redirect_uri": f"{base}/auth/sso/{row.id}/callback",
            "backchannel_logout_uri": f"{base}/auth/sso/{row.id}/backchannel-logout",
            "post_logout_redirect_uri": f"{base}/",
            "sign_in_link": f"{base}/?sso={row.id}"}


def _counts(db, row) -> dict:
    """How many accounts are linked to ``row``, how many of them sign in only through a provider, for how many
    this provider is the only way in, and how many identities a refusal still holds. A refusal the person has
    answered since, by a sign-in the provider admitted, is not one of them: it holds nobody, and nothing could
    clear it.

    The only way in: the account has no password it can type (it signs in only through a provider, or its
    password is one nobody knows, as for an account made at its first sign-in here) and no other identity that
    lets it in (app/core/sso_only.py another_way_in). Its passkey signs in after a provider only. While this
    provider is off, nothing signs such an account in."""
    from app.core import sso_only
    from app.core.models import ExternalIdentity, User
    from app.services import sign_in, sso_freshness
    identities = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all()
    only, only_way_in = 0, 0
    for identity in identities:
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is None:
            continue
        if getattr(user, "sso_only", False):
            only += 1
        if not sign_in.has_a_password_it_can_type(user) and not sso_only.another_way_in(db, user, without=identity):
            only_way_in += 1
    from app.core.models import SsoGroupMapping
    return {"identities": len(identities), "sso_only_accounts": only, "only_way_in_accounts": only_way_in,
            "refusals": sum(1 for i in identities if sso_freshness.refusal_in_force(i)),
            # How many of its groups are mapped to a department or a role (app/services/sso_group_mappings.py).
            "group_mappings": len(db.query(SsoGroupMapping).filter(SsoGroupMapping.provider_id == row.id).all())}


def made_here_and_held(db, row) -> int:
    """How many accounts sign in only through a provider because ``row`` made them at a first sign-in and does not
    let such accounts set a password (not because its people hold none)."""
    from app.core import sso_only
    from app.core.models import ExternalIdentity, User
    if sso_only.password_less(row):
        return 0
    held = 0
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id).all():
        user = db.query(User).filter(User.id == identity.user_id).first()
        if (user is not None and getattr(user, "sso_only", False)
                and sso_only.holds_to_no_password(row, user, getattr(identity, "linked_by", None))):
            held += 1
    return held


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
    if "policy" not in changes and "issuer" not in changes:
        return None
    # Judged as it would stand: the policy with what the request changes of it, at the issuer it would have (a
    # change of the issuer alone can make a tenant list say nothing more than the issuer does).
    stored = {**(row.policy if isinstance(row.policy, dict) else {}), **changes.get("policy", {})}
    policy = sso_policy.effective(stored)
    issuer = changes.get("issuer", getattr(row, "issuer", None))
    restricted = sso_policy.is_restricted(policy, account_policy, issuer=issuer)
    # A tenant list that only repeats the issuer's own tenant: said for what it is, with what does keep people out.
    repeats = ("" if restricted or not sso_policy.tenants_the_issuer_names(policy, issuer) else (
        " The tenant entered is the one the issuer already names: it keeps nobody out, guests of that tenant "
        "included. Require a group (Access), and at the provider let only assigned people use the app."))
    if policy["sso_account_creation"] == "jit" and not restricted:
        raise Conflict(NEEDS_RESTRICTION, (
            "Accounts are made at the first sign-in only for a provider that says who may sign in. Set a tenant, a "
            "domain or a required group first." + repeats))
    if policy["sso_link_by_email"] and not restricted:
        raise Conflict(NEEDS_RESTRICTION, (
            "An account is linked by its verified email address only for a provider that says who may sign in. Set a "
            "tenant, a domain or a required group first." + repeats))
    if "policy" not in changes:
        return None
    was = sso_policy.effective(row.policy)["sso_password_login"]
    if policy["sso_password_login"] == "disabled" and was != "disabled":
        why = sso_only.disabled_refusal(db, row)
        if why:
            raise Conflict(PRIVILEGED_LINKED, why)
    return stored


def apply(db, row, changes: dict, stored_policy, *, unknown_hash=None) -> dict:
    """Write ``changes`` to ``row`` (already judged by :func:`check`). Returns what happened beside the row itself:
    the fields that changed, whether the connection did (the last test no longer speaks for it), whether the stored
    secret was dropped because the provider was pointed somewhere else without a new one, and the accounts whose
    password sign-in was turned off or allowed again. ``unknown_hash``: what the caller hashed before it took the
    row (app/core/sso_only.a_password_nobody_knows), for the accounts whose password is replaced."""
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
    secret_cleared = False
    if any(field in changed for field in WHERE_IT_IS) and "client_secret" not in changed and row.client_secret_enc:
        # Never sent to an address it was not entered for: a test sign-in posts it to the provider's token endpoint.
        row.client_secret_enc = None
        secret_cleared = True
    accounts = {"made_sso_only": [], "restored": []}
    if stored_policy is not None:
        was = sso_policy.effective(row.policy)
        now = sso_policy.effective(stored_policy)
        keys = sorted(key for key in now if now[key] != was[key])
        if keys:
            row.policy = stored_policy
            changed.extend("policy." + key for key in keys)
        if (now["sso_password_login"] != was["sso_password_login"]
                or now["sso_jit_password"] != was["sso_jit_password"]):
            accounts = sso_only.apply_password_login(db, row, unknown_hash=unknown_hash)    # the new settings
    return {"changed": changed, "connection_changed": fingerprint(row) != before, "secret_cleared": secret_cleared,
            **accounts}


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
    from app.core import sso_only
    counts = _counts(db, row)
    if counts["sso_only_accounts"] and sso_only.password_less(row):
        # These accounts hold no password because of this provider's own setting. Allowing passwords first tells
        # each of them, and leaves them a way back in (a reset link). Accounts that sign in only through a provider
        # because of another one they are linked to keep that one, and are not in the way here.
        n = counts["sso_only_accounts"]
        return Conflict(ONLY_WAY_IN, (
            f"{n} account{'s' if n != 1 else ''} linked to this provider hold{'s' if n == 1 else ''} no password "
            "because of it. Allow password sign-in for this provider first (Access), so they can set one."))
    made_here = made_here_and_held(db, row)
    if made_here:
        # The same for the accounts this provider made at a first sign-in and holds to no password by that rule.
        n = made_here
        return Conflict(ONLY_WAY_IN, (
            f"{n} account{'s' if n != 1 else ''} made at a first sign-in through this provider hold{'s' if n == 1 else ''} "
            "no password because of it. Let such accounts set a password first (Access), so they can set one."))
    if counts["refusals"]:
        n = counts["refusals"]
        return Conflict(REFUSALS_IN_FORCE, (
            f"{n} account{'s are' if n != 1 else ' is'} held by a refusal this provider recorded. Clear "
            f"{'each' if n != 1 else 'it'} under Identities first: removing the provider would lift "
            f"{'them' if n != 1 else 'it'} unseen."))
    lapsed = (days_ran_out(db, row)
              if sso_policy.effective(getattr(row, "policy", None))["sso_lapse_ends_sign_in"] else 0)
    if lapsed:
        # Past their days, and not held: this provider closes the other ways in after its days, so a hold written
        # now, while it is off, would end these people's passwords (hold_lapsed writes none). Removed, the provider
        # would give them their paused keys back unseen. The sentence names the two ways on. (Where the days only
        # pause keys, the removal itself holds them, once its step-up has passed: held_by_the_removal.)
        n = lapsed
        many = n != 1
        return Conflict(DAYS_RAN_OUT, (
            f"{n} account{'s have' if many else ' has'} not signed in through this provider within its days, so "
            f"{'their' if many else 'its'} SSH keys, temporary credentials and devices are paused. Removing the "
            "provider would lift that unseen. The ways on: turn the provider on so that "
            f"{'they sign' if many else 'it signs'} in through it again; unlink {'each' if many else 'it'} under the "
            f"provider's Identities; or delete the account{'s' if many else ''}. Or turn off “After those days, or a "
            "refusal, the account signs in only through a provider” for it (Access) and remove it again: "
            f"{'they are' if many else 'it is'} then held, to be lifted under Identities, and nobody's password "
            "stops."))
    return None
