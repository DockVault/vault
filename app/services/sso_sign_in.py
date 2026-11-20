"""Single sign-on through an OpenID Connect provider: the start, the callback, and what each purpose does.

A start makes the login state (app/core/sso_state.py) and answers the authorization URL the browser is sent to.
The callback spends the state, checks the provider and the issuer parameter, exchanges the code, verifies the ID
token (app/services/oidc_client.py), and then does what the state's purpose says:

* ``sign_in``: judges the provider's restriction (app/core/sso_policy.py), finds the account the identity belongs
  to in the design's order (a known identity; the invitation the state carries, whose account is made now; an
  account made at this first sign-in when a restricted provider is set to make them; an account with this verified
  email when the provider links by email),
  and hands the pipeline's result over as a one-time code the web app redeems at
  ``POST /auth/finish`` (app/core/sign_in_codes.py), so no session ever travels in a URL;
* ``link``: links the identity to the signed-in account that started it (the state names the account and the
  session), with no sign-in and no session;
* ``test``: writes the summary an administrator reads on the provider's row (what the provider sent, and what the
  vault would do) and changes nothing else;
* ``step_up``: left to the provider re-authentication item.

Every refusal is a short reason code (``OidcError`` from the client, or :class:`Refusal` here); the provider's own
text never reaches the person. Nothing here commits for a ``test``.
"""
from __future__ import annotations

import hashlib
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Optional

from app.core import sso_policy, sso_state
from app.services import oidc_client as oc

# Reason codes of this module (the client's are in oidc_client).
STATE_UNKNOWN = "state_unknown"
PROVIDER_MIX_UP = "provider_mix_up"
PROVIDER_DISABLED = "provider_disabled"
NO_ACCOUNT = "no_account"
ACCOUNT_DISABLED = "account_disabled"
ALREADY_LINKED = "already_linked"
NOT_THIS_ACCOUNT = "not_this_account"
PURPOSE_NOT_READY = "purpose_not_ready"
REAUTH_STALE = "reauth_stale"
PROVIDER_CLOCK_AHEAD = oc.PROVIDER_CLOCK_AHEAD    # a time the provider states (its sign-in, its token) lies ahead
NO_PUBLIC_ADDRESS = "no_public_address"          # the vault has no address a provider can send the browser back to
PRIVILEGED_ON_PASSWORD_LESS = "privileged_on_password_less"
REAUTH_NO_MFA = "reauth_no_mfa"
REAUTH_MAX_AGE_SECONDS = 60
RESTRICTED = sso_policy.RESTRICTED
RESTRICTION_CLAIM_MISSING = sso_policy.RESTRICTION_CLAIM_MISSING
INVITATION_UNUSABLE = "invitation_unusable"
EMAIL_REQUIRED = "email_required"
ACCOUNT_LIMIT = "account_limit"
USERNAME_UNAVAILABLE = "username_unavailable"

USERNAME_MIN, USERNAME_MAX = 3, 50          # the account rules (the creation and invitation schemas)

# What a person is told for each reason, in words (the admin page and the sign-in page show these).
REASON_TEXTS = {
    oc.PROVIDER_ERROR: "Your organisation's sign-in did not complete. Try again, or contact your administrator.",
    oc.ISSUER_MISMATCH: "The sign-in answer did not come from the configured provider.",
    oc.TOKEN_INVALID: "The sign-in answer could not be verified.",
    oc.NONCE_MISMATCH: "The sign-in answer did not belong to this sign-in. Start again.",
    oc.ENDPOINT_REFUSED: "The provider's address is not one the vault may call. Contact your administrator.",
    oc.TEMPORARILY_UNAVAILABLE: "The provider could not be reached. Try again in a moment.",
    oc.DISCOVERY_INVALID: "The provider's configuration could not be read. Contact your administrator.",
    STATE_UNKNOWN: "This sign-in is unknown or has expired. Start again.",
    PROVIDER_MIX_UP: "The sign-in answer came back for another provider. Start again.",
    PROVIDER_DISABLED: "This sign-in method is not available.",
    NO_ACCOUNT: ("Your organisation's sign-in worked, but there is no account for you here. Ask an administrator to "
                 "invite you."),
    ACCOUNT_DISABLED: "Your account cannot sign in. Contact your administrator.",
    ALREADY_LINKED: "That organisation identity is already linked to an account.",
    NOT_THIS_ACCOUNT: "That organisation identity belongs to another account here.",
    PURPOSE_NOT_READY: "This step is not available yet.",
    REAUTH_STALE: "Your organisation's sign-in did not ask you to sign in again just now. Start again.",
    PROVIDER_CLOCK_AHEAD: ("Your organisation's sign-in reports a time that has not come yet, so its clock or this "
                           "vault's is wrong. Tell your administrator."),
    NO_PUBLIC_ADDRESS: ("Single sign-on is not available: this vault has no address your organisation's sign-in can "
                        "send you back to. Tell your administrator."),
    PRIVILEGED_ON_PASSWORD_LESS: ("An administrator's or auditor's account keeps a local password, so it cannot be linked "
                                  "to a provider whose people sign in without one."),
    REAUTH_NO_MFA: "Your organisation's sign-in did not confirm you with a second factor. Start again.",
    RESTRICTED: ("Your organisation's sign-in worked, but this vault is not open to your tenant, domain or group. Ask "
                 "your administrator."),
    RESTRICTION_CLAIM_MISSING: ("Your organisation's sign-in did not say which tenant, domain or groups you belong to, "
                                "so the vault could not check who it admits. Ask your administrator."),
    INVITATION_UNUSABLE: "This invitation can no longer be used. Ask your administrator for a new one.",
    EMAIL_REQUIRED: ("Your organisation's sign-in did not provide a verified email address, and this vault requires "
                     "one for a new account. Ask your administrator."),
    ACCOUNT_LIMIT: "This vault cannot take another account right now. Ask your administrator.",
    USERNAME_UNAVAILABLE: ("No usable username could be made for you from what your organisation's sign-in provided. "
                           "Ask your administrator to invite you."),
}


class Refusal(Exception):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def reason_text(code: str) -> str:
    return REASON_TEXTS.get(code, REASON_TEXTS[oc.PROVIDER_ERROR])


# --------------------------------------------------------------------------- the provider row as the client needs it

def provider_config(row) -> oc.ProviderConfig:
    """The client's view of a provider row; the secret is decrypted here and goes nowhere else."""
    from app.core.security import decrypt_secret
    secret = ""
    if row.client_secret_enc:
        try:
            secret = decrypt_secret(row.client_secret_enc)
        except Exception as exc:  # noqa: BLE001 -- a secret the key cannot open is a provider error, not a 500
            raise Refusal(oc.PROVIDER_ERROR, f"client secret unreadable: {type(exc).__name__}") from exc
    return oc.ProviderConfig(
        id=str(row.id), issuer=row.issuer or "", client_id=row.client_id or "", client_secret=secret,
        token_auth=row.token_auth or oc.TOKEN_AUTH_BASIC, scopes=row.scopes or "openid profile email",
        discovery_url=row.discovery_url or None, private_network=bool(row.private_network))


def usable_for(row, purpose: str) -> Optional[str]:
    """Why ``row`` cannot serve ``purpose`` now, or None: a sign-in or a link needs an enabled OpenID Connect
    provider; a test needs one that is configured (any state but a bare draft without an issuer). Every purpose needs
    the vault to have an address the provider can send the browser back to (``address_refusal``)."""
    if row is None or getattr(row, "kind", None) != "oidc":
        return PROVIDER_DISABLED
    if not (row.issuer and row.client_id and row.client_secret_enc):
        return PROVIDER_DISABLED
    if purpose != sso_state.TEST and row.state != "enabled":
        return PROVIDER_DISABLED
    return NO_PUBLIC_ADDRESS if address_refusal() else None


def address_refusal() -> Optional[str]:
    """Why single sign-on cannot be built on the vault's address as it is configured, in words for an administrator,
    or None when it can.

    A provider is given a redirect address on the vault's own and sends the browser back to it. That address is the
    configured one (the first ALLOWED_HOSTS entry that is not a wildcard), never the Host of the request that asked.
    With none, or one that is not https (plain http only on localhost), nothing is started, no provider is turned on
    and no test runs."""
    from app.core import public_url
    if public_url.public_base_url():
        return None
    return "Single sign-on needs the vault's public address. " + public_url.why_not_usable()


def redirect_uri(provider_id) -> str:
    """The address a provider sends the browser back to, on the vault's configured address. Refused when the vault
    has none: a provider is never handed an address made of anything else."""
    from app.core.public_url import public_base_url
    base = public_base_url()
    if not base:
        raise Refusal(NO_PUBLIC_ADDRESS)
    return f"{base}/auth/sso/{provider_id}/callback"


def post_logout_address() -> Optional[str]:
    """Where a provider sends the browser after its own logout: the vault's sign-in page, on the configured address.
    None when the vault has none to give."""
    from app.core.public_url import public_base_url
    base = public_base_url()
    return f"{base}/" if base else None


def claim_name(row, vault_name: str, default: str) -> str:
    claims = getattr(row, "claims", None) or {}
    value = claims.get(vault_name) if isinstance(claims, dict) else None
    return value if isinstance(value, str) and value else default


# --------------------------------------------------------------------------- the start

def start(row, *, purpose: str, source: str, client_ip: Optional[str], verifier_hash: Optional[str] = None,
          code_challenge: Optional[str] = None, return_to=None, user_id=None, session_hash: Optional[str] = None,
          step_up_action: Optional[str] = None, reauthenticate: bool = False, login_hint: Optional[str] = None,
          extras: Optional[dict] = None, fetch=None, cache=None, resolve=None) -> str:
    """Make the login state and return the authorization URL for ``row``. Raises :class:`Refusal`,
    :class:`oc.OidcError`, :class:`sso_state.TooManyAbandoned` or :class:`sso_state.Unavailable`."""
    why = usable_for(row, purpose)
    if why is not None:
        raise Refusal(why)
    fetch = fetch or oc.fetch_json
    provider = provider_config(row)
    discovery = oc.discover(provider, fetch=fetch, cache=cache, resolve=resolve)
    state = sso_state.begin(provider_id=str(row.id), purpose=purpose, source=source, client_ip=client_ip,
                            verifier_hash=verifier_hash, code_challenge=code_challenge, return_to=return_to,
                            user_id=user_id, session_hash=session_hash, step_up_action=step_up_action, extras=extras)
    requested_acr = policy_of(row)["sso_requested_acr"] or None
    return oc.authorization_url(provider, discovery, redirect_uri=redirect_uri(row.id), state=state.state,
                                nonce=state.nonce, code_verifier=state.code_verifier, reauthenticate=reauthenticate,
                                acr_values=requested_acr, login_hint=login_hint, resolve=resolve)


# --------------------------------------------------------------------------- the callback

@dataclass
class ProviderAnswer:
    """What the provider said about the person, verified."""
    claims: dict
    subject: str
    issuer: str
    tenant_id: Optional[str]
    email: Optional[str]
    email_verified: bool
    display_name: Optional[str]
    auth_time: Optional[datetime]
    amr: list = field(default_factory=list)
    acr: Optional[str] = None
    sid: Optional[str] = None
    id_token: Optional[str] = None
    hosted_domain: Optional[str] = None      # Google Workspace's hd
    groups: Optional[list] = None            # the groups claim as strings; None when the token has none
    groups_overage: bool = False             # Entra sent a marker instead of the groups (too many)


@dataclass
class CallbackOutcome:
    purpose: str
    state: sso_state.LoginState
    answer: ProviderAnswer
    user: object = None                      # the account the identity belongs to (sign_in, link, test)
    identity: object = None                  # the external_identities row
    linked_now: bool = False


def verified_answer(row, state: sso_state.LoginState, *, code: str, fetch=None, cache=None,
                    resolve=None, now=None) -> ProviderAnswer:
    """Exchange the code and verify the ID token for ``state``; read the claims the vault uses."""
    fetch = fetch or oc.fetch_json
    provider = provider_config(row)
    discovery = oc.discover(provider, fetch=fetch, cache=cache, resolve=resolve, now=now)
    tokens = oc.exchange_code(provider, discovery, code=code, redirect_uri=redirect_uri(row.id),
                              code_verifier=state.code_verifier, fetch=fetch, resolve=resolve)
    # A re-authentication's freshness (``auth_time``) is judged once, by reauth_refusal, with its own reason.
    claims = oc.verify_id_token(provider, discovery, tokens.id_token, nonce=state.nonce,
                                access_token=tokens.access_token, code=code, fetch=fetch, cache=cache,
                                resolve=resolve, now=now)
    email_name = claim_name(row, "email", "email")
    verified_name = claim_name(row, "email_verified", "email_verified")
    name_name = claim_name(row, "name", "name")
    tenant_name = claim_name(row, "tenant", "tid")
    email = claims.get(email_name)
    email = email.strip() if isinstance(email, str) and email.strip() else None
    display = claims.get(name_name)
    display = display.strip()[:255] if isinstance(display, str) and display.strip() else None
    tenant = claims.get(tenant_name)
    tenant = tenant.strip() if isinstance(tenant, str) else None
    tenant = tenant if tenant and len(tenant) <= 255 else None      # the column's width; longer is no tenant id
    # The provider's own sign-in cannot lie ahead of now: beyond the skew every token check allows, its clock (or
    # this server's) is wrong, and the time is refused, not kept with the provider's session. The number itself is
    # compared, before it is read as a time: one too large to place lies further ahead than any, it is not "no time".
    stated = claims.get("auth_time")
    if (isinstance(stated, (int, float)) and not isinstance(stated, bool)
            and stated > (time.time() if now is None else now) + oc.SKEW_SECONDS):
        raise oc.OidcError(PROVIDER_CLOCK_AHEAD, "auth_time lies in the future")
    auth_time = _as_time(stated)
    amr = claims.get("amr")
    amr = [a for a in amr if isinstance(a, str)] if isinstance(amr, list) else []
    acr = claims.get("acr")
    sid = claims.get("sid")
    hosted = claims.get(claim_name(row, "domain", "hd"))
    groups_name = claim_name(row, "groups", "groups")
    raw_groups = claims.get(groups_name)
    groups = ([str(g)[:255] for g in raw_groups if isinstance(g, (str, int)) and not isinstance(g, bool)][:1000]
              if isinstance(raw_groups, list) else None)
    names = claims.get("_claim_names")
    overage = isinstance(names, dict) and groups_name in names     # a marker makes any list beside it partial
    return ProviderAnswer(claims=claims, subject=str(claims["sub"]), issuer=str(claims["iss"]), tenant_id=tenant,
                          email=email, email_verified=claims.get(verified_name) is True, display_name=display,
                          auth_time=auth_time, amr=amr, acr=acr if isinstance(acr, str) else None,
                          sid=sid if isinstance(sid, str) else None, id_token=tokens.id_token,
                          hosted_domain=hosted.strip()[:255] if isinstance(hosted, str) and hosted.strip() else None,
                          groups=groups, groups_overage=overage)


def _as_time(value) -> Optional[datetime]:
    """A claim's seconds since the epoch as an aware UTC time, or None for anything that is not a sane one."""
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        return None
    if not (0 <= value < 2 ** 33):          # about the year 2242; beyond it the platform's clock arithmetic fails
        return None
    try:
        return datetime.fromtimestamp(value, tz=timezone.utc)
    except (OSError, OverflowError, ValueError):
        return None


def known_identity(db, row, answer: ProviderAnswer):
    """The identity row for this provider, issuer and subject, or None. An identity linked under a tenant is the
    same person only under that tenant: a token for another tenant, or none, does not match it."""
    from app.core.models import ExternalIdentity
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id,
                                                 ExternalIdentity.issuer == answer.issuer,
                                                 ExternalIdentity.subject == answer.subject).first()
    if identity is None:
        return None
    if identity.tenant_id and (answer.tenant_id or "").lower() != identity.tenant_id.strip().lower():
        return None
    return identity


def subject_owner(db, row, answer: ProviderAnswer):
    """The identity row holding this provider's subject under any tenant, or None: the table keys on the provider
    and the subject alone, so a subject pinned to another tenant can belong to nobody else."""
    from app.core.models import ExternalIdentity
    return db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id,
                                             ExternalIdentity.subject == answer.subject).first()


def usable_email(value) -> Optional[str]:
    """A provider's address claim in the shape the vault stores (one '@' with something on each side, ASCII, at most
    255 characters, folded), or None. The schema that validates an address at the forms is not on this path, so
    the shape is held here; an address that fails it is treated as absent."""
    from app.core.account_policy import signup_email_is_ascii
    from app.core.email_identity import normalize_email
    if not isinstance(value, str):
        return None
    email = normalize_email(value)
    if email is None or email.count("@") != 1 or len(email) > 255 or not signup_email_is_ascii(email):
        return None
    local, domain = email.split("@")
    if not local or not domain or any(ch.isspace() for ch in email):
        return None
    return email


def account_usable(user) -> bool:
    """An active account not locked by an administrator (a timed lock from failed sign-ins is the lockouts' to
    judge, at the sign-in itself)."""
    from app.services.auth_service import admin_locked
    return bool(user is not None and getattr(user, "is_active", True) and not admin_locked(user))


def answer_record(answer: ProviderAnswer) -> dict:
    """What a link or test keeps of the provider's answer while the tab claims it: the identity's key and display
    data, never a token."""
    return {"subject": answer.subject, "issuer": answer.issuer, "tenant_id": answer.tenant_id, "email": answer.email,
            "email_verified": answer.email_verified, "display_name": answer.display_name}


def answer_from_record(record: dict) -> ProviderAnswer:
    return ProviderAnswer(claims={}, subject=record["subject"], issuer=record["issuer"], tenant_id=record.get("tenant_id"),
                          email=record.get("email"), email_verified=bool(record.get("email_verified")),
                          display_name=record.get("display_name"), auth_time=None)


def _api():
    from app.api import api_server
    return api_server


def policy_of(row) -> dict:
    return sso_policy.effective(getattr(row, "policy", None))


def restriction_of(db, row, answer: ProviderAnswer) -> Optional[str]:
    """The provider's restriction judged on this answer: None when it admits the person (or there is none),
    else the reason (``restricted``, ``restriction_claim_missing``)."""
    policy = policy_of(row)
    account_policy = _api()._account_policy(db) if policy["sso_use_signup_domains"] else None
    return sso_policy.restriction(policy, tenant_id=answer.tenant_id, email=answer.email,
                                  email_verified=answer.email_verified, hosted_domain=answer.hosted_domain,
                                  groups=answer.groups, groups_overage=answer.groups_overage,
                                  account_policy=account_policy)


def mfa_trusted(row, answer: ProviderAnswer) -> bool:
    """Whether the provider's token counts as the second factor under the provider's policy (trust on, and an
    accepted ``amr`` or ``acr`` value present); nothing is trusted by default."""
    return sso_policy.mfa_trusted(policy_of(row), answer.amr, answer.acr)


def restriction_refusal(db, row, answer: ProviderAnswer) -> None:
    """Raise :class:`Refusal` when the restriction keeps this person out. Judged before who the person is, for
    every purpose but a test (which reports it instead)."""
    why = restriction_of(db, row, answer)
    if why is not None:
        raise Refusal(why)


@dataclass
class Resolution:
    """Who the person is, and what was done to find out."""
    user: object
    identity: object
    created: bool = False                 # an account was made at this sign-in (an invitation, or just in time)
    linked_now: bool = False              # the identity was linked at this sign-in
    linked_by: Optional[str] = None       # invitation | self (by verified email) | jit
    invitation: object = None             # the invitation accepted, when one was
    inviter_name: Optional[str] = None    # for an administrator's invitation: who made it


def resolve_account(db, row, answer: ProviderAnswer, *, login=None) -> Resolution:
    """Who the person is, for a sign-in, in the design's order: a known identity; the invitation the login state
    carries (the invited account is made now); creation at the first sign-in when the provider makes accounts (its
    item fills it in); an active account that is not an administrator with this verified email, when the provider
    links by email and is restricted; otherwise ``NO_ACCOUNT``. The restriction was judged by the caller first.
    What the invitation and email steps write stays in the caller's transaction; the caller commits."""
    from app.core.models import User
    identity = known_identity(db, row, answer)
    if identity is not None:
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is None:
            raise Refusal(NO_ACCOUNT)
        if not account_usable(user):
            raise Refusal(ACCOUNT_DISABLED)
        if identity.tenant_id is None and answer.tenant_id:
            identity.tenant_id = answer.tenant_id      # linked before the provider named a tenant: pinned from now on
        return Resolution(user, identity)
    extras = getattr(login, "extras", None) if login is not None else None
    invitation_id = extras.get("invitation_id") if isinstance(extras, dict) else None
    if invitation_id:
        return _accept_invitation(db, row, answer, invitation_id)
    policy = policy_of(row)
    if policy["sso_account_creation"] == "jit":
        made = _create_account(db, row, answer, policy)
        if made is not None:
            return made
    if policy["sso_link_by_email"]:
        linked = _link_by_email(db, row, answer, policy)
        if linked is not None:
            return linked
    raise Refusal(NO_ACCOUNT)


def _create_account(db, row, answer: ProviderAnswer, policy: dict):
    """Creation at the first sign-in (the design's step 3), only for a restricted provider (the save-time rule's
    condition, held here too so a hand-edited row never opens the door to anyone with an account at the provider):
    the role the policy names (never an administrator), a real password hash nobody knows, the provider's verified
    address when the account policy admits it (a required address that is not there is a refusal: the person can
    type nothing here), the username from the provider's claim, else the address's local part, else the subject,
    under the account rules with a numeric suffix on a collision; no departments (the group mapping lands with its
    item) and no vault access. None when the provider is not restricted: it then behaves as invite-only."""
    import secrets
    import uuid as _uuid
    from sqlalchemy.exc import IntegrityError
    from app.core.endpoint_permissions import grant_default_permissions_for_role
    from app.core.models import RoleEnum, User
    from app.core.security import hash_password
    api = _api()
    account_policy = api._account_policy(db)
    if not sso_policy.is_restricted(policy, account_policy):
        return None
    if subject_owner(db, row, answer) is not None:
        raise Refusal(ALREADY_LINKED, "subject_linked_elsewhere")     # the same subject, pinned to another tenant
    email = _admitted_address(db, answer, policy, account_policy)
    if email is None and account_policy.get("email_requirement") == "required":
        raise Refusal(EMAIL_REQUIRED, "email_required")
    try:
        api._enforce_user_cap(db)
    except Exception:          # noqa: BLE001 -- the plan's wording is for an administrator, not a person at a provider
        raise Refusal(ACCOUNT_LIMIT, "user_cap")
    username = username_for(db, row, answer)
    if username is None:
        raise Refusal(USERNAME_UNAVAILABLE, "no_username")
    role = RoleEnum(policy["sso_default_role"])
    sso_only = policy["sso_password_login"] == "disabled"
    now = datetime.utcnow()
    user = User(id=_uuid.uuid4(), username=username, email=email, password_hash=hash_password(secrets.token_urlsafe(32)),
                role=role, created_by=None, created_at=now, updated_at=now, is_active=True, is_locked=False,
                failed_login_attempts=0, sftp_enabled=True, sso_only=sso_only, sftp_password_auth=not sso_only)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise Refusal(USERNAME_UNAVAILABLE, "race_conflict")
    grant_default_permissions_for_role(str(user.id), user.role, db, commit=False)
    identity = link_identity(db, row, user, answer, linked_by="jit")
    return Resolution(user, identity, created=True, linked_now=True, linked_by="jit")


def _admitted_address(db, answer: ProviderAnswer, policy: dict, account_policy: dict) -> Optional[str]:
    """The provider's verified address when a new account may carry it: in the stored shape, on the provider's domain
    list when one is set, admitted by the account policy's sign-up domain list, and nobody's yet (no account, no
    pending invitation). None otherwise: the account is made without an address, or refused when one is required."""
    from app.core.account_policy import email_allowed_by_domain_gate
    from app.core.email_identity import email_in_use
    api = _api()
    email = usable_email(answer.email) if answer.email_verified else None
    if email is None or not sso_policy.address_admitted(policy, email):
        return None
    if not email_allowed_by_domain_gate(email, account_policy.get("signup_email_domain_mode"),
                                        account_policy.get("signup_email_domains")):
        return None
    if email_in_use(db, email) or api._email_has_pending_invite(db, email):
        return None
    return email


def username_for(db, row, answer: ProviderAnswer) -> Optional[str]:
    """The username a new account gets: the provider's username claim when it passes the account rules, else the
    verified address's local part, else the subject shortened; on a collision a numeric suffix (``-2``, ``-3``).
    None when nothing usable comes out of that (the person is asked to be invited)."""
    candidates = []
    preferred = answer.claims.get(claim_name(row, "username", "preferred_username"))
    if isinstance(preferred, str):
        candidates.append(preferred)
    email = usable_email(answer.email) if answer.email_verified else None
    if email is not None:
        candidates.append(email.rsplit("@", 1)[0])
    candidates.append(answer.subject)
    for raw in candidates:
        base = _username_base(raw)
        if base is None:
            continue
        for n in range(1, 100):
            name = base if n == 1 else f"{base[:USERNAME_MAX - len(str(n)) - 1]}-{n}"
            if len(name) < USERNAME_MIN:
                break
            if not _username_taken(db, name):
                return name
    return None


def _username_base(raw) -> Optional[str]:
    """``raw`` cut to the account rules, or None when it cannot be a username: too short, with spaces, or refused
    by the rules every new username meets (markup, '@', invisible characters, reserved and server names)."""
    base = (raw or "").strip()[:USERNAME_MAX]
    if len(base) < USERNAME_MIN or any(ch.isspace() for ch in base):
        return None
    try:
        _api()._validate_new_username(base)
    except ValueError:
        return None
    return base


def _username_taken(db, name: str) -> bool:
    from app.core.email_identity import email_in_use
    from app.core.models import User
    if db.query(User.id).filter(User.username == name).first() is not None:
        return True
    return email_in_use(db, name)      # a username that is someone's address would shadow them at the sign-in


def _email_match(db, row, answer: ProviderAnswer, policy: dict):
    """The one account a verified email may link to (the design's step 4), or None: the provider must be
    restricted (the save-time rule's condition, held here too so a hand-edited row never widens the door), the
    address verified by the provider, owned by exactly one active account that is not an administrator and has no
    identity on this provider yet, and confirmed for that account by the vault itself (an administrator or an
    invitation set it, or the person typed the code sent there: app/core/email_confirmation.py).

    The last condition is the vault's side of "verified". Without it, anyone with an account could write a
    colleague's address on their own account (a change of one's own address asks for the current password, not
    for a code, unless the administrator turned that on) and wait: the colleague's first sign-in through the
    provider would be linked to that account, and every later one would land there."""
    from app.core import email_confirmation, privileged_accounts
    from app.core.email_identity import find_user_by_email
    from app.core.models import ExternalIdentity
    api = _api()
    account_policy = api._account_policy(db) if policy["sso_use_signup_domains"] else None
    if not sso_policy.is_restricted(policy, account_policy):
        return None
    email = usable_email(answer.email) if answer.email_verified else None
    if email is None or not sso_policy.address_admitted(policy, email):
        return None                  # the hosted-domain claim admits the sign-in; the address must be on the list too
    user = find_user_by_email(db, email)
    if user is None or not account_usable(user):
        return None
    kind = privileged_accounts.kind(db, user)
    if kind is not None:
        # An administrator, or an account with the auditor right (open), reaches other people's vaults: a takeover of
        # its address at the provider must not reach it silently. It links only from its own profile, under step-up.
        raise Refusal(RESTRICTED, f"privileged_account:{kind}")
    if not email_confirmation.confirmed(user):
        raise Refusal(NO_ACCOUNT, ADDRESS_NOT_CONFIRMED)
    if db.query(ExternalIdentity.id).filter(ExternalIdentity.provider_id == row.id,
                                            ExternalIdentity.user_id == user.id).first() is not None:
        return None          # the account's identity on this provider is another one: an administrator sorts it out
    return user


# The audit's word for a link by email refused because the vault never confirmed the account's address.
ADDRESS_NOT_CONFIRMED = "address_not_confirmed"


def _link_by_email(db, row, answer: ProviderAnswer, policy: dict):
    user = _email_match(db, row, answer, policy)
    if user is None:
        return None
    identity = link_identity(db, row, user, answer, linked_by="self")
    return Resolution(user, identity, linked_now=True, linked_by="self")


def _accept_invitation(db, row, answer: ProviderAnswer, invitation_id) -> Resolution:
    """The login state carried an invitation: the invited account is made now, with the invitation's username
    and role, a real password hash nobody knows (the person signs in through the provider; a password is set
    through a reset), and this identity; the invitation is claimed once. The checks are the password acceptance's
    (app/api/api_server.py, accept_invite), in its order; each refusal is a reason here, its detail the audit's
    reason word. The person can type nothing in this flow, so a required address the provider did not verify is
    a refusal rather than a prompt."""
    import secrets
    import uuid as _uuid
    from sqlalchemy.exc import IntegrityError
    from app.core.email_identity import email_in_use
    from app.core.endpoint_permissions import grant_default_permissions_for_role
    from app.core.models import AccountInvitation, RoleEnum, User
    from app.core.security import hash_password
    api = _api()
    try:
        inv_id = _uuid.UUID(str(invitation_id))
    except ValueError:
        raise Refusal(INVITATION_UNUSABLE, "bad_id")
    inv = db.query(AccountInvitation).filter(AccountInvitation.id == inv_id).first()
    now = datetime.utcnow()
    if inv is None or inv.accepted_at is not None or inv.revoked_at is not None or inv.expires_at <= now:
        raise Refusal(INVITATION_UNUSABLE, "not_pending")
    account_policy = api._account_policy(db)
    if not account_policy.get("invite_enabled"):
        raise Refusal(INVITATION_UNUSABLE, "invitations_off")
    if not api._invitation_inviter_can_act(db, inv, lock=True):
        raise Refusal(INVITATION_UNUSABLE, "inviter_not_admin")
    if api._username_kept(inv.username):
        raise Refusal(INVITATION_UNUSABLE, "username_reserved")
    if subject_owner(db, row, answer) is not None:
        raise Refusal(ALREADY_LINKED, "subject_linked_elsewhere")     # the same subject, pinned to another tenant
    policy = policy_of(row)
    if inv.email:
        if email_in_use(db, inv.email):
            raise Refusal(INVITATION_UNUSABLE, "email_in_use")
        email = inv.email
    else:
        email = _admitted_address(db, answer, policy, account_policy)
        if email is None and account_policy.get("email_requirement") == "required":
            raise Refusal(EMAIL_REQUIRED, "email_required")
    try:
        api._enforce_user_cap(db)
    except Exception:          # noqa: BLE001 -- the plan's wording is for an administrator, not a person at a provider
        raise Refusal(ACCOUNT_LIMIT, "user_cap")
    if email_in_use(db, inv.username):
        raise Refusal(INVITATION_UNUSABLE, "username_email_conflict")
    try:
        role = RoleEnum(inv.role)
    except ValueError:
        raise Refusal(INVITATION_UNUSABLE, "bad_role")
    if role == RoleEnum.ADMIN and policy["sso_password_login"] == "disabled":
        # No administrator is ever linked to a provider whose people hold no password (the save of that setting
        # refuses while one is linked); an administrator's invitation goes through another provider or the form.
        raise Refusal(INVITATION_UNUSABLE, "administrator_on_password_less_provider")
    sso_only = policy["sso_password_login"] == "disabled"
    user = User(id=_uuid.uuid4(), username=inv.username, email=email,
                password_hash=hash_password(secrets.token_urlsafe(32)),
                role=role, created_by=inv.created_by, created_at=now, updated_at=now, is_active=True, is_locked=False,
                failed_login_attempts=0, sftp_enabled=True, sso_only=sso_only, sftp_password_auth=not sso_only)
    if inv.email:
        # The administrator wrote this address into the invitation. An address taken from the provider instead is
        # the provider's word, not the vault's, and stays unconfirmed.
        from app.core import email_confirmation
        email_confirmation.confirm(user, now=now)
    db.add(user)
    try:
        db.flush()             # surfaces a username or address taken meanwhile before the invitation is claimed
    except IntegrityError:
        db.rollback()
        raise Refusal(INVITATION_UNUSABLE, "race_conflict")
    claimed = db.query(AccountInvitation).filter(
        AccountInvitation.id == inv.id, AccountInvitation.accepted_at.is_(None),
        AccountInvitation.revoked_at.is_(None), AccountInvitation.expires_at > now,
    ).update({"accepted_at": now, "accepted_user_id": user.id}, synchronize_session=False)
    if claimed != 1:
        db.rollback()          # a lost race or a revoke in the window: the flushed account goes with it
        raise Refusal(INVITATION_UNUSABLE, "claim_lost")
    grant_default_permissions_for_role(str(user.id), user.role, db, commit=False)
    inviter_name = None
    if role == RoleEnum.ADMIN:
        inviter = (db.query(User).filter(User.id == inv.created_by).first() if inv.created_by else None)
        inviter_name = inviter.username if inviter is not None else "an administrator since deleted"
        try:
            api._record_admin_grant(db, user, by=inviter, by_name=inviter_name, inherited=inv.inviter_lineage)
        except Exception:      # noqa: BLE001 -- the promotion rules refused (the auditor right): no account
            db.rollback()
            raise Refusal(INVITATION_UNUSABLE, "promotion_refused")
    identity = link_identity(db, row, user, answer, linked_by="invitation")
    return Resolution(user, identity, created=True, linked_now=True, linked_by="invitation", invitation=inv,
                      inviter_name=inviter_name)


def would_do(db, row, answer: ProviderAnswer, tester=None) -> dict:
    """For a test sign-in: the restriction's verdict and, in words, what a sign-in would do with this identity;
    nothing is written."""
    verdict = restriction_of(db, row, answer)
    if verdict is not None:
        return {"restriction": verdict,
                "would": "refuse: " + ("the restriction excludes this person" if verdict == RESTRICTED
                                       else "the token lacks the claim the restriction needs")}
    identity = known_identity(db, row, answer)
    if identity is not None:
        return {"restriction": "passes",
                "would": ("sign in the linked account" if tester is not None and identity.user_id == tester.id
                          else "sign in another account this identity is linked to")}
    policy = policy_of(row)
    if policy["sso_account_creation"] == "jit":
        if sso_policy.is_restricted(policy, _api()._account_policy(db)):
            name = username_for(db, row, answer)
            return {"restriction": "passes",
                    "would": (f"create the account {name} at the first sign-in and sign it in" if name
                              else "refuse: no usable username could be made from the provider's answer")}
        return {"restriction": "passes", "would": "refuse: account creation at the first sign-in needs a restricted provider"}
    try:
        match = _email_match(db, row, answer, policy)
    except Refusal as refused:
        if refused.detail == ADDRESS_NOT_CONFIRMED:
            return {"restriction": "passes", "would": (
                "refuse: an account holds this address, but the vault never confirmed it is that account's (an "
                "administrator or an invitation sets an address, or its owner confirms it with an emailed code)")}
        return {"restriction": "passes", "would": "refuse: the account that owns this address is " + (
            "an administrator" if refused.detail.endswith("administrator") else "holding the auditor right") +
            "; it links only from its own signed-in profile"}
    if match is not None:
        return {"restriction": "passes",
                "would": f"link the account {match.username} by its verified email address and sign it in"}
    return {"restriction": "passes", "would": "refuse: no account is linked to this identity, and none would be made or linked"}


def link_refusal(db, row, user, answer: ProviderAnswer) -> None:
    """Raise :class:`Refusal` when ``answer``'s identity cannot be linked to ``user``: it already belongs to
    another account, or the account already has an identity on this provider."""
    from app.core.models import ExternalIdentity
    _password_less_refusal(db, row, user)
    existing = subject_owner(db, row, answer)
    if existing is not None and (existing.user_id != user.id or known_identity(db, row, answer) is None):
        raise Refusal(ALREADY_LINKED)         # another account's, or this account's under another tenant
    if existing is None and db.query(ExternalIdentity.id).filter(ExternalIdentity.provider_id == row.id,
                                                                  ExternalIdentity.user_id == user.id).first() is not None:
        raise Refusal(NOT_THIS_ACCOUNT, "this account already has an identity on the provider")


def link_identity(db, row, user, answer: ProviderAnswer, *, linked_by: str):
    """Link ``answer``'s identity to ``user``: refused when the subject already belongs to another account, or
    the account already has an identity on this provider. In the caller's transaction."""
    from app.core.models import ExternalIdentity
    _password_less_refusal(db, row, user)
    existing = subject_owner(db, row, answer)
    if existing is not None:
        if existing.user_id == user.id and known_identity(db, row, answer) is not None:
            return existing
        raise Refusal(ALREADY_LINKED)         # another account's, or this account's under another tenant
    mine = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row.id,
                                             ExternalIdentity.user_id == user.id).first()
    if mine is not None:
        raise Refusal(NOT_THIS_ACCOUNT, "this account already has an identity on the provider")
    import uuid
    identity = ExternalIdentity(id=uuid.uuid4(), user_id=user.id, provider_id=row.id, issuer=answer.issuer,
                                subject=answer.subject, subject_source="oidc:sub", tenant_id=answer.tenant_id,
                                email_at_link=(answer.email[:320] if answer.email else None),
                                display_name=answer.display_name, linked_at=datetime.utcnow(), linked_by=linked_by,
                                last_sign_in_at=None)
    db.add(identity)
    return identity


def _password_less_refusal(db, row, user) -> None:
    """A provider whose people hold no password (``sso_password_login`` disabled) never takes an administrator's or
    an auditor's account: those keep a local password for the fixed step-ups (app/core/sso_only.py)."""
    from app.core import privileged_accounts
    if policy_of(row)["sso_password_login"] != "disabled":
        return
    kind = privileged_accounts.kind(db, user)
    if kind is not None:
        raise Refusal(PRIVILEGED_ON_PASSWORD_LESS, kind)


def test_summary(db, row, answer: ProviderAnswer, tester) -> dict:
    """What an administrator reads after a test sign-in: the claim names (never the values but the tester's own
    identifiers), the proofs the token carried, and what the vault would do with this identity."""
    from app.services import sso_providers
    return {
        "outcome": "ok", "at": datetime.utcnow().isoformat() + "Z", "tester": tester.username,
        "claim_names": sorted(str(k) for k in answer.claims.keys()),
        "auth_time_present": answer.auth_time is not None, "amr": answer.amr, "acr": answer.acr,
        "email_verified": answer.email_verified, "email_present": answer.email is not None,
        "groups": _group_names(row, answer), "subject_length": len(answer.subject),
        "mfa_trusted": mfa_trusted(row, answer), **would_do(db, row, answer, tester),
        # The connection settings this sign-in passed with: a provider is turned on only while they still stand.
        "config": sso_providers.fingerprint(row),
    }


def _group_names(row, answer: ProviderAnswer) -> list:
    return sorted(answer.groups or [])[:200]


def pipeline_result(db, row, user, answer: ProviderAnswer, *, provider_id: str, client_ip: Optional[str],
                    linked_by_email_now: bool = False):
    """The pipeline's result for a provider sign-in: the provider is the first proof (``amr`` carries what the
    vault proved itself, nothing from the provider); the provider's MFA counts as the second factor only when the
    provider's policy trusts the values the token carried.

    ``linked_by_email_now``: this very sign-in linked the identity to the account by its email address. The
    provider's word alone put it there, so its MFA does not also stand in for the account's own second factor this
    once: an account with a factor in effect is asked for it, which is what stops an address taken over at the
    provider. From the next sign-in the identity is a known one and the policy applies as written."""
    from app.services.sign_in import SignInResult
    policy = policy_of(row)
    return SignInResult(user, [], client_ip, provider_id=provider_id,
                        provider_mfa_trusted=mfa_trusted(row, answer) and not linked_by_email_now,
                        provider_auth_time=answer.auth_time,
                        provider_sid=answer.sid, provider_sub=answer.subject,
                        provider_logout_hint=answer.id_token if policy["sso_idp_logout"] else None)


def reauth_refusal(db, row, user, answer: ProviderAnswer, *, now=None) -> None:
    """Raise :class:`Refusal` unless ``answer`` is a fresh sign-in of ``user``'s own identity at ``row``: the
    identity the token names must be the account's, the provider must say the person authenticated within the
    last minute (``auth_time``; a provider that sends none cannot re-authenticate), and, when the provider's MFA
    is trusted, the token must carry an accepted value."""
    identity = known_identity(db, row, answer)
    if identity is None or str(identity.user_id) != str(user.id):
        raise Refusal(NOT_THIS_ACCOUNT)
    now = now or datetime.now(timezone.utc)
    if answer.auth_time is None or not (0 <= (now - answer.auth_time).total_seconds() <= REAUTH_MAX_AGE_SECONDS):
        raise Refusal(REAUTH_STALE)
    if policy_of(row)["sso_trust_idp_mfa"] and not mfa_trusted(row, answer):
        raise Refusal(REAUTH_NO_MFA)


def _has_identities(db) -> bool:
    """Whether the database has the identities table (a database built only with the tables a test needs may not)."""
    from app.services import sign_in
    return sign_in.table_present(db, "external_identities")


def reauth_available(db, user) -> bool:
    """Whether a provider re-authentication may be offered to ``user`` for a step-up: an enabled provider the
    account has an identity on, whose last test sign-in carried ``auth_time`` (without it no freshness can be
    judged). False where the database holds no identities at all."""
    return bool(reauth_providers(db, user))


def reauth_providers(db, user) -> list:
    """The providers that may confirm ``user`` afresh (see :func:`reauth_available`), in the sign-in page's order."""
    from app.core.models import ExternalIdentity, SsoProvider
    if user is None or getattr(user, "id", None) is None or not _has_identities(db):
        return []
    found = []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if provider is not None and reauth_offered(provider) and provider not in found:
            found.append(provider)
    return sorted(found, key=lambda p: (getattr(p, "sort_order", 0) or 0, (p.label or p.name or "").lower()))


def reauth_offered(row) -> bool:
    last_test = getattr(row, "last_test", None) or {}
    return (getattr(row, "state", None) == "enabled" and getattr(row, "kind", None) == "oidc"
            and isinstance(last_test, dict) and last_test.get("auth_time_present") is True)


def renewal_refusal(db, user, provider_id, *, methods=(), now: Optional[datetime] = None) -> Optional[str]:
    """Why a session that came through the provider ``provider_id`` (its token's ``idp``) is not renewed, as the
    sentence the sign-in screen shows, or None when it may be. A renewal keeps the provider's sign-in going, so it
    needs what that sign-in would need now: the identity still linked, the provider turned on, no refusal by the
    provider in force and its freshness window not run out (app/services/sso_freshness.py). A record that cannot be
    read (no such provider, a database without the tables) is a refusal: nothing vouches for the session.

    ``methods`` are the old token's proofs (its ``amr``). A sign-in through a provider is whole without the vault's
    own second factor only while the provider's is trusted; when the account needs a second factor, the token shows
    none of the vault's own and the provider's is not trusted now, signing in again would ask for the vault's, so
    the renewal is refused as the renewal rules refuse a password alone."""
    import uuid
    from app.core.models import ExternalIdentity, SsoProvider
    from app.services import sign_in, sso_freshness
    unlinked = ("Your account is no longer linked to the identity provider this sign-in came through. Sign in again.")
    try:
        row_id = uuid.UUID(str(provider_id))
    except (TypeError, ValueError):
        return unlinked
    if not (sign_in.table_present(db, "external_identities") and sign_in.table_present(db, "sso_providers")):
        return unlinked
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == row_id,
                                                 ExternalIdentity.user_id == user.id).first()
    if identity is None:
        return unlinked
    provider = db.query(SsoProvider).filter(SsoProvider.id == row_id).first()
    name = ((getattr(provider, "name", None) or "").strip() or (getattr(provider, "label", None) or "").strip()
            or "your identity provider")
    if provider is None or getattr(provider, "state", None) != "enabled":
        return f"Signing in through {name} is turned off. Sign in again another way, or ask an administrator."
    found = sso_freshness.deadline_of(identity, provider)
    now = now or datetime.utcnow()
    if found is not None and (found.refused or found.due <= now):
        return f"Sign in through {name} again to stay signed in."
    from app.api import api_server as api
    own_factor = set(methods or ()) & sign_in.SECOND_KINDS
    if not own_factor and not policy_of(provider)["sso_trust_idp_mfa"] and api._login_second_factor_in_effect(db, user):
        return "Signing in now needs your second factor; sign in again."
    return None


def provider_logout_url(db, session_row) -> Optional[str]:
    """Where the browser goes after a vault sign-out when the session's provider wants its own logout: the
    provider's end-session address with the ID token as the hint and the vault's sign-in page to come back to.
    None when the session was not a provider's, the option is off, the provider has no such address, the vault has
    no configured address to come back to, or anything fails: the vault's sign-out stands on its own."""
    if session_row is None:
        return None
    try:
        from urllib.parse import urlencode
        from app.core.models import SsoProvider, SsoSession
        from app.core.security import decrypt_secret
        come_back_to = post_logout_address()
        if come_back_to is None:
            return None
        sso_session = db.query(SsoSession).filter(SsoSession.session_id == session_row.id).first()
        if sso_session is None or not sso_session.id_token_enc:
            return None
        row = db.query(SsoProvider).filter(SsoProvider.id == sso_session.provider_id).first()
        if row is None or not policy_of(row)["sso_idp_logout"]:
            return None
        discovery = oc.discover(provider_config(row), fetch=oc.fetch_json)
        if not discovery.end_session_endpoint:
            return None
        import secrets
        query = urlencode({"id_token_hint": decrypt_secret(sso_session.id_token_enc),
                           "post_logout_redirect_uri": come_back_to, "state": secrets.token_urlsafe(16)})
        separator = "&" if "?" in discovery.end_session_endpoint else "?"
        return f"{discovery.end_session_endpoint}{separator}{query}"
    except Exception:  # noqa: BLE001
        return None


def verifier_hash_of(verifier: str) -> str:
    return hashlib.sha256(verifier.encode("utf-8")).hexdigest()
