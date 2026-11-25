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
LINK_FROM_PROFILE = "link_from_profile"
LINK_FROM_YOUR_ACCOUNT = "link_from_your_account"    # not linked on the provider's word; the owner links it
HELD_TO_A_PROVIDER = "held_to_a_provider"        # the account signs in through another provider only, for now
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
INVITATION_ADDRESS = "invitation_address"      # the invitation names an address the provider did not confirm
ADMINISTRATOR_INVITATION = "administrator_invitation"
EMAIL_REQUIRED = "email_required"
ACCOUNT_LIMIT = "account_limit"
USERNAME_UNAVAILABLE = "username_unavailable"

USERNAME_MIN, USERNAME_MAX = 3, 50          # the account rules (the creation and invitation schemas)

# What a person is told for each reason, in words (the admin page and the sign-in page show these).
# A fresh sign-in that was to confirm an unlink and did not: said with what to do when it cannot.
UNLINK_OTHER_IDENTITY, UNLINK_NO_MFA, UNLINK_STALE = "unlink_other_identity", "unlink_no_mfa", "unlink_stale"

# The vault's own account was busy (its turn was held by a change of it): nothing of the provider's.
BUSY = "busy"

REASON_TEXTS = {
    oc.PROVIDER_ERROR: "Your organisation's sign-in did not complete. Try again, or contact your administrator.",
    oc.ISSUER_MISMATCH: "The sign-in answer did not come from the configured provider.",
    oc.TOKEN_INVALID: "The sign-in answer could not be verified.",
    oc.SIGNING_KEY_TOO_SHORT: ("Your organisation's sign-in signs its answers with a key this vault does not "
                               "accept. Tell your administrator."),
    oc.NONCE_MISMATCH: "The sign-in answer did not belong to this sign-in. Start again.",
    oc.ENDPOINT_REFUSED: "The provider's address is not one the vault may call. Contact your administrator.",
    oc.TEMPORARILY_UNAVAILABLE: "The provider could not be reached. Try again in a moment.",
    # The provider was reached; the vault's own account was being changed (app/services/sign_in.py, BUSY).
    BUSY: "Signing in is busy right now. Try again in a moment.",
    oc.DISCOVERY_INVALID: "The provider's configuration could not be read. Contact your administrator.",
    STATE_UNKNOWN: "This sign-in is unknown or has expired. Start again.",
    PROVIDER_MIX_UP: "The sign-in answer came back for another provider. Start again.",
    PROVIDER_DISABLED: "This sign-in method is not available.",
    # Said for every refusal with no account linked (the provider makes no accounts and nobody invited the person, or
    # the account with the address never had it confirmed), so it says nothing of whether an account exists. An
    # invitation for an address already in use is refused: someone with an account links from it instead, which
    # needs no confirmed address.
    NO_ACCOUNT: ("Your organisation's sign-in worked, but no account here is linked to it. If you already have an "
                 "account on this vault, sign in to it the way you usually do and link your organisation's sign-in "
                 "under Your account (Single sign-on). Otherwise ask an administrator to invite you."),
    ACCOUNT_DISABLED: "Your account cannot sign in. Contact your administrator.",
    ALREADY_LINKED: "That organisation identity is already linked to an account.",
    LINK_FROM_PROFILE: ("An account with your address is protected by its own second factor, so it is not linked on "
                        "your organisation's word alone. Sign in with your password, then link your organisation's "
                        "sign-in under Your account."),
    LINK_FROM_YOUR_ACCOUNT: ("This sign-in is not linked to an account here. If you have an account, sign in to it "
                             "the way you usually do, then link your organisation's sign-in under Your account. If "
                             "you have none, ask your administrator."),
    HELD_TO_A_PROVIDER: ("An account with your address signs in only through the sign-in it already uses, until "
                         "it has signed in there again, so no other sign-in is linked to it now. Use that sign-in, "
                         "or ask your administrator."),
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
    # The same three refusals where the fresh sign-in was to confirm an unlink (:func:`said_for_an_unlink`). A
    # person whose provider can no longer confirm them (their account there was made anew, or signs in without
    # the second factor the vault trusts) would start again for ever: they are told who can unlink it for them.
    UNLINK_OTHER_IDENTITY: ("Your organisation's sign-in came back as another identity than the one linked to "
                            "your account, so it does not confirm the unlink. If you cannot sign in there as the "
                            "linked identity, ask an administrator to unlink it for you."),
    UNLINK_NO_MFA: ("Your organisation's sign-in did not confirm you with a second factor, so it does not confirm "
                    "the unlink. Start again. If you cannot, ask an administrator to unlink it for you."),
    UNLINK_STALE: ("Your organisation's sign-in did not ask you to sign in again just now, so it does not confirm "
                   "the unlink. Start again. If you cannot, ask an administrator to unlink it for you."),
    RESTRICTED: ("Your organisation's sign-in worked, but this vault is not open to your tenant, domain or group. Ask "
                 "your administrator."),
    RESTRICTION_CLAIM_MISSING: ("Your organisation's sign-in did not say which tenant, domain or groups you belong to, "
                                "so the vault could not check who it admits. Ask your administrator."),
    INVITATION_UNUSABLE: "This invitation can no longer be used. Ask your administrator for a new one.",
    INVITATION_ADDRESS: ("This invitation was made for an email address that your organisation's sign-in did not "
                         "confirm as yours. Open the invitation again and choose a password there; you can link "
                         "your organisation's sign-in from Your account afterwards."),
    ADMINISTRATOR_INVITATION: ("An administrator's invitation is accepted with a password: an administrator types it at "
                               "every sign-in. Open the invitation again and choose a password there. Where your "
                               "organisation's sign-in lets accounts keep a password, you can link it from Your "
                               "account afterwards."),
    EMAIL_REQUIRED: ("Your organisation's sign-in did not provide a verified email address, and this vault requires "
                     "one for a new account. Ask your administrator."),
    ACCOUNT_LIMIT: "This vault cannot take another account right now. Ask your administrator.",
    USERNAME_UNAVAILABLE: ("No usable username could be made for you from what your organisation's sign-in provided. "
                           "Ask your administrator to invite you."),
}


class Refusal(Exception):
    """``about``: the account a refusal kept the sign-in away from, when there is one. It is for the vault's own
    notices to that account; nothing of it is shown to the person at the provider."""

    def __init__(self, code: str, detail: str = "", about=None):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail
        self.about = about


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
    sid = kept_sid(claims.get("sid"))
    hosted = claims.get(claim_name(row, "domain", "hd"))
    groups_name = claim_name(row, "groups", "groups")
    raw_groups = claims.get(groups_name)
    if isinstance(raw_groups, str) and raw_groups:
        # A provider that sends one value as a text and several as a list (AD FS does): a person in exactly one
        # group is in that group. Read as "no group information", the mappings were never applied for them, and
        # the administrators were told each day to check the provider's token.
        raw_groups = [raw_groups]
    # Each as it was sent, whole. A name longer than a mapping can hold matches no mapping, and is left out:
    # cut to that length, it matched a mapped name that was only its beginning.
    groups = ([str(g) for g in raw_groups if isinstance(g, (str, int)) and not isinstance(g, bool)
               and len(str(g)) <= GROUP_NAME_MAX]
              if isinstance(raw_groups, list) else None)
    names = claims.get("_claim_names")
    overage = isinstance(names, dict) and groups_name in names     # a marker makes any list beside it partial
    if groups is not None and len(groups) > GROUPS_KEPT:
        # More groups than the vault reads: "too many to say", as the provider's own marker says it. Cut to the
        # first thousand and read as the whole membership, a person whose mapped group came after them left its
        # department at that sign-in, an administrator approved through it was demoted, and a provider that
        # requires the group refused them: a list that is not whole never means "member of nothing".
        groups, overage = None, True
    return ProviderAnswer(claims=claims, subject=str(claims["sub"]), issuer=str(claims["iss"]), tenant_id=tenant,
                          email=email, email_verified=claims.get(verified_name) is True, display_name=display,
                          auth_time=auth_time, amr=amr, acr=acr if isinstance(acr, str) else None,
                          sid=sid, id_token=tokens.id_token,
                          hosted_domain=hosted.strip()[:255] if isinstance(hosted, str) and hosted.strip() else None,
                          groups=groups, groups_overage=overage)


# The width of the column a provider's session id is kept in (sso_sessions.idp_sid).
SID_WIDTH = 255


def kept_sid(sid) -> Optional[str]:
    """A provider's session id as the vault keeps it, or None for what is no session id. OpenID Connect sets no
    limit on its length and the column has one: an id that fits is kept as it is, a longer one as its SHA-256 in
    a marked form. Kept whole, a long id failed the commit of every sign-in through that provider, and an account
    with no password it can type had no other way in. The same form is made wherever an id comes in (a sign-in's
    ID token, a logout token), so a provider's logout still finds the session it names."""
    if not isinstance(sid, str) or not sid:
        return None
    if len(sid) <= SID_WIDTH:
        return sid
    import hashlib
    return "sha256:" + hashlib.sha256(sid.encode("utf-8")).hexdigest()


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


# How many of the provider's groups an invitation's acceptance keeps while it waits for its tab. More than this is
# kept as "too many to say" (as the provider's own overage marker): the mappings are then not applied, and never
# read as "member of nothing".
GROUPS_KEPT = 1000
GROUP_NAME_MAX = 255                 # what a mapping can hold (sso_group_mappings.GROUP_MAX, the column's width)


def held_invitation(row, answer: ProviderAnswer, *, invitation_id, provider_id, client_ip, began_at, verifier_hash,
                    code_challenge, purpose):
    """What the one-time sign-in code holds for an invitation that is being accepted through ``row``, until the
    tab that started the sign-in redeems it (app/core/sign_in_codes.Handover): the invitation, what the provider
    said of the person (the identity's key and display data, the groups; never a token but the provider's logout
    hint, encrypted, where the provider's logout wants it), and what the sign-in that follows the acceptance
    carries. No account: there is none yet."""
    from app.core import sign_in_codes
    groups, overage = answer.groups, bool(answer.groups_overage)
    if groups is not None and len(groups) > GROUPS_KEPT:
        groups, overage = None, True
    kept = {**answer_record(answer), "groups": None if groups is None else [str(g) for g in groups],
            "groups_overage": overage}
    return sign_in_codes.Handover(
        user_id="", methods=[], client_ip=client_ip, provider_id=str(provider_id),
        provider_mfa_trusted=bool(mfa_trusted(row, answer)), purpose=purpose, verifier_hash=verifier_hash,
        code_challenge=code_challenge, provider_sid=answer.sid, provider_sub=answer.subject,
        provider_logout_hint_enc=sign_in_codes._encrypted(answer.id_token if policy_of(row)["sso_idp_logout"] else None),
        provider_auth_time=int(answer.auth_time.timestamp()) if answer.auth_time is not None else None,
        provider_answered_at=began_at,
        invitation={"invitation_id": str(invitation_id), "answer": kept})


def answer_of_an_invitation(record: dict) -> ProviderAnswer:
    """The provider's answer an invitation's acceptance kept (:func:`held_invitation`)."""
    kept = record["answer"]
    answer = answer_from_record(kept)
    groups = kept.get("groups")
    answer.groups = [str(g) for g in groups] if isinstance(groups, list) else None
    answer.groups_overage = bool(kept.get("groups_overage"))
    return answer


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
                                  account_policy=account_policy, hosted_domain_only=hosted_domain_only(row))


GOOGLE_ISSUER = "https://accounts.google.com"


def hosted_domain_only(row) -> bool:
    """Whether ``row``'s domain list is judged on the provider's hosted-domain claim alone: Google, whatever the row
    says of its claims (it signs consumer accounts and Workspace accounts as one issuer, and tells them apart by
    ``hd`` only), and any provider whose row names such a claim. A provider with no such claim has only the
    verified address to go by, and there the address's domain is judged."""
    claims = getattr(row, "claims", None)
    named = claims.get("domain") if isinstance(claims, dict) else None
    if isinstance(named, str) and named.strip():
        return True
    return (getattr(row, "issuer", None) or "").strip().rstrip("/").lower() == GOOGLE_ISSUER


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
    linked_by: Optional[str] = None       # invitation | email (by verified email) | jit
    password_stopped: bool = False        # the link made the account sign in only through its provider
    invitation: object = None             # the invitation accepted, when one was
    inviter_name: Optional[str] = None    # for an administrator's invitation: who made it


def resolve_account(db, row, answer: ProviderAnswer) -> Resolution:
    """Who the person is, for a sign-in, by the provider's answer alone, in the design's order: a known identity;
    creation at the first sign-in when the provider makes accounts; an active account that is not an
    administrator with this verified email, when the provider links by email and is restricted; otherwise
    ``NO_ACCOUNT``. The restriction was judged by the caller first. What the creation and email steps write stays
    in the caller's transaction; the caller commits.

    Everything here is decided by what the provider said, never by whoever started the sign-in: the account that
    is made or linked is the provider identity's own. So it may be written at the callback, whichever browser
    reaches it (a start URL can be handed to anyone). An invitation is the starter's choice, and is not accepted
    here: :func:`judge_invitation` at the callback, :func:`accept_invitation` where the tab that started the
    sign-in has proved itself."""
    from app.core.models import User
    identity = known_identity(db, row, answer)
    if identity is not None:
        user = db.query(User).filter(User.id == identity.user_id).first()
        if user is None:
            raise Refusal(NO_ACCOUNT)
        if not account_usable(user):
            raise Refusal(ACCOUNT_DISABLED, about=user)
        if identity.tenant_id is None and answer.tenant_id:
            identity.tenant_id = answer.tenant_id      # linked before the provider named a tenant: pinned from now on
        return Resolution(user, identity)
    policy = policy_of(row)
    # An account the person already has comes before one made for them: where the provider links by address, the
    # account that holds the verified address is linked, or the sign-in is refused for the reason that account
    # gives. Tried after the creation, the link never ran where both were on: every existing person was given a
    # second account at their first sign-in.
    if policy["sso_link_by_email"]:
        linked = _link_by_email(db, row, answer, policy)
        if linked is not None:
            return linked
    if policy["sso_account_creation"] == "jit":
        made = _create_account(db, row, answer, policy)
        if made is not None:
            return made
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
    if not sso_policy.is_restricted(policy, account_policy, issuer=getattr(row, "issuer", None)):
        return None
    if subject_owner(db, row, answer) is not None:
        raise Refusal(ALREADY_LINKED, "subject_linked_elsewhere")     # the same subject, pinned to another tenant
    holder = address_holder(db, answer)
    if holder is not None:
        # The verified address is written on an account already. No second account is made for it: the person
        # signs in to the account they have and links the provider there. (Made all the same, the new account
        # carried no address, or was refused for want of one the provider had in fact sent, and the provider's
        # identity could no longer be linked to the real account.) Where that account never confirmed the address
        # it may not be this person's at all: the administrators are told, who can correct it.
        from app.core import email_confirmation
        raise Refusal(LINK_FROM_YOUR_ACCOUNT, (ADDRESS_HAS_AN_ACCOUNT if email_confirmation.confirmed(holder)
                                               else ADDRESS_ON_AN_UNCONFIRMED_ACCOUNT), about=holder)
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
    # Made here, with a password nobody knows: the account signs in only through its provider, whatever the
    # provider's password setting, unless the provider lets such accounts set one (app/core/sso_only.py).
    sso_only = made_here_is_provider_only(row)
    now = datetime.utcnow()
    user = User(id=_uuid.uuid4(), username=username, email=email, password_hash=hash_password(secrets.token_urlsafe(32)),
                role=role, created_by=None, created_at=now, updated_at=now, is_active=True, is_locked=False,
                failed_login_attempts=0, sftp_enabled=True, sso_only=sso_only, sftp_password_auth=not sso_only)
    _password_is_nobodys(user, now)
    db.add(user)
    try:
        db.flush()
    except IntegrityError:
        db.rollback()
        raise Refusal(USERNAME_UNAVAILABLE, "race_conflict")
    grant_default_permissions_for_role(str(user.id), user.role, db, commit=False)
    identity = link_identity(db, row, user, answer, linked_by="jit")
    return Resolution(user, identity, created=True, linked_now=True, linked_by="jit")


# The audit's words for a first sign-in refused because the provider's verified address is written on an account.
ADDRESS_HAS_AN_ACCOUNT = "address_has_an_account"
ADDRESS_ON_AN_UNCONFIRMED_ACCOUNT = "address_on_an_unconfirmed_account"


def address_holder(db, answer: ProviderAnswer):
    """The account the provider's verified address is written on, whatever its state, or None (no verified
    address, or nobody's)."""
    from app.core.email_identity import find_user_by_email
    email = usable_email(answer.email) if answer.email_verified else None
    return find_user_by_email(db, email) if email is not None else None


def _password_is_nobodys(user, now) -> None:
    """An account made through a provider holds a hash of random bytes: a password that is not its owner's. It is
    marked as one somebody else set (app/core/password_origin.py), so that the rules for such a password apply:
    made an administrator later, the account's password is taken back and the person is sent a link to choose
    one, where an administrator must type it at every sign-in; and until the person has chosen one, the account
    approves no held change. The mark goes when the person sets a password of their own."""
    from app.core import password_origin
    password_origin.set_by_other(user, None, now)
    password_origin.mark_nobody_knows(user)       # and nobody can type it: the account is asked for none


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
    address verified by the provider, owned by exactly one active account that is not an administrator, holds no
    second factor of its own and has no identity on this provider yet, and confirmed for that account by the vault
    itself (an administrator or an invitation set it, or the person typed the code sent there:
    app/core/email_confirmation.py).

    The last condition is the vault's side of "verified". Without it, anyone with an account could write a
    colleague's address on their own account (a change of one's own address asks for the current password, not
    for a code, unless the administrator turned that on) and wait: the colleague's first sign-in through the
    provider would be linked to that account, and every later one would land there."""
    from app.core import email_confirmation, privileged_accounts
    from app.core.email_identity import find_user_by_email
    from app.core.models import ExternalIdentity
    api = _api()
    account_policy = api._account_policy(db) if policy["sso_use_signup_domains"] else None
    if not sso_policy.is_restricted(policy, account_policy, issuer=getattr(row, "issuer", None)):
        return None
    email = usable_email(answer.email) if answer.email_verified else None
    if email is None or not sso_policy.address_admitted(policy, email):
        return None                  # the hosted-domain claim admits the sign-in; the address must be on the list too
    if account_policy is not None:
        # The vault's sign-up list is what restricts this provider. Where a hosted-domain claim admitted the
        # sign-in, the address has not been judged yet: it must be on that list itself, as for a new account,
        # or a member of the organisation would reach the account behind any address they hold at the provider.
        from app.core.account_policy import email_allowed_by_domain_gate
        if not email_allowed_by_domain_gate(email, account_policy.get("signup_email_domain_mode"),
                                            account_policy.get("signup_email_domains")):
            return None
    user = find_user_by_email(db, email)
    if user is None or not account_usable(user):
        return None
    kind = privileged_accounts.kind(db, user)
    if kind is not None:
        # An administrator, or an account with the auditor right (open), reaches other people's vaults: a takeover of
        # its address at the provider must not reach it silently. It links only from its own profile, under step-up.
        # The reason says that, in words that fit anyone the vault does not link: the restriction's own sentence
        # told an administrator in the admitted tenant that the vault was not open to their tenant.
        raise Refusal(LINK_FROM_YOUR_ACCOUNT, f"{PRIVILEGED_ACCOUNT}:{kind}", about=user)
    if not email_confirmation.confirmed(user):
        raise Refusal(NO_ACCOUNT, ADDRESS_NOT_CONFIRMED)
    from app.services import sso_freshness
    if sso_freshness.held_to_a_provider(db, user) is not None:
        # The account's sign-in through a provider it is linked to has lapsed, or that provider refused the
        # person, and it closes the other ways in until the person has signed in there again
        # (app/services/sso_freshness.py). A link made here would be another way in: the sign-in that made it
        # would finish as a provider's own, which is let in. Refused as the link from Your account is. Asked
        # before the account's own factor: an account that is held and has one was sent to sign in with its
        # password and link from its profile, and both are refused for it while it is held.
        raise Refusal(HELD_TO_A_PROVIDER, HELD_ACCOUNT, about=user)
    if set_up_its_own_factor(db, user):
        # The account set up a second factor of its own. A link made here would stand before that factor is given:
        # the identity is on the account from the moment the provider answered (and at a provider whose people hold
        # no password, the account's password is gone with it), and whoever holds the address at the provider
        # could leave the first sign-in at the account's factor, start a second one through the link now made, and
        # be asked for nothing of the account's. Such an account links the provider from its own profile, where
        # its own sign-in and its own factor stand behind the link.
        raise Refusal(LINK_FROM_PROFILE, HOLDS_A_FACTOR, about=user)
    if db.query(ExternalIdentity.id).filter(ExternalIdentity.provider_id == row.id,
                                            ExternalIdentity.user_id == user.id).first() is not None:
        return None          # the account's identity on this provider is another one: an administrator sorts it out
    return user


# The audit's word for a link by email refused because the account reaches other people's vaults by its standing.
PRIVILEGED_ACCOUNT = "privileged_account"

# The audit's word for a link by email refused because the vault never confirmed the account's address.
ADDRESS_NOT_CONFIRMED = "address_not_confirmed"
# The audit's word for a link by email refused because the account holds a second factor of its own (the reason
# shown is LINK_FROM_PROFILE: it is linked from its own profile only).
HOLDS_A_FACTOR = "account_holds_a_factor"
# The audit's word for a link by email refused because the account is held to another provider's sign-in.
HELD_ACCOUNT = "account_held_to_its_provider"
# How an identity linked by its verified email address is recorded (external_identities.linked_by): nobody at the
# vault asked for such a link, the provider's word put it on the account.
LINKED_BY_EMAIL = "email"


def set_up_its_own_factor(db, user) -> bool:
    """For the link by email: whether the account set up a second factor of its own, also while that factor is
    between two states. It did when it holds an authenticator; when it holds any passkey that was not retired,
    whether or not passkeys are switched on now (switched off they are no factor for a sign-in, and are one
    again the day they are switched back on); and when an administrator reset its second factor and it has not
    set the next one up yet (``second_factor_reset_at``: the next one is to be set up behind the account's own
    password). What a sign-in can be asked for right now (app/core/active_factors.py) is less than that: an
    account in between would be linked on the provider's word and its next factor set up by whoever holds its
    address there."""
    if getattr(user, "second_factor_reset_at", None) is not None:
        return True
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    from app.core.table_presence import has_table
    if db.query(SecondFactorEnrollment.id).filter(SecondFactorEnrollment.user_id == user.id,
                                                  SecondFactorEnrollment.status == "active").first() is not None:
        return True
    if not has_table(db, WebAuthnCredential.__tablename__):
        return False
    return db.query(WebAuthnCredential.id).filter(WebAuthnCredential.user_id == user.id,
                                                  WebAuthnCredential.retired_at.is_(None)).first() is not None


def _link_by_email(db, row, answer: ProviderAnswer, policy: dict):
    user = _email_match(db, row, answer, policy)
    if user is None:
        return None
    # The turn before the flag is read: what the link ends is told from the flag as it is committed.
    decide_in_the_accounts_turn(db, user)
    had_password = not getattr(user, "sso_only", False)
    identity = link_identity(db, row, user, answer, linked_by=LINKED_BY_EMAIL)
    return Resolution(user, identity, linked_now=True, linked_by=LINKED_BY_EMAIL,
                      password_stopped=had_password and bool(getattr(user, "sso_only", False)))


def judge_invitation(db, row, answer: ProviderAnswer, invitation_id, *, lock: bool = False):
    """Whether the invitation ``invitation_id`` may be accepted with this answer of the provider's, and with what:
    (the invitation, the account's address, its role, the provider's policy, now). Nothing is written. The checks
    are the password acceptance's (app/api/api_server.py, accept_invite), in its order; each refusal is a reason
    here, its detail the audit's reason word. The person can type nothing in this flow, so a required address the
    provider did not verify is a refusal rather than a prompt.

    An invitation that names an address names a person: it is accepted only where the provider says, verified,
    that the person at the provider holds that address. Anyone at the provider could otherwise finish the
    acceptance as the invited person; an invitation without an address rests on the tab that started it alone.

    ``lock``: hold the inviter's row until the transaction ends (the acceptance does; a look at the callback
    does not)."""
    import uuid as _uuid
    from app.core.email_identity import email_in_use
    from app.core.models import AccountInvitation, RoleEnum
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
    if not api._invitation_inviter_can_act(db, inv, lock=lock):
        raise Refusal(INVITATION_UNUSABLE, "inviter_not_admin")
    if api._username_kept(inv.username):
        raise Refusal(INVITATION_UNUSABLE, "username_reserved")
    if subject_owner(db, row, answer) is not None:
        raise Refusal(ALREADY_LINKED, "subject_linked_elsewhere")     # the same subject, pinned to another tenant
    policy = policy_of(row)
    if inv.email:
        if email_in_use(db, inv.email):
            raise Refusal(INVITATION_UNUSABLE, "email_in_use")
        said = usable_email(answer.email) if answer.email_verified else None
        if said is None or said != usable_email(inv.email):
            raise Refusal(INVITATION_ADDRESS, "address_not_confirmed" if said is None else "another_address")
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
    if role == RoleEnum.ADMIN:
        # An administrator types the account's password at every sign-in, after any provider. An account made here
        # holds a password nobody knows, so the new administrator could never finish one. The invitation is
        # accepted with the form, where the person chooses the password; the provider is linked afterwards. (This
        # also keeps every administrator off a provider whose people hold no password.)
        raise Refusal(ADMINISTRATOR_INVITATION, "administrator_invitation")
    return inv, email, role, policy, now


def accept_invitation(db, row, answer: ProviderAnswer, invitation_id) -> Resolution:
    """Accept the invitation with this answer of the provider's: the invited account is made now, with the
    invitation's username and role, a real password hash nobody knows (the person signs in through the provider;
    a password is set through a reset), and this identity; the invitation is claimed once. Judged first, again
    (:func:`judge_invitation`), in the caller's transaction, which the caller commits.

    Called only where the tab that started the sign-in has proved itself, by redeeming the one-time code with
    its verifier (app/api/sso_router.py, finish_invitation). The invitation is the starter's; the browser that
    reaches the provider's callback may be anybody's, so nothing of this is written there."""
    import secrets
    import uuid as _uuid
    from sqlalchemy.exc import IntegrityError
    from app.core.endpoint_permissions import grant_default_permissions_for_role
    from app.core.models import AccountInvitation, RoleEnum, User
    from app.core.security import hash_password
    api = _api()
    inv, email, role, policy, now = judge_invitation(db, row, answer, invitation_id, lock=True)
    # Whether the account signs in only through the provider is the one rule's to say, where the identity is
    # linked below (link_identity settles the account, told that it came by an invitation): a provider whose
    # people hold no password, or one that does not let the accounts it makes set one, holds it; an account
    # that must keep a password of its own (an administrator) is never held. Written here first for the provider
    # whose people hold none, as the row is made.
    sso_only = policy["sso_password_login"] == "disabled"
    user = User(id=_uuid.uuid4(), username=inv.username, email=email,
                password_hash=hash_password(secrets.token_urlsafe(32)),
                role=role, created_by=inv.created_by, created_at=now, updated_at=now, is_active=True, is_locked=False,
                failed_login_attempts=0, sftp_enabled=True, sso_only=sso_only, sftp_password_auth=not sso_only)
    _password_is_nobodys(user, now)
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


def invitation_takes_a_provider(inv) -> bool:
    """Whether ``inv`` may be accepted through a provider: any invitation but an administrator's, which is accepted
    with the form (``ADMINISTRATOR_INVITATION``): an administrator types the account's password at every sign-in, and
    an account made at a provider's callback holds a password nobody knows. The start refuses it before the person is
    sent to the provider, and the invitation page offers no provider for it."""
    return str(getattr(inv, "role", "")) != "admin"


def made_here_is_provider_only(row) -> bool:
    """Whether an account made at its first sign-in through ``row`` signs in only through its provider: the
    provider's people hold no password, or it does not let the accounts it makes set one."""
    from app.core import sso_only
    return sso_only.password_less(row) or sso_only.made_here_holds_no_password(row)


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
    if policy["sso_link_by_email"]:
        said = _would_link_by_email(db, row, answer, policy)
        if said is not None:
            return said
    if policy["sso_account_creation"] == "jit":
        account_policy = _api()._account_policy(db)
        if sso_policy.is_restricted(policy, account_policy, issuer=getattr(row, "issuer", None)):
            # What the sign-in itself refuses before it makes an account (_create_account), in its order: said
            # here too, so the summary of a test is what a first sign-in would meet. A provider that sends no
            # verified address was reported as "create the account", turned on, and then refused everybody.
            if subject_owner(db, row, answer) is not None:
                return {"restriction": "passes", "would": (
                    "refuse: this identity is linked to an account already, under another tenant of the provider")}
            if address_holder(db, answer) is not None:
                return {"restriction": "passes", "would": (
                    "refuse: an account here already holds this verified address, and no second one is made; its "
                    "owner signs in to it and links this provider under Your account")}
            if (_admitted_address(db, answer, policy, account_policy) is None
                    and account_policy.get("email_requirement") == "required"):
                return {"restriction": "passes", "would": (
                    "refuse: accounts here need an email address, and the provider's answer carries none a new "
                    "account may have (none, one it does not mark as verified, one outside the allowed domains, "
                    "or one already in use)")}
            try:
                _api()._enforce_user_cap(db)
            except Exception:  # noqa: BLE001 -- the plan's refusal, whatever its words
                return {"restriction": "passes", "would": (
                    "refuse: this vault has reached the number of accounts it may hold")}
            name = username_for(db, row, answer)
            return {"restriction": "passes",
                    "would": (f"create the account {name} at the first sign-in and sign it in"
                              + (" (it signs in only through this provider)" if made_here_is_provider_only(row)
                                 else "") if name
                              else "refuse: no usable username could be made from the provider's answer")}
        return {"restriction": "passes", "would": "refuse: account creation at the first sign-in needs a restricted provider"}
    return {"restriction": "passes", "would": "refuse: no account is linked to this identity, and none would be made or linked"}


def _would_link_by_email(db, row, answer: ProviderAnswer, policy: dict) -> Optional[dict]:
    """For a test sign-in: what the link by address would do with this answer, or None when it would do nothing
    (the sign-in then goes on to the next step, as :func:`resolve_account` does)."""
    try:
        match = _email_match(db, row, answer, policy)
    except Refusal as refused:
        if refused.detail == ADDRESS_NOT_CONFIRMED:
            return {"restriction": "passes", "would": (
                "refuse: an account holds this address, but the vault never confirmed it is that account's (an "
                "administrator or an invitation sets an address, or its owner confirms it with an emailed code)")}
        if refused.detail == HOLDS_A_FACTOR:
            return {"restriction": "passes", "would": (
                "refuse: the account that owns this address set up its own second factor; its owner links this "
                "provider under Your account")}
        if refused.detail == HELD_ACCOUNT:
            return {"restriction": "passes", "would": (
                "refuse: the account that owns this address signs in only through a provider it is already linked "
                "to, until it has signed in there again")}
        return {"restriction": "passes", "would": "refuse: the account that owns this address is " + (
            "an administrator" if refused.detail.endswith("administrator") else "holding the auditor right") +
            "; it links only from its own signed-in profile"}
    if match is not None:
        return {"restriction": "passes",
                "would": f"link the account {match.username} by its verified email address and sign it in"}
    return None


def link_freshness_refusal(row, answer: ProviderAnswer, *, now=None) -> None:
    """Raise :class:`Refusal` unless the provider signed the person in just now for this link, where it says when
    it did. A link is started with ``prompt=login`` and ``max_age=0``: the identity that is linked is to be the
    one of whoever is at the keyboard, not of whoever was still signed in at the provider in that browser (a
    shared computer, a sign-in the provider was tricked into). A provider that honours the request states an
    ``auth_time`` of a moment ago; an older one means it answered from a session it had. Judged only for a
    provider whose test sign-in carried ``auth_time``: without it there is nothing to judge by, and the request
    is made all the same."""
    last_test = getattr(row, "last_test", None) or {}
    if not (isinstance(last_test, dict) and last_test.get("auth_time_present") is True):
        return
    now = now or datetime.now(timezone.utc)
    if answer.auth_time is None or not (
            -oc.SKEW_SECONDS <= (now - answer.auth_time).total_seconds() <= REAUTH_MAX_AGE_SECONDS):
        raise Refusal(REAUTH_STALE)


def identity_shown(identity) -> str:
    """Who an identity is at its provider, in the provider's words when it was linked: the address, else the name,
    else nothing. For the account's owner to see which identity stands on their account."""
    for value in (getattr(identity, "email_at_link", None), getattr(identity, "display_name", None)):
        if isinstance(value, str) and value.strip():
            return value.strip()
    return ""


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


# The detail of a link refused because the account's turn was held for longer than a link waits. Its reason is
# BUSY, not the provider's "could not be reached": the provider answered, and it is the account that was busy.
ACCOUNT_BUSY = "account_busy"


def decide_in_the_accounts_turn(db, user) -> None:
    """Take ``user``'s turn at its sessions, and read again what a link is decided on, as it is committed: the
    account's flag and its role. The role decides whether a provider whose people hold no password takes the
    account at all; the flag is what the link's answer and notice are told from. Whether the account's password
    is one nobody knows decides for an account made at a first sign-in, and is not read here: where the flag is
    settled (app/core/sso_only.settle) it is read again in this same turn whenever a change is due, and no state
    exists in which a mark read earlier would hide a change that is due.

    What changes any of them takes the same turn: a provider's save that lets the account hold a password again,
    a provider's removal, an unlink, a promotion. A link decided on what was read a moment before such a change
    left what neither meant: an account linked to a provider whose people hold no password, with a password it
    could set again, or an administrator's account on such a provider. In the turn, the link comes wholly after
    the change and decides on what it left, or wholly before it, and the change then finds the link.

    The provider's row is held by the caller already (the order of the locks: the row, then the turn). The routes
    that link run on the server's one loop, so the wait is the short one of where a sign-in is written
    (app/services/sign_in.with_a_short_wait); a turn still held refuses the link as busy, with nothing written.
    Nothing for an account that is not written yet."""
    if getattr(user, "id", None) is None:
        return
    from sqlalchemy.exc import OperationalError
    from app.services import sign_in
    api = _api()
    try:
        sign_in.with_a_short_wait(db, lambda: api._sessions_turn(db, user.id))
    except OperationalError as waited:
        if getattr(getattr(waited, "orig", None), "pgcode", None) != "55P03":      # lock_not_available
            raise
        raise Refusal(BUSY, ACCOUNT_BUSY) from None
    # Each unless the caller has set it on the account and not written it yet: read again, such a value would
    # be put back to what the database still holds (app/core/sso_only.read_again).
    from app.core import sso_only
    sso_only.read_again(db, user, ["sso_only", "role"])


def link_identity(db, row, user, answer: ProviderAnswer, *, linked_by: str, keep_session=None):
    """Link ``answer``'s identity to ``user``: refused when the subject already belongs to another account, or
    the account already has an identity on this provider. In the caller's transaction, and in the same one the
    provider's password rule is applied to the account (app/core/sso_only.settle): linked to a provider whose
    people hold no password, the account holds none from this moment, however it came to be linked. All of it is
    decided in the account's turn (:func:`decide_in_the_accounts_turn`), taken before anything of the account is
    read."""
    from app.core.models import ExternalIdentity
    decide_in_the_accounts_turn(db, user)
    _password_less_refusal(db, row, user)
    existing = subject_owner(db, row, answer)
    if existing is not None:
        if existing.user_id == user.id and known_identity(db, row, answer) is not None:
            if linked_by == "self" and getattr(existing, "linked_by", None) == LINKED_BY_EMAIL:
                # The owner linked the provider from their own profile, under their own sign-in, and came back
                # as the identity the provider had meanwhile put on the account by its address: it is the
                # owner's own link from now on (its unlink asks the provider where the provider can hold the
                # account, and the provider's second factor counts again). Left as the provider's, the link
                # the owner had just made themselves stayed one click to remove.
                existing.linked_by = linked_by
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
    from app.core import sso_only
    sso_only.settle(db, user, also=row, also_by=linked_by, keep_session=keep_session)
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


def test_summary(db, row, answer: ProviderAnswer, tester, tested=None) -> dict:
    """What an administrator reads after a test sign-in: the claim names (never the values but the tester's own
    identifiers), the proofs the token carried, and what the vault would do with this identity. ``tested`` is the
    provider as the sign-in was made with it (the values read before the provider was called): the summary speaks
    for that connection, not for one saved while the provider was answering."""
    from app.services import sso_providers
    return {
        "outcome": "ok", "at": datetime.utcnow().isoformat() + "Z", "tester": tester.username,
        "claim_names": sorted(str(k) for k in answer.claims.keys()),
        "auth_time_present": answer.auth_time is not None, "amr": answer.amr, "acr": answer.acr,
        "email_verified": answer.email_verified, "email_present": answer.email is not None,
        "groups": _group_names(row, answer), "subject_length": len(answer.subject),
        "mfa_trusted": mfa_trusted(row, answer), **would_do(db, row, answer, tester),
        # The connection settings this sign-in passed with: a provider is turned on only while they still stand.
        "config": sso_providers.fingerprint(tested if tested is not None else row),
    }


# What an administrator reads when a test sign-in did not pass: the reason a person's sign-in is refused for, said
# for the one who can change the provider's settings (a person is told to contact their administrator).
TEST_FAILED_TEXTS = {
    oc.PROVIDER_ERROR: ("The provider sent the browser back with an error, or with no code. Its own sign-in log "
                        "says why: often the redirect address is not registered there, or the test was cancelled."),
    oc.ISSUER_MISMATCH: ("The answer named another issuer than the one entered here. Check the issuer on the "
                         "Connection page against the provider's own."),
    oc.TOKEN_INVALID: ("The provider's token could not be verified: the token endpoint refused the client id or "
                       "secret, or the token's signature, audience or times did not check. Enter the client "
                       "secret again, and check the client id and how the secret is sent."),
    oc.SIGNING_KEY_TOO_SHORT: (f"The provider signs its tokens with an RSA key shorter than {oc.RSA_KEY_MIN_BITS} "
                               "bits, which the vault does not accept: such a key can be forged. Nothing on this "
                               "page changes it. The key is replaced at the provider."),
    oc.NONCE_MISMATCH: "The provider's token did not belong to this test. Run the test again.",
    oc.ENDPOINT_REFUSED: ("An address of the provider is not one the vault may call: it is inside the network, or "
                          "not https. Turn on “Inside the network” for a provider there, or correct the address."),
    oc.TEMPORARILY_UNAVAILABLE: ("The provider did not answer in time. Check that the vault's server can reach the "
                                 "issuer's address, then run the test again."),
    oc.DISCOVERY_INVALID: ("The provider's discovery document could not be read at the issuer's address. Check the "
                           "issuer, or enter the discovery address itself."),
}


def test_failure_text(code: str) -> str:
    """The administrator's sentence for a test sign-in refused as ``code``."""
    return TEST_FAILED_TEXTS.get(code) or ("The test sign-in did not pass: " + reason_text(code))


def failed_test_summary(row, tester_name: str, code: str) -> dict:
    """What is kept of a test sign-in that did not pass: the reason, in an administrator's words, who ran it and
    when, and the connection it was run with (a provider is turned on only after a test that passed)."""
    from app.services import sso_providers
    return {"outcome": code, "at": datetime.utcnow().isoformat() + "Z", "tester": tester_name,
            "message": test_failure_text(code), "config": sso_providers.fingerprint(row)}


# What a test sign-in that passed establishes about the provider itself, which later checks read from the last
# test: whether it says when it signed the person in (the confirmations it can give, and whether a link's fresh
# sign-in is judged), and the groups it sent (what the Groups page offers to map).
ESTABLISHED_BY_A_PASSING_TEST = ("auth_time_present", "groups")


def keeping_what_a_passing_test_established(summary: dict, previous) -> dict:
    """``summary`` of a test sign-in as it is written on the provider, given the one written there before.

    A test that did not pass is recorded, so that a provider is not turned on with it. Its summary holds the
    reason and no more, and it replaced the last one. For a provider that is on, one failed test (the
    administrator cancelled at the provider, or tested with an account the application is not assigned to) then
    turned off what the passing test had established: the provider could confirm nobody any more (no step-up
    for an account that signs in only through it, no first passkey, an owner's unlink refused), and a link
    through it accepted a sign-in from a session the provider already had. Nothing told anybody, and it lasted
    until somebody ran a test that passed.

    A failed test says nothing of what the provider sends. While the connection it was run with is the one the
    earlier test was run with, what that test established is kept in the failure's summary. With another
    connection, nothing is known and nothing is kept."""
    if summary.get("outcome") == "ok" or not isinstance(previous, dict):
        return summary
    if not summary.get("config") or summary.get("config") != previous.get("config"):
        return summary
    kept = {key: previous[key] for key in ESTABLISHED_BY_A_PASSING_TEST if key in previous}
    return {**summary, **kept}


def _group_names(row, answer: ProviderAnswer) -> list:
    return sorted(answer.groups or [])[:200]


def pipeline_result(db, row, user, answer: ProviderAnswer, *, provider_id: str, client_ip: Optional[str],
                    began_at, identity=None):
    """The pipeline's result for a provider sign-in: the provider is the first proof (``amr`` carries what the
    vault proved itself, nothing from the provider); the provider's MFA counts as the second factor only when the
    provider's policy trusts the values the token carried, and never for an identity that stands on the provider's
    word alone while the account holds a factor of its own.

    ``identity``: the identity the sign-in came through. An identity is put on an account that set up its own
    second factor only by that account, from its profile (:func:`_email_match`, :func:`set_up_its_own_factor`).
    One linked by email before the account set a factor up stays linked; while the account holds a factor it can
    give, the provider's MFA does not stand in for it at sign-ins through that identity, and the account's
    factor is asked. Its owner makes the link their own under Your account: they unlink the identity (one step:
    it was the provider's link, not theirs) and link the provider again. A provider the account is already
    linked to is not linked a second time, so there is no shorter way; the one case in which the owner's own
    link meets the identity (it was put on the account by its address while the owner was at the provider)
    makes it theirs on the spot (:func:`link_identity`).

    The rule is :func:`linked_on_the_providers_word`: a factor it can give now, or one it is to set up again
    (after a reset, a removed last passkey, a key that can no longer be used: the sign-in is then held for that
    set-up). It is less than :func:`set_up_its_own_factor`: passkeys kept while they are switched off are no
    factor and nothing is owed for them, so such an account goes on as one without a factor does.

    ``began_at``: when the vault began this sign-in (app/core/sso_state.began_at), which is the moment the
    sign-in counts from for the provider's logouts. Not the moment the provider's answer was taken: the exchange
    of the code and the account's resolution take their time, and a browser may hold the provider's redirect for
    as long as the state lives. A logout the vault took in between found no session to end, and a moment stamped
    here, after it, let the sign-in finish with the session the provider had logged out. It is required, and a
    caller that cannot say when the sign-in was begun is refused as an unknown sign-in (the person starts
    again): taken as now, a missing moment brought that back for whoever called without one."""
    from app.services.sign_in import SignInResult
    if not isinstance(began_at, (int, float)) or isinstance(began_at, bool):
        raise Refusal(STATE_UNKNOWN, "the sign-in does not say when it was begun")
    counted_from = float(began_at)
    policy = policy_of(row)
    on_the_providers_word = linked_on_the_providers_word(db, user, identity)
    return SignInResult(user, [], client_ip, provider_id=provider_id, sessions_ended=sign_in_as_read(user),
                        provider_mfa_trusted=mfa_trusted(row, answer) and not on_the_providers_word,
                        provider_auth_time=answer.auth_time,
                        provider_sid=answer.sid, provider_sub=answer.subject, provider_answered_at=counted_from,
                        provider_logout_hint=answer.id_token if policy["sso_idp_logout"] else None)


def linked_on_the_providers_word(db, user, identity) -> bool:
    """Whether the provider's MFA is not taken for the account's second factor at a sign-in (or the renewal of a
    session) through ``identity``: the identity was linked by email, on the provider's word, and the account holds
    a second factor it can give now (an authenticator, a passkey that can be used) or is to set one up again (an
    administrator reset it, or removed its last passkey, or its only passkey can no longer be used).

    The second half is what a reset is for: the factor was taken from the account because somebody else may
    hold it, or the device is gone, and the next one is to be set up by the account itself. Whoever holds its
    address at the provider would otherwise sign in on the provider's MFA alone for as long as the reset stays
    unanswered. Nobody is shut out by it: the sign-in is held for the set-up, which an account with a password
    proves with that password (asked first), and one with none by the provider's sign-in itself. So the password
    is what keeps the holder of the address out: an account with none it can type has the provider for its only
    door, and for it the rule adds the set-up of a factor and keeps nobody out."""
    from app.services import sign_in
    if identity is None or getattr(identity, "linked_by", None) != LINKED_BY_EMAIL:
        return False
    if sign_in.holds_a_factor(db, user):
        return True
    return bool(_api()._second_factor_to_set_up_again(db, user, has_active=False))     # none is active: just read


def sign_in_as_read(user) -> int:
    """What the account's sessions had been ended to when the account was read for this sign-in
    (app/services/sign_in.py, as_read)."""
    from app.services import sign_in
    return sign_in.as_read(user)


def provider_mfa_still_counts(db, result) -> bool:
    """Whether the provider's MFA a sign-in carries is still taken for the account's second factor, where the
    sign-in is finished: not for an identity linked by email once the account holds a factor of its own or is to
    set one up again (:func:`linked_on_the_providers_word`), whatever was so when the provider answered."""
    import uuid
    from app.core.models import ExternalIdentity
    try:
        provider_id = uuid.UUID(str(result.provider_id))
    except ValueError:
        return True                    # not a provider's id at all: refused where the provider is judged
    identity = db.query(ExternalIdentity).filter(ExternalIdentity.provider_id == provider_id,
                                                 ExternalIdentity.user_id == result.user.id).first()
    # No identity here: nothing was linked by email to judge (the sign-in is refused where the provider is judged).
    return identity is None or not linked_on_the_providers_word(db, result.user, identity)


def said_for_an_unlink(code: str) -> str:
    """The reason the person is shown when a fresh sign-in that was to confirm an unlink is refused as ``code``:
    its own reason for the three refusals a person may be unable to get past, the code itself for any other."""
    return {NOT_THIS_ACCOUNT: UNLINK_OTHER_IDENTITY, REAUTH_NO_MFA: UNLINK_NO_MFA,
            REAUTH_STALE: UNLINK_STALE}.get(code, code)


def reauth_refusal(db, row, user, answer: ProviderAnswer, *, now=None) -> None:
    """Raise :class:`Refusal` unless ``answer`` is a fresh sign-in of ``user``'s own identity at ``row``: the
    identity the token names must be the account's, the provider must say the person authenticated within the
    last minute (``auth_time``; a provider that sends none cannot re-authenticate), and, when the provider's MFA
    is trusted, the token must carry an accepted value."""
    identity = known_identity(db, row, answer)
    if identity is None or str(identity.user_id) != str(user.id):
        raise Refusal(NOT_THIS_ACCOUNT)
    now = now or datetime.now(timezone.utc)
    # A sign-in a little ahead of this clock is a fresh one seen from a clock that runs behind, by no more than the
    # skew every token check allows (beyond it the answer was refused earlier, as the provider's clock being ahead).
    # The upper bound stays where it is: a minute old at most.
    if answer.auth_time is None or not (
            -oc.SKEW_SECONDS <= (now - answer.auth_time).total_seconds() <= REAUTH_MAX_AGE_SECONDS):
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


REAUTH_NOT_FOR_THIS = ("This step asks for your account's own password: a sign-in at your organisation does not stand "
                       "in for it.")


def reauth_permitted(db, user, action: Optional[str] = None) -> bool:
    """Whether a fresh sign-in at a provider may stand in for ``user``'s password in a step-up for ``action``, by the
    account and the action alone (whether a provider can confirm the account is :func:`reauth_available`).

    Only for an account that signs in only through its provider (or holds no password at all): it has no password
    it could type, so the provider is the one thing that can confirm it. Never for an account that has a password (the step-up means
    that password: a stolen session and the person's provider account together must not pass it). Never for an
    account that reaches other people's vaults by its standing (an administrator, an auditor right): those keep a
    local password for exactly these step-ups, whatever else the row says. And never for a compliance action,
    which asks for the account's own second factor and its own password. With no ``action`` the question is
    about the account alone. Asked where the method is offered, where a re-authentication starts, where its
    answer is staged and where the step-up takes it: none of them trusts another."""
    from app.core import password_origin
    from app.core import privileged_accounts, second_factor_actions as acts, second_factor_policy as pol
    if user is None or not (getattr(user, "sso_only", False) or not getattr(user, "password_hash", None)
                            or password_origin.nobody_knows(user)):
        return False            # the account has a password it can type: the step-up means that password
    if privileged_accounts.kind(db, user) is not None:
        return False
    if action is not None and acts.fixed_policy(action) == pol.POLICY_COMPLIANCE:
        return False
    return True


def reauth_allowed(db, user, action: Optional[str] = None) -> bool:
    """Whether a provider sign-in may be offered to and taken from ``user`` for ``action`` now: the account and the
    action permit it (:func:`reauth_permitted`), and a provider the account is linked to can confirm it afresh."""
    return reauth_permitted(db, user, action) and reauth_available(db, user)


def confirmed_address_wanted(db, user) -> bool:
    """Whether confirming ``user``'s address would let a provider's sign-in find the account: it has an address
    the vault has not confirmed, some provider that is on links by email and the account is not linked to it yet,
    and the account is one a link by email may reach at all (not privileged, no second factor of its own). The
    pages offer the confirmation only then."""
    from app.core import email_confirmation, privileged_accounts
    from app.core.models import ExternalIdentity, SsoProvider
    if not (getattr(user, "email", None) or "").strip() or email_confirmation.confirmed(user):
        return False
    if not _has_identities(db):
        return False
    linking = [p for p in db.query(SsoProvider).filter(SsoProvider.state == "enabled").all()
               if policy_of(p)["sso_link_by_email"]]
    linked = {i.provider_id for i in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all()}
    if all(p.id in linked for p in linking):        # also: no provider links by email at all
        return False
    return privileged_accounts.kind(db, user) is None and not set_up_its_own_factor(db, user)


def accounts_that_set_up_a_factor(db, users) -> set:
    """:func:`set_up_its_own_factor` for a list of accounts, as the ids it holds for, in two reads whatever the
    length of the list: a reset not answered yet, an authenticator, or any passkey that was not retired, whether
    or not passkeys are switched on."""
    from app.core.models import SecondFactorEnrollment, WebAuthnCredential
    from app.core.table_presence import has_table
    ids = [u.id for u in users]
    found = {u.id for u in users if getattr(u, "second_factor_reset_at", None) is not None}
    if not ids:
        return found
    found |= {row[0] for row in db.query(SecondFactorEnrollment.user_id).filter(
        SecondFactorEnrollment.user_id.in_(ids), SecondFactorEnrollment.status == "active").all()}
    if has_table(db, WebAuthnCredential.__tablename__):
        found |= {row[0] for row in db.query(WebAuthnCredential.user_id).filter(
            WebAuthnCredential.user_id.in_(ids), WebAuthnCredential.retired_at.is_(None)).all()}
    return found


def confirmed_address_wanted_among(db, users) -> set:
    """:func:`confirmed_address_wanted` for a list of accounts (the Users page), as the ids it holds for: one
    read of the providers, one of the identities and two of the factors, whatever the length of the list. An
    account with the auditor right is not told apart here (it holds a factor wherever the right is in use); the
    server refuses a confirmation for it."""
    from app.core import email_confirmation
    from app.core.models import ExternalIdentity, RoleEnum, SsoProvider
    open_ = [u for u in users if (getattr(u, "email", None) or "").strip() and not email_confirmation.confirmed(u)
             and getattr(u, "role", None) != RoleEnum.ADMIN]
    if not open_ or not _has_identities(db):
        return set()
    linking = {p.id for p in db.query(SsoProvider).filter(SsoProvider.state == "enabled").all()
               if policy_of(p)["sso_link_by_email"]}
    if not linking:
        return set()
    holding = accounts_that_set_up_a_factor(db, open_)
    open_ = [u for u in open_ if u.id not in holding]
    if not open_:
        return set()
    linked = {}
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id.in_([u.id for u in open_])).all():
        linked.setdefault(identity.user_id, set()).add(identity.provider_id)
    return {u.id for u in open_ if not linking <= linked.get(u.id, set())}


def reauth_stands(db, user, provider_id, subject=None) -> bool:
    """Whether the provider a re-authentication was made at may still confirm ``user``, by the identity it was
    made through: one of the account's own providers that confirms afresh now (:func:`reauth_providers`), and the
    account's identity there is still the one that confirmed (``subject``). A confirmation made at a provider
    that was turned off since (an incident), or through an identity the account was unlinked from (another one
    linked on the same provider since is another person's word), confirms nothing, whatever else is on."""
    from app.core.models import ExternalIdentity
    if not provider_id or not any(str(p.id) == str(provider_id) for p in reauth_providers(db, user)):
        return False
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user.id).all():
        if str(identity.provider_id) == str(provider_id):
            return same_identity(identity, subject)
    return False


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


# The name a fresh sign-in at a provider is staged under to confirm the owner's unlink of their identity there
# (app/api/sso_router.py unlink_my_identity). It is no step-up action: no step-up takes what is staged under it,
# and what is staged for a step-up does not confirm an unlink.
UNLINK_CONFIRMATION = "sso.identity.unlink"


def provider_can_hold(db, user, row) -> bool:
    """Whether ``row`` can hold ``user``'s account to its own sign-in at all: it closes the account's other ways in
    once the person has stopped signing in there, it has something to hold the account by (days that run out, or
    a refusal that ends access), and the account is one a hold reaches (app/services/sso_freshness.may_be_held).
    Where it can, an unlink of it takes the account out of that hold for good: that is where the owner's unlink
    asks the provider first, and where the administrators are told of an owner's unlink by email as well."""
    from app.services import sso_freshness
    if row is None:
        return False
    policy = policy_of(row)
    if not policy["sso_lapse_ends_sign_in"]:
        return False
    if policy["sso_freshness_days"] <= 0 and not policy["sso_refusal_ends_access"]:
        return False
    return sso_freshness.may_be_held(db, user)


def unlink_asks_the_provider(db, user, identity, row) -> bool:
    """Whether the owner's unlink of ``identity`` asks for a fresh sign-in through its provider ``row`` first.

    Where the provider closes the account's other ways in once the person has stopped signing in there
    (``sso_lapse_ends_sign_in``), unlinking it would end that for good: an account with no identity has no days
    to run out. A person the provider no longer signs in could unlink it on the day before, and keep the password.
    So the unlink is confirmed by what such a person cannot give: a sign-in through the provider, made now.

    Asked exactly where the provider can hold the account (:func:`provider_can_hold`). Not where it has nothing
    to hold it by: its days are 0 and a refusal of the person ends nothing (no deadline ever stands then, and a
    provider that cannot confirm would leave every owner to an administrator for a hold that cannot exist). Not
    for an account the hold never reaches (the same rule as the hold's own, so an account that is held cannot
    unlink in one step). And not for an identity the provider itself put on the account by a verified address:
    the owner's answer to a link they did not make stays one click, and the administrators are told of it."""
    if getattr(identity, "linked_by", None) == LINKED_BY_EMAIL:
        return False
    return provider_can_hold(db, user, row)


def reauth_offered(row) -> bool:
    last_test = getattr(row, "last_test", None) or {}
    return (getattr(row, "state", None) == "enabled" and getattr(row, "kind", None) == "oidc"
            and isinstance(last_test, dict) and last_test.get("auth_time_present") is True)


def same_identity(identity, subject) -> bool:
    """Whether ``subject`` (what a session or a sign-in under way came through at the provider) is the subject of
    ``identity``, the account's link on that provider now. No subject is no match."""
    return bool(subject) and str(getattr(identity, "subject", None) or "") == str(subject)


def renewal_refusal(db, user, provider_id, *, methods=(), subject: Optional[str] = None,
                    now: Optional[datetime] = None) -> Optional[str]:
    """Why a session that came through the provider ``provider_id`` (its token's ``idp``) is not renewed, as the
    sentence the sign-in screen shows, or None when it may be. A renewal keeps the provider's sign-in going, so it
    needs what that sign-in would need now: the identity still linked, the provider turned on, no refusal by the
    provider in force and its freshness window not run out (app/services/sso_freshness.py). A record that cannot be
    read (no such provider, a database without the tables) is a refusal: nothing vouches for the session.

    ``subject`` is the identity the session came through at the provider (``sso_sessions.idp_sub``). The account
    must be linked by that very identity now: a session that came through an identity since unlinked is not kept
    going by another identity the account has linked on the same provider afterwards, and a session with no record
    of the identity it came through has nothing to be compared by and is refused.

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
    if identity is None or not same_identity(identity, subject):
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
    # The provider's MFA stands in for the account's factor where the policy trusts it, and never for an identity
    # that was linked by email while the account holds a factor of its own (pipeline_result holds a new sign-in to
    # the same): a session from before that factor is not kept going past it.
    trusted = policy_of(provider)["sso_trust_idp_mfa"] and not linked_on_the_providers_word(db, user, identity)
    if not own_factor and not trusted and api._login_second_factor_in_effect(db, user):
        return "Signing in now needs your second factor; sign in again."
    return None


def provider_logout_url(db, session_row) -> Optional[str]:
    """Where the browser goes after a vault sign-out when the session's provider wants its own logout: the
    provider's end-session address with the ID token as the hint and the vault's sign-in page to come back to.
    None when the session was not a provider's, the option is off, the provider has no such address or one the
    endpoint rule refuses, the vault has no configured address to come back to, or anything fails: the vault's
    sign-out stands on its own.

    The provider may have to be asked for its discovery document (a wait of up to the provider call's whole
    time). What is needed of the database is read first and the read transaction ended, so the wait holds no
    database connection. Call it after the commit: the sign-out has committed its own writes by then. Where the
    session still holds rows it has not written (new, changed or deleted), the transaction is left as it is; work
    already written and not committed is not seen here, and would be lost with the transaction."""
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
        config, hint = provider_config(row), decrypt_secret(sso_session.id_token_enc)
        if not any(getattr(db, pending, None) for pending in ("new", "dirty", "deleted")):
            db.rollback()
        discovery = oc.discover(config, fetch=oc.fetch_json)
        if not discovery.end_session_endpoint:
            return None
        # Judged again where it is used, as every endpoint is: the document may be a kept copy, older than the
        # rule's last look at it, and this is an address the vault sends a browser to.
        oc.check_endpoint(discovery.end_session_endpoint, private_network=config.private_network)
        import secrets
        query = urlencode({"id_token_hint": hint,
                           "post_logout_redirect_uri": come_back_to, "state": secrets.token_urlsafe(16)})
        separator = "&" if "?" in discovery.end_session_endpoint else "?"
        return f"{discovery.end_session_endpoint}{separator}{query}"
    except Exception:  # noqa: BLE001
        return None


def verifier_hash_of(verifier: str) -> str:
    return hashlib.sha256(verifier.encode("utf-8")).hexdigest()
