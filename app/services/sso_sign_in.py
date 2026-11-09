"""Single sign-on through an OpenID Connect provider: the start, the callback, and what each purpose does.

A start makes the login state (app/core/sso_state.py) and answers the authorization URL the browser is sent to.
The callback spends the state, checks the provider and the issuer parameter, exchanges the code, verifies the ID
token (app/services/oidc_client.py), and then does what the state's purpose says:

* ``sign_in``: judges the provider's restriction (app/core/sso_policy.py), finds the account the identity belongs
  to in the design's order (a known identity; the invitation the state carries, whose account is made now; creation
  at the first sign-in, with its own item; an account with this verified email when the provider links by email),
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
RESTRICTED = sso_policy.RESTRICTED
RESTRICTION_CLAIM_MISSING = sso_policy.RESTRICTION_CLAIM_MISSING
INVITATION_UNUSABLE = "invitation_unusable"
EMAIL_REQUIRED = "email_required"
ACCOUNT_LIMIT = "account_limit"

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
    RESTRICTED: ("Your organisation's sign-in worked, but this vault is not open to your tenant, domain or group. Ask "
                 "your administrator."),
    RESTRICTION_CLAIM_MISSING: ("Your organisation's sign-in did not say which tenant, domain or groups you belong to, "
                                "so the vault could not check who it admits. Ask your administrator."),
    INVITATION_UNUSABLE: "This invitation can no longer be used. Ask your administrator for a new one.",
    EMAIL_REQUIRED: ("Your organisation's sign-in did not provide a verified email address, and this vault requires "
                     "one. Ask your administrator to put one on your invitation."),
    ACCOUNT_LIMIT: "This vault cannot take another account right now. Ask your administrator.",
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
    provider; a test needs one that is configured (any state but a bare draft without an issuer)."""
    if row is None or getattr(row, "kind", None) != "oidc":
        return PROVIDER_DISABLED
    if not (row.issuer and row.client_id and row.client_secret_enc):
        return PROVIDER_DISABLED
    if purpose == sso_state.TEST:
        return None
    if purpose == sso_state.STEP_UP:
        return PURPOSE_NOT_READY
    return None if row.state == "enabled" else PROVIDER_DISABLED


def redirect_uri(provider_id) -> str:
    from app.core.public_url import public_base_url
    return f"{public_base_url()}/auth/sso/{provider_id}/callback"


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
    return oc.authorization_url(provider, discovery, redirect_uri=redirect_uri(row.id), state=state.state,
                                nonce=state.nonce, code_verifier=state.code_verifier, reauthenticate=reauthenticate,
                                login_hint=login_hint, resolve=resolve)


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
    claims = oc.verify_id_token(provider, discovery, tokens.id_token, nonce=state.nonce,
                                max_age=0 if state.purpose == sso_state.STEP_UP else None,
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
    tenant = tenant if isinstance(tenant, str) and tenant else None
    auth_time = _as_time(claims.get("auth_time"))
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
    overage = groups is None and isinstance(names, dict) and groups_name in names
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
    if identity.tenant_id and identity.tenant_id != answer.tenant_id:
        return None
    return identity


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
    """Creation at the first sign-in lands with its own item; until then a provider set to make accounts behaves
    as invite-only (and the test summary says so)."""
    return None


def _email_match(db, row, answer: ProviderAnswer, policy: dict):
    """The one account a verified email may link to (the design's step 4), or None: the provider must be
    restricted (the save-time rule's condition, held here too so a hand-edited row never widens the door), the
    address verified, owned by exactly one active account that is not an administrator and has no identity on
    this provider yet."""
    from app.core.email_identity import find_user_by_email
    from app.core.models import ExternalIdentity, RoleEnum
    api = _api()
    account_policy = api._account_policy(db) if policy["sso_use_signup_domains"] else None
    if not sso_policy.is_restricted(policy, account_policy):
        return None
    if not (answer.email_verified and answer.email):
        return None
    user = find_user_by_email(db, answer.email)
    if user is None or getattr(user, "role", None) == RoleEnum.ADMIN or not account_usable(user):
        return None
    if db.query(ExternalIdentity.id).filter(ExternalIdentity.provider_id == row.id,
                                            ExternalIdentity.user_id == user.id).first() is not None:
        return None          # the account's identity on this provider is another one: an administrator sorts it out
    return user


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
    from app.core.account_policy import email_allowed_by_domain_gate, signup_email_is_ascii
    from app.core.email_identity import email_in_use, normalize_email
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
    if inv.email:
        if email_in_use(db, inv.email):
            raise Refusal(INVITATION_UNUSABLE, "email_in_use")
        email = inv.email
    else:
        email = normalize_email(answer.email) if answer.email_verified else None
        if email is not None and not (
                signup_email_is_ascii(email)
                and email_allowed_by_domain_gate(email, account_policy.get("signup_email_domain_mode"),
                                                 account_policy.get("signup_email_domains"))
                and not email_in_use(db, email) and not api._email_has_pending_invite(db, email)):
            email = None
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
    policy = policy_of(row)
    sso_only = policy["sso_password_login"] == "disabled" and role != RoleEnum.ADMIN   # an administrator keeps a password
    user = User(id=_uuid.uuid4(), username=inv.username, email=email,
                password_hash=hash_password(secrets.token_urlsafe(32)),
                role=role, created_by=inv.created_by, created_at=now, updated_at=now, is_active=True, is_locked=False,
                failed_login_attempts=0, sftp_enabled=True, sso_only=sso_only, sftp_password_auth=not sso_only)
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
        return {"restriction": "passes", "would": "refuse: account creation at the first sign-in is not available yet"}
    match = _email_match(db, row, answer, policy)
    if match is not None:
        return {"restriction": "passes",
                "would": f"link the account {match.username} by its verified email address and sign it in"}
    return {"restriction": "passes", "would": "refuse: no account is linked to this identity, and none would be made or linked"}


def link_refusal(db, row, user, answer: ProviderAnswer) -> None:
    """Raise :class:`Refusal` when ``answer``'s identity cannot be linked to ``user``: it already belongs to
    another account, or the account already has an identity on this provider."""
    from app.core.models import ExternalIdentity
    existing = known_identity(db, row, answer)
    if existing is not None and existing.user_id != user.id:
        raise Refusal(ALREADY_LINKED)
    if existing is None and db.query(ExternalIdentity.id).filter(ExternalIdentity.provider_id == row.id,
                                                                  ExternalIdentity.user_id == user.id).first() is not None:
        raise Refusal(NOT_THIS_ACCOUNT, "this account already has an identity on the provider")


def link_identity(db, row, user, answer: ProviderAnswer, *, linked_by: str):
    """Link ``answer``'s identity to ``user``: refused when the subject already belongs to another account, or
    the account already has an identity on this provider. In the caller's transaction."""
    from app.core.models import ExternalIdentity
    existing = known_identity(db, row, answer)
    if existing is not None:
        if existing.user_id == user.id:
            return existing
        raise Refusal(ALREADY_LINKED)
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


def test_summary(db, row, answer: ProviderAnswer, tester) -> dict:
    """What an administrator reads after a test sign-in: the claim names (never the values but the tester's own
    identifiers), the proofs the token carried, and what the vault would do with this identity."""
    return {
        "outcome": "ok", "at": datetime.utcnow().isoformat() + "Z", "tester": tester.username,
        "claim_names": sorted(str(k) for k in answer.claims.keys()),
        "auth_time_present": answer.auth_time is not None, "amr": answer.amr, "acr": answer.acr,
        "email_verified": answer.email_verified, "email_present": answer.email is not None,
        "groups": _group_names(row, answer), "subject_length": len(answer.subject),
        **would_do(db, row, answer, tester),
    }


def _group_names(row, answer: ProviderAnswer) -> list:
    return sorted(answer.groups or [])[:200]


def pipeline_result(db, user, answer: ProviderAnswer, *, provider_id: str, client_ip: Optional[str]):
    """The pipeline's result for a provider sign-in: the provider is the first proof (``amr`` carries what the
    vault proved itself, nothing from the provider); the provider's own MFA is trusted by its item, not here."""
    from app.services.sign_in import SignInResult
    return SignInResult(user, [], client_ip, provider_id=provider_id, provider_mfa_trusted=False,
                        auth_time=answer.auth_time or datetime.now(timezone.utc))


def verifier_hash_of(verifier: str) -> str:
    return hashlib.sha256(verifier.encode("utf-8")).hexdigest()
