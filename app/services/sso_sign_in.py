"""Single sign-on through an OpenID Connect provider: the start, the callback, and what each purpose does.

A start makes the login state (app/core/sso_state.py) and answers the authorization URL the browser is sent to.
The callback spends the state, checks the provider and the issuer parameter, exchanges the code, verifies the ID
token (app/services/oidc_client.py), and then does what the state's purpose says:

* ``sign_in``: finds the account the identity belongs to (a known identity; the other ways an account is found or
  made land with their own items) and hands the pipeline's result over as a one-time code the web app redeems at
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

from app.core import sso_state
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
          fetch=None, cache=None, resolve=None) -> str:
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
                            user_id=user_id, session_hash=session_hash, step_up_action=step_up_action)
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
    return ProviderAnswer(claims=claims, subject=str(claims["sub"]), issuer=str(claims["iss"]), tenant_id=tenant,
                          email=email, email_verified=claims.get(verified_name) is True, display_name=display,
                          auth_time=auth_time, amr=amr, acr=acr if isinstance(acr, str) else None,
                          sid=sid if isinstance(sid, str) else None, id_token=tokens.id_token)


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


def resolve_account(db, row, answer: ProviderAnswer):
    """Who the person is, for a sign-in: today the known identity alone (the invitation, creation and link-by-email
    steps land with their own items). ``NO_ACCOUNT`` when none; ``ACCOUNT_DISABLED`` for an inactive account."""
    from app.core.models import User
    identity = known_identity(db, row, answer)
    if identity is None:
        raise Refusal(NO_ACCOUNT)
    user = db.query(User).filter(User.id == identity.user_id).first()
    if user is None:
        raise Refusal(NO_ACCOUNT)
    if not account_usable(user):
        raise Refusal(ACCOUNT_DISABLED)
    if identity.tenant_id is None and answer.tenant_id:
        identity.tenant_id = answer.tenant_id      # linked before the provider named a tenant: pinned from now on
    return user, identity


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
    identity = known_identity(db, row, answer)
    if identity is not None:
        would = ("sign in the linked account" if identity.user_id == tester.id
                 else "sign in another account this identity is linked to")
    else:
        would = "refuse: no account is linked to this identity (invitation, creation and link-by-email come with their items)"
    return {
        "outcome": "ok", "at": datetime.utcnow().isoformat() + "Z", "tester": tester.username,
        "claim_names": sorted(str(k) for k in answer.claims.keys()),
        "auth_time_present": answer.auth_time is not None, "amr": answer.amr, "acr": answer.acr,
        "email_verified": answer.email_verified, "email_present": answer.email is not None,
        "groups": _group_names(row, answer), "subject_length": len(answer.subject), "would": would,
    }


def _group_names(row, answer: ProviderAnswer) -> list:
    groups = answer.claims.get(claim_name(row, "groups", "groups"))
    if not isinstance(groups, list):
        return []
    return sorted(str(g)[:255] for g in groups if isinstance(g, (str, int)))[:200]


def pipeline_result(db, user, answer: ProviderAnswer, *, provider_id: str, client_ip: Optional[str]):
    """The pipeline's result for a provider sign-in: the provider is the first proof (``amr`` carries what the
    vault proved itself, nothing from the provider); the provider's own MFA is trusted by its item, not here."""
    from app.services.sign_in import SignInResult
    return SignInResult(user, [], client_ip, provider_id=provider_id, provider_mfa_trusted=False,
                        auth_time=answer.auth_time or datetime.now(timezone.utc))


def verifier_hash_of(verifier: str) -> str:
    return hashlib.sha256(verifier.encode("utf-8")).hexdigest()
