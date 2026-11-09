"""Freshness: an account linked to a single sign-on provider keeps its SSH keys and temporary credentials only while
it keeps signing in through that provider, so a person who has left, and can no longer sign in there, loses them
within the provider's window even when nobody removes the account.

For every identity of an account on an enabled provider whose policy sets ``sso_freshness_days`` (0 turns the rule off
for that provider), the account is fresh while the identity's last sign-in through the provider (its link, when it has
not signed in since) is younger than that many days, and the provider has not refused the person since: a verified
token that excluded a known identity (the refusal-ends-access rule) stamps ``refused_at``, and only a later sign-in the
provider admits answers it. Each such provider asks on its own: a sign-in through another provider does not answer
it. Nothing is deleted, so the next sign-in through the provider restores everything. A refusal stays in force even
when the provider is disabled afterwards; an administrator may clear it (app/api/sso_admin_router.py).

The daily sweep warns the person :data:`WARNING_DAYS` days before, in the app and by email, and the administrators'
user list shows the due date. Device credentials of the desktop app join the same check when they exist.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from app.core import sso_policy

WARNING_DAYS = 5
LAPSE_MESSAGE = ("Sign in through {provider} again: your SSH keys and temporary credentials are paused until you "
                 "do.")


@dataclass(frozen=True)
class Deadline:
    """When an identity's provider stops answering for the account, unless the person signs in there first."""
    identity_id: str
    user_id: str
    provider_id: str
    provider_name: str          # the sign-in button's label, else the provider's name
    due: datetime               # naive UTC, like the columns
    refused: bool               # the provider refused the person after their last sign-in through it


def _tables_present(db) -> bool:
    from app.services.sign_in import table_present
    return table_present(db, "external_identities") and table_present(db, "sso_providers")


def deadline_of(identity, provider) -> Optional[Deadline]:
    """The deadline ``identity`` keeps on ``provider``, or None when the provider asks nothing. A refusal the provider
    made since the person's last sign-in through it pauses the keys whatever the window and whatever has become of
    the provider since: disabling a provider (during an incident, say) must not hand keys back to people it excluded.
    Only a later sign-in it admits, or an administrator clearing the refusal, lifts it. Otherwise a provider asks
    only while it is enabled and its freshness is on."""
    last = identity.last_sign_in_at
    refused_at = getattr(identity, "refused_at", None)
    refused = refused_at is not None and (last is None or refused_at >= last)
    enabled = provider is not None and getattr(provider, "state", None) == "enabled"
    days = sso_policy.effective(getattr(provider, "policy", None))["sso_freshness_days"] if enabled else 0
    if not refused and (not enabled or days <= 0):
        return None
    since = last or identity.linked_at or datetime.utcnow()
    due = since + timedelta(days=days) if days > 0 else refused_at
    name = (getattr(provider, "name", None) or "").strip() or (getattr(provider, "label", None) or "").strip()
    return Deadline(identity_id=str(identity.id), user_id=str(identity.user_id), provider_id=str(identity.provider_id),
                    provider_name=name or "your identity provider", due=due, refused=refused)


def deadlines(db, user_id) -> List[Deadline]:
    """One deadline for each identity of ``user_id`` on a provider that asks, earliest first; none when the tables
    are not there (a test database without them)."""
    if user_id is None or not _tables_present(db):
        return []
    from app.core.models import ExternalIdentity, SsoProvider
    out = []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user_id).all():
        provider = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        found = deadline_of(identity, provider)
        if found is not None:
            out.append(found)
    return sorted(out, key=lambda d: d.due)


def lapsed(db, user_id, *, now: Optional[datetime] = None) -> Optional[Deadline]:
    """The deadline the account has missed (a refusal counts at once), or None while it is fresh."""
    now = now or datetime.utcnow()
    for found in deadlines(db, user_id):
        if found.refused or found.due <= now:
            return found
    return None


def due_date(db, user_id) -> Optional[datetime]:
    """The earliest deadline, what the administrators' user list shows; None when no provider asks."""
    found = deadlines(db, user_id)
    return found[0].due if found else None


def refusal_text(found: Deadline) -> str:
    return LAPSE_MESSAGE.format(provider=found.provider_name)


def warning_text(found: Deadline, when: str) -> str:
    return (f"Sign in through {found.provider_name} by {when}. If you do not, your SSH keys, temporary credentials "
            f"and devices pause then, and a sign-in through {found.provider_name} restores them.")


def _all_deadlines(db) -> List[Deadline]:
    """Every identity's deadline in two queries (the identities, the providers), for the sweep and the user list."""
    if not _tables_present(db):
        return []
    from app.core.models import ExternalIdentity, SsoProvider
    providers = {str(p.id): p for p in db.query(SsoProvider).all()}
    out = []
    for identity in db.query(ExternalIdentity).all():
        found = deadline_of(identity, providers.get(str(identity.provider_id)))
        if found is not None:
            out.append(found)
    return out


def standing_of(db, now: Optional[datetime] = None) -> dict:
    """For each account a provider asks of: ``{"due", "provider", "lapsed", "refused"}`` for the deadline that
    matters most (a refusal, else a lapse, else the earliest), what the administrators' user list shows."""
    now = now or datetime.utcnow()
    best: dict = {}
    for found in _all_deadlines(db):
        rank = (0 if found.refused else 1 if found.due <= now else 2, found.due)
        held = best.get(found.user_id)
        if held is None or rank < held[0]:
            best[found.user_id] = (rank, found)
    return {uid: {"due": found.due.isoformat() + "Z", "provider": found.provider_name,
                  "lapsed": found.refused or found.due <= now, "refused": found.refused}
            for uid, (_, found) in best.items()}


# --------------------------------------------------------------------------- the daily sweep

WARNED = "sso_freshness_warned"
EXPIRED = "sso_freshness_expired"
NOTICE_TARGET = "#profile"


def _audit(db, action: str, *, user, details: dict) -> None:
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(action=action, status="success", user=user, resource_type="user",
                                     resource_id=str(user.id), details=details))


def sweep(db, now: Optional[datetime] = None) -> dict:
    """The daily pass: a person whose deadline is within :data:`WARNING_DAYS` days is told, in the app and by email,
    once for that deadline; one whose deadline has passed is told their keys paused, once for that deadline, and the
    administrators get one notice for the accounts that lapsed in this pass. A refusal was told when it happened and
    is not told again here. Writes its audit rows into ``db`` (the caller commits); the notices commit in their own
    sessions, and their dedup keys are what makes each telling happen once. Returns the counts."""
    from app.api import api_server as api
    from app.core.models import User
    now = now or datetime.utcnow()
    warned, paused = 0, []
    for found in _all_deadlines(db):
        if found.refused or found.due - timedelta(days=WARNING_DAYS) > now:
            continue
        user = db.query(User).filter(User.id == uuid.UUID(found.user_id)).first()
        if user is None or not user.is_active:
            continue
        due_day = found.due.strftime("%Y-%m-%d")
        when = found.due.strftime("%d %B %Y, %H:%M UTC")
        details = {"provider_id": found.provider_id, "identity_id": found.identity_id,
                   "expires_at": found.due.isoformat() + "Z"}
        if found.due > now:
            told = api._notify_users(
                [found.user_id], WARNED, title=f"Sign in through {found.provider_name} by {when}",
                body=(f"Your SSH keys, temporary credentials and devices pause on {when} unless you sign in through "
                      f"{found.provider_name} before then. Signing in restores them at any time."),
                target=NOTICE_TARGET, dedup_prefix=f"{WARNED}:{found.identity_id}:{due_day}")
            if told:
                warned += 1
                _audit(db, WARNED, user=user, details=details)
                if user.email:
                    api._fire_action_email(db, "sso_freshness_warning", email=user.email, username=user.username,
                                           action_context={"change": warning_text(found, when), "when": when})
        else:
            told = api._notify_users(
                [found.user_id], EXPIRED, title="Your SSH keys and temporary credentials are paused",
                body=refusal_text(found), target=NOTICE_TARGET,
                dedup_prefix=f"{EXPIRED}:{found.identity_id}:{due_day}")
            if told:
                paused.append(user.username)
                _audit(db, EXPIRED, user=user, details=details)
    if paused:
        admins = [str(a.id) for a in api._active_admins(db)]
        shown = ", ".join(sorted(paused)[:20]) + (f" and {len(paused) - 20} more" if len(paused) > 20 else "")
        api._notify_users(admins, EXPIRED, title=f"{len(paused)} account(s) paused for want of a provider sign-in",
                          body=(f"The SSH keys, temporary credentials and devices of {shown} paused: they have not "
                                "signed in through their identity provider within its freshness window. A sign-in "
                                "through the provider restores them."),
                          target="#users", dedup_prefix=f"{EXPIRED}:wave:{now:%Y-%m-%d-%H%M%S}")
    return {"warned": warned, "lapsed": len(paused)}


# --------------------------------------------------------------------------- refusal at the provider ends access

ENDED = "sso_access_ended_by_refusal"


def end_access_on_refusal(db, row, answer, *, client_ip: Optional[str] = None,
                          now: Optional[datetime] = None) -> bool:
    """The provider's verified token excluded a known identity: its restriction claim is present and leaves the person
    out, which is proof (a missing claim or an overage marker is not, and the caller does not pass those here). With
    ``sso_refusal_ends_access`` on, the account's sessions end durably (its SFTP connections close), its SSH keys,
    temporary credentials and devices pause until a sign-in the provider admits (``refused_at``), the step is
    recorded and the administrators are told. Commits. Returns whether access was ended."""
    from app.services import sso_sign_in as sso
    if not sso.policy_of(row)["sso_refusal_ends_access"]:
        return False
    identity = sso.known_identity(db, row, answer)
    if identity is None:
        return False
    from app.api import api_server as api
    from app.core.models import User
    user = db.query(User).filter(User.id == identity.user_id).first()
    if user is None:
        return False
    identity.refused_at = now or datetime.utcnow()
    ended = api._revoke_sessions(db, user_id=user.id, actor_username="system", durable=True)
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(
        action=ENDED, status="success", user=user, ip_address=client_ip, resource_type="user",
        resource_id=str(user.id),
        details={"provider_id": str(row.id), "identity_id": str(identity.id), "sessions": ended}))
    db.commit()
    label = (getattr(row, "name", None) or "").strip() or (getattr(row, "label", None) or "the identity provider")
    try:
        admins = [str(a.id) for a in api._active_admins(db)]
        api._notify_users(admins, ENDED, title=f"{label} refused {user.username}: access ended",
                          body=(f"{label} signed {user.username} in with a token its restriction excludes (a tenant, "
                                "a domain or a required group), so their sessions ended and their SSH keys, temporary "
                                "credentials and devices paused. A later sign-in the provider admits restores them."),
                          target="#users", dedup_prefix=f"{ENDED}:{identity.id}:{identity.refused_at:%Y-%m-%d}")
    except Exception:  # noqa: BLE001 -- the ending and its row stand without the notice
        pass
    return True
