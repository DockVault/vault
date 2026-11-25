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

The other ways in. A provider that says so (``sso_lapse_ends_sign_in``, on unless an administrator turns it off)
closes, from the same moment, every way in to the account that does not go through a provider
(:func:`held_to_a_provider`): its password on the web and over SFTP, a passkey by itself, and "Stay signed in" on a
session no provider made; an SFTP connection that is open goes no further (:func:`closes_a_connection`). Without
it a person who has left keeps signing in with a password the vault still holds, for as long as nobody removes the
account. An account that must keep a password of its own (an administrator, a holder of the auditor right) is never
held: its password is the way in while the provider cannot be reached.

While a provider is turned off here, its days close no other way in: nobody can sign in through it then, so not
having signed in there says nothing about a person, and every linked account would lose its password a window
after an administrator's turn-off. (The keys go on pausing on their day, as above.) What held an account before
the turn-off goes on holding it: a refusal by the provider, and days that had already run out, which the turn-off
records as one (app/services/sso_providers.py hold_lapsed). So turning a provider off, during an incident say,
hands nobody a password back; an administrator lifts each such account under Identities. Turned on again, the
days count as they stand: an account that did not sign in there within them signs in through the provider.
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
# For an account the provider holds to its own sign-in from then on (:func:`held_to_a_provider`).
LAPSE_MESSAGE_ALL = ("Sign in through {provider} again: your password, your passkeys, your SSH keys and your "
                     "temporary credentials do not work until you do.")


@dataclass(frozen=True)
class Deadline:
    """When an identity's provider stops answering for the account, unless the person signs in there first."""
    identity_id: str
    user_id: str
    provider_id: str
    provider_name: str          # the provider's name, else its button label
    due: datetime               # naive UTC, like the columns
    refused: bool               # the provider refused the person after their last sign-in through it
    window_days: int = 0        # the provider's freshness window (0: off, a refusal alone)
    ends_sign_in: bool = False  # missed, it also closes the account's ways in that go through no provider
    provider_on: bool = True    # the provider is turned on here (its days close the other ways in only then)


def warning_lead(window_days: int) -> timedelta:
    """How long before a deadline the person is warned: :data:`WARNING_DAYS`, but never more than half the window, so
    a short window does not warn right after every sign-in (a window of a day warns not at all)."""
    return timedelta(days=min(WARNING_DAYS, max(0, int(window_days)) // 2))


def _tables_present(db) -> bool:
    from app.services.sign_in import table_present
    return table_present(db, "external_identities") and table_present(db, "sso_providers")


def refusal_in_force(identity) -> bool:
    """Whether the refusal recorded on ``identity`` still holds the person: there is one, and no sign-in the
    provider admitted came after it (such a sign-in writes ``last_sign_in_at`` and leaves the stamp where it is).
    An answered stamp holds nobody: it pauses no key, is counted nowhere, and stands in the way of nothing."""
    refused_at = getattr(identity, "refused_at", None)
    last = getattr(identity, "last_sign_in_at", None)
    return refused_at is not None and (last is None or refused_at >= last)


def deadline_of(identity, provider) -> Optional[Deadline]:
    """The deadline ``identity`` keeps on ``provider``, or None when the provider asks nothing. A refusal the provider
    made since the person's last sign-in through it pauses the keys whatever the window and whatever has become of
    the provider since: disabling a provider (during an incident, say) must not hand keys back to people it excluded.
    Only a later sign-in it admits, or an administrator clearing the refusal, lifts it. Otherwise a provider asks
    while its freshness is on, whether it is on or off itself: the days go on counting while a provider is turned
    off (nobody can sign in through it then, so the keys pause on the day they would have), or a person who
    stopped signing in would keep their keys for as long as the provider stayed off. Turning the days to 0 ends
    the rule."""
    last = getattr(identity, "last_sign_in_at", None)
    refused_at = getattr(identity, "refused_at", None)
    refused = refusal_in_force(identity)
    policy = sso_policy.effective(getattr(provider, "policy", None))
    days = policy["sso_freshness_days"] if provider is not None else 0
    if not refused and days <= 0:
        return None
    since = last or getattr(identity, "linked_at", None) or datetime.utcnow()
    due = since + timedelta(days=days) if days > 0 else refused_at
    name = (getattr(provider, "name", None) or "").strip() or (getattr(provider, "label", None) or "").strip()
    return Deadline(identity_id=str(identity.id), user_id=str(identity.user_id), provider_id=str(identity.provider_id),
                    provider_name=name or "your identity provider", due=due, refused=refused, window_days=days,
                    ends_sign_in=bool(policy["sso_lapse_ends_sign_in"]),
                    provider_on=getattr(provider, "state", None) == "enabled")


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


def may_be_held(db, user) -> bool:
    """Whether a provider's hold can reach ``user`` at all: every account but one that keeps a password of its own
    in use now, which is an administrator, or the holder of an auditor right that is in force (an active grant).

    A proposal for the right exempts nobody, and neither does a right that is suspended: neither lets the account
    do anything yet that needs its password. Counted as exempt, an account with a proposal waiting could unlink
    its provider in one step, and after the proposal lapsed it was an ordinary account with no identity, which
    nothing holds.

    One rule for the hold itself (:func:`held_to_a_provider`), for what a person and the administrators are told
    of it (:func:`closes_the_other_ways_in`, :func:`password_after_a_refusal`) and for whether the owner's unlink
    asks the provider first (app/services/sso_sign_in.unlink_asks_the_provider): an account the hold reaches
    cannot step out of it by unlinking. Who may be linked by a verified address, or made to sign in only through
    a provider, is another question and keeps its own rule (app/core/privileged_accounts.py: a proposal counts
    there, since the account will need its password once the proposal is approved)."""
    from app.core import auditor_rights
    from app.core.models import RoleEnum
    if user is None:
        return False
    if getattr(user, "role", None) == RoleEnum.ADMIN:
        return False
    if getattr(db, "get_bind", None) is not None and not auditor_rights._has_grants(db):
        return True            # a database without the grants table holds no grant
    grant = auditor_rights.open_grant(db, getattr(user, "id", None))
    return grant is None or getattr(grant, "status", None) != "active"


def held_to_a_provider(db, user, *, now: Optional[datetime] = None) -> Optional[Deadline]:
    """The missed deadline that leaves ``user`` no way in but a provider's sign-in, or None.

    Missed (the days ran out, or the provider refused the person) on a provider that closes the other ways in
    then. The days count for this only while the provider is turned on; a refusal holds whatever the provider's
    state, and so do days that had run out before it was turned off (recorded as a refusal then). A sign-in
    through any provider the account is linked to is still let in, and one through the provider that asks
    restores everything; what is refused is what goes through none. Never an account that keeps a password of
    its own in use (:func:`may_be_held`: an administrator, a holder of an auditor right in force)."""
    if user is None or getattr(user, "id", None) is None:
        return None
    now = now or datetime.utcnow()
    missed = [found for found in deadlines(db, user.id) if closes_now(found, now)]
    if not missed:
        return None
    if not may_be_held(db, user):
        return None
    return missed[0]


def closes_now(found: Deadline, now: datetime) -> bool:
    """Whether ``found`` closes the ways in that go through no provider at ``now``, for an account that can be
    held at all: the provider says so, and either it refused the person, or its days have run out while it is
    turned on."""
    return bool(found.ends_sign_in) and (found.refused or (found.provider_on and found.due <= now))


def closes_the_other_ways_in(db, user, found: Deadline) -> bool:
    """Whether ``found``, once missed, also closes ``user``'s ways in that go through no provider: what the
    warning and the notices say to that person. Not while the provider is turned off: its days close nothing
    then, and the person is told of their keys alone."""
    return bool(found.ends_sign_in) and (found.refused or found.provider_on) and may_be_held(db, user)


def closes_a_connection(db, user, *, by_password: bool) -> bool:
    """Whether an SFTP connection of ``user`` that is already open goes no further: what made it would be refused
    now. A key's connection and a temporary credential's follow the rule their sign-in follows (any deadline
    missed: :func:`lapsed`), a password's the password's (:func:`held_to_a_provider`). Asked on every operation,
    as whether the account is still active is."""
    if by_password:
        return held_to_a_provider(db, user) is not None
    return lapsed(db, getattr(user, "id", None)) is not None


def way_in_text(db, found: Deadline) -> str:
    """What a person is told at a door that goes through no provider while :func:`held_to_a_provider` holds their
    account: the provider by name and how to reach it, or to ask an administrator where it cannot be reached or
    has refused them. Said only after the proof at that door was good."""
    from app.core.models import SsoProvider
    name = found.provider_name
    row = None
    try:
        row = db.query(SsoProvider).filter(SsoProvider.id == uuid.UUID(found.provider_id)).first()
    except ValueError:
        row = None
    if row is None or getattr(row, "state", None) != "enabled":
        return (f"Your account signs in only through {name} until it has signed in there again, and {name} is not "
                "available on this vault right now. Ask your administrator.")
    if found.refused:
        return (f"{name} did not admit your account when it last signed in there, so its password and passkeys do "
                f"not sign it in. Sign in through {name} once it admits you, or ask your administrator.")
    label = (getattr(row, "label", None) or "").strip() or name
    how = (f"Use the “{label}” button on the sign-in page." if getattr(row, "show_on_sign_in", True)
           else "Use the sign-in link your organisation gave you.")
    return (f"Sign in through {name}: your account has not signed in there within the time your organisation "
            f"allows, so its password and passkeys do not sign it in until it does. {how}")


def due_date(db, user_id) -> Optional[datetime]:
    """The earliest deadline, what the administrators' user list shows; None when no provider asks."""
    found = deadlines(db, user_id)
    return found[0].due if found else None


def refusal_text(found: Deadline, *, sign_in_too: bool = False) -> str:
    """What a person whose deadline is missed is told; ``sign_in_too`` for one whose other ways in closed with it
    (:func:`closes_the_other_ways_in`)."""
    return (LAPSE_MESSAGE_ALL if sign_in_too else LAPSE_MESSAGE).format(provider=found.provider_name)


def warning_text(found: Deadline, when: str, *, sign_in_too: bool = False) -> str:
    if sign_in_too:
        return (f"Sign in through {found.provider_name} by {when}. If you do not, your password and passkeys stop "
                "signing you in then, your SSH keys, temporary credentials and devices pause, and a sign-in "
                f"through {found.provider_name} restores them.")
    return (f"Sign in through {found.provider_name} by {when}. If you do not, your SSH keys, temporary credentials "
            f"and devices pause then, and a sign-in through {found.provider_name} restores them.")


def _identities_with_deadlines(db) -> list:
    """Every identity a provider asks of, with its deadline, in two queries (the identities, the providers)."""
    if not _tables_present(db):
        return []
    from app.core.models import ExternalIdentity, SsoProvider
    providers = {str(p.id): p for p in db.query(SsoProvider).all()}
    out = []
    for identity in db.query(ExternalIdentity).all():
        found = deadline_of(identity, providers.get(str(identity.provider_id)))
        if found is not None:
            out.append((identity, found))
    return out


def _all_deadlines(db) -> List[Deadline]:
    return [found for _, found in _identities_with_deadlines(db)]


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
    """The daily pass: a person whose deadline is near (:func:`warning_lead`) is told, in the app and by email, once
    for that deadline; one whose deadline has passed is told their keys paused, once for that deadline, and the
    administrators get one notice for the accounts that paused in this pass. A refusal was told when it happened and
    is not told again here. What was told is kept on the identity row (``freshness_warned_for``,
    ``freshness_paused_for``) in ``db``, with the audit rows, so a pass that rolls back tells again and a notice the
    person deleted is not sent again; the notices commit in their own sessions and keep their own dedup keys, so a
    retried pass adds no second notice or email. The caller commits. Returns the counts.

    While a provider is turned off here nobody is told to sign in through it, before the deadline or after: the
    sign-in page has no way to it, and the sentence would send the person where nothing answers. Nothing is kept
    as told either, so the first pass after the provider is turned on tells what then holds (the days went on
    counting meanwhile, as the provider's page says)."""
    from app.api import api_server as api
    from app.core.models import User
    now = now or datetime.utcnow()
    warned, paused, held = 0, [], 0
    for identity, found in _identities_with_deadlines(db):
        if found.refused or not found.provider_on:
            continue
        if found.due > now:
            lead = warning_lead(found.window_days)
            if not lead or found.due - lead > now or getattr(identity, "freshness_warned_for", None) == found.due:
                continue
        elif getattr(identity, "freshness_paused_for", None) == found.due:
            continue
        user = db.query(User).filter(User.id == uuid.UUID(found.user_id)).first()
        if user is None or not user.is_active:
            continue
        due_day = found.due.strftime("%Y-%m-%d")
        when = found.due.strftime("%d %B %Y, %H:%M UTC")
        # Whether this deadline closes the person's password and passkeys too: said in the same words wherever
        # the person is told.
        too = closes_the_other_ways_in(db, user, found)
        details = {"provider_id": found.provider_id, "identity_id": found.identity_id,
                   "expires_at": found.due.isoformat() + "Z", "ends_sign_in": too}
        if found.due > now:
            told = api._notify_users(
                [found.user_id], WARNED, title=f"Sign in through {found.provider_name} by {when}",
                body=((f"Your password and passkeys stop signing you in on {when}, and your SSH keys, temporary "
                       f"credentials and devices pause, unless you sign in through {found.provider_name} before "
                       "then. Signing in there restores them at any time.") if too else
                      (f"Your SSH keys, temporary credentials and devices pause on {when} unless you sign in through "
                       f"{found.provider_name} before then. Signing in restores them at any time.")),
                target=NOTICE_TARGET, dedup_prefix=f"{WARNED}:{found.identity_id}:{due_day}")
            warned += 1
            identity.freshness_warned_for = found.due
            _audit(db, WARNED, user=user, details=details)
            if told and user.email:
                api._fire_action_email(db, "sso_freshness_warning", email=user.email, username=user.username,
                                       action_context={"change": warning_text(found, when, sign_in_too=too),
                                                       "when": when})
        else:
            api._notify_users(
                [found.user_id], EXPIRED,
                title=(f"Sign in through {found.provider_name}: nothing else signs you in now" if too
                       else "Your SSH keys and temporary credentials are paused"),
                body=refusal_text(found, sign_in_too=too), target=NOTICE_TARGET,
                dedup_prefix=f"{EXPIRED}:{found.identity_id}:{due_day}")
            paused.append(user.username)
            held += 1 if too else 0
            identity.freshness_paused_for = found.due
            _audit(db, EXPIRED, user=user, details=details)
    if paused:
        admins = [str(a.id) for a in api._active_admins(db)]
        shown = ", ".join(sorted(paused)[:20]) + (f" and {len(paused) - 20} more" if len(paused) > 20 else "")
        api._notify_users(admins, EXPIRED, title=f"{len(paused)} account(s) paused for want of a provider sign-in",
                          body=(f"The SSH keys, temporary credentials and devices of {shown} paused: they have not "
                                "signed in through their identity provider within its freshness window. A sign-in "
                                "through the provider restores them."
                                + (f" For {held} of them the password and passkeys no longer sign in either, until "
                                   "then (the provider's rule; an administrator or an auditor keeps the password)."
                                   if held else "")),
                          target="#users", dedup_prefix=f"{EXPIRED}:wave:{now:%Y-%m-%d-%H%M%S}")
    return {"warned": warned, "lapsed": len(paused)}


def password_after_a_refusal(db, user) -> str:
    """What the administrators are told about the account's password when its provider refused the person: nothing
    for an account that holds none; that it no longer signs in, where the provider closes the other ways in; else
    that it still does, and why."""
    if getattr(user, "sso_only", False):
        return ""
    if held_to_a_provider(db, user) is not None:
        return (" Their password and passkeys no longer sign them in either, until the provider admits them again "
                "or the refusal is cleared.")
    if not may_be_held(db, user):
        return (" Their password still signs them in: an administrator or an auditor keeps a password of their own. "
                "Lock or deactivate the account if it should not.")
    return (" Their password still signs them in to the web app: this provider does not close the other ways in "
            "when it refuses a person (Sessions). Lock or deactivate the account if it should not.")


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
    # A sign-in already under way (a pending password or second-factor step) does not finish after the refusal.
    from app.services import sign_in
    sign_in.spend_sign_ins_under_way(db, user.id)
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(
        action=ENDED, status="success", user=user, ip_address=client_ip, resource_type="user",
        resource_id=str(user.id),
        details={"provider_id": str(row.id), "identity_id": str(identity.id), "sessions": ended}))
    db.commit()
    label = (getattr(row, "name", None) or "").strip() or (getattr(row, "label", None) or "the identity provider")
    try:
        admins = [str(a.id) for a in api._active_admins(db)]
        password_too = password_after_a_refusal(db, user)
        api._notify_users(admins, ENDED, title=f"{label} refused {user.username}: sessions ended, keys paused",
                          body=(f"{label} signed {user.username} in with a token its restriction excludes (a tenant, "
                                "a domain or a required group), so their sessions ended and their SSH keys, temporary "
                                "credentials and devices paused until a later sign-in the provider admits, or until "
                                "an administrator clears the refusal." + password_too),
                          target="#users", dedup_prefix=f"{ENDED}:{identity.id}:{identity.refused_at:%Y-%m-%d}")
    except Exception:  # noqa: BLE001 -- the ending and its row stand without the notice
        pass
    return True
