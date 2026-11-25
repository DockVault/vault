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

The daily pass warns the person up to :data:`WARNING_DAYS` days before (never more than half the window:
:func:`warning_lead`), in the app and by email, and the administrators' user list shows the due date. Device
credentials of the desktop app join the same check when they exist.

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
hands nobody a password back; an administrator lifts each such account on the provider's Identities page
(Settings, Sign-in; app/api/sso_admin_router.py). Turned on again, the days count as they stand: an account that did
not sign in there within them signs in through the provider.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import List, Optional

from app.core import sso_policy

WARNING_DAYS = 5
LAPSE_MESSAGE = ("Sign in through {provider} again: your SSH keys, temporary credentials and devices are paused until "
                 "you do.")
# For an account the provider holds to its own sign-in from then on (:func:`held_to_a_provider`); ``stops`` is what
# of its own ways in that stops (:func:`what_stops`), and ``do`` its verb ("do", or "does" for one thing).
LAPSE_MESSAGE_ALL = ("Sign in through {provider} again: {stops} {do} not sign you in, and your SSH keys, temporary "
                     "credentials and devices are paused until you do.")
ALL_THAT_STOPS = "your password and your passkeys"


@dataclass(frozen=True)
class Deadline:
    """When an identity's provider stops answering for the account, unless the person signs in there first."""
    identity_id: str
    user_id: str
    provider_id: str
    provider_name: str          # its name, else its button label: for the administrators and the records
    due: datetime               # naive UTC, like the columns
    refused: bool               # the provider refused the person after their last sign-in through it
    window_days: int = 0        # the provider's freshness window (0: off, a refusal alone)
    ends_sign_in: bool = False  # missed, it also closes the account's ways in that go through no provider
    provider_on: bool = True    # the provider is turned on here (its days close the other ways in only then)
    keys_only_hold: bool = False  # the hold on record is the vault's own, written while the days only paused keys
    # What the sign-in page's button says (its label, else the name): the person knows the provider by it, so every
    # sentence for the person names it so. The name is the administrators', and the person may never see it.
    provider_label: str = ""
    on_sign_in_page: bool = True  # the sign-in page shows its button (else the organisation hands out a link)

    def __post_init__(self):
        if not self.provider_label:
            object.__setattr__(self, "provider_label", self.provider_name)


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
    name = (getattr(provider, "name", None) or "").strip()
    label = (getattr(provider, "label", None) or "").strip()
    keys_only = getattr(identity, "keys_only_hold_at", None)
    return Deadline(identity_id=str(identity.id), user_id=str(identity.user_id), provider_id=str(identity.provider_id),
                    provider_name=name or label or "your identity provider", due=due, refused=refused,
                    window_days=days, ends_sign_in=bool(policy["sso_lapse_ends_sign_in"]),
                    provider_on=getattr(provider, "state", None) == "enabled",
                    keys_only_hold=bool(refused and keys_only is not None and keys_only == refused_at),
                    provider_label=label or name or "your identity provider",
                    on_sign_in_page=bool(getattr(provider, "show_on_sign_in", True)))


def deadlines(db, user_id) -> List[Deadline]:
    """One deadline for each identity of ``user_id`` on a provider that asks, earliest first; none when the tables
    are not there (a test database without them)."""
    if user_id is None or not _tables_present(db):
        return []
    from app.core.models import ExternalIdentity, SsoProvider
    # Asked at every door and on every SFTP operation: one read for the account's identities (the only one for an
    # account linked to nothing), and one for the providers, of which a vault holds a handful.
    identities = db.query(ExternalIdentity).filter(ExternalIdentity.user_id == user_id).all()
    if not identities:
        return []
    providers = {row.id: row for row in db.query(SsoProvider).all()}
    out = []
    for identity in identities:
        found = deadline_of(identity, providers.get(identity.provider_id))
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


def held_to_a_provider(db, user, *, now: Optional[datetime] = None, provider_id=None) -> Optional[Deadline]:
    """The missed deadline that leaves ``user`` no way in but a provider's sign-in, or None. ``provider_id``: asked
    of that provider alone (whether the deadline the account keeps there is such a one), for what is said of one
    provider's hold to an account that is linked to several.

    Missed (the days ran out, or the provider refused the person) on a provider that closes the other ways in
    then. The days count for this only while the provider is turned on; a refusal holds whatever the provider's
    state, and so do days that had run out before it was turned off (recorded as a refusal then). A sign-in
    through any provider the account is linked to is still let in, and one through the provider that asks
    restores everything; what is refused is what goes through none. Never an account that keeps a password of
    its own in use (:func:`may_be_held`: an administrator, a holder of an auditor right in force)."""
    if user is None or getattr(user, "id", None) is None:
        return None
    now = now or datetime.utcnow()
    missed = [found for found in deadlines(db, user.id) if closes_now(found, now)
              and (provider_id is None or found.provider_id == str(provider_id))]
    if not missed:
        return None
    if not may_be_held(db, user):
        return None
    return missed[0]


def a_hold_closes(found: Deadline) -> bool:
    """Whether the hold on record for ``found`` is one that closes the other ways in where the provider says a
    missed sign-in does: the provider's own refusal always, whatever the provider's state. Not, while the
    provider is off, a hold the vault wrote itself for days that had run out while those days only paused keys
    (at a turn-off, or before a removal). That person was told "your password signs you in as before", and
    nobody can sign in through a provider that is off: a later save that makes the days end sign-in closed
    their password, passkeys and SFTP password at once, with no way back in and nobody told."""
    return found.refused and (found.provider_on or not found.keys_only_hold)


def closes_now(found: Deadline, now: datetime) -> bool:
    """Whether ``found`` closes the ways in that go through no provider at ``now``, for an account that can be
    held at all: the provider says so, and either a hold on record closes them (:func:`a_hold_closes`), or its
    days have run out while it is turned on."""
    return bool(found.ends_sign_in) and (a_hold_closes(found) or (found.provider_on and found.due <= now))


def closes_the_other_ways_in(db, user, found: Deadline) -> bool:
    """Whether ``found``, once missed, also closes ``user``'s ways in that go through no provider: what the
    warning and the notices say to that person. Not while the provider is turned off: its days close nothing
    then, and the person is told of their keys alone."""
    return bool(found.ends_sign_in) and (a_hold_closes(found) or found.provider_on) and may_be_held(db, user)


def closes_a_connection(db, user, *, by_password: bool) -> bool:
    """Whether an SFTP connection of ``user`` that is already open goes no further: what made it would be refused
    now. A key's connection and a temporary credential's follow the rule their sign-in follows (any deadline
    missed: :func:`lapsed`), a password's the password's (:func:`held_to_a_provider`). Asked on every operation,
    as whether the account is still active is."""
    if by_password:
        return held_to_a_provider(db, user) is not None
    return lapsed(db, getattr(user, "id", None)) is not None


def _button_name(row) -> str:
    """What ``row``'s button on the sign-in page says: its label, else its name. The person knows a provider by it."""
    return (getattr(row, "label", None) or "").strip() or (getattr(row, "name", None) or "").strip()


def _how_to_reach(row, name: str) -> str:
    label = _button_name(row) or name
    return (f"Use the “{label}” button on the sign-in page." if getattr(row, "show_on_sign_in", True)
            else "Use the sign-in link your organisation gave you.")


def another_way_in(db, found: Deadline) -> Optional[str]:
    """Where the provider that holds the account cannot let the person in now (it is off, or it refused them):
    another provider the account is linked to that is on and holds no refusal of it, as "You can sign in through
    X instead: ...", or None when there is none. A sign-in through any provider the account is linked to is let in
    (:func:`held_to_a_provider`), so the person is not sent to an administrator while such a way stands. Named as
    its button names it; the first by that, so the sentence is the same each time. None while the vault's
    address cannot carry single sign-on: no sign-in through any provider starts then.

    A refusal the person has answered since (the provider admitted a later sign-in, which leaves the stamp where
    it is) holds nobody, and does not keep its provider from being named: skipped for the stamp alone, a provider
    that refused the person once was never named again, and the door said "ask your administrator" beside a
    button that would have let them in."""
    from app.core.models import ExternalIdentity, SsoProvider
    from app.services import sso_sign_in
    if sso_sign_in.address_refusal():
        return None
    try:
        owner = uuid.UUID(str(found.user_id))
    except ValueError:
        return None
    others = []
    for identity in db.query(ExternalIdentity).filter(ExternalIdentity.user_id == owner).all():
        if refusal_in_force(identity):
            continue                   # (the provider that holds the account is asked about only when it refused
                                       # the account or is off: it is left out by one of the two)
        other = db.query(SsoProvider).filter(SsoProvider.id == identity.provider_id).first()
        if other is not None and getattr(other, "state", None) == "enabled":
            name = _button_name(other)
            if name:
                others.append((name.lower(), name, other))
    if not others:
        return None
    _key, name, other = sorted(others, key=lambda entry: entry[0])[0]
    return f"You can sign in through {name} instead: {_how_to_reach(other, name)}"


def way_in_text(db, found: Deadline) -> str:
    """What a person is told at a door that goes through no provider while :func:`held_to_a_provider` holds their
    account: the provider as its button names it, and how to reach it; where it cannot be reached or has refused
    them, another provider of theirs that lets them in (:func:`another_way_in`), or to ask an administrator when
    there is none. Said only after the proof at that door was good. While the vault's address cannot carry single
    sign-on the sign-in page shows no provider's button, and no sign-in through one starts: the provider is not
    available then, as when it is off."""
    from app.core.models import SsoProvider
    from app.services import sso_sign_in
    name = found.provider_label
    row = None
    try:
        row = db.query(SsoProvider).filter(SsoProvider.id == uuid.UUID(found.provider_id)).first()
    except ValueError:
        row = None
    if row is not None:
        name = _button_name(row) or name              # as the button says it now
    if row is None or getattr(row, "state", None) != "enabled" or sso_sign_in.address_refusal():
        other = another_way_in(db, found)
        return (f"Your account signs in only through {name} until it has signed in there again, and {name} is not "
                "available on this vault right now. " + (other or "Ask your administrator."))
    if found.refused:
        # A hold on record is one of two things, and the row does not say which: the provider excluded the person
        # at their last sign-in there, or their days had run out when the provider was turned off or was to be
        # removed (app/services/sso_providers.py, hold_lapsed). "It did not admit your account" was said of both,
        # and is true of the first alone. What is said is true of both, and so is what to do.
        other = another_way_in(db, found)
        return (f"Your account is held to a sign-in through {name}: its password and passkeys do not sign it in "
                f"until {name} admits it. "
                + (other or f"{_how_to_reach(row, name)} If {name} does not admit you, ask your administrator."))
    return (f"Sign in through {name}: your account has not signed in there within the time your organisation "
            f"allows, so its password and passkeys do not sign it in until it does. {_how_to_reach(row, name)}")


def lift_the_hold(identity, provider, *, now: Optional[datetime] = None) -> bool:
    """An administrator lifts the hold on record for ``identity``: its ``refused_at`` is cleared, in the caller's
    transaction. Returns whether the lift counts for a removal of the provider.

    It counts where the hold was the vault's own, written for days that had run out when the provider was turned
    off or was to be removed (app/services/sso_providers.py, hold_lapsed, which marks it), and those days are
    still run out: the deadline the lift answered is then kept on the identity. The provider's days went on
    counting under the hold and the lift does not start them again, so the identity is as far past them as
    before. A removal holds every identity past its days first and is refused while one is held; told to clear
    each and remove again, the administrator cleared them and the next removal held the same people again, and
    told them and every administrator again, for as long as anyone tried. With the deadline kept, the identity is
    not held again for the deadline its lift answered. A later sign-in gives it another deadline, which the lift
    says nothing of.

    It does not count where the hold was the provider's own refusal. Lifting that says the refusal was a mistake.
    It does not say that the person should have their keys back when the provider goes: where their days have
    run out as well, they and the administrators are told that the keys stay paused. Kept for that lift too, the
    deadline let a removal months later pass the person over and give those keys back with nobody asked. Nor
    does it count while the days have not run out (they were made longer since the hold): nothing waits for a
    deadline that has not passed. A mark an earlier lift left is dropped with either."""
    now = now or datetime.utcnow()
    held = deadline_of(identity, provider)
    the_vaults_own = held is not None and held.keys_only_hold
    identity.refused_at = None
    standing = deadline_of(identity, provider)
    counts = the_vaults_own and standing is not None and standing.due <= now
    identity.hold_lifted_for = standing.due if counts else None
    return counts


def lift_answers(identity, standing: Optional[Deadline]) -> bool:
    """Whether an administrator's lift answered the deadline ``identity`` has now (``standing``)."""
    lifted_for = getattr(identity, "hold_lifted_for", None)
    return standing is not None and lifted_for is not None and lifted_for == standing.due


def after_a_hold_is_lifted(db, user, identity, provider, *, whose: str, now: Optional[datetime] = None,
                           held_before: Optional[Deadline] = None) -> str:
    """What is said of an account's keys once an administrator lifted the hold on record for ``identity``
    (``whose``: "your" to the person, "its" to the administrators), said after the lift is made in ``db``. They
    work again, unless the provider's days have run out as well: the days went on counting under the hold, and
    lifting it does not start them again. Then the keys stay paused until a sign-in through the provider, and
    where the provider closes the other ways in, and is on, the password and passkeys do too; a provider that is
    turned off signs nobody in, so that sign-in is one nobody can make until it is turned on. Told "they work
    again" in that state, the person found that nothing did. Nor do they while another identity of the account
    is refused or past its days (:func:`lapsed`).

    ``held_before``: :func:`held_to_a_provider` before the lift. Where it held the account, what of the password
    and passkeys the account has (:func:`what_stops`) is said to sign in again, or to sign in to nothing still,
    and which provider holds it then. The person reads a provider as its button names it, the administrators by
    its name."""
    now = now or datetime.utcnow()
    person = whose == "your"
    you = "you" if person else "it"

    def named(found: Deadline) -> str:
        return found.provider_label if person else found.provider_name

    # What of the account's own ways in a hold stops, named as the account has them (:func:`what_stops`).
    stops = what_stops(db, user) if user is not None else ""
    if not person:
        stops = stops.replace("your ", "its ")
    one = names_one(stops)
    standing = deadline_of(identity, provider)
    if standing is None or standing.refused or standing.due > now:
        still = lapsed(db, getattr(user, "id", None), now=now) if user is not None else None
        if still is None:
            said = f"{whose} SSH keys, temporary credentials and devices work again."
        else:
            said = (f"{whose} SSH keys, temporary credentials and devices stay paused all the same: {named(still)} "
                    "still holds them, until a sign-in through it"
                    + (" or an administrator lifts its refusal" if still.refused else "") + ".")
    else:
        closed = closes_now(standing, now) and user is not None and closes_the_other_ways_in(db, user, standing)
        until = f" until a sign-in through {named(standing)}"
        if not standing.provider_on:
            until += (", which is turned off on this vault now: ask your administrator" if person else
                      ", which is turned off: turn it on, or unlink the identity, to end the pause")
        said = (f"{whose} time to sign in through {named(standing)} has run out as well, so {whose} SSH keys, "
                "temporary credentials and devices stay paused"
                + (f", and {stops} {'signs' if one else 'sign'} in to nothing," if closed and stops else "")
                + until + ".")
    if held_before is None or user is None:
        return said
    held_now = held_to_a_provider(db, user, now=now)
    if not stops:
        return said                    # nothing of its own that a hold stops: its keys alone were said
    if held_now is None:
        return said + f" {_capitalised(stops)} {'signs' if one else 'sign'} {you} in again."
    if held_now.identity_id != str(identity.id):
        return said + (f" {_capitalised(stops)} still {'signs' if one else 'sign'} in to nothing: "
                       f"{named(held_now)} holds the account.")
    return said


def due_date(db, user_id) -> Optional[datetime]:
    """The earliest deadline, what the administrators' user list shows; None when no provider asks."""
    found = deadlines(db, user_id)
    return found[0].due if found else None


def what_stops(db, user) -> str:
    """What of ``user``'s own ways in a provider's hold stops, as the person is told it: "your password" where the
    account has one somebody can type, and "your passkeys" ("your passkey" for one) where it holds passkeys it can
    sign in with now (passkeys are on, and the key is one this vault accepts: webauthn_settings.usable_passkeys)
    and does not sign in only through its provider (its passkeys confirm the person after the provider's sign-in
    and never sign in alone). Empty when neither: such an account loses its SSH keys, temporary credentials and
    devices alone, and is told of those alone. Told of passkeys it never added, or of keys that sign nobody in, a
    person read of something they do not have."""
    from app.core import webauthn_settings
    from app.services import sign_in
    parts = ["your password"] if sign_in.has_a_password_it_can_type(user) else []
    if not getattr(user, "sso_only", False):
        keys = webauthn_settings.usable_passkeys(db, getattr(user, "id", None))
        if keys:
            parts.append("your passkey" if keys == 1 else "your passkeys")
    return " and ".join(parts)


def names_one(stops: str) -> bool:
    """Whether ``stops`` (:func:`what_stops`) names one thing, so that its verb is said in the singular: "your
    password stops", "your password and your passkeys stop"."""
    return bool(stops) and " and " not in stops and not stops.endswith("passkeys")


def _capitalised(text: str) -> str:
    return text[:1].upper() + text[1:]


def refusal_text(found: Deadline, *, sign_in_too: bool = False, stops: str = ALL_THAT_STOPS) -> str:
    """What a person whose deadline is missed is told; ``sign_in_too`` for one whose other ways in closed with it
    (:func:`closes_the_other_ways_in`), naming ``stops`` (:func:`what_stops`): with nothing to name, the keys
    alone."""
    if sign_in_too and stops:
        return LAPSE_MESSAGE_ALL.format(provider=found.provider_label, stops=stops,
                                        do="does" if names_one(stops) else "do")
    return LAPSE_MESSAGE.format(provider=found.provider_label)


def how_to_sign_in(found: Deadline) -> str:
    """How a person makes the sign-in ``found`` asks for, said wherever they are told of it before they reach the
    door: the provider's button, or the link the organisation hands out when the provider is not on the sign-in
    page. Only a sign-in through the provider counts, so a person signed in some other way signs out first. Not
    said at the door itself (:func:`refusal_text` is its answer too), where nobody is signed in. While the vault's
    address cannot carry single sign-on no provider can be reached here: the administrator then."""
    from app.services import sso_sign_in
    if sso_sign_in.address_refusal():
        return (f"This vault's sign-in page cannot offer {found.provider_label} right now: ask your "
                "administrator.")
    if found.on_sign_in_page:
        return (f"Use the “{found.provider_label}” button on the sign-in page (sign out first if you are signed "
                "in).")
    return "Use the sign-in link your organisation gave you (sign out first if you are signed in)."


def warning_text(found: Deadline, when: str, *, sign_in_too: bool = False, stops: str = ALL_THAT_STOPS) -> str:
    """What the warning email tells the person: the provider as its button names it, the date, what stops (``stops``
    where the other ways in close too: :func:`what_stops`), and how."""
    name = found.provider_label
    if sign_in_too and stops:
        return (f"Sign in through {name} by {when}. If you do not, {stops} {'stops' if names_one(stops) else 'stop'} "
                "signing you in then, your SSH keys, temporary credentials and devices pause, and a sign-in "
                f"through {name} restores them. {how_to_sign_in(found)}")
    return (f"Sign in through {name} by {when}. If you do not, your SSH keys, temporary credentials "
            f"and devices pause then, and a sign-in through {name} restores them. {how_to_sign_in(found)}")


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
    """For each account a provider asks of: ``{"due", "provider", "lapsed", "refused", "provider_on"}`` for the
    deadline that matters most (a refusal, else a lapse, else the earliest), what the administrators' user list
    shows. ``provider_on`` is false while that provider is turned off: its days go on counting (:func:`deadline_of`)
    and nobody can sign in through it, so the list does not offer that sign-in as what restores the keys."""
    now = now or datetime.utcnow()
    best: dict = {}
    for found in _all_deadlines(db):
        rank = (0 if found.refused else 1 if found.due <= now else 2, found.due)
        held = best.get(found.user_id)
        if held is None or rank < held[0]:
            best[found.user_id] = (rank, found)
    return {uid: {"due": found.due.isoformat() + "Z", "provider": found.provider_name,
                  "lapsed": found.refused or found.due <= now, "refused": found.refused,
                  "provider_on": found.provider_on}
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
    administrators get one notice for the accounts that paused in this pass. A refusal is told to the person and the
    administrators when it happens and is not told again here. What was told is kept on the identity row (``freshness_warned_for``,
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
        when = f"{found.due.day} {found.due:%B %Y, %H:%M} UTC"      # 5 December, as the vault writes a day
        # Whether this deadline closes the person's other ways in too, and which of them the account has: said in
        # the same words wherever the person is told. An account with none of them is told of its keys alone.
        too = closes_the_other_ways_in(db, user, found)
        stops = what_stops(db, user) if too else ""
        details = {"provider_id": found.provider_id, "identity_id": found.identity_id,
                   "expires_at": found.due.isoformat() + "Z", "ends_sign_in": too}
        name = found.provider_label         # the person knows the provider by its button
        how = how_to_sign_in(found)
        if found.due > now:
            told = api._notify_users(
                [found.user_id], WARNED, title=f"Sign in through {name} by {when}",
                body=((f"{_capitalised(stops)} {'stops' if names_one(stops) else 'stop'} signing you in on "
                       f"{when}, and your SSH keys, temporary "
                       f"credentials and devices pause, unless you sign in through {name} before "
                       f"then. Signing in there restores them at any time. {how}") if stops else
                      (f"Your SSH keys, temporary credentials and devices pause on {when} unless you sign in through "
                       f"{name} before then. Signing in restores them at any time. {how}")),
                target=NOTICE_TARGET, dedup_prefix=f"{WARNED}:{found.identity_id}:{due_day}")
            warned += 1
            identity.freshness_warned_for = found.due
            _audit(db, WARNED, user=user, details=details)
            if told and user.email:
                api._fire_action_email(db, "sso_freshness_warning", email=user.email, username=user.username,
                                       action_context={"change": warning_text(found, when, sign_in_too=too,
                                                                              stops=stops),
                                                       "when": when})
        else:
            api._notify_users(
                [found.user_id], EXPIRED,
                title=(f"Sign in through {name}: nothing else signs you in now" if stops
                       else "Your SSH keys, temporary credentials and devices are paused"),
                body=refusal_text(found, sign_in_too=too, stops=stops) + " " + how, target=NOTICE_TARGET,
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
    recorded, and the administrators and the person are told. Commits. Returns whether access was ended."""
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
    # The person, too: their keys stopped on another device with no word of why. Named as its button names it.
    try:
        named = _button_name(row) or "your identity provider"
        found = deadline_of(identity, row)
        stops = what_stops(db, user) if found is not None and closes_the_other_ways_in(db, user, found) else ""
        api._notify_users([str(user.id)], ENDED, title=f"{named} no longer admits your account here",
                          body=(f"{named} left your account out at your last sign-in there (a tenant, a domain or a "
                                "required group). Your sessions here ended, and your SSH keys, temporary credentials "
                                f"and devices are paused until {named} admits you again or an administrator lifts the "
                                "refusal." + (f" {_capitalised(stops)} {'does' if names_one(stops) else 'do'} not "
                                              "sign you in either until then." if stops else "")),
                          target=NOTICE_TARGET,
                          dedup_prefix=f"{ENDED}:{identity.id}:{identity.refused_at:%Y-%m-%d}:owner")
    except Exception:  # noqa: BLE001 -- the ending and its row stand without the notice
        pass
    return True
