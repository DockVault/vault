"""The rules of a compliance case, as pure functions: its statuses and the steps between them, its clocks, its
limits, what its scope covers and whom it concerns, narrowing, the password rule, and the suspension that
COMPLIANCE_ACCESS=disabled means. Nothing here reads or writes the database: app/core/cases.py takes each step
with these rules, and the content routes ask them on every request.

Statuses. A case is asked for (``pending``); a second, independent administrator approves it (``active``) or turns
it down (``rejected``); its auditor may withdraw it while it waits (``withdrawn``); unapproved after PENDING_DAYS it
expires (``expired_unapproved``). An active case gives access until ``access_ends_at``; then it closes, or, when a
legal hold of it still stands, it keeps only the hold (``hold_only``) until the hold is released. A case is closed
by its auditor or an independent administrator with a reason (``closed``). ``suspended`` is stored only for a
suspension its auditor's account caused; whether an active case is suspended now is computed on every request
(effective_status): compliance access turned off, or an auditor whose right is not in force now. Turning it on
again resumes such a case with nothing to undo.

Clocks. Access starts at the approval, never earlier or later, and lasts the days asked (DEFAULT_ACCESS_DAYS
unless the request says otherwise), at most COMPLIANCE_MAX_ACCESS_DAYS per period and COMPLIANCE_MAX_TOTAL_DAYS
from the approval across every extension. An extension adds a period to the current end, while access is open.
Access is open from its start to the second before its end.

Limits. An auditor has at most MAX_OPEN_CASES cases that give or wait to give access (pending, active, suspended);
a case covers at most COMPLIANCE_MAX_CASE_VAULTS vaults.

Scope. A case asks for vaults, folders (each with its subtree) and custodians (a person: the vaults they own when
the case is asked for, a list kept with the case; a vault made later is not added). The result is, per vault,
None (the whole vault) or the folders it covers; an empty set of folders covers nothing (a vault narrowed out of
the case). A scope can be narrowed with no approval; anything wider needs a new case.

Persons concerned: the owner of every vault in the scope, every custodian, and everyone the auditor named. A
person concerned can neither approve, turn down, extend nor close the case, nor confirm or release its hold, and
an auditor who is one is refused: an auditor does not investigate themselves.

Passwords. A vault with a password is refused (``refuse``), opened with its password (``with_password``), or
opened without it (``override``) only when the request asked for that. A case uses the stricter of the value in
force when it was approved and the value in force now, so changing .env never widens an active case.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, FrozenSet, Iterable, List, Mapping, Optional, Tuple

from app.core import compliance_settings as cs

# --------------------------------------------------------------------------- statuses and steps

PENDING = "pending"
ACTIVE = "active"
HOLD_ONLY = "hold_only"
CLOSED = "closed"
REJECTED = "rejected"
WITHDRAWN = "withdrawn"
EXPIRED_UNAPPROVED = "expired_unapproved"
SUSPENDED = "suspended"
STATUSES = (PENDING, ACTIVE, HOLD_ONLY, CLOSED, REJECTED, WITHDRAWN, EXPIRED_UNAPPROVED, SUSPENDED)
# Nothing follows these.
FINAL = (CLOSED, REJECTED, WITHDRAWN, EXPIRED_UNAPPROVED)
# The cases that give access, or wait to: they count toward an auditor's limit.
OPEN = (PENDING, ACTIVE, SUSPENDED)

APPROVE = "approve"
REJECT = "reject"
WITHDRAW = "withdraw"
EXPIRE_UNAPPROVED = "expire_unapproved"
EXTEND = "extend"
END_ACCESS = "end_access"
CLOSE = "close"
NARROW = "narrow"
OBJECTION = "objection"
SUSPEND = "suspend"
RESUME = "resume"
STEPS = (APPROVE, REJECT, WITHDRAW, EXPIRE_UNAPPROVED, EXTEND, END_ACCESS, CLOSE, NARROW, OBJECTION, SUSPEND, RESUME)

# (status, step) -> the status after it. END_ACCESS leads to HOLD_ONLY or CLOSED (next_status says which).
TRANSITIONS: Dict[Tuple[str, str], str] = {
    (PENDING, APPROVE): ACTIVE,
    (PENDING, REJECT): REJECTED,
    (PENDING, WITHDRAW): WITHDRAWN,
    (PENDING, EXPIRE_UNAPPROVED): EXPIRED_UNAPPROVED,
    (PENDING, NARROW): PENDING,
    (ACTIVE, EXTEND): ACTIVE,
    (ACTIVE, END_ACCESS): CLOSED,
    (ACTIVE, CLOSE): CLOSED,
    (ACTIVE, NARROW): ACTIVE,
    (ACTIVE, OBJECTION): ACTIVE,
    (ACTIVE, SUSPEND): SUSPENDED,
    (SUSPENDED, RESUME): ACTIVE,
    (SUSPENDED, END_ACCESS): CLOSED,
    (SUSPENDED, CLOSE): CLOSED,
    (SUSPENDED, NARROW): SUSPENDED,
    (SUSPENDED, OBJECTION): SUSPENDED,
    (HOLD_ONLY, CLOSE): CLOSED,
    (HOLD_ONLY, OBJECTION): HOLD_ONLY,
    (CLOSED, OBJECTION): CLOSED,
}

# Why a step or a request is refused.
NOT_NOW = "not_now"                       # the step does not apply to the case's status
ACCESS_OFF = "compliance_disabled"
AUDITOR_NOT_LIVE = "auditor_not_live"
ACCESS_ENDED = "access_ended"
NOT_STARTED = "not_started"
NOT_ACTIVE = "not_active"
BAD_PURPOSE = "bad_purpose"
BAD_BASIS = "bad_basis"
NO_LIA_REFERENCE = "no_lia_reference"
SHORT_JUSTIFICATION = "short_justification"
NO_OWNER_NOTE = "no_owner_note"
NO_ART9_CONDITION = "no_art9_condition"
BAD_ART9_CONDITION = "bad_art9_condition"
NO_SCOPE = "no_scope"
BAD_SCOPE_KIND = "bad_scope_kind"
NO_SUCH_VAULT = "no_such_vault"
NO_SUCH_FOLDER = "no_such_folder"
NO_SUCH_PERSON = "no_such_person"
NO_VAULTS = "no_vaults"
TOO_MANY_VAULTS = "too_many_vaults"
TOO_MANY_CASES = "too_many_cases"
AUDITOR_CONCERNED = "auditor_concerned"
BAD_DAYS = "bad_days"
TOO_LONG = "too_long"
BAD_RANGE = "bad_range"
PASSWORD_VAULT_REFUSED = "password_vault_refused"
OVERRIDE_NOT_ALLOWED = "override_not_allowed"
EXPORT_OFF = "export_off"
WIDENS = "widens"

# --------------------------------------------------------------------------- what a case is for

# What a case is for, and on what basis. Legal holds use the same lists (app/core/legal_holds.py).
PURPOSES = ("internal_investigation", "litigation_hold", "regulator_request", "data_subject_request",
            "security_incident", "other")
LEGAL_BASES = ("legal_obligation", "public_task", "legitimate_interests")
# A hold starts with the case unless asked otherwise, for these purposes.
HOLD_BY_DEFAULT = frozenset({"internal_investigation", "litigation_hold", "regulator_request", "security_incident"})
# The conditions of GDPR Art. 9(2) a case touching special-category data may rest on: (b) to (j). Explicit consent
# (a) is not offered, as consent is not offered as a legal basis: at work it is rarely free.
ART9_CONDITIONS = ("employment", "vital_interests", "not_for_profit", "made_public", "legal_claims",
                   "substantial_public_interest", "health_care", "public_health", "archiving_research")
JUSTIFICATION_MIN = 30
TEXT_MAX = 4000

# --------------------------------------------------------------------------- clocks and limits

DEFAULT_ACCESS_DAYS = 14
# Unapproved after this, a case expires.
PENDING_DAYS = 7
# Cases that give or wait to give access, per auditor.
MAX_OPEN_CASES = 5


def next_status(status: str, step: str, *, hold_stands: bool = False) -> Optional[str]:
    """The status ``step`` leads ``status`` to, or None when the step does not apply to it. Access that ends
    while a legal hold of the case still stands leaves the case holding only that (HOLD_ONLY)."""
    after = TRANSITIONS.get((status, step))
    if after is None:
        return None
    if step == END_ACCESS and hold_stands:
        return HOLD_ONLY
    return after


def step_refusal(status: str, step: str) -> Optional[str]:
    """NOT_NOW when ``step`` does not apply to a case in ``status``, else None."""
    return None if (status, step) in TRANSITIONS else NOT_NOW


def hold_by_default(purpose: str) -> bool:
    return purpose in HOLD_BY_DEFAULT


def pending_until(requested_at: datetime) -> datetime:
    """When a case nobody approved expires."""
    return requested_at + timedelta(days=PENDING_DAYS)


def pending_expired(requested_at: datetime, now: datetime) -> bool:
    return now >= pending_until(requested_at)


def access_days_refusal(days, max_access_days: int) -> Optional[str]:
    """Why ``days`` is not an access period a case may ask for or be extended by, or None."""
    if not isinstance(days, int) or isinstance(days, bool) or days < 1:
        return BAD_DAYS
    if days > max_access_days:
        return TOO_LONG
    return None


def access_window(approved_at: datetime, days: int) -> Tuple[datetime, datetime]:
    """(start, end) of the access an approval at ``approved_at`` gives for ``days``: it starts at the approval."""
    return approved_at, approved_at + timedelta(days=days)


def access_open(starts_at: Optional[datetime], ends_at: Optional[datetime], now: datetime) -> bool:
    """Access is open from its start to the second before its end."""
    return starts_at is not None and ends_at is not None and starts_at <= now < ends_at


def extension(starts_at: datetime, ends_at: datetime, days, *, now: datetime, max_access_days: int,
              max_total_days: int) -> Tuple[datetime, int]:
    """(the new end, the total days of access from the approval) of extending open access by ``days``: a period
    added to the current end. Raises CaseRuleRefused: access already ended, a period that is not allowed, or more
    than ``max_total_days`` from the approval."""
    if not access_open(starts_at, ends_at, now):
        raise CaseRuleRefused(ACCESS_ENDED)
    why = access_days_refusal(days, max_access_days)
    if why is not None:
        raise CaseRuleRefused(why)
    new_end = ends_at + timedelta(days=days)
    if new_end - starts_at > timedelta(days=max_total_days):
        raise CaseRuleRefused(TOO_LONG)
    return new_end, total_days(starts_at, new_end)


def total_days(starts_at: datetime, ends_at: datetime) -> int:
    """Whole days of access from the approval to the end (a part of a day counts as a day)."""
    span = ends_at - starts_at
    return span.days + (1 if span - timedelta(days=span.days) > timedelta(0) else 0)


def open_cases_refusal(open_count: int) -> Optional[str]:
    """TOO_MANY_CASES when an auditor with ``open_count`` cases that give or wait to give access asks for one more."""
    return TOO_MANY_CASES if open_count >= MAX_OPEN_CASES else None


def vault_count_refusal(count: int, max_vaults: int) -> Optional[str]:
    if count < 1:
        return NO_VAULTS
    return TOO_MANY_VAULTS if count > max_vaults else None


class CaseRuleRefused(Exception):
    """A rule refused: ``reason`` is one of the codes above."""

    def __init__(self, reason: str, *, detail: Optional[str] = None):
        super().__init__(reason)
        self.reason, self.detail = reason, detail


# --------------------------------------------------------------------------- the request's text

def _clean(value) -> str:
    return (value or "").strip() if isinstance(value, str) or value is None else ""


def text_problems(*, purpose, legal_basis, lia_reference, justification, owner_note,
                  special_category: bool = False, art9_condition=None) -> List[str]:
    """Why the text of a case (or of a hold-only case) is not acceptable, in the order shown; empty when it is."""
    problems = []
    if purpose not in PURPOSES:
        problems.append(BAD_PURPOSE)
    if legal_basis not in LEGAL_BASES:
        problems.append(BAD_BASIS)
    elif legal_basis == "legitimate_interests" and not _clean(lia_reference):
        problems.append(NO_LIA_REFERENCE)
    if len(_clean(justification)) < JUSTIFICATION_MIN:
        problems.append(SHORT_JUSTIFICATION)
    if not _clean(owner_note):
        problems.append(NO_OWNER_NOTE)
    if special_category:
        if not _clean(art9_condition):
            problems.append(NO_ART9_CONDITION)
        elif art9_condition not in ART9_CONDITIONS:
            problems.append(BAD_ART9_CONDITION)
    elif art9_condition not in (None, "") and art9_condition not in ART9_CONDITIONS:
        problems.append(BAD_ART9_CONDITION)
    return problems


def range_refusal(files_from: Optional[datetime], files_to: Optional[datetime]) -> Optional[str]:
    if files_from is not None and files_to is not None and files_from > files_to:
        return BAD_RANGE
    return None


# --------------------------------------------------------------------------- scope

VAULT, FOLDER, CUSTODIAN = "vault", "folder", "custodian"
SCOPE_KINDS = (VAULT, FOLDER, CUSTODIAN)


@dataclass(frozen=True)
class ScopeItem:
    kind: str
    target_id: uuid.UUID


@dataclass(frozen=True)
class VaultFacts:
    """What the rules need of a vault: never its name."""
    id: uuid.UUID
    owner_id: Optional[uuid.UUID]
    type: str = "standard"
    has_password: bool = False


@dataclass
class Resolution:
    """What a scope covers: per vault, None (the whole vault) or the folders it covers; the vaults' facts; the
    custodians asked for."""
    vaults: Dict[uuid.UUID, Optional[FrozenSet[uuid.UUID]]] = field(default_factory=dict)
    facts: Dict[uuid.UUID, VaultFacts] = field(default_factory=dict)
    custodians: List[uuid.UUID] = field(default_factory=list)

    def owners(self) -> Dict[uuid.UUID, Optional[uuid.UUID]]:
        return {vid: self.facts[vid].owner_id for vid in self.vaults}


def as_id(value) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None


def parse_scope(raw: Iterable) -> List[ScopeItem]:
    """The scope items of a request ({kind, target_id} each), duplicates dropped. Raises CaseRuleRefused."""
    items: List[ScopeItem] = []
    for entry in raw or ():
        kind = entry.get("kind") if isinstance(entry, Mapping) else getattr(entry, "kind", None)
        target = entry.get("target_id") if isinstance(entry, Mapping) else getattr(entry, "target_id", None)
        if kind not in SCOPE_KINDS:
            raise CaseRuleRefused(BAD_SCOPE_KIND)
        tid = as_id(target)
        if tid is None:
            raise CaseRuleRefused({VAULT: NO_SUCH_VAULT, FOLDER: NO_SUCH_FOLDER, CUSTODIAN: NO_SUCH_PERSON}[kind])
        item = ScopeItem(kind, tid)
        if item not in items:
            items.append(item)
    if not items:
        raise CaseRuleRefused(NO_SCOPE)
    return items


def resolve_scope(items: Iterable[ScopeItem], *, vault: Callable[[uuid.UUID], Optional[VaultFacts]],
                  folder_vault: Callable[[uuid.UUID], Optional[uuid.UUID]],
                  owned_by: Callable[[uuid.UUID], Iterable[VaultFacts]],
                  person_exists: Callable[[uuid.UUID], bool]) -> Resolution:
    """What ``items`` cover, read through the given lookups (``vault``: a vault's facts or None; ``folder_vault``:
    the vault a folder is in, or None; ``owned_by``: the vaults a person owns now; ``person_exists``). A whole vault
    wins over folders of it; folders of one vault add up. Raises CaseRuleRefused for anything that does not exist."""
    out = Resolution()
    for item in items:
        if item.kind == VAULT:
            facts = vault(item.target_id)
            if facts is None:
                raise CaseRuleRefused(NO_SUCH_VAULT)
            out.facts[facts.id] = facts
            out.vaults[facts.id] = None
        elif item.kind == FOLDER:
            vid = folder_vault(item.target_id)
            facts = vault(vid) if vid is not None else None
            if facts is None:
                raise CaseRuleRefused(NO_SUCH_FOLDER)
            out.facts[facts.id] = facts
            if facts.id in out.vaults and out.vaults[facts.id] is None:
                continue
            out.vaults[facts.id] = frozenset((out.vaults.get(facts.id) or frozenset()) | {item.target_id})
        else:
            if not person_exists(item.target_id):
                raise CaseRuleRefused(NO_SUCH_PERSON)
            if item.target_id not in out.custodians:
                out.custodians.append(item.target_id)
            for facts in owned_by(item.target_id):
                out.facts[facts.id] = facts
                out.vaults[facts.id] = None
    return out


# Why someone is concerned, from the strongest: a custodian is the person the case is about.
WHY_ORDER = ("custodian", "owner", "named")


def persons_concerned(resolution: Resolution, named: Iterable[uuid.UUID]) -> Dict[uuid.UUID, str]:
    """{person: why} for everyone ``resolution`` (and the people named) concerns."""
    out: Dict[uuid.UUID, str] = {}

    def add(person, why):
        if person is None:
            return
        if person not in out or WHY_ORDER.index(why) < WHY_ORDER.index(out[person]):
            out[person] = why

    for person in resolution.custodians:
        add(person, "custodian")
    for vid in resolution.vaults:
        add(resolution.facts[vid].owner_id, "owner")
    for person in named or ():
        add(person, "named")
    return out


def auditor_refusal(auditor_id, concerned: Mapping) -> Optional[str]:
    """AUDITOR_CONCERNED when the auditor is a person the case concerns: they do not investigate themselves."""
    return AUDITOR_CONCERNED if str(auditor_id) in {str(p) for p in concerned} else None


def in_scope(folders: Optional[Iterable], target_id, ancestry: Iterable) -> bool:
    """Whether a file or folder (``target_id``, inside the folder chain ``ancestry`` toward the root) is in a vault's
    scope: None covers the whole vault, an empty set nothing, else the folders and their subtrees."""
    if folders is None:
        return True
    wanted = {str(f) for f in folders}
    if not wanted:
        return False
    return any(str(x) in wanted for x in [target_id, *list(ancestry or ())])


def narrowing_refusal(old: Mapping, new: Mapping, *, ancestry: Callable[[uuid.UUID], Iterable]) -> Optional[str]:
    """WIDENS when the scope ``new`` ({vault: None or folders}) covers anything ``old`` did not, else None.
    ``ancestry(folder)`` is a folder's chain of parents toward the root (without itself). A vault left out of
    ``new`` is narrowed out."""
    for vid, folders in new.items():
        if vid not in old:
            return WIDENS
        before = old[vid]
        if before is None:
            continue
        if folders is None:
            return WIDENS
        for f in folders:
            if not in_scope(before, f, ancestry(f)):
                return WIDENS
    return None


def time_narrowing_refusal(old_from, old_to, new_from, new_to) -> Optional[str]:
    """WIDENS when a new time range starts earlier or ends later than the old one (None: no bound)."""
    if old_from is not None and (new_from is None or new_from < old_from):
        return WIDENS
    if old_to is not None and (new_to is None or new_to > old_to):
        return WIDENS
    return range_refusal(new_from, new_to)


def narrowed(old: Mapping, new: Mapping) -> Dict[uuid.UUID, Optional[FrozenSet]]:
    """Every vault of ``old`` with what it covers after narrowing to ``new``: a vault left out covers nothing (an
    empty set), so its record stays with the case."""
    return {vid: (new[vid] if vid in new else frozenset()) for vid in old}


# --------------------------------------------------------------------------- passwords

def password_policy(recorded: Optional[str], current: str, *, override_requested: bool) -> str:
    """How a case treats a vault with a password: the stricter of the value recorded at its approval (None before
    it) and the value in force now; ``override`` only when the request asked for it, else ``with_password``."""
    value = cs.stricter(cs.PASSWORD_VAULTS, recorded, current)
    if value == cs.OVERRIDE and not override_requested:
        return cs.WITH_PASSWORD
    return value


def password_vault_refusal(policy: str, has_password: bool) -> Optional[str]:
    return PASSWORD_VAULT_REFUSED if has_password and policy == cs.REFUSE else None


def override_refusal(override_requested: bool, current: str) -> Optional[str]:
    """OVERRIDE_NOT_ALLOWED when a request asks to open vaults without their password while the deployment does not
    allow that."""
    return OVERRIDE_NOT_ALLOWED if override_requested and current != cs.OVERRIDE else None


def export_refusal(can_export: bool, current: str) -> Optional[str]:
    return EXPORT_OFF if can_export and current != cs.ALLOWED else None


# --------------------------------------------------------------------------- suspension and access

def effective_status(status: str, *, access_enabled: bool, auditor_live: bool) -> str:
    """The status a case has now: an active case is suspended while compliance access is turned off or its
    auditor's right is not in force. Computed on every request; nothing is stored."""
    if status == ACTIVE and (not access_enabled or not auditor_live):
        return SUSPENDED
    return status


def access_refusal(status: str, starts_at: Optional[datetime], ends_at: Optional[datetime], *, now: datetime,
                   access_enabled: bool, auditor_live: bool) -> Optional[str]:
    """Why a case gives no access now, or None: compliance access off, the auditor's right not in force, a case that
    is not active, or outside its access period."""
    if not access_enabled:
        return ACCESS_OFF
    if status != ACTIVE:
        return NOT_ACTIVE
    if not auditor_live:
        return AUDITOR_NOT_LIVE
    if starts_at is None or now < starts_at:
        return NOT_STARTED
    if ends_at is None or now >= ends_at:
        return ACCESS_ENDED
    return None
