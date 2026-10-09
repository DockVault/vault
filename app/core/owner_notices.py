"""Telling a vault's owner about compliance access to their vaults: in the app, in the very transaction that gives
the access, and by email through an outbox a crash cannot lose.

In the app. notify_in_transaction() adds the Notification rows to the caller's own session, so they commit with
the step or not at all: an approval, a hold or an extension is never committed without its owner's notice, and a
failure to write the notice fails the step. The live nudge to the bell follows the commit and carries no content.

By email. tell_owners() writes, for each owner, the notification, one row of compliance_notice_outbox and the
``owner_notice_written`` audit row, all in the caller's transaction. The outbox row keeps the address the owner
has now, sealed, and the one before it when an administrator changed it in the last 14 days (that address gets a
copy): an email change made after the step cannot reroute the notice, and moving an owner's address cannot hide it
from them. An owner with no address is told in the app only, and the case says so (``no_email_address``).

The sender runs on a thread of its own in the web process, never on the event loop or in the periodic loop (mail
with retries there would freeze the app), and only one process sends: each pass takes an advisory lock of its own
first. It claims due rows with SKIP LOCKED, one transaction per row, and tries again 1, 5 and 15 minutes after a
failure; a row that still fails is marked ``failed`` and raises a security alert, while the notice in the app
stands. A crash between the step's commit and the send loses nothing: the row waits for the next pass, in this
process or another. A message handed to SMTP just before a crash may go twice: at least once, never lost.

Only the owners' notices go through the outbox. Administrators and the auditor are told after the commit, in the
app, best effort, as before.

What a notice says (notice_text) is built from the case's number, purpose and legal basis, the auditor's and the
approver's usernames, dates, and counts: never a vault, file or folder name, the justification or a person named.
The auditor's note to the owner is in the email (opened when it is sent, never stored in the clear) and on the
owner's page, not in the notification row.
"""
from __future__ import annotations

import threading
import time
import uuid
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Callable, Iterable, List, Mapping, Optional

from sqlalchemy import or_, text

from app.core import after_commit
from app.core.case_context import acting_for

NOTICE_TYPE = "compliance_access"
TARGET = "#my-access"
EMAIL_ACTION = "compliance_access_notice"
HOST_OPERATOR = "operator@host"
SYSTEM = "system"

# What an owner is told of.
ACTIVATION = "activation"
EXTENSION = "extension"
SCOPE_REMOVED = "scope_removed"
ACCESS_ENDED = "access_ended"
CLOSED = "closed"
HOLD_PLACED = "hold_placed"
HOLD_CONFIRMED = "hold_confirmed"
HOLD_RELEASED = "hold_released"
HOLD_RESTORED = "hold_restored"
HOLD_LAPSED = "hold_lapsed"
EXPORT = "export"
# Outside a case: an auditor revealed names the activity log recorded in full (app/core/name_reveal.py).
REVEAL = "reveal"
KINDS = (ACTIVATION, EXTENSION, SCOPE_REMOVED, ACCESS_ENDED, CLOSED, HOLD_PLACED, HOLD_CONFIRMED, HOLD_RELEASED,
         HOLD_RESTORED, HOLD_LAPSED, EXPORT, REVEAL)

# An outbox row's status, and what the case shows of its rows.
PENDING, SENT, RETRYING, FAILED, NO_ADDRESS = "pending", "sent", "retrying", "failed", "no_email_address"
CASE_QUEUED = "queued"
# A failed attempt is tried again after these, then the row is failed.
RETRY_MINUTES = (1, 5, 15)
# How long the sender sleeps between passes when nothing wakes it, how many rows a pass takes at most, and how long
# a pass may run.
POLL_SECONDS = 30.0
PASS_ROWS = 200
PASS_SECONDS = 120.0
STATEMENT_TIMEOUT_MS = 30000
# The advisory lock one sender holds for its pass (distinct from the pruner's).
SENDER_LOCK = (0x6f62, 1)
# The two places a notice may go.
ADDRESS, PREVIOUS = "address", "previous"

PURPOSE_WORDS = {
    "internal_investigation": "internal investigation", "litigation_hold": "litigation or legal hold",
    "regulator_request": "regulator or authority request", "data_subject_request": "data-subject request",
    "security_incident": "security incident", "other": "other",
}
BASIS_WORDS = {"legal_obligation": "legal obligation", "public_task": "public task",
               "legitimate_interests": "legitimate interests"}
REASON_WORDS = {"security_incident": "a security incident", "internal_investigation": "an internal investigation",
                "regulator_request": "a regulator's or an authority's request",
                "data_subject_request": "a data-subject request", "litigation_hold": "litigation",
                "other": "another reason"}


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


# --------------------------------------------------------------------------- in the app, in the transaction

_NUDGES = "owner_notice_nudges"
_WAKE = "owner_notice_outbox"


def notify_in_transaction(db, user_ids: Iterable, *, title: str, body: str, ntype: str = NOTICE_TYPE,
                          target: Optional[str] = TARGET, dedup: Optional[str] = None) -> list:
    """Add a Notification row for each of ``user_ids`` to ``db``'s session, in the caller's transaction: they
    commit with it or not at all, and an error here fails the caller's step. ``dedup`` (one event) keeps a
    person from getting two rows for it. The bell's live nudge follows the commit. Returns the rows."""
    from app.core.models import Notification
    rows = []
    for uid in dict.fromkeys(str(u) for u in user_ids if u):
        row = Notification(user_id=uuid.UUID(uid), type=ntype, title=title, body=body, target=target, dedup_key=dedup)
        db.add(row)
        rows.append(row)
        after_commit.later(db, _NUDGES, {"user_id": uid, "type": ntype, "target": target})
    db.flush()
    return rows


def _nudge(items) -> None:
    from app.api import api_server as api
    for item in items:
        try:
            api._fire_offloop(api.broadcast_event,
                              {"event": {"type": "notification", "notification_type": item["type"],
                                         "target": item["target"], "owner_user_id": item["user_id"]}},
                              include_metrics=False)
        except Exception as exc:  # noqa: BLE001 -- the row is what matters; the nudge is droppable
            print(f"Warning: a notification's live nudge was not sent ({type(exc).__name__})")


after_commit.handler(_NUDGES, _nudge)
after_commit.handler(_WAKE, lambda _items: wake())


# --------------------------------------------------------------------------- what a notice says

@dataclass(frozen=True)
class Facts:
    """Everything a notice may say: ids, codes, usernames of the auditor and the approver, dates and counts."""
    kind: str
    number: Optional[str]
    purpose: Optional[str] = None
    legal_basis: Optional[str] = None
    auditor: Optional[str] = None
    approver: Optional[str] = None
    by: Optional[str] = None
    ends_at: Optional[datetime] = None
    can_export: bool = False
    password_override: bool = False
    vaults: int = 0
    zero_knowledge: int = 0
    with_password: int = 0
    hold: bool = False
    purge_after: Optional[datetime] = None
    files_opened: int = 0
    exports: int = 0
    files: int = 0
    contact: Optional[str] = None
    reason: Optional[str] = None


def _plural(n: int, one: str, many: Optional[str] = None) -> str:
    return f"{n} {one}" if n == 1 else f"{n} {many or one + 's'}"


def _who(name: Optional[str]) -> str:
    if name in (None, ""):
        return "an administrator"
    return "the server's operator" if name == HOST_OPERATOR else name


def _when(value: Optional[datetime]) -> str:
    return f"{value:%d %b %Y, %H:%M} UTC" if value is not None else "-"


def _day(value: Optional[datetime]) -> str:
    return f"{value:%Y-%m-%d}" if value is not None else "-"


def notice_text(f: Facts) -> tuple:
    """(title, sentences) of a notice to a vault's owner. Never a vault, file or folder name, the justification or
    a person named: it is built from ``f`` alone."""
    case = f"Case {f.number}" if f.number else "A case"
    your = f"{f.vaults} of your vaults"
    owned = _plural(f.vaults, "vault") + " you own"
    contact = f"Questions or objections: {f.contact}." if f.contact else "Questions or objections: your administrator."
    if f.kind == ACTIVATION:
        lines = [f"{case} · Purpose: {PURPOSE_WORDS.get(f.purpose, '-')} · Legal basis: "
                 f"{BASIS_WORDS.get(f.legal_basis, '-')}.",
                 f"{_who(f.auditor)} (auditor) can view files{' and export copies' if f.can_export else ''} until "
                 f"{_when(f.ends_at)}. Approved by {_who(f.approver)}."]
        if f.hold:
            lines.append("A legal hold keeps files deleted from "
                         f"{'that vault' if f.vaults == 1 else 'those vaults'} until the case ends.")
        if f.zero_knowledge:
            lines.append(f"{_plural(f.zero_knowledge, 'of them is', 'of them are')} zero-knowledge: contents and "
                         "names cannot be opened.")
        if f.with_password:
            lines.append(f"{_plural(f.with_password, 'of them has', 'of them have')} a password: "
                         + ("an approved investigation may open "
                            f"{'it' if f.with_password == 1 else 'them'} without the password."
                            if f.password_override else "the auditor must type it."))
        lines += ["Every file opened is listed on Access to my vaults, as it happens.", contact]
        return f"An investigation can open {your}", lines
    if f.kind == EXTENSION:
        return ("An investigation of your vaults was extended",
                [f"{case}: {_who(f.auditor)} (auditor) can view files until {_when(f.ends_at)}. Extended by "
                 f"{_who(f.by)}.", contact])
    if f.kind == SCOPE_REMOVED:
        return (f"An investigation no longer covers {your}",
                [f"{case} no longer covers {owned}. Nothing more is opened there under it."])
    if f.kind in (ACCESS_ENDED, CLOSED):
        lines = [f"{case}: access to your vaults ended."
                 if f.kind == ACCESS_ENDED else f"{case} was closed by {_who(f.by)}.",
                 f"Files opened: {f.files_opened}. Exports: {f.exports}."]
        lines.append(f"A legal hold still keeps files deleted from {owned} until it is released."
                     if f.hold else "No legal hold of it remains on your vaults.")
        lines.append(contact)
        return ("An investigation's access to your vaults ended" if f.kind == ACCESS_ENDED
                else "An investigation of your vaults was closed"), lines
    if f.kind == HOLD_PLACED:
        return ("Legal hold on your vaults",
                [f"A legal hold under case {f.number} keeps what is deleted from {owned}, until it is released.",
                 "You can go on using them as before. See Access to my vaults.", contact])
    if f.kind == HOLD_CONFIRMED:
        return ("Legal hold confirmed",
                [f"The legal hold under case {f.number} on {owned} was confirmed by {_who(f.by)}. It stands until "
                 "it is released."])
    if f.kind == HOLD_RELEASED:
        return ("Legal hold released",
                [f"The legal hold under case {f.number} on {owned} was released. What it kept is deleted after "
                 f"{_day(f.purge_after)}."])
    if f.kind == HOLD_RESTORED:
        return ("Legal hold restored",
                [f"The release of the legal hold under case {f.number} on {owned} was undone: the hold stands "
                 "again."])
    if f.kind == HOLD_LAPSED:
        return ("Legal hold lapsed",
                [f"The legal hold under case {f.number} on {owned} lapsed: nobody confirmed it in time."])
    if f.kind == EXPORT:
        return ("Files exported from your vaults",
                [f"{case}: {_who(f.by)} (auditor) exported copies of {_plural(f.files, 'file')} from your vaults.",
                 contact])
    if f.kind == REVEAL:
        return ("Names in your vault's activity were revealed",
                [f"{_who(f.auditor)} (auditor) revealed names the activity log recorded about a vault you own, for "
                 f"{REASON_WORDS.get(f.reason, 'a stated reason')}. Each reveal is recorded with its reason; further "
                 "reveals by them in that vault today are recorded without another notice.", contact])
    return ("Compliance access to your vaults", [f"{case} changed."])


def contact(db) -> Optional[str]:
    """The privacy contact the operator states for the recording notice (or the brand's contact address)."""
    try:
        from app.core import recording_notice
        return recording_notice._stated(db)["recording_notice_contact"] or recording_notice._contact_fallback(db)
    except Exception:  # noqa: BLE001 -- the notice then says "your administrator"
        return None


def facts(db, case, kind: str, details: Optional[Mapping] = None) -> Facts:
    """The facts of a notice of ``kind`` about ``case``: read from the case's codes, dates and usernames, and the
    counts in ``details`` (an outbox row's). A notice outside a case (a reveal) reads ``details`` alone."""
    d = dict(details or {})
    if case is None:
        return Facts(kind=kind, number=None, auditor=d.get("auditor"), by=d.get("by"),
                     vaults=int(d.get("vaults") or 0), reason=d.get("reason"), contact=contact(db))

    def when(key):
        value = d.get(key)
        if isinstance(value, datetime) or value is None:
            return value
        try:
            return datetime.fromisoformat(str(value).rstrip("Z"))
        except ValueError:
            return None

    approver = HOST_OPERATOR if getattr(case, "approved_by_operator", False) else getattr(case, "approved_by_username", None)
    return Facts(kind=kind, number=case.number, purpose=case.purpose, legal_basis=case.legal_basis,
                 auditor=case.auditor_username, approver=approver, by=d.get("by"),
                 ends_at=when("ends_at") or case.access_ends_at, can_export=bool(case.can_export),
                 password_override=bool(case.password_override), vaults=int(d.get("vaults") or 0),
                 zero_knowledge=int(d.get("zero_knowledge") or 0), with_password=int(d.get("with_password") or 0),
                 hold=bool(d.get("hold")), purge_after=when("purge_after"), files_opened=int(d.get("files_opened") or 0),
                 exports=int(d.get("exports") or 0), files=int(d.get("files") or 0), contact=contact(db))


def app_text(f: Facts, *, has_note: bool) -> tuple:
    """(title, body) of the in-app notification: the notice, and where to read the auditor's note."""
    title, lines = notice_text(f)
    if has_note and f.kind == ACTIVATION:
        lines = lines[:-2] + ["The auditor's note to you is on Access to my vaults."] + lines[-2:]
    return title, " ".join(lines)


# --------------------------------------------------------------------------- the owners' notices

def destinations(db, user) -> tuple:
    """(the address the owner has now, the one before it when an administrator changed it in the last 14 days
    and the owner has not changed it since): where their notice goes. Either may be None."""
    from app.core import credential_changes as cc
    address = (getattr(user, "email", None) or "").strip() or None
    previous = None
    moves = cc.email_changes_in_window(db, user.id)
    if moves:
        latest = moves[-1].payload or {}
        if "new_email" not in latest or (latest.get("new_email") or "").strip().lower() == (address or "").lower():
            before = ((moves[0].payload or {}).get("previous_email") or "").strip() or None
            if before is not None and before.lower() != (address or "").lower():
                previous = before
    return address, previous


def tell_owners(db, case, kind: str, counts_by_owner: Mapping, *, now: Optional[datetime] = None,
                details: Optional[Mapping] = None) -> int:
    """Tell each owner in ``counts_by_owner`` ({owner id: {"vaults": n, ...}}) of ``kind`` about ``case``, in the
    caller's transaction: the notification, the outbox row (its address sealed now) and the audit row. Raises on
    any failure, which fails the caller's step. Returns how many owners were told."""
    from app.core.models import ComplianceNoticeOutbox, User
    from app.core.security import seal_case_field
    now = now or utcnow()
    event = uuid.uuid4().hex
    told = 0
    has_note = bool(getattr(case, "owner_note_enc", None))
    for owner_id, counts in counts_by_owner.items():
        if owner_id is None:
            continue
        owner = db.get(User, uuid.UUID(str(owner_id)))
        if owner is None:
            continue
        row_details = {**(details or {}), **dict(counts or {})}
        title, body = app_text(facts(db, case, kind, row_details), has_note=has_note)
        notify_in_transaction(db, [owner.id], title=title, body=body, dedup=f"case:{case.id}:{kind}:{event}")
        address, previous = destinations(db, owner)
        row_id = uuid.uuid4()
        row = ComplianceNoticeOutbox(
            id=row_id, case_id=case.id, user_id=owner.id, kind=kind, dedup_key=f"case:{case.id}:{kind}:{event}:{owner.id}",
            details=_jsonable(row_details), status=PENDING if address or previous else NO_ADDRESS, attempts=0,
            next_attempt_at=now if address or previous else None, created_at=now, sent_to=[])
        row.address_enc = seal_case_field(row_id, address, "notice_address") if address else None
        row.previous_address_enc = (seal_case_field(row_id, previous, "notice_previous_address")
                                    if previous else None)
        db.add(row)
        _audit(db, "owner_notice_written", case, actor_name=SYSTEM, user_id=owner.id,
               details={"kind": kind, "vaults": int((counts or {}).get("vaults") or 0),
                        "email_status": row.status if row.status == NO_ADDRESS else CASE_QUEUED,
                        "copy_to_previous": previous is not None})
        told += 1
    if told:
        db.flush()
        refresh_case_status(db, case)
        after_commit.later(db, _WAKE, 1)
    return told


def tell_owner_of_reveal(db, owner_id, *, auditor, vault_id, reason_category: str,
                         now: Optional[datetime] = None) -> bool:
    """Tell ``owner_id`` that ``auditor`` revealed names the log recorded about their vault ``vault_id``, once per
    auditor, vault and day (UTC), in the caller's transaction (the reveal's): the notification, the outbox row and
    the ``owner_notice_written`` row. A later reveal that day folds into it. Returns whether the owner was told now.
    The caller holds the auditor's row locked, so two reveals at once cannot both tell."""
    from app.core.models import ComplianceNoticeOutbox, User
    from app.core.security import seal_case_field
    now = now or utcnow()
    owner = db.get(User, uuid.UUID(str(owner_id)))
    if owner is None:
        return False
    key = f"reveal:{auditor.id}:{vault_id}:{now:%Y-%m-%d}"
    if db.query(ComplianceNoticeOutbox.id).filter(
            ComplianceNoticeOutbox.dedup_key == f"{key}:{owner.id}").first() is not None:
        return False
    row_details = {"auditor": auditor.username, "reason": reason_category, "vaults": 1}
    title, body = app_text(facts(db, None, REVEAL, row_details), has_note=False)
    notify_in_transaction(db, [owner.id], title=title, body=body, dedup=key)
    address, previous = destinations(db, owner)
    row_id = uuid.uuid4()
    row = ComplianceNoticeOutbox(
        id=row_id, case_id=None, user_id=owner.id, kind=REVEAL, dedup_key=f"{key}:{owner.id}",
        details=_jsonable(row_details), status=PENDING if address or previous else NO_ADDRESS, attempts=0,
        next_attempt_at=now if address or previous else None, created_at=now, sent_to=[])
    row.address_enc = seal_case_field(row_id, address, "notice_address") if address else None
    row.previous_address_enc = (seal_case_field(row_id, previous, "notice_previous_address")
                                if previous else None)
    db.add(row)
    _audit(db, "owner_notice_written", None, actor_name=SYSTEM, user_id=owner.id,
           details={"kind": REVEAL, "vaults": 1, "vault_id": str(vault_id),
                    "email_status": row.status if row.status == NO_ADDRESS else CASE_QUEUED,
                    "copy_to_previous": previous is not None})
    db.flush()
    after_commit.later(db, _WAKE, 1)
    return True


def _jsonable(details: Mapping) -> dict:
    out = {}
    for key, value in details.items():
        out[key] = _iso(value) if isinstance(value, datetime) else value
    return out


def _audit(db, action: str, case, *, actor_name: str, user_id=None, details: Optional[dict] = None,
           status: str = "success") -> None:
    """An audit row of the owner's notice, in the caller's transaction, under the case."""
    from app.services.audit_logger import AuditLogger
    with acting_for(case.id if case is not None else None):
        db.add(AuditLogger(db).build_row(
            action=action, status=status, user=None, username=actor_name, resource_type="user",
            resource_id=str(user_id) if user_id is not None else None,
            details={"case_number": getattr(case, "number", None), **(details or {})}))


def case_status(statuses: Iterable[str]) -> Optional[str]:
    """What a case shows of its owners' emails: failed, retrying, queued, sent, or no address, in that order of
    precedence; None when it has written none."""
    seen = set(statuses)
    if not seen:
        return None
    for status, shown in ((FAILED, FAILED), (RETRYING, RETRYING), (PENDING, CASE_QUEUED), (SENT, SENT)):
        if status in seen:
            return shown
    return NO_ADDRESS


def refresh_case_status(db, case) -> None:
    from app.core.models import ComplianceNoticeOutbox
    rows = db.query(ComplianceNoticeOutbox.status).filter(ComplianceNoticeOutbox.case_id == case.id).all()
    case.notice_email_status = case_status(r[0] for r in rows)


# --------------------------------------------------------------------------- the sender

def _limit_statements(db) -> None:
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


_local_turn = threading.Lock()


@contextmanager
def _sender_turn(engine):
    """Whether this pass may send: on Postgres the one holding a session-level advisory lock, taken on a
    connection of its own for the pass, across processes and hosts; elsewhere this process alone."""
    if not _local_turn.acquire(blocking=False):
        yield False
        return
    try:
        if engine is None or engine.dialect.name != "postgresql":
            yield True
            return
        conn = engine.connect().execution_options(isolation_level="AUTOCOMMIT")
        try:
            got = bool(conn.execute(text("SELECT pg_try_advisory_lock(:c, :k)"),
                                    {"c": SENDER_LOCK[0], "k": SENDER_LOCK[1]}).scalar())
            try:
                yield got
            finally:
                if got:
                    conn.execute(text("SELECT pg_advisory_unlock(:c, :k)"), {"c": SENDER_LOCK[0], "k": SENDER_LOCK[1]})
        finally:
            conn.invalidate()     # never back to the pool: a session lock must not outlive the pass
            conn.close()
    finally:
        _local_turn.release()


def open_destination(row, slot: str) -> Optional[str]:
    from app.core.security import open_case_field
    token = row.address_enc if slot == ADDRESS else row.previous_address_enc
    if not token:
        return None
    return open_case_field(row.id, token, "notice_address" if slot == ADDRESS else "notice_previous_address")


def owner_note(case) -> Optional[str]:
    """The auditor's note to the owner, opened for the email: never stored in the clear."""
    from app.core.security import open_case_field
    if not getattr(case, "owner_note_enc", None):
        return None
    try:
        return open_case_field(case.id, case.owner_note_enc, "owner_note")
    except Exception:  # noqa: BLE001 -- a note that does not open is left out, never shown as stored
        return None


def email_context(db, row, case) -> dict:
    """What the email says, for the email action: the notice, the auditor's note (with an activation), and the
    case number for the subject."""
    f = facts(db, case, row.kind, row.details)
    title, lines = notice_text(f)
    note = owner_note(case) if row.kind == ACTIVATION and case is not None else None
    change = " ".join([title + "."] + lines + ([f"Note from the auditor: “{note}”"] if note else []))
    return {"change": change, "code": (case.number if case is not None else None) or "", "when": _when(row.created_at),
            "by": f.contact or ""}


class SendFailed(Exception):
    def __init__(self, category: str):
        super().__init__(category)
        self.category = category


def send_email(db, row, case, address: str, username: Optional[str]) -> None:
    """Hand the notice to SMTP through the email action. Raises SendFailed."""
    from app.core import email_send
    from app.core.email_actions import send_action_email
    try:
        ok = send_action_email(db, EMAIL_ACTION, recipient={"email": address, "username": username or ""},
                               action_context=email_context(db, row, case), raise_errors=True)
    except email_send.EmailSendError as exc:
        raise SendFailed(exc.category)
    if not ok:
        raise SendFailed("not_sent")


def _attempt(db, row, now: datetime, send: Callable) -> str:
    """Send ``row`` to every destination it has not reached yet; record the outcome. Returns the row's status."""
    from app.core.models import ComplianceCase, SecurityAlert, User
    case = db.get(ComplianceCase, row.case_id) if row.case_id is not None else None
    owner = db.get(User, row.user_id) if row.user_id is not None else None
    done = list(row.sent_to or [])
    failure = None
    for slot in (ADDRESS, PREVIOUS):
        if slot in done:
            continue
        try:
            address = open_destination(row, slot)
        except Exception:  # noqa: BLE001 -- a sealed address that does not open cannot be sent to
            failure = failure or "address_unreadable"
            continue
        if address is None:
            continue
        try:
            send(db, row, case, address, owner.username if owner is not None else None)
            done.append(slot)
        except SendFailed as exc:
            failure = failure or exc.category
        except Exception as exc:  # noqa: BLE001 -- a send that breaks is a failed attempt, tried again
            failure = failure or type(exc).__name__
    row.sent_to = done
    row.attempts = (row.attempts or 0) + 1
    if failure is None:
        row.status, row.sent_at, row.next_attempt_at, row.last_error_class = SENT, now, None, None
        _audit(db, "owner_notice_email_sent", case, actor_name=SYSTEM, user_id=row.user_id,
               details={"kind": row.kind, "attempts": row.attempts, "copy_to_previous": PREVIOUS in done})
    elif row.attempts > len(RETRY_MINUTES):
        row.status, row.next_attempt_at, row.last_error_class = FAILED, None, failure[:64]
        _audit(db, "owner_notice_email_failed", case, actor_name=SYSTEM, user_id=row.user_id, status="failure",
               details={"kind": row.kind, "attempts": row.attempts, "send_error": failure[:64]})
        db.add(SecurityAlert(
            event_type="owner_notice_email_failed", severity="warning",
            message=("The email telling a vault's owner about compliance access to their vaults could not be sent "
                     f"after {row.attempts} attempts. The notice stands in the app; check the email settings."),
            user_id=row.user_id, details={"case_id": str(row.case_id) if row.case_id else None,
                                          "case_number": getattr(case, "number", None), "kind": row.kind,
                                          "error": failure[:64]},
            timestamp=now, resolved=False))
    else:
        row.status, row.last_error_class = RETRYING, failure[:64]
        row.next_attempt_at = now + timedelta(minutes=RETRY_MINUTES[row.attempts - 1])
    if case is not None:
        db.flush()
        refresh_case_status(db, case)
    return row.status


def due_query(db, now: datetime):
    """The rows due to be sent, oldest first, each locked for the transaction that reads it; a row another sender
    holds is skipped (SKIP LOCKED), not waited for. The sender's advisory lock already keeps a second sender out;
    one that got in anyway moves on to the next row instead of waiting for the first."""
    from app.core.models import ComplianceNoticeOutbox as O
    return (db.query(O).filter(O.status.in_((PENDING, RETRYING)),
                               or_(O.next_attempt_at.is_(None), O.next_attempt_at <= now))
            .order_by(O.created_at, O.id).with_for_update(skip_locked=True))


def due(db, now: datetime):
    """The next row due to be sent, locked for this transaction (rows another sender holds are skipped)."""
    return due_query(db, now).first()


def send_due(session_factory: Optional[Callable] = None, *, engine=None, now: Optional[Callable] = None,
             send: Optional[Callable] = None, max_rows: int = PASS_ROWS, budget_seconds: float = PASS_SECONDS) -> list:
    """One pass of the sender: every due row, one transaction each, while the pass has rows and time. Returns the
    statuses it left, or [] when another process holds the sender's turn. Never raises."""
    try:
        if session_factory is None:
            from app.core.database import _require_engine, started_session
            session_factory, engine = started_session, _require_engine()
    except Exception as exc:  # noqa: BLE001 -- the next pass asks again
        print(f"Warning: the owner notices' sender did not run ({type(exc).__name__})")
        return []
    clock = now or utcnow
    send = send or send_email
    deadline = time.monotonic() + budget_seconds
    out: List[str] = []
    with _sender_turn(engine) as mine:
        if not mine:
            return out
        while len(out) < max_rows and time.monotonic() < deadline:
            db = session_factory()
            try:
                _limit_statements(db)
                row = due(db, clock())
                if row is None:
                    db.rollback()
                    break
                out.append(_attempt(db, row, clock(), send))
                db.commit()
            except Exception as exc:  # noqa: BLE001 -- the row stays due; the next pass tries again
                db.rollback()
                print(f"Warning: an owner notice could not be sent this time ({type(exc).__name__})")
                break
            finally:
                db.close()
    return out


_wake = threading.Event()
_thread: Optional[threading.Thread] = None
_start_lock = threading.Lock()


def wake() -> None:
    """Send what is due now, not at the next poll (after a step's commit)."""
    _wake.set()


def _loop(poll: float) -> None:
    while True:
        _wake.wait(poll)
        _wake.clear()
        try:
            send_due()
        except Exception as exc:  # noqa: BLE001 -- the sender never stops
            print(f"Warning: the owner notices' sender failed ({type(exc).__name__})")


def start(poll: float = POLL_SECONDS) -> bool:
    """Start the sender's thread in this process (the web process only). Idempotent. Returns whether it started."""
    global _thread
    with _start_lock:
        if _thread is not None and _thread.is_alive():
            return False
        _thread = threading.Thread(target=_loop, args=(poll,), name="owner-notices", daemon=True)
        _thread.start()
        wake()
        return True
