"""Revealing a name the activity log recorded in full, outside a case.

An auditor whose right is in force asks for one event's recorded names, with a reason (a category from a short list,
and text). The answer is that event's values as the recording levels kept them in full (sealed in the row's
``recorded`` column, app/core/audit_privacy.py), and only those: never a name read now from the vault, never a value
kept only as a fingerprint (a fingerprint stays a fingerprint, and fingerprints are shown only for vaults the viewer
can read, so none is returned), never anything of a zero-knowledge vault or of a vault with a password, whatever
COMPLIANCE_PASSWORD_VAULTS says: outside a case there is no approver, so there is no override. A vault the auditor
can read shows its names on the event already; a vault gone since cannot be shown to have had no password, so it is
refused.

In the one transaction that answers it: the ``audit_name_revealed`` row (the event, the vault, the reason's
category), a ``compliance_reveals`` row with the reason's text sealed, and, the first time that day (UTC) that this
auditor reveals in that vault, its owner's notice (app/core/owner_notices.py: in the app and through the email
outbox; later reveals that day fold into it). The reveal row is written even when the event yields no value: asking
is what is accountable. COMPLIANCE_REVEALS_PER_DAY caps an auditor's reveals in a day; the auditor's account row is
locked for the reveal, so two at once cannot pass the cap or both tell the owner.

A refused reveal (no such event, no vault, a vault refused, the cap) is recorded, in a transaction of its own.
"""
from __future__ import annotations

import uuid
from datetime import datetime, timezone
from typing import Optional

from app.core import compliance_settings as cs

REASONS = ("security_incident", "internal_investigation", "regulator_request", "data_subject_request",
           "litigation_hold", "other")
REASON_MAX = 2000
ACTION = "audit_name_revealed"

NO_SUCH_EVENT = "no_such_event"
NO_VAULT = "no_vault"
VAULT_GONE = "vault_gone"
ZERO_KNOWLEDGE = "zero_knowledge"
PASSWORD_VAULT = "password_vault"
READABLE = "readable"
CAP = "reveal_cap"
BAD_REASON = "bad_reason"
NO_REASON = "no_reason"
LONG_REASON = "reason_too_long"

TEXTS = {
    NO_SUCH_EVENT: "There is no such event in the log.",
    NO_VAULT: "This event is not about a vault: it records no name to reveal.",
    VAULT_GONE: "The vault of this event no longer exists, so it cannot be shown to have had no password.",
    ZERO_KNOWLEDGE: "This event is about a zero-knowledge vault: nothing of its names was ever recorded.",
    PASSWORD_VAULT: "This event is about a vault with a password: its names are never revealed outside a case.",
    READABLE: "You can read this vault: its names show on the event already.",
    CAP: "You have revealed as many names today as this deployment allows (COMPLIANCE_REVEALS_PER_DAY).",
    BAD_REASON: "Choose the reason's category from the list.",
    NO_REASON: "Say why you reveal it.",
    LONG_REASON: f"Say why you reveal it in at most {REASON_MAX:,} characters.",
}
STATUS = {NO_SUCH_EVENT: 404, NO_VAULT: 409, VAULT_GONE: 409, ZERO_KNOWLEDGE: 403, PASSWORD_VAULT: 403,
          READABLE: 409, CAP: 429, BAD_REASON: 422, NO_REASON: 422, LONG_REASON: 422}


class RevealRefused(Exception):
    def __init__(self, reason: str, *, record: bool = True):
        super().__init__(reason)
        self.reason = reason
        self.record = record

    @property
    def status(self) -> int:
        return STATUS.get(self.reason, 403)

    @property
    def text(self) -> str:
        return TEXTS.get(self.reason, self.reason)


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def day_start(now: datetime) -> datetime:
    return now.replace(hour=0, minute=0, second=0, microsecond=0)


def check_reason(category: Optional[str], text: Optional[str]) -> str:
    """The reason's text, stripped. Raises RevealRefused (422, not recorded) for one missing, not on the list, or
    longer than REASON_MAX: the reason is sealed whole, never cut short."""
    if category not in REASONS:
        raise RevealRefused(BAD_REASON, record=False)
    cleaned = (text or "").strip()
    if not cleaned:
        raise RevealRefused(NO_REASON, record=False)
    if len(cleaned) > REASON_MAX:
        raise RevealRefused(LONG_REASON, record=False)
    return cleaned


def _event_vault(row) -> Optional[uuid.UUID]:
    from app.services.activity_events import row_view
    from app.services.activity_names import _recorded_names, _uuid, targets
    names = _recorded_names(row)
    if names and _uuid(names.get("vault")) is not None:
        return _uuid(names.get("vault"))
    return targets(row_view(row))[0]


def reveals_today(db, auditor, now: datetime) -> int:
    from sqlalchemy import func
    from app.core.models import ComplianceReveal
    return int(db.query(func.count(ComplianceReveal.id)).filter(
        ComplianceReveal.auditor_id == auditor.id, ComplianceReveal.created_at >= day_start(now)).scalar() or 0)


def reveal(db, auditor, event_id, *, reason_category: str, reason_text: str, now: Optional[datetime] = None) -> dict:
    """Reveal ``event_id``'s recorded names to the live auditor ``auditor``, in the caller's transaction (the caller
    commits before it answers). Returns {"event_id", "vault_id", "names": {key: value}, "not_in_full": [key]}.
    Raises RevealRefused."""
    from app.core import owner_notices
    from app.core.audit_privacy import open_name
    from app.core.models import AuditLog, ComplianceReveal, User, Vault
    from app.core.security import seal_case_field
    from app.services.activity_names import _recorded_names, readable_vault_ids
    now = now or utcnow()
    text = check_reason(reason_category, reason_text)
    # One reveal of this auditor at a time: the cap and the day's one notice hold under two at once.
    db.query(User.id).filter(User.id == auditor.id).with_for_update().first()
    try:
        eid = uuid.UUID(str(event_id))
    except (TypeError, ValueError):
        raise RevealRefused(NO_SUCH_EVENT)
    row = db.get(AuditLog, eid)
    if row is None:
        raise RevealRefused(NO_SUCH_EVENT)
    vault_id = _event_vault(row)
    if vault_id is None:
        raise RevealRefused(NO_VAULT)
    vault = db.get(Vault, vault_id)
    if vault is None:
        raise RevealRefused(VAULT_GONE)
    if (vault.type or "standard") == "zero_knowledge":
        raise RevealRefused(ZERO_KNOWLEDGE)
    if vault.password_hash:
        raise RevealRefused(PASSWORD_VAULT)
    if vault_id in readable_vault_ids(db, auditor, {vault_id}):
        raise RevealRefused(READABLE)
    if reveals_today(db, auditor, now) >= int(cs.current(cs.REVEALS_PER_DAY)):
        raise RevealRefused(CAP)

    names, not_in_full = {}, []
    kept = _recorded_names(row)
    if kept and kept.get("vault") is not None and str(kept.get("vault")) == str(vault_id):
        for key, value in kept["values"].items():
            if isinstance(value, dict) and value.get("sealed"):
                names[key] = open_name(vault_id, row.id, key, value["sealed"])
            else:
                not_in_full.append(key)

    reveal_id = uuid.uuid4()
    db.add(ComplianceReveal(id=reveal_id, event_id=row.id, auditor_id=auditor.id, auditor_username=auditor.username,
                            vault_id=vault_id, reason_category=reason_category,
                            reason_text_enc=seal_case_field(reveal_id, text, "reveal_reason"), created_at=now))
    _audit(db, auditor, row.id, details={"event_id": str(row.id), "vault_id": str(vault_id),
                                         "reason_category": reason_category, "count": len(names)})
    if vault.owner_id is not None:
        owner_notices.tell_owner_of_reveal(db, vault.owner_id, auditor=auditor, vault_id=vault_id,
                                           reason_category=reason_category, now=now)
    db.flush()
    return {"event_id": str(row.id), "vault_id": str(vault_id), "names": names, "not_in_full": sorted(not_in_full)}


def _audit(db, auditor, event_id, *, details: dict, status: str = "success") -> None:
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(action=ACTION, status=status, user=auditor, resource_type="audit_event",
                                     resource_id=str(event_id) if event_id is not None else None, details=details))


def record_refused(db, auditor, event_id, reason: str) -> None:
    """A refused reveal's row, in a transaction of its own. Never raises."""
    try:
        try:
            eid = str(uuid.UUID(str(event_id)))
        except (TypeError, ValueError):
            eid = None
        _audit(db, auditor, eid, details={"event_id": eid, "reason": reason}, status="failure")
        db.commit()
    except Exception:  # noqa: BLE001 -- the refusal stands either way
        db.rollback()
