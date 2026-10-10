"""The Activity page with a compliance case selected: its events, and the names the case lets its
auditor read.

Selecting a case (``case=<id>`` on the Events list, one event, the summary and the export) limits the events to the
case's own rows (``case_id``) and the events on its vaults. Its auditor and an administrator who may see the case
(cases.may_see: never one it concerns) may select it; anyone else is answered "no such case".

The case's auditor, while the case gives access (app/core/case_access.py, case_for), also counts as able to read
its vaults for the events' names, under the case's rules and never further: a vault's name as a reader of it sees
it; a file's or a folder's name (live, or kept by a hold) only in the case's folders, in its time range, in a vault
whose contents the case may open (never zero-knowledge; a password vault once unlocked with the case's receipt, or
under the override); and the names the recording levels kept in full in the log, on the same terms. A name never
leaves a vault the case does not cover.

Where the case would name an item but the vault's password, not yet given in the case, hides it, the item reads
"Name hidden: the vault has a password" (also for an auditor who is not a member of the vault) and the event carries
``unlock_in_case``: the page offers the vault's password there, sent to the case's own unlock route (the same rules
and receipt as the case workspace). No one else is told, and no event without it. An item the viewer already reads
through their own unlock of the vault on the Activity page (an administrator's: the name as recorded, or that none
was) keeps what that shows, and is not offered.

``case_names_viewed`` is written only when a page shows at least one name because of the case (a name the auditor
would not see without it), and at most once per auditor, case and set of such events in ten minutes. Every
committed row signals the open page, which fetches it: a row per page would feed itself. The row carries
how many events and their vaults' ids, never a name; it commits before the names are sent, and when it cannot be
written the page is refused (503).
"""
from __future__ import annotations

import hashlib
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from typing import Dict, List, Optional, Set

QUIET = timedelta(minutes=10)
VIEWED = "case_names_viewed"
# On an event whose item the case would name once the vault's password is given in the case.
UNLOCK_IN_CASE = "unlock_in_case"


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


@dataclass
class Selection:
    """A case selected on the Activity page: the vaults whose events it shows, and whether (and how) its names
    show."""
    case: object
    vault_ids: List[str]
    names: bool = False
    unlocked: Set[str] = field(default_factory=set)


def select(db, viewer, case_id, *, unlock_header: Optional[str] = None, session_hash: Optional[str] = None,
           now: Optional[datetime] = None) -> Selection:
    """The case ``case_id`` as ``viewer`` may select it. Raises HTTPException(404) for a case they may not see."""
    from fastapi import HTTPException
    from app.core import case_access as ca
    from app.core import case_rules as rules
    from app.core import cases
    from app.core.models import ComplianceCase
    cid = rules.as_id(case_id)
    case = db.get(ComplianceCase, cid) if cid is not None else None
    if case is None or not cases.may_see(db, case, viewer):
        raise HTTPException(status_code=404, detail="No such case.")
    vault_ids = [str(r.vault_id) for r in cases.vault_rows(db, case)]
    selection = Selection(case, vault_ids)
    if cases.is_auditor_of(case, viewer):
        try:
            ca.case_for(db, case.id, viewer, now=now)
        except ca.Refused:
            return selection
        selection.names = True
        selection.unlocked = ca.unlocked_vaults(db, case, viewer, session_hash,
                                                ca.parse_unlock_header(unlock_header))
    return selection


# --------------------------------------------------------------------------- what the case lets its auditor read

class _Reader:
    """What the selected case lets its auditor read, vault by vault, read once per page."""

    def __init__(self, db, selection: Selection, now: datetime):
        from app.core import case_access as ca
        from app.core.models import Vault
        self.db, self.case, self.now = db, selection.case, now
        self.rows = ca.covering_rows(db, self.case) if selection.names else {}
        self.vaults, self.openings, self.folders = {}, {}, {}
        for vid, row in self.rows.items():
            vault = db.get(Vault, vid)
            if vault is None:
                continue
            try:
                opening = ca.vault_opening(self.case, vault, row, selection.unlocked)
            except ca.Refused:
                continue
            self.vaults[vid] = vault
            self.openings[vid] = opening

    def covers(self, vault_id) -> bool:
        return vault_id in self.vaults

    def vault_name(self, vault_id) -> Optional[str]:
        return self.vaults[vault_id].name if vault_id in self.vaults else None

    def items_open(self, vault_id) -> bool:
        """Whether the case shows file and folder names in this vault: not zero-knowledge, not locked."""
        from app.core import case_access as ca
        opening = self.openings.get(vault_id)
        return (opening is not None and opening.names and not opening.locked
                and not ca.is_zero_knowledge(self.vaults[vault_id], self.rows[vault_id]))

    def _folders(self, vault_id):
        from app.core import case_access as ca
        if vault_id not in self.folders:
            self.folders[vault_id] = ca.Folders(self.db, vault_id, now=self.now)
        return self.folders[vault_id]

    def _scope(self, vault_id):
        from app.core import case_access as ca
        return ca.scope_of(self.rows[vault_id])

    def item(self, vault_id, kind: str, item_id):
        """The item (a file or a folder, live or kept) when the case may name it, else None."""
        if item_id is None or not self.items_open(vault_id):
            return None
        return self._in_case(vault_id, kind, item_id)

    def hidden_by_password(self, vault_id, kind: str, item_id) -> bool:
        """Whether only the vault's password keeps this item's name from the case's auditor: the case opens the vault
        with its password and it is not unlocked in the case, and the item (live or kept) is one the case names once
        it is (in its folders and time range, never a file with a password of its own). Reads only the columns those
        checks need, so no name is decrypted for it."""
        opening = self.openings.get(vault_id)
        if item_id is None or opening is None or not opening.locked:
            return False
        return self._in_case(vault_id, kind, item_id, names=False) is not None

    def _in_case(self, vault_id, kind: str, item_id, *, names: bool = True):
        """The item when it is in the case's vault, folders and time range (with ``names``, the row itself, its name
        decrypted on load; without, only the columns the checks read), else None."""
        from app.core import case_access as ca
        from app.core import case_rules as rules
        from app.core.models import File, Folder, HeldFile, HeldFolder
        live, kept = (File, HeldFile) if kind == "file" else (Folder, HeldFolder)
        if names:
            obj = self.db.get(live, item_id)
        else:
            obj = self.db.query(*_check_columns(live)).filter(live.id == item_id).first()
        if obj is None and ca._kept_readable(self.db):
            q = self.db.query(kept) if names else self.db.query(*_check_columns(kept))
            obj = q.filter(kept.id == item_id, ca._not_due(kept, self.now)).first()
        if obj is None or obj.vault_id != vault_id:
            return None
        scope = self._scope(vault_id)
        folders = self._folders(vault_id)
        if kind == "file":
            if scope is not None and not rules.in_scope(scope, obj.id, folders.chain(obj.folder_id)):
                return None
            if not ca.in_range(self.case, obj):
                return None
            if getattr(obj, "password_hash", None) and ca.policy(self.case) != "override":
                return None
        else:
            chain = folders.chain(obj.id)
            covered = scope is None or rules.in_scope(scope, obj.id, chain[1:])
            if not covered and str(obj.id) not in folders.leading(scope):
                return None
        return obj


# What _Reader._in_case checks of an item, and nothing else: its name stays sealed.
_CHECKED = ("id", "vault_id", "folder_id", "created_at", "updated_at", "password_hash")


def _check_columns(model):
    return [getattr(model, c) for c in _CHECKED if hasattr(model, c)]


def case_names(db, selection: Selection, events: List[dict], rows, *, now: Optional[datetime] = None) -> List[set]:
    """Show in ``events`` (with their "names" and "recorded_names" already set for the viewer) the names the case
    lets its auditor read, in place, and mark the events whose item the vault's password given in the case would name
    (UNLOCK_IN_CASE). Returns, per event, the keys shown because of the case (empty: none)."""
    from app.services.activity_names import NOT_SHOWN, PASSWORD_HIDDEN, VAULT_NAME_KEY, targets
    now = now or utcnow()
    shown: List[set] = [set() for _ in events]
    if not selection.names:
        return shown
    reader = _Reader(db, selection, now)
    for i, (event, row) in enumerate(zip(events, rows)):
        vault_id, (kind, item_id) = targets(event)
        if vault_id is None or not reader.covers(vault_id):
            continue
        names = event.setdefault("names", {}) or {}
        event["names"] = names
        vault_name = reader.vault_name(vault_id)
        if vault_name and names.get("vault") != vault_name:
            names["vault"] = vault_name
            shown[i].add("vault")
        if kind in ("file", "folder"):
            obj = reader.item(vault_id, kind, item_id)
            name = (getattr(obj, "original_name", None) or getattr(obj, "name", None)) if obj is not None else None
            if name and names.get("item") != name:
                names["item"] = name
                shown[i].add("item")
            elif (obj is None and names.get("item") in (NOT_SHOWN, PASSWORD_HIDDEN)
                  and reader.hidden_by_password(vault_id, kind, item_id)):
                # Not a name: what hides it, and that the vault's password given in the case shows it. Only over
                # what hid it from the viewer anyway: what their own unlock of the vault shows them stays.
                names["item"] = PASSWORD_HIDDEN
                event[UNLOCK_IN_CASE] = True
        recorded = _recorded(db, reader, row, vault_id, kind, item_id)
        if recorded:
            mine = event.get("recorded_names") or {}
            for key, entry in recorded.items():
                if entry.get("name") and (mine.get(key) or {}).get("name") != entry["name"]:
                    mine[key] = entry
                    shown[i].add("recorded:" + key if key != VAULT_NAME_KEY else "recorded:vault")
            event["recorded_names"] = mine
        if shown[i]:
            event["shown_by_case"] = sorted(shown[i])
    return shown


def _recorded(db, reader: _Reader, row, vault_id, kind, item_id) -> Optional[dict]:
    """The names the recording levels kept in full on ``row``, opened as the case lets its auditor read them: the
    vault's in a vault the case covers; an item's only where the case may name that item (it must still be found, in
    the case's folders and time range)."""
    from app.core.audit_privacy import open_name
    from app.services.activity_names import SEALED_UNREADABLE, VAULT_NAME_KEY, _recorded_names, _uuid
    kept = _recorded_names(row) if row is not None else None
    if not kept or _uuid(kept.get("vault")) != vault_id:
        return None
    item_ok = kind in ("file", "folder") and reader.item(vault_id, kind, item_id) is not None
    out = {}
    for key, value in kept["values"].items():
        if not isinstance(value, dict) or not value.get("sealed"):
            continue
        if key != VAULT_NAME_KEY and not item_ok:
            continue
        try:
            name = open_name(vault_id, row.id, key, value["sealed"])
        except Exception:  # noqa: BLE001 -- a value that does not open is said to, never guessed at
            name = SEALED_UNREADABLE
        out[key] = {"fingerprint": value.get("fp"), "name": name}
    return out


# --------------------------------------------------------------------------- recording what was shown

def events_digest(event_ids) -> str:
    return hashlib.sha256("\n".join(sorted(str(e) for e in event_ids)).encode("utf-8")).hexdigest()[:32]


def note_names_viewed(db, selection: Selection, viewer, events: List[dict], shown: List[set],
                      now: Optional[datetime] = None) -> bool:
    """Record that a page showed names because of the case (the events where ``shown`` is not empty), unless the
    same set was recorded for this auditor and case in the last ten minutes. Returns whether a row was written.
    Raises HTTPException(503) when it cannot be written: the names are then not sent."""
    from fastapi import HTTPException
    from app.core import case_access as ca
    from app.core.models import AuditLog
    from app.services.activity_names import targets
    now = now or utcnow()
    ids = [e.get("id") for e, keys in zip(events, shown) if keys]
    if not ids:
        return False
    digest = events_digest(ids)
    recent = db.query(AuditLog.id).filter(
        AuditLog.case_id == selection.case.id, AuditLog.user_id == viewer.id, AuditLog.action == VIEWED,
        AuditLog.status == "success", AuditLog.timestamp >= now - QUIET,
        AuditLog.details["events_digest"].as_string() == digest).first()
    if recent is not None:
        return False
    vaults = sorted({str(targets(e)[0]) for e, keys in zip(events, shown) if keys and targets(e)[0]})
    try:
        ca.record(db, selection.case, viewer, VIEWED, resource_type="case", resource_id=selection.case.id,
                  details={"events": len(ids), "events_digest": digest, "vault_ids": vaults})
    except ca.Refused:
        raise HTTPException(status_code=503, detail={
            "reason": ca.RECORD_FAILED,
            "text": "The names shown because of the case could not be recorded, so they were not shown."})
    return True


def as_uuid(value) -> Optional[uuid.UUID]:
    try:
        return uuid.UUID(str(value))
    except (TypeError, ValueError, AttributeError):
        return None
