"""Exporting a compliance case's files: prepared once with a fresh code, fetched once by the auditor who prepared it,
streamed as a ZIP64 archive built while it downloads, never stored.

Preparing (POST .../exports, the compliance step-up): the case must allow export (asked for and approved with it)
and the deployment must too (COMPLIANCE_EXPORT, the stricter of the value at the approval and now). The files are
chosen by id, or every file the case covers; each passes the checks of reading one (app/core/case_access.py: in the
case's vaults, folders and time range, never zero-knowledge, a password vault only once unlocked or under the
override). Their ids are kept on the export row with ``case_export_started``. No token is made: the export is
fetched with the auditor's own session.

Fetching (GET .../exports/{id}): once, by the account that prepared it, before COMPLIANCE_EXPORT_TTL_HOURS. The case
and every file are checked again first (nothing changes until they pass; a file gone from the vault altogether is
listed as missing). Then, in one transaction, the export is marked fetched and each owner of a vault it reads from
is told ("N files exported from your vaults"), in the app and through the email outbox
(app/core/owner_notices.py): no copy leaves before its owner's notice exists. Then the archive streams:

    files/<vault id>/<folder path>/<name>   each path segment made safe and unique; the original names are in
                                            the manifest, never trusted as a path
    manifest.json, manifest.csv             per file: id, vault, original path and name, size, uploaded and
                                            changed (when, by whom), status, the SHA-256 of the bytes exported
                                            and whether it matches the checksum stored for the file
    case.json                               number, purpose, legal basis, scope, auditor, approver, dates (never
                                            the justification, the owners' note or the people named)
    README.txt                              how to check it, and that it is personal data
    SHA256SUMS                              for ``sha256sum -c``

The stream reads with sessions of its own (the request's may be gone while it runs) and checks the case again
before each file: an export stops when the case's access does. Each file is checked again too, as the fetch checked
it: one moved out of the case's folders or time range, in a vault narrowed out of the case or made zero-knowledge,
or in a vault that has a password the fetch did not open, is left out and listed as having left the case. Files are decrypted piece by piece and written
straight into the archive, so memory stays bounded whatever their size. The stored checksum is used only to compare
and is never written out. When the stream ends, ``case_export_completed`` records the manifest's SHA-256, the
number of files and the bytes; a stream that stops early (the client went away, the case's access ended, a file
could not be read to its end) records ``case_export_aborted``, once, whether or not a byte was sent: a new export
is then needed, and is recorded too.
"""
from __future__ import annotations

import csv
import hashlib
import io
import json
import unicodedata
import uuid
import zipfile
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from typing import Callable, Dict, Iterable, Iterator, List, Optional, Tuple

from app.core import case_access as ca
from app.core import case_rules as rules
from app.core import compliance_settings as cs

# The most files one export carries.
MAX_FILES = 10_000

CASE_NO_EXPORT = "case_no_export"
EXPORT_OFF = rules.EXPORT_OFF
NO_FILES = "no_files"
TOO_MANY_FILES = "too_many_files"
NO_SUCH_EXPORT = "no_such_export"
FETCHED = "export_fetched"
EXPIRED = "export_expired"

TEXTS = {
    CASE_NO_EXPORT: "This case was not approved to export.",
    EXPORT_OFF: "Exports are turned off on this deployment.",
    NO_FILES: "Choose the files to export, or every file of the case.",
    TOO_MANY_FILES: f"An export carries at most {MAX_FILES:,} files: choose fewer.",
    NO_SUCH_EXPORT: "No such export.",
    FETCHED: "This export was fetched already: prepare a new one.",
    EXPIRED: "This export waited too long to be fetched: prepare a new one.",
}
ca.TEXTS.update(TEXTS)
ca.STATUS.update({NO_SUCH_EXPORT: 404, FETCHED: 410, EXPIRED: 410, NO_FILES: 422, TOO_MANY_FILES: 413,
                  CASE_NO_EXPORT: 403, EXPORT_OFF: 403})

# A path segment in the archive: at most this many characters.
SEGMENT_MAX = 120
_RESERVED = {"con", "prn", "aux", "nul", *(f"com{i}" for i in range(1, 10)), *(f"lpt{i}" for i in range(1, 10))}
_UNSAFE = set('<>:"|?*\\/')

# A file's status in the manifest, besides case_access's (live, expired, deleted_kept, expired_kept).
MISSING = "missing"            # gone from the vault before it could be read (not kept, or kept and now due)
UNREADABLE = "unreadable"      # its stored content could not be opened
LEFT_CASE = "left_case"        # no longer one the case may export when its turn came (see ExportStream._may_read)

OK, MISMATCH = "ok", "mismatch"


def refusal(case) -> Optional[str]:
    """Why ``case`` may not export now, or None."""
    if not case.can_export:
        return CASE_NO_EXPORT
    if cs.case_value(cs.EXPORT, case.settings_at_approval) != cs.ALLOWED:
        return EXPORT_OFF
    return None


def check(case) -> None:
    why = refusal(case)
    if why is not None:
        raise ca.Refused(why)


# --------------------------------------------------------------------------- choosing the files

def _all_files(db, case, unlocked, now) -> List[str]:
    """Every file the case covers that its export may read: live and kept, in its folders and time range, in the
    vaults whose contents it may open now (never zero-knowledge; a password vault once unlocked or under the
    override; a file with a password of its own only under the override)."""
    from app.core.models import File, HeldFile, Vault
    out: List[Tuple[str, str]] = []
    kept_ok = ca._kept_readable(db)
    for vid, row in ca.covering_rows(db, case).items():
        vault = db.get(Vault, vid)
        if vault is None or ca.is_zero_knowledge(vault, row):
            continue
        try:
            opening = ca.vault_opening(case, vault, row, unlocked)
        except ca.Refused:
            continue
        if opening.locked:
            continue
        own_passwords = ca.policy(case) == cs.OVERRIDE
        scope = ca.scope_of(row)
        folders = ca.Folders(db, vid, now=now)
        sources = [(File, False)] + ([(HeldFile, True)] if kept_ok else [])
        live = set()
        for model, kept in sources:
            q = db.query(model.id, model.folder_id, model.created_at, model.updated_at,
                         model.password_hash).filter(model.vault_id == vid)
            if kept:
                q = q.filter(ca._not_due(model, now))
            for fid, folder, created, updated, own_password in q.all():
                if kept and str(fid) in live:
                    continue
                if not ca.times_in_range(case, created, updated):
                    continue
                if scope is not None and not rules.in_scope(scope, fid, folders.chain(folder)):
                    continue
                if own_password and not own_passwords:
                    continue
                if not kept:
                    live.add(str(fid))
                out.append((str(vid), str(fid)))
    return [fid for _v, fid in sorted(set(out))]


def choose(db, case, *, file_ids: Optional[Iterable] = None, every: bool = False, unlocked: Iterable = (),
           now: Optional[datetime] = None) -> List[ca.Found]:
    """The files an export of ``case`` carries: ``file_ids``, or ``every`` file the case covers. Each passes the
    checks of reading one. Raises Refused."""
    now = now or ca.utcnow()
    if every == bool(file_ids):
        raise ca.Refused(NO_FILES, record=False)
    ids = _all_files(db, case, unlocked, now) if every else list(dict.fromkeys(str(i) for i in file_ids))
    if not ids:
        raise ca.Refused(NO_FILES, record=False)
    if len(ids) > MAX_FILES:
        raise ca.Refused(TOO_MANY_FILES, record=False)
    found = []
    for fid in ids:
        item = ca.file_for(db, case, fid, now=now)
        ca.content_opening(case, item, unlocked)
        found.append(item)
    return found


# --------------------------------------------------------------------------- preparing

def prepare(db, case, user, found: List[ca.Found], *, unlocked: Iterable = (), now: Optional[datetime] = None):
    """The export row for ``found``, with its ``case_export_started`` row, in the caller's transaction."""
    from app.core.models import ComplianceExport
    now = now or ca.utcnow()
    ttl = int(cs.case_value(cs.EXPORT_TTL_HOURS, case.settings_at_approval))
    export = ComplianceExport(id=uuid.uuid4(), case_id=case.id, created_by=user.id, created_at=now,
                              expires_at=now + timedelta(hours=ttl), status="ready",
                              file_ids=[str(f.item.id) for f in found], file_count=len(found),
                              total_bytes=sum(int(f.item.size_bytes or 0) for f in found))
    db.add(export)
    details = {"export_id": str(export.id), "file_count": len(found), "total_bytes": export.total_bytes,
               "vault_ids": sorted({str(f.vault.id) for f in found}), "expires_at": ca._iso(export.expires_at)}
    if any(ca.content_opening(case, f, unlocked).override for f in found):
        details["password_override"] = True
    ca._row(db, case, user, "case_export_started", resource_type="case", resource_id=case.id, details=details)
    return export


# --------------------------------------------------------------------------- fetching

@dataclass
class Entry:
    """One file of the export: what the manifest says of it. Ids and text only: the stream reads the rows again
    with sessions of its own."""
    file_id: str
    vault_id: Optional[str] = None
    kept: bool = False
    status: str = MISSING
    folder_path: List[str] = field(default_factory=list)
    name: Optional[str] = None
    arcname: Optional[str] = None
    size: Optional[int] = None
    uploaded_at: Optional[str] = None
    uploaded_by: Optional[str] = None
    changed_at: Optional[str] = None
    changed_by: Optional[str] = None
    sha256: Optional[str] = None
    integrity: Optional[str] = None
    when: Optional[datetime] = None
    # Its vault's password was given (a receipt) when the export was fetched: the stream reads it as opened then.
    unlocked: bool = False


def claim(db, case_id, export_id, user, *, unlocked_given=None, session_hash=None, now: Optional[datetime] = None):
    """(case, export, entries) for fetching ``export_id``: the case and every file checked again, then, in one
    transaction, the export marked fetched (only once, only by its maker, before it expires) and each owner told.
    Raises Refused before anything changes."""
    from sqlalchemy import update
    from app.core import owner_notices
    from app.core.models import ComplianceExport
    now = now or ca.utcnow()
    case = ca.case_for(db, case_id, user, now=now)
    check(case)
    eid = rules.as_id(export_id)
    export = db.get(ComplianceExport, eid) if eid is not None else None
    if export is None or export.case_id != case.id or str(export.created_by) != str(user.id):
        raise ca.Refused(NO_SUCH_EXPORT)
    if export.fetched_at is not None:
        raise ca.Refused(FETCHED)
    if export.expires_at <= now:
        raise ca.Refused(EXPIRED)
    unlocked = ca.unlocked_vaults(db, case, user, session_hash, unlocked_given or {})
    entries: List[Entry] = []
    owners: Dict[str, Dict[str, object]] = {}
    for fid in export.file_ids or []:
        try:
            found = ca.file_for(db, case, fid, now=now)
        except ca.Refused as refused:
            if refused.reason != ca.NO_SUCH_FILE:
                raise
            entries.append(Entry(file_id=str(fid)))
            continue
        ca.content_opening(case, found, unlocked)
        entries.append(Entry(file_id=str(found.item.id), vault_id=str(found.vault.id), kept=found.kept,
                             status=found.status, unlocked=str(found.vault.id) in unlocked))
        if found.vault.owner_id is not None:
            counts = owners.setdefault(str(found.vault.owner_id), {"files": 0, "vaults": set()})
            counts["files"] += 1
            counts["vaults"].add(str(found.vault.id))
    taken = db.execute(update(ComplianceExport).where(
        ComplianceExport.id == export.id, ComplianceExport.fetched_at.is_(None),
        ComplianceExport.created_by == user.id, ComplianceExport.expires_at > now)
        .values(fetched_at=now, status="streaming")).rowcount
    if taken != 1:
        db.rollback()
        raise ca.Refused(FETCHED)
    owner_notices.tell_owners(db, case, owner_notices.EXPORT,
                              {o: {"files": c["files"], "vaults": len(c["vaults"])} for o, c in owners.items()},
                              now=now, details={"by": case.auditor_username})
    db.commit()
    db.refresh(export)
    return case, export, entries


# --------------------------------------------------------------------------- the archive's names

def safe_segment(text: Optional[str], fallback: str) -> str:
    """One path segment of the archive: no separator, no drive, no parent or current folder, no control or
    formatting character, no name Windows reserves, at most SEGMENT_MAX characters (the extension kept)."""
    value = unicodedata.normalize("NFC", text or "")
    value = "".join("_" if ch in _UNSAFE else ch for ch in value
                    if unicodedata.category(ch) not in ("Cc", "Cf", "Cs", "Co", "Zl", "Zp"))
    value = value.strip().strip(".").strip()
    if not value:
        value = fallback
    stem, dot, ext = value.rpartition(".")
    if not dot or not stem or len(ext) > 16:
        stem, ext = value, ""
    if stem.split(".")[0].strip().lower() in _RESERVED:
        stem = "_" + stem
    if len(stem) + len(ext) + (1 if ext else 0) > SEGMENT_MAX:
        stem = stem[:SEGMENT_MAX - len(ext) - (1 if ext else 0)].rstrip(". ") or fallback[:8]
    return f"{stem}.{ext}" if ext else stem


def unique_path(path: str, taken: set) -> str:
    """``path``, or ``name (2).ext`` and so on, unused in ``taken`` (compared ignoring case); added to it."""
    folder, _, name = path.rpartition("/")
    stem, dot, ext = name.rpartition(".")
    if not dot or not stem:
        stem, ext = name, ""
    candidate, n = path, 1
    while candidate.casefold() in taken:
        n += 1
        candidate = f"{folder}/{stem} ({n}){'.' + ext if ext else ''}"
    taken.add(candidate.casefold())
    return candidate


def _row_of(db, entry: Entry, now: datetime):
    """(the file's row, its vault, kept) as they stand now, or (None, None, False): the live row, else the row a
    hold kept, also since the export was fetched."""
    from app.core.models import File, HeldFile, Vault
    if entry.vault_id is None:
        return None, None, False
    fid, vid = uuid.UUID(entry.file_id), uuid.UUID(entry.vault_id)
    item, kept = (None if entry.kept else db.get(File, fid)), False
    if item is None and ca._kept_readable(db):
        item = db.query(HeldFile).filter(HeldFile.id == fid, ca._not_due(HeldFile, now)).first()
        kept = item is not None
    if item is None or item.vault_id != vid:
        return None, None, False
    return item, db.get(Vault, vid), kept


def place(db, entries: List[Entry], *, now: datetime) -> None:
    """Give each entry its original folder path, name and dates, and its archive path, made safe and unique."""
    rows: Dict[str, object] = {}
    for e in entries:
        item, _vault, kept = _row_of(db, e, now)
        if item is None:
            e.status = MISSING
            continue
        rows[e.file_id] = item
        if kept and not e.kept:
            e.kept, e.status = True, ca.status_of(item, True, now)
    users = ca._usernames(db, [getattr(i, a, None) for i in rows.values() for a in ("uploaded_by", "modified_by")])
    by_vault: Dict[str, List[Entry]] = {}
    for e in entries:
        if e.file_id in rows:
            by_vault.setdefault(e.vault_id, []).append(e)
    taken: set = set()
    for vid in sorted(by_vault):
        folders = ca.Folders(db, uuid.UUID(vid), now=now)
        chains = {e.file_id: list(reversed(folders.chain(rows[e.file_id].folder_id))) for e in by_vault[vid]}
        names = ca.folders_names(db, uuid.UUID(vid), sorted({f for c in chains.values() for f in c}), True)
        for e in by_vault[vid]:
            item = rows[e.file_id]
            by = getattr(item, "uploaded_by", None)
            changed = getattr(item, "modified_by", None) or by
            e.folder_path = [names.get(f) or f for f in chains[e.file_id]]
            e.name = item.original_name or item.name
            e.uploaded_at, e.changed_at = ca._iso(item.created_at), ca._iso(item.updated_at)
            e.uploaded_by = users.get(str(by)) if by else None
            e.changed_by = users.get(str(changed)) if changed else None
            e.when = item.updated_at or item.created_at
        for e in sorted(by_vault[vid], key=lambda x: (x.folder_path, x.name or "", x.file_id)):
            parts = ["files", vid] + [safe_segment(names.get(f), f[:8]) for f in chains[e.file_id]]
            parts.append(safe_segment(e.name, e.file_id[:8]))
            e.arcname = unique_path("/".join(parts), taken)


# --------------------------------------------------------------------------- the archive

class _Sink:
    """What zipfile writes to: it keeps the bytes until the stream takes them."""

    def __init__(self):
        self._parts: List[bytes] = []
        self.written = 0

    def write(self, data) -> int:
        data = bytes(data)
        self._parts.append(data)
        self.written += len(data)
        return len(data)

    def flush(self) -> None:
        pass

    def take(self) -> bytes:
        out = b"".join(self._parts)
        self._parts.clear()
        return out


def _zip_time(value: Optional[datetime]) -> Tuple[int, int, int, int, int, int]:
    value = value or datetime(1980, 1, 1)
    if value.year < 1980:
        value = datetime(1980, 1, 1)
    if value.year > 2107:
        value = datetime(2107, 12, 31, 23, 59, 58)
    return (value.year, value.month, value.day, value.hour, value.minute, value.second)


def _csv_cell(value) -> str:
    """A value as a spreadsheet cell: text that a spreadsheet would read as a formula starts with an apostrophe."""
    text = "" if value is None else str(value)
    return "'" + text if text[:1] in ("=", "+", "-", "@", "\t", "\r") else text


MANIFEST_FIELDS = ("file_id", "vault_id", "path", "name", "entry", "size", "uploaded_at", "uploaded_by",
                   "changed_at", "changed_by", "status", "sha256", "integrity")


def manifest_rows(entries: List[Entry]) -> List[dict]:
    return [{"file_id": e.file_id, "vault_id": e.vault_id, "path": "/".join(e.folder_path), "name": e.name,
             "entry": e.arcname if e.sha256 is not None else None, "size": e.size, "uploaded_at": e.uploaded_at,
             "uploaded_by": e.uploaded_by, "changed_at": e.changed_at, "changed_by": e.changed_by,
             "status": e.status, "sha256": e.sha256, "integrity": e.integrity} for e in entries]


def case_document(db, case, export) -> dict:
    """case.json: what the export is of. Never the justification, the owners' note or the people named."""
    rows = ca.covering_rows(db, case)
    return {"case": {"id": str(case.id), "number": case.number, "purpose": case.purpose,
                     "legal_basis": case.legal_basis, "lia_reference": case.lia_reference,
                     "art9_condition": case.art9_condition if case.special_category else None,
                     "auditor": case.auditor_username,
                     "approved_by": "operator@host" if case.approved_by_operator else case.approved_by_username,
                     "approved_at": ca._iso(case.approved_at), "access_starts_at": ca._iso(case.access_starts_at),
                     "access_ends_at": ca._iso(case.access_ends_at), "files_from": ca._iso(case.files_from),
                     "files_to": ca._iso(case.files_to), "password_policy": ca.policy(case),
                     "scope": [{"vault_id": str(v), "covers": "whole" if r.folder_ids is None else "folders",
                                "folders": list(r.folder_ids or [])}
                               for v, r in sorted(rows.items(), key=lambda x: str(x[0]))]},
            "export": {"id": str(export.id), "prepared_at": ca._iso(export.created_at),
                       "fetched_at": ca._iso(export.fetched_at), "files": len(export.file_ids or [])}}


README = """This archive is an export of files from a compliance case of a DockVault deployment.

What it holds
  files/<vault id>/<folder>/<name>   the files, as stored. Their paths were made safe for any computer to unpack:
                                     the original folder and file names are in the manifest.
  manifest.json, manifest.csv        one row per file: its id, vault, original path and name, its path in this
                                     archive, its size, when and by whom it was uploaded and last changed, its
                                     status (live, expired, or deleted or expired and kept by a legal hold), the
                                     SHA-256 of the bytes in this archive, and whether that matches the checksum
                                     the deployment stored for the file (ok, or mismatch: the bytes differ from
                                     what was stored, or no checksum was stored). A file listed as "missing" had
                                     left the vault before it could be exported, one listed as "unreadable"
                                     could not be opened, and one listed as "left_case" was no longer in the
                                     case when its turn came (moved out of its folders, for example); none of
                                     them is in files/. In the CSV, a value a spreadsheet
                                     would read as a formula starts with an apostrophe.
  case.json                          the case: its number, purpose, legal basis, scope, auditor, approver and dates.
  SHA256SUMS                         the SHA-256 of every file above.

How to check it
  Unpack the archive, go into the folder it made, and run:  sha256sum -c SHA256SUMS
  The deployment recorded the SHA-256 of manifest.json when this export ended (case_export_completed in its audit
  log): compare it with  sha256sum manifest.json

This export is personal data. Keep it, share it and delete it only as the operator's policy for this case says.
"""

_GONE = object()


def _open_stored(db_factory, entry: Entry, now: datetime):
    """The stored content of ``entry`` opened (a BoundedDownload), read with a session of its own, closed before the
    first byte; _GONE when the file is no longer there (it is then listed as missing)."""
    db = db_factory()
    try:
        item, vault, kept = _row_of(db, entry, now)
        if item is None or vault is None:
            return _GONE
        if kept and not entry.kept:
            entry.kept, entry.status = True, ca.status_of(item, True, now)
        return ca._vault_service(db)._open_stored_file(item, vault, item.id, whole=False)
    finally:
        db.close()


class Stopped(Exception):
    """The export stopped before its end (the case's access ended); its reason is recorded."""

    def __init__(self, reason: str):
        super().__init__(reason)
        self.reason = reason


class ExportStream:
    """The archive, piece by piece, as an iterator the response reads (each step may run on another thread; every
    step uses a session of its own from ``db_factory``). ``close()`` ends it: when the archive did not reach its
    end (the client went away, a step failed, it never started), ``case_export_aborted`` is recorded, once."""

    def __init__(self, db_factory: Callable, case_id, export_id, user_id, entries: List[Entry], *,
                 now: Optional[datetime] = None):
        self._db_factory = db_factory
        self.case_id, self.export_id, self.user_id = case_id, export_id, user_id
        self.entries = entries
        self.now = now or ca.utcnow()
        self.files_done = 0
        self.bytes_done = 0
        self.reason: Optional[str] = None
        self.ended = False
        # Made at the first read: an iterator never read holds no generator, so dropping it ends it at once.
        self._gen: Optional[Iterator[bytes]] = None

    def __iter__(self):
        return self

    def __next__(self) -> bytes:
        if self._gen is None:
            if self.ended:
                raise StopIteration
            self._gen = self._pieces()
        try:
            return next(self._gen)
        except StopIteration:
            raise
        except Stopped as stop:
            self.reason = stop.reason
            raise
        except Exception as exc:
            self.reason = self.reason or f"failed:{type(exc).__name__}"
            raise

    def __del__(self):
        # A response that never read it (the client left before the first piece) still ends it, recorded.
        try:
            if not self.ended:
                self.close()
        except Exception:  # noqa: BLE001 -- nothing may escape a finaliser
            pass

    def close(self) -> None:
        try:
            if self._gen is not None:
                self._gen.close()
                self._gen = None
        finally:
            if not self.ended:
                self.ended = True
                details = {"export_id": str(self.export_id), "file_count": self.files_done,
                           "bytes": self.bytes_done, "reason": self.reason or "stopped"}
                _finish(self._db_factory, self.case_id, self.export_id, self.user_id, completed=False,
                        details=details)

    # -- the steps

    def _may_read(self, entry: Entry) -> bool:
        """Before each file: the case still gives its auditor access, and export (else the export stops: Stopped);
        and the file is still one the case may export, as the fetch checked it, now: else it is left out, listed
        LEFT_CASE, or MISSING when it is gone from the vault (also a kept file now due for its purge)."""
        from app.core.models import User
        db = self._db_factory()
        try:
            user = db.get(User, self.user_id)
            if user is None:
                raise Stopped(ca.NOT_AUDITOR)
            now = ca.utcnow()
            try:
                case = ca.case_for(db, self.case_id, user, now=now)
            except ca.Refused as refused:
                raise Stopped(refused.reason)
            why = refusal(case)
            if why is not None:
                raise Stopped(why)
            try:
                found = ca.file_for(db, case, entry.file_id, now=now)
                ca.content_opening(case, found, {entry.vault_id} if entry.unlocked else ())
            except ca.Refused as refused:
                entry.status = MISSING if refused.reason == ca.NO_SUCH_FILE else LEFT_CASE
                return False
            return True
        finally:
            db.close()

    def _pieces(self) -> Iterator[bytes]:
        from app.core.models import ComplianceCase, ComplianceExport
        db = self._db_factory()
        try:
            place(db, self.entries, now=self.now)
            case = db.get(ComplianceCase, self.case_id)
            export = db.get(ComplianceExport, self.export_id)
            document = case_document(db, case, export)
            number = case.number
        finally:
            db.close()
        self.entries.sort(key=lambda e: (e.arcname is None, e.arcname or e.file_id))
        sink = _Sink()
        sums: List[Tuple[str, str]] = []
        with zipfile.ZipFile(sink, mode="w", compression=zipfile.ZIP_STORED, allowZip64=True) as archive:
            for entry in self.entries:
                if entry.status == MISSING:
                    continue
                if not self._may_read(entry):
                    continue
                try:
                    download = _open_stored(self._db_factory, entry, self.now)
                except Exception:  # noqa: BLE001 -- nothing of it is in the archive: the manifest says so
                    download = None
                if download is _GONE or download is None:
                    entry.status = MISSING if download is _GONE else UNREADABLE
                    continue
                info = zipfile.ZipInfo(entry.arcname, date_time=_zip_time(entry.when))
                info.compress_type = zipfile.ZIP_STORED
                info.external_attr = 0o644 << 16
                hasher = hashlib.sha256()
                size = 0
                with download, archive.open(info, mode="w", force_zip64=True) as out:
                    # Every stored byte goes into the archive; the checksum is compared below and the manifest says
                    # whether it matched (a download would cut the response short instead).
                    for piece in download.pieces():
                        out.write(piece)
                        hasher.update(piece)
                        size += len(piece)
                        yield sink.take()
                entry.size, entry.sha256 = size, hasher.hexdigest()
                stored = download.checksum
                entry.integrity = OK if stored and stored == entry.sha256 else MISMATCH
                sums.append((entry.sha256, entry.arcname))
                self.files_done += 1
                self.bytes_done += size
                yield sink.take()
            rows = manifest_rows(self.entries)
            manifest = json.dumps({"case_number": number, "case_id": str(self.case_id),
                                   "export_id": str(self.export_id), "fields": list(MANIFEST_FIELDS), "files": rows},
                                  indent=2, ensure_ascii=False).encode("utf-8") + b"\n"
            table = io.StringIO()
            writer = csv.writer(table, lineterminator="\r\n")
            writer.writerow(MANIFEST_FIELDS)
            for row in rows:
                writer.writerow([_csv_cell(row[f]) for f in MANIFEST_FIELDS])
            documents = [("manifest.json", manifest), ("manifest.csv", table.getvalue().encode("utf-8")),
                         ("case.json", json.dumps(document, indent=2, ensure_ascii=False).encode("utf-8") + b"\n"),
                         ("README.txt", README.encode("utf-8"))]
            for name, data in documents:
                info = zipfile.ZipInfo(name, date_time=_zip_time(self.now))
                info.external_attr = 0o644 << 16
                archive.writestr(info, data)
                sums.append((hashlib.sha256(data).hexdigest(), name))
                yield sink.take()
            listing = "".join(f"{digest}  {name}\n" for digest, name in sums).encode("utf-8")
            info = zipfile.ZipInfo("SHA256SUMS", date_time=_zip_time(self.now))
            info.external_attr = 0o644 << 16
            archive.writestr(info, listing)
        yield sink.take()
        manifest_sha256 = hashlib.sha256(manifest).hexdigest()
        self.ended = True
        _finish(self._db_factory, self.case_id, self.export_id, self.user_id, completed=True, details={
            "export_id": str(self.export_id), "manifest_sha256": manifest_sha256, "file_count": self.files_done,
            "bytes": self.bytes_done, "missing": sum(1 for e in self.entries if e.status == MISSING),
            "unreadable": sum(1 for e in self.entries if e.status == UNREADABLE),
            "left_case": sum(1 for e in self.entries if e.status == LEFT_CASE),
            "mismatched": sum(1 for e in self.entries if e.integrity == MISMATCH)},
            manifest_sha256=manifest_sha256)


def _finish(db_factory, case_id, export_id, user_id, *, completed: bool, details: dict,
            manifest_sha256: Optional[str] = None) -> None:
    """The export's end, recorded in a session of its own. Never raises: the stream is over either way."""
    from app.core.models import ComplianceCase, ComplianceExport, User
    db = None
    try:
        db = db_factory()
        case = db.get(ComplianceCase, case_id)
        user = db.get(User, user_id)
        row = db.get(ComplianceExport, export_id)
        if row is not None:
            row.status = "completed" if completed else "aborted"
            row.completed_at = ca.utcnow()
            if completed:
                row.manifest_sha256 = manifest_sha256
        ca._row(db, case, user, "case_export_completed" if completed else "case_export_aborted",
                resource_type="case", resource_id=case_id, details=details,
                status="success" if completed else "failure")
        db.commit()
    except Exception as exc:  # noqa: BLE001 -- the archive was sent (or stopped) either way; say so in the log
        print(f"Warning: the end of a case export could not be recorded ({type(exc).__name__})")
        if db is not None:
            db.rollback()
    finally:
        if db is not None:
            db.close()
