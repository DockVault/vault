"""Reading a vault for a compliance case: the only code that opens a file for a case.

An auditor whose case is approved reads the vaults it covers through the routes in app/api/compliance_router.py,
and every one of them asks here. Nothing else opens a file for a case: the permission service, VaultService.get_vault
and the SFTP server never import this module (a test pins it), so being an auditor gives nothing anywhere else.

Opening a file checks, in this order, and stops at the first refusal:

1. The case: it exists, the caller is its auditor in a session of their own, compliance access is on, the case is
   active, its auditor's right is in force under the grant the case was asked under, and its access period is
   open now (case_rules.access_refusal).
2. The file: a live file, or one a legal hold kept (``held_files``) and not yet due for its purge; its vault is a
   vault of the case that still covers something; the file is inside the case's folders (the live tree, with the
   kept folders; a file moved out of them is out); and, when the case has a time range, it was uploaded or last
   changed inside it.
3. Zero-knowledge vaults are never opened, whatever the settings say. A vault with a vault password follows the
   case's password rule, the stricter of the value recorded at the approval and the value in force now: refused,
   opened with a receipt its password gave (POST .../unlock, app/core/vault_unlock_receipts.py), or opened without
   it when the deployment allows that and the request asked for it; then every row says so
   (``password_override``). A file with its own password opens only under that override.
4. The audit row, committed: the first view of a file in ten minutes writes ``case_file_viewed`` (later views and
   byte ranges in those ten minutes add none) and commits it before anything is read; a row that cannot be written
   refuses the view. A new view past COMPLIANCE_VIEW_RATE views in the last hour is refused: bulk reading belongs
   in an export. The auditor's account row is locked from the check to the commit, so views made at once are
   counted, and recorded, one after the other.
5. Only then is the stored file opened (VaultService._open_stored_file, which opens a kept file as it opens a live
   one: the ids its keys bind are the original ones).

Nothing here changes the vault: no ``last_accessed``, no ``vault_views`` row, no share or download counter, no
transfer entry under the file's name. Listing a folder (``case_folder_listed``) and searching (``case_search``) are
recorded too, a listing once per folder in ten minutes. Names appear only where the case may read them: never in a
zero-knowledge vault (its structure, sizes and dates only), in a vault with a password only once it is unlocked (or
under the override).

Every refusal raises Refused; the routes record it (``case_access_refused``, record_refused) and answer with its
status: 404 where the answer would tell whether something exists that the caller may not see (another auditor's
case, a file out of scope), 403 for the rest, 429 past the view rate, 503 when the audit row could not be written.
"""
from __future__ import annotations

import uuid
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from typing import Dict, Iterable, List, Mapping, Optional, Set, Tuple

from sqlalchemy.orm.exc import ObjectDeletedError

from app.core import case_rules as rules
from app.core import compliance_settings as cs
from app.core.case_context import acting_for

# --------------------------------------------------------------------------- why a read is refused

NO_CASE = "no_case"
NOT_AUDITOR = "not_your_case"
TEMPORARY = "temporary_credential"
NO_SUCH_FILE = "no_such_file"
NO_SUCH_VAULT = "no_such_vault"
NO_SUCH_FOLDER = "no_such_folder"
OUT_OF_SCOPE = "out_of_scope"
OUT_OF_RANGE = "out_of_range"
ZERO_KNOWLEDGE = "zero_knowledge"
PASSWORD_REFUSED = rules.PASSWORD_VAULT_REFUSED
LOCKED = "vault_locked"
FILE_PASSWORD = "file_password"
VIEW_RATE = "view_rate"
RECORD_FAILED = "record_failed"
TOO_LARGE = "too_large"

TEXTS = {
    NO_CASE: "No such case.",
    NOT_AUDITOR: "No such case.",
    TEMPORARY: "A temporary credential cannot read a case.",
    NO_SUCH_FILE: "No such file in this case.",
    NO_SUCH_VAULT: "No such vault in this case.",
    NO_SUCH_FOLDER: "No such folder in this case.",
    OUT_OF_SCOPE: "No such file in this case.",
    OUT_OF_RANGE: "No such file in this case.",
    ZERO_KNOWLEDGE: "A zero-knowledge vault's contents and names can never be opened: the server does not have "
                    "them.",
    PASSWORD_REFUSED: "This deployment does not open password-protected vaults in a case.",
    LOCKED: "This vault has a vault password: unlock it with that password first.",
    FILE_PASSWORD: "This file has a password of its own: a case opens it only when the deployment allows opening "
                   "password-protected vaults without their password and the case asked for that.",
    VIEW_RATE: "Too many files opened in the last hour. Export what you need instead.",
    RECORD_FAILED: "The file was not opened: the record of opening it could not be written.",
    TOO_LARGE: "This file is too large to show here.",
    rules.ACCESS_OFF: "Compliance access is turned off on this deployment.",
    rules.NOT_ACTIVE: "This case gives no access now.",
    rules.AUDITOR_NOT_LIVE: "Your auditor right is not in force now.",
    rules.NOT_STARTED: "This case's access has not started.",
    rules.ACCESS_ENDED: "This case's access has ended.",
}

# What each refusal answers. A refusal not listed answers 403.
STATUS = {NO_CASE: 404, NOT_AUDITOR: 404, NO_SUCH_FILE: 404, NO_SUCH_VAULT: 404, NO_SUCH_FOLDER: 404,
          OUT_OF_SCOPE: 404, OUT_OF_RANGE: 404, VIEW_RATE: 429, RECORD_FAILED: 503, TOO_LARGE: 413}

# A listing, a view: recorded once per folder, per file, in this long.
QUIET = timedelta(minutes=10)
# The most entries a listing returns at once, and the most names a search reads.
LIST_MAX = 2000
SEARCH_MAX = 2000
QUERY_MAX = 255

LIVE, EXPIRED = "live", "expired"
KEPT_DELETED, KEPT_EXPIRED = "deleted_kept", "expired_kept"

# The receipts of unlocked vaults, sent back with each request: "<vault id>=<receipt>", comma-separated.
UNLOCK_HEADER = "X-Case-Unlock"
MAX_UNLOCKED = 25


class Refused(Exception):
    """A read refused: ``reason`` is one of the codes above (or case_rules'), ``status`` what the route answers."""

    def __init__(self, reason: str, *, status: Optional[int] = None, record: bool = True):
        super().__init__(reason)
        self.reason = reason
        self.status = status or STATUS.get(reason, 403)
        self.record = record

    @property
    def text(self) -> str:
        return TEXTS.get(self.reason, "This case gives no access to that.")


def utcnow() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _iso(value: Optional[datetime]) -> Optional[str]:
    return value.isoformat() + "Z" if value is not None else None


# --------------------------------------------------------------------------- 1. the case

def case_for(db, case_id, user, *, now: Optional[datetime] = None, lock: bool = False):
    """The case ``user`` may read now, as its auditor. Raises Refused: no such case (also another auditor's: it
    is not confirmed to exist), a temporary credential, or why the case gives no access now."""
    from app.core import cases
    from app.core.models import ComplianceCase
    now = now or utcnow()
    cid = rules.as_id(case_id)
    q = db.query(ComplianceCase).filter(ComplianceCase.id == cid) if cid is not None else None
    if q is not None and lock:
        q = q.with_for_update()
    case = q.first() if q is not None else None
    if case is None:
        raise Refused(NO_CASE)
    if getattr(user, "_is_temp_session", False):
        raise Refused(TEMPORARY)
    if not cases.is_auditor_of(case, user):
        raise Refused(NOT_AUDITOR)
    live, _standing = cases.auditor_standing(db, case, now)
    why = rules.access_refusal(case.status, case.access_starts_at, case.access_ends_at, now=now,
                               access_enabled=cases.access_enabled(), auditor_live=live)
    if why is not None:
        raise Refused(why)
    return case


# --------------------------------------------------------------------------- 2. what the case covers

def covering_rows(db, case) -> Dict[uuid.UUID, object]:
    """{vault id: its row in compliance_case_vaults} of the vaults the case still covers something of."""
    from app.core import cases
    return {r.vault_id: r for r in cases.vault_rows(db, case, covering_only=True)}


def scope_of(row) -> Optional[frozenset]:
    """What a case's vault row covers: None (the whole vault) or its folders."""
    if row.folder_ids is None:
        return None
    return frozenset(str(uuid.UUID(str(f))) for f in row.folder_ids)


def _kept_readable(db) -> bool:
    from app.core import kept_tables
    return kept_tables._readable(db)


def _not_due(model, now: datetime):
    """A kept row still to be read: no purge set, or a purge still ahead (an undone release clears it)."""
    from sqlalchemy import or_
    return or_(model.purge_after.is_(None), model.purge_after > now)


class Folders:
    """The folders of one vault, live and kept, by id: what a folder's chain toward the root is, read once."""

    def __init__(self, db, vault_id, *, now: Optional[datetime] = None):
        from app.core.models import Folder, HeldFolder
        self.vault_id = vault_id
        self.parent: Dict[str, Optional[str]] = {}
        self.kept: Set[str] = set()
        for fid, parent in db.query(Folder.id, Folder.parent_folder_id).filter(Folder.vault_id == vault_id):
            self.parent[str(fid)] = str(parent) if parent is not None else None
        if _kept_readable(db):
            for fid, parent in (db.query(HeldFolder.id, HeldFolder.parent_folder_id)
                                .filter(HeldFolder.vault_id == vault_id, _not_due(HeldFolder, now or utcnow()))):
                if str(fid) not in self.parent:
                    self.parent[str(fid)] = str(parent) if parent is not None else None
                    self.kept.add(str(fid))

    def chain(self, folder_id) -> List[str]:
        """``folder_id`` and its parents toward the root (empty for the root)."""
        out, seen = [], set()
        cur = str(folder_id) if folder_id is not None else None
        while cur is not None and cur not in seen and cur in self.parent:
            seen.add(cur)
            out.append(cur)
            cur = self.parent[cur]
        return out

    def leading(self, scope: Optional[frozenset]) -> Set[str]:
        """Every folder on the way to a folder of ``scope`` (the folders themselves included)."""
        out: Set[str] = set()
        for f in scope or ():
            out.update(self.chain(f))
        return out


def chain(db, vault_id, folder_id, *, now: Optional[datetime] = None) -> List[str]:
    """``folder_id`` and its parents toward the root, live or kept, in ``vault_id`` (empty for the root). One query
    per step: for a single file; a listing reads Folders once."""
    from app.core.models import Folder, HeldFolder
    out, seen = [], set()
    cur = folder_id
    kept = _kept_readable(db)
    while cur is not None and str(cur) not in seen:
        seen.add(str(cur))
        row = db.query(Folder.id, Folder.parent_folder_id).filter(Folder.id == cur, Folder.vault_id == vault_id).first()
        if row is None and kept:
            row = (db.query(HeldFolder.id, HeldFolder.parent_folder_id)
                   .filter(HeldFolder.id == cur, HeldFolder.vault_id == vault_id,
                           _not_due(HeldFolder, now or utcnow())).first())
        if row is None:
            break
        out.append(str(row[0]))
        cur = row[1]
    return out


def in_range(case, item) -> bool:
    """Whether ``item`` was uploaded or last changed inside the case's time range (always, without one)."""
    return times_in_range(case, getattr(item, "created_at", None), getattr(item, "updated_at", None))


def times_in_range(case, created: Optional[datetime], updated: Optional[datetime]) -> bool:
    lo, hi = case.files_from, case.files_to
    if lo is None and hi is None:
        return True
    times = [t for t in (created, updated) if t is not None]
    return any((lo is None or t >= lo) and (hi is None or t <= hi) for t in times)


def status_of(item, kept: bool, now: datetime) -> str:
    if kept:
        return KEPT_EXPIRED if getattr(item, "kept_reason", None) == "expired" else KEPT_DELETED
    expires = getattr(item, "expires_at", None)
    return EXPIRED if expires is not None and expires <= now else LIVE


@dataclass
class Found:
    """A file a case may reach: the row (live or kept), its vault, the case's row for that vault, and its status."""
    item: object
    vault: object
    row: object
    kept: bool
    status: str


def file_for(db, case, file_id, *, now: Optional[datetime] = None) -> Found:
    """The file ``file_id`` when the case covers it (check 2). Raises Refused."""
    from app.core.models import File, HeldFile, Vault
    now = now or utcnow()
    fid = rules.as_id(file_id)
    item, kept = (db.get(File, fid) if fid is not None else None), False
    if item is None and fid is not None and _kept_readable(db):
        item = db.query(HeldFile).filter(HeldFile.id == fid, _not_due(HeldFile, now)).first()
        kept = item is not None
    if item is None:
        raise Refused(NO_SUCH_FILE)
    row = covering_rows(db, case).get(item.vault_id)
    if row is None:
        raise Refused(OUT_OF_SCOPE)
    scope = scope_of(row)
    if scope is not None and not rules.in_scope(scope, item.id, chain(db, item.vault_id, item.folder_id, now=now)):
        raise Refused(OUT_OF_SCOPE)
    if not in_range(case, item):
        raise Refused(OUT_OF_RANGE)
    vault = db.get(Vault, item.vault_id)
    if vault is None:
        raise Refused(NO_SUCH_FILE)
    return Found(item, vault, row, kept, status_of(item, kept, now))


# --------------------------------------------------------------------------- 3. zero-knowledge and passwords

def policy(case) -> str:
    """The case's password rule now: the stricter of the value recorded at its approval and the value in force."""
    return rules.password_policy(case.password_policy, cs.current(cs.PASSWORD_VAULTS),
                                 override_requested=bool(case.password_override))


def is_zero_knowledge(vault, row=None) -> bool:
    return (getattr(vault, "type", None) or "standard") == "zero_knowledge" or (
        row is not None and getattr(row, "vault_type_at_approval", None) == "zero_knowledge")


@dataclass
class Opening:
    """How a vault opens for the case: whether names show, and whether its password was passed over."""
    names: bool
    override: bool = False
    locked: bool = False


def vault_opening(case, vault, row, unlocked: Iterable) -> Opening:
    """How ``vault`` opens for ``case`` now. Raises Refused for a vault the case may never read the contents of
    with a password under ``refuse``. A zero-knowledge vault opens with no names (its structure only)."""
    if is_zero_knowledge(vault, row):
        return Opening(names=False)
    if not vault.password_hash:
        return Opening(names=True)
    rule = policy(case)
    if rule == cs.REFUSE:
        raise Refused(PASSWORD_REFUSED)
    if rule == cs.OVERRIDE:
        return Opening(names=True, override=True)
    if str(vault.id) in {str(v) for v in unlocked or ()}:
        return Opening(names=True)
    return Opening(names=False, locked=True)


def content_opening(case, found: Found, unlocked: Iterable) -> Opening:
    """Check 3 for opening a file's contents. Raises Refused: zero-knowledge (always), a password vault the rule
    refuses or that is not unlocked, a file with a password of its own outside the override."""
    if is_zero_knowledge(found.vault, found.row):
        raise Refused(ZERO_KNOWLEDGE)
    opening = vault_opening(case, found.vault, found.row, unlocked)
    if opening.locked:
        raise Refused(LOCKED)
    own_password = bool(getattr(found.item, "password_hash", None))
    if own_password and policy(case) != cs.OVERRIDE:
        raise Refused(FILE_PASSWORD)
    return Opening(names=True, override=opening.override or own_password)


def unlocked_vaults(db, case, user, session_hash: Optional[str], given: Mapping[str, str]) -> Set[str]:
    """The vaults of the case whose receipts (``given``: {vault id: receipt}) unlock them now, for this session,
    case and auditor, with each vault's password as it is now."""
    from app.core import vault_unlock_receipts as receipts
    from app.core.models import Vault
    out: Set[str] = set()
    if not session_hash:
        return out
    rows = covering_rows(db, case)
    for vid, receipt in list((given or {}).items())[:MAX_UNLOCKED]:
        vault_id = rules.as_id(vid)
        if vault_id is None or vault_id not in rows:
            continue
        vault = db.get(Vault, vault_id)
        if vault is None or not vault.password_hash or is_zero_knowledge(vault, rows[vault_id]):
            continue
        if receipts.verify(receipt, purpose=receipts.PURPOSE_CASE, session_hash=session_hash, case_id=case.id,
                           vault_id=vault.id, user_id=user.id, credential=receipts.credential_digest(vault.password_hash)):
            out.add(str(vault.id))
    return out


def parse_unlock_header(header: Optional[str]) -> Dict[str, str]:
    """{vault id: receipt} of an X-Case-Unlock header."""
    out: Dict[str, str] = {}
    for part in (header or "").split(",")[:MAX_UNLOCKED]:
        vid, _, receipt = part.strip().partition("=")
        if vid and receipt:
            out[vid.strip()] = receipt.strip()
    return out


# --------------------------------------------------------------------------- 4. the record

def _recent(db, case, user, action: str, resource_id: str, now: datetime) -> bool:
    """Whether ``action`` on ``resource_id`` was recorded for this case and auditor in the last ten minutes."""
    from app.core.models import AuditLog
    return db.query(AuditLog.id).filter(
        AuditLog.case_id == case.id, AuditLog.user_id == user.id, AuditLog.action == action,
        AuditLog.status == "success", AuditLog.resource_id == str(resource_id),
        AuditLog.timestamp >= now - QUIET).first() is not None


def views_in_last_hour(db, user, now: datetime) -> int:
    from sqlalchemy import func
    from app.core.models import AuditLog
    return int(db.query(func.count(AuditLog.id)).filter(
        AuditLog.user_id == user.id, AuditLog.action == "case_file_viewed", AuditLog.status == "success",
        AuditLog.timestamp >= now - timedelta(hours=1)).scalar() or 0)


def view_rate(case) -> int:
    return int(cs.case_value(cs.VIEW_RATE, case.settings_at_approval))


def _row(db, case, user, action: str, *, resource_type: str, resource_id, details: dict, status: str = "success"):
    from app.services.audit_logger import AuditLogger
    with acting_for(case.id if case is not None else None):
        db.add(AuditLogger(db).build_row(
            action=action, status=status, user=user, resource_type=resource_type,
            resource_id=str(resource_id) if resource_id is not None else None,
            details={**({"case_number": case.number} if case is not None else {}), **details}))


def record(db, case, user, action: str, *, resource_type: str, resource_id, details: dict,
           status: str = "success") -> None:
    """Write and commit a read's row under the case. Raises Refused(RECORD_FAILED) when it cannot be written: the
    read is then refused."""
    try:
        _row(db, case, user, action, resource_type=resource_type, resource_id=resource_id, details=details,
             status=status)
        db.commit()
    except Exception:  # noqa: BLE001 -- no read without its record
        db.rollback()
        raise Refused(RECORD_FAILED)


def record_once(db, case, user, action: str, *, resource_type: str, resource_id, details: dict,
                now: datetime) -> bool:
    """record() unless the same read was recorded in the last ten minutes. Returns whether a row was written."""
    if _recent(db, case, user, action, str(resource_id), now):
        return False
    record(db, case, user, action, resource_type=resource_type, resource_id=resource_id, details=details)
    return True


def record_refused(db, case_id, user, refused: Refused, *, resource_type: Optional[str] = None,
                   resource_id=None, details: Optional[dict] = None) -> None:
    """Record a refused read (``case_access_refused``) on its own, under the case when there is one. Never
    raises."""
    from app.core.models import ComplianceCase
    from app.services.audit_logger import AuditLogger
    try:
        db.rollback()
        cid = rules.as_id(case_id)
        case = db.get(ComplianceCase, cid) if cid is not None else None
        with acting_for(case.id if case is not None else None):
            db.add(AuditLogger(db).build_row(
                action="case_access_refused", status="failure",
                user=user if getattr(user, "id", None) is not None else None,
                resource_type=resource_type or "case",
                resource_id=str(resource_id) if resource_id is not None else (str(cid) if cid else None),
                details={"reason": refused.reason, **({"case_number": case.number} if case is not None else {}),
                         **(details or {})}))
        db.commit()
    except Exception:  # noqa: BLE001 -- the refusal stands without its row
        db.rollback()


# --------------------------------------------------------------------------- 5. opening

def _vault_service(db):
    from app.core.authorization import PermissionService
    from app.services.vault_service import VaultService
    return VaultService(db, PermissionService(db))


def _lock_auditor(db, user) -> None:
    """Lock the auditor's account row until this read's record commits: two first views of one file at once write
    one row, and views in flight cannot pass the hourly rate together (as two reveals at once cannot pass theirs).
    The read that needs no row commits at once, so the lock is never held while a file is sent."""
    from app.core.models import User
    db.query(User.id).filter(User.id == user.id).with_for_update().first()


def view_details(found: Found, opening: Opening, **extra) -> dict:
    details = {"vault_id": str(found.vault.id), "status": found.status, **extra}
    if opening.override:
        details["password_override"] = True
    return details


def open_file(db, case_id, file_id, user, *, unlocked_given: Optional[Mapping[str, str]] = None,
              session_hash: Optional[str] = None, now: Optional[datetime] = None, preview: bool = False):
    """Open ``file_id`` for the auditor ``user`` under ``case_id``, after checks 1 to 4. Returns (case, Found,
    BoundedDownload); the caller closes the download. Raises Refused (the caller records it)."""
    now = now or utcnow()
    case = case_for(db, case_id, user, now=now)                               # 1
    found = file_for(db, case, file_id, now=now)                              # 2
    unlocked = unlocked_vaults(db, case, user, session_hash, unlocked_given or {})
    opening = content_opening(case, found, unlocked)                          # 3
    _lock_auditor(db, user)                                                   # 4
    if not _recent(db, case, user, "case_file_viewed", str(found.item.id), now):
        if views_in_last_hour(db, user, now) >= view_rate(case):
            raise Refused(VIEW_RATE)
        record(db, case, user, "case_file_viewed", resource_type="file", resource_id=found.item.id,
               details=view_details(found, opening, **({"preview": True} if preview else {})))
    else:
        db.commit()                                                           # the lock, released
    try:
        download = _vault_service(db)._open_stored_file(found.item, found.vault, found.item.id, whole=False)   # 5
    except ObjectDeletedError:
        # Deleted (or kept by a hold, which moves its row) between the commit and the opening: no such file now.
        raise Refused(NO_SUCH_FILE)
    return case, found, download


# --------------------------------------------------------------------------- what a case lists

def _usernames(db, ids) -> Dict[str, str]:
    from app.core.models import User
    wanted = {i for i in ids if i is not None}
    if not wanted:
        return {}
    return {str(i): n for i, n in db.query(User.id, User.username).filter(User.id.in_(wanted)).all()}


def file_entry(item, *, kept: bool, status: str, names: bool, users: Mapping[str, str]) -> dict:
    """What a listing shows of a file: never its stored checksum; its name and type only where names show."""
    by = getattr(item, "uploaded_by", None)
    changed = getattr(item, "modified_by", None) or by
    return {"kind": "file", "id": str(item.id), "vault_id": str(item.vault_id),
            "folder_id": str(item.folder_id) if item.folder_id else None,
            "name": (item.original_name or item.name) if names else None,
            "mime_type": item.mime_type if names else None, "size": int(item.size_bytes or 0),
            "uploaded_at": _iso(item.created_at), "uploaded_by": users.get(str(by)) if by else None,
            "uploaded_by_id": str(by) if by else None, "changed_at": _iso(item.updated_at),
            "changed_by": users.get(str(changed)) if changed else None, "status": status,
            "kept_at": _iso(getattr(item, "kept_at", None)) if kept else None,
            "has_password": bool(getattr(item, "password_hash", None))}


def folder_entry(item, *, kept: bool, names: bool, in_scope: bool) -> dict:
    return {"kind": "folder", "id": str(item.id), "vault_id": str(item.vault_id),
            "parent_id": str(item.parent_folder_id) if item.parent_folder_id else None,
            "name": item.name if names else None, "created_at": _iso(item.created_at),
            "status": KEPT_DELETED if kept else LIVE, "kept_at": _iso(getattr(item, "kept_at", None)) if kept else None,
            # A folder shown only because a folder of the case is inside it: its own files are not in the case.
            "in_scope": in_scope}


def vault_entry(db, case, row, vault, unlocked: Iterable) -> dict:
    """A vault of the case as its auditor sees it: type, label (a zero-knowledge vault's label is what its members
    see while it is locked), counts, and how it opens."""
    if vault is None:
        return {"vault_id": str(row.vault_id), "exists": False, "type": row.vault_type_at_approval}
    zk = is_zero_knowledge(vault, row)
    try:
        opening = vault_opening(case, vault, row, unlocked)
        refused = None
    except Refused as exc:
        opening, refused = Opening(names=False), exc.reason
    # A vault's own name shows as it does to a reader of the vault (a zero-knowledge vault's is the label its members
    # see while it is locked); its files' and folders' names follow the opening.
    return {"vault_id": str(vault.id), "exists": True, "type": vault.type or "standard",
            "name": vault.name if refused is None else None, "zero_knowledge": zk,
            "has_password": bool(vault.password_hash), "locked": opening.locked, "refused": refused,
            "password_override": opening.override,
            "covers": "whole" if row.folder_ids is None else "folders",
            "file_count": int(vault.file_count or 0), "bytes": int(vault.total_size_bytes or 0)}


def tree(db, case, user, vault_id, folder_id=None, *, unlocked: Iterable = (), now: Optional[datetime] = None,
         offset: int = 0, limit: int = LIST_MAX) -> dict:
    """One folder of a vault of the case (the root without ``folder_id``): its folders and, where the case covers
    them, its files, live and kept, with their status. A folder above the case's folders lists only the way to
    them. Records ``case_folder_listed`` once per folder in ten minutes, before answering. Raises Refused."""
    from app.core.models import File, Folder, HeldFile, HeldFolder, Vault
    now = now or utcnow()
    vid = rules.as_id(vault_id)
    row = covering_rows(db, case).get(vid) if vid is not None else None
    if row is None:
        raise Refused(NO_SUCH_VAULT)
    vault = db.get(Vault, vid)
    if vault is None:
        raise Refused(NO_SUCH_VAULT)
    opening = vault_opening(case, vault, row, unlocked)
    scope = scope_of(row)
    folders = Folders(db, vid, now=now)
    leading = folders.leading(scope)
    fid = str(rules.as_id(folder_id)) if folder_id is not None and rules.as_id(folder_id) is not None else None
    if folder_id is not None and fid is None:
        raise Refused(NO_SUCH_FOLDER)
    if fid is not None and fid not in folders.parent:
        raise Refused(NO_SUCH_FOLDER)
    here = folders.chain(fid) if fid is not None else []
    covered = scope is None or (fid is not None and rules.in_scope(scope, fid, here[1:]))
    if fid is not None and not covered and fid not in leading:
        # Answered (and recorded) as a folder the case does not know: whether that id is a folder of the vault
        # outside the case is not the case's to tell.
        raise Refused(NO_SUCH_FOLDER)
    kept_ok = _kept_readable(db)
    parent = rules.as_id(fid) if fid is not None else None

    entries: List[dict] = []
    child_q = db.query(Folder).filter(Folder.vault_id == vid, Folder.parent_folder_id == parent if parent is not None
                                      else Folder.parent_folder_id.is_(None))
    children = [(f, False) for f in child_q.order_by(Folder.created_at, Folder.id).all()]
    if kept_ok:
        live_ids = {str(f.id) for f, _ in children}
        kq = db.query(HeldFolder).filter(HeldFolder.vault_id == vid, _not_due(HeldFolder, now),
                                         HeldFolder.parent_folder_id == parent if parent is not None
                                         else HeldFolder.parent_folder_id.is_(None))
        children += [(f, True) for f in kq.order_by(HeldFolder.created_at, HeldFolder.id).all()
                     if str(f.id) not in live_ids]
    for f, kept in children:
        inside = covered or str(f.id) in (scope or ())
        if inside or str(f.id) in leading:
            entries.append(folder_entry(f, kept=kept, names=opening.names, in_scope=inside))

    files: List[Tuple[object, bool]] = []
    if covered:
        fq = db.query(File).filter(File.vault_id == vid, File.folder_id == parent if parent is not None
                                   else File.folder_id.is_(None))
        files = [(f, False) for f in fq.order_by(File.created_at, File.id).all()]
        if kept_ok:
            kq = db.query(HeldFile).filter(HeldFile.vault_id == vid, _not_due(HeldFile, now),
                                           HeldFile.folder_id == parent if parent is not None
                                           else HeldFile.folder_id.is_(None))
            live = {str(f.id) for f, _ in files}
            files += [(f, True) for f in kq.order_by(HeldFile.created_at, HeldFile.id).all() if str(f.id) not in live]
        files = [(f, kept) for f, kept in files if in_range(case, f)]
    users = _usernames(db, [getattr(f, a, None) for f, _ in files for a in ("uploaded_by", "modified_by")])
    entries += [file_entry(f, kept=kept, status=status_of(f, kept, now), names=opening.names, users=users)
                for f, kept in files]
    total = len(entries)
    offset = max(0, int(offset or 0))
    limit = max(1, min(int(limit or LIST_MAX), LIST_MAX))
    page = entries[offset:offset + limit]
    details = {"vault_id": str(vid), "folder_id": fid, "count": total}
    if opening.override:
        details["password_override"] = True
    record_once(db, case, user, "case_folder_listed", resource_type="folder" if fid else "vault",
                resource_id=fid or str(vid), details=details, now=now)
    path_names = folders_names(db, vid, here, opening.names)
    return {"vault": vault_entry(db, case, row, vault, unlocked), "folder_id": fid,
            "path": [{"id": f, "name": path_names.get(f)} for f in reversed(here)],
            "entries": page, "total": total, "offset": offset, "more": offset + len(page) < total}


def folders_names(db, vault_id, ids, names: bool) -> Dict[str, Optional[str]]:
    """{folder id: its name, or None where names do not show}, live or kept."""
    from app.core.models import Folder, HeldFolder
    out: Dict[str, Optional[str]] = {str(i): None for i in ids}
    if not names or not ids:
        return out
    wanted = [rules.as_id(i) for i in ids if rules.as_id(i) is not None]
    for f in db.query(Folder).filter(Folder.vault_id == vault_id, Folder.id.in_(wanted)).all():
        out[str(f.id)] = f.name
    if _kept_readable(db):
        for f in db.query(HeldFolder).filter(HeldFolder.vault_id == vault_id, HeldFolder.id.in_(wanted)).all():
            out.setdefault(str(f.id), None)
            if out[str(f.id)] is None:
                out[str(f.id)] = f.name
    return out


def file_info(db, case, user, file_id, *, unlocked: Iterable = (), now: Optional[datetime] = None) -> dict:
    """One file's metadata in the case (as a listing shows it, with its folder path). Its name is read as a listing
    reads it, so its folder's listing is recorded (once in ten minutes). Raises Refused."""
    now = now or utcnow()
    found = file_for(db, case, file_id, now=now)
    opening = vault_opening(case, found.vault, found.row, unlocked)
    users = _usernames(db, [getattr(found.item, "uploaded_by", None), getattr(found.item, "modified_by", None)])
    entry = file_entry(found.item, kept=found.kept, status=found.status, names=opening.names, users=users)
    path = list(reversed(chain(db, found.vault.id, found.item.folder_id, now=now)))
    names = folders_names(db, found.vault.id, path, opening.names)
    entry["path"] = [{"id": f, "name": names.get(f)} for f in path]
    entry["zero_knowledge"] = is_zero_knowledge(found.vault, found.row)
    entry["locked"] = opening.locked
    details = {"vault_id": str(found.vault.id), "folder_id": str(found.item.folder_id) if found.item.folder_id
               else None, "count": 1}
    if opening.override:
        details["password_override"] = True
    fid = str(found.item.folder_id) if found.item.folder_id else None
    record_once(db, case, user, "case_folder_listed", resource_type="folder" if fid else "vault",
                resource_id=fid or str(found.vault.id), details=details, now=now)
    return entry


# --------------------------------------------------------------------------- search

EXACT, PREFIX = "exact", "prefix"


def _matches(name: Optional[str], query: str, mode: str) -> bool:
    if not name:
        return False
    a, b = name.casefold(), query.casefold()
    return a == b if mode == EXACT else a.startswith(b)


def search(db, case, user, query: str, *, mode: str = PREFIX, vault_id=None, unlocked: Iterable = (),
           now: Optional[datetime] = None) -> dict:
    """File names in the case that are ``query`` (``exact``) or start with it (``prefix``), ignoring case: in the
    vaults whose names the case may read (never zero-knowledge; a password vault once unlocked, or under the
    override), live and kept, inside the case's folders and time range. At most SEARCH_MAX names are read per
    query, newest first; ``truncated`` says when more were left. Records ``case_search`` with the query's length
    and the number of matches, never the text. Raises Refused."""
    from app.core.models import File, HeldFile, Vault
    now = now or utcnow()
    query = (query or "").strip()
    if not query or len(query) > QUERY_MAX:
        raise Refused("bad_query", status=422, record=False)
    if mode not in (EXACT, PREFIX):
        raise Refused("bad_query", status=422, record=False)
    rows = covering_rows(db, case)
    if vault_id is not None:
        vid = rules.as_id(vault_id)
        if vid is None or vid not in rows:
            raise Refused(NO_SUCH_VAULT)
        rows = {vid: rows[vid]}
    candidates: List[Tuple[datetime, str, uuid.UUID, bool]] = []
    openings: Dict[uuid.UUID, Opening] = {}
    folder_maps: Dict[uuid.UUID, Folders] = {}
    kept_ok = _kept_readable(db)
    for vid, row in rows.items():
        vault = db.get(Vault, vid)
        if vault is None:
            continue
        try:
            opening = vault_opening(case, vault, row, unlocked)
        except Refused:
            continue
        if not opening.names:
            continue
        openings[vid] = opening
        scope = scope_of(row)
        folders = folder_maps.setdefault(vid, Folders(db, vid, now=now))
        sources = [(File, False)] + ([(HeldFile, True)] if kept_ok else [])
        for model, kept in sources:
            q = db.query(model.id, model.folder_id, model.created_at, model.updated_at).filter(model.vault_id == vid)
            if kept:
                q = q.filter(_not_due(model, now))
            for fid, folder, created, updated in q.all():
                if not times_in_range(case, created, updated):
                    continue
                if scope is not None and not rules.in_scope(scope, fid, folders.chain(folder)):
                    continue
                candidates.append((updated or created or datetime.min, str(fid), vid, kept))
    candidates.sort(key=lambda c: (c[0], c[1]), reverse=True)
    seen: Set[str] = set()
    unique = []
    for c in candidates:
        if c[1] not in seen:
            seen.add(c[1])
            unique.append(c)
    truncated = len(unique) > SEARCH_MAX
    unique = unique[:SEARCH_MAX]
    live_ids = [uuid.UUID(c[1]) for c in unique if not c[3]]
    kept_ids = [uuid.UUID(c[1]) for c in unique if c[3]]
    items: List[Tuple[object, bool]] = []
    for model, ids, kept in ((File, live_ids, False), (HeldFile, kept_ids, True)):
        for start in range(0, len(ids), 500):
            items += [(f, kept) for f in db.query(model).filter(model.id.in_(ids[start:start + 500])).all()]
    found = [(f, kept) for f, kept in items if _matches(f.original_name or f.name, query, mode)]
    users = _usernames(db, [getattr(f, a, None) for f, _ in found for a in ("uploaded_by", "modified_by")])
    results = [file_entry(f, kept=kept, status=status_of(f, kept, now), names=True, users=users)
               for f, kept in found]
    results.sort(key=lambda e: (e["changed_at"] or e["uploaded_at"] or "", e["id"]), reverse=True)
    details = {"query_length": len(query), "matches": len(results), "scanned": len(unique), "truncated": truncated,
               "mode": mode, "vault_ids": sorted(str(v) for v in openings)}
    if any(o.override for o in openings.values()):
        details["password_override"] = True
    record(db, case, user, "case_search", resource_type="case", resource_id=case.id, details=details)
    return {"results": results, "scanned": len(unique), "truncated": truncated,
            "vaults_searched": sorted(str(v) for v in openings),
            "vaults_not_searched": sorted(str(v) for v in rows if v not in openings)}



def vaults(db, case, user, *, unlocked: Iterable = (), now: Optional[datetime] = None) -> dict:
    """The vaults of the case as its auditor reads them (their names, as a reader of each vault sees them; how each
    opens). Recorded as a listing of the case, once in ten minutes."""
    from app.core.models import Vault
    now = now or utcnow()
    rows = covering_rows(db, case)
    out = [vault_entry(db, case, row, db.get(Vault, vid), unlocked) for vid, row in rows.items()]
    record_once(db, case, user, "case_folder_listed", resource_type="case", resource_id=case.id,
                details={"count": len(out), "vault_ids": sorted(str(v) for v in rows)}, now=now)
    return {"vaults": out}
