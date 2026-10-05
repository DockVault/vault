"""The head record: the server's own copy of the audit chain's head, kept outside the database.

It lives in the web process's memory and in a file on the keys volume (AUDIT_CHAIN_HEAD_FILE), which the
database container does not mount. Every writer of a seal checks the database's chain against it before it
writes (app/core/audit_integrity.py), so seals cut from the tail, a chain rewritten under a made-up key, or a
seal edited before the head stop sealing instead of being sealed over.

What it holds:
    generation, discards    raised by a restore the host accepts and by each discard of seals after it;
                            records are ordered by (generation, discards, seq), and a writer never writes a
                            record lower than the one on disk
    seq, link, key_id       the newest seal the server wrote (its link as the server computed it)
    newest_hour_end         where the newest hour seal ends
    keys                    the key history: each key that has been in force, with the seqs from and to which
                            it was, per generation; and the key seals the host accepted without a proof
    after_record            seals a writer accepted after the record without having written them, with the
                            time the server first accepted each and whether the host acknowledged it
    hours, days, links      hour summaries of the last 30 days, a digest per older day, every 64th link
    check, status, failures the daily check's positions and outcome, and every failure not yet acknowledged,
                            with when it was first and last seen

Not secret and not MAC'd: whoever can write the file can read .env in the same container.

Writes happen after the seal's transaction commits, under an exclusive lock on a file beside it, held from the
read of the file through its replace: a temporary file in the same directory, fsync, os.replace, fsync of the
directory. Every write is a merge: failures keep their earliest first sighting and latest last one, positions
and counts never move back, lists only grow (an acknowledgment only marks what it names), and hour summaries
are dropped only once older than 30 days.
"""
from __future__ import annotations

import copy
import json
import os
import tempfile
import threading
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Any, Dict, Optional

VERSION = 1
SUMMARY_DAYS = 30
LINK_EVERY = 64


def empty() -> Dict[str, Any]:
    return {"version": VERSION, "generation": 1, "discards": 0, "seq": 0, "link": None, "key_id": None,
            "newest_hour_end": None, "keys": [], "unverified_keys": [], "after_record": [], "hours": {},
            "days": {}, "links": {}, "check": {}, "status": {}, "failures": {}, "warnings": {},
            "checkpoints": {}, "restore": {}}


def order(record: Optional[Dict[str, Any]]) -> tuple:
    if not record:
        return (0, 0, 0)
    return (int(record.get("generation") or 0), int(record.get("discards") or 0), int(record.get("seq") or 0))


# --------------------------------------------------------------------------- file locking

@contextmanager
def _file_lock(path: str):
    """An exclusive lock on ``path`` + '.lock', between processes."""
    lock_path = path + ".lock"
    os.makedirs(os.path.dirname(lock_path) or ".", exist_ok=True)
    fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            import time
            while True:
                try:
                    os.lseek(fd, 0, 0)
                    msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
                    break
                except OSError:
                    time.sleep(0.05)
            try:
                yield
            finally:
                os.lseek(fd, 0, 0)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def read_file(path: str) -> Optional[Dict[str, Any]]:
    """The record in ``path``, or None when there is none. Raises ValueError for a file that is not one."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except FileNotFoundError:
        return None
    if not isinstance(data, dict) or data.get("version") != VERSION:
        raise ValueError("the head record is not readable")
    base = empty()
    base.update(data)
    return base


def _write_file(path: str, record: Dict[str, Any]) -> None:
    directory = os.path.dirname(path) or "."
    os.makedirs(directory, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=".audit-chain-head.", dir=directory)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(record, fh, sort_keys=True, separators=(",", ":"))
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise
    try:
        dfd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(dfd)
        finally:
            os.close(dfd)
    except OSError:
        pass   # not every platform can fsync a directory


# --------------------------------------------------------------------------- merging

def _later(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None:
        return b
    if b is None:
        return a
    return max(a, b)


def _earlier(a: Optional[str], b: Optional[str]) -> Optional[str]:
    if a is None:
        return b
    if b is None:
        return a
    return min(a, b)


def _merge_entries(old: Dict[str, Any], new: Dict[str, Any]) -> Dict[str, Any]:
    """Failures and warnings by kind: the earliest first sighting, the latest last one, and acknowledged only
    once the acknowledgment covers the last sighting."""
    out = copy.deepcopy(old)
    for kind, entry in new.items():
        have = out.get(kind)
        if have is None:
            out[kind] = copy.deepcopy(entry)
            continue
        merged = dict(have)
        merged.update({k: v for k, v in entry.items() if k not in ("first_seen", "last_seen", "acknowledged_at")})
        merged["first_seen"] = _earlier(have.get("first_seen"), entry.get("first_seen"))
        merged["last_seen"] = _later(have.get("last_seen"), entry.get("last_seen"))
        merged["acknowledged_at"] = _later(have.get("acknowledged_at"), entry.get("acknowledged_at"))
        out[kind] = merged
    return out


def _key_entry_id(e: Dict[str, Any]) -> tuple:
    return (e.get("generation"), e.get("key_id"), e.get("from_seq"))


def _seal_entry_id(e: Dict[str, Any]) -> tuple:
    return (e.get("generation"), e.get("seq"), e.get("link"))


def _merge_lists(old: list, new: list, ident) -> list:
    out = {ident(e): copy.deepcopy(e) for e in old}
    for e in new:
        k = ident(e)
        if k in out:
            merged = dict(out[k])
            for field, value in e.items():
                if field in ("acknowledged", "discarded"):
                    merged[field] = bool(merged.get(field)) or bool(value)
                elif field == "to_seq":
                    merged[field] = value if merged.get(field) is None else merged[field]
                elif field not in merged or merged[field] is None:
                    merged[field] = value
            out[k] = merged
        else:
            out[k] = copy.deepcopy(e)
    return sorted(out.values(), key=lambda e: tuple("" if v is None else str(v).zfill(20) for v in ident(e)))


def merge(disk: Optional[Dict[str, Any]], mine: Dict[str, Any], now: datetime) -> Dict[str, Any]:
    """``mine`` merged into the record on disk. The higher of the two by (generation, discards, seq) gives the
    head; everything that only grows is unioned."""
    if not disk:
        result = copy.deepcopy(mine)
    else:
        base, other = (copy.deepcopy(mine), disk) if order(mine) >= order(disk) else (copy.deepcopy(disk), mine)
        result = base
        result["keys"] = _merge_lists(base.get("keys", []), other.get("keys", []), _key_entry_id)
        result["unverified_keys"] = _merge_lists(base.get("unverified_keys", []), other.get("unverified_keys", []),
                                                 _seal_entry_id)
        result["after_record"] = _merge_lists(base.get("after_record", []), other.get("after_record", []),
                                              _seal_entry_id)
        hours = dict(other.get("hours", {}))
        hours.update(base.get("hours", {}))
        result["hours"] = hours
        days = dict(other.get("days", {}))
        days.update(base.get("days", {}))
        result["days"] = days
        links = dict(other.get("links", {}))
        links.update(base.get("links", {}))
        result["links"] = links
        result["failures"] = _merge_entries(other.get("failures", {}), base.get("failures", {}))
        result["warnings"] = _merge_entries(other.get("warnings", {}), base.get("warnings", {}))
        check = dict(other.get("check", {}))
        for k, v in base.get("check", {}).items():
            if k.endswith("_seq") or k == "rolling_from":
                check[k] = max(v, check.get(k) or 0) if isinstance(v, int) else (v or check.get(k))
            elif k.endswith("_at"):
                check[k] = _later(check.get(k), v)
            else:
                check[k] = v
        result["check"] = check
        if (other.get("status") or {}).get("at", "") > (base.get("status") or {}).get("at", ""):
            result["status"] = copy.deepcopy(other["status"])
    cutoff = (now - timedelta(days=SUMMARY_DAYS)).strftime("%Y-%m-%dT%H:00:00Z")
    result["hours"] = {h: v for h, v in result.get("hours", {}).items() if h >= cutoff}
    result["version"] = VERSION
    return result


# --------------------------------------------------------------------------- the store

class HeadStore:
    """The head record of one process: its copy in memory and the file."""

    def __init__(self, path: str):
        self.path = path
        self.memory: Optional[Dict[str, Any]] = None
        self.unwritable: Optional[str] = None
        self._mutex = threading.Lock()

    def load(self) -> Optional[Dict[str, Any]]:
        """The higher of memory and the file. Raises ValueError for a file that is not a record."""
        with self._mutex:
            with _file_lock(self.path):
                disk = read_file(self.path)
            if disk is None:
                return copy.deepcopy(self.memory) if self.memory else None
            if self.memory is None or order(disk) >= order(self.memory):
                self.memory = disk
            return copy.deepcopy(self.memory)

    def exists(self) -> bool:
        return os.path.exists(self.path) or self.memory is not None

    def write(self, change, now: datetime) -> Dict[str, Any]:
        """Apply ``change(record) -> record`` to the merged record under the file lock, and write it. Keeps the
        result in memory even when the file cannot be written (``unwritable`` then says why)."""
        with self._mutex:
            try:
                with _file_lock(self.path):
                    try:
                        disk = read_file(self.path)
                    except ValueError:
                        disk = None
                    base = merge(disk, self.memory or empty(), now) if (disk or self.memory) else empty()
                    record = change(copy.deepcopy(base))
                    record = merge(disk, record, now)
                    _write_file(self.path, record)
                self.unwritable = None
            except OSError as exc:
                base = copy.deepcopy(self.memory or empty())
                record = change(base)
                self.unwritable = f"{type(exc).__name__}: {exc}"
            self.memory = record
            return copy.deepcopy(record)
