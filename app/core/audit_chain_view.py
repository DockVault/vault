"""The verified view of the audit chain: what a process has accepted of the seals, kept small.

For every seal from 1 to the newest the process has accepted, the view keeps its link (recomputed from the
seal's body and the link before it, never read from the stored column), its sealed_at and its kind, in flat
arrays: 41 bytes a seal. For every sealed hour (a run of empty hours is one unit until a late seal splits an
hour out of it) it keeps, for each seal that set the hour's roots, that seal's number, its sealed_at, and the
hour's row count and bytes it records: about 50 bytes an hour. Ten years of hourly seals are about 8 MB.

The roots themselves are not kept. Whoever needs an hour's roots reads its seal again and uses it only when
its link, recomputed from the body just read and the view's link for the seal before it, equals the view's
link for its number (app/core/audit_integrity.py, hour_root): a seal edited after the view accepted it is
never acted on. A one-off check that walks the whole chain (the verifier) may keep the roots as well
(``keep_roots``), 96 bytes an entry, so it reads no seal twice.

The retention state (the policy seals, the requests, cancels and acknowledgments) is kept as it is: those
seals are few. So is the archive: for every day with blocks, its latest ``archive`` seal's number, cause,
whether it is complete, and each part's hours, rows, bound length and digest (about 350 bytes a day).
"""
from __future__ import annotations

import bisect
from array import array
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Any, Dict, Iterator, List, Optional, Tuple

from app.core import audit_chain_format as fmt

EPOCH = datetime(1970, 1, 1)
HOUR = timedelta(hours=1)
_US = timedelta(microseconds=1)
INT64_MAX = (1 << 63) - 1
GAP_US = 12 * 3600 * 1000000                       # a gap in the chain's time (app/core/audit_chain_times.py)

KINDS = ("genesis", "policy", "request", "cancel", "hour", "late", "prune", "rewrite", "erase", "archive", "key",
         "ack", "restore")
_CODE = {k: i for i, k in enumerate(KINDS)}
_UNKNOWN = 255


def to_us(t: datetime) -> int:
    return (t - EPOCH) // _US


def from_us(us: int) -> datetime:
    return EPOCH + timedelta(microseconds=us)


def to_hours(t: datetime) -> int:
    return (t - EPOCH) // HOUR


def from_hours(h: int) -> datetime:
    return EPOCH + h * HOUR


def _clip(n) -> int:
    n = int(n or 0)
    return max(0, min(n, INT64_MAX))


def _b(v) -> Optional[bytes]:
    return bytes(v) if v is not None else None


@dataclass
class RootEntry:
    """One seal that set an hour's roots: its number, when it was sealed, and the hour's count and bytes as it
    records them. The roots are filled only in a view that keeps them, or by reading the seal again."""
    seq: int
    count: int
    bytes: int
    sealed_at: datetime
    kind: str
    root_s: Optional[bytes] = None
    root_c: Optional[bytes] = None
    ids_digest: Optional[bytes] = None


@dataclass
class HourEntry:
    """An hour's unit of the index, as one call asks for it: a single hour or a run of empty hours, with the
    seals that set its roots (oldest first) and the erase seals after the newest of them."""
    start: datetime
    end: datetime
    roots: List[RootEntry] = field(default_factory=list)
    erases: List[int] = field(default_factory=list)

    @property
    def root(self) -> RootEntry:
        return self.roots[-1]

    @property
    def is_run(self) -> bool:
        return self.end - self.start > HOUR


@dataclass(frozen=True, slots=True)
class ArchivePart:
    """One part of an archived day as its ``archive`` seal binds it: its number, the first and last hour it holds
    (whole hours of the day, both included; hours with no rows may be among them), its rows, the length of its
    payload as stored and the SHA-256 of that payload (64 hex digits)."""
    part: int
    first_hour: datetime
    last_hour: datetime
    rows: int
    length: int
    sha256: str

    def holds(self, hour: datetime) -> bool:
        return self.first_hour <= hour <= self.last_hour

    def hours(self) -> List[datetime]:
        out, h = [], self.first_hour
        while h <= self.last_hour:
            out.append(h)
            h += HOUR
        return out

    def as_list(self) -> list:
        return [self.part, fmt.hour_text(self.first_hour), fmt.hour_text(self.last_hour), self.rows, self.length,
                self.sha256]


@dataclass(frozen=True, slots=True)
class ArchiveEntry:
    """A day's latest ``archive`` seal: its number, cause, whether its parts cover the day, and the parts."""
    seq: int
    cause: str
    complete: bool
    parts: Tuple[ArchivePart, ...] = ()

    def part_for(self, hour: datetime) -> Optional[ArchivePart]:
        for p in self.parts:
            if p.holds(hour):
                return p
        return None


_HEX = frozenset("0123456789abcdef")


def archive_day(detail: dict) -> date:
    """The day an ``archive`` seal's detail names. Raises ValueError."""
    value = detail.get("day")
    if not isinstance(value, str) or len(value) != 10:
        raise ValueError("an archive seal with no day")
    return date.fromisoformat(value)


def archive_parts(detail: dict) -> Tuple[ArchivePart, ...]:
    """The parts an ``archive`` seal's detail lists, in its order. Raises ValueError on one that is not well
    formed: [part, first hour, last hour, rows, length, digest], whole numbers not below 0 (a part numbered
    from 1), hours as the chain writes them, the digest 64 lowercase hex digits."""
    raw = detail.get("parts")
    if not isinstance(raw, list):
        raise ValueError("an archive seal whose parts are not a list")
    out = []
    for p in raw:
        if not isinstance(p, list) or len(p) != 6:
            raise ValueError("a part is not [part, first hour, last hour, rows, length, digest]")
        number, first, last, rows, length, digest = p
        for n in (number, rows, length):
            if not isinstance(n, int) or isinstance(n, bool) or n < 0:
                raise ValueError("a part's number, rows or length is not a whole number")
        if number < 1:
            raise ValueError("a part numbered below 1")
        if not isinstance(digest, str) or len(digest) != 64 or not set(digest) <= _HEX:
            raise ValueError("a part's digest is not 64 hex digits")
        if not isinstance(first, str) or not isinstance(last, str):
            raise ValueError("a part's hours are not times")
        first_hour, last_hour = fmt.parse_time_text(first), fmt.parse_time_text(last)
        if fmt.hour_text(first_hour) != first or fmt.hour_text(last_hour) != last:
            raise ValueError("a part's range is not whole hours")
        out.append(ArchivePart(number, first_hour, last_hour, rows, length, digest))
    return tuple(out)


class View:
    """The seals this process has accepted, with every link recomputed, and the fields the pruner acts on."""

    def __init__(self, keep_roots: bool = False):
        self.keep_roots = keep_roots
        self.reset()

    def reset(self, generation: int = 1, discards: int = 0) -> None:
        self.generation = generation
        self.discards = discards
        # one per seal
        self._links = bytearray()
        self._at = array("q")
        self._kind = bytearray()
        self.gap_ends: List[int] = []                  # seqs at which a gap of more than 12 hours ends
        # the hour index: units by start, each with the newest of its root entries
        self._u_start = array("i")
        self._u_end = array("i")
        self._u_last = array("i")
        # the root entries, in the order they were accepted; each names the one before it for its unit
        self._e_seq = array("q")
        self._e_at = array("q")
        self._e_bytes = array("q")
        self._e_count = array("q")
        self._e_prev = array("i")
        self._e_kind = bytearray()
        self._e_roots = bytearray()
        self._erases: Dict[int, List[int]] = {}       # hour (in hours since the epoch) -> erase seals
        self.newest_hour_end: Optional[datetime] = None
        self.genesis: Optional[dict] = None
        self.genesis_root: Optional[RootEntry] = None   # the undated rows' figures
        self.key_history: List[list] = []              # [key_id, from_seq, to_seq or None]
        self.policies: List[tuple] = []                # (seq, detail)
        self.requests: Dict[int, dict] = {}
        self.cancels: Dict[int, int] = {}              # request seq -> cancel seq
        self.cancel_by: Dict[int, str] = {}            # cancel seq -> who wrote it
        self.applied: Dict[int, int] = {}              # request seq -> seal that acted on it
        self.finals: Dict[int, int] = {}
        self.restores: List[tuple] = []                # (seq, detail)
        self.acked: Dict[int, List[int]] = {}          # acknowledged seq -> the ack seals naming it
        self.acked_rows: Dict[str, List[int]] = {}     # row id -> the host ack seals naming it
        self.late_seqs: List[int] = []
        self.erase_through: Dict[int, Any] = {}        # erase request seq -> its run's scope
        self.erased_rows: set = set()
        self.archives: Dict[date, ArchiveEntry] = {}   # day -> its latest archive seal
        # The newest prune, rewrite or erase seal and the days it changed: an archive seal of cause rewrite
        # follows one in its transaction.
        self.last_change: Optional[Tuple[int, frozenset]] = None
        self.record_seq = 0

    # -- the archive

    def archived_part(self, hour: datetime) -> Optional[ArchivePart]:
        """The part of its day's latest archive seal that holds ``hour``, or None: the hour is then not archived,
        and its rows are in audit_logs."""
        entry = self.archives.get(hour.date())
        return entry.part_for(hour) if entry is not None else None

    def archived_parts(self) -> Iterator[Tuple[date, ArchivePart]]:
        """(day, part) of every archived part, oldest first."""
        for day in sorted(self.archives):
            for p in sorted(self.archives[day].parts, key=lambda p: p.first_hour):
                yield day, p

    # -- per seal

    @property
    def position(self) -> int:
        return len(self._at)

    def link_at(self, seq: int) -> bytes:
        if seq < 1:
            return fmt.LINK_0
        return bytes(self._links[(seq - 1) * 32:seq * 32])

    def at(self, seq: int) -> datetime:
        return from_us(self._at[seq - 1])

    def at_us(self, seq: int) -> int:
        return self._at[seq - 1]

    @property
    def times(self) -> array:
        """Every seal's sealed_at, in microseconds since the epoch, by seq (index seq - 1)."""
        return self._at

    def newest_at(self) -> Optional[datetime]:
        return from_us(self._at[-1]) if self._at else None

    def kind_of(self, seq: int) -> str:
        code = self._kind[seq - 1]
        return KINDS[code] if code < len(KINDS) else "?"

    def key_in_force(self) -> Optional[str]:
        return self.key_history[-1][0] if self.key_history else None

    def key_at(self, seq: int) -> Optional[str]:
        """The key in force at seal ``seq``."""
        for kid, start, end in reversed(self.key_history):
            if start <= seq and (end is None or seq <= end):
                return kid
        return None

    def ever_in_force(self, key_id: str) -> bool:
        return any(e[0] == key_id for e in self.key_history)

    # -- the hour index

    def first_hour(self) -> Optional[datetime]:
        if not self.genesis:
            return None
        first = self.genesis.get("first_row_hour")
        if first:
            return fmt.parse_time_text(first)
        return fmt.parse_time_text(self.genesis["backlog_through"]) + HOUR

    def _unit(self, h: int) -> int:
        """The index of the unit that covers hour ``h`` (hours since the epoch), or -1."""
        i = bisect.bisect_right(self._u_start, h) - 1
        if i >= 0 and self._u_start[i] <= h < self._u_end[i]:
            return i
        return -1

    def _entries(self, last: int) -> List[RootEntry]:
        out = []
        e = last
        while e >= 0:
            out.append(self._root_entry(e))
            e = self._e_prev[e]
        out.reverse()
        return out

    def _root_entry(self, e: int) -> RootEntry:
        code = self._e_kind[e]
        kind = KINDS[code] if code < len(KINDS) else "?"
        r = RootEntry(self._e_seq[e], self._e_count[e], self._e_bytes[e], from_us(self._e_at[e]), kind)
        if self.keep_roots:
            blob = self._e_roots[e * 96:(e + 1) * 96]
            r.root_s, r.root_c, r.ids_digest = bytes(blob[:32]), bytes(blob[32:64]), bytes(blob[64:])
        return r

    def entry_for(self, hour: datetime) -> Optional[HourEntry]:
        """The index entry of ``hour``: its own, or the run that covers it."""
        h = to_hours(hour)
        i = self._unit(h)
        if i < 0:
            return None
        start = from_hours(self._u_start[i])
        entry = HourEntry(start, from_hours(self._u_end[i]), self._entries(self._u_last[i]))
        if self._u_end[i] - self._u_start[i] == 1:
            entry.erases = list(self._erases.get(h, ()))
        return entry

    def has_own(self, hour: datetime) -> bool:
        """Whether ``hour`` has a unit of its own (not a run's)."""
        i = self._unit(to_hours(hour))
        return i >= 0 and self._u_end[i] - self._u_start[i] == 1

    def own_entry(self, hour: datetime) -> Optional[HourEntry]:
        """``hour``'s own entry, or None when it has none (no unit, or inside a run)."""
        return self.entry_for(hour) if self.has_own(hour) else None

    def single_hours(self) -> Iterator[datetime]:
        """The start of every hour with a unit of its own, oldest first."""
        for i in range(len(self._u_start)):
            if self._u_end[i] - self._u_start[i] == 1:
                yield from_hours(self._u_start[i])

    def runs(self) -> Iterator[tuple]:
        """(start, end, the run seal's number) of every run of empty hours, oldest first."""
        for i in range(len(self._u_start)):
            if self._u_end[i] - self._u_start[i] > 1:
                e = self._u_last[i]
                while self._e_prev[e] >= 0:
                    e = self._e_prev[e]
                yield from_hours(self._u_start[i]), from_hours(self._u_end[i]), self._e_seq[e]

    def units(self) -> Iterator[tuple]:
        """(start, end, newest root entry index) of every unit, oldest first."""
        for i in range(len(self._u_start)):
            yield from_hours(self._u_start[i]), from_hours(self._u_end[i]), self._u_last[i]

    def unit_count(self) -> int:
        return len(self._u_start)

    def recent_units(self, since: datetime) -> List[HourEntry]:
        """The units whose newest root entry was sealed at or after ``since``."""
        threshold = to_us(since)
        out = []
        for i in range(len(self._u_start)):
            if self._e_at[self._u_last[i]] >= threshold:
                out.append(HourEntry(from_hours(self._u_start[i]), from_hours(self._u_end[i]),
                                     self._entries(self._u_last[i]),
                                     list(self._erases.get(self._u_start[i], ()))
                                     if self._u_end[i] - self._u_start[i] == 1 else []))
        return out

    def entry_chain(self, last: int) -> List[tuple]:
        """(seq, sealed_at in microseconds, bytes) of a unit's root entries, oldest first."""
        out = []
        e = last
        while e >= 0:
            out.append((self._e_seq[e], self._e_at[e], self._e_bytes[e]))
            e = self._e_prev[e]
        out.reverse()
        return out

    def _new_entry(self, seq: int, at_us: int, count, nbytes, kind: str, prev: int, roots=None) -> int:
        self._e_seq.append(seq)
        self._e_at.append(at_us)
        self._e_bytes.append(_clip(nbytes))
        self._e_count.append(_clip(count))
        self._e_prev.append(prev)
        self._e_kind.append(_CODE.get(kind, _UNKNOWN))
        if self.keep_roots:
            rs, rc, idd = roots or (b"", b"", b"")
            self._e_roots += (_b(rs) or b"").ljust(32, b"\0")[:32]
            self._e_roots += (_b(rc) or b"").ljust(32, b"\0")[:32]
            self._e_roots += (_b(idd) or b"").ljust(32, b"\0")[:32]
        return len(self._e_seq) - 1

    def _split_out(self, hour: datetime) -> int:
        """The unit index of ``hour`` alone: split out of the run that covers it (the run's other hours keep
        the run's seal), or a new unit when no unit covers it."""
        h = to_hours(hour)
        i = self._unit(h)
        if i >= 0 and self._u_end[i] - self._u_start[i] == 1:
            return i
        if i < 0:
            j = bisect.bisect_right(self._u_start, h)
            self._u_start.insert(j, h)
            self._u_end.insert(j, h + 1)
            self._u_last.insert(j, -1)
            return j
        start, end, last = self._u_start[i], self._u_end[i], self._u_last[i]
        first = last
        while self._e_prev[first] >= 0:
            first = self._e_prev[first]
        empty = (fmt.EMPTY_ROOT, fmt.EMPTY_ROOT, fmt.ids_digest([]))
        copy = self._new_entry(self._e_seq[first], self._e_at[first], 0, 0, KINDS[self._e_kind[first]]
                               if self._e_kind[first] < len(KINDS) else "?", -1, empty)
        pieces = []
        if start < h:
            pieces.append((start, h, last))
        pieces.append((h, h + 1, copy))
        if h + 1 < end:
            pieces.append((h + 1, end, last))
        del self._u_start[i]
        del self._u_end[i]
        del self._u_last[i]
        at = i
        for s, e, l in pieces:
            self._u_start.insert(at, s)
            self._u_end.insert(at, e)
            self._u_last.insert(at, l)
            at += 1
        return i + (1 if start < h else 0)

    def _add_root(self, hour: datetime, seq: int, at_us: int, count, nbytes, kind: str, roots) -> None:
        i = self._split_out(hour)
        self._u_last[i] = self._new_entry(seq, at_us, count, nbytes, kind, self._u_last[i], roots)
        self._erases.pop(to_hours(hour), None)

    # -- accepting a seal

    def accept(self, seal, link: bytes) -> None:
        assert seal.seq == self.position + 1, (seal.seq, self.position)
        self._links += link
        at_us = to_us(seal.sealed_at)
        if self._at and at_us - self._at[-1] > GAP_US:
            self.gap_ends.append(seal.seq)
        self._at.append(at_us)
        self._kind.append(_CODE.get(seal.kind, _UNKNOWN))
        d = seal.detail if isinstance(seal.detail, dict) else {}
        kind = seal.kind
        if kind == "genesis":
            self.genesis = dict(d)
            self.genesis_root = RootEntry(seal.seq, int(seal.row_count), int(seal.row_bytes), seal.sealed_at, kind,
                                          _b(seal.root_s) or b"", _b(seal.root_c) or b"", _b(seal.ids_digest) or b"")
            self.key_history.append([seal.key_id, seal.seq, None])
        elif kind == "key":
            if self.key_history:
                self.key_history[-1][2] = seal.seq - 1
            self.key_history.append([seal.key_id, seal.seq, None])
        elif kind == "hour":
            start, end = to_hours(seal.period_start), to_hours(seal.period_end)
            roots = (seal.root_s, seal.root_c, seal.ids_digest)
            j = bisect.bisect_right(self._u_start, start)
            if j > 0 and self._u_end[j - 1] > start or j < len(self._u_start) and self._u_start[j] < end:
                # An hour seal over hours already in the index (only a seal the checks refuse can be one): it
                # becomes the newest root entry of each hour it covers, as a late seal would.
                for h in range(start, end):
                    self._add_root(from_hours(h), seal.seq, at_us, seal.row_count, seal.row_bytes, kind, roots)
            else:
                e = self._new_entry(seal.seq, at_us, seal.row_count, seal.row_bytes, kind, -1, roots)
                self._u_start.insert(j, start)
                self._u_end.insert(j, end)
                self._u_last.insert(j, e)
            if self.newest_hour_end is None or seal.period_end > self.newest_hour_end:
                self.newest_hour_end = seal.period_end
        elif kind == "late":
            hour = fmt.parse_time_text(d.get("hour")) if d.get("hour") else seal.period_start
            self._add_root(hour, seal.seq, at_us, seal.row_count, seal.row_bytes, kind,
                           (seal.root_s, seal.root_c, seal.ids_digest))
            if d.get("by") != "host":
                self.late_seqs.append(seal.seq)
        elif kind in ("prune", "rewrite"):
            days = set()
            for h in d.get("hours") or []:
                hour = fmt.parse_time_text(h[0])
                days.add(hour.date())
                self._add_root(hour, seal.seq, at_us, int(h[2]), int(h[3]), kind,
                               (bytes.fromhex(h[4]), bytes.fromhex(h[5]), bytes.fromhex(h[6])))
            self.last_change = (seal.seq, frozenset(days))
            if d.get("request_seq") is not None and d.get("final"):
                self.finals[int(d["request_seq"])] = seal.seq
        elif kind == "erase":
            if d.get("request_seq") is not None:
                self.erase_through.setdefault(int(d["request_seq"]), d.get("through"))
            for row in d.get("rows") or []:
                if row:
                    self.erased_rows.add(row[0])
            days = set()
            if d.get("hour"):
                hour = fmt.parse_time_text(d["hour"])
                days.add(hour.date())
                self._split_out(hour)
                self._erases.setdefault(to_hours(hour), []).append(seal.seq)
            self.last_change = (seal.seq, frozenset(days))
            if d.get("final") and d.get("request_seq") is not None:
                self.finals[int(d["request_seq"])] = seal.seq
        elif kind == "archive":
            # A seal the checks refuse (no day, a part not well formed) changes nothing the view holds; audit
            # verify reports it (app/core/audit_archive.py, archive_problem).
            try:
                day = archive_day(d)
                parts = archive_parts(d)
            except (TypeError, ValueError):
                day = None
            if day is not None:
                self.archives[day] = ArchiveEntry(seal.seq, str(d.get("cause")), bool(d.get("complete")), parts)
        elif kind == "policy":
            self.policies.append((seal.seq, d))
            if d.get("cause") == "applies" and d.get("request_seq") is not None:
                self.applied[int(d["request_seq"])] = seal.seq
        elif kind == "request":
            self.requests[seal.seq] = d
        elif kind == "cancel":
            if d.get("cancels") is not None:
                self.cancels[int(d["cancels"])] = seal.seq
            self.cancel_by[seal.seq] = d.get("by")
        elif kind == "ack":
            for s in d.get("acknowledges") or []:
                self.acked.setdefault(int(s), []).append(seal.seq)
            if d.get("by") == "host":
                for rid in d.get("rows") or []:
                    self.acked_rows.setdefault(str(rid), []).append(seal.seq)
        elif kind == "restore":
            self.restores.append((seal.seq, d))
            for s in d.get("acknowledges") or []:
                self.acked.setdefault(int(s), []).append(seal.seq)

    # -- the retention state

    def newest_policy(self) -> Optional[tuple]:
        return self.policies[-1] if self.policies else None

    def newest_state(self) -> dict:
        p = self.newest_policy()
        return (p[1].get("state") or {}) if p else {}

    def pending_requests(self) -> Dict[int, dict]:
        """The requests no cancel, applies, final or newer change has ended."""
        out = {}
        for seq, d in self.requests.items():
            if seq in self.cancels or seq in self.applied or seq in self.finals:
                continue
            if d.get("what") == "setting" and self._superseded(seq, d.get("setting")):
                continue
            out[seq] = d
        return out

    def _superseded(self, seq: int, setting: Optional[str]) -> bool:
        for other, d in self.requests.items():
            if other > seq and d.get("what") == "setting" and d.get("setting") == setting:
                return True
        for pseq, d in self.policies:
            if pseq > seq and d.get("cause") in ("request", "database", "restore"):
                entry = (d.get("state") or {}).get(setting) or {}
                if entry.get("set_by") == pseq:
                    return True
        return False

    def memory(self) -> int:
        """The bytes the arrays take (the retention state's few seals aside)."""
        arrays = (self._at, self._u_start, self._u_end, self._u_last, self._e_seq, self._e_at, self._e_bytes,
                  self._e_count, self._e_prev)
        return (len(self._links) + len(self._kind) + len(self._e_kind) + len(self._e_roots)
                + sum(a.itemsize * len(a) for a in arrays))
