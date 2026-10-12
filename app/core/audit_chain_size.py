"""What the audit log's size cap counts: each hour's bytes as the chain bound them, and growth only after the
delay.

Every figure comes from the verified view (app/core/audit_chain_view.py), never from a column: an hour's bytes
are the row_bytes of the seals that set its roots. Whoever can add rows decides those figures, so the cap acts
on each hour's lagged bytes: the least the hour counted at any moment of its window, which reaches back from
now over one delay of time while sealing ran (the delay plus every gap inside the window, an open gap
included, each gap it takes in lengthening it again; app/core/audit_chain_times.py). At each moment the hour
counts the newest, in seal order, of its entries sealed by then, and 0 before its first. Rows inserted into an
hour therefore count only once a delay of sealing has passed after the seal that took them in: until then the
cap deletes nothing because of them.

On the server the window is the longer of two: with the seals dated as the chain dates them, and with each seal
another writer appended after the head record placed at the time the server first accepted it.

An entry of such a seal (an hour, late, prune or rewrite figure another writer appended) is held back: it
counts exactly the smaller of its own bytes and what the hour's entry before it counts (0 when it is the hour's
first), unless the host has acknowledged its seal and both the time the server first accepted it and its own
sealed_at lie at or before the window's start. So it never raises what the hour counts before the host has
seen it and a delay of sealing has passed.

Each entry also binds the bytes of its hour's administration and security rows, which the size cap never deletes
(``protected_bytes``). The chain alone says which hours the cap keeps whole (kept_whole): those whose protected
bytes, counted the same way (protected_hours), reach their bytes, and those wholly younger than the minimum for
every row. The share of any other hour, or of a part's other hours, the cap may never delete is taken from the
rows (an archived part's aggregates), but never above those protected bytes. A database writer who adds, deletes
or relabels rows, or edits an archived part's aggregates, can lower such a share, but cannot raise one, nor make
an hour the chain keeps whole look partly unprotected; either would move the cap's cutoff newer and delete rows
it keeps honestly. Lowering a share only ever moves the cutoff older (audit_retention.size_cutoff).

An archived part (app/core/audit_archive.py) counts the smaller of its bound length, the one its day's archive
seal records, and the lagged bytes of the hours it holds: archiving shrinks what the cap counts, never adds to it,
and a length another writer inflated changes nothing. Its hours then count only through it. A day archived over
several passes counts its parts for the hours they hold, and lagged hot bytes for its other hours.

Each size-cap prune records the cap and the delay it used, the window's start (``from``), the seals it held
back (``held_back``) and the total it counted (``counted``), so that ``audit verify`` recomputes the total from
the chain alone.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Set, Tuple

from app.core import audit_chain_format as fmt
from app.core import audit_chain_times as times
from app.core.audit_chain_view import from_hours, to_us


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def window_start(view, record: Optional[dict], now: datetime, delay: timedelta, *, server: bool = True) -> int:
    """The start of the size cap's window (microseconds): one delay of time while sealing ran back from now,
    on the chain's timeline and, on the server, on its own; the earlier of the two."""
    chain, own = times.timelines(view, record)
    now_us = times.us(now)
    length = int(delay.total_seconds() * 1000000)
    start = chain.window_start(now_us, length)
    if server:
        start = min(start, own.window_start(now_us, length))
    return start


def held_back(view, record: Optional[dict], start_us: int, *, before_seq: Optional[int] = None) -> Set[int]:
    """The seals whose entries a pass with this window holds back: another writer's seals after the head
    record, unless the host has acknowledged the seal and both its acceptance and its sealed_at lie at or
    before the window's start. ``before_seq``: only acknowledgments sealed before that seal count (a check of
    an earlier prune)."""
    ai = _ai()
    foreign = ai.foreign_entries(view, record)
    out = set()
    for seq, entry in foreign.items():
        if seq > view.position or (before_seq is not None and seq >= before_seq):
            continue
        released = False
        if entry.get("acknowledged"):
            acks = [a for a in view.acked.get(seq, ()) if a not in foreign
                    and (before_seq is None or a < before_seq)]
            if acks or before_seq is None:
                try:
                    accepted = to_us(fmt.parse_time_text(entry.get("accepted_at")))
                except (TypeError, ValueError):
                    accepted = None
                released = accepted is not None and accepted <= start_us and view.at_us(seq) <= start_us
        if not released:
            out.add(seq)
    return out


def counted_entries(chain: List[tuple], held: Set[int]) -> List[tuple]:
    """(seq, sealed_at, bytes counted) of an hour's entries, oldest first: a held-back entry counts the
    smaller of its own bytes and what the entry before it counts (0 for the hour's first)."""
    out = []
    before = 0
    for seq, at, nbytes in chain:
        counted = min(nbytes, before) if seq in held else nbytes
        out.append((seq, at, counted))
        before = counted
    return out


def lagged(entries: List[tuple], start_us: int) -> int:
    """The least an hour counted at any moment from ``start`` on: at the window's start and at every entry
    sealed after it. At each moment it counts the newest entry (by seq) sealed by then, and 0 before its
    first."""
    def at(t):
        best = None
        for seq, sealed, counted in entries:
            if sealed <= t and (best is None or seq > best[0]):
                best = (seq, counted)
        return best[1] if best is not None else 0
    least = at(start_us)
    for _seq, sealed, _counted in entries:
        if sealed > start_us:
            least = min(least, at(sealed))
    return least


def _lagged_hours(view, start_us: int, held: Set[int]) -> Dict[datetime, int]:
    """{hour: lagged bytes} of every hour with a unit of its own that counts more than nothing (runs of empty
    hours count nothing), archived or not."""
    out = {}
    for start, end, last in view.units():
        if end - start != _ai().HOUR:
            continue
        chain = view.entry_chain(last)
        n = lagged(counted_entries(chain, held), start_us)
        if n:
            out[start] = n
    return out


def counted(view, start_us: int, held: Set[int]) -> Tuple[Dict[datetime, int], List[tuple]]:
    """What the size cap counts: ({hour: lagged bytes} of every hour not archived that counts more than nothing,
    [(day, part, counted, {hour: lagged bytes}) of every archived part]). A part counts the smaller of its bound
    length (its archive seal's) and the lagged bytes of the hours it holds, so it never counts more than its hours
    did as rows, and a length another writer's seal inflated changes nothing."""
    lagged_hours = _lagged_hours(view, start_us, held)
    parts = []
    archived = set()
    for day, part in view.archived_parts():
        hours = {}
        for h in part.hours():
            archived.add(h)
            if h in lagged_hours:
                hours[h] = lagged_hours[h]
        parts.append((day, part, min(int(part.length), sum(hours.values())), hours))
    hot = {h: n for h, n in lagged_hours.items() if h not in archived}
    return hot, parts


def cap_count(view, record: Optional[dict], now: datetime, delay: timedelta, *, server: bool = True) -> tuple:
    """What the size cap counts now: (the window's start in microseconds, the seals held back, {hour: lagged bytes}
    of the hours not archived, the archived parts as counted() gives them, and the total). The pruner's plan
    (audit_retention.chain_size_plan) and the retention screen's Storage card (retention_storage.cap_counted) both
    take it from here, so the card shows what the pruner counts. Off the server (a host's verify) nothing is held
    back."""
    start_us = window_start(view, record, now, delay, server=server)
    held = held_back(view, record, start_us) if server else set()
    by_hour, parts = counted(view, start_us, held)
    return start_us, held, by_hour, parts, sum(by_hour.values()) + sum(c for _d, _p, c, _h in parts)


def now_count(view, record: Optional[dict], now: datetime) -> int:
    """What the size cap would count if every hour counted its figure now rather than the least over the window:
    each hour's newest entry (another writer's held back no more than the entry before it) and each archived part
    the smaller of its bound length and those. Growth reaches it at once and the cap's count a delay later; the
    retention screen warns on it, ahead of the cap."""
    now_us = times.us(now)
    by_hour, parts = counted(view, now_us, held_back(view, record, now_us))
    return sum(by_hour.values()) + sum(c for _d, _p, c, _h in parts)


def first_over(view, record: Optional[dict], now: datetime, delay: timedelta, limit: int) -> Optional[datetime]:
    """The earliest the size cap's count passes ``limit`` from what is sealed now, if sealing keeps running and
    nothing changes: each hour's newer figures count once the window's start has passed the seal that recorded
    them, a delay of sealing after it. Every gap in sealing since that seal (on either timeline: the server's
    window is the longer of the two) moves that on; a gap still to come would only move it later. None when the
    count never passes it."""
    start_us, held, hot, parts, total = cap_count(view, record, now, delay)
    if total > limit:
        return now
    now_us = times.us(now)
    length = int(delay.total_seconds() * 1000000)
    lines = times.timelines(view, record)
    archived = {h for _d, part in view.archived_parts() for h in part.hours()}
    moving = {}
    for start, end, last in view.units():
        if end - start != _ai().HOUR or start in archived:
            continue
        entries = counted_entries(view.entry_chain(last), held)
        if any(at > start_us for _seq, at, _n in entries):
            moving[start] = entries
    fixed = sum(c for _d, _p, c, _h in parts) + sum(n for h, n in hot.items() if h not in moving)
    # The window's start at a moment to come is the earlier of the two timelines' (window_start), so it passes a
    # seal at the later of the two moments each timeline's start passes it.
    due = {max(line.reached(at, now_us, length) for line in lines)
           for entries in moving.values() for _seq, at, _n in entries if at > start_us}
    for t in sorted(due):
        then = min(line.window_start_then(now_us, t, length) for line in lines)
        if fixed + sum(lagged(entries, then) for entries in moving.values()) > limit:
            return times.dt(t)
    return None


def protected_hours(view, start_us: int, held: Set[int]) -> Dict[datetime, int]:
    """{hour: lagged protected bytes} of every hour with a unit of its own whose rows the size cap never deletes
    count more than nothing, archived or not: the protected bytes its root entries record, counted as the hour's
    bytes are (a held-back entry no more than the entry before it, the least over the window), so never more than
    the hour's lagged bytes. An hour it reaches those for the cap keeps whole (kept_whole); the cap's protected
    share of any other hour never exceeds it, so rows added in the database, or an archived part's aggregates
    edited there, can only lower that share, never raise it."""
    out = {}
    for start, end, last in view.units():
        if end - start != _ai().HOUR:
            continue
        n = lagged(counted_entries(view.entry_chain(last, protected=True), held), start_us)
        if n:
            out[start] = n
    return out


def kept_whole(hour: datetime, lagged_bytes: int, bound: Dict[datetime, int], young: Optional[datetime]) -> bool:
    """Whether the size cap keeps ``hour`` whole, as the chain alone says: every row of it younger than the minimum
    for every row (``young``: now less that minimum, None without one; an hour that starts at or after it), or its
    lagged protected bytes (``bound``, protected_hours) reaching its lagged bytes (``lagged_bytes``). Never what its
    rows or an archived part's aggregates say: those can be changed in the database, and an hour they made look
    partly unprotected would become one the cap cuts at, newer than any it cuts at honestly
    (audit_retention.size_cutoff)."""
    return (young is not None and hour >= young) or bound.get(hour, 0) >= lagged_bytes


def hour_bytes(view, start_us: int, held: Set[int]) -> Dict[datetime, int]:
    """{hour: lagged bytes} of every hour not archived that counts more than nothing."""
    return counted(view, start_us, held)[0]


def total(view, start_us: int, held: Set[int]) -> int:
    """What the size cap counts: every hot hour's lagged bytes, and every archived part's count."""
    hot, parts = counted(view, start_us, held)
    return sum(hot.values()) + sum(c for _d, _p, c, _h in parts)


# --------------------------------------------------------------------------- the check of a size-cap prune

def size_problem(view, seal, *, record: Optional[dict] = None) -> Optional[str]:
    """Why a size-cap prune is not justified by the chain before it, or None: its counted total recomputed
    over its window with the seals it held back, its window at least its delay of sealing time as the chain
    dates the seals, its cap and delay at least the policy seal's it names, and the total over the cap. With
    the head record (on the server), also: its held-back seals exactly the ones held back then, and its window
    at least as long as the server's."""
    from app.core import audit_chain_policy as pol
    from app.core.audit_retention import MB
    d = seal.detail if isinstance(seal.detail, dict) else {}
    size = d.get("size")
    if not isinstance(size, dict):
        return "a size-cap prune with no size"
    try:
        cap, delay_days = int(size["cap"]), int(size["delay"])
        start = to_us(fmt.parse_time_text(size["from"]))
        counted = int(size["counted"])
        held = {int(s) for s in size.get("held_back") or []}
    except (KeyError, TypeError, ValueError):
        return "a size-cap prune whose size is not well formed"
    policy = next((pd for ps_, pd in view.policies if ps_ == d.get("policy_seq")), None)
    state = (policy or {}).get("state") or {}
    max_mb = pol.value_of(state, "audit_max_mb")
    if not max_mb:
        return "a size-cap prune under a policy with no cap"
    if cap < int(max_mb) * MB or delay_days < pol.delay_days(state):
        return "a size-cap prune whose cap or delay keeps less than its policy seal's"
    chain = times.Timeline(view.times, view.gap_ends)
    at = times.us(seal.sealed_at)
    if start > chain.window_start(at, delay_days * 24 * 3600 * 1000000):
        return "a size-cap prune whose window is shorter than its delay of sealing time"
    if record is not None:
        if held != held_back(view, record, start, before_seq=seal.seq):
            return "a size-cap prune whose held-back seals are not the ones held back then"
        _c, server = times.timelines(view, record)
        if start > server.window_start(at, delay_days * 24 * 3600 * 1000000):
            return "a size-cap prune whose window is shorter than the server's"
    recomputed = total(view, start, held)
    if recomputed != counted:
        return f"a size-cap prune that counted {counted} bytes where the chain gives {recomputed}"
    if counted <= cap:
        return "a size-cap prune under its cap"
    return None
