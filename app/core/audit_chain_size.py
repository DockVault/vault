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
(``protected_bytes``). The share of an hour or a part the cap may never delete is taken from the rows (an archived
part's aggregates), but never above those bytes counted the same way (protected_hours): a database writer who adds
a protected row to an old hour, or edits an archived part's aggregates, can lower a share, which keeps more, but
cannot raise one and so make the cap delete newer rows sooner.

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


def protected_hours(view, start_us: int, held: Set[int]) -> Dict[datetime, int]:
    """{hour: lagged protected bytes} of every hour with a unit of its own whose rows the size cap never deletes
    count more than nothing, archived or not: the protected bytes its root entries record, counted as the hour's
    bytes are (a held-back entry no more than the entry before it, the least over the window). The cap's protected
    share of an hour never exceeds it, so rows added in the database, or an archived part's aggregates edited
    there, can only lower a share (which keeps more), never raise it."""
    out = {}
    for start, end, last in view.units():
        if end - start != _ai().HOUR:
            continue
        n = lagged(counted_entries(view.entry_chain(last, protected=True), held), start_us)
        if n:
            out[start] = n
    return out


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
