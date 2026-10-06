"""When the server counts what the audit chain says: the gaps in the chain's time, where another writer's seals
sit, and the dates the pruner acts from.

A gap is two consecutive seals whose times differ by more than 12 hours, or, to the pruner, a newest seal more
than 12 hours old (an open gap, which ends when the next seal is written). A running server writes a seal at
least every few hours, so a gap is time sealing did not run: a stop, a rollback to a release without the chain,
a restore made by hand. No delay counts it: its length is added to every date that counts time from before it.

Each date is computed on two timelines, and the server takes the later:

- the chain's, where every seal sits at its own sealed_at: what a check off the server sees;
- the server's, where a seal another writer appended after the head record sits at the time the server first
  accepted it (the head record keeps that time). Seals appended across a stop, each dated less than 12 hours
  after the last, cannot hide the stop there.

The dates (app/core/audit_chain_policy_seals.py and the size cap use them):

- a pending request's effective not_before (condition 4): the latest of its own not_before plus every gap
  after its seal, and the grace_until of every restore seal (and of a genesis that replaces a lost chain) plus
  every gap after that seal; for a request another writer appended (condition 5), also the time the server
  first accepted it plus the delay then, plus every gap after that;
- a request another writer's applies seal applied: its due date, the date the pruner itself could first have
  applied it, with only the gaps that open before that date (so the date is fixed once sealing has run past
  it);
- the size cap's window: one delay of time while sealing ran, counted back from now, each gap it takes in
  lengthening it again.

Times are microseconds since the epoch (app/core/audit_chain_view.py), as the view keeps them.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, Iterable, List, Optional, Tuple

from app.core.audit_chain_view import from_us, to_us

GAP = timedelta(hours=12)
GAP_US = 12 * 3600 * 1000000
DAY_US = 24 * 3600 * 1000000


class Timeline:
    """The seals' times on one timeline: the chain's (``placed`` empty), or the server's (another writer's
    seals at the times the server first accepted them). ``gap_ends`` are the seqs at which a chain-dated gap
    ends (the view keeps them as it accepts seals); ``times`` every seal's sealed_at by seq."""

    def __init__(self, times, gap_ends: Iterable[int], placed: Optional[Dict[int, int]] = None,
                 upto: Optional[int] = None):
        self.times = times
        self.n = len(times) if upto is None else min(upto, len(times))
        self.placed = {s: t for s, t in (placed or {}).items() if 1 <= s <= self.n}
        self._gaps = self._build(gap_ends)

    def t(self, seq: int) -> int:
        """Where seal ``seq`` sits."""
        p = self.placed.get(seq)
        return p if p is not None else self.times[seq - 1]

    def _build(self, gap_ends) -> List[Tuple[int, int, int]]:
        """(seq at which the gap ends, its start, its end), in seq order."""
        touched = set()
        for s in self.placed:
            touched.add(s)
            touched.add(s + 1)
        out = []
        for g in gap_ends:
            if g > self.n or g in touched:
                continue
            out.append((g, self.times[g - 2], self.times[g - 1]))
        for g in touched:
            if 2 <= g <= self.n:
                a, b = self.t(g - 1), self.t(g)
                if b - a > GAP_US:
                    out.append((g, a, b))
        out.sort()
        return out

    @property
    def gaps(self) -> List[Tuple[int, int, int]]:
        return self._gaps

    def newest(self) -> Optional[int]:
        return self.t(self.n) if self.n else None

    def open_gap(self, now_us: int) -> int:
        """The length of the gap open at ``now``: the time since the newest seal, when over 12 hours."""
        newest = self.newest()
        if newest is None or now_us - newest <= GAP_US:
            return 0
        return now_us - newest

    def after(self, seq: int, now_us: Optional[int] = None) -> int:
        """The length of every gap between seal ``seq`` and the newest, and the one open at ``now``."""
        total = sum(b - a for g, a, b in self._gaps if g > seq)
        if now_us is not None:
            total += self.open_gap(now_us)
        return total

    def since(self, since_us: int, now_us: Optional[int] = None) -> int:
        """The length of every gap that ends after ``since`` (whole, even one that began before it), and the
        one open at ``now``."""
        total = sum(b - a for g, a, b in self._gaps if b > since_us)
        if now_us is not None:
            total += self.open_gap(now_us)
        return total

    def push(self, base_us: int, *, after_seq: int = 0, since_us: Optional[int] = None,
             now_us: Optional[int] = None) -> int:
        """``base`` moved on by every gap after seal ``after_seq`` (or ending after ``since``) that opens before
        the date as it moves: the date something waiting from then on could first come, with the gaps that
        open after it left out. With ``now``, the gap open at ``now`` counts too when it opened before the
        date."""
        date = base_us
        for g, a, b in sorted(self._gaps, key=lambda x: x[1]):
            if g <= after_seq or (since_us is not None and b <= since_us):
                continue
            if a < date:
                date += b - a
        if now_us is not None:
            newest = self.newest()
            if newest is not None and now_us - newest > GAP_US and newest < date:
                date += now_us - newest
        return date

    def window_start(self, now_us: int, length_us: int) -> int:
        """The start of a window that reaches back from ``now`` over ``length`` of time while sealing ran: the
        length, plus every gap inside the window, an open gap included, each gap it takes in lengthening it
        again (a gap that reaches into the window counts whole)."""
        start = now_us - length_us
        start -= self.open_gap(now_us)
        for g, a, b in sorted(self._gaps, key=lambda x: x[2], reverse=True):
            if b > start:
                start -= b - a
        return start

    def running_between(self, start_us: int, end_us: int) -> int:
        """The time while sealing ran in [start, end]: its length less every gap that lies in it (a gap that
        crosses an end counts for the part inside)."""
        total = end_us - start_us
        for g, a, b in self._gaps:
            lo, hi = max(a, start_us), min(b, end_us)
            if hi > lo:
                total -= hi - lo
        newest = self.newest()
        if newest is not None and end_us - newest > GAP_US:
            lo = max(newest, start_us)
            if end_us > lo:
                total -= end_us - lo
        return total


def gap_ends(times) -> List[int]:
    """The seqs at which a chain-dated gap ends, over ``times`` (sealed_at by seq, microseconds)."""
    return [i + 1 for i in range(1, len(times)) if times[i] - times[i - 1] > GAP_US]


def placements(record: Optional[dict], generation: int) -> Dict[int, int]:
    """{seq: microseconds} of the seals another writer appended after the head record, at the times the server
    first accepted them (the head record's list; a discarded seal sits nowhere)."""
    from app.core import audit_chain_format as fmt
    out = {}
    for e in (record or {}).get("after_record") or []:
        if e.get("generation") != generation or e.get("discarded") or not e.get("accepted_at"):
            continue
        try:
            out[int(e["seq"])] = to_us(fmt.parse_time_text(e["accepted_at"]))
        except (TypeError, ValueError, KeyError):
            continue
    return out


def timelines(view, record: Optional[dict], upto: Optional[int] = None) -> Tuple[Timeline, Timeline]:
    """(the chain's timeline, the server's) of ``view``, up to seal ``upto``."""
    ends = view.gap_ends
    chain = Timeline(view.times, ends, upto=upto)
    placed = placements(record, view.generation)
    server = Timeline(view.times, ends, placed, upto=upto) if placed else chain
    return chain, server


def us(t: datetime) -> int:
    return to_us(t)


def dt(t_us: int) -> datetime:
    return from_us(t_us)
