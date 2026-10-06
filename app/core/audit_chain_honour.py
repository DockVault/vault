"""What the audit pruner acts on when another writer appended seals: the honoured state, and the dates.

Seals another writer appended after the head record (someone who holds the key in force but not the host:
a copy of .env, or ENCRYPTION_KEY on an install still under the key derived from it) are accepted as
warnings and listed in the head record. Until the host acknowledges one, the pruner honours it only where it
keeps more:

- the honoured state is built from the chain's state (the newest policy seal's, which holds everything such
  a seal set, what keeps more included) and the replay: the state the chain's policy seals give when every
  seal that does not count yet is left out. Each .env bound is taken as the more-keeping of the two states'
  (the higher ceiling, cap or floor), each entry's setting as the more-keeping of the two (an entry with no
  setting counts with its value), and its value as the more-keeping of the two values and that setting
  resolved under those bounds. So a hold turned on, a value that deletes later, a bound raised and a veto
  count at once, and a value that deletes sooner counts once its seal counts;
- such a seal counts from the host's acknowledgment of it; an applies among them from the later of that and
  its request's due date (the date the pruner itself could first have applied the request), and, when the
  request is another writer's seal too, not before the host has acknowledged the request as well;
- a request among them is due only once acknowledged, and a delay after the time the server first accepted
  it (with the delay honoured then), plus every gap after that.

The dates are app/core/audit_chain_times.py's: every gap of more than 12 hours moves a date on, on the
chain's timeline and on the server's (another writer's seals where the server first accepted them), and the
later counts. A grace after a restore (a restore seal's grace_until, or a genesis that replaces a lost chain)
holds every pending request back to its end, plus the gaps after it.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from app.core import audit_chain_format as fmt
from app.core import audit_chain_policy as pol
from app.core import audit_chain_times as times
from app.core import settings_registry as registry


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _parse(text) -> Optional[datetime]:
    try:
        return fmt.parse_time_text(text)
    except (TypeError, ValueError):
        return None


# --------------------------------------------------------------------------- acknowledgments

def ack_time(view, record: Optional[dict], seq: int) -> Optional[datetime]:
    """When the host acknowledged another writer's seal ``seq``, or None while it has not. Only the head
    record's list says the host acknowledged it; the time is the earliest acknowledgment that counts naming
    it (an ``ack`` seal, or ``accept-restore``'s restore seal), else the time the list was marked."""
    ai = _ai()
    foreign = ai.foreign_entries(view, record)
    entry = foreign.get(seq)
    if entry is None:
        return None
    if not entry.get("acknowledged"):
        return None
    stamps = [view.at(a) for a in view.acked.get(seq, ()) if a not in foreign and a <= view.position]
    if stamps:
        return min(stamps)
    marked = _parse(entry.get("acknowledged_at"))
    return marked or view.newest_at()


def accepted_at(record: Optional[dict], view, seq: int) -> Optional[datetime]:
    entry = _ai().foreign_entries(view, record).get(seq)
    return _parse(entry.get("accepted_at")) if entry else None


# --------------------------------------------------------------------------- the dates of a request

def grace_terms(view, upto: Optional[int] = None) -> List[Tuple[int, int]]:
    """(seq, grace_until in microseconds) of every restore seal, and of a genesis that replaces a lost
    chain, up to seal ``upto``."""
    out = []
    g = view.genesis or {}
    if g.get("grace_until") and (upto is None or upto >= 1):
        t = _parse(g["grace_until"])
        if t is not None:
            out.append((1, times.us(t)))
    for seq, d in view.restores:
        if upto is not None and seq > upto:
            continue
        t = _parse((d or {}).get("grace_until"))
        if t is not None:
            out.append((seq, times.us(t)))
    return out


def _terms(view, record, req: int, timeline, *, server: bool) -> List[tuple]:
    """The terms of request ``req``'s effective date on ``timeline``: (base, after_seq, since)."""
    d = view.requests.get(req) or {}
    out = []
    nb = _parse(d.get("not_before"))
    if nb is not None:
        out.append((times.us(nb), req, None))
    for seq, until in grace_terms(view):
        out.append((until, seq, None))
    if server:
        entry = _ai().foreign_entries(view, record).get(req)
        if entry is not None:
            acc = _parse(entry.get("accepted_at"))
            if acc is not None:
                delay = entry.get("delay_days")
                if not isinstance(delay, int) or isinstance(delay, bool):
                    delay = pol.delay_days(view.newest_state())
                out.append((times.us(acc + timedelta(days=int(delay))), None, times.us(acc)))
    return out


def _term_at(timeline, term, date_us: int, now_us: Optional[int]) -> int:
    base, after_seq, since = term
    total = base
    for g, a, b in timeline.gaps:
        if after_seq is not None and g <= after_seq:
            continue
        if since is not None and b <= since:
            continue
        if a < date_us:
            total += b - a
    if now_us is not None:
        newest = timeline.newest()
        if newest is not None and now_us - newest > times.GAP_US and newest < date_us:
            total += now_us - newest
    return total


def effective_not_before(view, record: Optional[dict], req: int, now: datetime) -> datetime:
    """A pending request's effective not_before as of ``now`` (conditions 4 and 5): the latest of its terms,
    each moved on by every gap after it, on both timelines."""
    now_us = times.us(now)
    chain, server = times.timelines(view, record)
    best = None
    for tl, is_server in ((chain, False), (server, True)):
        for term in _terms(view, record, req, tl, server=is_server):
            v = _term_at(tl, term, now_us + 1, now_us)
            best = v if best is None else max(best, v)
    if best is None:
        return now + timedelta(days=36500)
    return times.dt(best)


def request_due(view, record: Optional[dict], req: int, now: datetime) -> datetime:
    """The date the pruner itself could first have applied request ``req`` (another writer's applies applied
    it): its terms moved on only by the gaps that open before that date, so the date is fixed once sealing
    has run past it."""
    now_us = times.us(now)
    chain, server = times.timelines(view, record)
    best = None
    for tl, is_server in ((chain, False), (server, True)):
        terms = _terms(view, record, req, tl, server=is_server)
        if not terms:
            continue
        date = max(t[0] for t in terms)
        for _ in range(10000):
            new = max(_term_at(tl, t, date, now_us) for t in terms)
            if new == date:
                break
            date = new
        best = date if best is None else max(best, date)
    if best is None:
        return now + timedelta(days=36500)
    return times.dt(best)


def counts_from(view, record: Optional[dict], seq: int, now: datetime) -> Optional[datetime]:
    """From when seal ``seq`` counts for the pruner: None when it does not yet (another writer's seal the host
    has not acknowledged, or an applies of a request the host has not acknowledged either); the time it does
    otherwise, which may lie ahead for another writer's applies (its request's due date). A seal of this
    server counts from its own place."""
    ai = _ai()
    foreign = ai.foreign_entries(view, record)
    if seq not in foreign:
        return view.at(seq) if 1 <= seq <= view.position else None
    acked = ack_time(view, record, seq)
    if acked is None:
        return None
    if view.kind_of(seq) != "policy":
        return acked
    detail = next((d for s, d in view.policies if s == seq), None) or {}
    if detail.get("cause") != "applies":
        return acked
    req = detail.get("request_seq")
    if not isinstance(req, int) or req not in view.requests:
        return acked
    out = max(acked, request_due(view, record, req, now))
    if req in foreign:
        req_acked = ack_time(view, record, req)
        if req_acked is None:
            return None
        out = max(out, req_acked)
    return out


def not_counting(view, record: Optional[dict], now: datetime) -> set:
    """The policy seals that do not count yet as of ``now``."""
    ai = _ai()
    foreign = ai.foreign_entries(view, record)
    out = set()
    for seq, _d in view.policies:
        if seq not in foreign:
            continue
        since = counts_from(view, record, seq, now)
        if since is None or since > now:
            out.add(seq)
    return out


# --------------------------------------------------------------------------- the honoured state

def _copy(state: dict) -> dict:
    return {name: dict(entry) for name, entry in (state or {}).items()}


def replay(view, skip: set) -> Tuple[dict, dict]:
    """(state, inputs) the chain's policy seals give with the seals in ``skip`` left out, each applied at its
    own place, as its cause says: an env seal's inputs replace the replay's (entries of source env or default
    recomputed, every setting resolved again under the new bounds); any other cause gives each entry it sets
    that seal's setting resolved under the replay's bounds (an entry with no setting: the .env input or the
    default under the replay's inputs)."""
    state: dict = {}
    inputs: dict = {}
    specs = {s.key: s for s in pol.chain_specs()}
    for seq, d in view.policies:
        if seq in skip:
            continue
        cause = d.get("cause")
        if cause == "genesis" or not state:
            state = _copy(d.get("state") or {})
            inputs = dict(d.get("inputs") or {})
            continue
        if cause == "env":
            inputs = dict(d.get("inputs") or {})
            state = pol.env_state(state, inputs, seq)
            continue
        ns = pol.settings_from_inputs(inputs)
        for name, entry in (d.get("state") or {}).items():
            if entry.get("set_by") != seq or name not in specs:
                continue
            spec = specs[name]
            if entry.get("setting") is None:
                fields = pol.input_entry(spec, ns, inputs)
            else:
                value, source = pol.resolve_setting(spec, entry["setting"], ns)
                if entry.get("source") == "held" and source == "setting":
                    source = "held"
                fields = {"value": value, "source": source, "setting": entry["setting"]}
            state[name] = {**fields, "request_seq": entry.get("request_seq"), "set_by": seq}
    return state, inputs


def _keeps_more(spec, a, b):
    """Whichever of two values of ``spec`` keeps more (``b`` when neither deletes sooner)."""
    if a is None:
        return b
    if b is None:
        return a
    return a if registry.is_reduction(spec, a, b) else b


def _merged_bounds(spec, ns_a, ns_b) -> tuple:
    """(floor, ceiling): the more-keeping of each state's. With no bound the state keeps most for a ceiling
    and least for a floor (for a setting whose lowering deletes sooner; the other way round otherwise)."""
    fa, ca = registry.bounds(spec, ns_a)
    fb, cb = registry.bounds(spec, ns_b)
    lower_deletes = spec.reduction == registry.LOWER
    if lower_deletes:
        floor = _keeps_more(spec, fa, fb)
        ceiling = None if (ca is None or cb is None) else _keeps_more(spec, ca, cb)
    else:
        floor = None if (fa is None or fb is None) else _keeps_more(spec, fa, fb)
        ceiling = _keeps_more(spec, ca, cb)
    return floor, ceiling


def merge_entry(spec, chain: dict, other: dict, ns_chain, ns_other) -> dict:
    """The honoured entry of ``spec`` from the chain's entry and the replay's (merge rules above)."""
    floor, ceiling = _merged_bounds(spec, ns_chain, ns_other)
    sc = chain.get("setting") if chain.get("setting") is not None else chain.get("value")
    so = other.get("setting") if other.get("setting") is not None else other.get("value")
    setting = _keeps_more(spec, sc, so)
    resolved = registry.clamp(spec, setting, floor, ceiling) if setting is not None else None
    value = _keeps_more(spec, _keeps_more(spec, chain.get("value"), other.get("value")), resolved)
    for entry in (chain, other):
        es = entry.get("setting") if entry.get("setting") is not None else entry.get("value")
        if entry.get("value") == value and es == setting:
            return dict(entry)
    no_setting = chain.get("setting") is None and other.get("setting") is None
    out = dict(chain)
    out["value"] = value
    out["setting"] = None if no_setting else setting
    if no_setting:
        out["source"] = "clamped" if value not in (chain.get("value"), other.get("value")) else (
            chain.get("source") if value == chain.get("value") else other.get("source"))
    else:
        out["source"] = "setting" if value == setting else "clamped"
    return out


def honoured_state(view, record: Optional[dict], now: Optional[datetime] = None) -> dict:
    """The state the pruner acts on (see the module's docstring). Equal to the chain's newest state when every
    seal counts."""
    newest = view.newest_policy()
    if newest is None:
        return {}
    chain = newest[1].get("state") or {}
    now = now or _ai().utcnow()
    skip = not_counting(view, record, now)
    if not skip:
        return _copy(chain)
    other, other_inputs = replay(view, skip)
    ns_chain = pol.settings_from_inputs(newest[1].get("inputs") or {})
    ns_other = pol.settings_from_inputs(other_inputs)
    specs = {s.key: s for s in pol.chain_specs()}
    out = _copy(chain)
    for name, entry in chain.items():
        o = other.get(name)
        if o is None:
            continue
        if name == pol.DELAY_ENTRY:
            if int(o.get("value") or 0) > int(entry.get("value") or 0):
                out[name] = dict(o)
            continue
        spec = specs.get(name)
        if spec is None:
            continue
        out[name] = merge_entry(spec, entry, o, ns_chain, ns_other)
    return out


def honoured_delay(view, record: Optional[dict], now: Optional[datetime] = None) -> timedelta:
    """The honoured delay: the honoured value of the delay's entry, never shorter than the delay in force."""
    days = max(pol.delay_days(honoured_state(view, record, now)), pol.delay_days(view.newest_state()))
    return timedelta(days=days)


# --------------------------------------------------------------------------- the grace after a restore

def grace_until(view, record: Optional[dict], now: datetime) -> Optional[datetime]:
    """The end of the grace after the newest restore that is still running (each restore seal's grace_until
    plus every gap after it, on both timelines, the later), or None when none runs."""
    now_us = times.us(now)
    chain, server = times.timelines(view, record)
    latest = None
    for seq, until in grace_terms(view):
        for tl in (chain, server):
            end = _term_at(tl, (until, seq, None), now_us + 1, now_us)
            latest = end if latest is None else max(latest, end)
    if latest is None or latest <= now_us:
        return None
    return times.dt(latest)
