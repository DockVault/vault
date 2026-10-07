"""Sealing over rows a release without the chain removed (``dockvault.py audit acknowledge-removed-before``).

A rollback to 0.33.x runs its own retention prune, which deletes audit rows by time and seals nothing; back on
0.34.x, those rows are ``rows-missing``. This is the only way to seal over them, and it accepts only a removal
that is exactly a time cutoff over the sealed rows, checked against every sealed hour's list of rows:

- the cutoff hour is the hour of the earliest sealed row kept; every sealed hour before it lost all its rows,
  in the cutoff hour the missing rows are exactly the first ones of its (timestamp, id) list, and no hour after
  it lost a row, nor holds a row its seal does not, nor changed (every hour checks out against its seal);
- the cutoff the operator names falls in the cutoff hour;
- the cutoff is as old as the retention that made it: a database writer who deletes every row before a recent
  time makes exactly the shape of a retention prune, so the operator states the AUDIT_LOG_RETENTION_DAYS the
  older release ran with, and a removal reaching an hour later than that many days before the end of the latest
  period in which no seal was written (when 0.34.x was not running) is refused, to the hour.

Anything else is refused, with the counts per hour printed. The write phase reads the rows again under the
chain lock and refuses unless they are what the read phase printed; it then writes one ``prune`` seal per UTC
day (reason external, by the host) re-rooting the hours over the rows kept.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional

from app.core import audit_chain_format as fmt
from app.core import audit_chain_times as times
from app.core.audit_chain_host import Refused, chain_state, check_expected, host_audit_row, token

ACTION = "audit_removal_acknowledged"


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _hour_state(db, view, hour: datetime) -> dict:
    """An hour's sealed list against its rows now: {sealed, present, missing, added, fig, root, wr, salt}."""
    ai = _ai()
    root = ai.hour_root(db, view, hour)
    wr = ai.working_row(db, hour)
    sealed_blob = bytes(wr.row_ids or b"") if wr is not None else b""
    if fmt.ids_digest_of_blob(sealed_blob) != root.ids_digest:
        raise Refused(f"the list of rows sealed for {fmt.hour_text(hour)} no longer matches its seal")
    sealed = [sealed_blob[i:i + 16] for i in range(0, len(sealed_blob), 16)]
    salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
    fig = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), salt)
    present = [fig.ids[i:i + 16] for i in range(0, len(fig.ids), 16)]
    present_set, sealed_set = set(present), set(sealed)
    return {"sealed": sealed, "present": present, "missing": [i for i in sealed if i not in present_set],
            "added": [i for i in present if i not in sealed_set], "fig": fig, "root": root, "wr": wr, "salt": salt}


def latest_stop_end(view) -> Optional[datetime]:
    """The end of the latest period in which no seal was written (a gap of more than 12 hours in the chain's
    time), or None."""
    tl = times.Timeline(view.times, view.gap_ends)
    if not tl.gaps:
        return None
    return times.dt(max(b for _g, _a, b in tl.gaps))


def removal_plan(db, view, record: Optional[dict], before: datetime, retention_days: int) -> dict:
    """The read phase: the shape of the removal, checked; the hours it re-roots; the state."""
    ai = _ai()
    if retention_days is None or retention_days < 1:
        raise Refused("--retention-days: the AUDIT_LOG_RETENTION_DAYS the older release ran with (1 or more)")
    hours = [h for h in view.single_hours() if view.entry_for(h).root.count]
    states: Dict[datetime, dict] = {}
    lines = ["Sealed hours with rows: sealed count, count now"]
    for h in hours:
        s = _hour_state(db, view, h)
        states[h] = s
        lines.append(f"  {fmt.hour_text(h)}: {len(s['sealed'])} -> {len(s['present'])}")
    changed = [h for h in hours if states[h]["missing"]]
    if not changed:
        raise Refused("no sealed row is missing: there is nothing to acknowledge")
    for h in hours:
        if states[h]["added"]:
            raise Refused(f"{fmt.hour_text(h)} holds rows its seal does not: this is not a removal")
    kept = [h for h in hours if states[h]["present"]]
    cutoff = kept[0] if kept else ai.hour_floor(before)
    for h in hours:
        s = states[h]
        if h < cutoff and s["present"]:
            raise Refused(f"{fmt.hour_text(h)}, before the cutoff hour, kept rows: not a time cutoff")
        if h > cutoff and s["missing"]:
            raise Refused(f"{fmt.hour_text(h)}, after the cutoff hour, lost rows: not a time cutoff")
        if h == cutoff and s["missing"] != s["sealed"][:len(s["missing"])]:
            raise Refused(f"in the cutoff hour {fmt.hour_text(h)} the rows missing are not its first ones: not a "
                          "time cutoff")
        if not s["missing"]:
            fig, root = s["fig"], s["root"]
            if (fig.count, fig.root_s, fig.root_c, fig.ids_digest) != (root.count, root.root_s, root.root_c,
                                                                      root.ids_digest):
                raise Refused(f"{fmt.hour_text(h)} does not check out against its seal: run audit verify")
        elif h == cutoff:
            kept_rows = [r for r in ai.iter_rows(db, h, h + ai.HOUR)]
            fig = ai.hour_figures(kept_rows, s["salt"])
            if fig.count != len(s["sealed"]) - len(s["missing"]):
                raise Refused(f"{fmt.hour_text(h)}'s rows do not add up")
    if ai.hour_floor(before) != cutoff:
        raise Refused(f"the cutoff {fmt.time_text(before)} does not fall in the cutoff hour {fmt.hour_text(cutoff)}")
    stop_end = latest_stop_end(view)
    if stop_end is None:
        raise Refused("the chain shows no period in which no seal was written: no release without the chain ran "
                      "since sealing began, so nothing it removed can be acknowledged")
    latest = ai.hour_floor(stop_end - timedelta(days=retention_days))
    newest_lost = max(changed)
    lines.append(f"The cutoff hour {fmt.hour_text(cutoff)} is {(view.newest_at() - cutoff).days} days old; the newest "
                 f"hour that lost rows is {fmt.hour_text(newest_lost)}; sealing was last stopped until "
                 f"{fmt.time_text(stop_end)}.")
    if newest_lost > latest:
        raise Refused(f"a release that kept {retention_days} days and ran until {fmt.time_text(stop_end)} removed "
                      f"nothing after {fmt.hour_text(latest)}, but {fmt.hour_text(newest_lost)} lost rows: the "
                      "cutoff is too recent")
    first_kept = None
    if cutoff in states and states[cutoff]["present"]:
        first_kept = str(fmt.as_uuid(states[cutoff]["present"][0]))
    lines.append(f"Seals over {len(changed)} hours, one prune seal per day.")
    state = {"chain": chain_state(view, record), "command": "removed-before", "before": fmt.time_text(before),
             "retention_days": retention_days, "cutoff": fmt.hour_text(cutoff),
             "hours": [[fmt.hour_text(h), len(states[h]["present"]), fmt.ids_digest_of_blob(
                 b"".join(states[h]["present"])).hex()] for h in hours]}
    return {"state": state, "lines": lines, "changed": changed, "states": states, "cutoff": cutoff,
            "first_kept": first_kept, "stop_end": stop_end}


def acknowledge_removed_before(engine, st, before: datetime, *, retention_days: int, expect: Optional[str] = None,
                               read: bool = False) -> dict:
    """See the module's docstring. Raises Refused."""
    ai = _ai()
    sealed: List[int] = []
    with ai.ChainWriter(engine, st, wait=30, writer="host", snapshot=True) as w:
        plan = removal_plan(w.db, w.st.view, w.record or {}, before, retention_days)
        if read:
            return {"state": token(plan["state"]), "lines": plan["lines"]}
        check_expected(plan["state"], expect)
    by_day: Dict = {}
    for h in plan["changed"]:
        by_day.setdefault(h.date(), []).append(h)
    expected = {h: plan["states"][h]["present"] for h in plan["changed"]}
    cutoff = {"hour": fmt.hour_text(plan["cutoff"]), "first_kept": plan["first_kept"], "retention_days": retention_days,
              "not_sealing_until": fmt.time_text(plan["stop_end"])}
    for day in sorted(by_day):
        with ai.ChainWriter(engine, st, wait=30, writer="host", snapshot=True) as w:
            entries = []
            for h in by_day[day]:
                s = _hour_state(w.db, w.st.view, h)
                if s["present"] != expected[h] or s["added"]:
                    raise Refused(f"{fmt.hour_text(h)} changed while its removal was being sealed; seals written "
                                  f"so far: {sealed or 'none'}")
                fig = s["fig"]
                if s["wr"] is not None:
                    s["wr"].row_ids = fig.ids
                entries.append([fmt.hour_text(h), s["root"].seq, fig.count, fig.bytes, fig.root_s.hex(),
                                fig.root_c.hex(), fig.ids_digest.hex()])
            host_audit_row(w.db, ACTION, {"day": day.isoformat(), "hours": len(entries), "cutoff": cutoff["hour"],
                                          "retention_days": retention_days})
            seal = w.append("prune", detail={"reason": "external", "policy_seq": None, "request_seq": None,
                                             "hours": entries, "cutoff": cutoff, "by": "host"})
            sealed.append(seal.seq)
    return {"sealed": sealed, "cutoff": cutoff["hour"], "hours": len(plan["changed"])}
