"""Deleting sealed audit rows without breaking the chain: a ``prune`` seal per day of hours changed.

The pruner deletes audit rows one sealed hour at a time, and at most one UTC day per transaction. Each
transaction, under the chain lock:

1. verifies each hour first: its rows (with the nonces its salt gives, and an erase's earlier commitments)
   must give the roots of the hour's newest root seal in the verified view; an hour that does not is left
   as it is, and the failure is reported, so a prune never seals over a tamper or destroys its evidence;
2. writes the derived nonces of rows written without one into their rows and deletes the hour's salt, which
   changes no leaf;
3. deletes the rows and writes the ``prune`` seal with each changed hour's new count, bytes, roots and ids,
   naming the ``policy`` seal in force, together with the ``retention_pruned`` audit row.

Only sealed hours are pruned: rows in hours not yet sealed (the first start's backlog, the current hour) wait. An
hour whose root seal, or an erase seal after it, is a seal another writer appended after the head record is left
as it is until the host acknowledges that seal: its rows may have been edited and sealed over.

Archived rows are deleted first, a day per transaction, through the block-rewrite primitive
(app/core/audit_archive.py): the ``prune`` seal and an ``archive`` seal of cause ``rewrite`` commit with the new
blocks. The caller says how to select them, as conditions over any model shaped like audit_logs (``archived``),
and before what time no row is selected (``before``): days that start later are not read. A day where nothing
was selected is read again the next day (the size cap's: once ``before`` has moved on).
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Optional

from sqlalchemy import and_, func

from app.core import audit_chain_format as fmt


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _hours_matching(db, conditions, before: datetime, limit: int) -> List[datetime]:
    from app.core.audit_retention import _hour, _as_time
    from app.core.models import AuditLog as A
    dialect = db.get_bind().dialect.name
    hour = _hour(A, dialect)
    rows = (db.query(hour).filter(*conditions, A.timestamp < before).group_by(hour).order_by(hour)
            .limit(limit).all())
    return [_as_time(r[0]) for r in rows]


class HourNotVerified(Exception):
    pass


@dataclass
class Selection:
    """What one size-cap transaction deletes: the conditions over audit_logs, the size its seal records, and for
    archived rows the same conditions over another model (``archived``) and the time before which they lie."""
    conditions: list
    size: Optional[dict] = None
    archived: Optional[Callable] = None
    before: Optional[datetime] = None


def _verify_hour(w, hour: datetime):
    """(the hour's root entry, its working row, its salt, the erase commitments) once its rows check out, read
    streamed."""
    ai = _ai()
    view = w.st.view
    own = view.own_entry(hour)
    try:
        root = ai.hour_root(w.db, view, hour)
    except ai.ChainStopped:
        raise HourNotVerified(fmt.hour_text(hour))
    wr = ai.working_row(w.db, hour)
    salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
    c_prev = ai.erase_c_prev(w.db, view, own) if own is not None and own.erases else {}
    fig = ai.hour_figures(ai.iter_rows(w.db, hour, hour + ai.HOUR), salt, c_prev)
    if (fig.count, fig.root_s, fig.root_c, fig.ids_digest) != (root.count, root.root_s, root.root_c,
                                                               root.ids_digest) or fig.missing_nonce:
        raise HourNotVerified(fmt.hour_text(hour))
    return root, wr, salt, c_prev


def _materialise(w, hour: datetime, salt: Optional[bytes], wr) -> None:
    """Write each nonce-less row's derived nonce into the row, then delete the hour's salt."""
    from app.core.models import AuditLog as A
    if salt is None:
        return
    ai = _ai()
    nonceless = [row["id"] for row in ai.iter_rows(w.db, hour, hour + ai.HOUR) if row["seal_nonce"] is None]
    for row_id in nonceless:
        w.db.query(A).filter(A.id == row_id).update({A.seal_nonce: fmt.legacy_nonce(salt, row_id)},
                                                    synchronize_session=False)
    if wr is not None:
        wr.legacy_salt = None


def prune(p, conditions, *, reason: str, size: Optional[dict] = None, plan=None,
          archived: Optional[Callable] = None, before: Optional[datetime] = None):
    """Delete the audit rows meeting ``conditions`` in sealed hours, oldest first, one day of hours per
    ``prune`` seal and transaction, while the pass has time. ``plan(writer)``, when given, decides each
    transaction's Selection under the chain lock from the view as it stands, or None to stop: the size cap's,
    whose total each seal records as of its own place. ``archived`` and ``before`` (or the plan's): the archived
    rows the same conditions select, deleted first (see the module's docstring). Nothing is deleted while a
    restore is not finished or its grace runs. Returns a retention.JobResult."""
    from app.core import retention
    from app.core.models import AuditLog as A
    ai = _ai()
    st = ai.state()
    result = retention.JobResult()
    engine = ai._engine_of(p.session_factory)
    failures: Dict[str, str] = {}
    # A view that held no archived day when it was last brought up to date skips this; a block another process
    # archived meanwhile is read at the next pass.
    if (archived is not None or plan is not None) and st.view.archives:
        done = _prune_archived(p, st, engine, failures, reason=reason, size=size, plan=plan, archived=archived,
                               before=before)
        result.add(done.deleted, done.oldest, done.newest)
    skipped: set = set()
    while p.time_left():
        with ai.ChainWriter(engine, st) as w:
            view = w.st.view
            newest = view.newest_policy()
            if newest is None or view.newest_hour_end is None:
                break
            if w.st.holds_deletion():
                break
            if plan is not None:
                planned = plan(w)
                if planned is None:
                    break
                conditions, size = planned.conditions, planned.size
            hours = [h for h in _hours_matching(w.db, conditions, view.newest_hour_end, 200) if h not in skipped]
            if not hours:
                break
            day = hours[0].date()
            entries = []
            batch = retention.JobResult()
            for hour in hours:
                if hour.date() != day or batch.deleted >= p.batch_rows:
                    break
                if view.entry_for(hour) is None:
                    skipped.add(hour)
                    continue
                if view.archived_part(hour) is not None:
                    # No legitimate path writes a row into an archived hour: it is never deleted as genuine.
                    skipped.add(hour)
                    failures["row-in-archived-day"] = f"rows of audit_logs are in {fmt.hour_text(hour)}, which is " \
                                                      "archived; they were not pruned"
                    continue
                if ai.hour_held(view, w.record, hour) is not None:
                    skipped.add(hour)
                    continue
                try:
                    root, wr, salt, c_prev = _verify_hour(w, hour)
                except HourNotVerified:
                    skipped.add(hour)
                    failures["rows-altered"] = f"the rows of {fmt.hour_text(hour)} no longer give its seal; it was " \
                                               "not pruned"
                    continue
                found = w.db.query(A.id, A.timestamp).filter(
                    *conditions, A.timestamp >= hour, A.timestamp < hour + ai.HOUR).all()
                gone = [r[0] for r in found]
                if not gone:
                    skipped.add(hour)
                    continue
                _materialise(w, hour, salt, wr)
                times = [r[1] for r in found if r[1] is not None]
                w.db.query(A).filter(A.id.in_(gone)).delete(synchronize_session=False)
                w.db.flush()
                # The new roots are over the rows as they are now: an erase newer than the root seal is
                # then part of them, and the prune seal ends the erase entries (as a late seal does).
                fig = ai.hour_figures(ai.iter_rows(w.db, hour, hour + ai.HOUR), None)
                if wr is not None:
                    wr.row_ids = fig.ids
                entries.append([fmt.hour_text(hour), root.seq, fig.count, fig.bytes, fig.root_s.hex(),
                                fig.root_c.hex(), fig.ids_digest.hex()])
                batch.add(len(gone), min(times) if times else None, max(times) if times else None)
            if not entries:
                w.db.rollback()
                if all(h in skipped for h in hours):
                    continue
                break
            detail = {"reason": reason, "policy_seq": newest[0], "request_seq": None, "hours": entries}
            if size is not None:
                detail["size"] = size
            p.record(w.db, batch, A.__tablename__)
            w.append("prune", detail=detail)
        result.add(batch.deleted, batch.oldest, batch.newest)
    if failures:
        ai.report_failures(st, p.session_factory, failures)
    return result


def _prune_archived(p, st, engine, failures: Dict[str, str], *, reason: str, size: Optional[dict], plan,
                    archived: Optional[Callable], before: Optional[datetime]):
    """The archived rows the caller's conditions select, oldest day first, one day per transaction (see the
    module's docstring)."""
    from app.core import audit_archive as arc
    from app.core import retention
    ai = _ai()
    result = retention.JobResult()
    today = p.now.date()
    looked = st.archive_checked
    while p.time_left():
        batch = None
        with ai.ChainWriter(engine, st) as w:
            view = w.st.view
            newest = view.newest_policy()
            if newest is None or w.st.holds_deletion():
                break
            make, until, seal_size = archived, before, size
            if plan is not None:
                planned = plan(w)
                if planned is None:
                    break
                make, until, seal_size = planned.archived, planned.before, planned.size
            if make is None or until is None:
                break

            def due(d, e) -> bool:
                seen = looked.get((d, e.seq, reason))
                if seen is None or seen[0] != today:
                    return True
                return reason != "retention" and seen[1] < until
            days = [d for d in sorted(view.archives) if view.archives[d].parts and arc.day_start(d) < until
                    and due(d, view.archives[d])]
            if not days:
                break
            day = days[0]
            looked[(day, view.archives[day].seq, reason)] = (today, until)
            try:
                rw = arc.prune_day(w, day, make, p.now)
            except arc.NotVerified as nv:
                failures[nv.kind] = f"{nv}; nothing in {day.isoformat()} was deleted"
                rw = None
            except arc.NotArchivable as why:
                arc._say(f"The pruner leaves {day.isoformat()} as it is for now: {why}")
                rw = None
            if rw is None:
                w.db.rollback()
                continue
            batch = retention.JobResult()
            batch.add(rw.changed, rw.oldest, rw.newest)
            detail = {"reason": reason, "policy_seq": newest[0], "request_seq": None, "hours": rw.entries}
            if seal_size is not None:
                detail["size"] = seal_size
            p.record(w.db, batch, "audit_logs")
            change = w.append("prune", detail=detail)
            arc.seal_rewrite(w, day, change.seq, rw, p.now)
        if batch is not None:
            result.add(batch.deleted, batch.oldest, batch.newest)
    # Forget the looks at days no seal names any more.
    current = {(d, e.seq) for d, e in st.view.archives.items()}
    for key in [k for k in looked if (k[0], k[1]) not in current]:
        del looked[key]
    return result
