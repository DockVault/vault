"""The retention state in the audit chain: the seals every retention change writes, and what the pruner acts on.

Every input to the audit pruner is a seal, written in the transaction of the change it records:

- the first ``policy`` seal (cause ``genesis``) holds the state .env and the defaults give, and the raw .env
  inputs; when AUDIT_LOG_RETENTION_DAYS is positive at the first start, the maximum is held at "for ever" and
  the server's own ``request`` seal asks for the .env value, so it waits the delay like an administrator's;
- an .env change gives a ``policy`` seal of cause ``env`` before the pruner acts under it;
- an administrator's change that deletes later gives a ``policy`` seal of cause ``request``; one that deletes
  sooner a ``request`` seal, whose ``not_before`` is its own time plus the delay; a cancel a ``cancel`` seal;
- a due request is applied by the pruner with a ``policy`` seal of cause ``applies``, which writes the
  database's counterparts (the stored value, the change row marked applied) in the same transaction;
- a value in the database that keeps more than the chain is honoured and sealed as a veto (cause
  ``database``, at most once a day); one that deletes sooner is refused (``unjustified-input``).

So someone who can write to the database but holds no key cannot make the pruner delete sooner: the pruner
reads the state from seals this process authenticated (the verified view), and the database can only hold a
deletion back. Only .env sets the delay: no request, change or veto may name it.

While sealing is stopped, or before the first seal, a change that deletes sooner is refused with the reason;
one that deletes later, and a cancel, are saved, and the next pass seals them from the database.
"""
from __future__ import annotations

import uuid
from contextlib import contextmanager
from datetime import datetime, timedelta
from typing import Dict, Optional

from app.core import audit_chain_format as fmt
from app.core import audit_chain_policy as pol
from app.core import settings_registry as registry

SERVER_NAME = "the server (AUDIT_LOG_RETENTION_DAYS in .env)"


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _uuid_text(v) -> Optional[str]:
    return str(v) if v is not None else None


def _policy_detail(state: dict, inputs: dict, cause: str, *, by: str, request_seq=None, request=None,
                   audit_row=None, user_id=None) -> dict:
    return {"state": state, "inputs": inputs, "cause": cause, "request_seq": request_seq, "request": request,
            "audit_row": audit_row, "by": by, "user_id": user_id}


def _copy_state(state: dict) -> dict:
    return {name: dict(entry) for name, entry in (state or {}).items()}


def _set(state: dict, name: str, new_fields: dict, seq: int) -> bool:
    """Set ``name``'s fields; ``set_by`` becomes ``seq`` when any field changed. True when it changed."""
    entry = state.get(name) or {}
    changed = any(new_fields.get(f) != entry.get(f) for f in pol.FIELDS)
    if changed:
        state[name] = {**{f: new_fields.get(f) for f in pol.FIELDS}, "set_by": seq}
    return changed


# --------------------------------------------------------------------------- genesis, the first start and .env

def hold_first_retention(db, inputs: dict) -> Optional[int]:
    """The first start's AUDIT_LOG_RETENTION_DAYS that must wait as a request, or None."""
    from app.core import audit_retention
    from app.core.models import ManagedSetting, SystemSetting
    raw = inputs.get(pol.MAX_DAYS_INPUT)
    try:
        days = int(raw.strip()) if raw is not None else 0
    except ValueError:
        return None
    spec = registry.spec_for(pol.MAX_DAYS)
    if days <= 0 or registry.is_locked(spec):
        return None
    if db.get(SystemSetting, audit_retention.MARKER) is not None:
        # The once-only decision was already taken outside the chain: hold only what it left waiting.
        from app.core import setting_changes
        waiting = [c for c in setting_changes.pending_for(db, pol.MAX_DAYS) if c.requested_by is None]
        return days if waiting else None
    row = db.get(ManagedSetting, pol.MAX_DAYS)
    if row is not None and row.value is not None:
        return None
    return days


def write_genesis_policy(engine, st, now: datetime) -> None:
    """Seal 2 right after genesis, and, when the first start's AUDIT_LOG_RETENTION_DAYS is positive, the
    server's request for it as seal 3."""
    from app.core import setting_changes
    ai = _ai()
    notice = None
    with ai.ChainWriter(engine, st) as w:
        if w.st.view.position != 1 or w.st.view.newest_policy() is not None:
            return
        inputs = pol.raw_inputs()
        days = hold_first_retention(w.db, inputs)
        state = pol.genesis_state(inputs, 2, hold_max_days=days is not None)
        w.append("policy", detail=_policy_detail(state, inputs, "genesis", by="server"))
        if days is not None:
            notice = _write_first_retention_request(w, days, now, state)
    if notice is not None:
        registry.refresh()
        setting_changes.announce(setting_changes.SCHEDULED, notice)


def _write_first_retention_request(w, days: int, now: datetime, state: dict) -> None:
    from app.core import audit_retention, setting_changes
    from app.core.models import ManagedSettingChange as Change, SystemSetting
    db = w.db
    marker = db.get(SystemSetting, audit_retention.MARKER)
    waiting = [c for c in setting_changes.pending_for(db, pol.MAX_DAYS) if c.requested_by is None]
    if waiting:
        change = waiting[-1]
        audit_row = None
    else:
        registry.store(db, pol.MAX_DAYS, 0, by_name=SERVER_NAME, now=now)
        rows = []
        scheduled = setting_changes.schedule(db, pol.MAX_DAYS, days, by_name=SERVER_NAME, old_value=0, now=now,
                                             rows=rows)
        change = db.get(Change, uuid.UUID(scheduled["change_id"]))
        audit_row = str(rows[0].id)
    if marker is None:
        db.add(SystemSetting(key=audit_retention.MARKER, value={"at": fmt.time_text(now), "days": days,
                                                                "scheduled": True}))
    delay = timedelta(days=pol.delay_days(state))
    seal = w.append("request", detail=_setting_request(str(change.id), pol.MAX_DAYS, 0, days, delay, audit_row,
                                                       by="server", user_id=None))
    change.effective_at = fmt.parse_time_text(seal.detail["not_before"])
    if audit_row is None:
        return None          # the notice went out when the change was scheduled
    return {"key": pol.MAX_DAYS, "old": 0, "new": days, "setting": days, "change_id": str(change.id),
            "effective_at": change.effective_at.isoformat() + "Z", "requested_by": SERVER_NAME}


def _setting_request(change_id: str, setting: str, old, new, delay: timedelta, audit_row: Optional[str], *,
                     by: str, user_id: Optional[str]):
    """The detail of a setting's ``request`` seal, made once its time is known: ``not_before`` is the seal's
    own time plus the delay."""
    return lambda seq, sealed_at: {
        "what": "setting", "request": change_id, "setting": setting, "old": old, "new": new, "subject": None,
        "placeholder": None, "not_before": fmt.time_text(sealed_at + delay), "audit_row": audit_row, "by": by,
        "user_id": user_id}


def seal_env_change(engine, st, now: datetime) -> bool:
    """A ``policy`` seal of cause ``env`` when .env's inputs differ from the newest seal's. True when written."""
    ai = _ai()
    inputs = pol.raw_inputs()
    newest = st.view.newest_policy()
    if newest is None or (newest[1].get("inputs") or {}) == inputs:
        return False
    with ai.ChainWriter(engine, st) as w:
        newest = w.st.view.newest_policy()
        if newest is None or (newest[1].get("inputs") or {}) == inputs:
            return False
        seq = w.st.view.position + 1
        state = pol.env_state(newest[1].get("state") or {}, inputs, seq)
        w.append("policy", detail=_policy_detail(state, inputs, "env", by="server"))
    return True


# --------------------------------------------------------------------------- the honoured state

def honoured_state(view, record: Optional[dict]) -> dict:
    """The state the pruner acts on: the chain's newest state, with every entry that a seal another writer
    appended after the head record (and the host has not acknowledged) set to delete sooner taken from the
    replay without those seals, whichever keeps more."""
    chain = view.newest_state()
    foreign = set()
    for e in (record or {}).get("after_record") or []:
        if e.get("generation") == view.generation and not e.get("acknowledged") and not e.get("discarded"):
            foreign.add(int(e["seq"]))
    foreign -= set(view.acked)
    if not foreign:
        return _copy_state(chain)
    replay: dict = {}
    for seq, detail in view.policies:
        if seq in foreign:
            continue
        for name, entry in (detail.get("state") or {}).items():
            if detail.get("cause") == "genesis" or entry.get("set_by") == seq or name not in replay:
                replay[name] = dict(entry)
    specs = {s.key: s for s in pol.chain_specs()}
    out = _copy_state(chain)
    for name, entry in chain.items():
        other = replay.get(name)
        if other is None:
            continue
        spec = specs.get(name)
        if name == pol.DELAY_ENTRY:
            if int(other.get("value") or 0) > int(entry.get("value") or 0):
                out[name] = dict(other)
        elif spec is not None and pol.deletes_sooner(spec, other, entry):
            out[name] = dict(other)
    return out


def numbers(st=None) -> Optional[dict]:
    """The values the audit pruner acts on, from the honoured state, or None when the chain cannot give them
    (no chain yet, or sealing stopped): then nothing is deleted."""
    ai = _ai()
    st = st or ai.state()
    if st.stopped is not None or st.view.newest_policy() is None:
        return None
    record = st.head_store().memory
    state = honoured_state(st.view, record)
    out = {name: entry.get("value") for name, entry in state.items()}
    return out


# --------------------------------------------------------------------------- an administrator's change

@contextmanager
def change_transaction(engine, *, wait: float = 5.0):
    """A transaction for a retention change, holding the chain lock, whose seal commits with it. Raises
    ChainBusy after ``wait`` seconds, and ChainStopped when sealing is stopped or has not started."""
    ai = _ai()
    with ai.ChainWriter(engine, wait=wait, writer="admin") as w:
        if w.st.view.newest_policy() is None:
            raise ai.ChainStopped("not-started", "the audit chain has not started yet")
        yield w


def setting_fields(spec, setting, ns, inputs, request_seq: int) -> dict:
    """An entry's fields once ``setting`` is set by the seal or request ``request_seq``: the setting resolved
    under the state's bounds, or, for no setting (back to the deployment's value), the .env input or default."""
    if setting is None:
        fields = pol.input_entry(spec, ns, inputs)
    else:
        value, source = pol.resolve_setting(spec, setting, ns)
        fields = {"value": value, "source": source, "setting": setting}
    fields["request_seq"] = request_seq
    return fields


def _actor_fields(actor) -> dict:
    return {"by": "admin", "user_id": _uuid_text(getattr(actor, "id", None))}


def seal_request_outcome(w, outcome, actor) -> None:
    """The seals of what setting_changes.request() did, in its transaction: a ``policy`` seal of cause
    ``request`` for a change that deletes later, a ``request`` seal for one that deletes sooner, and a
    ``cancel`` seal for every pending change it superseded by keeping the value in force."""
    view = w.st.view
    spec = registry.spec_for(outcome.key)
    w.commit_without_seal = True
    if outcome.status == "kept":
        for change, row in zip(outcome.superseded, outcome.cancel_rows):
            req = request_seq_for(view, change.id)
            if req is not None and req in view.pending_requests():
                w.append("cancel", detail={"cancels": req, "request": str(change.id), "audit_row": str(row.id),
                                           **_actor_fields(actor)})
        return
    if outcome.status == "applied":
        newest = view.newest_policy()
        state = _copy_state(newest[1].get("state") or {})
        inputs = newest[1].get("inputs") or {}
        seq = view.position + 1
        ns = pol.settings_from_inputs(inputs)
        fields = setting_fields(spec, outcome.setting, ns, inputs, seq)
        if not _set(state, outcome.key, fields, seq):
            return
        w.append("policy", detail=_policy_detail(
            state, inputs, "request", request_seq=None, request=None,
            audit_row=_uuid_text(getattr(outcome.audit_row, "id", None)), **_actor_fields(actor)))
        return
    if outcome.status == "pending":
        change = outcome.change
        delay = timedelta(days=pol.delay_days(honoured_state(view, w.record)))
        old = pol.value_of(honoured_state(view, w.record), outcome.key)

        seal = w.append("request", detail=_setting_request(
            str(change.id), outcome.key, old, outcome.setting, delay,
            _uuid_text(getattr(outcome.audit_row, "id", None)), **_actor_fields(actor)))
        change.effective_at = fmt.parse_time_text(seal.detail["not_before"])


def seal_cancel(w, change, actor) -> None:
    view = w.st.view
    req = request_seq_for(view, change.id)
    w.commit_without_seal = True
    if req is None or req not in view.pending_requests():
        return
    row = getattr(change, "_audit_row", None)
    w.append("cancel", detail={"cancels": req, "request": str(change.id),
                               "audit_row": _uuid_text(getattr(row, "id", None)), **_actor_fields(actor)})


def request_seq_for(view, change_id) -> Optional[int]:
    wanted = str(change_id)
    for seq, d in view.requests.items():
        if d.get("request") == wanted:
            return seq
    return None


def refuses_while_stopped(db, key: str, requested) -> bool:
    """Whether a change must be refused because sealing is stopped: one that deletes sooner."""
    from app.core import setting_changes
    spec = registry.spec_for(key)
    if spec is None:
        return False
    _stored, old_setting, _old_value = setting_changes.in_force(db, spec)
    new_setting = requested if requested is not None else registry.deployment_value(spec)[0]
    return setting_changes.deletes_sooner(spec, old_setting, new_setting)


# --------------------------------------------------------------------------- applying due requests

def due_requests(view, now: datetime) -> list:
    """The pending setting requests whose delay has run, oldest first. A delay counts only time while sealing
    ran: every gap of more than 12 hours between seals after the request adds its length, and while a gap is
    open (no seal for 12 hours) nothing is due."""
    out = []
    if not view.sealed_at or now - view.sealed_at[-1] > pol.GAP:
        return out
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "setting":
            continue
        try:
            not_before = fmt.parse_time_text(d.get("not_before"))
        except (TypeError, ValueError):
            continue
        due = now >= not_before + pol.gaps_after(view.sealed_at, seq, now)
        if due and seq > _entry_request_seq(view, d.get("setting")):
            out.append(seq)
    return out


def _entry_request_seq(view, setting: str) -> int:
    entry = view.newest_state().get(setting) or {}
    return int(entry.get("request_seq") or 0)


def apply_due(engine, st, now: datetime) -> list:
    """Apply every due request, one per transaction: its ``policy`` seal of cause ``applies``, the stored value
    and the change row marked applied, with the audit row. A request whose change row the database no longer
    shows pending is ended with a ``cancel`` seal by the database. Returns (request seq, outcome) pairs."""
    from app.core import setting_changes
    from app.core.models import ManagedSettingChange as Change
    ai = _ai()
    done = []
    announcements = []
    for req in due_requests(st.view, now):
        with ai.ChainWriter(engine, st) as w:
            view = w.st.view
            d = view.requests.get(req)
            if d is None or req not in view.pending_requests() or req not in due_requests(view, now):
                continue
            db = w.db
            setting_changes._lock(db)
            try:
                change = db.get(Change, uuid.UUID(str(d.get("request"))))
            except ValueError:
                change = None
            if change is None or change.status != setting_changes.PENDING:
                w.append("cancel", detail={"cancels": req, "request": d.get("request"), "audit_row": None,
                                           "by": "database", "user_id": None})
                done.append((req, "cancelled-by-database"))
                continue
            spec = registry.spec_for(d["setting"])
            newest = view.newest_policy()
            state = _copy_state(newest[1].get("state") or {})
            inputs = newest[1].get("inputs") or {}
            ns = pol.settings_from_inputs(inputs)
            seq = view.position + 1
            fields = setting_fields(spec, d.get("new"), ns, inputs, req)
            value = fields["value"]
            state[d["setting"]] = {**fields, "set_by": seq}
            before = pol.value_of(honoured_state(view, w.record), d["setting"])
            registry.store(db, d["setting"], d.get("new"), by_id=change.requested_by,
                           by_name=change.requested_by_name, now=now)
            setting_changes._end(change, setting_changes.APPLIED, by_id=None, by_name=None, now=now, reason=None)
            details = {"key": change.key, "change_id": str(change.id), "old": before, "new": value,
                       "setting": change.setting, "requested_by": change.requested_by_name,
                       "requested_at": change.requested_at.isoformat() + "Z"}
            row = setting_changes._audit(db, setting_changes.APPLIED_ACTION, key=change.key, details=details)
            w.append("policy", detail=_policy_detail(state, inputs, "applies", request_seq=req,
                                                     request=str(change.id), audit_row=str(row.id), by="server"))
            done.append((req, "applied"))
            announcements.append(details)
    if announcements:
        registry.refresh()
        for details in announcements:
            setting_changes.announce(setting_changes.TOOK_EFFECT, details)
    return done


# --------------------------------------------------------------------------- the database's values (the backstop)

def backstop(engine, st, now: datetime, session_factory) -> Dict[str, str]:
    """Compare what the database holds with the chain. A stored value that keeps more is honoured and sealed
    as a veto (cause ``database``, at most one such seal a day, which supersedes a pending reduction of that
    setting); one that deletes sooner is refused: ``unjustified-input``. A pending change row with no request
    seal is ignored, and so is a cancelled one whose request is still pending (it is sealed as a cancel by the
    database). Returns the findings."""
    from app.core import setting_changes
    from app.core.models import ManagedSetting, ManagedSettingChange as Change
    ai = _ai()
    findings: Dict[str, str] = {}
    view = st.view
    newest = view.newest_policy()
    if newest is None:
        return findings
    db = session_factory()
    try:
        stored = {row.key: row.value for row in db.query(ManagedSetting).all()}
        pending_rows = {str(c.id): c.status for c in db.query(Change).all()}
    finally:
        db.close()
    state = newest[1].get("state") or {}
    inputs = newest[1].get("inputs") or {}
    ns = pol.settings_from_inputs(inputs)
    vetoes = {}
    for spec in pol.chain_specs():
        entry = state.get(spec.key) or {}
        value = stored.get(spec.key)
        if value is None or registry.check_value(spec, value) is not None or registry.is_locked(spec):
            continue
        resolved, source = pol.resolve_setting(spec, value, ns)
        candidate = {"value": resolved, "source": source, "setting": value}
        if all(candidate.get(f) == entry.get(f) for f in ("value", "setting")):
            continue
        if pol.deletes_sooner(spec, entry, candidate):
            findings["unjustified-input"] = (f"managed_settings holds {spec.key} = {value}, which deletes sooner "
                                             "than the chain allows; it is not acted on")
            continue
        if not pol.deletes_sooner(spec, candidate, entry):
            continue     # the chain's value keeps as much: nothing to hold back
        vetoes[spec.key] = candidate
    for seq, d in view.pending_requests().items():
        if d.get("what") == "setting":
            status = pending_rows.get(d.get("request"))
            if status is None or status in (setting_changes.CANCELLED, setting_changes.SUPERSEDED):
                vetoes.setdefault(("cancel", seq), d)
    for change_id, status_ in pending_rows.items():
        if status_ == setting_changes.PENDING and request_seq_for(view, change_id) is None:
            findings["unjustified-input"] = "a waiting change in the database has no request seal; it is ignored"
    if vetoes and _veto_allowed_today(view, now):
        with ai.ChainWriter(engine, st) as w:
            view = w.st.view
            for key, item in list(vetoes.items()):
                if isinstance(key, tuple):
                    req = key[1]
                    if req in view.pending_requests():
                        w.append("cancel", detail={"cancels": req, "request": item.get("request"), "audit_row": None,
                                                   "by": "database", "user_id": None})
                    del vetoes[key]
            if vetoes:
                newest = view.newest_policy()
                state = _copy_state(newest[1].get("state") or {})
                seq = view.position + len(w.written) + 1
                for key, candidate in vetoes.items():
                    _set(state, key, {**candidate, "request_seq": seq}, seq)
                w.append("policy", detail=_policy_detail(state, newest[1].get("inputs") or {}, "database",
                                                         by="database"))
        findings.setdefault("veto-from-database", "a value in the database that keeps more was sealed as a veto")
    return findings


def _veto_allowed_today(view, now: datetime) -> bool:
    day = now.date()
    for seq, d in view.policies:
        if d.get("cause") == "database" and view.sealed_at[seq - 1].date() == day:
            return False
    return True
