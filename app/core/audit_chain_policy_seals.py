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
    # Only the head record's list says the host acknowledged a seal: an acknowledgment in another writer's own
    # ``ack`` seal counts for nothing.
    foreign = _ai().unacknowledged_foreign(view, record)
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
    record = st.known_record()
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


class Judge:
    """An administrator's change of a chain setting, judged against the verified view under the chain lock: the
    honoured entry (what the pruner acts on) and the chain's (the newest policy seal's). The database's stored
    value decides nothing here: someone who can write to the database but holds no key could have set it, and
    an honest raise from that value would then be a reduction applied at once."""

    def __init__(self, view, record, key: str):
        newest = view.newest_policy()
        self.spec = registry.spec_for(key)
        self.inputs = newest[1].get("inputs") or {}
        self.ns = pol.settings_from_inputs(self.inputs)
        self.chain = dict((newest[1].get("state") or {}).get(key) or {})
        self.honoured = dict(honoured_state(view, record).get(key) or {})

    def entry(self, requested) -> dict:
        """The entry ``requested`` gives (None: back to the deployment's value), under the chain's bounds."""
        return setting_fields(self.spec, requested, self.ns, self.inputs, None)

    def in_force(self) -> tuple:
        """(stored, setting, value) as setting_changes.in_force() gives them, from the honoured entry."""
        h = self.honoured
        stored = h.get("setting") if h.get("source") not in ("env", "default") else None
        return stored, (stored if stored is not None else h.get("value")), h.get("value")

    def deletes_sooner(self, requested) -> bool:
        """Whether the change deletes sooner than the honoured entry or the chain's: then it is a request."""
        new = self.entry(requested)
        return pol.deletes_sooner(self.spec, self.honoured, new) or pol.deletes_sooner(self.spec, self.chain, new)

    def alters_chain(self, requested) -> bool:
        """Whether the change sets a field of the chain's entry (the honoured setting given again after another
        writer's seal made the chain's lower does)."""
        new = self.entry(requested)
        return any(new.get(f) != self.chain.get(f) for f in ("value", "source", "setting"))


def judge(view, record, key: str) -> Optional[Judge]:
    """The judge of a change of ``key``, or None for a setting the chain does not record (or no chain yet)."""
    if key not in pol.chain_setting_keys() or view.newest_policy() is None:
        return None
    return Judge(view, record, key)


def change(w, key: str, requested, actor, *, now: Optional[datetime] = None):
    """An administrator's change of ``key`` in the chain writer ``w``'s transaction: its direction decided
    against the chain (Judge), the database's rows and audit row (setting_changes.request), and its seals."""
    from app.core import setting_changes
    outcome = setting_changes.request(w.db, key, requested, actor=actor, now=now,
                                      judge=judge(w.st.view, w.record, key))
    seal_request_outcome(w, outcome, actor)
    return outcome


def honoured_entries(st=None) -> dict:
    """The honoured state's entries, for the panel (the values the pruner acts on), or {} before the chain's
    first policy seal."""
    ai = _ai()
    st = st or ai.state()
    if st.view.newest_policy() is None:
        return {}
    return honoured_state(st.view, st.known_record())


def seal_request_outcome(w, outcome, actor) -> None:
    """The seals of what setting_changes.request() did, in its transaction: a ``policy`` seal of cause
    ``request`` for a change that deletes later, a ``request`` seal for one that deletes sooner, and a
    ``cancel`` seal for every pending change it superseded by keeping the value in force."""
    view = w.st.view
    spec = registry.spec_for(outcome.key)
    w.commit_without_seal = True
    if outcome.key not in pol.chain_setting_keys():
        return                # a setting the chain does not record: no seal
    if outcome.status == "kept":
        _cancel_superseded(w, outcome.superseded, outcome.cancel_rows, actor)
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


def _cancel_superseded(w, superseded, rows, actor) -> None:
    """A cancel seal for each change ``superseded`` whose request seal is still pending, naming its audit row."""
    view = w.st.view
    for change, row in zip(superseded, rows):
        req = request_seq_for(view, change.id)
        if req is not None and req in view.pending_requests():
            w.append("cancel", detail={"cancels": req, "request": str(change.id),
                                       "audit_row": _uuid_text(getattr(row, "id", None)), **_actor_fields(actor)})


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


def judge_now(key: str, st=None) -> Optional[Judge]:
    """The judge of a change of ``key`` from this process's view as it stands, without the chain lock: for a
    change made while sealing is stopped, which writes no seal."""
    st = st or _ai().state()
    return judge(st.view, st.known_record(), key)


def refuses_while_stopped(db, key: str, requested, st=None) -> bool:
    """Whether a change must be refused because sealing is stopped: one that deletes sooner than what the chain
    last gave (the database's value before the chain's first policy seal)."""
    from app.core import setting_changes
    spec = registry.spec_for(key)
    if spec is None:
        return False
    j = judge_now(key, st)
    if j is not None:
        return j.deletes_sooner(requested)
    _stored, old_setting, _old_value = setting_changes.in_force(db, spec)
    new_setting = requested if requested is not None else registry.deployment_value(spec)[0]
    return setting_changes.deletes_sooner(spec, old_setting, new_setting)


# --------------------------------------------------------------------------- applying due requests

def due_requests(view, now: datetime, record: Optional[dict] = None) -> list:
    """The pending setting requests whose delay has run, oldest first. A delay counts only time while sealing
    ran: every gap of more than 12 hours between seals after the request adds its length, and while a gap is
    open (no seal for 12 hours) nothing is due. A request another writer appended after the head record is due
    only once the host has acknowledged it, and a delay after the server first accepted it (the honoured
    delay, plus every gap after that): its own ``sealed_at`` and ``not_before`` are whoever appended it."""
    out = []
    if not view.sealed_at or now - view.sealed_at[-1] > pol.GAP:
        return out
    foreign = _ai().foreign_entries(view, record)
    delay = None
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "setting":
            continue
        try:
            not_before = fmt.parse_time_text(d.get("not_before"))
        except (TypeError, ValueError):
            continue
        if now < not_before + pol.gaps_after(view.sealed_at, seq, now):
            continue
        entry = foreign.get(seq)
        if entry is not None:
            if not entry.get("acknowledged"):
                continue
            if delay is None:
                delay = timedelta(days=pol.delay_days(honoured_state(view, record)))
            accepted = fmt.parse_time_text(entry["accepted_at"])
            if now < accepted + delay + pol.gaps_since(view.sealed_at, accepted, now):
                continue
        out.append(seq)
    return out


def apply_due(engine, st, now: datetime) -> list:
    """Apply every due request, one per transaction: its ``policy`` seal of cause ``applies``, the stored value
    and the change row marked applied, with the audit row. A request whose change row the database no longer
    shows pending is ended with a ``cancel`` seal by the database. Returns (request seq, outcome) pairs."""
    from app.core import setting_changes
    from app.core.models import ManagedSettingChange as Change
    ai = _ai()
    done = []
    announcements = []
    for req in due_requests(st.view, now, st.known_record()):
        with ai.ChainWriter(engine, st) as w:
            view = w.st.view
            d = view.requests.get(req)
            if d is None or req not in view.pending_requests() or req not in due_requests(view, now, w.record):
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
    setting); one that deletes sooner is refused: ``unjustified-input``. No stored value (no row, a NULL, or a
    value the registry cannot use) stands for the deployment's value and is judged the same way, so removing an
    administrator's value is refused when the deployment's deletes sooner. A pending change row with no request
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
        if registry.is_locked(spec):
            continue
        value = stored.get(spec.key)
        if value is not None and registry.check_value(spec, value) is not None:
            value = None          # the settings registry reads no valid value there either
        if value is None:
            # No value stored, or none it can use: what reads the database gets the deployment's value, the
            # entry with no setting. Removing an administrator's value can delete sooner like any other.
            candidate = pol.input_entry(spec, ns, inputs)
            shown = f"no value for {spec.key} (the deployment's {candidate['value']} applies)"
        else:
            resolved, source = pol.resolve_setting(spec, value, ns)
            candidate = {"value": resolved, "source": source, "setting": value}
            shown = f"{spec.key} = {value}"
        if all(candidate.get(f) == entry.get(f) for f in ("value", "setting")):
            continue
        if pol.deletes_sooner(spec, entry, candidate):
            findings["unjustified-input"] = (f"managed_settings holds {shown}, which deletes sooner than the chain "
                                             "allows; it is not acted on")
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
        # One seal per transaction (a crash between a commit and the head record's write then leaves at most
        # one seal unrecorded): each cancel, then the veto of the values.
        for key, item in sorted((k, v) for k, v in vetoes.items() if isinstance(k, tuple)):
            with ai.ChainWriter(engine, st) as w:
                if key[1] in w.st.view.pending_requests():
                    w.append("cancel", detail={"cancels": key[1], "request": item.get("request"), "audit_row": None,
                                               "by": "database", "user_id": None})
            del vetoes[key]
        if vetoes:
            with ai.ChainWriter(engine, st) as w:
                newest = w.st.view.newest_policy()
                state = _copy_state(newest[1].get("state") or {})
                seq = w.st.view.position + 1
                for key, candidate in vetoes.items():
                    _set(state, key, {**candidate, "request_seq": seq}, seq)
                w.append("policy", detail=_policy_detail(state, newest[1].get("inputs") or {}, "database",
                                                         by="database"))
    # Each seal written here is a warning until the host acknowledges it (audit_integrity.database_seqs).
    return findings


def _veto_allowed_today(view, now: datetime) -> bool:
    day = now.date()
    for seq, d in view.policies:
        if d.get("cause") == "database" and view.sealed_at[seq - 1].date() == day:
            return False
    return True
