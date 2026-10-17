"""Verifying the audit log's integrity chain, on the server and off it.

``python -m app.core.audit_integrity verify`` (run by ``dockvault.py audit verify`` in the web container)
prints every finding and the head to keep elsewhere. Exit codes: 0 clean (information only), 1 failures or
warnings, 2 cannot run.

The algorithm, in order:

1. the head record (on the server): the database must hold the recorded head; seals after it are sorted
   (a kind only the host writes, one that fails the checks below, or another writer's, which is a warning
   until the host acknowledges it);
2. the seals: seq runs from 1 with no gap, seal 1 is genesis and no other is, sealed_at never steps back more
   than five minutes, every link is recomputed from the bodies (a stored link that differs is link-broken),
   the key sequence holds, and each MAC verifies under its key wherever the verifier holds it;
3. coverage: the hour seals tile time from the chain's first hour, and once the first start's backlog is
   sealed its hours hold the rows genesis counted;
4. justification, from the chain alone: every policy seal has a cause that holds against the one before it
   and sets only what its cause may set (only .env sets the delay), every request names a setting the
   panel manages and waits at least the delay in force, every cancel names a pending request, every late
   seal follows its hour's root seal within 6 hours, every rewrite keeps the stable root, every archive seal
   lists whole-hour parts of its day that do not overlap, says complete exactly when they cover the day, adds
   parts only after the day's earlier ones, and changes them only right after a change of that day;
5-7. per hour: the rows (or an erase's earlier commitments) rebuilt into both roots and compared with the
   hour's newest root seal, naming missing and added rows by id; an archived hour's rows come from the block
   of its day that holds it, read only once its length and digest are the ones the day's latest archive seal
   binds (block-altered, block-missing, block-unsealed), and a row of audit_logs in an archived hour is
   row-in-archived-day; a block of a later release's block format is a warning (block-later-format), which this
   release neither checks nor changes;
8. outside the chain: rows naming an account that is not theirs, account rows unlinked from an account that
   still exists, rows before the chain's first hour or dated ahead, undated rows, and hooks on the tables.

With ``--anchor dvchain1:...`` and no key, the links up to the anchor authenticate every seal up to it; a later
late, prune, rewrite or erase seal that changes an hour the anchor covered, or archive seal that rebinds a day
holding such an hour, is reported as not authenticated (a warning), whoever it says wrote it, and an anchor whose
seal a restore lost is reported against that restore seal.

Information, for good: what each prune, rewrite, erase, acknowledgment and restore did, the hours a restore
sealed again and the ones it found changed, a restore that accepted history under a key the chain had left,
and each gap of more than 12 hours in the seals' times with the requests it pushed back.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import date, datetime, timedelta
from typing import Dict, List, Optional

from sqlalchemy import func, text

from app.core import audit_chain_format as fmt
from app.core import audit_chain_policy as pol

FAILURE, WARNING, INFO = "failure", "warning", "information"
PLACEHOLDER = re.compile(r"^erased-[0-9a-f]{8}$")


@dataclass
class Finding:
    severity: str
    kind: str
    message: str
    seq: Optional[int] = None
    hour: Optional[str] = None

    def as_dict(self) -> dict:
        return {k: v for k, v in self.__dict__.items() if v is not None}


@dataclass
class Report:
    findings: List[Finding] = field(default_factory=list)
    head: Optional[str] = None
    head_at: Optional[str] = None
    key_id: Optional[str] = None
    seals: int = 0
    hours_checked: int = 0
    rows_checked: int = 0
    # The view the check built from the seals it read: what a later step over the same snapshot reads by.
    view: Optional[object] = field(default=None, repr=False, compare=False)

    def add(self, severity, kind, message, seq=None, hour=None) -> None:
        self.findings.append(Finding(severity, kind, message, seq, hour))

    def kinds(self, severity: Optional[str] = None) -> List[str]:
        return sorted({f.kind for f in self.findings if severity is None or f.severity == severity})

    @property
    def exit_code(self) -> int:
        return 1 if any(f.severity in (FAILURE, WARNING) for f in self.findings) else 0


def _ai():
    from app.core import audit_integrity
    return audit_integrity


# --------------------------------------------------------------------------- step 4, one seal at a time

def _state_ok(state) -> bool:
    return isinstance(state, dict) and all(isinstance(v, dict) for v in state.values())


def _set_entries(prev: dict, state: dict) -> set:
    return {name for name in set(prev) | set(state)
            if any((prev.get(name) or {}).get(f) != (state.get(name) or {}).get(f) for f in pol.FIELDS)}


def _holds_together(state: dict, inputs: dict) -> Optional[str]:
    """Every entry of a state agrees with its own bounds. The delay's entry is not looked at here: a genesis
    or env seal's state must equal exactly what its inputs give, and any other seal may not set the delay at
    all, so the delay always holds .env's value (source env or default, no setting, no request)."""
    ns = pol.settings_from_inputs(inputs)
    specs = {s.key: s for s in pol.chain_specs()}
    for name, entry in state.items():
        if name == pol.DELAY_ENTRY:
            continue
        spec = specs.get(name)
        if spec is None:
            return f"{name} is not a setting the chain records"
        source = entry.get("source")
        if source not in pol.SOURCES:
            return f"{name} has an unknown source"
        if source in ("env", "default"):
            if entry.get("setting") is not None:
                return f"{name} has a setting and a source of {source}"
            want = pol.input_entry(spec, ns, inputs)
            if (entry.get("value"), source) != (want["value"], want["source"]):
                return f"{name} does not hold its .env input resolved under its bounds"
        else:
            value, how = pol.resolve_setting(spec, entry.get("setting"), ns)
            if entry.get("value") != value:
                return f"{name} does not hold its setting resolved under its bounds"
            if source == "held":
                if entry.get("setting") != 0 or how != "setting":
                    return f"{name} is held with a setting other than for ever"
            elif source != how:
                return f"{name}'s source is {source}, but its bounds make it {how}"
    return None


def grace_problem(view, seal) -> Optional[str]:
    """Why a seal that applies a request, erases or prunes was sealed inside the grace after a restore (a
    restore seal's grace_until, or a genesis that replaced a lost chain, each plus every gap after it), or
    None. Judged by the chain's own times, as a check off the server sees them."""
    from app.core import audit_chain_honour as honour
    from app.core import audit_chain_times as times
    terms = honour.grace_terms(view)
    if not terms:
        return None
    tl = times.Timeline(view.times, view.gap_ends)
    at = times.us(seal.sealed_at)
    for seq, until in terms:
        if at < until + tl.after(seq, at):
            return f"sealed inside the grace after seal {seq} (a restore), which ends at {fmt.time_text(times.dt(until))}"
    return None


def policy_problem(view, seal) -> Optional[str]:
    """Why a policy seal is not justified against the policy seal before it, or None (step 4 above)."""
    d = seal.detail if isinstance(seal.detail, dict) else {}
    cause, state, inputs = d.get("cause"), d.get("state"), d.get("inputs")
    if cause not in pol.CAUSES or not _state_ok(state) or not isinstance(inputs, dict):
        return "a policy seal that is not well formed"
    for name, entry in state.items():
        if entry.get("set_by") is None:
            return f"{name} names no seal that set it"
    prev = view.newest_policy()
    seq = seal.seq
    if cause == "genesis":
        if seq != 2 or prev is not None:
            return "a genesis policy seal that is not seal 2"
        if pol.contract_problems(inputs):
            return "its .env inputs are ones the server refuses to start with"
        plain = pol.genesis_state(inputs, 2, hold_max_days=False)
        held = pol.genesis_state(inputs, 2, hold_max_days=True)
        try:
            positive = int((inputs.get(pol.MAX_DAYS_INPUT) or "0").strip()) > 0
        except ValueError:
            positive = False
        if state != plain and not (positive and state == held):
            return "its state is not the one its .env inputs and the defaults give"
        return None
    if prev is None:
        return "a policy seal before the first one"
    prev_state = prev[1].get("state") or {}
    prev_inputs = prev[1].get("inputs") or {}
    if set(state) != set(prev_state):
        return "its entries are not the previous seal's"
    changed = _set_entries(prev_state, state)
    for name in set(state):
        entry, before = state[name], prev_state.get(name) or {}
        if name in changed:
            if entry.get("set_by") != seq:
                return f"{name} is set but does not name this seal"
        elif entry != before:
            return f"{name} is not copied from the previous seal"
    if cause == "env":
        if inputs == prev_inputs:
            return "an env seal whose inputs are the previous seal's"
        if pol.contract_problems(inputs):
            return "its .env inputs are ones the server refuses to start with"
        want = pol.env_state(prev_state, inputs, seq)
        if state != want:
            return "an env seal that changes more than .env's inputs give"
        return _holds_together(state, inputs)
    if inputs != prev_inputs:
        return "a seal other than genesis or env that changes the inputs"
    # Only .env sets the delay, and only the chain's settings may be named.
    names = set(pol.chain_setting_keys())
    for name in changed:
        if name not in names:
            return f"a {cause} seal may not set {name}"
    problem = _holds_together(state, inputs)
    if problem:
        return problem
    specs = {s.key: s for s in pol.chain_specs()}
    if cause in ("request", "database", "restore"):
        if cause == "restore":
            if not view.restores or view.restores[-1][0] != seq - 1:
                return "a restore policy seal that does not follow a restore seal"
        if not changed:
            return f"a {cause} seal that sets nothing"
        for name in changed:
            if pol.deletes_sooner(specs[name], prev_state[name], state[name]):
                return f"a {cause} seal that deletes sooner in {name}"
            if state[name].get("request_seq") != seq:
                return f"{name}'s request_seq is not this seal"
        if cause == "database":
            day = seal.sealed_at.date()
            for pseq, pd in view.policies:
                if pd.get("cause") == "database" and view.at(pseq).date() == day:
                    return "a second database seal in one day"
        return None
    if cause == "applies":
        req = d.get("request_seq")
        asked = view.requests.get(req) if isinstance(req, int) else None
        if asked is None or asked.get("what") != "setting":
            return "an applies seal that names no setting request"
        name = asked.get("setting")
        if changed - {name}:
            return "an applies seal that sets more than its request's setting"
        # A cancelled or applied request is not pending, and neither is one a newer request or change of the
        # setting superseded: so an applies never replays a request older than the setting's last change.
        if req not in view.pending_requests():
            return "an applies seal for a request that is not pending"
        try:
            not_before = fmt.parse_time_text(asked.get("not_before"))
        except (TypeError, ValueError):
            return "its request has no not_before"
        if seal.sealed_at < not_before + pol.gaps_after(view.times, req, seal.sealed_at):
            return "an applies seal before its request's delay has run"
        grace = grace_problem(view, seal)
        if grace:
            return f"an applies seal {grace}"
        ns = pol.settings_from_inputs(inputs)
        from app.core.audit_chain_policy_seals import setting_fields
        want = {**setting_fields(specs[name], asked.get("new"), ns, inputs, req), "set_by": seq}
        if state.get(name) != want:
            return "an applies seal that does not set its request's value"
        return None
    return None


def request_problem(view, seal) -> Optional[str]:
    d = seal.detail if isinstance(seal.detail, dict) else {}
    what = d.get("what")
    if what not in ("setting", "erase", "removal"):
        return "a request that is not well formed"
    prev = view.newest_policy()
    if prev is None:
        return "a request before the first policy seal"
    delay = timedelta(days=pol.delay_days(prev[1].get("state") or {}))
    try:
        not_before = fmt.parse_time_text(d.get("not_before"))
    except (TypeError, ValueError):
        return "a request with no not_before"
    if not_before < seal.sealed_at + delay:
        return "a request whose not_before is short of the delay in force"
    if what == "setting":
        if d.get("setting") not in pol.chain_setting_keys():
            return f"a request for {d.get('setting')!r}, which is not a setting the panel manages"
        if d.get("subject") is not None or d.get("placeholder") is not None:
            return "a setting request with an erase's fields"
    if what == "erase":
        ph = d.get("placeholder")
        if not isinstance(ph, str) or not PLACEHOLDER.match(ph) or not d.get("subject"):
            return "an erase request without its subject and placeholder"
        if any(d.get(f) is not None for f in ("setting", "old", "new")):
            return "an erase request naming a setting or a value"
        for other in view.requests.values():
            if other.get("placeholder") == ph:
                return "an erase request sharing another's placeholder"
    if d.get("by") == "server":
        state = prev[1].get("state") or {}
        inputs = prev[1].get("inputs") or {}
        if seal.seq != 3 or prev[0] != 2 or (state.get(pol.MAX_DAYS) or {}).get("source") not in ("held", "clamped") \
                or d.get("setting") != pol.MAX_DAYS or str(d.get("new")) != (inputs.get(pol.MAX_DAYS_INPUT) or "").strip():
            return "a request by the server other than the first start's"
    elif d.get("by") != "admin":
        return "a request by neither an administrator nor the server"
    return None


def _not_a_share(value, nbytes) -> bool:
    try:
        most = int(nbytes)
    except (TypeError, ValueError):
        return True
    return isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= most


def protected_problem(seal) -> Optional[str]:
    """Each hour an hour, late, prune or rewrite seal sets binds its protected bytes (the stored bytes of its rows
    of the actions the size cap never deletes), a whole number from 0 to the hour's bytes. It is a bound, never
    compared with the rows: which actions are protected can change between releases, and a figure below the rows'
    only makes the cap keep more."""
    d = seal.detail if isinstance(seal.detail, dict) else {}
    if seal.kind in ("hour", "late"):
        if _not_a_share(d.get("protected_bytes"), seal.row_bytes):
            return f"a {seal.kind} seal whose protected bytes are not a figure from 0 to its bytes"
    elif seal.kind in ("prune", "rewrite"):
        for h in d.get("hours") or []:
            if not isinstance(h, list) or len(h) != 8 or _not_a_share(h[7], h[3]):
                return f"a {seal.kind} seal whose hour has no protected bytes from 0 to its bytes"
    return None


def other_problem(view, seal, record: Optional[dict] = None) -> Optional[str]:
    """Step 4 for the kinds other than policy and request. ``record``: the head record, on the server."""
    d = seal.detail if isinstance(seal.detail, dict) else {}
    problem = protected_problem(seal)
    if problem:
        return problem
    if seal.kind == "cancel":
        if d.get("cancels") not in view.pending_requests():
            return "a cancel of a request that is not pending"
    elif seal.kind == "late":
        try:
            hour = fmt.parse_time_text(d.get("hour"))
        except (TypeError, ValueError):
            return "a late seal with no hour"
        entry = view.entry_for(hour)
        if entry is None:
            return "a late seal for an hour not sealed"
        prev = entry.root
        if d.get("prev_seq") != prev.seq:
            return "a late seal that does not follow its hour's root seal"
        if d.get("by") != "host" and seal.sealed_at - prev.sealed_at > _ai().LATE_WINDOW:
            return "a late seal more than 6 hours after its hour's seal"
    elif seal.kind in ("prune", "rewrite"):
        hours = d.get("hours")
        if not isinstance(hours, list) or not hours:
            return f"a {seal.kind} seal with no hours"
        days = set()
        for h in hours:
            try:
                hour = fmt.parse_time_text(h[0])
            except (TypeError, ValueError, IndexError):
                return f"a {seal.kind} seal with a bad hour"
            days.add(hour.date())
            entry = view.entry_for(hour)
            if entry is None:
                return f"a {seal.kind} of an hour not sealed"
            prev = entry.root
            if h[1] != prev.seq:
                return f"a {seal.kind} seal whose hour does not follow its root seal"
            if seal.kind == "rewrite" and (bytes.fromhex(h[4]) != prev.root_s or bytes.fromhex(h[6]) != prev.ids_digest):
                return "stable-changed"
        if len(days) > 1:
            return f"a {seal.kind} seal over more than one day"
        if d.get("reason") != "external":
            grace = grace_problem(view, seal)
            if grace:
                return f"a {seal.kind} seal {grace}"
            p = d.get("policy_seq")
            newest = view.newest_policy()
            if newest is None or p != newest[0]:
                return f"a {seal.kind} seal that does not name the policy seal in force"
            if seal.kind == "prune" and d.get("reason") == "size-cap":
                from app.core import audit_chain_size
                problem = audit_chain_size.size_problem(view, seal, record=record)
                if problem:
                    return problem
    elif seal.kind == "erase":
        req = view.requests.get(d.get("request_seq"))
        if req is None or req.get("what") != "erase" or req.get("placeholder") != d.get("placeholder"):
            return "an erase seal whose request or placeholder is not its own"
        # A cancelled request, or one a final erase seal completed, is not pending.
        req_seq = d.get("request_seq")
        if req_seq not in view.pending_requests():
            return "an erase seal for a request that is not pending"
        newest = view.newest_policy()
        if newest is None or d.get("policy_seq") != newest[0]:
            return "an erase seal that does not name the policy seal in force"
        try:
            not_before = fmt.parse_time_text(req.get("not_before"))
        except (TypeError, ValueError):
            return "an erase seal whose request has no not_before"
        first = view.erase_through.get(req_seq)
        if first is None and seal.sealed_at < not_before + pol.gaps_after(view.times, req_seq, seal.sealed_at):
            return "an erase before its request's delay has run"
        grace = grace_problem(view, seal)
        if grace:
            return f"an erase seal {grace}"
        if first is not None and d.get("through") != first:
            return "an erase seal whose scope is not its run's"
        if d.get("hour"):
            try:
                if fmt.parse_time_text(d["hour"]) > fmt.parse_time_text(d.get("through")):
                    return "an erase seal for an hour after its run's scope"
            except (TypeError, ValueError):
                return "an erase seal with a bad hour or scope"
        for row in d.get("rows") or []:
            if row and row[0] in view.erased_rows:
                return "a row erased twice"
    elif seal.kind == "archive":
        from app.core import audit_archive
        return audit_archive.archive_problem(view, seal)
    elif seal.kind == "key":
        pass
    return None


def justification_problem(view, seal, record: Optional[dict] = None) -> Optional[str]:
    if seal.kind == "policy":
        return policy_problem(view, seal)
    if seal.kind == "request":
        return request_problem(view, seal)
    return other_problem(view, seal, record)


# --------------------------------------------------------------------------- hooks on the audit tables

def db_hooks(db) -> List[str]:
    """What is wrong with the audit tables as the database resolves and guards them (Postgres only)."""
    bind = db.get_bind()
    if bind is None or bind.dialect.name != "postgresql":
        return []
    found = []
    for table in ("audit_logs", "audit_seals"):
        row = db.execute(text(
            "SELECT c.oid, n.nspname, c.relkind, c.relrowsecurity FROM pg_class c "
            "JOIN pg_namespace n ON n.oid = c.relnamespace WHERE c.oid = to_regclass(:t)"), {"t": table}).first()
        if row is None:
            found.append(f"{table} does not resolve to a table")
            continue
        oid, schema, kind, rls = row
        if schema != "public" or kind != "r":
            found.append(f"{table} resolves to {schema}.{table} of kind {kind}, not the app's table")
        if rls:
            found.append(f"{table} has row security on")
        for tg in db.execute(text(
                "SELECT t.tgname, p.proname, pn.nspname, l.lanname, p.prosrc, con.contype, con.conrelid, "
                "con.confrelid FROM pg_trigger t JOIN pg_proc p ON p.oid = t.tgfoid "
                "JOIN pg_namespace pn ON pn.oid = p.pronamespace JOIN pg_language l ON l.oid = p.prolang "
                "LEFT JOIN pg_constraint con ON con.oid = t.tgconstraint WHERE t.tgrelid = :oid"), {"oid": oid}):
            name, proname, pschema, lang, src, contype, conrel, confrel = tg
            if not (contype == "f" and oid in (conrel, confrel) and pschema == "pg_catalog"
                    and proname.startswith("RI_FKey_") and lang == "internal" and src == proname):
                found.append(f"{table} has a trigger {name} that is not a foreign-key check")
        rules = db.execute(text("SELECT count(*) FROM pg_rewrite WHERE ev_class = :oid"), {"oid": oid}).scalar()
        if rules:
            found.append(f"{table} has {rules} rewrite rules")
        policies = db.execute(text("SELECT count(*) FROM pg_policy WHERE polrelid = :oid"), {"oid": oid}).scalar()
        if policies:
            found.append(f"{table} has {policies} row-security policies")
        inherits = db.execute(text("SELECT count(*) FROM pg_inherits WHERE inhrelid = :oid OR inhparent = :oid"),
                              {"oid": oid}).scalar()
        if inherits:
            found.append(f"{table} has a parent or a child table")
    settings = db.execute(text(
        "SELECT unnest(setconfig) FROM pg_db_role_setting WHERE "
        "(setrole = 0 OR setrole = (SELECT oid FROM pg_roles WHERE rolname = current_user)) AND "
        "(setdatabase = 0 OR setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database()))")).all()
    for (cfg,) in settings:
        if str(cfg).lower().startswith("search_path="):
            found.append("a search_path is set for the app's role or database")
    for name in ("shared_preload_libraries", "session_preload_libraries", "local_preload_libraries"):
        value = db.execute(text(f"SELECT current_setting('{name}')")).scalar()
        if (value or "").strip():
            found.append(f"{name} loads {value}")
    return found


# --------------------------------------------------------------------------- the whole check

def _record_after(record, generation) -> Dict[int, dict]:
    return {int(e["seq"]): e for e in (record or {}).get("after_record") or []
            if e.get("generation") == generation and not e.get("discarded")}


# In a session's info, the transaction whose snapshot one_state_and_record took: the check then reads by it.
SNAPSHOT_TAKEN = "audit_chain_one_state"


def one_state(db) -> None:
    """Make every read of ``db``'s transaction from here on see the database as it was at the first: the seals,
    the blocks and the rows of one state, whatever another process commits meanwhile (a host's ``audit unarchive``,
    the server's archive job or pruner). Without it a check walks the seals, then reads blocks and rows a change
    committed after the walk, and reports failures that are not there. REPEATABLE READ on Postgres; on SQLite (the
    offline tests) a read transaction begun now, which needs WAL for a writer to commit meanwhile. ``db`` must not
    have read yet, unless one_state_and_record took its snapshot."""
    if db.info.get(SNAPSHOT_TAKEN) is not None and db.info[SNAPSHOT_TAKEN] is db.get_transaction():
        return
    if db.in_transaction():
        raise RuntimeError("a check reads one state of the database: it needs a session that has not read yet")
    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        db.execute(text("SET TRANSACTION ISOLATION LEVEL REPEATABLE READ"))
    elif dialect == "sqlite":
        db.execute(text("BEGIN"))


def one_state_and_record(db, st, *, wait: float = 30.0) -> Optional[dict]:
    """Take ``db``'s one state (one_state) and read the head record from its file, both under the chain lock
    (audit_integrity.chain_lock), and return the record (None when there is none, or none this release can read).
    Every writer commits and then writes the record under that lock, the host's commands in processes of their
    own among them, so the record lists exactly the seals of the snapshot: read at different moments, a seal
    committed between them shows as one the record does not know (``host-seal-unrecorded``, ``after-record``) or
    the record names one the snapshot lacks. The lock is held only while the snapshot is taken and the record
    read. Raises ChainBusy when the lock is not free within ``wait`` seconds."""
    ai = _ai()
    with ai.chain_lock(db.get_bind(), st, wait=wait):
        one_state(db)
        db.execute(text("SELECT max(seq) FROM audit_seals"))     # the snapshot starts with the first read
        db.info[SNAPSHOT_TAKEN] = db.get_transaction()
        try:
            return st.head_store().load()
        except ValueError:
            return None


def verify(db, *, record: Optional[dict] = None, held: Optional[dict] = None, current_key_id: Optional[str] = None,
           anchor: Optional[str] = None, from_hour: Optional[datetime] = None, to_hour: Optional[datetime] = None,
           check_rows: bool = True, now: Optional[datetime] = None, key_shared: bool = False,
           information: bool = True) -> Report:
    """Verify the chain in ``db``. ``record`` is the head record (None off the server); ``held`` the keys
    this verifier holds, by id. Rows are rebuilt for the hours in [from_hour, to_hour) (all when None).
    ``information`` False leaves out what each seal did (the daily check keeps only failures and warnings, and
    a long chain holds a prune seal for nearly every hour). Every read is of one state of the database (one_state):
    ``db`` must be a session that has not read yet, or one whose snapshot one_state_and_record took with the
    ``record`` it returned, and a caller that reads more for the same check uses it and ``report.view``."""
    ai = _ai()
    one_state(db)
    now = now or ai.utcnow()
    report = Report()
    held = held or {}
    view = ai.View(keep_roots=True)
    report.view = view
    generation = int((record or {}).get("generation") or 1)
    view.reset(generation, int((record or {}).get("discards") or 0))
    rec_seq = int(record["seq"]) if record and record.get("seq") else None
    rec_link = bytes.fromhex(record["link"]) if record and record.get("link") else None
    after = _record_after(record, generation)
    anchor_seq = anchor_link = None
    if anchor:
        anchor_seq, anchor_link = fmt.parse_head(anchor)
    anchor_bad: Optional[str] = None       # "differs" or "short": judged once every restore seal is known
    anchor_covers = None                   # the end of the newest hour sealed at the anchor, when it matched
    verified: set = set()                  # the seals whose MAC this check verified
    uncovered: List[int] = []
    prev_link = fmt.LINK_0
    expected = 1
    tol = timedelta(seconds=fmt.BACKWARDS_TOLERANCE_SECONDS)
    hour_seals: List = []
    newest = None
    for seal in ai.read_seals(db, 0):
        newest = seal
        if seal.seq != expected:
            report.add(FAILURE, "seq-gap", f"the seals jump from {expected - 1} to {seal.seq}", seal.seq)
            break
        expected += 1
        link = fmt.link(prev_link, seal.body())
        if seal.link is not None and seal.link != link:
            report.add(FAILURE, "link-broken", f"seal {seal.seq}'s stored link is not the one its body gives",
                       seal.seq)
        if (seal.seq == 1) != (seal.kind == "genesis"):
            report.add(FAILURE, "unjustified", f"seal {seal.seq} is {seal.kind}; only seal 1 is genesis", seal.seq)
        if view.position and seal.sealed_at < view.newest_at() - tol:
            sev = FAILURE if rec_seq is not None and seal.seq > rec_seq and seal.seq not in after else WARNING
            kind = "after-record-invalid" if sev == FAILURE else "sealed-at-backwards"
            report.add(sev, kind, f"seal {seal.seq}'s sealed_at steps back more than five minutes", seal.seq)
        problem = ai.key_sequence_problem(view, seal)
        if problem:
            report.add(FAILURE, "key-sequence", problem, seal.seq)
        k = held.get(seal.key_id)
        if k is not None:
            if not ai._mac_ok(k, link, seal.mac):
                report.add(FAILURE, "mac-invalid", f"seal {seal.seq}'s MAC does not verify", seal.seq)
            else:
                verified.add(seal.seq)
        else:
            uncovered.append(seal.seq)
        if seal.kind == "key":
            d = seal.detail or {}
            old = held.get(d.get("old_key_id"))
            proof = d.get("old_key_proof")
            ok = old is not None and proof and ai._proof_ok(old, prev_link, seal.key_id, proof)
            listed = any(e.get("seq") == seal.seq and e.get("generation") == generation
                         for e in (record or {}).get("unverified_keys") or [])
            if not ok:
                if d.get("accepted_unverified") and listed:
                    report.add(INFO, "key-accepted-unverified",
                               f"history before seal {seal.seq} was accepted without its key by the host operator",
                               seal.seq)
                elif d.get("accepted_unverified") and record is None:
                    report.add(INFO, "key-accepted-unverified",
                               f"seal {seal.seq} was accepted without its key, not confirmed by a head record", seal.seq)
                elif old is not None or d.get("accepted_unverified"):
                    report.add(FAILURE, "key-unverified", f"key seal {seal.seq}'s proof does not verify", seal.seq)
            if k is not None and ai._mac_ok(k, link, seal.mac):
                # A key seal whose own MAC verifies covers every MAC before it: the links fix every body
                # before it, so an older MAC adds nothing (its proof is checked above wherever the old key is
                # held).
                uncovered = []
        problem = justification_problem(view, seal, record)
        if problem == "stable-changed":
            report.add(FAILURE, "stable-changed", f"rewrite seal {seal.seq} changes a stable root or the ids", seal.seq)
        elif problem:
            report.add(FAILURE, "unjustified", f"seal {seal.seq} ({seal.kind}): {problem}", seal.seq)
        if rec_seq is not None and seal.seq == rec_seq and link != rec_link:
            report.add(FAILURE, "head-record-mismatch", f"seal {rec_seq} is not the one the head record holds",
                       seal.seq)
        if anchor_seq is not None and seal.seq == anchor_seq and link != anchor_link:
            anchor_bad = "differs"
        # Another writer's seals: those after the recorded head, and those the record lists as accepted after it,
        # wherever its head has moved since (the list decides, as the server's status does).
        entry = after.get(seal.seq)
        if rec_seq is not None and seal.seq > rec_seq and ai.is_host_kind(seal) and entry is None:
            report.add(FAILURE, "host-seal-unrecorded",
                       f"seal {seal.seq} ({seal.kind}) is one only the host writes, and the head record does not "
                       "list it", seal.seq)
        elif (entry is not None or (rec_seq is not None and seal.seq > rec_seq)) and \
                (entry is None or not entry.get("acknowledged")):
            report.add(WARNING, "after-record",
                       f"seal {seal.seq} ({seal.kind}) was appended after the head record by another writer; it "
                       "waits for the host", seal.seq)
        if seal.kind == "hour":
            hour_seals.append(seal)
        if anchor_covers is not None and seal.seq not in verified:
            for hour in changed_hours(seal):
                if hour < anchor_covers:
                    what = (f"day {hour.date().isoformat()}'s blocks" if seal.kind == "archive"
                            else f"hour {fmt.hour_text(hour)}")
                    report.add(WARNING, "changed-after-anchor",
                               f"{what} changed after the anchor by seal {seal.seq} ({seal.kind}, "
                               "not authenticated)", seal.seq, fmt.hour_text(hour))
        if information:
            _event(view, seal, report)
        view.accept(seal, link)
        prev_link = link
        if anchor_seq is not None and seal.seq == anchor_seq and anchor_bad is None:
            anchor_covers = view.newest_hour_end or datetime.min
    report.seals = view.position
    if view.position:
        report.head = fmt.head(view.position, view.link_at(view.position))
        report.head_at = fmt.time_text(view.newest_at())
        report.key_id = view.key_at(view.position)
    if rec_seq is not None and view.position < rec_seq:
        report.add(FAILURE, "head-record-mismatch",
                   f"the database's chain ends at seal {view.position}, before the recorded head {rec_seq}")
    if record is None and rec_seq is None and view.position and anchor is None:
        pass
    if anchor_seq is not None and view.position < anchor_seq:
        anchor_bad = "short"
    if anchor_bad:
        _anchor_lost(view, report, anchor_seq, anchor_link, anchor_bad, verified)
    elif anchor_seq is not None:
        # The links authenticate every seal up to a matching anchor.
        uncovered = [s for s in uncovered if s > anchor_seq]
    if information:
        _restore_findings(view, report)
        _gap_findings(view, record, report)
    if uncovered:
        report.add(FAILURE if held else INFO, "key-unverified" if held else "not-checked",
                   f"{len(uncovered)} seals are under a key this check does not hold, and no later verified key "
                   "seal covers them", uncovered[0])
    if view.position and current_key_id and view.key_in_force() != current_key_id:
        in_force = view.key_in_force()
        if view.ever_in_force(current_key_id) or ai._ever_in_force(record or {}, current_key_id):
            report.add(FAILURE, "key-not-current", "the current key is one the chain has left")
        elif in_force in held:
            report.add(INFO, "key-change-pending", "the sealer will move the chain to the current key")
        else:
            report.add(WARNING, "key-change-waiting", "the chain's key changed without the old one: set "
                                                      "AUDIT_CHAIN_KEY back to the key in force")
    if key_shared:
        report.add(INFO, "key-shared", "the chain's key is derived from ENCRYPTION_KEY; set AUDIT_CHAIN_KEY")
    if not view.position:
        report.add(INFO, "not-started", "the chain has no seal yet")
        return report
    _coverage(view, hour_seals, report, now)
    done = ai.acknowledged(view, record)
    for seq in view.late_seqs:
        if seq not in done:
            report.add(WARNING, "late", f"late seal {seq} waits to be acknowledged", seq)
    for seq in ai.database_seqs(view):
        if seq not in done:
            report.add(WARNING, "veto-from-database", f"seal {seq} holds back a deletion from the database's "
                                                      "values; it waits to be acknowledged", seq)
    if check_rows:
        _rows(db, view, report, from_hour, to_hour)
    _outside(db, view, report, now)
    return report


def changed_hours(seal) -> List[datetime]:
    """The hours a late, prune, rewrite or erase seal changes: each re-roots an hour sealed before it, or records
    a change to its rows; and, for an archive seal, which rebinds its day's blocks, the day's first hour. A late
    seal counts whoever it says wrote it (the host, or the sealer with an acknowledgment): without the key
    neither its writer nor the acknowledgment is authenticated."""
    d = seal.detail or {}
    if seal.kind == "late":
        try:
            return [fmt.parse_time_text(d["hour"])]
        except (KeyError, TypeError, ValueError):
            return []
    if seal.kind in ("prune", "rewrite"):
        out = []
        for h in d.get("hours") or []:
            try:
                out.append(fmt.parse_time_text(h[0]))
            except (TypeError, ValueError, IndexError):
                continue
        return out
    if seal.kind == "erase" and d.get("hour"):
        try:
            return [fmt.parse_time_text(d["hour"])]
        except (TypeError, ValueError):
            return []
    if seal.kind == "archive":
        # It rebinds its day's blocks: reported once, by the day's first hour.
        try:
            day = date.fromisoformat(d["day"])
        except (KeyError, TypeError, ValueError):
            return []
        return [datetime(day.year, day.month, day.day)]
    return []


def _event(view, seal, report: Report) -> None:
    """Information, for good: what a prune, rewrite, erase or acknowledgment did (read before ``view`` accepts
    it, so a prune's removed rows are counted against the hour's root before it)."""
    d = seal.detail or {}
    when = fmt.time_text(seal.sealed_at)
    if seal.kind in ("prune", "rewrite"):
        hours = d.get("hours") or []
        removed = 0
        for h in hours:
            try:
                entry = view.entry_for(fmt.parse_time_text(h[0]))
                if entry is not None and not entry.is_run:
                    removed += max(0, int(entry.root.count) - int(h[2]))
            except (TypeError, ValueError, IndexError):
                continue
        if seal.kind == "prune":
            report.add(INFO, "pruned", f"seal {seal.seq} on {when}: {d.get('reason')} prune of {len(hours)} hours, "
                                       f"{removed} rows removed", seal.seq)
        else:
            report.add(INFO, "rewritten", f"seal {seal.seq} on {when}: a rewrite of {len(hours)} hours "
                                          f"({d.get('reason')})", seal.seq)
    elif seal.kind == "erase":
        report.add(INFO, "erased", f"seal {seal.seq} on {when}: {len(d.get('rows') or [])} rows of hour "
                                   f"{d.get('hour')} erased for request {d.get('request_seq')}"
                                   + (" (its last)" if d.get("final") else ""), seal.seq)
    elif seal.kind == "archive" and d.get("cause") == "unarchive":
        # Archiving and its rewrites are routine; putting a day back as rows is the host's.
        report.add(INFO, "unarchived", f"seal {seal.seq} on {when}: {d.get('day')} restored as rows by the host",
                   seal.seq)
    elif seal.kind == "ack":
        parts = []
        if d.get("acknowledges"):
            parts.append("seals " + ", ".join(map(str, d["acknowledges"])))
        if d.get("failures"):
            parts.append("failures " + ", ".join(str(f[0] if isinstance(f, list) else f) for f in d["failures"]))
        if d.get("rows"):
            parts.append(f"{len(d['rows'])} rows")
        if d.get("discarded"):
            parts.append("discarded seals " + ", ".join(str(x[0] if isinstance(x, list) else x)
                                                        for x in d["discarded"]))
        report.add(INFO, "acknowledged", f"seal {seal.seq} on {when}, by {d.get('by')}: "
                                         + ("; ".join(parts) or "nothing"), seal.seq)


def _anchor_lost(view, report: Report, seq: int, link: bytes, how: str, verified: set) -> None:
    """An anchor whose seal the chain no longer holds: reported against the restore seal whose lost range takes it
    in (as not authenticated when this check could not verify that restore seal), or a failure."""
    for rseq, d in view.restores:
        try:
            first, last = int(d.get("lost_from_seq")), int(d.get("lost_through_seq"))
        except (TypeError, ValueError):
            continue
        if not first <= seq <= last:
            continue
        if seq == last and d.get("lost_head"):
            try:
                if fmt.parse_head(d["lost_head"])[1] != link:
                    continue
            except (TypeError, ValueError):
                continue
        sure = rseq in verified
        report.add(INFO if sure else WARNING, "anchor-lost",
                   f"the anchor's seal {seq} was lost when the database went back: restore seal {rseq} "
                   f"({d.get('cause')}) on {fmt.time_text(view.at(rseq))} lost seals {first}-{last}"
                   + ("" if sure else " (not authenticated)"), rseq)
        return
    if how == "short":
        report.add(FAILURE, "anchor-mismatch", f"the chain ends at seal {view.position}, before the anchor's seal")
    else:
        report.add(FAILURE, "anchor-mismatch", f"seal {seq} is not the one the anchor names", seq)


def _restore_findings(view, report: Report) -> None:
    """Information, for good, from each restore seal: what it lost, what it sealed again, and its key."""
    for seq, d in view.restores:
        when = fmt.time_text(view.at(seq))
        lost = (f"seals {d.get('lost_from_seq')}-{d.get('lost_through_seq')} lost"
                if d.get("lost_from_seq") is not None else "no seal it could name lost")
        acks = d.get("acknowledges") or []
        report.add(INFO, "restored",
                   f"seal {seq}: a {d.get('cause')} restore accepted by the host operator on {when}: {lost}"
                   + (", the head record missing" if d.get("record_missing") else "")
                   + (f", seals {', '.join(map(str, acks))} of the backup's window acknowledged" if acks else "")
                   + f"; nothing deleted until {d.get('grace_until')}", seq)
        hours = d.get("hours") or {}
        if (hours.get("lost") or hours.get("changed") or hours.get("days_changed")
                or hours.get("deleted_through_seq") is not None):
            parts = []
            if hours.get("lost"):
                parts.append(f"hours {hours['lost'][0]} to {hours['lost'][1]} sealed again from their rows")
            if hours.get("changed"):
                parts.append("changed: " + ", ".join(f"{h} ({a} rows recorded, {b} now)"
                                                     for h, a, b in hours["changed"]))
            if hours.get("days_changed"):
                parts.append("days changed: " + ", ".join(map(str, hours["days_changed"])))
            parts.append(f"compared from {hours.get('compared_from') or 'nothing'}")
            if hours.get("deleted_through_seq") is not None:
                parts.append(f"seals through {hours['deleted_through_seq']} were deleted, not lost with an older "
                             "copy")
            report.add(INFO, "resealed-after-restore", f"restore seal {seq}: " + "; ".join(parts), seq)
        under = d.get("under_left_key")
        if under:
            first = d.get("lost_from_seq") or seq
            report.add(INFO, "restored-under-left-key",
                       f"history from seal {first} was accepted by the host operator on {when} from a database whose "
                       f"chain ended under key {under.get('key_id')}, which the chain had left at seal "
                       f"{under.get('left_at_seq')}; anyone holding it could have written it", seq)


def _gap_findings(view, record: Optional[dict], report: Report) -> None:
    """Information: each gap of more than 12 hours in the seals' times, with the requests it pushed back; on the
    server, also each gap that shows only once another writer's seals sit where the server first accepted them."""
    from app.core import audit_chain_times as times
    chain, server = times.timelines(view, record)
    seen = set()
    for label, timeline in (("", chain), (" (another writer's seals placed where the server accepted them)", server)):
        for g, a, b in timeline.gaps:
            if (a, b) in seen:
                continue
            seen.add((a, b))
            pushed = []
            for r in sorted(view.requests):
                ends = [e for e in (view.cancels.get(r), view.applied.get(r), view.finals.get(r)) if e is not None]
                if r < g and (not ends or min(ends) >= g):
                    pushed.append(r)
            hours = (b - a) / 3_600_000_000
            report.add(INFO, "gap", f"no seal from {fmt.time_text(times.dt(a))} to {fmt.time_text(times.dt(b))} "
                                    f"({hours:.1f} hours){label}; requests pushed back by it: "
                                    + (", ".join(map(str, pushed)) or "none"), g)


def _coverage(view, hour_seals, report: Report, now: datetime) -> None:
    ai = _ai()
    expected = view.first_hour()
    for seal in hour_seals:
        if expected is not None and seal.period_start != expected:
            kind = "hour-missing" if seal.period_start > expected else "unjustified"
            report.add(FAILURE, kind, f"hour seal {seal.seq} starts at {fmt.hour_text(seal.period_start)}, not "
                                      f"{fmt.hour_text(expected)}", seal.seq)
        if seal.period_end - seal.period_start > ai.HOUR and seal.row_count:
            report.add(FAILURE, "unjustified", f"run seal {seal.seq} holds rows", seal.seq)
        if seal.detail and seal.detail.get("open_since"):
            report.add(INFO, "sealed-past-open-transaction",
                       f"hour {fmt.hour_text(seal.period_start)} was sealed past a transaction open since "
                       f"{seal.detail['open_since']}", seal.seq)
        expected = seal.period_end
    genesis = view.genesis or {}
    try:
        through = fmt.parse_time_text(genesis.get("backlog_through"))
    except (TypeError, ValueError):
        return
    newest = view.newest_hour_end
    next_hour = newest or view.first_hour()
    if next_hour is not None and next_hour <= through:
        report.add(INFO, "backlog-in-progress",
                   f"the first start's backlog is sealed through {fmt.hour_text(newest) if newest else 'nothing'} "
                   f"of {fmt.hour_text(through)}")
        return
    counted = sum(s.row_count for s in hour_seals if s.period_end <= through + ai.HOUR)
    if counted != int(genesis.get("backlog_rows") or 0):
        report.add(FAILURE, "backlog-count", f"the backlog's hours hold {counted} rows; genesis counted "
                                             f"{genesis.get('backlog_rows')}")
    if newest is None:
        report.add(INFO, "sealing-behind", "no hour is sealed yet: the first is sealed once it has closed")
    elif now - newest > ai.lag() + timedelta(hours=2):
        report.add(INFO, "sealing-behind", f"hours are sealed through {fmt.hour_text(newest)}")
    for seal in hour_seals:
        if seal.period_end > through + ai.HOUR and seal.sealed_at - seal.period_end > timedelta(days=1):
            report.add(INFO, "sealed-late", f"hour {fmt.hour_text(seal.period_start)} was sealed more than a day "
                                            "after it closed", seal.seq)


def _erase_entries(db, view, entry):
    """{row id: (c_prev, c_next, placeholder)} of the erase seals after the hour's root seal."""
    ai = _ai()
    out = {}
    for seq in entry.erases:
        seal = ai.read_seal(db, seq)
        if seal is None:
            continue
        d = seal.detail or {}
        for rid, c_prev, c_next in d.get("rows") or []:
            out.setdefault(fmt.as_uuid(rid), (bytes.fromhex(c_prev), bytes.fromhex(c_next), d.get("placeholder")))
    return out


def check_hour(db, view, entry, hour: datetime, report: Report) -> None:
    """Steps 5-7 for one hour: rebuild its rows into both roots and compare with its newest root seal."""
    ai = _ai()
    own = view.own_entry(hour)
    try:
        root = ai.hour_root(db, view, hour)
    except ai.ChainStopped as stop:
        report.add(FAILURE, "link-broken", str(stop), stop.seq, fmt.hour_text(hour))
        return
    wr = ai.working_row(db, hour)
    salt = bytes(wr.legacy_salt) if wr is not None and wr.legacy_salt is not None else None
    erased = _erase_entries(db, view, own) if own is not None and own.erases else {}
    c_prev = {rid: e[0] for rid, e in erased.items()}
    # Streamed (the rows are never held as a list): only the ids and the two trees grow with the hour.
    fig = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), salt, c_prev)
    report.rows_checked += fig.count
    label = fmt.hour_text(hour)
    for rid, (_cp, c_next, placeholder) in erased.items():
        row = next((r for r in ai.iter_rows(db, hour, hour + ai.HOUR) if r["id"] == rid), None)
        if row is None:
            continue
        if not ai.erased_as_sealed(row, c_next, placeholder):
            report.add(FAILURE, "unjustified", f"erased row {rid} is not what its erase seal says", hour=label)
    if fig.missing_nonce:
        report.add(FAILURE, "nonce-missing", f"{len(fig.missing_nonce)} rows in {label} have no nonce and the hour "
                                             "no salt", hour=label)
    if fig.unwritable:
        # A value no release writes: the row was written or changed outside the app. Once the host has looked
        # at it (``acknowledge --rows``), it is information.
        seen = [r for r in fig.unwritable if str(r) in view.acked_rows]
        unseen = [r for r in fig.unwritable if str(r) not in view.acked_rows]
        if unseen:
            report.add(FAILURE, "rows-altered", f"value-not-writable: {len(unseen)} rows of {label} hold a value no "
                                                f"release writes: {', '.join(str(r) for r in unseen[:20])}",
                       root.seq, label)
        if seen:
            report.add(INFO, "value-not-writable", f"{len(seen)} rows of {label} hold a value no release writes; "
                                                   "the host acknowledged them", root.seq, label)
    if (fig.count, fig.root_s, fig.root_c, fig.ids_digest) == (root.count, root.root_s, root.root_c,
                                                               root.ids_digest):
        return
    sealed_ids = bytes(wr.row_ids or b"") if wr is not None and wr.row_ids is not None else None
    if sealed_ids is not None and fmt.ids_digest_of_blob(sealed_ids) == root.ids_digest:
        sealed = [sealed_ids[i:i + 16] for i in range(0, len(sealed_ids), 16)]
        now_ids = [fig.ids[i:i + 16] for i in range(0, len(fig.ids), 16)]
        sealed_set, now_set = set(sealed), set(now_ids)
        missing = [str(fmt.as_uuid(i)) for i in sealed if i not in now_set]
        added = [str(fmt.as_uuid(i)) for i in now_ids if i not in sealed_set]
        if missing:
            report.add(FAILURE, "rows-missing", f"{len(missing)} sealed rows of {label} are gone: "
                                                f"{', '.join(missing[:20])}", root.seq, label)
        if added:
            report.add(FAILURE, "rows-added", f"{len(added)} rows in {label} are not in its seal: "
                                              f"{', '.join(added[:20])}", root.seq, label)
        if missing:
            return
        if added:
            # The rows the seal holds, without the added ones, must still give its roots.
            kept = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), salt, c_prev,
                                   exclude={fmt.as_uuid(a) for a in added})
            if (kept.root_s, kept.root_c) != (root.root_s, root.root_c):
                which = "stable fields" if kept.root_s != root.root_s else "personal values"
                report.add(FAILURE, "rows-altered", f"rows of {label} changed in their {which}", root.seq, label)
            return
    elif fig.count != root.count:
        kind = "rows-missing" if fig.count < root.count else "rows-added"
        report.add(FAILURE, kind, f"{label} holds {fig.count} rows; its seal {root.count}", root.seq, label)
        return
    which = "stable fields" if fig.root_s != root.root_s else "personal values"
    reason = " (a value no release writes)" if fig.unwritable else ""
    report.add(FAILURE, "rows-altered", f"rows of {label} changed in their {which}{reason}", root.seq, label)


def _rows(db, view, report: Report, from_hour, to_hour) -> None:
    from app.core import audit_archive
    ai = _ai()
    # The blocks: the set and each one's length against the archive seals (no payload read), rows put back into
    # archived hours, then each part in the range read once, whole.
    audit_archive.check_block_set(db, view, report)
    audit_archive.check_parts(db, view, report, audit_archive.archived_parts_in(view, from_hour, to_hour))
    for hour in list(view.single_hours()):
        if (from_hour and hour < from_hour) or (to_hour and hour >= to_hour):
            continue
        if view.archived_part(hour) is not None:
            continue
        report.hours_checked += 1
        check_hour(db, view, view.entry_for(hour), hour, report)
    from app.core.models import AuditLog as A
    for run_start, run_end, run_seq in list(view.runs()):
        start = max(run_start, from_hour) if from_hour else run_start
        end = min(run_end, to_hour) if to_hour else run_end
        if start >= end:
            continue
        times = [r[0] for r in db.query(A.timestamp).filter(A.timestamp >= start, A.timestamp < end).all()]
        for hour in sorted({ai.hour_floor(t) for t in times}):
            if view.has_own(hour) or view.archived_part(hour) is not None:
                continue
            report.add(FAILURE, "rows-added", f"rows in {fmt.hour_text(hour)}, an hour sealed empty",
                       run_seq, fmt.hour_text(hour))
    check_undated(db, view, report)


def check_undated(db, view, report: Report) -> None:
    """The rows with no timestamp, against genesis's roots: genesis sealed them, and no hour holds them."""
    ai = _ai()
    from app.core.models import AuditSeal as S
    root = view.genesis_root
    if root is None:
        return
    got = db.query(S.legacy_salt, S.row_ids).filter(S.seq == 1).first()
    salt = bytes(got[0]) if got is not None and got[0] is not None else None
    fig = ai.hour_figures(ai.iter_rows(db, None, None), salt)
    report.rows_checked += fig.count
    if (fig.count, fig.root_s, fig.root_c, fig.ids_digest) == (root.count, root.root_s, root.root_c,
                                                               root.ids_digest):
        return
    sealed_ids = bytes(got[1]) if got is not None and got[1] is not None else b""
    if fmt.ids_digest_of_blob(sealed_ids) == root.ids_digest:
        sealed = {sealed_ids[i:i + 16] for i in range(0, len(sealed_ids), 16)}
        now = {fig.ids[i:i + 16] for i in range(0, len(fig.ids), 16)}
        missing, added = sorted(sealed - now), sorted(now - sealed)
        if missing:
            report.add(FAILURE, "rows-missing", f"{len(missing)} undated rows genesis sealed are gone: "
                                                f"{', '.join(str(fmt.as_uuid(i)) for i in missing[:20])}", 1, "undated")
        if added:
            report.add(FAILURE, "rows-added", f"{len(added)} undated rows are not in genesis's seal: "
                                              f"{', '.join(str(fmt.as_uuid(i)) for i in added[:20])}", 1, "undated")
        if missing or added:
            return
    which = "stable fields" if fig.root_s != root.root_s else "personal values"
    report.add(FAILURE, "rows-altered", f"undated rows changed in their {which}", 1, "undated")


def _outside(db, view, report: Report, now: datetime) -> None:
    from app.core import audit_catalog
    from app.core.credential_changes import HOST_OPERATOR
    from app.core.models import AuditLog as A, User as U
    ai = _ai()
    mismatch = db.query(func.count()).select_from(A).join(U, U.id == A.user_id).filter(
        A.username != U.username).scalar() or 0
    if mismatch:
        report.add(FAILURE, "user-mismatch", f"{mismatch} rows name an account whose username is not theirs")
    try:
        from app.core.audit_privacy import SERVER_CONFIGURATION
    except ImportError:
        SERVER_CONFIGURATION = None
    accountish = [a.name for a in audit_catalog.ACTIONS if not a.automatic and not a.typed_name]
    names = []
    for a in audit_catalog.ACTIONS:
        if a.name in accountish:
            names.extend((a.name,) + a.aliases)
    excluded = [HOST_OPERATOR] + ([SERVER_CONFIGURATION] if SERVER_CONFIGURATION else [])
    unlinked = db.query(func.count()).select_from(A).join(U, U.username == A.username).filter(
        A.user_id.is_(None), A.action.in_(names), A.username.notin_(excluded),
        U.created_at <= A.timestamp).scalar() or 0
    if unlinked:
        report.add(FAILURE, "user-unlinked", f"{unlinked} rows of an account that still exists were unlinked from it")
    first = view.first_hour()
    if first is not None:
        before = db.query(func.count()).select_from(A).filter(A.timestamp < first).scalar() or 0
        if before:
            report.add(FAILURE, "row-before-genesis", f"{before} rows are dated before the chain's first hour")
    future = db.query(func.count()).select_from(A).filter(A.timestamp > now + ai.FUTURE_SLACK).scalar() or 0
    if future:
        report.add(FAILURE, "future-dated", f"{future} rows are dated more than an hour ahead")
    undated = db.query(func.count()).select_from(A).filter(A.timestamp.is_(None)).scalar() or 0
    if undated != int((view.genesis or {}).get("undated_rows") or 0):
        report.add(FAILURE, "undated-row", f"{undated} rows have no timestamp")
    for problem in db_hooks(db):
        report.add(FAILURE, "db-hooks", problem)


# --------------------------------------------------------------------------- the daily check

ROLLING_DAYS = 30


def daily_check(session_factory, st=None, now: Optional[datetime] = None, *, force: bool = False) -> Optional[Report]:
    """Once a day: the whole seal chain walked again, the hours of the last 7 days rebuilt from their rows, and
    a thirtieth of the older hours in turn. The outcome goes into the head record; each new failure is
    announced once. Returns the report, or None when it was not due."""
    ai = _ai()
    st = st or ai.state()
    now = now or st.clock()
    last = ((st.head_store().memory or {}).get("check") or {}).get("daily_at")
    if not force and last and now - fmt.parse_time_text(last) < ai.DAILY:
        return None
    db = session_factory()
    try:
        # The record that goes with the snapshot, read from the file under the chain lock: this process's copy can
        # be older than a host command's seals the snapshot holds. A lock kept longer than the wait leaves the check
        # for the next pass.
        try:
            record = one_state_and_record(db, st)
        except ai.ChainBusy:
            return None
        if record is None:
            record = st.head_store().memory or {}
        keys_held = {k: v.key for k, v in st.keys_held().items()}
        report = verify(db, record=record, held=keys_held, current_key_id=st.current_key().key_id,
                        from_hour=ai.hour_floor(now) - timedelta(days=7), now=now,
                        key_shared=st.current_key().source == "encryption", information=False)
        rolling_from = (record.get("check") or {}).get("rolling_from")
        # The same snapshot and the view built from it: the process's own view can be older than the snapshot
        # (a host command committed meanwhile), and a part it still lists would read as gone.
        next_from = _rolling(db, report.view, report, ai.hour_floor(now) - timedelta(days=7),
                             fmt.parse_time_text(rolling_from) if rolling_from else None)
        # Step 4 for each pending erase, which only a holder of ENCRYPTION_KEY can do: its row opens to the name its
        # request seal commits to, with the placeholder the seal names (app/core/audit_chain_erase.py).
        try:
            from app.core import audit_chain_erase
            for message in audit_chain_erase.pending_input_problems(db, report.view, st.cfg()):
                report.add(FAILURE, "unjustified-input", message)
        except Exception as exc:  # noqa: BLE001 -- the next check tries again
            ai._say(f"Warning: the waiting erases were not checked ({type(exc).__name__})")
    finally:
        db.close()
    failures = {f.kind: f.message for f in report.findings if f.severity == FAILURE}
    warnings = {f.kind: f.message for f in report.findings if f.severity == WARNING
                and f.kind not in ("late", "after-record", "veto-from-database")}
    ai.report_failures(st, session_factory, failures, warnings, outcome="clean")

    def change(rec):
        check = rec.setdefault("check", {})
        check["daily_at"] = fmt.time_text(now)
        if not failures and report.head:
            check["clean_seq"] = report.seals
            check["clean_link"] = report.head.split(":")[-1]
            check["clean_at"] = fmt.time_text(now)
        if next_from is not None:
            check["rolling_from"] = fmt.time_text(next_from)
        return rec

    st.head_store().write(change, now)
    return report


def bisect_hours(hours, at) -> int:
    import bisect
    i = bisect.bisect_left(hours, at)
    return i if i < len(hours) else 0


def _rolling(db, view, report: Report, before: datetime, rolling_from: Optional[datetime]) -> Optional[datetime]:
    """The rolling check: about a thirtieth of the sealed hours older than ``before`` and of the archived parts,
    in order from ``rolling_from`` (a part weighs as many hours as it holds, and is read once, whole), so that
    every hour and every block is checked at least every 30 days. Returns where the next check starts."""
    from app.core import audit_archive
    ai = _ai()
    items = [(h, 1, None) for h in view.single_hours() if h < before and view.archived_part(h) is None]
    items += [(part.first_hour, len(part.hours()), (day, part)) for day, part in view.archived_parts()
              if part.first_hour < before]
    if not items:
        return None
    items.sort(key=lambda it: it[0])
    per_day = max(1, sum(w for _t, w, _p in items) // ROLLING_DAYS + 1)
    start = bisect_hours([t for t, _w, _p in items], rolling_from) if rolling_from else 0
    taken, weight = [], 0
    for item in items[start:]:
        if weight >= per_day:
            break
        taken.append(item)
        weight += item[1]
    if not taken:
        taken = items[:1]
    for when, _w, part in taken:
        if part is None:
            check_hour(db, view, view.entry_for(when), when, report)
        else:
            audit_archive.check_parts(db, view, report, [part])
    last_when, _w, last_part = taken[-1]
    return (last_part[1].last_hour if last_part is not None else last_when) + ai.HOUR


# --------------------------------------------------------------------------- the host command

def _print_report(report: Report, out) -> None:
    for f in report.findings:
        where = f" (seal {f.seq})" if f.seq else ""
        where += f" [{f.hour}]" if f.hour else ""
        out.write(f"{f.severity.upper():12} {f.kind}{where}: {f.message}\n")
    if not report.findings:
        out.write("clean\n")
    out.write(f"seals: {report.seals}; hours checked: {report.hours_checked}; rows checked: {report.rows_checked}\n")
    if report.head:
        out.write(f"head (keep it somewhere else): {report.head}  at {report.head_at}  key {report.key_id}\n")


def main(argv=None) -> int:
    """The host's command line (app/core/audit_chain_cli.py)."""
    from app.core.audit_chain_cli import main as cli
    return cli(argv)
