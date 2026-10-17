"""Changing the personal values of sealed audit rows while the integrity chain stays valid: ``rewrite`` seals.

Two changes rewrite rows:

- a removal of the values recorded under earlier recording levels (app/core/audit_value_removal.py): once a level
  has been tightened, an administrator may ask for the rows written before to keep only what the levels in force
  record (seal reason ``levels``, naming the removal's ``request`` seal);
- keeping full addresses for a number of days only (``audit_ip_full_days``, AUDIT_IP_FULL_DAYS in .env; no limit by
  default): an address recorded in full is shortened to the network it is in once its row is that many days old
  (seal reason ``shorten-ip``, the pruner's ``audit_ip_shortening`` job). Setting a number, or a smaller one, deletes
  sooner: it waits the reduction delay like any such change (app/core/setting_changes.py).

What a row keeps (reduced()): of each kind of personal data whose level is below full, what a row written at that
level keeps of the values it holds (app/core/audit_privacy.py):

- an address (the ip_address column, and each detail classified as an address): shortened, it goes into
  ``recorded`` as the network it is in (``recorded.ip``, ``recorded.details``); not recorded, it goes, with a
  shortened form already in ``recorded``;
- the browser's description (the user_agent column, and such details), and email addresses in the details: gone;
- a name typed at a failed sign-in (the username of a failed sign-in row with no account and no temporary
  credential, whose name is now no account's, temporary credential's or the server's), and text typed into an
  Activity filter (the details classified so): as a fingerprint, its fingerprint goes into ``recorded``; not
  recorded, it goes, with a fingerprint already there;
- vault, file and folder names (``recorded.names``): as fingerprints, the sealed names go and the fingerprints stay;
  not recorded, both go. A name an earlier release left in a row's details goes too.

Nothing else changes: the stable fields (so the stable root and the ids), the endpoint, the error, the temporary
credential's name, the details of other kinds, and keys nothing classifies. A row that holds nothing above the levels
is not touched, and neither is a row an erase changed.

One transaction per unit, under the chain lock:

- the hours of rows of one UTC day: each hour's rows checked against its seal first (and each row an erase changed
  against that erase's seal); an hour that does not check out is reported and left as it is, and one with rows that
  arrived after its seal within the late window waits for that seal. Its nonces are materialised and its salt
  deleted, then each changed row takes its reduced values and a fresh random nonce, so the commitment root its seal
  kept can no longer be tested against guesses of the old values. The hour's new figures must keep its count, its
  stable root and its ids; one ``rewrite`` seal carries the day's hours;
- an archived day, through the block-rewrite primitive (app/core/audit_archive.py): each part holding a changed row
  written anew and checked as stored, its changed hours' salts dropped and every changed row given a fresh nonce;
  the ``rewrite`` seal, then the day's ``archive`` seal of cause ``rewrite``.

Nothing is rewritten while the hold switch is on (the jobs are held), while a restore is not finished or its grace
runs, or while a rule another part of the app registers holds deletions back (person_erase.register_wait: legal
holds and open cases).
"""
from __future__ import annotations

import functools
import json
import re
import secrets
from datetime import datetime, timedelta
from typing import Callable, Dict, List, Mapping, Optional, Tuple

from app.core import audit_chain_format as fmt
from app.core import settings_registry as registry

FULL_DAYS_KEY = "audit_ip_full_days"
LEVELS = "levels"
SHORTEN = "shorten-ip"
REASONS = (LEVELS, SHORTEN)
HOUR = timedelta(hours=1)
_PLACEHOLDER = re.compile(r"^erased-[0-9a-f]{8}$")
_UNREADABLE = object()

registry.register(registry.SettingSpec(
    level=registry.ADVANCED, since="0.34.0",
    key=FULL_DAYS_KEY, kind="int", default=0, env="audit_ip_full_days", minimum=1, maximum=36500, unlimited=0,
    reduction=registry.LOWER, group="audit_retention", unit="days",
    label="Keep full addresses in audit rows for",
    help="After this, an address recorded in full is shortened to the network it is in (a /24, or a /48 for IPv6). "
         "No limit keeps addresses as they were recorded."))


def _ap():
    from app.core import audit_privacy
    return audit_privacy


def _ai():
    from app.core import audit_integrity
    return audit_integrity


# --------------------------------------------------------------------------- what a rewritten row keeps

class Context:
    """What reduced() needs besides the row: the usernames of the accounts and the names of the temporary credentials
    that exist now (a failed sign-in for one names it, and keeps its name at every level)."""

    def __init__(self, accounts=(), credentials=()):
        self.accounts = frozenset(accounts)
        self.credentials = frozenset(credentials)

    @classmethod
    def load(cls, db) -> "Context":
        from app.core.models import TemporaryCredential, User
        return cls((u for (u,) in db.query(User.username).all() if u),
                   (c for (c,) in db.query(TemporaryCredential.temp_username).all() if c))


@functools.lru_cache(maxsize=1)
def typed_actions() -> frozenset:
    from app.core import audit_catalog
    return frozenset(a.name for a in audit_catalog.ACTIONS if a.typed_name)


@functools.lru_cache(maxsize=1)
def _system_names() -> frozenset:
    from app.core.credential_changes import HOST_OPERATOR
    return frozenset({HOST_OPERATOR, _ap().SERVER_CONFIGURATION})


def is_typed_name(row: Mapping, ctx: Context) -> bool:
    """Whether the row's username is a name someone typed at a failed sign-in, as far as a stored row can tell: a
    row of a typed-name action with no account and no temporary credential, whose username is now no account's,
    temporary credential's, the server's, or an erase's placeholder."""
    name = row.get("username")
    if not isinstance(name, str) or not name or row.get("action") not in typed_actions():
        return False
    if row.get("user_id") is not None or row.get("temp_credential_id") is not None:
        return False
    return (name not in ctx.accounts and name not in ctx.credentials and name not in _system_names()
            and not _PLACEHOLDER.match(name))


def _load(value):
    """A JSON column as read (its stored text, or already decoded): the value, None for NULL, or _UNREADABLE."""
    if value is None or isinstance(value, (dict, list)):
        return value
    try:
        return json.loads(value)
    except (TypeError, ValueError):
        return _UNREADABLE


def _other_form(kind: str, level: str, value):
    """What a value of ``kind`` above ``level`` leaves in ``recorded``: a shortened address, a fingerprint, or None."""
    ap = _ap()
    if kind == ap.ADDRESS and level == ap.SHORTENED and isinstance(value, str):
        return ap.shorten(value)
    if kind == ap.SIGNIN_NAME and level == ap.FINGERPRINT and isinstance(value, str) and value:
        from app.core.audit_fingerprints import SIGNIN, fingerprint
        return fingerprint(SIGNIN, value)
    return None


def _above(levels: Mapping[str, str], kind: Optional[str]) -> Optional[str]:
    """The level ``kind``'s values are brought down to, or None when its level is full (or it is no personal kind)."""
    ap = _ap()
    policy = ap.KIND_POLICY.get(kind) if kind is not None else None
    if policy is None:
        return None
    level = levels.get(policy, ap.FULL)
    return None if level == ap.FULL else level


def _reduce_details(value: dict, levels, moved: dict, prefix: str = "") -> Tuple[dict, bool]:
    """(the details kept, whether any value went): each value of a personal kind above its level taken out, with
    what its level keeps put into ``moved`` (path -> value)."""
    ap = _ap()
    out, changed = {}, False
    for key, v in value.items():
        path = prefix + str(key)
        kind = ap.kind_of(path)
        if kind == ap.NESTED and isinstance(v, dict):
            inner, inner_changed = _reduce_details(v, levels, moved, path + ".")
            out[key] = inner
            changed = changed or inner_changed
            continue
        level = _above(levels, kind)
        if level is None or v is None:
            out[key] = v
            continue
        other = _other_form(kind, level, v)
        if other is not None:
            moved[path] = other
        changed = True
    return out, changed


def _dump(value) -> Optional[str]:
    return None if value is None else json.dumps(value, ensure_ascii=False, separators=(",", ":"))


def reduced(row: Mapping, levels: Mapping[str, str], ctx: Context) -> Optional[dict]:
    """The committed columns of ``row`` that change when it keeps only what ``levels`` record (kind -> level; a kind
    left out is full), as {column: new value} with the JSON columns as text, or None when nothing changes. ``row``
    is as read: the committed columns (JSON columns as their stored text, or decoded), with ``action``,
    ``temp_credential_id`` and ``user_id``."""
    ap = _ap()
    recorded = _load(row.get("recorded"))
    if recorded is _UNREADABLE or (recorded is not None and not isinstance(recorded, dict)):
        return None                       # a recorded value this release does not read is left as it is
    recorded = dict(recorded or {})
    out: dict = {}
    # The address, the browser's description and a typed name, in their own columns.
    ip_level = _above(levels, ap.ADDRESS)
    if ip_level is not None and row.get("ip_address") is not None:
        out["ip_address"] = None
        other = _other_form(ap.ADDRESS, ip_level, row.get("ip_address"))
        if other is not None and recorded.get("ip") is None:
            recorded["ip"] = other
    if ip_level == ap.NONE and "ip" in recorded:
        del recorded["ip"]
    if _above(levels, ap.AGENT) is not None and row.get("user_agent") is not None:
        out["user_agent"] = None
    name_level = _above(levels, ap.SIGNIN_NAME)
    if name_level is not None and is_typed_name(row, ctx):
        out["username"] = None
        other = _other_form(ap.SIGNIN_NAME, name_level, row.get("username"))
        if other is not None and recorded.get("signin_name") is None:
            recorded["signin_name"] = other
    if name_level == ap.NONE and "signin_name" in recorded:
        del recorded["signin_name"]
    # The details: what is above its level goes, its other form into recorded.details.
    details = _load(row.get("details"))
    moved: dict = {}
    if isinstance(details, dict):
        kept, changed = _reduce_details(details, levels, moved)
        if changed:
            out["details"] = _dump(kept)
    recorded_details = dict(recorded.get("details") or {}) if isinstance(recorded.get("details"), dict) else None
    if recorded_details is not None:
        for path in list(recorded_details):
            if _above(levels, ap.kind_of(path)) == ap.NONE:
                del recorded_details[path]
    if moved:
        recorded_details = dict(recorded_details or {})
        for path, value in moved.items():
            recorded_details.setdefault(path, value)
    if recorded_details is not None:
        if recorded_details:
            recorded["details"] = recorded_details
        else:
            recorded.pop("details", None)
    # Vault, file and folder names: the sealed names go below full, the fingerprints too at none.
    names_level = levels.get(ap.NAMES, ap.FULL)
    names = recorded.get("names")
    if isinstance(names, dict) and names_level != ap.FULL:
        if names_level == ap.NONE:
            del recorded["names"]
        else:
            values = names.get("values")
            if isinstance(values, dict):
                recorded["names"] = dict(names, values={
                    path: ({k: v for k, v in kept.items() if k != "sealed"} if isinstance(kept, dict) else kept)
                    for path, kept in values.items()})
    after = recorded or None
    if not _same(after, _load(row.get("recorded"))):
        out["recorded"] = _dump(after)
    return out or None


def _same(a, b) -> bool:
    """Whether two decoded JSON values are the same value (as the chain encodes them)."""
    if a is None or b is None:
        return a is None and b is None
    try:
        return fmt.canonical_json(a) == fmt.canonical_json(b)
    except Exception:  # noqa: BLE001 -- a value the format cannot canonicalise: compared as Python values
        return a == b


def shortened(row: Mapping) -> Optional[dict]:
    """reduced() for keeping full addresses no longer: the addresses alone brought down to shortened."""
    ap = _ap()
    return reduced(row, {ap.IP: ap.SHORTENED}, Context())


# --------------------------------------------------------------------------- the prefilter

def _key_names(kinds) -> Tuple[set, set]:
    """(the last parts, the whole paths) of every detail key classified as one of ``kinds``."""
    ap = _ap()
    last, whole = set(), set()
    for path, kind in ap.DETAIL_KEYS.items():
        if kind in kinds and not path.endswith(".*"):
            last.add(path.rsplit(".", 1)[-1])
            whole.add(path)
    return last, whole


def prefilter(model, levels: Mapping[str, str]) -> list:
    """Conditions every row reduced() would change meets (more rows meet them: reduced() decides), as one or_(), or
    none when every level is full."""
    from sqlalchemy import Text, and_, cast, or_
    ap = _ap()
    details, recorded = cast(model.details, Text), cast(model.recorded, Text)
    conds = []

    def keys_in(column, names):
        return [column.contains(f'"{n}"') for n in sorted(names)]
    ip, agent, email = levels.get(ap.IP, ap.FULL), levels.get(ap.USER_AGENT, ap.FULL), levels.get(ap.EMAILS, ap.FULL)
    signin, names = levels.get(ap.SIGNIN_NAMES, ap.FULL), levels.get(ap.NAMES, ap.FULL)
    if ip != ap.FULL:
        last, whole = _key_names({ap.ADDRESS})
        conds += [model.ip_address.isnot(None)] + keys_in(details, last)
        if ip == ap.NONE:
            conds += keys_in(recorded, whole | {"ip"})
    if agent != ap.FULL:
        conds += [model.user_agent.isnot(None)] + keys_in(details, _key_names({ap.AGENT})[0])
    if email != ap.FULL:
        conds += keys_in(details, _key_names({ap.EMAIL})[0])
    if signin != ap.FULL:
        last, whole = _key_names({ap.SIGNIN_NAME})
        conds += [and_(model.action.in_(sorted(typed_actions())), model.username.isnot(None),
                       model.user_id.is_(None), model.temp_credential_id.is_(None))] + keys_in(details, last)
        if signin == ap.NONE:
            conds += keys_in(recorded, whole | {"signin_name"})
    if names != ap.FULL:
        conds += keys_in(recorded, {"names"}) + keys_in(details, _key_names({ap.NAME})[0])
    return [or_(*conds)] if conds else []


# --------------------------------------------------------------------------- one unit

class NotRewritten(Exception):
    """A unit that cannot be rewritten now: ``kind`` is a finding (reported), or None (it waits). ``until`` is the
    end of the unit (step() sets it)."""

    def __init__(self, message: str, kind: Optional[str] = None):
        super().__init__(message)
        self.kind = kind
        self.until: Optional[datetime] = None


def _write_row(db, row_id, new: dict, nonce: bytes) -> None:
    from sqlalchemy import null
    from app.core.models import AuditLog as A
    values = {A.seal_nonce: nonce}
    for column, value in new.items():
        if column in ("details", "recorded"):
            values[getattr(A, column)] = json.loads(value) if value is not None else null()
        else:
            values[getattr(A, column)] = value
    db.query(A).filter(A.id == row_id).update(values, synchronize_session=False)


def _keeps_stable(fig, root) -> bool:
    return (fig.count, fig.root_s, fig.ids_digest) == (root.count, root.root_s, root.ids_digest) \
        and not fig.missing_nonce


def _took(r: Mapping, want: dict, nonce: bytes) -> bool:
    """Whether the row as read back holds the values written and the nonce."""
    if r["seal_nonce"] != nonce:
        return False
    for column, value in want.items():
        if column in ("details", "recorded"):
            if not _same(_load(r[column]), _load(value)):
                return False
        elif r[column] != value:
            return False
    return True


def rewrite_hour(w, hour: datetime, change: Callable[[dict], Optional[dict]], *, now: datetime,
                 before: datetime) -> Tuple[int, Optional[list]]:
    """Rewrite the rows of the sealed ``hour`` (those before ``before``) that ``change`` changes, in ``w``'s
    transaction: (rows changed, the hour's entry for the rewrite seal), or (0, None) when none changes. Raises
    NotRewritten."""
    from sqlalchemy import func
    from app.core import audit_chain_prune as prune_mod
    from app.core.models import AuditLog as A
    ai = _ai()
    db, view = w.db, w.st.view
    held = ai.hour_held(view, w.record, hour)
    if held is not None:
        raise NotRewritten(f"{fmt.hour_text(hour)}'s seal {held} was appended by another writer and waits for the "
                           "host operator")
    entry = view.entry_for(hour)
    if entry is None:
        raise NotRewritten(f"{fmt.hour_text(hour)} is not sealed yet")
    root_entry = entry.root
    if root_entry.sealed_at >= now - ai.LATE_WINDOW and int(
            db.query(func.count()).select_from(A).filter(A.timestamp >= hour, A.timestamp < hour + HOUR).scalar()
            or 0) > root_entry.count:
        raise NotRewritten(f"rows arrived in {fmt.hour_text(hour)} after its seal, and the sealer seals them first")
    try:
        root, wr, salt, _c_prev = prune_mod._verify_hour(w, hour)
    except prune_mod.HourNotVerified as nv:
        if nv.kind == "rows-altered":
            raise NotRewritten(f"the rows of {fmt.hour_text(hour)} no longer give its seal; nothing in it was "
                               "rewritten", "rows-altered") from None
        raise NotRewritten(f"an erased row of {fmt.hour_text(hour)} is not what its erase seal says; nothing in it "
                           "was rewritten", nv.kind) from None
    users = dict(db.query(A.id, A.user_id).filter(A.timestamp >= hour, A.timestamp < hour + HOUR).all())
    changes = {}
    for r in ai.iter_rows(db, hour, hour + HOUR):
        if r["timestamp"] is None or r["timestamp"] >= before or str(r["id"]) in view.erased_rows:
            continue
        new = change(dict(r, user_id=users.get(r["id"])))
        if new:
            changes[r["id"]] = new
    if not changes:
        return 0, None
    prune_mod._materialise(w, hour, salt, wr)
    db.flush()
    nonces = {}
    for row_id, new in changes.items():
        nonces[row_id] = secrets.token_bytes(16)
        _write_row(db, row_id, new, nonces[row_id])
    db.flush()
    for r in ai.iter_rows(db, hour, hour + HOUR):
        if r["id"] in changes and not _took(r, changes[r["id"]], nonces[r["id"]]):
            raise NotRewritten(f"a row of {fmt.hour_text(hour)} did not take its new values", "unjustified")
    fig = ai.hour_figures(ai.iter_rows(db, hour, hour + HOUR), None)
    if not _keeps_stable(fig, root):
        raise NotRewritten(f"the rewritten rows of {fmt.hour_text(hour)} would change its stable fields or its rows; "
                           "nothing was rewritten", "rows-altered")
    if wr is not None:
        wr.row_ids = fig.ids
    return len(changes), ai.hour_entry(hour, root.seq, fig)


def rewrite_archived_day(w, day, change: Callable[[dict], Optional[dict]], *, now: datetime, before: datetime):
    """Rewrite the archived rows of ``day`` (those before ``before``) that ``change`` changes, in ``w``'s
    transaction, through the block-rewrite primitive: its Rewritten (the rewrite seal's entries and the new parts),
    or None when none changes. Raises NotRewritten."""
    from app.core import audit_archive as arc
    view = w.st.view
    erased = view.erased_rows

    def wanted(row) -> Optional[dict]:
        t = row.get("timestamp")
        if t is None or t >= before or str(row["id"]) in erased:
            return None
        return change(row)

    def pick(rows):
        return {r["id"]: r["timestamp"] for r in rows if wanted(r)}

    def transform(row):
        new = wanted(row)
        if new:
            row.update(new)
            row["seal_nonce"] = secrets.token_bytes(16)
        return row
    try:
        rw = arc.rewrite_day(w, day, pick, transform, now)
    except arc.NotVerified as nv:
        if nv.kind == arc.LATER_FORMAT:
            raise NotRewritten(f"{day.isoformat()} is archived in a later release's block format, which this "
                               "release does not change") from None
        raise NotRewritten(f"{nv}; nothing in {day.isoformat()} was rewritten", nv.kind) from None
    except arc.NotArchivable as why:
        raise NotRewritten(str(why)) from None
    if rw is None:
        return None
    for e in rw.entries:
        root = arc._root(w.db, view, fmt.parse_time_text(e[0]))
        if root is None or (int(e[2]), bytes.fromhex(e[4]), bytes.fromhex(e[6])) != (root.count, root.root_s,
                                                                                        root.ids_digest):
            raise NotRewritten(f"the rewritten rows of {day.isoformat()} would change its stable fields or its rows; "
                               "nothing was rewritten", "rows-altered")
    return rw


# --------------------------------------------------------------------------- a run over the rows

class Scope:
    """What one run rewrites: the rows before ``before`` (an hour boundary) that ``change`` changes, found among the
    rows ``conditions`` select (a superset); sealed with ``reason``, and for a removal its ``request_seq`` and
    ``through``."""

    def __init__(self, reason: str, before: datetime, change: Callable[[dict], Optional[dict]], conditions: list,
                 *, request_seq: Optional[int] = None, through: Optional[str] = None):
        self.reason, self.before, self.change, self.conditions = reason, before, change, conditions
        self.request_seq, self.through = request_seq, through

    def detail(self, policy_seq: int, entries: list, *, final: bool = False) -> dict:
        d = {"reason": self.reason, "policy_seq": policy_seq, "request_seq": self.request_seq, "hours": entries}
        if self.request_seq is not None:
            d.update(through=self.through, final=bool(final))
        return d


CHANGED, CLEAN, FINISHED = "changed", "clean", "finished"


def _next_hot_hours(db, scope: Scope, cursor: datetime, limit: int = 48) -> List[datetime]:
    """The hours of rows the conditions select from ``cursor`` on, within the UTC day of the first such row: each
    transaction reads one day's rows, never the whole table (the first is found in the timestamp's order)."""
    from app.core import audit_archive as arc
    from app.core import audit_chain_prune as prune_mod
    from app.core.models import AuditLog as A
    if not scope.conditions:
        return []
    first = (db.query(A.timestamp).filter(*scope.conditions, A.timestamp >= cursor, A.timestamp < scope.before)
             .order_by(A.timestamp).limit(1).scalar())
    if first is None:
        return []
    start = _ai().hour_floor(first)
    end = min(arc.day_start(start.date()) + timedelta(days=1), scope.before)
    return prune_mod._hours_matching(db, list(scope.conditions) + [A.timestamp >= start], end, limit)


def step(p, w, scope: Scope, cursor: datetime) -> tuple:
    """One transaction of a run: (outcome, the new cursor, rows changed, oldest, newest, the unit: "day" for an
    archived day, "hours" for hours of rows, None when FINISHED). The rows and archived days before ``cursor`` are
    done; the earliest of the next archived day and the next hours of rows goes next. Writes a rewrite seal only when
    it returns CHANGED. Raises NotRewritten."""
    from app.core import audit_archive as arc
    view = w.st.view
    newest = view.newest_policy()
    days = [d for d, e in sorted(view.archives.items())
            if e.parts and arc.day_start(d) < scope.before and arc.day_start(d) + timedelta(days=1) > cursor]
    hot = _next_hot_hours(w.db, scope, cursor)
    first_day = arc.day_start(days[0]) if days else None
    if first_day is not None and (not hot or first_day <= hot[0]):
        day = days[0]
        end = min(arc.day_start(day) + timedelta(days=1), scope.before)
        try:
            rw = rewrite_archived_day(w, day, scope.change, now=p.now, before=scope.before)
        except NotRewritten as nr:
            nr.until = nr.until or end
            raise
        if rw is None:
            return CLEAN, end, 0, None, None, "day"
        seal = w.append("rewrite", detail=scope.detail(newest[0], rw.entries))
        arc.seal_rewrite(w, day, seal.seq, rw, p.now)
        return CHANGED, end, rw.changed, rw.oldest, rw.newest, "day"
    if not hot:
        return FINISHED, cursor, 0, None, None, None
    day = hot[0].date()
    entries, changed, reached = [], 0, cursor
    for hour in hot:
        if hour.date() != day or changed >= p.batch_rows:
            break
        try:
            if view.archived_part(hour) is not None:
                # Rows in an archived hour: no legitimate path writes them (the pruner reports them too).
                raise NotRewritten(f"rows of audit_logs are in {fmt.hour_text(hour)}, which is archived; nothing "
                                   "was rewritten", "row-in-archived-day")
            # Each hour in a savepoint: an hour that cannot be rewritten leaves nothing behind, and the hours before
            # it are sealed now; it is met again, first, by the next transaction.
            with w.db.begin_nested():
                n, entry = rewrite_hour(w, hour, scope.change, now=p.now, before=scope.before)
        except NotRewritten as nr:
            if entries:
                break
            nr.until = nr.until or hour + HOUR
            raise
        reached = hour + HOUR
        if entry is not None:
            entries.append(entry)
            changed += n
    if not entries:
        return CLEAN, reached, 0, None, None, "hours"
    w.append("rewrite", detail=scope.detail(newest[0], entries))
    hours = [fmt.parse_time_text(e[0]) for e in entries]
    return CHANGED, reached, changed, min(hours), max(hours) + HOUR, "hours"


# --------------------------------------------------------------------------- keeping full addresses for N days

_cursors: Dict[tuple, datetime] = {}
_EPOCH = datetime(1970, 1, 1)


def full_days(st) -> Optional[int]:
    """The days an address stays in full, as the chain gives them (the honoured state's and the newest policy seal's,
    the longer of the two), or None for no limit, or when the chain cannot give them (then nothing is shortened)."""
    from app.core import audit_chain_policy as pol
    from app.core import audit_chain_policy_seals as ps
    values = ps.numbers(st)
    if values is None:
        return None
    days = []
    for value in (values.get(FULL_DAYS_KEY, 0), pol.value_of(st.view.newest_state(), FULL_DAYS_KEY)):
        if not isinstance(value, int) or isinstance(value, bool) or value <= 0:
            return None
        days.append(value)
    return max(days)


def shorten_job(p):
    """The pruner's audit_ip_shortening job: addresses whose rows are older than audit_ip_full_days shortened, through
    rewrite seals of reason shorten-ip. Returns a retention.JobResult (the rows changed, as cleared)."""
    from app.core import person_erase as pe
    from app.core import retention
    from app.core.models import AuditLog
    ai = _ai()
    ap = _ap()
    result = retention.JobResult()
    st = ai.state()
    if st.stopped is not None or not st.view.position or st.view.newest_policy() is None:
        return result
    days = full_days(st)
    if days is None:
        return result
    why = st.holds_deletion()
    if why:
        ai._say(f"The pruner's audit_ip_shortening job shortens nothing: {why}")
        return result
    engine = ai._engine_of(p.session_factory)
    key = (id(st), st.view.generation)
    conditions = prefilter(AuditLog, {ap.IP: ap.SHORTENED})
    findings: Dict[str, str] = {}
    while p.time_left():
        before = ai.hour_floor(min(p.now, st.clock()) - timedelta(days=days))
        cursor = _cursors.get(key, _EPOCH)
        if cursor >= before:
            break
        outcome = None
        with ai.ChainWriter(engine, st) as w:
            if w.st.holds_deletion():
                break
            waits = pe.rule_waits(w.db, p.now)
            if waits:
                ai._say(f"The pruner's audit_ip_shortening job waits: {waits}")
                break
            try:
                outcome, cursor, changed, oldest, newest, _unit = step(
                    p, w, Scope(SHORTEN, before, shortened, conditions), cursor)
            except NotRewritten as nr:
                w.written = []
                w.db.rollback()
                if not nr.kind or nr.until is None:
                    ai._say(f"The pruner's audit_ip_shortening job waits: {nr}")
                    break
                # A finding: the unit is left as it is (reported), and the run goes on after it, as the audit
                # job's prune does; this process tries it again after a restart.
                findings[nr.kind] = f"{nr}; its addresses were not shortened"
                outcome, cursor, changed = CLEAN, nr.until, 0
            if outcome == CHANGED:
                batch = retention.JobResult()
                batch.cleared = changed
                batch.oldest, batch.newest = oldest, newest
                p.record(w.db, batch, AuditLog.__tablename__)
            else:
                w.written = []
                w.db.rollback()
        if outcome == FINISHED:
            # Every row and archived day before the cutoff is done: the next pass reads only what has aged since.
            _cursors[key] = before
            break
        _cursors[key] = cursor
        result.cleared += changed
    if findings:
        ai.report_failures(st, p.session_factory, findings)
    return result


# --------------------------------------------------------------------------- what audit verify checks (step 4)

def removal_scope(request: Mapping) -> Tuple[Dict[str, str], datetime]:
    """(levels, before) of a removal's request seal: every kind's level, at least one below full, and the hour
    boundary its rows lie before. Raises ValueError for one that is not well formed."""
    ap = _ap()
    new = request.get("new")
    if not isinstance(new, dict) or set(new) != {"levels", "before"}:
        raise ValueError("a removal's scope is its levels and the time its rows lie before")
    levels = new["levels"]
    if not isinstance(levels, dict) or set(levels) != set(ap.POLICY_KEYS):
        raise ValueError("a removal names a level for each kind")
    for key, level in levels.items():
        if level not in ap.CHOICES[key]:
            raise ValueError(f"{level!r} is not a level of {key}")
    if all(level == ap.FULL for level in levels.values()):
        raise ValueError("a removal with every level full removes nothing")
    before = fmt.parse_time_text(new["before"])
    if before != _ai().hour_floor(before):
        raise ValueError("a removal's rows lie before an hour boundary")
    return dict(levels), before


def removal_request_problem(d: Mapping, sealed_at: datetime) -> Optional[str]:
    """Why a removal's request seal is not well formed, or None. Its rows are those written before the end of the
    hour it was sealed in."""
    if any(d.get(f) is not None for f in ("setting", "old", "subject", "placeholder")):
        return "a removal request naming a setting, an old value or an erase's fields"
    try:
        _levels, before = removal_scope(d)
    except (TypeError, ValueError) as why:
        return f"a removal request that is not well formed ({why})"
    if before != _ai().hour_floor(sealed_at) + HOUR:
        return "a removal request whose rows do not end with the hour it was asked in"
    return None


def rewrite_problem(view, seal) -> Optional[str]:
    """Step 4 for a rewrite seal, beyond what every prune or rewrite seal is held to (each hour follows its root seal
    and keeps its stable root and ids; one day; the policy seal in force; outside a restore's grace): a shortening of
    addresses only while full addresses are kept for a number of days, over hours that many days old; a removal's
    seals only while it is pending, from its delay on, over its own scope, the last one final and with no hour."""
    from app.core import audit_chain_policy as pol
    d = seal.detail if isinstance(seal.detail, dict) else {}
    reason, hours = d.get("reason"), d.get("hours") or []
    try:
        starts = [fmt.parse_time_text(h[0]) for h in hours]
    except (TypeError, ValueError, IndexError):
        return "a rewrite seal with a bad hour"
    if reason == SHORTEN:
        if any(f in d for f in ("through", "final")) or d.get("request_seq") is not None:
            return "a shortening of addresses naming a request"
        if not hours:
            return "a rewrite seal with no hours"
        newest = view.newest_policy()
        days = pol.value_of((newest[1].get("state") or {}) if newest else {}, FULL_DAYS_KEY)
        if not isinstance(days, int) or isinstance(days, bool) or days <= 0:
            return "a shortening of addresses while full addresses are kept with no limit"
        if any(h + HOUR > seal.sealed_at - timedelta(days=days) for h in starts):
            return "a shortening of addresses in rows younger than the days they are kept in full"
        return None
    if reason != LEVELS:
        return "a rewrite seal for no reason a rewrite has"
    req_seq = d.get("request_seq")
    req = view.requests.get(req_seq) if isinstance(req_seq, int) and not isinstance(req_seq, bool) else None
    if req is None or req.get("what") != "removal":
        return "a rewrite seal for levels that names no removal"
    if req_seq not in view.pending_requests():
        return "a rewrite seal for a removal that is not pending"
    try:
        _levels, before = removal_scope(req)
        not_before = fmt.parse_time_text(req.get("not_before"))
    except (TypeError, ValueError):
        return "a rewrite seal for a removal that is not well formed"
    if d.get("through") != fmt.hour_text(before - HOUR) or not isinstance(d.get("final"), bool):
        return "a rewrite seal whose scope is not its removal's"
    if req_seq not in view.rewrite_through and seal.sealed_at < not_before + pol.gaps_after(view.times, req_seq,
                                                                                           seal.sealed_at):
        return "a removal before its request's delay has run"
    if d["final"] and hours:
        return "a removal's last seal that rewrites hours"
    if not d["final"] and not hours:
        return "a rewrite seal with no hours"
    if any(h >= before for h in starts):
        return "a rewrite seal for an hour after its removal's scope"
    return None
