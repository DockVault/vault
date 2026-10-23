"""Accepting a restored audit chain on the host (``dockvault.py audit accept-database-head``, ``accept-restore``).

``accept-database-head`` is for a database whose chain does not reach the head record (a database restored on
its own from an older dump, or a tail cut by someone with database access, which look the same), and for a
lost head record. In its read phase it:

- authenticates the database's chain: every link recomputed from seal 1, every MAC checked under its key where
  that key is held, and the newest seal's MAC under the key in force there, which through the links
  authenticates every body before it; it refuses on any MAC that fails, and on any seal under a key it lacks
  that no later key seal covers;
- says where the database's chain stops matching the recorded one (every link the head record keeps: every
  64th seal, the hour summaries' seals, the daily check's clean position, the key seals of the key history,
  the retention checkpoints, the recorded head): a genuine older copy is a prefix of the recorded chain; a
  recorded link that differs at a seq the database holds means its chain was rewritten from there;
- says when the database's chain ends under a key the recorded chain had left (anyone holding it could have
  written everything after the point where the chains part);
- says whether seals were deleted, not lost with an older copy: a row the database holds, dated more than ten
  minutes after a lost seal's sealed_at (and not after the newest time the head record knows of, so the rows
  the server wrote after the restore are no evidence), shows the copy was taken after that seal;
- compares every lost hour the head record summarises with its rows (count, both roots, ids digest), and each
  older lost day with the day's digest, naming every hour or day whose rows changed;
- says what the restore loses from the retention checkpoints: the newest policy state, the cancels of requests
  the database shows pending (when the request's link is the one recorded), the erases that had completed, and
  offers to seal the lost cancels and the lost settings that delete later than the accepted chain's again, in
  their honoured form, as host seals right after the restore seal (both only keep more);
- prints the accepted chain's retention state entry by entry, flagging every env seal whose inputs differ from
  the current .env.

What it asks to confirm by name (a rewritten chain, deleted seals, a key the chain had left, the key history
with no head record) the write phase takes with ``--confirm``. It then writes a ``restore`` seal (cause
database) under the database chain's key in force, with its grace, the hours and what was lost, raises the
head record's generation and writes a new record keeping the earlier generations' key history, links and
completed erases. If the database holds no seal at all, it writes a new genesis naming the lost head.

``accept-restore`` is the last step of ``dockvault.py restore``: it reads the restore mark, says what the
restore undid from the record it replaced, writes a ``restore`` seal (cause backup) that acknowledges the
seals of the backup's window (written between its keys archive and its database part, accepted at the first
start after the mark), folds the replaced record's key history, links and completed erases into the new one,
and removes the mark.
"""
from __future__ import annotations

from datetime import datetime, timedelta
from typing import Dict, List, Optional, Tuple

from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_keys as keys
from app.core import audit_chain_policy as pol
from app.core.audit_chain_host import Refused, check_expected, digest, host_audit_row, token

RESTORED_ACTION = "audit_chain_restored"
DELETED_MARGIN = timedelta(minutes=10)
STOP_KINDS = ("head-record-mismatch", "head-record-missing", "key-not-current", "key-unverified", "key-sequence",
              "seq-gap", "link-broken", "after-record-invalid", "host-seal-unrecorded")


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _order(record):
    from app.core.audit_head_record import order
    return order(record)


# --------------------------------------------------------------------------- the database's own chain

def database_chain(db, held: Dict[str, keys.ChainKey], generation: int):
    """The view of the database's chain from seal 1, authenticated by its MACs alone: (view, problems,
    lines). Refuses (problems) on a seq gap, a break of the key sequence, a MAC that fails under a held key,
    a seal under a key no later verified key seal covers, or a newest seal whose MAC does not verify under the
    key in force there."""
    ai = _ai()
    view = ai.View()
    view.reset(generation, 0)
    problems, uncovered = [], []
    newest = None
    for seal in ai.read_seals(db, 0):
        if seal.seq != view.position + 1:
            problems.append(f"the seals jump from {view.position} to {seal.seq}")
            break
        link = fmt.link(view.link_at(seal.seq - 1), seal.body())
        ks = ai.key_sequence_problem(view, seal)
        if ks:
            problems.append(ks)
        k = held.get(seal.key_id)
        if k is None:
            uncovered.append(seal.seq)
        elif not ai._mac_ok(k.key, link, seal.mac):
            problems.append(f"seal {seal.seq}'s MAC does not verify (mac-invalid)")
        elif seal.kind == "key":
            uncovered = []          # only a key seal whose own MAC verified covers the seals before it
        view.accept(seal, link)
        newest = seal
    if uncovered:
        problems.append(f"{len(uncovered)} seals (from {uncovered[0]}) are under a key this command does not hold, "
                        "and no later key seal covers them: give it with --old-key-file")
    if newest is not None:
        # Defence in depth: the checks above already refuse a newest seal under a key not held (uncovered, as no
        # key seal follows it) or whose MAC fails; this states the rule the command rests on in one place.
        k = held.get(view.key_in_force())
        if k is None or not ai._mac_ok(k.key, view.link_at(view.position), newest.mac):
            problems.append(f"the newest seal ({view.position}) does not verify under the key in force there "
                            f"({view.key_in_force()}): the database's chain cannot be authenticated")
    return view, problems


def recorded_links(record: dict) -> Dict[int, Tuple[str, str]]:
    """{seq: (link, where the head record keeps it)} of the current generation."""
    gen = int(record.get("generation") or 1)
    out: Dict[int, Tuple[str, str]] = {}
    for key, link in (record.get("links") or {}).items():
        g, _, s = str(key).partition(":")
        if s and g.isdigit() and int(g) == gen:
            out[int(s)] = (link, "the link history")
    for hour, e in (record.get("hours") or {}).items():
        if e.get("seq") and e.get("link") and int(e.get("generation") or gen) == gen:
            out.setdefault(int(e["seq"]), (e["link"], f"the summary of {hour}"))
    check = record.get("check") or {}
    if check.get("clean_seq") and check.get("clean_link"):
        out.setdefault(int(check["clean_seq"]), (check["clean_link"], "the daily check's clean position"))
    for e in record.get("keys") or []:
        if int(e.get("generation") or 0) == gen and e.get("link") and e.get("from_seq"):
            out.setdefault(int(e["from_seq"]), (e["link"], f"the key seal of {e.get('key_id')}"))
    cp = record.get("checkpoints") or {}
    if (cp.get("policy") or {}).get("link") and int((cp.get("policy") or {}).get("generation") or gen) == gen:
        out.setdefault(int(cp["policy"]["seq"]), (cp["policy"]["link"], "the newest policy seal"))
    for c in cp.get("cancels") or []:
        if int(c.get("generation") or 0) == gen and c.get("request_link"):
            out.setdefault(int(c["request_seq"]), (c["request_link"], "a cancelled request"))
    if record.get("seq") and record.get("link"):
        out[int(record["seq"])] = (record["link"], "the recorded head")
    return out


def parting(view, record: dict) -> dict:
    """Where the database's chain stops matching the recorded one."""
    last_match, first_mismatch, where = None, None, None
    for seq, (link, src) in sorted(recorded_links(record).items()):
        if seq > view.position:
            continue
        if view.link_at(seq).hex() == link:
            last_match = seq
        elif first_mismatch is None:
            first_mismatch, where = seq, src
    return {"last_match": last_match, "first_mismatch": first_mismatch, "where": where,
            "prefix": first_mismatch is None}


def lost_range(view, record: Optional[dict]) -> Tuple[Optional[int], Optional[int], Optional[str]]:
    """(lost_from_seq, lost_through_seq, lost_head): the recorded seals the database's chain does not hold. When
    the database's chain is a prefix of the recorded one, from the seal after its newest; when the two part, from
    the seal after the last recorded link that still matches (the parting point lies after it, and no seal
    before it differs), through the recorded head. (None, None, head) when nothing recorded is lost."""
    if not record or not record.get("seq") or not record.get("link"):
        return None, None, None
    seq = int(record["seq"])
    head = fmt.head(seq, bytes.fromhex(record["link"]))
    part = parting(view, record)
    first = view.position + 1 if part["prefix"] else (part["last_match"] or 0) + 1
    if first > seq:
        return None, None, head
    return first, seq, head


def left_key(view, record: dict) -> Optional[dict]:
    """The key the database's chain ends under, when the recorded chain had left it (in any generation)."""
    kid = view.key_in_force()
    entries = [e for e in record.get("keys") or [] if e.get("key_id") == kid and e.get("to_seq") is not None]
    if not entries or kid == record.get("key_id"):
        return None
    e = max(entries, key=lambda e: (int(e.get("generation") or 0), int(e.get("to_seq") or 0)))
    return {"key_id": kid, "left_at_seq": int(e["to_seq"]) + 1, "generation": int(e.get("generation") or 1)}


def deleted_through(db, view, record: dict) -> Tuple[Optional[int], Optional[str]]:
    """The newest lost seal a row shows was deleted rather than lost with an older copy, and that row's time."""
    from sqlalchemy import func
    from app.core.models import AuditLog as A
    known = []
    gen = int(record.get("generation") or 1)
    if record.get("seq") and record.get("sealed_at"):
        known.append((int(record["seq"]), fmt.parse_time_text(record["sealed_at"])))
    for e in (record.get("hours") or {}).values():
        if e.get("seq") and e.get("sealed_at") and int(e.get("generation") or gen) == gen:
            known.append((int(e["seq"]), fmt.parse_time_text(e["sealed_at"])))
    lost = [(s, t) for s, t in known if s > view.position]
    if not lost:
        return None, None
    bound = max(t for _s, t in known)
    out, evidence = None, None
    for seq, at in sorted(lost):
        row = db.query(func.max(A.timestamp)).filter(A.timestamp > at + DELETED_MARGIN,
                                                     A.timestamp <= bound + DELETED_MARGIN).scalar()
        if row is not None:
            out, evidence = seq, fmt.time_text(row)
    return out, evidence


def _expand(record: dict, gen: int) -> Dict[datetime, dict]:
    """The head record's hour summaries of the current generation, one entry an hour (runs expanded)."""
    out = {}
    for key, e in (record.get("hours") or {}).items():
        if int(e.get("generation") or gen) != gen and not e.get("unsealed"):
            continue
        try:
            start = fmt.parse_time_text(key)
            end = fmt.parse_time_text(e.get("end") or key)
        except (TypeError, ValueError):
            continue
        h = start
        while h < max(end, start + timedelta(hours=1)):
            single = dict(e)
            if end - start > timedelta(hours=1):
                single.update(count=0, root_s=fmt.EMPTY_ROOT.hex(), root_c=fmt.EMPTY_ROOT.hex(),
                              ids_digest=fmt.ids_digest([]).hex(), salt=None)
            out[h] = single
            h += timedelta(hours=1)
    return out


def lost_hours(db, view, record: dict, now: datetime) -> dict:
    """The lost hours compared with the head record: {lost, compared_from, changed, days_changed, lines,
    figures}."""
    ai = _ai()
    gen = int(record.get("generation") or 1)
    summaries = _expand(record, gen)
    start = view.newest_hour_end or view.first_hour()
    ends = [h + ai.HOUR for h in summaries]
    if record.get("newest_hour_end"):
        ends.append(fmt.parse_time_text(record["newest_hour_end"]))
    end = max(ends) if ends else None
    out = {"lost": None, "compared_from": None, "changed": [], "days_changed": [], "lines": [], "figures": []}
    if start is None or end is None or end <= start:
        return out
    out["lost"] = [fmt.hour_text(start), fmt.hour_text(end - ai.HOUR)]
    compared = []
    # Hours the summaries cover. A summary holds no salt (audit_integrity._summarise), so the personal values of
    # rows without a nonce cannot be compared: such an hour is compared by its stable root, as a day is; a salt
    # in a record an earlier build wrote is not used either, so one rule holds whatever the record's age.
    for h in sorted(x for x in summaries if start <= x < end):
        s = summaries[h]
        fig = ai.hour_figures(ai.iter_rows(db, h, h + ai.HOUR), None)
        personal = s.get("unsealed") or not fig.nonceless
        same = (fig.count == s.get("count") and fig.root_s.hex() == s.get("root_s")
                and fig.ids_digest.hex() == s.get("ids_digest")
                and (not personal or fig.root_c.hex() == s.get("root_c")))
        compared.append(h)
        out["figures"].append([fmt.hour_text(h), fig.count, fig.root_s.hex(), fig.ids_digest.hex()])
        if not same:
            out["changed"].append([fmt.hour_text(h), s.get("count"), fig.count])
    # Older lost days, by their digest.
    days = record.get("days") or {}
    day = start.date()
    first_summary = min(summaries) if summaries else end
    while datetime(day.year, day.month, day.day) < min(end, first_summary):
        d = days.get(day.isoformat())
        if d and int(d.get("generation") or gen) == gen:
            entries = []
            nonceless = False
            day_start = datetime(day.year, day.month, day.day)
            for i in range(24):
                h = day_start + i * ai.HOUR
                if view.first_hour() is not None and h < view.first_hour():
                    continue
                if h >= end:
                    break
                fig = ai.hour_figures(ai.iter_rows(db, h, h + ai.HOUR), None)
                nonceless = nonceless or bool(fig.nonceless)
                entries.append((h, h + ai.HOUR, fig.count, fig.root_s, fig.root_c, fig.ids_digest))
            if d.get("salted") or nonceless:
                now_digest = fmt.day_digest([(a, b, c, rs, None, i) for a, b, c, rs, _rc, i in entries]).hex()
                same = now_digest == d.get("stable")
            else:
                same = fmt.day_digest(entries).hex() == d.get("full")
            compared.append(day_start)
            out["figures"].append([day.isoformat(), same])
            if not same:
                out["days_changed"].append(day.isoformat())
        day += timedelta(days=1)
    if compared:
        out["compared_from"] = fmt.hour_text(min(compared))
    newest_row = None
    from sqlalchemy import func
    from app.core.models import AuditLog as A
    newest_row = db.query(func.max(A.timestamp)).filter(A.timestamp < end).scalar()
    for h, recorded, now_count in out["changed"]:
        hour = fmt.parse_time_text(h)
        honest = newest_row is not None and hour >= ai.hour_floor(newest_row) and now_count < (recorded or 0)
        out["lines"].append(f"  {h}: the head record summarised {recorded} rows, the database holds {now_count}"
                            + ("" if honest else " -- a change made while its seal was missing"))
    for d in out["days_changed"]:
        out["lines"].append(f"  {d}: the day's rows no longer give the digest the head record kept")
    return out


def archive_mismatch(db, view) -> List[str]:
    """The archive blocks whose day and part no archive seal of ``view`` names, with the length it binds, and the
    parts it names that have no such block: "<day> part <n>" each."""
    from app.core import audit_archive
    stored = audit_archive.stored_blocks(db)
    named = {(d, p.part): p.length for d, p in view.archived_parts()}
    out = [f"{d.isoformat()} part {n}" for (d, n), length in sorted(stored.items()) if named.get((d, n)) != length]
    out += [f"{d.isoformat()} part {n} (missing)" for (d, n) in sorted(named) if (d, n) not in stored]
    return out


def lost_retention(view, record: dict) -> dict:
    """What the head record's checkpoints say the accepted chain lacks: {policy, cancels, erases}."""
    cp = record.get("checkpoints") or {}
    out = {"policy": None, "cancels": [], "erases": []}
    policy = cp.get("policy")
    if policy and (int(policy["seq"]) > view.position or view.link_at(int(policy["seq"])).hex() != policy["link"]):
        out["policy"] = {"seq": int(policy["seq"]), "state": policy.get("state") or {},
                         "honoured": policy.get("honoured") or {}}
    pending = view.pending_requests()
    gen = int(record.get("generation") or 1)
    for c in cp.get("cancels") or []:
        r = int(c.get("request_seq") or 0)
        if int(c.get("generation") or 0) != gen or not (1 <= r <= view.position):
            continue
        if view.link_at(r).hex() != c.get("request_link") or r not in pending:
            continue
        if int(c.get("seq") or 0) <= view.position and view.cancels.get(r) == int(c["seq"]):
            continue
        out["cancels"].append([r, int(c.get("seq") or 0)])
    for e in cp.get("erases") or []:
        r = int(e.get("request_seq") or 0)
        if int(e.get("generation") or 0) == gen and r in view.finals and r <= view.position:
            continue
        out["erases"].append([e.get("request_id"), r, e.get("final_seq")])
    return out


def reseal_settings(view, lost: dict) -> Dict[str, dict]:
    """The lost settings that delete later than the accepted chain's, in their honoured form: {name: setting}."""
    if not lost.get("policy"):
        return {}
    newest = view.newest_policy()
    if newest is None:
        return {}
    state = newest[1].get("state") or {}
    specs = {s.key: s for s in pol.chain_specs()}
    out = {}
    for name, entry in (lost["policy"].get("state") or {}).items():
        if name not in specs:
            continue
        form = (lost["policy"].get("honoured") or {}).get(name) or entry
        if form.get("setting") is None or name not in state:
            continue
        if pol.deletes_sooner(specs[name], form, state[name]):
            out[name] = form.get("setting")
    return out


def unsuperseded_cancels(view, lost: dict, settings: Dict[str, object]) -> List[int]:
    """The lost cancels to seal again: those of requests the values sealed again do not supersede (a policy
    seal of cause restore setting a setting supersedes every request for it before it, and a cancel of a request
    that is not pending would fail verification for good)."""
    return [r for r, _c in lost["cancels"] if (view.requests.get(r) or {}).get("setting") not in settings]


def superseded_changes(db, view, settings: Dict[str, object]) -> List[list]:
    """The waiting changes the values sealed again supersede: [request seq, setting, change id] for each request
    the accepted chain holds pending for one of those settings whose change row the database shows waiting. The
    chain will never apply them, so their rows end as superseded in the transaction of the policy seal, as a
    newer change of the setting ends them on the panel; left waiting they would be shown as due for good."""
    from app.core import setting_changes
    from app.core.models import ManagedSettingChange as Change
    out = []
    for seq, d in sorted(view.pending_requests().items()):
        if d.get("what") != "setting" or d.get("setting") not in settings or not d.get("request"):
            continue
        try:
            change = db.get(Change, fmt.as_uuid(d.get("request")))
        except (TypeError, ValueError):
            change = None
        if change is not None and change.status == setting_changes.PENDING:
            out.append([seq, d.get("setting"), str(change.id)])
    return out


def restore_changes(settings: Dict[str, object], cancels: List[int], superseded: List[list]) -> dict:
    """What a restore changes in the retention settings, for its own audit row, so that the Activity page alone
    shows it: the values sealed again and stored in managed_settings, the requests whose lost cancels are sealed
    again, and the waiting changes those values supersede (their change rows end as superseded). The policy and
    cancel seals record the same in the chain."""
    return {"resealed": {k: v for k, v in sorted(settings.items())}, "resealed_cancels": list(cancels),
            "superseded": [c for _s, _n, c in superseded]}


def _superseded_lines(superseded: List[list]) -> List[str]:
    if not superseded:
        return []
    return ["Waiting changes the values sealed again supersede (their rows end as superseded): "
            + ", ".join(f"request {seq} ({name})" for seq, name, _c in superseded)]


def retention_lines(view) -> List[str]:
    newest = view.newest_policy()
    if newest is None:
        return ["  no policy seal"]
    lines = []
    current = pol.raw_inputs()
    for seq, d in view.policies:
        if d.get("cause") == "env" and (d.get("inputs") or {}) != current:
            lines.append(f"  env seal {seq}: its .env inputs are not the ones this server's .env gives")
    by_seq = {s: d for s, d in view.policies}
    for name, e in sorted((newest[1].get("state") or {}).items()):
        setter = by_seq.get(e.get("set_by")) or {}
        lines.append(f"  {name} = {e.get('value')!r} (setting {e.get('setting')!r}, source {e.get('source')}), set by "
                     f"seal {e.get('set_by')} ({setter.get('cause')} by {setter.get('by')})")
    return lines


def grace_days(view, *records) -> int:
    """The grace's length: the longest of the accepted chain's delay, the delay the records' checkpoints last
    saw (honoured where longer), and .env's."""
    days = [pol.delay_days(view.newest_state())]
    for rec in records:
        cp = ((rec or {}).get("checkpoints") or {}).get("policy") or {}
        days.append(pol.delay_days(cp.get("state") or {}))
        days.append(pol.delay_days({**(cp.get("state") or {}), **(cp.get("honoured") or {})}))
    try:
        days.append(int((pol.raw_inputs().get(pol.DELAY_INPUT) or "").strip() or 0))
    except ValueError:
        pass
    return max(d for d in days if d)


def _summaries_from(db, view, now: datetime) -> Dict[str, dict]:
    """Hour summaries of the last 30 days rebuilt from the accepted chain's seals (for the new generation)."""
    ai = _ai()
    out = {}
    floor = now - timedelta(days=30)
    for start, end, last in view.units():
        if end <= floor:
            continue
        seq = view.entry_chain(last)[-1][0]
        seal = ai.read_authenticated(db, view, seq)
        figures = ai.seal_figures(seal, start)
        if figures is None:
            continue
        count, _nb, rs, rc, idd = figures
        out[fmt.hour_text(start)] = {"end": fmt.hour_text(end), "seq": seq, "link": view.link_at(seq).hex(),
                                     "sealed_at": fmt.time_text(view.at(seq)), "count": count,
                                     "root_s": rs.hex() if rs else None, "root_c": rc.hex() if rc else None,
                                     "ids_digest": idd.hex() if idd else None, "salt": None, "unsealed": False,
                                     "generation": view.generation}
    return out


def _confirm_missing(needed: List[str], given: List[str]) -> List[str]:
    return [n for n in needed if n not in set(given or [])]


# --------------------------------------------------------------------------- accept-database-head

def accept_database_head(engine, st, *, old_key: Optional[bytes] = None, confirm: Optional[List[str]] = None,
                         reseal: bool = True, expect: Optional[str] = None, read: bool = False) -> dict:
    """See the module's docstring. Raises Refused."""
    ai = _ai()
    from app.core.audit_chain_recovery import _held
    with ai.ChainWriter(engine, st, wait=30, writer="host", check_chain=False, snapshot=True) as w:
        now = w.st.clock()
        record = w.record if (w.record and w.record.get("link")) else None
        try:
            has_file = w.st.head_store().exists()
        except Exception:  # noqa: BLE001
            has_file = False
        gen = int((w.record or {}).get("generation") or 1)
        held = _held(w.st, old_key)
        view, problems = database_chain(w.db, held, gen + 1)
        lines: List[str] = []
        needed: List[str] = []
        if problems:
            raise Refused("the database's chain cannot be accepted: " + "; ".join(problems))
        if record is not None and view.position >= int(record.get("seq") or 0) and \
                view.link_at(int(record["seq"])).hex() == record["link"]:
            raise Refused("the database's chain reaches the head record: nothing to accept (for seals after it, "
                          "use after-record)")
        part = parting(view, record) if record else {"prefix": None}
        under = left_key(view, record) if record else None
        deleted, evidence = deleted_through(w.db, view, record) if record else (None, None)
        hours = lost_hours(w.db, view, record, now) if record else {"lost": None, "compared_from": None,
                                                                     "changed": [], "days_changed": [],
                                                                     "lines": [], "figures": []}
        lost = lost_retention(view, record) if record else {"policy": None, "cancels": [], "erases": []}
        settings = reseal_settings(view, lost) if reseal else {}
        cancels = unsuperseded_cancels(view, lost, settings) if reseal else []
        superseded = superseded_changes(w.db, view, settings)
        if under:
            lines.append(f"THE DATABASE'S CHAIN ENDS UNDER {under['key_id']}, A KEY THE RECORDED CHAIN LEFT AT SEAL "
                         f"{under['left_at_seq']}: anyone holding it could have written everything after the point "
                         "where the two chains part. Sealing then waits for audit rekey, with its confirmation.")
            needed.append(f"left-key-{under['key_id']}")
        if record is None:
            lines.append("There is no head record to compare with: this command cannot tell another writer's seals "
                         "from the server's. Check the key history below.")
            lines += [f"  key {k} from seal {f} to {t or 'now'}" for k, f, t in view.key_history]
            needed.append("key-history-" + digest([list(e) for e in view.key_history])[:8])
        else:
            lines.append(f"The head record: seal {record.get('seq')} under {record.get('key_id')}; the database's "
                         f"chain ends at seal {view.position}.")
            if part["prefix"] and part["last_match"] is None:
                lines.append("The database holds none of the recorded seals.")
            elif part["prefix"]:
                lines.append(f"The database's chain is a prefix of the recorded one (every recorded link it holds "
                             f"matches, the last at seal {part['last_match']}): an older copy.")
            else:
                lines.append(f"THE CHAINS PART: the recorded link of seal {part['first_mismatch']} ({part['where']}) "
                             f"is not the database's; the last that matches is seal {part['last_match']}. The "
                             "database's chain was rewritten from there by someone holding the key in force then, "
                             "or it comes from another install.")
                needed.append(f"rewritten-from-{part['first_mismatch']}")
            if deleted is not None:
                lines.append(f"SEALS WERE DELETED, not lost with an older copy: the database holds a row dated "
                             f"{evidence}, more than ten minutes after seal {deleted} was written. (A clock that ran "
                             "fast and was stepped back can explain it; the chain shows no such step only if no "
                             "sealed-at-backwards warning was seen.)")
                needed.append(f"deleted-through-{deleted}")
        if hours["lost"]:
            lines.append(f"Hours {hours['lost'][0]} to {hours['lost'][1]} will be sealed again from their rows as they "
                         f"stand; compared from {hours['compared_from'] or 'nothing'}:")
            lines += hours["lines"] or ["  every lost hour compared gives what the head record kept"]
        blocks = archive_mismatch(w.db, view)
        if blocks:
            lines.append(f"{len(blocks)} archive blocks are not the ones the accepted chain's archive seals name "
                         f"(lost with their seals, or added): audit verify will report them, and their days' rows are "
                         f"in no block a seal binds: " + ", ".join(blocks[:10]))
        if lost["policy"]:
            lines.append(f"Lost: the newest policy seal ({lost['policy']['seq']}) and the state it set.")
        for r, c in lost["cancels"]:
            lines.append(f"Lost: the cancel ({c}) of request {r}, which the database shows pending again.")
        for rid, r, f in lost["erases"]:
            lines.append(f"Lost: the completed erase or removal {rid} (request {r}, final {f}): request it again.")
        if settings:
            lines.append("Sealed again right after the restore seal (they only keep more): "
                         + ", ".join(f"{k} = {v!r}" for k, v in sorted(settings.items())))
        if cancels:
            lines.append("Cancels sealed again: requests " + ", ".join(map(str, cancels)))
        lines += _superseded_lines(superseded)
        grace = grace_days(view, record)
        lines.append(f"Nothing is deleted for {grace} days of running time after the restore seal. Cancels, holds and "
                     "requests made after the database's newest seal are lost and must be made again.")
        lines.append("The accepted chain's retention state:")
        lines += retention_lines(view)
        state = {"command": "accept-database-head", "db_head": fmt.head(view.position, view.link_at(view.position))
                 if view.position else None, "record": list(_order(record)) if record else None,
                 "file": bool(has_file), "part": part, "under": under, "deleted": deleted,
                 "hours": [hours["lost"], hours["changed"], hours["days_changed"], digest(hours["figures"])],
                 "lost": lost, "reseal": [sorted(settings.items()), cancels, superseded], "needed": needed,
                 "blocks": blocks}
        if read:
            return {"state": token(state), "lines": lines, "confirm": needed}
        check_expected(state, expect)
        missing = _confirm_missing(needed, confirm)
        if missing:
            raise Refused("confirm by name first: " + ", ".join(missing))
        lost_from, lost_through, lost_head = lost_range(view, record)
        restored = {"cause": "database", "lost_from_seq": lost_from, "lost_through_seq": lost_through,
                    "lost_head": lost_head,
                    "record_missing": record is None, "under_left_key": under, "acknowledges": [],
                    "hours": {"lost": hours["lost"], "compared_from": hours["compared_from"],
                              "changed": hours["changed"], "days_changed": hours["days_changed"],
                              "deleted_through_seq": deleted},
                    "lost": {"policy": lost["policy"], "cancels": lost["cancels"], "erases": lost["erases"]},
                    "by": "host"}
        host_audit_row(w.db, RESTORED_ACTION, {"cause": "database", "lost_through_seq": restored["lost_through_seq"],
                                               "deleted_through_seq": deleted,
                                               **restore_changes(settings, cancels, superseded)})
        w.st.view = view
        w.st.own.clear()
        w.st.pending_after = []
        was_empty = view.position == 0
        if was_empty:
            seal = ai.write_genesis(w, now, replaces=restored["lost_head"] or "unknown", grace_days=grace)
        else:
            k = held.get(view.key_in_force())
            seal = w.append("restore", detail=lambda seq, at: {**restored, "grace_until": fmt.time_text(
                at + timedelta(days=grace))}, key=k)
            if settings:
                _append_restore_policy(w, settings, superseded, key=k)
        summaries = _summaries_from(w.db, view, now) if view.position else {}
        carried = _carried_after_record(record, view) if record else []
        w.after_record_change = _new_generation(view, summaries, carried, now)
    if was_empty:
        from app.core import audit_chain_policy_seals as ps
        ps.write_genesis_policy(engine, st, now)
    if cancels:
        _reseal_cancels(engine, st, cancels)
    return {"restored": seal.seq, "generation": w.st.view.generation, "grace_days": grace,
            "resealed": sorted(settings), "cancels": cancels, "superseded": [c for _s, _n, c in superseded]}


def _append_restore_policy(w, settings: Dict[str, object], superseded: List[list], key) -> None:
    """A policy seal of cause restore by the host, right after the restore seal, setting the lost values that
    keep more; and each value stored in managed_settings in the same transaction, as after any change: the
    restored database's own value, older and deleting sooner, would otherwise be one the chain does not allow
    (unjustified-input). The waiting changes it supersedes (``superseded_changes``) end as superseded."""
    from app.core import setting_changes
    from app.core.models import ManagedSettingChange as Change
    from app.core import audit_chain_policy_seals as ps
    from app.core import settings_registry as registry
    from app.core.credential_changes import HOST_OPERATOR
    view = w.st.view
    newest = view.newest_policy()
    state = {n: dict(e) for n, e in (newest[1].get("state") or {}).items()}
    inputs = newest[1].get("inputs") or {}
    ns = pol.settings_from_inputs(inputs)
    specs = {s.key: s for s in pol.chain_specs()}
    seq = view.position + len(w.written) + 1
    for name, setting in settings.items():
        ps._set(state, name, ps.setting_fields(specs[name], setting, ns, inputs, seq), seq)
    w.append("policy", detail=ps._policy_detail(state, inputs, "restore", by="host"), key=key)
    for name, setting in settings.items():
        try:
            registry.store(w.db, name, setting, by_name=HOST_OPERATOR, now=w.st.clock())
        except registry.SettingRefused:
            continue      # one .env now locks or keeps from the panel: the chain's entry holds it alone
    for _seq, _name, change_id in superseded:
        change = w.db.get(Change, fmt.as_uuid(change_id))
        if change is not None and change.status == setting_changes.PENDING:
            setting_changes._end(change, setting_changes.SUPERSEDED, by_id=None, by_name=HOST_OPERATOR,
                                 now=w.st.clock(), reason="a value sealed again after a restore")


def _reseal_cancels(engine, st, requests: List[int]) -> None:
    """The lost cancels sealed again by the host, one per transaction, under the key in force (which may be one
    the chain is to move off: rekey then follows), each with its change row ended in the same transaction: the
    restored database shows it waiting again, and a row left waiting would be offered for a cancel the chain
    no longer accepts."""
    from app.core import setting_changes
    from app.core.credential_changes import HOST_OPERATOR
    from app.core.models import ManagedSettingChange as Change
    ai = _ai()
    for r in requests:
        with ai.ChainWriter(engine, st, wait=30, writer="host", check_key=False) as w:
            if r not in w.st.view.pending_requests():
                continue
            d = w.st.view.requests.get(r) or {}
            key = w.st.keys_held().get(w.st.view.key_in_force())
            w.append("cancel", detail={"cancels": r, "request": d.get("request"), "audit_row": None, "by": "host",
                                       "user_id": None}, key=key)
            change = w.db.get(Change, fmt.as_uuid(d.get("request"))) if d.get("request") else None
            if change is not None and change.status == setting_changes.PENDING:
                setting_changes._end(change, setting_changes.CANCELLED, by_id=None, by_name=HOST_OPERATOR,
                                     now=w.st.clock(), reason="cancelled again after a restore")


def _carried_after_record(record: dict, view) -> List[dict]:
    """The seals the record listed as another writer's and not acknowledged that the accepted chain still holds
    with the same link: they keep that status and their acceptance time in the new generation."""
    gen = int(record.get("generation") or 1)
    out = []
    for e in record.get("after_record") or []:
        if e.get("generation") != gen or e.get("acknowledged") or e.get("discarded"):
            continue
        seq = int(e.get("seq") or 0)
        if 1 <= seq <= view.position and view.link_at(seq).hex() == e.get("link"):
            moved = dict(e)
            moved["generation"] = view.generation
            out.append(moved)
    return out


def _new_generation(view, summaries: Dict[str, dict], carried: List[dict], now: datetime):
    """The head record of the new generation: the earlier generations' key history, links, completed erases
    and seals kept (the merge unions them), the hour summaries rebuilt from the accepted chain, the day
    digests computed afresh, the stop's failures acknowledged."""
    def change(rec):
        rec["generation"] = view.generation
        rec["hours"] = {**{k: v for k, v in (rec.get("hours") or {}).items()
                           if int(v.get("generation") or 0) == view.generation}, **summaries}
        rec["days"] = {}
        rec["days_through"] = None
        rec["check"] = {}
        rec["view_warnings"] = {}
        rec.setdefault("after_record", []).extend(carried)
        stamp = fmt.time_text(now)
        for kind in STOP_KINDS:
            entry = (rec.get("failures") or {}).get(kind)
            if entry is not None:
                entry["acknowledged_at"] = stamp
            warn = (rec.get("warnings") or {}).get(kind)
            if warn is not None:
                warn["acknowledged_at"] = stamp
        rec["status"] = {"outcome": "acknowledged", "at": stamp, "kinds": []}
        rec["restore"] = {"at": stamp, "generation": view.generation}
        return rec
    return change


# --------------------------------------------------------------------------- accept-restore

def first_start_entries(record: dict, mark_at: datetime, generation: int, restored: Optional[set] = None) -> List[int]:
    """The seals after the restored record that the first start after the mark accepted (the web process's start
    walk; or this command's own acceptance, when no process has read the chain since the mark). ``restored``:
    the (generation, seq) of the seals the restored record already listed, which are never the first start's,
    whatever the clocks of the host (the mark's time) and the server (the acceptance's) say."""
    restored = restored or set()
    entries = [e for e in record.get("after_record") or [] if e.get("generation") == generation
               and (e.get("generation"), e.get("seq")) not in restored
               and not e.get("discarded") and e.get("accepted_at")
               and fmt.parse_time_text(e["accepted_at"]) >= mark_at]
    starts = [e for e in entries if e.get("where") in ("start", "host") and e.get("process_started_at")]
    if not starts:
        return []
    first = min(fmt.parse_time_text(e["process_started_at"]) for e in starts)
    return sorted(int(e["seq"]) for e in starts if fmt.parse_time_text(e["process_started_at"]) == first)


def accept_restore(engine, st, *, reseal: bool = True, expect: Optional[str] = None, read: bool = False) -> dict:
    """See the module's docstring. Raises Refused."""
    ai = _ai()
    from app.core import audit_head_record as hr
    with ai.ChainWriter(engine, st, wait=30, writer="host", check_key=False, snapshot=True) as w:
        now = w.st.clock()
        mark = w.st.restore_mark()
        if mark is None:
            raise Refused("there is no restore mark: nothing to accept")
        if mark.get("unreadable"):
            raise Refused(f"the restore mark cannot be read ({mark['unreadable']}): remove it by hand once you have "
                          "checked the restore")
        view, record = w.st.view, w.record or {}
        replaced = mark.get("record") or None
        try:
            mark_at = fmt.parse_time_text(mark.get("at"))
        except (TypeError, ValueError):
            mark_at = now
        # The seals the restored record did not list, accepted at the first start after the mark (or now).
        before = {(e.get("generation"), e.get("seq")) for e in ((mark.get("restored_record") or {}).get("after_record")
                                                                  or [])}
        window = first_start_entries(record, mark_at, view.generation, before)
        lines = [f"The restore of {mark.get('bundle') or 'a backup'} (marked {mark.get('at')})."]
        if window:
            lines.append("Seals written between the backup's keys archive and its database part, which this "
                         "acknowledges:")
            for seq in window:
                lines += ["  " + ln for ln in host.describe_seal(view, record, seq, now)]
        kept = sorted(s for s, e in ai.foreign_entries(view, record).items() if not e.get("acknowledged")
                      and s not in window)
        if kept:
            lines.append("Seals another writer appended that stay warnings until the host acknowledges them: "
                         + ", ".join(map(str, kept)))
        under = left_key(view, replaced) if replaced else None
        lost = lost_retention(view, replaced) if replaced and replaced.get("link") else \
            {"policy": None, "cancels": [], "erases": []}
        settings = reseal_settings(view, lost) if reseal else {}
        cancels = unsuperseded_cancels(view, lost, settings) if reseal else []
        superseded = superseded_changes(w.db, view, settings)
        if under:
            lines.append(f"THE RESTORED CHAIN IS UNDER {under['key_id']}, WHICH THE REPLACED RECORD HAD LEFT: the "
                         "bundle's .env brought it back, so anyone holding it can write seals again. Set a new "
                         "AUDIT_CHAIN_KEY.")
        if lost["policy"]:
            lines.append(f"Undone by the restore: the policy state of seal {lost['policy']['seq']}.")
        for r, c in lost["cancels"]:
            lines.append(f"Undone by the restore: the cancel ({c}) of request {r}, pending again.")
        for rid, r, f in lost["erases"]:
            lines.append(f"Undone by the restore: the completed erase or removal {rid}: request it again.")
        if settings:
            lines.append("Sealed again right after the restore seal: "
                         + ", ".join(f"{k} = {v!r}" for k, v in sorted(settings.items())))
        if cancels:
            lines.append("Cancels sealed again: requests " + ", ".join(map(str, cancels)))
        lines += _superseded_lines(superseded)
        grace = grace_days(view, record, replaced)
        lines.append(f"Nothing is deleted for {grace} days of running time after the restore seal.")
        lines.append("The restored chain's retention state:")
        lines += retention_lines(view)
        from app.core import audit_chain_honour as honour
        for seq, d in sorted(view.pending_requests().items()):
            due = max(honour.effective_not_before(view, record, seq, now), now + timedelta(days=grace))
            lines.append(f"  pending request {seq}: {d.get('what')} {d.get('setting') or ''} -> {d.get('new')!r}, "
                         f"from {fmt.time_text(due)}")
        state = {"chain": host.chain_state(view, record), "command": "accept-restore", "mark": mark.get("at"),
                 "window": window, "kept": kept, "under": under, "lost": lost,
                 "reseal": [sorted(settings.items()), cancels, superseded]}
        if read:
            return {"state": token(state), "lines": lines}
        check_expected(state, expect)
        host_audit_row(w.db, RESTORED_ACTION, {"cause": "backup", "bundle": mark.get("bundle"),
                                               "acknowledges": window,
                                               **restore_changes(settings, cancels, superseded)})
        new_generation = max(int(record.get("generation") or 1), int((replaced or {}).get("generation") or 1)) + 1
        # The replaced record's seals the restored database does not hold: an anchor taken from them is
        # reported against this seal.
        lost_from, lost_through, lost_head = lost_range(view, replaced)
        detail = {"cause": "backup", "lost_from_seq": lost_from, "lost_through_seq": lost_through,
                  "lost_head": lost_head,
                  "record_missing": False, "under_left_key": under, "acknowledges": window,
                  "hours": {"lost": None, "compared_from": None, "changed": [], "days_changed": [],
                            "deleted_through_seq": None},
                  "lost": {"policy": lost["policy"], "cancels": lost["cancels"], "erases": lost["erases"]},
                  "by": "host"}
        key = w.st.keys_held().get(view.key_in_force())
        carried = [dict(e, generation=new_generation) for e in record.get("after_record") or []
                   if e.get("generation") == view.generation and int(e.get("seq") or 0) in kept]
        seal = w.append("restore", detail=lambda seq, at: {**detail, "grace_until": fmt.time_text(
            at + timedelta(days=grace))}, key=key)
        if settings:
            _append_restore_policy(w, settings, superseded, key=key)
        # The new generation: the restored chain's seals of the backup's window are the host's now (the restore
        # seal acknowledges them); another writer's seals the restored record listed keep that status.
        view.generation = new_generation
        w.st.pending_after = []

        def change(rec):
            from app.core.audit_head_record import _key_entry_id, _merge_lists, _seal_entry_id, merge_checkpoints
            rec["generation"] = max(int(rec.get("generation") or 1), new_generation)
            if replaced:
                rec["keys"] = _merge_lists(rec.get("keys") or [], replaced.get("keys") or [], _key_entry_id)
                rec["unverified_keys"] = _merge_lists(rec.get("unverified_keys") or [],
                                                      replaced.get("unverified_keys") or [], _seal_entry_id)
                for k, v in (replaced.get("links") or {}).items():
                    rec.setdefault("links", {}).setdefault(k, v)
                rec["checkpoints"] = merge_checkpoints(rec.get("checkpoints") or {},
                                                       {"erases": (replaced.get("checkpoints") or {}).get("erases")
                                                        or []})
            rec.setdefault("after_record", []).extend(carried)
            rec["days_through"] = None
            rec["restore"] = {"at": fmt.time_text(now), "cause": "backup", "bundle": mark.get("bundle")}
            return rec
        w.after_record_change = change
    unsure = None
    try:
        hr.remove_mark(st.head_store().path)
    except OSError as exc:
        unsure = exc
    if cancels:
        _reseal_cancels(engine, st, cancels)
    if unsure is not None:
        # The restore seal is written and the lost cancels sealed again; the mark may still be on the disk, which
        # keeps the pruner from deleting, erasing or rewriting anything until it is gone.
        raise Refused(f"the restore is accepted (restore seal {seal.seq}), but its mark could not be removed for "
                      f"certain ({type(unsure).__name__}: {unsure}): until {hr.mark_path(st.head_store().path)} is "
                      "gone the pruner deletes nothing; remove it by hand once the disk answers")
    return {"restored": seal.seq, "acknowledged": window, "grace_days": grace, "resealed": sorted(settings),
            "cancels": cancels, "superseded": [c for _s, _n, c in superseded]}
