"""The host's commands that let sealing go on after it stopped, or that finish a restore
(``dockvault.py audit``): each runs in two phases (app/core/audit_chain_host.py) and records the host
operator.

    rekey [--old-key-file F]           moves the chain to the current key with a key seal and its proof under
                                       the key in force (held by the server, or given). A return to a key the
                                       chain had left asks --confirm-return: whoever holds it can write seals
                                       again. --accept-unverified-history writes the key seal with no proof,
                                       when the old key is lost, and lists it in the head record; a chain
                                       rewritten under a made-up key id looks exactly like that, so it first
                                       prints the head record and the database's newest seals.
    rekey --old-key-stdin --now        dockvault.py's own key change: the old key on standard input, forward
                                       with its proof, in one step.
    after-record                       seals after the head record that no writer accepts (a host command that
                                       crashed before its record write, a seal refused on its face): accepts the
                                       ones that chain, keep the key sequence and carry a valid MAC, lists them
                                       as the host's and acknowledges the failures they caused.
    after-record --discard [--from N]  deletes the seals after the head record from N on (by default the first
                                       one no writer accepted), only seals no writer accepted, saving their rows
                                       beside the head record first; the deletion and the ack seal naming them
                                       commit together, and the head record's discard count rises so that every
                                       writer rebuilds its view.
    accept-database-head               a database restored on its own, a cut tail, a lost head record.
    accept-restore                     the last step of dockvault.py restore.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from typing import Dict, List, Optional

from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_keys as keys
from app.core.audit_chain_host import Refused, chain_state, check_expected, describe_seal, host_audit_row, token

KEY_ACTION = "audit_chain_key_changed"
ACCEPTED_ACTION = "audit_seals_accepted"
DISCARDED_ACTION = "audit_seals_discarded"
RESTORED_ACTION = "audit_chain_restored"

# The failures seals after the head record cause, which the host's acceptance or discard acknowledges.
AFTER_RECORD_KINDS = ("host-seal-unrecorded", "after-record-invalid", "key-unverified", "key-sequence",
                      "mac-invalid", "seq-gap")


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _held(st, old_key: Optional[bytes]) -> Dict[str, keys.ChainKey]:
    held = dict(st.keys_held())
    if old_key is not None:
        kid = fmt.key_id(old_key)
        held[kid] = keys.ChainKey(old_key, kid, "given")
    return held


def _newest_seals(db, n: int = 5) -> List[str]:
    from app.core.models import AuditSeal as S
    rows = db.query(S.seq, S.kind, S.sealed_at, S.key_id).order_by(S.seq.desc()).limit(n).all()
    return [f"  seal {r[0]} ({r[1]}) sealed {fmt.time_text(r[2])} under {r[3]}" for r in rows]


def _record_lines(record: Optional[dict]) -> List[str]:
    if not record or not record.get("link"):
        return ["  no head record"]
    return [f"  head record: seal {record.get('seq')} {record.get('link')} under {record.get('key_id')}, "
            f"generation {record.get('generation')}, discards {record.get('discards')}"]


# --------------------------------------------------------------------------- rekey

def rekey(engine, st, *, old_key: Optional[bytes] = None, accept_unverified: bool = False,
          confirm_return: bool = False, expect: Optional[str] = None, read: bool = False,
          one_step: bool = False) -> dict:
    """Move the chain to the current key (see the module's docstring). Raises Refused."""
    ai = _ai()
    with ai.ChainWriter(engine, st, wait=30, writer="host", check_key=False, snapshot=True) as w:
        view, record = w.st.view, w.record or {}
        if not view.position:
            raise Refused("the chain has no seal yet")
        current = w.st.current_key()
        in_force = view.key_in_force()
        held = _held(w.st, old_key)
        if in_force == current.key_id:
            raise Refused(f"the chain is already under the current key ({current.key_id}): nothing to do")
        returning = view.ever_in_force(current.key_id) or ai._ever_in_force(record, current.key_id)
        lines = [f"The chain is under {in_force}; the current key is {current.key_id}."]
        if returning:
            lines.append(f"{current.key_id} is a key the chain had left: from now on whoever holds it can write "
                         "seals again (--confirm-return).")
        after = sorted(ai.foreign_entries(view, record))
        if after:
            lines.append("Seals after the head record, which the key seal chains over (each stays a warning until "
                         "acknowledged):")
            for seq in after:
                lines += ["  " + ln for ln in describe_seal(view, record, seq, w.st.clock())]
        proof = None
        newest = ai.read_seal(w.db, view.position)
        if accept_unverified:
            if one_step:
                raise Refused("--accept-unverified-history is never written in one step")
            lines.append("The key seal is written WITHOUT the old key's proof. A chain rewritten under a made-up "
                         "key id looks exactly like this: check that the head record and the newest seals below "
                         "are the ones you expect.")
            lines += _record_lines(record) + _newest_seals(w.db)
        else:
            old = held.get(in_force)
            if old is None:
                raise Refused(f"the key in force ({in_force}) is not held: give it with --old-key-file, or, if it "
                              "is lost, use --accept-unverified-history")
            if newest is None or not ai._mac_ok(old.key, view.link_at(view.position), newest.mac):
                raise Refused(f"the newest seal ({view.position}) does not verify under {in_force}: the chain cannot "
                              "be moved with a proof (key-unverified)")
            proof = fmt.old_key_proof(old.key, view.link_at(view.position), current.key_id)
        state = {"chain": chain_state(view, record), "command": "rekey", "from": in_force, "to": current.key_id,
                 "unverified": bool(accept_unverified), "returning": bool(returning)}
        if read:
            return {"state": token(state), "lines": lines, "returning": bool(returning)}
        if one_step:
            if returning:
                raise Refused("a return to a key the chain left is never written in one step")
        else:
            check_expected(state, expect)
        if returning and not confirm_return:
            raise Refused("a return to a key the chain had left needs --confirm-return")
        host_audit_row(w.db, KEY_ACTION, {"from_key": in_force, "to_key": current.key_id,
                                          "proof": proof is not None})
        seal = w.append("key", detail={"old_key_id": in_force, "new_key_id": current.key_id,
                                       "old_key_proof": proof.hex() if proof is not None else None,
                                       "accepted_unverified": bool(accept_unverified), "by": "host"}, key=current)
        if accept_unverified:
            now = w.st.clock()

            def listed(rec):
                rec.setdefault("unverified_keys", []).append(
                    {"generation": view.generation, "seq": seal.seq, "link": None, "at": fmt.time_text(now)})
                return rec
            w.after_record_change = listed
    return {"sealed": seal.seq, "from": in_force, "to": current.key_id, "unverified": bool(accept_unverified)}


# --------------------------------------------------------------------------- after-record

def _prefix_view(db, record: dict, upto: Optional[int] = None):
    """The view of the chain up to the head record (or seal ``upto``), its link checked against the record."""
    ai = _ai()
    view = ai.View()
    view.reset(int(record.get("generation") or 1), int(record.get("discards") or 0))
    rec_seq = int(record.get("seq") or 0)
    rec_link = bytes.fromhex(record["link"]) if record.get("link") else None
    end = rec_seq if upto is None else upto
    for seal in ai.read_seals(db, 0, upto=end):
        if seal.seq != view.position + 1:
            raise Refused(f"the seals jump from {view.position} to {seal.seq}: use accept-database-head")
        view.accept(seal, fmt.link(view.link_at(seal.seq - 1), seal.body()))
    if view.position < rec_seq or view.link_at(rec_seq) != rec_link:
        raise Refused("the database's chain does not reach the head record: use accept-database-head")
    return view


def classify_after(db, view, record: dict, held: Dict[str, keys.ChainKey], now: datetime,
                   confirm_unverified: bool = False) -> List[dict]:
    """Every seal after the head record, judged as a writer would and accepted into ``view`` as it goes:
    [{seq, kind, link, listed, acknowledged, problems (what no host acceptance cures), notes (what the host
    may accept), lines}]."""
    ai = _ai()
    out = []
    foreign = ai.foreign_entries(view, record)
    for seal in ai.read_seals(db, view.position):
        if seal.seq != view.position + 1:
            out.append({"seq": seal.seq, "kind": seal.kind, "link": None, "listed": False, "acknowledged": False,
                        "problems": [f"the seals jump from {view.position} to {seal.seq}"], "notes": [],
                        "lines": [], "seal": seal})
            break
        link = fmt.link(view.link_at(seal.seq - 1), seal.body())
        listed = ai._record_lists(record, view.generation, seal.seq, link)
        problems, notes = [], []
        if ai.is_host_kind(seal) and not listed:
            notes.append("a kind only the host writes, which the head record does not list")
        ks = ai.key_sequence_problem(view, seal)
        if ks:
            problems.append(ks)
        k = held.get(seal.key_id)
        if k is None:
            problems.append(f"under {seal.key_id}, a key this command does not hold (give it with --old-key-file)")
        elif not ai._mac_ok(k.key, link, seal.mac):
            problems.append("its MAC does not verify")
        d = seal.detail if isinstance(seal.detail, dict) else {}
        if seal.kind == "key" and not ks:
            old = held.get(d.get("old_key_id"))
            proof = d.get("old_key_proof")
            if not (old is not None and proof and ai._proof_ok(old.key, view.link_at(seal.seq - 1), seal.key_id,
                                                                proof)):
                if d.get("accepted_unverified"):
                    if not confirm_unverified:
                        problems.append("a key seal with no proof (accepted_unverified): accept it with "
                                        "--confirm-unverified only if you wrote it")
                    else:
                        notes.append("a key seal with no proof, accepted as yours")
                else:
                    problems.append("a key seal whose proof does not verify")
        face = ai.face_problem(view, seal, now, record=record)
        if face:
            notes.append(f"a writer refuses it on its face: {face}")
        entry = foreign.get(seal.seq)
        out.append({"seq": seal.seq, "kind": seal.kind, "link": link.hex(), "listed": listed,
                    "acknowledged": bool(entry and entry.get("acknowledged")), "problems": problems,
                    "notes": notes, "seal": seal, "unverified_key": seal.kind == "key" and bool(
                        d.get("accepted_unverified"))})
        view.accept(seal, link)
        out[-1]["lines"] = describe_seal(view, record, seal.seq, now)
    return out


def _save_discarded(path: str, db, first: int, now: datetime) -> str:
    from app.core.audit_head_record import _owned_like_directory
    from app.core.models import AuditSeal as S
    rows = db.query(S).filter(S.seq >= first).order_by(S.seq).all()
    saved = []
    for r in rows:
        item = {}
        for col in S.__table__.columns:
            v = getattr(r, col.name)
            if isinstance(v, (bytes, bytearray, memoryview)):
                v = bytes(v).hex()
            elif isinstance(v, datetime):
                v = fmt.time_text(v)
            item[col.name] = v
        saved.append(item)
    stamp = now.strftime("%Y%m%dT%H%M%SZ")
    target = f"{path}.discarded-{stamp}-{first}.json"
    with open(target, "w", encoding="utf-8") as fh:
        json.dump(saved, fh, indent=1, sort_keys=True)
        fh.flush()
        _owned_like_directory(target)          # before the sync: the file synced is the final one, owner and all
        os.fsync(fh.fileno())
    return target


def after_record(engine, st, *, discard: bool = False, discard_from: Optional[int] = None,
                 old_key: Optional[bytes] = None, confirm_unverified: bool = False, expect: Optional[str] = None,
                 read: bool = False) -> dict:
    """Accept, or discard, the seals after the head record (see the module's docstring). Raises Refused."""
    ai = _ai()
    from app.core.models import AuditSeal as S
    with ai.ChainWriter(engine, st, wait=30, writer="host", check_chain=False, snapshot=True) as w:
        record = w.record
        if not record or not record.get("link"):
            raise Refused("there is no head record to accept seals after: use accept-database-head")
        now = w.st.clock()
        view = _prefix_view(w.db, record)
        held = _held(w.st, old_key)
        seals = classify_after(w.db, view, record, held, now, confirm_unverified)
        waiting = sorted(s for s, e in ai.foreign_entries(view, record).items() if not e.get("acknowledged"))
        if not seals and not waiting:
            raise Refused("there is no seal after the head record")
        lines = ["Seals after the head record:" if seals else "No seal after the head record."]
        for s in seals:
            lines += ["  " + ln for ln in s["lines"]]
            lines += ["    accepted by a writer already (listed in the head record)"] if s["listed"] else []
            lines += [f"    NOTE: {n}" for n in s["notes"]]
            lines += [f"    REFUSED: {p}" for p in s["problems"]]
        listed_seqs = [s["seq"] for s in seals if s["listed"]]
        first_unlisted = next((s["seq"] for s in seals if not s["listed"]), None)
        if discard:
            first = discard_from if discard_from is not None else first_unlisted
            if first is None:
                raise Refused("every seal after the head record was accepted by a writer: none may be discarded")
            if first <= int(record.get("seq") or 0) or (listed_seqs and first <= max(listed_seqs)):
                raise Refused(f"seal {first} is at or before a seal a writer accepted: only seals no writer accepted "
                              "are discarded")
            gone = [s for s in seals if s["seq"] >= first]
            if not gone:
                raise Refused(f"there is no seal from {first} on")
            lines.append(f"Discards seals {first} to {gone[-1]['seq']}: their rows are saved beside the head record, "
                         "then deleted with an ack seal naming them.")
            if any(s["kind"] in ("prune", "rewrite", "erase", "archive") for s in gone):
                lines.append("Discarding a prune, rewrite, erase or archive seal does not undo its change: those "
                             "hours will then fail verification.")
            state = {"chain": chain_state(view, record), "command": "after-record-discard", "first": first,
                     "seals": [[s["seq"], s["kind"], s["link"]] for s in seals]}
        else:
            refused = [s for s in seals if s["problems"]]
            if refused:
                lines.append(f"Seal {refused[0]['seq']} cannot be accepted; discard it and the seals after it with "
                             f"--discard --from {refused[0]['seq']}.")
            state = {"chain": chain_state(view, record), "command": "after-record",
                     "seals": [[s["seq"], s["kind"], s["link"]] for s in seals], "waiting": waiting}
        if read:
            return {"state": token(state), "lines": lines}
        check_expected(state, expect)
        findings = [f for f in host.open_findings(record) if f[1] in AFTER_RECORD_KINDS]
        listed = [[kind, first_seen, last] for _t, kind, first_seen, last in findings]
        if discard:
            saved = _save_discarded(w.st.head_store().path, w.db, first, now)
            w.db.query(S).filter(S.seq >= first).delete(synchronize_session=False)
            w.db.flush()
            prefix = _prefix_view(w.db, record, upto=first - 1) if first - 1 > int(record.get("seq") or 0) \
                else _prefix_view(w.db, record)
            w.st.view = prefix
            w.st.own.clear()
            discarded = [[s["seq"], s["kind"], s["link"]] for s in gone]
            row = host_audit_row(w.db, DISCARDED_ACTION, {"seals": [d[0] for d in discarded], "saved": saved})
            w.append("ack", detail={"acknowledges": [], "failures": listed, "rows": [], "discarded": discarded,
                                    "by": "host", "user_id": None, "request": str(row.id)})
            mark = host.marker(prefix, set(), findings, bool(listed), now)

            def change(rec):
                rec = mark(rec)
                rec["discards"] = int(rec.get("discards") or 0) + 1
                after = rec.setdefault("after_record", [])
                for seq, kind, link in discarded:
                    after.append({"generation": prefix.generation, "seq": seq, "kind": kind, "link": link,
                                  "discarded": True, "acknowledged": False, "accepted_at": None, "where": "host"})
                return rec
            w.after_record_change = change
            return {"discarded": [d[0] for d in discarded], "saved": saved}
        if [s for s in seals if s["problems"]]:
            raise Refused("a seal after the head record cannot be accepted (see the read)")
        w.st.view = view
        w.st.own.clear()
        w.accepted = [(s["seal"], bytes.fromhex(s["link"])) for s in seals]
        for seal, _link in w.accepted:
            if seal.kind in ai.ROOT_KINDS:
                seal.salt = ai._salt_of(w.db, seal)
        acked = sorted({s["seq"] for s in seals} | set(waiting))
        row = host_audit_row(w.db, ACCEPTED_ACTION, {"seals": acked, "failures": [k for k, _f, _l in listed]})
        w.append("ack", detail={"acknowledges": acked, "failures": listed, "rows": [], "discarded": [],
                                "by": "host", "user_id": None, "request": str(row.id)})
        mark = host.marker(view, set(acked), findings, bool(listed), now)
        unverified = [s for s in seals if s.get("unverified_key")]

        def change(rec):
            after = rec.setdefault("after_record", [])
            for s in seals:
                if not any(e.get("generation") == view.generation and e.get("seq") == s["seq"] for e in after):
                    after.append({"generation": view.generation, "seq": s["seq"], "kind": s["kind"], "link": s["link"],
                                  "accepted_at": fmt.time_text(now), "where": "host", "acknowledged": False,
                                  "discarded": False, "delay_days": None,
                                  "process_started_at": fmt.time_text(w.st.process_started_at)})
            for s in unverified:
                rec.setdefault("unverified_keys", []).append(
                    {"generation": view.generation, "seq": s["seq"], "link": s["link"], "at": fmt.time_text(now)})
            return mark(rec)
        w.after_record_change = change
    return {"accepted": acked, "failures": [k for k, _f, _l in listed]}
