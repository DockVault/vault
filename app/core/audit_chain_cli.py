"""The host's command line for the audit chain: ``python -m app.core.audit_integrity <command>``, which
``dockvault.py audit`` runs in the web container (the ``accounts`` pattern).

    verify [--from H] [--to H] [--anchor dvchain1:...] [--json] [--old-key-file F]
    head
    acknowledge (--seqs ... | --failures | --rows ... | --late-rows H) (--read | --expect dvstate1:...)
    rekey [--old-key-file F | --old-key-stdin] [--accept-unverified-history] [--confirm-return]
          (--read | --expect dvstate1:... | --now)
    after-record [--discard [--from SEQ]] [--old-key-file F] [--confirm-unverified] (--read | --expect)
    accept-database-head [--old-key-file F] [--confirm NAME ...] [--no-reseal] (--read | --expect)
    accept-restore [--no-reseal] (--read | --expect)
    acknowledge-removed-before T --retention-days N (--read | --expect)

Every command but verify and head answers with one JSON line on standard output (dockvault.py reads it):
``{"ok": true, ...}`` or ``{"ok": false, "error": ...}``; what the app prints while it starts goes to standard
error. Exit codes: verify 0 clean, 1 failures or warnings, 2 cannot run; the others 0 done (or read), 2 refused.
"""
from __future__ import annotations

import argparse
import contextlib
import json
import sys
from typing import Callable, Optional


def _ai():
    from app.core import audit_integrity
    return audit_integrity


def _server():
    """Load the app's configuration and database as the server has them; the chain state of this process (the
    host tool, a separate process from the web server)."""
    import app.api.api_server  # noqa: F401
    from app.core.database import _require_engine
    ai = _ai()
    st = ai.ChainState()
    st.process_kind = "host"
    return _require_engine(), st


def _old_key(args) -> Optional[bytes]:
    """The old chain key given to the host tool (--old-key-file or --old-key-stdin), as the key derived from
    the text, or None. Never put on a command line or into an environment."""
    from app.core import audit_chain_format as fmt
    text = None
    if getattr(args, "old_key_file", None):
        with open(args.old_key_file, "r", encoding="utf-8") as fh:
            text = fh.read()
    elif getattr(args, "old_key_stdin", False):
        text = sys.stdin.read()
    if text is None:
        return None
    text = text.strip()
    if not text:
        raise ValueError("the old key given is empty")
    return fmt.chain_key(text)


def _answer(run: Callable[[], dict]) -> int:
    """Run a host command; write its JSON answer."""
    out = sys.stdout
    try:
        with contextlib.redirect_stdout(sys.stderr):
            from app.core import audit_chain_host as host
            ai = _ai()
            try:
                done = run()
            except host.Refused as why:
                out.write(json.dumps({"ok": False, "error": str(why)}) + "\n")
                return 2
            except ai.ChainStopped as stop:
                out.write(json.dumps({"ok": False, "error": f"{stop.kind}: {stop}"}) + "\n")
                return 2
            except ai.ChainBusy:
                out.write(json.dumps({"ok": False, "error": "busy: the server is writing a seal; try again"}) + "\n")
                return 2
    except Exception as exc:  # noqa: BLE001
        out.write(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}) + "\n")
        return 2
    out.write(json.dumps({"ok": True, **done}, default=str) + "\n")
    return 0


def _phase(p) -> None:
    g = p.add_mutually_exclusive_group(required=True)
    g.add_argument("--read", action="store_true", help="read and say what would be written, with the state seen")
    g.add_argument("--expect", help="write, if the state is still the one the read printed (dvstate1:...)")


def _acknowledge(args) -> int:
    from app.core import audit_chain_format as fmt

    def run():
        from app.core import audit_chain_host as host
        engine, st = _server()
        if args.late_rows:
            return host.seal_late_rows(engine, st, fmt.parse_time_text(args.late_rows), expect=args.expect,
                                       read=args.read)
        try:
            seqs = [int(s) for s in (args.seqs or "").split(",") if s.strip()]
        except ValueError:
            raise host.Refused("--seqs takes seal numbers")
        rows = [row.strip() for row in (args.rows or "").split(",") if row.strip()]
        return host.acknowledge(engine, st, seqs=seqs, failures=args.failures, rows=rows, expect=args.expect,
                                read=args.read)
    return _answer(run)


def _rekey(args) -> int:
    def run():
        from app.core import audit_chain_recovery as recovery
        engine, st = _server()
        old = _old_key(args)
        return recovery.rekey(engine, st, old_key=old, accept_unverified=args.accept_unverified_history,
                              confirm_return=args.confirm_return, expect=args.expect, read=args.read,
                              one_step=args.now)
    return _answer(run)


def _after_record(args) -> int:
    def run():
        from app.core import audit_chain_recovery as recovery
        engine, st = _server()
        return recovery.after_record(engine, st, discard=args.discard, discard_from=args.from_seq,
                                     old_key=_old_key(args), confirm_unverified=args.confirm_unverified,
                                     expect=args.expect, read=args.read)
    return _answer(run)


def _accept_database_head(args) -> int:
    def run():
        from app.core import audit_chain_restore as restore
        engine, st = _server()
        return restore.accept_database_head(engine, st, old_key=_old_key(args), confirm=args.confirm or [],
                                             reseal=not args.no_reseal, expect=args.expect, read=args.read)
    return _answer(run)


def _accept_restore(args) -> int:
    def run():
        from app.core import audit_chain_restore as restore
        engine, st = _server()
        return restore.accept_restore(engine, st, reseal=not args.no_reseal, expect=args.expect, read=args.read)
    return _answer(run)


def _removed_before(args) -> int:
    from app.core import audit_chain_format as fmt

    def run():
        from app.core import audit_chain_external as external
        engine, st = _server()
        return external.acknowledge_removed_before(engine, st, fmt.parse_time_text(args.before),
                                                   retention_days=args.retention_days, expect=args.expect,
                                                   read=args.read)
    return _answer(run)


def _verify(args) -> int:
    from app.core import audit_chain_format as fmt
    from app.core import audit_chain_verify as v
    out = sys.stdout
    try:
        with contextlib.redirect_stdout(sys.stderr):
            import app.api.api_server  # noqa: F401 -- the configuration and the database, as the server has them
            from app.core.database import SessionLocal
            ai = _ai()
            st = ai.ChainState()
            try:
                record = st.head_store().load()
            except ValueError:
                record = None
            db = SessionLocal()
            try:
                if args.action == "head":
                    report = v.verify(db, record=record, check_rows=False)
                else:
                    held = {k: c.key for k, c in st.keys_held().items()}
                    old = _old_key(args)
                    if old is not None:
                        held[fmt.key_id(old)] = old
                    report = v.verify(db, record=record, held=held, current_key_id=st.current_key().key_id,
                                      anchor=args.anchor,
                                      from_hour=fmt.parse_time_text(args.from_) if args.from_ else None,
                                      to_hour=fmt.parse_time_text(args.to) if args.to else None,
                                      key_shared=st.current_key().source == "encryption")
                    if record is None and report.seals:
                        report.add(v.FAILURE, "head-record-missing", f"no head record at {st.head_store().path}")
                    for kind, e in ai.open_failures(record).items():
                        if kind not in report.kinds(v.FAILURE):
                            report.add(v.FAILURE, kind, f"{e.get('message', '')} (first seen {e.get('first_seen')}, "
                                                        "not acknowledged)")
                    for kind, e in ai.open_warnings(record).items():
                        if kind not in report.kinds(v.WARNING):
                            report.add(v.WARNING, kind, f"{e.get('message', '')} (first seen {e.get('first_seen')}, "
                                                        "not acknowledged)")
                    mark = st.restore_mark()
                    if mark is not None and "restore-pending" not in report.kinds(v.WARNING):
                        report.add(v.WARNING, "restore-pending", "a restore of a backup is not finished: run "
                                                                 "dockvault.py audit accept-restore")
            finally:
                db.close()
    except Exception as exc:  # noqa: BLE001
        sys.stderr.write(f"cannot verify: {type(exc).__name__}: {exc}\n")
        if getattr(args, "json", False):
            out.write(json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}) + "\n")
        return 2
    if getattr(args, "json", False):
        out.write(json.dumps({"ok": True, "head": report.head, "head_at": report.head_at, "key_id": report.key_id,
                              "seals": report.seals, "exit_code": report.exit_code,
                              "findings": [f.as_dict() for f in report.findings]}) + "\n")
    elif args.action == "head":
        out.write((report.head or "no seal yet") + "\n")
        return 0
    else:
        v._print_report(report, out)
    return report.exit_code


def main(argv=None) -> int:
    p = argparse.ArgumentParser(prog="python -m app.core.audit_integrity")
    sub = p.add_subparsers(dest="action")
    v = sub.add_parser("verify", help="verify the audit log's integrity chain and print the head")
    v.add_argument("--from", dest="from_", help="first hour to rebuild from its rows (YYYY-MM-DDTHH:00:00Z)")
    v.add_argument("--to", dest="to", help="hour to stop before")
    v.add_argument("--anchor", help="a head kept elsewhere (dvchain1:...)")
    v.add_argument("--json", action="store_true", help="print the report as JSON")
    v.add_argument("--old-key-file", help="a file holding an earlier AUDIT_CHAIN_KEY, to check seals under it")
    v.add_argument("--old-key-stdin", action="store_true", help=argparse.SUPPRESS)
    sub.add_parser("head", help="print the head to keep elsewhere")
    a = sub.add_parser("acknowledge", help="acknowledge warnings (by seal), failures, rows, or late rows, as the host")
    a.add_argument("--seqs", default="", help="the warning seals to acknowledge, comma-separated")
    a.add_argument("--failures", action="store_true",
                   help="acknowledge every failure, and every warning kept by kind, not yet acknowledged")
    a.add_argument("--rows", default="", help="rows holding a value no release writes, by id, comma-separated")
    a.add_argument("--late-rows", help="seal the rows added to this sealed hour (YYYY-MM-DDTHH:00:00Z)")
    _phase(a)
    rk = sub.add_parser("rekey", help="move the chain to the current key, or accept its history without the old one")
    k = rk.add_mutually_exclusive_group()
    k.add_argument("--old-key-file", help="a file holding the AUDIT_CHAIN_KEY the chain is under")
    k.add_argument("--old-key-stdin", action="store_true", help="read that key from standard input")
    rk.add_argument("--accept-unverified-history", action="store_true",
                   help="write the key seal without the old key's proof (the old key is lost)")
    rk.add_argument("--confirm-return", action="store_true", help="return to a key the chain had left")
    g = rk.add_mutually_exclusive_group(required=True)
    g.add_argument("--read", action="store_true")
    g.add_argument("--expect")
    g.add_argument("--now", action="store_true",
                   help="write at once, forward with the old key's proof only (dockvault.py's own key change)")
    ar = sub.add_parser("after-record", help="accept, or discard, the seals after the head record")
    ar.add_argument("--discard", action="store_true", help="delete the seals no writer accepted")
    ar.add_argument("--from", dest="from_seq", type=int, help="the first seal to discard")
    ar.add_argument("--old-key-file", help="a file holding the key those seals are under")
    ar.add_argument("--old-key-stdin", action="store_true", help=argparse.SUPPRESS)
    ar.add_argument("--confirm-unverified", action="store_true",
                    help="accept a key seal written without its proof, which the operator wrote")
    _phase(ar)
    dh = sub.add_parser("accept-database-head", help="accept a database that lost seals, or a lost head record")
    dh.add_argument("--old-key-file", help="a file holding the key the database's chain ends under")
    dh.add_argument("--old-key-stdin", action="store_true", help=argparse.SUPPRESS)
    dh.add_argument("--confirm", action="append", help="confirm, by name, what the read phase asks to confirm")
    dh.add_argument("--no-reseal", action="store_true", help="do not seal again the cancels and values lost")
    _phase(dh)
    rs = sub.add_parser("accept-restore", help="finish a restore of a backup (dockvault.py restore)")
    rs.add_argument("--no-reseal", action="store_true", help="do not seal again the cancels and values lost")
    _phase(rs)
    rb = sub.add_parser("acknowledge-removed-before",
                        help="seal over rows a release without the chain removed by age (a rollback)")
    rb.add_argument("before", help="the removal's cutoff time (YYYY-MM-DDTHH:MM:SSZ)")
    rb.add_argument("--retention-days", type=int, required=True,
                    help="the AUDIT_LOG_RETENTION_DAYS the older release ran with")
    _phase(rb)
    args = p.parse_args(argv)
    handlers = {"acknowledge": _acknowledge, "rekey": _rekey, "after-record": _after_record,
                "accept-database-head": _accept_database_head, "accept-restore": _accept_restore,
                "acknowledge-removed-before": _removed_before}
    if args.action in handlers:
        return handlers[args.action](args)
    if args.action not in ("verify", "head"):
        p.print_help()
        return 2
    return _verify(args)
