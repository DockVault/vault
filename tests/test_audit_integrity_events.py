"""The audit log's integrity chain, offline: the changes after sealing that keep it valid (a prune, an erase),
the keys and their sequence, the head record and the integrity status, the checks outside the chain, and the
head in every export. On a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py)."""
import json
import os
import secrets
import uuid
from datetime import datetime, timedelta

import pytest

from _audit_chain_env import Env, T0, failures
from app.core import audit_chain_format as fmt
from app.core import audit_chain_verify as v
from app.core import audit_integrity as ai
from app.core import retention
from app.core.models import AuditLog, AuditSeal, RoleEnum, User

pytestmark = pytest.mark.unit


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path)
    yield e
    e.close()


def _update(env, row_id, **values):
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == row_id).update(values, synchronize_session=False)
        db.commit()


def _sealed(env, n=4):
    ids = [env.row(T0 - timedelta(hours=8, minutes=m)) for m in range(0, 60, 60 // n)]
    env.run_until_sealed()
    assert failures(env.verify()) == []
    return ids


def _start_with_retention(env, monkeypatch, days=30):
    """A chain started under the defaults, then AUDIT_LOG_RETENTION_DAYS set in .env on the running install
    (an operator's change: sealed, then acted on at once)."""
    env.run_until_sealed()
    monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", str(days))
    env.settings.audit_log_retention_days = days


def _pass(env, minutes=30):
    env.clock.advance(minutes=minutes)
    return dict(retention.run_pass(env.session, now=env.clock()))


# --------------------------------------------------------------------------- a prune keeps the chain valid

def test_a_whole_and_a_partial_prune_keep_the_chain_valid(env, monkeypatch):
    old_plain = [env.row(T0 - timedelta(days=40, minutes=m)) for m in (5, 15)]
    old_admin = env.row(T0 - timedelta(days=40, minutes=25), action="settings_updated")
    other_hour = env.row(T0 - timedelta(days=39))
    young = env.row(T0 - timedelta(days=2))
    _start_with_retention(env, monkeypatch)
    _pass(env)
    with env.session() as db:
        left = {r[0] for r in db.query(AuditLog.id).all()}
    assert not set(old_plain) & left and other_hour not in left
    assert old_admin in left and young in left           # administration rows are kept 365 days
    prunes = [s for s in env.seals() if s.kind == "prune"]
    assert prunes and all(p.detail["reason"] == "retention" for p in prunes)
    assert prunes[0].detail["policy_seq"] == [s for s in env.seals() if s.kind == "policy"][-1].seq
    report = env.verify()
    assert failures(report) == [], report.findings


def test_a_prune_of_rows_without_a_nonce_writes_their_nonces_and_drops_the_salt(env, monkeypatch):
    legacy = [env.row(T0 - timedelta(days=40, minutes=m), nonce=False) for m in (5, 15, 25)]
    env.row(T0 - timedelta(days=40, minutes=35), nonce=False, action="settings_updated")
    _start_with_retention(env, monkeypatch)
    hour = [s for s in env.seals() if s.kind == "hour" and s.row_count == 4][0]
    assert hour.legacy_salt is not None
    _pass(env)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(legacy)).count() == 0
        kept = db.query(AuditLog).filter(AuditLog.action == "settings_updated").one()
        assert kept.seal_nonce is not None
        assert db.get(AuditSeal, hour.seq).legacy_salt is None
    assert failures(env.verify()) == []


def test_a_prune_never_seals_over_a_tampered_hour(env, monkeypatch):
    rows = [env.row(T0 - timedelta(days=40, minutes=m)) for m in (5, 15)]
    _start_with_retention(env, monkeypatch)
    _update(env, rows[0], username="mallory")
    _pass(env)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.id.in_(rows)).count() == 2
    assert "rows-altered" in env.st.head_store().load()["failures"]
    assert not [s for s in env.seals() if s.kind == "prune"]


def test_rows_of_an_hour_not_yet_sealed_are_never_pruned(env, monkeypatch):
    env.row(T0 - timedelta(days=40))
    _start_with_retention(env, monkeypatch, days=1)
    fresh = env.row(env.clock() - timedelta(minutes=5))
    env.clock.at = env.clock() + timedelta(days=3)       # its hour is old now, and not sealed yet
    from app.core import audit_chain_prune, audit_retention as ar
    with env.session() as db:
        db.rollback()
    p = retention.Pass(env.session, now=env.clock())
    cond = [AuditLog.timestamp < env.clock() - timedelta(days=1)]
    audit_chain_prune.prune(p, cond, reason="retention")
    with env.session() as db:
        assert db.get(AuditLog, fresh) is not None
    assert ar


# --------------------------------------------------------------------------- an erase keeps the chain valid

def _request_erase(env):
    placeholder = "erased-" + secrets.token_hex(4)
    with ai.ChainWriter(env.engine, env.st) as w:
        delay = timedelta(days=7)
        req = w.append("request", detail=lambda seq, at: {
            "what": "erase", "request": str(uuid.uuid4()), "setting": None, "old": None, "new": None,
            "subject": "ab" * 32, "placeholder": placeholder, "not_before": fmt.time_text(at + delay),
            "audit_row": None, "by": "admin", "user_id": None})
    return req, placeholder


def _run_erase(env, req, placeholder, hour, rows):
    """What the erase job does to one hour: each row's personal values replaced, its nonce zero, and each
    row's commitment before and after in the erase seal."""
    with ai.ChainWriter(env.engine, env.st) as w:
        entries = []
        for rid in rows:
            row = next(r for r in ai.iter_rows(w.db, hour, hour + ai.HOUR) if r["id"] == rid)
            c_prev = fmt.commitment(row["seal_nonce"], row)
            w.db.query(AuditLog).filter(AuditLog.id == rid).update(
                {AuditLog.username: placeholder, AuditLog.ip_address: None, AuditLog.user_agent: None,
                 AuditLog.endpoint: None, AuditLog.details: None, AuditLog.seal_nonce: fmt.ZERO_NONCE},
                synchronize_session=False)
            w.db.flush()
            row = next(r for r in ai.iter_rows(w.db, hour, hour + ai.HOUR) if r["id"] == rid)
            entries.append([str(rid), c_prev.hex(), fmt.commitment(fmt.ZERO_NONCE, row).hex()])
        return w.append("erase", detail={"hour": fmt.hour_text(hour), "request_seq": req.seq,
                                         "request_id": req.detail["request"], "placeholder": placeholder,
                                         "policy_seq": w.st.view.newest_policy()[0],
                                         "bytes_now": 0, "through": fmt.hour_text(hour), "final": True,
                                         "rows": entries})


def test_an_erase_keeps_the_chain_valid_and_its_rows_are_checked(env):
    rows = [env.row(T0 - timedelta(hours=8, minutes=m), username="eve") for m in (5, 15)]
    env.row(T0 - timedelta(hours=8, minutes=25), username="alice")
    env.run_until_sealed()
    req, placeholder = _request_erase(env)
    for _ in range(30):            # seven days of passes every six hours
        env.clock.advance(hours=6)
        env.seal()
    hour = ai.hour_floor(T0 - timedelta(hours=8, minutes=5))
    _run_erase(env, req, placeholder, hour, rows)
    report = env.verify()
    assert failures(report) == [], report.findings
    _update(env, rows[0], username="eve")
    assert "unjustified" in failures(env.verify())


def test_an_erase_before_its_delay_is_unjustified(env):
    rows = [env.row(T0 - timedelta(hours=8, minutes=5), username="eve")]
    env.run_until_sealed()
    req, placeholder = _request_erase(env)
    env.clock.advance(hours=1)
    _run_erase(env, req, placeholder, ai.hour_floor(T0 - timedelta(hours=8, minutes=5)), rows)
    found = [f for f in env.verify().findings if f.kind == "unjustified"]
    assert found and "delay" in found[0].message


def test_an_erase_then_a_late_seal_in_the_same_hour_keeps_the_chain_valid(env):
    """The late seal's roots are over the rows as they are now: the erased row counts with its new values."""
    env.row(T0 - timedelta(hours=3, minutes=10), username="bob")
    env.run_until_sealed()
    req, placeholder = _request_erase(env)
    for _ in range(29):            # the erase's delay runs out
        env.clock.advance(hours=6)
        env.seal()
    env.clock.advance(hours=1)
    at = env.clock() - timedelta(hours=2, minutes=50)
    erased = env.row(at, username="eve")
    env.run_until_sealed()
    hour = ai.hour_floor(at)
    assert hour + ai.HOUR <= env.st.view.newest_hour_end
    _run_erase(env, req, placeholder, hour, [erased])
    assert failures(env.verify()) == []
    env.row(hour + timedelta(minutes=40), username="carol")
    env.clock.advance(minutes=20)
    assert env.seal().late == 1
    report = env.verify()
    assert failures(report) == [], report.findings
    late = [s for s in env.seals() if s.kind == "late"][-1]
    with env.session() as db:
        now = ai.hour_figures(ai.iter_rows(db, hour, hour + ai.HOUR), None)
    assert bytes(late.root_c) == now.root_c


def test_an_erase_then_a_partial_prune_of_the_same_hour_keeps_the_chain_valid(env, monkeypatch):
    """An erased person's administration row is kept by its floor while the rest of its hour is pruned: the
    prune seal's roots are over the rows kept as they are now."""
    at = T0 - timedelta(days=40)
    erased = env.row(at + timedelta(minutes=5), username="eve", action="settings_updated")
    plain = env.row(at + timedelta(minutes=15), username="alice")
    env.run_until_sealed()
    req, placeholder = _request_erase(env)
    for _ in range(30):
        env.clock.advance(hours=6)
        env.seal()
    _run_erase(env, req, placeholder, ai.hour_floor(at), [erased])
    assert failures(env.verify()) == []
    monkeypatch.setenv("AUDIT_LOG_RETENTION_DAYS", "30")
    env.settings.audit_log_retention_days = 30
    env.clock.advance(minutes=30)
    retention.run_pass(env.session, now=env.clock())
    with env.session() as db:
        left = {r[0] for r in db.query(AuditLog.id).all()}
    assert plain not in left and erased in left
    report = env.verify()
    assert failures(report) == [], report.findings
    env.clock.advance(minutes=30)
    retention.run_pass(env.session, now=env.clock())       # the hour still checks out for the next pass
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- keys

def _shared_then_own_key(env):
    env.settings.audit_chain_key = ""
    env.row(T0 - timedelta(hours=5))
    env.run_until_sealed()
    assert ai.status(env.st)["key_shared"] is True
    env.settings.audit_chain_key = "d" * 64
    env.clock.advance(hours=1)
    env.seal()


def test_setting_the_chain_key_moves_the_chain_with_a_proof(env):
    _shared_then_own_key(env)
    key_seals = [s for s in env.seals() if s.kind == "key"]
    assert len(key_seals) == 1 and key_seals[0].detail["old_key_proof"]
    report = env.verify()
    assert failures(report) == [], report.findings
    assert ai.status(env.st)["key_shared"] is False


def test_a_seal_under_a_key_the_chain_left_is_refused(env):
    _shared_then_own_key(env)
    left = [k for k in env.st.keys_held().values() if k.source == "encryption"][0]
    with env.session() as db:
        seals = list(ai.read_seals(db, 0))
    prev = fmt.LINK_0
    for s in seals:
        prev = fmt.link(prev, s.body())
    seal = ai.Seal(seals[-1].seq + 1, "ack", None, None, fmt.FORMAT, 0, 0, None, None, None,
                   {"acknowledges": [], "failures": [], "rows": [], "discarded": [], "by": "admin", "user_id": None,
                    "request": None}, left.key_id, env.clock())
    link = fmt.link(prev, seal.body())
    with env.session() as db:
        db.add(AuditSeal(seq=seal.seq, kind="ack", format=1, row_count=0, row_bytes=0, detail=seal.detail,
                         key_id=left.key_id, sealed_at=seal.sealed_at, mac=fmt.mac(left.key, link), link=link))
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-sequence"
    assert "key-sequence" in failures(env.verify())


def test_returning_to_a_key_the_chain_left_stops_sealing(env):
    _shared_then_own_key(env)
    env.settings.audit_chain_key = ""
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-not-current"


def test_a_key_changed_without_the_old_one_waits_for_the_host_then_fails(env):
    env.run_until_sealed()
    env.settings.audit_chain_key = "e" * 64
    env.settings.encryption_key = "Z2hhbmdlbWVjaGFuZ2VtZWNoYW5nZW1lY2hhbmdlbWU="
    env.clock.advance(hours=1)
    assert env.seal().stopped == "key-change-waiting"
    record = env.st.head_store().load()
    assert "key-change-waiting" in record["warnings"] and "key-change-waiting" not in record.get("failures", {})
    env.clock.advance(hours=25)
    env.seal()
    assert "key-change-waiting" in env.st.head_store().load()["failures"]


def test_the_start_refuses_a_weak_or_shared_chain_key():
    from types import SimpleNamespace
    from app.core.audit_chain_keys import key_problem
    assert key_problem(SimpleNamespace(audit_chain_key="", encryption_key="x")) is None
    assert "shorter than 32" in key_problem(SimpleNamespace(audit_chain_key="short", encryption_key="x"))
    same = "f" * 44
    assert "equals ENCRYPTION_KEY" in key_problem(SimpleNamespace(audit_chain_key=same, encryption_key=same))
    assert key_problem(SimpleNamespace(audit_chain_key="g" * 64, encryption_key=same)) is None


# --------------------------------------------------------------------------- the head record and the status

def test_seals_without_a_head_record_stop_sealing(env):
    env.run_until_sealed()
    os.remove(env.settings.audit_chain_head_file)
    env.fresh_process()
    env.clock.advance(hours=2)
    assert env.seal().stopped == "head-record-missing"


def test_a_failure_stays_on_the_status_when_its_announcement_is_deleted(env):
    ids = _sealed(env)
    _update(env, ids[0], action="logout")
    v.daily_check(env.session, env.st, env.clock(), force=True)
    with env.session() as db:
        assert db.query(AuditLog).filter(AuditLog.action == ai.FAILED_ACTION).count() == 1
        db.query(AuditLog).filter(AuditLog.action == ai.FAILED_ACTION).delete()
        db.commit()
    status = ai.status(env.st)
    assert status["outcome"] == "failed" and "rows-altered" in status["failures"]
    v.daily_check(env.session, env.st, env.clock() + timedelta(days=1), force=True)
    with env.session() as db:      # announced once, not again
        assert db.query(AuditLog).filter(AuditLog.action == ai.FAILED_ACTION).count() == 0


def test_the_daily_check_records_a_clean_position(env):
    _sealed(env)
    report = v.daily_check(env.session, env.st, env.clock(), force=True)
    assert report is not None and report.exit_code in (0, 1)
    check = env.st.head_store().load()["check"]
    assert check["clean_seq"] == report.seals and check["daily_at"]
    assert v.daily_check(env.session, env.st, env.clock() + timedelta(hours=1)) is None


# --------------------------------------------------------------------------- outside the chain

def test_an_unlinked_account_row_is_found_and_a_failed_sign_in_is_not(env):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username="carol", email="c@example.com", password_hash="x", role=RoleEnum.USER,
                    is_active=True, created_at=datetime(2020, 1, 1)))
        db.commit()
    env.row(T0 - timedelta(hours=6), action="login_failure", username="carol")
    linked = env.row(T0 - timedelta(hours=6, minutes=-5), action="file_uploaded", username="carol", user_id=uid)
    env.run_until_sealed()
    assert failures(env.verify()) == []
    _update(env, linked, user_id=None)
    assert "user-unlinked" in failures(env.verify())


def test_a_row_naming_another_account_is_a_mismatch(env):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username="dan", email="d@example.com", password_hash="x", role=RoleEnum.USER,
                    is_active=True))
        db.commit()
    row = env.row(T0 - timedelta(hours=6), username="dan", user_id=uid)
    env.run_until_sealed()
    _update(env, row, user_id=None)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == row).update({AuditLog.user_id: uid, AuditLog.username: "dan"})
        db.query(User).filter(User.id == uid).update({User.username: "danny"})
        db.commit()
    assert "user-mismatch" in failures(env.verify())


def test_only_failed_sign_ins_carry_a_typed_name():
    """Every call that writes a username without an account is a failed sign-in (the catalog's typed_name)
    or the host operator's own row; nothing else may, or user-unlinked would flag it."""
    import re
    from pathlib import Path
    from app.core import audit_catalog
    typed = sorted(a.name for a in audit_catalog.ACTIONS if a.typed_name)
    assert typed == ["login_failure"]
    root = Path(__file__).resolve().parent.parent / "app"
    found = []
    for path in root.rglob("*.py"):
        text = path.read_text(encoding="utf-8")
        for m in re.finditer(r"(log_action|build_row)\(([^()]|\([^()]*\))*?username=([^,)]+)", text, re.S):
            value = m.group(3).strip()
            if value in ("username", "None") or "HOST_OPERATOR" in value or "user.username" in value:
                continue
            found.append(f"{path.name}: {value}")
    # A failed sign-in's name, the server's own configuration rows (named as such, never an account), and compliance
    # access's steps without an actor: the host's operator, or the steps it takes on its own (legal_holds.SYSTEM),
    # both left out by the check's user-unlinked; a step caused by an account's change names that account with its id.
    assert sorted(found) == ["audit_logger.py: recorded_name",
                             "audit_privacy.py: None if user is not None else by_name",
                             "auditor_rights.py: None if actor is not None else username",
                             "auditor_rights.py: by_name",
                             "cases.py: None if actor is not None else actor_name",
                             "legal_holds.py: None if actor is not None else actor_name",
                             "legal_holds.py: None if getattr(actor",
                             "owner_notices.py: actor_name"], found


# --------------------------------------------------------------------------- the head, shown and exported

def test_the_head_goes_into_every_export():
    from app.services import activity_events as ev

    def fetch(after):
        return [], None

    head = "dvchain1:9:" + "ab" * 32
    csv_lines = list(ev.export_lines(fetch, "csv", 0, head=head))
    assert csv_lines[-1].startswith("# Audit chain head when this export started: " + head)
    nd = list(ev.export_lines(fetch, "ndjson", 0, head=head))
    assert json.loads(nd[-1]) == {"audit_chain_head": head}
    assert list(ev.export_lines(fetch, "ndjson", 0, head=None)) == []


def test_the_status_route_is_a_plain_function_for_administrators(env):
    import inspect
    from app.api import audit_integrity_router as r
    assert not inspect.iscoroutinefunction(r.get_integrity)
    _sealed(env)
    out = r.get_integrity(current_user=None)
    assert out["head"].startswith("dvchain1:") and out["outcome"] == "clean" and out["failures"] == []
    assert "not against the server's operator" in out["claim"]


# --------------------------------------------------------------------------- the configuration

def test_the_chain_settings_are_configured_documented_and_kept_by_the_tool(monkeypatch):
    import importlib.util
    from pathlib import Path
    from app.core.config import Settings
    from app.core import settings_registry as reg
    root = Path(__file__).resolve().parent.parent
    assert Settings.model_fields["audit_chain_key"].default == ""
    assert Settings.model_fields["audit_seal_lag_minutes"].default == 60
    assert Settings.model_fields["audit_chain_head_file"].default == "/app/keys/audit-chain-head.json"
    example = (root / ".env.example").read_text(encoding="utf-8")
    for line in ("# AUDIT_CHAIN_KEY=", "# AUDIT_SEAL_LAG_MINUTES=60",
                 "# AUDIT_CHAIN_HEAD_FILE=/app/keys/audit-chain-head.json"):
        assert example.count("\n" + line + "\n") == 1, line
    assert reg.spec_for(ai.LAG_KEY).editable == reg.ENV_ONLY
    assert {"audit_chain_key", "audit_chain_head_file"} <= reg.refused_settings_keys()
    spec = importlib.util.spec_from_file_location("dockvault_chain", root / "dockvault.py")
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config({"AUDIT_SEAL_LAG_MINUTES": "30"}, "prefix-1", "dep-1")
    assert len(cfg["audit_chain_key"]) == 64
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    written = dv.parse_env("\n".join(lines))
    assert written["AUDIT_CHAIN_KEY"] == cfg["audit_chain_key"] and written["AUDIT_SEAL_LAG_MINUTES"] == "30"
    plain = dv.build_env_lines({**dv.new_set_config({}, "prefix-1", "dep-1"), "server_name": "localhost"})
    assert not [ln for ln in plain if ln.split("=")[0] in ("AUDIT_SEAL_LAG_MINUTES", "AUDIT_CHAIN_HEAD_FILE")]
    assert [m for m in dv.MENU if m[0] == "audit"]


# --------------------------------------------------------------------------- the host's acknowledgment

def test_the_host_acknowledges_a_late_seal_it_has_seen_and_nothing_appended_since(env):
    from app.core import audit_chain_host as host
    env.row(T0 - timedelta(hours=3, minutes=10))
    env.run_until_sealed()
    env.row(ai.hour_floor(T0 - timedelta(hours=3)) + timedelta(minutes=20))
    env.clock.advance(hours=1)
    env.seal()
    late = [s for s in env.seals() if s.kind == "late"][0]
    assert "late" in ai.status(env.st)["warnings"]
    seen = host.acknowledge(env.engine, env.st, seqs=[late.seq], failures=False, read=True)
    assert seen["state"].startswith("dvstate1:") and any(f"seal {late.seq} (late)" in ln for ln in seen["lines"])
    with pytest.raises(host.Refused):
        host.acknowledge(env.engine, env.st, seqs=[late.seq], failures=False, expect="dvchain1:1:" + "00" * 32)
    with pytest.raises(host.Refused):
        host.acknowledge(env.engine, env.st, seqs=[1], failures=False, read=True)
    # A seal appended between the two phases changes the state: nothing is written.
    env.clock.advance(hours=1)
    env.seal()
    with pytest.raises(host.Refused, match="changed since you looked"):
        host.acknowledge(env.engine, env.st, seqs=[late.seq], failures=False, expect=seen["state"])
    assert env.seals()[-1].kind != "ack"
    seen = host.acknowledge(env.engine, env.st, seqs=[late.seq], failures=False, read=True)
    done = host.acknowledge(env.engine, env.st, seqs=[late.seq], failures=False, expect=seen["state"])
    assert done["acknowledged"] == [late.seq]
    ack = env.seals()[-1]
    assert ack.kind == "ack" and ack.detail["by"] == "host" and ack.detail["acknowledges"] == [late.seq]
    assert "late" not in ai.status(env.st)["warnings"]
    report = env.verify()
    assert "late" not in report.kinds("warning") and failures(report) == []
    with env.session() as db:
        row = db.query(AuditLog).filter(AuditLog.action == ai.ACKNOWLEDGED_ACTION).one()
        assert row.username == "operator@host"
    env.fresh_process()           # another process accepts the host's seal through the head record
    env.clock.advance(hours=1)
    assert env.seal().stopped is None


def test_the_host_acknowledges_failures_and_they_leave_the_status(env):
    from app.core import audit_chain_host as host
    ids = _sealed(env)
    _update(env, ids[0], action="logout")
    v.daily_check(env.session, env.st, env.clock(), force=True)
    assert ai.status(env.st)["outcome"] == "failed"
    _update(env, ids[0], action="file_uploaded")
    seen = host.acknowledge(env.engine, env.st, seqs=[], failures=True, read=True)
    done = host.acknowledge(env.engine, env.st, seqs=[], failures=True, expect=seen["state"])
    assert done["failures"] == ["rows-altered"]
    assert ai.status(env.st)["failures"] == {}
    assert env.seals()[-1].detail["failures"][0][0] == "rows-altered"


def test_a_head_record_written_by_root_belongs_to_the_directorys_owner(tmp_path, monkeypatch):
    """A host command runs in the web container as root; the web process runs as the app's user, so every
    file of the head record a root process writes is handed to the owner of the keys directory."""
    from app.core import audit_head_record as hr
    chowned = []
    monkeypatch.setattr(hr.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(hr.os, "chown", lambda path, uid, gid: chowned.append(os.path.basename(path)), raising=False)
    store = hr.HeadStore(str(tmp_path / "keys" / "audit-chain-head.json"))
    store.write(lambda rec: {**rec, "seq": 1}, datetime(2026, 1, 1))
    assert "audit-chain-head.json.lock" in chowned
    assert any(name.startswith(".audit-chain-head.") for name in chowned)       # the file before its rename
    chowned.clear()
    monkeypatch.setattr(hr.os, "geteuid", lambda: 10001, raising=False)
    store.write(lambda rec: {**rec, "seq": 2}, datetime(2026, 1, 1))
    assert chowned == []


def test_a_head_record_written_by_root_is_handed_to_its_owner_before_it_is_synced(tmp_path, monkeypatch):
    """The file is given its owner before its sync, so the file synced, then put in place, is the final one, owner
    and all; the restore mark is written the same way."""
    from app.core import audit_head_record as hr
    events = []
    real_fsync, real_replace = os.fsync, os.replace
    monkeypatch.setattr(hr.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(hr.os, "chown", lambda path, uid, gid: events.append(("chown", os.path.basename(path))),
                        raising=False)
    monkeypatch.setattr(hr.os, "fsync", lambda fd: (events.append(("fsync", fd)), real_fsync(fd))[1])
    monkeypatch.setattr(hr.os, "replace", lambda a, b: (events.append(("replace", os.path.basename(a))),
                                                        real_replace(a, b))[1])
    path = str(tmp_path / "keys" / "audit-chain-head.json")
    for write in (lambda: hr.HeadStore(path).write(lambda rec: {**rec, "seq": 1}, datetime(2026, 1, 1)),
                  lambda: hr.write_mark(path, {"at": "2026-01-01T00:00:00Z"})):
        events.clear()
        write()
        at = next(i for i, e in enumerate(events) if e[0] == "replace")
        tmp = events[at][1]
        assert tmp.startswith(".audit-chain-head.")
        assert events[at - 1][0] == "fsync", events                       # the file's sync, then its rename
        assert ("chown", tmp) in events[:at - 1], events                  # its owner before that sync


def test_a_head_record_that_cannot_be_read_stops_a_new_process_and_not_a_running_one(env, monkeypatch):
    from app.core import audit_head_record as hr
    env.run_until_sealed()

    def refuse(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(hr, "read_file", refuse)
    env.clock.advance(hours=2)
    assert env.seal().stopped is None                     # the running process goes on from its own copy
    assert "head-record-unwritable" in ai.status(env.st)["warnings"]
    env.fresh_process()
    assert env.seal().stopped == "head-record-missing"   # a new one cannot know the head


def test_an_unreadable_head_record_never_lets_genesis_run_again(env, monkeypatch):
    from app.core import audit_head_record as hr

    def refuse(path):
        raise PermissionError(13, "Permission denied", path)

    monkeypatch.setattr(hr, "read_file", refuse)
    assert env.seal().stopped == "head-record-missing"
    assert env.seals() == []
