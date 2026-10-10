"""The audit log's archive (app/core/audit_archive.py, the format app/core/audit_archive_format.py), offline,
on a throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py):

- the block format: every model column, a round trip identical in every column, the dictionary, aggregates;
- the job: only sealed days older than the row window, nothing inside the grace period after the chain's
  genesis, a day the host put back left as rows for a grace of its own, parts of whole hours, a day over several
  passes, verified before the rows go (a corrupt block or a changed row keeps the rows), an hour an erase or
  another writer's unacknowledged seal holds left as rows, a crash between the steps, the data marker with the
  first block and gone with the last;
- the chain: the archive seal's rules, audit verify over blocks (altered, missing, unsealed, moved, a row put
  back), the daily check reading blocks in turn, an anchor checked without the key;
- changes to archived rows through the block-rewrite primitive (the audit job's deletions), the size cap's count
  of archived parts and what it may never delete of them, the preview of a retention change;
- the host's unarchive (rows and each hour's working data back, the chain still clean), its two phases, and its
  estimate; compact; the acknowledgment of a removal made by an older release with blocks present.
"""
import os
import uuid
from datetime import datetime, time, timedelta

import pytest
from sqlalchemy import func, text

from _audit_chain_env import Env, T0, failures
from test_audit_chain_held import _foreign_late
from app.core import audit_archive as arc
from app.core import audit_archive_format as af
from app.core import audit_chain_format as fmt
from app.core import audit_chain_host as host
from app.core import audit_chain_prune
from app.core import audit_chain_size as chain_size
from app.core import audit_chain_verify as v
from app.core import audit_integrity as ai
from app.core import audit_retention as ar
from app.core import retention
from app.core.audit_chain_view import ArchivePart, to_hours
from app.core.models import AuditArchiveBlock, AuditLog, RoleEnum, User

pytestmark = pytest.mark.unit

DAY = (T0 - timedelta(days=100)).date()


def at(hour, minute=0, day=DAY):
    return datetime.combine(day, time(hour, minute))


@pytest.fixture
def env(monkeypatch, tmp_path):
    e = Env(monkeypatch, tmp_path, audit_archive_start_after_days=0)
    arc._marker_checked.clear()
    arc._figures.clear()
    yield e
    e.close()


def _pass(env):
    return retention.Pass(env.session, now=env.clock())


def _archive(env):
    return arc.archive_job(_pass(env))


def _blocks(env):
    with env.session() as db:
        return db.query(AuditArchiveBlock).order_by(AuditArchiveBlock.day, AuditArchiveBlock.part).all()


def _archive_seals(env):
    return [s for s in env.seals() if s.kind == "archive"]


def _hot(env, day=DAY):
    with env.session() as db:
        return db.query(func.count()).select_from(AuditLog).filter(
            AuditLog.timestamp >= at(0, day=day), AuditLog.timestamp < at(0, day=day) + timedelta(days=1)).scalar()


def _rows(env, start, end):
    with env.session() as db:
        return list(arc.iter_full_rows(db, start, end))


def _put(env, when, **values):
    """A row with any column set."""
    row = dict(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=when, username="alice",
               ip_address="203.0.113.9", details={"n": 1}, seal_nonce=uuid.uuid4().bytes)
    row.update(values)
    with env.session() as db:
        db.add(AuditLog(**row))
        db.commit()
    return row["id"]


def _day_rows(env, per_hour, day=DAY, **kw):
    ids = []
    for hour, n in per_hour.items():
        for i in range(n):
            ids.append(env.row(at(hour, i % 60, day=day), **kw))
    return ids


def _sealed_day(env, per_hour=None, **kw):
    ids = _day_rows(env, per_hour or {3: 2, 4: 3, 6: 1}, **kw)
    env.run_until_sealed()
    assert failures(env.verify()) == []
    return ids


def _marker(env):
    with env.session() as db:
        try:
            return db.execute(text("SELECT requires_at_least, reason FROM data_requirements WHERE key = :k"),
                              {"k": arc.MARKER_KEY}).first()
        except Exception:  # noqa: BLE001 -- no table yet
            return None


def _unarchive(env, first=None, last=None):
    """The host's unarchive, both phases: the read, then the write with the state it printed."""
    seen = arc.unarchive(env.engine, env.st, first, last, read=True)
    return arc.unarchive(env.engine, env.st, first, last, expect=seen["state"])


def _ack_by_host(env, seqs):
    seen = host.acknowledge(env.engine, env.st, seqs=list(seqs), failures=False, read=True)
    return host.acknowledge(env.engine, env.st, seqs=list(seqs), failures=False, expect=seen["state"])


def _seal_days(env, days):
    """Sealing every six hours for ``days`` (no job deletes)."""
    end = env.clock() + timedelta(days=days)
    while env.clock() + timedelta(hours=6) <= end:
        env.clock.advance(hours=6)
        env.seal()


def _flip_block_byte(env, where=-3):
    """Change one byte of the first block's payload (flipping it again puts it back)."""
    payload = bytearray(_blocks(env)[0].payload)
    payload[where] ^= 1
    with env.session() as db:
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.part == 1).update(
            {AuditArchiveBlock.payload: bytes(payload)}, synchronize_session=False)
        db.commit()


def _numbers(max_days=95, admin_min=0, max_mb=0, min_days=0):
    return ar.Numbers(max_days, min_days, admin_min, max_mb)


def _blob(n):
    """``n`` bytes that do not compress: a row of about 2n bytes of hex."""
    return {"blob": os.urandom(n).hex()}


# --------------------------------------------------------------------------- the format

def test_a_block_holds_every_column_of_the_model():
    assert [c.name for c in AuditLog.__table__.columns] == list(af.NAMES)
    assert af.COLUMNS == (
        ("id", "uuid"), ("user_id", "uuid"), ("username", "text"), ("action", "text"),
        ("temp_credential_id", "uuid"), ("temp_credential_name", "text"), ("resource_type", "text"),
        ("resource_id", "text"), ("timestamp", "time"), ("ip_address", "text"), ("user_agent", "text"),
        ("method", "text"), ("endpoint", "text"), ("channel", "text"), ("status", "text"), ("details", "json"),
        ("error_message", "text"), ("seal_nonce", "bytes"), ("privacy_version", "int"), ("recorded", "json"),
        ("ip_via", "text"), ("case_id", "uuid"))


def test_a_column_of_a_type_the_archive_cannot_write_is_refused():
    import sqlalchemy as sa
    with pytest.raises(TypeError):
        af._kind_of(sa.Column("x", sa.Float()))


def test_the_dictionary_writes_a_repeated_value_once_and_reads_it_back():
    w = af.BlockWriter(DAY, 1)
    agents = ["Mozilla/5.0 (X11; Linux) é", "curl/8", "Mozilla/5.0 (X11; Linux) é", None, "curl/8"]
    for i, agent in enumerate(agents):
        w.add({"id": uuid.uuid4(), "timestamp": at(3, i), "action": "a", "status": "success", "user_agent": agent,
               "endpoint": "/api/files", "_bytes": 7})
    payload = w.finish()
    from compression import zstd
    lines = zstd.decompress(payload).decode("utf-8").splitlines()
    assert lines[1].count("Mozilla") == 1 and lines[3].count("Mozilla") == 0 and '"/api/files"' not in lines[2]
    block = af.open_block(payload)
    rows = list(block.rows())
    assert [r["user_agent"] for r in rows] == agents
    assert [r["_bytes"] for r in rows] == [7] * 5
    assert block.identity.digest() == w.identity.digest() and block.aggregates == w.aggregates
    assert w.aggregates["hours"] == [[fmt.hour_text(at(3)), 5, 35]]


def _raw_block(*rows):
    from compression import zstd
    import json
    head = zstd.decompress(af.BlockWriter(DAY, 1).finish()).decode("utf-8").splitlines()[0]
    return zstd.compress((head + "\n" + "".join(json.dumps(r) + "\n" for r in rows)).encode())


def _raw_row(**values):
    row = [None] * len(af.NAMES) + [0]
    row[af.NAMES.index("id")] = uuid.uuid4().hex
    for name, value in values.items():
        if name == "_bytes":
            row[-1] = value
        else:
            row[af.NAMES.index(name)] = value
    return row


@pytest.mark.parametrize("values", [{"user_agent": 0}, {"_bytes": "12"}, {"_bytes": True},
                                    {"timestamp": "yesterday"}, {"seal_nonce": "zz"}])
def test_a_row_the_format_does_not_allow_is_refused(values):
    with pytest.raises(af.BlockError):
        list(af.open_block(_raw_block(_raw_row(**values))).rows())


def test_a_payload_of_another_format_or_columns_is_refused():
    from compression import zstd
    with pytest.raises(af.BlockError):
        af.open_block(zstd.compress(b'{"format": 2, "columns": []}\n'))
    with pytest.raises(af.BlockError):
        af.open_block(zstd.compress(b'{"format": 1, "columns": ["id"]}\n'))
    with pytest.raises(af.BlockError):
        af.open_block(b"not zstd at all")


def test_a_round_trip_is_identical_in_every_column(env):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username="alice", email="alice@example.com", password_hash="x", role=RoleEnum.USER,
                    is_active=True))
        db.commit()
    ids = [env.row(at(3, 5), username="alice", user_id=uid, temp_credential_id=uuid.uuid4(),
                   temp_credential_name="temp_x", resource_type="file", resource_id="r-1", user_agent="Agent é",
                   method="POST", endpoint="/api/files/upload", channel="sftp", error_message="none\nat all",
                   privacy_version=3, recorded={"ip": "shortened", "n": [1, 2.5]}, ip_via="direct",
                   case_id=uuid.uuid4(), details={"a": None}),
           env.row(at(3, 6), nonce=False, details=None, ip_address=None),
           _put(env, at(4, 0), action="settings_updated", status="failure", channel=None)]
    with env.engine.begin() as conn:     # a JSON text as the database stored it, spelled oddly
        conn.exec_driver_sql("UPDATE audit_logs SET details = ? WHERE id = ?",
                             ('{ "b" : [1, 2.50, "x"],  "a": null }', ids[0].hex))
    env.run_until_sealed()
    before = _rows(env, at(0), at(0) + timedelta(days=1))
    _archive(env)
    assert _hot(env) == 0 and len(_blocks(env)) == 1
    assert failures(env.verify()) == []
    done = _unarchive(env)
    assert done == {"days": [DAY.isoformat()], "rows": 3}
    after = _rows(env, at(0), at(0) + timedelta(days=1))
    assert after == before
    assert after[0]["details"] == '{ "b" : [1, 2.50, "x"],  "a": null }'
    assert failures(env.verify()) == []


def test_aggregates_equal_the_sql_counts(env):
    _day_rows(env, {3: 2, 5: 3})
    _put(env, at(5, 30), action="login", status="failure", channel="web")
    _put(env, at(7, 1), action="login", status="failure", channel="web")
    env.run_until_sealed()
    with env.session() as db:
        counts = {(a, s, c): n for a, s, c, n in db.query(
            AuditLog.action, AuditLog.status, AuditLog.channel, func.count()).filter(
            AuditLog.timestamp < at(0) + timedelta(days=1)).group_by(AuditLog.action, AuditLog.status,
                                                                     AuditLog.channel).all()}
        per_hour = {}
        for (t,) in db.query(AuditLog.timestamp).filter(AuditLog.timestamp < at(0) + timedelta(days=1)).all():
            h = fmt.hour_text(ai.hour_floor(t))
            per_hour[h] = per_hour.get(h, 0) + 1
    _archive(env)
    found, hours = {}, {}
    for block in _blocks(env):
        for action, status, channel, rows, line, stored in block.aggregates["by"]:
            found[(action, status, channel)] = found.get((action, status, channel), 0) + rows
            assert line > 0 and stored > 0
        for h, rows, stored in block.aggregates["hours"]:
            hours[h] = hours.get(h, 0) + rows
            assert stored > 0
    assert found == counts and counts[("login", "failure", "web")] == 2
    assert hours == per_hour


# --------------------------------------------------------------------------- the job

def test_a_sealed_day_older_than_the_window_moves_into_a_block(env):
    _sealed_day(env)
    _archive(env)
    assert _hot(env) == 0
    blocks = _blocks(env)
    # The chain starts at the day's first row (03:00): the part runs from there to the day's last hour.
    assert [(b.part, b.first_hour, b.last_hour, b.row_count, b.codec, b.format) for b in blocks] == \
        [(1, at(3), at(23), 6, "zstd", 1)]
    (seal,) = _archive_seals(env)
    d = seal.detail
    assert d["day"] == DAY.isoformat() and d["cause"] == "archive" and d["after_seq"] is None and d["complete"]
    assert d["parts"] == [[1, fmt.hour_text(at(3)), fmt.hour_text(at(23)), 6, len(blocks[0].payload),
                           af.digest(blocks[0].payload)]]
    assert seal.period_start == at(0) and seal.row_count == 6 and seal.row_bytes == len(blocks[0].payload)
    with env.session() as db:      # the hours' working data went with the rows
        assert all(ai.working_row(db, at(h)).row_ids is None for h in (3, 4, 6))
    assert failures(env.verify()) == []


def test_a_day_inside_the_window_and_a_day_not_sealed_stay_rows(env, monkeypatch):
    young = (T0 - timedelta(days=89)).date()
    env.row(at(10, day=young))
    _day_rows(env, {3: 1, 4: 1, 5: 1, 6: 1})
    monkeypatch.setattr(ai, "ROW_BUDGET", 2)
    env.seal()                     # genesis, then hours until two rows are sealed: the day is not sealed whole
    assert env.st.view.newest_hour_end <= at(6)
    _archive(env)
    assert _blocks(env) == [] and _hot(env) == 4
    monkeypatch.setattr(ai, "ROW_BUDGET", 50000)
    env.run_until_sealed()
    _archive(env)
    assert _hot(env) == 0 and _hot(env, young) == 1
    assert [b.day for b in _blocks(env)] == [DAY]


def test_the_row_window_is_a_setting(env):
    young = (T0 - timedelta(days=40)).date()
    env.row(at(10, day=young))
    env.run_until_sealed()
    _archive(env)
    assert _hot(env, young) == 1
    env.settings.audit_hot_days = 31
    _archive(env)
    assert _hot(env, young) == 0 and arc.summary(env.st)["hot_days"] == 31


def test_nothing_is_archived_inside_the_grace_period_after_the_chains_genesis(env):
    env.settings.audit_archive_start_after_days = 14
    _sealed_day(env)
    genesis = env.st.view.at(1)
    assert genesis == T0
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == []
    env.clock.advance(days=13, hours=23)
    env.seal()
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == []
    s = arc.summary(env.st)
    assert s["first_start"] == fmt.time_text(genesis) and s["starts_on"] == fmt.time_text(genesis + timedelta(days=14))
    assert s["start_after_days"] == 14
    env.clock.advance(hours=1)
    env.seal()
    _archive(env)
    assert _hot(env) == 0


def test_a_day_the_host_put_back_stays_rows_for_the_grace(env):
    _sealed_day(env)
    _archive(env)
    _unarchive(env)
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == []            # at least a day, with no grace set
    env.clock.advance(hours=23)
    env.seal()
    _archive(env)
    assert _hot(env) == 6
    env.clock.advance(hours=1)
    env.seal()
    _archive(env)
    assert _hot(env) == 0 and failures(env.verify()) == []


def test_parts_hold_whole_hours_and_a_large_hour_has_its_own(env, monkeypatch):
    monkeypatch.setattr(arc, "PART_ROWS", 5)
    _sealed_day(env, {0: 3, 1: 3, 2: 7, 5: 2})
    _archive(env)
    ranges = [(b.part, b.first_hour.hour, b.last_hour.hour, b.row_count) for b in _blocks(env)]
    # The empty hours after the large one go with it; the day's last part reaches its last hour.
    assert ranges == [(1, 0, 0, 3), (2, 1, 1, 3), (3, 2, 4, 7), (4, 5, 23, 2)]
    seals = _archive_seals(env)
    assert [len(s.detail["parts"]) for s in seals] == [1, 2, 3, 4]
    assert [s.detail["complete"] for s in seals] == [False, False, False, True]
    assert failures(env.verify()) == []


def test_a_day_archived_over_two_passes_is_complete_only_on_the_second(env, monkeypatch):
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    _sealed_day(env, {2: 3, 9: 3})
    monkeypatch.setattr(ai, "ROW_BUDGET", 3)
    _archive(env)
    assert [s.detail["complete"] for s in _archive_seals(env)] == [False]
    assert _hot(env) == 3                         # the later hours are still rows, and that is no finding
    assert failures(env.verify()) == []
    _archive(env)
    assert [s.detail["complete"] for s in _archive_seals(env)] == [False, True]
    assert _hot(env) == 0 and failures(env.verify()) == []


def test_a_changed_row_is_not_archived_and_is_reported(env):
    ids = _sealed_day(env)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.id == ids[0]).update({AuditLog.username: "mallory"},
                                                                synchronize_session=False)
        db.commit()
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == [] and _archive_seals(env) == []
    assert "rows-altered" in ai.open_failures(env.st.head_store().load())


def test_a_block_stored_wrong_keeps_the_rows(env, monkeypatch):
    _sealed_day(env)
    real = arc._insert_block

    def corrupt(db, day, number, first, last, bw, payload, now):
        real(db, day, number, first, last, bw, payload[:-1] + bytes([payload[-1] ^ 1]), now)
    monkeypatch.setattr(arc, "_insert_block", corrupt)
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == [] and _archive_seals(env) == []


def test_a_block_that_gives_other_rows_keeps_the_rows(env, monkeypatch):
    """The stored block decodes, its length and digest are right, and still it is not the rows: the identity
    check catches it before anything is deleted."""
    _sealed_day(env)
    real_add = af.BlockWriter.add

    def add(self, row):
        real_add(self, row)
        self.identity.update(b"x")                # what was read differs from what the block gives back
    monkeypatch.setattr(af.BlockWriter, "add", add)
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == []


def test_a_crash_between_the_steps_leaves_the_rows(env, monkeypatch):
    _sealed_day(env)
    real = arc._clear_working_data

    def crash(db, hours):
        raise RuntimeError("the process stopped here")
    monkeypatch.setattr(arc, "_clear_working_data", crash)
    with pytest.raises(RuntimeError):
        arc._archive_days(_pass(env), env.engine, env.st, {})
    assert _hot(env) == 6 and _blocks(env) == [] and _archive_seals(env) == []
    assert _marker(env) is None
    monkeypatch.setattr(arc, "_clear_working_data", real)
    env.fresh_process()
    env.seal()
    _archive(env)
    assert _hot(env) == 0 and failures(env.verify()) == []


def test_a_crash_after_the_commit_and_before_the_record_write(env, monkeypatch):
    """The archive seal committed and the head record was not written: the next process accepts it as
    another writer's, a warning until the host acknowledges it; nothing is lost."""
    _sealed_day(env)
    real = ai.ChainWriter.still_locked
    monkeypatch.setattr(ai.ChainWriter, "still_locked", lambda self: False)
    _archive(env)
    monkeypatch.setattr(ai.ChainWriter, "still_locked", real)
    seq = _archive_seals(env)[0].seq
    assert int(env.st.head_store().load()["seq"]) < seq          # the record does not have it
    env.fresh_process()
    env.seal()
    assert env.st.stopped is None and _hot(env) == 0 and len(_blocks(env)) == 1
    assert "after-record" in ai.status(env.st)["warnings"]
    assert host.warning_seqs(env.st.view, env.st.head_store().load()) == [seq]
    assert failures(env.verify()) == []
    _ack_by_host(env, [seq])
    assert "after-record" not in ai.status(env.st)["warnings"]
    assert [f for f in env.verify().findings if f.severity != v.INFO] == []


def test_the_marker_appears_with_the_first_block_and_goes_with_the_last(env):
    _sealed_day(env)
    _archive(env)
    marker = _marker(env)
    assert marker is not None and "compressed daily blocks" in marker[1]
    _unarchive(env)
    assert _marker(env) is None and _blocks(env) == []


def test_the_daily_check_puts_the_marker_back(env):
    _sealed_day(env)
    _archive(env)
    with env.engine.begin() as conn:
        conn.exec_driver_sql("DELETE FROM data_requirements")
    arc._marker_checked.clear()
    _archive(env)
    assert _marker(env) is not None


def test_an_hour_an_erase_follows_is_left_as_rows(env):
    _sealed_day(env)
    # An erase seal after hour 4's seal, as the view would hold it (seal 2, which reads back cleanly and erases
    # no row, stands in for one: no writer of erase seals yet).
    env.st.view._erases[to_hours(at(4))] = [2]
    _archive(env)
    assert _hot(env) == 6 and _blocks(env) == []


def test_an_hour_another_writer_resealed_is_left_as_rows_until_the_host_acknowledges_it(env):
    _sealed_day(env)
    extra = env.row(at(4, 30))
    late = _foreign_late(env, at(4), [extra])
    env.clock.advance(minutes=30)
    assert env.seal().stopped is None
    _archive(env)
    assert _hot(env) == 7 and _blocks(env) == []                  # nothing of the day, not just hour 4
    _ack_by_host(env, [late])
    _archive(env)
    assert _hot(env) == 0 and len(_blocks(env)) == 1
    assert failures(env.verify()) == []


# --------------------------------------------------------------------------- the chain over blocks

def test_rows_without_a_nonce_keep_their_salt_in_the_block_and_get_it_back(env):
    _sealed_day(env, nonce=False)
    with env.session() as db:
        salt = bytes(ai.working_row(db, at(3)).legacy_salt)
    _archive(env)
    with env.session() as db:
        assert ai.working_row(db, at(3)).legacy_salt is None
    block = af.open_block(_blocks(env)[0].payload)
    assert block.salts[at(3)] == salt
    assert failures(env.verify()) == []
    _unarchive(env)
    with env.session() as db:
        wr = ai.working_row(db, at(3))
        assert bytes(wr.legacy_salt) == salt and len(wr.row_ids) == 2 * 16
    assert all(r["seal_nonce"] is None for r in _rows(env, at(0), at(23)))
    assert failures(env.verify()) == []


def test_a_changed_block_is_found(env):
    _sealed_day(env)
    _archive(env)
    _flip_block_byte(env, len(_blocks(env)[0].payload) // 2)
    assert "block-altered" in failures(env.verify())


def test_a_block_of_another_length_is_found_without_reading_it(env, monkeypatch):
    _sealed_day(env)
    _archive(env)
    with env.session() as db:
        db.query(AuditArchiveBlock).update({AuditArchiveBlock.payload: _blocks(env)[0].payload + b"x"},
                                           synchronize_session=False)
        db.commit()
    monkeypatch.setattr(arc, "read_payload", lambda *a, **k: pytest.fail("a payload was read"))
    report = env.verify(check_rows=True, from_hour=T0 - timedelta(days=7))
    assert any(f.kind == "block-altered" and "bytes" in f.message for f in report.findings)


def test_a_removed_block_and_an_added_block_are_found(env):
    _sealed_day(env)
    _archive(env)
    block = _blocks(env)[0]
    with env.session() as db:
        db.add(AuditArchiveBlock(day=block.day, part=2, first_hour=block.first_hour, last_hour=block.last_hour,
                                 row_count=block.row_count, codec="zstd", format=1, payload=block.payload,
                                 raw_bytes=block.raw_bytes, aggregates=block.aggregates, created_at=T0))
        db.commit()
    assert "block-unsealed" in failures(env.verify())
    with env.session() as db:
        db.query(AuditArchiveBlock).delete(synchronize_session=False)
        db.commit()
    found = failures(env.verify())
    assert "block-missing" in found and "block-unsealed" not in found


def test_changed_aggregates_are_found(env):
    _sealed_day(env)
    _archive(env)
    agg = dict(_blocks(env)[0].aggregates)
    agg["by"] = [["file_uploaded", "success", None, 99, 1, 1]]
    with env.session() as db:
        db.query(AuditArchiveBlock).update({AuditArchiveBlock.aggregates: agg}, synchronize_session=False)
        db.commit()
    assert "block-altered" in failures(env.verify())


def test_two_parts_swapped_are_found(env, monkeypatch):
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    _sealed_day(env, {2: 3, 9: 3})
    _archive(env)
    first, second = _blocks(env)
    with env.session() as db:         # both payloads swapped: each is a block a seal binds, for the other part
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.part == 1).update(
            {AuditArchiveBlock.payload: second.payload}, synchronize_session=False)
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.part == 2).update(
            {AuditArchiveBlock.payload: first.payload}, synchronize_session=False)
        db.commit()
    assert "block-altered" in failures(env.verify())


def test_a_row_put_back_into_an_archived_hour_is_found_and_never_pruned_or_sealed_over(env):
    _sealed_day(env)
    _archive(env)
    back = env.row(at(4, 30))
    assert "row-in-archived-day" in failures(env.verify())
    audit_chain_prune.prune(_pass(env), [AuditLog.timestamp < T0], reason="retention")
    with env.session() as db:
        assert db.get(AuditLog, back) is not None
    assert "row-in-archived-day" in ai.open_failures(env.st.head_store().load())
    with pytest.raises(host.Refused, match="archived"):
        host.seal_late_rows(env.engine, env.st, at(4), read=True)


def test_the_daily_check_reads_the_blocks_in_turn(env):
    _sealed_day(env)
    _archive(env)
    _flip_block_byte(env)                        # the same length: only reading the block shows it
    report = v.daily_check(env.session, env.st, force=True)
    assert "block-altered" in failures(report)


def test_the_rolling_check_reaches_every_part_and_hour_in_thirty_days(env, monkeypatch):
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    for d in range(4):
        _day_rows(env, {2: 3, 9: 3}, day=DAY + timedelta(days=d))
    env.row(T0 - timedelta(days=20))
    env.run_until_sealed()
    _archive(env)
    parts = list(env.st.view.archived_parts())
    assert len(parts) == 8
    read, hours = [], []
    monkeypatch.setattr(arc, "check_parts", lambda db, view, report, ps: read.extend(ps))
    monkeypatch.setattr(v, "check_hour", lambda db, view, entry, hour, report: hours.append(hour))
    rolling = None
    for _ in range(v.ROLLING_DAYS):
        with env.session() as db:
            rolling = v._rolling(db, env.st.view, v.Report(), T0 - timedelta(days=7), rolling)
    assert {p for _d, p in read} == {p for _d, p in parts}
    assert ai.hour_floor(T0 - timedelta(days=20)) in hours


# --------------------------------------------------------------------------- the archive seal's rules

def _part(first, last, rows=1, length=10, number=1):
    return [number, fmt.hour_text(first), fmt.hour_text(last), rows, length, "ab" * 32]


def _forge_archive(env, parts, *, cause="archive", complete=None, after=None, period=None, day=DAY, totals=None):
    view = env.st.view
    if complete is None:
        try:
            listed = [ArchivePart(p[0], fmt.parse_time_text(p[1]), fmt.parse_time_text(p[2]), p[3], p[4], p[5])
                      for p in parts]
            complete = bool(parts) and arc.covers_day(view, listed, day)
        except (TypeError, ValueError):
            complete = False
    detail = {"day": day.isoformat(), "cause": cause, "after_seq": after, "complete": complete, "parts": parts}
    start = period or datetime.combine(day, time())
    rows, length = totals or (sum(p[3] for p in parts), sum(p[4] for p in parts))
    with ai.ChainWriter(env.engine, env.st) as w:
        return w.append("archive", detail=detail, period_start=start, period_end=start + timedelta(days=1),
                        row_count=rows, row_bytes=length).seq


def _unjustified(env):
    with env.session() as db:
        report = v.verify(db, record=None, held={}, now=env.clock(), check_rows=False)
    return [f.message for f in report.findings if f.kind == "unjustified"]


@pytest.mark.parametrize("parts,kw,why", [
    ([_part(at(3), at(5)), _part(at(5), at(23), number=2)], {}, "overlap"),
    ([_part(at(3), at(23))], {"complete": False}, "complete flag"),
    ([_part(at(3), at(23))], {"cause": "rewrite"}, "does not follow its change"),
    ([_part(at(3), at(23))], {"cause": "unarchive"}, "keeps a part"),
    ([_part(at(3), at(23))], {"cause": "other"}, "of cause 'other'"),
    ([_part(at(3), at(23))], {"period": at(1)}, "period is not its day"),
    ([_part(at(3), at(23) + timedelta(hours=1))], {}, "not in its day"),
    ([_part(at(3), at(23)), _part(at(3), at(3), number=1)], {}, "a part twice"),
    ([_part(at(1), at(23))], {}, "hours not sealed"),
    ([[0, fmt.hour_text(at(3)), fmt.hour_text(at(23)), 1, 10, "ab" * 32]], {}, "bad part"),
    ([[1, fmt.hour_text(at(3)), fmt.hour_text(at(23)), 1, 10, "AB" * 32]], {}, "bad part"),
    ([[1, fmt.time_text(at(3, 30)), fmt.hour_text(at(23)), 1, 10, "ab" * 32]], {}, "bad part"),
    ([], {}, "with a change or no part"),
    ([_part(at(3), at(23))], {"totals": (2, 10)}, "totals are not its parts'"),
    ([_part(at(3), at(23))], {"totals": (1, 11)}, "totals are not its parts'"),
])
def test_an_archive_seal_breaking_a_rule_is_unjustified(env, parts, kw, why):
    _sealed_day(env)
    _forge_archive(env, parts, **kw)
    assert any(why in m for m in _unjustified(env)), _unjustified(env)


@pytest.mark.parametrize("complete", ["", 0, "false", True])
def test_an_unarchive_seal_must_say_it_is_not_complete_and_nothing_else(env, complete):
    _sealed_day(env)
    _archive(env)
    _forge_archive(env, [], cause="unarchive", complete=complete)
    assert any("complete flag" in m for m in _unjustified(env)), _unjustified(env)


@pytest.mark.parametrize("after,why", [(1, "does not follow its change"), (None, "does not follow its change"),
                                       (True, "does not follow its change"),
                                       ("last", "whose change is not one of its day")])
def test_a_rewrite_seal_must_follow_right_after_a_change_of_its_day(env, after, why):
    _sealed_day(env)
    _archive(env)
    (seal,) = _archive_seals(env)
    _forge_archive(env, seal.detail["parts"], cause="rewrite", after=seal.seq if after == "last" else after)
    assert any(why in m for m in _unjustified(env)), _unjustified(env)


def test_an_archive_seal_may_not_change_the_days_earlier_parts(env, monkeypatch):
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    _sealed_day(env, {2: 3, 9: 3})
    monkeypatch.setattr(ai, "ROW_BUDGET", 3)
    _archive(env)
    (first,) = _archive_seals(env)
    changed = list(first.detail["parts"][0])
    changed[3] += 1
    _forge_archive(env, [changed, _part(at(9), at(23), number=2)])
    assert any("changes the day's parts without a change" in m for m in _unjustified(env))


def test_an_archive_seal_of_hours_not_sealed_is_unjustified(env):
    env.run_until_sealed()
    day = (T0 - timedelta(hours=2)).date()
    start = datetime.combine(day, time())
    _forge_archive(env, [_part(start, start + timedelta(hours=23))], day=day)
    assert any("hours not sealed" in m for m in _unjustified(env)), _unjustified(env)


def test_an_archive_seal_appended_after_the_record_is_judged_by_its_rules(env):
    """Accepted when it meets them (then found missing its block), refused when it does not."""
    from test_audit_chain_guards import _forge
    _sealed_day(env)
    _forge(env, "archive", {"day": DAY.isoformat(), "cause": "archive", "after_seq": None, "complete": False,
                            "parts": [_part(at(3), at(5))]}, period_start=at(0), period_end=at(0) + timedelta(days=1),
           row_count=1, row_bytes=10)
    env.clock.advance(minutes=30)
    assert env.seal().stopped is None
    assert "block-missing" in failures(env.verify())


def test_an_archive_seal_with_overlapping_parts_appended_after_the_record_is_refused(env):
    from test_audit_chain_guards import _forge, _stopped_by
    _sealed_day(env)
    _forge(env, "archive", {"day": DAY.isoformat(), "cause": "archive", "after_seq": None, "complete": False,
                            "parts": [_part(at(3), at(4)), _part(at(4), at(5), number=2)]},
           period_start=at(0), period_end=at(0) + timedelta(days=1), row_count=2, row_bytes=20)
    assert "overlap" in _stopped_by(env, "after-record-invalid")


def test_without_the_key_an_archive_seal_after_an_anchor_that_covered_the_day_is_not_authenticated(env):
    from test_audit_chain_guards import _off
    _sealed_day(env)
    anchor = env.verify().head
    _archive(env)
    report = _off(env, anchor=anchor)
    found = [f for f in report.findings if f.kind == "changed-after-anchor"]
    assert [(f.severity, f.seq) for f in found] == [(v.WARNING, _archive_seals(env)[0].seq)]
    assert DAY.isoformat() in found[0].message
    later = env.verify().head
    assert [f for f in _off(env, anchor=later).findings if f.kind == "changed-after-anchor"] == []
    assert [f for f in env.verify(anchor=anchor).findings if f.kind == "changed-after-anchor"] == []


# --------------------------------------------------------------------------- deleting archived rows

def test_the_audit_job_deletes_archived_rows_by_rewriting_the_block(env):
    protected = ar.protected_actions()[0]
    ids = _day_rows(env, {3: 2, 4: 3, 6: 1})
    keep = env.row(at(8), action=protected)
    env.run_until_sealed()
    _archive(env)
    ar.prune(_pass(env), _numbers(admin_min=365))
    seals = env.seals()
    prune, rewrite = seals[-2], seals[-1]
    assert prune.kind == "prune" and rewrite.kind == "archive"
    assert rewrite.detail["cause"] == "rewrite" and rewrite.detail["after_seq"] == prune.seq
    assert [h[0] for h in prune.detail["hours"]] == [fmt.hour_text(at(h)) for h in (3, 4, 6)]
    (block,) = _blocks(env)
    rows = list(af.open_block(block.payload).rows())
    assert [r["id"] for r in rows] == [keep] and block.rewritten_at == T0
    assert rewrite.detail["parts"][0][3] == 1 and rewrite.detail["complete"]
    assert failures(env.verify()) == []
    with env.session() as db:
        pruned = db.query(AuditLog).filter(AuditLog.action == "retention_pruned").all()
    assert pruned and pruned[-1].details["deleted"] == len(ids)


def test_a_day_whose_archived_rows_all_go_loses_its_blocks(env):
    _sealed_day(env, nonce=False)
    _archive(env)
    ar.prune(_pass(env), _numbers())
    assert _blocks(env) == [] and _marker(env) is None
    last = _archive_seals(env)[-1]
    assert last.detail["cause"] == "rewrite" and last.detail["parts"] == [] and not last.detail["complete"]
    assert failures(env.verify()) == []


def test_a_partial_deletion_materialises_the_hours_nonces(env):
    protected = ar.protected_actions()[0]
    env.row(at(3, 1), nonce=False)
    kept = env.row(at(3, 2), nonce=False, action=protected)
    env.row(at(5, 1), nonce=False, action=protected)
    env.run_until_sealed()
    _archive(env)
    ar.prune(_pass(env), _numbers(admin_min=365))
    block = af.open_block(_blocks(env)[0].payload)
    rows = {r["id"]: r for r in block.rows()}
    assert rows[kept]["seal_nonce"] is not None                 # its hour changed: the nonce is written
    assert at(3) not in block.salts and at(5) in block.salts    # the unchanged hour keeps its salt
    assert failures(env.verify()) == []


def test_an_archived_day_with_nothing_to_delete_is_read_once_a_day(env, monkeypatch):
    protected = ar.protected_actions()[0]
    env.row(at(3), action=protected)
    env.run_until_sealed()
    _archive(env)
    reads = []
    real = arc.rewrite_day
    monkeypatch.setattr(arc, "rewrite_day", lambda *a, **k: reads.append(1) or real(*a, **k))
    ar.prune(_pass(env), _numbers(admin_min=365))
    ar.prune(_pass(env), _numbers(admin_min=365))
    assert reads == [1]
    env.clock.advance(days=1)
    env.seal()
    ar.prune(_pass(env), _numbers(admin_min=365))
    assert reads == [1, 1] and len(_blocks(env)) == 1


def test_a_changed_block_stops_the_deletion_of_its_day(env):
    _sealed_day(env)
    _archive(env)
    _flip_block_byte(env)
    before = len(env.seals())
    ar.prune(_pass(env), _numbers())
    assert len(env.seals()) == before and len(_blocks(env)) == 1
    assert "block-altered" in ai.open_failures(env.st.head_store().load())


def test_an_archived_hour_another_writer_resealed_is_not_changed_until_acknowledged(env):
    """An hour whose root seal is another writer's, not acknowledged, waits: here the view says so of hour 4
    (tests above build such a seal; the rule is the same function the hot rows' prune uses)."""
    _sealed_day(env)
    _archive(env)
    held = list(env.st.view.archives[DAY].parts)
    real = arc.held_hour
    arc.held_hour = lambda view, record, hour: 99 if hour == at(4) else None
    try:
        before = len(env.seals())
        ar.prune(_pass(env), _numbers())
        assert len(env.seals()) == before and list(env.st.view.archives[DAY].parts) == held
    finally:
        arc.held_hour = real
    env.clock.advance(days=1)                     # a day it found nothing to change in is read again the next day
    env.seal()
    ar.prune(_pass(env), _numbers())
    assert _blocks(env) == []


def test_a_crash_after_a_change_to_an_archived_hour_and_before_the_record_write(env, monkeypatch):
    """Both seals of the transaction (the prune and the archive seal of cause rewrite) committed, the head record
    not written: the next process accepts both as another writer's, warnings until the host acknowledges them."""
    _sealed_day(env)
    _archive(env)
    real = ai.ChainWriter.still_locked
    monkeypatch.setattr(ai.ChainWriter, "still_locked", lambda self: False)
    ar.prune(_pass(env), _numbers())
    monkeypatch.setattr(ai.ChainWriter, "still_locked", real)
    prune, rewrite = env.seals()[-2:]
    assert (prune.kind, rewrite.kind, rewrite.detail["after_seq"]) == ("prune", "archive", prune.seq)
    env.fresh_process()
    env.seal()
    assert env.st.stopped is None
    assert host.warning_seqs(env.st.view, env.st.head_store().load()) == [prune.seq, rewrite.seq]
    assert failures(env.verify()) == []
    _ack_by_host(env, [prune.seq, rewrite.seq])
    assert [f for f in env.verify().findings if f.severity != v.INFO] == []


def test_a_part_reaches_over_an_hour_a_whole_hour_prune_emptied(env):
    _day_rows(env, {3: 2, 5: 2})
    env.run_until_sealed()
    audit_chain_prune.prune(_pass(env), [AuditLog.timestamp < at(4)], reason="retention")
    assert _hot(env) == 2
    _archive(env)
    ((_n, first, last, rows, _l, _d),) = _archive_seals(env)[-1].detail["parts"]
    assert (first, last, rows) == (fmt.hour_text(at(3)), fmt.hour_text(at(23)), 2)
    assert _archive_seals(env)[-1].detail["complete"] is True
    assert failures(env.verify()) == []


def test_a_day_archived_in_part_counts_its_parts_and_its_hot_hours(env, monkeypatch):
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    _sealed_day(env, {2: 3, 9: 3})
    monkeypatch.setattr(ai, "ROW_BUDGET", 3)
    _archive(env)
    _seal_days(env, 8)
    hot, parts = _counted(env)
    ((_d, part, counted, hours),) = parts
    assert set(hours) == {at(2)} and part.last_hour == at(8)
    assert hot[at(9)] == env.st.view.entry_for(at(9)).root.bytes
    st = env.st
    start = chain_size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=7))
    assert chain_size.total(st.view, start, set()) == counted + sum(hot.values())


# --------------------------------------------------------------------------- the size cap

def _counted(env, delay=7):
    st = env.st
    start = chain_size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=delay))
    return chain_size.counted(st.view, start, chain_size.held_back(st.view, st.known_record(), start))


def test_the_size_cap_counts_an_archived_part_by_the_smaller_of_its_length_and_its_hours(env):
    _sealed_day(env)
    _archive(env)
    _seal_days(env, 8)
    hot, parts = _counted(env)
    ((day, part, counted, hours),) = parts
    lagged = {h: env.st.view.entry_for(h).root.bytes for h in (at(3), at(4), at(6))}
    assert day == DAY and hours == lagged and not (set(hot) & set(lagged))
    assert counted == min(part.length, sum(lagged.values()))
    with env.session() as db:
        plan = ar.chain_size_plan(db, AuditLog, env.st.view, env.st.known_record(), env.clock(),
                                  _numbers(max_days=0, max_mb=1), timedelta(days=7))
    assert plan.counted_bytes == sum(hot.values()) + counted == plan.size["counted"]


def test_an_archived_part_counts_nothing_before_a_delay_of_sealing_has_passed_after_its_hours(env):
    _sealed_day(env)
    _archive(env)
    assert _counted(env)[1][0][2] == 0


def test_an_inflated_part_length_counts_no_more_than_its_hours(env):
    _sealed_day(env)
    _archive(env)
    _seal_days(env, 8)
    (_d, part, counted, hours) = _counted(env)[1][0]
    inflated = ArchivePart(part.part, part.first_hour, part.last_hour, part.rows, 10 ** 12, part.sha256)
    entry = env.st.view.archives[DAY]
    env.st.view.archives[DAY] = type(entry)(entry.seq, entry.cause, entry.complete, (inflated,))
    assert _counted(env)[1][0][2] == sum(hours.values()) >= counted


def _capped(env, monkeypatch):
    """The chain's own cap of 1, in bytes: a size-cap prune under a test's larger cap is then justified."""
    monkeypatch.setattr(ar, "MB", 1)
    monkeypatch.setenv("AUDIT_LOG_MAX_MB", "1")
    env.settings.audit_log_max_mb = 1


def test_the_size_cap_deletes_archived_rows_beyond_it_and_verify_recomputes_its_total(env, monkeypatch):
    _capped(env, monkeypatch)
    env.row(at(3), details=_blob(15000))
    env.row(at(9), details=_blob(15000))
    env.run_until_sealed()
    _archive(env)
    _seal_days(env, 8)
    (_d, part, counted, hours) = _counted(env)[1][0]
    cap = counted * hours[at(9)] // sum(hours.values()) + 1000     # room for the newer hour only
    assert cap < counted
    ar.prune(_pass(env), _numbers(max_days=0, max_mb=cap))
    prune = [s for s in env.seals() if s.kind == "prune"][-1]
    assert prune.detail["reason"] == "size-cap" and prune.detail["size"]["counted"] == counted
    rows = list(af.open_block(_blocks(env)[0].payload).rows())
    assert [r["timestamp"] for r in rows] == [at(9)]
    report = env.verify()
    assert failures(report) == []


def test_the_size_cap_never_deletes_the_archived_rows_it_protects_and_counts_them(env, monkeypatch):
    _capped(env, monkeypatch)
    protected = ar.protected_actions()[0]
    admin = env.row(at(3), action=protected, details=_blob(15000))
    env.row(at(9), details=_blob(15000))
    env.run_until_sealed()
    _archive(env)
    _seal_days(env, 8)
    with env.session() as db:
        plan = ar.chain_size_plan(db, AuditLog, env.st.view, env.st.known_record(), env.clock(),
                                  _numbers(max_days=0, max_mb=1), timedelta(days=7))
    assert 0 < plan.protected_bytes < plan.counted_bytes and not plan.met
    ar.prune(_pass(env), _numbers(max_days=0, max_mb=1))
    rows = [r["id"] for r in af.open_block(_blocks(env)[0].payload).rows()]
    assert rows == [admin]
    assert failures(env.verify()) == []


def test_part_units_spread_a_parts_count_and_protected_share_over_its_hours():
    part = ArchivePart(1, at(3), at(6), 9, 1000, "ab" * 32)
    lagged = {at(3): 400, at(4): 400, at(6): 400}
    figures = arc.PartFigures(rows=(3, 3, 0, 3), stored=(300, 300, 0, 300), protected_rows=3, protected_stored=300)
    # The chain binds the protected bytes of hour 3 only: its spread is protected, the other hours' are not.
    units = arc.part_units(part, 900, lagged, {at(3): 400}, figures, T0, 0)
    assert [u[0] for u in units] == [at(3), at(4), at(6)]
    assert [u[1] for u in units] == [300, 300, 300] and [u[2] for u in units] == [300, 0, 0]
    # Half an hour's bytes bound as protected: half its spread.
    assert [u[2] for u in arc.part_units(part, 900, lagged, {at(4): 200}, figures, T0, 0)] == [0, 150, 0]
    # A bound above the hour's bytes counts the whole hour, never more.
    assert [u[2] for u in arc.part_units(part, 900, lagged, {at(6): 10 ** 9}, figures, T0, 0)] == [0, 0, 300]
    # Aggregates that say more never raise a share; aggregates that say less lower it, from the oldest hour on.
    more = arc.PartFigures(rows=(3, 3, 0, 3), stored=(300, 300, 0, 300), protected_rows=9, protected_stored=900)
    assert [u[2] for u in arc.part_units(part, 900, lagged, {at(3): 400}, more, T0, 0)] == [300, 0, 0]
    less = arc.PartFigures(rows=(3, 3, 0, 3), stored=(300, 300, 0, 300), protected_rows=1, protected_stored=100)
    both = {at(3): 400, at(6): 400}
    assert [u[2] for u in arc.part_units(part, 900, lagged, both, less, T0, 0)] == [0, 0, 100]
    assert [u[2] for u in arc.part_units(part, 900, lagged, both, None, T0, 0)] == [0, 0, 0]
    # Every hour younger than the minimum for every row: the whole part, whatever the chain binds.
    young = arc.part_units(part, 900, lagged, {}, figures, at(6) + timedelta(days=5), 30)
    assert sum(u[2] for u in young) == 900
    assert all(0 <= u[2] <= u[1] for u in units)
    assert arc.part_units(part, 0, {at(3): 1}, {}, figures, T0, 0) == []


def test_the_preview_counts_the_archived_rows_a_change_would_delete(env):
    protected = ar.protected_actions()[0]
    _day_rows(env, {3: 2, 4: 3})
    env.row(at(5), action=protected)
    env.run_until_sealed()
    _archive(env)
    with env.session() as db:
        kept = ar.preview(db, env.clock(), _numbers(max_days=0))
        cut = ar.preview(db, env.clock(), _numbers(max_days=95, admin_min=365))
        every = ar.preview(db, env.clock(), _numbers(max_days=95, admin_min=0))
    assert kept["archived"]["by_age"] == {"rows": 0, "bytes": 0}
    assert cut["archived"]["by_age"]["rows"] == 5 and cut["by_age"]["rows"] == 0
    assert every["archived"]["by_age"]["rows"] == 6 and every["archived"]["by_age"]["bytes"] > 0


# --------------------------------------------------------------------------- unarchive

def test_unarchive_takes_a_range_of_days_and_estimates_first(env):
    other = DAY + timedelta(days=1)
    _day_rows(env, {3: 2})
    env.row(at(5, day=other))
    env.run_until_sealed()
    _archive(env)
    assert len(_blocks(env)) == 2
    with env.session() as db:
        est = arc.estimate(db, DAY, DAY)
        both = arc.estimate(db, None, None)
    assert est["days"] == 1 and est["rows"] == 2 and est["blocks"] == 1
    assert est["restored_low_bytes"] == 7 * est["compressed_bytes"]
    assert est["restored_high_bytes"] == 12 * est["compressed_bytes"]
    assert both["days"] == 2 and both["rows"] == 3
    seen = arc.unarchive(env.engine, env.st, other, other, read=True)
    assert seen["estimate"]["rows"] == 1 and seen["state"].startswith("dvstate1:")
    assert any("7 to 12 times" in line for line in seen["lines"])
    done = arc.unarchive(env.engine, env.st, other, other, expect=seen["state"])
    assert done == {"days": [other.isoformat()], "rows": 1}
    assert _hot(env) == 0 and _hot(env, other) == 1 and [b.day for b in _blocks(env)] == [DAY]
    assert _marker(env) is not None                      # a block is left
    last = _archive_seals(env)[-1]
    assert last.detail == {"day": other.isoformat(), "cause": "unarchive", "after_seq": None, "complete": False,
                           "parts": []}
    with env.session() as db:
        row = db.query(AuditLog).filter(AuditLog.action == "audit_archive_restored").one()
        assert row.details == {"day": other.isoformat(), "rows": 1} and row.username == "operator@host"
    assert failures(env.verify()) == []


def test_unarchive_writes_only_the_state_its_read_saw(env, monkeypatch):
    _day_rows(env, {3: 2})
    env.row(at(10, day=DAY + timedelta(days=1)))
    env.run_until_sealed()
    monkeypatch.setattr(arc, "DAYS_PER_PASS", 1)
    _archive(env)
    assert len(_blocks(env)) == 1
    seen = arc.unarchive(env.engine, env.st, None, None, read=True)
    with pytest.raises(host.Refused):
        arc.unarchive(env.engine, env.st, None, None, expect="dvstate1:" + "0" * 64)
    _archive(env)                                     # another day archived between the read and the write
    assert len(_blocks(env)) == 2
    with pytest.raises(host.Refused, match="changed since you looked"):
        arc.unarchive(env.engine, env.st, None, None, expect=seen["state"])
    assert len(_blocks(env)) == 2
    with pytest.raises(host.Refused, match="no archived day"):
        arc.unarchive(env.engine, env.st, DAY - timedelta(days=5), DAY - timedelta(days=4), read=True)


def test_unarchive_refuses_a_block_that_does_not_verify(env):
    _sealed_day(env)
    _archive(env)
    _flip_block_byte(env)
    seen = arc.unarchive(env.engine, env.st, None, None, read=True)
    with pytest.raises(arc.NotVerified) as why:
        arc.unarchive(env.engine, env.st, None, None, expect=seen["state"])
    assert why.value.kind == "block-altered" and _hot(env) == 0 and len(_blocks(env)) == 1


def test_unarchive_clears_the_link_of_an_account_deleted_since(env):
    uid = uuid.uuid4()
    with env.session() as db:
        db.add(User(id=uid, username="bob", email="bob@example.com", password_hash="x", role=RoleEnum.USER,
                    is_active=True))
        db.commit()
    env.row(at(3), user_id=uid, username="bob")
    env.run_until_sealed()
    _archive(env)
    with env.session() as db:
        db.query(User).filter(User.id == uid).delete(synchronize_session=False)
        db.commit()
    _unarchive(env)
    (row,) = _rows(env, at(0), at(23))
    assert row["user_id"] is None and row["username"] == "bob"
    assert failures(env.verify()) == []


def test_a_late_row_after_an_unarchive_of_a_legacy_day_is_sealed_again(env):
    """The day's nonce-less rows verify with the salt put back, and a row added to one of its hours is sealed
    over by the host as in any hour."""
    _sealed_day(env, nonce=False)
    _archive(env)
    _unarchive(env)
    added = env.row(at(4, 40), nonce=False)
    assert "rows-added" in failures(env.verify())
    seen = host.seal_late_rows(env.engine, env.st, at(4), read=True)
    host.seal_late_rows(env.engine, env.st, at(4), expect=seen["state"])
    assert failures(env.verify()) == []
    with env.session() as db:
        assert db.get(AuditLog, added) is not None


def test_compact_vacuums_both_audit_tables(env):
    done = arc.compact(env.engine)
    assert [t["table"] for t in done["tables"]] == ["audit_logs", "audit_archive_blocks"]


def test_the_status_says_what_is_archived(env):
    _sealed_day(env)
    _archive(env)
    s = arc.summary(env.st)
    assert s["days"] == 1 and s["oldest_day"] == DAY.isoformat() and s["blocks"] == 1 and s["rows"] == 6
    assert s["bytes"] == len(_blocks(env)[0].payload) and s["hot_days"] == 90


# --------------------------------------------------------------------------- a removal by an older release

def test_a_removal_by_an_older_release_is_acknowledged_with_blocks_present_only_while_they_verify(env):
    """The archived day stays whole (an older release deletes rows only); the hot rows before the cutoff go."""
    from app.core import audit_chain_external as external
    recent = (T0 - timedelta(days=50)).date()
    _day_rows(env, {3: 2, 4: 3, 6: 1})
    _day_rows(env, {2: 2, 8: 2}, day=recent)
    env.run_until_sealed()
    _archive(env)
    assert len(_blocks(env)) == 1 and _hot(env, recent) == 4
    env.clock.advance(days=2)              # the older release ran for two days: no seal meanwhile
    cutoff = at(8, 0, day=recent)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete(synchronize_session=False)
        db.commit()
    env.seal()
    assert "rows-missing" in failures(env.verify())
    _flip_block_byte(env)
    with pytest.raises(host.Refused, match="archive block"):
        external.acknowledge_removed_before(env.engine, env.st, cutoff, retention_days=40, read=True)
    _flip_block_byte(env)                  # put back
    seen = external.acknowledge_removed_before(env.engine, env.st, cutoff, retention_days=40, read=True)
    external.acknowledge_removed_before(env.engine, env.st, cutoff, retention_days=40, expect=seen["state"])
    assert failures(env.verify()) == [] and len(_blocks(env)) == 1


def test_a_removal_over_a_legacy_day_put_back_as_rows_is_acknowledged(env):
    """Unarchive restores a nonce-less day's row ids and salt: the prefix rule of the acknowledgment works over
    it as over any hour."""
    from app.core import audit_chain_external as external
    _day_rows(env, {3: 2, 4: 3, 6: 1}, nonce=False)
    env.run_until_sealed()
    _archive(env)
    _unarchive(env)
    env.clock.advance(days=2)              # an older release ran for two days: no seal meanwhile
    cutoff = at(4, 1)
    with env.session() as db:
        db.query(AuditLog).filter(AuditLog.timestamp < cutoff).delete(synchronize_session=False)
        db.commit()
    env.seal()
    assert "rows-missing" in failures(env.verify())
    seen = external.acknowledge_removed_before(env.engine, env.st, cutoff, retention_days=90, read=True)
    external.acknowledge_removed_before(env.engine, env.st, cutoff, retention_days=90, expect=seen["state"])
    assert failures(env.verify()) == [] and _hot(env) == 3


def test_a_payload_inflated_in_the_database_changes_nothing_the_size_cap_counts(env):
    _sealed_day(env)
    _archive(env)
    _seal_days(env, 8)
    before = _counted(env)
    with env.session() as db:
        db.query(AuditArchiveBlock).update({AuditArchiveBlock.payload: _blocks(env)[0].payload + b"x" * 100000},
                                           synchronize_session=False)
        db.commit()
    assert _counted(env) == before
    assert "block-altered" in failures(env.verify())


def test_a_part_is_pruned_and_put_back_a_chunk_at_a_time(env, monkeypatch):
    """The rows of a part go through the temporary table and back into audit_logs a chunk at a time, never held
    whole."""
    monkeypatch.setattr(arc, "PROBE_CHUNK", 2)
    protected = ar.protected_actions()[0]
    _day_rows(env, {3: 3, 4: 2})
    kept = [env.row(at(6, i), action=protected) for i in range(3)]
    env.run_until_sealed()
    _archive(env)
    ar.prune(_pass(env), _numbers(admin_min=365))
    assert [r["id"] for r in af.open_block(_blocks(env)[0].payload).rows()] == kept
    _unarchive(env)
    assert sorted(r["id"] for r in _rows(env, at(0), at(23))) == sorted(kept)
    assert failures(env.verify()) == []


def test_a_reader_stopped_early_runs_its_checks_when_finished(env):
    _sealed_day(env)
    _archive(env)
    agg = dict(_blocks(env)[0].aggregates)
    agg["hours"] = []
    with env.session() as db:
        db.query(AuditArchiveBlock).update({AuditArchiveBlock.aggregates: agg}, synchronize_session=False)
        db.commit()
    (part,) = env.st.view.archives[DAY].parts
    with env.session() as db:
        reader = arc.PartReader(db, env.st.view, DAY, part)
        next(iter(reader.rows()))
        assert not reader.checked
        with pytest.raises(arc.NotVerified, match="aggregates"):
            reader.finish()


def test_a_row_written_into_the_parts_hours_while_it_is_archived_is_never_deleted_unarchived(env, monkeypatch):
    """A row that lands in the part's hours between the block's check and the delete (a statement of another
    transaction, here in this one) makes the deleted count differ: the transaction rolls back."""
    _sealed_day(env)
    real = arc._check_stored

    def check_then_write(db, view, day, part, bw, expected=None):
        real(db, view, day, part, bw, expected)
        db.add(AuditLog(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=at(5, 30),
                        username="mallory", seal_nonce=uuid.uuid4().bytes))
        db.flush()
    monkeypatch.setattr(arc, "_check_stored", check_then_write)
    _archive(env)
    assert _blocks(env) == [] and _hot(env) == 6 and _archive_seals(env) == []


def test_the_part_planner_takes_no_day_not_sealed_whole(env, monkeypatch):
    _day_rows(env, {3: 1, 4: 1, 5: 1, 6: 1})
    monkeypatch.setattr(ai, "ROW_BUDGET", 2)
    env.seal()
    with ai.ChainWriter(env.engine, env.st) as w:
        with pytest.raises(arc.NotArchivable, match="not sealed whole"):
            arc.archive_next_part(w, DAY, env.clock())


def _store_payload(env, payload):
    with env.session() as db:
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.part == 1).update(
            {AuditArchiveBlock.payload: payload}, synchronize_session=False)
        db.commit()


def test_a_block_is_refused_when_it_is_not_the_part_its_seal_names(env):
    """Each of these needs a seal that binds the block (only the key's holder writes one): the block is still
    read against what the seal says of it."""
    _sealed_day(env)
    _archive(env)
    (part,) = env.st.view.archives[DAY].parts
    view = env.st.view
    with env.session() as db:
        more = ArchivePart(part.part, part.first_hour, part.last_hour, part.rows + 1, part.length, part.sha256)
        with pytest.raises(arc.NotVerified, match="holds 6 rows; its seal 7"):
            arc.PartReader(db, view, DAY, more).finish()
        shorter = ArchivePart(part.part, part.first_hour, at(3), part.rows, part.length, part.sha256)
        with pytest.raises(arc.NotVerified, match="outside the part"):
            arc.PartReader(db, view, DAY, shorter).finish()
    rows = list(af.open_block(_blocks(env)[0].payload).rows())
    other = af.BlockWriter(DAY, 2)
    for row in rows:
        other.add(row)
    payload = other.finish()
    _store_payload(env, payload)
    with env.session() as db:
        named = ArchivePart(1, part.first_hour, part.last_hour, part.rows, len(payload), af.digest(payload))
        with pytest.raises(arc.NotVerified, match="says it is another part"):
            arc.PartReader(db, view, DAY, named).finish()


def test_a_block_keeping_a_salt_of_an_hour_it_does_not_hold_is_refused(env):
    _sealed_day(env)
    _archive(env)
    (part,) = env.st.view.archives[DAY].parts
    rows = list(af.open_block(_blocks(env)[0].payload).rows())
    other = af.BlockWriter(DAY, 1, {at(1): os.urandom(32)})
    for row in rows:
        other.add(row)
    payload = other.finish()
    _store_payload(env, payload)
    with env.session() as db:
        named = ArchivePart(1, part.first_hour, part.last_hour, part.rows, len(payload), af.digest(payload))
        with pytest.raises(arc.NotVerified, match="salt of an hour it does not hold"):
            arc.PartReader(db, env.st.view, DAY, named).finish()


def test_accepting_a_database_that_lost_an_archive_seal_names_its_blocks(env):
    """A tail cut back to before an archive seal leaves its blocks bound by no seal: the read phase of
    accept-database-head names them (verify then reports them)."""
    from app.core import audit_chain_restore as restore
    from app.core.models import AuditSeal
    _sealed_day(env)
    _archive(env)
    (seal,) = _archive_seals(env)
    with env.session() as db:
        db.query(AuditSeal).filter(AuditSeal.seq >= seal.seq).delete()
        db.commit()
    env.clock.advance(hours=1)
    assert env.seal().stopped == "head-record-mismatch"
    host_st = ai.ChainState(settings=env.settings, clock=env.clock)
    host_st.process_kind = "host"
    seen = restore.accept_database_head(env.engine, host_st, read=True)
    lines = "\n".join(seen["lines"])
    assert "archive blocks are not the ones the accepted chain's archive seals name" in lines
    assert f"{DAY.isoformat()} part 1" in lines


def test_a_block_of_the_day_no_seal_names_stops_its_change_and_its_unarchive(env):
    _sealed_day(env)
    _archive(env)
    block = _blocks(env)[0]
    with env.session() as db:
        db.add(AuditArchiveBlock(day=block.day, part=9, first_hour=block.first_hour, last_hour=block.last_hour,
                                 row_count=block.row_count, codec="zstd", format=1, payload=block.payload,
                                 raw_bytes=block.raw_bytes, aggregates=block.aggregates, created_at=T0))
        db.commit()
    before = len(env.seals())
    ar.prune(_pass(env), _numbers())
    assert len(env.seals()) == before and len(_blocks(env)) == 2
    assert "block-unsealed" in ai.open_failures(env.st.head_store().load())
    seen = arc.unarchive(env.engine, env.st, None, None, read=True)
    with pytest.raises(arc.NotVerified) as why:
        arc.unarchive(env.engine, env.st, None, None, expect=seen["state"])
    assert why.value.kind == "block-unsealed" and _hot(env) == 0


def test_a_rewritten_block_stored_wrong_changes_nothing(env, monkeypatch):
    """A block written anew is checked as the table stores it before the change commits."""
    _day_rows(env, {3: 2, 4: 3})
    env.row(at(6), action=ar.protected_actions()[0])
    env.run_until_sealed()
    _archive(env)
    real_add = af.BlockWriter.add

    def add(self, row):
        real_add(self, row)
        self.identity.update(b"x")
    monkeypatch.setattr(af.BlockWriter, "add", add)
    before = len(env.seals())
    payload = _blocks(env)[0].payload
    ar.prune(_pass(env), _numbers(admin_min=365))
    assert len(env.seals()) == before and _blocks(env)[0].payload == payload
    assert "block-altered" in ai.open_failures(env.st.head_store().load())


def test_unarchive_refuses_a_day_with_a_row_put_back_into_its_archived_hours(env):
    _sealed_day(env)
    _archive(env)
    env.row(at(4, 30))
    seen = arc.unarchive(env.engine, env.st, None, None, read=True)
    with pytest.raises(arc.NotVerified) as why:
        arc.unarchive(env.engine, env.st, None, None, expect=seen["state"])
    assert why.value.kind == "row-in-archived-day" and _hot(env) == 1 and len(_blocks(env)) == 1


def test_the_protected_share_never_exceeds_the_parts_count_whatever_its_aggregates_say():
    part = ArchivePart(1, at(3), at(4), 2, 100, "ab" * 32)
    inflated = arc.PartFigures(rows=(1, 1), stored=(50, 50), protected_rows=99, protected_stored=10 ** 9)
    assert arc.protected_share(part, 70, inflated, T0, 0) == 70
    young = arc.PartFigures(rows=(1, 1), stored=(50, 50), protected_rows=0, protected_stored=0)
    assert arc.protected_share(part, 70, young, at(3) + timedelta(days=1), 30) == 70
    assert arc.protected_share(part, 70, None, T0, 0) == 0


# --------------------------------------------------------------------------- what a database writer cannot make the cap do

def _ids_in_blocks(env, day):
    out = []
    for blk in _blocks(env):
        if blk.day == day:
            out += [r["id"] for r in af.open_block(blk.payload).rows()]
    return out


def _say_every_row_is_protected(env, day):
    """What a database writer without the key can do: edit the aggregates of ``day``'s block to say every row of
    it is of an action the size cap never deletes."""
    protected = ar.protected_actions()[0]
    with env.session() as db:
        blk = db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == day).one()
        aggregates = dict(blk.aggregates)
        aggregates["by"] = [[protected] + list(row[1:]) for row in aggregates["by"]]
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == day).update(
            {AuditArchiveBlock.aggregates: aggregates}, synchronize_session=False)
        db.commit()


@pytest.mark.parametrize("edited", [False, True])
def test_aggregates_edited_in_the_database_never_make_the_size_cap_delete_a_newer_archived_row(env, monkeypatch,
                                                                                                 edited):
    """Two archived days of one row each, and a cap with room for the newer day only. Aggregates edited to say the
    older day's row is protected would raise that part's protected share, move the cutoff a day newer and delete
    the newer day's row under a prune verify finds justified: a part's share never exceeds what the chain binds of
    its hours, so the edit can only lower it."""
    _capped(env, monkeypatch)
    newer = DAY + timedelta(days=1)
    older = env.row(at(3), details=_blob(15000))
    kept = env.row(at(3, day=newer), details=_blob(15000))
    env.run_until_sealed()
    _archive(env)
    assert len(_blocks(env)) == 2
    _seal_days(env, 8)
    _hot, ((_d1, _p1, older_count, _h1), (_d2, _p2, newer_count, _h2)) = _counted(env)
    cap = newer_count + 1000
    assert cap < older_count + newer_count
    if edited:
        _say_every_row_is_protected(env, DAY)
    ar.prune(_pass(env), _numbers(max_days=0, max_mb=cap))
    assert _ids_in_blocks(env, newer) == [kept]
    # Honest, the cap takes the older day's row; edited, that block no longer gives its rows and stays as it is.
    assert _ids_in_blocks(env, DAY) == ([older] if edited else [])
    assert ("block-altered" in failures(env.verify())) is edited


@pytest.mark.parametrize("added", [False, True])
def test_a_protected_row_added_to_an_old_hour_never_makes_the_size_cap_delete_a_newer_row(env, monkeypatch, added):
    """The same over rows not archived: a row of a protected action written into an older sealed hour in the
    database would raise that hour's protected share and delete the newer hour's row. The share never exceeds the
    protected bytes the chain binds for the hour."""
    _capped(env, monkeypatch)
    d = (T0 - timedelta(days=20)).date()
    older = env.row(at(3, day=d), details=_blob(15000))
    newer = env.row(at(9, day=d), details=_blob(15000))
    env.run_until_sealed()
    _seal_days(env, 8)
    hot, _parts = _counted(env)
    cap = hot[at(9, day=d)] + 1000
    assert cap < hot[at(3, day=d)] + hot[at(9, day=d)]
    if added:
        env.row(at(3, 30, day=d), action=ar.protected_actions()[0], details=_blob(15000))
    ar.prune(_pass(env), _numbers(max_days=0, max_mb=cap))
    with env.session() as db:
        left = {r[0] for r in db.query(AuditLog.id).filter(AuditLog.id.in_([older, newer])).all()}
    # Honest, the cap takes the older hour's row; with a row added, that hour no longer gives its seal and stays.
    assert left == ({older, newer} if added else {newer})
    assert ("rows-added" in failures(env.verify())) is added


def test_the_chain_binds_each_hours_protected_bytes_and_an_archived_parts_share_comes_from_them(env):
    protected = ar.protected_actions()[0]
    admin = env.row(at(3), action=protected, details=_blob(4000))
    env.row(at(3, 5), details=_blob(4000))
    env.row(at(4), details=_blob(4000))
    env.run_until_sealed()
    hour3 = next(s for s in env.seals() if s.kind == "hour" and s.period_start == at(3))
    hour4 = next(s for s in env.seals() if s.kind == "hour" and s.period_start == at(4))
    with env.session() as db:
        admin_bytes = db.query(ar._row_bytes(AuditLog, "sqlite")).filter(AuditLog.id == admin).scalar()
    assert hour3.detail["protected_bytes"] == admin_bytes and 0 < admin_bytes < hour3.row_bytes
    assert hour4.detail["protected_bytes"] == 0
    _archive(env)
    _seal_days(env, 8)
    st = env.st
    start = chain_size.window_start(st.view, st.known_record(), env.clock(), timedelta(days=7))
    bound = chain_size.protected_hours(st.view, start, chain_size.held_back(st.view, st.known_record(), start))
    assert bound.get(at(3)) == admin_bytes and at(4) not in bound
    _hot, ((_d, part, count, lagged),) = _counted(env)
    with env.session() as db:
        figures = arc.part_figures(db, st.view)[(DAY, part.part)]
    units = arc.part_units(part, count, lagged, bound, figures, env.clock(), 0)
    share3 = next(u for u in units if u[0] == at(3))
    assert sum(u[2] for u in units) == share3[2] == share3[1] * admin_bytes // lagged[at(3)] > 0
    # A prune that keeps the protected row records the hour's protected bytes beside its bytes.
    ar.prune(_pass(env), _numbers(max_days=95, admin_min=365))
    prune = [s for s in env.seals() if s.kind == "prune"][-1]
    entry = next(h for h in prune.detail["hours"] if h[0] == fmt.hour_text(at(3)))
    assert entry[7] == admin_bytes == entry[3]
    assert _ids_in_blocks(env, DAY) == [admin] and failures(env.verify()) == []


# --------------------------------------------------------------------------- a block the day's seal does not name

def _plant(env, day, number, like):
    """A block row a database writer adds for ``day`` with part ``number``, a copy of ``like``."""
    with env.session() as db:
        db.add(AuditArchiveBlock(day=day, part=number, first_hour=like.first_hour, last_hour=like.last_hour,
                                 row_count=like.row_count, codec="zstd", format=1, payload=like.payload,
                                 raw_bytes=like.raw_bytes, aggregates=like.aggregates, created_at=T0))
        db.commit()


def _half_archived(env, monkeypatch):
    """A day whose first part is archived and whose second waits, and a later day not archived yet."""
    monkeypatch.setattr(arc, "PART_ROWS", 3)
    later = DAY + timedelta(days=1)
    _day_rows(env, {2: 3, 9: 3})
    _day_rows(env, {5: 1}, day=later)
    env.run_until_sealed()
    monkeypatch.setattr(ai, "ROW_BUDGET", 3)
    _archive(env)
    (block,) = _blocks(env)
    assert block.day == DAY and _hot(env) == 3
    monkeypatch.setattr(ai, "ROW_BUDGET", 100000)
    return later, block


def test_a_block_planted_with_the_days_next_part_number_leaves_that_day_and_archives_the_next(env, monkeypatch):
    """A database writer adds a block numbered as the day's next part. The job leaves that day as it is
    (block-unsealed, reported) and still archives the next day, pass after pass, never stopping at the first."""
    later, block = _half_archived(env, monkeypatch)
    _plant(env, DAY, 2, block)
    _archive(env)
    _archive(env)
    assert later in {b.day for b in _blocks(env)} and _hot(env) == 3
    assert "block-unsealed" in ai.open_failures(env.st.head_store().load())


def test_a_block_planted_for_a_day_not_archived_yet_leaves_that_day_and_archives_the_next(env, monkeypatch):
    monkeypatch.setattr(arc, "DAYS_PER_PASS", 1)
    second, third = DAY + timedelta(days=1), DAY + timedelta(days=2)
    for day in (DAY, second, third):
        _day_rows(env, {5: 1}, day=day)
    env.run_until_sealed()
    _archive(env)
    (block,) = _blocks(env)
    assert block.day == DAY
    _plant(env, second, 1, block)
    _archive(env)
    assert {b.day for b in _blocks(env)} == {DAY, second, third} and _hot(env, second) == 1 and _hot(env, third) == 0
    assert "block-unsealed" in ai.open_failures(env.st.head_store().load())


def test_a_block_conflict_after_the_check_is_a_finding_not_a_crash(env, monkeypatch):
    """Should a block of the next part number appear between the day's check and the insert, the insert's conflict
    is reported as a block no seal names, and the pass goes on."""
    later, block = _half_archived(env, monkeypatch)
    _plant(env, DAY, 2, block)
    monkeypatch.setattr(arc, "_check_day_blocks", lambda db, entry, day: None)
    _archive(env)
    assert later in {b.day for b in _blocks(env)} and _hot(env) == 3
    assert "block-unsealed" in ai.open_failures(env.st.head_store().load())


def test_a_part_whose_block_is_gone_or_of_another_length_stops_its_days_next_part_only(env, monkeypatch):
    later, block = _half_archived(env, monkeypatch)
    with env.session() as db:
        db.query(AuditArchiveBlock).update({AuditArchiveBlock.payload: bytes(block.payload) + b"\0"},
                                           synchronize_session=False)
        db.commit()
    _archive(env)
    assert later in {b.day for b in _blocks(env)} and _hot(env) == 3
    assert "block-altered" in ai.open_failures(env.st.head_store().load())
    with env.session() as db:
        db.query(AuditArchiveBlock).filter(AuditArchiveBlock.day == DAY).delete()
        db.commit()
    _archive(env)
    assert _hot(env) == 3 and "block-missing" in ai.open_failures(env.st.head_store().load())
