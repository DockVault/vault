"""File expiry: the rule, the sweep, and the switch that postpones both.

A vault's "expire files after" setting (and an upload link's retention, the same setting on the
link's vault) stamps ``File.expires_at`` at upload -- UTC, in a column without a time zone. Until
0.32.6 nothing read it back: an expired file stayed listed, downloadable and stored. These cover what
makes the deadline real, without a running deployment:

* the comparison (``app/core/file_expiry``): naive UTC on both sides, whatever zone a caller's
  "now" carries, and a deadline that is exactly now has passed;
* the sweep's transaction (``VaultService.cleanup_expired_files``) against a recording session:
  lock order, counters, one name-free audit row per file, and bytes destroyed only after the commit;
* the loop around it: batches, a failure that is logged rather than raised, a loop that survives;
* ``ENFORCE_FILE_EXPIRY=false``: nothing hidden, nothing swept -- the pre-enforcement behaviour;
* that each read path consults the rule (source pins; the live module proves the behaviour);
* the setting's plumbing: config default, .env.example, and dockvault.py carrying a postponement.

The live behaviour -- listing, download, SFTP, links, shares, the sweep and its audit rows on a real
stack -- is in tests/test_file_expiry_live.py.
"""
import asyncio
import contextlib
import importlib.util
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace
import uuid

import pytest
from sqlalchemy.dialects import postgresql

from _async_run import run_coroutine
from app.core import file_expiry
from app.core.config import Settings, settings
from app.core.models import AuditLog, File, Vault

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def enforced(monkeypatch):
    monkeypatch.setattr(settings, "enforce_file_expiry", True)


@pytest.fixture
def postponed(monkeypatch):
    monkeypatch.setattr(settings, "enforce_file_expiry", False)


def _sql(clause):
    return str(clause.compile(dialect=postgresql.dialect()))


def _bound_values(clause):
    return list(clause.compile(dialect=postgresql.dialect()).params.values())


# ---------------------------------------------------------------------------------------------
# The comparison
# ---------------------------------------------------------------------------------------------


def test_now_is_naive_utc():
    now = file_expiry.utc_now()
    assert now.tzinfo is None
    assert abs((now - datetime.now(timezone.utc).replace(tzinfo=None)).total_seconds()) < 5


def test_a_deadline_is_compared_in_utc_whatever_zone_now_carries(enforced):
    """The stored value is UTC with no zone. A caller's aware "now" in another zone is converted,
    never compared by its wall-clock digits -- which would be wrong by the zone's offset."""
    deadline = datetime(2026, 9, 26, 12, 0, 0)                     # 12:00 UTC, as stored
    athens = timezone(timedelta(hours=3))
    assert not file_expiry.is_past(deadline, datetime(2026, 9, 26, 14, 59, 59, tzinfo=athens))
    assert file_expiry.is_past(deadline, datetime(2026, 9, 26, 15, 0, 0, tzinfo=athens))
    # An aware deadline (as an older writer produced) is normalised the same way.
    assert file_expiry.is_past(deadline.replace(tzinfo=timezone.utc),
                               datetime(2026, 9, 26, 12, 0, 1))


def test_the_boundary_is_inclusive_and_no_deadline_never_expires(enforced):
    t = datetime(2026, 1, 1, 0, 0, 0)
    assert file_expiry.is_past(t, t), "a deadline that is exactly now has passed"
    assert not file_expiry.is_past(t, t - timedelta(microseconds=1))
    assert not file_expiry.is_past(None, t)
    assert not file_expiry.is_expired(SimpleNamespace(expires_at=None))
    assert not file_expiry.is_expired(None)


def test_is_expired_reads_the_row(enforced):
    past = file_expiry.utc_now() - timedelta(minutes=1)
    future = file_expiry.utc_now() + timedelta(minutes=1)
    assert file_expiry.is_expired(SimpleNamespace(expires_at=past))
    assert not file_expiry.is_expired(SimpleNamespace(expires_at=future))


def test_the_live_filter_binds_a_naive_utc_now(enforced):
    """The query side of the same rule: the value bound against the zone-less column is naive
    UTC, so the database never converts it through its session's time zone."""
    clause = file_expiry.live_clause()
    assert _sql(clause) == "files.expires_at IS NULL OR files.expires_at > %(expires_at_1)s"
    (bound,) = _bound_values(clause)
    assert bound.tzinfo is None
    assert abs((bound - file_expiry.utc_now()).total_seconds()) < 5

    athens = timezone(timedelta(hours=3))
    (bound,) = _bound_values(file_expiry.live_clause(datetime(2026, 9, 26, 15, 0, tzinfo=athens)))
    assert bound == datetime(2026, 9, 26, 12, 0)


def test_the_expired_filter_is_the_exact_complement(enforced):
    t = datetime(2026, 9, 26, 12, 0)
    assert _sql(file_expiry.expired_clause(t)) == (
        "files.expires_at IS NOT NULL AND files.expires_at <= %(expires_at_1)s")
    assert _bound_values(file_expiry.expired_clause(t)) == [t]
    assert _bound_values(file_expiry.live_clause(t)) == [t]


def test_upload_stamps_a_naive_utc_deadline():
    from app.services.vault_service import calculate_file_expiration

    before = file_expiry.utc_now()
    for value, unit, delta in ((1, "minutes", timedelta(minutes=1)),
                               (2, "hours", timedelta(hours=2)),
                               (3, "days", timedelta(days=3)),
                               (3, None, timedelta(days=3))):
        got = calculate_file_expiration(
            SimpleNamespace(expire_files_after_days=value, expire_files_unit=unit))
        assert got.tzinfo is None, "stored as UTC without a zone, like the column"
        assert before + delta <= got <= file_expiry.utc_now() + delta
    assert calculate_file_expiration(
        SimpleNamespace(expire_files_after_days=None, expire_files_unit="days")) is None


# ---------------------------------------------------------------------------------------------
# ENFORCE_FILE_EXPIRY=false: exactly the behaviour before enforcement existed
# ---------------------------------------------------------------------------------------------


def test_postponed_hides_nothing(postponed):
    long_gone = SimpleNamespace(expires_at=datetime(2000, 1, 1))
    assert not file_expiry.is_expired(long_gone)
    assert _sql(file_expiry.live_clause()) == "true", "every file stays in every query"
    # The deadline itself is still a fact -- the startup report counts it either way.
    assert file_expiry.is_past(long_gone.expires_at)


def test_postponed_sweeps_nothing(postponed, monkeypatch):
    """Not even a session is opened.

    The stand-in records the attempt rather than raising: sweep_once catches every exception from a
    batch and logs it, so an assertion raised in here would be swallowed, and the test would pass
    whether or not the switch was checked."""
    import app.core.database as database
    opened = []

    @contextlib.contextmanager
    def _record():
        opened.append(1)
        yield object()

    monkeypatch.setattr(database, "get_db_context", _record)
    assert file_expiry.sweep_once() == 0
    assert opened == [], "the sweep opened a database session while postponed"
    # The same stand-in does see a session opened once enforcement is on, so it can tell.
    monkeypatch.setattr(settings, "enforce_file_expiry", True)
    file_expiry.sweep_once()
    assert opened == [1]


def test_the_setting_defaults_on_and_reads_false_from_the_env():
    assert Settings.model_fields["enforce_file_expiry"].default is True
    assert Settings.model_construct().enforce_file_expiry is True
    for raw in ("false", "0", "no", "off", "False"):
        assert Settings(enforce_file_expiry=raw).enforce_file_expiry is False
    assert Settings(enforce_file_expiry="true").enforce_file_expiry is True


# ---------------------------------------------------------------------------------------------
# The sweep's transaction, against a recording session
# ---------------------------------------------------------------------------------------------


class _Query:
    def __init__(self, db, entities):
        self.db, self.entities, self.ops = db, entities, []
        db.queries.append(self)

    def _op(self, *op):
        self.ops.append(op)
        return self

    def filter(self, *criteria):
        return self._op("filter", criteria)

    def distinct(self):
        return self._op("distinct")

    def limit(self, n):
        return self._op("limit", n)

    def order_by(self, *cols):
        return self._op("order_by", cols)

    def with_for_update(self, **kw):
        self.db.log.append(("lock", self))
        return self._op("for_update", kw)

    def all(self):
        self.db.log.append(("select", self))
        return self.db.results.pop(0)

    def delete(self, synchronize_session=None):
        self.db.log.append(("delete", self))
        return 0


class _DB:
    """Records every statement in order; `results` feeds each .all() in turn."""

    def __init__(self, results, fail_commit=False):
        self.results = list(results)
        self.fail_commit = fail_commit
        self.queries, self.log, self.added = [], [], []

    def query(self, *entities):
        return _Query(self, entities)

    def add(self, obj):
        self.log.append(("add", obj))
        self.added.append(obj)

    def commit(self):
        if self.fail_commit:
            raise RuntimeError("commit failed")
        self.log.append(("commit",))

    def rollback(self):
        self.log.append(("rollback",))


class _Storage:
    def __init__(self, db):
        self.db = db

    def secure_delete(self, path):
        self.db.log.append(("destroy", path.name))
        path.unlink()


def _service(db, root):
    from app.services.vault_service import VaultService
    service = VaultService.__new__(VaultService)
    service.db = db
    service.storage_path = root
    service.encrypted_storage = _Storage(db)
    service.totals = {}

    def _record_totals(vault_id, size_delta, count_delta):
        db.log.append(("totals", vault_id))
        service.totals[vault_id] = (size_delta, count_delta)

    service._adjust_vault_totals_by_id = _record_totals
    return service


def _row(vault_id, size, root, name, expires_at):
    blob = root / name
    blob.write_bytes(b"x" * size)
    return SimpleNamespace(id=uuid.uuid4(), vault_id=vault_id, size_bytes=size,
                           storage_path=name, expires_at=expires_at)


def _names(log):
    return [entry[0] for entry in log]


def test_the_sweep_deletes_audits_and_only_then_destroys_the_bytes(tmp_path):
    v1, v2 = uuid.uuid4(), uuid.uuid4()
    due = datetime(2026, 9, 26, 11, 0)
    rows = [_row(v1, 10, tmp_path, "a", due), _row(v1, 20, tmp_path, "b", due),
            _row(v2, 5, tmp_path, "c", due)]
    db = _DB([[(v1,), (v2,)], [(v2,), (v1,)], rows])
    svc = _service(db, tmp_path)

    athens = timezone(timedelta(hours=3))
    out = svc.cleanup_expired_files(batch_size=3, now=datetime(2026, 9, 26, 15, 0, tzinfo=athens))

    assert out == [{"file_id": r.id, "vault_id": r.vault_id} for r in rows]
    # Each vault's counters drop by exactly what left it.
    assert svc.totals == {v1: (-30, -2), v2: (-5, -1)}
    # One delete, of exactly these rows.
    deletes = [e[1] for e in db.log if e[0] == "delete"]
    assert len(deletes) == 1 and deletes[0].entities == (File,)
    (criterion,) = deletes[0].ops[0][1]
    assert criterion.right.value == [r.id for r in rows]
    # One audit row per file: which file, which vault, when it was due -- and no name.
    assert len(db.added) == 3 and all(isinstance(a, AuditLog) for a in db.added)
    for audit, r in zip(db.added, rows):
        assert audit.action == "file_expired" and audit.status == "success"
        assert audit.resource_type == "file" and audit.resource_id == str(r.id)
        assert audit.details == {"vault_id": str(r.vault_id), "expires_at": due.isoformat()}
        assert audit.user_id is None
        assert audit.timestamp == datetime(2026, 9, 26, 12, 0), "recorded in naive UTC"
    # Rows, counters and audit rows commit together; the bytes are destroyed only afterwards.
    order = _names(db.log)
    commit = order.index("commit")
    assert order.count("commit") == 1
    assert max(i for i, k in enumerate(order) if k in ("totals", "delete", "add")) < commit
    assert [e for e in db.log if e[0] == "destroy"] == [("destroy", "a"), ("destroy", "b"),
                                                       ("destroy", "c")]
    assert min(i for i, k in enumerate(order) if k == "destroy") > commit
    assert not any(tmp_path.iterdir())


def test_the_sweep_locks_the_vault_before_the_file_and_never_waits(tmp_path):
    """Vault row, then file row -- the order every other deleting path takes -- and both SKIP
    LOCKED, so the sweep cannot deadlock with an upload and never queues behind a request."""
    v1 = uuid.uuid4()
    rows = [_row(v1, 1, tmp_path, "a", datetime(2026, 1, 1))]
    db = _DB([[(v1,)], [(v1,)], rows])
    _service(db, tmp_path).cleanup_expired_files(now=datetime(2026, 9, 26))

    locks = [e[1] for e in db.log if e[0] == "lock"]
    assert len(locks) == 2
    vault_lock, file_lock = locks
    assert vault_lock.entities == (Vault.id,)
    assert dict(vault_lock.ops)["for_update"] == {"key_share": True, "skip_locked": True}
    assert all(getattr(e, "class_", None) is File for e in file_lock.entities)
    assert dict(file_lock.ops)["for_update"] == {"of": File, "skip_locked": True}
    # Both the candidate read and the locked re-read select by the expired filter.
    for q in (db.queries[0], file_lock):
        assert "files.expires_at IS NOT NULL AND files.expires_at <=" in _sql(q.ops[0][1][0])


def test_nothing_due_takes_no_lock(tmp_path):
    db = _DB([[]])
    assert _service(db, tmp_path).cleanup_expired_files() == []
    assert "lock" not in _names(db.log) and "delete" not in _names(db.log)
    assert "commit" not in _names(db.log)


def test_a_vault_someone_else_holds_is_left_for_the_next_run(tmp_path):
    rows_would_be = _row(uuid.uuid4(), 1, tmp_path, "a", datetime(2026, 1, 1))
    db = _DB([[(rows_would_be.vault_id,)], []])
    assert _service(db, tmp_path).cleanup_expired_files() == []
    assert _names(db.log).count("lock") == 1, "the file rows are never locked"
    assert "delete" not in _names(db.log) and "add" not in _names(db.log)
    assert (tmp_path / "a").exists()


def test_only_the_files_of_the_vaults_the_sweep_holds_are_deleted(tmp_path):
    """Some vaults held by someone else, others free. The file rows of a held vault are not locked
    by anyone, so only the file query's vault filter keeps the sweep off them -- and off counters
    it does not hold the lock for. Run against a session that applies the filters it is given."""
    from _memory_db import MemoryDB

    due = datetime(2026, 1, 1)
    vaults = [SimpleNamespace(id=uuid.uuid4(), expire_files_after_days=1) for _ in range(4)]
    files = [_row(v.id, 10 + i, tmp_path, f"f{i}", due) for i, v in enumerate(vaults)]
    db = MemoryDB({Vault: vaults, File: files})
    db.held = {vaults[1].id, vaults[3].id}            # another session holds these vault rows
    svc = _service(db, tmp_path)

    out = svc.cleanup_expired_files(now=datetime(2026, 9, 26))

    # (Rows due at the same moment come back in file-id order, which is random here.)
    assert sorted((d["file_id"], d["vault_id"]) for d in out) == sorted(
        (files[i].id, vaults[i].id) for i in (0, 2))
    assert db.rows_of(File) == [files[1], files[3]]
    assert svc.totals == {vaults[0].id: (-10, -1), vaults[2].id: (-12, -1)}
    assert sorted(a.resource_id for a in db.added) == sorted(str(files[i].id) for i in (0, 2))
    assert sorted(p.name for p in tmp_path.iterdir()) == ["f1", "f3"]


def test_a_failed_commit_rolls_back_and_destroys_nothing(tmp_path):
    v1 = uuid.uuid4()
    rows = [_row(v1, 7, tmp_path, "a", datetime(2026, 1, 1))]
    db = _DB([[(v1,)], [(v1,)], rows], fail_commit=True)
    with pytest.raises(RuntimeError):
        _service(db, tmp_path).cleanup_expired_files()
    assert _names(db.log)[-1] == "rollback"
    assert "destroy" not in _names(db.log)
    assert (tmp_path / "a").exists(), "a row that is still live keeps its bytes"


def test_a_blob_that_is_already_gone_or_will_not_go_does_not_stop_the_others(tmp_path, monkeypatch):
    v1 = uuid.uuid4()
    rows = [_row(v1, 1, tmp_path, "a", datetime(2026, 1, 1)),
            _row(v1, 1, tmp_path, "b", datetime(2026, 1, 1)),
            _row(v1, 1, tmp_path, "c", datetime(2026, 1, 1))]
    (tmp_path / "a").unlink()
    db = _DB([[(v1,)], [(v1,)], rows])
    svc = _service(db, tmp_path)

    real = svc.encrypted_storage.secure_delete

    def _stuck_on_b(path):
        if path.name == "b":
            raise OSError("device busy")
        real(path)

    svc.encrypted_storage.secure_delete = _stuck_on_b
    assert len(svc.cleanup_expired_files()) == 3
    assert not (tmp_path / "c").exists()
    assert (tmp_path / "b").exists(), "left as an orphan, logged, not retried in the transaction"


# ---------------------------------------------------------------------------------------------
# The loop around it
# ---------------------------------------------------------------------------------------------


@contextlib.contextmanager
def _no_session():
    yield object()


def _patch_sweep(monkeypatch, cleanup):
    import app.core.authorization as authorization
    import app.core.database as database
    import app.services.vault_service as vault_service

    class _Svc:
        def __init__(self, db, permission_service):
            pass

        def cleanup_expired_files(self, batch_size):
            return cleanup(batch_size)

    monkeypatch.setattr(database, "get_db_context", _no_session)
    monkeypatch.setattr(authorization, "PermissionService", lambda db: None)
    monkeypatch.setattr(vault_service, "VaultService", _Svc)


def test_a_pass_runs_batches_until_one_comes_back_short(enforced, monkeypatch):
    sizes, asked = iter([3, 3, 1, 3]), []

    def cleanup(batch_size):
        asked.append(batch_size)
        return [{}] * next(sizes)

    _patch_sweep(monkeypatch, cleanup)
    assert file_expiry.sweep_once(batch_size=3, max_batches=10) == 7
    assert asked == [3, 3, 3]


def test_a_pass_is_bounded(enforced, monkeypatch):
    _patch_sweep(monkeypatch, lambda batch_size: [{}] * batch_size)
    assert file_expiry.sweep_once(batch_size=2, max_batches=4) == 8


def test_a_failed_batch_is_logged_and_ends_the_pass(enforced, monkeypatch, capsys):
    calls = []

    def cleanup(batch_size):
        calls.append(1)
        if len(calls) == 2:
            raise RuntimeError("could not serialize access")
        return [{}] * batch_size

    _patch_sweep(monkeypatch, cleanup)
    assert file_expiry.sweep_once(batch_size=2, max_batches=5) == 2
    assert len(calls) == 2
    out = capsys.readouterr().out
    assert "file-expiry.sweep.failed" in out and "RuntimeError" in out


def test_the_loop_survives_a_pass_that_raises(monkeypatch):
    calls = []

    def flaky():
        calls.append(1)
        if len(calls) == 1:
            raise RuntimeError("database away")
        return 0

    monkeypatch.setattr(file_expiry, "sweep_once", flaky)

    async def body():
        task = asyncio.create_task(file_expiry.run_forever(interval_seconds=0.01, cleared=True))
        for _ in range(500):
            await asyncio.sleep(0.01)
            if len(calls) >= 3:
                break
        task.cancel()
        with pytest.raises(asyncio.CancelledError):
            await task

    run_coroutine(body())
    assert len(calls) >= 3, "the loop kept going after the first pass raised"


def test_the_startup_report_counts_either_way_and_never_raises(monkeypatch, capsys):
    import app.core.database as database

    class _Count:
        def filter(self, *a):
            return self

        def scalar(self):
            return 4

    @contextlib.contextmanager
    def _ctx():
        yield SimpleNamespace(query=lambda *a: _Count())

    monkeypatch.setattr(database, "get_db_context", _ctx)
    monkeypatch.setattr(settings, "enforce_file_expiry", True)
    file_expiry.report_at_startup()
    assert "4 file(s) are past their expiry and will be deleted" in capsys.readouterr().out
    monkeypatch.setattr(settings, "enforce_file_expiry", False)
    file_expiry.report_at_startup()
    out = capsys.readouterr().out
    assert "NOT enforced (ENFORCE_FILE_EXPIRY=false)" in out and "4 file(s)" in out

    def _down():
        raise RuntimeError("no database")

    monkeypatch.setattr(database, "get_db_context", _down)
    file_expiry.report_at_startup()
    assert "file-expiry.startup-count.failed" in capsys.readouterr().out


# ---------------------------------------------------------------------------------------------
# Every read path consults the rule. Pins the wiring the live module exercises end to end.
# ---------------------------------------------------------------------------------------------


def _code(src):
    return "\n".join(l for l in src.splitlines() if not l.lstrip().startswith("#"))


def _function(src, head):
    """The body of the one function whose definition line starts with `head`, up to the next
    top-level or method definition at the same indent."""
    start = src.index(head)
    assert src.count(head) == 1, f"{head!r} is not unique"
    indent = head[:len(head) - len(head.lstrip())]
    ends = [src.find(f"\n{indent}def ", start + 1), src.find(f"\n{indent}async def ", start + 1),
            src.find(f"\n{indent}@", start + 1), src.find("\nclass ", start + 1)]
    ends = [e for e in ends if e != -1]
    return src[start:min(ends) if ends else len(src)]


API = _code((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"))
SFTP = _code((ROOT / "app" / "sftp" / "sftp_server.py").read_text(encoding="utf-8"))
SERVICE = _code((ROOT / "app" / "services" / "vault_service.py").read_text(encoding="utf-8"))

# (source, function head, how many times it must consult the rule)
_READ_PATHS = [
    (API, "async def list_vault_files(", 1),
    (API, "async def download_file(", 1),
    (API, "async def get_file_info(", 1),
    (API, "async def preview_render_file(", 1),
    (API, "async def copy_file_endpoint(", 1),
    (API, "async def move_file_endpoint(", 1),
    (API, "async def delete_file(", 1),              # an expired file answers 404 here too
    (API, "async def create_public_link(", 1),
    (API, "async def redeem_public_link(", 2),      # a file target, and a folder's children
    (API, "async def download_public_link(", 1),
    (API, "async def create_share(", 1),
    (API, "def _claim_resolved_share(", 1),
    (API, "def _share_dict(", 1),
    (API, "def _shared_with_me_dict(", 1),
    (API, "def _shared_available_dict(", 2),        # not offered, and no name
    (SFTP, "    def _resolve_file(", 1),             # stat, open, remove, rename
    (SFTP, "    def list_folder(", 1),
    (SERVICE, "    def _resolve_download(", 1),      # web download + preview, SFTP open, copy
    (SERVICE, "    def rename_file(", 1),
    (SERVICE, "    def copy_file(", 1),
    (SERVICE, "    def move_file(", 1),
    (SERVICE, "    def _copy_folder_recursive(", 1),
]


@pytest.mark.parametrize("src,head,times", _READ_PATHS, ids=[h.strip() for _, h, _ in _READ_PATHS])
def test_each_read_path_consults_the_rule(src, head, times):
    body = _function(src, head)
    uses = body.count("file_expiry.live_clause()") + body.count("file_expiry.is_expired(")
    assert uses == times, f"{head.strip()} consults file expiry {uses} time(s), expected {times}"


def test_the_download_lookups_answer_404_before_any_bytes_or_budget():
    """The web download refuses an expired file where it refuses a missing one: before a transfer
    slot is taken and before a share download is burned."""
    body = _function(API, "async def download_file(")
    lookup = body.index("File.id == file_id, File.vault_id == vault_id, file_expiry.live_clause()")
    assert lookup < body.index("transfer_admission.acquire()")
    assert lookup < body.index("burn_share_download(")


def test_the_web_process_starts_the_sweep_and_the_sftp_process_does_not():
    """After the startup step, which clears the deadlines left in vaults whose expiry is off, and
    passing on whether that worked: the loop sweeps nothing until it has (tests/test_file_expiry_off)."""
    start = API.index("async def lifespan")
    lifespan = API[start:API.index("app.router.lifespan_context", start)]
    prepare = "expiry_cleared = file_expiry.prepare_at_startup()"
    loop = "expiry_task = asyncio.create_task(file_expiry.run_forever(cleared=expiry_cleared))"
    assert lifespan.count(prepare) == 1 and lifespan.count(loop) == 1
    assert lifespan.index(prepare) < lifespan.index(loop)
    assert "run_forever" not in lifespan.replace(loop, "")
    assert lifespan.count("expiry_task.cancel()") == 1
    assert "run_forever" not in SFTP and "sweep_once" not in SFTP
    assert "cleanup_expired_files" not in SFTP


def test_nothing_else_calls_the_sweep():
    """One sweeper, in one place: the loop. Anything else deleting expired files would bypass the
    switch."""
    callers = [p for p in (ROOT / "app").rglob("*.py")
               if "cleanup_expired_files(" in p.read_text(encoding="utf-8")]
    assert sorted(p.name for p in callers) == ["file_expiry.py", "vault_service.py"]


# ---------------------------------------------------------------------------------------------
# The setting's plumbing
# ---------------------------------------------------------------------------------------------


def _dockvault():
    spec = importlib.util.spec_from_file_location("dockvault_expiry", ROOT / "dockvault.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_env_example_documents_the_switch():
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\nENFORCE_FILE_EXPIRY=true\n") == 1


def test_a_fresh_volume_set_keeps_a_postponement(monkeypatch):
    dv = _dockvault()
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config({"ENFORCE_FILE_EXPIRY": "false"}, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert "ENFORCE_FILE_EXPIRY=false" in lines
    written = dv.parse_env("\n".join(lines))["ENFORCE_FILE_EXPIRY"]
    assert Settings(enforce_file_expiry=written).enforce_file_expiry is False


@pytest.mark.parametrize("env", [{}, {"ENFORCE_FILE_EXPIRY": "true"}])
def test_an_enforcing_env_says_nothing(env):
    """The common case authors the .env it always did; the application's default applies."""
    dv = _dockvault()
    cfg = dv.new_set_config(env, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert not [l for l in lines if l.startswith("ENFORCE_FILE_EXPIRY")]
