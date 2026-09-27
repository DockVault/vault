"""A vault whose file expiry is off has no file that can expire.

Before 0.32.6 a file's deadline was stamped at upload and never read, so turning a vault's expiry off
left the deadlines on its files, harmlessly. Enforcing them would have deleted those files within a
minute of the first boot. Three things now keep the rule:

* turning a vault's expiry off takes the deadline off every file in it, in the same transaction
  (``VaultService.set_file_expiry``, which the vault settings endpoint calls); changing the value
  leaves every existing deadline where it is;
* at boot, before the sweep's first run, the web process clears the deadlines earlier versions left in
  vaults whose expiry is off (``file_expiry.prepare_at_startup``), and the loop sweeps nothing until
  that has succeeded;
* the sweep only deletes from vaults whose expiry is on, re-checked under the vault's row lock.

These run the real functions against an in-memory session that applies the queries' filters
(tests/_memory_db.py). tests/test_file_expiry_off_live.py does the same against a running stack.
"""
import contextlib
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

from _async_run import run_coroutine
from _memory_db import MemoryDB
from app.core import file_expiry
from app.core.config import settings
from app.core.models import AuditLog, File, Vault

pytestmark = pytest.mark.unit

T0 = datetime(2026, 9, 1, 8, 0, 0)        # every row's modified time; clearing must not move it


def _vault(value, unit="days"):
    return SimpleNamespace(id=uuid.uuid4(), expire_files_after_days=value, expire_files_unit=unit)


def _file(vault, expires_at, size=10):
    return SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, folder_id=None, size_bytes=size,
                           storage_path=f"blob-{uuid.uuid4().hex}", expires_at=expires_at,
                           updated_at=T0, created_at=T0)


def _service(db, root=None):
    from app.services.vault_service import VaultService
    svc = VaultService.__new__(VaultService)
    svc.db = db
    svc.storage_path = root
    return svc


def _past(days=3):
    return file_expiry.utc_now() - timedelta(days=days)


def _future(days=3):
    return file_expiry.utc_now() + timedelta(days=days)


# ---------------------------------------------------------------------------------------------
# Changing a vault's setting
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("off", [None, 0, "0"])
def test_turning_expiry_off_takes_the_deadline_off_every_file_in_the_vault(off):
    vault, other = _vault(7), _vault(7)
    due, later, none = _file(vault, _past()), _file(vault, _future()), _file(vault, None)
    elsewhere = _file(other, _future())
    db = MemoryDB({Vault: [vault, other], File: [due, later, none, elsewhere]})

    removed = _service(db).set_file_expiry(vault, expire_files_after_days=off)

    assert removed == 2
    assert vault.expire_files_after_days is None, "0 is stored as off, like a blank"
    assert due.expires_at is None and later.expires_at is None and none.expires_at is None
    # Another vault's files are not touched, and no file's modified time moves.
    assert elsewhere.expires_at is not None
    assert {f.updated_at for f in (due, later, none, elsewhere)} == {T0}
    # The vault row is locked before a file row is changed: the lock an upload finishing at the
    # same moment waits on (see finalize_streaming_upload below).
    kinds = [(e[0], e[1]) for e in db.log if e[0] in ("lock", "update")]
    assert kinds == [("lock", Vault), ("update", File)]
    assert db.log[0][2] == {"key_share": True}, "FOR NO KEY UPDATE, as every deleting path takes it"


def test_changing_the_value_keeps_every_deadline_already_given():
    vault = _vault(7)
    due, later, none = _file(vault, _past()), _file(vault, _future()), _file(vault, None)
    before = [(f.expires_at, f.updated_at) for f in (due, later, none)]
    db = MemoryDB({Vault: [vault], File: [due, later, none]})
    svc = _service(db)

    assert svc.set_file_expiry(vault, expire_files_after_days=30) == 0
    assert svc.set_file_expiry(vault, expire_files_unit="hours") == 0
    assert svc.set_file_expiry(vault, expire_files_after_days=2, expire_files_unit="minutes") == 0
    assert (vault.expire_files_after_days, vault.expire_files_unit) == (2, "minutes")
    assert [(f.expires_at, f.updated_at) for f in (due, later, none)] == before
    assert not [e for e in db.log if e[0] == "update"], "no file row is written"


def test_turning_expiry_on_gives_no_existing_file_a_deadline():
    vault = _vault(None)
    kept = _file(vault, None)
    db = MemoryDB({Vault: [vault], File: [kept]})
    assert _service(db).set_file_expiry(vault, expire_files_after_days=1,
                                        expire_files_unit="days") == 0
    assert kept.expires_at is None and vault.expire_files_after_days == 1


@pytest.mark.parametrize("changes", [
    {"expire_files_after_days": -1},
    {"expire_files_after_days": True},
    {"expire_files_after_days": "seven"},
    {"expire_files_after_days": 1.5},
    {"expire_files_after_days": [7]},
    {"expire_files_unit": "weeks"},
    {"expire_files_unit": None},
    {"expire_files_after_days": None, "expire_files_unit": "fortnights"},
])
def test_a_bad_value_is_refused_before_anything_changes(changes):
    vault = _vault(7)
    held = _file(vault, _past())
    db = MemoryDB({Vault: [vault], File: [held]})
    with pytest.raises(ValueError):
        _service(db).set_file_expiry(vault, **changes)
    assert (vault.expire_files_after_days, vault.expire_files_unit) == (7, "days")
    assert held.expires_at is not None and db.log == []


def test_a_negative_setting_an_earlier_version_stored_counts_as_off():
    """Earlier versions stored whatever the settings endpoint was sent. A negative retention would
    have stamped every upload with a deadline in the past; it means off, as 0 does."""
    from app.services.vault_service import calculate_file_expiration

    for value in (None, 0, -3):
        assert file_expiry.expiry_is_off(value)
        assert calculate_file_expiration(SimpleNamespace(expire_files_after_days=value,
                                                         expire_files_unit="days")) is None
    assert not file_expiry.expiry_is_off(1)


def test_the_settings_endpoint_goes_through_set_file_expiry():
    """Both fields, and only through the one function that keeps the rule. (The live module drives
    the endpoint itself.)"""
    src = (Path(__file__).resolve().parents[1] / "app" / "api" / "api_server.py").read_text(
        encoding="utf-8")
    start = src.index("async def update_vault_settings(")
    body = src[start:src.index("\n@app.", start)]
    assert body.count("vault_service.set_file_expiry(vault, **expiry_changes)") == 1
    assert "vault.expire_files_after_days =" not in body and "vault.expire_files_unit =" not in body


# ---------------------------------------------------------------------------------------------
# An upload that finishes after the owner turned expiry off
# ---------------------------------------------------------------------------------------------


def _finalize(monkeypatch, db, vault, expires_at):
    import app.core.security as security
    import app.services.vault_service as vs
    monkeypatch.setattr(vs, "_seal_named_object", lambda *a, **k: None)
    monkeypatch.setattr(vs, "_seal_file_checksum", lambda *a, **k: None)
    monkeypatch.setattr(security, "content_mac", lambda *a, **k: "mac")
    info = {"id": uuid.uuid4(), "name": "a.txt", "original_name": "a.txt", "vault_id": vault.id,
            "folder_id": None, "mime_type": "text/plain", "storage_path": "blob",
            "is_encrypted": True, "password_hash": None, "expires_at": expires_at,
            "uploaded_by": uuid.uuid4(), "vault": vault}
    return _service(db).finalize_streaming_upload(info, 5, "0" * 64)


def test_an_upload_finishing_after_expiry_was_turned_off_keeps_no_deadline(monkeypatch):
    """The deadline is worked out when the upload starts. Turned off before it finishes, the new
    file must not keep it -- the others lost theirs, and this one was not there yet."""
    vault = _vault(7)
    db = MemoryDB({Vault: [vault]})
    started = _future(7)
    vault.expire_files_after_days = None           # the owner turned expiry off meanwhile
    added = _finalize(monkeypatch, db, vault, started)
    assert added.expires_at is None


def test_an_upload_finishing_with_expiry_still_on_keeps_its_deadline(monkeypatch):
    vault = _vault(7)
    db = MemoryDB({Vault: [vault]})
    started = _future(7)
    vault.expire_files_after_days = 30             # changed, not turned off: the deadline stands
    assert _finalize(monkeypatch, db, vault, started).expires_at == started


# ---------------------------------------------------------------------------------------------
# At boot, before the sweep
# ---------------------------------------------------------------------------------------------


def _mixed():
    off, zero, negative, on = _vault(None), _vault(0), _vault(-2), _vault(7)
    rows = {v.id: [_file(v, _past()), _file(v, _future()), _file(v, None)]
            for v in (off, zero, negative, on)}
    db = MemoryDB({Vault: [off, zero, negative, on], File: [f for fs in rows.values() for f in fs]})
    return db, (off, zero, negative), on, rows


def test_startup_clears_the_deadlines_left_in_vaults_whose_expiry_is_off():
    db, offs, on, rows = _mixed()
    assert file_expiry.clear_deadlines_where_expiry_is_off(db) == 6
    for v in offs:
        assert [f.expires_at for f in rows[v.id]] == [None, None, None]
    assert [f.expires_at is None for f in rows[on.id]] == [False, False, True], \
        "a vault whose expiry is on keeps every deadline"
    assert {f.updated_at for fs in rows.values() for f in fs} == {T0}
    # Idempotent: a second boot has nothing to do.
    assert file_expiry.clear_deadlines_where_expiry_is_off(db) == 0


def _db_context(db):
    @contextlib.contextmanager
    def ctx():
        yield db
        db.commit()
    return ctx


def test_prepare_at_startup_clears_then_reports(monkeypatch, capsys):
    import app.core.database as database
    db, offs, on, rows = _mixed()
    monkeypatch.setattr(database, "get_db_context", _db_context(db))
    monkeypatch.setattr(file_expiry, "count_past_expiry", lambda _db: sum(
        1 for f in _db.rows_of(File) if file_expiry.is_past(f.expires_at)))
    monkeypatch.setattr(settings, "enforce_file_expiry", True)

    assert file_expiry.prepare_at_startup() is True
    out = capsys.readouterr().out
    assert "removed the deadline from 6 file(s) in vaults whose expiry is off" in out
    # The report runs after the clearing, so it counts only what the sweep will really delete.
    assert "1 file(s) are past their expiry and will be deleted" in out


def test_prepare_at_startup_says_so_when_it_cannot_clear_and_never_raises(monkeypatch, capsys):
    import app.core.database as database

    def _down():
        raise RuntimeError("no database")

    monkeypatch.setattr(database, "get_db_context", _down)
    assert file_expiry.prepare_at_startup() is False
    assert "file-expiry.clear-off-vaults.failed" in capsys.readouterr().out


def _loop(monkeypatch, clear_results, cleared):
    events, results = [], iter(clear_results)

    def clear():
        ok = next(results, True)
        events.append(("clear", ok))
        return ok

    def sweep():
        events.append(("sweep",))
        return 0

    monkeypatch.setattr(file_expiry, "clear_at_startup", clear)
    monkeypatch.setattr(file_expiry, "sweep_once", sweep)

    async def body():
        task = file_expiry.asyncio.create_task(
            file_expiry.run_forever(interval_seconds=0.01, cleared=cleared))
        for _ in range(500):
            await file_expiry.asyncio.sleep(0.01)
            if events.count(("sweep",)) >= 2:
                break
        task.cancel()
        with pytest.raises(file_expiry.asyncio.CancelledError):
            await task

    run_coroutine(body())
    return events


def test_the_loop_sweeps_nothing_until_the_clearing_has_succeeded(monkeypatch):
    events = _loop(monkeypatch, [False, False, True], cleared=False)
    first_sweep = events.index(("sweep",))
    assert events[:first_sweep] == [("clear", False), ("clear", False), ("clear", True)]
    assert events.count(("clear", True)) == 1, "cleared once, not before every pass"


def test_a_loop_started_after_a_successful_clearing_goes_straight_to_the_sweep(monkeypatch):
    events = _loop(monkeypatch, [], cleared=True)
    assert events and all(e == ("sweep",) for e in events)


# ---------------------------------------------------------------------------------------------
# The sweep itself
# ---------------------------------------------------------------------------------------------


class _Storage:
    def __init__(self):
        self.destroyed = []

    def secure_delete(self, path):
        self.destroyed.append(path.name)
        path.unlink()


def _sweeper(db, root):
    svc = _service(db, root)
    svc.encrypted_storage = _Storage()
    svc.totals = {}

    def _record(vault_id, size_delta, count_delta):
        size, count = svc.totals.get(vault_id, (0, 0))
        svc.totals[vault_id] = (size + size_delta, count + count_delta)

    svc._adjust_vault_totals_by_id = _record
    return svc


def _stored(root, f):
    (root / f.storage_path).write_bytes(b"x" * f.size_bytes)
    return f


def test_the_sweep_never_deletes_from_a_vault_whose_expiry_is_off(tmp_path):
    off, on = _vault(None), _vault(7)
    kept = _stored(tmp_path, _file(off, _past(), size=4))
    gone = _stored(tmp_path, _file(on, _past(), size=6))
    db = MemoryDB({Vault: [off, on], File: [kept, gone]})
    svc = _sweeper(db, tmp_path)

    assert svc.cleanup_expired_files() == [{"file_id": gone.id, "vault_id": on.id}]
    assert db.rows_of(File) == [kept] and (tmp_path / kept.storage_path).exists()
    assert svc.totals == {on.id: (-6, -1)}
    assert [a.resource_id for a in db.added if isinstance(a, AuditLog)] == [str(gone.id)]


def test_the_sweep_checks_the_setting_again_under_the_vault_lock(tmp_path):
    """Expiry turned off between the sweep's first read and its lock: nothing is deleted."""
    vault = _vault(7)
    due = _stored(tmp_path, _file(vault, _past()))
    db = MemoryDB({Vault: [vault], File: [due]})
    db.on_lock.append(lambda: setattr(vault, "expire_files_after_days", None))
    svc = _sweeper(db, tmp_path)

    assert svc.cleanup_expired_files() == []
    assert db.rows_of(File) == [due] and svc.totals == {}
    assert ("rollback",) in db.log and ("commit",) not in db.log


def test_a_leftover_deadline_in_a_vault_whose_expiry_is_off_does_not_hold_up_the_sweep(tmp_path):
    """The candidate read skips such vaults too. Were it to return one first, a batch could be taken
    up by a vault the locked read then refuses, and the files really due would wait behind it."""
    off, on = _vault(None), _vault(7)
    stale = _stored(tmp_path, _file(off, _past(days=9)))
    due = _stored(tmp_path, _file(on, _past(days=1)))
    db = MemoryDB({Vault: [off, on], File: [stale, due]})
    svc = _sweeper(db, tmp_path)

    assert svc.cleanup_expired_files(batch_size=1) == [{"file_id": due.id, "vault_id": on.id}]
    assert db.rows_of(File) == [stale]
