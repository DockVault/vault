"""The rollback condition of the legal holds, offline (app/core/legal_hold_marker.py).

While a hold stands or kept rows wait for their purge, a release before 0.34.0 would destroy the kept files. So
the holds keep a row in data_requirements (the marker 0.33.1 and later read): such an image refuses to start
below it, whatever host tool the operator runs, and dockvault.py update asks the running container's
downgrade-blockers before going back and refuses unless --force-downgrade. CONDITION is the upgrade matrix's
condition, with the flag that says it blocks a rollback when its query finds a row. test_legal_holds.py checks
that the row follows the holds; test_legal_holds_live.py runs the condition's query and the host action on
Postgres.
"""
import importlib.util
import json
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import legal_hold_marker as marker  # noqa: E402
from app.core import models as m  # noqa: E402
from app.core import recording_marker  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def _matrix_module():
    spec = importlib.util.spec_from_file_location("upgrade_matrix_for_holds",
                                                  ROOT / ".github" / "scripts" / "upgrade_matrix.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("released", [False, True], ids=["now", "at-the-release"])
def test_the_condition_is_one_the_matrix_accepts_and_blocks_a_rollback(released):
    """Added to the newest edge below 0.34.0, which carries none of 0.34.0's conditions, whether or not the matrix
    declares 0.34.0 already (it does from the release commit on)."""
    import _release_conditions as rc
    um = _matrix_module()
    data = json.loads((ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8"))
    data = rc.before_the_release(rc.with_the_release(data) if released else data)
    edge = data["edges"][-1]
    assert marker.CONDITION["id"] not in {c["id"] for c in edge.get("conditions", [])}
    edge.setdefault("conditions", []).append(dict(marker.CONDITION))
    um.validate_matrix(data, released_ceiling=None)
    assert marker.CONDITION["blocks_rollback"] is True and marker.CONDITION["detect"] == marker.DETECT_SQL
    assert marker.CONDITION["id"] == "legal-holds-block-rollback"


def test_the_condition_finds_a_standing_hold_or_any_kept_row():
    """A kept file, folder or old name: an older release would retire the keys the kept rows were sealed under, as
    it would destroy a kept file's bytes."""
    sql = marker.DETECT_SQL
    assert "FROM legal_hold_vaults WHERE released_at IS NULL" in sql
    for table in ("held_files", "held_folders", "held_name_history"):
        assert sql.count(f"UNION ALL SELECT 1 FROM {table} ") == 1, table


@pytest.fixture
def db():
    from _kept_db import kept_database
    with kept_database() as (make, _engine):
        session = make()
        yield session
        session.close()


def _row(db):
    from sqlalchemy import text
    return db.execute(text("SELECT key, requires_at_least, reason, undo FROM data_requirements")).fetchall()


@pytest.mark.parametrize("what", ["hold", "file", "folder", "old name"])
def test_the_marker_is_there_while_a_hold_stands_or_a_kept_row_remains(db, what, monkeypatch):
    monkeypatch.setattr(recording_marker, "running_version", lambda: "0.34.0")
    vault_id = uuid.uuid4()
    if what == "hold":
        db.add(m.LegalHoldVault(case_id=uuid.uuid4(), vault_id=vault_id, placed_by_username="a"))
    elif what == "file":
        db.add(m.HeldFile(id=uuid.uuid4(), vault_id=vault_id, storage_path="p"))
    elif what == "folder":
        db.add(m.HeldFolder(id=uuid.uuid4(), vault_id=vault_id))
    else:
        db.add(m.HeldNameHistory(id=uuid.uuid4(), object_id=uuid.uuid4(), vault_id=vault_id, kind="file",
                                 enc_name="zk2:old", name_key_version=1))
    assert marker.sync(db) is True
    ((key, needs, reason, undo),) = _row(db)
    assert (key, needs) == ("legal-holds", "0.34.0")
    assert reason.startswith("Legal holds keep files deleted from vaults") and "0.34.0" in reason
    assert "Release every legal hold" in undo
    db.commit()
    assert marker.sync(db) is True and len(_row(db)) == 1, "written once, then kept"


@pytest.mark.parametrize("running", ["0.34.0", "0.33.6"])
def test_the_refusal_an_older_release_prints_names_the_release_that_removes_the_marker(db, monkeypatch, running):
    """The released 0.33.x prints the undo after "To go back to this version, first undo it with the newer version:",
    where "this version" is itself, the release that refuses: the undo names the release to start instead, the one
    the marker asks for (an earlier build of this one asks for its own version)."""
    from app.core import data_requirements as dr
    monkeypatch.setattr(recording_marker, "running_version", lambda: running)
    db.add(m.HeldFile(id=uuid.uuid4(), vault_id=uuid.uuid4(), storage_path="p"))
    assert marker.sync(db) is True
    db.commit()
    rows = dr.unmet(dr.read_requirements(db.connection()), "0.33.5")
    message = dr.refusal_message(rows, "0.33.5")
    assert f"Needs DockVault {running} or later (legal-holds)" in message
    (undo,) = [line for line in message.splitlines() if "first undo it with the newer version" in line]
    assert undo.endswith(f"then start DockVault {running} or later once so it removes this marker.")
    assert "this version once" not in undo


def test_the_marker_goes_when_nothing_is_held_or_kept(db, monkeypatch):
    monkeypatch.setattr(recording_marker, "running_version", lambda: "0.34.0")
    hold = m.LegalHoldVault(case_id=uuid.uuid4(), vault_id=uuid.uuid4(), placed_by_username="a")
    db.add(hold)
    marker.sync(db)
    db.commit()
    hold.released_at = datetime.utcnow()
    assert marker.sync(db) is False and _row(db) == []


@pytest.mark.parametrize("running, needs", [("0.33.2", "0.33.2"), ("0.34.0", "0.34.0"), ("0.34.1", "0.34.0"),
                                             ("", "0.34.0")])
def test_the_marker_asks_for_the_release_with_the_holds_or_an_earlier_builds_own_version(monkeypatch, running,
                                                                                         needs):
    monkeypatch.setattr(recording_marker, "running_version", lambda: running)
    assert marker.required_version() == needs


def test_the_start_checks_the_marker_after_building_the_triggers():
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    body = source.split("\ndef _run_lightweight_migrations(", 1)[1].split("\ndef ", 1)[0]
    lines = [ln.strip() for ln in body.splitlines()]
    assert lines.count("legal_hold_marker.check_at_start()") == 1
    assert body.index("kept_tables.install(db)") < body.index("legal_hold_marker.check_at_start()")


def _downgrade_answer(db, target):
    from app.core import host_compliance
    return {"ok": True, "target": target, "blockers": host_compliance.downgrade_blockers(db, target)}


def test_the_host_action_names_the_holds_to_an_older_target_only(db, monkeypatch):
    monkeypatch.setattr(recording_marker, "running_version", lambda: "0.34.0")
    db.add(m.HeldFile(id=uuid.uuid4(), vault_id=uuid.uuid4(), storage_path="p"))
    marker.sync(db)
    db.commit()
    (blocker,) = _downgrade_answer(db, "0.33.2")["blockers"]
    assert blocker["key"] == "legal-holds" and blocker["requires_at_least"] == "0.34.0"
    assert _downgrade_answer(db, "0.34.0")["blockers"] == []


def test_the_undo_names_only_what_releases_a_hold():
    """A hold is released on the Compliance page (or by closing its case there); the host tool releases none."""
    from app.core import host_compliance
    undo = marker.UNDO.format(version="0.34.0")
    assert undo.startswith("Release every legal hold on the Compliance page (dockvault.py cases cannot release one)")
    assert not any(a.startswith(("close", "release")) for a in host_compliance.ACTIONS)
    tool = (ROOT / "dockvault.py").read_text(encoding="utf-8")
    actions = tool.split("\nCASE_ACTIONS = (", 1)[1].split("\n)\n", 1)[0]
    assert "release" not in actions.lower()


def test_dockvault_refuses_to_go_back_over_the_holds_unless_forced(db, monkeypatch, tmp_path, capsys):
    from test_data_requirements import _Deployment, _answers
    monkeypatch.setattr(recording_marker, "running_version", lambda: "0.34.0")
    db.add(m.LegalHoldVault(case_id=uuid.uuid4(), vault_id=uuid.uuid4(), placed_by_username="a"))
    marker.sync(db)
    db.commit()
    blockers = _downgrade_answer(db, "0.33.2")["blockers"]
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers(blockers))
    with pytest.raises(SystemExit):
        deployment.update("v0.33.2")
    out = capsys.readouterr().out
    assert "Legal holds keep files deleted from vaults" in out and "Release every legal hold" in out
    assert deployment.image() == deployment.dv.LOCAL_IMAGE, "it did not go back"
    deployment.update("v0.33.2", force_downgrade=True)
    assert deployment.image().endswith(":v0.33.2")
