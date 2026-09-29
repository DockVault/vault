"""An image refuses to start on data a newer release changed in a way it cannot read.

A release that stores something an older one cannot read marks the database with a row in
data_requirements: the oldest version that can read the data, what changed, and how to undo it. Every
image with the reader checks the table before anything touches the database, in the web process and
in the SFTP process, and refuses to start when a row names a version above its own -- unless the
operator sets ALLOW_START_ON_NEWER_DATA. The host tool, before going back to an older version, asks
the running deployment what is in the way, when the deployment can answer.

The reader runs here against a real database engine (SQLite, through the same SQLAlchemy calls); the
start-up wiring is pinned in the source; the host tool runs its real update path with only its
compose, backup and health calls stubbed.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import tempfile
from pathlib import Path

import pytest
import sqlalchemy as sa

from app.core import data_requirements as dr
from app.core.models import DataRequirement

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture
def engine():
    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'marks.db'}")
        yield engine
        engine.dispose()


@pytest.fixture
def marked(engine):
    """The table as the model builds it. Written out, because the model's server default is
    PostgreSQL's; the columns are pinned to the model's by the test below."""
    with engine.begin() as conn:
        conn.execute(sa.text(
            "CREATE TABLE data_requirements (key VARCHAR(64) PRIMARY KEY, "
            "requires_at_least VARCHAR(32) NOT NULL, reason TEXT NOT NULL, undo TEXT, "
            "since DATETIME NOT NULL)"))
    return engine


def test_the_model_has_the_columns_older_readers_select_by_name():
    table = DataRequirement.__table__
    assert table.name == "data_requirements"
    columns = {c.name: c for c in table.columns}
    assert set(columns) == {"key", "requires_at_least", "reason", "undo", "since"}
    assert [c.name for c in table.primary_key.columns] == ["key"]
    assert {name for name, c in columns.items() if c.nullable} == {"undo"}


def _mark(engine, key, requires, reason="made a change", undo="undo it"):
    with engine.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO data_requirements (key, requires_at_least, reason, undo, since) "
            "VALUES (:k, :r, :why, :undo, CURRENT_TIMESTAMP)"),
            {"k": key, "r": requires, "why": reason, "undo": undo})


def _check(engine, version, allow=False):
    with engine.connect() as conn:
        return dr.check(conn, version, allow=allow)


# --- the reader -------------------------------------------------------------------------------------

def test_no_table_no_effect(engine):
    """A database no release with the reader has touched, and every database before one writes."""
    assert _check(engine, "0.33.1") == []


def test_an_empty_table_no_effect(marked):
    assert _check(marked, "0.33.1") == []


def test_a_requirement_above_this_version_refuses_to_start_and_says_how_to_undo_it(marked):
    _mark(marked, "audit-archive", "0.34.0",
          reason="moved audit history older than 90 days into compressed archive blocks",
          undo="run `python3 dockvault.py audit unarchive`")

    with pytest.raises(dr.NewerDataRefusal) as refused:
        _check(marked, "0.33.1")

    message = str(refused.value)
    assert message.startswith("DockVault 0.33.1 will not start")
    assert "Needs DockVault 0.34.0 or later (audit-archive): moved audit history older than 90 days" \
        in message
    assert "first undo it with the newer version: run `python3 dockvault.py audit unarchive`" \
        in message
    assert "set ALLOW_START_ON_NEWER_DATA=true" in message
    assert "incomplete audit log" in message, "what the escape risks"


@pytest.mark.parametrize("requires", ["0.33.1", "0.33.0", "0.9.9"])
def test_a_requirement_this_version_meets_does_not_stop_it(marked, requires):
    """Version order, not text order: 0.9.9 is below 0.33.1."""
    _mark(marked, "met", requires)
    assert _check(marked, "0.33.1") == []


def test_only_the_unmet_requirements_are_named(marked):
    _mark(marked, "met", "0.33.0", reason="an old change")
    _mark(marked, "legal-holds", "0.34.0", reason="keeps records under a legal hold",
          undo="release the holds")

    with pytest.raises(dr.NewerDataRefusal) as refused:
        _check(marked, "0.33.2")

    assert "legal-holds" in str(refused.value)
    assert "an old change" not in str(refused.value)


@pytest.mark.parametrize("requires", ["1.0", "0.34", "latest", ""])
def test_a_requirement_this_version_cannot_parse_counts_as_unmet(marked, requires):
    _mark(marked, "odd", requires)
    with pytest.raises(dr.NewerDataRefusal):
        _check(marked, "0.33.1")


@pytest.mark.parametrize("version", ["", "dev", "0.33"])
def test_a_version_that_cannot_parse_its_own_meets_nothing(marked, version):
    _mark(marked, "any", "0.1.0")
    with pytest.raises(dr.NewerDataRefusal):
        _check(marked, version)


def test_a_requirement_with_no_undo_step_points_at_the_release_notes(marked):
    _mark(marked, "levels", "0.34.0", reason="records less than everything", undo=None)
    with pytest.raises(dr.NewerDataRefusal) as refused:
        _check(marked, "0.33.1")
    assert "The newer version's release notes say how to undo it." in str(refused.value)


def test_a_table_this_version_cannot_read_refuses_too(engine):
    """Something newer made it, and this version cannot tell what it asks for."""
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE data_requirements (key VARCHAR(64) PRIMARY KEY, "
                             "needs VARCHAR(32))"))
    with pytest.raises(dr.NewerDataRefusal, match="cannot be read by this version"):
        _check(engine, "0.33.1")


def test_the_escape_starts_it_with_a_warning_naming_each_requirement(marked, capsys):
    _mark(marked, "audit-archive", "0.34.0", reason="archived audit history", undo="unarchive it")

    unmet = _check(marked, "0.33.1", allow=True)

    assert [row.key for row in unmet] == ["audit-archive"]
    err = capsys.readouterr().err
    assert "WARNING: ALLOW_START_ON_NEWER_DATA is set" in err
    assert "WARNING: - Needs DockVault 0.34.0 or later (audit-archive): archived audit history" in err


def test_the_escape_also_covers_a_table_it_cannot_read(engine, capsys):
    with engine.begin() as conn:
        conn.execute(sa.text("CREATE TABLE data_requirements (key VARCHAR(64) PRIMARY KEY)"))
    assert _check(engine, "0.33.1", allow=True) == []
    assert "cannot read the data_requirements table" in capsys.readouterr().err


def test_the_escape_says_nothing_when_nothing_is_in_the_way(marked, capsys):
    assert _check(marked, "0.33.1", allow=True) == []
    assert capsys.readouterr().err == ""


def test_this_images_version_is_its_version_file():
    assert dr.running_version() == (ROOT / "VERSION").read_text(encoding="utf-8").strip()


# --- the start-up check, as each process runs it ---------------------------------------------------

@pytest.fixture
def startup(monkeypatch, marked):
    from app.core import config, database
    monkeypatch.setattr(database, "_require_engine", lambda: marked)
    monkeypatch.setattr(dr, "running_version", lambda: "0.33.1")
    monkeypatch.setattr(config.settings, "allow_start_on_newer_data", False)
    return marked


def test_the_start_up_check_leads_the_log_with_the_plain_message(startup, capsys):
    _mark(startup, "legal-holds", "0.34.0", reason="keeps records under a legal hold",
          undo="release the holds")

    with pytest.raises(dr.NewerDataRefusal):
        dr.check_at_startup("sftp")

    err = capsys.readouterr().err
    assert err.startswith("[sftp] DockVault 0.33.1 will not start")
    assert "[sftp]   To go back to this version, first undo it with the newer version: release " \
        "the holds" in err


def test_the_start_up_check_reads_the_setting(startup, monkeypatch, capsys):
    from app.core import config
    _mark(startup, "legal-holds", "0.34.0")
    monkeypatch.setattr(config.settings, "allow_start_on_newer_data", True)

    dr.check_at_startup("web")

    assert "WARNING: ALLOW_START_ON_NEWER_DATA is set" in capsys.readouterr().err


def test_the_start_up_check_passes_on_a_clean_database(startup, capsys):
    dr.check_at_startup("web")
    assert capsys.readouterr().err == ""


def _function(source: str, name: str) -> str:
    assert source.count(f"\ndef {name}(") + source.count(f"\nasync def {name}(") == 1, name
    body = re.split(rf"\n(?:async )?def {name}\(", source, maxsplit=1)[1]
    return re.split(r"\n(?:async )?def |\n@|\nclass ", body, maxsplit=1)[0]


def test_the_web_process_checks_before_anything_touches_the_database():
    lifespan = _function((ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8"),
                         "lifespan")
    assert lifespan.count('_check_data_requirements("web")') == 1
    assert lifespan.index("initialize_runtime()") < lifespan.index('_check_data_requirements("web")')
    assert lifespan.index('_check_data_requirements("web")') < lifespan.index("init_db()")
    assert lifespan.index('_check_data_requirements("web")') < lifespan.index(
        "_run_lightweight_migrations()")


def test_the_sftp_process_checks_before_it_serves_anyone():
    """In the program's entry, which both the split container and the one-container launcher run
    (python -m app.sftp.sftp_server), before the server starts."""
    source = (ROOT / "app" / "sftp" / "sftp_server.py").read_text(encoding="utf-8")
    assert source.count('_check_data_requirements("sftp")') == 1
    assert source.count("\nif __name__ == '__main__':\n") == 1
    entry = source.split("\nif __name__ == '__main__':\n", 1)[1]
    assert entry.index('_check_data_requirements("sftp")') < entry.index("start_sftp_server()")
    launcher = (ROOT / "run_combined.py").read_text(encoding="utf-8")
    assert '_spawn("app.sftp.sftp_server", "sftp")' in launcher
    compose = (ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8")
    assert 'command: ["python", "-m", "app.sftp.sftp_server"]' in compose


# --- the setting ------------------------------------------------------------------------------------

def test_the_setting_is_off_by_default_and_documented():
    from app.core.config import Settings
    assert Settings.model_fields["allow_start_on_newer_data"].default is False
    example = (ROOT / ".env.example").read_text(encoding="utf-8")
    assert example.count("\nALLOW_START_ON_NEWER_DATA=false\n") == 1


def _dockvault():
    spec = importlib.util.spec_from_file_location("dockvault_marker", ROOT / "dockvault.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize("env", [{}, {"ALLOW_START_ON_NEWER_DATA": "true"}])
def test_setup_never_writes_the_escape(monkeypatch, env):
    """Not on a fresh install, and not carried into a fresh volume set: it is set by hand, for as
    long as it is needed."""
    dv = _dockvault()
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    cfg = dv.new_set_config(env, "prefix-1", "dep-1")
    lines = dv.build_env_lines({**cfg, "server_name": "localhost"})
    assert not [line for line in lines if "ALLOW_START_ON_NEWER_DATA" in line]
    assert dv.NEWER_DATA_ESCAPE == "ALLOW_START_ON_NEWER_DATA"


# --- the host tool, going back ---------------------------------------------------------------------

def _matrix():
    """0.33.0 has no reader; 0.33.1, the first release with one, and 0.34.0 do."""
    return {
        "schema_version": 3, "about": "test", "kinds": {"direct": "a", "blocked": "b"},
        "advisories": {},
        "versions": {"0.33.0": {"released": "2026-01-01", "notes": "a"},
                     "0.33.1": {"released": "2026-01-02", "notes": "b"},
                     "0.34.0": {"released": "2026-01-03", "notes": "c"}},
        "edges": [{"from": "0.33.0", "to": "0.33.1", "kind": "direct", "reversible": True,
                   "requires_backup": False},
                  {"from": "0.33.1", "to": "0.34.0", "kind": "direct", "reversible": True,
                   "requires_backup": False}],
    }


class _Deployment:
    """A deployment at `running`, with the compose, backup and health calls stubbed and every
    `docker compose` call recorded. `ask` answers the host operator's downgrade-blockers action."""

    def __init__(self, tmp_path, monkeypatch, *, running="0.34.0", ask=None, source="the running container",
                 env_extra=""):
        self.dv = dv = _dockvault()
        monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
        monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
        monkeypatch.setattr(dv, "fetch_release_tags", lambda *a, **k: [])
        monkeypatch.setattr(dv, "fetch_main_lifecycle_matrix", lambda *a, **k: None)
        (tmp_path / "VERSION").write_text(running + "\n", encoding="utf-8", newline="")
        (tmp_path / ".env").write_text(
            "COMPOSE_PROFILES=combined\nDOCKVAULT_IMAGE=%s\n%s" % (dv.LOCAL_IMAGE, env_extra),
            encoding="utf-8", newline="")
        (tmp_path / "docs").mkdir(exist_ok=True)
        (tmp_path / "docs" / "upgrade-matrix.json").write_text(
            json.dumps(_matrix()), encoding="utf-8", newline="")
        monkeypatch.setattr(dv, "fetch_upgrade_matrix", lambda tag, root=None, opener=None: (
            _matrix(), "the test matrix"))
        self.tool = tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
        self.calls = []

        def run_dc(*args, **kw):
            self.calls.append(args)
            if "downgrade-blockers" in args and ask is not None:
                return ask(args)
            return argparse.Namespace(returncode=0, stdout="", stderr="")

        monkeypatch.setattr(tool, "_run_dc", run_dc)
        monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
        monkeypatch.setattr(tool, "_start_secure_stack", lambda *a, **k: True)
        monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
        monkeypatch.setattr(tool, "_running_version", lambda *a, **k: (running, source))
        monkeypatch.setattr(tool, "_do_backup", lambda env, args: None)
        self.env = tmp_path / ".env"

    def update(self, tag, **flags):
        self.tool.update(argparse.Namespace(
            tag=tag, source=False, yes=True, non_interactive=True, dry_run=False,
            backup_verified=True, **flags))

    def asked(self):
        return [c for c in self.calls if "downgrade-blockers" in c]

    def image(self):
        return self.dv.parse_env(self.env.read_text(encoding="utf-8")).get("DOCKVAULT_IMAGE", "")


def _answers(blockers):
    def ask(_args):
        return argparse.Namespace(returncode=0, stderr="", stdout="booting...\n" + json.dumps(
            {"ok": True, "blockers": blockers}) + "\n")
    return ask


def _not_offered(_args):
    return argparse.Namespace(returncode=2, stdout="", stderr=(
        "usage: python -m app.core.host_operator [-h] ...\npython -m app.core.host_operator: "
        "error: argument action: invalid choice: 'downgrade-blockers' (choose from 'lookup', "
        "'list')\n"))


_HOLD = {"key": "legal-holds", "requires_at_least": "0.34.0", "reason": "keeps records under a hold",
         "undo": "release the holds"}


def test_going_back_asks_the_running_version_and_refuses_while_something_is_in_the_way(
        tmp_path, monkeypatch, capsys):
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers([_HOLD]))

    with pytest.raises(SystemExit):
        deployment.update("v0.33.1")

    out = capsys.readouterr().out
    assert deployment.asked() == [("exec", "-T", "vault", "python", "-m", "app.core.host_operator",
                                   "downgrade-blockers", "--target", "0.33.1")]
    assert "0.34.0 has changed this deployment's data in a way v0.33.1 cannot read" in out
    assert "keeps records under a hold (needs 0.34.0 or later)" in out
    assert "undo it first, with 0.34.0 running: release the holds" in out
    assert "v0.33.1 would refuse to start on this data" in out
    assert "--force-downgrade" in out and "ALLOW_START_ON_NEWER_DATA=true" in out
    assert deployment.image() == deployment.dv.LOCAL_IMAGE, "the downgrade went ahead"


def test_going_back_can_be_forced_and_says_what_the_older_image_will_do(tmp_path, monkeypatch, capsys):
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers([_HOLD]))

    deployment.update("v0.33.1", force_downgrade=True)

    assert ("v0.33.1 refuses to start on this data unless ALLOW_START_ON_NEWER_DATA=true"
            in capsys.readouterr().out)
    assert deployment.image().endswith(":v0.33.1")


@pytest.mark.parametrize("forced", [False, True])
def test_going_back_to_a_version_without_the_check_is_refused_even_when_forced(
        tmp_path, monkeypatch, capsys, forced):
    """0.33.0 has no check: it starts on this data regardless, and may delete or change what the
    running version keeps. Nothing but this tool stands in the way, so nothing forces it past."""
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers([_HOLD]))

    with pytest.raises(SystemExit):
        deployment.update("v0.33.0", force_downgrade=forced)

    out = capsys.readouterr().out
    assert "0.34.0 has changed this deployment's data in a way v0.33.0 cannot read" in out
    assert "undo it first, with 0.34.0 running: release the holds" in out
    assert ("v0.33.0 is older than 0.33.1, the first version that checks for this: it would start on "
            "this data regardless, and may delete or change what 0.34.0 keeps") in out
    assert "--force-downgrade does not go back to a version older than 0.33.1" in out
    assert "refuse to start" not in out and "refuses to start" not in out
    assert "ALLOW_START_ON_NEWER_DATA" not in out, "the setting does nothing on a version without the check"
    assert deployment.image() == deployment.dv.LOCAL_IMAGE, "the downgrade went ahead"


def test_going_back_with_nothing_in_the_way_goes_ahead(tmp_path, monkeypatch):
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers([]))

    deployment.update("v0.33.0")

    assert len(deployment.asked()) == 1
    assert deployment.image().endswith(":v0.33.0")


def test_a_running_version_without_the_action_is_not_a_problem(tmp_path, monkeypatch, capsys):
    """Every release before the one that adds the action wrote nothing an older one cannot read."""
    deployment = _Deployment(tmp_path, monkeypatch, ask=_not_offered)

    deployment.update("v0.33.0")

    out = capsys.readouterr().out
    assert len(deployment.asked()) == 1, "asked once, of the first service that answered"
    assert "Could not ask" not in out
    assert deployment.image().endswith(":v0.33.0")


def _cannot_be_asked(_args):
    return argparse.Namespace(returncode=1, stdout="", stderr="service \"vault\" is not running")


def test_a_deployment_that_cannot_be_asked_is_said_so(tmp_path, monkeypatch, capsys):
    deployment = _Deployment(tmp_path, monkeypatch, ask=_cannot_be_asked)

    deployment.update("v0.33.1")

    out = capsys.readouterr().out
    assert [c[2] for c in deployment.asked()] == ["vault", "vault-api"]
    assert ("Could not ask the running deployment whether v0.33.1 can read its data. If it cannot, "
            "v0.33.1 refuses to start and says how to undo the change.") in out
    assert deployment.image().endswith(":v0.33.1")


def test_a_deployment_that_cannot_be_asked_about_a_version_without_the_check_is_told_what_that_risks(
        tmp_path, monkeypatch, capsys):
    deployment = _Deployment(tmp_path, monkeypatch, ask=_cannot_be_asked)

    deployment.update("v0.33.0")

    out = capsys.readouterr().out
    assert ("Could not ask the running deployment whether v0.33.0 can read its data. v0.33.0 is older "
            "than 0.33.1, the first version that checks for this: if 0.34.0 changed the data in a way "
            "v0.33.0 cannot read, v0.33.0 starts anyway and may delete or change what 0.34.0 keeps."
            ) in out
    assert "refuses to start" not in out
    assert deployment.image().endswith(":v0.33.0")


@pytest.mark.parametrize("answer", [
    {"ok": False, "error": "no"},
    {"ok": False, "blockers": []},
    {"ok": "false", "blockers": []},
    {"ok": True},
    {"ok": True, "blockers": "none"},
    {"ok": True, "blockers": ["not an object"]},
])
def test_an_answer_that_does_not_say_is_not_read_as_nothing_in_the_way(tmp_path, monkeypatch, capsys,
                                                                       answer):
    deployment = _Deployment(tmp_path, monkeypatch, ask=lambda _a: argparse.Namespace(
        returncode=0, stderr="", stdout=json.dumps(answer) + "\n"))

    deployment.update("v0.33.1")

    assert "Could not ask the running deployment" in capsys.readouterr().out


def test_an_upgrade_does_not_ask(tmp_path, monkeypatch):
    deployment = _Deployment(tmp_path, monkeypatch, running="0.33.1", ask=_answers([_HOLD]))

    deployment.update("v0.34.0")

    assert deployment.asked() == []
    assert deployment.image().endswith(":v0.34.0")


def test_a_guessed_running_version_is_not_asked(tmp_path, monkeypatch):
    """With nothing running there is nothing to ask; the older image's own check still holds."""
    deployment = _Deployment(tmp_path, monkeypatch, ask=_answers([_HOLD]),
                             source="this checkout's VERSION file (nothing is running to ask)")

    deployment.update("v0.33.1")

    assert deployment.asked() == []


@pytest.mark.parametrize("version, checks", [
    ("0.33.1", True), ("v0.33.1", True), ("0.33.2", True), ("0.34.0", True), ("1.0.0", True),
    ("0.33.0", False), ("v0.32.6", False), ("0.9.9", False), ("latest", False), ("", False),
])
def test_the_tool_knows_which_versions_check(version, checks):
    dv = _dockvault()
    assert dv.FIRST_NEWER_DATA_CHECK == "0.33.1", "the first release whose image reads the mark"
    assert dv.checks_newer_data(version) is checks


def test_the_tool_says_when_the_escape_is_left_set(tmp_path, monkeypatch, capsys):
    deployment = _Deployment(tmp_path, monkeypatch, running="0.33.1",
                             env_extra="ALLOW_START_ON_NEWER_DATA=true\n")
    deployment.update("v0.34.0")
    assert "ALLOW_START_ON_NEWER_DATA is set in .env" in capsys.readouterr().out


def test_the_tool_says_nothing_of_the_escape_when_it_is_not_set(tmp_path, monkeypatch, capsys):
    deployment = _Deployment(tmp_path, monkeypatch, running="0.33.1",
                             env_extra="ALLOW_START_ON_NEWER_DATA=false\n")
    deployment.update("v0.34.0")
    assert "ALLOW_START_ON_NEWER_DATA" not in capsys.readouterr().out
