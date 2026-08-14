"""The launcher tells its children which log components are actually being written.

The API serves the log pull by reading a sink file, but it is a child process and cannot tell
whether anything writes one. Only the launcher does, so it exports a marker. Two properties matter
and both are easy to get wrong:

* it is derived from whether the sink really initialised, not from whether one was intended, so an
  unwritable logs directory reports unavailable; and
* it names WHICH components, because the SFTP child is spawned only under RUN_SFTP and the shipped
  default leaves that empty — a bare "sink active" would promise SFTP logs nothing writes.
"""
import importlib
import os
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
run_combined = importlib.import_module("run_combined")

MARKER = "VAULT_LOG_SINK_ACTIVE"
COMPONENTS = "VAULT_LOG_SINK_COMPONENTS"


@pytest.fixture(autouse=True)
def _isolate_env(monkeypatch):
    """setenv (not delenv) so monkeypatch records a restore.

    delenv on an ABSENT key records nothing, so a value the code under test then writes would
    survive this module and leak into every later test in the process.
    """
    monkeypatch.setenv(MARKER, "")
    monkeypatch.setenv(COMPONENTS, "")
    monkeypatch.delenv(MARKER)
    monkeypatch.delenv(COMPONENTS)


@pytest.fixture(autouse=True)
def _reset_sink():
    """Close handlers between tests — _init_sink attaches a new one to a module-global logger."""
    yield
    lg = run_combined.logging.getLogger("dockvault.logsink")
    for h in list(lg.handlers):
        try:
            h.close()
        except Exception:
            pass
    lg.handlers = []
    run_combined._sink_logger = None


def _init_at(monkeypatch, path):
    monkeypatch.setattr(run_combined, "_SINK_PATH", str(path))
    monkeypatch.setattr(run_combined, "_sink_logger", None)
    run_combined._init_sink()


def test_web_is_marked_when_the_sink_initialises(monkeypatch, tmp_path):
    monkeypatch.delenv("RUN_SFTP", raising=False)
    _init_at(monkeypatch, tmp_path / "logs" / "combined.log")
    assert run_combined._sink_logger is not None, "precondition: the sink should have initialised"

    assert run_combined.mark_sink_active() is True
    assert os.environ[MARKER] == "1"
    assert os.environ[COMPONENTS] == "web"


def test_sftp_is_marked_only_when_it_actually_runs(monkeypatch, tmp_path):
    """The shipped default is RUN_SFTP empty, and the launcher then never spawns that child.

    Claiming SFTP collection there would reproduce, for that component, the exact dead end this
    marker exists to prevent: a token that returns 200 and an empty list forever.
    """
    _init_at(monkeypatch, tmp_path / "logs" / "combined.log")
    monkeypatch.setenv("RUN_SFTP", "1")
    assert run_combined.mark_sink_active() is True
    assert os.environ[COMPONENTS] == "web,sftp"


def test_marker_is_withheld_when_the_sink_failed_to_initialise(monkeypatch):
    """The unwritable-logs-directory case, which _init_sink swallows by design."""
    monkeypatch.setattr(run_combined, "_sink_logger", None)
    assert run_combined.mark_sink_active() is False
    assert MARKER not in os.environ
    assert COMPONENTS not in os.environ


def test_a_stale_marker_from_the_environment_is_CLEARED_not_merely_left(monkeypatch):
    """The whole .env reaches the container via env_file, so the marker can arrive from outside.

    Declining to set it is not enough: an inherited value would survive into every child and the
    API would report a working sink precisely when it is broken — the failure this guards against.
    """
    monkeypatch.setenv(MARKER, "1")
    monkeypatch.setenv(COMPONENTS, "web,sftp")
    monkeypatch.setattr(run_combined, "_sink_logger", None)

    assert run_combined.mark_sink_active() is False
    assert MARKER not in os.environ, "a forged marker survived a failed sink"
    assert COMPONENTS not in os.environ


def test_an_unwritable_sink_directory_really_does_leave_it_disabled(monkeypatch, tmp_path):
    blocker = tmp_path / "not-a-dir"
    blocker.write_text("i am a file", encoding="utf-8")
    _init_at(monkeypatch, blocker / "logs" / "combined.log")
    assert run_combined._sink_logger is None, "a file in the path should defeat makedirs"
    assert run_combined.mark_sink_active() is False
    assert MARKER not in os.environ


def test_the_marker_reaches_a_child_environment_before_it_is_spawned(monkeypatch, tmp_path):
    """_spawn snapshots os.environ per child, so a marker set afterwards would never reach them.

    Driven through the real _spawn rather than only reading main()'s source: a recorder captures
    what the child would actually receive, which is the property that matters.
    """
    _init_at(monkeypatch, tmp_path / "logs" / "combined.log")
    monkeypatch.delenv("RUN_SFTP", raising=False)
    run_combined.mark_sink_active()

    seen = {}

    class _FakePopen:
        def __init__(self, argv, env=None, **kw):
            seen.update(env or {})
            self.stdout = iter(())

        def poll(self):
            return 0

    monkeypatch.setattr(run_combined.subprocess, "Popen", _FakePopen)
    monkeypatch.setattr(run_combined, "_PROCS", [])
    run_combined._spawn("app.api.api_server", "web")

    assert seen.get(MARKER) == "1", "the child would not have seen the marker"
    assert seen.get(COMPONENTS) == "web"


def test_main_marks_before_spawning(monkeypatch):
    """Ordering guard on main() itself, complementing the behavioural test above."""
    import inspect
    src = inspect.getsource(run_combined.main)
    assert src.index("_init_sink()") < src.index("mark_sink_active()") < src.index("_spawn(")
