"""A backup that ends while it holds the deployment paused resumes it first (dockvault.py: SignalsEndTheRun,
_do_backup, _pause_for_backup, _resume_after_backup):

- a closed SSH session (SIGHUP), kill or a timeout (SIGTERM) and, on Windows, Ctrl-Break (SIGBREAK) end the process
  without running a single `finally` by default; while the backup holds the deployment paused they become an exit
  that resumes it, removes the incomplete backup and says so, with the status a shell gives a process a signal ended;
- a signal that comes while a pause or the resume is running waits for it, and a second one does not cut the resume
  short; a signal the run ignores (nohup) is left ignored, and every signal's action is put back afterwards;
- a pause cut short (a timeout, Ctrl-C) may have taken effect: that service is resumed on its own;
- the interactive menu, which goes back to its list after a command's error, ends on a signal.

The signals are real (sent to a child process that runs the backup with Docker stubbed); the rest is in process."""
import argparse
import os
import signal
import subprocess
import sys
import textwrap
import time
from pathlib import Path

import pytest

import dockvault as dv
from test_dockvault_tool import _reusable_env_cfg, _tgz

pytestmark = pytest.mark.unit
ROOT = Path(__file__).resolve().parent.parent
posix_only = pytest.mark.skipif(os.name == "nt", reason="sends POSIX signals to a child process")

# The child: the real _do_backup of this checkout's dockvault.py, Docker stubbed. Each step it takes is a line in
# calls.log; it waits where the test sends a signal until the test lets it go on (a file named go or go-archive).
_CHILD = textwrap.dedent('''
    import argparse, importlib.util, io, os, signal, sys, tarfile, time
    root, dv_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    spec = importlib.util.spec_from_file_location("dockvault_backup_signals_child", dv_path)
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    log = os.path.join(root, "calls.log")

    def note(line):
        with open(log, "a", encoding="utf-8") as f:
            f.write(line + "\\n")

    def wait_for(name):
        for _ in range(900):
            if os.path.exists(os.path.join(root, name)):
                return
            time.sleep(0.1)
        note("never let go on: " + name)
        raise SystemExit(3)

    class Result(object):
        returncode, stdout, stderr = 0, "", ""

    def run_dc(*a, **k):
        line = " ".join(a)
        if mode == "pausing" and line == "pause vault-db":
            note("pausing vault-db")
            wait_for("go")
        if mode == "resume" and a[0] == "unpause":
            note("unpausing")
            wait_for("go")
        note(line)
        return Result()

    def tar(vol, bundle, archive, **k):
        if mode in ("archive", "nohup", "resume"):
            note("archiving " + vol)
            wait_for("go-archive")
        with tarfile.open(os.path.join(bundle, archive), "w:gz") as t:
            info = tarfile.TarInfo("marker.txt")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
        return True

    # As a run started from a terminal has them (a test run under nohup hands its children SIGHUP ignored).
    signal.signal(signal.SIGHUP, signal.SIG_IGN if mode == "nohup" else signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    dv.volume_exists = lambda name, **k: not name.endswith("_vault_brand")
    dv.container_running = lambda name, **k: name in ("vault", "vault-db")
    dv.container_paused = lambda name, **k: False
    dv.tighten_secret_file = lambda path: True
    dv.tar_volume = tar
    tool = dv.DockVault(dv.Palette(False), root=root)
    tool._run_dc = run_dc
    tool._do_backup(tool._load_env(), argparse.Namespace(non_interactive=True,
                                                         backup_dir=os.path.join(root, "backups")))
    note("done")
''')


def _calls(root):
    log = root / "calls.log"
    return log.read_text(encoding="utf-8").splitlines() if log.exists() else []


def _wait_line(root, start, proc, timeout=60):
    """Until calls.log has a line beginning with `start` (the child is there); fails if the child ends first."""
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if any(line.startswith(start) for line in _calls(root)):
            return
        if proc.poll() is not None:
            break
        time.sleep(0.05)
    pytest.fail("the backup never reached %r: %s" % (start, _calls(root)))


def _run_child(tmp_path, mode, steps):
    """Run the child backup in `mode`, let `steps(proc, root)` drive it, and return (exit status, the docker compose
    calls it made, its output with the spacing folded, the deployment folder)."""
    root = tmp_path / "deploy"
    root.mkdir()
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-sg", deployment_id="sg")
    (root / ".env").write_text("\n".join(dv.build_env_lines(cfg)) + "\n", encoding="utf-8")
    script = tmp_path / "child.py"
    script.write_text(_CHILD, encoding="utf-8")
    env = dict(os.environ)
    for name in ("XDG_DATA_HOME", "LOCALAPPDATA", "APPDATA"):
        env[name] = str(tmp_path / "app-data")
    with open(tmp_path / "out.txt", "w", encoding="utf-8") as out:
        proc = subprocess.Popen([sys.executable, str(script), str(root), str(ROOT / "dockvault.py"), mode],
                                stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL, env=env)
        try:
            steps(proc, root)
            proc.wait(timeout=90)
        finally:
            if proc.poll() is None:
                proc.kill()
                proc.wait()
    said = " ".join((tmp_path / "out.txt").read_text(encoding="utf-8").split())
    compose = [c for c in _calls(root) if c.startswith(("pause ", "unpause "))]
    return proc.returncode, compose, said, root


def _bundles(root):
    folder = root / "backups"
    return sorted(folder.iterdir()) if folder.is_dir() else []


@posix_only
@pytest.mark.parametrize("signame", ["SIGHUP", "SIGTERM"])
def test_a_backup_ended_by_a_signal_while_it_archives_resumes_the_deployment_and_removes_itself(tmp_path, signame):
    """Python's default action for SIGHUP (an SSH session that drops) and SIGTERM (kill, timeout, a service stop) ends
    the process without the `finally` that resumes the deployment, which a paused container's restart policy and
    health check never notice."""
    sig = getattr(signal, signame)

    def steps(proc, root):
        _wait_line(root, "archiving ", proc)
        proc.send_signal(sig)

    code, compose, said, root = _run_child(tmp_path, "archive", steps)
    assert compose == ["pause vault", "pause vault-db", "unpause vault vault-db"], said
    assert code == 128 + sig, said
    assert _bundles(root) == [], "the incomplete backup holds a copy of .env"
    assert ("The backup was stopped (%s) before it was complete: the deployment was resumed, and the incomplete "
            "backup was removed." % signame) in said


@posix_only
def test_a_signal_while_the_database_is_being_paused_waits_for_the_pause_then_resumes_both(tmp_path):
    """A pause cut short by the signal could take effect with its service out of the list the resume reads."""

    def steps(proc, root):
        _wait_line(root, "pausing vault-db", proc)
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        (root / "go").write_text("", encoding="utf-8")

    code, compose, said, root = _run_child(tmp_path, "pausing", steps)
    assert compose == ["pause vault", "pause vault-db", "unpause vault vault-db"], said
    assert code == 128 + signal.SIGTERM, said
    assert _bundles(root) == []


@posix_only
def test_a_second_signal_does_not_cut_the_resume_short(tmp_path):
    def steps(proc, root):
        _wait_line(root, "archiving ", proc)
        proc.send_signal(signal.SIGTERM)
        _wait_line(root, "unpausing", proc)
        proc.send_signal(signal.SIGHUP)
        proc.send_signal(signal.SIGTERM)
        time.sleep(0.5)
        (root / "go").write_text("", encoding="utf-8")

    code, compose, said, root = _run_child(tmp_path, "resume", steps)
    assert compose == ["pause vault", "pause vault-db", "unpause vault vault-db"], said
    assert code == 128 + signal.SIGTERM, said
    assert _bundles(root) == []


@posix_only
def test_a_backup_run_with_hangups_ignored_goes_on_when_its_terminal_closes(tmp_path):
    """nohup sets SIGHUP to be ignored: that run must not end on it."""

    def steps(proc, root):
        _wait_line(root, "archiving ", proc)
        proc.send_signal(signal.SIGHUP)
        time.sleep(0.5)
        (root / "go-archive").write_text("", encoding="utf-8")

    code, compose, said, root = _run_child(tmp_path, "nohup", steps)
    assert code == 0, said
    assert compose == ["pause vault", "pause vault-db", "unpause vault vault-db"]
    assert [b.name for b in _bundles(root) if (b / "manifest.json").is_file()] == [b.name for b in _bundles(root)]
    assert len(_bundles(root)) == 1


# --------------------------------------------------------------------------- the guard, in process (every platform)

@pytest.fixture
def _default_actions():
    """Each of RUN_ENDING_SIGNALS this platform has at its default action for the test, put back after it."""
    saved = {}
    for name in dv.RUN_ENDING_SIGNALS:
        signum = getattr(signal, name, None)
        if signum is not None:
            saved[signum] = signal.signal(signum, signal.SIG_DFL)
    yield sorted(saved)
    for signum, previous in saved.items():
        signal.signal(signum, previous if previous is not None else signal.SIG_DFL)


def test_inside_the_guard_each_signal_that_ends_the_process_raises_and_after_it_each_is_as_before(_default_actions):
    """SIGHUP and SIGTERM on POSIX; SIGTERM and Ctrl-Break (SIGBREAK) on Windows."""
    sigs = _default_actions
    assert signal.SIGTERM in sigs
    assert (signal.SIGBREAK in sigs) if os.name == "nt" else (signal.SIGHUP in sigs)
    for signum in sigs:
        with dv.SignalsEndTheRun():
            handler = signal.getsignal(signum)
            assert callable(handler)
            with pytest.raises(dv.StoppedBySignal) as stopped:
                handler(signum, None)
        assert stopped.value.signum == signum and stopped.value.code == 128 + signum
        assert isinstance(stopped.value, SystemExit)
    assert all(signal.getsignal(s) is signal.SIG_DFL for s in sigs)


@pytest.mark.skipif(not hasattr(signal, "SIGHUP"), reason="POSIX: nohup ignores SIGHUP")
def test_a_signal_the_run_ignores_stays_ignored(_default_actions):
    signal.signal(signal.SIGHUP, signal.SIG_IGN)
    with dv.SignalsEndTheRun():
        assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN
    assert signal.getsignal(signal.SIGHUP) is signal.SIG_IGN


def test_a_signal_while_the_guard_holds_is_raised_when_the_stretch_or_the_block_ends(_default_actions):
    with dv.SignalsEndTheRun() as guard:
        guard.hold()
        signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)       # noted, not raised
        with pytest.raises(dv.StoppedBySignal) as stopped:
            guard.release()
    assert stopped.value.signum == signal.SIGTERM
    reached = []
    with pytest.raises(dv.StoppedBySignal):
        with dv.SignalsEndTheRun() as guard:
            guard.hold()
            signal.getsignal(signal.SIGTERM)(signal.SIGTERM, None)
            reached.append(True)
    assert reached == [True]
    with dv.SignalsEndTheRun() as guard:
        guard.hold()
        guard.release()                                               # nothing came: nothing raised


# --------------------------------------------------------------------------- pauses cut short, and the menu

def _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: False):
    cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-sc", deployment_id="sc")
    (tmp_path / ".env").write_text("\n".join(dv.build_env_lines(cfg)) + "\n", encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    monkeypatch.setattr(dv, "volume_exists", lambda name, **k: not name.endswith("_vault_brand"))
    monkeypatch.setattr(dv, "container_running", lambda name, **k: name in ("vault", "vault-db"))
    monkeypatch.setattr(dv, "container_paused", lambda name, **k: paused_now(name))
    monkeypatch.setattr(dv, "tighten_secret_file", lambda path: True)
    monkeypatch.setattr(dv, "tar_volume", lambda vol, bundle, archive, **k: _tgz(Path(bundle) / archive) and True)
    monkeypatch.setattr(tool, "_run_dc", run_dc)
    return tool, argparse.Namespace(non_interactive=True, backup_dir=str(tmp_path / "backups"))


class _Result(object):
    def __init__(self, code=0):
        self.returncode, self.stdout, self.stderr = code, "", ""


def test_a_ctrl_c_while_the_database_is_being_paused_resumes_it_on_its_own(tmp_path, monkeypatch, capsys):
    """Ctrl-C cut the database's pause short: it may have taken effect. It is resumed on its own (Docker refuses to
    resume a container that never paused), after the app."""
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if " ".join(a) == "pause vault-db":
            raise KeyboardInterrupt
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc)
    with pytest.raises(KeyboardInterrupt):
        tool._do_backup(tool._load_env(), args)
    assert calls == ["pause vault", "pause vault-db", "unpause vault", "unpause vault-db"]
    assert list((tmp_path / "backups").iterdir()) == []
    said = " ".join(capsys.readouterr().out.split())
    assert ("The backup was stopped (Ctrl-C) before it was complete: the deployment was resumed, and the incomplete "
            "backup was removed.") in said


def test_a_pause_that_timed_out_is_resumed_on_its_own_and_named_when_it_stays_paused(tmp_path, monkeypatch, capsys):
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if " ".join(a) == "pause vault-db":
            raise subprocess.TimeoutExpired(a, 60)
        if a == ("unpause", "vault-db"):
            return _Result(1)
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: name == "vault-db")
    with pytest.raises(SystemExit) as failed:
        tool._do_backup(tool._load_env(), args)
    assert not isinstance(failed.value, dv.StoppedBySignal) and failed.value.code == 1
    assert calls == ["pause vault", "pause vault-db", "unpause vault", "unpause vault-db"]
    said = " ".join(capsys.readouterr().out.split())
    assert "could not pause vault-db for the backup" in said
    assert "the deployment could not be resumed after the backup: run docker unpause vault-db" in said
    assert list((tmp_path / "backups").iterdir()) == []


def test_the_menu_ends_on_a_signal_instead_of_going_back_to_its_list(tmp_path, monkeypatch):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    choice = str([key for key, _label in dv.MENU].index("backup") + 1)
    answers = iter([choice, "q"])
    monkeypatch.setattr("builtins.input", lambda *a, **k: next(answers))

    def backup(*a, **k):
        raise dv.StoppedBySignal(signal.SIGTERM)

    monkeypatch.setattr(tool, "backup", backup)
    with pytest.raises(dv.StoppedBySignal):
        tool.run_menu()
