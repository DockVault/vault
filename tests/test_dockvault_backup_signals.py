"""A backup that ends while it holds the deployment paused resumes it first (dockvault.py: SignalsEndTheRun,
_do_backup, _pause_for_backup, _resume_after_backup):

- a closed SSH session (SIGHUP), kill or a timeout (SIGTERM) and, on Windows, Ctrl-Break (SIGBREAK) end the process
  without running a single `finally` by default; while the backup holds the deployment paused they become an exit
  that resumes it, removes the incomplete backup and says so, with the status a shell gives a process a signal ended;
- a signal that comes while a pause or the resume is running waits for it, and a second one does not cut the resume
  short; a signal the run ignores (nohup) is left ignored, and every signal's action is put back afterwards;
- a pause cut short (a timeout, Ctrl-C), or one whose docker did not answer 0, may have taken effect: that service is
  resumed on its own;
- a terminal's hangup, systemd's stop and GNU timeout signal the run's whole process group, not the run alone: the
  docker children that pause and resume the deployment run in a session of their own (on Windows a process group of
  their own, with no console), and a resume Docker does not confirm is asked about and tried again, so a closed SSH
  session leaves the deployment running;
- the interactive menu, which goes back to its list after a command's error, ends on a signal.

The signals are real (sent to a child process that runs the backup, to its process group, or through a
pseudo-terminal that is hung up), with Docker stubbed in the child or a stand-in `docker` on PATH; the rest is in
process."""
import argparse
import os
import shlex
import shutil
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


# --------------------------------------------------------------------------- signals to the whole process group

# A stand-in `docker` on PATH, so that the backup's real _run_dc and container_paused run, and each `docker compose
# pause` / `unpause` and `docker inspect` is a process of its own, as it is on a host. A pause takes effect (a file
# paused-<service>) before it answers. The pause of the service named in WAIT_PAUSE, and the first unpause when
# WAIT_UNPAUSE is set, wait for a file named go before they answer (their pid in waiting-pid). An unpause takes
# UNPAUSE_DELAY seconds, then resumes what is paused, answering 1 when one of its services was not. Each call is a
# line in calls.log.
_STUB_DOCKER = r'''#!/bin/sh
S="$STUB_STATE"
if [ "$1" = inspect ]; then
    for name in "$@"; do :; done
    echo "inspect $name" >> "$S/calls.log"
    if [ -e "$S/paused-$name" ]; then echo true; else echo false; fi
    exit 0
fi
[ "$1" = compose ] || exit 0
while [ $# -gt 0 ]; do
    case "$1" in pause|unpause) break;; esac
    shift
done
verb="$1"
shift
echo "$verb $*" >> "$S/calls.log"
wait_go() {
    echo $$ > "$S/waiting-pid"
    n=0
    while [ ! -e "$S/go" ] && [ $n -lt 1200 ]; do sleep 0.05; n=$((n + 1)); done
}
if [ "$verb" = pause ]; then
    for s in "$@"; do : > "$S/paused-$s"; done
    if [ "$*" = "$WAIT_PAUSE" ]; then wait_go; fi
    exit 0
fi
if [ -n "$WAIT_UNPAUSE" ] && [ ! -e "$S/waited" ]; then
    : > "$S/waited"
    wait_go
fi
if [ -n "$UNPAUSE_DELAY" ]; then sleep "$UNPAUSE_DELAY"; fi
rc=0
for s in "$@"; do
    if [ -e "$S/paused-$s" ]; then rm -f "$S/paused-$s"; else rc=1; fi
done
exit $rc
'''

# The child for the stand-in: the real _do_backup with only the volumes, the archive and which containers run
# stubbed. In mode "archive" each archive waits for a file named go-archive in the stand-in's folder.
_CHILD_WITH_DOCKER = textwrap.dedent('''
    import argparse, importlib.util, io, os, signal, sys, tarfile, time
    root, dv_path, mode = sys.argv[1], sys.argv[2], sys.argv[3]
    spec = importlib.util.spec_from_file_location("dockvault_backup_group_child", dv_path)
    dv = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(dv)
    state = os.environ["STUB_STATE"]

    def note(line):
        with open(os.path.join(state, "calls.log"), "a", encoding="utf-8") as f:
            f.write(line + "\\n")

    def tar(vol, bundle, archive, **k):
        note("archiving " + vol)
        if mode == "archive":
            for _ in range(1200):
                if os.path.exists(os.path.join(state, "go-archive")):
                    break
                time.sleep(0.05)
        with tarfile.open(os.path.join(bundle, archive), "w:gz") as t:
            info = tarfile.TarInfo("marker.txt")
            info.size = 1
            t.addfile(info, io.BytesIO(b"x"))
        return True

    # As a run started from a terminal has them (a test run under nohup hands its children SIGHUP ignored).
    signal.signal(signal.SIGHUP, signal.SIG_DFL)
    signal.signal(signal.SIGTERM, signal.SIG_DFL)
    dv.volume_exists = lambda name, **k: not name.endswith("_vault_brand")
    dv.container_running = lambda name, **k: name in ("vault", "vault-db")
    dv.tighten_secret_file = lambda path: True
    dv.tar_volume = tar
    tool = dv.DockVault(dv.Palette(False), root=root)
    try:
        tool._do_backup(tool._load_env(), argparse.Namespace(non_interactive=True,
                                                             backup_dir=os.path.join(root, "backups")))
    except BaseException as exc:
        note("ended %s" % getattr(exc, "code", type(exc).__name__))
        raise
    note("ended 0")
''')


class _WithDocker(object):
    """A deployment folder, the stand-in `docker` first on PATH, and the child that backs it up."""

    def __init__(self, tmp_path, mode, **stub_env):
        self.tmp, self.mode = tmp_path, mode
        self.root, self.state, bin_dir = tmp_path / "deploy", tmp_path / "docker-state", tmp_path / "bin"
        for folder in (self.root, self.state, bin_dir):
            folder.mkdir()
        stub = bin_dir / "docker"
        stub.write_text(_STUB_DOCKER, encoding="utf-8")
        stub.chmod(0o755)
        cfg = dict(_reusable_env_cfg(), volume_prefix="dockvault-vault-sp", deployment_id="sp")
        (self.root / ".env").write_text("\n".join(dv.build_env_lines(cfg)) + "\n", encoding="utf-8")
        self.script = tmp_path / "child.py"
        self.script.write_text(_CHILD_WITH_DOCKER, encoding="utf-8")
        self.env = dict(os.environ, PATH=str(bin_dir) + os.pathsep + os.environ.get("PATH", ""),
                        STUB_STATE=str(self.state), **stub_env)
        for name in ("XDG_DATA_HOME", "LOCALAPPDATA", "APPDATA"):
            self.env[name] = str(tmp_path / "app-data")

    def argv(self):
        return [sys.executable, str(self.script), str(self.root), str(ROOT / "dockvault.py"), self.mode]

    def let_go(self):
        for name in ("go", "go-archive"):
            (self.state / name).write_text("", encoding="utf-8")

    def stand_in_pid(self):
        """The pid of the stand-in that waits for the file named go, once it waits."""
        path = self.state / "waiting-pid"
        for _ in range(400):
            words = path.read_text(encoding="utf-8").split() if path.exists() else []
            if words and words[0].isdigit():
                return int(words[0])
            time.sleep(0.05)
        pytest.fail("no stand-in waited: %s" % self.calls())

    def run(self, steps):
        """Start the child in a process group of its own, so that a signal to its group reaches it and its docker
        children and nothing else; let `steps(proc)` drive it; return its exit status."""
        with open(self.tmp / "out.txt", "w", encoding="utf-8") as out:
            proc = subprocess.Popen(self.argv(), stdout=out, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                                    env=self.env, start_new_session=True)
            try:
                steps(proc)
                proc.wait(timeout=90)
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGKILL)
                    proc.wait()
                self.let_go()               # a stand-in still waiting (in a session of its own) ends too
        return proc.returncode

    def said(self):
        path = self.tmp / "out.txt"
        return " ".join(path.read_text(encoding="utf-8").split()) if path.exists() else ""

    def calls(self):
        return _calls(self.state)

    def compose(self):
        return [c for c in self.calls() if c.startswith(("pause ", "unpause "))]

    def still_paused(self):
        return sorted(p.name[len("paused-"):] for p in self.state.iterdir() if p.name.startswith("paused-"))


_RESUMED = ("The backup was stopped (%s) before it was complete: the deployment was resumed, and the incomplete "
            "backup was removed.")


@posix_only
@pytest.mark.parametrize("signame", ["SIGTERM", "SIGHUP"])
def test_a_signal_to_the_runs_process_group_while_the_database_is_being_paused_leaves_nothing_paused(tmp_path,
                                                                                                    signame):
    """A hangup, systemd's stop and GNU timeout signal the whole process group: a `docker compose pause` in that group
    was ended with it, its pause taken all the same, and the database was never resumed while the tool said it was.
    The pause runs in a session of its own, answers, and both services are resumed together."""
    sig = getattr(signal, signame)
    host = _WithDocker(tmp_path, "pausing", WAIT_PAUSE="vault-db")

    def steps(proc):
        host.stand_in_pid()                     # the database's pause has taken effect, and not answered
        os.killpg(proc.pid, sig)
        time.sleep(0.5)
        (host.state / "go").write_text("", encoding="utf-8")

    code = host.run(steps)
    assert host.still_paused() == [], host.said()
    assert host.compose() == ["pause vault", "pause vault-db", "unpause vault vault-db"], host.said()
    assert code == 128 + sig, host.said()
    assert _bundles(host.root) == []
    assert _RESUMED % signame in host.said()


@posix_only
def test_a_second_signal_to_the_runs_process_group_does_not_end_the_resume(tmp_path):
    """A terminal's hangup comes twice (the shell passes its SIGHUP on to its jobs, then the terminal sends its own):
    the second one ended the `docker compose unpause` the first one started."""
    host = _WithDocker(tmp_path, "archive", WAIT_UNPAUSE="1")

    def steps(proc):
        _wait_line(host.state, "archiving ", proc)
        os.killpg(proc.pid, signal.SIGHUP)
        host.stand_in_pid()                     # the resume's docker runs
        os.killpg(proc.pid, signal.SIGHUP)
        os.killpg(proc.pid, signal.SIGTERM)
        time.sleep(0.5)
        (host.state / "go").write_text("", encoding="utf-8")

    code = host.run(steps)
    assert host.still_paused() == [], host.said()
    assert host.compose() == ["pause vault", "pause vault-db", "unpause vault vault-db"], host.said()
    assert code == 128 + signal.SIGHUP, host.said()
    assert _bundles(host.root) == []
    assert _RESUMED % "SIGHUP" in host.said()


@posix_only
def test_a_first_signal_while_a_finished_backup_resumes_the_deployment_waits_for_the_resume(tmp_path):
    """Every archive written, the deployment is being resumed when the signal comes: the resume runs held, so the
    signal does not cut it short (which would end its docker child with it), and ends the run once it has answered."""
    host = _WithDocker(tmp_path, "resume", WAIT_UNPAUSE="1")

    def steps(proc):
        host.stand_in_pid()                     # the resume's docker runs
        os.killpg(proc.pid, signal.SIGTERM)
        time.sleep(0.5)
        (host.state / "go").write_text("", encoding="utf-8")

    code = host.run(steps)
    assert host.still_paused() == [], host.said()
    assert host.compose() == ["pause vault", "pause vault-db", "unpause vault vault-db"], host.said()
    assert code == 128 + signal.SIGTERM, host.said()
    assert _bundles(host.root) == []
    assert _RESUMED % "SIGTERM" in host.said()


@posix_only
def test_a_stop_that_signals_every_process_while_the_database_is_being_paused_resumes_it(tmp_path):
    """systemd's stop signals every process of the service, whatever its session: the pause's docker is ended after
    its pause took effect, and does not answer 0. A pause that did not answer 0 is resumed on its own."""
    host = _WithDocker(tmp_path, "pausing", WAIT_PAUSE="vault-db")

    def steps(proc):
        stand_in = host.stand_in_pid()
        os.kill(proc.pid, signal.SIGTERM)
        os.kill(stand_in, signal.SIGTERM)

    code = host.run(steps)
    assert host.still_paused() == [], host.said()
    assert host.compose() == ["pause vault", "pause vault-db", "unpause vault", "unpause vault-db"], host.said()
    assert code == 128 + signal.SIGTERM, host.said()
    assert _RESUMED % "SIGTERM" in host.said()


@posix_only
def test_a_stop_that_signals_every_process_while_the_deployment_is_resumed_has_it_resumed_again(tmp_path):
    """The resume's docker is ended before it resumed anything: Docker is asked what is still paused, and that is
    resumed again."""
    host = _WithDocker(tmp_path, "archive", WAIT_UNPAUSE="1")

    def steps(proc):
        _wait_line(host.state, "archiving ", proc)
        os.kill(proc.pid, signal.SIGTERM)
        stand_in = host.stand_in_pid()
        os.kill(proc.pid, signal.SIGTERM)
        os.kill(stand_in, signal.SIGTERM)

    code = host.run(steps)
    assert host.still_paused() == [], host.said()
    assert host.compose() == ["pause vault", "pause vault-db", "unpause vault vault-db", "unpause vault",
                              "unpause vault-db"], host.said()
    assert code == 128 + signal.SIGTERM, host.said()
    assert _RESUMED % "SIGTERM" in host.said()


# The hangup of an SSH session: an interactive bash on a pseudo-terminal runs the backup, and the terminal's other
# side is closed, as sshd closes it when the connection drops. The kernel and the shell then send SIGHUP to the
# backup's process group, within moments of each other.
_HANGUP_DRIVER = textwrap.dedent('''
    import os, pty, select, signal, sys, time
    state, command = sys.argv[1], sys.argv[2]
    log = os.path.join(state, "calls.log")
    signal.signal(signal.SIGHUP, signal.SIG_DFL)        # as a terminal's session has it

    def seen(text):
        try:
            with open(log, encoding="utf-8") as f:
                return text in f.read()
        except OSError:
            return False

    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", "--norc", "--noprofile", "-i"])
    os.write(fd, (command + "\\n").encode())
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not seen("archiving "):
        ready, _, _ = select.select([fd], [], [], 0.05)
        if ready:
            try:
                os.read(fd, 65536)
            except OSError:
                break
    time.sleep(0.3)
    os.close(fd)                                         # the hangup
    deadline = time.monotonic() + 60
    while time.monotonic() < deadline and not seen("ended "):
        time.sleep(0.05)
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
''')


@pytest.mark.skipif(not sys.platform.startswith("linux") or not shutil.which("bash"),
                    reason="a pseudo-terminal hung up under an interactive bash, as on a Linux host")
@pytest.mark.parametrize("output, attempt", [("terminal", 1), ("terminal", 2), ("file", 1), ("file", 2)])
def test_a_closed_ssh_session_leaves_the_deployment_running(tmp_path, output, attempt):
    """The run's output on the terminal that is gone, or in a file. Before the backup's docker children ran apart from
    its process group, and a resume Docker did not confirm was tried again, most hangups left both services paused."""
    host = _WithDocker(tmp_path, "archive", UNPAUSE_DELAY="0.05", HISTFILE=str(tmp_path / "history"))
    command = " ".join(shlex.quote(word) for word in host.argv())
    if output == "file":
        command += " > %s 2>&1" % shlex.quote(str(tmp_path / "out.txt"))
    driver = tmp_path / "hangup.py"
    driver.write_text(_HANGUP_DRIVER, encoding="utf-8")
    try:
        subprocess.run([sys.executable, str(driver), str(host.state), command], env=host.env,
                       stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=150,
                       start_new_session=True)
    finally:
        host.let_go()
    ended = [line for line in host.calls() if line.startswith("ended ")]
    assert ended == ["ended %d" % (128 + signal.SIGHUP)], host.calls()
    assert host.still_paused() == [], host.calls()
    # The first unpause is often ended before it runs (started in the moment the second SIGHUP comes): the tries
    # again resume the deployment.
    compose = host.compose()
    assert compose[:2] == ["pause vault", "pause vault-db"] and compose[2:], host.calls()
    assert all(call.startswith("unpause ") for call in compose[2:]), host.calls()
    assert _bundles(host.root) == []
    if output == "file":
        assert _RESUMED % "SIGHUP" in host.said()


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
    monkeypatch.setattr(dv, "RESUME_RETRY_GAP", 0)
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
    assert calls == (["pause vault", "pause vault-db", "unpause vault", "unpause vault-db"]
                     + ["unpause vault-db"] * dv.RESUME_RETRIES)
    said = " ".join(capsys.readouterr().out.split())
    assert "could not pause vault-db for the backup" in said
    assert "the deployment could not be resumed after the backup: run docker unpause vault-db" in said
    assert list((tmp_path / "backups").iterdir()) == []


def test_a_cut_short_pause_docker_then_cannot_tell_about_is_named_as_not_resumed(tmp_path, monkeypatch, capsys):
    """Docker does not answer whether the database is paused after its pause was cut short: it may be, so it is
    named, never counted as running."""
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if " ".join(a) == "pause vault-db":
            raise subprocess.TimeoutExpired(a, 60)
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: None if name == "vault-db" else
                             False)
    with pytest.raises(SystemExit) as failed:
        tool._do_backup(tool._load_env(), args)
    assert failed.value.code == 1
    assert calls == (["pause vault", "pause vault-db", "unpause vault", "unpause vault-db"]
                     + ["unpause vault-db"] * dv.RESUME_RETRIES)
    said = " ".join(capsys.readouterr().out.split())
    assert "the deployment could not be resumed after the backup: run docker unpause vault-db" in said


def test_a_resume_docker_did_not_confirm_is_asked_about_and_tried_again(tmp_path, monkeypatch, capsys):
    """The resume's docker child can be ended by the signal that ends the run (one started in the very moment it
    comes; any one under systemd's stop): Docker is asked what is still paused, and that is resumed again. The
    backup here goes on to the end."""
    state = {"vault": False, "vault-db": False}
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if a == ("unpause", "vault", "vault-db"):
            return _Result(-15)                 # ended by a signal before it resumed anything
        for service in a[1:]:
            state[service] = a[0] == "pause"
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: state[name])
    monkeypatch.setattr(dv, "RESUME_RETRY_GAP", 0.25)
    slept = []
    monkeypatch.setattr(time, "sleep", slept.append)
    tool._do_backup(tool._load_env(), args)
    assert calls == ["pause vault", "pause vault-db", "unpause vault vault-db", "unpause vault", "unpause vault-db"]
    assert slept == [0.25], "a moment apart: a hangup's signals come in a burst"
    assert state == {"vault": False, "vault-db": False}
    said = " ".join(capsys.readouterr().out.split())
    assert "WARNING" not in said and "Backup written to" in said


def test_a_pause_whose_docker_could_not_be_started_is_not_resumed(tmp_path, monkeypatch, capsys):
    """No docker ran, so nothing can have paused: nothing to resume, and nothing named as maybe paused."""
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if " ".join(a) == "pause vault-db":
            raise FileNotFoundError("docker")
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: None)
    with pytest.raises(SystemExit):
        tool._do_backup(tool._load_env(), args)
    assert calls == ["pause vault", "pause vault-db", "unpause vault"]
    said = " ".join(capsys.readouterr().out.split())
    assert "could not pause vault-db for the backup" in said and "could not be resumed" not in said


def test_a_service_docker_says_runs_is_not_resumed_again(tmp_path, monkeypatch, capsys):
    """Asked again, Docker says the app runs (the first try did resume it, and answered otherwise): only what is still
    paused is tried again."""
    state = {"vault": False, "vault-db": False}
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if a == ("unpause", "vault", "vault-db"):
            state["vault"] = False              # resumed the app, not the database, and answered 1
            return _Result(1)
        for service in a[1:]:
            state[service] = a[0] == "pause"
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: state[name])
    tool._do_backup(tool._load_env(), args)
    assert calls == ["pause vault", "pause vault-db", "unpause vault vault-db", "unpause vault-db"]
    assert state == {"vault": False, "vault-db": False}
    assert "WARNING" not in capsys.readouterr().out


def test_a_docker_that_does_not_answer_in_time_is_not_asked_again_and_again(tmp_path, monkeypatch, capsys):
    """The tries again stop once RESUME_RETRY_SECONDS have passed since the first: a resume whose unpause waited out
    its whole timeout is named at once."""
    calls = []

    def run_dc(*a, **k):
        calls.append(" ".join(a))
        if a[0] == "unpause":
            raise subprocess.TimeoutExpired(a, 60)
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: True)
    monkeypatch.setattr(dv, "RESUME_RETRY_SECONDS", -1)
    tool._do_backup(tool._load_env(), args)            # the archives are of one moment: the backup stands
    assert calls == ["pause vault", "pause vault-db", "unpause vault vault-db"]
    said = " ".join(capsys.readouterr().out.split())
    assert "the deployment could not be resumed after the backup: run docker unpause vault vault-db" in said
    assert "Backup written to" in said


@pytest.mark.parametrize("what_fails", ["the-resume", "the-database-pause"])
def test_each_docker_child_of_the_pause_and_the_resume_runs_out_of_reach_of_the_runs_signals(tmp_path, monkeypatch,
                                                                                            what_fails):
    """The pause, the resume, each try again, the resume of a pause that did not answer 0, and Docker's answer about a
    paused container (own_session_kwargs)."""
    container_paused = dv.container_paused
    marked, unmarked = [], []
    state = {"vault": False, "vault-db": False}

    def run_dc(*a, **k):
        (marked if k.get("own") == "session" else unmarked).append(" ".join(a))
        if what_fails == "the-resume" and a[0] == "unpause" and len(a) > 2:
            return _Result(1)
        if what_fails == "the-database-pause" and " ".join(a) == "pause vault-db":
            return _Result(1)
        for service in a[1:]:
            state[service] = a[0] == "pause"
        return _Result()

    tool, args = _backing_up(tmp_path, monkeypatch, run_dc, paused_now=lambda name: state[name])
    monkeypatch.setattr(dv, "own_session_kwargs", lambda: {"own": "session"})
    if what_fails == "the-resume":
        tool._do_backup(tool._load_env(), args)
        assert marked == ["pause vault", "pause vault-db", "unpause vault vault-db", "unpause vault",
                          "unpause vault-db"]
    else:
        with pytest.raises(SystemExit):
            tool._do_backup(tool._load_env(), args)
        assert marked == ["pause vault", "pause vault-db", "unpause vault", "unpause vault-db"]
    assert unmarked == []
    seen = []
    container_paused("vault-db", run=lambda argv, **k: seen.append(k) or _Result())
    assert len(seen) == 1 and seen[0]["own"] == "session" and seen[0]["stdin"] is subprocess.DEVNULL


def test_a_docker_child_gets_a_session_of_its_own_on_posix_and_on_windows_a_group_without_the_console(monkeypatch):
    """On Windows: a process group of its own (CREATE_NEW_PROCESS_GROUP) and no console (CREATE_NO_WINDOW): Ctrl-Break
    typed at the console reaches every process attached to it, whatever its group."""
    with monkeypatch.context() as m:
        m.setattr(dv.os, "name", "nt")
        windows = dv.own_session_kwargs()
    with monkeypatch.context() as m:
        m.setattr(dv.os, "name", "posix")
        posix = dv.own_session_kwargs()
    assert windows == {"creationflags": 0x00000200 | 0x08000000}
    assert posix == {"start_new_session": True}


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
