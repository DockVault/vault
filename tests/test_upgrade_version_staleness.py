"""What the host tool believes it is running after an upgrade, and what it actually is.

`dockvault.py update` has two paths to the same destination. The from-source path runs
`git checkout <tag>`, which brings the tracked `VERSION` file along with it. The pull path -- the
default, and the one an operator without a build toolchain uses -- repoints `DOCKVAULT_IMAGE` at the
published release and recreates from it, and never touches `VERSION`. The container is correct
either way: its version is baked in at build time. The host checkout is only correct on one of them.

That is not merely a cosmetic wrong number in a banner. `VERSION` is the sole input to the tool's
idea of "current", and "current" is what decides whether the next version change is announced as a
DOWNGRADE. Upgrade by pull, and the step back that follows is announced as an ordinary version
change, because the comparison is against a version that stopped being true one upgrade ago -- and
the version printed beside it is that stale one, so nothing on screen contradicts it.

To be exact about what is and is not lost: the "no down-migrations, back up first" warning is
printed unconditionally on every path, so it still appears. What the stale comparison suppresses is
the DOWNGRADE label that tells an operator the warning is about THEM this time, and the red it is
printed in. The generic caution survives; the specific one does not.

WHAT CHANGED SINCE THESE WERE WRITTEN. The pull path still does not rewrite `VERSION`, and that is
now harmless: the tool asks the RUNNING CONTAINER what it is and only falls back to the file when
nothing is running to ask. So the consequence described above -- an operator being told the wrong
current version, and a step backwards announced as an ordinary change -- no longer happens on a
live deployment.

And with nothing running, the tool no longer falls back to the file alone: it takes the highest of
the stopped container's own version file, the release `.env` pins in `DOCKVAULT_IMAGE` (which the
pull path does rewrite) and the file. After a pull upgrade that is the version the pull went to, so
a step back is announced as the DOWNGRADE it is, and gated as one from a guessed origin.

These tests run with nothing running, so they exercise the fallback, and that is deliberate. They
pin that the file really is stale after a pull upgrade (so it is one input to the guess and not a
source of truth), and that the guess sees past it. A live deployment reading its version from the
container is asserted separately, in the upgrade-gate tests.

Nothing here touches Docker or the network: the update paths are driven with their compose and
health calls stubbed, so what runs is the tool's real decision-making.
"""

from __future__ import annotations

import argparse
import importlib.util
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.characterization]

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("dockvault_mod_upg", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    """No host ACL changes, no Docker, no network -- the decisions under test need none of them."""
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _path: True)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    monkeypatch.setattr(dv, "fetch_release_tags", lambda *a, **k: [])


def _deployment(tmp_path, version, image=""):
    """A deployment root: a VERSION file and an .env, as the tool expects to find them."""
    (tmp_path / "VERSION").write_text(version + "\n", encoding="utf-8")
    (tmp_path / ".env").write_text(
        "COMPOSE_PROFILES=combined\nDOCKVAULT_IMAGE=%s\n" % image, encoding="utf-8")
    return dv.DockVault(dv.Palette(False), root=str(tmp_path))


def _stub_the_engine(monkeypatch, tool):
    """Let the update run reach its end without Docker. Everything the tool DECIDES stays real."""
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: argparse.Namespace(
        returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    # Recorded rather than performed. A downgrade now requires a backup, so these runs would
    # otherwise write real bundles into the deployment root for tests that are about what the tool
    # SAYS -- and two updates inside one second collide on the timestamped bundle name.
    tool.backups_taken = []
    monkeypatch.setattr(tool, "_do_backup", lambda env, args: tool.backups_taken.append(True))


def _update(tool, tag, source=False):
    tool.update(argparse.Namespace(
        tag=tag, source=source, yes=True, non_interactive=True))


def test_the_pull_path_moves_the_image_and_leaves_version_behind(tmp_path, monkeypatch):
    """The divergence itself, from a real run of the default update path.

    The image reference is the thing that decides what actually runs, and it moves. `VERSION` is the
    thing the tool reads to say what is running, and it does not.
    """
    tool = _deployment(tmp_path, "0.9.0", image=dv.LOCAL_IMAGE)
    _stub_the_engine(monkeypatch, tool)

    _update(tool, "v0.10.0")

    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == "%s:v0.10.0" % dv.GHCR_IMAGE, (
        "the upgrade did not happen, so nothing below is about staleness")

    assert (tmp_path / "VERSION").read_text(encoding="utf-8").strip() == "0.9.0", (
        "the pull path now maintains VERSION; this characterization is obsolete and the tests "
        "below should become assertions that the tool's 'current' matches what it is running")
    assert dv.read_version_file(str(tmp_path)) == "0.9.0"


def test_with_nothing_running_a_step_back_after_a_pull_upgrade_is_seen_as_a_downgrade(tmp_path, monkeypatch,
                                                                                       capsys):
    """What the stale file used to cost, and no longer does.

    Two updates in sequence, both through the pull path. The first goes to 0.10.0. The second goes
    to 0.9.5 -- a genuine step backwards from what is running. Compared against the 0.9.0 the file
    still holds, it was announced as an ordinary version change and went ahead. The guess now reads
    the release the first update pinned in .env (0.10.0): the step back is a DOWNGRADE, from a
    guessed origin, to a version that checks nothing of the data itself, so it is refused even when
    forced, with nothing changed.
    """
    tool = _deployment(tmp_path, "0.9.0", image=dv.LOCAL_IMAGE)
    _stub_the_engine(monkeypatch, tool)

    _update(tool, "v0.10.0")
    capsys.readouterr()                      # the first run's output is not what is being read

    with pytest.raises(SystemExit):
        _update(tool, "v0.9.5")
    second = " ".join(capsys.readouterr().out.split())

    assert dv.read_version_file(str(tmp_path)) == "0.9.0", "the file is still stale"
    assert "current version : 0.10.0 (from the release image .env names (nothing is running to ask))" in second
    assert "DOWNGRADE: 0.10.0 -> v0.9.5" in second
    assert "no down-migrations" in second, "the generic caution still prints on every path"
    assert "0.10.0 -> v0.9.5 is a downgrade from a version that could only be guessed" in second
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == "%s:v0.10.0" % dv.GHCR_IMAGE, "nothing was changed"


def test_the_from_source_path_keeps_version_current_because_git_checkout_does(tmp_path, monkeypatch):
    """The other path, for contrast -- recorded so the gap is not mistaken for a wider one.

    `VERSION` is maintained; it is maintained by `git checkout`, which only the from-source path
    runs. Establishing that here is what makes the pull path's silence a divergence between two
    paths rather than a file nobody keeps up to date.
    """
    if shutil.which("git") is None:
        pytest.skip("needs git to exercise the checkout the from-source path performs")

    def git(*args):
        done = subprocess.run(["git"] + list(args), cwd=str(tmp_path),
                              capture_output=True, text=True, timeout=60)
        assert done.returncode == 0, " ".join(args) + ": " + (done.stderr or "")[:200]

    git("init", "-q")
    git("config", "user.email", "test@example.test")
    git("config", "user.name", "test")
    for version in ("0.9.0", "0.10.0"):
        (tmp_path / "VERSION").write_text(version + "\n", encoding="utf-8")
        git("add", "VERSION")
        git("commit", "-qm", version)
        git("tag", "v" + version)
    git("checkout", "-q", "v0.9.0")

    (tmp_path / ".env").write_text(
        "COMPOSE_PROFILES=combined\nDOCKVAULT_IMAGE=%s:v0.9.0\n" % dv.GHCR_IMAGE, encoding="utf-8")
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    _stub_the_engine(monkeypatch, tool)
    assert dv.read_version_file(str(tmp_path)) == "0.9.0"

    _update(tool, "v0.10.0", source=True)

    assert dv.read_version_file(str(tmp_path)) == "0.10.0", (
        "the from-source path no longer leaves VERSION current; this test's premise has changed")
    # And the same run repoints .env away from the release image, so a rebuild cannot be published-
    # image-shaped. Asserted because it is the from-source path's own correctness, and a change
    # there would otherwise be invisible to this file.
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == dv.LOCAL_IMAGE
