"""What `dockvault.py update` knows about a change before it makes it.

Three things used to be missing, and they compound. The tool read the version from the checkout's
`VERSION`, which the pull path never rewrites -- so after one pull upgrade it reported the version
it was installed at, and every later hop was computed from a wrong origin. It had no idea what a
change involved. And "BACK UP FIRST" was a printed sentence, not a gate.

Now the running container is asked what it is, the hop is resolved against the upgrade matrix and
described, and a change that needs a backup does not proceed without one.

The update paths run for real here with only their compose, backup and health calls stubbed, so
what is exercised is the tool's own decision-making. Nothing writes outside pytest's tmp_path.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_spec = importlib.util.spec_from_file_location("dockvault_gate", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)


def _matrix(*, backup=False, reversible=True, kind="direct", conditions=None):
    """Two adjacent releases with one edge between them, shaped as the real file is."""
    edge = {"from": "0.1.0", "to": "0.2.0", "kind": kind,
            "reversible": reversible, "requires_backup": backup}
    if kind == "blocked":
        edge["reason"] = "0.2.0 rewrites something 0.1.0 still writes"
    if conditions:
        edge["conditions"] = conditions
    return {
        "schema_version": 1, "about": "test", "kinds": {"direct": "a", "blocked": "b"},
        "versions": {"0.1.0": {"released": "2026-01-01", "notes": "a"},
                     "0.2.0": {"released": "2026-01-02", "notes": "b"}},
        "edges": [edge],
    }


# --- resolving a hop --------------------------------------------------------------------------

def test_a_described_hop_reports_what_it_involves():
    plan = dv.plan_upgrade_path(_matrix(backup=True, reversible=False), "0.1.0", "0.2.0")
    assert plan["known"] and plan["requires_backup"] and plan["irreversible"]
    assert len(plan["steps"]) == 1


def test_a_multi_release_hop_is_composed_from_the_adjacent_edges():
    """The matrix declares neighbours only, so a longer upgrade is a walk over them.

    Any step needing a backup makes the whole walk need one; the operator takes one journey, not
    one per edge.
    """
    matrix = _matrix()
    matrix["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "c"}
    matrix["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                            "reversible": False, "requires_backup": True})
    plan = dv.plan_upgrade_path(matrix, "0.1.0", "0.3.0")
    assert plan["known"] and len(plan["steps"]) == 2
    assert plan["requires_backup"] and plan["irreversible"]


@pytest.mark.parametrize("current, target", [
    ("0.1.0", "9.9.9"),      # target not declared
    ("9.9.9", "0.2.0"),      # current not declared
    ("0.2.0", "0.1.0"),      # a downgrade: the matrix describes forward edges only
])
def test_an_undescribed_hop_is_not_assumed_safe(current, target):
    """Unknown resolves to "needs a backup, may be irreversible", never to "fine".

    A default of safe would make every gap in the matrix a silent hole, and the gaps are exactly
    where nobody has thought about the upgrade.
    """
    plan = dv.plan_upgrade_path(_matrix(), current, target)
    assert not plan["known"]
    assert plan["requires_backup"] and plan["irreversible"]


def test_a_hop_with_a_missing_intermediate_edge_is_unknown():
    """Non-vacuity for the walk: a gap between neighbours is not silently stepped over."""
    matrix = _matrix()
    matrix["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "c"}
    assert not dv.plan_upgrade_path(matrix, "0.1.0", "0.3.0")["known"]


def test_a_malformed_matrix_is_unknown_rather_than_an_exception():
    for junk in (None, [], "matrix", {"versions": "no"}, {"versions": {"x": {}}, "edges": []}):
        plan = dv.plan_upgrade_path(junk, "0.1.0", "0.2.0")
        assert not plan["known"] and plan["requires_backup"]


# --- where the description comes from -----------------------------------------------------------

def test_the_published_matrix_is_preferred_over_this_checkout(tmp_path):
    """The checkout can be older than the release being installed, and an older file cannot
    describe a newer hop."""
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "upgrade-matrix.json").write_text(
        json.dumps(_matrix()), encoding="utf-8", newline="")

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        @staticmethod
        def read():
            return json.dumps(_matrix(backup=True)).encode("utf-8")

    matrix, source = dv.fetch_upgrade_matrix(
        "v0.2.0", root=str(tmp_path), opener=lambda url, timeout=0: _Response())
    assert "published" in source
    assert matrix["edges"][0]["requires_backup"] is True


def test_the_local_matrix_is_the_offline_fallback_and_says_so(tmp_path):
    (tmp_path / "docs").mkdir()
    (tmp_path / "docs" / "upgrade-matrix.json").write_text(
        json.dumps(_matrix()), encoding="utf-8", newline="")

    def unreachable(url, timeout=0):
        raise OSError("no network")

    matrix, source = dv.fetch_upgrade_matrix("v0.2.0", root=str(tmp_path), opener=unreachable)
    assert matrix is not None and "predate" in source


def test_with_neither_source_nothing_is_classified(tmp_path):
    def unreachable(url, timeout=0):
        raise OSError("no network")

    matrix, source = dv.fetch_upgrade_matrix("v0.2.0", root=str(tmp_path), opener=unreachable)
    assert matrix is None and "no upgrade matrix" in source
    assert not dv.plan_upgrade_path(matrix, "0.1.0", "0.2.0")["known"]


# --- driving the command --------------------------------------------------------------------

@pytest.fixture(autouse=True)
def _hermetic(monkeypatch):
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    monkeypatch.setattr(dv, "fetch_release_tags", lambda *a, **k: [])


def _deployment(tmp_path, version="0.1.0", matrix=None):
    (tmp_path / "VERSION").write_text(version + "\n", encoding="utf-8", newline="")
    (tmp_path / ".env").write_text(
        "COMPOSE_PROFILES=combined\nDOCKVAULT_IMAGE=%s\n" % dv.LOCAL_IMAGE,
        encoding="utf-8", newline="")
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "upgrade-matrix.json").write_text(
        json.dumps(matrix if matrix is not None else _matrix()), encoding="utf-8", newline="")
    return dv.DockVault(dv.Palette(False), root=str(tmp_path))


def _stub(monkeypatch, tool, *, backups):
    """Stub the engine; record backups instead of taking them."""
    monkeypatch.setattr(dv, "fetch_upgrade_matrix",
                        lambda tag, root=None, opener=None: (
                            json.loads((Path(root) / "docs" / "upgrade-matrix.json").read_text(
                                encoding="utf-8")), "the test matrix"))
    monkeypatch.setattr(tool, "_run_dc", lambda *a, **k: argparse.Namespace(
        returncode=0, stdout="", stderr=""))
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: True)
    monkeypatch.setattr(tool, "_start_secure_stack", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: True)
    monkeypatch.setattr(tool, "_running_version", lambda *a, **k: ("0.1.0", "the running container"))
    monkeypatch.setattr(tool, "_do_backup", lambda env, args: backups.append(True))


def _update(tool, tag="v0.2.0", **kw):
    tool.update(argparse.Namespace(
        tag=tag, source=False, yes=True, non_interactive=True,
        dry_run=kw.get("dry_run", False), backup_verified=kw.get("backup_verified", False)))


def test_a_hop_needing_a_backup_takes_one_before_changing_anything(tmp_path, monkeypatch):
    backups = []
    tool = _deployment(tmp_path, matrix=_matrix(backup=True))
    _stub(monkeypatch, tool, backups=backups)

    _update(tool)

    assert backups, "the change proceeded without a backup"
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"].endswith(":v0.2.0"), "the upgrade did not happen"


def test_a_hop_not_needing_one_does_not_take_a_backup(tmp_path, monkeypatch):
    """Non-vacuity for the test above: the gate is conditional, not always-on.

    An always-on backup would pass that test while making every routine update slow enough that
    operators reach for a flag to skip it.
    """
    backups = []
    tool = _deployment(tmp_path, matrix=_matrix(backup=False))
    _stub(monkeypatch, tool, backups=backups)
    _update(tool)
    assert not backups


def test_backup_verified_skips_taking_one_and_says_it_was_not_checked(tmp_path, monkeypatch, capsys):
    backups = []
    tool = _deployment(tmp_path, matrix=_matrix(backup=True))
    _stub(monkeypatch, tool, backups=backups)

    _update(tool, backup_verified=True)

    assert not backups
    out = capsys.readouterr().out
    assert "has not checked" in out, (
        "the flag must not imply the tool verified anything; it accepted the operator's word")


def test_a_failed_backup_stops_the_change(tmp_path, monkeypatch):
    """The gate has to hold when the backup itself fails, which is when it matters most."""
    tool = _deployment(tmp_path, matrix=_matrix(backup=True))
    _stub(monkeypatch, tool, backups=[])

    def broken(env, args):
        raise RuntimeError("no space left on device")

    monkeypatch.setattr(tool, "_do_backup", broken)
    _update(tool)

    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == dv.LOCAL_IMAGE, (
        "the image was repointed even though the required backup failed")


def test_a_dry_run_changes_nothing(tmp_path, monkeypatch):
    backups = []
    tool = _deployment(tmp_path, matrix=_matrix(backup=True))
    _stub(monkeypatch, tool, backups=backups)

    _update(tool, dry_run=True)

    assert not backups, "a dry run took a backup"
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == dv.LOCAL_IMAGE, "a dry run repointed the image"


def test_a_blocked_hop_refuses(tmp_path, monkeypatch):
    tool = _deployment(tmp_path, matrix=_matrix(kind="blocked"))
    _stub(monkeypatch, tool, backups=[])
    with pytest.raises(SystemExit):
        _update(tool)
    env = dv.parse_env((tmp_path / ".env").read_text(encoding="utf-8"))
    assert env["DOCKVAULT_IMAGE"] == dv.LOCAL_IMAGE


def test_an_undescribed_hop_still_demands_a_backup(tmp_path, monkeypatch, capsys):
    """The fail-safe, end to end: no description means treat it as the worst case."""
    backups = []
    tool = _deployment(tmp_path, matrix=_matrix())
    _stub(monkeypatch, tool, backups=backups)

    _update(tool, tag="v0.9.9")   # not in the matrix at all

    assert backups, "an undescribed change proceeded without a backup"
    assert "NOT DESCRIBED" in capsys.readouterr().out


def test_the_conditions_on_a_hop_are_printed(tmp_path, monkeypatch, capsys):
    """A condition an operator cannot see is the same as one nobody recorded."""
    tool = _deployment(tmp_path, matrix=_matrix(conditions=[{
        "id": "email-case-collision",
        "summary": "Accounts differing only in case keep working, but the index is not created.",
        "detect": "SELECT lower(email) FROM users GROUP BY 1 HAVING count(*) > 1"}]))
    _stub(monkeypatch, tool, backups=[])
    _update(tool, dry_run=True)
    out = capsys.readouterr().out
    assert "differing only in case" in out
    assert "SELECT lower(email)" in out


# --- which version is running -----------------------------------------------------------------

def test_the_running_version_comes_from_the_container(tmp_path, monkeypatch):
    """The defect this fixes: the file describes what was checked out, not what is running."""
    tool = _deployment(tmp_path, version="0.1.0")
    monkeypatch.setattr(dv.subprocess, "run", lambda *a, **k: argparse.Namespace(
        returncode=0, stdout="0.7.3\n", stderr=""))
    version, source = tool._running_version("combined")
    assert version == "0.7.3" and "running container" in source


def test_it_falls_back_to_the_file_and_says_so_when_nothing_is_running(tmp_path, monkeypatch):
    tool = _deployment(tmp_path, version="0.1.0")
    monkeypatch.setattr(dv.subprocess, "run", lambda *a, **k: argparse.Namespace(
        returncode=1, stdout="", stderr="No such container"))
    version, source = tool._running_version("combined")
    assert version == "0.1.0" and "VERSION file" in source


def test_unparseable_output_from_the_container_is_not_believed(tmp_path, monkeypatch):
    """A container that answers with something that is not a version is not a source of truth."""
    tool = _deployment(tmp_path, version="0.1.0")
    monkeypatch.setattr(dv.subprocess, "run", lambda *a, **k: argparse.Namespace(
        returncode=0, stdout="<html>404</html>\n", stderr=""))
    version, source = tool._running_version("combined")
    assert version == "0.1.0" and "VERSION file" in source


# `docker` rather than `integration`: the module is marked unit, and the conftest treats a test
# carrying both unit and integration as a usage error -- which aborts the whole pytest session, not
# just this file. Marked docker, it lands in the docker lane and is deselected from the offline one.
@pytest.mark.docker
def test_the_running_version_is_read_from_a_real_container():
    """The stubs above prove the decision; this proves the transport.

    Asked over `docker exec` rather than HTTP because the endpoint carrying the version sits behind
    whatever port and certificate the deployment chose, and a self-signed certificate on a
    non-default port is the normal case here. A test that mocked the transport would not have
    caught the version file being absent from the image, which is the only way this can fail.
    """
    import os
    import subprocess as sp

    container = os.environ.get("VAULT_API_CONTAINER")
    if not container:
        pytest.skip("VAULT_API_CONTAINER is unset; no deployment to ask")
    probe = sp.run(["docker", "exec", container, "cat", "/app/VERSION"],
                   capture_output=True, text=True, timeout=60)
    if probe.returncode != 0:
        pytest.skip(f"cannot reach {container}")

    reported = probe.stdout.strip()
    assert dv.parse_semver(reported), (
        f"the container's /app/VERSION is {reported!r}, which is not a version. The tool would "
        "silently fall back to the checkout's file, which is the defect this replaced")


def test_a_guessed_origin_is_not_described(tmp_path, monkeypatch, capsys):
    """When the version came from the file rather than the container, the hop is a guess.

    The pull path never rewrites VERSION, and a container being down is the normal state when you
    want to change version -- which is exactly when the fallback is used. Planning from that file
    can find a chain of reversible, no-backup edges while the real operation is a downgrade across
    a database with no down-migrations. Treating an unknown origin as undescribed costs an accurate
    description in the one case the tool cannot be sure, and buys back the gate.
    """
    backups = []
    tool = _deployment(tmp_path, matrix=_matrix(backup=False))
    _stub(monkeypatch, tool, backups=backups)
    monkeypatch.setattr(tool, "_running_version",
                        lambda *a, **k: ("0.1.0", "this checkout's VERSION file (nothing is "
                                                  "running to ask)"))
    _update(tool)

    out = capsys.readouterr().out
    assert "NOT DESCRIBED" in out, out
    assert backups, "a hop planned from a guessed origin proceeded without a backup"


def test_a_backup_that_captured_no_data_is_not_a_backup(tmp_path, monkeypatch):
    """The gate's worst failure would be accepting an empty bundle.

    `_do_backup` skipped a volume that was not found -- right for the optional brand volume, and it
    used to swallow the case where NONE were found, printing success. An .env whose volume prefix
    no longer matches the deployment produces exactly that, with no docker fault involved.
    """
    monkeypatch.setattr(dv, "volume_exists", lambda name: False)
    tool = _deployment(tmp_path, matrix=_matrix(backup=True))
    (tmp_path / ".env").write_text(
        "COMPOSE_PROFILES=combined\nVAULT_VOLUME_PREFIX=nothing_here\n"
        "DOCKVAULT_IMAGE=%s\n" % dv.LOCAL_IMAGE, encoding="utf-8", newline="")

    with pytest.raises(SystemExit):
        tool._do_backup(tool._load_env(), argparse.Namespace(backup_dir=str(tmp_path / "b")))


def _matrix_with_backport():
    """The real shape: 0.9.1 released AFTER 0.10.0, so it sorts between two shipped releases.

    The validator exempts (0.9.1, 0.10.0) from needing an edge, because demanding one would force
    a claim about upgrading from a backport into a release that predates its fix.
    """
    return {
        "schema_version": 1, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
        "versions": {
            "0.9.0": {"released": "2026-01-01", "notes": "a"},
            "0.9.1": {"released": "2026-03-01", "notes": "backport, shipped last"},
            "0.10.0": {"released": "2026-02-01", "notes": "b"},
        },
        "edges": [
            {"from": "0.9.0", "to": "0.10.0", "kind": "direct",
             "reversible": True, "requires_backup": False},
            {"from": "0.9.0", "to": "0.9.1", "kind": "direct",
             "reversible": True, "requires_backup": False},
        ],
    }


def test_a_backport_does_not_make_the_hop_it_sits_between_undescribable():
    """The mismatch this closes: two halves disagreeing about what "adjacent" means.

    Marching through version-order neighbours looked for 0.9.1 -> 0.10.0, found nothing, and
    called 0.9.0 -> 0.10.0 undescribable -- a hop the file describes perfectly well, and one the
    validator deliberately does not require an edge for. Following the declared edges asks the
    file what it says instead of assuming what it should contain.

    It fails safe rather than dangerous, so it is noise rather than risk: the operator is forced
    through a backup and a typed acknowledgement for a drop-in change. Noise is how a gate gets
    switched off.
    """
    matrix = _matrix_with_backport()
    plan = dv.plan_upgrade_path(matrix, "0.9.0", "0.10.0")
    assert plan["known"], "the hop the file declares is still being called undescribable"
    assert len(plan["steps"]) == 1
    assert not plan["requires_backup"] and not plan["irreversible"]


def test_a_route_that_genuinely_does_not_exist_is_still_unknown():
    """Non-vacuity for the above: following edges must not invent one.

    0.9.1 has no outgoing edge, so there is no route from it to 0.10.0 -- which is the honest
    answer, and the reason the validator does not demand that edge in the first place.
    """
    assert not dv.plan_upgrade_path(_matrix_with_backport(), "0.9.1", "0.10.0")["known"]


def test_the_shortest_declared_route_is_taken():
    """With two routes to one target, the answer must be the same every run and on both
    implementations, or the tool and the banner can disagree about the same upgrade."""
    matrix = _matrix_with_backport()
    matrix["versions"]["0.11.0"] = {"released": "2026-04-01", "notes": "c"}
    matrix["edges"].append({"from": "0.10.0", "to": "0.11.0", "kind": "direct",
                            "reversible": True, "requires_backup": True})
    matrix["edges"].append({"from": "0.9.0", "to": "0.11.0", "kind": "direct",
                            "reversible": True, "requires_backup": False})
    plan = dv.plan_upgrade_path(matrix, "0.9.0", "0.11.0")
    assert plan["known"] and len(plan["steps"]) == 1, (
        "expected the one-hop route; a longer walk would report a backup this upgrade does not need")
    assert not plan["requires_backup"]
