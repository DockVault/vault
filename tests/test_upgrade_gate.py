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

from conftest import skip_if_container_absent

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
    # Reachability first, on its own, so that the read below can be judged on its merits.
    try:
        reachable = sp.run(["docker", "exec", container, "true"],
                           capture_output=True, text=True, timeout=60)
    except (OSError, sp.SubprocessError) as exc:
        pytest.skip(f"cannot run docker to reach {container}: {exc}")
    skip_if_container_absent(reachable, container)
    if reachable.returncode != 0:
        pytest.skip(f"cannot reach {container}: {(reachable.stderr or '').strip()[:200]}")

    probe = sp.run(["docker", "exec", container, "cat", "/app/VERSION"],
                   capture_output=True, text=True, timeout=60)
    skip_if_container_absent(probe, container)
    assert probe.returncode == 0, (
        f"{container} answers, but /app/VERSION cannot be read from it. That is the version file "
        "being absent from the image -- the single way this can fail, per the description above, "
        "and the one the tool would paper over by falling back to the checkout's copy: "
        f"{(probe.stderr or '').strip()[:200]}")

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


# --- a release the upgrade has to land on -------------------------------------------------------

def _staged_matrix(*, stop_at="0.2.0", backup_on_first=False):
    """0.1.0 -> 0.2.0 -> 0.3.0, where 0.2.0 cannot be passed through in one step."""
    versions = {
        "0.1.0": {"released": "2026-01-01", "notes": "a"},
        "0.2.0": {"released": "2026-01-02", "notes": "b"},
        "0.3.0": {"released": "2026-01-03", "notes": "c"},
    }
    if stop_at:
        versions[stop_at]["must_land_here"] = True
    return {
        "schema_version": 1, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
        "versions": versions,
        "edges": [
            {"from": "0.1.0", "to": "0.2.0", "kind": "direct",
             "reversible": True, "requires_backup": backup_on_first},
            {"from": "0.2.0", "to": "0.3.0", "kind": "direct",
             "reversible": True, "requires_backup": False},
        ],
    }


def test_an_ordinary_upgrade_is_still_one_recreate():
    """The default has to stay the default.

    Staging exists for the rare release that cannot be passed through. If declaring nothing
    produced two legs, every ordinary upgrade would get slower and more fragile for no reason.
    """
    plan = dv.plan_upgrade_path(_staged_matrix(stop_at=None), "0.1.0", "0.3.0")
    assert [leg["to"] for leg in plan["legs"]] == ["0.3.0"]


def test_a_release_marked_must_land_here_splits_the_upgrade():
    plan = dv.plan_upgrade_path(_staged_matrix(), "0.1.0", "0.3.0")
    assert [leg["to"] for leg in plan["legs"]] == ["0.2.0", "0.3.0"]
    # The overall verdict is still the union: what the whole change involves, not one leg's share.
    assert plan["known"] and plan["steps"] and len(plan["steps"]) == 2


def test_each_leg_carries_its_own_requirements():
    """So a stage that needs a backup can be told apart from one that does not."""
    plan = dv.plan_upgrade_path(_staged_matrix(backup_on_first=True), "0.1.0", "0.3.0")
    first, second = plan["legs"]
    assert first["to"] == "0.2.0" and first["requires_backup"] is True
    assert second["to"] == "0.3.0" and second["requires_backup"] is False
    assert plan["requires_backup"] is True, "the whole change still needs one"


def test_landing_on_the_marked_release_itself_is_one_leg():
    """Stopping AT the version is not passing through it, so nothing is split."""
    plan = dv.plan_upgrade_path(_staged_matrix(), "0.1.0", "0.2.0")
    assert [leg["to"] for leg in plan["legs"]] == ["0.2.0"]


def test_the_tool_performs_every_leg_itself(tmp_path, monkeypatch, capsys):
    """One command, several recreates. The operator does not run update twice.

    This is the whole point of doing it in the tool: an instruction to come back and run it again
    is one an operator can miss, and a deployment left on an intermediate release because nobody
    read the last line is worse than one that took longer.
    """
    tool = _deployment(tmp_path, matrix=_staged_matrix())
    _stub(monkeypatch, tool, backups=[])
    monkeypatch.setattr(tool, "_running_version", lambda *a, **k: ("0.1.0", "the running container"))
    images = []
    monkeypatch.setattr(tool, "_set_env_key",
                        lambda path, key, value: images.append(value) if key == "DOCKVAULT_IMAGE"
                        else None)
    recreates = []
    monkeypatch.setattr(tool, "_recreate_stack", lambda build: recreates.append(build) or True)

    tool.update(argparse.Namespace(non_interactive=True, tag="v0.3.0", source=False, yes=True))

    assert images == ["ghcr.io/dockvault/vault:v0.2.0", "ghcr.io/dockvault/vault:v0.3.0"], images
    assert len(recreates) == 2, "each leg is its own recreate"
    out = capsys.readouterr().out
    assert "2 stages" in out and "one command" in out, out


def test_a_stage_that_does_not_come_back_stops_the_rest(tmp_path, monkeypatch, capsys):
    """The property that makes staging worth doing.

    The next stage's migration is written assuming this one finished. Running it over a boot that
    did not complete is how a recoverable problem becomes an unrecoverable one -- so the walk stops,
    and says where the deployment is, which is a real release rather than somewhere in between.
    """
    tool = _deployment(tmp_path, matrix=_staged_matrix())
    _stub(monkeypatch, tool, backups=[])
    monkeypatch.setattr(tool, "_running_version", lambda *a, **k: ("0.1.0", "the running container"))
    images = []
    monkeypatch.setattr(tool, "_set_env_key",
                        lambda path, key, value: images.append(value) if key == "DOCKVAULT_IMAGE"
                        else None)
    monkeypatch.setattr(tool, "_wait_secure_healthy", lambda *a, **k: False)

    tool.update(argparse.Namespace(non_interactive=True, tag="v0.3.0", source=False, yes=True))

    assert images == ["ghcr.io/dockvault/vault:v0.2.0"], (
        "the second stage ran after the first failed to come back: %r" % (images,))
    out = capsys.readouterr().out
    assert "NOT run" in out and "v0.2.0" in out, out


def test_the_backup_is_taken_once_for_the_whole_change(tmp_path, monkeypatch):
    """Before anything moves, not before each leg.

    The meaningful restore point is the deployment as it was before the upgrade started. A backup
    taken between stages captures a database already half-migrated, which is not a state anyone
    wants to be restored to.
    """
    backups = []
    tool = _deployment(tmp_path, matrix=_staged_matrix(backup_on_first=True))
    _stub(monkeypatch, tool, backups=backups)
    monkeypatch.setattr(tool, "_running_version", lambda *a, **k: ("0.1.0", "the running container"))
    tool.update(argparse.Namespace(non_interactive=True, tag="v0.3.0", source=False, yes=True))
    assert len(backups) == 1, f"expected one backup for the whole change, got {len(backups)}"


# --- downgrade refusal + lifecycle: the host tool's floor enforcement -------------------------

def test_a_downgrade_across_a_blocked_edge_is_refused():
    refused, reason = dv.downgrade_refusal(_matrix(kind="blocked"), "0.2.0", "0.1.0")
    assert refused is True and "0.2.0 rewrites" in (reason or "")


def test_a_downgrade_across_an_irreversible_edge_is_refused():
    refused, reason = dv.downgrade_refusal(_matrix(reversible=False), "0.2.0", "0.1.0")
    assert refused is True and "irreversible" in (reason or "")


def test_a_downgrade_across_a_reversible_edge_is_allowed():
    assert dv.downgrade_refusal(_matrix(reversible=True), "0.2.0", "0.1.0") == (False, None)


def test_a_downgrade_the_matrix_cannot_describe_is_not_force_refused():
    # Out of range / unknown -> not refused here; it flows through the 'undescribed, needs a backup'
    # path unchanged, so behaviour outside the declared range does not change.
    assert dv.downgrade_refusal(_matrix(), "0.2.0", "9.9.9") == (False, None)
    assert dv.downgrade_refusal(None, "0.2.0", "0.1.0") == (False, None)
    # An UPGRADE is never a downgrade refusal, even across an irreversible edge.
    assert dv.downgrade_refusal(_matrix(reversible=False), "0.1.0", "0.2.0") == (False, None)


def _lifecycle_matrix():
    m = _matrix()
    m["schema_version"] = 2
    m["versions"]["0.1.0"]["support"] = {"eol": True, "secure": False,
                                         "security_support": "2027-01-01"}
    m["versions"]["0.2.0"]["support"] = {"eol": False, "secure": True}
    return m


def test_is_eol_and_version_support_read_the_lifecycle():
    m = _lifecycle_matrix()
    assert dv.is_eol(m, "0.1.0") is True
    assert dv.is_eol(m, "v0.2.0") is False            # tolerates a v-prefix
    assert dv.is_eol(m, "9.9.9") is False             # unknown -> not eol
    assert dv.version_support(m, "0.2.0") == {"eol": False, "secure": True}


def test_support_is_empty_for_a_pre_lifecycle_matrix():
    # A schema_version-1 matrix has no support blocks -> {} everywhere, so an older published file
    # keeps working instead of erroring.
    assert dv.version_support(_matrix(), "0.1.0") == {}
    assert dv.is_eol(_matrix(), "0.1.0") is False


def test_support_line_names_eol_tail_and_insecurity():
    m = _lifecycle_matrix()
    line = dv.support_line(m, "0.1.0")
    assert "end-of-life" in line and "security support until 2027-01-01" in line
    assert "unpatched" in line                        # insecure is named
    assert dv.support_line(m, "0.2.0") == "supported"
    assert dv.support_line(_matrix(), "0.1.0") == ""  # nothing stated -> empty


# --- the per-version vulnerability list, and escape-stripping matrix-sourced strings ------------

def _matrix_with_vulnerabilities():
    m = _matrix()
    m["schema_version"] = 2
    m["versions"]["0.1.0"]["support"] = {"eol": False, "secure": False}
    m["versions"]["0.1.0"]["vulnerabilities"] = [
        {"title": "First issue", "description": "d", "severity": None, "cvss": None,
         "id": None, "fixed_in": "0.2.0", "published": "2026-01-02"},
        {"title": "Second issue", "description": "d", "severity": None, "cvss": None,
         "id": None, "fixed_in": "0.2.0", "published": "2026-01-02"},
    ]
    m["versions"]["0.2.0"]["support"] = {"eol": False, "secure": True}
    return m


def test_version_vulnerabilities_is_tolerant_of_an_older_or_odd_matrix():
    m = _matrix_with_vulnerabilities()
    assert len(dv.version_vulnerabilities(m, "0.1.0")) == 2
    assert dv.version_vulnerabilities(m, "v0.1.0")                       # tolerates a v-prefix
    assert dv.version_vulnerabilities(_matrix(), "0.1.0") == []          # field absent -> []
    assert dv.version_vulnerabilities({"versions": {"0.1.0": {"vulnerabilities": "x"}}}, "0.1.0") == []
    assert dv.version_vulnerabilities(None, "0.1.0") == []


def test_support_line_counts_vulnerabilities_by_severity_and_names_the_fix():
    # One line per release in the list: how many, how bad, and what fixes them. The titles and details
    # belong to the version the operator picks (describe_vulnerabilities), not to every line.
    older = _matrix_with_vulnerabilities()                              # a schema-2 file: unrated
    line = dv.support_line(older, "0.1.0")
    assert "2 known vulnerabilities (2 unrated)" in line and "fixed in 0.2.0" in line
    assert "First issue" not in line
    assert dv.support_line(older, "0.2.0") == "supported"               # secure -> just supported
    # An insecure version whose matrix predates the field still names the bare fact.
    assert "unpatched" in dv.support_line(_lifecycle_matrix(), "0.1.0")

    m = _v3_matrix()
    assert "2 known vulnerabilities (1 high, 1 medium) -- fixed in 0.2.0, 0.3.0" in dv.support_line(m, "0.1.0")
    assert "1 known vulnerability (1 medium) -- fixed in 0.3.0" in dv.support_line(m, "0.2.0")
    m = _v3_matrix(unfixed_in_newest=True)
    assert dv.support_line(m, "0.3.0").endswith("1 known vulnerability (1 unrated) -- 1 with no fix released yet")


# A colour code, a reset, and a screen-clearing CSI sequence around visible text.
_CLEARING_TITLE = "\x1b[31mDANGER\x1b[0m\x1b[2Jcleared"


def test_clean_matrix_text_removes_terminal_escapes_but_keeps_visible_text():
    assert dv.clean_matrix_text(_CLEARING_TITLE) == "DANGERcleared"
    # A lone ESC, a C0 (BEL) and a C1 (NEL) control are dropped; a plain space and printable Unicode
    # (an em dash, an accented letter) survive.
    assert dv.clean_matrix_text("a\x1b\x07b\x85 — café") == "ab — café"
    assert dv.clean_matrix_text(123) == ""                              # non-strings answer empty


def test_a_tampered_advisory_prints_without_its_escape_sequences():
    # The runtime protection: a fetched (possibly tampered) matrix whose advisory carries escape
    # sequences must not print them raw to the operator's terminal -- in any field the tool prints.
    m = _v3_matrix()
    for field in ("impact", "remediation", "mitigation", "cvss"):
        m["advisories"]["old-issue"][field] = _CLEARING_TITLE
    m["versions"]["0.1.0"]["vulnerabilities"][0]["title"] = _CLEARING_TITLE
    m["versions"]["0.1.0"]["vulnerabilities"][0]["fixed_in"] = _CLEARING_TITLE
    lines = dv.describe_vulnerabilities(dv.version_vulnerabilities(m, "0.1.0"))
    printed = "\n".join(lines + [dv.support_line(m, "0.1.0")])
    assert "\x1b" not in printed and "[31m" not in printed and "[2J" not in printed
    assert printed.count("DANGERcleared") >= 6                          # the visible text survives


# --- schema-3 advisories: what the tool reads and shows -------------------------------------------

_HIGH_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
_MEDIUM_VECTOR = "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"


def _v3_matrix(*, unfixed_in_newest=False):
    """0.1.0 -> 0.2.0 -> 0.3.0, schema 3, every edge direct and reversible.

    old-issue (high) affects 0.1.0 and is fixed in 0.2.0. mid-issue (medium) affects 0.1.0 and 0.2.0
    and is fixed in 0.3.0. With `unfixed_in_newest`, new-issue (unrated, no fix yet, with a
    mitigation) affects 0.3.0 only -- a regression in the newest release."""
    def advisory(title, fixed_in, severity, vector, mitigation=None):
        return {"title": title, "description": "d", "impact": title + " impact",
                "remediation": ("Upgrade to %s." % fixed_in) if fixed_in else "Apply the mitigation.",
                "mitigation": mitigation, "severity": severity, "cvss": vector, "id": None,
                "fixed_in": fixed_in, "published": "2026-01-03"}

    def ref(slug, title, fixed_in):
        return {"advisory": slug, "title": title, "fixed_in": fixed_in}

    m = {
        "schema_version": 3, "about": "test", "kinds": {"direct": "a", "blocked": "b"},
        "advisories": {"old-issue": advisory("Old issue", "0.2.0", "high", _HIGH_VECTOR),
                       "mid-issue": advisory("Mid issue", "0.3.0", "medium", _MEDIUM_VECTOR)},
        "versions": {
            "0.1.0": {"released": "2026-01-01", "notes": "a", "support": {"eol": False, "secure": False},
                      "vulnerabilities": [ref("old-issue", "Old issue", "0.2.0"),
                                          ref("mid-issue", "Mid issue", "0.3.0")]},
            "0.2.0": {"released": "2026-01-02", "notes": "b", "support": {"eol": False, "secure": False},
                      "vulnerabilities": [ref("mid-issue", "Mid issue", "0.3.0")]},
            "0.3.0": {"released": "2026-01-03", "notes": "c", "support": {"eol": False, "secure": True}},
        },
        "edges": [{"from": "0.1.0", "to": "0.2.0", "kind": "direct", "reversible": True, "requires_backup": False},
                  {"from": "0.2.0", "to": "0.3.0", "kind": "direct", "reversible": True, "requires_backup": False}],
    }
    if unfixed_in_newest:
        m["advisories"]["new-issue"] = advisory("New issue", None, None, None,
                                                mitigation="Turn the new feature off.")
        m["versions"]["0.3.0"]["support"]["secure"] = False
        m["versions"]["0.3.0"]["vulnerabilities"] = [ref("new-issue", "New issue", None)]
    return m


def test_a_schema_3_reference_is_read_through_its_advisory():
    by_title = {v["title"]: v for v in dv.version_vulnerabilities(_v3_matrix(), "0.1.0")}
    assert set(by_title) == {"Old issue", "Mid issue"}
    old = by_title["Old issue"]
    assert (old["advisory"], old["severity"], old["fixed_in"]) == ("old-issue", "high", "0.2.0")
    assert old["impact"] == "Old issue impact" and old["remediation"] == "Upgrade to 0.2.0."
    assert old["cvss"] == _HIGH_VECTOR and old["mitigation"] is None


@pytest.mark.parametrize("severity, expected", [
    ("high", "high"), (" HIGH ", "high"),                  # a spelling this tool can recognise
    ("severe", None), ("CRITICAL!!", None), (9, None), ({"band": "high"}, None), (None, None),
])
def test_a_severity_the_tool_does_not_recognise_reads_as_unrated(severity, expected):
    # A fetched matrix is untrusted: an unknown severity must not invent a bucket in the counts.
    m = _v3_matrix()
    m["advisories"]["old-issue"]["severity"] = severity
    assert dv.version_vulnerabilities(m, "0.1.0")[0]["severity"] == expected


def test_advisory_details_are_bounded_and_a_missing_advisory_still_lists_its_title():
    m = _v3_matrix()
    m["advisories"]["old-issue"]["impact"] = "x" * 50_000
    assert len(dv.version_vulnerabilities(m, "0.1.0")[0]["impact"]) <= dv._DETAIL_CAP
    del m["advisories"]["old-issue"]                        # a reference to nothing: still a finding
    old = dv.version_vulnerabilities(m, "0.1.0")[0]
    assert (old["title"], old["fixed_in"], old["severity"], old["impact"]) == ("Old issue", "0.2.0", None, None)


def test_the_detail_lists_the_most_severe_first_and_says_when_there_is_no_fix():
    lines = dv.describe_vulnerabilities(dv.version_vulnerabilities(_v3_matrix(), "0.1.0"))
    text = "\n".join(lines)
    assert text.index("[HIGH] Old issue -- fixed in 0.2.0") < text.index("[MEDIUM] Mid issue -- fixed in 0.3.0")
    assert "Impact: Old issue impact" in text and "Remediation: Upgrade to 0.2.0." in text
    assert "CVSS: " + _HIGH_VECTOR in text
    unfixed = "\n".join(dv.describe_vulnerabilities(
        dv.version_vulnerabilities(_v3_matrix(unfixed_in_newest=True), "0.3.0")))
    assert "[UNRATED] New issue -- no fix released yet" in unfixed
    assert "Mitigation: Turn the new feature off." in unfixed


def test_a_merged_main_copy_brings_its_advisory_details_with_it():
    # The advisory published on main after this checkout was cut: the merge resolves it against MAIN's
    # advisories, so the operator sees its severity and remediation, not only a title.
    local = _v3_matrix()
    main = _v3_matrix(unfixed_in_newest=True)
    merged, source = dv.merge_lifecycle_matrix(local, main, "0.3.0")
    assert source == "main"
    new = dv.version_vulnerabilities(merged, "0.3.0")
    assert [(v["title"], v["fixed_in"], v["mitigation"]) for v in new] == [
        ("New issue", None, "Turn the new feature off.")]
    assert dv.version_support(merged, "0.3.0")["secure"] is False


# --- a safer release: advice, never a refusal ------------------------------------------------------

_TAGS = ["v0.3.0", "v0.2.0", "v0.1.0"]


def test_the_safer_alternative_has_a_strict_subset_and_the_fewest():
    m = _v3_matrix()
    # 0.2.0 {mid} and 0.3.0 {} are both strict subsets of 0.1.0 {old, mid}: the fewest wins.
    assert dv.safer_alternative(m, "v0.1.0", _TAGS) == "v0.3.0"
    assert dv.safer_alternative(m, "v0.1.0", ["v0.2.0", "v0.1.0"]) == "v0.2.0"
    # Nothing listed: nothing is a strict subset of an empty set.
    assert dv.safer_alternative(m, "v0.3.0", _TAGS) is None


def test_a_release_the_matrix_does_not_describe_is_never_called_safer():
    # v0.9.0 lists nothing only because nothing is known about it.
    assert dv.safer_alternative(_v3_matrix(), "v0.2.0", ["v0.9.0"]) is None
    assert dv.safer_alternative(_v3_matrix(), "v0.9.0", _TAGS) is None


def test_a_release_with_a_vulnerability_the_target_lacks_is_not_safer():
    m = _v3_matrix(unfixed_in_newest=True)
    # 0.3.0 {new} is not a subset of 0.2.0 {mid}: they trade one known issue for another.
    assert dv.safer_alternative(m, "v0.2.0", ["v0.3.0"]) is None
    # ...and the same set is not strictly smaller.
    m["versions"]["0.3.0"]["vulnerabilities"] = list(m["versions"]["0.2.0"]["vulnerabilities"])
    m["advisories"]["mid-issue"]["fixed_in"] = None
    for ver in ("0.1.0", "0.2.0", "0.3.0"):
        for v in m["versions"][ver].get("vulnerabilities", []):
            if v["advisory"] == "mid-issue":
                v["fixed_in"] = None
    assert dv.safer_alternative(m, "v0.2.0", ["v0.3.0"]) is None


def test_a_regression_in_the_newest_release_makes_the_previous_one_safer():
    # The newest release is not automatically the safest: when it introduced a known issue its
    # predecessor does not have, going back is the advice, and a rollback is exactly this case.
    m = _v3_matrix(unfixed_in_newest=True)
    m["versions"]["0.2.0"]["vulnerabilities"] = []
    m["versions"]["0.2.0"]["support"]["secure"] = True
    m["advisories"]["mid-issue"]["fixed_in"] = "0.2.0"
    m["versions"]["0.1.0"]["vulnerabilities"][1]["fixed_in"] = "0.2.0"
    assert dv.safer_alternative(m, "v0.3.0", _TAGS) == "v0.2.0"


def test_the_advice_always_ends_somewhere():
    # The property that means the advice can never shut every door: following "a safer release" from
    # any release strictly shrinks the set of known vulnerabilities, so it always stops at a release
    # with no safer alternative -- and at least one such release always exists.
    # Exhaustive over every way three findings can sit on four releases: 8**4 = 4,096 cases.
    import itertools
    findings = ["a", "b", "c"]
    versions = ["0.1.0", "0.2.0", "0.3.0", "0.4.0"]
    tags = ["v" + v for v in versions]
    for combo in itertools.product(range(2 ** len(findings)), repeat=len(versions)):
        m = {"versions": {v: {"vulnerabilities": [{"title": f, "fixed_in": None}
                                                  for bit, f in enumerate(findings) if mask >> bit & 1]}
                          for v, mask in zip(versions, combo)}}
        ends = [t for t in tags if dv.safer_alternative(m, t, tags) is None]
        assert ends, combo
        for t in tags:
            steps, at = 0, t
            while (nxt := dv.safer_alternative(m, at, tags)) is not None:
                assert len(dv._finding_keys(m, nxt)) < len(dv._finding_keys(m, at))
                at, steps = nxt, steps + 1
                assert steps <= len(findings), (combo, t)


# --- the update flow ---------------------------------------------------------------------------------

def _answers(monkeypatch, typed):
    """Interactive: yes to every confirm; `typed` to the version-typed-back prompt and to the version
    list; and 'i accept' to the irreversible-change prompt, which a downgrade raises on its own (a
    backward hop is undescribed, so it is treated as possibly irreversible)."""
    asked = []
    monkeypatch.setattr(dv, "confirm", lambda prompt, pal, default=True: True)

    def ask(prompt, pal, default=None):
        asked.append(prompt)
        return "i accept" if "'i accept'" in prompt else typed
    monkeypatch.setattr(dv, "ask", ask)
    return asked


def _v3_deployment(tmp_path, monkeypatch, *, running, matrix=None, tags=_TAGS):
    tool = _deployment(tmp_path, matrix=matrix or _v3_matrix())
    _stub(monkeypatch, tool, backups=[])
    monkeypatch.setattr(tool, "_running_version", lambda *a, **k: (running, "the running container"))
    monkeypatch.setattr(dv, "fetch_release_tags", lambda *a, **k: list(tags))
    monkeypatch.setattr(dv, "fetch_main_lifecycle_matrix", lambda *a, **k: None)   # hermetic
    images = []
    monkeypatch.setattr(tool, "_set_env_key",
                        lambda path, key, value: images.append(value) if key == "DOCKVAULT_IMAGE" else None)
    return tool, images


def _interactive(tool, tag):
    tool.update(argparse.Namespace(tag=tag, source=False, yes=False, non_interactive=False,
                                   dry_run=False, backup_verified=False))


def test_choosing_a_less_safe_release_asks_for_its_name_and_then_proceeds(tmp_path, monkeypatch, capsys):
    tool, images = _v3_deployment(tmp_path, monkeypatch, running="0.3.0")
    asked = _answers(monkeypatch, typed="v0.1.0")
    _interactive(tool, "v0.1.0")
    out = capsys.readouterr().out
    assert "WARNING: v0.1.0 has 2 known vulnerabilities (1 high, 1 medium)" in out
    assert "[HIGH] Old issue -- fixed in 0.2.0" in out and "Impact: Old issue impact" in out
    assert "brings back 2 known vulnerabilities that 0.3.0 does not have" in out
    assert "v0.3.0 is affected by 2 fewer known vulnerabilities than v0.1.0" in out
    assert any("Type v0.1.0 to install it anyway" in q for q in asked), asked
    assert images == ["ghcr.io/dockvault/vault:v0.1.0"], "typing the version back must let it proceed"


def test_anything_but_the_version_typed_back_cancels(tmp_path, monkeypatch, capsys):
    tool, images = _v3_deployment(tmp_path, monkeypatch, running="0.3.0")
    _answers(monkeypatch, typed="yes")
    _interactive(tool, "v0.1.0")
    assert images == [] and "Cancelled." in capsys.readouterr().out


def test_without_a_terminal_the_advice_is_printed_and_nothing_is_refused(tmp_path, monkeypatch, capsys):
    # A scripted rollback with --yes must still work: the data can warn, never block.
    tool, images = _v3_deployment(tmp_path, monkeypatch, running="0.3.0")
    _update(tool, tag="v0.1.0", backup_verified=True)
    assert "is affected by 2 fewer known vulnerabilities" in capsys.readouterr().out
    assert images == ["ghcr.io/dockvault/vault:v0.1.0"]


def test_an_upgrade_says_what_it_fixes_and_asks_nothing_extra(tmp_path, monkeypatch, capsys):
    tool, images = _v3_deployment(tmp_path, monkeypatch, running="0.1.0")
    asked = _answers(monkeypatch, typed="unexpected")
    _interactive(tool, "v0.3.0")
    out = capsys.readouterr().out
    assert "Moving to v0.3.0 fixes 2 known vulnerabilities in 0.1.0." in out
    assert not any("install it anyway" in q for q in asked), asked
    assert images == ["ghcr.io/dockvault/vault:v0.3.0"]


def test_the_newest_release_with_an_unfixed_issue_is_still_installable(tmp_path, monkeypatch, capsys):
    # The lock-out case: every release carries a known vulnerability, the newest one with no fix yet.
    # The list says so, the mitigation is shown, and the change still goes through.
    m = _v3_matrix(unfixed_in_newest=True)
    tool, images = _v3_deployment(tmp_path, monkeypatch, running="0.2.0", matrix=m)
    asked = _answers(monkeypatch, typed="")
    tool.update(argparse.Namespace(tag=None, source=False, yes=False, non_interactive=False,
                                   dry_run=False, backup_verified=False))
    listing = capsys.readouterr().out
    assert "Every release listed has known vulnerabilities" in listing
    assert "v0.3.0" in listing and "1 with no fix released yet" in listing
    assert asked, "the list must still offer a choice"

    _answers(monkeypatch, typed="unexpected")
    _interactive(tool, "v0.3.0")
    out = capsys.readouterr().out
    assert "Mitigation: Turn the new feature off." in out
    assert images == ["ghcr.io/dockvault/vault:v0.3.0"]


# Every ECMA-48 sequence family, and the payload-survival defect they exposed: an OSC/DCS/APC/PM/SOS
# string type used to have its ESC removed but its PAYLOAD left as visible text, and RIS/charset/
# keypad escapes left their final byte. The regex now consumes each as a whole unit, and the
# isprintable pass guarantees no ESC survives even a malformed one.
_ESC, _BEL, _ST = "\x1b", "\x07", "\x1b\\"
_ESCAPE_CASES = [
    (_ESC + "]0;PWNED" + _BEL, ""),                                          # OSC, BEL-terminated
    (_ESC + "]0;PWNED" + _ST, ""),                                           # OSC, ST-terminated
    (_ESC + "]8;;http://evil" + _BEL + "link" + _ESC + "]8;;" + _BEL, "link"),  # OSC-8: label survives
    (_ESC + "_APC" + _ST, ""),                                               # APC
    (_ESC + "Pq#0;2;0;0;0" + _ST, ""),                                       # DCS
    (_ESC + "^PM" + _ST, ""),                                                # PM
    (_ESC + "Xsos" + _ST, ""),                                               # SOS
    (_ESC + "[31mred" + _ESC + "[0m", "red"),                                # CSI colour pair
    (_ESC + "[2J", ""),                                                      # CSI screen-clear
    (_ESC + "c", ""),                                                        # RIS (Fs)
    (_ESC + "(B", ""),                                                       # charset designation (nF)
    (_ESC + "=", ""),                                                        # keypad mode (Fp)
    (_ESC + "[31", "31"),                                    # unterminated CSI: "ESC [" go, params stay
    ("just text", "just text"),                                             # plain text untouched
]


@pytest.mark.parametrize("raw, expected", _ESCAPE_CASES)
def test_clean_matrix_text_consumes_whole_ecma48_sequences_including_string_payloads(raw, expected):
    out = dv.clean_matrix_text(raw)
    assert out == expected, f"{raw!r} -> {out!r}, expected {expected!r}"
    assert "\x1b" not in out          # the second pass guarantees no ESC ever reaches the terminal


# The 8-bit C1 introducers and terminator, and unterminated string types. A C1 byte was always
# dropped by the isprintable pass, but its PAYLOAD used to survive as text, and an unterminated
# OSC/DCS/... left its payload too. Each C1 form and each unterminated string type is now consumed
# whole. C1 bytes: CSI U+009B, OSC U+009D, DCS U+0090, PM U+009E, APC U+009F, SOS U+0098, ST U+009C.
_CSI8, _OSC8, _DCS8, _PM8, _APC8, _SOS8, _ST8 = "\x9b", "\x9d", "\x90", "\x9e", "\x9f", "\x98", "\x9c"
_C1_AND_UNTERMINATED_CASES = [
    (_CSI8 + "31mred", "red"),                       # 8-bit CSI
    (_OSC8 + "0;PWN" + _ST8, ""),                     # 8-bit OSC, 8-bit ST
    (_OSC8 + "0;PWN" + "\x07", ""),                   # 8-bit OSC, BEL-terminated
    (_DCS8 + "q#0" + _ST8, ""),                       # 8-bit DCS
    (_APC8 + "x" + "\x1b\\", ""),                     # 8-bit APC, 7-bit ST
    (_PM8 + "p" + _ST8, ""),                          # 8-bit PM
    (_SOS8 + "s" + _ST8, ""),                          # 8-bit SOS
    ("\x1b]0;PWN", ""),                               # unterminated OSC -> swallowed to end of string
    ("\x1bPdcs-no-term", ""),                         # unterminated DCS -> to end
    (_APC8 + "apc-no-term", ""),                       # unterminated 8-bit APC -> to end
    ("\x1bPq\x07more\x1b\\", ""),                      # BEL is not a DCS terminator; runs to ST
    ("\x1b]0;a\x1bb\x1b\\", ""),                       # ESC inside an OSC payload -> whole run to ST
    ("\x1b]1;A\x07mid\x1b]2;B\x07", "mid"),            # nested/adjacent OSC: the middle text survives
]


@pytest.mark.parametrize("raw, expected", _C1_AND_UNTERMINATED_CASES)
def test_clean_matrix_text_handles_c1_forms_and_unterminated_string_types(raw, expected):
    out = dv.clean_matrix_text(raw)
    assert out == expected, f"{raw!r} -> {out!r}, expected {expected!r}"
    # No control or C1 byte survives (C0 0x00-0x1F, DEL/C1 0x7F-0x9F).
    assert not any(ord(ch) < 0x20 or 0x7f <= ord(ch) <= 0x9f for ch in out)


def test_lifecycle_is_read_from_the_newest_local_view_not_the_frozen_target():
    # A version becomes end-of-life AFTER it ships; the target's own published matrix is frozen at
    # cut time and forever self-declares eol:false, so this checkout's newer view must win.
    local = _lifecycle_matrix()
    local["versions"]["0.2.0"]["support"] = {"eol": True, "secure": False}
    frozen = _lifecycle_matrix()                          # the target's own: 0.2.0 eol:false
    chosen = dv.preferred_lifecycle_matrix(local, frozen, "0.2.0")
    assert dv.is_eol(chosen, "0.2.0") is True
    # But when the local view does not describe the target at all (a release newer than this
    # checkout), fall back to the fetched matrix, which does.
    newer = {"schema_version": 2, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
             "versions": {"0.9.0": {"released": "2026-01-01", "notes": "n",
                                    "support": {"eol": False, "secure": True}}}, "edges": []}
    assert dv.preferred_lifecycle_matrix(local, newer, "0.9.0") is newer
