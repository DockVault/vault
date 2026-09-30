"""Offline contracts for main-only publication of one fully tested commit."""

from __future__ import annotations

import datetime
import importlib.util
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_WORKFLOW = (_WORKFLOWS / "release.yml").read_text(encoding="utf-8")
_TESTS = (_WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
_SETUP = (_WORKFLOWS / "setup-matrix.yml").read_text(encoding="utf-8")
_ACTIONLINT = (_ROOT / ".github" / "actionlint.yaml").read_text(encoding="utf-8")
_SCRIPT = _ROOT / ".github" / "scripts" / "release_gate.py"
_SPEC = importlib.util.spec_from_file_location("release_gate", _SCRIPT)
assert _SPEC and _SPEC.loader
_GATE = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _GATE
_SPEC.loader.exec_module(_GATE)


def _job(name: str, next_name: str | None = None) -> str:
    body = _WORKFLOW.split(f"  {name}:", 1)[1]
    return body if next_name is None else body.split(f"  {next_name}:", 1)[0]


def _git(repository: Path, *args: str, env: dict[str, str] | None = None) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
        env=None if env is None else {**os.environ, **env},
    )
    return result.stdout.strip()


def _vkey(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _matrix(released: dict[str, str]) -> dict:
    """A minimal valid matrix declaring `released` (version -> release date).

    Each version is reached from the one before it in version order, except a maintenance release
    shipped after the next minor: the next minor is then reached from the newest release no later
    than it, which is the shape the validator's backport rule asks for, and the maintenance release
    has its own way up, into the next minor's first release.
    """
    ordered = sorted(released, key=_vkey)
    edges = []
    for earlier, later in zip(ordered, ordered[1:]):
        source = earlier
        if released[later] < released[earlier]:
            source = max((v for v in ordered
                          if _vkey(v) < _vkey(later) and released[v] <= released[later]),
                         key=_vkey)
            edges.append({"from": earlier, "to": later, "kind": "direct",
                          "reversible": True, "requires_backup": False})
        edges.append({"from": source, "to": later, "kind": "direct",
                      "reversible": True, "requires_backup": False})
    return {
        "schema_version": 3,
        "about": "release contract fixture",
        "kinds": {"direct": "one step", "blocked": "do not"},
        "advisories": {},
        "versions": {v: {"released": released[v], "notes": f"release {v}",
                         "support": {"eol": False, "secure": True}} for v in ordered},
        "edges": edges,
    }


class _History:
    """A release repository built commit by commit: releases on main, maintenance branches, tags.

    Each release commit carries a VERSION and a matrix declaring every release made so far plus its
    own -- the synced single matrix every branch is meant to carry. A test can hand a commit a
    different matrix to break exactly one thing.
    """

    def __init__(self, path: Path) -> None:
        self.path = path
        self.released: dict[str, str] = {}
        self._born = False
        self._clock = 1767225600  # 2026-01-01, advanced a minute per commit and per tag
        path.mkdir()
        _git(path, "init", "-b", "main")
        _git(path, "config", "user.name", "Release Contract")
        _git(path, "config", "user.email", "release-contract@example.invalid")
        _git(path, "config", "commit.gpgsign", "false")
        _git(path, "config", "tag.gpgsign", "false")
        # Checkouts must leave VERSION byte-exact: the gate refuses a CRLF, as it should.
        _git(path, "config", "core.autocrlf", "false")

    def commit(self, version: str, *, branch: str = "main", tag: bool = True,
               matrix: dict | None = None, annotated: bool = True) -> str:
        """One commit on `branch` whose VERSION is `version`, tagged unless told otherwise."""
        if self._born:
            _git(self.path, "checkout", "-q", branch)
        self._born = True
        date = f"2026-01-{len(self.released) + 1:02d}"
        declared = {**self.released, version: date}
        (self.path / "VERSION").write_bytes(f"{version}\n".encode())
        (self.path / "docs").mkdir(exist_ok=True)
        (self.path / "docs" / "upgrade-matrix.json").write_text(
            json.dumps(matrix if matrix is not None else _matrix(declared)),
            encoding="utf-8", newline="\n")
        _git(self.path, "add", "VERSION", "docs/upgrade-matrix.json")
        _git(self.path, "commit", "-q", "--allow-empty", "-m", f"release {version}",
             env=self._tick())
        if tag:
            self.tag(version, annotated=annotated)
        return _git(self.path, "rev-parse", "HEAD")

    def tag(self, version: str, *, annotated: bool = True) -> None:
        # A release tag is annotated, and so carries the time it was made. A lightweight tag has no
        # time of its own (git reports its commit's); the gate refuses one for the release it cuts.
        if annotated:
            _git(self.path, "tag", "-a", f"v{version}", "-m", f"release {version}",
                 env=self._tick())
        else:
            _git(self.path, "tag", f"v{version}")
        self.released.setdefault(version, f"2026-01-{len(self.released) + 1:02d}")

    def matrix_only_commit(self, branch: str = "main") -> str:
        """A commit that changes only the matrix, as after a release on an older line."""
        _git(self.path, "checkout", "-q", branch)
        (self.path / "docs" / "upgrade-matrix.json").write_text(
            json.dumps(_matrix(self.released)), encoding="utf-8", newline="\n")
        _git(self.path, "add", "docs/upgrade-matrix.json")
        _git(self.path, "commit", "-q", "--allow-empty", "-m", "sync the matrix", env=self._tick())
        return _git(self.path, "rev-parse", "HEAD")

    def _tick(self) -> dict[str, str]:
        """Distinct, ordered dates, so which release was tagged first never rests on a race."""
        self._clock += 60
        stamp = f"{self._clock} +0000"
        return {"GIT_COMMITTER_DATE": stamp, "GIT_AUTHOR_DATE": stamp}

    def branch_line(self, line: str, from_version: str) -> None:
        _git(self.path, "branch", f"release/{line}", f"v{from_version}")

    def push(self) -> None:
        """What a fetch from origin would leave: main and every release/* as remote refs."""
        for ref in _git(self.path, "for-each-ref", "--format=%(refname:strip=2)",
                        "refs/heads/").split():
            _git(self.path, "update-ref", f"refs/remotes/origin/{ref}",
                 _git(self.path, "rev-parse", ref))

    def gate(self, version: str, **kwargs):
        """Run the gate as the workflow does: the tagged commit checked out, the tag as the event."""
        _git(self.path, "checkout", "-q", f"v{version}")
        sha = _git(self.path, "rev-parse", "HEAD")
        return _GATE.validate_release(
            self.path,
            ref=f"refs/tags/v{version}",
            event_sha=sha,
            main_ref="refs/remotes/origin/main",
            repository_owner="DockVault",
            **kwargs,
        )


def _new_repository(path: Path) -> str:
    """A main branch with one earlier release and an untagged 0.8.0 candidate at its tip.

    Each test tags the release under test itself, sometimes annotated, sometimes on another branch.
    The fixture supplies the history around it, not the release.
    """
    history = _History(path)
    history.commit("0.7.0")
    sha = history.commit("0.8.0", tag=False)
    history.push()
    return sha


def test_only_tag_pushes_can_enter_release_and_manual_test_runs_remain():
    triggers = _WORKFLOW.split("on:", 1)[1].split("permissions:", 1)[0]

    assert "push:" in triggers and 'tags: ["v*.*.*"]' in triggers
    assert "workflow_dispatch:" not in triggers
    assert "branches:" not in triggers
    assert "workflow_dispatch:" in _TESTS
    assert "workflow_dispatch:" in _SETUP


def test_default_permissions_are_read_only_and_only_publish_can_write():
    defaults = _WORKFLOW.split("permissions:", 1)[1].split("concurrency:", 1)[0]
    before_publish = _WORKFLOW.split("  publish:", 1)[0]
    publish = _job("publish")

    assert "contents: read" in defaults
    assert "contents: write" not in before_publish
    assert "packages: write" not in before_publish
    assert "contents: write" in publish
    assert "packages: write" in publish
    assert _WORKFLOW.count("actions/checkout@") == 2
    assert _WORKFLOW.count("persist-credentials: false") == 2


def test_publish_waits_for_both_same_commit_reusable_gates():
    tests = _job("tests", "setup")
    setup = _job("setup", "publish")
    publish = _job("publish")

    assert "needs: validate" in tests
    assert "uses: ./.github/workflows/tests.yml" in tests
    assert "expected_sha: ${{ needs.validate.outputs.sha }}" in tests
    assert "needs: validate" in setup
    assert "uses: ./.github/workflows/setup-matrix.yml" in setup
    assert "expected_sha: ${{ needs.validate.outputs.sha }}" in setup
    assert "needs: [validate, tests, setup]" in publish
    assert "if: ${{ success() }}" in publish
    assert "ref: ${{ needs.validate.outputs.sha }}" in publish
    assert 'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"' in publish


def test_publication_needs_the_suite_and_the_configuration_scenarios():
    """The Tests workflow runs its stack in two jobs: the suite, and the configuration scenarios that
    used to follow it. The release's `tests` job calls that whole workflow, and a called workflow
    succeeds only when every job in it does, so `needs: tests` holds publication for both -- as long
    as neither job can be skipped on a tag (a skipped job counts as a pass) and neither one runs
    only after the other has passed (a scenario must not quietly depend on the suite's leftovers)."""
    import yaml

    release = yaml.safe_load(_WORKFLOW)["jobs"]
    assert release["tests"]["uses"] == "./.github/workflows/tests.yml"
    assert "tests" in release["publish"]["needs"]

    jobs = yaml.safe_load(_TESTS)["jobs"]
    stack_jobs = {
        name for name, job in jobs.items()
        if any("docker compose up -d --build" in step.get("run", "") for step in job.get("steps", []))
    }
    assert stack_jobs == {"integration", "scenarios"}
    for name in stack_jobs:
        assert "if" not in jobs[name], name
        assert jobs[name]["needs"] == "preflight", name
    scenario_runs = " ".join(step.get("run", "") for step in jobs["scenarios"]["steps"])
    for scenario_file in (
        "tests/test_transfer_admission_live.py",
        "tests/test_api_log_pull.py",
        "tests/test_vault_type_allowlist.py",
        "tests/test_auth_survives_cache_outage.py",
        "tests/test_login_throttle.py",
        "tests/test_device_sync_preflight_live.py",
    ):
        assert scenario_file in scenario_runs, scenario_file


def test_each_reusable_gate_checks_out_and_verifies_the_requested_sha():
    preflight = (_WORKFLOWS / "preflight.yml").read_text(encoding="utf-8")
    # Called by Tests on a candidate and inside a release, so it gates the published commit too.
    proxy_matrix = (_WORKFLOWS / "proxy-matrix.yml").read_text(encoding="utf-8")

    for workflow in (preflight, _TESTS, _SETUP, proxy_matrix):
        assert "expected_sha:" in workflow
        assert "ref: ${{ inputs.expected_sha || github.sha }}" in workflow
        assert "if: ${{ inputs.expected_sha != '' }}" in workflow
        assert 'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"' in workflow
        assert "persist-credentials: false" in workflow
    assert "expected_sha: ${{ inputs.expected_sha }}" in _TESTS
    assert "expected_sha: ${{ inputs.expected_sha }}" in _SETUP


def test_publication_is_serial_and_scan_auth_push_release_order_is_fail_closed():
    concurrency = _WORKFLOW.split("concurrency:", 1)[1].split("jobs:", 1)[0]
    publish = _job("publish")

    assert "group: release-publication-${{ github.repository }}" in concurrency
    assert "queue: max" in concurrency
    assert "cancel-in-progress: false" in concurrency
    assert ".github/workflows/release.yml:" in _ACTIONLINT
    assert 'unexpected key "queue" for "concurrency" section' in _ACTIONLINT
    assert publish.index("Fetch current release refs") < publish.index(
        "Validate publication inputs before build"
    )
    assert publish.index(
        "Refresh release refs immediately before authentication"
    ) < publish.index("Revalidate immediately before authentication")
    assert publish.count("release_gate.py") == 2
    # What reaches GHCR must be the staged index that was scanned, under every tag this run moves,
    # and nothing else: the copy is verified against the staging digest rather than trusted.
    assert 'test "$resolved_version" = "$staged_digest"' in publish
    assert 'test "$resolved_floating" = "$staged_digest"' in publish
    assert 'echo "digest=${resolved_version}" >> "$GITHUB_OUTPUT"' in publish
    assert "+refs/heads/main:refs/remotes/origin/main" in publish
    order = [
        publish.index("Validate publication inputs before build"),
        publish.index("Build every platform into the staging registry"),
        publish.index("Load each platform for scanning"),
        publish.index("Generate the SPDX SBOM (amd64)"),
        publish.index("Generate the SPDX SBOM (arm64)"),
        publish.index("Render the revision-bound scan VEX for each platform"),
        publish.index("Scan the exact staged image (amd64)"),
        publish.index("Scan the exact staged image (arm64)"),
        publish.index("Refresh release refs immediately before authentication"),
        publish.index("Revalidate immediately before authentication"),
        publish.index("Refuse to publish a finished release again"),
        publish.index("Log in to GHCR"),
        publish.index("Copy the scanned index to GHCR and resolve its digest"),
        publish.index("Verify every published platform is anonymously pullable"),
        publish.index("Bind release VEX to the published registry digest"),
        publish.index("Attest build provenance"),
        publish.index("Attest the SBOM (amd64)"),
        publish.index("Attest the SBOM (arm64)"),
        publish.index("Create GitHub Release"),
    ]
    assert order == sorted(order)
    assert 'anonymous_config="$(mktemp -d "$RUNNER_TEMP/docker-anon.XXXXXX")"' in publish
    assert "printf '%s\\n' '{\"auths\":{}}'" in publish
    assert (
        'DOCKER_CONFIG="$anonymous_config" docker pull --quiet "${IMAGE}@${manifest}"'
        in publish
    )
    assert "steps.publish_gate.outputs.version" in publish
    assert "steps.publish_gate.outputs.image" in publish
    assert "steps.publish_gate.outputs.tag" in publish


def test_validation_fetches_main_and_exports_one_immutable_identity():
    validate = _job("validate", "tests")

    assert "fetch-depth: 0" in validate
    assert "git fetch --no-tags --prune origin" in validate
    assert "+refs/heads/main:refs/remotes/origin/main" in validate
    assert "+refs/heads/release/*:refs/remotes/origin/release/*" in validate
    assert "+refs/tags/v*:refs/tags/v*" in validate
    assert "release_gate.py" in validate
    for name in ("version", "tag", "sha", "image"):
        assert f"{name}: ${{{{ steps.gate.outputs.{name} }}}}" in validate


@pytest.mark.parametrize(
    "raw",
    [
        b"\xef\xbb\xbf0.8.0\n",
        b"\xff0.8.0\n",
        b"0.8.0",
        b"0.8.0\r\n",
        b"0.8.0\n\n",
        b" 0.8.0\n",
        b"0.8.0\ntrailing",
    ],
)
def test_version_rejects_bom_invalid_utf8_and_extra_bytes(tmp_path, raw):
    version_file = tmp_path / "VERSION"
    version_file.write_bytes(raw)

    with pytest.raises(_GATE.ReleaseGateError):
        _GATE.read_canonical_version(version_file)


def test_version_accepts_only_canonical_x_y_z_plus_lf(tmp_path):
    version_file = tmp_path / "VERSION"
    version_file.write_bytes(b"12.34.567\n")

    assert _GATE.read_canonical_version(version_file) == "12.34.567"


@pytest.mark.parametrize(
    "ref",
    [
        "refs/heads/main",
        "v0.8.0",
        "refs/tags/0.8.0",
        "refs/tags/v0.8",
        "refs/tags/v0.8.0-rc1",
        "refs/tags/v0.8.0/extra",
        "refs/tags/v1x2x3",
    ],
)
def test_malformed_or_non_tag_refs_are_rejected(ref):
    with pytest.raises(_GATE.ReleaseGateError, match="exactly refs/tags"):
        _GATE.version_from_tag_ref(ref)


def test_tag_and_version_mismatch_is_rejected_before_git(tmp_path):
    (tmp_path / "VERSION").write_bytes(b"0.8.0\n")

    with pytest.raises(_GATE.ReleaseGateError, match="does not match"):
        _GATE.validate_release(
            tmp_path,
            ref="refs/tags/v0.8.1",
            event_sha="0" * 40,
            main_ref="refs/remotes/origin/main",
            repository_owner="DockVault",
        )


def test_valid_main_tag_resolves_one_immutable_version(tmp_path):
    repository = tmp_path / "valid"
    sha = _new_repository(repository)
    _git(repository, "tag", "-a", "v0.8.0", "-m", "release 0.8.0")

    metadata = _GATE.validate_release(
        repository,
        ref="refs/tags/v0.8.0",
        event_sha=sha,
        main_ref="refs/remotes/origin/main",
        repository_owner="DockVault",
    )

    assert metadata == _GATE.ReleaseMetadata(
        version="0.8.0",
        tag="v0.8.0",
        sha=sha,
        image="ghcr.io/dockvault/vault",
        channel="main",
        floating_tags=("latest", "v0.8"),
        make_latest=True,
        previous_tag="v0.7.0",
        notes_preamble="",
    )


def test_annotated_tag_object_resolves_to_the_same_immutable_commit(tmp_path):
    repository = tmp_path / "annotated"
    sha = _new_repository(repository)
    _git(repository, "tag", "-a", "v0.8.0", "-m", "annotated release")
    tag_object = _git(repository, "rev-parse", "refs/tags/v0.8.0")
    assert tag_object != sha

    metadata = _GATE.validate_release(
        repository,
        ref="refs/tags/v0.8.0",
        event_sha=tag_object,
        main_ref="refs/remotes/origin/main",
        repository_owner="DockVault",
    )

    assert metadata.sha == sha
    assert metadata.tag == "v0.8.0"


def test_tag_outside_main_is_rejected(tmp_path):
    repository = tmp_path / "outside-main"
    _new_repository(repository)
    _git(repository, "checkout", "-b", "feature")
    (repository / "payload.txt").write_text("feature\n", encoding="utf-8", newline="\n")
    _git(repository, "add", "payload.txt")
    _git(repository, "commit", "-m", "feature candidate")
    sha = _git(repository, "rev-parse", "HEAD")
    _git(repository, "tag", "v0.8.0")

    with pytest.raises(_GATE.ReleaseGateError, match="not an ancestor"):
        _GATE.validate_release(
            repository,
            ref="refs/tags/v0.8.0",
            event_sha=sha,
            main_ref="refs/remotes/origin/main",
            repository_owner="DockVault",
        )


def test_stale_or_different_event_sha_is_rejected(tmp_path):
    repository = tmp_path / "stale"
    first_sha = _new_repository(repository)
    _git(repository, "tag", "v0.8.0")
    (repository / "payload.txt").write_text("later\n", encoding="utf-8", newline="\n")
    _git(repository, "add", "payload.txt")
    _git(repository, "commit", "-m", "later main")

    with pytest.raises(_GATE.ReleaseGateError, match="one immutable commit"):
        _GATE.validate_release(
            repository,
            ref="refs/tags/v0.8.0",
            event_sha=first_sha,
            main_ref="refs/remotes/origin/main",
            repository_owner="DockVault",
        )


# --- releases from a maintenance line ------------------------------------------------------------
#
# A line `release/X.Y` serves an older minor once a newer one has shipped from main. The gate says
# which of the two a tag comes from and what the publication may move. Each scenario below is a real
# git history, because every rule is about ancestry.


def _two_lines(tmp_path: Path) -> _History:
    """0.1.0, 0.1.1 and 0.2.0 from main; release/0.1 cut at v0.1.1; 0.1.2 tagged on it."""
    history = _History(tmp_path / "lines")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.commit("0.2.0")
    history.branch_line("0.1", "0.1.1")
    history.commit("0.1.2", branch="release/0.1")
    history.push()
    return history


def test_a_maintenance_release_after_the_next_minor_ships_moves_only_its_line_tag(tmp_path):
    history = _two_lines(tmp_path)

    metadata = history.gate("0.1.2")

    assert metadata.channel == "line"
    assert metadata.floating_tags == ("v0.1",)
    assert metadata.make_latest is False
    assert metadata.previous_tag == "v0.1.1"
    assert metadata.notes_preamble == (
        "Maintenance release of the 0.1 line. The newest release is v0.2.0.")


def test_a_maintenance_release_before_the_next_minor_ships_is_refused(tmp_path):
    """Until a newer minor exists, the older line's patches come from main, which stays linear."""
    history = _History(tmp_path / "early")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.branch_line("0.1", "0.1.1")
    history.commit("0.1.2", branch="release/0.1")
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="only after a newer minor has been released"):
        history.gate("0.1.2")


def test_a_newer_minor_that_never_reached_main_does_not_open_a_line(tmp_path):
    history = _History(tmp_path / "side")
    history.commit("0.1.0")
    history.commit("0.1.1")
    _git(history.path, "checkout", "-q", "-b", "side")
    history.commit("0.2.0", branch="side")
    history.branch_line("0.1", "0.1.1")
    history.commit("0.1.2", branch="release/0.1")
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="only after a newer minor has been released"):
        history.gate("0.1.2")


@pytest.mark.parametrize("version", ["0.2.1", "0.0.9"])
def test_a_tag_of_another_line_on_a_maintenance_branch_is_refused(tmp_path, version):
    history = _two_lines(tmp_path)
    history.commit(version, branch="release/0.1", matrix={})
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="nor of the maintenance branch"):
        history.gate(version)


def test_a_line_cut_from_an_unreleased_main_commit_is_refused(tmp_path):
    history = _History(tmp_path / "unreleased-base")
    history.commit("0.1.0")
    history.commit("0.1.1")
    unreleased = history.commit("0.1.2", tag=False)
    history.commit("0.2.0")
    _git(history.path, "branch", "release/0.1", unreleased)
    history.commit("0.1.2", branch="release/0.1")
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="does not branch from a released 0.1 tag"):
        history.gate("0.1.2")


def test_a_line_cut_from_another_lines_release_is_refused(tmp_path):
    """release/0.1 must start at a 0.1 release: cut from v0.2.0, it would carry 0.2 into 0.1."""
    history = _History(tmp_path / "wrong-base")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.commit("0.2.0")
    history.branch_line("0.1", "0.2.0")
    history.commit("0.1.2", branch="release/0.1", matrix={})
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="does not branch from a released 0.1 tag"):
        history.gate("0.1.2")


def test_a_lower_version_tagged_on_main_is_refused(tmp_path):
    history = _History(tmp_path / "backwards")
    history.commit("0.1.0")
    history.commit("0.2.0")
    history.commit("0.1.5", matrix={})
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="is below v0.2.0"):
        history.gate("0.1.5")


def test_a_lower_version_tagged_on_a_line_after_a_higher_one_is_refused(tmp_path):
    history = _two_lines(tmp_path)
    _git(history.path, "tag", "-d", "v0.1.2")
    del history.released["0.1.2"]
    history.commit("0.1.3", branch="release/0.1")
    history.commit("0.1.2", branch="release/0.1", matrix={})
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="is below v0.1.3"):
        history.gate("0.1.2")


def test_a_tag_on_both_main_and_a_line_is_a_main_release(tmp_path):
    """release/X.Y is cut from a tag on main, and that tag stays a main release."""
    history = _History(tmp_path / "both")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.branch_line("0.1", "0.1.1")
    history.push()

    metadata = history.gate("0.1.1")

    assert metadata.channel == "main"
    assert metadata.floating_tags == ("latest", "v0.1")
    assert metadata.make_latest is True
    assert metadata.previous_tag == "v0.1.0"
    assert metadata.notes_preamble == ""


def test_two_releases_cut_the_same_day_each_keep_their_own_moving_tags(tmp_path):
    """The older of a same-day pair is checked again just before it authenticates, by which time
    the newer one is already tagged on top of it and queued behind this run. It must still publish,
    and it must leave `latest` to the newer one. Its own matrix cannot know the newer release."""
    history = _History(tmp_path / "pair")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.commit("0.2.0")
    history.push()

    older = history.gate("0.1.1")
    newer = history.gate("0.2.0")

    assert (older.channel, older.floating_tags, older.make_latest, older.previous_tag) == (
        "main", ("v0.1",), False, "v0.1.0")
    assert (newer.channel, newer.floating_tags, newer.make_latest, newer.previous_tag) == (
        "main", ("latest", "v0.2"), True, "v0.1.1")


def test_an_older_release_re_run_after_its_successor_moves_no_tag(tmp_path):
    """Re-running a release whose successor on the same line is already tagged on top of it
    republishes only its own version tag: the line tag and `latest` belong to newer releases. The
    gate cannot tell this from the first run of the older of a same-day pair, so it accepts both;
    a re-run of a release that finished is stopped by the publish step, which finds its GitHub
    Release (see test_a_finished_release_is_not_published_again)."""
    history = _two_lines(tmp_path)
    history.commit("0.1.3", branch="release/0.1")
    history.push()

    metadata = history.gate("0.1.2")

    assert metadata.channel == "line"
    assert metadata.floating_tags == ()
    assert metadata.make_latest is False
    assert metadata.previous_tag == "v0.1.1"


def test_a_released_tag_missing_from_the_matrix_is_refused(tmp_path):
    """Every release, on any line, must be declared in the matrix a release publishes."""
    history = _two_lines(tmp_path)
    stale = _matrix({v: d for v, d in {**history.released, "0.2.1": "2026-01-09"}.items()
                     if v != "0.1.2"})
    history.commit("0.2.1", matrix=stale)
    history.push()

    with pytest.raises(_GATE.ReleaseGateError,
                       match=r"no entry for the released version\(s\) 0\.1\.2"):
        history.gate("0.2.1")


def test_a_release_whose_matrix_declares_every_release_passes(tmp_path):
    history = _two_lines(tmp_path)
    history.commit("0.2.1")
    history.push()

    metadata = history.gate("0.2.1")

    assert metadata.floating_tags == ("latest", "v0.2")
    assert metadata.previous_tag == "v0.2.0"


def test_main_one_matrix_only_commit_past_the_last_tag_is_accepted(tmp_path):
    """After a release on an older line, main gets a commit that only syncs the matrix. The gate
    checks ancestry, not that main's tip is tagged, so both lines still publish and re-run."""
    history = _two_lines(tmp_path)
    history.matrix_only_commit("main")
    history.push()

    rerun = history.gate("0.2.0")
    assert rerun.channel == "main"
    # The notes compare against the release this one was built on, not the higher-numbered 0.1.2,
    # which is on another line.
    assert rerun.previous_tag == "v0.1.1"
    assert history.gate("0.1.2").channel == "line"

    history.commit("0.2.1")
    history.push()
    metadata = history.gate("0.2.1")
    assert metadata.floating_tags == ("latest", "v0.2")
    assert metadata.previous_tag == "v0.2.0"


def test_tags_not_named_like_a_release_take_no_part(tmp_path):
    history = _History(tmp_path / "odd-tags")
    history.commit("0.1.0")
    history.commit("0.1.1")
    _git(history.path, "tag", "v0.9")
    _git(history.path, "tag", "v9.9.9-rc1")
    _git(history.path, "tag", "v09.1.1")
    history.push()

    metadata = history.gate("0.1.1")

    assert metadata.floating_tags == ("latest", "v0.1")


def test_an_unresolvable_main_ref_is_an_error(tmp_path):
    history = _History(tmp_path / "no-main")
    history.commit("0.1.0")

    with pytest.raises(_GATE.ReleaseGateError, match="cannot resolve"):
        history.gate("0.1.0")


def test_the_gate_writes_where_the_release_goes(tmp_path):
    output = tmp_path / "out"
    _GATE.write_github_outputs(output, _GATE.ReleaseMetadata(
        version="0.1.2", tag="v0.1.2", sha="a" * 40, image="ghcr.io/dockvault/vault",
        channel="line", floating_tags=("v0.1",), make_latest=False, previous_tag="v0.1.1",
        notes_preamble="Maintenance release of the 0.1 line. The newest release is v0.2.0."))
    written = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())

    assert written["channel"] == "line"
    assert written["floating_tags"] == "v0.1"
    assert written["make_latest"] == "false"
    assert written["previous_tag"] == "v0.1.1"
    assert written["notes_preamble"].startswith("Maintenance release of the 0.1 line.")

    output.unlink()
    _GATE.write_github_outputs(output, _GATE.ReleaseMetadata(
        version="0.2.0", tag="v0.2.0", sha="a" * 40, image="ghcr.io/dockvault/vault",
        floating_tags=("latest", "v0.2"), make_latest=True))
    written = dict(line.split("=", 1) for line in output.read_text(encoding="utf-8").splitlines())
    assert written["floating_tags"] == "latest v0.2"
    assert written["make_latest"] == "true"


@pytest.mark.parametrize("until, warned", [
    ("2026-06-30", True),
    ("2026-07-01", False),
    ("2026-12-31", False),
    (None, False),
])
def test_a_release_past_its_line_support_date_is_warned_about_not_refused(until, warned):
    data = {"lines": {"0.33": {"security_fixes_until": until}}}

    warning = _GATE.line_support_warning(data, "0.33.4", datetime.date(2026, 7, 1))

    assert (warning is not None) is warned
    if warned:
        assert "0.33" in warning and until in warning


def test_a_matrix_without_support_periods_gives_no_support_warning():
    assert _GATE.line_support_warning({}, "0.33.4", datetime.date(2030, 1, 1)) is None
    assert _GATE.line_support_warning(
        {"lines": {"0.34": {"security_fixes_until": "2026-01-01"}}}, "0.33.4",
        datetime.date(2030, 1, 1)) is None


def test_a_fix_on_two_lines_publishes_in_the_prescribed_order(tmp_path):
    """The older line is tagged first, the newest line last, and both runs queue. When the older
    one is checked again just before it publishes, the newer tag already exists and is missing from
    the older release's matrix, which was written before it. That must not stop it."""
    history = _History(tmp_path / "two-line-fix")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.commit("0.2.0")
    history.branch_line("0.1", "0.1.1")
    history.commit("0.1.2", branch="release/0.1")
    history.commit("0.2.1")
    history.push()

    older = history.gate("0.1.2")
    newer = history.gate("0.2.1")

    assert (older.channel, older.floating_tags, older.make_latest) == ("line", ("v0.1",), False)
    assert older.notes_preamble.endswith("The newest release is v0.2.1.")
    assert (newer.channel, newer.floating_tags, newer.make_latest) == (
        "main", ("latest", "v0.2"), True)


def test_a_release_tagged_after_this_one_need_not_be_in_its_matrix(tmp_path):
    """A main release is still running when a fix only the older line needs is tagged there."""
    history = _History(tmp_path / "tagged-meanwhile")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.commit("0.2.0")
    history.branch_line("0.1", "0.1.1")
    history.commit("0.2.1")
    history.commit("0.1.2", branch="release/0.1")
    history.push()

    assert history.gate("0.2.1").floating_tags == ("latest", "v0.2")


def test_the_older_of_a_pair_tagged_second_still_publishes(tmp_path):
    """Pushed in the other order: the newer release is tagged first. The older one's matrix still
    cannot know it, because the newer release is built on top of the older one."""
    history = _History(tmp_path / "pair-reversed")
    history.commit("0.1.0")
    history.commit("0.1.1", tag=False)
    history.commit("0.2.0")
    _git(history.path, "checkout", "-q", "main~1")
    history.tag("0.1.1", annotated=True)
    history.push()

    metadata = history.gate("0.1.1")

    assert metadata.floating_tags == ("v0.1",)
    assert metadata.make_latest is False


def test_a_lightweight_release_tag_is_refused(tmp_path):
    """A lightweight tag records no time of its own, and the gate orders releases cut the same day
    by when each was tagged."""
    repository = tmp_path / "lightweight"
    sha = _new_repository(repository)
    _git(repository, "tag", "v0.8.0")

    with pytest.raises(_GATE.ReleaseGateError) as refused:
        _GATE.validate_release(
            repository,
            ref="refs/tags/v0.8.0",
            event_sha=sha,
            main_ref="refs/remotes/origin/main",
            repository_owner="DockVault",
        )

    assert "v0.8.0 does not record when it was tagged" in str(refused.value)
    assert "git tag -a v0.8.0" in str(refused.value)


def _newest_line_committed_first(tmp_path, *, newest_annotated: bool) -> _History:
    """A fix on two lines where the newest line's release commit was made before the older line's,
    but, as prescribed, the older line was tagged first and the newest last. The newest release's
    matrix declares the older one, as its release commit must."""
    history = _History(tmp_path / f"committed-first-{newest_annotated}")
    history.commit("0.1.0")
    history.commit("0.1.1")
    history.commit("0.2.0")
    history.branch_line("0.1", "0.1.1")
    history.commit("0.2.1", tag=False, matrix=_matrix(
        {**history.released, "0.1.2": "2026-01-04", "0.2.1": "2026-01-05"}))
    history.commit("0.1.2", branch="release/0.1")
    _git(history.path, "checkout", "-q", "main")
    history.tag("0.2.1", annotated=newest_annotated)
    history.push()
    return history


def test_tags_order_a_pair_by_when_they_were_tagged_not_when_their_commits_were_made(tmp_path):
    history = _newest_line_committed_first(tmp_path, newest_annotated=True)

    older = history.gate("0.1.2")

    assert (older.channel, older.floating_tags, older.make_latest) == ("line", ("v0.1",), False)
    assert history.gate("0.2.1").floating_tags == ("latest", "v0.2")


def test_a_lightweight_tag_never_counts_as_tagged_later(tmp_path):
    """Its date is its commit's, which here is older than the older line's tag, though the tag itself
    came later. The gate cannot tell, so it holds the older release to the rule and says why."""
    history = _newest_line_committed_first(tmp_path, newest_annotated=False)

    with pytest.raises(_GATE.ReleaseGateError) as refused:
        history.gate("0.1.2")
    assert "no entry for the released version(s) 0.2.1" in str(refused.value)
    assert ("v0.2.1: a lightweight tag does not record when it was made, so it cannot count as "
            "tagged after this one; release tags must be annotated") in str(refused.value)

    with pytest.raises(_GATE.ReleaseGateError, match="v0.2.1 does not record when it was tagged"):
        history.gate("0.2.1")


def test_a_higher_tag_on_the_same_commit_is_not_a_release_built_on_it(tmp_path):
    history = _History(tmp_path / "same-commit")
    history.commit("0.1.0")
    history.commit("0.1.1")
    _git(history.path, "tag", "v0.2.0")
    history.push()

    with pytest.raises(_GATE.ReleaseGateError, match="is below v0.2.0"):
        history.gate("0.1.1")


# --- publication of a release from either line ---------------------------------------------------


def _step_text(job: str, name: str) -> str:
    """One step of a job, from its name to the next step (exactly once)."""
    assert job.count(f"- name: {name}\n") == 1, name
    body = job.split(f"- name: {name}\n", 1)[1]
    return body.split("\n      - ", 1)[0]


@pytest.mark.parametrize("step", [
    "Fetch current release refs",
    "Refresh release refs immediately before authentication",
])
def test_every_gate_run_sees_the_maintenance_branches_and_every_release_tag(step):
    """The gate places a tag on main or on release/X.Y and against every other release, so each of
    its runs needs those refs as they are at that moment -- not main and this one tag only."""
    text = _step_text(_job("publish"), step)

    assert "--no-tags --prune origin" in text
    assert '"+refs/heads/main:refs/remotes/origin/main"' in text
    assert '"+refs/heads/release/*:refs/remotes/origin/release/*"' in text
    assert '"+refs/tags/v*:refs/tags/v*"' in text
    assert "EXPECTED_TAG" not in text


def test_the_moving_tags_come_from_the_gate_just_before_authentication():
    publish = _job("publish")
    push = _step_text(publish, "Copy the scanned index to GHCR and resolve its digest")

    # Only what the last gate run decided: a release tagged on top of this one while it was being
    # tested owns `latest` and the line tag by then.
    assert "FLOATING_TAGS: ${{ steps.auth_gate.outputs.floating_tags }}" in push
    assert "outputs.floating_tags" not in publish.replace(
        "steps.auth_gate.outputs.floating_tags", "")
    # No moving tag is written by name: `latest` is one of the gate's answers, not a constant.
    assert ":latest" not in push
    assert 'tag_args=(--tag "${IMAGE}:${TAG}")' in push
    assert 'tag_args+=(--tag "${IMAGE}:${floating}")' in push
    assert 'docker buildx imagetools create "${tag_args[@]}" "${STAGING_IMAGE}:${TAG}"' in push
    # Each moving tag is checked against what the registry holds before the copy, and against the
    # staged digest after it.
    assert "refusing to move it backwards" in push
    assert push.index("refusing to move it backwards") < push.index("imagetools create")
    assert '"org.opencontainers.image.version"' in push
    assert "sort -V" in push
    assert 'test "$resolved_floating" = "$staged_digest"' in push
    assert push.index("imagetools create") < push.index('test "$resolved_floating"')
    # A name the gate did not mean is refused rather than pushed.
    assert r"^(latest|v[0-9]+\.[0-9]+)$" in push


def test_github_is_told_which_release_is_latest_and_what_to_compare_against():
    release = _step_text(_job("publish"), "Create GitHub Release")

    assert "generate_release_notes: true" in release
    assert "make_latest: ${{ steps.auth_gate.outputs.make_latest }}" in release
    assert "previous_tag: ${{ steps.auth_gate.outputs.previous_tag }}" in release
    assert "body: ${{ steps.auth_gate.outputs.notes_preamble }}" in release


# The publish step's moving-tag checks are shell, and a pin on their text cannot tell a working
# comparison from a disabled one, so the step itself runs here against a stand-in `docker` that
# answers what a registry would.
_DOCKER_STUB = r"""#!/usr/bin/env bash
echo "docker $*" >> "$STUB_LOG"
if [ "$3" = "inspect" ]; then
  ref="$4"; fmt="$6"; name="${ref##*:}"; name="${name//./_}"
  case "$fmt" in
    *Labels*)
      var="LABEL_${name}"
      case "${!var:-}" in
        NOTFOUND) echo "ERROR: ${ref}: not found" >&2; exit 1 ;;
        BROKEN) echo "ERROR: unexpected status from GET request: 500" >&2; exit 1 ;;
      esac
      printf '%s' "${!var:-}" ;;
    *Digest*)
      var="DIGEST_${name}"
      echo "\"${!var:-sha256:staged}\"" ;;
  esac
fi
exit 0
"""


def _bash() -> str | None:
    """A bash that runs POSIX scripts: Git's own on Windows (whatever `bash` resolves to there may
    be the WSL launcher), the system one elsewhere."""
    if sys.platform == "win32":
        git = shutil.which("git")
        if git is not None:
            # git.exe is in Git\cmd or Git\mingw64\bin; bash.exe is in Git\bin.
            for folder in list(Path(git).resolve().parents)[:3]:
                candidate = folder / "bin" / "bash.exe"
                if candidate.is_file():
                    return str(candidate)
        return None
    return shutil.which("bash")


def _run_push_step(tmp_path: Path, floating: str, **registry: str):
    bash = _bash()
    if bash is None:
        if os.environ.get("CI"):
            pytest.fail("no bash to run the publish step with; this check would silently not run")
        pytest.skip("no bash on this machine")
    import yaml

    steps = yaml.safe_load(_WORKFLOW)["jobs"]["publish"]["steps"]
    (script,) = [s["run"] for s in steps if s.get("id") == "push"]
    (tmp_path / "push.sh").write_text(script, encoding="utf-8", newline="\n")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "docker").write_text(_DOCKER_STUB, encoding="utf-8", newline="\n")
    (stub_dir / "docker").chmod(0o755)
    env = {
        **os.environ,
        "STUB_BIN": str(stub_dir),
        "STUB_LOG": str(tmp_path / "docker.log"),
        "IMAGE": "ghcr.io/dockvault/vault",
        "TAG": "v0.34.0",
        "VERSION": "0.34.0",
        "STAGING_IMAGE": "localhost:5000/dockvault/vault",
        "GITHUB_OUTPUT": str(tmp_path / "output"),
        "RUNNER_TEMP": str(tmp_path),
        "FLOATING_TAGS": floating,
        **registry,
    }
    (tmp_path / "docker.log").write_text("", encoding="utf-8")
    run = subprocess.run(
        [bash, "-c",
         'PATH="$( (cygpath -u "$STUB_BIN") 2>/dev/null || printf %s "$STUB_BIN"):$PATH"; '
         '. "$1"', "push-step", str(tmp_path / "push.sh")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    calls = (tmp_path / "docker.log").read_text(encoding="utf-8").splitlines()
    created = [c.split(" create ", 1)[1] for c in calls if " imagetools create " in c]
    return run, created


def test_a_release_moves_every_tag_the_gate_named_and_checks_each_one(tmp_path):
    run, created = _run_push_step(tmp_path, "latest v0.34",
                                  LABEL_latest="0.33.2", LABEL_v0_34="NOTFOUND")

    assert run.returncode == 0, run.stdout + run.stderr
    assert created == [
        "--tag ghcr.io/dockvault/vault:v0.34.0 --tag ghcr.io/dockvault/vault:latest "
        "--tag ghcr.io/dockvault/vault:v0.34 localhost:5000/dockvault/vault:v0.34.0"]
    assert (tmp_path / "output").read_text(encoding="utf-8") == "digest=sha256:staged\n"


def test_a_release_the_gate_gave_no_moving_tag_moves_only_its_own(tmp_path):
    run, created = _run_push_step(tmp_path, "")

    assert run.returncode == 0, run.stdout + run.stderr
    assert created == [
        "--tag ghcr.io/dockvault/vault:v0.34.0 localhost:5000/dockvault/vault:v0.34.0"]


@pytest.mark.parametrize("current", ["0.34.0", "0.33.9", "0.9.99"])
def test_a_moving_tag_may_stay_or_go_forward(tmp_path, current):
    run, created = _run_push_step(tmp_path, "latest", LABEL_latest=current)

    assert run.returncode == 0, run.stdout + run.stderr
    assert len(created) == 1


@pytest.mark.parametrize("current", ["0.34.1", "0.35.0", "1.0.0"])
def test_a_moving_tag_is_never_moved_backwards(tmp_path, current):
    """Version order, not text order: 0.9.x sorts after 0.10.x as text."""
    run, created = _run_push_step(tmp_path, "latest", LABEL_latest=current)

    assert run.returncode != 0
    assert created == []
    assert f"holds {current}, above 0.34.0; refusing to move it backwards" in run.stdout


def test_a_moving_tag_below_the_release_in_version_order_but_not_in_text_order(tmp_path):
    run, created = _run_push_step(tmp_path, "latest", LABEL_latest="0.10.0", VERSION="0.9.0")

    assert run.returncode != 0
    assert created == []


def test_a_registry_that_cannot_say_what_a_tag_holds_stops_the_release(tmp_path):
    run, created = _run_push_step(tmp_path, "latest", LABEL_latest="BROKEN")

    assert run.returncode != 0
    assert created == []
    assert "cannot read what ghcr.io/dockvault/vault:latest holds now" in run.stdout


def test_a_moving_tag_the_gate_did_not_mean_is_refused(tmp_path):
    run, created = _run_push_step(tmp_path, "latest;touch")

    assert run.returncode != 0
    assert created == []
    assert "unexpected moving tag" in run.stdout


def test_a_moving_tag_that_names_another_image_after_the_copy_fails_the_release(tmp_path):
    run, created = _run_push_step(tmp_path, "v0.34", LABEL_v0_34="0.34.0",
                                  DIGEST_v0_34="sha256:elsewhere")

    assert run.returncode != 0
    assert len(created) == 1
    assert "resolves to sha256:elsewhere, not sha256:staged" in run.stdout
    assert not (tmp_path / "output").exists()


# The GitHub Release is the last thing a publication makes, so the step before authentication reads
# it to tell a finished release from one that is running for the first time or after a failure. The
# step runs here against a stand-in `gh` that answers what GitHub would.
_GH_STUB = r"""#!/usr/bin/env bash
echo "gh $*" >> "$STUB_LOG"
case "$GH_ANSWER" in
  exists) echo '{"tagName":"v0.34.0"}' ;;
  missing) echo "release not found" >&2; exit 1 ;;
  broken) echo "HTTP 502: Bad Gateway (https://api.github.com/graphql)" >&2; exit 1 ;;
  no-repo) echo "HTTP 404: Not Found (https://api.github.com/repos/DockVault/vault/releases/tags/v0.34.0)" >&2; exit 1 ;;
esac
"""


def _run_release_check(tmp_path: Path, answer: str):
    bash = _bash()
    if bash is None:
        if os.environ.get("CI"):
            pytest.fail("no bash to run the publish step with; this check would silently not run")
        pytest.skip("no bash on this machine")
    import yaml

    steps = yaml.safe_load(_WORKFLOW)["jobs"]["publish"]["steps"]
    (step,) = [s for s in steps if s.get("id") == "not_published"]
    (tmp_path / "check.sh").write_text(step["run"], encoding="utf-8", newline="\n")
    stub_dir = tmp_path / "bin"
    stub_dir.mkdir()
    (stub_dir / "gh").write_text(_GH_STUB, encoding="utf-8", newline="\n")
    (stub_dir / "gh").chmod(0o755)
    (tmp_path / "gh.log").write_text("", encoding="utf-8")
    env = {
        **os.environ,
        "STUB_BIN": str(stub_dir),
        "STUB_LOG": str(tmp_path / "gh.log"),
        "GH_ANSWER": answer,
        "TAG": "v0.34.0",
        "GITHUB_REPOSITORY": "DockVault/vault",
        "RUNNER_TEMP": str(tmp_path),
    }
    run = subprocess.run(
        [bash, "-c",
         'PATH="$( (cygpath -u "$STUB_BIN") 2>/dev/null || printf %s "$STUB_BIN"):$PATH"; '
         '. "$1"', "check-step", str(tmp_path / "check.sh")],
        cwd=tmp_path, env=env, capture_output=True, text=True, timeout=60)
    return run, (tmp_path / "gh.log").read_text(encoding="utf-8").splitlines()


def test_the_finished_release_check_runs_before_authentication_on_this_releases_tag():
    import yaml

    steps = yaml.safe_load(_WORKFLOW)["jobs"]["publish"]["steps"]
    names = [s.get("name") for s in steps]
    (step,) = [s for s in steps if s.get("id") == "not_published"]
    assert names.index(step["name"]) == names.index("Revalidate immediately before authentication") + 1
    assert names.index(step["name"]) + 1 == names.index("Log in to GHCR")
    assert step["env"]["TAG"] == "${{ steps.publish_gate.outputs.tag }}"
    assert step["env"]["GH_TOKEN"] == "${{ github.token }}"
    # Its answer rests on the GitHub Release being the last thing a publication makes.
    assert names[-1] == "Create GitHub Release"


def test_a_first_run_goes_on(tmp_path):
    run, calls = _run_release_check(tmp_path, "missing")

    assert run.returncode == 0, run.stdout + run.stderr
    assert calls == ["gh release view v0.34.0 --repo DockVault/vault --json tagName"]


def test_a_finished_release_is_not_published_again(tmp_path):
    run, calls = _run_release_check(tmp_path, "exists")

    assert run.returncode != 0
    assert len(calls) == 1
    assert "the GitHub Release v0.34.0 exists, so v0.34.0 has already been published" in run.stdout
    assert "delete the release (not the tag) and re-run" in run.stdout
    assert "cannot tell" not in run.stdout, "stopped as finished, not as unknown"


@pytest.mark.parametrize("answer, shown", [
    ("broken", "HTTP 502"),
    # "Not Found" about the repository is not "release not found": it says nothing of the release.
    ("no-repo", "HTTP 404: Not Found"),
])
def test_not_knowing_whether_a_release_is_out_stops_the_publication(tmp_path, answer, shown):
    run, calls = _run_release_check(tmp_path, answer)

    assert run.returncode != 0
    assert "cannot tell whether v0.34.0 has already been published" in run.stdout
    assert shown in run.stdout
