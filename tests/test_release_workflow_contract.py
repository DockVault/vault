"""Offline contracts for main-only publication of one fully tested commit."""

from __future__ import annotations

import importlib.util
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


def _git(repository: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=repository,
        check=True,
        capture_output=True,
        text=True,
        timeout=30,
    )
    return result.stdout.strip()


def _new_repository(path: Path) -> str:
    path.mkdir()
    _git(path, "init", "-b", "main")
    _git(path, "config", "user.name", "Release Contract")
    _git(path, "config", "user.email", "release-contract@example.invalid")
    _git(path, "config", "commit.gpgsign", "false")
    (path / "VERSION").write_bytes(b"0.8.0\n")
    (path / "payload.txt").write_text("main\n", encoding="utf-8", newline="\n")
    _git(path, "add", "VERSION", "payload.txt")
    _git(path, "commit", "-m", "main candidate")
    sha = _git(path, "rev-parse", "HEAD")
    _git(path, "update-ref", "refs/remotes/origin/main", sha)
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


def test_each_reusable_gate_checks_out_and_verifies_the_requested_sha():
    preflight = (_WORKFLOWS / "preflight.yml").read_text(encoding="utf-8")

    for workflow in (preflight, _TESTS, _SETUP):
        assert "expected_sha:" in workflow
        assert "ref: ${{ inputs.expected_sha || github.sha }}" in workflow
        assert "if: ${{ inputs.expected_sha != '' }}" in workflow
        assert 'test "$(git rev-parse HEAD)" = "$EXPECTED_SHA"' in workflow
        assert "persist-credentials: false" in workflow
    assert "expected_sha: ${{ inputs.expected_sha }}" in _TESTS
    assert "expected_sha: ${{ inputs.expected_sha }}" in _SETUP


def test_publication_is_serial_and_login_push_release_order_is_fail_closed():
    concurrency = _WORKFLOW.split("concurrency:", 1)[1].split("jobs:", 1)[0]
    publish = _job("publish")

    assert "group: release-publication-${{ github.repository }}" in concurrency
    assert "queue: max" in concurrency
    assert "cancel-in-progress: false" in concurrency
    assert ".github/workflows/release.yml:" in _ACTIONLINT
    assert 'unexpected key "queue" for "concurrency" section' in _ACTIONLINT
    assert publish.index("Fetch current release refs") < publish.index(
        "Revalidate immediately before authentication"
    )
    assert publish.count("release_gate.py") == 1
    assert "+refs/heads/main:refs/remotes/origin/main" in publish
    assert "+refs/tags/${EXPECTED_TAG}:refs/tags/${EXPECTED_TAG}" in publish
    assert publish.index("Revalidate immediately before authentication") < publish.index(
        "Log in to GHCR"
    )
    assert publish.index("Log in to GHCR") < publish.index("Build and push image")
    assert publish.index("Build and push image") < publish.index("Create GitHub Release")
    assert "steps.publish_gate.outputs.version" in publish
    assert "steps.publish_gate.outputs.image" in publish
    assert "steps.publish_gate.outputs.tag" in publish


def test_validation_fetches_main_and_exports_one_immutable_identity():
    validate = _job("validate", "tests")

    assert "fetch-depth: 0" in validate
    assert "git fetch --no-tags --prune origin" in validate
    assert "+refs/heads/main:refs/remotes/origin/main" in validate
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
    _git(repository, "tag", "v0.8.0")

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
