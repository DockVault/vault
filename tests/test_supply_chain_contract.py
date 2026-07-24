"""Offline contracts for reproducible images and release evidence."""

from __future__ import annotations

import hashlib
import importlib.util
import json
import re
import sys
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_DOCKERFILE = (_ROOT / "Dockerfile").read_text(encoding="utf-8")
_PREFLIGHT = (_ROOT / ".github" / "workflows" / "preflight.yml").read_text(
    encoding="utf-8"
)
_RELEASE = (_ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
_DEPENDABOT = (_ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8")
_RENDERER_SCRIPT = _ROOT / ".github" / "scripts" / "render_release_vex.py"
_RENDERER_SPEC = importlib.util.spec_from_file_location(
    "render_release_vex", _RENDERER_SCRIPT
)
assert _RENDERER_SPEC and _RENDERER_SPEC.loader
_RENDERER = importlib.util.module_from_spec(_RENDERER_SPEC)
sys.modules[_RENDERER_SPEC.name] = _RENDERER
_RENDERER_SPEC.loader.exec_module(_RENDERER)
_PUSH_DIGEST_SCRIPT = _ROOT / ".github" / "scripts" / "release_push_digest.py"
_PUSH_DIGEST_SPEC = importlib.util.spec_from_file_location(
    "release_push_digest", _PUSH_DIGEST_SCRIPT
)
assert _PUSH_DIGEST_SPEC and _PUSH_DIGEST_SPEC.loader
_PUSH_DIGEST = importlib.util.module_from_spec(_PUSH_DIGEST_SPEC)
sys.modules[_PUSH_DIGEST_SPEC.name] = _PUSH_DIGEST
_PUSH_DIGEST_SPEC.loader.exec_module(_PUSH_DIGEST)

_PYTHON_DIGEST = (
    "python:3.14-alpine@"
    "sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92"
)
_POSTGRES_DIGEST = (
    "postgres:15-alpine@"
    "sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"
)
_REDIS_DIGEST = (
    "redis:7-alpine@"
    "sha256:6ab0b6e7381779332f97b8ca76193e45b0756f38d4c0dcda72dbb3c32061ab99"
)
_CPYTHON_SNAPSHOT = "07efb08123ba9367a7107325adb9d5626dca1ca9"
_BACKPORT_HASHES = {
    Path("security/cpython-backports/Lib/tarfile.py"): (
        "3c8d585a77d7d376aea66e5e11a4d53c2605100d4c05a71b5385ed54bc526f51"
    ),
    Path("security/cpython-backports/Lib/html/parser.py"): (
        "5c5ed245889135564e75dfed9a47aeb6b4d3e5a2e9614d918a986767e3747539"
    ),
    Path("security/cpython-backports/PSF-LICENSE.txt"): (
        "b0e25a78cffb43f4d92de8b61ccfa1f1f98ecbc22330b54b5251e7b6ba010231"
    ),
}


def _publish_job() -> str:
    return _RELEASE.split("  publish:", 1)[1]


def test_runtime_and_sidecars_use_reviewed_manifest_list_digests():
    assert _DOCKERFILE.startswith(f"FROM {_PYTHON_DIGEST}\n")

    for compose_name in ("docker-compose.yml", "docker-compose.secure.yml"):
        compose = (_ROOT / "deploy" / compose_name).read_text(encoding="utf-8")
        assert compose.count(f"image: {_POSTGRES_DIGEST}") == 1
        assert compose.count(f"image: {_REDIS_DIGEST}") == 1
        assert not re.search(
            r"^\s+image: (?:postgres|redis):[^@\n]+$", compose, re.MULTILINE
        )


def test_image_installs_only_the_hash_locked_production_environment():
    assert "COPY requirements.lock ." in _DOCKERFILE
    assert (
        "pip install --no-cache-dir --require-hashes -r requirements.lock"
        in _DOCKERFILE
    )
    assert "&& pip check" in _DOCKERFILE
    assert "python -m pip uninstall --yes pip" in _DOCKERFILE
    assert "adduser -D -u 10001 appuser" in _DOCKERFILE
    assert "COPY requirements.txt ." not in _DOCKERFILE
    assert "apt-get" not in _DOCKERFILE
    assert "curl" not in _DOCKERFILE


def test_cpython_security_backports_are_exact_and_verified_during_build():
    readme = (_ROOT / "security" / "cpython-backports" / "README.md").read_text(
        encoding="utf-8"
    )
    for relative_path, expected_hash in _BACKPORT_HASHES.items():
        payload = (_ROOT / relative_path).read_bytes()
        assert hashlib.sha256(payload).hexdigest() == expected_hash
        assert expected_hash in _DOCKERFILE
        assert expected_hash in readme

    assert _CPYTHON_SNAPSHOT in readme
    assert "COPY security/cpython-backports /tmp/cpython-backports" in _DOCKERFILE
    assert "cp Lib/tarfile.py /usr/local/lib/python3.14/tarfile.py" in _DOCKERFILE
    assert (
        "cp Lib/html/parser.py /usr/local/lib/python3.14/html/parser.py" in _DOCKERFILE
    )
    assert (
        "cp PSF-LICENSE.txt /usr/share/licenses/cpython-backports/PSF-LICENSE.txt"
    ) in _DOCKERFILE
    for cve, upstream_commit in (
        ("CVE-2026-11940", "79c06bd5c6afa3c440d50faf7ee1b147c8832b4c"),
        ("CVE-2026-11972", "e86666c9dd256d52d0fbef6feb1ea4a51768fdec"),
        ("CVE-2026-15308", _CPYTHON_SNAPSHOT),
    ):
        assert cve in readme
        assert upstream_commit in readme


def test_production_lock_is_fully_pinned_and_hashed():
    source = (_ROOT / "requirements.txt").read_text(encoding="utf-8")
    lock = (_ROOT / "requirements.lock").read_text(encoding="utf-8")

    direct = [
        line.strip()
        for line in source.splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    ]
    assert direct
    assert all(
        re.match(r"^[A-Za-z0-9_.-]+(?:\[[A-Za-z0-9_,.-]+\])?==[^=\s]+$", line)
        for line in direct
    )
    assert "autogenerated by pip-compile with Python 3.14" in lock
    assert (
        "python -m piptools compile --generate-hashes --strip-extras "
        "--output-file requirements.lock requirements.txt"
    ) in lock

    requirement_blocks = [
        block
        for block in re.split(r"(?m)(?=^[A-Za-z0-9])", lock)
        if re.match(r"^[A-Za-z0-9_.-]+==", block)
    ]
    assert requirement_blocks
    for block in requirement_blocks:
        assert re.match(r"^[A-Za-z0-9_.-]+==[^\s\\]+", block)
        assert re.search(r"--hash=sha256:[0-9a-f]{64}", block)


def test_preflight_reproduces_installs_checks_and_audits_the_lock():
    expected_command = (
        "python -m piptools compile --generate-hashes --strip-extras "
        "--output-file requirements.lock requirements.txt"
    )
    assert _PREFLIGHT.count(expected_command) == 1
    order = [
        _PREFLIGHT.index(
            'cp requirements.lock "$RUNNER_TEMP/requirements.lock.checked"'
        ),
        _PREFLIGHT.index("rm requirements.lock"),
        _PREFLIGHT.index(expected_command),
        _PREFLIGHT.index(
            'cmp requirements.lock "$RUNNER_TEMP/requirements.lock.checked"'
        ),
    ]
    assert order == sorted(order)
    assert "git diff --exit-code -- requirements.lock" not in _PREFLIGHT
    assert "python -m pip install --require-hashes -r requirements.lock" in _PREFLIGHT
    assert "python -m pip check" in _PREFLIGHT
    assert "python -m pip_audit" in _PREFLIGHT
    assert "--require-hashes" in _PREFLIGHT
    assert "--disable-pip" in _PREFLIGHT

    test_input = (_ROOT / "tests" / "requirements-test.txt").read_text(encoding="utf-8")
    test_lock = (_ROOT / "tests" / "requirements-test.lock").read_text(encoding="utf-8")
    for package, version in (("pip-tools", "7.6.0"), ("pip-audit", "2.10.1")):
        assert f"{package}=={version}" in test_input
        assert f"{package}=={version}" in test_lock


def test_oci_identity_is_baked_from_release_inputs():
    for label in ("source", "version", "revision", "licenses"):
        assert f"org.opencontainers.image.{label}=" in _DOCKERFILE
    assert "org.opencontainers.image.licenses=AGPL-3.0-only" in _DOCKERFILE

    publish = _publish_job()
    assert "OCI_SOURCE=https://github.com/${{ github.repository }}" in publish
    assert "OCI_VERSION=${{ steps.publish_gate.outputs.version }}" in publish
    assert "OCI_REVISION=${{ needs.validate.outputs.sha }}" in publish


def test_release_scans_before_auth_and_attests_one_push_bound_registry_digest(
    tmp_path,
):
    publish = _publish_job()
    order = [
        publish.index("Validate publication inputs before build"),
        publish.index("Build the tested image locally"),
        publish.index("Generate the SPDX SBOM"),
        publish.index("Render the revision-bound scan VEX"),
        publish.index("Scan the exact local image"),
        publish.index("Refresh release refs immediately before authentication"),
        publish.index("Revalidate immediately before authentication"),
        publish.index("Log in to GHCR"),
        publish.index("Push the scanned image and resolve its digest"),
        publish.index("Bind release VEX to the published registry digest"),
        publish.index("Attest build provenance"),
        publish.index("Attest the SBOM"),
        publish.index("Create GitHub Release"),
    ]
    assert order == sorted(order)
    assert "load: true" in publish
    assert "push: false" in publish
    assert "format: spdx-json" in publish
    assert "syft-version: v1.44.0" in publish
    assert "grype-version: v0.112.0" in publish
    assert "severity-cutoff: high" in publish
    assert "only-fixed" not in publish
    assert (
        "vex: dockvault-${{ steps.publish_gate.outputs.tag }}.openvex.json" in publish
    )
    assert publish.count("release_gate.py") == 2
    assert "git fetch --force --no-tags --prune origin" in publish
    assert "id: auth_gate" in publish
    assert publish.count("release_push_digest.py") == 2
    assert 'test "$latest_digest" = "$version_digest"' in publish
    assert 'test "$resolved_version" = "$version_digest"' in publish
    assert 'test "$resolved_latest" = "$version_digest"' in publish
    assert 'echo "digest=${version_digest}" >> "$GITHUB_OUTPUT"' in publish
    assert 'echo "digest=${resolved_version}"' not in publish
    assert publish.count("subject-digest: ${{ steps.push.outputs.digest }}") == 2
    assert publish.count("push-to-registry: true") == 2
    assert (
        "sbom-path: dockvault-${{ steps.publish_gate.outputs.tag }}.spdx.json"
        in publish
    )
    assert "dockvault-${{ steps.publish_gate.outputs.tag }}.spdx.json" in publish
    assert "dockvault-${{ steps.publish_gate.outputs.tag }}.openvex.json" in publish

    for action, sha in (
        ("anchore/sbom-action", "e22c389904149dbc22b58101806040fa8d37a610"),
        ("anchore/scan-action", "e1165082ffb1fe366ebaf02d8526e7c4989ea9d2"),
        ("actions/attest", "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"),
    ):
        assert f"{action}@{sha}" in publish

    digest = f"sha256:{'c' * 64}"
    valid_log = tmp_path / "push.log"
    valid_log.write_text(
        "The push refers to repository [ghcr.io/dockvault/vault]\n"
        f"v0.8.0: digest: {digest} size: 856\n",
        encoding="utf-8",
    )
    assert _PUSH_DIGEST.extract_push_digest(valid_log) == digest

    for invalid_output in (
        "pushed without a digest summary\n",
        f"v0.8.0: digest: {digest} size: 856\nlatest: digest: {digest} size: 856\n",
        "v0.8.0: digest: sha256:not-a-digest size: 856\n",
        f"v0.8.0: digest: {digest} size: 0\n",
    ):
        valid_log.write_text(invalid_output, encoding="utf-8")
        with pytest.raises(ValueError, match="exactly one"):
            _PUSH_DIGEST.extract_push_digest(valid_log)


def test_scanner_exceptions_are_code_backed_narrow_and_documented():
    assert "only-fixed" not in _RELEASE
    assert "severity-cutoff: high" in _RELEASE
    assert not (_ROOT / ".grype.yaml").exists()
    assert not (_ROOT / ".grype.yml").exists()
    vex = json.loads(
        (_ROOT / "security" / "vex.openvex.json").read_text(encoding="utf-8")
    )
    assert {statement["vulnerability"]["name"] for statement in vex["statements"]} == {
        "CVE-2026-11940",
        "CVE-2026-11972",
        "CVE-2026-15308",
    }
    for statement in vex["statements"]:
        assert statement["status"] == "not_affected"
        assert statement["justification"] == "vulnerable_code_not_present"
        assert statement["products"] == [
            {
                "@id": (
                    "pkg:oci/vault@__IMAGE_DIGEST__"
                    "?repository_url=ghcr.io/dockvault/vault"
                ),
                "subcomponents": [{"@id": "pkg:generic/python@3.14.6"}],
            },
            {
                "@id": "__IMAGE_REFERENCE__",
                "subcomponents": [{"@id": "pkg:generic/python@3.14.6"}],
            },
        ]
        assert _CPYTHON_SNAPSHOT in statement["impact_statement"]
        assert "__SOURCE_REVISION__" in statement["impact_statement"]

    evidence = (_ROOT / "docs" / "supply-chain-controls.md").read_text(encoding="utf-8")
    assert "There is no blanket `only-fixed` bypass" in evidence
    assert "fails for every unexcepted vulnerability" in evidence
    assert _CPYTHON_SNAPSHOT in evidence
    assert "vulnerable_code_not_present" in evidence
    assert "exact registry manifest digest" in evidence
    assert (
        "both push responses and both immediate tag resolutions must agree" in evidence
    )
    for control in (
        "Private vulnerability reporting",
        "Required status checks",
        "Tag protection",
        "CodeQL/default code scanning",
        "Secret scanning",
        "Secret-scanning push protection",
    ):
        assert control in evidence


def test_vex_renderer_binds_digest_version_and_revision(tmp_path):
    output = tmp_path / "release.openvex.json"
    digest = f"sha256:{'a' * 64}"
    revision = "b" * 40
    image_reference = "ghcr.io/dockvault/vault:v0.8.0"

    document = _RENDERER.render(
        _ROOT / "security" / "vex.openvex.json",
        output,
        image_digest=digest,
        image_reference=image_reference,
        source_revision=revision,
        generated_at="2026-07-24T00:00:00Z",
    )

    rendered = output.read_text(encoding="utf-8")
    assert "__" not in rendered
    assert document["@id"].endswith(revision)
    expected_products = {
        f"pkg:oci/vault@{digest}?repository_url=ghcr.io/dockvault/vault",
        image_reference,
    }
    for statement in document["statements"]:
        assert {
            product["@id"] for product in statement["products"]
        } == expected_products
        assert revision in statement["impact_statement"]

    with pytest.raises(ValueError, match="image digest"):
        _RENDERER.render(
            _ROOT / "security" / "vex.openvex.json",
            output,
            image_digest="sha256:not-a-digest",
            image_reference=image_reference,
            source_revision=revision,
        )


def test_dependabot_covers_every_dependency_location():
    assert 'package-ecosystem: "pip"' in _DEPENDABOT
    assert 'directories:\n      - "/"\n      - "/tests"' in _DEPENDABOT
    assert 'package-ecosystem: "docker"\n    directory: "/"' in _DEPENDABOT
    assert (
        'package-ecosystem: "docker-compose"\n    directory: "/deploy"' in _DEPENDABOT
    )
    assert 'package-ecosystem: "github-actions"\n    directory: "/"' in _DEPENDABOT
