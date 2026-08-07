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

_PYTHON_DIGEST = (
    "python:3.14-alpine@"
    "sha256:26730869004e2b9c4b9ad09cab8625e81d256d1ce97e72df5520e806b1709f92"
)
_POSTGRES_DIGEST = (
    "postgres:18-alpine@"
    "sha256:9a8afca54e7861fd90fab5fdf4c42477a6b1cb7d293595148e674e0a3181de15"
)
_REDIS_DIGEST = (
    "redis:8-alpine@"
    "sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241"
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


def _direct_pins(path: Path) -> dict[str, str]:
    pins = {}
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        match = re.fullmatch(
            r"(?P<name>[A-Za-z0-9_.-]+)(?:\[[A-Za-z0-9_,.-]+\])?"
            r"==(?P<version>[^=\s\\]+)(?:\s+\\)?",
            line,
        )
        if match:
            name = re.sub(r"[-_.]+", "-", match.group("name")).lower()
            pins[name] = match.group("version")
    return pins


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


def test_cross_platform_test_lock_tracks_the_explicit_host_import_subset():
    host_import_packages = {
        "argon2-cffi",
        "bcrypt",
        "cryptography",
        "email-validator",
        "fastapi",
        "paramiko",
        "psycopg2-binary",
        "pydantic",
        "pydantic-settings",
        "pyjwt",
        "python-dotenv",
        "python-multipart",
        "redis",
        "sqlalchemy",
        "starlette",
    }
    production_pins = _direct_pins(_ROOT / "requirements.txt")
    test_input_pins = _direct_pins(_ROOT / "tests" / "requirements-test.txt")
    production_lock_pins = _direct_pins(_ROOT / "requirements.lock")
    test_lock_pins = _direct_pins(_ROOT / "tests" / "requirements-test.lock")

    for pins in (
        production_pins,
        test_input_pins,
        production_lock_pins,
        test_lock_pins,
    ):
        assert host_import_packages <= pins.keys()
    assert {
        name: test_input_pins.get(name) for name in host_import_packages
    } == {
        name: production_pins.get(name) for name in host_import_packages
    }
    assert {
        name: test_lock_pins.get(name) for name in host_import_packages
    } == {
        name: production_lock_pins.get(name) for name in host_import_packages
    }

    common_packages = production_lock_pins.keys() & test_lock_pins.keys()
    assert common_packages
    assert {
        name: test_lock_pins[name] for name in common_packages
    } == {
        name: production_lock_pins[name] for name in common_packages
    }

    forbidden_packages = {"keyring", "uvicorn", "uvloop"}
    assert forbidden_packages.isdisjoint(test_input_pins)
    assert forbidden_packages.isdisjoint(test_lock_pins)


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
        _PREFLIGHT.index(expected_command),
        _PREFLIGHT.index(
            'cmp requirements.lock "$RUNNER_TEMP/requirements.lock.checked"'
        ),
    ]
    assert order == sorted(order)
    assert "git diff --exit-code -- requirements.lock" not in _PREFLIGHT
    # The recompile must happen IN PLACE. Deleting the lock first turns this gate from "the
    # committed lock resolves requirements.txt" into "the lock is the newest resolution on the
    # index right now" - which no commit can keep true, so every upstream release of an unpinned
    # transitive reddened main and every open pull request until someone regenerated by hand.
    assert "rm requirements.lock" not in _PREFLIGHT
    # Staleness is reported instead of blocking, and reporting it must never fail the job.
    assert "Report available lock refreshes" in _PREFLIGHT
    assert "::warning::%s is pinned at %s; %s is available" in _PREFLIGHT
    assert (
        "python -m pip install --force-reinstall --require-hashes -r requirements.lock"
        in _PREFLIGHT
    )
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


def test_release_scans_before_auth_and_attests_one_push_bound_registry_digest():
    publish = _publish_job()
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

    # A multi-platform image cannot be loaded into the daemon under one tag, so the pre-scan
    # artifact is staged in a registry ON THE RUNNER. That is only acceptable while the staging
    # target is loopback - anything else would publish the image before it had been scanned.
    assert "STAGING_IMAGE: localhost:5000/dockvault/vault" in publish
    assert "PLATFORMS: linux/amd64,linux/arm64" in publish
    assert "platforms: ${{ env.PLATFORMS }}" in publish
    assert "tags: ${{ env.STAGING_IMAGE }}:${{ steps.publish_gate.outputs.tag }}" in publish
    # Nothing may WRITE to GHCR before the scans. The build's one and only push target is the
    # staging registry, and the single step that writes to GHCR runs after authentication.
    # A ghcr.io-shaped LOCAL TAG before then is not a publication — see the scan identity below.
    assert publish.count("push: true") == 1
    assert "docker push" not in publish
    assert publish.index("docker buildx imagetools create") > publish.index("Log in to GHCR")
    # Buildx's own attestation manifests would ride along into the published index and duplicate
    # the signed attestations below.
    assert "provenance: false" in publish
    assert "sbom: false" in publish

    assert "format: spdx-json" in publish
    assert "syft-version: v1.44.0" in publish
    assert publish.count("grype-version: v0.112.0") == 2
    assert publish.count("severity-cutoff: high") == 2
    assert publish.count("fail-build: true") == 2
    assert "only-fixed" not in publish

    # The scanned image must wear the RELEASE reference, and each per-platform VEX must name the
    # same reference. A VEX statement applies only to a product it lists, so scanning under an
    # unrelated local name suppresses NOTHING: every reviewed exception goes unapplied and the
    # release fails on the CPython findings the VEX exists to account for. That is not
    # hypothetical — it is how the first multi-architecture release failed.
    scan_ref = "${{ steps.publish_gate.outputs.image }}:${{ steps.publish_gate.outputs.tag }}"
    for platform in ("amd64", "arm64"):
        assert f"image: {scan_ref}-{platform}" in publish
        assert (
            f"vex: dockvault-${{{{ steps.publish_gate.outputs.tag }}}}-{platform}.openvex.json"
            in publish
        )
        assert (
            f"sbom-path: dockvault-${{{{ steps.publish_gate.outputs.tag }}}}-{platform}.spdx.json"
            in publish
        )
    assert '--image-reference "${IMAGE}:${TAG}-${platform}"' in publish
    assert "dockvault-scan" not in publish, "a name the VEX does not list suppresses nothing"

    # Each platform must be pulled by ITS OWN manifest digest. `docker pull --platform <p> <tag>`
    # resolves the index under the containerd image store, so both iterations would land the host
    # architecture and the arm64 "scan" would be a second amd64 scan that always passes.
    assert 'docker pull --quiet "${STAGING_IMAGE}@${digest}"' in publish
    assert "docker pull --quiet --platform" not in publish
    assert '{{if eq .Platform.Architecture \\"${platform}\\"}}{{.Digest}}{{end}}' in publish
    assert (
        'got="$(docker image inspect -f \'{{.Architecture}}\' "${IMAGE}:${TAG}-${platform}")"'
        in publish
    )
    # ...and the two must not collapse to one image id, or one scan would cover both.
    assert (
        'test "$(docker image inspect -f \'{{.Id}}\' "${IMAGE}:${TAG}-amd64")"' in publish
    )

    assert publish.count("release_gate.py") == 2
    assert "git fetch --force --no-tags --prune origin" in publish
    assert "id: auth_gate" in publish
    assert 'test "$resolved_version" = "$staged_digest"' in publish
    assert 'test "$resolved_latest" = "$staged_digest"' in publish
    assert 'echo "digest=${resolved_version}" >> "$GITHUB_OUTPUT"' in publish
    # provenance + one SBOM per platform, every one bound to the published index digest
    assert publish.count("subject-digest: ${{ steps.push.outputs.digest }}") == 3
    assert publish.count("push-to-registry: true") == 3
    assert 'anonymous_config="$(mktemp -d "$RUNNER_TEMP/docker-anon.XXXXXX")"' in publish
    assert "printf '%s\\n' '{\"auths\":{}}'" in publish
    assert (
        'DOCKER_CONFIG="$anonymous_config" docker pull --quiet "${IMAGE}@${manifest}"'
        in publish
    )
    assert "::error::the published index does not advertise $platform" in publish
    assert "dockvault-${{ steps.publish_gate.outputs.tag }}-amd64.spdx.json" in publish
    assert "dockvault-${{ steps.publish_gate.outputs.tag }}-arm64.spdx.json" in publish
    assert "dockvault-${{ steps.publish_gate.outputs.tag }}.openvex.json" in publish

    for action, sha in (
        ("anchore/sbom-action", "e22c389904149dbc22b58101806040fa8d37a610"),
        ("anchore/scan-action", "e1165082ffb1fe366ebaf02d8526e7c4989ea9d2"),
        ("actions/attest", "f7c74d28b9d84cb8768d0b8ca14a4bac6ef463e6"),
        ("docker/setup-qemu-action", "96fe6ef7f33517b61c61be40b68a1882f3264fb8"),
    ):
        assert f"{action}@{sha}" in publish

    # The staging registry holds the pre-scan artifact, so it is pinned by digest like every other
    # image this pipeline trusts.
    assert (
        "image: registry@sha256:"
        "a3d8aaa63ed8681a604f1dea0aa03f100d5895b6a58ace528858a7b332415373" in publish
    )

    # The published digest is no longer scraped out of `docker push` output. Publication copies the
    # staged index, so the check that carries the guarantee is that what GHCR resolves for BOTH
    # tags equals the digest that was scanned.
    assert "docker buildx imagetools create" in publish
    assert "release_push_digest" not in publish
    assert not (_ROOT / ".github" / "scripts" / "release_push_digest.py").exists()


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


def test_vex_names_the_per_platform_image_the_release_actually_scans(tmp_path):
    # A multi-architecture release scans one image per platform, and a VEX statement applies only
    # to a product it names. So the renderer has to accept the per-platform reference those images
    # wear — otherwise the release either cannot render the document or renders one that names an
    # image nobody scans, silently suppressing nothing and failing on reviewed findings.
    output = tmp_path / "release.openvex.json"
    digest = f"sha256:{'a' * 64}"
    revision = "b" * 40

    for platform in ("amd64", "arm64"):
        reference = f"ghcr.io/dockvault/vault:v0.10.0-{platform}"
        document = _RENDERER.render(
            _ROOT / "security" / "vex.openvex.json",
            output,
            image_digest=digest,
            image_reference=reference,
            source_revision=revision,
        )
        for statement in document["statements"]:
            assert reference in {product["@id"] for product in statement["products"]}

    # The suffix is scan-time only and narrow: it must not become a hole for arbitrary tags.
    for rejected in (
        "ghcr.io/dockvault/vault:v0.10.0-rc1",
        "ghcr.io/dockvault/vault:latest",
        "ghcr.io/dockvault/vault:v0.10.0-amd64-extra",
        "docker.io/dockvault/vault:v0.10.0",
    ):
        with pytest.raises(ValueError, match="image reference"):
            _RENDERER.render(
                _ROOT / "security" / "vex.openvex.json",
                output,
                image_digest=digest,
                image_reference=rejected,
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
