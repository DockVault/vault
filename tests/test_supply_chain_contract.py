"""Offline contracts for reproducible images and release evidence."""

from __future__ import annotations

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
    "sha256:f6a589d43c42b9e7f7dc67a12d37132491f362859a5d750607710cc56da3bc72"
)
_POSTGRES_DIGEST = (
    "postgres:15-alpine@"
    "sha256:3d0f7584ed7d04e27fa050d6683a74746608faf21f202be78460d679cc56461f"
)
_REDIS_DIGEST = (
    "redis:8-alpine@"
    "sha256:978f0e01593e65eed801f2402944efcd936d43b5027e4908a7897baf88ed6241"
)


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


def test_apk_upgrade_is_the_only_unpinned_install():
    """`RUN apk --no-cache upgrade` is the ONE deliberate unpinned network install: it ships the
    base-OS security patches the release scan requires, at the cost of byte-for-byte reproducibility
    (documented in docs/supply-chain-controls.md). Keep it the only one, so the exception stays a
    single reviewed line and a second unpinned install cannot be added quietly under this file's
    "reproducible images" contract."""
    apk_lines = [
        ln.strip() for ln in _DOCKERFILE.splitlines()
        if re.search(r"\bapk\b", ln) and not ln.lstrip().startswith("#")
    ]
    assert apk_lines == ["RUN apk --no-cache upgrade"], (
        "the only apk line must be the documented `RUN apk --no-cache upgrade`; found: %r" % apk_lines
    )
    doc = (_ROOT / "docs" / "supply-chain-controls.md").read_text(encoding="utf-8")
    assert "apk --no-cache upgrade" in doc and "reproducib" in doc.lower(), (
        "the apk reproducibility exception must be documented in docs/supply-chain-controls.md"
    )
    # ...and enforce the docstring's wider promise: no OTHER unpinned fetch-and-execute install can be
    # added quietly under another tool. pip is covered by the --require-hashes assertions above; apk is
    # the one documented exception. Word boundaries so a shell pipe ('| sh') is caught but 'sha256sum'
    # (a '| sha256sum' hash check) is not.
    forbidden = [
        r"\bcurl\b", r"\bwget\b", r"\bnpm\b", r"\byarn\b", r"\bpnpm\b",
        r"\bgo\s+(?:install|get)\b", r"\bgem\s+install\b", r"\bcargo\s+install\b",
        r"\|\s*(?:sh|bash)\b",
    ]
    for pat in forbidden:
        m = re.search(pat, _DOCKERFILE)
        assert m is None, (
            "Dockerfile has an unpinned fetch-and-execute install matching %r: ...%r..."
            % (pat, _DOCKERFILE[max(0, m.start() - 15):m.start() + 25]))


def test_the_image_keeps_the_base_images_own_standard_library():
    """The image runs the pinned base image's standard library as shipped. An earlier image copied
    two files over it from a reviewed CPython snapshot, and the base later carried newer fixes in one
    of them, so the copy would have taken that file back to an older version with no scanner
    noticing. Nothing in the build may write into the standard library again without first checking
    the base's own file, which this pin makes a reviewed change rather than a quiet one."""
    instructions = [line.strip() for line in _DOCKERFILE.splitlines()
                    if line.strip() and not line.lstrip().startswith("#")]
    assert not [line for line in instructions if "/usr/local/lib/python" in line]
    assert not [line for line in instructions if re.match(r"COPY\s+security/", line)]
    assert not (_ROOT / "security" / "cpython-backports").exists()
    # The one COPY of the whole tree comes after the dependency install, and copies into /app only.
    copies = [line for line in instructions if line.startswith("COPY ")]
    assert copies == ["COPY requirements.lock .", "COPY . ."]
    assert re.search(r"^WORKDIR /app$", _DOCKERFILE, re.MULTILINE)

    evidence = (_ROOT / "docs" / "supply-chain-controls.md").read_text(encoding="utf-8")
    assert "The image runs the base image's standard library unmodified." in evidence
    assert "must check the base image's own file hash" in evidence


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
    # These are reviewed pins, not incidental ones: the preflight job regenerates and audits the
    # production lock with exactly these tools, so moving either is a supply-chain decision. That
    # is why the version is repeated here rather than read from the requirements file -- a bump has
    # to be made twice, deliberately, and this assertion is the second time.
    for package, version in (("pip-tools", "7.6.1"), ("pip-audit", "2.10.1")):
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
    # release fails on the findings the VEX exists to account for. That is not hypothetical — it is
    # how the first multi-architecture release failed.
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
    assert 'test "$resolved_floating" = "$staged_digest"' in publish
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
    # The release VEX is attached under the name its render step gave, and only when it wrote one
    # (tests/test_release_workflow_contract.py runs that step).
    assert '--output "dockvault-${TAG}.openvex.json"' in publish
    assert "${{ steps.release_vex.outputs.asset }}" in publish

    for action, sha in (
        ("anchore/sbom-action", "e22c389904149dbc22b58101806040fa8d37a610"),
        ("anchore/scan-action", "e1165082ffb1fe366ebaf02d8526e7c4989ea9d2"),
        ("actions/attest", "1e69f48acb82d1966a394da916b4c1698aa569d6"),
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
    # No reviewed exception: the scan applies the document and it suppresses nothing. The last
    # statements were bound to package versions the image no longer contains, so they suppressed
    # nothing either, and check_vex_sbom.py fails the image scan on such a pin. An exception is a
    # deliberate, reviewed addition: its statement, its entry here and its paragraph in the evidence
    # document, together.
    assert vex["statements"] == []
    assert vex["@id"].endswith("/__SOURCE_REVISION__")

    evidence = (_ROOT / "docs" / "supply-chain-controls.md").read_text(encoding="utf-8")
    assert "There is no blanket `only-fixed` bypass" in evidence
    assert "fails for every unexcepted vulnerability" in evidence
    assert "It holds no statements now." in evidence
    flat = " ".join(evidence.split())
    assert ("The GitHub Release publishes the rendered VEX beside the SBOMs only when the template "
            "holds at least one statement.") in flat
    assert "OpenVEX requires a document to hold at least one" in flat
    assert "with an empty statement list" not in flat
    assert "and\nthe renderer refuses one that does not" in evidence
    assert "exact registry manifest digest" in evidence
    # Publication copies the scanned index (no push digest is scraped), and every tag it writes,
    # the moving ones included, is checked against the scanned digest.
    assert (
        "The release tag `:vX.Y.Z` and each moving tag the release gate names must\n"
        "  resolve to the scanned digest" in evidence
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


def _template_with_a_statement(tmp_path, **statement_over) -> Path:
    """A template shaped like the committed one, holding one statement as a reviewed exception is
    written: the subcomponent under the digest product and under the image reference."""
    subs = [{"@id": "pkg:generic/python@3.14.8"}]
    statement = {
        "vulnerability": {"name": "CVE-0000-0001"},
        "products": [
            {"@id": "pkg:oci/vault@__IMAGE_DIGEST__?repository_url=ghcr.io/dockvault/vault",
             "subcomponents": subs},
            {"@id": "__IMAGE_REFERENCE__", "subcomponents": subs},
        ],
        "status": "not_affected",
        "justification": "vulnerable_code_not_present",
        "impact_statement": "Reviewed for source revision __SOURCE_REVISION__.",
        "timestamp": "__GENERATED_AT__",
    }
    statement.update(statement_over)
    document = json.loads((_ROOT / "security" / "vex.openvex.json").read_text(encoding="utf-8"))
    document["statements"] = [statement]
    path = tmp_path / "template.openvex.json"
    path.write_text(json.dumps(document), encoding="utf-8")
    return path


def test_the_committed_vex_renders_with_no_statements(tmp_path):
    """No reviewed exception today: for a scan, the committed template renders to a document bound to
    the source revision, with an empty statement list, which the scan applies and which suppresses
    nothing."""
    output = tmp_path / "scan.openvex.json"
    revision = "b" * 40
    document = _RENDERER.render(
        _ROOT / "security" / "vex.openvex.json",
        output,
        image_digest=f"sha256:{'a' * 64}",
        image_reference="ghcr.io/dockvault/vault:v0.33.4-amd64",
        source_revision=revision,
        generated_at="2026-10-16T00:00:00Z",
    )
    assert document["statements"] == []
    assert document["@id"] == f"https://github.com/DockVault/vault/security/vex/{revision}"
    assert document["timestamp"] == "2026-10-16T00:00:00Z"
    assert "__" not in output.read_text(encoding="utf-8")


def test_a_release_publishes_no_vex_without_a_statement(tmp_path):
    """OpenVEX requires a document to hold at least one statement, so the committed template, which
    holds none, renders no release asset: nothing is written, and a file already at the output path
    is removed, so the release cannot attach an invalid or a stale document."""
    kwargs = dict(image_digest=f"sha256:{'a' * 64}", image_reference="ghcr.io/dockvault/vault:v0.33.4",
                  source_revision="b" * 40, generated_at="2026-10-16T00:00:00Z", publish=True)
    output = tmp_path / "dockvault-v0.33.4.openvex.json"
    document = _RENDERER.render(_ROOT / "security" / "vex.openvex.json", output, **kwargs)
    assert document["statements"] == []
    assert not output.exists()

    output.write_text('{"statements": []}\n', encoding="utf-8")
    _RENDERER.render(_ROOT / "security" / "vex.openvex.json", output, **kwargs)
    assert not output.exists(), "a file left at the output path would be attached as the release VEX"


def test_a_release_publishes_the_vex_when_it_holds_a_statement(tmp_path):
    output = tmp_path / "dockvault-v0.33.4.openvex.json"
    document = _RENDERER.render(
        _template_with_a_statement(tmp_path),
        output,
        image_digest=f"sha256:{'a' * 64}",
        image_reference="ghcr.io/dockvault/vault:v0.33.4",
        source_revision="b" * 40,
        publish=True,
    )
    written = json.loads(output.read_text(encoding="utf-8"))
    assert written == document
    assert len(written["statements"]) == 1
    assert written["statements"][0]["vulnerability"] == {"name": "CVE-0000-0001"}


def test_vex_renderer_refuses_a_statement_that_does_not_bind_the_image_or_revision(tmp_path):
    output = tmp_path / "release.openvex.json"
    kwargs = dict(image_digest=f"sha256:{'a' * 64}",
                  image_reference="ghcr.io/dockvault/vault:v0.8.0", source_revision="b" * 40)
    only_digest = [{"@id": "pkg:oci/vault@__IMAGE_DIGEST__?repository_url=ghcr.io/dockvault/vault",
                    "subcomponents": [{"@id": "pkg:generic/python@3.14.8"}]}]
    with pytest.raises(ValueError, match="bind the digest and versioned image"):
        _RENDERER.render(_template_with_a_statement(tmp_path, products=only_digest), output, **kwargs)
    with pytest.raises(ValueError, match="bind the reviewed source revision"):
        _RENDERER.render(_template_with_a_statement(tmp_path, impact_statement="Reviewed."),
                         output, **kwargs)
    # A template that does not name its revision in its own @id is refused too.
    bare = tmp_path / "bare.openvex.json"
    bare.write_text(json.dumps({"@id": "x", "timestamp": "__GENERATED_AT__",
                                "note": "__SOURCE_REVISION__", "statements": []}), encoding="utf-8")
    with pytest.raises(ValueError, match="@id must name the reviewed source revision"):
        _RENDERER.render(bare, output, **kwargs)
    missing = tmp_path / "missing.openvex.json"
    missing.write_text(json.dumps({"@id": "x/__SOURCE_REVISION__", "statements": []}),
                       encoding="utf-8")
    with pytest.raises(ValueError, match="missing required token __GENERATED_AT__"):
        _RENDERER.render(missing, output, **kwargs)
    # An empty list is allowed; no list at all is a broken template.
    listless = tmp_path / "listless.openvex.json"
    listless.write_text(json.dumps({"@id": "x/__SOURCE_REVISION__",
                                    "timestamp": "__GENERATED_AT__"}), encoding="utf-8")
    with pytest.raises(ValueError, match="must contain a statements list"):
        _RENDERER.render(listless, output, **kwargs)
    assert not output.exists(), "a refused template must leave no rendered document behind"


def test_vex_renderer_binds_digest_version_and_revision(tmp_path):
    output = tmp_path / "release.openvex.json"
    digest = f"sha256:{'a' * 64}"
    revision = "b" * 40
    image_reference = "ghcr.io/dockvault/vault:v0.8.0"

    document = _RENDERER.render(
        _template_with_a_statement(tmp_path),
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
    assert len(document["statements"]) == 1
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

    template = _template_with_a_statement(tmp_path)
    for platform in ("amd64", "arm64"):
        reference = f"ghcr.io/dockvault/vault:v0.10.0-{platform}"
        document = _RENDERER.render(
            template,
            output,
            image_digest=digest,
            image_reference=reference,
            source_revision=revision,
        )
        assert len(document["statements"]) == 1
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


def test_every_non_pr_tests_run_applies_the_release_scan_policy():
    """A release candidate's Tests run must fail on a finding the publish-time scan would refuse.

    The pull-request image scan blocks only on findings that have a fix (only-fixed), which is right
    for a PR author and wrong for a release: a CVE with no fix yet passes it and then stops the
    publish, after the release's advisories are already public on main. The Tests workflow therefore
    runs the image scan with the release gate's policy on every run that is not a pull request.
    """
    import yaml

    tests = yaml.safe_load((_ROOT / ".github" / "workflows" / "tests.yml").read_text(encoding="utf-8"))
    job = tests["jobs"]["image-scan"]
    assert job["uses"] == "./.github/workflows/image-scan-pr.yml"
    assert job["with"] == {"release_policy": True}
    assert job["if"] == "github.event_name != 'pull_request'"
    assert "needs" not in job                              # in parallel with the suites, not after
    assert job["permissions"] == {"contents": "read"}

    scan = yaml.safe_load((_ROOT / ".github" / "workflows" / "image-scan-pr.yml").read_text(encoding="utf-8"))
    triggers = scan[True]                                   # YAML reads the bare key `on` as True
    for trigger in ("workflow_call", "workflow_dispatch"):
        policy = triggers[trigger]["inputs"]["release_policy"]
        assert policy["type"] == "boolean" and policy["default"] is False
    grype = [s for s in scan["jobs"]["scan"]["steps"] if s.get("uses", "").startswith("anchore/scan-action@")]
    assert len(grype) == 1
    options = grype[0]["with"]
    # The release policy turns only-fixed OFF; a pull request (empty inputs) keeps it on.
    assert options["only-fixed"] == "${{ inputs.release_policy && 'false' || 'true' }}"
    assert options["severity-cutoff"] == "high" and options["fail-build"] is True
    assert options["vex"]                                   # reviewed exceptions still apply
    assert scan["concurrency"]["group"].startswith("image-scan-")


def test_the_advisory_lock_refresh_report_cannot_run_out_the_preflight_clock():
    """The refresh report resolves the newest dependency set against the live index, which has taken
    longer than the whole preflight job is allowed. Being advisory, it must never fail the job -- and
    running out the job's clock is failing it, before any test has run."""
    import yaml

    preflight = yaml.safe_load(_PREFLIGHT)
    steps = [s for job in preflight["jobs"].values() for s in job.get("steps", [])]
    report = [s for s in steps if s.get("name") == "Report available lock refreshes"]
    assert len(report) == 1
    step = report[0]
    assert step["continue-on-error"] is True
    assert 1 <= step["timeout-minutes"] <= 5
    assert "timeout --kill-after=10 180 python -m piptools compile" in step["run"]
