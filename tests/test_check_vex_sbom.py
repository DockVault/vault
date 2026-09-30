"""A reviewed VEX statement is bound to exact package versions, and the image scan checks that the
image still contains them."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_TEMPLATE = _ROOT / "security" / "vex.openvex.json"
_SPEC = importlib.util.spec_from_file_location(
    "check_vex_sbom_under_test", _ROOT / ".github" / "scripts" / "check_vex_sbom.py")
assert _SPEC and _SPEC.loader
_CHECK = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _CHECK
_SPEC.loader.exec_module(_CHECK)

_ALPINE = "?arch=x86_64&distro=alpine-3.24.1"


def _spdx(*purls: str) -> dict:
    """An SPDX document shaped like syft's: each package's purl is an external reference."""
    return {
        "spdxVersion": "SPDX-2.3",
        "packages": [
            {"name": purl.split("/")[-1].split("@")[0], "SPDXID": f"SPDXRef-Package-{n}",
             "externalRefs": [
                 {"referenceCategory": "SECURITY", "referenceType": "cpe23Type",
                  "referenceLocator": "cpe:2.3:a:x:y:1:*:*:*:*:*:*:*"},
                 {"referenceCategory": "PACKAGE-MANAGER", "referenceType": "purl",
                  "referenceLocator": purl},
             ]}
            for n, purl in enumerate(purls)
        ],
    }


def _image_as_reviewed() -> dict:
    """The packages the committed VEX was reviewed against, as syft names them."""
    return _spdx(
        "pkg:generic/python@3.14.7",
        f"pkg:apk/alpine/libssl3@3.5.7-r0{_ALPINE}&upstream=openssl",
        f"pkg:apk/alpine/libcrypto3@3.5.7-r0{_ALPINE}&upstream=openssl",
        f"pkg:apk/alpine/zlib@1.3.2-r0{_ALPINE}",
        "pkg:pypi/fastapi@0.136.0",
    )


def _vex() -> dict:
    return json.loads(_TEMPLATE.read_text(encoding="utf-8"))


def test_the_committed_vex_matches_the_image_it_was_reviewed_against():
    assert _CHECK.stale_pins(_vex(), _image_as_reviewed()) == []
    pinned = {purl for _, purl, _ in _CHECK.vex_pins(_vex())}
    assert pinned == {"pkg:generic/python@3.14.7", "pkg:apk/alpine/libssl3@3.5.7-r0",
                      "pkg:apk/alpine/libcrypto3@3.5.7-r0", "pkg:apk/alpine/zlib@1.3.2-r0"}


def test_a_newer_package_in_the_image_makes_its_statement_stale():
    sbom = _image_as_reviewed()
    for package in sbom["packages"]:
        for ref in package["externalRefs"]:
            ref["referenceLocator"] = ref["referenceLocator"].replace(
                "zlib@1.3.2-r0", "zlib@1.3.2-r1")

    stale = _CHECK.stale_pins(_vex(), sbom)

    assert stale == [_CHECK.Stale("CVE-2026-85091", "pkg:apk/alpine/zlib@1.3.2-r0",
                                  ("pkg:apk/alpine/zlib@1.3.2-r1",))]
    message = _CHECK.explain(stale[0])
    assert message.startswith(
        "CVE-2026-85091 is bound to pkg:apk/alpine/zlib@1.3.2-r0, which this image no longer "
        "contains (it has pkg:apk/alpine/zlib@1.3.2-r1 instead)")
    for place in ("security/vex.openvex.json",
                  "tests/test_supply_chain_contract.py "
                  "(test_scanner_exceptions_are_code_backed_narrow_and_documented)",
                  "docs/supply-chain-controls.md"):
        assert place in message
    assert "review it again and change the version in all three" in message


def test_a_newer_python_makes_each_cpython_statement_stale():
    sbom = _image_as_reviewed()
    sbom["packages"][0]["externalRefs"][1]["referenceLocator"] = "pkg:generic/python@3.14.8"

    stale = _CHECK.stale_pins(_vex(), sbom)

    assert [(s.vulnerability, s.purl) for s in stale] == [
        (cve, "pkg:generic/python@3.14.7")
        for cve in ("CVE-2026-11940", "CVE-2026-11972", "CVE-2026-15308")]
    assert all(s.found == ("pkg:generic/python@3.14.8",) for s in stale)


def test_a_package_the_image_no_longer_has_at_all_is_stale():
    sbom = _image_as_reviewed()
    sbom["packages"] = [p for p in sbom["packages"] if p["name"] != "zlib"]

    [stale] = _CHECK.stale_pins(_vex(), sbom)

    assert stale.found == ()
    assert "(it has no such package at all)" in _CHECK.explain(stale)


def test_an_empty_sbom_proves_nothing_and_is_refused():
    with pytest.raises(_CHECK.CheckError, match="the SBOM lists no packages"):
        _CHECK.stale_pins(_vex(), {"spdxVersion": "SPDX-2.3", "packages": []})


def test_a_version_is_compared_exactly_and_qualifiers_are_ignored():
    # 1.3.2-r0 is not 1.3.2-r01 or 1.3.2; the distro and architecture qualifiers are not part of it.
    vex = {"statements": [{"vulnerability": {"name": "CVE-1"}, "products": [
        {"@id": "x", "subcomponents": [{"@id": "pkg:apk/alpine/zlib@1.3.2-r0"}]}]}]}
    for version in ("1.3.2-r01", "1.3.2", "1.3.2-r0.1"):
        assert _CHECK.stale_pins(vex, _spdx(f"pkg:apk/alpine/zlib@{version}{_ALPINE}")), version
    assert _CHECK.stale_pins(vex, _spdx("pkg:apk/alpine/zlib@1.3.2-r0?arch=aarch64#sub")) == []
    # The same name under another type or namespace is another package.
    assert _CHECK.stale_pins(vex, _spdx("pkg:apk/wolfi/zlib@1.3.2-r0"))[0].found == ()
    assert _CHECK.stale_pins(vex, _spdx("pkg:deb/alpine/zlib@1.3.2-r0"))[0].found == ()


def test_a_subcomponent_without_a_version_pins_nothing():
    vex = {"statements": [{"vulnerability": {"name": "CVE-1"}, "products": [
        {"@id": "x", "subcomponents": [{"@id": "pkg:apk/alpine/zlib"}]}]}]}
    assert _CHECK.vex_pins(vex) == []
    assert _CHECK.stale_pins(vex, _spdx("pkg:apk/alpine/musl@1.2.5-r10")) == []


def test_each_pin_is_reported_once_per_finding():
    # The template binds each subcomponent twice, under the digest and under the image reference.
    vex = _vex()
    assert len(_CHECK.vex_pins(vex)) == 6
    sbom = _spdx("pkg:pypi/fastapi@0.136.0")
    assert len(_CHECK.stale_pins(vex, sbom)) == 6


@pytest.mark.parametrize("shape", ["syft-json", "cyclonedx"])
def test_the_other_sbom_formats_syft_writes_are_read_too(shape):
    purls = [ref["referenceLocator"] for p in _image_as_reviewed()["packages"]
             for ref in p["externalRefs"] if ref["referenceType"] == "purl"]
    if shape == "syft-json":
        sbom = {"artifacts": [{"name": "x", "purl": purl} for purl in purls]}
    else:
        sbom = {"bomFormat": "CycloneDX",
                "components": [{"name": "x", "purl": purls[0],
                                "components": [{"name": "y", "purl": p} for p in purls[1:]]}]}
    assert _CHECK.stale_pins(_vex(), sbom) == []
    # Above, the CycloneDX zlib sat in a nested component and counted; without it, it is stale.
    shorter = copy.deepcopy(sbom)
    if shape == "syft-json":
        shorter["artifacts"] = [a for a in shorter["artifacts"] if "zlib" not in a["purl"]]
    else:
        shorter["components"][0]["components"] = [
            c for c in shorter["components"][0]["components"] if "zlib" not in c["purl"]]
    assert [s.purl for s in _CHECK.stale_pins(_vex(), shorter)] == ["pkg:apk/alpine/zlib@1.3.2-r0"]


def test_the_command_fails_with_an_annotation_on_the_template(tmp_path, capsys):
    vex = tmp_path / "vex.json"
    vex.write_bytes(_TEMPLATE.read_bytes())
    sbom = tmp_path / "sbom.json"
    sbom.write_text(json.dumps(_image_as_reviewed()), encoding="utf-8")

    assert _CHECK.main(["--vex", str(vex), "--sbom", str(sbom)]) == 0
    assert "every package version the VEX names is in the image (6 checked)" in capsys.readouterr().out

    sbom.write_text(json.dumps(_spdx("pkg:generic/python@3.14.7")), encoding="utf-8")
    assert _CHECK.main(["--vex", str(vex), "--sbom", str(sbom)]) == 1
    lines = capsys.readouterr().out.splitlines()
    assert len(lines) == 3
    assert all(line.startswith("::error file=security/vex.openvex.json::CVE-2026-") for line in lines)


@pytest.mark.parametrize("sbom_text", ["not json", "[]", '{"packages": []}'])
def test_the_command_refuses_an_sbom_it_cannot_read(tmp_path, capsys, sbom_text):
    sbom = tmp_path / "sbom.json"
    sbom.write_text(sbom_text, encoding="utf-8")
    assert _CHECK.main(["--vex", str(_TEMPLATE), "--sbom", str(sbom)]) == 2
    assert capsys.readouterr().out.startswith("::error::")


def test_the_image_scan_checks_the_vex_against_the_image_before_scanning():
    import yaml

    scan = yaml.safe_load((_ROOT / ".github" / "workflows" / "image-scan-pr.yml")
                          .read_text(encoding="utf-8"))
    steps = scan["jobs"]["scan"]["steps"]
    names = [step.get("name") for step in steps]
    sbom = steps[names.index("Generate the SPDX SBOM (amd64)")]
    check = steps[names.index("Check the VEX against the image's packages")]
    grype = next(s for s in steps if s.get("uses", "").startswith("anchore/scan-action@"))
    built = names.index("Build the image (amd64, local)")

    assert built < names.index(sbom["name"]) < names.index(check["name"]) < steps.index(grype)
    assert sbom["uses"] == ("anchore/sbom-action@e22c389904149dbc22b58101806040fa8d37a610")
    assert sbom["with"]["image"] == grype["with"]["image"] == "ghcr.io/dockvault/vault:v0.0.0-amd64"
    assert sbom["with"]["format"] == "spdx-json"
    assert sbom["with"]["syft-version"] == "v1.44.0"
    assert sbom["with"]["upload-artifact"] is False
    assert "python3 .github/scripts/check_vex_sbom.py" in check["run"]
    assert "--vex security/vex.openvex.json" in check["run"]
    assert f"--sbom {sbom['with']['output-file']}" in check["run"]
    assert "continue-on-error" not in check and "if" not in check
    # A change to the checker runs the scan on the pull request that makes it.
    assert ".github/scripts/check_vex_sbom.py" in scan[True]["pull_request"]["paths"]


def test_the_supply_chain_document_describes_the_check():
    evidence = (_ROOT / "docs" / "supply-chain-controls.md").read_text(encoding="utf-8")
    assert "`.github/scripts/check_vex_sbom.py` compares every versioned subcomponent" in evidence
    assert "reviewed\nagain and its version changed in all three" in evidence
