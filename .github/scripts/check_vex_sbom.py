#!/usr/bin/env python3
"""Check every package version a reviewed VEX statement names against what the image contains.

Each statement in security/vex.openvex.json binds a finding to exact package versions, for example
`pkg:apk/alpine/zlib@1.3.2-r0`. When the image moves on (a base-image update, or the build's
`apk upgrade` taking a newer Alpine package), the pin stops matching and the statement suppresses
nothing. That is the intended failure mode for the scan, but the statement itself stays behind in
three places, describing a package the image no longer has: the VEX template, its entry in the
supply-chain contract test, and its paragraph in docs/supply-chain-controls.md. This check fails the
image scan until those are removed, or reviewed again for the new version.

    python3 .github/scripts/check_vex_sbom.py --vex security/vex.openvex.json --sbom IMAGE.spdx.json

The SBOM is the image's SPDX JSON as syft writes it (a syft JSON or CycloneDX JSON document also
works). Package URLs are compared by type, namespace, name and version; qualifiers such as
`?arch=x86_64&distro=alpine-3.24.1` are ignored. A subcomponent without a version pins nothing and is
not checked. Exit status 0 when every pinned version is in the image, 1 when one is not, 2 when the
input cannot be read.

Stdlib only, like the rest of the release scripts.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NamedTuple, Sequence
from urllib.parse import unquote

VEX_TEMPLATE = "security/vex.openvex.json"
CONTRACT_TEST = ("tests/test_supply_chain_contract.py "
                 "(test_scanner_exceptions_are_code_backed_narrow_and_documented)")
EVIDENCE = "docs/supply-chain-controls.md"


class CheckError(ValueError):
    """An input that cannot be read as a VEX document or an SBOM."""


class Package(NamedTuple):
    type: str
    namespace: str
    name: str
    version: str | None

    def without_version(self) -> tuple[str, str, str]:
        return self.type, self.namespace, self.name


class Stale(NamedTuple):
    vulnerability: str
    purl: str
    found: tuple[str, ...]


def parse_purl(purl: str) -> Package | None:
    """The identifying parts of a package URL, or None when it is not one."""
    if not isinstance(purl, str) or not purl.startswith("pkg:"):
        return None
    rest = purl[len("pkg:"):].split("#", 1)[0].split("?", 1)[0].strip("/")
    version = None
    if "@" in rest:
        rest, version = rest.rsplit("@", 1)
        version = unquote(version) or None
    parts = [unquote(part) for part in rest.split("/") if part]
    if len(parts) < 2:
        return None
    return Package(parts[0].lower(), "/".join(parts[1:-1]), parts[-1], version)


def _describe(package: Package) -> str:
    path = "/".join(p for p in (package.type, package.namespace, package.name) if p)
    return f"pkg:{path}@{package.version}" if package.version else f"pkg:{path}"


def sbom_packages(sbom: dict) -> set[Package]:
    """Every package URL an SPDX, syft or CycloneDX JSON document lists."""
    if not isinstance(sbom, dict):
        raise CheckError("the SBOM is not a JSON object")
    purls: list[str] = []
    for package in sbom.get("packages") or []:  # SPDX
        for ref in (package.get("externalRefs") or []) if isinstance(package, dict) else []:
            if isinstance(ref, dict) and ref.get("referenceType") == "purl":
                purls.append(ref.get("referenceLocator"))
    for artifact in sbom.get("artifacts") or []:  # syft JSON
        if isinstance(artifact, dict):
            purls.append(artifact.get("purl"))
    pending = list(sbom.get("components") or [])  # CycloneDX, nested components included
    while pending:
        component = pending.pop()
        if isinstance(component, dict):
            purls.append(component.get("purl"))
            pending.extend(component.get("components") or [])
    return {package for package in map(parse_purl, purls) if package is not None}


def vex_pins(vex: dict) -> list[tuple[str, str, Package]]:
    """(vulnerability, subcomponent purl, parsed) for every versioned subcomponent, in order, once."""
    if not isinstance(vex, dict) or not isinstance(vex.get("statements"), list):
        raise CheckError("the VEX document has no statements list")
    pins: list[tuple[str, str, Package]] = []
    seen: set[tuple[str, str]] = set()
    for statement in vex["statements"]:
        if not isinstance(statement, dict):
            raise CheckError("a VEX statement is not an object")
        vulnerability = (statement.get("vulnerability") or {}).get("name") or "an unnamed finding"
        for product in statement.get("products") or []:
            for sub in (product.get("subcomponents") or []) if isinstance(product, dict) else []:
                purl = sub.get("@id") if isinstance(sub, dict) else None
                package = parse_purl(purl)
                if package is None or package.version is None:
                    continue
                if (vulnerability, purl) not in seen:
                    seen.add((vulnerability, purl))
                    pins.append((vulnerability, purl, package))
    return pins


def stale_pins(vex: dict, sbom: dict) -> list[Stale]:
    """Each pinned package version the image does not contain, with the versions it does."""
    in_image = sbom_packages(sbom)
    if not in_image:
        raise CheckError("the SBOM lists no packages; a failed or empty SBOM proves nothing")
    stale = []
    for vulnerability, purl, package in vex_pins(vex):
        if package in in_image:
            continue
        found = tuple(sorted(_describe(p) for p in in_image
                             if p.without_version() == package.without_version()))
        stale.append(Stale(vulnerability, purl, found))
    return stale


def explain(item: Stale) -> str:
    has = (f"it has {', '.join(item.found)} instead" if item.found
           else "it has no such package at all")
    return (f"{item.vulnerability} is bound to {item.purl}, which this image no longer contains "
            f"({has}), so the statement suppresses nothing. If the image's version is not affected, "
            f"remove the statement from {VEX_TEMPLATE}, its entry in {CONTRACT_TEST} and its "
            f"paragraph in {EVIDENCE}. If it is still affected and the reasoning still holds, "
            "review it again and change the version in all three.")


def _load(path: Path, what: str) -> dict:
    try:
        return json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CheckError(f"cannot read the {what} {path}: {exc}") from exc


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    parser.add_argument("--vex", type=Path, required=True)
    parser.add_argument("--sbom", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        vex = _load(args.vex, "VEX document")
        stale = stale_pins(vex, _load(args.sbom, "SBOM"))
    except CheckError as exc:
        print(f"::error::{exc}")
        return 2
    for item in stale:
        print(f"::error file={VEX_TEMPLATE}::{explain(item)}")
    if stale:
        return 1
    pins = vex_pins(vex)
    print(f"every package version the VEX names is in the image ({len(pins)} checked)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
