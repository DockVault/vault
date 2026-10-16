#!/usr/bin/env python3
"""Render the reviewed OpenVEX template for one immutable release artifact."""

from __future__ import annotations

import argparse
import json
import re
from datetime import UTC, datetime
from pathlib import Path


_DIGEST_RE = re.compile(r"sha256:[0-9a-f]{64}\Z")
_REVISION_RE = re.compile(r"[0-9a-f]{40}\Z")
# The published artifact is `<repo>:vX.Y.Z`. The optional architecture suffix covers the
# per-platform images the release scans BEFORE publication: a multi-architecture release has one
# image per platform to scan and one VEX per image, and a VEX statement only applies to a product
# it names. Scanning `…:vX.Y.Z-amd64` against a VEX that names `…:vX.Y.Z` silently suppresses
# nothing — every exception in the document goes unapplied and the scan fails on findings that
# were already reviewed. The suffix is scan-time only; nothing publishes it, and the release VEX
# asset is re-rendered against the canonical reference and the published digest.
_IMAGE_RE = re.compile(
    r"ghcr\.io/[a-z0-9._/-]+:v?[0-9]+\.[0-9]+\.[0-9]+(?:-(?:amd64|arm64))?\Z"
)
_TOKENS = {
    "__IMAGE_DIGEST__",
    "__IMAGE_REFERENCE__",
    "__SOURCE_REVISION__",
    "__GENERATED_AT__",
}
# The tokens the document itself carries: its @id names the reviewed source revision and its
# timestamp the render. The image tokens belong to the statements, so a template with no statements
# (no reviewed exception at all) has none of them; every statement it does hold must bind both, which
# the checks below enforce statement by statement.
_DOCUMENT_TOKENS = ("__SOURCE_REVISION__", "__GENERATED_AT__")


def render(
    template_path: Path,
    output_path: Path,
    *,
    image_digest: str,
    image_reference: str,
    source_revision: str,
    generated_at: str | None = None,
    publish: bool = False,
) -> dict:
    """Render the template for one image and return the document.

    With `publish`, the document is the one a release attaches beside its SBOMs. OpenVEX requires a
    document to hold at least one statement, so a template with none (no reviewed exception) has no
    document to publish: nothing is written, and a file already at `output_path` is removed, so the
    release finds no VEX to attach instead of an invalid or a stale one. Without `publish` (the
    scans), an empty statement list is written: applied to a scan it suppresses nothing.
    """
    if not _DIGEST_RE.fullmatch(image_digest):
        raise ValueError("image digest must be lowercase sha256:<64 hex>")
    if not _REVISION_RE.fullmatch(source_revision):
        raise ValueError("source revision must be a lowercase 40-character commit SHA")
    if not _IMAGE_RE.fullmatch(image_reference):
        raise ValueError("image reference must be a versioned ghcr.io image")

    timestamp = generated_at or datetime.now(UTC).replace(
        microsecond=0
    ).isoformat().replace("+00:00", "Z")
    source = template_path.read_text(encoding="utf-8")
    replacements = {
        "__IMAGE_DIGEST__": image_digest,
        "__IMAGE_REFERENCE__": image_reference,
        "__SOURCE_REVISION__": source_revision,
        "__GENERATED_AT__": timestamp,
    }
    for token in _DOCUMENT_TOKENS:
        if token not in source:
            raise ValueError(f"template is missing required token {token}")
    for token, value in replacements.items():
        source = source.replace(token, value)
    if any(token in source for token in _TOKENS):
        raise ValueError("rendered VEX still contains an unresolved token")

    document = json.loads(source)
    if not str(document.get("@id", "")).endswith(source_revision):
        raise ValueError("the VEX document @id must name the reviewed source revision")
    expected_products = {
        f"pkg:oci/vault@{image_digest}?repository_url=ghcr.io/dockvault/vault",
        image_reference,
    }
    statements = document.get("statements")
    if not isinstance(statements, list):
        raise ValueError("rendered VEX must contain a statements list")
    # An empty list is a release with no reviewed exception: the scan applies the document and it
    # suppresses nothing, so every High or Critical finding still fails the scan. Such a document is
    # for the scans only; it is never published (see `publish`).
    for statement in statements:
        if not isinstance(statement, dict):
            raise ValueError("every VEX statement must be an object")
        products = {product["@id"] for product in statement.get("products", [])}
        if products != expected_products:
            raise ValueError(
                "every VEX statement must bind the digest and versioned image"
            )
        if source_revision not in statement.get("impact_statement", ""):
            raise ValueError(
                "every VEX impact statement must bind the reviewed source revision"
            )

    if publish and not statements:
        output_path.unlink(missing_ok=True)
        return document
    output_path.write_text(
        json.dumps(document, indent=2, sort_keys=False) + "\n",
        encoding="utf-8",
        newline="\n",
    )
    return document


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--template", type=Path, required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--image-digest", required=True)
    parser.add_argument("--image-reference", required=True)
    parser.add_argument("--source-revision", required=True)
    parser.add_argument("--generated-at")
    parser.add_argument(
        "--publish",
        action="store_true",
        help="render the document a release attaches: with no statement, write nothing",
    )
    args = parser.parse_args()
    document = render(
        args.template,
        args.output,
        image_digest=args.image_digest,
        image_reference=args.image_reference,
        source_revision=args.source_revision,
        generated_at=args.generated_at,
        publish=args.publish,
    )
    if args.publish and not document["statements"]:
        print(f"No reviewed exception: there is no VEX to publish, so {args.output} was not written.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
