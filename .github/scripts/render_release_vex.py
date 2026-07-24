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
_IMAGE_RE = re.compile(r"ghcr\.io/[a-z0-9._/-]+:v?[0-9]+\.[0-9]+\.[0-9]+\Z")
_TOKENS = {
    "__IMAGE_DIGEST__",
    "__IMAGE_REFERENCE__",
    "__SOURCE_REVISION__",
    "__GENERATED_AT__",
}


def render(
    template_path: Path,
    output_path: Path,
    *,
    image_digest: str,
    image_reference: str,
    source_revision: str,
    generated_at: str | None = None,
) -> dict:
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
    for token, value in replacements.items():
        if token not in source:
            raise ValueError(f"template is missing required token {token}")
        source = source.replace(token, value)
    if any(token in source for token in _TOKENS):
        raise ValueError("rendered VEX still contains an unresolved token")

    document = json.loads(source)
    expected_products = {
        f"pkg:oci/vault@{image_digest}?repository_url=ghcr.io/dockvault/vault",
        image_reference,
    }
    statements = document.get("statements")
    if not isinstance(statements, list) or not statements:
        raise ValueError("rendered VEX must contain statements")
    for statement in statements:
        products = {product["@id"] for product in statement.get("products", [])}
        if products != expected_products:
            raise ValueError(
                "every VEX statement must bind the digest and versioned image"
            )
        if source_revision not in statement.get("impact_statement", ""):
            raise ValueError(
                "every VEX impact statement must bind the reviewed source revision"
            )

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
    args = parser.parse_args()
    render(
        args.template,
        args.output,
        image_digest=args.image_digest,
        image_reference=args.image_reference,
        source_revision=args.source_revision,
        generated_at=args.generated_at,
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
