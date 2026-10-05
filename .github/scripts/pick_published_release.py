"""Pick the published release a scenario should install: the highest one not above this checkout.

Reads GitHub's releases list (the JSON array of `GET /repos/{owner}/{repo}/releases`) on stdin and
prints the chosen tag, `vX.Y.Z`, or nothing when no release qualifies.

The list's order is not something to rely on. GitHub sorts it by each release's creation time, which
is the time of its tagged commit rather than of publication, so a maintenance release of an older
line made after a newer minor comes first. Taking the first entry would then install an older line
than the checkout's; taking the highest version overall would, on a maintenance branch, install a
newer line than the one under test. So: drafts and prereleases are skipped, and of the rest the
highest version that is not above the checkout's own VERSION wins.

Exit status 2 means the input could not be read as a releases list; the caller retries.

Stdlib only, like the rest of the release scripts.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path
from typing import Sequence

_TAG_RE = re.compile(r"v((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})", re.ASCII)
_VERSION_RE = re.compile(r"((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})\n?", re.ASCII)


def _key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def pick(releases: object, ceiling: str) -> str | None:
    """The highest published, final release whose version is not above `ceiling`, or None."""
    if not isinstance(releases, list):
        raise ValueError("the releases list is not a JSON array")
    best: tuple[tuple[int, int, int], str] | None = None
    for release in releases:
        if not isinstance(release, dict):
            continue
        if release.get("draft") is not False or release.get("prerelease") is not False:
            continue
        tag = release.get("tag_name")
        match = _TAG_RE.fullmatch(tag) if isinstance(tag, str) else None
        if match is None:
            continue
        key = _key(match.group(1))
        if key > _key(ceiling):
            continue
        if best is None or key > best[0]:
            best = (key, tag)
    return None if best is None else best[1]


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--version-file", type=Path, required=True)
    args = parser.parse_args(argv)

    match = _VERSION_RE.fullmatch(args.version_file.read_text(encoding="utf-8"))
    if match is None:
        print(f"{args.version_file} does not hold a version", file=sys.stderr)
        return 2
    try:
        chosen = pick(json.load(sys.stdin), match.group(1))
    except ValueError as exc:
        print(f"cannot read the releases list: {exc}", file=sys.stderr)
        return 2
    if chosen is not None:
        print(chosen)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
