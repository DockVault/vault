"""Fail-closed validation for a tag-triggered DockVault release."""

from __future__ import annotations

import argparse
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_VERSION_RE = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)\n", re.ASCII)
_TAG_REF_RE = re.compile(r"refs/tags/v([0-9]+\.[0-9]+\.[0-9]+)", re.ASCII)
_OWNER_RE = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})", re.ASCII)
_UTF8_BOM = b"\xef\xbb\xbf"


class ReleaseGateError(ValueError):
    """The candidate release does not satisfy the publication contract."""


@dataclass(frozen=True)
class ReleaseMetadata:
    version: str
    tag: str
    sha: str
    image: str


def read_canonical_version(path: Path) -> str:
    raw = path.read_bytes()
    if raw.startswith(_UTF8_BOM):
        raise ReleaseGateError("VERSION must not contain a UTF-8 BOM")
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeDecodeError as exc:
        raise ReleaseGateError("VERSION is not valid UTF-8") from exc
    match = _VERSION_RE.fullmatch(text)
    if match is None:
        raise ReleaseGateError("VERSION must be exactly X.Y.Z followed by one LF")
    return match.group(1)


def version_from_tag_ref(ref: str) -> str:
    match = _TAG_REF_RE.fullmatch(ref)
    if match is None:
        raise ReleaseGateError("release ref must be exactly refs/tags/vX.Y.Z")
    return match.group(1)


def _git(
    repository: Path,
    args: Sequence[str],
    *,
    check: bool = True,
) -> subprocess.CompletedProcess[str]:
    try:
        return subprocess.run(
            ["git", *args],
            cwd=repository,
            check=check,
            capture_output=True,
            text=True,
            timeout=30,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise ReleaseGateError(f"git {' '.join(args)} failed") from exc


def _commit(repository: Path, revision: str) -> str:
    result = _git(repository, ["rev-parse", "--verify", f"{revision}^{{commit}}"])
    return result.stdout.strip()


def validate_release(
    repository: Path,
    *,
    ref: str,
    event_sha: str,
    main_ref: str,
    repository_owner: str,
    version_file: Path | None = None,
) -> ReleaseMetadata:
    repository = repository.resolve()
    version = read_canonical_version(version_file or repository / "VERSION")
    tag_version = version_from_tag_ref(ref)
    if tag_version != version:
        raise ReleaseGateError(f"tag v{tag_version} does not match VERSION {version}")
    if _OWNER_RE.fullmatch(repository_owner) is None:
        raise ReleaseGateError("repository owner is not a valid container namespace")

    head = _commit(repository, "HEAD")
    tagged = _commit(repository, ref)
    event = _commit(repository, event_sha)
    if len({head, tagged, event}) != 1:
        raise ReleaseGateError("checkout, tag, and event do not resolve to one immutable commit")

    ancestry = _git(
        repository,
        ["merge-base", "--is-ancestor", head, main_ref],
        check=False,
    )
    if ancestry.returncode != 0:
        raise ReleaseGateError("tagged commit is not an ancestor of origin/main")

    return ReleaseMetadata(
        version=version,
        tag=f"v{version}",
        sha=head,
        image=f"ghcr.io/{repository_owner.lower()}/vault",
    )


def write_github_outputs(path: Path, metadata: ReleaseMetadata) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"version={metadata.version}\n")
        stream.write(f"tag={metadata.tag}\n")
        stream.write(f"sha={metadata.sha}\n")
        stream.write(f"image={metadata.image}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--ref", required=True)
    parser.add_argument("--event-sha", required=True)
    parser.add_argument("--main-ref", default="refs/remotes/origin/main")
    parser.add_argument("--repository-owner", required=True)
    parser.add_argument("--version-file", type=Path)
    parser.add_argument("--github-output", type=Path, required=True)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        metadata = validate_release(
            args.repository,
            ref=args.ref,
            event_sha=args.event_sha,
            main_ref=args.main_ref,
            repository_owner=args.repository_owner,
            version_file=args.version_file,
        )
        write_github_outputs(args.github_output, metadata)
    except ReleaseGateError as exc:
        print(f"::error::Release validation failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
