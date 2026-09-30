"""Fail-closed validation for a tag-triggered DockVault release.

A release comes from one of two places:

- `main`, the newest line. The tagged commit is an ancestor of origin/main.
- a maintenance line `release/X.Y`, for security fixes to an older minor once a newer one has
  shipped. The tagged commit is an ancestor of origin/release/X.Y and not of origin/main.

The gate says which, and derives from it what the publication may move: the version's own tag
always, `:vX.Y` only for the newest release of its line, and `:latest` (and GitHub's "latest
release") only for the highest version there is. Nothing is moved backwards.
"""

from __future__ import annotations

import argparse
import datetime
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Sequence


_VERSION_RE = re.compile(r"([0-9]+\.[0-9]+\.[0-9]+)\n", re.ASCII)
_TAG_REF_RE = re.compile(r"refs/tags/v([0-9]+\.[0-9]+\.[0-9]+)", re.ASCII)
# A released tag is named exactly vX.Y.Z. Anything else under refs/tags is not a release this
# workflow could have published (the tag trigger refuses it), so it takes no part in ordering.
_RELEASE_TAG_RE = re.compile(r"v((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})", re.ASCII)
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
    # True when this version ships without a declared upgrade path, by an explicit waiver in the
    # matrix. Carried out as a job output so the workflow can act on it; the durable record is the
    # waiver itself, which is in the release commit and in the published asset.
    upgrade_entry_waived: bool = False
    # "main" or "line" (a maintenance branch release/X.Y).
    channel: str = "main"
    # The moving image tags this release may take, besides its own vX.Y.Z: "vX.Y" when it is the
    # newest release of its line, and "latest" when it is the highest version there is. Empty when a
    # newer release of its line is already tagged on top of this commit and will take them itself.
    floating_tags: tuple[str, ...] = ()
    # Whether GitHub should show this release as the latest one. The same rule as `latest`.
    make_latest: bool = False
    # The release the notes compare against: the highest released tag below this version in this
    # commit's own history. Empty for the very first release.
    previous_tag: str = ""
    # A first line for the release notes of a maintenance release, else empty.
    notes_preamble: str = ""


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


def _commit_or_none(repository: Path, revision: str) -> str | None:
    result = _git(
        repository,
        ["rev-parse", "--verify", "--quiet", f"{revision}^{{commit}}"],
        check=False,
    )
    commit = result.stdout.strip()
    return commit if result.returncode == 0 and commit else None


def _is_ancestor(repository: Path, ancestor: str, descendant: str) -> bool:
    """True when `ancestor` is in `descendant`'s history (a commit is its own ancestor).

    git answers 0 for yes and 1 for no; anything else is a failure, which is not a "no".
    """
    result = _git(repository, ["merge-base", "--is-ancestor", ancestor, descendant], check=False)
    if result.returncode not in (0, 1):
        raise ReleaseGateError(f"cannot tell whether {ancestor} is an ancestor of {descendant}")
    return result.returncode == 0


def _version_key(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def _line(version: str) -> str:
    """The release line a version belongs to: "0.33" for 0.33.2."""
    major, minor, _ = _version_key(version)
    return f"{major}.{minor}"


def _release_tags(repository: Path) -> tuple[dict[str, str], dict[str, int | None]]:
    """Every released version in this checkout: the commit its tag names, and when it was tagged.

    Only an annotated tag records when it was made (its tagger's date). A lightweight tag carries no
    date of its own -- git reports its commit's, which says nothing about when the tag appeared -- so
    its time is None, as is one that cannot be read.

    A failure to read tags is an error rather than an empty answer: treating "cannot see" as "none
    exist" would switch off every check that compares this release with the others, exactly when it
    cannot do its job.
    """
    listed = _git(
        repository,
        ["for-each-ref",
         "--format=%(refname:strip=2)%09%(objecttype)%09%(objectname)%09%(*objecttype)"
         "%09%(*objectname)%09%(creatordate:unix)",
         "refs/tags/"],
        check=False,
    )
    if listed.returncode != 0:
        raise ReleaseGateError("cannot list tags, so this release cannot be placed among the others")
    tags: dict[str, str] = {}
    created: dict[str, int | None] = {}
    for line in listed.stdout.splitlines():
        fields = line.split("\t")
        if len(fields) != 6:
            raise ReleaseGateError("cannot read the tag list, so this release cannot be placed")
        name, kind, target, peeled_kind, peeled, when = fields
        match = _RELEASE_TAG_RE.fullmatch(name)
        if match is None:
            continue
        if kind == "commit":
            commit: str | None = target
        elif peeled_kind == "commit":
            commit = peeled
        else:
            commit = _commit_or_none(repository, f"refs/tags/{name}")
        # A tag that names no commit was never published by this workflow, which checks out the
        # tagged commit before anything else.
        if commit is None:
            continue
        tags[match.group(1)] = commit
        created[match.group(1)] = int(when) if kind == "tag" and when.isdigit() else None
    return tags, created


def validate_release(
    repository: Path,
    *,
    ref: str,
    event_sha: str,
    main_ref: str,
    repository_owner: str,
    version_file: Path | None = None,
    upgrade_matrix: Path | None = None,
    line_ref_prefix: str = "refs/remotes/origin/release/",
    today: datetime.date | None = None,
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

    tags, created = _release_tags(repository)
    placement, queued = _place_release(
        repository,
        version=version,
        head=head,
        tags=tags,
        main_ref=main_ref,
        line_ref_prefix=line_ref_prefix,
    )

    # The releases this one's matrix cannot know: tagged on top of it, or tagged after it. The gate
    # runs again just before publication, an hour or more after the tag, and by then a release on
    # another line may have been tagged too -- which is the prescribed order when a fix lands on
    # several lines (the older lines first, the newest last, within hours). Which was tagged first is
    # read from the tags themselves, so a release tag must say when it was made: an annotated tag
    # does, a lightweight one does not. A release tag whose time is unknown never counts as later.
    tagged_at = created.get(version)
    if tagged_at is None:
        raise ReleaseGateError(
            f"v{version} does not record when it was tagged: a release tag must be an annotated tag "
            f"(git tag -a v{version}), because its time decides which releases this one's matrix "
            "must already declare")
    later = queued | {v for v, when in created.items() if when is not None and when > tagged_at}

    waiver, data = _check_upgrade_matrix(
        upgrade_matrix or repository / "docs" / "upgrade-matrix.json",
        version,
        set(tags),
        later=frozenset(later),
        undated=frozenset(v for v, when in created.items() if when is None),
    )
    warning = line_support_warning(
        data, version, today or datetime.datetime.now(datetime.timezone.utc).date())
    if warning is not None:
        print(f"::warning::{warning}")

    return ReleaseMetadata(
        version=version,
        tag=f"v{version}",
        sha=head,
        image=f"ghcr.io/{repository_owner.lower()}/vault",
        upgrade_entry_waived=waiver is not None,
        **placement,
    )


def _place_release(
    repository: Path,
    *,
    version: str,
    head: str,
    tags: dict[str, str],
    main_ref: str,
    line_ref_prefix: str,
) -> tuple[dict, frozenset[str]]:
    """Decide where this release comes from and what it may move. Raises when it may not ship.

    Returns the ReleaseMetadata fields it decides, and the releases already tagged on top of this
    commit (which this commit's matrix cannot know about).

    The rule that holds everywhere: version order agrees with history. A release above this one (on
    main; on a maintenance branch, above it in its own line) may exist only as a descendant of this
    commit -- a newer release already tagged on top of it and queued behind this run, which is what
    happens when two releases are cut the same day. That one then takes the moving tags, and this run
    leaves them alone. A higher release anywhere else means this version is being cut out of order,
    and is refused.
    """
    main_commit = _commit_or_none(repository, main_ref)
    if main_commit is None:
        raise ReleaseGateError(f"cannot resolve {main_ref}, so the tagged commit cannot be placed")
    line = _line(version)
    minor = _version_key(version)[:2]

    if _is_ancestor(repository, head, main_commit):
        # Reachable from main, whether or not a maintenance branch also contains it: a release/X.Y
        # branch is cut from a tag on main, and that tag stays a main release.
        channel = "main"
    else:
        line_commit = _commit_or_none(repository, f"{line_ref_prefix}{line}")
        if line_commit is None or not _is_ancestor(repository, head, line_commit):
            raise ReleaseGateError(
                f"tagged commit is not an ancestor of origin/main, nor of the maintenance branch "
                f"release/{line}")
        channel = "line"
        # A maintenance branch serves a line that is no longer the newest. Until a newer minor has
        # shipped from main, patches to this line come from main itself, so main stays linear and
        # each new minor contains every fix of the one below it.
        newer_minor = sorted(
            (v for v in tags if _version_key(v)[:2] > minor), key=_version_key, reverse=True)
        if not any(_is_ancestor(repository, tags[v], main_commit) for v in newer_minor):
            raise ReleaseGateError(
                f"release/{line} can publish only after a newer minor has been released from main; "
                f"until then a {line} release comes from main")
        # The branch must start at a release of its own line. Cut from anywhere else, it would carry
        # main commits that no release of this line has ever contained.
        fork = _git(repository, ["merge-base", head, main_commit], check=False)
        fork_point = fork.stdout.strip() if fork.returncode == 0 else ""
        if not any(commit == fork_point for v, commit in tags.items()
                   if _version_key(v)[:2] == minor and v != version):
            raise ReleaseGateError(
                f"release/{line} does not branch from a released {line} tag on main")

    higher = sorted((v for v in tags if _version_key(v) > _version_key(version)), key=_version_key)
    if channel == "line":
        # Newer minors are expected above a maintenance release. Within its own line the rule holds.
        in_scope = [v for v in higher if _version_key(v)[:2] == minor]
    else:
        in_scope = higher
    out_of_order = [v for v in in_scope
                    if tags[v] == head or not _is_ancestor(repository, head, tags[v])]
    if out_of_order:
        raise ReleaseGateError(
            f"v{version} is below v{out_of_order[-1]}, which does not build on this commit; a "
            "release must be above every release before it")
    if in_scope:
        print(f"::warning::v{in_scope[-1]} is already tagged on top of this commit, so this release "
              "leaves the moving tags to it")

    floating: list[str] = []
    if not higher:
        floating.append("latest")
    if not any(_version_key(v)[:2] == minor for v in higher):
        floating.append(f"v{line}")

    below = sorted((v for v in tags if _version_key(v) < _version_key(version)),
                   key=_version_key, reverse=True)
    previous = next((v for v in below if _is_ancestor(repository, tags[v], head)), None)

    preamble = ""
    if channel == "line":
        newest = max(tags, key=_version_key)
        preamble = (f"Maintenance release of the {line} line. The newest release is "
                    f"v{newest}.")

    placement = {
        "channel": channel,
        "floating_tags": tuple(floating),
        "make_latest": "latest" in floating,
        "previous_tag": f"v{previous}" if previous else "",
        "notes_preamble": preamble,
    }
    return placement, frozenset(in_scope)


def line_support_warning(data: dict, version: str, today: datetime.date) -> str | None:
    """A warning, never a refusal, when this version's line is past its published support date.

    The promise is a minimum: a critical fix may still be worth shipping on a line whose support has
    ended, and the maintainer who tags it has decided so. Reads the matrix's optional top-level
    `lines` map; a matrix without one says nothing about support periods.
    """
    lines = data.get("lines")
    if not isinstance(lines, dict):
        return None
    entry = lines.get(_line(version))
    if not isinstance(entry, dict):
        return None
    until = entry.get("security_fixes_until")
    if not isinstance(until, str):
        return None
    try:
        ends = datetime.date.fromisoformat(until)
    except ValueError:
        return None
    if ends >= today:
        return None
    return (f"the {_line(version)} line's security fixes ended on {until}; this release is "
            "published after its support period")


def _upgrade_matrix_module():
    """Load the sibling validator by path rather than by name.

    A plain `import upgrade_matrix` works when this file is run as a script, because Python puts
    the script's own directory on the path -- but not when it is loaded by path, which is how the
    workflow-contract tests load it. Resolving relative to `__file__` works in both.
    """
    import importlib.util

    path = Path(__file__).resolve().parent / "upgrade_matrix.py"
    spec = importlib.util.spec_from_file_location("dockvault_upgrade_matrix", path)
    if spec is None or spec.loader is None:  # pragma: no cover - a broken checkout
        raise ReleaseGateError(f"cannot load the upgrade-matrix validator at {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _check_upgrade_matrix(
    path: Path, version: str, released: set[str], *, later: frozenset[str] = frozenset(),
    undated: frozenset[str] = frozenset(),
) -> tuple[str | None, dict]:
    """Require the release to have declared how an operator reaches it, and every other release too.

    Returns the stated reason when this version is waived in the matrix (else None), and the matrix.

    Every released tag must have its entry. The published file is what the site, the running app and
    the host tool read about every version, not only this one, so a release whose matrix misses an
    earlier release -- one cut on another line and never synced, say -- would tell every install of
    it nothing about that release. The exception is `later`: releases tagged after this one, or on
    top of it, which its file cannot know about.

    The escape hatch is a `waivers` entry in the file rather than a command-line flag. A flag would
    have to be threaded through a tag-triggered workflow to be reachable at all, and once passed it
    leaves no trace in anything published -- so a waived release would be indistinguishable from a
    declared one. Declaring it in the file makes the omission part of the release commit, part of
    the diff, and part of the published asset, and it goes stale-with-an-error once the version is
    properly declared, so the hatch cannot quietly become the normal route.

    Either way the file itself must still validate. Shipping without a declared path is a judgement
    call a maintainer can make under time pressure; shipping a matrix that does not parse breaks
    the asset and every consumer of it, for every version, not just this one.
    """
    matrix = _upgrade_matrix_module()
    try:
        # A vulnerability's `fixed_in` may not name a version that is not released yet. The ceiling is
        # the newest released version: the highest of the already-released tags and the one being cut
        # now (which is being released by this very run). Taking the max rather than just the version
        # being cut keeps it correct for a backport, whose version is below the newest release.
        newest_released = max({version} | released, key=_version_key)
        data = matrix.validate_matrix(matrix.load_matrix(path), released_ceiling=newest_released)
        matrix.assert_no_phantom_versions(data, released, version)
        reason = matrix.assert_release_declared(data, version)
    except matrix.UpgradeMatrixError as exc:
        raise ReleaseGateError(str(exc)) from exc

    # The version being cut is covered above, with its own message and its own waiver.
    undeclared = sorted(
        (v for v in released if v != version and v not in later and v not in data["versions"]),
        key=_version_key)
    if undeclared:
        # Say why a tag that may well be newer still counts: it cannot show that it is.
        lightweight = [f"v{v}" for v in undeclared if v in undated]
        hint = (f" ({', '.join(lightweight)}: a lightweight tag does not record when it was made, "
                "so it cannot count as tagged after this one; release tags must be annotated)"
                if lightweight else "")
        raise ReleaseGateError(
            f"docs/upgrade-matrix.json has no entry for the released version(s) "
            f"{', '.join(undeclared)}; bring the matrix up to date with every release before "
            f"cutting this one{hint}")

    if reason is not None:
        print(f"::warning::{version} ships without a declared upgrade path: {reason}")
    return reason, data


def write_github_outputs(path: Path, metadata: ReleaseMetadata) -> None:
    with path.open("a", encoding="utf-8", newline="\n") as stream:
        stream.write(f"version={metadata.version}\n")
        stream.write(f"tag={metadata.tag}\n")
        stream.write(f"sha={metadata.sha}\n")
        stream.write(f"image={metadata.image}\n")
        stream.write(
            f"upgrade_entry_waived={'true' if metadata.upgrade_entry_waived else 'false'}\n")
        stream.write(f"channel={metadata.channel}\n")
        stream.write(f"floating_tags={' '.join(metadata.floating_tags)}\n")
        stream.write(f"make_latest={'true' if metadata.make_latest else 'false'}\n")
        stream.write(f"previous_tag={metadata.previous_tag}\n")
        stream.write(f"notes_preamble={metadata.notes_preamble}\n")


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repository", type=Path, default=Path("."))
    parser.add_argument("--ref", required=True)
    parser.add_argument("--event-sha", required=True)
    parser.add_argument("--main-ref", default="refs/remotes/origin/main")
    parser.add_argument("--line-ref-prefix", default="refs/remotes/origin/release/")
    parser.add_argument("--repository-owner", required=True)
    parser.add_argument("--version-file", type=Path)
    parser.add_argument("--upgrade-matrix", type=Path)
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
            line_ref_prefix=args.line_ref_prefix,
            repository_owner=args.repository_owner,
            version_file=args.version_file,
            upgrade_matrix=args.upgrade_matrix,
        )
        write_github_outputs(args.github_output, metadata)
    except ReleaseGateError as exc:
        print(f"::error::Release validation failed: {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
