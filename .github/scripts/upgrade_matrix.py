"""Validate the declared upgrade matrix, and refuse a release that has not declared itself.

`docs/upgrade-matrix.json` says what it takes to move between released versions. Its value depends
entirely on being complete: a claim about upgrading is only worth something if every release is
obliged to make one. So the release workflow calls `assert_release_declared` and will not cut a tag
whose version is absent.

The one way past that is a `waivers` entry naming the version and the reason. It lives in the file
rather than in a command-line flag on purpose: a flag would have to be threaded through a
tag-triggered workflow to be reachable at all, and once passed it would leave no trace in anything
published, so a waived release would look exactly like a declared one. In the file, the omission is
part of the release commit, part of the diff, and part of the published asset -- and it becomes a
validation error once the version is properly declared, so the hatch cannot drift into being the
normal route.

Validation is deliberately strict and rejects unknown keys at every level. The file is committed to
this repository and so is trusted in origin, but it is also published as a release asset and read by
things outside it; a validator that silently ignores a misspelt key would let a typo'd condition
disappear from the operator-facing side while still passing here.

Stdlib only, like the rest of the release scripts.
"""

from __future__ import annotations

import json
import re
from pathlib import Path

# Generous next to a file that holds a few dozen short records, and small enough that a runaway or
# hostile file cannot make the parser the problem.
MAX_BYTES = 256 * 1024
SUPPORTED_SCHEMA_VERSION = 1

_UTF8_BOM = b"\xef\xbb\xbf"
_VERSION_RE = re.compile(r"[0-9]+\.[0-9]+\.[0-9]+", re.ASCII)
_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)

KINDS = ("direct", "blocked")

_VERSION_KEYS = {"released", "notes"}
_EDGE_KEYS = {"from", "to", "kind", "reversible", "requires_backup", "reason", "conditions"}
_CONDITION_KEYS = {"id", "summary", "detect"}
_WAIVER_KEYS = {"version", "reason"}
_TOP_KEYS = {"schema_version", "about", "kinds", "versions", "edges", "waivers"}


class UpgradeMatrixError(ValueError):
    """The upgrade matrix does not satisfy its contract."""


def _sort_key(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split("."))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise UpgradeMatrixError(message)


def _string(value: object, where: str, *, pattern: re.Pattern[str] | None = None) -> str:
    _require(isinstance(value, str), f"{where} must be a string")
    text = value  # type: ignore[assignment]
    _require(bool(text.strip()), f"{where} must not be empty")
    if pattern is not None:
        _require(pattern.fullmatch(text) is not None, f"{where} is malformed: {text!r}")
    return text


def _no_unknown_keys(mapping: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    _require(not unknown, f"{where} has unknown key(s): {', '.join(unknown)}")


def load_matrix(path: Path) -> dict:
    """Read and parse the matrix, refusing anything that is not plainly a UTF-8 JSON object."""
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UpgradeMatrixError(f"cannot read the upgrade matrix: {exc}") from exc
    _require(len(raw) <= MAX_BYTES, f"upgrade matrix is larger than {MAX_BYTES} bytes")
    _require(not raw.startswith(_UTF8_BOM), "upgrade matrix must not contain a UTF-8 BOM")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpgradeMatrixError(f"upgrade matrix is not valid UTF-8 JSON: {exc}") from exc
    _require(isinstance(data, dict), "upgrade matrix must be a JSON object")
    return data


def validate_matrix(data: dict) -> dict:
    """Check the whole file. Returns it unchanged so callers can chain."""
    _no_unknown_keys(data, _TOP_KEYS, "upgrade matrix")
    _require(
        data.get("schema_version") == SUPPORTED_SCHEMA_VERSION,
        f"upgrade matrix schema_version must be {SUPPORTED_SCHEMA_VERSION}, "
        f"got {data.get('schema_version')!r}",
    )

    # `about` and `kinds` are what make the published asset readable on its own, by someone who
    # fetched upgrade.json and has no repository to consult. Validated rather than merely permitted:
    # a validator that rejects unknown keys but ignores known ones would let the self-description
    # rot into something misleading while still passing.
    _string(data.get("about"), "upgrade matrix 'about'")
    kinds = data.get("kinds")
    _require(isinstance(kinds, dict), "upgrade matrix 'kinds' must be an object")
    _require(
        set(kinds) == set(KINDS),
        f"upgrade matrix 'kinds' must describe exactly {', '.join(KINDS)}; got "
        f"{', '.join(sorted(kinds)) or 'nothing'}",
    )
    for kind, description in kinds.items():
        _string(description, f"kinds[{kind}]")

    versions = data.get("versions")
    _require(isinstance(versions, dict) and versions, "upgrade matrix needs a non-empty 'versions'")
    for version, meta in versions.items():
        _string(version, "version key", pattern=_VERSION_RE)
        _require(isinstance(meta, dict), f"versions[{version}] must be an object")
        _no_unknown_keys(meta, _VERSION_KEYS, f"versions[{version}]")
        _string(meta.get("released"), f"versions[{version}].released", pattern=_DATE_RE)
        _string(meta.get("notes"), f"versions[{version}].notes")

    edges = data.get("edges")
    _require(isinstance(edges, list), "upgrade matrix needs an 'edges' list")

    seen: set[tuple[str, str]] = set()
    for index, edge in enumerate(edges):
        where = f"edges[{index}]"
        _require(isinstance(edge, dict), f"{where} must be an object")
        _no_unknown_keys(edge, _EDGE_KEYS, where)
        source = _string(edge.get("from"), f"{where}.from", pattern=_VERSION_RE)
        target = _string(edge.get("to"), f"{where}.to", pattern=_VERSION_RE)
        # An edge naming a version that does not exist is the failure this catches most often in
        # practice -- a typo in a version number, which would otherwise publish a path to nowhere.
        _require(source in versions, f"{where}.from is not a declared version: {source}")
        _require(target in versions, f"{where}.to is not a declared version: {target}")
        _require(source != target, f"{where} goes from {source} to itself")
        _require((source, target) not in seen, f"duplicate edge {source} -> {target}")
        seen.add((source, target))

        kind = _string(edge.get("kind"), f"{where}.kind")
        _require(kind in KINDS, f"{where}.kind must be one of {', '.join(KINDS)}, got {kind!r}")

        # Required, not defaulted. These are the two things an operator most needs to know before
        # starting, and a default would answer for a release author who never considered the
        # question -- in whichever direction the default happened to point.
        for flag in ("reversible", "requires_backup"):
            _require(isinstance(edge.get(flag), bool),
                     f"{where}.{flag} must be present and a boolean")

        if kind == "blocked":
            # A blocked edge that does not say why tells an operator nothing they can act on.
            #
            # There is deliberately no "go via X" field. Edges are adjacency-only, and every
            # adjacent pair must have one, so a genuine intermediate version cannot exist for an
            # adjacent edge -- declaring one would make the pair non-adjacent and this edge
            # unnecessary. A field that can never be filled meaningfully is worse than no field:
            # it looks like an answer. The reason carries whatever the operator should do instead.
            _string(edge.get("reason"), f"{where}.reason")
        else:
            _require("reason" not in edge, f"{where}.reason is only meaningful on a blocked edge")

        conditions = edge.get("conditions", [])
        _require(isinstance(conditions, list), f"{where}.conditions must be a list")
        condition_ids: set[str] = set()
        for position, condition in enumerate(conditions):
            spot = f"{where}.conditions[{position}]"
            _require(isinstance(condition, dict), f"{spot} must be an object")
            _no_unknown_keys(condition, _CONDITION_KEYS, spot)
            identifier = _string(condition.get("id"), f"{spot}.id", pattern=_ID_RE)
            _require(identifier not in condition_ids, f"{spot}.id is repeated: {identifier}")
            condition_ids.add(identifier)
            _string(condition.get("summary"), f"{spot}.summary")
            if "detect" in condition:
                _string(condition.get("detect"), f"{spot}.detect")

    # Adjacency completeness. Declaring edges only between neighbours is what lets a longer upgrade
    # be composed by walking them, so a missing neighbour link silently breaks every path across it.
    ordered = sorted(versions, key=_sort_key)
    missing = [f"{a} -> {b}" for a, b in zip(ordered, ordered[1:]) if (a, b) not in seen]
    _require(not missing, "no edge declared between adjacent releases: " + ", ".join(missing))

    waivers = data.get("waivers", [])
    _require(isinstance(waivers, list), "upgrade matrix 'waivers' must be a list")
    waived: set[str] = set()
    for index, waiver in enumerate(waivers):
        where = f"waivers[{index}]"
        _require(isinstance(waiver, dict), f"{where} must be an object")
        _no_unknown_keys(waiver, _WAIVER_KEYS, where)
        version = _string(waiver.get("version"), f"{where}.version", pattern=_VERSION_RE)
        _string(waiver.get("reason"), f"{where}.reason")
        _require(version not in waived, f"{where} waives {version} twice")
        waived.add(version)
        # A waiver for a version that IS declared is stale, and a stale waiver is how an escape
        # hatch quietly becomes the normal route. Erroring forces it to be removed.
        _require(
            version not in versions,
            f"{where} waives {version}, which is declared anyway -- remove the waiver",
        )

    return data


def waived_versions(data: dict) -> dict[str, str]:
    """Versions allowed to ship undeclared, mapped to the stated reason."""
    return {w["version"]: w["reason"] for w in data.get("waivers", [])}


def assert_release_declared(data: dict, version: str) -> str | None:
    """Refuse a release that has not said how to reach it. Returns a waiver reason, or None.

    Three obligations, because each alone leaves a hole: the version has to exist, the release
    before it has to have an edge leading here, and that edge has to describe an upgrade someone
    can actually take. A version entry with no inbound edge is reachable from nowhere, which is a
    name rather than a declaration -- and an inbound edge marked `blocked` says in so many words
    that the upgrade must not be taken, which is not a way to reach the release either.
    """
    waived = waived_versions(data)
    if version in waived:
        return waived[version]

    versions = data.get("versions", {})
    if version not in versions:
        raise UpgradeMatrixError(
            f"{version} has no entry in docs/upgrade-matrix.json. Add one saying how an operator "
            "reaches it from the previous release before cutting the tag"
        )

    ordered = sorted(versions, key=_sort_key)
    index = ordered.index(version)
    if index == 0:
        return None  # the earliest declared release has nothing before it
    previous = ordered[index - 1]
    inbound = {
        (edge["from"], edge["to"]): edge for edge in data.get("edges", [])
    }.get((previous, version))
    if inbound is None:
        raise UpgradeMatrixError(
            f"docs/upgrade-matrix.json declares {version} but no edge from {previous} to it, so "
            "nothing says how to get there"
        )
    if inbound["kind"] == "blocked":
        raise UpgradeMatrixError(
            f"the only way into {version} is an edge from {previous} marked blocked "
            f"({inbound['reason']}), so the matrix says this release cannot be reached. Declare a "
            "route that can be taken, or waive it deliberately"
        )
    return None


def validate_matrix_file(path: Path, version: str | None = None) -> dict:
    """Load, validate, and optionally require that `version` has declared itself."""
    data = validate_matrix(load_matrix(path))
    if version is not None:
        assert_release_declared(data, version)
    return data
