"""Keep one upgrade matrix across main and the maintenance branches.

main's docs/upgrade-matrix.json is the master copy: the site, the running app and the host tool all
read it. A maintenance branch release/X.Y carries main's matrix plus its own newest entry, and after
a release on that branch main takes the entry in turn. Merging the file by hand across branches is
how entries get lost or reordered, so both directions go through this script, and it writes the
same bytes whichever side runs it.

    python3 .github/scripts/matrix_sync.py sync --main MAIN.json --branch BRANCH.json [--output OUT]

        Writes main's matrix plus what the branch has and main does not: its version entries, the
        edges it declares that main does not, waivers, and advisories main does not have yet
        together with each version's reference to them (and that version's `secure` flag). Where
        both declare the same thing, main's is kept and the difference is reported. The result is
        validated before anything is written. OUT defaults to BRANCH.json.

        On a maintenance branch, before its release commit:
            git show origin/main:docs/upgrade-matrix.json > /tmp/main.json
            python3 .github/scripts/matrix_sync.py sync --main /tmp/main.json \\
                --branch docs/upgrade-matrix.json
        On main, after a release on that branch:
            git show origin/release/X.Y:docs/upgrade-matrix.json > /tmp/line.json
            python3 .github/scripts/matrix_sync.py sync --main docs/upgrade-matrix.json \\
                --branch /tmp/line.json --output docs/upgrade-matrix.json

    python3 .github/scripts/matrix_sync.py check A.json B.json

        Exit status 0 when the two files are byte-identical, 1 otherwise, naming the first line
        that differs. After both syncs, main's file and the branch's are identical.

Stdlib only, like the rest of the release scripts.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from typing import Sequence


class MatrixSyncError(ValueError):
    """The two matrices cannot be combined into a valid one."""


# The top-level keys combined entry by entry. Any other key is main's, and a branch that differs
# there is reported, like an entry both declare.
_MERGED = ("versions", "edges", "advisories", "waivers")


def _validator():
    path = Path(__file__).resolve().parent / "upgrade_matrix.py"
    spec = importlib.util.spec_from_file_location("dockvault_upgrade_matrix_for_sync", path)
    if spec is None or spec.loader is None:  # pragma: no cover - a broken checkout
        raise MatrixSyncError(f"cannot load the upgrade-matrix validator at {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


def _key(version: str) -> tuple[int, ...]:
    return tuple(int(part) for part in version.split("."))


def _edge_key(edge: dict) -> tuple[tuple[int, ...], tuple[int, ...]]:
    return _key(edge["to"]), _key(edge["from"])


def _copy(value):
    return json.loads(json.dumps(value))


def render(data: dict) -> bytes:
    """The one serialisation every branch writes: two-space indent, UTF-8, a final newline."""
    return (json.dumps(data, indent=2, ensure_ascii=False) + "\n").encode("utf-8")


def _insert_versions(versions: dict, extra: dict) -> dict:
    """main's versions in main's order, each extra one placed after the last lower version."""
    ordered = list(versions.items())
    for version in sorted(extra, key=_key):
        position = 0
        for index, (existing, _) in enumerate(ordered):
            if _key(existing) < _key(version):
                position = index + 1
        ordered.insert(position, (version, extra[version]))
    return dict(ordered)


def _insert_edges(edges: list, extra: list) -> list:
    """main's edges in main's order, each extra one placed after the last edge that sorts below it."""
    merged = list(edges)
    for edge in sorted(extra, key=_edge_key):
        position = 0
        for index, existing in enumerate(merged):
            if _edge_key(existing) < _edge_key(edge):
                position = index + 1
        merged.insert(position, edge)
    return merged


def sync(main: dict, branch: dict) -> tuple[dict, list[str]]:
    """main's matrix plus what only the branch has. Returns the result and notes on what was done."""
    for name, data in (("main", main), ("branch", branch)):
        for field, kind in (("versions", dict), ("edges", list), ("advisories", dict)):
            if not isinstance(data.get(field), kind):
                raise MatrixSyncError(f"the {name} matrix has no {field} {kind.__name__}")

    notes: list[str] = []
    result: dict = {}
    for field in list(main) + [f for f in branch if f not in main]:
        result[field] = _copy(main[field] if field in main else branch[field])
        if field not in main:
            notes.append(f"took '{field}' from the branch; main has none")
        elif field in branch and field not in _MERGED and branch[field] != main[field]:
            notes.append(f"kept main's '{field}'; the branch's differs")

    extra_versions = {v: _copy(e) for v, e in branch["versions"].items() if v not in main["versions"]}
    for version, entry in branch["versions"].items():
        if version in main["versions"] and entry != main["versions"][version]:
            notes.append(f"kept main's entry for {version}; the branch's differs")
    result["versions"] = _insert_versions(result["versions"], extra_versions)
    for version in extra_versions:
        notes.append(f"took {version} from the branch")

    main_edges = {(e["from"], e["to"]): e for e in main["edges"]}
    extra_edges = []
    for edge in branch["edges"]:
        pair = (edge["from"], edge["to"])
        if pair not in main_edges:
            extra_edges.append(_copy(edge))
            notes.append(f"took the edge {pair[0]} -> {pair[1]} from the branch")
        elif edge != main_edges[pair]:
            notes.append(f"kept main's edge {pair[0]} -> {pair[1]}; the branch's differs")
    result["edges"] = _insert_edges(result["edges"], extra_edges)

    for slug, record in branch["advisories"].items():
        if slug in main["advisories"]:
            if record != main["advisories"][slug]:
                notes.append(f"kept main's advisory {slug}; the branch's differs")
            continue
        result["advisories"][slug] = _copy(record)
        notes.append(f"took the advisory {slug} from the branch")
        # Each version the branch marks as affected carries the reference, and with it the flag that
        # says the version is not secure; a version only the branch declares already has both.
        for version, entry in branch["versions"].items():
            if version in extra_versions or version not in result["versions"]:
                continue
            refs = [r for r in entry.get("vulnerabilities") or [] if r.get("advisory") == slug]
            if not refs:
                continue
            target = result["versions"][version]
            support = entry.get("support")
            if (not isinstance(support, dict) or "secure" not in support
                    or not isinstance(target.get("support"), dict)):
                raise MatrixSyncError(
                    f"{version} has no support block to carry whether {slug} leaves it secure")
            target.setdefault("vulnerabilities", []).extend(_copy(refs))
            target["support"]["secure"] = support["secure"]

    if "waivers" in branch:
        waived = {w.get("version") for w in result.get("waivers", [])}
        for waiver in branch["waivers"]:
            if waiver.get("version") not in waived:
                result.setdefault("waivers", []).append(_copy(waiver))
                notes.append(f"took the waiver for {waiver.get('version')} from the branch")

    validator = _validator()
    try:
        validator.validate_matrix(result, released_ceiling=None)
    except validator.UpgradeMatrixError as exc:
        raise MatrixSyncError(f"the combined matrix is not valid: {exc}") from exc
    return result, notes


def first_difference(a: bytes, b: bytes) -> str | None:
    """None when identical; otherwise where the two first differ, by line."""
    if a == b:
        return None
    lines_a, lines_b = a.split(b"\n"), b.split(b"\n")
    for number, (left, right) in enumerate(zip(lines_a, lines_b), start=1):
        if left != right:
            return f"line {number} differs"
    return f"one file ends at line {min(len(lines_a), len(lines_b))}"


def _load(path: Path) -> dict:
    try:
        data = json.loads(path.read_bytes().decode("utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise MatrixSyncError(f"cannot read {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise MatrixSyncError(f"{path} is not a JSON object")
    return data


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n", 1)[0])
    commands = parser.add_subparsers(dest="command", required=True)
    do_sync = commands.add_parser("sync")
    do_sync.add_argument("--main", type=Path, required=True)
    do_sync.add_argument("--branch", type=Path, required=True)
    do_sync.add_argument("--output", type=Path)
    do_check = commands.add_parser("check")
    do_check.add_argument("first", type=Path)
    do_check.add_argument("second", type=Path)
    args = parser.parse_args(argv)

    try:
        if args.command == "check":
            where = first_difference(args.first.read_bytes(), args.second.read_bytes())
            if where is not None:
                print(f"{args.first} and {args.second} differ: {where}")
                return 1
            print(f"{args.first} and {args.second} are identical")
            return 0
        result, notes = sync(_load(args.main), _load(args.branch))
        (args.output or args.branch).write_bytes(render(result))
    except (MatrixSyncError, OSError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1
    for note in notes:
        print(note)
    print(f"wrote {args.output or args.branch}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
