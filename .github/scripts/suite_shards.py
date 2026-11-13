#!/usr/bin/env python3
"""Which test files each shard of the full suite runs.

The tests that need a running stack run in several jobs at once, each on a stack of its own. This
script decides which test files a job runs, from `.github/suite-shards.json`:

- `shards`: how many jobs there are.
- `seconds`: for each test file whose tests needed the stack when the times were recorded, how long
  those tests took in one full run.

A listed file goes to the shard that is lightest when its turn comes, heaviest file first, so the
shards take about the same time. A file the data does not list (a new test file, or one whose tests
all run offline) goes to the shard a hash of its path names. Either way a file's shard depends only
on the data file and on the file's own path: adding or deleting a test file moves no other file,
and two branches that each add tests need not touch the data.

Every test file is in exactly one shard, the offline-only ones included. Each shard runs its files
with the offline lane's marker expression negated, so a file's offline tests are not run a second
time there and a file that has no other tests runs nothing.

Usage:
  suite_shards.py files --shard N     the files shard N runs, one per line
  suite_shards.py count               how many shards there are
  suite_shards.py balance             each shard's files and recorded time, and what the data names
                                      that is no longer there
  suite_shards.py record REPORT       write the seconds again, from the joined report of a full run
                                      (the `pytest-results` artifact)
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(".github") / "suite-shards.json"

# Directories pytest does not look for tests in (its `norecursedirs` default), as far as they can
# occur under tests/: a hidden directory is where a local virtual environment usually lives.
_NOT_SEARCHED = {"__pycache__", "build", "dist", "node_modules", "venv"}


def load(path: Path) -> tuple[int, dict[str, float]]:
    """The shard count and the recorded seconds per file, checked."""
    data = json.loads(path.read_text(encoding="utf-8"))
    shards, seconds = data.get("shards"), data.get("seconds")
    if isinstance(shards, bool) or not isinstance(shards, int) or shards < 1:
        raise ValueError("`shards` must be a whole number of at least 1")
    if not isinstance(seconds, dict):
        raise ValueError("`seconds` must map test files to seconds")
    for name, value in seconds.items():
        if isinstance(value, bool) or not isinstance(value, (int, float)) or value < 0:
            raise ValueError(f"`seconds` of {name} must be a number, zero or more")
        if not (name.startswith("tests/") and name.rsplit("/", 1)[1].startswith("test_")
                and name.endswith(".py") and "\\" not in name):
            raise ValueError(f"`seconds` names {name}, which is not a test file's path")
    return shards, seconds


def suite_files(root: Path) -> list[str]:
    """Every file pytest collects from: `test_*.py` anywhere under `tests/` (pytest.ini)."""
    found = []
    for path in (root / "tests").rglob("test_*.py"):
        relative = path.relative_to(root)
        if any(part.startswith(".") or part in _NOT_SEARCHED for part in relative.parts[:-1]):
            continue
        found.append(relative.as_posix())
    return sorted(found)


def hashed_shard(path: str, shards: int) -> int:
    """The shard (from 1) of a file the data does not list: the same on every machine and run."""
    digest = hashlib.sha256(path.encode("utf-8")).digest()
    return int.from_bytes(digest[:8], "big") % shards + 1


def place_listed(seconds: dict[str, float], shards: int) -> dict[str, int]:
    """Each listed file's shard (from 1): heaviest first, each to the lightest shard so far.

    Every listed file takes its turn, one that no longer exists too, so deleting a test file leaves
    the others where they were. Loads are whole tenths of a second, so the sums are exact.
    """
    loads = [0] * shards
    placed = {}
    for path in sorted(seconds, key=lambda name: (-seconds[name], name)):
        lightest = min(range(shards), key=lambda index: (loads[index], index))
        loads[lightest] += round(seconds[path] * 10)
        placed[path] = lightest + 1
    return placed


def assign(files: list[str], seconds: dict[str, float], shards: int) -> dict[str, int]:
    """The shard (from 1) of every file in `files`."""
    placed = place_listed(seconds, shards)
    return {path: placed[path] if path in placed else hashed_shard(path, shards) for path in files}


def missing_files(files: list[str], seconds: dict[str, float]) -> list[str]:
    """Files the data lists that are not there any more."""
    return sorted(set(seconds) - set(files))


def balance(files: list[str], seconds: dict[str, float], shards: int) -> list[dict]:
    """Per shard: how many files, how many of them listed, and their recorded seconds."""
    assigned = assign(files, seconds, shards)
    rows = [{"shard": number, "files": 0, "listed": 0, "seconds": 0.0} for number in range(1, shards + 1)]
    for path, shard in assigned.items():
        row = rows[shard - 1]
        row["files"] += 1
        if path in seconds:
            row["listed"] += 1
            row["seconds"] += seconds[path]
    return rows


def recorded_seconds(report: Path, files: list[str]) -> tuple[dict[str, float], int]:
    """Seconds of stack tests per test file, from the shards' suites of a joined report.

    Also returns how many cases belong to no file that is there. A case's class name is its file's
    path with dots for slashes, then any classes: the longest leading part that is a file is its
    file. The offline lane's suite is left out: its tests are not stack tests.
    """
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"no usable report ({exc})") from exc
    suites = [suite for suite in root.iter("testsuite") if (suite.get("name") or "").startswith("shard-")]
    if not suites:
        raise ValueError("the report holds no shard's suite; give the joined report of a full run")
    modules = {path[:-3].replace("/", "."): path for path in files}
    totals: dict[str, float] = {}
    unplaced = 0
    for suite in suites:
        for case in suite.iter("testcase"):
            parts = (case.get("classname") or "").split(".")
            path = next((modules[".".join(parts[:end])] for end in range(len(parts), 0, -1)
                         if ".".join(parts[:end]) in modules), None)
            if path is None:
                unplaced += 1
            else:
                totals[path] = totals.get(path, 0.0) + float(case.get("time") or 0)
    return {path: round(totals[path], 1) for path in sorted(totals)}, unplaced


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--root", type=Path, default=ROOT, help="the repository (default: this one)")
    parser.add_argument("--data", type=Path, default=None, help="the shard data (default: .github/suite-shards.json)")
    commands = parser.add_subparsers(dest="command", required=True)
    files_command = commands.add_parser("files", help="the files one shard runs, one per line")
    files_command.add_argument("--shard", type=int, required=True)
    commands.add_parser("count", help="how many shards there are")
    commands.add_parser("balance", help="each shard's files and recorded time")
    record_command = commands.add_parser("record", help="write the seconds again from a joined report")
    record_command.add_argument("report", type=Path)
    args = parser.parse_args(argv)

    data_path = args.data or args.root / DATA
    try:
        shards, seconds = load(data_path)
    except (OSError, ValueError) as exc:
        print(f"::error::the shard data is not usable: {exc}", file=sys.stderr)
        return 1
    files = suite_files(args.root)

    if args.command == "record":
        try:
            seconds, unplaced = recorded_seconds(args.report, files)
        except ValueError as exc:
            print(f"::error::{exc}", file=sys.stderr)
            return 1
        data = json.loads(data_path.read_text(encoding="utf-8"))
        data["seconds"] = seconds
        with open(data_path, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(json.dumps(data, indent=2) + "\n")
        print(f"recorded {len(seconds)} file(s), {sum(seconds.values()) / 60:.1f} min of stack tests")
        if unplaced:
            print(f"{unplaced} case(s) of a file that is not there were left out")
        return 0

    if args.command == "count":
        print(shards)
        return 0

    if args.command == "files":
        if not 1 <= args.shard <= shards:
            print(f"::error::there is no shard {args.shard}: the shards are 1 to {shards}", file=sys.stderr)
            return 1
        mine = [path for path, shard in assign(files, seconds, shards).items() if shard == args.shard]
        if not mine:
            print(f"::error::shard {args.shard} has no test file to run", file=sys.stderr)
            return 1
        print("\n".join(mine))
        return 0

    rows = balance(files, seconds, shards)
    print("shard  files  listed  recorded")
    for row in rows:
        print(f"{row['shard']:5d}  {row['files']:5d}  {row['listed']:6d}  {row['seconds'] / 60:5.1f} min")
    listed = sum(row["listed"] for row in rows)
    print(f"{len(files)} test files: {listed} with a recorded time, {len(files) - listed} placed by their path")
    gone = missing_files(files, seconds)
    if gone:
        print(f"::warning::the shard data lists {len(gone)} file(s) that are not there any more: " + ", ".join(gone))
    return 0


if __name__ == "__main__":
    sys.exit(main())
