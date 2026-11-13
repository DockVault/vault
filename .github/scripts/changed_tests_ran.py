#!/usr/bin/env python3
"""Check that the tests of every test file changed since the last release ran in their lanes.

A new or changed test proves nothing on a system it never ran on, and a lane can leave one out
without failing: a marker expression that no longer selects it, a guard that skips it, a file that is
not collected there. So this takes the test files added or changed since the last release and looks
each of their tests up, by name, in the lanes' JUnit reports:

- a test the offline lane runs must be in the report of every offline lane given (the Linux one and
  the Windows one, when both ran);
- a test that needs the stack must be in one of the stack reports given (the shards').

A test is there when the report shows it passed, or shows it skipped with a reason: a skip is a
decision someone wrote down, and each one is printed with its reason. A test that is not in the
report at all, a skip that gives no reason, or a failure fails the check.

A test that cannot exist on one system is therefore written as a skip with a reason there, not left
out of a parametrization: the names are the collection's, made on Linux.

Usage:
  changed_tests_ran.py --collected collected.txt --offline-collected collected-offline.txt \
      --offline-lane linux=linux.xml --offline-lane windows=windows.xml \
      --stack-report shard-1.xml shard-2.xml ... [--base-ref v1.2.3]

`collected.txt` is the output of `python -m pytest --collect-only -q`, and `collected-offline.txt`
the same with the offline lane's marker expression. Without --base-ref the comparison is with the
last release: the highest version tag that is an ancestor of this commit and is not on it.
"""
from __future__ import annotations

import argparse
import importlib.util
import re
import subprocess
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
# How many lines of one kind are printed before the rest are counted.
SHOWN = 20
_RELEASE_TAG = re.compile(r"v(\d+)\.(\d+)\.(\d+)")
_TEST_FILE = re.compile(r"tests/(?:.+/)?test_[^/]+\.py")


def _reports_module():
    """Load the sibling report reader by path, so this works run as a script and loaded by path."""
    path = Path(__file__).resolve().parent / "join_suite_reports.py"
    spec = importlib.util.spec_from_file_location("dockvault_join_suite_reports", path)
    if spec is None or spec.loader is None:  # pragma: no cover - a broken checkout
        raise RuntimeError(f"cannot load {path}")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_REPORTS = _reports_module()


def _git(repository: Path, *arguments: str) -> str:
    done = subprocess.run(["git", "-C", str(repository), *arguments], capture_output=True, text=True,
                          encoding="utf-8", timeout=120)
    if done.returncode != 0:
        raise ValueError(f"git {' '.join(arguments)} failed: {done.stderr.strip()}")
    return done.stdout


def last_release_tag(repository: Path) -> str:
    """The highest release tag that is an ancestor of HEAD and does not name HEAD itself.

    On the commit a release is being made from, the tag on it is the release under test, and the
    comparison is with the one before it.
    """
    head = _git(repository, "rev-parse", "HEAD").strip()
    found = []
    for tag in _git(repository, "tag", "--merged", "HEAD", "--list", "v*").split():
        match = _RELEASE_TAG.fullmatch(tag)
        if not match:
            continue
        if _git(repository, "rev-parse", f"{tag}^{{commit}}").strip() == head:
            continue
        found.append((tuple(int(part) for part in match.groups()), tag))
    if not found:
        raise ValueError("no release tag is an ancestor of this commit (the checkout needs the tags "
                         "and the history); give the base with --base-ref")
    return max(found)[1]


def changed_test_files(repository: Path, base: str) -> list[str]:
    """Test files added or changed between `base` and HEAD. A renamed file counts as added."""
    names = _git(repository, "diff", "--name-only", "--no-renames", "--diff-filter=AM",
                 base, "HEAD", "--", "tests").splitlines()
    return sorted(name for name in names if _TEST_FILE.fullmatch(name))


def read_lane(path: Path) -> tuple[dict[tuple[str, str], tuple[str, str]], dict[str, str]]:
    """What a lane's report says: each test's (outcome, reason), and the files it skipped whole.

    The outcome is "ran", "skipped" or "failed". pytest reports a test that failed as its `xfail`
    mark expects as skipped; it ran. A file skipped at import is one case named after the file.
    """
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"no usable report ({exc})") from exc
    cases: dict[tuple[str, str], tuple[str, str]] = {}
    whole_files: dict[str, str] = {}
    for case in root.iter("testcase"):
        key = (case.get("classname", ""), case.get("name", ""))
        skipped = case.find("skipped")
        if case.find("failure") is not None or case.find("error") is not None:
            cases[key] = ("failed", "")
        elif skipped is None or skipped.get("type") == "pytest.xfail":
            cases.setdefault(key, ("ran", ""))
        elif skipped.get("message") == "collection skipped":
            whole_files[key[1]] = (skipped.text or "").strip()
        else:
            cases.setdefault(key, ("skipped", (skipped.get("message") or "").strip()))
    return cases, whole_files


def check_lane(lane: str, tests: list[str], reports: list[Path]) -> tuple[list[str], list[str]]:
    """Look `tests` up in a lane's report(s). Returns (lines to print, problems)."""
    cases: dict[tuple[str, str], tuple[str, str]] = {}
    whole_files: dict[str, str] = {}
    problems = []
    for path in reports:
        try:
            more_cases, more_files = read_lane(path)
        except ValueError as exc:
            problems.append(f"{lane}: the report {path} is missing: {exc}")
            continue
        cases.update(more_cases)
        whole_files.update(more_files)

    ran, skips, absent, unexplained, failed = 0, [], [], [], []
    for test in tests:
        outcome, reason = cases.get(_REPORTS.report_name(test), ("absent", ""))
        if outcome == "absent":
            module = _REPORTS.report_name(test.split("::", 1)[0])[1]
            if module in whole_files:
                outcome, reason = "skipped", whole_files[module]
        if outcome == "ran":
            ran += 1
        elif outcome == "failed":
            failed.append(test)
        elif outcome == "absent":
            absent.append(test)
        elif not reason:
            unexplained.append(test)
        else:
            skips.append((reason, test))

    lines = [f"{lane}: {len(tests)} test(s) of the changed files: {ran} ran, {len(skips)} skipped"]
    by_reason = Counter(reason for reason, _test in skips)
    first = {}
    for reason, test in skips:
        first.setdefault(reason, test)
    for reason, count in sorted(by_reason.items(), key=lambda item: (-item[1], item[0]))[:SHOWN]:
        lines.append(f"  skipped ({count}): {reason} [{first[reason]}]")
    if len(by_reason) > SHOWN:
        lines.append(f"  and {len(by_reason) - SHOWN} more reasons")
    for what, names in (("are not in the report", absent),
                        ("are skipped without a reason", unexplained),
                        ("failed", failed)):
        if names:
            shown = "; ".join(names[:SHOWN]) + (f"; and {len(names) - SHOWN} more" if len(names) > SHOWN else "")
            problems.append(f"{lane}: {len(names)} test(s) of changed files {what}: {shown}")
    return lines, problems


def _lane_argument(value: str) -> tuple[str, Path]:
    lane, separator, path = value.partition("=")
    if not separator or not lane or not path:
        raise argparse.ArgumentTypeError("a lane is given as NAME=PATH")
    return lane, Path(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--repository", type=Path, default=ROOT, help="the checkout (default: this one)")
    parser.add_argument("--base-ref", default=None, help="what to compare with (default: the last release tag)")
    parser.add_argument("--collected", type=Path, required=True,
                        help="the output of `python -m pytest --collect-only -q`")
    parser.add_argument("--offline-collected", type=Path, required=True,
                        help="the same, with the offline lane's marker expression")
    parser.add_argument("--offline-lane", type=_lane_argument, action="append", default=[],
                        metavar="NAME=PATH", help="an offline lane's JUnit report; every one must hold the tests")
    parser.add_argument("--stack-report", type=Path, nargs="+", default=[],
                        help="the JUnit reports of the lanes that run the stack tests, together")
    args = parser.parse_args(argv)
    if not args.offline_lane and not args.stack_report:
        parser.error("give at least one report to look the tests up in")

    try:
        base = args.base_ref or last_release_tag(args.repository)
        changed = changed_test_files(args.repository, base)
        collected = _REPORTS.read_collection(args.collected)
        offline = set(_REPORTS.read_collection(args.offline_collected))
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    if not offline <= set(collected):
        print("::error::the offline collection lists a test the whole collection does not", file=sys.stderr)
        return 1

    wanted = set(changed)
    offline_tests = [test for test in collected if test in offline and test.split("::", 1)[0] in wanted]
    stack_tests = [test for test in collected if test not in offline and test.split("::", 1)[0] in wanted]
    print(f"compared with {base}: {len(changed)} test file(s) added or changed, holding "
          f"{len(offline_tests)} offline test(s) and {len(stack_tests)} stack test(s)")

    problems = []
    for lane, path in args.offline_lane:
        lines, found = check_lane(lane, offline_tests, [path])
        print("\n".join(lines))
        problems += found
    if args.stack_report:
        lines, found = check_lane("stack", stack_tests, args.stack_report)
        print("\n".join(lines))
        problems += found
    elif stack_tests:
        print(f"stack: {len(stack_tests)} test(s) of the changed files not looked up (no stack report given)")
    if not args.offline_lane and offline_tests:
        print(f"offline: {len(offline_tests)} test(s) of the changed files not looked up (no offline lane given)")

    if problems:
        for problem in problems:
            print(f"::error::{problem}", file=sys.stderr)
        return 1
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
