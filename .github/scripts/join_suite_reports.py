#!/usr/bin/env python3
"""Join the JUnit reports of the lanes that together run the whole suite, and check them by name.

The suite is not one pytest session any more: the offline lane runs the tests that need no stack,
and each shard runs its share of the others on a stack of its own. One session wrote one report, and
comparing its count with the collection was enough. Several sessions can each be complete and still,
between them, leave a test out or run one twice with the counts adding up, so this compares the
tests' names with the collection's.

It fails unless:

- every report it is given is there and readable;
- every test the collection lists is in exactly one report;
- no report holds a test the collection does not list.

It writes all the reports as one file, one suite per lane, whether or not the check passed: the
result audit (pytest_result_audit.py) reads that file next, and it is the file kept from the run.
It prints what each lane's report holds and, for the run as a whole, how many tests were skipped
for each reason: a skip is not a failure, but a new one is a test that stopped running.

Usage:
  join_suite_reports.py --collected collected.txt --report offline=offline.xml \
      --report shard-1=shard-1.xml ... --output pytest-results.xml

`collected.txt` is the output of `python -m pytest --collect-only -q`.
"""
from __future__ import annotations

import argparse
import re
import sys
import xml.etree.ElementTree as ET
from collections import Counter
from pathlib import Path

# How many names a problem prints before it says how many more there are, and how many reasons
# for a skip are printed.
SHOWN = 20
REASONS_SHOWN = 80

# The line pytest ends a collection with: "15006 tests collected in 50.07s", or, when a marker
# expression selected some of them, "11414/15006 tests collected (3592 deselected) in 46.31s".
_COUNT_LINE = re.compile(r"^(\d+)(?:/\d+)? tests? collected(?: \(\d+ deselected\))? in .+$")


def read_collection(path: Path) -> list[str]:
    """The test ids `pytest --collect-only -q` printed, checked against the count it printed.

    The ids are the lines before the first empty one, each a path, `::` and a name; the count is
    on a line of its own after them. Anything else (a collection that failed, or the output of
    another command) is refused, not read as a short list.
    """
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except (OSError, UnicodeDecodeError) as exc:
        raise ValueError(f"no usable collection ({exc})") from exc
    ids = []
    for line in lines:
        if not line.strip():
            break
        ids.append(line)
    counts = [int(match.group(1)) for match in map(_COUNT_LINE.match, lines[len(ids):]) if match]
    if len(counts) != 1:
        raise ValueError("the collection does not end with one count of the tests it collected")
    stray = [line for line in ids if "::" not in line or line[:1].isspace()]
    if stray:
        raise ValueError(f"the collection starts with a line that is not a test id: {stray[0]!r}")
    if counts[0] != len(ids) or not ids:
        raise ValueError(f"the collection lists {len(ids)} tests and says it collected {counts[0]}")
    if len(set(ids)) != len(ids):
        raise ValueError("the collection lists a test twice")
    return ids


def report_name(test_id: str) -> tuple[str, str]:
    """The (classname, name) pytest's JUnit writer gives a test id.

    `tests/test_a.py::TestThing::test_two[x-1]` is written as class `tests.test_a.TestThing` and
    name `test_two[x-1]`: the file's path dotted, and whatever a parameter holds left as it is. The
    writer changes only a character XML cannot carry, and a test id holds none: pytest escapes a
    control character in a parameter before it names the test.
    """
    path, bracket, parameters = test_id.partition("[")
    names = path.split("::")
    names[0] = re.sub(r"\.py$", "", names[0].replace("/", "."))
    names[-1] += bracket + parameters
    return ".".join(names[:-1]), names[-1]


def read_report(path: Path) -> tuple[list[ET.Element], list[tuple[tuple[str, str], str, str]]]:
    """A report's suites, and each test case in it as ((classname, name), outcome, skip reason)."""
    try:
        root = ET.parse(path).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"no usable report ({exc})") from exc
    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        raise ValueError("the report contains no test suite")
    cases = []
    for case in root.iter("testcase"):
        reason = ""
        if case.find("failure") is not None:
            outcome = "failed"
        elif case.find("error") is not None:
            outcome = "errored"
        elif case.find("skipped") is not None:
            outcome = "skipped"
            reason = (case.find("skipped").get("message") or "").strip() or "no reason given"
        else:
            outcome = "passed"
        cases.append(((case.get("classname", ""), case.get("name", "")), outcome, reason))
    return suites, cases


def _some(names: list[str]) -> str:
    shown = "; ".join(names[:SHOWN])
    return shown if len(names) <= SHOWN else f"{shown}; and {len(names) - SHOWN} more"


def join(collected: list[str], reports: dict[str, Path]) -> tuple[list[str], list[str], ET.Element]:
    """Check the reports against the collection.

    Returns the problems (none when the reports hold every collected test exactly once), what to
    print (a line per lane saying what its report holds, then the skips of all lanes by reason, so
    that a run shows in one place what did not run and why), and the joined report.
    """
    problems, summary = [], []
    reasons = Counter()
    joined = ET.Element("testsuites", name="pytest tests")
    wanted = {}
    for test_id in collected:
        key = report_name(test_id)
        if key in wanted:
            problems.append(f"{wanted[key]} and {test_id} have the same name in a report, so they cannot be told apart")
        wanted[key] = test_id
    lanes_of: dict[tuple[str, str], list[str]] = {key: [] for key in wanted}
    unlisted: list[str] = []

    for lane, path in reports.items():
        try:
            suites, cases = read_report(path)
        except ValueError as exc:
            problems.append(f"the {lane} report is missing: {exc}")
            summary.append(f"{lane}: no report")
            continue
        for suite in suites:
            suite.set("name", lane)
            joined.append(suite)
        before: dict[tuple[str, str], list[str]] = {}
        outcomes = Counter()
        for key, outcome, reason in cases:
            outcomes[outcome] += 1
            if reason:
                reasons[reason] += 1
            earlier = before.setdefault(key, [])
            earlier.append(outcome)
            # pytest writes a test that failed and then failed again while tearing down as two
            # cases with one name: the failure, then the error. That is one test, not one run twice.
            if earlier == ["failed", "errored"]:
                continue
            if key in lanes_of:
                lanes_of[key].append(lane)
            else:
                unlisted.append(f"{'.'.join(part for part in key if part)} ({lane})")
        seconds = sum(float(suite.get("time", 0) or 0) for suite in suites)
        summary.append(
            f"{lane}: {len(cases)} cases in {seconds / 60:.1f} min "
            f"({outcomes['passed']} passed, {outcomes['skipped']} skipped, "
            f"{outcomes['failed']} failed, {outcomes['errored']} errored)"
        )

    if reasons:
        summary.append(f"{sum(reasons.values())} skipped, by reason:")
        by_count = sorted(reasons.items(), key=lambda item: (-item[1], item[0]))
        summary += [f"  {count}: {reason}" for reason, count in by_count[:REASONS_SHOWN]]
        if len(by_count) > REASONS_SHOWN:
            summary.append(f"  and {len(by_count) - REASONS_SHOWN} more reasons")

    absent = [wanted[key] for key, lanes in lanes_of.items() if not lanes]
    repeated = [f"{wanted[key]} ({', '.join(lanes)})" for key, lanes in lanes_of.items() if len(lanes) > 1]
    if absent:
        problems.append(f"{len(absent)} collected test(s) are in no report: {_some(absent)}")
    if repeated:
        problems.append(f"{len(repeated)} test(s) are in a report more than once: {_some(repeated)}")
    if unlisted:
        problems.append(f"{len(unlisted)} report case(s) are not in the collection: {_some(unlisted)}")
    return problems, summary, joined


def _report_argument(value: str) -> tuple[str, Path]:
    lane, separator, path = value.partition("=")
    if not separator or not lane or not path:
        raise argparse.ArgumentTypeError("a report is given as LANE=PATH")
    return lane, Path(path)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--collected", type=Path, required=True,
                        help="the output of `python -m pytest --collect-only -q`")
    parser.add_argument("--report", type=_report_argument, action="append", required=True,
                        metavar="LANE=PATH", help="a lane's JUnit report; give every lane")
    parser.add_argument("--output", type=Path, required=True, help="where to write the joined report")
    args = parser.parse_args(argv)

    lanes = [lane for lane, _path in args.report]
    if len(set(lanes)) != len(lanes):
        parser.error("each lane is given once")
    try:
        collected = read_collection(args.collected)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    problems, summary, joined = join(collected, dict(args.report))
    ET.ElementTree(joined).write(args.output, encoding="utf-8", xml_declaration=True)
    for line in summary:
        print(line)
    if problems:
        for problem in problems:
            print(f"::error::{problem}", file=sys.stderr)
        return 1
    print(f"every one of the {len(collected)} collected tests is in exactly one report")
    print("OK")
    return 0


if __name__ == "__main__":
    sys.exit(main())
