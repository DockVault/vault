"""Validate that a successful pytest JUnit report represents the full suite."""

from __future__ import annotations

import argparse
import sys
import xml.etree.ElementTree as ET
from pathlib import Path


MAX_SKIP_RATIO = 0.15


def _non_negative(value: str) -> int:
    parsed = int(value)
    if parsed < 0:
        raise argparse.ArgumentTypeError("must be non-negative")
    return parsed


def audit(report: Path, expected_total: int, max_skip_ratio: float) -> str:
    try:
        root = ET.parse(report).getroot()
    except (OSError, ET.ParseError) as exc:
        raise ValueError(f"no usable pytest report ({exc})") from exc

    suites = [root] if root.tag == "testsuite" else list(root.iter("testsuite"))
    if not suites:
        raise ValueError("pytest report contains no test suites")

    def count(attribute: str) -> int:
        return sum(int(suite.get(attribute, 0)) for suite in suites)

    total = count("tests")
    skipped = count("skipped")
    failures = count("failures")
    errors = count("errors")
    ran = total - skipped

    problems: list[str] = []
    if failures or errors:
        problems.append(f"{failures} failed, {errors} errored")
    if total != expected_total:
        problems.append(f"report contains {total} tests; preflight collected {expected_total}")
    if total == 0:
        problems.append("report contains no tests")
    elif skipped / total > max_skip_ratio:
        problems.append(
            f"{skipped} of {total} tests skipped "
            f"({skipped / total:.0%}, ceiling is {max_skip_ratio:.0%})"
        )
    if problems:
        raise ValueError("; ".join(problems))

    return (
        f"collected={total} ran={ran} skipped={skipped} "
        f"failed={failures} errored={errors}"
    )


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("report", type=Path)
    parser.add_argument("--expected-total", required=True, type=_non_negative)
    parser.add_argument("--max-skip-ratio", type=float, default=MAX_SKIP_RATIO)
    args = parser.parse_args(argv)

    if not 0 <= args.max_skip_ratio <= 1:
        parser.error("--max-skip-ratio must be between 0 and 1")

    try:
        summary = audit(args.report, args.expected_total, args.max_skip_ratio)
    except ValueError as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1

    print(summary)
    print("OK")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
