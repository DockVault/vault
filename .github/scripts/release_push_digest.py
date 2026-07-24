#!/usr/bin/env python3
"""Extract one registry-confirmed manifest digest from ``docker push`` output."""

from __future__ import annotations

import argparse
import re
import sys
from pathlib import Path


_SUMMARY_RE = re.compile(
    r"^(?:[^:\r\n]+:\s+)?digest:\s+"
    r"(sha256:[0-9a-f]{64})\s+size:\s+[1-9][0-9]*\s*$"
)


def extract_push_digest(log_path: Path) -> str:
    matches = [
        match.group(1)
        for line in log_path.read_text(encoding="utf-8").splitlines()
        if (match := _SUMMARY_RE.fullmatch(line))
    ]
    if len(matches) != 1:
        raise ValueError(
            "docker push output must contain exactly one canonical digest summary"
        )
    return matches[0]


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("log", type=Path)
    args = parser.parse_args()
    try:
        digest = extract_push_digest(args.log)
    except (OSError, UnicodeError, ValueError) as exc:
        print(f"::error::{exc}", file=sys.stderr)
        return 1
    print(digest)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
