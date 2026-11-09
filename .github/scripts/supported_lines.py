#!/usr/bin/env python3
"""Which release lines are still supported, read from the upgrade matrix's `lines`.

Prints two GitHub Actions outputs, each a JSON list of "X.Y" strings:

- `maintenance`: the older lines that still get security fixes, one `release/X.Y` branch each. The
  nightly checks run the suites on these branches.
- `published`: every supported line, the newest included. The weekly scan checks each line's
  published `:vX.Y` image.

A line is supported while its `security_fixes_until` is unset (the newest line) or not yet past, in
UTC. The newest line is the one with no date; it is released from `main`, not from a branch.

Usage: supported_lines.py [--matrix docs/upgrade-matrix.json] [--today YYYY-MM-DD]
"""
from __future__ import annotations

import argparse
import datetime as dt
import json
import sys
from pathlib import Path


def _key(line: str) -> tuple[int, ...]:
    return tuple(int(part) for part in line.split("."))


def supported(lines: dict, today: dt.date) -> tuple[list[str], list[str]]:
    """Return (maintenance, published) for the matrix's `lines` on `today`."""
    if not isinstance(lines, dict) or not lines:
        raise ValueError("the matrix has no `lines`")
    maintenance, published = [], []
    for line, entry in lines.items():
        until = (entry or {}).get("security_fixes_until")
        if until is None:
            published.append(line)
            continue
        if dt.date.fromisoformat(until) >= today:
            published.append(line)
            maintenance.append(line)
    newest = [line for line, entry in lines.items() if (entry or {}).get("security_fixes_until") is None]
    if len(newest) != 1:
        raise ValueError(f"exactly one line must have no end date, found {newest}")
    return sorted(maintenance, key=_key), sorted(published, key=_key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--matrix", default="docs/upgrade-matrix.json")
    parser.add_argument("--today", default=None, help="UTC date to judge by (default: today)")
    args = parser.parse_args(argv)
    today = dt.date.fromisoformat(args.today) if args.today else dt.datetime.now(dt.timezone.utc).date()
    data = json.loads(Path(args.matrix).read_text(encoding="utf-8"))
    maintenance, published = supported(data.get("lines"), today)
    print(f"maintenance={json.dumps(maintenance)}")
    print(f"published={json.dumps(published)}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
