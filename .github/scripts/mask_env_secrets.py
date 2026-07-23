#!/usr/bin/env python3
"""Mask secret values from a generated dotenv file in GitHub Actions logs."""

from __future__ import annotations

import sys
from pathlib import Path


SECRET_KEYS = {
    "ADMIN_PASSWORD",
    "ENCRYPTION_KEY",
    "JWT_SECRET_KEY",
    "LOG_TOKEN_PEPPER",
    "REDIS_PASSWORD",
    "VAULT_DB_PASSWORD",
}


def _dotenv_value(raw: str) -> str:
    value = raw.strip()
    if len(value) >= 2 and value[0] == value[-1] and value[0] in {"'", '"'}:
        value = value[1:-1]
    return value


def _workflow_escape(value: str) -> str:
    return value.replace("%", "%25").replace("\r", "%0D").replace("\n", "%0A")


def mask_commands(path: Path) -> list[str]:
    commands: list[str] = []
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        if "=" not in raw_line or raw_line.lstrip().startswith("#"):
            continue
        key, raw_value = raw_line.split("=", 1)
        if key.strip() in SECRET_KEYS:
            value = _dotenv_value(raw_value)
            if value:
                commands.append(f"::add-mask::{_workflow_escape(value)}")
    return commands


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(f"usage: {Path(argv[0]).name} <dotenv-path>", file=sys.stderr)
        return 2
    path = Path(argv[1])
    if not path.is_file():
        print(f"dotenv file not found: {path}", file=sys.stderr)
        return 1
    for command in mask_commands(path):
        print(command)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
