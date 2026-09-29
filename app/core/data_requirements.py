"""Refuse to start on data that a newer release has changed in a way this one cannot read.

Some changes a release makes to stored data cannot be read by an older release: audit history moved
into compressed archive blocks, records kept under a legal hold, a recording level that stores less
than everything. Rolling the image back over such data would show an incomplete audit log, or let the
older release delete what must be kept, without saying so.

The release that makes such a change writes a row in ``data_requirements`` naming the oldest version
that can read the data, what changed, and how to undo it with the newer release; it removes the row
once the change is undone. Every release that has this module reads the table before it touches the
database, and refuses to start when a row names a version above its own. The check sits in the image
itself, so it holds however the image was changed -- by the host tool, or by editing the image tag by
hand -- which a check in the host tool alone cannot.

The table is read by name, column by column, so a later release may add columns but keeps these five
(``key``, ``requires_at_least``, ``reason``, ``undo``, ``since``).

Escape: ``ALLOW_START_ON_NEWER_DATA=true`` starts the process anyway, with a warning naming each row.
It is for an operator who has decided that running the older release on this data is better than not
running at all -- in an outage, say -- and it is never written by setup.

A release older than this module has no reader, so a rollback to one of those is not protected.
"""
from __future__ import annotations

import re
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

ESCAPE_VARIABLE = "ALLOW_START_ON_NEWER_DATA"
TABLE = "data_requirements"

_VERSION_RE = re.compile(r"(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)", re.ASCII)


class NewerDataRefusal(RuntimeError):
    """This release cannot safely start on the data in this database."""


@dataclass(frozen=True)
class Requirement:
    key: str
    requires_at_least: str
    reason: str
    undo: str | None
    since: datetime | None


def running_version() -> str:
    """This image's own version: the VERSION file baked into it, which the release gate ties to the
    release's tag. Not the branding setting, which an operator's .env can override."""
    for path in (Path(__file__).resolve().parents[2] / "VERSION", Path("/app/VERSION")):
        try:
            value = path.read_text(encoding="utf-8").strip()
        except OSError:
            continue
        if value:
            return value
    return ""


def _parse(version: str):
    match = _VERSION_RE.fullmatch((version or "").strip())
    return tuple(int(part) for part in match.groups()) if match else None


def read_requirements(connection) -> list[Requirement]:
    """Every row of the table, or [] when the table does not exist (nothing newer has run here).

    Raises NewerDataRefusal when the table exists but cannot be read the way this release expects:
    something newer made it, and this release cannot tell what it requires.
    """
    from sqlalchemy import inspect, text

    if not inspect(connection).has_table(TABLE):
        return []
    try:
        rows = connection.execute(text(
            f"SELECT key, requires_at_least, reason, undo, since FROM {TABLE} ORDER BY key"
        )).fetchall()
    except Exception as exc:  # noqa: BLE001 -- any failure to read it is a failure to verify
        raise NewerDataRefusal(
            f"The {TABLE} table in this database cannot be read by this version "
            f"({type(exc).__name__}), so whether a newer DockVault changed the data cannot be "
            f"told. {_escape_advice()}") from exc
    return [Requirement(key=str(r[0]), requires_at_least=str(r[1] or ""), reason=str(r[2] or ""),
                        undo=(str(r[3]) if r[3] else None), since=r[4]) for r in rows]


def unmet(requirements: list[Requirement], version: str) -> list[Requirement]:
    """The requirements this version does not meet.

    A row whose version cannot be parsed counts as unmet: a newer release wrote it, and this one cannot
    tell what it asks for. So does every row when this release cannot parse its own version.
    """
    own = _parse(version)
    result = []
    for requirement in requirements:
        needed = _parse(requirement.requires_at_least)
        if own is None or needed is None or needed > own:
            result.append(requirement)
    return result


def _escape_advice() -> str:
    return (f"To start this version anyway, set {ESCAPE_VARIABLE}=true in .env and recreate the "
            "container. It will then run on data it cannot fully read: it may show an incomplete "
            "audit log, and it may delete or change records the newer version keeps. Remove the "
            "setting as soon as you are back on the newer version or have undone the change.")


def refusal_message(rows: list[Requirement], version: str) -> str:
    lines = [f"DockVault {version or '(unknown version)'} will not start: a newer version changed "
             "this database in a way this version cannot read."]
    for row in rows:
        lines.append(f"- Needs DockVault {row.requires_at_least or '(unreadable version)'} or later "
                     f"({row.key}): {row.reason or 'no reason recorded'}")
        if row.undo:
            lines.append(f"  To go back to this version, first undo it with the newer version: "
                         f"{row.undo}")
        else:
            lines.append("  The newer version's release notes say how to undo it.")
    lines.append("Or start the newer version again: it reads this data as it is.")
    lines.append(_escape_advice())
    return "\n".join(lines)


def check(connection, version: str, *, allow: bool) -> list[Requirement]:
    """Refuse (raise NewerDataRefusal) when a requirement is unmet and the escape is not set.

    Returns the unmet requirements, which is empty unless the escape let the process start anyway.
    """
    try:
        rows = unmet(read_requirements(connection), version)
    except NewerDataRefusal:
        if not allow:
            raise
        _warn(f"{ESCAPE_VARIABLE} is set, so this version starts although it cannot read the "
              f"{TABLE} table.")
        return []
    if not rows:
        return []
    message = refusal_message(rows, version)
    if not allow:
        raise NewerDataRefusal(message)
    _warn(f"{ESCAPE_VARIABLE} is set, so this version starts on data it cannot fully read.\n"
          + message)
    return rows


def _warn(text: str) -> None:
    print("WARNING: " + text.replace("\n", "\nWARNING: "), file=sys.stderr, flush=True)


def check_at_startup(process: str) -> None:
    """Run the check against this process's database before anything else touches it.

    On a refusal the message is printed as plain lines before the exception propagates, so it leads
    the container log rather than sitting inside a traceback. A database that cannot be reached fails
    the start here, as it would a moment later anyway: the check is never skipped, so a database that
    comes up between this step and the next cannot let an unchecked start through.
    """
    from app.core.config import settings
    from app.core.database import _require_engine

    version = running_version()
    try:
        with _require_engine().connect() as connection:
            check(connection, version, allow=bool(settings.allow_start_on_newer_data))
    except NewerDataRefusal as refusal:
        print(f"[{process}] " + str(refusal).replace("\n", f"\n[{process}] "),
              file=sys.stderr, flush=True)
        raise
