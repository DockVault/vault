"""Refuse to start on data that a newer release has changed in a way this one cannot read.

Some changes a later release may make to stored data cannot be read by an older release: for example,
audit history moved into compressed archive blocks, records kept under a legal hold, or a recording
level that stores less than everything. Rolling the image back over such data would show an
incomplete audit log, or let the older release delete what must be kept, without saying so.

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

import os
import re
import sys
import time
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


def _describe(rows: list[Requirement], undo_lead: str) -> list[str]:
    lines = []
    for row in rows:
        lines.append(f"- Needs DockVault {row.requires_at_least or '(unreadable version)'} or later "
                     f"({row.key}): {row.reason or 'no reason recorded'}")
        if row.undo:
            lines.append(f"  {undo_lead}, first undo it with the newer version: {row.undo}")
        else:
            lines.append("  The newer version's release notes say how to undo it.")
    return lines


def refusal_message(rows: list[Requirement], version: str) -> str:
    lines = [f"DockVault {version or '(unknown version)'} will not start: a newer version changed "
             "this database in a way this version cannot read."]
    lines += _describe(rows, "To go back to this version")
    lines.append("Or start the newer version again: it reads this data as it is.")
    lines.append(_escape_advice())
    return "\n".join(lines)


def escape_message(rows: list[Requirement], version: str) -> str:
    """What a start let through by the escape says: that it is running on such data, what each row is
    and how to undo it -- not how to start, since it is starting."""
    lines = [f"{ESCAPE_VARIABLE} is set, so DockVault {version or '(unknown version)'} starts on data "
             "a newer version changed in a way this version cannot read. It may show an incomplete "
             "audit log, and it may delete or change records the newer version keeps."]
    lines += _describe(rows, f"To run this version without {ESCAPE_VARIABLE}")
    lines.append(f"Remove {ESCAPE_VARIABLE} from .env as soon as you are back on the newer version or "
                 "have undone the change.")
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
    if not allow:
        raise NewerDataRefusal(refusal_message(rows, version))
    _warn(escape_message(rows, version))
    return rows


def _warn(text: str) -> None:
    print("WARNING: " + text.replace("\n", "\nWARNING: "), file=sys.stderr, flush=True)


#: How long a start waits for a database it cannot reach yet. After a host restarts, the database and
#: the vault start together, and the database can take a while to answer: a recovery after a power
#: cut, or many deployments starting on one host. Long enough for that, and short enough that a
#: database that is really gone still stops the start, with its error, within two minutes.
DATABASE_WAIT_SECONDS = 120.0
_FIRST_PAUSE = 1.0
_LONGEST_PAUSE = 5.0

# A server that answers with one of these is starting or stopping: reached, but not ready yet.
_NOT_READY = (
    "the database system is starting up",
    "the database system is not yet accepting connections",
    "the database system is in recovery mode",
    "the database system is shutting down",
)

# What the client library says when it found no server to talk to yet, compared in lower case: the
# question it asks after a connect that failed, whatever the reason (refused, no route, no such socket),
# in its wordings for a host and for a socket; the connect timeout; a name not found (yet); a server
# that closed the connection before it answered; the older client library's "could not connect"; and
# the reasons a connect fails with, as either C library words them, in case a client library says
# them without that question.
_CANNOT_REACH = (
    "is the server running",
    "timeout expired",
    "could not translate host name",
    "server closed the connection unexpectedly",
    "could not connect to server",
    "connection refused",
    "no route to host",
    "host is unreachable",
    "network is unreachable",
    "network unreachable",
)

# Seams for the tests, which run the wait on a clock of their own.
_clock = time.monotonic
_sleep = time.sleep


def _not_reachable_yet(exc: BaseException) -> bool:
    """Whether a failed connection means the database cannot be reached yet.

    Only what is known to mean that is waited for: the client library's own words for a server it
    could not reach (_CANNOT_REACH), and a server that answers it is starting or stopping
    (_NOT_READY). Everything else stops the start at once, as waiting changes nothing: a refusal the
    server sent (a wrong password, a missing database or role, a rule that does not admit this
    address), one the client library made itself (no password given, SSL required of a server
    without it, a setting it does not know), and words it does not know, as from a server that
    answers in another language.
    """
    from sqlalchemy.exc import OperationalError

    if not isinstance(exc, OperationalError):
        return False
    text = str(getattr(exc, "orig", None) or exc)
    if "FATAL:" in text:
        return any(marker in text for marker in _NOT_READY)
    lowered = text.lower()
    return any(marker in lowered for marker in _CANNOT_REACH)


def _reason(exc: BaseException) -> str:
    """The client library's own words for why, on one line: "timeout expired", "Connection refused"."""
    text = str(getattr(exc, "orig", None) or exc).strip()
    line = text.splitlines()[0].strip() if text else type(exc).__name__
    if "failed: " in line:
        line = line.split("failed: ", 1)[1]
    return line[:200]


def _say(text: str) -> None:
    print(text, file=sys.stderr, flush=True)


def _connect_when_reachable(engine, prefix: str):
    """A connection to the database, waiting up to DATABASE_WAIT_SECONDS for one it cannot reach yet.

    One plain line per wait. Every other failure -- and the last one, when the wait runs out -- is
    raised as it was before there was a wait.
    """
    started = _clock()
    deadline = started + DATABASE_WAIT_SECONDS
    pause = _FIRST_PAUSE
    waited = False
    while True:
        try:
            connection = engine.connect()
        except Exception as exc:  # noqa: BLE001 -- classified below; anything else is raised
            if not _not_reachable_yet(exc):
                raise
            left = deadline - _clock()
            if left <= 0:
                _say(f"{prefix}The database could not be reached within {DATABASE_WAIT_SECONDS:g} s "
                     f"({_reason(exc)}); stopping.")
                raise
            this_pause = min(pause, left)
            _say(f"{prefix}The database cannot be reached yet ({_reason(exc)}); trying again in "
                 f"{this_pause:g} s.")
            _sleep(this_pause)
            pause = min(pause * 2, _LONGEST_PAUSE)
            waited = True
            continue
        if waited:
            _say(f"{prefix}The database answered after {_clock() - started:.0f} s.")
        return connection


def check_at_startup(process: str) -> None:
    """Run the check against this process's database before anything else touches it.

    On a refusal the message is printed as plain lines before the exception propagates, so it leads
    the container log rather than sitting inside a traceback.

    A database that cannot be reached yet is waited for, within DATABASE_WAIT_SECONDS: after a host
    restart it starts with the vault, and failing at once stopped the container for Docker to start it
    again. The check itself is never skipped: it runs on the connection the wait ends with, so a
    database that comes up during the wait is checked like any other. A refusal, and every failure
    other than a database that cannot be reached yet, stops the start at once.
    """
    from app.core.config import settings
    from app.core.database import _require_engine

    version = running_version()
    # Each line names the process, except under the one-container launcher, which already puts the
    # process's name in front of every line it passes on.
    prefix = "" if os.environ.get("VAULT_LOG_SINK_OWNER") == "run_combined" else f"[{process}] "
    try:
        with _connect_when_reachable(_require_engine(), prefix) as connection:
            check(connection, version, allow=bool(settings.allow_start_on_newer_data))
    except NewerDataRefusal as refusal:
        print(prefix + str(refusal).replace("\n", "\n" + prefix), file=sys.stderr, flush=True)
        raise
