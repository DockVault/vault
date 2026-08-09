"""Operational logging that is safe to put in a container log.

Anything printed here goes straight to the container log, which is read by whoever runs
`docker logs`, copied into bug reports, and — in the combined deployment — appended to the
rotating sink the log-pull API serves. So the rule is the one the vault applies to stored
data: an operator may learn WHAT happened and to WHICH object, never the content or the names.

Two things made that untrue. A successful and a rejected upload each printed the plaintext
FILENAME -- and for a zero-knowledge vault the client seals that name before it is ever sent, so
it sat encrypted in the database and in the clear in the log beside it. And most failures printed
the raw exception, which is not ours to vouch for: a driver can put a query fragment, a host path,
or a value from the row it choked on into that string.

It lives in `core` rather than beside one caller because the SFTP server is not the only
writer into that log: the vault service prints from blob replacement and deletion, which the
SFTP finalizer and remove path call into. A rule enforced at one of two doors is not enforced.

This module deliberately imports nothing else from the application, so it stays testable
without a database, a config, or a running server.
"""

import re

# Only names that a call site actually uses. An unused permissive name is not free: a filename
# MATCHES the value pattern below (`payroll-2026.xlsx` passes), so the field-name whitelist is the
# real defence and the pattern is only the backstop. A pre-authorised `reason` field would have
# invited exactly the free text this module exists to keep out.
_SAFE_FIELDS = frozenset({
    "vault", "file", "session", "user",     # identifiers (UUIDs, or an 8-char session prefix)
    "bytes", "limit", "removed", "port",    # magnitudes
    "peer", "signal",                       # network / process facts
})

# Identifiers, integers and short enumerated tokens. Anything else -- a name, a sentence, a path
# -- fails this and is redacted rather than printed.
#
# Note what is NOT in the class: `/`. An earlier version allowed it, and the test written for this
# rule immediately showed that `/app/storage/.sftp_tmp/secret-merger-terms.pdf` sailed straight
# through -- a whitelisted field name carrying exactly the payload the whitelist exists to stop.
# No legitimate value here needs a slash.
_SAFE_VALUE = re.compile(r"^[A-Za-z0-9._:-]{1,64}$")

# The event code itself. It is meant to be a literal at every call site, but "meant to" is not a
# control: an f-string here would print whatever it interpolated -- straight past the field
# whitelist, in the one function that exists to enforce it -- and an embedded newline would let a
# caller forge log lines. Cheap to check, so check it.
_SAFE_CODE = re.compile(r"^[a-z0-9][a-z0-9.-]{0,47}$")


def safe_event(code: str, exc: BaseException | None = None, **fields) -> None:
    """Emit one operational event: a stable code, whitelisted fields, and an exception class.

    `code` is a short stable token (``upload.rejected.too-large``) that an operator can grep for
    and that a reader can look up. It is never interpolated from input.

    Anything not in the whitelist is dropped silently -- dropping is the safe direction, and a
    test enumerates the call sites so a mistyped field is caught there rather than by its absence
    at three in the morning.
    """
    if not _SAFE_CODE.fullmatch(str(code)):
        code = "invalid-code"
    # No service name here. This module now has callers in more than one process, and a
    # hardcoded one was actively misleading: a vault deletion on the web path announced itself
    # as SFTP. The code carries the domain, the container carries the process, and the combined
    # launcher already tags each line with the half it came from.
    parts = ["event", str(code)]
    for key in sorted(fields):
        if key not in _SAFE_FIELDS:
            continue
        value = fields[key]
        if value is None:
            continue
        # A peer address arrives as paramiko's (host, port) tuple. Rendered with str() it would
        # fail the shape check and be redacted -- technically safe, operationally useless, and
        # silently so. Take the host and drop the ephemeral port, which tells nobody anything.
        if key == "peer" and isinstance(value, (tuple, list)) and value:
            value = value[0]
        text = str(value)
        parts.append(f"{key}={text if _SAFE_VALUE.fullmatch(text) else '<redacted>'}")
    if exc is not None:
        # The class, never str(exc). This is the whole point of the helper.
        parts.append(f"err={type(exc).__name__}")
    # flush=True is not cosmetic. This process writes to a pipe, not a terminal, so Python block
    # buffers stdout -- and the SFTP server is long-lived and low-volume, so an 8 KB buffer can
    # take days to fill. The practical effect was that `docker logs` for this container was
    # EMPTY: every operational event, including session termination and upload rejection, sat
    # unread in memory. A log an operator cannot see is not a log.
    print(" ".join(parts), flush=True)
