"""ALLOWED_HOSTS, read one way for both things it sets: the Host check and the base of every emailed link.

An entry is a bare name (``vault.example.com``, or ``vault.example.com:8443``), a wildcard (``*.example.com``), or a
full origin (``https://vault.example.com:8443``, ``http://name:port``).

- The Host check (starlette's TrustedHostMiddleware) compares host names only, so it gets each entry's host name,
  without a scheme or a port, and ``localhost`` and ``127.0.0.1`` for the container's own health probe.
- The link base is the first entry that is not a wildcard, taken as an origin: a full origin as written, a bare name
  as ``https://name`` (with its port when it names one). A wildcard is never a link base. With no such entry there is
  no link base, and no reset or invitation link is emailed (app/core/email_actions.public_base_url).

Pure, so both readers and the host tool's documentation can be held to it offline (tests/test_allowed_hosts.py).
"""
from typing import List
from urllib.parse import urlsplit

_HEALTH_PROBE_HOSTS = ("localhost", "127.0.0.1")


def entries(raw) -> List[str]:
    return [e.strip() for e in (raw or "").split(",") if e.strip()]


def _is_wildcard(entry: str) -> bool:
    return entry in ("*", "0.0.0.0") or entry.startswith("*") or entry.startswith(".")


def host_name(entry: str) -> str:
    """An entry's host name, as the Host check compares it: a wildcard as written, an origin's host, a bare name
    without its port."""
    if "://" in entry:
        return urlsplit(entry).hostname or ""
    if _is_wildcard(entry):
        return entry
    return entry.split(":", 1)[0] if entry.count(":") == 1 else entry


def middleware_hosts(raw) -> List[str]:
    """What TrustedHostMiddleware is given: every entry's host name, once, then the health probe's; [] when none is
    set (the Host is then not checked)."""
    hosts: List[str] = []
    for entry in entries(raw):
        name = host_name(entry)
        if name and name not in hosts:
            hosts.append(name)
    if hosts:
        hosts += [h for h in _HEALTH_PROBE_HOSTS if h not in hosts]
    return hosts


def link_base(raw) -> str:
    """The origin every emailed link is built on: the first entry that is not a wildcard (a bare name as
    https://name), or "" when there is none."""
    for entry in entries(raw):
        if _is_wildcard(entry):
            continue
        if "://" in entry:
            parts = urlsplit(entry)
            if parts.scheme in ("http", "https") and parts.hostname:
                return f"{parts.scheme}://{parts.netloc}"
            continue
        return f"https://{entry}".rstrip("/")
    return ""
