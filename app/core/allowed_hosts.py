"""ALLOWED_HOSTS, read one way for both things it sets: the Host check and the base of every emailed link.

An entry is a bare name (``vault.example.com``, or ``vault.example.com:8443``), a wildcard (``*.example.com``), or a
full origin (``https://vault.example.com:8443``, ``http://name:port``).

- The Host check (starlette's TrustedHostMiddleware) compares host names only, so it gets each entry's host name,
  without a scheme or a port, and ``localhost`` and ``127.0.0.1`` for the container's own health probe.
- The link base is the first entry that is not a wildcard, taken as an origin: a full origin as written, a bare name
  as ``https://name`` (with its port when it names one). A wildcard, bare or written as an origin
  (``https://*.example.com``), is never a link base. With no such entry there is no link base, and no reset or
  invitation link is emailed (app/core/email_actions.public_base_url).
- Host names are read in lower case, a bare name without anything after a ``/``, as a browser sends the Host.
- An entry with no host name that can be read (``https://``, ``:8443``) stops the server at start, naming it
  (``problems``; app/core/config._validate_runtime_settings). IPv6 literals and ``0.0.0.0`` are not host names the
  check can match: the Host check then refuses every request but the health probe's.

Pure, so both readers and the host tool's documentation can be held to it offline (tests/test_allowed_hosts.py).
"""
from typing import List, Optional, Tuple
from urllib.parse import urlsplit

_HEALTH_PROBE_HOSTS = ("localhost", "127.0.0.1")


def entries(raw) -> List[str]:
    return [e.strip() for e in (raw or "").split(",") if e.strip()]


def _is_wildcard(name: str) -> bool:
    return name in ("*", "0.0.0.0") or name.startswith(".") or "*" in name


def _bare(entry: str) -> str:
    """A bare entry as the Host check and the link base read it: lower case, without anything after a "/"."""
    return entry.split("/", 1)[0].lower()


def _origin(entry: str) -> Optional[Tuple[str, str, str]]:
    """An origin entry's scheme, host name and network location, or None when its host cannot be read."""
    try:
        parts = urlsplit(entry)
        host = parts.hostname or ""
    except ValueError:
        return None
    return (parts.scheme.lower(), host, parts.netloc.lower()) if host else None


def host_name(entry: str) -> str:
    """An entry's host name, as the Host check compares it: a wildcard as written, an origin's host, a bare name
    without its port. "" when it has none that can be read."""
    if "://" in entry:
        origin = _origin(entry)
        return origin[1] if origin else ""
    bare = _bare(entry)
    if _is_wildcard(bare):
        return bare
    return bare.split(":", 1)[0] if bare.count(":") == 1 else bare


def problems(raw) -> List[str]:
    """The entries with no host name that can be read, each quoted, for the error that stops the server at start."""
    return [repr(entry) for entry in entries(raw) if not host_name(entry)]


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
        if "://" in entry:
            origin = _origin(entry)
            if origin and origin[0] in ("http", "https") and not _is_wildcard(origin[1]) and "*" not in origin[2]:
                return f"{origin[0]}://{origin[2]}"
            continue
        bare = _bare(entry)
        if host_name(entry) and not _is_wildcard(bare):
            return f"https://{bare}"
    return ""
