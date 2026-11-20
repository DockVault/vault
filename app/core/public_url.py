"""The vault's public address, as the sign-in features need it.

There is one configured address and it is never taken from a request: the first ``ALLOWED_HOSTS`` entry that is
not a wildcard, read as an origin (``app/core/allowed_hosts.link_base``). It is the base of every emailed link.
Passkeys and single sign-on are built on the same address, and ask more of it than an email does:

- a passkey is bound to the address the browser shows (the relying-party id is its host; the origin the browser
  signs into every assertion includes the scheme and the port), and a browser makes passkeys only in a secure
  context and never for an IP address;
- an identity provider sends the browser back to a redirect address registered with it, on https (plain http only
  for localhost).

So for these features the address must be ``https://host[:port]``, or ``http://`` on localhost, 127.0.0.1 or ::1
(a browser treats those as a secure context, so tests and a laptop need no TLS). An address that is anything else
stays what the emailed links use and is no address for sign-in: passkeys and single sign-on are then off, and
``readiness`` says why. With no address at all (``ALLOWED_HOSTS`` empty, or wildcards only) they are off too.
Nothing here looks for another entry or another setting: one address, or none.

``problem`` says why an address cannot serve sign-in; ``public_base_url`` is the address itself; ``rp_id`` and
``expected_origin`` are what passkeys need; ``readiness`` is what the administrator page and the host tool say, and
``why_not_usable`` and ``why_no_passkeys`` say it in words.
"""
from __future__ import annotations

import ipaddress
from typing import Optional
from urllib.parse import urlsplit

# Hosts that may use plain http: a browser treats them as a secure context, so tests and a laptop need no TLS.
_PLAIN_HTTP_HOSTS = frozenset({"localhost", "127.0.0.1", "::1"})
_DEFAULT_PORTS = {"https": 443, "http": 80}
# What the reasons call it: the address is set in one place.
_NAME = "The vault's address (the first ALLOWED_HOSTS entry)"

NO_PUBLIC_HOST = "no_public_host"            # no address is configured
ADDRESS_NOT_USABLE = "address_not_usable"    # an address is configured that sign-in cannot be built on
IP_ADDRESS = "ip_address"                    # an address reached by IP: browsers make no passkey for one
OK = "ok"


def problem(value: Optional[str]) -> Optional[str]:
    """Why ``value`` is not an address sign-in can be built on, or None when it is (or is empty).

    Usable: ``https://host``, ``https://host:port``, and ``http://`` for localhost, 127.0.0.1 and ::1 only.
    Not usable, with a plain reason that never repeats the value: another scheme, a missing host, a user name or
    password in the address, a path, a query or a fragment (the address is where the vault is, not a page in it),
    a port outside 1-65535, plain http for any other host, and a host name written in another script: the browser
    writes such a name in its ``xn--`` form, and the conversions differ (the one at hand turns a sharp s into
    ``ss``, a different name from the one the browser asks for), so the name is taken only as the browser writes it.
    """
    raw = (value or "").strip()
    if not raw:
        return None
    try:
        parts = urlsplit(raw)
    except ValueError:
        return f"{_NAME} cannot be read as an address"
    scheme = (parts.scheme or "").lower()
    if scheme not in _DEFAULT_PORTS:
        return f"{_NAME} must start with https:// (http:// only for localhost or 127.0.0.1)"
    if parts.username is not None or parts.password is not None:
        return f"{_NAME} must not carry a user name or password"
    try:
        host = parts.hostname
        port = parts.port
    except ValueError:
        return f"{_NAME} has a port that is not a number between 1 and 65535"
    if not host:
        return f"{_NAME} has no host name"
    if not host.isascii():
        return (f"{_NAME} has a host name written in another script: write it in its xn-- form, as the browser's "
                "address bar shows it")
    if _host_problem(host):
        return f"{_NAME} has a host name no browser accepts (letters, digits, hyphens and dots, or an IP address)"
    if port is not None and not (1 <= port <= 65535):
        return f"{_NAME} has a port that is not a number between 1 and 65535"
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        return f"{_NAME} is the vault's address only: scheme, host and optional port, with no path"
    if scheme == "http" and host.lower() not in _PLAIN_HTTP_HOSTS:
        return f"{_NAME} must use https:// for sign-in (http:// is allowed only for localhost or 127.0.0.1)"
    return None


def _host_problem(host: str) -> bool:
    """Whether ``host`` is not one a browser would put in an origin: an IP address (no zone id), or a name of
    letters, digits, hyphens and dots whose labels start and end with a letter or digit (a name in another
    script only in its ``xn--`` form, which is such a name; ``problem`` refuses the other spelling in words)."""
    if not host or "%" in host:          # no zone id, no escaped character: an origin carries neither
        return True
    try:
        ipaddress.ip_address(host)
        return False
    except ValueError:
        pass
    try:
        name = host.rstrip(".").encode("idna").decode("ascii").lower()
    except UnicodeError:
        return True
    if not name or len(name) > 253:
        return True
    for label in name.split("."):
        if not label or len(label) > 63 or label[0] == "-" or label[-1] == "-":
            return True
        if not all(ch.isascii() and (ch.isalnum() or ch == "-") for ch in label):
            return True
    return False


def _origin_host(host: str) -> str:
    """``host`` as the browser writes it in an origin: lower case, punycode, an IPv6 address in brackets."""
    try:
        ipaddress.ip_address(host)
        return f"[{host.lower()}]" if ":" in host else host
    except ValueError:
        return host.rstrip(".").encode("idna").decode("ascii").lower()


def normalize(value: Optional[str]) -> str:
    """``value`` as the browser writes an origin: lower-case scheme, the host in punycode and lower case, the
    port only when it is not the scheme's default, no trailing slash. Empty for an empty or unusable value."""
    raw = (value or "").strip()
    if not raw or problem(raw) is not None:
        return ""
    parts = urlsplit(raw)
    scheme = parts.scheme.lower()
    host = _origin_host(parts.hostname)
    port = parts.port
    if port is None or port == _DEFAULT_PORTS[scheme]:
        return f"{scheme}://{host}"
    return f"{scheme}://{host}:{port}"


def link_base() -> str:
    """The one configured address, as the emailed links read it (app/core/allowed_hosts.link_base); "" when there
    is none. Never a request's own host. Never raises."""
    try:
        from app.core.allowed_hosts import link_base as _link_base
        from app.core.config import settings
        return _link_base(getattr(settings, "allowed_hosts", "") or "")
    except Exception:  # noqa: BLE001 -- without settings there is no address
        return ""


def _configured() -> str:
    """The configured address when sign-in can be built on it, as a browser writes an origin; else ""."""
    return normalize(link_base())


def public_base_url() -> str:
    """The vault's public address for sign-in, without a trailing slash, or "" when none is configured or the
    configured one cannot serve sign-in. Never a request's own host."""
    return _configured()


def expected_origin() -> str:
    """The origin a browser at the public address signs into a passkey assertion (``scheme://host[:port]``,
    the port only when not the default), or ""."""
    return _configured()


def rp_id() -> str:
    """The relying-party id for passkeys: the public address's host, lower-case, without a port; "" when
    there is no address sign-in can use."""
    base = _configured()
    if not base:
        return ""
    try:
        host = urlsplit(base).hostname or ""
    except ValueError:
        return ""
    return _origin_host(host).strip("[]")


def is_ip_address(host: str) -> bool:
    try:
        ipaddress.ip_address((host or "").strip("[]"))
        return True
    except ValueError:
        return False


def readiness() -> dict:
    """What passkeys and single sign-on can do with the address: ``{"usable", "rp_id", "origin", "reason"}``
    with ``reason`` one of ``ok``, ``no_public_host`` (no address is configured), ``address_not_usable`` (one is,
    and sign-in cannot be built on it: ``why_not_usable`` says why) and ``ip_address`` (an address reached by IP:
    browsers do not create passkeys for one). The administrator page and the host tool say it in words."""
    if not link_base():
        return {"usable": False, "rp_id": "", "origin": "", "reason": NO_PUBLIC_HOST}
    host = rp_id()
    origin = expected_origin()
    if not host:
        return {"usable": False, "rp_id": "", "origin": "", "reason": ADDRESS_NOT_USABLE}
    if is_ip_address(host):
        return {"usable": False, "rp_id": host, "origin": origin, "reason": IP_ADDRESS}
    return {"usable": True, "rp_id": host, "origin": origin, "reason": OK}


def why_not_usable() -> str:
    """In words, why sign-in cannot be built on the address as configured; "" when it can.

    With no address: how to set one. With one that cannot serve sign-in: what is wrong with it, never the value
    itself (this text reaches an administrator's page and the server's log)."""
    base = link_base()
    if not base:
        return ("The vault has no public address. Set ALLOWED_HOSTS in .env to the address people open the vault "
                "at (dockvault.py setup writes it), then restart.")
    return (problem(base) or "") and f"{problem(base)}. Change ALLOWED_HOSTS in .env, then restart."


def why_no_passkeys() -> str:
    """In words, why no passkey can be made at the address as configured; "" when one can. No address, an address
    sign-in cannot be built on (``why_not_usable``), or an address reached by IP: a browser makes no passkey for
    one, though single sign-on and the emailed links work there."""
    ready = readiness()
    if ready["usable"]:
        return ""
    if ready["reason"] == IP_ADDRESS:
        return ("Browsers make no passkey for an address reached by IP. Put the vault's host name first in "
                "ALLOWED_HOSTS in .env, then restart.")
    return why_not_usable()
