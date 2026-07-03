"""Trusted-proxy-aware client IP resolution.

Per-IP throttling and audit logging must use the REAL client IP, but X-Forwarded-For is
client-controllable and trivially spoofable when read blindly. We therefore honour XFF only
when the immediate TCP peer (request.client.host) is a trusted proxy, and even then we do NOT
blindly take the left-most entry — append-style proxies (nginx proxy_add_x_forwarded_for,
Traefik, ALB) APPEND the connecting IP, so a client that sends `X-Forwarded-For: 9.9.9.9`
produces `9.9.9.9, <real-ip>` at the app and the left-most value is attacker-chosen. Instead we
walk the chain RIGHT-TO-LEFT and return the first entry that is NOT itself a trusted proxy — the
real client. This closes the spoof both for a direct public client (untrusted peer => XFF
ignored) and behind a trusted proxy chain.

Trust set (settings.trusted_proxies, CIDR or bare IP, comma-separated). Empty => the safe
default of loopback + RFC1918 private ranges (the reverse proxy / ingress sits on the internal
network; a public peer never does). settings.trust_all_proxies=true honours XFF from any peer
(only correct behind a proxy that itself strips/normalises client-supplied XFF).
"""
import ipaddress
from functools import lru_cache
from typing import List, Optional

from config import settings


# Loopback + RFC1918 private ranges + link-local + unique-local (IPv6). A reverse proxy /
# docker ingress fronting the app lives in one of these; a public client never does.
_DEFAULT_TRUSTED = [
    "127.0.0.0/8", "::1/128",
    "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16",
    "169.254.0.0/16", "fc00::/7", "fe80::/10",
]


@lru_cache(maxsize=1)
def _trusted_networks() -> List[ipaddress._BaseNetwork]:
    """Parsed trusted-proxy networks (cached). settings.trusted_proxies overrides the default
    private+loopback set; unparseable entries are skipped."""
    raw = (getattr(settings, "trusted_proxies", "") or "").strip()
    specs = [s.strip() for s in raw.split(",") if s.strip()] if raw else _DEFAULT_TRUSTED
    nets: List[ipaddress._BaseNetwork] = []
    for spec in specs:
        try:
            nets.append(ipaddress.ip_network(spec, strict=False))
        except ValueError:
            continue
    return nets


def _normalize(addr: "ipaddress._BaseAddress") -> "ipaddress._BaseAddress":
    """Map an IPv4-mapped IPv6 address (::ffff:a.b.c.d) to its IPv4 form so the membership
    test and the returned value are consistent on dual-stack listeners."""
    if addr.version == 6 and addr.ipv4_mapped is not None:
        return addr.ipv4_mapped
    return addr


def _parse_ip(token: Optional[str]) -> Optional["ipaddress._BaseAddress"]:
    """Parse an XFF token (or peer host) to a normalized ip address, tolerating an optional
    :port and [ipv6] wrapper. Returns None for a non-IP token (e.g. 'unknown', '_hidden')."""
    if not token:
        return None
    token = token.strip()
    candidates = [token]
    if token.startswith("[") and "]" in token:              # [::1] or [::1]:443
        candidates.append(token[1:token.index("]")])
    elif token.count(":") == 1:                              # 1.2.3.4:5678
        candidates.append(token.rsplit(":", 1)[0])
    for cand in candidates:
        try:
            return _normalize(ipaddress.ip_address(cand))
        except ValueError:
            continue
    return None


def _is_trusted_addr(addr: Optional["ipaddress._BaseAddress"]) -> bool:
    if getattr(settings, "trust_all_proxies", False):
        return True
    if addr is None:
        return False
    return any(addr in net for net in _trusted_networks())


def _is_trusted_peer(peer: Optional[str]) -> bool:
    return _is_trusted_addr(_parse_ip(peer))


def _real_client_from_xff(forwarded: str) -> Optional[str]:
    """Walk the X-Forwarded-For chain RIGHT-TO-LEFT and return the first entry that is a valid
    IP and NOT a trusted proxy — i.e. the real client. If every hop is trusted (all-internal
    traffic) fall back to the left-most valid entry. Junk / non-IP tokens are skipped."""
    parsed = [_parse_ip(p) for p in forwarded.split(",")]
    parsed = [a for a in parsed if a is not None]
    if not parsed:
        return None
    for addr in reversed(parsed):
        if not _is_trusted_addr(addr):
            return str(addr)
    return str(parsed[0])  # all hops trusted -> the originating (left-most) address


def client_ip(request) -> str:
    """Best-effort real client IP for a Starlette/FastAPI request.

    Honours X-Forwarded-For ONLY when the immediate peer is a trusted proxy, and then returns
    the right-most untrusted entry (so a direct/untrusted client — or a forged left-most value
    behind a trusted proxy — can't spoof its IP). Falls back to the peer address, then
    'unknown'."""
    peer = request.client.host if request.client else None
    forwarded = request.headers.get("X-Forwarded-For")
    if forwarded and _is_trusted_peer(peer):
        real = _real_client_from_xff(forwarded)
        if real:
            return real
    parsed_peer = _parse_ip(peer)
    return str(parsed_peer) if parsed_peer is not None else (peer or "unknown")
