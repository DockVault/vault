"""Opt-in, fail-closed-silent update check against GitHub Releases.

DEFAULT OFF (``config.update_check_enabled``). When enabled, the running container makes at most
one outbound request per ``CACHE_TTL`` to the public GitHub Releases API to learn the latest
published version; the admin UI shows a dismissible banner if it is newer than this build.

Privacy / safety contract (all HARD requirements):
  * OPT-IN, default off — air-gapped / firewalled installs stay completely silent.
  * Fail-closed-silent — any error (no egress, timeout, rate limit, bad JSON) yields "no update
    known"; it NEVER raises, blocks a request, or shows an error to the user.
  * No telemetry — the request carries NO instance identifier, account data, or even the current
    version: just a plain unauthenticated GET with a generic User-Agent. The only thing GitHub
    learns is the egress IP, inherent to any outbound HTTP (documented in README / SECURITY.md).
  * SUPPRESSED for a control-plane-managed deployment (``managed_deployment``), which upgrades via
    operator promote, not self-service — so the banner never shows a CTA the customer can't use.
"""
import json
import re
import time
import urllib.request

GITHUB_LATEST_URL = "https://api.github.com/repos/DockVault/vault/releases/latest"
RAW_VERSION_URL = "https://raw.githubusercontent.com/DockVault/vault/main/VERSION"
CACHE_TTL = 24 * 3600   # seconds between outbound checks
TIMEOUT = 5             # per-request seconds (short — never hang a page)
MAX_BODY_BYTES = 512 * 1024  # cap the response we buffer/parse (fail-closed on anything larger)
_USER_AGENT = "DockVault-update-check"

# Process-level cache; re-checks after a restart, which is fine (no persistence needed).
_cache = {"checked_at": 0.0, "latest": None, "url": None, "notes": None}


def _parse_semver(v):
    """('v1.2.3-rc1' | '1.2.3') -> (1, 2, 3); pre-release/build suffix ignored. None if unparseable."""
    if not v:
        return None
    m = re.match(r"[vV]?(\d+)\.(\d+)\.(\d+)", str(v).strip())
    return tuple(int(x) for x in m.groups()) if m else None


def is_newer(latest, current):
    """True iff ``latest`` is a strictly-higher release than ``current`` (both semver-ish).
    A never-flags-on-uncertainty comparator: unparseable input => False (no false 'update')."""
    lv, cv = _parse_semver(latest), _parse_semver(current)
    return bool(lv and cv and lv > cv)


def _read_capped(r):
    """Read at most MAX_BODY_BYTES; raise if the response is larger (fail-closed on an oversized
    body from a compromised/anomalous endpoint rather than buffering it all)."""
    raw = r.read(MAX_BODY_BYTES + 1)
    if len(raw) > MAX_BODY_BYTES:
        raise ValueError("update-check response exceeds the size cap")
    return raw


def _http_json(url):
    req = urllib.request.Request(
        url, headers={"User-Agent": _USER_AGENT, "Accept": "application/vnd.github+json"})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310 (fixed https URL)
        return json.loads(_read_capped(r).decode("utf-8"))


def _http_text(url):
    req = urllib.request.Request(url, headers={"User-Agent": _USER_AGENT})
    with urllib.request.urlopen(req, timeout=TIMEOUT) as r:  # noqa: S310
        return _read_capped(r).decode("utf-8").strip()


def _fetch_latest():
    """Best-effort: GitHub Releases first (carries notes + url), else the raw VERSION on main.
    Returns (latest, url, notes) or (None, None, None). NEVER raises."""
    try:
        data = _http_json(GITHUB_LATEST_URL)
        tag = (data.get("tag_name") or "").strip()
        if _parse_semver(tag):
            return tag, data.get("html_url"), (data.get("body") or "")[:2000]
    except Exception:  # noqa: BLE001 — fail-closed-silent
        pass
    try:
        ver = _http_text(RAW_VERSION_URL)
        if _parse_semver(ver):
            return ver, "https://github.com/DockVault/vault/releases", ""
    except Exception:  # noqa: BLE001
        pass
    return None, None, None


def get_update_status(current_version, enabled, managed, force=False):
    """Return the update-status dict for the admin UI. Fail-closed-silent; safe to call often
    (it only hits the network at most once per CACHE_TTL)."""
    if managed:
        return {"enabled": False, "managed": True, "current": current_version, "update_available": False}
    if not enabled:
        return {"enabled": False, "managed": False, "current": current_version, "update_available": False}
    if force or _cache["latest"] is None or (time.time() - _cache["checked_at"]) > CACHE_TTL:
        latest, url, notes = _fetch_latest()
        # Only advance checked_at on a successful fetch, so a transient outage retries next call
        # instead of going quiet for a whole TTL.
        if latest is not None:
            _cache.update({"checked_at": time.time(), "latest": latest, "url": url, "notes": notes})
    latest = _cache["latest"]
    return {
        "enabled": True,
        "managed": False,
        "current": current_version,
        "latest": latest,
        "update_available": is_newer(latest, current_version),
        "url": _cache["url"],
        "notes": _cache["notes"],
        "checked_at": _cache["checked_at"] or None,
    }
