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
    learns is the egress IP, inherent to any outbound HTTP (documented in README.md and
    .github/SECURITY.md).
  * SUPPRESSED for a centrally managed deployment (``managed_deployment``), which upgrades via
    operator promote, not self-service — so the banner never shows a CTA the customer can't use.
"""
import json
import re
import threading
import time
import urllib.request

GITHUB_LATEST_URL = "https://api.github.com/repos/DockVault/vault/releases/latest"
RAW_VERSION_URL = "https://raw.githubusercontent.com/DockVault/vault/main/VERSION"
CACHE_TTL = 24 * 3600   # default seconds between outbound checks (used when no interval is passed)
# Admin-configurable check-interval bounds (minutes). The FLOOR keeps the outbound cadence
# rate-limit-safe: GitHub's unauthenticated API is ~60 req/hr/IP, and the shared process cache means
# every admin poll reads the cache while only ONE real request goes out per interval.
MIN_INTERVAL_MINUTES = 15
MAX_INTERVAL_MINUTES = 30 * 24 * 60      # 30 days
DEFAULT_INTERVAL_MINUTES = 360           # 6 hours (more often than daily, still gentle)
# A forced "check now" bypasses the interval but not this hard minimum age between real requests,
# so repeated button clicks can't be spammed into the rate limit.
FORCE_MIN_SECONDS = 60
TIMEOUT = 5             # per-request seconds (short — never hang a page)
MAX_BODY_BYTES = 512 * 1024  # cap the response we buffer/parse (fail-closed on anything larger)
_USER_AGENT = "DockVault-update-check"

# Process-level cache; re-checks after a restart, which is fine (no persistence needed).
_cache = {"checked_at": 0.0, "latest": None, "url": None, "notes": None, "matrix": None}
# Serialize the outbound fetch so concurrent admin requests (this runs in FastAPI's sync-endpoint
# threadpool) coalesce into ONE GitHub call per interval instead of a thundering herd at expiry.
_fetch_lock = threading.Lock()


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


def clamp_interval_minutes(minutes):
    """Clamp a requested check interval into [MIN_INTERVAL_MINUTES, MAX_INTERVAL_MINUTES]. A non-int
    or out-of-range value snaps into range, so a mis-set override can never drive the outbound
    cadence below the rate-limit-safe floor (or absurdly high). Returns an int number of minutes."""
    try:
        m = int(minutes)
    except (TypeError, ValueError):
        return DEFAULT_INTERVAL_MINUTES
    return max(MIN_INTERVAL_MINUTES, min(MAX_INTERVAL_MINUTES, m))


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


def get_update_status(current_version, enabled, managed, force=False, interval_seconds=None,
                      force_min_seconds=FORCE_MIN_SECONDS):
    """Return the update-status dict for the admin UI. Fail-closed-silent; safe to call often
    (a real outbound request goes out at most once per ``interval_seconds`` — the shared cache
    protects GitHub's rate limit no matter how frequently the UI polls). ``force`` is a manual
    "check now" that bypasses the interval but still honours ``force_min_seconds`` between real
    requests, so repeated clicks can't be spammed into the rate limit."""
    if managed:
        return {"enabled": False, "managed": True, "current": current_version, "update_available": False}
    if not enabled:
        return {"enabled": False, "managed": False, "current": current_version, "update_available": False}
    ttl = CACHE_TTL if interval_seconds is None else max(1, int(interval_seconds))

    def _due():
        age = time.time() - _cache["checked_at"]
        if force:
            return age >= max(0, force_min_seconds)
        return (_cache["latest"] is None) or (age > ttl)

    if _due():
        # Double-checked locking: a caller that waited on the lock re-checks and skips the fetch a
        # peer just did, so concurrent admin requests make ONE outbound call. Only advance
        # checked_at on a SUCCESSFUL fetch, so a transient outage retries next call rather than
        # going quiet for a whole interval.
        with _fetch_lock:
            if _due():
                latest, url, notes = _fetch_latest()
                if latest is not None:
                    # The matrix is fetched inside the same lock and the same interval as the
                    # release check, so a polling admin page still costs one round of outbound
                    # requests however often it polls. A matrix that cannot be fetched is left
                    # None: the banner then degrades to what it said before this existed, which is
                    # a worse banner but not a broken one.
                    _cache.update({"checked_at": time.time(), "latest": latest, "url": url,
                                   "notes": notes, "matrix": _fetch_matrix(latest)})
    latest = _cache["latest"]
    available = is_newer(latest, current_version)
    status = {
        "enabled": True,
        "managed": False,
        "current": current_version,
        "latest": latest,
        "update_available": available,
        "url": _cache["url"],
        "notes": _cache["notes"],
        "checked_at": _cache["checked_at"] or None,
    }
    if available:
        # Only when there is something to describe. Attaching an "unknown, assume the worst"
        # verdict to a deployment that is already current would put a warning on the screen about
        # an upgrade nobody is being offered.
        status["upgrade"] = describe_hop(_cache.get("matrix"), current_version, latest)
    return status


# --- what the available update would cost -------------------------------------------------------
#
# The banner used to say only that a version exists. An operator who reads "0.11.0 available" and
# presses update has no way to know whether that is a drop-in or a one-way schema change, and the
# place they find out should not be afterwards.
#
# This deliberately mirrors `plan_upgrade_path` in `dockvault.py` rather than importing it. That
# script is stdlib-only and runs on the host, outside the image, precisely so it keeps working when
# the app does not; making it import from `app/` would give that up. Two implementations of one
# rule is a drift risk, so a test feeds both the same matrices and asserts they agree.

MATRIX_URL = "https://raw.githubusercontent.com/DockVault/vault/%s/docs/upgrade-matrix.json"


def _semver_key(version):
    return tuple(int(part) for part in version.split("."))


def _walk_edges(matrix, current, target):
    """The declared edges leading from `current` to `target`, or None if there is no route.

    A breadth-first search over what the file actually declares, rather than a march through
    version-order neighbours. The difference only shows up once a backport exists, and then it
    matters: releasing 0.9.1 after 0.10.0 has shipped puts it BETWEEN them by version, so a
    neighbour march looks for 0.9.1 -> 0.10.0, finds nothing, and calls a hop undescribable that
    the file describes perfectly well with 0.9.0 -> 0.10.0. The validator already exempts that
    pair from needing an edge, so the two halves disagreed about what "adjacent" meant.

    Shortest route, and ties broken by version order, so the answer is the same on every run and
    on both implementations.
    """
    edges = {}
    for edge in (matrix.get("edges") or []):
        if isinstance(edge, dict) and edge.get("from") and edge.get("to"):
            edges.setdefault(edge["from"], []).append(edge)
    for outgoing in edges.values():
        outgoing.sort(key=lambda e: _semver_key(e["to"]))

    queue = [(current, [])]
    seen = {current}
    while queue:
        node, path = queue.pop(0)
        if node == target:
            return path
        for edge in edges.get(node, []):
            nxt = edge["to"]
            if nxt in seen:
                continue
            seen.add(nxt)
            queue.append((nxt, path + [edge]))
    return None


def _split_into_legs(matrix, steps):
    """Group the route's edges into the legs the upgrade must actually be performed in.

    A version marked `must_land_here` cannot be passed through in one recreate: the deployment has
    to come up ON it, finish its boot, and be verified before continuing. That happens where a
    migration needs the previous release's data already rewritten, or where a change is staged
    across two releases and the second assumes the first has run.

    The operator still runs ONE upgrade. The legs are what the tool does underneath, and what the
    database goes through -- not extra work for the person. A route with no such version is one leg,
    which is the ordinary case and stays a single recreate.
    """
    versions = matrix.get("versions") or {}
    legs, current = [], []
    for edge in steps:
        current.append(edge)
        if versions.get(edge.get("to"), {}).get("must_land_here"):
            legs.append(current)
            current = []
    if current:
        legs.append(current)
    return legs


def _leg_summary(leg):
    return {
        "to": leg[-1]["to"],
        "steps": leg,
        "requires_backup": any(e.get("requires_backup") for e in leg),
        "irreversible": any(not e.get("reversible", True) for e in leg),
        "conditions": [c for e in leg for c in (e.get("conditions") or [])],
    }


def describe_hop(matrix, current, target):
    """What moving from `current` to `target` involves, per the matrix.

    Returns {known, requires_backup, irreversible, blocked, conditions, steps}. Unknown resolves to
    "needs a backup, may be irreversible" -- the banner says so rather than implying a drop-in,
    because a gap in the matrix is where nobody has considered the upgrade.
    """
    unknown = {"known": False, "requires_backup": True, "irreversible": True,
               "blocked": False, "conditions": [], "steps": 0, "stages": 0}
    if not isinstance(matrix, dict):
        return unknown
    versions = matrix.get("versions")
    if not isinstance(versions, dict):
        return unknown
    current = (current or "").lstrip("vV")
    target = (target or "").lstrip("vV")
    if current not in versions or target not in versions:
        return unknown
    try:
        ordered = sorted(versions, key=_semver_key)
    except (TypeError, ValueError):
        return unknown
    if _semver_key(target) <= _semver_key(current):
        return unknown

    steps = _walk_edges(matrix, current, target)
    if steps is None:
        return unknown

    return {
        "known": True,
        # How many times the deployment is recreated on the way. More than one means the upgrade
        # takes longer, NOT that the operator does more: the tool performs the legs itself.
        "stages": len(_split_into_legs(matrix, steps)),
        "requires_backup": any(e.get("requires_backup") for e in steps),
        "irreversible": any(not e.get("reversible", True) for e in steps),
        "blocked": any(e.get("kind") == "blocked" for e in steps),
        "conditions": [c.get("summary", "") for e in steps for c in (e.get("conditions") or [])
                       if isinstance(c, dict)],
        "steps": len(steps),
    }


def _fetch_matrix(tag):
    """The upgrade matrix published with `tag`, or None. NEVER raises.

    Goes through the same capped, timed-out reader as every other outbound call here, so an
    oversized or slow response cannot become this process's problem.
    """
    try:
        return _http_json(MATRIX_URL % (tag if str(tag).startswith("v") else "v%s" % tag))
    except Exception:  # noqa: BLE001 — fail-closed-silent, like the rest of this module
        return None
