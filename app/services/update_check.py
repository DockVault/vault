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
_cache = {"checked_at": 0.0, "latest": None, "url": None, "notes": None, "matrix": None,
          "main_matrix": None, "main_fetched_at": None, "line_matrices": {}}
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
        return {"enabled": False, "managed": True, "current": current_version, "update_available": False,
                "security": merged_security(current_version, released_ceiling=None, main_matrix=None)}
    if not enabled:
        return {"enabled": False, "managed": False, "current": current_version, "update_available": False,
                "security": merged_security(current_version, released_ceiling=None, main_matrix=None)}
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
                    main_matrix = fetch_main_matrix()
                    # An install on an older release line is offered the newest release of that
                    # line too, but only once that release's own published matrix has been
                    # fetched: main's copy names it, the tag's matrix proves it was released. The
                    # matrices of every older supported line's newest release are fetched, in the
                    # same round, whatever this install runs: requests that depended on the running
                    # version would tell GitHub which line it is on.
                    _cache.update({"checked_at": time.time(), "latest": latest, "url": url,
                                   "notes": notes, "matrix": _fetch_matrix(latest),
                                   "main_matrix": main_matrix,
                                   "main_fetched_at": time.time(),
                                   "line_matrices": {v: _fetch_matrix(v) for v in
                                                     _older_line_releases(main_matrix, latest)}})
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
    # The deployment's OWN security posture, merged add-only from the copy on main into the bundled
    # copy. Always present when the check runs (fail-safe source "bundled" when main is unreachable);
    # never a false secure. The ceiling for a credible remote fix is the newest release we can see
    # (latest), never the running version, so a fix in a newer release is still surfaced.
    bundled = _read_bundled_matrix()
    status["security"] = merged_security(
        current_version, released_ceiling=latest,
        local_matrix=bundled, main_matrix=_cache.get("main_matrix"),
        fetched_at=_cache.get("main_fetched_at"))
    try:
        line = line_status(current_version, bundled, _cache.get("main_matrix"))
        if line is not None:
            status["line"] = line
        update = line_update(current_version, latest, bundled, _cache.get("main_matrix"),
                             _cache.get("line_matrices"))
        if update is not None:
            status["line_update"] = update
    except Exception:  # noqa: BLE001 -- a malformed remote never breaks the status; no line notice
        pass
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

    A version's `vulnerabilities` list plays no part in describing a hop: the app surfaces the
    RUNNING version's own findings in the banner (_version_vulnerabilities, below), and the host tool
    reads them per target. This consumer reads the matrix permissively, so here the key is ignored
    like any it does not use -- a matrix carrying it describes a hop exactly as one without.
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


# --- Lifecycle from main: the version's security posture can change AFTER its tag was cut ----------
#
# A version's own shipped matrix (and its tag-frozen copy) self-declares secure forever -- it cannot
# know a vulnerability found later. So the security verdict for the DEPLOYMENT'S OWN version is read
# from the bundled copy MERGED, add-only, with the copy on main:
#   secure  = bundled AND main       (main can only ADD an insecure verdict, never clear one)
#   eol     = bundled OR main
#   vulns   = UNION (dedupe title+fixed_in)  support-end dates = the EARLIER
# No source is preferred and nothing is ever cleared; a retraction is a code release. The merge can
# only TIGHTEN, so a poisoned main can raise a false warning but can NEVER produce a false secure.
# The host tool applies the same rule for its own display; a test feeds both the same matrices and
# asserts they agree, since the two live apart (the tool is stdlib-only, host-side).
MAIN_MATRIX_URL = "https://raw.githubusercontent.com/DockVault/vault/main/docs/upgrade-matrix.json"


def _version_support(matrix, version):
    """The `support` block for `version`, or {} (tolerant: an old/permissive matrix reads as
    'nothing stated', never an error)."""
    if not isinstance(matrix, dict):
        return {}
    version = (version or "").lstrip("vV")
    meta = (matrix.get("versions") or {}).get(version) or {}
    support = meta.get("support")
    return support if isinstance(support, dict) else {}


def _release_line(version):
    """'0.33' for '0.33.2' or 'v0.33.2'; None when the version does not parse."""
    parsed = _parse_semver(version)
    return "%d.%d" % parsed[:2] if parsed else None


def _fix_list(value):
    """An advisory's `fixed_in_lines` as a list of version strings (at most 20, each one that parses
    as a version), or [] when it is absent or not a list."""
    if not isinstance(value, list):
        return []
    out = []
    for item in value[:20]:
        if isinstance(item, str) and _parse_semver(item) and item[:32] not in out:
            out.append(item[:32])
    return out


def _line_fix(version, fixes):
    """The lowest of an advisory's fixes above `version`: the fix on its own line when that line has
    one (every other line's fix above it is on a higher line), else the next line's; or None."""
    parsed = _parse_semver(version)
    above = [f for f in fixes if parsed and _parse_semver(f) > parsed]
    return min(above, key=_parse_semver) if above else None


def _reference_title_and_fix(ref, advisories, version=None):
    """A version's reference to an advisory, as (title, fixed_in).

    A reference repeats its advisory's title and fixed_in today, because readers older than the
    top-level `advisories` map read nothing else. A later matrix may carry only the advisory's id
    ({"advisory": "<slug>"}); a field the reference leaves out is then taken from that advisory in the
    same matrix -- the fix on `version`'s own line when the advisory lists one per line
    (`fixed_in_lines`) -- and a missing title falls back to the id, so the vulnerability is still
    counted and named. A field the reference does carry wins, as it always has, so both forms of one
    advisory dedupe to the same (title, fixed_in)."""
    slug = ref.get("advisory") if isinstance(ref.get("advisory"), str) else None
    record = advisories.get(slug) if slug is not None else None
    record = record if isinstance(record, dict) else {}
    title = ref["title"] if "title" in ref else (record.get("title") or slug)
    if "fixed_in" in ref:
        fixed_in = ref["fixed_in"]
    else:
        fixed_in = (_line_fix(version, _fix_list(record.get("fixed_in_lines")))
                    or record.get("fixed_in"))
    return title, fixed_in


def _version_vulnerabilities(matrix, version):
    """The declared vulnerabilities for `version`, or []. Tolerant like _version_support. Each entry
    is normalised to {title, fixed_in} with BOTH coerced to a bounded str or None as it is read --
    before it ever reaches the dedupe -- so an unhashable JSON value ({} / []) in either field can
    never blow the (title, fixed_in) dedupe key. A non-dict entry is dropped. A reference that carries
    only its advisory's id takes its title and fixed_in from the matrix's `advisories` map
    (_reference_title_and_fix)."""
    return [{"title": v["title"], "fixed_in": v["fixed_in"]}
            for v in _version_findings(matrix, version)]


def _version_findings(matrix, version):
    """_version_vulnerabilities with each entry's advisory id kept ({title, fixed_in, advisory}), which
    is what tells one advisory apart across lines: a reference names its own line's fix, so the same
    advisory reads (title, 0.33.2) on 0.33.1 and (title, 0.34.1) on 0.34.0."""
    if not isinstance(matrix, dict):
        return []
    version = (version or "").lstrip("vV")
    meta = (matrix.get("versions") or {}).get(version) or {}
    if not isinstance(meta, dict):
        return []
    vulns = meta.get("vulnerabilities")
    if not isinstance(vulns, list):
        return []
    advisories = matrix.get("advisories")
    advisories = advisories if isinstance(advisories, dict) else {}
    out = []
    for v in vulns:
        if not isinstance(v, dict):
            continue
        title, fixed_in = _reference_title_and_fix(v, advisories, version)
        slug = v.get("advisory") if isinstance(v.get("advisory"), str) and v.get("advisory") else None
        out.append({"title": _bound(title), "fixed_in": _bound(fixed_in), "advisory": _bound(slug)})
    return out


def _knows_version(matrix, version):
    """True when `matrix` LISTS `version` at all (a versions entry, even an empty one). Distinct from
    having a support block: it is how a positive 'secure' is earned -- a source must actually know the
    version to vouch for it."""
    if not isinstance(matrix, dict):
        return False
    version = (version or "").lstrip("vV")
    return version in (matrix.get("versions") or {})


def _credible_remote_vulns(remote_vulns, released_ceiling):
    """Drop a remote vulnerability whose `fixed_in` names a version NEWER than the newest RELEASE the
    consumer can see -- an unreleased fix is not a credible disclosure (a poisoning tell). The ceiling
    is the newest RELEASE tag, NEVER the running version, so a fix in a newer-but-released version is
    kept (else exactly the deployments this exists for would drop the warning). A vuln with no fix
    stated (a known-unpatched one) is kept; an unparseable ceiling keeps everything (never over-drop)."""
    ceil = _parse_semver(released_ceiling)
    out = []
    for v in remote_vulns:
        if not isinstance(v, dict):
            continue
        fx = _parse_semver(v.get("fixed_in"))
        if fx is None or ceil is None or fx <= ceil:
            out.append(v)
    return out


def _earlier_date(a, b):
    """The earlier of two ISO (YYYY-MM-DD) date strings; whichever is present when only one is.
    ISO dates sort chronologically as strings. Add-only: support never ends LATER than either says."""
    present = [d for d in (a, b) if isinstance(d, str) and d]
    return min(present) if present else None


def _merge_support(local_s, remote_s):
    """Add-only merge of two `support` blocks: insecure if EITHER is insecure, eol if EITHER is eol,
    support-end the EARLIER. Never lets the remote CLEAR a local insecure/eol, and never sets secure
    (so no false secure:true)."""
    merged = dict(local_s or {})
    if local_s.get("secure") is False or remote_s.get("secure") is False:
        merged["secure"] = False
    if local_s.get("eol") is True or remote_s.get("eol") is True:
        merged["eol"] = True
    for key in ("code_support", "security_support"):
        d = _earlier_date(local_s.get(key), remote_s.get(key))
        if d is not None:
            merged[key] = d
    return merged


def _merge_vulnerabilities(local_vulns, remote_vulns):
    """Union of two vulnerability lists. Two entries are one finding when both name the same advisory
    id, or when either names none and their (title, fixed_in) agree -- the host tool's rule, pinned by
    a test that feeds both the same matrices. Local (bundled) entries are always kept; the remote can
    only ADD."""
    ids, pairs, out = set(), {}, []
    for v in list(local_vulns or []) + list(remote_vulns or []):
        if not isinstance(v, dict):
            continue
        slug = v.get("advisory") if isinstance(v.get("advisory"), str) and v.get("advisory") else None
        pair = (v.get("title"), v.get("fixed_in"))
        if slug is not None and slug in ids:
            continue
        if pair in pairs and (slug is None or pairs[pair] is None):
            continue
        if slug is not None:
            ids.add(slug)
        pairs.setdefault(pair, slug)
        out.append(v)
    return out


def _finding_key(v):
    """One vulnerability's identity: its advisory's id when it names one, else (title, fixed_in)."""
    slug = v.get("advisory")
    if isinstance(slug, str) and slug:
        return ("advisory", slug)
    return ("finding", v.get("title"), v.get("fixed_in"))


# --- release lines ----------------------------------------------------------------------------------
#
# A line is every release sharing major.minor. From 0.33 on, the matrix's top-level `lines` map says
# until when each line gets security fixes (null for the newest line). An install on an older line is
# told about the newest release of its own line -- a smaller move than the newest release overall --
# and when its line's fixes have ended. Main's copy is read add-only here too: a line it states is
# added, and where both copies state one, the earlier end wins. The host tool applies the same rules;
# a test feeds both the same matrices.

_DAY_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}")
_LINE_RE = re.compile(r"[0-9]+[.][0-9]+")


def _line_support_until(matrix, line):
    """(stated, until) for `line` in a matrix's `lines` map: until is a YYYY-MM-DD day, or None for
    the newest line. stated is False when the map does not state the line in that shape."""
    lines = matrix.get("lines") if isinstance(matrix, dict) else None
    entry = lines.get(line) if isinstance(lines, dict) and isinstance(line, str) else None
    if not isinstance(entry, dict) or "security_fixes_until" not in entry:
        return False, None
    until = entry["security_fixes_until"]
    if until is None:
        return True, None
    if isinstance(until, str) and _DAY_RE.fullmatch(until):
        return True, until
    return False, None


def _merge_lines(local_lines, main_lines):
    """Every line either copy states, mapped to its end; where both do, the earlier end (a day is
    earlier than none)."""
    merged = {}
    for source in (local_lines, main_lines):
        if not isinstance(source, dict):
            continue
        for line in source:
            stated, until = _line_support_until({"lines": source}, line)
            if not stated or not _LINE_RE.fullmatch(str(line)):
                continue
            if line in merged:
                until = _earlier_date(merged[line], until)
            merged[line] = until
    return merged


def _lines_of(matrix):
    return matrix.get("lines") if isinstance(matrix, dict) else None


def line_status(current_version, local_matrix, main_matrix, today=None):
    """{line, security_fixes_until, ended} for the running version's line, or None when neither copy
    states it. ended is True once the day has passed."""
    line = _release_line(current_version)
    merged = _merge_lines(_lines_of(local_matrix), _lines_of(main_matrix))
    if line is None or line not in merged:
        return None
    until = merged[line]
    today = today or time.strftime("%Y-%m-%d", time.gmtime())
    return {"line": line, "security_fixes_until": until, "ended": until is not None and until < today}


def _line_newest(main_matrix, current_version, latest):
    """The highest release main's copy declares on the running version's line, above it -- only when
    that line is not the newest release's line, whose update is the ordinary one. None otherwise."""
    line = _release_line(current_version)
    if line is None or line == _release_line(latest) or not isinstance(main_matrix, dict):
        return None
    versions = main_matrix.get("versions")
    if not isinstance(versions, dict):
        return None
    current = _parse_semver(current_version)
    above = [v for v in versions if isinstance(v, str) and _release_line(v) == line
             and _parse_semver(v) > current]
    return max(above, key=_parse_semver) if above else None


# At most this many older lines are asked about per round; SECURITY.md supports far fewer at once.
_MAX_OLDER_LINES = 5


def _older_line_releases(main_matrix, latest):
    """The newest release main's copy declares on each line its `lines` map lists, other than the
    newest release's line, newest line first and at most _MAX_OLDER_LINES of them. Read from main's
    copy alone, so the requests made for them are the same on every install."""
    if not isinstance(main_matrix, dict):
        return []
    lines = main_matrix.get("lines")
    versions = main_matrix.get("versions")
    if not isinstance(lines, dict) or not isinstance(versions, dict):
        return []
    newest = {}
    for version in versions:
        line = _release_line(version) if isinstance(version, str) else None
        if line is None or line not in lines or line == _release_line(latest):
            continue
        if line not in newest or _parse_semver(version) > _parse_semver(newest[line]):
            newest[line] = version
    ordered = sorted(newest.values(), key=_parse_semver, reverse=True)
    return ordered[:_MAX_OLDER_LINES]


def line_update(current_version, latest, local_matrix, main_matrix, line_matrices, today=None):
    """The newest release of the running version's line, when that is not the newest line:
    {version, line, fixes_vulnerability, security_fixes_until}, or None.

    Named by main's copy, and offered only when that release's own published matrix was fetched
    (`line_matrices`, by version) and declares it: that proves the tag exists, since main's copy
    alone is not trusted to say what was released. fixes_vulnerability is True when the running
    version has a vulnerability that release does not."""
    version = _line_newest(main_matrix, current_version, latest)
    line_matrix = line_matrices.get(version) if isinstance(line_matrices, dict) else None
    if version is None or not isinstance(line_matrix, dict):
        return None
    declared = line_matrix.get("versions")
    if not isinstance(declared, dict) or version not in declared:
        return None
    have = _merge_vulnerabilities(
        _version_findings(local_matrix, current_version),
        _credible_remote_vulns(_version_findings(main_matrix, current_version), latest))
    after = _merge_vulnerabilities(
        _version_findings(line_matrix, version),
        _credible_remote_vulns(_version_findings(main_matrix, version), latest))
    status = line_status(current_version, local_matrix, main_matrix, today)
    return {
        "version": _bound(version, cap=32),
        "line": _release_line(current_version),
        "fixes_vulnerability": bool({_finding_key(v) for v in have}
                                    - {_finding_key(v) for v in after}),
        "security_fixes_until": status["security_fixes_until"] if status else None,
    }


def _read_bundled_matrix():
    """The upgrade matrix shipped in THIS image (the offline copy), or None. Never raises."""
    import os
    here = os.path.dirname(os.path.abspath(__file__))
    for path in ("/app/docs/upgrade-matrix.json",
                 os.path.join(here, "..", "..", "docs", "upgrade-matrix.json")):
        try:
            with open(path, encoding="utf-8") as fh:
                data = json.load(fh)
            if isinstance(data, dict):
                return data
        except Exception:  # noqa: BLE001 — an unreadable/absent copy is just 'no bundled matrix'
            continue
    return None


def fetch_main_matrix(opener=None):
    """The lifecycle matrix on MAIN (fixed URL), or None. Bounded (timeout + size cap) and fail-safe:
    any error, oversized body, or wrong shape yields None so the caller uses the bundled copy. Never
    raises. TLS-to-GitHub-authenticated and nothing more, which is why the merge that consumes it is
    add-only (a compromised copy can only tighten, never clear or falsely secure)."""
    try:
        data = _http_json(MAIN_MATRIX_URL)
    except Exception:  # noqa: BLE001 — fail-closed-silent like the rest of this module
        return None
    if isinstance(data, dict) and isinstance(data.get("versions"), dict):
        return data
    return None


def _bound(value, cap=200):
    """Coerce an untrusted matrix scalar to a bounded str (or None). A fetched matrix can
    carry any JSON type (a huge string, a number, a nested object) in a title/fixed_in up to
    the body cap; str-coerce it and cap the length before it enters the block, so it cannot
    bloat the response or a render. None (a vulnerability with no fix stated) stays None."""
    return None if value is None else str(value)[:cap]


_UNSET = object()


def merged_security(current_version, released_ceiling, *, local_matrix=_UNSET, main_matrix=_UNSET, fetched_at=None):
    """The `security` block for `current_version`, merging the copy on main ADD-ONLY into the bundled
    copy. Returns {secure, vulnerabilities:[{title, fixed_in}], source, fetched_at}:
      * source 'main' when main's copy was available and merged, else 'bundled' (fail-safe);
      * secure is False when EITHER copy marks it insecure OR any vulnerability is listed; it is only
        True when nothing -- bundled or main -- says otherwise, so the merge never produces a false
        secure:true;
      * vulnerabilities are the union, each reduced to {title, fixed_in}, with a remote fix newer than
        `released_ceiling` (the newest release the consumer can see) dropped as not credible.
    `local_matrix`/`main_matrix` are injectable for tests; by default the bundled copy is read from
    the image and main is fetched here."""
    # A sentinel default distinguishes "not provided -> obtain it here" from an explicit None, which
    # means "unavailable" (an unreachable main, an unreadable bundled copy) and must be honoured, not
    # re-fetched -- so the caller can pass a cached/absent copy and get the fail-safe verdict.
    local_matrix = _read_bundled_matrix() if local_matrix is _UNSET else local_matrix
    if main_matrix is _UNSET:
        main_matrix = fetch_main_matrix()
    try:
        return _security_block(current_version, released_ceiling, local_matrix, main_matrix, fetched_at)
    except Exception:  # noqa: BLE001 -- a malformed remote entry must NEVER raise out of the status;
        # fall back to the bundled verdict, computed WITHOUT the merge path (which is what may have
        # thrown), so /api/update-status stays 200 while main serves a bad file.
        return _bundled_verdict(current_version, local_matrix)


def _bundled_verdict(current_version, local_matrix):
    """The security verdict from the BUNDLED copy alone, built without the merge path -- the fail-safe
    when merging an untrusted remote raises. source "bundled", fetched_at None; same three-valued
    secure rule (False on an insecure verdict/vulnerability, True when the bundled copy lists the
    version and nothing is wrong, None when it does not know it)."""
    local_s = _version_support(local_matrix, current_version)
    local_v = _version_vulnerabilities(local_matrix, current_version)
    if local_s.get("secure") is False or local_v:
        secure = False
    elif _knows_version(local_matrix, current_version):
        secure = True
    else:
        secure = None
    return {
        "secure": secure,
        "vulnerabilities": [{"title": _bound(v.get("title")), "fixed_in": _bound(v.get("fixed_in"))} for v in local_v],
        "source": "bundled",
        "fetched_at": None,
    }


def _security_block(current_version, released_ceiling, local_matrix, main_matrix, fetched_at):
    """The merge itself. Split out so merged_security can wrap it in the fetch's own fail-safe."""
    import time as _time
    source = "main" if main_matrix is not None else "bundled"

    local_s = _version_support(local_matrix, current_version)
    local_v = _version_findings(local_matrix, current_version)
    remote_s = _version_support(main_matrix, current_version)
    remote_v = _credible_remote_vulns(_version_findings(main_matrix, current_version),
                                      released_ceiling)

    support = _merge_support(local_s, remote_s)
    vulns = _merge_vulnerabilities(local_v, remote_v)
    # Three-valued: False on any explicit insecure verdict OR any listed vulnerability; True only when
    # at least one source actually KNOWS the version and nothing says otherwise; None when NEITHER
    # source knows it (reachable only as a failure state -- an unreadable bundled copy AND a silent
    # main). A positive with no evidence must never be asserted; the remote can add badness, never
    # remove it, so this is never a false secure. The SPA banner keys on `=== false`, so None hides.
    if support.get("secure") is False or vulns:
        secure = False
    elif _knows_version(local_matrix, current_version) or _knows_version(main_matrix, current_version):
        secure = True
    else:
        secure = None
    return {
        "secure": secure,
        "vulnerabilities": [{"title": _bound(v.get("title")), "fixed_in": _bound(v.get("fixed_in"))} for v in vulns],
        "source": source,
        # None when the verdict is the bundled copy: a failed or skipped fetch has no fetch
        # time, so it must not stamp one (a "bundled at <now>" would misread as fresh).
        "fetched_at": None if source == "bundled" else (fetched_at if fetched_at is not None else _time.time()),
    }
