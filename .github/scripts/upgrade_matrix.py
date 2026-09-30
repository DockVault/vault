"""Validate the declared upgrade matrix, and refuse a release that has not declared itself.

`docs/upgrade-matrix.json` says what it takes to move between released versions. Its value depends
entirely on being complete: a claim about upgrading is only worth something if every release is
obliged to make one. So the release workflow calls `assert_release_declared` and will not cut a tag
whose version is absent.

The one way past that is a `waivers` entry naming the version and the reason. It lives in the file
rather than in a command-line flag on purpose: a flag would have to be threaded through a
tag-triggered workflow to be reachable at all, and once passed it would leave no trace in anything
published, so a waived release would look exactly like a declared one. In the file, the omission is
part of the release commit, part of the diff, and part of the published asset -- and it becomes a
validation error once the version is properly declared, so the hatch cannot drift into being the
normal route.

Validation is deliberately strict and rejects unknown keys at every level. The file is committed to
this repository and so is trusted in origin, but it is also published as a release asset and read by
things outside it; a validator that silently ignores a misspelt key would let a typo'd condition
disappear from the operator-facing side while still passing here.

Stdlib only, like the rest of the release scripts.
"""

from __future__ import annotations

import calendar
import datetime
import importlib.util
import json
import re
import sys
from pathlib import Path


def _load_cvss4():
    """The sibling CVSS v4.0 scorer, loaded by path.

    This module is itself loaded by path (by the release gate and by the tests), so the scripts
    directory is not on sys.path and a plain `import cvss4` would not resolve. Resolving relative to
    `__file__` works however this module was reached.
    """
    name = "dockvault_cvss4"
    if name in sys.modules:
        return sys.modules[name]
    path = Path(__file__).resolve().parent / "cvss4.py"
    spec = importlib.util.spec_from_file_location(name, path)
    if spec is None or spec.loader is None:  # pragma: no cover - a broken checkout
        raise ImportError(f"cannot load the CVSS v4.0 scorer at {path}")
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


cvss4 = _load_cvss4()

# The validator's cap stays below what every reader in a supported release (0.17.0 and later)
# accepts, so a file the release gate passes is one that every reader will read. Those limits:
# - the running app's update check (app/services/update_check.py): 512 KiB, in every supported
#   release;
# - dockvault.py: main's lifecycle copy at 512 KiB since 0.30.0 (before it, there was no main copy
#   to read), and a release's own copy, fetched by its tag, read whole in every release;
# - the documentation site, which reads main's copy at request time: 512 KiB.
# A reader handed a larger file falls back silently and loses every advisory with it, so the cap
# keeps a 64 KiB margin below the smallest of them, and the test's warning line (three quarters of
# this cap) comes well before the cap itself. 256 KiB until 0.33.0, whose eight advisories took the
# file to about 284 KB. That is still small enough that a runaway or hostile file cannot make the
# parser the problem.
MAX_BYTES = 448 * 1024
# 2 adds a required per-version `support` block (lifecycle: end-of-life, security posture, and
# optional extended-support end dates). A schema_version-1 file has no such block and would leave
# every version's lifecycle undeclared, so the bump is not backward-compatible on purpose.
# 3 moves each vulnerability into a top-level `advisories` record -- stated once, with its impact,
# remediation, optional mitigation and a CVSS v4.0 vector -- and leaves each affected version a
# reference to it. Copying the full record onto every affected version grew the file by a whole
# record per affected release, per release, and let two copies of one finding disagree.
SUPPORTED_SCHEMA_VERSION = 3

_UTF8_BOM = b"\xef\xbb\xbf"
# No leading zeros: "0.10.00" and "0.10.0" would be two keys for one release, and the second would
# never match a tag.
_VERSION_RE = re.compile(r"(?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2}", re.ASCII)
_ID_RE = re.compile(r"[a-z0-9]+(?:-[a-z0-9]+)*", re.ASCII)
_DATE_RE = re.compile(r"[0-9]{4}-[0-9]{2}-[0-9]{2}", re.ASCII)

KINDS = ("direct", "blocked")

_VERSION_KEYS = {"released", "notes", "must_land_here", "support", "vulnerabilities"}
# A version's lifecycle. `eol`/`secure` are always required so no release ships with its status
# unstated. `code_support`/`security_support` are the extended-support end dates -- features/bug
# fixes and security fixes can end on different days (the common security-only tail), and either may
# be absent. They describe support GIVEN PAST end-of-life, so they are only meaningful on an EOL
# version.
_SUPPORT_KEYS = {"eol", "secure", "code_support", "security_support"}
# A version's list of the advisories that affect it. Each entry names its advisory and repeats the
# advisory's `title` and `fixed_in` verbatim: those two fields are what every reader that predates
# advisories shows (the host tool's older copies and the running app read a version's list and
# nothing else), so the repetition is what keeps them informed. They must match the advisory exactly.
_VULN_KEYS = {"advisory", "title", "fixed_in"}
# Below this version a reference may carry only its advisory's id ({"advisory": "<slug>"}); the
# readers of 0.33.0 and later, and the documentation site, take the title and fix from the advisory.
# The boundary is where the older readers' list of releases stops. The host tool of 0.30.0 to
# 0.32.x merges main's copy of this file into every version it knows, and prints a line for each of
# the 15 newest releases that are not end-of-life, counting what each reference's own `title` and
# `fixed_in` say: an id-only reference in that window would read as "no fix released yet". That
# window reaches 0.27.0 today and only moves up as releases are added, so references on 0.27.0 and
# later keep both fields. Below it that tool still reads a short reference for a release asked for
# by name, or for the release a container runs; tests/test_upgrade_matrix_older_readers.py states
# what it then shows.
ID_ONLY_REFERENCES_BELOW = "0.27.0"
# One record per vulnerability. title, description, impact and remediation carry the meaning and are
# always stated. The ratings are required keys that may be null, so an unrated finding says so rather
# than omitting the field: `cvss` is a CVSS v4.0 base vector and `severity` the band it scores to
# (derived and checked, never chosen). `mitigation` is what an operator can do before, or instead of,
# upgrading; it is required when there is no fix.
_ADVISORY_KEYS = {"title", "description", "impact", "remediation", "mitigation",
                  "severity", "cvss", "id", "fixed_in", "published"}
# Optional. Once two release lines are supported, one vulnerability can be fixed in a release of
# each: `fixed_in_lines` lists those releases, one per line, lowest first, and `fixed_in` stays the
# lowest of them, because every deployed reader expects a single value there. Missing, it means
# [fixed_in]. Which versions the advisory affects then follows from the lines (see `_affected`), and
# each version's reference names the fix for its own line (see `_fix_for`), which is what the
# readers that predate this field print.
_ADVISORY_OPTIONAL_KEYS = {"fixed_in_lines"}
_SEVERITIES = ("low", "medium", "high", "critical")
# The secure/vulnerabilities consistency below is enforced only from this version on. Releases before
# it predate the vulnerability-list feature; the owner's decision is to leave their (end-of-life)
# status as a bare secure:false without itemising it.
_VULN_LISTED_FROM = "0.28.0"
_EDGE_KEYS = {"from", "to", "kind", "reversible", "requires_backup", "reason", "conditions"}
# A condition is something to know before an upgrade, with an optional `detect` query that finds
# whether it applies to a deployment. `blocks_rollback: true` marks one that, once its query finds
# rows, stops the upgraded deployment going back across this edge: the older version cannot read
# what the newer one wrote until that state is undone with the newer version. A host tool that reads
# the flag refuses the rollback while the query finds rows; one that predates it ignores the key. The
# flag informs; what stops an older image from starting on such data is the database's own record of
# the version it needs, which the image reads at startup whatever tool is used.
_CONDITION_KEYS = {"id", "summary", "detect", "blocks_rollback"}
_WAIVER_KEYS = {"version", "reason"}
_TOP_KEYS = {"schema_version", "about", "kinds", "advisories", "versions", "edges", "waivers",
             "lines"}
# The optional top-level `lines` map says until when each release line receives security fixes:
# {"0.33": {"security_fixes_until": "2027-06-26"}, "0.34": {"security_fixes_until": null}}. It is
# separate from a version's `eol`, which marks the releases an install can no longer move to or from.
# Lines start at 0.33, the first with a support period (.github/SECURITY.md); older lines are
# unsupported by definition and are not listed. The newest line's date is null, as its end is not
# known until the next minor ships; every other listed line has a date at least SUPPORT_MONTHS after
# the next line's first release, which is the published promise, checked here.
_FIRST_SUPPORTED_LINE = "0.33"
SUPPORT_MONTHS = 6
_LINE_RE = re.compile(r"(?:0|[1-9][0-9]*)\.(?:0|[1-9][0-9]*)", re.ASCII)
_LINE_KEYS = {"security_fixes_until"}


class UpgradeMatrixError(ValueError):
    """The upgrade matrix does not satisfy its contract."""


def _sort_key(version: str) -> tuple[int, int, int]:
    return tuple(int(part) for part in version.split("."))


def _line(version: str) -> str:
    """The release line a version belongs to: 0.33 for 0.33.2."""
    return version.rsplit(".", 1)[0]


def _fixes(advisory: dict) -> list[str]:
    """Every release that fixes the advisory, lowest first; [] when nothing fixes it yet."""
    if advisory.get("fixed_in") is None:
        return []
    return list(advisory.get("fixed_in_lines") or [advisory["fixed_in"]])


def _fix_for(version: str, fixes: list[str]) -> str | None:
    """The fix a reference on `version` names: its own line's, else the lowest fix above it.

    None when neither exists: `version` is then not affected, or the advisory is not fixed yet.
    """
    for fix in fixes:
        if _line(fix) == _line(version):
            return fix
    above = [fix for fix in fixes if _sort_key(fix) > _sort_key(version)]
    return min(above, key=_sort_key) if above else None


def _affected(version: str, first: str, fixes: list[str]) -> bool:
    """Whether an advisory first listed on `first`, with these fixes, affects `version`.

    Nothing below the first affected release is affected. A version whose line has a fix is affected
    until that fix. A version on a line with no fix is affected when it is below the highest fix:
    an older or unsupported line that never got one. Above every fix, on a line with no fix, it is
    not affected; `_validate_advisory_coverage` checks that such a line started after the fix.
    With no fix at all, every release from the first on is affected.
    """
    if _sort_key(version) < _sort_key(first):
        return False
    if not fixes:
        return True
    for fix in fixes:
        if _line(fix) == _line(version):
            return _sort_key(version) < _sort_key(fix)
    return _sort_key(version) < _sort_key(max(fixes, key=_sort_key))


def _inbound_edge(data: dict, version: str) -> dict | None:
    """The edge into `version` from its version-order predecessor, or None.

    None means either the version is the earliest declared one (nothing leads in) or no edge was
    declared for that adjacent pair. Used both to require a takeable route into a release and to
    tell a deliberately-unreachable floor release (a blocked route in) from a version a waiver has
    no business covering.
    """
    versions = data.get("versions", {})
    if version not in versions:
        return None
    ordered = sorted(versions, key=_sort_key)
    index = ordered.index(version)
    if index == 0:
        return None
    previous = ordered[index - 1]
    return {(edge["from"], edge["to"]): edge
            for edge in data.get("edges", [])}.get((previous, version))


def _require(condition: bool, message: str) -> None:
    if not condition:
        raise UpgradeMatrixError(message)


def _string(value: object, where: str, *, pattern: re.Pattern[str] | None = None) -> str:
    _require(isinstance(value, str), f"{where} must be a string")
    text = value  # type: ignore[assignment]
    _require(bool(text.strip()), f"{where} must not be empty")
    if pattern is not None:
        _require(pattern.fullmatch(text) is not None, f"{where} is malformed: {text!r}")
    return text


def _printable_string(value: object, where: str) -> str:
    """A non-empty string carrying no control or otherwise non-printable characters.

    The matrix is published as a release asset and the host tool prints these strings RAW on an
    operator's terminal. A title or description carrying an escape sequence -- a colour code, a cursor
    move, a screen-clear -- would execute there. The runtime tool strips such sequences defensively
    from a fetched asset; rejecting them here keeps them out of the committed file in the first place.
    `str.isprintable()` is the yardstick: it counts a plain space as printable and treats the C0/C1
    controls (ESC included), line separators, and the other control/format categories as not.
    """
    text = _string(value, where)
    bad = sorted({ch for ch in text if not ch.isprintable()})
    _require(not bad, f"{where} contains non-printable character(s): "
                      + ", ".join(hex(ord(ch)) for ch in bad))
    return text


def _no_unknown_keys(mapping: dict, allowed: set[str], where: str) -> None:
    unknown = sorted(set(mapping) - allowed)
    _require(not unknown, f"{where} has unknown key(s): {', '.join(unknown)}")


def _no_duplicate_keys(pairs):
    """Reject a duplicated key instead of letting the last one win.

    `json.loads` keeps the last of a repeated key and says nothing. In a file that is read by a
    human in review and by a machine at release time, that is a silent disagreement: the reviewer
    reads the block that lost.
    """
    seen = set()
    for key, _ in pairs:
        if key in seen:
            raise UpgradeMatrixError(f"upgrade matrix repeats the key {key!r}")
        seen.add(key)
    return dict(pairs)


def _validate_support(support: object, where: str) -> None:
    """A version's lifecycle block, required on every version.

    `eol` and `secure` are booleans that must be present, so no release ships with its end-of-life
    or security status left unstated. `code_support` and `security_support` are optional
    extended-support END DATES: after end-of-life a version may still receive feature/bug fixes for
    a while (code) and security fixes for longer (the common security-only tail). They describe
    support given PAST end-of-life, so they are meaningful only when `eol` is true, and security
    support may not end before code support.
    """
    _require(isinstance(support, dict), f"{where}.support must be present and an object")
    _no_unknown_keys(support, _SUPPORT_KEYS, f"{where}.support")
    for flag in ("eol", "secure"):
        _require(isinstance(support.get(flag), bool),
                 f"{where}.support.{flag} must be present and a boolean")
    dates: dict[str, str] = {}
    for field in ("code_support", "security_support"):
        if field in support:
            _require(support["eol"] is True,
                     f"{where}.support.{field} is extended support and is only meaningful once "
                     "eol is true")
            # Lexical order of an ISO date is chronological order, so a plain string compare below
            # is a date compare.
            dates[field] = _string(support[field], f"{where}.support.{field}", pattern=_DATE_RE)
    if "code_support" in dates and "security_support" in dates:
        _require(dates["security_support"] >= dates["code_support"],
                 f"{where}.support.security_support must not end before code_support")


def _validate_advisories(data: dict, versions: dict, released_ceiling: str | None) -> dict:
    """The top-level `advisories` records: one per vulnerability, keyed by a stable slug.

    This is a public repository, so publishing a vulnerability is publishing it to an attacker. The
    rule that keeps the list safe: an advisory names the release that fixes it, and that release must
    exist. `released_ceiling`, when supplied, is the newest RELEASED version -- on a push to main the
    VERSION file, which the release commit bumps; at release time the version being cut. A `fixed_in`
    above it names a fix nobody can install yet, which would turn the advisory into the unpatched
    disclosure the rule exists to prevent. Declared-and-later alone does not catch this: a phantom
    version can be declared to bridge the adjacency chain, and phantoms are only rejected in the
    release gate. Left None (e.g. validating a published asset with no VERSION at hand) the ceiling is
    not enforced and every other rule still holds.

    The one deliberate exception is an advisory with no fix yet (`fixed_in` null). It is allowed only
    with a `mitigation`: an unfixed issue is published when operators must act before the fix exists,
    and then the entry exists to tell them what to do. An unfixed advisory that gives them nothing to
    do would help an attacker and nobody else.

    `severity` is never chosen by hand. When `cvss` carries a CVSS v4.0 base vector, `severity` must be
    the band that vector scores to, recomputed here, so the two cannot drift apart; when `cvss` is
    null the advisory is unrated and `severity` is null too. A vector that scores 0.0 describes no
    impact at all, which is not a vulnerability. title, description, impact, remediation and
    mitigation are printed raw by the host tool and must be printable (see `_printable_string`).
    """
    advisories = data.get("advisories")
    _require(isinstance(advisories, dict),
             "upgrade matrix needs an 'advisories' object (empty when nothing is known)")
    for slug, advisory in advisories.items():
        _string(slug, "advisory key", pattern=_ID_RE)
        where = f"advisories[{slug}]"
        _require(isinstance(advisory, dict), f"{where} must be an object")
        _no_unknown_keys(advisory, _ADVISORY_KEYS | _ADVISORY_OPTIONAL_KEYS, where)
        missing = sorted(_ADVISORY_KEYS - set(advisory))
        _require(not missing, f"{where} is missing required key(s): {', '.join(missing)}")
        for field in ("title", "description", "impact", "remediation"):
            _printable_string(advisory[field], f"{where}.{field}")
        mitigation = advisory["mitigation"]
        if mitigation is not None:
            _printable_string(mitigation, f"{where}.mitigation")
        if advisory["id"] is not None:
            _printable_string(advisory["id"], f"{where}.id")
        _string(advisory["published"], f"{where}.published", pattern=_DATE_RE)

        vector, severity = advisory["cvss"], advisory["severity"]
        if vector is None:
            _require(severity is None,
                     f"{where}.severity is {severity!r} with no cvss vector; the band is derived from "
                     "the vector, so an unrated advisory leaves both null")
        else:
            try:
                score = cvss4.base_score(vector)
            except cvss4.CvssError as exc:
                raise UpgradeMatrixError(f"{where}.cvss: {exc}") from exc
            band = cvss4.severity_band(score)
            _require(band != "none",
                     f"{where}.cvss scores 0.0: a vector with no impact on anything describes no "
                     "vulnerability")
            _require(severity == band,
                     f"{where}.severity must be the band its cvss vector scores to: the vector scores "
                     f"{score} ({band}), got {severity!r}")

        fixed_in = advisory["fixed_in"]
        if fixed_in is None:
            _require(mitigation is not None,
                     f"{where} has no fix (fixed_in null) and no mitigation; an unfixed issue is "
                     "published only when there is something operators can do before the fix exists")
        else:
            _string(fixed_in, f"{where}.fixed_in", pattern=_VERSION_RE)
            _require(fixed_in in versions, f"{where}.fixed_in is not a declared version: {fixed_in}")
            if released_ceiling is not None:
                _require(_sort_key(fixed_in) <= _sort_key(released_ceiling),
                         f"{where} names {fixed_in} as the fix but the newest released version is "
                         f"{released_ceiling}; an unreleased fix is an unpatched disclosure")
        if "fixed_in_lines" in advisory:
            _validate_fixed_in_lines(advisory, versions, released_ceiling, where)
    return advisories


def _validate_fixed_in_lines(advisory: dict, versions: dict, released_ceiling: str | None,
                             where: str) -> None:
    """An advisory's fixes on several release lines: one per line, lowest first, each released."""
    fixes = advisory["fixed_in_lines"]
    spot = f"{where}.fixed_in_lines"
    _require(advisory["fixed_in"] is not None,
             f"{spot} lists fixes, but fixed_in is null; an advisory fixed nowhere has no fixes")
    _require(isinstance(fixes, list) and fixes, f"{spot} must be a non-empty list")
    for position, fix in enumerate(fixes):
        _string(fix, f"{spot}[{position}]", pattern=_VERSION_RE)
        _require(fix in versions, f"{spot}[{position}] is not a declared version: {fix}")
        if released_ceiling is not None:
            _require(_sort_key(fix) <= _sort_key(released_ceiling),
                     f"{spot} names {fix} as a fix but the newest released version is "
                     f"{released_ceiling}; an unreleased fix is an unpatched disclosure")
    lines = [_line(fix) for fix in fixes]
    repeated = sorted({line for line in lines if lines.count(line) > 1})
    _require(not repeated, f"{spot} names more than one fix on the {', '.join(repeated)} line; "
                           "a line is fixed once, by its first release that contains the fix")
    _require(fixes == sorted(fixes, key=_sort_key), f"{spot} must be in version order")
    _require(advisory["fixed_in"] == fixes[0],
             f"{where}.fixed_in must be the lowest of fixed_in_lines, {fixes[0]} (got "
             f"{advisory['fixed_in']}); it is the one fix every reader can read")


def _validate_vulnerabilities(meta: dict, version: str, advisories: dict, where: str) -> None:
    """A version's optional list of references to the advisories that affect it.

    Each entry names an advisory and repeats its `title` and `fixed_in` exactly (see `_VULN_KEYS`).
    Below ID_ONLY_REFERENCES_BELOW an entry may instead carry the advisory's id alone. A version
    cannot be affected by an advisory fixed in it or before it, and lists each advisory once.
    """
    vulns = meta.get("vulnerabilities")
    if vulns is None:
        return
    _require(isinstance(vulns, list), f"{where}.vulnerabilities must be a list")
    id_only_allowed = _sort_key(version) < _sort_key(ID_ONLY_REFERENCES_BELOW)
    seen: set[str] = set()
    for position, ref in enumerate(vulns):
        spot = f"{where}.vulnerabilities[{position}]"
        _require(isinstance(ref, dict), f"{spot} must be an object")
        _no_unknown_keys(ref, _VULN_KEYS, spot)
        id_only = id_only_allowed and set(ref) == {"advisory"}
        missing = sorted(_VULN_KEYS - set(ref))
        _require(id_only or not missing,
                 f"{spot} is missing required key(s): {', '.join(missing)}"
                 + (f"; from {ID_ONLY_REFERENCES_BELOW} on a reference repeats its advisory's "
                    "title and fixed_in for the host tools of 0.30.0 to 0.32.x"
                    if set(ref) == {"advisory"} else ""))
        slug = _string(ref["advisory"], f"{spot}.advisory", pattern=_ID_RE)
        _require(slug in advisories, f"{spot}.advisory names {slug}, which 'advisories' does not declare")
        _require(slug not in seen, f"{spot} lists advisory {slug} a second time")
        seen.add(slug)
        advisory = advisories[slug]
        fixes = _fixes(advisory)
        fix = _fix_for(version, fixes)
        if fixes:
            _require(fix is not None,
                     f"{spot} names advisory {slug}, fixed in {' and '.join(fixes)}; {version} is "
                     "above every fix, on a line that has none, so it is not affected")
            _require(_sort_key(fix) > _sort_key(version),
                     f"{spot} names advisory {slug}, fixed_in ({fix}), which must be a version "
                     f"later than {version}; a release cannot be affected by an issue fixed in it or "
                     "an earlier one")
        if id_only:
            # Every reader that takes a short reference's fix from its advisory reads `fixed_in`.
            _require(fix == advisory["fixed_in"],
                     f"{spot} carries only the advisory id, but the fix for {version} is {fix}, "
                     f"not the advisory's fixed_in {advisory['fixed_in']}; write it in full")
            continue
        _require(ref["title"] == advisory["title"],
                 f"{spot}.title must repeat advisories[{slug}].title exactly; it is what a "
                 f"reader that predates advisories shows (got {ref['title']!r}, "
                 f"expected {advisory['title']!r})")
        if "fixed_in_lines" in advisory:
            _require(ref["fixed_in"] == fix,
                     f"{spot}.fixed_in must name the fix on the {_line(version)} line, or the lowest "
                     f"fix above {version}: {fix} (got {ref['fixed_in']!r}); it is the release a "
                     "reader that predates fixed_in_lines tells this version to move to")
        else:
            _require(ref["fixed_in"] == advisory["fixed_in"],
                     f"{spot}.fixed_in must repeat advisories[{slug}].fixed_in exactly; it is what a "
                     f"reader that predates advisories shows (got {ref['fixed_in']!r}, "
                     f"expected {advisory['fixed_in']!r})")


def _validate_advisory_coverage(advisories: dict, versions: dict) -> None:
    """Every advisory affects an unbroken run of releases, from the first that lists it up to its fix.

    An issue present in 0.10.0 and in 0.12.0 was present in 0.11.0. A gap is a release someone forgot
    to mark, and the operator running it would be told nothing. An unfixed advisory runs to the newest
    declared release. An advisory nothing references describes no release at all.
    """
    ordered = sorted(versions, key=_sort_key)
    affected: dict[str, list[str]] = {slug: [] for slug in advisories}
    for version in ordered:
        for ref in versions[version].get("vulnerabilities") or []:
            affected[ref["advisory"]].append(version)
    for slug, advisory in advisories.items():
        where = f"advisories[{slug}]"
        listed = affected[slug]
        _require(bool(listed), f"{where} is listed by no version; an advisory affects at least one release")
        first, fixes = listed[0], _fixes(advisory)
        expected = [v for v in ordered if _affected(v, first, fixes)]
        gaps = [v for v in expected if v not in listed]
        _require(not gaps,
                 f"{where} affects {first} and is fixed in {' and '.join(fixes) or 'no release yet'}, "
                 f"so every release in between is affected too; not listed on: {', '.join(gaps)}")
        if not fixes:
            continue
        # Above every fix, a line with no fix of its own is unaffected only if it began after the
        # highest fix was released, and so contains it. A line that began earlier (0.34.0 released
        # before the fix in 0.33.2) was forked without the fix: it needs its own, or its X.Y.0 when
        # it was never affected. So the newest line is always fixed, never left out.
        highest = max(fixes, key=_sort_key)
        fixed_lines = {_line(fix) for fix in fixes}
        later_lines = {_line(v) for v in ordered if _sort_key(v) > _sort_key(highest)}
        for line in sorted(later_lines - fixed_lines, key=lambda name: _sort_key(name + ".0")):
            start = min((v for v in ordered if _line(v) == line), key=_sort_key)
            _require(versions[start]["released"] >= versions[highest]["released"],
                     f"{where} is fixed in {' and '.join(fixes)}, but the {line} line began with "
                     f"{start} on {versions[start]['released']}, before {highest} was released; "
                     f"name the {line} line's own fix in fixed_in_lines, or {line}.0 if it was never "
                     "affected")


def _validate_routes(edges: list, versions: dict) -> None:
    """What the edges must allow together, once releases come from more than one line.

    - Every edge leads from an older release to a newer one: edges describe upgrades, and a
      downgrade is read off them in reverse.
    - Every release that is not end-of-life reaches the newest release by edges that are not
      blocked. A release of an older line made after the next line began has no newer neighbour on
      its own line, so it needs an edge of its own into the next line.
    - No edge brings back a vulnerability: an edge from `a` to `b` is refused when `b` is affected by
      an advisory that already affected `a` or a release below it, and `a` is not affected.
    - A step is an edge to the next release of the same line, or into the first release of the next
      line. Any other edge skips releases, and the readers take the shortest route, so it replaces
      the route of steps it jumps over: the shortest route of steps that are not blocked from `a`,
      or, where the line was left from below `a`, from the highest lower release of `a`'s line that
      has one (0.33.2 -> 0.34.1 replaces 0.33.1 -> 0.34.0 -> 0.34.1). It must be at least as
      cautious as that route: it requires a backup if any step does, is irreversible if any step
      is, carries every step's conditions, and passes no release an upgrade must land on
      (`must_land_here`). A skip with no such route, because a step it jumps is blocked or missing,
      is refused.
    """
    ordered = sorted(versions, key=_sort_key)
    lines: list[str] = []
    for version in ordered:
        if _line(version) not in lines:
            lines.append(_line(version))
    in_line = {line: [v for v in ordered if _line(v) == line] for line in lines}
    takeable = [edge for edge in edges if edge["kind"] != "blocked"]

    for index, edge in enumerate(edges):
        _require(_sort_key(edge["from"]) < _sort_key(edge["to"]),
                 f"edges[{index}] goes from {edge['from']} down to {edge['to']}; an edge describes an "
                 "upgrade, and a downgrade is read off it in reverse")

    newest = ordered[-1]
    forward: dict[str, set[str]] = {}
    for edge in takeable:
        forward.setdefault(edge["from"], set()).add(edge["to"])
    reaches = {newest}
    for version in reversed(ordered):               # every edge leads upwards, so one pass is enough
        if forward.get(version, set()) & reaches:
            reaches.add(version)
    stranded = [v for v in ordered if v not in reaches and not versions[v]["support"]["eol"]]
    _require(not stranded,
             f"{', '.join(stranded)} cannot reach {newest} by edges that are not blocked; a release "
             "that is not end-of-life needs a way to the newest one (a release of an older line needs "
             "an edge of its own into the next line)")

    listed = {v: {ref["advisory"] for ref in versions[v].get("vulnerabilities") or []}
              for v in ordered}
    first: dict[str, str] = {}
    for version in ordered:
        for slug in listed[version]:
            first.setdefault(slug, version)
    for edge in takeable:
        source, target = edge["from"], edge["to"]
        back = sorted(slug for slug in listed[target] - listed[source]
                      if _sort_key(first[slug]) <= _sort_key(source))
        _require(not back,
                 f"the edge {source} -> {target} brings back {', '.join(back)}: {target} is affected "
                 f"and {source} is not; an upgrade must not reinstate a fixed vulnerability")

    def is_step(edge: dict) -> bool:
        source, target = edge["from"], edge["to"]
        if _line(source) == _line(target):
            same = in_line[_line(source)]
            return same.index(target) == same.index(source) + 1
        return (target == in_line[_line(target)][0]
                and lines.index(_line(target)) == lines.index(_line(source)) + 1)

    steps: dict[str, list[dict]] = {}
    for edge in takeable:
        if is_step(edge):
            steps.setdefault(edge["from"], []).append(edge)
    for outgoing in steps.values():
        outgoing.sort(key=lambda e: _sort_key(e["to"]))

    def route_of_steps(source: str, target: str) -> list[dict] | None:
        # Breadth-first, as the readers walk; `source` first, then each lower release of its line,
        # so the route leaves the line from the highest release that can.
        starts = [v for v in reversed(in_line[_line(source)]) if _sort_key(v) <= _sort_key(source)]
        queue: list[tuple[str, list[dict]]] = [(v, []) for v in starts]
        seen = set(starts)
        while queue:
            node, path = queue.pop(0)
            if node == target:
                return path
            for step in steps.get(node, []):
                if step["to"] not in seen:
                    seen.add(step["to"])
                    queue.append((step["to"], path + [step]))
        return None

    for edge in takeable:
        if is_step(edge):
            continue
        source, target = edge["from"], edge["to"]
        where = f"the edge {source} -> {target}"
        route = route_of_steps(source, target)
        _require(route is not None,
                 f"{where} skips releases, but no route of steps that are not blocked leads from "
                 f"{source}, or a lower release of its line, to {target}; there is no route for it "
                 "to replace")
        described = " -> ".join([route[0]["from"]] + [step["to"] for step in route])
        for step in route[:-1]:
            _require(not versions[step["to"]].get("must_land_here"),
                     f"{where} passes {step['to']}, where an upgrade must land (must_land_here); the "
                     f"route it replaces is {described}")
        if any(step["requires_backup"] for step in route):
            _require(edge["requires_backup"],
                     f"{where} must require a backup: the route it replaces, {described}, does")
        if not all(step["reversible"] for step in route):
            _require(not edge["reversible"],
                     f"{where} cannot be reversible: the route it replaces, {described}, is not")
        have = {condition["id"] for condition in edge.get("conditions", [])}
        left_out = [cid for cid in dict.fromkeys(condition["id"] for step in route
                                                 for condition in step.get("conditions", []))
                    if cid not in have]
        _require(not left_out,
                 f"{where} leaves out the condition(s) {', '.join(left_out)} of the route it "
                 f"replaces, {described}")


def _add_months(day: datetime.date, months: int) -> datetime.date:
    """The same day `months` calendar months later, or the month's last day when it has no such day."""
    year, month = divmod(day.month - 1 + months, 12)
    year += day.year
    month += 1
    return day.replace(year=year, month=month, day=min(day.day, calendar.monthrange(year, month)[1]))


def _validate_lines(lines: object, versions: dict, advisories: dict) -> None:
    """The support period of each release line, and what it means for an unfixed advisory.

    Every line from the first listed one up to the newest declared line is listed. Only the newest
    has no date. Every other date is at least SUPPORT_MONTHS after the next line's first release,
    the promise .github/SECURITY.md makes. And an advisory that leaves the newest release of a line
    affected while that line was still supported (on the advisory's `published` date) must say what
    to do meanwhile: a supported line is expected to be fixed, and when it is not, the mitigation is
    all its operators have.
    """
    _require(isinstance(lines, dict) and lines, "upgrade matrix 'lines' must be a non-empty object")
    by_line: dict[str, list[str]] = {}
    for version in versions:
        by_line.setdefault(_line(version), []).append(version)
    declared = sorted(by_line, key=lambda name: _sort_key(name + ".0"))
    newest = declared[-1]
    until: dict[str, str | None] = {}
    for line, entry in lines.items():
        where = f"lines[{line}]"
        _string(line, "line key", pattern=_LINE_RE)
        _require(_sort_key(line + ".0") >= _sort_key(_FIRST_SUPPORTED_LINE + ".0"),
                 f"{where}: lines start at {_FIRST_SUPPORTED_LINE}, the first with a support period; "
                 "an older line is unsupported by definition")
        _require(line in by_line, f"{where} names a line with no declared release")
        _require(isinstance(entry, dict), f"{where} must be an object")
        _no_unknown_keys(entry, _LINE_KEYS, where)
        _require("security_fixes_until" in entry, f"{where} is missing required key(s): "
                                                   "security_fixes_until")
        date = entry["security_fixes_until"]
        if date is None:
            _require(line == newest,
                     f"{where}.security_fixes_until is null, but only the newest line, {newest}, has "
                     "no end date; the support of every earlier line ends on a stated day")
        else:
            _string(date, f"{where}.security_fixes_until", pattern=_DATE_RE)
            _require(line != newest,
                     f"{where}.security_fixes_until is {date}, but {line} is the newest line; its "
                     "support ends six months after the next minor release, which has not shipped")
        until[line] = date
    first_listed = min(until, key=lambda name: _sort_key(name + ".0"))
    missing = [line for line in declared
               if _sort_key(line + ".0") >= _sort_key(first_listed + ".0") and line not in until]
    _require(not missing, f"upgrade matrix 'lines' does not list {', '.join(missing)}; every line "
                          f"from {first_listed} on states its support period")
    for line, date in until.items():
        if date is None:
            continue
        successor = declared[declared.index(line) + 1]
        start = min(by_line[successor], key=_sort_key)
        released = versions[start]["released"]
        try:
            promised = _add_months(datetime.date.fromisoformat(released), SUPPORT_MONTHS)
            ends = datetime.date.fromisoformat(date)
        except ValueError as exc:
            raise UpgradeMatrixError(f"lines[{line}]: {exc}") from exc
        _require(ends >= promised,
                 f"lines[{line}].security_fixes_until is {date}, but {start} was released on "
                 f"{released}, so the promise of {SUPPORT_MONTHS} months after the next minor "
                 f"release runs to {promised.isoformat()}")

    for slug, advisory in advisories.items():
        if advisory["mitigation"] is not None:
            continue
        for line, date in until.items():
            if date is not None and date < advisory["published"]:
                continue                           # support had ended when it was published
            last = max(by_line[line], key=_sort_key)
            listed = {ref.get("advisory") for ref in versions[last].get("vulnerabilities") or []}
            _require(slug not in listed,
                     f"advisories[{slug}] leaves {last}, the newest release of the {line} line, "
                     f"affected while that line is supported, and has no mitigation; fix it on that "
                     "line or say what operators can do meanwhile")


def load_matrix(path: Path) -> dict:
    """Read and parse the matrix, refusing anything that is not plainly a UTF-8 JSON object."""
    # A symlink would let the file the gate validates differ from the file the release publishes,
    # which is the one property the copy-verbatim step exists to guarantee.
    if path.is_symlink() or (path.exists() and not path.is_file()):
        raise UpgradeMatrixError(f"the upgrade matrix must be a regular file, not {path}")
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise UpgradeMatrixError(f"cannot read the upgrade matrix: {exc}") from exc
    _require(len(raw) <= MAX_BYTES, f"upgrade matrix is larger than {MAX_BYTES} bytes")
    _require(not raw.startswith(_UTF8_BOM), "upgrade matrix must not contain a UTF-8 BOM")
    try:
        data = json.loads(raw.decode("utf-8", errors="strict"),
                          object_pairs_hook=_no_duplicate_keys)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise UpgradeMatrixError(f"upgrade matrix is not valid UTF-8 JSON: {exc}") from exc
    _require(isinstance(data, dict), "upgrade matrix must be a JSON object")
    return data


def validate_matrix(data: dict, *, released_ceiling: str | None) -> dict:
    """Check the whole file. Returns it unchanged so callers can chain.

    `released_ceiling` is the newest released version, against which a vulnerability's `fixed_in` is
    bounded so an unreleased fix cannot be listed (see `_validate_vulnerabilities`). Callers supply it
    from the VERSION file (on main) or the newest of the released tags and the version being cut (at
    release time). It is KEYWORD-ONLY WITH NO DEFAULT on purpose: a bare call is a TypeError, so a
    caller cannot silently switch the unreleased-fix check off by forgetting the argument -- the one
    place that legitimately wants no bound (e.g. validating a published asset with no VERSION at hand)
    must write `released_ceiling=None` deliberately.
    """
    _no_unknown_keys(data, _TOP_KEYS, "upgrade matrix")
    _require(
        data.get("schema_version") == SUPPORTED_SCHEMA_VERSION,
        f"upgrade matrix schema_version must be {SUPPORTED_SCHEMA_VERSION}, "
        f"got {data.get('schema_version')!r}",
    )

    # `about` and `kinds` are what make the published asset readable on its own, by someone who
    # fetched upgrade.json and has no repository to consult. Validated rather than merely permitted:
    # a validator that rejects unknown keys but ignores known ones would let the self-description
    # rot into something misleading while still passing.
    _string(data.get("about"), "upgrade matrix 'about'")
    kinds = data.get("kinds")
    _require(isinstance(kinds, dict), "upgrade matrix 'kinds' must be an object")
    _require(
        set(kinds) == set(KINDS),
        f"upgrade matrix 'kinds' must describe exactly {', '.join(KINDS)}; got "
        f"{', '.join(sorted(kinds)) or 'nothing'}",
    )
    for kind, description in kinds.items():
        _string(description, f"kinds[{kind}]")

    versions = data.get("versions")
    _require(isinstance(versions, dict) and versions, "upgrade matrix needs a non-empty 'versions'")
    advisories = _validate_advisories(data, versions, released_ceiling)
    for version, meta in versions.items():
        _string(version, "version key", pattern=_VERSION_RE)
        _require(isinstance(meta, dict), f"versions[{version}] must be an object")
        _no_unknown_keys(meta, _VERSION_KEYS, f"versions[{version}]")
        _string(meta.get("released"), f"versions[{version}].released", pattern=_DATE_RE)
        _string(meta.get("notes"), f"versions[{version}].notes")
        if "must_land_here" in meta:
            # A release an upgrade cannot pass through in one go. The deployment has to come up ON
            # this version, complete its boot, and be verified healthy before continuing -- for a
            # migration that needs the previous release's data written in its new shape first, or a
            # two-stage change where the second stage assumes the first has run everywhere.
            #
            # It does NOT mean the operator runs the upgrade twice. The tool walks the legs itself
            # and presents one upgrade; the stop is about what the DATABASE goes through, not what
            # the person does.
            _require(isinstance(meta["must_land_here"], bool),
                     f"versions[{version}].must_land_here must be a boolean")
        _validate_support(meta.get("support"), f"versions[{version}]")
        _validate_vulnerabilities(meta, version, advisories, f"versions[{version}]")
        # secure and the vulnerability list must agree. A version affected by any advisory, of any
        # severity, is not secure -- a single low finding is still a known vulnerability. And from
        # _VULN_LISTED_FROM on, a version that declares itself insecure must say what is wrong with it.
        secure = meta["support"]["secure"]
        listed = meta.get("vulnerabilities") or []
        _require(not (secure and listed),
                 f"versions[{version}] is marked support.secure but lists {len(listed)} "
                 "vulnerability(ies); a secure version has none outstanding")
        if _sort_key(version) >= _sort_key(_VULN_LISTED_FROM):
            _require(secure or listed,
                     f"versions[{version}] is marked support.secure=false but lists no "
                     f"vulnerabilities; from {_VULN_LISTED_FROM} on, an insecure version must name "
                     "its known vulnerabilities")

    _validate_advisory_coverage(advisories, versions)
    if "lines" in data:
        _validate_lines(data["lines"], versions, advisories)

    edges = data.get("edges")
    _require(isinstance(edges, list), "upgrade matrix needs an 'edges' list")

    seen: set[tuple[str, str]] = set()
    for index, edge in enumerate(edges):
        where = f"edges[{index}]"
        _require(isinstance(edge, dict), f"{where} must be an object")
        _no_unknown_keys(edge, _EDGE_KEYS, where)
        source = _string(edge.get("from"), f"{where}.from", pattern=_VERSION_RE)
        target = _string(edge.get("to"), f"{where}.to", pattern=_VERSION_RE)
        # An edge naming a version that does not exist is the failure this catches most often in
        # practice -- a typo in a version number, which would otherwise publish a path to nowhere.
        _require(source in versions, f"{where}.from is not a declared version: {source}")
        _require(target in versions, f"{where}.to is not a declared version: {target}")
        _require(source != target, f"{where} goes from {source} to itself")
        _require((source, target) not in seen, f"duplicate edge {source} -> {target}")
        seen.add((source, target))

        kind = _string(edge.get("kind"), f"{where}.kind")
        _require(kind in KINDS, f"{where}.kind must be one of {', '.join(KINDS)}, got {kind!r}")

        # Required, not defaulted. These are the two things an operator most needs to know before
        # starting, and a default would answer for a release author who never considered the
        # question -- in whichever direction the default happened to point.
        for flag in ("reversible", "requires_backup"):
            _require(isinstance(edge.get(flag), bool),
                     f"{where}.{flag} must be present and a boolean")

        if kind == "blocked":
            # A blocked edge that does not say why tells an operator nothing they can act on.
            #
            # There is deliberately no "go via X" field. Edges are adjacency-only, and every
            # adjacent pair must have one, so a genuine intermediate version cannot exist for an
            # adjacent edge -- declaring one would make the pair non-adjacent and this edge
            # unnecessary. A field that can never be filled meaningfully is worse than no field:
            # it looks like an answer. The reason carries whatever the operator should do instead.
            _string(edge.get("reason"), f"{where}.reason")
        else:
            _require("reason" not in edge, f"{where}.reason is only meaningful on a blocked edge")

        conditions = edge.get("conditions", [])
        _require(isinstance(conditions, list), f"{where}.conditions must be a list")
        condition_ids: set[str] = set()
        for position, condition in enumerate(conditions):
            spot = f"{where}.conditions[{position}]"
            _require(isinstance(condition, dict), f"{spot} must be an object")
            _no_unknown_keys(condition, _CONDITION_KEYS, spot)
            identifier = _string(condition.get("id"), f"{spot}.id", pattern=_ID_RE)
            _require(identifier not in condition_ids, f"{spot}.id is repeated: {identifier}")
            condition_ids.add(identifier)
            _string(condition.get("summary"), f"{spot}.summary")
            if "detect" in condition:
                _string(condition.get("detect"), f"{spot}.detect")
            if "blocks_rollback" in condition:
                _require(condition["blocks_rollback"] is True,
                         f"{spot}.blocks_rollback is only ever true; leave it out when a condition "
                         "does not stop a rollback")
                _require("detect" in condition,
                         f"{spot}.blocks_rollback needs a detect query: it is the query finding rows "
                         "that stops the rollback")

    # Adjacency completeness. Declaring an edge between every pair of neighbours is what lets a longer
    # upgrade be composed by walking them, so a missing neighbour link silently breaks every path
    # across it. An edge that skips releases is allowed only as _validate_routes describes.
    #
    # "Adjacent" is by version order, but the requirement is skipped where the later version was
    # released EARLIER -- a backport. Inserting 0.9.1 after 0.10.0 has shipped makes (0.9.1, 0.10.0)
    # newly adjacent by version, and demanding that edge would force the maintainer to assert an
    # upgrade from a backport into a release that predates its fix. There is no honest answer to
    # that demand, so the price of shipping a backport would be a false declaration.
    #
    # Skipping it outright would orphan the later version if its real predecessor link were also
    # removed, so the fallback still requires SOMETHING released no later than it to lead in.
    ordered = sorted(versions, key=_sort_key)
    missing = []
    for earlier, later in zip(ordered, ordered[1:]):
        if (earlier, later) in seen:
            continue
        if versions[later]["released"] >= versions[earlier]["released"]:
            missing.append(f"{earlier} -> {later}")
        elif not any(target == later and source != later
                     and versions[source]["released"] <= versions[later]["released"]
                     for source, target in seen):
            missing.append(f"(some release older than {later}) -> {later}")
    _require(not missing, "no edge declared between adjacent releases: " + ", ".join(missing))
    _validate_routes(edges, versions)

    waivers = data.get("waivers", [])
    _require(isinstance(waivers, list), "upgrade matrix 'waivers' must be a list")
    waived: set[str] = set()
    for index, waiver in enumerate(waivers):
        where = f"waivers[{index}]"
        _require(isinstance(waiver, dict), f"{where} must be an object")
        _no_unknown_keys(waiver, _WAIVER_KEYS, where)
        version = _string(waiver.get("version"), f"{where}.version", pattern=_VERSION_RE)
        _string(waiver.get("reason"), f"{where}.reason")
        _require(version not in waived, f"{where} waives {version} twice")
        waived.add(version)
        # A waiver names a version with no takeable route in. That is normally an UNDECLARED version.
        # It is also a declared FLOOR release: one that carries its own entry (notes, lifecycle) but
        # whose only route in is a `blocked` edge -- reached by fresh deploy + restore, never by an
        # in-place upgrade. The waiver is what lets such a release be cut while the blocked edge says
        # why the in-place upgrade is refused. A declared version that is genuinely REACHABLE (a
        # non-blocked inbound edge) needs no waiver, and a stale waiver there is how the hatch quietly
        # becomes the normal route -- so that stays an error.
        if version in versions:
            inbound = _inbound_edge(data, version)
            _require(
                inbound is not None and inbound.get("kind") == "blocked",
                f"{where} waives {version}, which is declared and reachable -- a waiver is only for "
                "a version with no takeable route in (undeclared, or a floor release whose only "
                "inbound edge is blocked). Remove the waiver",
            )

    return data


def waived_versions(data: dict) -> dict[str, str]:
    """Versions allowed to ship undeclared, mapped to the stated reason."""
    return {w["version"]: w["reason"] for w in data.get("waivers", [])}


def assert_no_phantom_versions(data: dict, released: set[str], being_cut: str) -> None:
    """Every declared version must be a release that exists, or the one being cut right now.

    Adjacency completeness is satisfied by any chain of entries, so a version nobody released could
    be invented to bridge a gap: the file would validate, the gate would find the fabricated
    predecessor supplying an inbound edge, and the published matrix would describe a release nobody
    can install.

    `being_cut` is exempt because the release commit necessarily declares itself before its tag is
    reachable everywhere.
    """
    phantom = sorted(v for v in data.get("versions", {})
                     if v not in released and v != being_cut)
    if phantom:
        raise UpgradeMatrixError(
            f"docs/upgrade-matrix.json declares {', '.join(phantom)}, which are not released "
            "versions. A version that does not exist can satisfy the adjacency rule while "
            "describing a release nobody can get"
        )


def assert_release_declared(data: dict, version: str) -> str | None:
    """Refuse a release that has not said how to reach it. Returns a waiver reason, or None.

    Three obligations, because each alone leaves a hole: the version has to exist, the release
    before it has to have an edge leading here, and that edge has to describe an upgrade someone
    can actually take. A version entry with no inbound edge is reachable from nowhere, which is a
    name rather than a declaration -- and an inbound edge marked `blocked` says in so many words
    that the upgrade must not be taken, which is not a way to reach the release either.
    """
    waived = waived_versions(data)
    if version in waived:
        return waived[version]

    versions = data.get("versions", {})
    if version not in versions:
        raise UpgradeMatrixError(
            f"{version} has no entry in docs/upgrade-matrix.json. Add one saying how an operator "
            "reaches it from the previous release before cutting the tag"
        )

    ordered = sorted(versions, key=_sort_key)
    index = ordered.index(version)
    if index == 0:
        return None  # the earliest declared release has nothing before it
    previous = ordered[index - 1]
    inbound = {
        (edge["from"], edge["to"]): edge for edge in data.get("edges", [])
    }.get((previous, version))
    if inbound is None:
        raise UpgradeMatrixError(
            f"docs/upgrade-matrix.json declares {version} but no edge from {previous} to it, so "
            "nothing says how to get there"
        )
    if inbound["kind"] == "blocked":
        raise UpgradeMatrixError(
            f"the only way into {version} is an edge from {previous} marked blocked "
            f"({inbound['reason']}), so the matrix says this release cannot be reached. Declare a "
            "route that can be taken, or waive it deliberately"
        )
    return None
