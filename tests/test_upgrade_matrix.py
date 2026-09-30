"""The upgrade matrix, and the gate that makes it complete.

`docs/upgrade-matrix.json` says what it takes to move between released versions. Its worth rests
entirely on being complete -- a claim about upgrading means nothing if a release can decline to make
one -- so the release gate refuses to cut a tag whose version is absent from it.

These tests cover three things: that the committed file is valid and says what it should, that the
validator rejects each way of getting it wrong, and that the gate fails closed. The override that
lets a security fix ship without a declaration is tested for what it does NOT waive as much as for
what it does.
"""

from __future__ import annotations

import copy
import importlib.util
import json
import os
import re
import subprocess
import sys
import warnings
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
MATRIX_PATH = ROOT / "docs" / "upgrade-matrix.json"


def _load(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / ".github" / "scripts" / filename)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    sys.modules[name] = module
    spec.loader.exec_module(module)
    return module


um = _load("upgrade_matrix_under_test", "upgrade_matrix.py")
gate = _load("release_gate_under_test", "release_gate.py")


def _support(eol=False, secure=True, **extra):
    return {"eol": eol, "secure": secure, **extra}


def _valid():
    """A minimal matrix that passes, as the starting point for each rejection case."""
    return {
        "schema_version": 3,
        "about": "test fixture",
        "kinds": {"direct": "one step", "blocked": "do not"},
        "advisories": {},
        "versions": {
            "0.1.0": {"released": "2026-01-01", "notes": "first", "support": _support()},
            "0.2.0": {"released": "2026-01-02", "notes": "second", "support": _support()},
        },
        "edges": [{"from": "0.1.0", "to": "0.2.0", "kind": "direct",
                   "reversible": True, "requires_backup": False}],
    }


# --- the committed file ------------------------------------------------------------------------

# --- reading the repository ----------------------------------------------------------------------
#
# The same tests run on main and on a maintenance branch release/X.Y, whose matrix is main's plus its
# own newest entry. These helpers are what lets one set of rules hold on both.

_RELEASE_TAG = re.compile(r"v((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})", re.ASCII)
_ADDED_VERSION = re.compile(r"^\+((?:0|[1-9][0-9]*)(?:\.(?:0|[1-9][0-9]*)){2})\s*$", re.M)


def _vkey(version: str) -> tuple[int, int, int]:
    major, minor, patch = (int(part) for part in version.split("."))
    return major, minor, patch


def _git_out(root: Path, *args: str) -> subprocess.CompletedProcess:
    return subprocess.run(["git", *args], cwd=root, capture_output=True, text=True, timeout=60)


def _released_versions(root: Path) -> list[str]:
    """The released versions, from the vX.Y.Z tags in this checkout, in version order."""
    tags = _git_out(root, "tag", "-l", "v*.*.*")
    # A git that FAILED is not a checkout without tags, and folding them together reproduces the
    # very mistake this check was written to fix -- one level down. `git tag -l` does not fail on a
    # repository with no tags; it prints nothing and exits 0. A non-zero exit means something else
    # is wrong, everywhere, so it fails everywhere.
    assert tags.returncode == 0, (
        "git tag -l failed, which is not the same as having no tags: %s"
        % (tags.stderr or "").strip()[:200])
    found = (_RELEASE_TAG.fullmatch(name) for name in tags.stdout.split())
    return sorted({m.group(1) for m in found if m}, key=_vkey)


def _versions_in_history(root: Path) -> set[str]:
    """Every version the VERSION file has held in this commit's own history, this commit included.

    A release candidate can be built on another that is not tagged yet: 0.34.0's candidate on top of
    0.33.2's, when both ship the same day. The earlier one's entry is then declared but has no tag,
    and it is not the VERSION of this commit either -- it is the VERSION of an ancestor.
    """
    log = _git_out(root, "log", "--format=", "-p", "--no-color", "--no-ext-diff", "--", "VERSION")
    assert log.returncode == 0, "git log failed: %s" % (log.stderr or "").strip()[:200]
    return set(_ADDED_VERSION.findall(log.stdout))


def _is_shallow(root: Path) -> bool:
    return _git_out(root, "rev-parse", "--is-shallow-repository").stdout.strip() == "true"


def _released_ceiling(preparing: str, released: list[str]) -> str:
    """The newest released version a fix may name: the highest of VERSION and the tags.

    On main that is VERSION. On a maintenance branch VERSION is on an older line, while the matrix,
    synced from main, names fixes released on newer lines.
    """
    return max([preparing, *released], key=_vkey)


def _undeclared(released: list[str], declared, preparing: str) -> tuple[list[str], list[str]]:
    """Released versions the matrix does not declare: (failures, warnings).

    On main every one is a failure: main's matrix is the one the site and every reader use, and it
    must not lag. On a maintenance branch -- VERSION on an older line than the newest release -- a
    release of a newer line is only a warning: it is declared on main, and this branch takes main's
    matrix at its next release. The release gate is strict everywhere.
    """
    newest_line = max(_vkey(v)[:2] for v in [preparing, *released])
    on_maintenance_branch = _vkey(preparing)[:2] < newest_line
    failures, warnings_ = [], []
    for version in released:
        if version in declared:
            continue
        if on_maintenance_branch and _vkey(version)[:2] > _vkey(preparing)[:2]:
            warnings_.append(version)
        else:
            failures.append(version)
    return failures, warnings_


def _unreachable(data: dict, released: list[str]) -> list[str]:
    """Released, declared versions with no takeable route in, each with the reason.

    The gate's rule is an edge from the version-order predecessor. A maintenance release made after
    the next minor makes itself that minor's predecessor, and no honest edge leads from it into a
    release that predates its fix; the validator's backport rule then asks for an edge from some
    release no later than it instead, and so does this.
    """
    versions = data["versions"]
    ordered = sorted(versions, key=_vkey)
    edges = data.get("edges", [])
    problems = []
    for version in released:
        if version not in versions:
            continue
        index = ordered.index(version)
        previous = ordered[index - 1] if index else None
        if previous is not None and versions[previous]["released"] > versions[version]["released"]:
            if not any(e["to"] == version and e["kind"] != "blocked"
                       and versions[e["from"]]["released"] <= versions[version]["released"]
                       for e in edges):
                problems.append(f"{version}: no route in from a release made before it")
            continue
        try:
            um.assert_release_declared(data, version)
        except um.UpgradeMatrixError as exc:
            problems.append(f"{version}: {exc}")
    return problems


def _phantoms(declared, released: list[str], pending: set[str]) -> list[str]:
    """Declared versions that are neither released nor pending in this commit's history."""
    return sorted((v for v in declared if v not in released and v not in pending), key=_vkey)


def _require_no_phantoms(root: Path, declared, released: list[str], preparing: str) -> None:
    """Fail when the matrix declares a version that is neither released nor prepared in this
    commit's history. A shallow checkout cannot see that history, so it fails too -- as a failure,
    not a skip, since a skip would leave the check silently off wherever CI checks out shallow."""
    pending = _versions_in_history(root) | {preparing}
    phantom = _phantoms(declared, released, pending)
    if phantom and _is_shallow(root):
        pytest.fail(
            f"docs/upgrade-matrix.json declares {phantom}, which are not released tags, and this "
            "checkout is shallow, so whether they are pending in this commit's history cannot be "
            "told. The checkout needs its history (fetch-depth: 0)")
    assert not phantom, (
        f"docs/upgrade-matrix.json declares {phantom}, which are not released tags and not a "
        f"version prepared in this commit's history ({preparing} now). A version that does not "
        "exist can satisfy the adjacency rule while describing a release nobody can get")


def test_the_committed_matrix_is_valid():
    # Against the newest released version: on main that is the VERSION file, so a vulnerability
    # naming an unreleased `fixed_in` is caught here on an ordinary push, not only at release. On a
    # maintenance branch it is the newest tag, since the matrix there names newer lines' fixes too.
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    ceiling = _released_ceiling(version, _released_versions(ROOT))
    um.validate_matrix(um.load_matrix(MATRIX_PATH), released_ceiling=ceiling)


def test_every_one_way_edge_in_the_committed_matrix_asks_for_a_backup():
    """An edge that cannot be rolled back says so in `requires_backup` too.

    The host tool demands a backup for any one-way hop whatever this flag says, but the website and
    the app show the flag as written. Two edges into 0.30.0 said "backup not required" on a hop that
    can never be undone."""
    matrix = um.load_matrix(MATRIX_PATH)
    one_way = [e for e in matrix["edges"] if e.get("reversible") is False]
    assert one_way, "the matrix has one-way edges; an empty set would make this vacuous"
    missing = [(e["from"], e["to"]) for e in one_way if e.get("requires_backup") is not True]
    assert not missing, f"one-way edges that do not ask for a backup: {missing}"


def test_every_released_tag_has_an_entry_and_a_way_to_reach_it():
    """The backfill is checked against git, not against a list typed into the test.

    A hand-copied list would drift the moment a release is cut, and would then agree with a matrix
    that had drifted the same way.
    """
    released = _released_versions(ROOT)
    if not released:
        # Skipping here is only acceptable on a developer's partial checkout. In CI it means the
        # check did not run in the job that gates publication -- which is exactly how this test
        # spent its first day doing nothing: the default checkout is shallow and tagless, so
        # `git tag -l` returned nothing and this skipped, silently and only there.
        if os.environ.get("CI"):
            pytest.fail(
                "no release tags visible in CI, so this check cannot run. The checkout needs "
                "fetch-tags; a silent skip here removes the only guard on the matrix matching the "
                "releases that exist")
        pytest.skip("no release tags in this checkout")
    preparing = (ROOT / "VERSION").read_text(encoding="utf-8").strip()

    data = um.validate_matrix(um.load_matrix(MATRIX_PATH), released_ceiling=None)
    missing, elsewhere = _undeclared(released, data["versions"], preparing)
    assert not missing, (
        f"released but undeclared in docs/upgrade-matrix.json: {missing}. The release gate would "
        "have refused these; they predate it, so add them")
    if elsewhere:
        warnings.warn(
            f"releases of newer lines not yet in this branch's matrix: {elsewhere}. main declares "
            "them; take main's matrix before this branch's next release")

    # And each is reachable, which is the assertion the gate itself makes.
    unreachable = _unreachable(data, released)
    assert not unreachable, f"released versions with no route in: {unreachable}"

    # The converse, which matters more than it looks. Adjacency completeness is satisfied by any
    # chain of entries, so a version that was never released could be invented to bridge a gap --
    # and the file would validate while describing a release nobody can install. Every declared
    # version must correspond to a real tag.
    #
    # Checked here rather than in the validator on purpose: at release time the tag being cut does
    # exist, but the validator runs without a guaranteed view of the tag list, and a check that
    # silently passes when it cannot see tags would be worse than no check.
    #
    # A version being prepared is exempt: a release-prep commit bumps VERSION and adds the matrix
    # entry together, and the tag only appears afterwards. Without the exemption the two rules
    # deadlock -- the gate refuses to cut a version the matrix does not declare, and this refuses a
    # declared version that is not yet tagged, so main would be red for the whole window between the
    # two. "Being prepared" is this commit's VERSION or any VERSION in its history: two releases cut
    # the same day are prepared as two candidates, the later built on the earlier, and each must pass
    # CI before either is tagged. The release gate stays strict; it exempts only the tag it cuts.
    _require_no_phantoms(ROOT, data["versions"], released, preparing)


def test_the_committed_matrix_declares_every_released_edge_direct():
    """Pins the fact the backfill rests on, so a later edit cannot quietly contradict it.

    Every released pair really is schema-identical: across all seven tags the boot DDL string set
    is byte-identical and the model differs only in comment text. If a future edge is not direct,
    that is fine and expected -- but it should be a deliberate edit, not a silent one.
    """
    data = um.load_matrix(MATRIX_PATH)
    # A blocked edge INTO a FLOOR release is the deliberate exception -- it says that version is the
    # minimum reached by a fresh deploy + restore, not an in-place upgrade. That is true of the
    # release being prepared AND of an already-released floor (marked by a waiver), whose blocked
    # inbound edge stays deliberately non-direct after it ships (e.g. 0.16.1 -> 0.17.0). Every OTHER
    # edge between already-RELEASED versions must still be direct.
    preparing = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    floors = {w["version"] for w in data.get("waivers", [])} | {preparing}
    non_direct = [(edge["from"], edge["to"], edge["kind"]) for edge in data["edges"]
                  if edge["kind"] != "direct" and edge["to"] not in floors]
    assert not non_direct, (
        f"the matrix now declares non-direct edge(s) between released versions: {non_direct}; if a "
        "released upgrade has stopped being direct, update this test deliberately")


# --- rejection cases ---------------------------------------------------------------------------

@pytest.mark.parametrize("mutate, expected", [
    (lambda m: m.update({"schema_version": 4}), "schema_version"),
    (lambda m: m.update({"schema_version": "3"}), "schema_version"),
    (lambda m: m.pop("versions"), "versions"),
    (lambda m: m.update({"versions": {}}), "versions"),
    (lambda m: m.update({"surprise": 1}), "unknown key"),
    (lambda m: m.pop("about"), "'about'"),
    (lambda m: m.update({"about": "   "}), "must not be empty"),
    (lambda m: m.update({"kinds": {"direct": "one step"}}), "must describe exactly"),
    (lambda m: m.update({"kinds": {"direct": "a", "blocked": "b", "other": "c"}}),
     "must describe exactly"),
    (lambda m: m.update({"kinds": 5}), "must be an object"),
    (lambda m: m["kinds"].update({"direct": ""}), "must not be empty"),
    (lambda m: m["versions"].update({"nope": {"released": "2026-01-03", "notes": "x", "support": _support()}}),
     "malformed"),
    (lambda m: m["versions"]["0.1.0"].update({"released": "yesterday"}), "malformed"),
    (lambda m: m["versions"]["0.1.0"].update({"extra": 1}), "unknown key"),
    (lambda m: m["versions"]["0.1.0"].update({"notes": ""}), "must not be empty"),
    # --- the per-version support block ---
    (lambda m: m["versions"]["0.1.0"].pop("support"), "support must be present"),
    (lambda m: m["versions"]["0.1.0"].update({"support": []}), "support must be present"),
    (lambda m: m["versions"]["0.1.0"]["support"].pop("eol"), "eol must be present and a boolean"),
    (lambda m: m["versions"]["0.1.0"]["support"].pop("secure"), "secure must be present and a boolean"),
    (lambda m: m["versions"]["0.1.0"]["support"].update({"eol": "yes"}), "eol must be present and a boolean"),
    (lambda m: m["versions"]["0.1.0"]["support"].update({"extra": 1}), "unknown key"),
    # extended-support dates are only meaningful once eol is true
    (lambda m: m["versions"]["0.1.0"]["support"].update({"code_support": "2026-01-01"}),
     "only meaningful once eol is true"),
    (lambda m: m["versions"]["0.1.0"]["support"].update({"eol": True, "code_support": "nope"}), "malformed"),
    (lambda m: m["versions"]["0.1.0"]["support"].update(
        {"eol": True, "code_support": "2026-06-01", "security_support": "2026-01-01"}),
     "must not end before code_support"),
    (lambda m: m["edges"][0].update({"to": "9.9.9"}), "not a declared version"),
    (lambda m: m["edges"][0].update({"from": "9.9.9"}), "not a declared version"),
    (lambda m: m["edges"][0].update({"to": "0.1.0"}), "to itself"),
    (lambda m: m["edges"][0].update({"kind": "maybe"}), "kind must be one of"),
    (lambda m: m["edges"].append({"from": "0.1.0", "to": "0.2.0", "kind": "direct",
                             "reversible": True, "requires_backup": False}),
     "duplicate edge"),
    (lambda m: m.update({"edges": []}), "no edge declared between adjacent releases"),
    (lambda m: m["edges"][0].update({"reason": "because"}), "only meaningful on a blocked edge"),
    (lambda m: m["edges"][0].update({"kind": "blocked"}), "reason"),
    (lambda m: m["edges"][0].update({"kind": "blocked", "reason": "r", "via": ["0.1.0"]}),
     "unknown key"),
    (lambda m: m["edges"][0].update({"conditions": [{"id": "Bad Id", "summary": "s"}]}),
     "malformed"),
    (lambda m: m["edges"][0].update({"conditions": [{"id": "ok", "summary": ""}]}),
     "must not be empty"),
    (lambda m: m["edges"][0].update({"conditions": [{"id": "ok", "summary": "s", "huh": 1}]}),
     "unknown key"),
    (lambda m: m["edges"][0].update(
        {"conditions": [{"id": "dup", "summary": "a"}, {"id": "dup", "summary": "b"}]}),
     "repeated"),
])
def test_the_validator_rejects(mutate, expected):
    data = _valid()
    mutate(data)
    with pytest.raises(um.UpgradeMatrixError) as caught:
        # These synthetic matrices exercise structure only, not the release ceiling, so they pass
        # released_ceiling=None explicitly -- the argument is keyword-only with no default (a bare
        # call is a TypeError), which is what keeps a real caller from skipping the check by accident.
        um.validate_matrix(data, released_ceiling=None)
    assert expected in str(caught.value), f"expected {expected!r}, got {caught.value}"


def test_validate_matrix_requires_the_release_ceiling_to_be_passed():
    # released_ceiling is keyword-only with no default: a bare call raises rather than validating
    # with the disclosure check silently off. The no-bound escape hatch must write None on purpose.
    with pytest.raises(TypeError):
        um.validate_matrix(_valid())


# --- advisories, and the versions that reference them ------------------------------------------

#: A canonical CVSS v4.0 base vector that scores 5.9 (medium) -- the interrupted-upload rating.
_MEDIUM = "CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N"
#: 7.1 (high) -- the stalled-upload rating.
_HIGH = "CVSS:4.0/AV:N/AC:L/AT:N/PR:L/UI:N/VC:N/VI:N/VA:H/SC:N/SI:N/SA:N"
#: 1.0 (low): physical access, high complexity, high privileges, a little availability.
_LOW = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:L/SC:N/SI:N/SA:N"


def _advisory(title="A fixed issue", fixed_in="0.2.0", vector=_MEDIUM, severity="medium", **extra):
    return {
        "title": title,
        "description": "Something that was wrong and is now put right.",
        "impact": "What it let someone do.",
        "remediation": "Upgrade.",
        "mitigation": None,
        "severity": severity,
        "cvss": vector,
        "id": None,
        "fixed_in": fixed_in,
        "published": "2026-01-02",
        **extra,
    }


def _ref(slug="a-fixed-issue", title="A fixed issue", fixed_in="0.2.0"):
    return {"advisory": slug, "title": title, "fixed_in": fixed_in}


def _valid_with_vuln():
    """_valid() with one well-formed advisory affecting 0.1.0, fixed in 0.2.0."""
    m = _valid()
    m["advisories"] = {"a-fixed-issue": _advisory()}
    m["versions"]["0.1.0"]["support"] = _support(secure=False)
    m["versions"]["0.1.0"]["vulnerabilities"] = [_ref()]
    return m


def _three_releases():
    """0.1.0 -> 0.2.0 -> 0.3.0, all secure, no advisories: the base for coverage cases."""
    m = _valid()
    m["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}
    m["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                       "reversible": True, "requires_backup": False})
    return m


def _reject(data, expected, ceiling=None):
    with pytest.raises(um.UpgradeMatrixError) as caught:
        um.validate_matrix(data, released_ceiling=ceiling)
    assert expected in str(caught.value), f"expected {expected!r}, got {caught.value}"


def test_a_well_formed_advisory_and_its_reference_are_accepted():
    um.validate_matrix(_valid_with_vuln(), released_ceiling=None)


def test_an_empty_advisories_object_is_accepted_and_a_missing_one_is_not():
    um.validate_matrix(_valid(), released_ceiling=None)
    data = _valid()
    del data["advisories"]
    _reject(data, "needs an 'advisories' object")


def test_the_previous_schema_is_refused():
    # A schema-2 file copies full records onto every version; read as schema 3 its entries would be
    # misunderstood, so the version is checked before anything else.
    data = _valid()
    data["schema_version"] = 2
    _reject(data, "schema_version must be 3")


@pytest.mark.parametrize("mutate, expected", [
    (lambda a: a.update({"surprise": 1}), "unknown key"),
    (lambda a: a.pop("title"), "missing required key"),
    (lambda a: a.pop("impact"), "missing required key"),
    (lambda a: a.pop("remediation"), "missing required key"),
    (lambda a: a.pop("mitigation"), "missing required key"),
    (lambda a: a.pop("severity"), "missing required key"),
    (lambda a: a.pop("cvss"), "missing required key"),
    (lambda a: a.pop("fixed_in"), "missing required key"),
    (lambda a: a.update({"impact": ""}), "must not be empty"),
    (lambda a: a.update({"remediation": "   "}), "must not be empty"),
    # An escape sequence in a string that the host tool prints raw on a terminal.
    (lambda a: a.update({"title": "bad\x1b[31mred\x1b[0m"}), "non-printable"),
    (lambda a: a.update({"description": "line\nbreak"}), "non-printable"),
    (lambda a: a.update({"impact": "bell\x07"}), "non-printable"),
    (lambda a: a.update({"remediation": "tab\there"}), "non-printable"),
    (lambda a: a.update({"mitigation": "\x1b]0;title\x07"}), "non-printable"),
    (lambda a: a.update({"id": "GHSA\x1b[2J"}), "non-printable"),
    (lambda a: a.update({"published": "soon"}), "malformed"),
    (lambda a: a.update({"fixed_in": "9.9.9"}), "not a declared version"),
])
def test_the_validator_rejects_a_bad_advisory(mutate, expected):
    data = _valid_with_vuln()
    mutate(data["advisories"]["a-fixed-issue"])
    _reject(data, expected)


def test_an_advisory_key_must_be_a_slug():
    data = _valid_with_vuln()
    data["advisories"] = {"Not A Slug": data["advisories"]["a-fixed-issue"]}
    _reject(data, "advisory key is malformed")


# --- the rating: a CVSS v4.0 base vector, and the band it scores to ------------------------------

@pytest.mark.parametrize("vector, expected", [
    ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", "starts with 'CVSS:4.0/'"),
    ("AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", "starts with 'CVSS:4.0/'"),
    # a base metric missing, and one extra (threat/environmental metrics belong to the operator)
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N", "exactly the 11 base metrics"),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N/E:A", "exactly the 11 base metrics"),
    # the specification's order, so one rating has one spelling
    ("CVSS:4.0/AC:L/AV:N/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", "metric 1 of a CVSS v4.0 base vector is AV"),
    ("CVSS:4.0/AV:X/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:N/SA:N", "AV must be one of"),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI:S/SA:N", "SI must be one of"),
    ("CVSS:4.0/AV:N/AC:L/AT:P/PR:L/UI:P/VC:N/VI:H/VA:N/SC:N/SI/SA:N", "metric 10 of a CVSS v4.0 base vector is SI"),
    (7.5, "must be a string"),   # the schema-2 numeric score is not a vector
])
def test_a_malformed_vector_is_rejected(vector, expected):
    data = _valid_with_vuln()
    data["advisories"]["a-fixed-issue"]["cvss"] = vector
    _reject(data, expected)


def test_the_band_is_derived_from_the_vector_not_chosen():
    # The vector scores 5.9 (medium). Stating "high" beside it is the drift this rule exists to stop;
    # the error names the score so the author can see which of the two is wrong.
    data = _valid_with_vuln()
    data["advisories"]["a-fixed-issue"]["severity"] = "high"
    _reject(data, "the vector scores 5.9 (medium), got 'high'")


@pytest.mark.parametrize("vector, band", [(_LOW, "low"), (_MEDIUM, "medium"), (_HIGH, "high"),
    ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", "critical")])
def test_each_band_is_accepted_beside_a_vector_that_scores_to_it(vector, band):
    data = _valid_with_vuln()
    data["advisories"]["a-fixed-issue"].update({"cvss": vector, "severity": band})
    um.validate_matrix(data, released_ceiling=None)


def test_an_unrated_advisory_leaves_both_null_and_is_still_a_vulnerability():
    data = _valid_with_vuln()
    data["advisories"]["a-fixed-issue"].update({"cvss": None, "severity": None})
    um.validate_matrix(data, released_ceiling=None)
    # ...and a band with no vector is a band chosen by hand.
    data["advisories"]["a-fixed-issue"]["severity"] = "low"
    _reject(data, "with no cvss vector")


def test_a_vector_with_no_impact_is_not_a_vulnerability():
    data = _valid_with_vuln()
    data["advisories"]["a-fixed-issue"].update({
        "cvss": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N", "severity": "none"})
    _reject(data, "scores 0.0")


# --- the rule the user named: one finding of any severity makes a version insecure ---------------

@pytest.mark.parametrize("vector, band", [(_LOW, "low"), (None, None)])
def test_a_secure_version_may_not_be_affected_by_even_one_low_or_unrated_advisory(vector, band):
    data = _valid_with_vuln()
    data["advisories"]["a-fixed-issue"].update({"cvss": vector, "severity": band})
    data["versions"]["0.1.0"]["support"] = _support(secure=True)
    _reject(data, "marked support.secure but lists 1 vulnerability")


# --- references ------------------------------------------------------------------------------------

@pytest.mark.parametrize("mutate, expected", [
    (lambda r: r.update({"description": "copied"}), "unknown key"),
    (lambda r: r.pop("advisory"), "missing required key"),
    (lambda r: r.pop("title"), "missing required key"),
    (lambda r: r.pop("fixed_in"), "missing required key"),
    (lambda r: r.update({"advisory": "no-such-advisory"}), "which 'advisories' does not declare"),
    (lambda r: r.update({"advisory": "Bad Slug"}), "malformed"),
    # title and fixed_in are what an older reader shows, so they must be the advisory's exactly
    (lambda r: r.update({"title": "A fixed issue."}), "title must repeat advisories[a-fixed-issue].title"),
    (lambda r: r.update({"fixed_in": "0.1.0"}), "fixed_in must repeat advisories[a-fixed-issue].fixed_in"),
])
def test_the_validator_rejects_a_bad_reference(mutate, expected):
    data = _valid_with_vuln()
    mutate(data["versions"]["0.1.0"]["vulnerabilities"][0])
    _reject(data, expected)


def test_a_vulnerabilities_value_that_is_not_a_list_is_rejected():
    data = _valid_with_vuln()
    data["versions"]["0.1.0"]["vulnerabilities"] = {"advisory": "a-fixed-issue"}
    _reject(data, "must be a list")


def test_a_version_lists_an_advisory_once():
    data = _valid_with_vuln()
    data["versions"]["0.1.0"]["vulnerabilities"].append(_ref())
    _reject(data, "lists advisory a-fixed-issue a second time")


def test_a_release_cannot_be_affected_by_an_issue_fixed_in_it():
    data = _valid_with_vuln()
    data["versions"]["0.2.0"]["support"] = _support(secure=False)
    data["versions"]["0.2.0"]["vulnerabilities"] = [_ref()]
    _reject(data, "must be a version later than 0.2.0")


# --- references that carry only the advisory id --------------------------------------------------

def _across_the_id_only_boundary():
    """0.26.0 -> 0.27.0 -> 0.28.0, one advisory affecting the first two and fixed in the third.

    The references are in full; each test shortens the one it is about.
    """
    data = _valid()
    data["versions"] = {
        ver: {"released": f"2026-01-0{day}", "notes": ver, "support": _support(secure=secure)}
        for day, (ver, secure) in enumerate((("0.26.0", False), ("0.27.0", False),
                                             ("0.28.0", True)), start=1)
    }
    data["edges"] = [{"from": a, "to": b, "kind": "direct", "reversible": True,
                      "requires_backup": False}
                     for a, b in (("0.26.0", "0.27.0"), ("0.27.0", "0.28.0"))]
    data["advisories"] = {"a-fixed-issue": _advisory(fixed_in="0.28.0")}
    for ver in ("0.26.0", "0.27.0"):
        data["versions"][ver]["vulnerabilities"] = [_ref(fixed_in="0.28.0")]
    return data


def test_the_id_only_boundary_is_0_27_0():
    # The host tools of 0.30.0 to 0.32.x print a line for each of the 15 newest releases that are not
    # end-of-life, from each reference's own title and fixed_in; that list reaches 0.27.0 today. The
    # frozen-reader tests in test_upgrade_matrix_older_readers.py check the list itself.
    assert um.ID_ONLY_REFERENCES_BELOW == "0.27.0"


def test_below_the_boundary_a_reference_may_carry_only_its_advisory_id():
    data = _across_the_id_only_boundary()
    um.validate_matrix(data, released_ceiling=None)
    data["versions"]["0.26.0"]["vulnerabilities"] = [{"advisory": "a-fixed-issue"}]
    um.validate_matrix(data, released_ceiling="0.28.0")


def test_from_the_boundary_on_a_reference_repeats_its_advisory_title_and_fix():
    data = _across_the_id_only_boundary()
    data["versions"]["0.27.0"]["vulnerabilities"] = [{"advisory": "a-fixed-issue"}]
    _reject(data, "versions[0.27.0].vulnerabilities[0] is missing required key(s): fixed_in, title; "
                  "from 0.27.0 on a reference repeats its advisory's title and fixed_in for the host "
                  "tools of 0.30.0 to 0.32.x")


def test_below_the_boundary_a_reference_is_whole_or_the_id_alone():
    # Half a reference is a mistake, not the short form: it is refused like any missing key, and the
    # note about the boundary is not given, since the boundary is not the reason.
    data = _across_the_id_only_boundary()
    data["versions"]["0.26.0"]["vulnerabilities"] = [{"advisory": "a-fixed-issue",
                                                      "title": "A fixed issue"}]
    with pytest.raises(um.UpgradeMatrixError) as caught:
        um.validate_matrix(data, released_ceiling=None)
    assert "versions[0.26.0].vulnerabilities[0] is missing required key(s): fixed_in" in str(caught.value)
    assert "from 0.27.0 on" not in str(caught.value)


@pytest.mark.parametrize("refs, expected", [
    ([{"advisory": "no-such-advisory"}], "which 'advisories' does not declare"),
    ([{"advisory": "Bad Slug"}], "malformed"),
    ([{"advisory": "a-fixed-issue"}, {"advisory": "a-fixed-issue"}],
     "lists advisory a-fixed-issue a second time"),
    ([{"advisory": "a-fixed-issue"}, _ref(fixed_in="0.28.0")],
     "lists advisory a-fixed-issue a second time"),
])
def test_an_id_only_reference_is_checked_like_a_whole_one(refs, expected):
    data = _across_the_id_only_boundary()
    data["versions"]["0.26.0"]["vulnerabilities"] = refs
    _reject(data, expected)


def test_an_id_only_reference_still_counts_toward_the_advisory_coverage():
    # The advisory affects 0.26.0 and 0.27.0; with 0.26.0's short reference dropped the advisory
    # starts at 0.27.0, which is still unbroken. With 0.27.0's dropped instead, the gap is found.
    data = _across_the_id_only_boundary()
    data["versions"]["0.26.0"]["vulnerabilities"] = [{"advisory": "a-fixed-issue"}]
    data["versions"]["0.27.0"]["vulnerabilities"] = []
    data["versions"]["0.27.0"]["support"] = _support(secure=True)
    data["versions"]["0.28.0"]["support"] = _support(secure=True)
    _reject(data, "not listed on: 0.27.0")


def test_an_id_only_reference_cannot_name_an_advisory_fixed_in_its_own_release():
    data = _across_the_id_only_boundary()
    data["advisories"]["a-fixed-issue"]["fixed_in"] = "0.26.0"
    data["versions"]["0.26.0"]["vulnerabilities"] = [{"advisory": "a-fixed-issue"}]
    data["versions"]["0.27.0"]["vulnerabilities"] = []
    data["versions"]["0.27.0"]["support"] = _support(secure=True)
    _reject(data, "must be a version later than 0.26.0")


# --- a fix released on several lines (fixed_in_lines) ---------------------------------------------

def _two_lines(fixes=("0.33.2", "0.34.1")):
    """0.32.6 .. 0.34.1 after the first fix released on two lines.

    0.34.0 shipped before the fix; the fix then went out as 0.33.2 (on the 0.33 line) and 0.34.1 the
    same day. The advisory reaches back to 0.32.6. Each version's reference names the fix on its own
    line, or, on the unsupported 0.32 line, the lowest fix above it.
    """
    dates = {"0.32.6": "2026-09-27", "0.33.0": "2026-09-29", "0.33.1": "2026-10-28",
             "0.34.0": "2026-12-10", "0.33.2": "2027-01-11", "0.34.1": "2027-01-11"}
    data = _valid()
    data["versions"] = {ver: {"released": day, "notes": ver, "support": _support(secure=True)}
                        for ver, day in sorted(dates.items(), key=lambda item: um._sort_key(item[0]))}
    data["edges"] = [{"from": a, "to": b, "kind": "direct", "reversible": True,
                      "requires_backup": False}
                     for a, b in (("0.32.6", "0.33.0"), ("0.33.0", "0.33.1"), ("0.33.1", "0.33.2"),
                                  ("0.33.1", "0.34.0"), ("0.34.0", "0.34.1"), ("0.33.2", "0.34.1"))]
    data["advisories"] = {"on-two-lines": _advisory(title="On two lines", fixed_in=fixes[0],
                                                    fixed_in_lines=list(fixes))}
    for ver, fix in (("0.32.6", "0.33.2"), ("0.33.0", "0.33.2"), ("0.33.1", "0.33.2"),
                     ("0.34.0", "0.34.1")):
        data["versions"][ver]["support"] = _support(secure=False)
        data["versions"][ver]["vulnerabilities"] = [
            _ref(slug="on-two-lines", title="On two lines", fixed_in=fix)]
    return data


def test_a_fix_on_two_lines_is_accepted():
    um.validate_matrix(_two_lines(), released_ceiling="0.34.1")


@pytest.mark.parametrize("version, fix", [("0.33.1", "0.33.2"), ("0.34.0", "0.34.1"),
                                          ("0.32.6", "0.33.2")])
def test_each_reference_names_the_fix_for_its_own_line(version, fix):
    assert um._fix_for(version, ["0.33.2", "0.34.1"]) == fix
    # Any other released fix is refused, including the advisory's own fixed_in on the 0.34 line.
    for other in {"0.33.2", "0.34.1"} - {fix}:
        data = _two_lines()
        data["versions"][version]["vulnerabilities"][0]["fixed_in"] = other
        _reject(data, f"versions[{version}].vulnerabilities[0].fixed_in must name the fix on the "
                      f"{version.rsplit('.', 1)[0]} line, or the lowest fix above {version}: {fix} "
                      f"(got '{other}')")


def test_a_version_the_fix_leaves_affected_must_list_it():
    data = _two_lines()
    del data["versions"]["0.34.0"]["vulnerabilities"]
    data["versions"]["0.34.0"]["support"] = _support(secure=True)
    _reject(data, "advisories[on-two-lines] affects 0.32.6 and is fixed in 0.33.2 and 0.34.1, so every "
                  "release in between is affected too; not listed on: 0.34.0")


@pytest.mark.parametrize("fixed", ["0.33.2", "0.34.1"])
def test_a_release_that_contains_the_fix_on_its_line_cannot_list_it(fixed):
    data = _two_lines()
    data["versions"][fixed]["support"] = _support(secure=False)
    data["versions"][fixed]["vulnerabilities"] = [
        _ref(slug="on-two-lines", title="On two lines", fixed_in=fixed)]
    _reject(data, f"fixed_in ({fixed}), which must be a version later than {fixed}")


def test_a_release_above_every_fix_on_a_later_line_cannot_list_it():
    data = _two_lines()
    data["versions"]["0.35.0"] = {"released": "2027-02-01", "notes": "0.35.0",
                                  "support": _support(secure=False),
                                  "vulnerabilities": [_ref(slug="on-two-lines", title="On two lines",
                                                           fixed_in="0.34.1")]}
    data["edges"].append({"from": "0.34.1", "to": "0.35.0", "kind": "direct", "reversible": True,
                          "requires_backup": False})
    _reject(data, "versions[0.35.0].vulnerabilities[0] names advisory on-two-lines, fixed in 0.33.2 "
                  "and 0.34.1; 0.35.0 is above every fix, on a line that has none, so it is not "
                  "affected")
    # Unlisted, it is fine: the 0.35 line began after both fixes.
    data["versions"]["0.35.0"]["support"] = _support(secure=True)
    del data["versions"]["0.35.0"]["vulnerabilities"]
    um.validate_matrix(data, released_ceiling=None)


@pytest.mark.parametrize("mutate, expected", [
    (lambda a: a.update({"fixed_in_lines": ["0.33.2", "0.34.0", "0.34.1"]}),
     "names more than one fix on the 0.34 line"),
    (lambda a: a.update({"fixed_in": "0.34.1"}),
     "fixed_in must be the lowest of fixed_in_lines, 0.33.2 (got 0.34.1)"),
    (lambda a: a.update({"fixed_in_lines": ["0.34.1", "0.33.2"]}), "must be in version order"),
    (lambda a: a.update({"fixed_in_lines": ["0.33.2", "0.34.9"]}),
     "fixed_in_lines[1] is not a declared version: 0.34.9"),
    (lambda a: a.update({"fixed_in_lines": []}), "must be a non-empty list"),
    (lambda a: a.update({"fixed_in_lines": "0.33.2"}), "must be a non-empty list"),
    (lambda a: a.update({"fixed_in_lines": ["0.33.2", "0.34.01"]}), "malformed"),
    (lambda a: a.update({"fixed_in": None, "mitigation": "Turn it off."}),
     "lists fixes, but fixed_in is null"),
])
def test_the_validator_rejects_a_bad_fixed_in_lines(mutate, expected):
    data = _two_lines()
    mutate(data["advisories"]["on-two-lines"])
    _reject(data, expected)


def test_a_fix_on_a_line_is_bounded_by_the_released_ceiling():
    # 0.34.1 is not released yet: naming it would disclose an unpatched issue on the 0.34 line.
    _reject(_two_lines(), "fixed_in_lines names 0.34.1 as a fix but the newest released version is "
                          "0.34.0", ceiling="0.34.0")


def test_a_line_that_began_before_the_fix_needs_its_own():
    # The fix went out only as 0.33.2, a month after 0.34.0 shipped without it: 0.34.0 is affected,
    # and nothing tells a 0.34 install what to move to. The newest line is never left out.
    data = _two_lines(fixes=("0.33.2",))
    del data["advisories"]["on-two-lines"]["fixed_in_lines"]
    del data["versions"]["0.34.0"]["vulnerabilities"]
    data["versions"]["0.34.0"]["support"] = _support(secure=True)
    _reject(data, "advisories[on-two-lines] is fixed in 0.33.2, but the 0.34 line began with 0.34.0 "
                  "on 2026-12-10, before 0.33.2 was released; name the 0.34 line's own fix in "
                  "fixed_in_lines, or 0.34.0 if it was never affected")


def test_a_line_that_was_never_affected_names_its_first_release():
    # The same issue, but 0.34.0 already had the fix when it shipped: its line's fix is 0.34.0.
    data = _two_lines(fixes=("0.33.2", "0.34.0"))
    del data["versions"]["0.34.0"]["vulnerabilities"]
    data["versions"]["0.34.0"]["support"] = _support(secure=True)
    um.validate_matrix(data, released_ceiling=None)


def _three_lines():
    """_two_lines() with a 0.35 line that began on 2027-01-08, between the two fixes' releases.

    0.33.2 is released on 2027-01-04 and 0.34.1 on 2027-01-11 here.
    """
    data = _two_lines()
    data["versions"]["0.33.2"]["released"] = "2027-01-04"
    data["versions"]["0.35.0"] = {"released": "2027-01-08", "notes": "0.35.0", "support": _support()}
    data["edges"].append({"from": "0.34.0", "to": "0.35.0", "kind": "direct", "reversible": True,
                          "requires_backup": False})
    return data


def test_a_later_line_is_checked_against_the_highest_fix_not_the_lowest():
    # 0.35.0 began after 0.33.2 but before 0.34.1, so it was cut without the 0.34 fix.
    _reject(_three_lines(), "the 0.35 line began with 0.35.0 on 2027-01-08, before 0.34.1 was released")


def test_a_line_between_two_fixes_with_none_of_its_own_stays_affected():
    # Fixed on 0.33 and 0.35; the 0.34 line in between got no fix and is affected throughout.
    data = _three_lines()
    data["versions"]["0.35.0"]["released"] = "2027-01-12"
    data["versions"]["0.35.1"] = {"released": "2027-01-13", "notes": "0.35.1", "support": _support()}
    data["edges"] += [{"from": a, "to": b, "kind": "direct", "reversible": True,
                       "requires_backup": False} for a, b in (("0.34.1", "0.35.0"), ("0.35.0", "0.35.1"))]
    # 0.33.2 cannot move into the affected 0.34 line; its way up skips to the fix on 0.35.
    data["edges"] = [e for e in data["edges"] if (e["from"], e["to"]) != ("0.33.2", "0.34.1")]
    data["edges"].append({"from": "0.33.2", "to": "0.35.1", "kind": "direct", "reversible": True,
                          "requires_backup": False})
    advisory = data["advisories"]["on-two-lines"]
    advisory["fixed_in_lines"] = ["0.33.2", "0.35.1"]
    data["versions"]["0.35.0"]["support"] = _support(secure=False)
    data["versions"]["0.35.0"]["vulnerabilities"] = [
        _ref(slug="on-two-lines", title="On two lines", fixed_in="0.35.1")]
    data["versions"]["0.34.0"]["vulnerabilities"][0]["fixed_in"] = "0.35.1"
    data["versions"]["0.34.1"]["support"] = _support(secure=False)
    data["versions"]["0.34.1"]["vulnerabilities"] = [
        _ref(slug="on-two-lines", title="On two lines", fixed_in="0.35.1")]
    um.validate_matrix(data, released_ceiling=None)
    del data["versions"]["0.34.1"]["vulnerabilities"]
    data["versions"]["0.34.1"]["support"] = _support(secure=True)
    _reject(data, "not listed on: 0.34.1")


def test_a_fix_released_the_same_day_as_the_next_line_needs_no_second_fix():
    # 0.33.1 carries the fix and 0.34.0, built on it, ships the same day: one fixed_in is exact.
    data = _valid()
    data["versions"] = {
        "0.33.0": {"released": "2026-09-29", "notes": "a", "support": _support(secure=False),
                   "vulnerabilities": [_ref(slug="same-day", title="Same day", fixed_in="0.33.1")]},
        "0.33.1": {"released": "2026-12-20", "notes": "b", "support": _support()},
        "0.34.0": {"released": "2026-12-20", "notes": "c", "support": _support()},
    }
    data["edges"] = [{"from": a, "to": b, "kind": "direct", "reversible": True,
                      "requires_backup": False} for a, b in (("0.33.0", "0.33.1"), ("0.33.1", "0.34.0"))]
    data["advisories"] = {"same-day": _advisory(title="Same day", fixed_in="0.33.1")}
    um.validate_matrix(data, released_ceiling="0.34.0")
    # One day later, 0.34.0 would have been cut before the fix and need its own.
    data["versions"]["0.34.0"]["released"] = "2026-12-19"
    _reject(data, "the 0.34 line began with 0.34.0 on 2026-12-19, before 0.33.1 was released")


def test_a_short_reference_is_refused_where_its_line_has_another_fix():
    # Readers take a short reference's fix from the advisory's fixed_in, the lowest fix. Below the
    # id-only boundary that is right for every line but one with its own, later fix.
    data = _valid()
    days = {"0.25.0": "2026-01-01", "0.26.0": "2026-01-02", "0.25.1": "2026-01-03",
            "0.26.1": "2026-01-03"}
    data["versions"] = {ver: {"released": day, "notes": ver, "support": _support()}
                        for ver, day in sorted(days.items(), key=lambda item: um._sort_key(item[0]))}
    data["edges"] = [{"from": a, "to": b, "kind": "direct", "reversible": True,
                      "requires_backup": False}
                     for a, b in (("0.25.0", "0.25.1"), ("0.25.0", "0.26.0"), ("0.26.0", "0.26.1"),
                                  ("0.25.1", "0.26.1"))]
    data["advisories"] = {"two": _advisory(title="Two", fixed_in="0.25.1",
                                           fixed_in_lines=["0.25.1", "0.26.1"])}
    for ver in ("0.25.0", "0.26.0"):
        data["versions"][ver]["support"] = _support(secure=False)
    data["versions"]["0.25.0"]["vulnerabilities"] = [{"advisory": "two"}]
    data["versions"]["0.26.0"]["vulnerabilities"] = [_ref(slug="two", title="Two", fixed_in="0.26.1")]
    um.validate_matrix(data, released_ceiling=None)
    data["versions"]["0.26.0"]["vulnerabilities"] = [{"advisory": "two"}]
    _reject(data, "versions[0.26.0].vulnerabilities[0] carries only the advisory id, but the fix for "
                  "0.26.0 is 0.26.1, not the advisory's fixed_in 0.25.1; write it in full")


def test_an_advisory_without_fixed_in_lines_reads_as_fixed_on_its_one_line():
    data = _two_lines(fixes=("0.33.2", "0.34.1"))
    single = copy.deepcopy(data["advisories"]["on-two-lines"])
    del single["fixed_in_lines"]
    assert um._fixes(single) == ["0.33.2"]
    assert um._fixes(data["advisories"]["on-two-lines"]) == ["0.33.2", "0.34.1"]
    assert um._fixes(_advisory(fixed_in=None, mitigation="m")) == []


# --- a condition that stops a rollback -----------------------------------------------------------

def _with_condition(**condition):
    data = _valid()
    data["edges"][0]["conditions"] = [{"id": "kept-rows", "summary": "Rows are kept.", **condition}]
    return data


def test_a_condition_may_say_it_blocks_a_rollback_when_its_query_finds_rows():
    um.validate_matrix(_with_condition(detect="SELECT 1 FROM held_files LIMIT 1",
                                       blocks_rollback=True), released_ceiling=None)


@pytest.mark.parametrize("condition, expected", [
    ({"detect": "SELECT 1", "blocks_rollback": False}, "blocks_rollback is only ever true"),
    ({"detect": "SELECT 1", "blocks_rollback": "true"}, "blocks_rollback is only ever true"),
    ({"detect": "SELECT 1", "blocks_rollback": 1}, "blocks_rollback is only ever true"),
    ({"blocks_rollback": True}, "blocks_rollback needs a detect query"),
    ({"detect": "SELECT 1", "blocks_rollback": True, "blocks": True}, "unknown key"),
])
def test_a_malformed_rollback_flag_is_refused(condition, expected):
    _reject(_with_condition(**condition), expected)


def test_the_readers_in_this_tree_describe_a_flagged_condition_like_any_other():
    import dockvault
    from app.services import update_check

    data = _with_condition(detect="SELECT 1 FROM held_files LIMIT 1", blocks_rollback=True)
    assert update_check.describe_hop(data, "0.1.0", "0.2.0")["conditions"] == ["Rows are kept."]
    assert [c["id"] for c in dockvault.plan_upgrade_path(data, "0.1.0", "0.2.0")["conditions"]] == [
        "kept-rows"]

# --- support periods of release lines ------------------------------------------------------------

def _lines(**lines):
    """_two_lines() with a `lines` map: 0.34.0 shipped on 2026-12-10."""
    data = _two_lines()
    data["lines"] = {line: {"security_fixes_until": until} for line, until in lines.items()}
    return data


def test_support_periods_are_accepted_when_they_keep_the_promise():
    # Six calendar months after 0.34.0 shipped (2026-12-10) is 2027-06-10.
    um.validate_matrix(_lines(**{"0.33": "2027-06-10", "0.34": None}), released_ceiling=None)
    um.validate_matrix(_lines(**{"0.34": None}), released_ceiling=None)


@pytest.mark.parametrize("lines, expected", [
    ({"0.33": None, "0.34": None},
     "lines[0.33].security_fixes_until is null, but only the newest line, 0.34, has no end date"),
    ({"0.33": "2027-06-10", "0.34": "2027-12-31"},
     "lines[0.34].security_fixes_until is 2027-12-31, but 0.34 is the newest line"),
    ({"0.33": "2027-06-10"}, "upgrade matrix 'lines' does not list 0.34"),
    ({"0.33": "2027-06-09", "0.34": None},
     "lines[0.33].security_fixes_until is 2027-06-09, but 0.34.0 was released on 2026-12-10, so "
     "the promise of 6 months after the next minor release runs to 2027-06-10"),
    ({"0.32": "2027-06-10", "0.33": "2027-06-10", "0.34": None},
     "lines[0.32]: lines start at 0.33, the first with a support period"),
    ({"0.34": None, "0.35": None}, "lines[0.35] names a line with no declared release"),
    ({"0.33": "10 June 2027", "0.34": None}, "malformed"),
    ({"0.33.0": None}, "malformed"),
])
def test_the_validator_rejects_bad_support_periods(lines, expected):
    _reject(_lines(**lines), expected)


def test_a_line_entry_names_only_its_end_of_security_fixes():
    data = _lines(**{"0.34": None})
    data["lines"]["0.34"]["code_fixes_until"] = None
    _reject(data, "unknown key")
    data = _lines(**{"0.34": None})
    data["lines"]["0.34"] = {}
    _reject(data, "lines[0.34] is missing required key(s): security_fixes_until")
    data["lines"] = {}
    _reject(data, "'lines' must be a non-empty object")


def test_six_calendar_months_end_on_the_last_day_of_a_shorter_month():
    assert um._add_months(__import__("datetime").date(2026, 8, 31), 6).isoformat() == "2027-02-28"
    assert um._add_months(__import__("datetime").date(2027, 8, 31), 6).isoformat() == "2028-02-29"
    assert um._add_months(__import__("datetime").date(2026, 12, 10), 6).isoformat() == "2027-06-10"


def _left_unfixed_on_the_older_line(published="2027-01-11", mitigation=None):
    """The advisory fixed only on the 0.34 line, leaving 0.33.2, the newest 0.33, affected."""
    data = _lines(**{"0.33": "2027-06-10", "0.34": None})
    advisory = data["advisories"]["on-two-lines"]
    advisory.update({"fixed_in": "0.34.1", "fixed_in_lines": ["0.34.1"], "published": published,
                     "mitigation": mitigation})
    for ver in ("0.32.6", "0.33.0", "0.33.1", "0.33.2", "0.34.0"):
        data["versions"][ver]["support"] = _support(secure=False)
        data["versions"][ver]["vulnerabilities"] = [
            _ref(slug="on-two-lines", title="On two lines", fixed_in="0.34.1")]
    return data


def test_an_advisory_that_leaves_a_supported_line_affected_needs_a_mitigation():
    _reject(_left_unfixed_on_the_older_line(),
            "advisories[on-two-lines] leaves 0.33.2, the newest release of the 0.33 line, affected "
            "while that line is supported, and has no mitigation")
    um.validate_matrix(_left_unfixed_on_the_older_line(mitigation="Turn the feature off."),
                       released_ceiling=None)


def test_a_line_whose_support_had_ended_needs_no_mitigation():
    # Published after 0.33's support ended: that line is no longer promised a fix.
    um.validate_matrix(_left_unfixed_on_the_older_line(published="2027-06-11"),
                       released_ceiling=None)
    _reject(_left_unfixed_on_the_older_line(published="2027-06-10"), "has no mitigation")


def test_the_gate_warns_from_the_same_field():
    # The release gate reads lines[X.Y].security_fixes_until for its support-date warning.
    import datetime

    data = _lines(**{"0.33": "2027-06-10", "0.34": None})
    assert gate.line_support_warning(data, "0.33.3", datetime.date(2027, 6, 10)) is None
    assert "ended on 2027-06-10" in gate.line_support_warning(data, "0.33.3",
                                                              datetime.date(2027, 6, 11))


def test_the_committed_matrix_takes_the_lines_map_its_next_release_writes():
    # Until a release commit writes `lines`, the next one adds the newest line with no end date.
    data = um.load_matrix(MATRIX_PATH)
    if "lines" not in data:
        newest = max(data["versions"], key=um._sort_key)
        data["lines"] = {um._line(newest): {"security_fixes_until": None}}
    um.validate_matrix(data, released_ceiling=None)


# --- routes across lines ---------------------------------------------------------------------------
# _two_lines(): 0.33.2 (the fix on 0.33) leads up by the edge 0.33.2 -> 0.34.1, which skips 0.34.0.
# The route of steps it replaces is 0.33.1 -> 0.34.0 -> 0.34.1.

def _edge_between(data, source, target):
    return next(e for e in data["edges"] if (e["from"], e["to"]) == (source, target))


def _without_edge(data, source, target):
    data["edges"] = [e for e in data["edges"] if (e["from"], e["to"]) != (source, target)]
    return data


def test_a_maintenance_release_with_no_way_up_is_refused():
    _reject(_without_edge(_two_lines(), "0.33.2", "0.34.1"),
            "0.33.2 cannot reach 0.34.1 by edges that are not blocked")
    data = _two_lines()
    _edge_between(data, "0.33.2", "0.34.1").update({"kind": "blocked", "reason": "not this way"})
    _reject(data, "0.33.2 cannot reach 0.34.1 by edges that are not blocked")


def test_an_edge_into_a_release_the_fix_leaves_affected_is_refused():
    data = _without_edge(_two_lines(), "0.33.2", "0.34.1")
    data["edges"].append({"from": "0.33.2", "to": "0.34.0", "kind": "direct", "reversible": True,
                          "requires_backup": False})
    _reject(data, "the edge 0.33.2 -> 0.34.0 brings back on-two-lines: 0.34.0 is affected and 0.33.2 "
                  "is not; an upgrade must not reinstate a fixed vulnerability")
    # Kept as a blocked edge beside the way up, it is no route, so it reinstates nothing.
    data = _two_lines()
    data["edges"].append({"from": "0.33.2", "to": "0.34.0", "kind": "blocked", "reversible": False,
                          "requires_backup": True, "reason": "0.34.0 is affected; go to 0.34.1"})
    um.validate_matrix(data, released_ceiling=None)


def test_an_edge_into_the_release_that_introduced_a_vulnerability_is_not_a_regression():
    data = _two_lines()
    data["advisories"]["new-in-0-34"] = _advisory(title="New in 0.34", fixed_in="0.34.1")
    data["versions"]["0.34.0"]["vulnerabilities"].append(
        _ref(slug="new-in-0-34", title="New in 0.34", fixed_in="0.34.1"))
    um.validate_matrix(data, released_ceiling=None)            # 0.33.1 -> 0.34.0 brings it in first


@pytest.mark.parametrize("step", [("0.33.1", "0.34.0"), ("0.34.0", "0.34.1")])
def test_a_skip_edge_is_as_cautious_as_the_route_it_replaces(step):
    data = _two_lines()
    _edge_between(data, *step).update({"requires_backup": True})
    _reject(data, "the edge 0.33.2 -> 0.34.1 must require a backup: the route it replaces, "
                  "0.33.1 -> 0.34.0 -> 0.34.1, does")
    _edge_between(data, "0.33.2", "0.34.1")["requires_backup"] = True
    um.validate_matrix(data, released_ceiling=None)

    data = _two_lines()
    _edge_between(data, *step).update({"reversible": False, "requires_backup": True})
    _edge_between(data, "0.33.2", "0.34.1")["requires_backup"] = True
    _reject(data, "the edge 0.33.2 -> 0.34.1 cannot be reversible: the route it replaces, "
                  "0.33.1 -> 0.34.0 -> 0.34.1, is not")
    _edge_between(data, "0.33.2", "0.34.1")["reversible"] = False
    um.validate_matrix(data, released_ceiling=None)


def test_a_skip_edge_carries_every_condition_of_the_route_it_replaces():
    data = _two_lines()
    crossing = {"id": "crossing-note", "summary": "Said on the way into 0.34."}
    in_line = {"id": "patch-note", "summary": "Said on the way to 0.34.1."}
    _edge_between(data, "0.33.1", "0.34.0")["conditions"] = [crossing]
    _edge_between(data, "0.34.0", "0.34.1")["conditions"] = [in_line]
    _edge_between(data, "0.33.2", "0.34.1")["conditions"] = [in_line]
    _reject(data, "the edge 0.33.2 -> 0.34.1 leaves out the condition(s) crossing-note of the route "
                  "it replaces, 0.33.1 -> 0.34.0 -> 0.34.1")
    _edge_between(data, "0.33.2", "0.34.1")["conditions"] = [crossing]
    _reject(data, "leaves out the condition(s) patch-note")
    _edge_between(data, "0.33.2", "0.34.1")["conditions"] = [
        in_line, crossing, {"id": "own-note", "summary": "Only this way."}]
    um.validate_matrix(data, released_ceiling=None)


def test_a_skip_edge_never_passes_a_release_an_upgrade_must_land_on():
    data = _two_lines()
    data["versions"]["0.34.0"]["must_land_here"] = True
    _reject(data, "the edge 0.33.2 -> 0.34.1 passes 0.34.0, where an upgrade must land "
                  "(must_land_here); the route it replaces is 0.33.1 -> 0.34.0 -> 0.34.1")
    data["versions"]["0.34.0"]["must_land_here"] = False
    um.validate_matrix(data, released_ceiling=None)


def test_a_skip_edge_may_end_on_a_release_an_upgrade_must_land_on():
    # Landing there is what must_land_here asks for; only passing it is refused.
    data = _two_lines()
    data["versions"]["0.34.1"]["must_land_here"] = True
    um.validate_matrix(data, released_ceiling=None)


def test_a_skip_edge_over_a_blocked_step_is_refused():
    data = _two_lines()
    _edge_between(data, "0.33.1", "0.34.0").update({"kind": "blocked", "reversible": False,
                                                     "requires_backup": True, "reason": "no"})
    _reject(data, "the edge 0.33.2 -> 0.34.1 skips releases, but no route of steps that are not "
                  "blocked leads from 0.33.2, or a lower release of its line, to 0.34.1")


def test_the_route_a_skip_replaces_leaves_the_line_from_the_highest_release_that_can():
    data = _two_lines()
    older = {"id": "from-0-33-0-only", "summary": "What moving from 0.33.0 involves."}
    data["edges"].append({"from": "0.33.0", "to": "0.34.0", "kind": "direct", "reversible": True,
                          "requires_backup": False, "conditions": [older]})
    um.validate_matrix(data, released_ceiling=None)            # replaced: 0.33.1 -> 0.34.0 -> 0.34.1
    _edge_between(data, "0.33.1", "0.34.0").update({"kind": "blocked", "reversible": False,
                                                     "requires_backup": True, "reason": "no"})
    _reject(data, "leaves out the condition(s) from-0-33-0-only of the route it replaces, "
                  "0.33.0 -> 0.34.0 -> 0.34.1")


def test_a_skip_within_a_line_replaces_the_releases_in_between():
    data = _two_lines()
    data["edges"].append({"from": "0.33.0", "to": "0.33.2", "kind": "direct", "reversible": True,
                          "requires_backup": False})
    um.validate_matrix(data, released_ceiling=None)
    _edge_between(data, "0.33.1", "0.33.2")["requires_backup"] = True
    _reject(data, "the edge 0.33.0 -> 0.33.2 must require a backup: the route it replaces, "
                  "0.33.0 -> 0.33.1 -> 0.33.2, does")


def test_a_skip_over_a_whole_line_replaces_the_route_through_it():
    data = _two_lines()
    data["versions"]["0.35.0"] = {"released": "2027-02-01", "notes": "0.35.0", "support": _support()}
    data["edges"] += [
        {"from": "0.34.1", "to": "0.35.0", "kind": "direct", "reversible": False,
         "requires_backup": True},
        {"from": "0.33.2", "to": "0.35.0", "kind": "direct", "reversible": True,
         "requires_backup": False}]
    _reject(data, "the edge 0.33.2 -> 0.35.0 must require a backup: the route it replaces, "
                  "0.33.1 -> 0.34.0 -> 0.34.1 -> 0.35.0, does")
    _edge_between(data, "0.33.2", "0.35.0").update({"reversible": False, "requires_backup": True})
    um.validate_matrix(data, released_ceiling=None)


def test_an_edge_leads_upwards():
    data = _two_lines()
    data["edges"].append({"from": "0.34.1", "to": "0.33.2", "kind": "direct", "reversible": True,
                          "requires_backup": False})
    _reject(data, f"edges[{len(data['edges']) - 1}] goes from 0.34.1 down to 0.33.2")


# --- coverage: an advisory affects an unbroken run of releases ------------------------------------

def test_an_advisory_affects_every_release_up_to_its_fix():
    data = _three_releases()
    data["advisories"] = {"a-fixed-issue": _advisory(fixed_in="0.3.0")}
    for ver in ("0.1.0", "0.2.0"):
        data["versions"][ver]["support"] = _support(secure=False)
        data["versions"][ver]["vulnerabilities"] = [_ref(fixed_in="0.3.0")]
    um.validate_matrix(data, released_ceiling=None)
    # Forget 0.2.0 and an operator running it is told nothing.
    data["versions"]["0.2.0"]["vulnerabilities"] = []
    data["versions"]["0.2.0"]["support"] = _support(secure=True)
    _reject(data, "not listed on: 0.2.0")


def test_an_advisory_no_version_lists_is_rejected():
    data = _valid_with_vuln()
    data["advisories"]["an-orphan"] = _advisory(title="Orphan")
    _reject(data, "advisories[an-orphan] is listed by no version")


# --- an advisory with no fix yet ------------------------------------------------------------------

def _unfixed(mitigation="Turn the feature off until the fix ships."):
    """_three_releases() with an unfixed advisory introduced in 0.2.0 and still present in 0.3.0."""
    data = _three_releases()
    data["advisories"] = {"not-fixed-yet": _advisory(title="Not fixed yet", fixed_in=None,
                                                       mitigation=mitigation)}
    for ver in ("0.2.0", "0.3.0"):
        data["versions"][ver]["support"] = _support(secure=False)
        data["versions"][ver]["vulnerabilities"] = [
            _ref(slug="not-fixed-yet", title="Not fixed yet", fixed_in=None)]
    return data


def test_an_unfixed_advisory_is_accepted_with_a_mitigation():
    # Including below a release ceiling: there is no fix for the ceiling to bound.
    um.validate_matrix(_unfixed(), released_ceiling="0.3.0")


def test_an_unfixed_advisory_without_a_mitigation_is_rejected():
    # With nothing for an operator to do, publishing an unpatched issue would only help an attacker.
    _reject(_unfixed(mitigation=None), "has no fix (fixed_in null) and no mitigation")


def test_an_unfixed_advisory_runs_to_the_newest_release():
    data = _unfixed()
    data["versions"]["0.3.0"]["vulnerabilities"] = []
    data["versions"]["0.3.0"]["support"] = _support(secure=True)
    _reject(data, "fixed in no release yet, so every release in between is affected too; "
                  "not listed on: 0.3.0")


def test_an_unfixed_advisory_makes_the_newest_release_insecure():
    data = _unfixed()
    data["versions"]["0.3.0"]["support"] = _support(secure=True)
    _reject(data, "versions[0.3.0] is marked support.secure but lists 1")


# --- secure/insecure and the itemisation rule (unchanged behaviour) -------------------------------

def _matrix_reaching_0_29_0():
    """_valid() extended with 0.28.0 (insecure) and 0.29.0, and the edges that reach them."""
    m = _valid()
    m["versions"]["0.28.0"] = {"released": "2026-09-04", "notes": "device sync",
                               "support": _support(secure=False)}
    m["versions"]["0.29.0"] = {"released": "2026-09-15", "notes": "later",
                               "support": _support(secure=True)}
    m["edges"] += [
        {"from": "0.2.0", "to": "0.28.0", "kind": "direct", "reversible": True, "requires_backup": False},
        {"from": "0.28.0", "to": "0.29.0", "kind": "direct", "reversible": True, "requires_backup": False},
    ]
    return m


def test_an_insecure_version_from_0_28_0_on_must_name_its_vulnerabilities():
    # 0.28.0 is insecure with no list: from 0.28.0 on that is a validation error, so the file cannot
    # silently declare a release unsafe without saying what is wrong (and how to escape it).
    _reject(_matrix_reaching_0_29_0(), "must name its known")


def test_such_a_version_validates_once_it_lists_a_fixed_vulnerability():
    data = _matrix_reaching_0_29_0()
    data["advisories"] = {"t": _advisory(title="t", fixed_in="0.29.0")}
    data["versions"]["0.28.0"]["vulnerabilities"] = [_ref(slug="t", title="t", fixed_in="0.29.0")]
    um.validate_matrix(data, released_ceiling=None)


def test_an_insecure_version_before_0_28_0_need_not_itemise():
    # The pre-0.28.0 end-of-life releases carry a bare secure:false with no itemisation, by decision;
    # the rule only bites from 0.28.0 on.
    data = _valid()
    data["versions"]["0.1.0"]["support"] = _support(secure=False)
    um.validate_matrix(data, released_ceiling=None)


def _matrix_with_a_fix_in_the_newest_version():
    """0.28.0 and 0.29.0 are insecure and each name a later fix; 0.30.0 is the newest and secure."""
    m = _valid()
    m["advisories"] = {"a": _advisory(title="a", fixed_in="0.29.0"),
                       "b": _advisory(title="b", fixed_in="0.30.0")}
    m["versions"]["0.28.0"] = {"released": "2026-09-04", "notes": "x", "support": _support(secure=False),
                               "vulnerabilities": [_ref(slug="a", title="a", fixed_in="0.29.0")]}
    m["versions"]["0.29.0"] = {"released": "2026-09-15", "notes": "y", "support": _support(secure=False),
                               "vulnerabilities": [_ref(slug="b", title="b", fixed_in="0.30.0")]}
    m["versions"]["0.30.0"] = {"released": "2026-09-20", "notes": "z", "support": _support(secure=True)}
    m["edges"] += [
        {"from": "0.2.0", "to": "0.28.0", "kind": "direct", "reversible": True, "requires_backup": False},
        {"from": "0.28.0", "to": "0.29.0", "kind": "direct", "reversible": True, "requires_backup": False},
        {"from": "0.29.0", "to": "0.30.0", "kind": "direct", "reversible": True, "requires_backup": False},
    ]
    return m


def test_a_fix_in_an_unreleased_version_is_rejected_below_the_ceiling():
    # b names 0.30.0 as its fix. With the newest released version at 0.29.1, 0.30.0 does not exist
    # yet -- listing it would disclose an unpatched issue -- so validation is refused.
    _reject(_matrix_with_a_fix_in_the_newest_version(),
            "names 0.30.0 as the fix but the newest released", ceiling="0.29.1")


def test_the_same_fix_is_accepted_once_its_version_is_released():
    # In the release commit that cuts 0.30.0 the ceiling rises to 0.30.0, and the same entry passes.
    data = _matrix_with_a_fix_in_the_newest_version()
    um.validate_matrix(data, released_ceiling="0.30.0")
    # And with no ceiling supplied the check is simply not applied (the declared-and-later rule holds).
    um.validate_matrix(data, released_ceiling=None)


#: The 0.29.1-era defect titles. Every version released BEFORE 0.29.1 must keep listing these as
#: fixed_in 0.29.1, so a later release appending its own defects cannot silently drop them. Titles,
#: not a count -- a future release adds more entries to these same versions.
_VULNS_FIXED_IN_0_29_1 = {
    "Temporary-credential sessions could manage devices",
    "Sign-in and credential minting failed or consumed a credential when the session cache was unavailable",
}


def test_the_committed_matrix_holds_its_vulnerability_invariants():
    # Durable invariants of the COMMITTED docs/upgrade-matrix.json (never a fixture), so this survives
    # every future release commit instead of snapshotting one release's state.
    data = um.load_matrix(MATRIX_PATH)
    versions, advisories = data["versions"], data["advisories"]

    # (a) MEMBERSHIP: 0.28.0 and 0.29.0 each still list the 0.29.1-era titles, fixed_in 0.29.1.
    for ver in ("0.28.0", "0.29.0"):
        by_title = {v["title"]: v for v in (versions[ver].get("vulnerabilities") or [])}
        for title in _VULNS_FIXED_IN_0_29_1:
            assert title in by_title, f"{ver} no longer lists the 0.29.1-fixed defect {title!r}"
            assert by_title[title]["fixed_in"] == "0.29.1", f"{ver}:{title!r} must be fixed_in 0.29.1"

    # (b) FIXED_IN STRICTLY LATER, over EVERY version: the release that fixes a defect never lists it.
    # A reference that carries only the advisory id (below the id-only boundary) takes the fix from
    # the advisory, as every reader that accepts it does.
    for ver, meta in versions.items():
        for v in (meta.get("vulnerabilities") or []):
            fixed_in = v.get("fixed_in", advisories[v["advisory"]]["fixed_in"])
            if fixed_in is not None:
                assert um._sort_key(fixed_in) > um._sort_key(ver), (
                    f"{ver} lists {v['advisory']} with fixed_in={fixed_in}, "
                    f"which is not strictly later than {ver}")

    # (c) SECURE DERIVED: any version carrying a vulnerability entry reads support.secure false.
    for ver, meta in versions.items():
        if meta.get("vulnerabilities"):
            assert meta["support"]["secure"] is False, (
                f"{ver} lists vulnerabilities but is marked support.secure true")

    # (d) ONE RECORD PER FINDING: what an older reader sees on each version (title, fixed_in) is the
    # advisory's own, so the two can never tell an operator different things. Below the id-only
    # boundary a reference may carry the id alone and say nothing of its own.
    for ver, meta in versions.items():
        for v in (meta.get("vulnerabilities") or []):
            advisory = advisories[v["advisory"]]
            if set(v) == {"advisory"}:
                assert um._sort_key(ver) < um._sort_key(um.ID_ONLY_REFERENCES_BELOW), (
                    f"{ver}:{v['advisory']} carries only the advisory id")
                continue
            # A fix released on several lines: each version names its own line's.
            fix = um._fix_for(ver, um._fixes(advisory))
            assert (v["title"], v["fixed_in"]) == (advisory["title"], fix), (
                f"{ver}:{v['advisory']} disagrees with its advisory")


def test_the_committed_matrix_stays_well_inside_what_its_readers_will_read():
    # Readers cap what they fetch (the validator at MAX_BYTES; deployed tools, apps and the
    # documentation site at 512 KiB in every supported release) and fall back SILENTLY when the file
    # is larger -- losing every advisory with it. Storing each finding once is what keeps the file
    # from growing by a full record per affected release, but each affected release still repeats the
    # advisory's title and fixed_in, because the readers in 0.30.x dedupe and print by those two
    # fields and have no advisories map. An advisory that reaches back to the first release therefore
    # adds about 10 KB. The warning line is three quarters of the validator's cap, which still leaves
    # a margin before a release is refused.
    #
    # The cap was raised once, from 256 to 448 KiB in 0.33.0, when that release's eight advisories
    # took the file to 283,912 bytes, past the old cap. That raise was safe because it stays below
    # every reader: the smallest limit any supported reader has is 512 KiB, so a file the validator
    # passes is still one they all read, with 64 KiB to spare. There is no such room for another.
    # The other lever is the short form: a reference below the validator's ID_ONLY_REFERENCES_BELOW
    # may carry only the advisory id, which the readers accept from 0.33.0 on, and a release commit
    # writes it with `matrix_sync.py compact` (283,912 bytes become 217,553). The boundary sits
    # where the host tools of 0.30.0 to 0.32.x stop listing releases from the repeated fields; it
    # can rise as the releases in their list move up, never fall.
    size = MATRIX_PATH.stat().st_size
    assert size < um.MAX_BYTES * 3 // 4, f"docs/upgrade-matrix.json is {size} bytes"
    # The cap itself stays below the smallest reader's limit, or the validator would pass a file a
    # deployed reader drops; and the file 0.33.0 publishes (283,912 bytes with its advisories) sits
    # inside the warning line, with room for a few more.
    assert um.MAX_BYTES <= 512 * 1024 - 64 * 1024
    assert 240_000 < um.MAX_BYTES * 3 // 4


def test_the_shapes_a_real_non_trivial_upgrade_will_need_are_accepted():
    """Both richer edge shapes, so the rejections above are not all the schema is exercised against.

    Not hypothetical: the next release already needs the first one. The boot DDL now lowercases
    every email behind a unique index, and where two accounts differ only in case the index is
    skipped and the deployment boots without it -- an upgrade that is direct, but not unconditional.
    """
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}
    # An end-of-life release carrying an extended-support tail: code fixes ended, security fixes run
    # on for a while -- the shape a real product uses, exercised here so the schema is proven to accept it.
    data["versions"]["0.4.0"] = {"released": "2026-01-04", "notes": "fourth",
                                 "support": _support(eol=True, secure=True,
                                                     code_support="2026-06-01",
                                                     security_support="2026-12-01")}
    data["edges"].append({
        "from": "0.2.0", "to": "0.3.0", "kind": "direct",
        "reversible": False, "requires_backup": True,
        "conditions": [{
            "id": "email-case-collision",
            "summary": "Two accounts whose addresses differ only in case keep working, but the "
                       "case-insensitive unique index is not created.",
            "detect": "SELECT lower(email) FROM users GROUP BY 1 HAVING count(*) > 1",
        }],
    })
    data["edges"].append({
        "from": "0.3.0", "to": "0.4.0", "kind": "blocked",
        "reversible": False, "requires_backup": True,
        "reason": "the 0.4.0 boot rewrites a column 0.3.0 still writes to.",
    })
    # A blocked route into the newest release leaves every release below it end-of-life, as the
    # floor release did: an install there has no way up in place.
    for ver in ("0.1.0", "0.2.0", "0.3.0"):
        data["versions"][ver]["support"] = _support(eol=True)
    um.validate_matrix(data, released_ceiling=None)


def test_parsing_refuses_oversized_and_malformed_input(tmp_path):
    big = tmp_path / "big.json"
    big.write_bytes(b"{" + b" " * (um.MAX_BYTES + 1) + b"}")
    with pytest.raises(um.UpgradeMatrixError, match="larger than"):
        um.load_matrix(big)

    bom = tmp_path / "bom.json"
    bom.write_bytes(b"\xef\xbb\xbf{}")
    with pytest.raises(um.UpgradeMatrixError, match="BOM"):
        um.load_matrix(bom)

    broken = tmp_path / "broken.json"
    broken.write_text("{not json", encoding="utf-8")
    with pytest.raises(um.UpgradeMatrixError, match="not valid UTF-8 JSON"):
        um.load_matrix(broken)

    listy = tmp_path / "list.json"
    listy.write_text("[]", encoding="utf-8")
    with pytest.raises(um.UpgradeMatrixError, match="must be a JSON object"):
        um.load_matrix(listy)

    with pytest.raises(um.UpgradeMatrixError, match="cannot read"):
        um.load_matrix(tmp_path / "absent.json")


# --- what the gate does with it ------------------------------------------------------------------

def test_an_undeclared_release_is_refused():
    data = _valid()
    with pytest.raises(um.UpgradeMatrixError, match="no entry"):
        um.assert_release_declared(data, "0.3.0")


def test_a_declared_release_with_no_way_in_is_refused():
    """A version entry alone is a name, not a declaration."""
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}
    with pytest.raises(um.UpgradeMatrixError, match="no edge from 0.2.0"):
        um.assert_release_declared(data, "0.3.0")


def test_the_earliest_release_needs_no_inbound_edge():
    um.assert_release_declared(_valid(), "0.1.0")


def _repo(tmp_path, version, matrix):
    """A throwaway repository shaped the way the gate expects: one commit, one tag, on main."""
    # newline="" so the LF survives: Python's text mode rewrites it to CRLF on Windows, and the
    # gate rejects a VERSION that is not exactly X.Y.Z followed by one LF -- correctly, since that
    # is a real way for a release to be malformed.
    (tmp_path / "VERSION").write_text(version + "\n", encoding="utf-8", newline="")
    (tmp_path / "docs").mkdir(exist_ok=True)
    (tmp_path / "docs" / "upgrade-matrix.json").write_text(
        json.dumps(matrix), encoding="utf-8", newline="")

    def git(*args, check=True):
        done = subprocess.run(["git", *args], cwd=tmp_path, capture_output=True, text=True,
                              timeout=60)
        if check:
            assert done.returncode == 0, " ".join(args) + ": " + (done.stderr or "")[:300]
        return done

    git("init", "-q", "-b", "main")
    git("config", "user.email", "test@example.test")
    git("config", "user.name", "test")
    git("config", "tag.gpgsign", "false")
    git("add", "-A")
    git("commit", "-qm", version)
    # Tag every version the matrix declares, not only the one being cut: the gate now checks that
    # a declared version corresponds to a real release, so a fixture that declares versions it
    # never tagged is describing a repository that could not exist. Annotated, as release tags are:
    # the gate refuses a lightweight one for the release it cuts.
    for declared in sorted(set(matrix.get("versions", {})) | {version}):
        git("tag", "-a", f"v{declared}", "-m", f"release {declared}")
    # The gate requires the tagged commit to be an ancestor of the main ref it is given.
    return tmp_path


def _run_gate(repo, version, tmp_path, **kwargs):
    return gate.validate_release(
        repo,
        ref=f"refs/tags/v{version}",
        event_sha="HEAD",
        main_ref="main",
        repository_owner="DockVault",
        **kwargs,
    )


def test_the_gate_refuses_a_release_the_matrix_does_not_declare(tmp_path):
    """The whole point: you cannot cut a release without saying how to reach it."""
    matrix = _valid()
    repo = _repo(tmp_path, "0.3.0", matrix)
    with pytest.raises(gate.ReleaseGateError, match="no entry in docs/upgrade-matrix.json"):
        _run_gate(repo, "0.3.0", tmp_path)


def test_the_gate_passes_a_declared_release(tmp_path):
    matrix = _valid()
    matrix["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}
    matrix["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                            "reversible": True, "requires_backup": False})
    repo = _repo(tmp_path, "0.3.0", matrix)
    metadata = _run_gate(repo, "0.3.0", tmp_path)
    assert metadata.version == "0.3.0"
    assert metadata.upgrade_entry_waived is False




def test_an_inbound_edge_marked_blocked_is_not_a_way_in(tmp_path):
    """A release whose only route in says "do not take this route" has not declared a route.

    The gate originally compared only (from, to) and ignored kind, so a blocked edge satisfied it --
    the matrix would say in so many words that the upgrade must not be taken, and the tag would be
    cut anyway.
    """
    matrix = _valid()
    matrix["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}
    matrix["versions"]["0.4.0"] = {"released": "2026-01-04", "notes": "fourth", "support": _support()}
    matrix["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                            "reversible": True, "requires_backup": False})
    matrix["edges"].append({
        "from": "0.3.0", "to": "0.4.0", "kind": "blocked",
        "reversible": False, "requires_backup": True,
        "reason": "0.4.0 rewrites a column 0.3.0 still writes to.",
    })
    for ver in ("0.1.0", "0.2.0", "0.3.0"):                  # below a blocked way up, as the floor
        matrix["versions"][ver]["support"] = _support(eol=True)
    repo = _repo(tmp_path, "0.4.0", matrix)
    with pytest.raises(gate.ReleaseGateError, match="marked blocked"):
        _run_gate(repo, "0.4.0", tmp_path)


def test_a_waiver_in_the_file_lets_an_undeclared_release_through(tmp_path):
    """The escape hatch, which lives in the matrix rather than in a command-line flag.

    A flag would have to be threaded through a tag-triggered workflow to be reachable at all, and
    once passed it would leave no trace in anything published -- a waived release would look exactly
    like a declared one. Declared in the file, the omission is in the release commit, in the diff,
    and in the published asset.
    """
    matrix = _valid()
    matrix["waivers"] = [{"version": "0.3.0", "reason": "security fix; path declared next release"}]
    repo = _repo(tmp_path, "0.3.0", matrix)
    metadata = _run_gate(repo, "0.3.0", tmp_path)
    assert metadata.upgrade_entry_waived is True


def test_a_waiver_does_not_excuse_a_broken_file(tmp_path):
    """The distinction the hatch exists for.

    Shipping without a declared upgrade path is a judgement call a maintainer can make. Shipping a
    matrix that does not validate is not: it breaks the published asset and every consumer of it,
    for every version, not only this one.
    """
    broken = _valid()
    broken["waivers"] = [{"version": "0.3.0", "reason": "urgent"}]
    broken["edges"][0]["to"] = "9.9.9"
    repo = _repo(tmp_path, "0.3.0", broken)
    with pytest.raises(gate.ReleaseGateError, match="not a declared version"):
        _run_gate(repo, "0.3.0", tmp_path)


def test_a_waiver_goes_stale_once_the_version_is_declared():
    """So the hatch cannot quietly become the normal route.

    Left in place, a waiver would keep excusing a version that no longer needs excusing, and the
    next person to read the file would find a permanent-looking exemption.
    """
    data = _valid()
    data["waivers"] = [{"version": "0.2.0", "reason": "no longer true"}]
    with pytest.raises(um.UpgradeMatrixError, match="declared and reachable"):
        um.validate_matrix(data, released_ceiling=None)


def test_a_waiver_may_cover_a_declared_floor_release_reached_only_by_a_blocked_edge():
    """The floor case: a version that carries its own entry (notes, lifecycle) but whose only route
    in is a blocked edge -- reached by fresh deploy + restore, not an in-place upgrade. The waiver is
    what lets it be cut; the blocked edge is why the upgrade is refused. This must NOT be a stale
    waiver, unlike a declared+reachable version."""
    data = _valid()
    data["edges"][0]["kind"] = "blocked"
    data["edges"][0]["reason"] = "no in-place upgrade; deploy fresh and restore"
    data["versions"]["0.1.0"]["support"] = _support(eol=True)  # below the floor, as in the real file
    data["waivers"] = [{"version": "0.2.0", "reason": "floor release, reached by restore only"}]
    um.validate_matrix(data, released_ceiling=None)                                  # accepted, not stale
    # And the gate lets it be cut, returning the waiver reason rather than refusing on the blocked edge.
    assert "floor release" in (um.assert_release_declared(data, "0.2.0") or "")


def test_the_waiver_is_reported_as_a_job_output(tmp_path):
    """The workflow exports this; a waiver the workflow cannot see cannot be acted on."""
    matrix = _valid()
    matrix["waivers"] = [{"version": "0.3.0", "reason": "urgent"}]
    repo = _repo(tmp_path, "0.3.0", matrix)
    out = tmp_path / "gh-output"
    gate.write_github_outputs(out, _run_gate(repo, "0.3.0", tmp_path))
    assert "upgrade_entry_waived=true" in out.read_text(encoding="utf-8")

    gate.write_github_outputs(
        out, gate.ReleaseMetadata(version="0.3.0", tag="v0.3.0", sha="abc", image="x"))
    assert "upgrade_entry_waived=false" in out.read_text(encoding="utf-8")


def test_the_workflow_exports_the_waiver_output():
    """Written by the script AND declared by the job, or nothing downstream can read it.

    Checked because the first version of this wrote the value to GITHUB_OUTPUT and stopped there:
    the job did not export it, so it was invisible to every later job, and the commit message
    claimed an audit trail that did not exist.
    """
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    validate_job = workflow.split("  validate:", 1)[1].split("\n  tests:", 1)[0]
    outputs = validate_job.split("outputs:", 1)[1].split("steps:", 1)[0]
    assert "upgrade_entry_waived:" in outputs, (
        "the validate job does not export upgrade_entry_waived, so no later job can see it")


def test_a_release_with_no_matrix_at_all_is_refused(tmp_path):
    """The gate must fail closed when the file is missing, not treat absence as nothing to check."""
    repo = _repo(tmp_path, "0.2.0", _valid())
    (repo / "docs" / "upgrade-matrix.json").unlink()
    with pytest.raises(gate.ReleaseGateError, match="cannot read"):
        _run_gate(repo, "0.2.0", tmp_path)


# --- the workflow ---------------------------------------------------------------------------

def _publish_steps():
    """The publish job's steps, in order, as (name, body) pairs.

    Parsed from the text rather than with a YAML library. PyYAML is not in the test lock, and the
    lock is pip-compile generated and guarded by a supply-chain contract, so adding a dependency
    for two assertions is not proportionate. This is scoped to one file with consistent
    indentation, and it fails loudly if that shape changes rather than passing quietly.
    """
    import re

    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    publish = workflow.split("\n  publish:\n", 1)
    assert len(publish) == 2, "the publish job has been renamed"
    # Up to the next top-level job, which is a name at exactly two spaces of indent. Splitting on
    # "\n  " alone stops at the very next line instead, since every nested line starts with it.
    body = re.split(r"\n  [A-Za-z_][\w-]*:\n", publish[1], maxsplit=1)[0]
    chunks = body.split("\n      - ")[1:]
    assert len(chunks) > 3, f"only found {len(chunks)} steps in publish; the shape has changed"
    steps = []
    for chunk in chunks:
        first = chunk.splitlines()[0]
        name = first.split("name:", 1)[1].strip() if first.startswith("name:") else first.strip()
        steps.append((name, chunk))
    return steps


def test_the_release_workflow_publishes_the_matrix_verbatim():
    """The asset has to be the file the gate validated.

    Checked for ORDER and for being unconditional, not just for the presence of a string. The grep
    version of this passed for a step that had been disabled with `if: false`, moved after the
    release, or dropped into a job with no checkout -- it asserted a rename, not a contract.
    """
    steps = _publish_steps()
    names = [name for name, _ in steps]

    staging = [i for i, n in enumerate(names) if "upgrade matrix" in n.lower()]
    release = [i for i, n in enumerate(names) if n == "Create GitHub Release"]
    assert staging, f"no step stages the upgrade matrix; steps are {names}"
    assert release, f"no step creates the release; steps are {names}"
    assert staging[0] < release[0], "the matrix is staged after the release is created"
    assert "\n        if:" not in steps[staging[0]][1], (
        "the staging step is now conditional, so the asset can be silently omitted")

    files = steps[release[0]][1].split("files:", 1)
    assert len(files) == 2, "the release step no longer lists files"
    assert "upgrade.json" in files[1], f"upgrade.json is not attached; block is {files[1][:200]!r}"


def test_staging_the_asset_reproduces_the_committed_file_byte_for_byte(tmp_path):
    """Run the staging command for real, rather than trusting that `cp` means what it says.

    If it is ever replaced by a generator this fails, which is the point: a re-serialised copy
    would be valid JSON and could still disagree with the repository it claims to describe.
    """
    import shutil

    steps = dict(_publish_steps())
    name = next(n for n in steps if "upgrade matrix" in n.lower())
    command = steps[name].split("run:", 1)[1].strip().splitlines()[0].strip()
    assert command.startswith("cp "), (
        f"the asset is no longer a straight copy ({command!r}); prove the published file still "
        "matches the committed one")

    source, destination = command.split()[1:3]
    shutil.copy(ROOT / source, tmp_path / destination)
    assert (tmp_path / destination).read_bytes() == (ROOT / source).read_bytes()
    assert (ROOT / source) == MATRIX_PATH, (
        f"the staged file is {source}, not the one the gate validates")


def test_every_workflow_that_runs_pytest_fetches_tags():
    """Because fixing one of them and assuming the rest is how this went wrong the first time.

    The check above compares the matrix against the releases that exist, and it reads them from
    `git tag -l`. actions/checkout does not fetch tags by default, so any workflow that runs the
    suite without asking for them turns that check into a hard failure -- which is the designed
    behaviour, but it should be caught here rather than discovered in CI.

    File-level rather than per-step: a workflow that runs pytest anywhere and never asks for tags
    is the regression worth catching, and matching checkout blocks to jobs would be more parsing
    than the question deserves.
    """
    workflows = ROOT / ".github" / "workflows"
    offenders = []
    for path in sorted(workflows.glob("*.yml")):
        text = path.read_text(encoding="utf-8")
        if "-m pytest" not in text or "actions/checkout" not in text:
            continue
        if "fetch-tags: true" not in text and "fetch-depth: 0" not in text:
            offenders.append(path.name)
    assert not offenders, (
        "these workflows run pytest but check out without tags, so the released-versions check "
        f"will fail in them: {', '.join(offenders)}. Add `fetch-tags: true` to their checkout")


# --- what the last round of attacks found ---------------------------------------------------

def test_a_backport_released_after_a_later_version_does_not_have_to_lie(tmp_path):
    """Cutting 0.9.1 after 0.10.0 has shipped must not require asserting 0.9.1 -> 0.10.0.

    Adjacency is by version order, so inserting a backport makes (0.9.1, 0.10.0) newly adjacent and
    the naive rule demands an edge out of the backport into a release that predates its fix. There
    is no honest answer to that demand: `direct` claims an untested and backwards hop, `blocked`
    admits the pair is not really adjacent. The price of shipping a backport would be a false
    declaration, which is precisely what this gate exists to prevent -- so the requirement is
    skipped where the later version was released earlier.
    """
    data = _valid()
    data["versions"]["0.2.1"] = {"released": "2026-02-01", "notes": "backport, shipped later", "support": _support()}
    data["edges"].append({"from": "0.2.0", "to": "0.2.1", "kind": "direct",
                          "reversible": True, "requires_backup": False})
    um.validate_matrix(data, released_ceiling=None)   # no edge 0.2.1 -> ... is demanded

    repo = _repo(tmp_path, "0.2.1", data)
    assert _run_gate(repo, "0.2.1", tmp_path).version == "0.2.1"


def test_the_backport_exemption_does_not_let_a_release_be_orphaned():
    """The narrow shape of that exemption, because skipping the rule outright opens a hole.

    If the backport's insertion is used as cover to also drop the real predecessor link, the later
    version ends up with no way in at all. Something released no later than it must still lead in.
    """
    data = _valid()
    # 0.1.5 sorts between the two but shipped after both: the backport shape. Its own inbound edge
    # is declared; 0.2.0's is not, so 0.2.0 is left with no way in at all.
    data["versions"]["0.1.5"] = {"released": "2026-02-01", "notes": "backport", "support": _support()}
    data["edges"] = [{"from": "0.1.0", "to": "0.1.5", "kind": "direct",
                      "reversible": True, "requires_backup": False}]
    with pytest.raises(um.UpgradeMatrixError, match="older than 0.2.0"):
        um.validate_matrix(data, released_ceiling=None)


def test_an_ordinary_forward_gap_is_still_rejected():
    """Non-vacuity for the two above: the relaxed rule still catches the case it is meant to."""
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-03-01", "notes": "later in both senses", "support": _support()}
    with pytest.raises(um.UpgradeMatrixError, match=r"0\.2\.0 -> 0\.3\.0"):
        um.validate_matrix(data, released_ceiling=None)


def test_the_gate_rejects_a_version_that_was_never_released(tmp_path):
    """Closed at the gate, not only in the test lane.

    A fabricated predecessor satisfies adjacency and supplies the inbound edge the gate looks for,
    so without this the matrix could describe a release nobody can install and still cut a tag.
    """
    data = _valid()
    data["versions"]["0.1.5"] = {"released": "2026-01-15", "notes": "never existed", "support": _support()}
    data["edges"] = [
        {"from": "0.1.0", "to": "0.1.5", "kind": "direct",
         "reversible": True, "requires_backup": False},
        {"from": "0.1.5", "to": "0.2.0", "kind": "direct",
         "reversible": True, "requires_backup": False},
    ]
    repo = _repo(tmp_path, "0.2.0", data)
    subprocess.run(["git", "tag", "-d", "v0.1.5"], cwd=repo, capture_output=True, timeout=60)
    with pytest.raises(gate.ReleaseGateError, match="not released versions"):
        _run_gate(repo, "0.2.0", tmp_path)


def test_a_repeated_json_key_is_rejected(tmp_path):
    """json.loads keeps the last one and says nothing, so a reviewer reads the block that lost."""
    path = tmp_path / "dupe.json"
    path.write_text(
        '{"schema_version": 1, "schema_version": 2, "about": "x"}', encoding="utf-8", newline="")
    with pytest.raises(um.UpgradeMatrixError, match="repeats the key"):
        um.load_matrix(path)


def test_a_version_with_a_leading_zero_is_rejected():
    """"0.10.00" and "0.10.0" would be two keys for one release, and one could never match a tag."""
    data = _valid()
    data["versions"]["0.02.0"] = {"released": "2026-01-05", "notes": "x", "support": _support()}
    with pytest.raises(um.UpgradeMatrixError, match="malformed"):
        um.validate_matrix(data, released_ceiling=None)


def test_a_symlinked_matrix_is_refused(tmp_path):
    """The gate must validate the same bytes the release publishes.

    A symlink would let those differ, which defeats the one property the copy-verbatim step exists
    to guarantee.
    """
    real = tmp_path / "real.json"
    real.write_bytes(MATRIX_PATH.read_bytes())
    link = tmp_path / "link.json"
    try:
        link.symlink_to(real)
    except (OSError, NotImplementedError):
        pytest.skip("this platform/user cannot create symlinks")
    with pytest.raises(um.UpgradeMatrixError, match="regular file"):
        um.load_matrix(link)


def test_the_release_workflow_does_not_redirect_the_gate_to_another_file():
    """The gate reads docs/upgrade-matrix.json; the staging step copies that same path.

    Passing --upgrade-matrix in the workflow would let the gate validate one file while the release
    published another, and nothing else would notice.
    """
    workflow = (ROOT / ".github" / "workflows" / "release.yml").read_text(encoding="utf-8")
    assert "--upgrade-matrix" not in workflow, (
        "release.yml now points the gate at a specific matrix path; make sure it is the same file "
        "the staging step copies, or the published asset is not the one that was validated")


# --- the same tests on main and on a maintenance branch ------------------------------------------


def _history_repo(tmp_path: Path, versions: list[str], *, tags: tuple[str, ...] = ()) -> Path:
    """A repository whose VERSION held each of `versions` in turn, one commit each."""
    root = tmp_path / "history"
    root.mkdir()
    for args in (("init", "-q", "-b", "main"), ("config", "user.name", "t"),
                 ("config", "user.email", "t@example.invalid"), ("config", "commit.gpgsign", "false"),
                 ("config", "core.autocrlf", "false")):
        assert _git_out(root, *args).returncode == 0
    for version in versions:
        (root / "VERSION").write_bytes(f"{version}\n".encode())
        assert _git_out(root, "add", "VERSION").returncode == 0
        assert _git_out(root, "commit", "-q", "-m", version).returncode == 0
        if version in tags:
            assert _git_out(root, "tag", f"v{version}").returncode == 0
    return root


def test_a_version_pending_in_this_commits_history_is_not_a_phantom(tmp_path):
    """The later of two same-day candidates declares the earlier one, not yet tagged."""
    root = _history_repo(tmp_path, ["0.33.0", "0.33.1", "0.34.0"], tags=("0.33.0",))

    assert _versions_in_history(root) == {"0.33.0", "0.33.1", "0.34.0"}
    assert _released_versions(root) == ["0.33.0"]
    assert _phantoms(["0.33.0", "0.33.1", "0.34.0"], _released_versions(root),
                     _versions_in_history(root)) == []
    # A version no commit in this history ever prepared is still a phantom.
    assert _phantoms(["0.33.0", "0.33.1", "0.33.5", "0.34.0"], _released_versions(root),
                     _versions_in_history(root)) == ["0.33.5"]


def test_a_version_prepared_only_on_another_branch_is_a_phantom(tmp_path):
    root = _history_repo(tmp_path, ["0.33.0"], tags=("0.33.0",))
    assert _git_out(root, "checkout", "-q", "-b", "other").returncode == 0
    (root / "VERSION").write_bytes(b"0.33.9\n")
    assert _git_out(root, "commit", "-qam", "elsewhere").returncode == 0
    assert _git_out(root, "checkout", "-q", "main").returncode == 0

    assert "0.33.9" not in _versions_in_history(root)
    assert _phantoms(["0.33.0", "0.33.9"], ["0.33.0"], _versions_in_history(root)) == ["0.33.9"]


def test_a_shallow_checkout_fails_the_check_rather_than_skipping_it(tmp_path):
    """In a one-commit clone the earlier candidate's VERSION is out of sight, so a version pending
    in history looks like a phantom. That must fail, loudly, not skip: a skip in CI is a check that
    quietly stopped running."""
    source = _history_repo(tmp_path, ["0.33.0", "0.33.1", "0.34.0"], tags=("0.33.0",))
    clone = tmp_path / "shallow"
    cloned = _git_out(tmp_path, "clone", "-q", "--depth", "1", source.resolve().as_uri(), str(clone))
    assert cloned.returncode == 0, cloned.stderr
    assert _is_shallow(clone) and not _is_shallow(source)
    declared = ["0.33.0", "0.33.1", "0.34.0"]

    # Caught as any outcome, so that a skip is seen as the wrong outcome here rather than skipping
    # this test too.
    with pytest.raises(BaseException, match="this checkout is shallow") as outcome:
        _require_no_phantoms(clone, declared, ["0.33.0"], "0.34.0")
    assert outcome.type is pytest.fail.Exception

    # With its history, the same matrix is fine: 0.33.1 is pending in an ancestor.
    _require_no_phantoms(source, declared, ["0.33.0"], "0.34.0")
    # And a real phantom is an ordinary failure, shallow or not.
    with pytest.raises(AssertionError, match=r"declares \['0\.33\.5'\]"):
        _require_no_phantoms(source, [*declared, "0.33.5"], ["0.33.0"], "0.34.0")


def test_tags_that_are_not_releases_are_not_read_as_releases(tmp_path):
    root = _history_repo(tmp_path, ["0.33.0"], tags=("0.33.0",))
    for name in ("v0.34.0-rc1", "v0.34", "v00.1.0", "other"):
        assert _git_out(root, "tag", name).returncode == 0

    assert _released_versions(root) == ["0.33.0"]


def test_a_fix_on_a_newer_line_is_within_the_ceiling_on_a_maintenance_branch():
    """On release/0.33, VERSION is 0.33.3 while main's synced matrix names a fix released in 0.34.1."""
    assert _released_ceiling("0.33.3", ["0.33.2", "0.34.0", "0.34.1"]) == "0.34.1"
    assert _released_ceiling("0.35.0", ["0.33.2", "0.34.1"]) == "0.35.0"
    assert _released_ceiling("0.35.0", []) == "0.35.0"


def test_an_undeclared_release_fails_on_main_and_a_newer_lines_warns_on_a_maintenance_branch():
    declared = {"0.33.0", "0.33.1", "0.34.0"}

    # main: VERSION is on the newest line, so anything undeclared fails.
    assert _undeclared(["0.33.0", "0.33.1", "0.33.2", "0.34.0"], declared, "0.34.1") == (
        ["0.33.2"], [])
    # release/0.33: a newer line's release is main's to declare first, so it only warns...
    assert _undeclared(["0.33.0", "0.33.1", "0.34.0", "0.34.1"], declared, "0.33.2") == (
        [], ["0.34.1"])
    # ...but a release of its own line, or an older one, still fails.
    assert _undeclared(["0.32.9", "0.33.0", "0.33.1", "0.34.0"], declared, "0.33.2") == (
        ["0.32.9"], [])
    assert _undeclared(["0.33.0", "0.33.1", "0.33.2", "0.34.0"], declared, "0.33.3") == (
        ["0.33.2"], [])


def test_a_minor_after_a_later_maintenance_release_is_still_reachable():
    """Once 0.2.1 ships on the 0.2 line after 0.3.0, 0.3.0's version-order predecessor is 0.2.1, made
    after it, so an edge from 0.2.1 is 0.2.1's way up, not 0.3.0's way in. The route in from 0.2.0
    still counts."""
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}
    data["versions"]["0.2.1"] = {"released": "2026-01-04", "notes": "patch", "support": _support()}
    data["edges"] += [
        {"from": "0.2.0", "to": "0.3.0", "kind": "direct", "reversible": True,
         "requires_backup": False},
        {"from": "0.2.0", "to": "0.2.1", "kind": "direct", "reversible": True,
         "requires_backup": False},
        # 0.2.1's own way up to the newest release.
        {"from": "0.2.1", "to": "0.3.0", "kind": "direct", "reversible": True,
         "requires_backup": False},
    ]
    um.validate_matrix(data, released_ceiling=None)

    assert _unreachable(data, ["0.1.0", "0.2.0", "0.2.1", "0.3.0"]) == []

    # Without that route, it is not reachable, and says so -- an edge from the later patch into a
    # release that predates its fix is not a route in either.
    data["edges"] = [e for e in data["edges"] if (e["from"], e["to"]) != ("0.2.0", "0.3.0")]
    assert [p.split(":")[0] for p in _unreachable(data, ["0.1.0", "0.2.0", "0.2.1", "0.3.0"])] == [
        "0.3.0"]


def test_an_ordinary_release_with_no_edge_in_is_unreachable():
    data = _valid()
    data["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "third", "support": _support()}

    assert [p.split(":")[0] for p in _unreachable(data, ["0.1.0", "0.2.0", "0.3.0"])] == ["0.3.0"]


def test_the_suites_that_read_the_matrix_check_out_history():
    """The pending-version exemption reads VERSION's history, so the jobs that run this file check
    out with history, not only tags. A shallow checkout fails the check rather than skipping it."""
    workflows = ROOT / ".github" / "workflows"
    for name, marker in (("preflight.yml", "actions/checkout@"),
                         ("fast-tests.yml", "actions/checkout@"),
                         ("tests.yml", "  integration:")):
        text = (workflows / name).read_text(encoding="utf-8")
        checkout = text.split(marker, 1)[1].split("- name:", 1)[0]
        assert "fetch-depth: 0" in checkout, name
