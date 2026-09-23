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

import importlib.util
import json
import os
import subprocess
import sys
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

def test_the_committed_matrix_is_valid():
    # Against the real VERSION file: on main that is the newest released version, so a vulnerability
    # naming an unreleased `fixed_in` would be caught here on an ordinary push, not only at release.
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    um.validate_matrix(um.load_matrix(MATRIX_PATH), released_ceiling=version)


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
    tags = subprocess.run(
        ["git", "tag", "-l", "v*.*.*"], cwd=ROOT, capture_output=True, text=True, timeout=60)
    # A git that FAILED is not a checkout without tags, and folding them together reproduces the
    # very mistake this check was written to fix -- one level down. `git tag -l` does not fail on a
    # repository with no tags; it prints nothing and exits 0. A non-zero exit means something else
    # is wrong, everywhere, so it fails everywhere.
    assert tags.returncode == 0, (
        "git tag -l failed, which is not the same as having no tags: %s"
        % (tags.stderr or "").strip()[:200])
    if not tags.stdout.strip():
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
    released = sorted(
        (line[1:] for line in tags.stdout.split() if line.startswith("v")),
        key=lambda v: tuple(int(p) for p in v.split(".")))

    data = um.validate_matrix(um.load_matrix(MATRIX_PATH), released_ceiling=None)
    missing = [v for v in released if v not in data["versions"]]
    assert not missing, (
        f"released but undeclared in docs/upgrade-matrix.json: {missing}. The release gate would "
        "have refused these; they predate it, so add them")

    # And each is reachable, which is the assertion the gate itself makes.
    for version in released:
        um.assert_release_declared(data, version)

    # The converse, which matters more than it looks. Adjacency completeness is satisfied by any
    # chain of entries, so a version that was never released could be invented to bridge a gap --
    # and the file would validate while describing a release nobody can install. Every declared
    # version must correspond to a real tag.
    #
    # Checked here rather than in the validator on purpose: at release time the tag being cut does
    # exist, but the validator runs without a guaranteed view of the tag list, and a check that
    # silently passes when it cannot see tags would be worse than no check.
    #
    # The version in VERSION is exempt: a release-prep commit bumps it and adds the matrix entry
    # together, and the tag only appears afterwards. Without the exemption the two rules deadlock --
    # the gate refuses to cut a version the matrix does not declare, and this refuses a declared
    # version that is not yet tagged, so main would be red for the whole window between the two.
    # It holds only if the bump and the entry land in the same commit, which is what release prep
    # does and what the gate independently enforces at tag time by comparing tag to VERSION.
    preparing = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    phantom = [v for v in data["versions"] if v not in released and v != preparing]
    assert not phantom, (
        f"docs/upgrade-matrix.json declares {phantom}, which are not released tags and are not the "
        f"version being prepared ({preparing}). A version that does not exist can satisfy the "
        "adjacency rule while describing a release nobody can get")


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
    for ver, meta in versions.items():
        for v in (meta.get("vulnerabilities") or []):
            if v["fixed_in"] is not None:
                assert um._sort_key(v["fixed_in"]) > um._sort_key(ver), (
                    f"{ver} lists {v['title']!r} with fixed_in={v['fixed_in']}, "
                    f"which is not strictly later than {ver}")

    # (c) SECURE DERIVED: any version carrying a vulnerability entry reads support.secure false.
    for ver, meta in versions.items():
        if meta.get("vulnerabilities"):
            assert meta["support"]["secure"] is False, (
                f"{ver} lists vulnerabilities but is marked support.secure true")

    # (d) ONE RECORD PER FINDING: what an older reader sees on each version (title, fixed_in) is the
    # advisory's own, so the two can never tell an operator different things.
    for ver, meta in versions.items():
        for v in (meta.get("vulnerabilities") or []):
            advisory = advisories[v["advisory"]]
            assert (v["title"], v["fixed_in"]) == (advisory["title"], advisory["fixed_in"]), (
                f"{ver}:{v['advisory']} disagrees with its advisory")


def test_the_committed_matrix_stays_well_inside_what_its_readers_will_read():
    # Readers cap what they fetch (the validator at MAX_BYTES; deployed tools and apps at their own
    # limits) and fall back SILENTLY when the file is larger -- losing every advisory with it. Storing
    # each finding once is what keeps the file from growing by a full record per affected release.
    # Half the validator's cap leaves room for years of releases; hitting this means rethinking, not
    # raising, the limit.
    size = MATRIX_PATH.stat().st_size
    assert size < um.MAX_BYTES // 2, f"docs/upgrade-matrix.json is {size} bytes"


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
    git("add", "-A")
    git("commit", "-qm", version)
    # Tag every version the matrix declares, not only the one being cut: the gate now checks that
    # a declared version corresponds to a real release, so a fixture that declares versions it
    # never tagged is describing a repository that could not exist.
    for declared in sorted(set(matrix.get("versions", {})) | {version}):
        git("tag", f"v{declared}")
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
