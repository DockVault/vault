"""A version's reference to an advisory may carry only the advisory's id.

Each version in docs/upgrade-matrix.json lists the advisories that affect it, and each reference
repeats its advisory's `title` and `fixed_in`, because the 0.30.x readers (the host tool and the app's
update check) read nothing else. Repeated across every affected release, one advisory costs about
10 KB, so the format will change to references that carry only the id. Readers have to accept that
form several releases before anything writes it; these are the two in this repository. A title or
fixed_in a reference leaves out is taken from the top-level `advisories` map, and a missing title
falls back to the id. The validator accepts the short form only below 0.27.0: the host tools of
0.30.0 to 0.32.x list the newest releases from the repeated fields, and that list reaches 0.27.0.
"""
import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

import dockvault as dv
from app.services import update_check as U

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
MATRIX = json.loads((ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8"))


def _ids_only(matrix):
    """The same matrix, written the next way: every reference carries only its advisory's id."""
    out = copy.deepcopy(matrix)
    for meta in out["versions"].values():
        for ref in meta.get("vulnerabilities") or []:
            ref.pop("title", None)
            ref.pop("fixed_in", None)
    return out


def _newest(matrix):
    return max(matrix["versions"], key=lambda v: tuple(int(p) for p in v.split(".")))


AFFECTED = sorted(v for v, meta in MATRIX["versions"].items() if meta.get("vulnerabilities"))


def test_the_committed_matrix_has_references_to_strip():
    # Without affected versions the comparisons below would compare empty lists.
    assert len(AFFECTED) > 5
    stripped = _ids_only(MATRIX)
    assert all(set(ref) == {"advisory"} for v in AFFECTED
               for ref in stripped["versions"][v]["vulnerabilities"])


@pytest.mark.parametrize("version", AFFECTED)
def test_both_readers_read_an_id_only_matrix_as_they_read_the_full_one(version):
    ids = _ids_only(MATRIX)
    full_tool = dv.version_vulnerabilities(MATRIX, version)
    assert full_tool and all(v["title"] for v in full_tool)
    assert dv.version_vulnerabilities(ids, version) == full_tool
    assert U._version_vulnerabilities(ids, version) == U._version_vulnerabilities(MATRIX, version)


def test_the_app_names_the_advisories_of_an_id_only_matrix():
    version = AFFECTED[0]
    block = U.merged_security(version, _newest(MATRIX), local_matrix=_ids_only(MATRIX), main_matrix=None)
    assert block["secure"] is False
    expected = sorted((MATRIX["advisories"][r["advisory"]]["title"],
                       MATRIX["advisories"][r["advisory"]]["fixed_in"])
                      for r in MATRIX["versions"][version]["vulnerabilities"])
    assert sorted((v["title"], v["fixed_in"]) for v in block["vulnerabilities"]) == expected


@pytest.mark.parametrize("version", AFFECTED[:3])
def test_a_full_bundled_copy_and_an_id_only_copy_on_main_dedupe_to_one(version):
    # The case a deployment meets first: its bundled copy is the old form, main's is the new one.
    ceiling = _newest(MATRIX)
    count = len(MATRIX["versions"][version]["vulnerabilities"])
    merged, source = dv.merge_lifecycle_matrix(MATRIX, _ids_only(MATRIX), ceiling)
    assert source == "main"
    assert len(dv.version_vulnerabilities(merged, version)) == count
    block = U.merged_security(version, ceiling, local_matrix=MATRIX, main_matrix=_ids_only(MATRIX))
    assert block["source"] == "main" and len(block["vulnerabilities"]) == count


def test_the_tool_prints_an_id_only_vulnerability_with_its_advisory():
    version = AFFECTED[0]
    lines = "\n".join(dv.describe_vulnerabilities(dv.version_vulnerabilities(_ids_only(MATRIX), version)))
    for ref in MATRIX["versions"][version]["vulnerabilities"]:
        advisory = MATRIX["advisories"][ref["advisory"]]
        assert dv.clean_matrix_text(advisory["title"]) in lines


def test_a_reference_to_an_undeclared_advisory_still_counts_under_its_id():
    matrix = {"advisories": {}, "versions": {"1.0.0": {"vulnerabilities": [{"advisory": "not-declared"}]}}}
    tool = dv.version_vulnerabilities(matrix, "1.0.0")
    assert [(v["title"], v["fixed_in"]) for v in tool] == [("not-declared", None)]
    assert U._version_vulnerabilities(matrix, "1.0.0") == [{"title": "not-declared", "fixed_in": None}]
    assert U.merged_security("1.0.0", "1.0.0", local_matrix=matrix, main_matrix=None)["secure"] is False


def test_a_field_the_reference_carries_wins_over_its_advisory():
    # As every older reader has always read it: the reference's own title and fixed_in.
    matrix = {"advisories": {"a": {"title": "From the advisory", "fixed_in": "1.0.1", "severity": "high"}},
              "versions": {"1.0.0": {"vulnerabilities": [
                  {"advisory": "a", "title": "From the reference", "fixed_in": None}]}}}
    tool = dv.version_vulnerabilities(matrix, "1.0.0")
    assert [(v["title"], v["fixed_in"], v["severity"]) for v in tool] == [("From the reference", None, "high")]
    assert U._version_vulnerabilities(matrix, "1.0.0") == [{"title": "From the reference", "fixed_in": None}]


def test_a_reference_missing_only_one_field_takes_that_one_from_its_advisory():
    matrix = {"advisories": {"a": {"title": "From the advisory", "fixed_in": "1.0.1"}},
              "versions": {"1.0.0": {"vulnerabilities": [{"advisory": "a", "title": "Kept"}]}}}
    assert U._version_vulnerabilities(matrix, "1.0.0") == [{"title": "Kept", "fixed_in": "1.0.1"}]
    assert [(v["title"], v["fixed_in"]) for v in dv.version_vulnerabilities(matrix, "1.0.0")] == [
        ("Kept", "1.0.1")]


def test_the_validator_still_requires_the_repeated_fields_where_older_readers_list_them():
    # The 0.30.x to 0.32.x host tools list the newest releases from the repeated fields alone, so on
    # those releases a short reference is still refused.
    spec = importlib.util.spec_from_file_location(
        "upgrade_matrix_for_references", ROOT / ".github" / "scripts" / "upgrade_matrix.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    with pytest.raises(module.UpgradeMatrixError, match="missing required key"):
        module.validate_matrix(_ids_only(MATRIX), released_ceiling=None)
