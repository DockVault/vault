"""One matrix across main and the maintenance branches: main's plus the branch's own entry, and the
same bytes whichever side writes it."""

from __future__ import annotations

import copy
import importlib.util
import json
import sys
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_ROOT = Path(__file__).resolve().parents[1]
_MATRIX = _ROOT / "docs" / "upgrade-matrix.json"
_SPEC = importlib.util.spec_from_file_location(
    "matrix_sync_under_test", _ROOT / ".github" / "scripts" / "matrix_sync.py")
assert _SPEC and _SPEC.loader
_SYNC = importlib.util.module_from_spec(_SPEC)
sys.modules[_SPEC.name] = _SYNC
_SPEC.loader.exec_module(_SYNC)


def _entry(date: str, *, secure: bool = True, vulnerabilities: list | None = None) -> dict:
    entry = {"released": date, "notes": f"released {date}",
             "support": {"eol": False, "secure": secure}}
    if vulnerabilities:
        entry["vulnerabilities"] = vulnerabilities
    return entry


def _edge(source: str, target: str) -> dict:
    return {"from": source, "to": target, "kind": "direct", "reversible": True,
            "requires_backup": False}


def _main() -> dict:
    """main after 0.34.0: two lines, 0.33 not yet branched."""
    return {
        "schema_version": 3,
        "about": "fixture",
        "kinds": {"direct": "one step", "blocked": "do not"},
        "advisories": {},
        "versions": {
            "0.33.0": _entry("2026-09-29"),
            "0.33.1": _entry("2026-10-28"),
            "0.34.0": _entry("2026-12-10"),
        },
        "edges": [_edge("0.33.0", "0.33.1"), _edge("0.33.1", "0.34.0")],
    }


def _branch_release(main: dict) -> dict:
    """release/0.33 at its 0.33.2 candidate: main's matrix as it was, plus its own entry."""
    branch = copy.deepcopy(main)
    branch["versions"]["0.33.2"] = _entry("2026-12-20")
    branch["edges"].append(_edge("0.33.1", "0.33.2"))
    return branch


def test_syncing_the_committed_matrix_with_itself_changes_nothing():
    """The one serialisation every branch writes is the one the committed file already has."""
    data = json.loads(_MATRIX.read_bytes())

    result, notes = _SYNC.sync(data, copy.deepcopy(data))

    assert _SYNC.render(result) == _MATRIX.read_bytes()
    assert notes == []


def test_a_maintenance_release_entry_joins_mains_matrix_in_version_order():
    main = _main()
    branch = _branch_release(main)
    main["versions"]["0.34.1"] = _entry("2026-12-18")        # main moved on meanwhile
    main["edges"].append(_edge("0.34.0", "0.34.1"))

    result, notes = _SYNC.sync(main, branch)

    assert list(result["versions"]) == ["0.33.0", "0.33.1", "0.33.2", "0.34.0", "0.34.1"]
    assert [(e["from"], e["to"]) for e in result["edges"]] == [
        ("0.33.0", "0.33.1"), ("0.33.1", "0.33.2"), ("0.33.1", "0.34.0"), ("0.34.0", "0.34.1")]
    assert "took 0.33.2 from the branch" in notes
    assert "took the edge 0.33.1 -> 0.33.2 from the branch" in notes


def test_both_branches_end_with_the_same_bytes():
    """The branch syncs from main before its release; main takes the entry after it; the branch
    takes main's next release later. After each round the two files are identical."""
    main = _main()
    branch = _branch_release(main)
    main["versions"]["0.34.1"] = _entry("2026-12-18")
    main["edges"].append(_edge("0.34.0", "0.34.1"))

    branch_file, _ = _SYNC.sync(main, branch)                  # on release/0.33
    main_file, _ = _SYNC.sync(main, branch_file)               # on main, after the release
    assert _SYNC.render(main_file) == _SYNC.render(branch_file)

    main_file["versions"]["0.34.2"] = _entry("2027-01-15")     # main's next release
    main_file["edges"].append(_edge("0.34.1", "0.34.2"))
    branch_file, notes = _SYNC.sync(main_file, branch_file)
    assert _SYNC.render(branch_file) == _SYNC.render(main_file)
    assert notes == []                                        # nothing is only on the branch


def test_where_both_declare_the_same_thing_mains_is_kept_and_reported():
    main = _main()
    branch = _branch_release(main)
    branch["versions"]["0.33.1"]["notes"] = "rewritten on the branch"
    branch["edges"][0]["requires_backup"] = True

    result, notes = _SYNC.sync(main, branch)

    assert result["versions"]["0.33.1"]["notes"] == main["versions"]["0.33.1"]["notes"]
    assert result["edges"][0]["requires_backup"] is False
    assert "kept main's entry for 0.33.1; the branch's differs" in notes
    assert "kept main's edge 0.33.0 -> 0.33.1; the branch's differs" in notes


def test_a_top_level_key_the_branch_changed_is_reported_and_mains_kept():
    main = _main()
    branch = _branch_release(main)
    branch["about"] = "the wording the branch was cut with"

    result, notes = _SYNC.sync(main, branch)

    assert result["about"] == "fixture"
    assert "kept main's 'about'; the branch's differs" in notes
    # The keys combined entry by entry are reported entry by entry, not as a whole.
    assert not [note for note in notes if note.startswith(("kept main's 'versions'",
                                                           "kept main's 'edges'"))]


def _older_line_advisory(branch: dict, version: str) -> None:
    reference = {"advisory": "older-line-only", "title": "Older line only", "fixed_in": "0.33.2"}
    branch["advisories"]["older-line-only"] = {
        "title": "Older line only", "description": "d", "impact": "i", "remediation": "r",
        "mitigation": None, "severity": None, "cvss": None, "id": None, "fixed_in": "0.33.2",
        "published": "2026-12-20"}
    branch["versions"][version]["vulnerabilities"] = [reference]


@pytest.mark.parametrize("side, key", [
    ("main", "support"), ("branch", "support"), ("branch", "secure")])
def test_an_affected_version_without_a_support_block_is_refused_not_a_crash(side, key):
    main = _main()
    branch = _branch_release(main)
    _older_line_advisory(branch, "0.33.1")
    entry = (main if side == "main" else branch)["versions"]["0.33.1"]
    del (entry if key == "support" else entry["support"])[key]

    with pytest.raises(_SYNC.MatrixSyncError, match="0.33.1 has no support block"):
        _SYNC.sync(main, branch)


def test_a_fix_only_the_older_line_needs_brings_its_advisory_to_main():
    """The advisory, each affected version's reference to it, and those versions' secure flag."""
    main = _main()
    branch = _branch_release(main)
    reference = {"advisory": "older-line-only", "title": "Older line only", "fixed_in": "0.33.2"}
    branch["advisories"]["older-line-only"] = {
        "title": "Older line only", "description": "d", "impact": "i", "remediation": "r",
        "mitigation": None, "severity": None, "cvss": None, "id": None, "fixed_in": "0.33.2",
        "published": "2026-12-20"}
    for version in ("0.33.0", "0.33.1"):
        branch["versions"][version]["support"]["secure"] = False
        branch["versions"][version]["vulnerabilities"] = [dict(reference)]

    result, notes = _SYNC.sync(main, branch)

    assert "older-line-only" in result["advisories"]
    for version in ("0.33.0", "0.33.1"):
        assert result["versions"][version]["vulnerabilities"] == [reference]
        assert result["versions"][version]["support"]["secure"] is False
    assert "vulnerabilities" not in result["versions"]["0.34.0"]
    assert "took the advisory older-line-only from the branch" in notes


def test_a_combination_that_does_not_validate_is_refused():
    main = _main()
    branch = _branch_release(main)
    branch["edges"].append(_edge("0.33.2", "0.35.0"))         # to a version nobody declares

    with pytest.raises(_SYNC.MatrixSyncError, match="not valid"):
        _SYNC.sync(main, branch)


def test_the_command_writes_nothing_when_it_refuses(tmp_path):
    main = _main()
    branch = _branch_release(main)
    branch["edges"].append(_edge("0.33.2", "0.35.0"))
    (tmp_path / "main.json").write_bytes(_SYNC.render(main))
    (tmp_path / "branch.json").write_bytes(_SYNC.render(branch))
    before = (tmp_path / "branch.json").read_bytes()

    assert _SYNC.main(["sync", "--main", str(tmp_path / "main.json"),
                       "--branch", str(tmp_path / "branch.json")]) == 1
    assert (tmp_path / "branch.json").read_bytes() == before


def test_the_command_syncs_then_checks(tmp_path, capsys):
    main = _main()
    (tmp_path / "main.json").write_bytes(_SYNC.render(main))
    (tmp_path / "branch.json").write_bytes(_SYNC.render(_branch_release(main)))

    assert _SYNC.main(["sync", "--main", str(tmp_path / "main.json"),
                       "--branch", str(tmp_path / "branch.json")]) == 0
    assert _SYNC.main(["sync", "--main", str(tmp_path / "main.json"),
                       "--branch", str(tmp_path / "branch.json"),
                       "--output", str(tmp_path / "main.json")]) == 0
    capsys.readouterr()

    assert _SYNC.main(["check", str(tmp_path / "main.json"), str(tmp_path / "branch.json")]) == 0

    (tmp_path / "main.json").write_bytes((tmp_path / "main.json").read_bytes() + b"\n")
    assert _SYNC.main(["check", str(tmp_path / "main.json"), str(tmp_path / "branch.json")]) == 1
    assert "differ" in capsys.readouterr().out


def test_first_difference_names_the_line():
    assert _SYNC.first_difference(b"a\nb\n", b"a\nb\n") is None
    assert _SYNC.first_difference(b"a\nb\n", b"a\nc\n") == "line 2 differs"
    assert _SYNC.first_difference(b"a\n", b"a\nb\n") == "line 2 differs"


def test_a_waiver_only_the_branch_declares_is_carried():
    main = _main()
    branch = copy.deepcopy(main)
    branch["versions"]["0.33.2"] = _entry("2026-12-20")
    branch["edges"].append({"from": "0.33.1", "to": "0.33.2", "kind": "blocked",
                            "reversible": False, "requires_backup": True,
                            "reason": "restore from a backup instead"})
    branch["waivers"] = [{"version": "0.33.2", "reason": "reached by restore only"}]

    result, notes = _SYNC.sync(main, branch)
    assert result["waivers"] == branch["waivers"]

    # With waivers of its own, main keeps them and gains the branch's.
    main["waivers"] = [{"version": "0.34.5", "reason": "shipped undeclared"}]
    result, notes = _SYNC.sync(main, branch)
    assert result["waivers"] == main["waivers"] + branch["waivers"]
    assert "took the waiver for 0.33.2 from the branch" in notes
