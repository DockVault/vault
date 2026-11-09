"""The checks of older release lines, and their dependency updates, follow the matrix's `lines`.

`.github/workflows/maintenance-lines.yml` reads the supported lines from `docs/upgrade-matrix.json`
through `.github/scripts/supported_lines.py`. Nightly it runs the suites on each older line's
`release/X.Y` branch; weekly it scans the published image of every supported line. Dependabot aims
patch updates at each older line's branch. These pins keep all of it tied to `lines`, so a line is
checked while it is supported and nothing is aimed at a branch the matrix does not know, and they
keep the workflow's rights as narrow as its work.
"""
import datetime as dt
import importlib.util
import json
import re
from pathlib import Path

import pytest
import yaml

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
_SPEC = importlib.util.spec_from_file_location("supported_lines", ROOT / ".github" / "scripts" / "supported_lines.py")
assert _SPEC and _SPEC.loader
SUPPORTED = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(SUPPORTED)

WORKFLOW_TEXT = (ROOT / ".github" / "workflows" / "maintenance-lines.yml").read_text(encoding="utf-8")
WORKFLOW = yaml.safe_load(WORKFLOW_TEXT)
DEPENDABOT = yaml.safe_load((ROOT / ".github" / "dependabot.yml").read_text(encoding="utf-8"))
MATRIX = json.loads((ROOT / "docs" / "upgrade-matrix.json").read_text(encoding="utf-8"))
NIGHTLY, WEEKLY = "30 4 * * *", "0 5 * * 1"
TODAY = dt.datetime.now(dt.timezone.utc).date()


# ---- which lines are supported -------------------------------------------------------------------

TWO = {"0.33": {"security_fixes_until": "2027-05-09"}, "0.34": {"security_fixes_until": None}}


@pytest.mark.parametrize("today,maintenance,published", [
    ("2026-11-09", ["0.33"], ["0.33", "0.34"]),
    ("2027-05-09", ["0.33"], ["0.33", "0.34"]),          # the last day of support still counts
    ("2027-05-10", [], ["0.34"]),                          # the day after, the line drops by itself
])
def test_a_line_is_checked_until_its_date_passes(today, maintenance, published):
    assert SUPPORTED.supported(TWO, dt.date.fromisoformat(today)) == (maintenance, published)


def test_lines_are_ordered_by_number_not_by_text():
    lines = {"0.9": {"security_fixes_until": "2030-01-01"}, "0.10": {"security_fixes_until": "2030-01-01"},
             "0.11": {"security_fixes_until": None}}
    assert SUPPORTED.supported(lines, dt.date(2026, 1, 1)) == (["0.9", "0.10"], ["0.9", "0.10", "0.11"])


@pytest.mark.parametrize("lines", [
    None, {},
    {"0.33": {"security_fixes_until": "2027-05-09"}},                                   # no newest line
    {"0.33": {"security_fixes_until": None}, "0.34": {"security_fixes_until": None}},  # two newest
])
def test_a_matrix_without_exactly_one_newest_line_is_refused(lines):
    with pytest.raises(ValueError):
        SUPPORTED.supported(lines, dt.date(2026, 11, 9))


def test_the_script_writes_two_github_outputs(tmp_path, capsys):
    matrix = tmp_path / "m.json"
    matrix.write_text(json.dumps({"lines": TWO}), encoding="utf-8")
    assert SUPPORTED.main(["--matrix", str(matrix), "--today", "2026-11-09"]) == 0
    assert capsys.readouterr().out.splitlines() == ['maintenance=["0.33"]', 'published=["0.33", "0.34"]']


def test_the_real_matrix_names_one_newest_line():
    maintenance, published = SUPPORTED.supported(MATRIX["lines"], TODAY)
    assert set(maintenance) < set(published)


# ---- the workflow --------------------------------------------------------------------------------

def _job(name):
    return WORKFLOW["jobs"][name]


def test_the_workflow_runs_on_its_two_schedules_and_by_hand():
    triggers = WORKFLOW[True]                                  # YAML reads the bare key `on` as True
    assert [c["cron"] for c in triggers["schedule"]] == [NIGHTLY, WEEKLY]
    assert "workflow_dispatch" in triggers
    assert set(triggers) == {"schedule", "workflow_dispatch"}  # never on a push or a pull request


def test_the_workflow_holds_the_least_rights_its_jobs_need():
    assert WORKFLOW["permissions"] == {"contents": "read"}
    assert "permissions" not in _job("lines") and "permissions" not in _job("scan")
    assert _job("suites")["permissions"] == {"actions": "write"}   # only to dispatch the line's runs
    assert "secrets." not in WORKFLOW_TEXT                         # the job token is all it uses


def test_the_lines_come_from_the_matrix_not_from_the_workflow():
    run = _job("lines")["steps"][-1]["run"]
    assert "supported_lines.py --matrix docs/upgrade-matrix.json" in run
    assert _job("suites")["strategy"]["matrix"]["line"] == "${{ fromJSON(needs.lines.outputs.maintenance) }}"
    assert _job("scan")["strategy"]["matrix"]["line"] == "${{ fromJSON(needs.lines.outputs.published) }}"
    assert not re.search(r"release/\d+\.\d+|dockvault/vault:v\d", WORKFLOW_TEXT)   # no line written in by hand


def test_nightly_runs_both_suites_on_each_older_lines_branch():
    suites = _job("suites")
    assert f"github.event.schedule == '{NIGHTLY}'" in suites["if"]
    assert "needs.lines.outputs.maintenance != '[]'" in suites["if"]      # an empty matrix fails a run
    run = suites["steps"][0]["run"]
    assert 'gh workflow run tests.yml --repo "$GITHUB_REPOSITORY" --ref "release/${LINE}"' in run
    assert 'gh workflow run setup-matrix.yml --repo "$GITHUB_REPOSITORY" --ref "release/${LINE}"' in run
    for name in ("tests.yml", "setup-matrix.yml"):                         # both can be dispatched
        triggers = yaml.safe_load((ROOT / ".github" / "workflows" / name).read_text(encoding="utf-8"))[True]
        assert "workflow_dispatch" in triggers, name


def test_weekly_scans_each_published_image_with_the_release_policy():
    scan = _job("scan")
    assert f"github.event.schedule == '{WEEKLY}'" in scan["if"]
    prepare, grype = scan["steps"][1]["run"], scan["steps"][2]["with"]
    assert 'docker pull --platform linux/amd64 "ghcr.io/dockvault/vault:v${LINE}"' in prepare
    assert 'git show "${tag}:security/vex.openvex.json"' in prepare           # the line's own exceptions
    assert 'test "v${label}" = "$tag"' in prepare                           # :vX.Y is that release
    assert grype == {"image": "${{ env.IMAGE }}", "grype-version": "v0.112.0", "fail-build": True,
                     "severity-cutoff": "high", "only-fixed": False, "vex": "line-scan.openvex.json"}


def test_every_action_is_pinned_to_a_commit():
    uses = re.findall(r"uses:\s*(\S+)", WORKFLOW_TEXT)
    assert uses and all(re.fullmatch(r"[\w.-]+/[\w.-]+@[0-9a-f]{40}", u) for u in uses), uses


# ---- Dependabot ----------------------------------------------------------------------------------

def _entries(branch):
    return {u["package-ecosystem"]: u for u in DEPENDABOT["updates"] if u.get("target-branch") == branch}


def test_each_older_line_still_supported_gets_its_patch_updates():
    maintenance, _ = SUPPORTED.supported(MATRIX["lines"], TODAY)
    for line in maintenance:
        entries = _entries(f"release/{line}")
        assert set(entries) == {"pip", "docker", "docker-compose", "github-actions"}, line
        assert entries["pip"]["directories"] == ["/", "/tests"]
        assert entries["docker"]["directory"] == "/"
        assert entries["docker-compose"]["directory"] == "/deploy"
        assert entries["github-actions"]["directory"] == "/"
        majors_minors = {"version-update:semver-major", "version-update:semver-minor"}
        for ecosystem in ("pip", "docker"):                    # patch only: no new minor on a line
            ignored = {t for rule in entries[ecosystem]["ignore"] for t in rule["update-types"]}
            assert majors_minors <= ignored, ecosystem
        compose_ignored = {t for rule in entries["docker-compose"]["ignore"] for t in rule["update-types"]}
        assert compose_ignored == {"version-update:semver-major"}  # a postgres minor carries its fixes


def test_nothing_is_aimed_at_a_branch_the_matrix_does_not_know():
    newest = [line for line, entry in MATRIX["lines"].items() if entry.get("security_fixes_until") is None]
    known = {f"release/{line}" for line in MATRIX["lines"]} - {f"release/{line}" for line in newest}
    targets = {u["target-branch"] for u in DEPENDABOT["updates"] if "target-branch" in u}
    assert targets <= known, targets - known
    main_entries = [u["package-ecosystem"] for u in DEPENDABOT["updates"] if "target-branch" not in u]
    assert sorted(main_entries) == ["docker", "docker-compose", "github-actions", "pip"]
