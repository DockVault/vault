"""Unit coverage for the split of the stack tests into shards (.github/scripts/suite_shards.py).

The full suite's stack tests run in several jobs, each given its files by this script. What must
hold: every test file is in exactly one shard, a file's shard does not depend on anything but the
committed data and its own path, and the shards are even on the recorded times.
"""

from __future__ import annotations

import importlib.util
import json
import random
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_SCRIPT = _ROOT / ".github" / "scripts" / "suite_shards.py"
_DATA = _ROOT / ".github" / "suite-shards.json"
_SPEC = importlib.util.spec_from_file_location("suite_shards", _SCRIPT)
assert _SPEC and _SPEC.loader
_SHARDS = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SHARDS)


def _tracked_test_files() -> list[str]:
    """The test files git tracks: found without the script, to compare it with."""
    listed = subprocess.run(["git", "-C", str(_ROOT), "ls-files", "-z", "--", "tests"],
                            capture_output=True, check=True, timeout=60).stdout.decode("utf-8")
    return sorted(name for name in listed.split("\0")
                  if name.endswith(".py") and name.rsplit("/", 1)[-1].startswith("test_"))


def _shard_files(capsys, shard: int, *extra: str) -> list[str]:
    assert _SHARDS.main([*extra, "files", "--shard", str(shard)]) == 0
    return capsys.readouterr().out.splitlines()


def _repository(tmp_path: Path, files: list[str], data: dict) -> Path:
    for name in files:
        path = tmp_path / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text("", encoding="utf-8")
    (tmp_path / ".github").mkdir(exist_ok=True)
    (tmp_path / ".github" / "suite-shards.json").write_text(json.dumps(data), encoding="utf-8")
    return tmp_path


def test_every_test_file_is_in_exactly_one_shard(capsys):
    shards, _seconds = _SHARDS.load(_DATA)
    printed = [_shard_files(capsys, number) for number in range(1, shards + 1)]
    together = [name for files in printed for name in files]

    assert len(together) == len(set(together)), "a test file is in two shards"
    tracked = _tracked_test_files()
    assert len(tracked) > 900
    assert set(tracked) <= set(together), sorted(set(tracked) - set(together))
    assert "tests/test_ci_suite_shards.py" in together        # a file the recorded times do not list
    # Nothing but test files, each printed as pytest is to be given it, in a fixed order.
    assert set(together) == set(_SHARDS.suite_files(_ROOT))
    for files in printed:
        assert files and files == sorted(files)
        assert all(name.startswith("tests/") and name.endswith(".py") for name in files)


def test_pytest_looks_for_tests_where_the_script_does():
    """The script lists `test_*.py` under `tests/`; pytest.ini must go on saying the same."""
    ini = (_ROOT / "pytest.ini").read_text(encoding="utf-8")
    assert "\ntestpaths = tests\n" in ini
    assert "\npython_files = test_*.py\n" in ini


def test_a_files_shard_does_not_depend_on_the_order_or_the_machine():
    shards, seconds = _SHARDS.load(_DATA)
    files = _SHARDS.suite_files(_ROOT)
    first = _SHARDS.assign(files, seconds, shards)

    shuffled = list(files)
    random.Random(7).shuffle(shuffled)
    assert _SHARDS.assign(shuffled, dict(reversed(list(seconds.items()))), shards) == first
    # A hash of the path's bytes, not Python's own hash of a string (which differs from one process
    # to the next): these are the values every machine must agree on.
    assert _SHARDS.hashed_shard("tests/test_example.py", 6) == 2
    assert _SHARDS.hashed_shard("tests/test_another_example.py", 6) == 6
    assert [_SHARDS.hashed_shard(f"tests/test_{n}.py", 4) for n in range(8)] == [1, 4, 1, 4, 4, 2, 1, 3]


def test_adding_or_deleting_a_test_file_moves_no_other_file():
    shards, seconds = _SHARDS.load(_DATA)
    files = _SHARDS.suite_files(_ROOT)
    before = _SHARDS.assign(files, seconds, shards)

    new = "tests/test_a_file_nobody_has_written_yet.py"
    assert new not in files and new not in seconds
    after = _SHARDS.assign(sorted([*files, new]), seconds, shards)
    assert after.pop(new) == _SHARDS.hashed_shard(new, shards)
    assert after == before

    heaviest = max(seconds, key=seconds.get)
    unlisted = next(name for name in files if name not in seconds)
    for gone in (heaviest, unlisted):
        rest = [name for name in files if name != gone]
        assert _SHARDS.assign(rest, seconds, shards) == {name: before[name] for name in rest}, gone


def test_listed_files_are_dealt_heaviest_first_to_the_lightest_shard():
    seconds = {"tests/test_a.py": 10, "tests/test_b.py": 9, "tests/test_c.py": 8, "tests/test_d.py": 1.5,
               "tests/test_e.py": 1.5}
    # a -> 1 (10); b -> 2 (9); c -> 2, the lighter (17); d -> 1 (11.5); e -> 1 again (13).
    assert _SHARDS.place_listed(seconds, 2) == {
        "tests/test_a.py": 1, "tests/test_b.py": 2, "tests/test_c.py": 2, "tests/test_d.py": 1,
        "tests/test_e.py": 1}
    # Equal loads go to the lower shard, and equal weights go in the order of their names.
    assert _SHARDS.place_listed({"tests/test_y.py": 5, "tests/test_x.py": 5, "tests/test_z.py": 5}, 3) == {
        "tests/test_x.py": 1, "tests/test_y.py": 2, "tests/test_z.py": 3}


def test_no_shard_is_above_35_minutes_on_the_recorded_times():
    shards, seconds = _SHARDS.load(_DATA)
    rows = _SHARDS.balance(_SHARDS.suite_files(_ROOT), seconds, shards)

    assert [row["shard"] for row in rows] == list(range(1, shards + 1))
    longest = max(row["seconds"] for row in rows)
    assert longest <= 35 * 60, f"the longest shard has {longest / 60:.1f} minutes of recorded tests"
    # Even, not merely under the limit: a shard far under the others means the split is not doing
    # its work and the next slow file tips one over.
    assert min(row["seconds"] for row in rows) >= 0.8 * longest
    assert sum(row["files"] for row in rows) == len(_SHARDS.suite_files(_ROOT))


def test_the_data_names_no_missing_file_without_the_script_saying_so(tmp_path, capsys):
    root = _repository(tmp_path, ["tests/test_here.py", "tests/test_also_here.py"], {
        "shards": 2,
        "seconds": {"tests/test_here.py": 3, "tests/test_gone.py": 40, "tests/test_gone_too.py": 1},
    })
    assert _SHARDS.main(["--root", str(root), "balance"]) == 0
    out = capsys.readouterr().out
    assert ("::warning::the shard data lists 2 file(s) that are not there any more: "
            "tests/test_gone.py, tests/test_gone_too.py") in out
    # A file that is gone is in no shard; the ones that are there each are in one.
    _shards, seconds = _SHARDS.load(root / ".github" / "suite-shards.json")
    assigned = _SHARDS.assign(_SHARDS.suite_files(root), seconds, 2)
    assert sorted(assigned) == ["tests/test_also_here.py", "tests/test_here.py"]
    assert set(assigned.values()) <= {1, 2}

    # The committed data, read without the script: whatever it lists that is gone, the script says.
    seconds = json.loads(_DATA.read_text(encoding="utf-8"))["seconds"]
    gone = sorted(name for name in seconds if not (_ROOT / name).is_file())
    assert _SHARDS.main(["balance"]) == 0
    out = capsys.readouterr().out
    assert ("::warning::" in out) == bool(gone)
    for name in gone:
        assert name in out


def test_only_what_pytest_collects_from_is_dealt_out(tmp_path):
    root = _repository(tmp_path, [
        "tests/test_top.py",
        "tests/deeper/test_nested.py",
        "tests/.venv/lib/test_in_a_virtual_environment.py",
        "tests/__pycache__/test_cached.py",
        "tests/helper.py",
        "tests/conftest.py",
        "elsewhere/test_not_under_tests.py",
    ], {"shards": 1, "seconds": {}})
    assert _SHARDS.suite_files(root) == ["tests/deeper/test_nested.py", "tests/test_top.py"]


@pytest.mark.parametrize("data, said", [
    ({"shards": 0, "seconds": {}}, "`shards` must be a whole number"),
    ({"shards": True, "seconds": {}}, "`shards` must be a whole number"),
    ({"shards": "6", "seconds": {}}, "`shards` must be a whole number"),
    ({"shards": 2}, "`seconds` must map"),
    ({"shards": 2, "seconds": {"tests/test_a.py": -1}}, "must be a number, zero or more"),
    ({"shards": 2, "seconds": {"tests/test_a.py": True}}, "must be a number, zero or more"),
    ({"shards": 2, "seconds": {"tests/test_a.py": "3"}}, "must be a number, zero or more"),
    ({"shards": 2, "seconds": {"tests\\test_a.py": 3}}, "not a test file's path"),
    ({"shards": 2, "seconds": {"tests/helper.py": 3}}, "not a test file's path"),
    ({"shards": 2, "seconds": {"app/test_a.py": 3}}, "not a test file's path"),
], ids=["no-shard", "a-flag", "a-string", "no-seconds", "negative", "flag-seconds", "string-seconds",
        "backslash", "not-a-test", "not-under-tests"])
def test_unusable_data_is_refused(tmp_path, capsys, data, said):
    root = _repository(tmp_path, ["tests/test_a.py"], data)
    for command in (["files", "--shard", "1"], ["count"], ["balance"]):
        assert _SHARDS.main(["--root", str(root), *command]) == 1
        captured = capsys.readouterr()
        assert captured.out == ""
        assert "::error::the shard data is not usable" in captured.err and said in captured.err


def test_a_shard_that_does_not_exist_is_refused(tmp_path, capsys):
    shards, _seconds = _SHARDS.load(_DATA)
    for number in (0, shards + 1, -1):
        assert _SHARDS.main(["files", "--shard", str(number)]) == 1
        captured = capsys.readouterr()
        assert captured.out == "" and f"the shards are 1 to {shards}" in captured.err
    assert _SHARDS.main(["count"]) == 0
    assert capsys.readouterr().out == f"{shards}\n"

    # A shard with nothing to run is an error, not an empty list pytest would turn into "run all".
    root = _repository(tmp_path, ["tests/test_only.py"], {"shards": 2, "seconds": {"tests/test_only.py": 1}})
    assert _SHARDS.main(["--root", str(root), "files", "--shard", "1"]) == 0
    assert capsys.readouterr().out == "tests/test_only.py\n"
    assert _SHARDS.main(["--root", str(root), "files", "--shard", "2"]) == 1
    captured = capsys.readouterr()
    assert captured.out == "" and "shard 2 has no test file to run" in captured.err


def _joined_report(path: Path, suites: dict[str, list[tuple[str, str]]]) -> Path:
    """A joined report: a suite per lane, each case given as (class name, seconds)."""
    body = ""
    for lane, cases in suites.items():
        body += f'<testsuite name="{lane}" tests="{len(cases)}">'
        body += "".join(f'<testcase classname="{classname}" name="test_it" time="{seconds}"/>'
                        for classname, seconds in cases)
        body += "</testsuite>"
    path.write_text(f'<testsuites name="pytest tests">{body}</testsuites>', encoding="utf-8")
    return path


def test_the_times_are_recorded_again_from_a_joined_report(tmp_path, capsys):
    """The seconds come from the shards' suites of a run's joined report: each case's time goes to its
    test file, whatever class it is in. The offline lane's cases are not stack tests and count for
    nothing, and the shard count and the note stay as they were."""
    root = _repository(tmp_path, ["tests/test_a.py", "tests/test_b.py", "tests/deeper/test_nested.py",
                                  "tests/test_offline_only.py"],
                       {"about": "what this file is", "shards": 3, "seconds": {"tests/test_old.py": 99}})
    report = _joined_report(tmp_path / "pytest-results.xml", {
        "offline": [("tests.test_offline_only", "50.0"), ("tests.test_a", "40.0")],
        "shard-1": [("tests.test_a", "1.25"), ("tests.test_a.TestThing", "2.5"),
                    ("tests.test_a.TestThing.TestInner", "0.25")],
        "shard-2": [("tests.test_b", "0.04"), ("tests.deeper.test_nested", "7"),
                    ("tests.test_deleted_since", "3")],
    })

    assert _SHARDS.main(["--root", str(root), "record", str(report)]) == 0
    out = capsys.readouterr().out
    assert "recorded 3 file(s), 0.2 min of stack tests" in out
    assert "1 case(s) of a file that is not there were left out" in out
    written = (root / ".github" / "suite-shards.json").read_bytes()
    assert written.endswith(b"}\n") and b"\r" not in written
    assert json.loads(written) == {
        "about": "what this file is",
        "shards": 3,
        "seconds": {"tests/deeper/test_nested.py": 7.0, "tests/test_a.py": 4.0, "tests/test_b.py": 0.0},
    }
    assert list(json.loads(written)["seconds"]) == sorted(json.loads(written)["seconds"])
    # What was written is data the script reads.
    assert _SHARDS.main(["--root", str(root), "balance"]) == 0
    assert "4 test files: 3 with a recorded time, 1 placed by their path" in capsys.readouterr().out


def test_a_report_without_the_shards_suites_records_nothing(tmp_path, capsys):
    before = {"shards": 2, "seconds": {"tests/test_a.py": 5}}
    root = _repository(tmp_path, ["tests/test_a.py"], before)
    # One session's report (the suite is named as pytest names it), and no report at all.
    one_session = _joined_report(tmp_path / "one.xml", {"pytest": [("tests.test_a", "9")]})
    for report, said in ((one_session, "the report holds no shard's suite"),
                         (tmp_path / "never-written.xml", "no usable report")):
        assert _SHARDS.main(["--root", str(root), "record", str(report)]) == 1
        captured = capsys.readouterr()
        assert captured.out == "" and f"::error::{said}" in captured.err
        assert json.loads((root / ".github" / "suite-shards.json").read_text(encoding="utf-8")) == before
