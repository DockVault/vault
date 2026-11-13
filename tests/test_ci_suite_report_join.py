"""Unit coverage for the check that joins the lanes' JUnit reports (.github/scripts/join_suite_reports.py).

The suite runs as an offline lane and several shards, each writing its own report. The join is what
says every collected test ran exactly once, so it must accept a correct set of reports and refuse a
test in two reports, a test in none, a missing report and a report case the collection does not
list -- also when the counts happen to add up, which is all the older audit looks at.
"""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
import xml.etree.ElementTree as ET
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_SCRIPTS = Path(__file__).parents[1] / ".github" / "scripts"


def _load(name: str):
    spec = importlib.util.spec_from_file_location(name, _SCRIPTS / f"{name}.py")
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


_JOIN = _load("join_suite_reports")
_AUDIT = _load("pytest_result_audit")

_IDS = [
    "tests/test_a.py::test_one",
    "tests/test_a.py::TestThing::test_two[x-1]",
    "tests/test_b.py::test_three[a/b]",
    "tests/test_c.py::test_four",
]
# The same four tests as a report names them, written out here and not taken from the script.
_ONE = ("tests.test_a", "test_one")
_TWO = ("tests.test_a.TestThing", "test_two[x-1]")
_THREE = ("tests.test_b", "test_three[a/b]")
_FOUR = ("tests.test_c", "test_four")
_SKIPPED = '<skipped type="pytest.skip" message="no mail sink">tests/test_b.py:3: no mail sink</skipped>'
_FAILED = '<failure message="assert 1 == 2">boom</failure>'
_ERRORED = '<error message="failed on teardown">boom</error>'


def _collection(tmp_path: Path, ids: list[str], count_line: str | None = None) -> Path:
    path = tmp_path / "collected.txt"
    lines = [*ids, "", count_line or f"{len(ids)} tests collected in 0.12s"]
    path.write_text("\n".join(lines) + "\n", encoding="utf-8")
    return path


def _report(tmp_path: Path, lane: str, *cases) -> Path:
    """A report as pytest writes one: a suite with its counts and a case per test."""
    body, skipped, failures, errors = "", 0, 0, 0
    for case in cases:
        (classname, name), inner = (case, "") if isinstance(case[0], str) else case
        skipped += "<skipped" in inner
        failures += "<failure" in inner
        errors += "<error" in inner
        body += f'<testcase classname="{classname}" name="{name}" time="1.500">{inner}</testcase>'
    path = tmp_path / f"{lane}.xml"
    path.write_text(
        '<?xml version="1.0" encoding="utf-8"?><testsuites name="pytest tests">'
        f'<testsuite name="pytest" errors="{errors}" failures="{failures}" skipped="{skipped}" '
        f'tests="{len({case if isinstance(case[0], str) else case[0] for case in cases})}" time="3.000">'
        f"{body}</testsuite></testsuites>",
        encoding="utf-8",
    )
    return path


def _run(tmp_path: Path, capsys, reports: dict[str, Path], ids: list[str] = _IDS):
    arguments = ["--collected", str(_collection(tmp_path, ids)), "--output", str(tmp_path / "joined.xml")]
    for lane, path in reports.items():
        arguments += ["--report", f"{lane}={path}"]
    code = _JOIN.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _complete(tmp_path: Path) -> dict[str, Path]:
    return {
        "offline": _report(tmp_path, "offline", _ONE, _TWO),
        "shard-1": _report(tmp_path, "shard-1", (_THREE, _SKIPPED)),
        "shard-2": _report(tmp_path, "shard-2", _FOUR),
    }


def test_a_complete_set_of_reports_is_accepted_and_joined(tmp_path, capsys):
    code, out, err = _run(tmp_path, capsys, _complete(tmp_path))

    assert code == 0 and err == ""
    assert "offline: 2 cases in 0.1 min (2 passed, 0 skipped, 0 failed, 0 errored)" in out
    assert "shard-1: 1 cases in 0.1 min (0 passed, 1 skipped, 0 failed, 0 errored)" in out
    assert out.endswith("every one of the 4 collected tests is in exactly one report\nOK\n")

    # One file, a suite per lane named after it, every case kept with its time and outcome.
    joined = ET.parse(tmp_path / "joined.xml").getroot()
    assert joined.tag == "testsuites"
    assert [suite.get("name") for suite in joined] == ["offline", "shard-1", "shard-2"]
    cases = [(case.get("classname"), case.get("name"), case.get("time")) for case in joined.iter("testcase")]
    assert cases == [(*key, "1.500") for key in (_ONE, _TWO, _THREE, _FOUR)]
    assert len(joined.findall(".//skipped")) == 1
    # The audit the single job's report went through reads the joined one as it stands.
    assert _AUDIT.audit(tmp_path / "joined.xml", 4, 0.5) == "collected=4 ran=3 skipped=1 failed=0 errored=0"
    assert (tmp_path / "joined.xml").read_bytes().startswith(b"<?xml version='1.0' encoding='utf-8'?>")


def test_the_runs_skips_are_printed_by_reason(tmp_path, capsys):
    """Seven reports' skips are in seven logs. The join prints them together, the most frequent
    reason first, so a test that stopped running shows in one place."""
    mail = '<skipped type="pytest.skip" message="no mail sink">tests/test_b.py:3: no mail sink</skipped>'
    windows = '<skipped type="pytest.skip" message="needs a real Windows host">x</skipped>'
    reports = {
        "offline": _report(tmp_path, "offline", (_ONE, windows), (_TWO, mail)),
        "shard-1": _report(tmp_path, "shard-1", (_THREE, mail)),
        "shard-2": _report(tmp_path, "shard-2", (_FOUR, "<skipped/>")),
    }
    code, out, _err = _run(tmp_path, capsys, reports)

    assert code == 0
    assert ("4 skipped, by reason:\n"
            "  2: no mail sink\n"
            "  1: needs a real Windows host\n"
            "  1: no reason given\n") in out

    # A run with no skip says nothing about skips.
    code, out, _err = _run(tmp_path, capsys, {"offline": _report(tmp_path, "offline", _ONE, _TWO, _THREE, _FOUR)})
    assert code == 0 and "skipped, by reason" not in out


def test_a_test_in_two_reports_is_refused(tmp_path, capsys):
    reports = _complete(tmp_path)
    reports["shard-1"] = _report(tmp_path, "shard-1", (_THREE, _SKIPPED), _FOUR)
    code, out, err = _run(tmp_path, capsys, reports)

    assert code == 1 and "OK" not in out
    assert ("::error::1 test(s) are in a report more than once: "
            "tests/test_c.py::test_four (shard-1, shard-2)") in err
    assert (tmp_path / "joined.xml").is_file()            # written for the run to keep, failed or not


def test_a_test_in_no_report_is_refused(tmp_path, capsys):
    reports = _complete(tmp_path)
    reports["shard-2"] = _report(tmp_path, "shard-2")
    code, out, err = _run(tmp_path, capsys, reports)

    assert code == 1 and "OK" not in out
    assert "::error::1 collected test(s) are in no report: tests/test_c.py::test_four" in err


def test_counts_that_add_up_do_not_hide_a_test_that_did_not_run(tmp_path, capsys):
    """One test left out and another run twice: four cases for four collected tests. The count audit
    passes on that; the names do not."""
    reports = {
        "offline": _report(tmp_path, "offline", _ONE, _TWO),
        "shard-1": _report(tmp_path, "shard-1", _THREE),
        "shard-2": _report(tmp_path, "shard-2", _THREE),
    }
    code, _out, err = _run(tmp_path, capsys, reports)

    assert _AUDIT.audit(tmp_path / "joined.xml", 4, 0.5).startswith("collected=4 ran=4")
    assert code == 1
    assert "1 collected test(s) are in no report: tests/test_c.py::test_four" in err
    assert "1 test(s) are in a report more than once: tests/test_b.py::test_three[a/b] (shard-1, shard-2)" in err


@pytest.mark.parametrize("content, said", [
    (None, "the shard-2 report is missing: no usable report"),
    ("<testsuites><testsuite", "the shard-2 report is missing: no usable report"),
    ("<testsuites/>", "the shard-2 report is missing: the report contains no test suite"),
], ids=["no-file", "cut-off", "no-suite"])
def test_a_missing_or_unreadable_report_is_refused(tmp_path, capsys, content, said):
    reports = _complete(tmp_path)
    if content is None:
        reports["shard-2"].unlink()
    else:
        reports["shard-2"].write_text(content, encoding="utf-8")
    code, out, err = _run(tmp_path, capsys, reports)

    assert code == 1 and "OK" not in out
    assert f"::error::{said}" in err
    assert "shard-2: no report" in out
    # The lanes that did report are still joined, for the run to keep.
    joined = ET.parse(tmp_path / "joined.xml").getroot()
    assert [suite.get("name") for suite in joined] == ["offline", "shard-1"]


def test_a_report_case_the_collection_does_not_list_is_refused(tmp_path, capsys):
    reports = _complete(tmp_path)
    reports["shard-2"] = _report(tmp_path, "shard-2", _FOUR, ("tests.test_c", "test_from_another_commit"),
                                 (("", "tests.test_skipped_whole"), _SKIPPED))
    code, _out, err = _run(tmp_path, capsys, reports)

    assert code == 1
    assert ("::error::2 report case(s) are not in the collection: "
            "tests.test_c.test_from_another_commit (shard-2); tests.test_skipped_whole (shard-2)") in err


def test_one_report_listing_a_test_twice_is_refused(tmp_path, capsys):
    reports = _complete(tmp_path)
    reports["shard-2"] = _report(tmp_path, "shard-2", _FOUR, _FOUR)
    code, _out, err = _run(tmp_path, capsys, reports)

    assert code == 1
    assert "1 test(s) are in a report more than once: tests/test_c.py::test_four (shard-2, shard-2)" in err


def test_two_collected_tests_a_report_names_alike_are_refused(tmp_path, capsys):
    """A report names a test by its file's path with dots, its classes and its name, so a test in a
    class and a test in a file inside a directory of the first file's name are written the same. One
    case in a report would then stand for both, and the other could be missing unseen: the join says
    so instead of counting them as one."""
    ids = ["tests/test_a.py::TestThing::test_two", "tests/test_a/TestThing.py::test_two", "tests/test_c.py::test_four"]
    same = ("tests.test_a.TestThing", "test_two")
    code, out, err = _run(tmp_path, capsys, {"offline": _report(tmp_path, "offline", same, _FOUR)}, ids)

    assert code == 1 and "OK" not in out
    assert err.strip() == ("::error::tests/test_a.py::TestThing::test_two and tests/test_a/TestThing.py::test_two "
                           "have the same name in a report, so they cannot be told apart")


def test_a_failure_and_its_teardown_error_are_one_test(tmp_path, capsys):
    """pytest writes a test that failed and then failed again in teardown as two cases with one name.
    That is not a test run twice; the report still fails, at the audit, for the failure."""
    reports = _complete(tmp_path)
    reports["shard-2"] = _report(tmp_path, "shard-2", (_FOUR, _FAILED), (_FOUR, _ERRORED))
    code, out, err = _run(tmp_path, capsys, reports)

    assert code == 0 and err == ""
    assert "shard-2: 2 cases in 0.1 min (0 passed, 0 skipped, 1 failed, 1 errored)" in out
    with pytest.raises(ValueError, match="1 failed, 1 errored"):
        _AUDIT.audit(tmp_path / "joined.xml", 4, 0.5)

    # Any other pair is a test listed twice: an error first, or two failures.
    for pair in ((_ERRORED, _FAILED), (_FAILED, _FAILED), ("", _ERRORED)):
        reports["shard-2"] = _report(tmp_path, "shard-2", (_FOUR, pair[0]), (_FOUR, pair[1]))
        code, _out, err = _run(tmp_path, capsys, reports)
        assert code == 1 and "tests/test_c.py::test_four (shard-2, shard-2)" in err, pair


def test_a_long_list_of_names_is_cut_short(tmp_path, capsys):
    ids = [f"tests/test_many.py::test_{number:03d}" for number in range(_JOIN.SHOWN + 5)]
    code, _out, err = _run(tmp_path, capsys, {"offline": _report(tmp_path, "offline")}, ids)

    assert code == 1
    assert f"::error::{len(ids)} collected test(s) are in no report: tests/test_many.py::test_000; " in err
    assert err.rstrip().endswith(f"tests/test_many.py::test_{_JOIN.SHOWN - 1:03d}; and 5 more")


def test_each_lane_is_given_once(tmp_path, capsys):
    reports = _complete(tmp_path)
    with pytest.raises(SystemExit) as stopped:
        _JOIN.main(["--collected", str(_collection(tmp_path, _IDS)), "--output", str(tmp_path / "joined.xml"),
                    "--report", f"shard-1={reports['shard-1']}", "--report", f"shard-1={reports['shard-2']}"])
    assert stopped.value.code == 2
    assert "each lane is given once" in capsys.readouterr().err
    with pytest.raises(SystemExit):
        _JOIN.main(["--collected", "c.txt", "--output", "j.xml", "--report", "no-equals-sign"])


def test_the_collection_is_read_as_pytest_prints_it(tmp_path):
    # The whole suite, a selection, and a single test; with warnings between the ids and the count.
    assert _JOIN.read_collection(_collection(tmp_path, _IDS)) == _IDS
    assert _JOIN.read_collection(_collection(
        tmp_path, _IDS[:2], "2/4 tests collected (2 deselected) in 46.31s")) == _IDS[:2]
    assert _JOIN.read_collection(_collection(tmp_path, _IDS[:1], "1 test collected in 0.01s")) == _IDS[:1]
    with_warnings = tmp_path / "with-warnings.txt"
    with_warnings.write_text(
        "\n".join(_IDS) + "\n\n"
        "============================== warnings summary ===============================\n"
        "tests/test_a.py:89\n"
        "  /somewhere/tests/test_a.py:89: DeprecationWarning: utcnow() is deprecated\n"
        "    stamp = utcnow()\n\n"
        "-- Docs: https://docs.pytest.org/en/stable/how-to/capture-warnings.html\n"
        "4 tests collected in 45.76s\n", encoding="utf-8")
    assert _JOIN.read_collection(with_warnings) == _IDS


@pytest.mark.parametrize("text, said", [
    ("", "does not end with one count"),
    ("tests/test_a.py::test_one\n", "does not end with one count"),
    ("tests/test_a.py::test_one\n\n2 tests collected in 0.1s\n", "lists 1 tests and says it collected 2"),
    ("\n0 tests collected in 0.1s\n", "lists 0 tests and says it collected 0"),
    ("tests/test_a.py::test_one\ntests/test_a.py::test_one\n\n2 tests collected in 0.1s\n", "lists a test twice"),
    ("ERROR tests/test_a.py - SyntaxError\n\n1 test collected in 0.1s\n", "is not a test id"),
    ("tests/test_a.py::test_one\n\n1 test collected in 0.1s\n1 test collected in 0.2s\n",
     "does not end with one count"),
    ("tests/test_a.py::test_one\n\n1 test collected, 1 error in 0.1s\n", "does not end with one count"),
], ids=["empty", "no-count", "wrong-count", "nothing-collected", "twice", "an-error", "two-counts", "errors"])
def test_what_is_not_a_collection_is_refused(tmp_path, capsys, text, said):
    path = tmp_path / "collected.txt"
    path.write_text(text, encoding="utf-8")
    with pytest.raises(ValueError, match=said):
        _JOIN.read_collection(path)
    with pytest.raises(ValueError, match="no usable collection"):
        _JOIN.read_collection(tmp_path / "never-written.txt")

    report = _report(tmp_path, "offline", _ONE)
    assert _JOIN.main(["--collected", str(path), "--report", f"offline={report}",
                       "--output", str(tmp_path / "joined.xml")]) == 1
    assert "::error::" in capsys.readouterr().err
    assert not (tmp_path / "joined.xml").exists()


_PROBE = '''
import pytest


def test_plain():
    pass


class TestGroup:
    def test_in_a_class(self):
        pass

    @pytest.mark.parametrize("value", ["a/b", "x::y", "has space", "br[ack]et", "caf\\u00e9", "tab\\there",
                                       "<&>\\"'"])
    def test_with_a_parameter(self, value):
        pass

    class TestNested:
        def test_deeper(self):
            pass


@pytest.mark.parametrize("value", [1, 2], ids=["one", "two"])
def test_with_ids(value):
    pass


@pytest.mark.skip(reason="not today")
def test_skipped():
    pass
'''


def test_the_names_are_the_ones_pytest_writes(tmp_path, capsys):
    """The join compares a collection's test ids with a report's class and test names, so it must turn
    one into the other exactly as pytest does. Here pytest itself collects a file and then runs it
    with a report: classes, nested classes, and parameters holding a slash, `::`, brackets, a space,
    a letter outside ASCII, a tab and XML's own characters."""
    (tmp_path / "pytest.ini").write_text("[pytest]\n", encoding="utf-8")
    (tmp_path / "tests").mkdir()
    (tmp_path / "tests" / "test_probe.py").write_text(_PROBE, encoding="utf-8")
    env = dict(os.environ, PYTEST_DISABLE_PLUGIN_AUTOLOAD="1", PYTHONUTF8="1")
    base = [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider", "tests"]

    collected = subprocess.run([*base, "--collect-only"], cwd=tmp_path, env=env, capture_output=True,
                               text=True, encoding="utf-8", timeout=120)
    assert collected.returncode == 0, collected.stdout + collected.stderr
    (tmp_path / "collected.txt").write_text(collected.stdout, encoding="utf-8")
    ran = subprocess.run([*base, "--junitxml=report.xml"], cwd=tmp_path, env=env, capture_output=True,
                         text=True, encoding="utf-8", timeout=120)
    assert ran.returncode == 0, ran.stdout + ran.stderr

    ids = _JOIN.read_collection(tmp_path / "collected.txt")
    assert len(ids) == 13 and "tests/test_probe.py::TestGroup::TestNested::test_deeper" in ids
    assert any("x::y" in test for test in ids) and any("br[ack]et" in test for test in ids)
    code = _JOIN.main(["--collected", str(tmp_path / "collected.txt"), "--report",
                       f"all={tmp_path / 'report.xml'}", "--output", str(tmp_path / "joined.xml")])
    captured = capsys.readouterr()
    assert code == 0, captured.err
    assert "all: 13 cases" in captured.out and "(12 passed, 1 skipped, 0 failed, 0 errored)" in captured.out
