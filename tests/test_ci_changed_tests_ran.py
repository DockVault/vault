"""Unit coverage for the check that changed tests ran in their lanes (.github/scripts/changed_tests_ran.py).

For every test file added or changed since the last release, each of its tests must be in the report
of every offline lane given (Linux and Windows) or, for a test that needs the stack, in a shard's
report: passed, or skipped with a reason the report shows. The reports here are written by hand and
the history is a repository made for the test.
"""

from __future__ import annotations

import importlib.util
import subprocess
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_SCRIPT = Path(__file__).parents[1] / ".github" / "scripts" / "changed_tests_ran.py"
_SPEC = importlib.util.spec_from_file_location("changed_tests_ran", _SCRIPT)
assert _SPEC and _SPEC.loader
_CHANGED = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_CHANGED)

# What the suite holds at the commit under test. test_new.py and test_edited.py changed since the
# release; test_old.py did not.
_OFFLINE = [
    "tests/test_edited.py::test_unit_one",
    "tests/test_edited.py::TestGroup::test_unit_two[a]",
    "tests/test_new.py::test_unit_three",
    "tests/test_old.py::test_unit_untouched",
]
_STACK = [
    "tests/test_edited.py::test_live_one",
    "tests/test_new.py::test_live_two",
    "tests/test_old.py::test_live_untouched",
]
_SKIP = '<skipped type="pytest.skip" message="{}">tests/test_x.py:3: text</skipped>'


def _git(repository: Path, *arguments: str) -> str:
    done = subprocess.run(["git", "-C", str(repository), *arguments], capture_output=True, text=True,
                          timeout=60)
    assert done.returncode == 0, done.stderr
    return done.stdout.strip()


class _History:
    """A repository with a release and work after it."""

    def __init__(self, path: Path) -> None:
        self.path = path
        path.mkdir()
        _git(path, "init", "-q", "-b", "main")
        for key, value in (("user.name", "Changed Tests"), ("user.email", "changed-tests@example.invalid"),
                           ("commit.gpgsign", "false"), ("tag.gpgsign", "false"), ("core.autocrlf", "false")):
            _git(path, "config", key, value)

    def commit(self, files: dict[str, str | None], message: str, tag: str | None = None) -> str:
        for name, content in files.items():
            target = self.path / name
            if content is None:
                target.unlink()
            else:
                target.parent.mkdir(parents=True, exist_ok=True)
                target.write_text(content, encoding="utf-8")
        _git(self.path, "add", "-A")
        _git(self.path, "commit", "-q", "--allow-empty", "-m", message)
        if tag:
            _git(self.path, "tag", "-a", tag, "-m", tag)
        return _git(self.path, "rev-parse", "HEAD")


@pytest.fixture
def history(tmp_path):
    """v1.0.0, then work that edits one test file, adds one, renames one, deletes one, and touches
    files that are not test files."""
    made = _History(tmp_path / "repository")
    made.commit({
        "tests/test_edited.py": "one\n",
        "tests/test_old.py": "old\n",
        "tests/test_dropped.py": "dropped\n",
        "tests/test_before_rename.py": "a long enough body to be found again after it is renamed\n",
        "tests/conftest.py": "fixtures\n",
        "app/main.py": "app\n",
    }, "release 1.0.0", tag="v1.0.0")
    made.commit({
        "tests/test_edited.py": "two\n",
        "tests/test_new.py": "new\n",
        "tests/deeper/test_nested_new.py": "nested\n",
        "tests/test_dropped.py": None,
        "tests/test_before_rename.py": None,
        "tests/test_after_rename.py": "a long enough body to be found again after it is renamed\n",
        "tests/conftest.py": "other fixtures\n",
        "tests/_helper.py": "helper\n",
        "tests/README.md": "notes\n",
        "app/main.py": "changed app\n",
        "app/test_not_under_tests.py": "elsewhere\n",
    }, "work after the release")
    return made


def _collection(tmp_path: Path, name: str, ids: list[str]) -> Path:
    path = tmp_path / name
    path.write_text("\n".join(ids) + f"\n\n{len(ids)} tests collected in 0.10s\n", encoding="utf-8")
    return path


def _case(test_id: str, inner: str = "") -> str:
    """A report's case for a test id, as pytest names it: the file dotted with any class, then the test."""
    path, _bracket, _rest = test_id.partition("[")
    parts = path.split("::")
    classname = ".".join([parts[0][:-3].replace("/", "."), *parts[1:-1]])
    name = parts[-1] + test_id[len(path):]
    return f'<testcase classname="{classname}" name="{name}" time="0.1">{inner}</testcase>'


def _report(tmp_path: Path, name: str, *cases: str) -> Path:
    path = tmp_path / name
    path.write_text('<testsuites><testsuite name="pytest">' + "".join(cases) + "</testsuite></testsuites>",
                    encoding="utf-8")
    return path


def _run(tmp_path, capsys, history, *, lanes: dict[str, Path], stack: list[Path], base: str | None = None):
    arguments = [
        "--repository", str(history.path),
        "--collected", str(_collection(tmp_path, "collected.txt", _OFFLINE + _STACK)),
        "--offline-collected", str(_collection(tmp_path, "collected-offline.txt", _OFFLINE)),
    ]
    if base:
        arguments += ["--base-ref", base]
    for lane, path in lanes.items():
        arguments += ["--offline-lane", f"{lane}={path}"]
    if stack:
        arguments += ["--stack-report", *[str(path) for path in stack]]
    code = _CHANGED.main(arguments)
    captured = capsys.readouterr()
    return code, captured.out, captured.err


def _all_ran(tmp_path: Path) -> tuple[dict[str, Path], list[Path]]:
    lanes = {
        "linux": _report(tmp_path, "linux.xml", *[_case(test) for test in _OFFLINE]),
        "windows": _report(tmp_path, "windows.xml", *[_case(test) for test in _OFFLINE]),
    }
    stack = [_report(tmp_path, "shard-1.xml", _case(_STACK[0]), _case(_STACK[2])),
             _report(tmp_path, "shard-2.xml", _case(_STACK[1]))]
    return lanes, stack


def test_the_changed_test_files_are_the_added_and_the_edited_ones(history):
    assert _CHANGED.changed_test_files(history.path, "v1.0.0") == [
        "tests/deeper/test_nested_new.py",
        "tests/test_after_rename.py",          # a renamed file is a new file: its tests are named anew
        "tests/test_edited.py",
        "tests/test_new.py",
    ]
    assert _CHANGED.changed_test_files(history.path, "HEAD") == []
    with pytest.raises(ValueError, match="git diff"):
        _CHANGED.changed_test_files(history.path, "v9.9.9")


def test_the_last_release_is_the_highest_tag_behind_this_commit(history):
    assert _CHANGED.last_release_tag(history.path) == "v1.0.0"

    # A maintenance release made on a branch of its own is not behind this commit.
    _git(history.path, "checkout", "-q", "-b", "release/1.0", "v1.0.0")
    history.commit({"VERSION": "1.0.1\n"}, "release 1.0.1", tag="v1.0.1")
    assert _CHANGED.last_release_tag(history.path) == "v1.0.0"       # the tag on this commit is the one being made
    history.commit({"notes.md": "after 1.0.1\n"}, "work on the line")
    assert _CHANGED.last_release_tag(history.path) == "v1.0.1"
    _git(history.path, "checkout", "-q", "main")
    assert _CHANGED.last_release_tag(history.path) == "v1.0.0"

    # Later releases on main: the highest version, not the one that sorts last as text, and nothing
    # that is not a release tag.
    history.commit({"VERSION": "1.9.0\n"}, "release 1.9.0", tag="v1.9.0")
    history.commit({"VERSION": "1.10.0\n"}, "release 1.10.0", tag="v1.10.0")
    history.commit({"notes.md": "next\n"}, "work")
    _git(history.path, "tag", "v2.0.0-rc1")
    _git(history.path, "tag", "vault-import")
    history.commit({"notes.md": "more\n"}, "more work")
    assert _CHANGED.last_release_tag(history.path) == "v1.10.0"
    # On the commit a release is made from, the comparison is with the release before it.
    _git(history.path, "tag", "-a", "v1.11.0", "-m", "v1.11.0")
    assert _CHANGED.last_release_tag(history.path) == "v1.10.0"


def test_a_checkout_without_a_release_tag_is_refused(tmp_path, capsys):
    bare = _History(tmp_path / "no-tags")
    bare.commit({"tests/test_a.py": "a\n"}, "first")
    with pytest.raises(ValueError, match="no release tag is an ancestor of this commit"):
        _CHANGED.last_release_tag(bare.path)

    collected = _collection(tmp_path, "collected.txt", ["tests/test_a.py::test_a"])
    report = _report(tmp_path, "linux.xml", _case("tests/test_a.py::test_a"))
    assert _CHANGED.main(["--repository", str(bare.path), "--collected", str(collected),
                          "--offline-collected", str(collected), "--offline-lane", f"linux={report}"]) == 1
    assert "::error::no release tag is an ancestor of this commit" in capsys.readouterr().err


def test_changed_tests_that_ran_in_every_lane_pass(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    code, out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)

    assert code == 0 and err == ""
    assert ("compared with v1.0.0: 4 test file(s) added or changed, holding 3 offline test(s) "
            "and 2 stack test(s)") in out
    assert "linux: 3 test(s) of the changed files: 3 ran, 0 skipped" in out
    assert "windows: 3 test(s) of the changed files: 3 ran, 0 skipped" in out
    assert "stack: 2 test(s) of the changed files: 2 ran, 0 skipped" in out
    assert out.endswith("OK\n")


def test_a_changed_test_missing_from_one_lane_fails_and_an_unchanged_one_does_not(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    # Windows never ran one changed test, nor the one in the file nobody touched.
    lanes["windows"] = _report(tmp_path, "windows.xml", _case(_OFFLINE[0]), _case(_OFFLINE[1]))
    code, out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)

    assert code == 1 and "OK" not in out
    assert err.strip() == ("::error::windows: 1 test(s) of changed files are not in the report: "
                           "tests/test_new.py::test_unit_three")
    assert "linux: 3 test(s) of the changed files: 3 ran, 0 skipped" in out


def test_a_changed_stack_test_must_be_in_a_shard_report(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    stack[1] = _report(tmp_path, "shard-2.xml")
    code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)

    assert code == 1
    assert "::error::stack: 1 test(s) of changed files are not in the report: tests/test_new.py::test_live_two" in err
    # An offline lane's report does not stand in for a shard's.
    lanes["linux"] = _report(tmp_path, "linux.xml", *[_case(test) for test in _OFFLINE + _STACK])
    code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)
    assert code == 1 and "tests/test_new.py::test_live_two" in err


def test_a_skip_with_a_reason_is_shown_and_one_without_is_refused(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    lanes["windows"] = _report(
        tmp_path, "windows.xml",
        _case(_OFFLINE[0], _SKIP.format("sends POSIX signals to a child process")),
        _case(_OFFLINE[1], _SKIP.format("sends POSIX signals to a child process")),
        _case(_OFFLINE[2], '<skipped type="pytest.xfail" message="known"/>'))
    code, out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)

    assert code == 0 and err == ""
    assert "windows: 3 test(s) of the changed files: 1 ran, 2 skipped" in out     # an expected failure ran
    assert ("  skipped (2): sends POSIX signals to a child process "
            "[tests/test_edited.py::test_unit_one]") in out

    for empty in (_SKIP.format(""), _SKIP.format("   "), "<skipped/>"):
        lanes["windows"] = _report(tmp_path, "windows.xml", _case(_OFFLINE[0], empty),
                                   _case(_OFFLINE[1]), _case(_OFFLINE[2]))
        code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)
        assert code == 1, empty
        assert ("::error::windows: 1 test(s) of changed files are skipped without a reason: "
                "tests/test_edited.py::test_unit_one") in err


def test_a_file_skipped_whole_with_a_reason_stands_for_its_tests(tmp_path, capsys, history):
    """A file that skips itself at import is one case in the report, named after the file."""
    lanes, stack = _all_ran(tmp_path)
    whole = ('<testcase classname="" name="tests.test_edited" time="0.0"><skipped message="collection skipped">'
             "('tests/test_edited.py', 9, 'Skipped: the hook is for Linux')</skipped></testcase>")
    lanes["windows"] = _report(tmp_path, "windows.xml", whole, _case(_OFFLINE[2]))
    code, out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)

    assert code == 0 and err == ""
    assert "windows: 3 test(s) of the changed files: 1 ran, 2 skipped" in out
    assert "Skipped: the hook is for Linux" in out

    # Another file's whole-file skip explains nothing, and neither does one with no reason.
    for other in (whole.replace("tests.test_edited", "tests.test_old"),
                  '<testcase classname="" name="tests.test_edited"><skipped message="collection skipped"/></testcase>'):
        lanes["windows"] = _report(tmp_path, "windows.xml", other, _case(_OFFLINE[2]))
        code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)
        assert code == 1 and "tests/test_edited.py::test_unit_one" in err, other


def test_a_changed_test_that_failed_in_a_lane_fails_the_check(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    for inner in ('<failure message="assert">boom</failure>', '<error message="setup">boom</error>'):
        lanes["windows"] = _report(tmp_path, "windows.xml", _case(_OFFLINE[0], inner),
                                   _case(_OFFLINE[1]), _case(_OFFLINE[2]))
        code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)
        assert code == 1
        assert "::error::windows: 1 test(s) of changed files failed: tests/test_edited.py::test_unit_one" in err


def test_a_lane_whose_report_is_missing_fails(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    lanes["windows"] = tmp_path / "never-uploaded.xml"
    code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)
    assert code == 1
    assert "::error::windows: the report" in err and "is missing: no usable report" in err
    assert "windows: 3 test(s) of changed files are not in the report" in err

    lanes, stack = _all_ran(tmp_path)
    stack.append(tmp_path / "shard-3-never-uploaded.xml")
    code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack)
    assert code == 1 and "::error::stack: the report" in err


def test_the_base_can_be_given_and_nothing_changed_is_nothing_to_check(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    lanes["windows"] = _report(tmp_path, "windows.xml")           # empty: it would fail any changed test
    code, out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack, base="HEAD")
    assert code == 0 and err == ""
    assert "compared with HEAD: 0 test file(s) added or changed, holding 0 offline test(s) and 0 stack test(s)" in out

    code, _out, err = _run(tmp_path, capsys, history, lanes=lanes, stack=stack, base="no-such-ref")
    assert code == 1 and "::error::git diff" in err


def test_what_is_not_looked_up_is_said_and_no_report_at_all_is_refused(tmp_path, capsys, history):
    lanes, stack = _all_ran(tmp_path)
    code, out, _err = _run(tmp_path, capsys, history, lanes=lanes, stack=[])
    assert code == 0 and "stack: 2 test(s) of the changed files not looked up (no stack report given)" in out
    code, out, _err = _run(tmp_path, capsys, history, lanes={}, stack=stack)
    assert code == 0 and "offline: 3 test(s) of the changed files not looked up (no offline lane given)" in out
    with pytest.raises(SystemExit) as stopped:
        _run(tmp_path, capsys, history, lanes={}, stack=[])
    assert stopped.value.code == 2

    # An offline collection that is not part of the whole one is two different commits' output.
    whole = _collection(tmp_path, "whole.txt", _STACK)
    offline = _collection(tmp_path, "offline.txt", _OFFLINE)
    assert _CHANGED.main(["--repository", str(history.path), "--collected", str(whole),
                          "--offline-collected", str(offline), "--offline-lane", f"linux={lanes['linux']}"]) == 1
    assert "the offline collection lists a test the whole collection does not" in capsys.readouterr().err
