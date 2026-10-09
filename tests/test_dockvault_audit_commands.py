"""dockvault.py's audit commands on the host: each that writes a seal runs in two steps (read, then write with the
state the read printed), an old key goes to the tool on its standard input and never on a command line, and what
the read asks to confirm by name is typed or given with --confirm. The tool in the container is stubbed."""
import pytest

import dockvault as dv

pytestmark = pytest.mark.unit


class _Calls:
    def __init__(self, read_answer, write_answer):
        self.calls = []
        self.read_answer = read_answer
        self.write_answer = write_answer

    def __call__(self, *args, input_text=None):
        self.calls.append((list(args), input_text))
        return self.read_answer if "--read" in args else self.write_answer


def _tool(tmp_path, monkeypatch, read_answer, write_answer):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    calls = _Calls(read_answer, write_answer)
    monkeypatch.setattr(tool, "_audit_tool", calls)
    return tool, calls


def _args(*argv):
    return dv.build_parser().parse_args(["audit", *argv])


def test_rekey_reads_then_writes_with_the_state_shown_and_the_key_on_standard_input(tmp_path, monkeypatch):
    key = tmp_path / "old.key"
    key.write_text("k" * 64 + "\n", encoding="utf-8")
    tool, calls = _tool(tmp_path, monkeypatch, {"ok": True, "state": "dvstate1:abc", "lines": ["x"]},
                        {"ok": True, "sealed": 9})
    tool.audit(_args("rekey", "--old-key-file", str(key), "--yes"))
    (read, read_in), (write, write_in) = calls.calls
    assert read == ["rekey", "--old-key-stdin", "--read"]
    assert write == ["rekey", "--old-key-stdin", "--expect", "dvstate1:abc"]
    assert read_in == write_in == "k" * 64 + "\n"
    assert not any("k" * 64 in a for a in read + write)


def test_a_confirmation_by_name_is_needed_before_the_write(tmp_path, monkeypatch):
    read = {"ok": True, "state": "dvstate1:s", "lines": [], "confirm": ["deleted-through-12"]}
    tool, calls = _tool(tmp_path, monkeypatch, read, {"ok": True, "restored": 13})
    with pytest.raises(SystemExit):
        tool.audit(_args("accept-database-head", "--yes"))
    assert len(calls.calls) == 1
    tool, calls = _tool(tmp_path, monkeypatch, read, {"ok": True, "restored": 13})
    tool.audit(_args("accept-database-head", "--yes", "--confirm", "deleted-through-12"))
    assert calls.calls[-1][0] == ["accept-database-head", "--expect", "dvstate1:s", "--confirm",
                                  "deleted-through-12"]


def test_typing_anything_but_yes_writes_nothing(tmp_path, monkeypatch):
    tool, calls = _tool(tmp_path, monkeypatch, {"ok": True, "state": "dvstate1:s", "lines": []}, {"ok": True})
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    tool.audit(_args("acknowledge", "--seqs", "4"))
    assert [c[0][-1] for c in calls.calls] == ["--read"]


@pytest.mark.parametrize("argv,tool_args", [
    (["acknowledge", "--late-rows", "2026-10-20T07:00:00Z"], ["acknowledge", "--late-rows", "2026-10-20T07:00:00Z"]),
    (["acknowledge", "--rows", "a,b", "--failures"], ["acknowledge", "--failures", "--rows", "a,b"]),
    (["after-record", "--discard", "--discard-from", "17"], ["after-record", "--discard", "--from", "17"]),
    (["accept-restore", "--no-reseal"], ["accept-restore", "--no-reseal"]),
    (["acknowledge-removed-before", "--before", "2026-09-19T18:00:00Z", "--retention-days", "34"],
     ["acknowledge-removed-before", "2026-09-19T18:00:00Z", "--retention-days", "34"]),
    (["verify", "--acknowledge-removed-before", "2026-09-19T18:00:00Z", "--retention-days", "34"],
     ["acknowledge-removed-before", "2026-09-19T18:00:00Z", "--retention-days", "34"]),
    (["rekey", "--accept-unverified-history"], ["rekey", "--accept-unverified-history"]),
])
def test_each_command_hands_the_tool_its_arguments(tmp_path, monkeypatch, argv, tool_args):
    tool, calls = _tool(tmp_path, monkeypatch, {"ok": True, "state": "dvstate1:s", "lines": []}, {"ok": True})
    tool.audit(_args(*argv, "--yes"))
    assert calls.calls[0][0] == tool_args + ["--read"]
    assert calls.calls[1][0] == tool_args + ["--expect", "dvstate1:s"]


def test_a_refused_write_fails_the_command(tmp_path, monkeypatch):
    tool, calls = _tool(tmp_path, monkeypatch, {"ok": True, "state": "dvstate1:s", "lines": []},
                        {"ok": False, "error": "the chain changed since you looked"})
    with pytest.raises(SystemExit):
        tool.audit(_args("acknowledge", "--failures", "--yes"))


def test_a_name_typed_wrong_writes_nothing_even_when_yes_follows(tmp_path, monkeypatch):
    read = {"ok": True, "state": "dvstate1:s", "lines": [], "confirm": ["deleted-through-12"]}
    tool, calls = _tool(tmp_path, monkeypatch, read, {"ok": True, "restored": 13})
    answers = iter(["deleted-through-1", "yes"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    tool.audit(_args("accept-database-head"))
    assert [c[0][-1] for c in calls.calls] == ["--read"]


@pytest.mark.parametrize("argv,extra", [
    ([], []),
    (["--anchor", "dvchain1:7:ab"], ["--anchor", "dvchain1:7:ab"]),
    (["--anchor", "dvchain1:7:ab", "--no-key"], ["--anchor", "dvchain1:7:ab", "--no-key"]),
])
def test_verify_hands_the_check_its_anchor_and_the_keyless_flag(tmp_path, monkeypatch, argv, extra):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    seen = []

    class _Done:
        stdout = '{"ok": true, "head": "dvchain1:9:cd", "seals": 9, "exit_code": 0, "findings": []}\n'

    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(tool, "_run_dc", lambda *args, **kw: seen.append(list(args)) or _Done())
    tool.audit(_args("verify", *argv))
    assert seen[0][seen[0].index("app.core.audit_integrity") + 1:] == ["verify", "--json", *extra]
