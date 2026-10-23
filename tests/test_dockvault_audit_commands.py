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


# --------------------------------------------------------------------------- unarchive and compact

def _df(free_kb):
    class _Done:
        stdout = ("Filesystem     1024-blocks    Used Available Capacity Mounted on\n"
                  f"/dev/sda1         1000000    1000 {free_kb}      1% /var/lib/postgresql/data\n")
    return _Done()


def _unarchive_tool(tmp_path, monkeypatch, free_kb, high=12000):
    read = {"ok": True, "state": "dvstate1:u", "lines": ["2 archived days"],
            "estimate": {"restored_low_bytes": 7000, "restored_high_bytes": high}}
    tool, calls = _tool(tmp_path, monkeypatch, read, {"ok": True, "days": ["2026-07-01"], "rows": 3})
    asked = []
    monkeypatch.setattr(tool, "_run_dc", lambda *args, **kw: asked.append(list(args)) or _df(free_kb))
    return tool, calls, asked


def test_unarchive_reads_checks_the_free_space_then_writes(tmp_path, monkeypatch):
    tool, calls, asked = _unarchive_tool(tmp_path, monkeypatch, free_kb=100)
    tool.audit(_args("unarchive", "--from", "2026-07-01", "--to", "2026-07-02T00:00:00Z", "--yes"))
    assert calls.calls[0][0] == ["unarchive", "--from", "2026-07-01", "--to", "2026-07-02", "--read"]
    assert calls.calls[1][0] == ["unarchive", "--from", "2026-07-01", "--to", "2026-07-02", "--expect", "dvstate1:u"]
    assert asked == [["exec", "-T", dv.DB_CONTAINER, "df", "-Pk", "/var/lib/postgresql/data"]]


def test_unarchive_refuses_with_the_numbers_when_the_days_would_not_fit(tmp_path, monkeypatch, capsys):
    tool, calls, _asked = _unarchive_tool(tmp_path, monkeypatch, free_kb=10, high=12000)    # 10 KB free
    with pytest.raises(SystemExit) as stop:
        tool.audit(_args("unarchive", "--yes"))
    assert stop.value.code == 1
    assert [c[0][-1] for c in calls.calls] == ["--read"]
    out = capsys.readouterr().out
    assert "would not fit" in out and dv.format_bytes(12000) in out and dv.format_bytes(10 * 1024) in out


def test_unarchive_refuses_when_the_free_space_cannot_be_read(tmp_path, monkeypatch):
    tool, calls, _asked = _unarchive_tool(tmp_path, monkeypatch, free_kb=100)
    monkeypatch.setattr(tool, "_db_free_bytes", lambda: None)
    with pytest.raises(SystemExit):
        tool.audit(_args("unarchive", "--yes"))
    assert [c[0][-1] for c in calls.calls] == ["--read"]


def test_df_output_is_read_for_its_available_bytes():
    assert dv.parse_df_available(_df(2048).stdout) == 2048 * 1024
    assert dv.parse_df_available("") is None
    assert dv.parse_df_available("Filesystem 1024-blocks Used Available\n/dev/x 1 2 lots\n") is None


def test_compact_warns_and_asks_first(tmp_path, monkeypatch, capsys):
    tool, calls = _tool(tmp_path, monkeypatch, {}, {"ok": True, "tables": [
        {"table": "audit_logs", "before_bytes": 4096, "after_bytes": 2048}]})
    monkeypatch.setattr("builtins.input", lambda prompt="": "no")
    tool.audit(_args("compact"))
    assert calls.calls == [] and "locked" in capsys.readouterr().out
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    tool.audit(_args("compact"))
    assert calls.calls[0][0] == ["compact"]
