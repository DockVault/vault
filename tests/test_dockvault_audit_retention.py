"""dockvault.py's audit menu and `audit retention` on the host, with the tool in the container stubbed.

Chosen from the top menu, `audit` asks what to do: how long records are kept, verify, unarchive or compact.
`audit retention` prints what the server answers (each setting's value in force, where it comes from, the .env
lines that set and bound it, the changes waiting). With --set NAME=VALUE the server checks the lines first; a line
it refuses writes nothing, one that deletes sooner is said to and written only after yes (or --yes), a locked
.env is never written, and what the server sends is cleaned before it reaches the terminal.
"""
import pytest

import dockvault as dv

pytestmark = pytest.mark.unit

SETTINGS = [
    {"key": "audit_max_days", "group": "audit_retention", "label": "Keep audit rows for at most", "unit": "days",
     "kind": "int", "value": 0, "source": "default", "unlimited": 0, "env": "AUDIT_LOG_RETENTION_DAYS",
     "ceiling": None, "ceiling_env": "PLAN_LOG_MAX_DAYS", "floor": None, "floor_env": None, "editable": "admin"},
    {"key": "security_record_days", "group": "retention", "label": "Keep failed sign-ins in full for",
     "unit": "days", "kind": "int", "value": 40, "source": "admin", "unlimited": None, "env": "SECURITY_RECORD_DAYS",
     "floor": 7, "floor_env": "SECURITY_RECORD_MIN_DAYS", "ceiling": 365, "ceiling_env": "SECURITY_RECORD_MAX_DAYS",
     "editable": "admin"},
    {"key": "logs_hold", "group": "retention", "label": "Hold all deletion of logs", "unit": "", "kind": "bool",
     "value": True, "source": "env", "unlimited": None, "env": "RETENTION_HOLD", "floor": False,
     "floor_env": "RETENTION_HOLD", "ceiling": None, "ceiling_env": None, "editable": "admin"},
    {"key": "log_pull_sink_max_mb", "group": "retention", "label": "Size of the log-access file", "unit": "MB",
     "kind": "int", "value": 15, "source": "default", "unlimited": None, "env": "LOG_PULL_SINK_MAX_MB",
     "editable": "env_only"},
    {"key": "ended_invitation_days", "group": "working_records", "label": "Invitations that ended", "unit": "days",
     "kind": "int", "value": 30, "source": "default", "unlimited": None, "env": None, "editable": "fixed"},
]
PENDING = [{"key": "audit_max_days", "label": "Keep audit rows for at most", "old": 0, "new": 30,
            "effective_at": "2026-10-27T12:00:00Z", "requested_by": "ada", "status": "waiting"}]


class _Tool:
    def __init__(self, check=None, error=None):
        self.calls = []
        self.check = check
        self.error = error

    def __call__(self, *args, input_text=None):
        self.calls.append(list(args))
        if self.error:
            return {"ok": False, "error": self.error}
        out = {"ok": True, "settings": SETTINGS, "pending": PENDING, "chain_started": True}
        if "--set" in args:
            out["check"] = self.check or {"problems": [], "changes": [], "deletes_sooner": []}
        return out


def _setup(tmp_path, monkeypatch, check=None, error=None, env="EXISTING=1\n"):
    tool = dv.DockVault(dv.Palette(False), root=str(tmp_path))
    stub = _Tool(check, error)
    monkeypatch.setattr(tool, "_audit_tool", stub)
    monkeypatch.setattr(dv, "tighten_secret_file", lambda _p: True)
    if env is not None:
        (tmp_path / ".env").write_text(env, encoding="utf-8")
    return tool, stub


def _args(*argv):
    return dv.build_parser().parse_args(["audit", *argv])


def _env(tmp_path):
    return (tmp_path / ".env").read_text(encoding="utf-8")


def test_the_parser_takes_retention_and_its_lines():
    a = _args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30", "--set", "RETENTION_HOLD=true", "--yes")
    assert (a.audit_action, a.audit_set, a.yes) == ("retention", ["AUDIT_LOG_RETENTION_DAYS=30", "RETENTION_HOLD=true"],
                                                   True)
    assert _args().audit_action == "verify"
    with pytest.raises(SystemExit):
        _args("retain")


def test_the_top_menu_names_what_the_audit_menu_does():
    label = dict(dv.MENU)["audit"]
    for word in ("retention", "verify", "unarchive", "compact"):
        assert word in label
    assert [k for k, _ in dv.AUDIT_MENU] == ["retention", "verify", "unarchive", "compact"]


@pytest.mark.parametrize("texts, ok", [
    (["AUDIT_LOG_RETENTION_DAYS=30"], [("AUDIT_LOG_RETENTION_DAYS", "30")]),
    ([" RETENTION_HOLD = true "], [("RETENTION_HOLD", "true")]),
    (["A=1", "B=x=y"], [("A", "1"), ("B", "x=y")]),
    ([], []),
])
def test_lines_are_read_as_name_and_value(texts, ok):
    assert dv.parse_retention_sets(texts) == ok


@pytest.mark.parametrize("texts", [["AUDIT_LOG_RETENTION_DAYS"], ["audit_log_retention_days=30"], ["A="],
                                   ["=1"], ["A=1\nB=2"], ["A=1", "A=2"], ["1A=2"]])
def test_a_line_not_of_that_form_is_refused(texts):
    with pytest.raises(ValueError):
        dv.parse_retention_sets(texts)


def test_retention_shows_what_the_server_has(tmp_path, monkeypatch, capsys):
    tool, stub = _setup(tmp_path, monkeypatch)
    tool.audit(_args("retention"))
    assert stub.calls == [["retention"]]
    out = capsys.readouterr().out
    for text in ("Audit log", "Keep audit rows for at most", "no limit", "default; set by AUDIT_LOG_RETENTION_DAYS",
                 "Other records", "40 days", "set in the panel", "at least 7 days (SECURITY_RECORD_MIN_DAYS)",
                 "at most 365 days (SECURITY_RECORD_MAX_DAYS)", "on", "from .env; set by RETENTION_HOLD",
                 "15 MB", "only .env changes it", "Fixed periods", "fixed",
                 "Waiting", "Keep audit rows for at most: 0 -> 30 from 2026-10-27T12:00:00Z, asked by ada"):
        assert text in out, text
    # A switch's floor of off holds nothing, so nothing is said of it.
    assert "at least off" not in out and "kept on by" not in out
    assert _env(tmp_path) == "EXISTING=1\n"


def test_a_switch_held_on_by_env_says_so():
    held = dict(SETTINGS[2], floor=True)
    lines = dv.describe_retention({"settings": [held]})
    assert any("from .env; set by RETENTION_HOLD; kept on by RETENTION_HOLD" in line for line in lines), lines
    assert not any("at least" in line for line in lines)


def test_a_failure_of_the_server_fails_the_command(tmp_path, monkeypatch):
    tool, stub = _setup(tmp_path, monkeypatch, error="refused: NOPE is not a .env line")
    with pytest.raises(SystemExit):
        tool.audit(_args("retention", "--set", "NOPE=1"))
    assert stub.calls == [["retention", "--set", "NOPE=1"]]
    assert _env(tmp_path) == "EXISTING=1\n"


def test_the_tool_hands_the_server_each_line_to_check(tmp_path, monkeypatch):
    tool, stub = _setup(tmp_path, monkeypatch)
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30", "--set", "RETENTION_HOLD=true", "--yes"))
    assert stub.calls == [["retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30", "--set", "RETENTION_HOLD=true"]]


def test_a_line_the_server_would_not_start_with_writes_nothing(tmp_path, monkeypatch, capsys):
    check = {"problems": ["SECURITY_RECORD_MIN_DAYS (400) is above SECURITY_RECORD_MAX_DAYS (365)"], "changes": [],
             "deletes_sooner": []}
    tool, _stub = _setup(tmp_path, monkeypatch, check=check)
    with pytest.raises(SystemExit) as stop:
        tool.audit(_args("retention", "--set", "SECURITY_RECORD_MIN_DAYS=400", "--yes"))
    assert stop.value.code == 2
    assert "nothing written" in capsys.readouterr().out
    assert _env(tmp_path) == "EXISTING=1\n"


SOONER = {"problems": [], "deletes_sooner": ["audit_max_days"],
          "changes": [{"key": "audit_max_days", "label": "Keep audit rows for at most", "unit": "days",
                       "unlimited": 0, "before": 0, "after": 30}]}


def test_a_line_that_deletes_sooner_is_said_to_and_written_only_after_yes(tmp_path, monkeypatch, capsys):
    tool, _stub = _setup(tmp_path, monkeypatch, check=SOONER)
    asked = []
    monkeypatch.setattr("builtins.input", lambda prompt="": asked.append(prompt) or "no")
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30"))
    out = capsys.readouterr().out
    assert "Keep audit rows for at most: no limit -> 30 days  (deletes sooner)" in out
    assert "deletes records sooner, at the restart" in out
    assert len(asked) == 1 and _env(tmp_path) == "EXISTING=1\n"
    monkeypatch.setattr("builtins.input", lambda prompt="": "yes")
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30"))
    assert _env(tmp_path) == "EXISTING=1\nAUDIT_LOG_RETENTION_DAYS=30\n"
    assert "python dockvault.py restart" in capsys.readouterr().out


def test_with_yes_the_line_is_written_without_asking_and_replaces_the_old_one(tmp_path, monkeypatch):
    tool, _stub = _setup(tmp_path, monkeypatch, check=SOONER, env="AUDIT_LOG_RETENTION_DAYS=0\nEXISTING=1\n")
    monkeypatch.setattr("builtins.input", lambda prompt="": pytest.fail("asked"))
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30", "--yes"))
    assert _env(tmp_path) == "AUDIT_LOG_RETENTION_DAYS=30\nEXISTING=1\n"


@pytest.mark.parametrize("answer", ["", "y", "Y", "ok", "no", "yes please", None])
def test_only_yes_writes(tmp_path, monkeypatch, capsys, answer):
    """Enter, y, anything but yes, or the end of the input: nothing is written."""
    tool, _stub = _setup(tmp_path, monkeypatch, check=SOONER)

    def ask(prompt=""):
        if answer is None:
            raise EOFError
        return answer
    monkeypatch.setattr("builtins.input", ask)
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30"))
    assert _env(tmp_path) == "EXISTING=1\n"
    assert "Nothing written." in capsys.readouterr().out


@pytest.mark.parametrize("answer", ["yes", "YES", " Yes "])
def test_yes_in_any_case_writes(tmp_path, monkeypatch, answer):
    tool, _stub = _setup(tmp_path, monkeypatch, check=SOONER)
    monkeypatch.setattr("builtins.input", lambda prompt="": answer)
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30"))
    assert _env(tmp_path) == "EXISTING=1\nAUDIT_LOG_RETENTION_DAYS=30\n"


def test_every_line_given_is_written(tmp_path, monkeypatch):
    tool, _stub = _setup(tmp_path, monkeypatch, env="RETENTION_HOLD=false\nEXISTING=1\n")
    tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30", "--set", "RETENTION_HOLD=true", "--set",
                     "LOG_PULL_SINK_MAX_MB=60", "--yes"))
    assert _env(tmp_path) == ("RETENTION_HOLD=true\nEXISTING=1\nAUDIT_LOG_RETENTION_DAYS=30\n"
                              "LOG_PULL_SINK_MAX_MB=60\n")


def test_values_the_chain_could_not_give_are_said_to_be_the_databases(tmp_path, monkeypatch, capsys):
    tool, _stub = _setup(tmp_path, monkeypatch)
    answer = {"ok": True, "settings": SETTINGS, "pending": [], "chain_unreadable": "ChainBusy: busy, retry"}
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, input_text=None: answer)
    tool.audit(_args("retention"))
    out = capsys.readouterr().out
    assert ("The audit chain could not be read (ChainBusy: busy, retry): the values are the database's, not "
            "necessarily what the pruner acts on.") in out
    answer.pop("chain_unreadable")
    tool.audit(_args("retention"))
    assert "could not be read" not in capsys.readouterr().out


def test_a_locked_env_is_never_written(tmp_path, monkeypatch):
    tool, stub = _setup(tmp_path, monkeypatch, check=SOONER, env=None)
    (tmp_path / ".env.enc").write_text("sealed", encoding="utf-8")
    with pytest.raises(SystemExit):
        tool.audit(_args("retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30", "--yes"))
    assert stub.calls == [["retention", "--set", "AUDIT_LOG_RETENTION_DAYS=30"]]       # checked, then refused
    assert not (tmp_path / ".env").exists()


def test_what_the_server_sends_is_cleaned_before_it_is_printed(tmp_path, monkeypatch, capsys):
    tool, _stub = _setup(tmp_path, monkeypatch)
    hostile = dict(SETTINGS[0], label="Keep\x1b]0;owned\x07 rows")
    monkeypatch.setattr(tool, "_audit_tool", lambda *a, input_text=None: {"ok": True, "settings": [hostile],
                                                                          "pending": []})
    tool.audit(_args("retention"))
    assert "\x1b" not in capsys.readouterr().out


def test_the_audit_menu_asks_what_to_do(tmp_path, monkeypatch):
    tool, stub = _setup(tmp_path, monkeypatch)
    seen = []
    monkeypatch.setattr(tool, "_audit_unarchive", lambda args: seen.append(("unarchive", args)))
    monkeypatch.setattr(tool, "_audit_compact", lambda args: seen.append(("compact", args)))
    answers = iter(["1", ""])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    tool.audit()
    assert stub.calls == [["retention"]] and _env(tmp_path) == "EXISTING=1\n"
    answers = iter(["3", "2026-07-01", ""])
    tool.audit()
    (what, args), = seen
    assert what == "unarchive" and (args.audit_from, args.audit_to) == ("2026-07-01", None)
    answers = iter(["4"])
    tool.audit()
    assert seen[-1] == ("compact", None)
    answers = iter(["q"])
    tool.audit()
    assert len(seen) == 2 and stub.calls == [["retention"]]


def test_the_audit_menu_verifies_when_asked(tmp_path, monkeypatch):
    tool, _stub = _setup(tmp_path, monkeypatch)
    seen = []

    class _Done:
        stdout = '{"ok": true, "head": "dvchain1:9:cd", "seals": 9, "exit_code": 0, "findings": []}\n'

    monkeypatch.setattr(dv, "docker_available", lambda *a, **k: (True, ""))
    monkeypatch.setattr(tool, "_run_dc", lambda *args, **kw: seen.append(list(args)) or _Done())
    monkeypatch.setattr("builtins.input", lambda prompt="": "2")
    tool.audit()
    assert seen[0][seen[0].index("app.core.audit_integrity") + 1:] == ["verify", "--json"]


def test_the_menus_retention_changes_one_line_the_server_checked(tmp_path, monkeypatch):
    tool, stub = _setup(tmp_path, monkeypatch, check={"problems": [], "deletes_sooner": [], "changes": [
        {"key": "logs_hold", "label": "Hold all deletion of logs", "unit": "", "unlimited": None, "before": False,
         "after": True}]})
    answers = iter(["1", "RETENTION_HOLD=true", "yes"])
    monkeypatch.setattr("builtins.input", lambda prompt="": next(answers))
    tool.audit()
    assert stub.calls == [["retention"], ["retention", "--set", "RETENTION_HOLD=true"]]
    assert _env(tmp_path) == "EXISTING=1\nRETENTION_HOLD=true\n"
