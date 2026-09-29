"""`dockvault.py accounts`: the host operator resets a password or a second factor, or approves a held
change, by running the account tool inside the deployment's web container.

Offline: the container is replaced by a stand-in that records what it was asked and answers as the
tool does. What must hold:
  * nothing is changed unless the account's username is typed a second time, exactly;
  * a reset link or temporary password reaches the operator's terminal through _emit_secret and is
    never printed to standard output (a log, a pipe, a CI transcript);
  * the tool runs in the web service, whichever of the two layouts is up, and its answer is the last
    line of what it prints.
test_host_operator_live.py runs the tool itself on a running stack.
"""
import importlib.util
import json
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_accounts_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

SECRET = "https://vault.example.com/?reset=THE-ONE-TIME-TOKEN"


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


class _Tool:
    """Stands in for the account tool in the container: records each call, answers from a script."""

    def __init__(self, answers):
        self.calls = []
        self.answers = answers

    def __call__(self, *tool_args):
        self.calls.append(list(tool_args))
        return self.answers[tool_args[0]]


@pytest.fixture
def app(monkeypatch):
    a = dv.DockVault(dv.Palette(False))
    shown = []
    monkeypatch.setattr(a, "_emit_secret", lambda text: shown.append(text))
    a.shown = shown
    return a


def _args(*argv):
    return dv.build_parser().parse_args(["accounts", *argv])


ACCOUNT = {"ok": True, "account": {"username": "alice", "email": "alice@example.com", "role": "user",
                                   "active": True, "last_login": None, "second_factor": True}}


def test_the_answer_is_the_last_line_the_tool_prints():
    noise = "startup warning: something\n✓ ready\n"
    assert dv.parse_operator_answer(noise + json.dumps({"ok": True, "x": 1}) + "\n\n") == {"ok": True, "x": 1}
    assert dv.parse_operator_answer(noise) is None
    assert dv.parse_operator_answer(json.dumps({"no": "ok key"})) is None
    assert dv.parse_operator_answer("") is None


def test_the_username_must_be_typed_again_exactly():
    assert dv.username_confirmation_problem("alice", "alice") is None
    assert dv.username_confirmation_problem("alice", "Alice")
    assert dv.username_confirmation_problem("alice", "alice ")
    assert dv.username_confirmation_problem("alice", None)
    assert dv.username_confirmation_problem("", "")


def test_the_menu_and_the_command_exist():
    assert "accounts" in {k for k, _ in dv.MENU}
    args = _args("--action", "approve", "--request-id", "r1", "--confirm-username", "alice",
                 "--non-interactive")
    assert (args.account_action, args.request_id, args.confirm_username, args.non_interactive) == (
        "approve", "r1", "alice", True)
    assert all(ord(ch) < 128 for ch in dict(dv.MENU)["accounts"]), "menu labels stay ASCII"


def test_a_mismatched_username_changes_nothing(app, monkeypatch):
    tool = _Tool({"lookup": ACCOUNT})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    with pytest.raises(SystemExit):
        app.accounts(_args("--action", "reset-password", "--username", "alice",
                           "--confirm-username", "alicia", "--non-interactive"))
    assert [c[0] for c in tool.calls] == ["lookup"], "only the read happened"
    with pytest.raises(SystemExit):
        app.accounts(_args("--action", "reset-second-factor", "--username", "alice", "--non-interactive"))
    assert [c[0] for c in tool.calls] == ["lookup", "lookup"]


def test_the_reset_link_goes_to_the_terminal_only(app, monkeypatch, capsys):
    tool = _Tool({"lookup": ACCOUNT, "reset-password": {"ok": True, "account": "alice", "secret": SECRET,
                                                        "secret_kind": "reset_link", "expires_in_minutes": 5}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    app.accounts(_args("--action", "reset-password", "--username", "alice", "--confirm-username", "alice",
                       "--non-interactive"))
    assert tool.calls[-1] == ["reset-password", "--username", "alice", "--confirm-username", "alice"]
    assert "THE-ONE-TIME-TOKEN" not in capsys.readouterr().out
    assert len(app.shown) == 1 and SECRET in app.shown[0]


def test_a_temporary_password_is_asked_for_and_shown_the_same_way(app, monkeypatch, capsys):
    tool = _Tool({"lookup": ACCOUNT, "reset-password": {"ok": True, "account": "alice", "secret": "Tmp-Pw-123!x",
                                                        "secret_kind": "temporary_password"}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    app.accounts(_args("--action", "reset-password", "--username", "alice", "--confirm-username", "alice",
                       "--temporary-password", "--non-interactive"))
    assert tool.calls[-1][-1] == "--temporary-password"
    assert "Tmp-Pw-123!x" not in capsys.readouterr().out
    assert "Tmp-Pw-123!x" in app.shown[0] and "change it" in app.shown[0]


def test_approving_passes_the_confirmation_and_shows_a_link_on_the_terminal(app, monkeypatch, capsys):
    tool = _Tool({"approve": {"ok": True, "approved": {"label": "Password reset link", "target_username": "alice",
                                                       "requested_by": "bob"}, "secret": SECRET}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    app.accounts(_args("--action", "approve", "--request-id", "r1", "--confirm-username", "alice",
                       "--non-interactive"))
    assert tool.calls == [["approve", "--request-id", "r1", "--confirm-username", "alice"]]
    out = capsys.readouterr().out
    assert "Approved" in out and "THE-ONE-TIME-TOKEN" not in out
    assert SECRET in app.shown[0]


def test_approving_without_the_username_is_refused_before_the_container(app, monkeypatch):
    tool = _Tool({})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    with pytest.raises(SystemExit):
        app.accounts(_args("--action", "approve", "--request-id", "r1", "--non-interactive"))
    assert tool.calls == []


def test_a_refusal_from_the_container_stops_with_its_reason(app, monkeypatch, capsys):
    tool = _Tool({"lookup": ACCOUNT, "reset-second-factor": {"ok": False, "error": "No such thing."}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    with pytest.raises(SystemExit):
        app.accounts(_args("--action", "reset-second-factor", "--username", "alice",
                           "--confirm-username", "alice", "--non-interactive"))
    assert "No such thing." in capsys.readouterr().out


def test_interactively_the_username_is_asked_for_twice(app, monkeypatch):
    tool = _Tool({"lookup": ACCOUNT, "reset-second-factor": {"ok": True, "account": "alice"}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    typed = iter(["2", "alice", "alice"])
    monkeypatch.setattr("builtins.input", lambda *_a, **_k: next(typed))
    app.accounts(None)
    assert tool.calls[-1] == ["reset-second-factor", "--username", "alice", "--confirm-username", "alice"]


def test_the_tool_runs_in_the_web_service_of_either_layout(app, monkeypatch):
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    seen = []

    def run_dc(*args, **_kw):
        seen.append(args)
        service = args[2]
        if service == "vault":        # not up in the split layout
            return _Proc(1, "", "service \"vault\" is not running")
        return _Proc(0, "noise\n" + json.dumps({"ok": True, "requests": []}) + "\n")

    monkeypatch.setattr(app, "_run_dc", run_dc)
    assert app._run_account_tool("list") == {"ok": True, "requests": []}
    assert [a[:3] for a in seen] == [("exec", "-T", "vault"), ("exec", "-T", "vault-api")]
    assert seen[-1][3:] == ("python", "-m", "app.core.host_operator", "list")


ESC = chr(27)
HOSTILE = f"ev{ESC}]0;owned{chr(7)}il{ESC}[2J{chr(0x9b)}31m"   # a window title, a screen clear, a C1 CSI


def _no_control(text):
    return not any(ord(ch) < 32 and ch != "\n" or 0x7f <= ord(ch) < 0xa0 for ch in text)


def test_a_username_from_the_server_cannot_act_on_the_terminal(app, monkeypatch, capsys):
    # A username stored before the server refused control characters reaches this terminal through the
    # lookup, the list and the approval. Each is printed with its escape sequences removed.
    account = {"ok": True, "account": {"username": HOSTILE, "email": f"x{ESC}[1m@example.com", "role": "user",
                                       "active": True, "last_login": f"2026{ESC}[H", "second_factor": False}}
    tool = _Tool({"lookup": account, "reset-second-factor": {"ok": True, "account": HOSTILE},
                  "list": {"ok": True, "requests": [{"id": "r1", "label": "Password reset link",
                                                     "target_username": HOSTILE, "requested_by": HOSTILE,
                                                     "requested_at": "2026-09-01", "expires_at": "2026-09-08"}]},
                  "approve": {"ok": True, "approved": {"label": "Password reset link", "target_username": HOSTILE,
                                                       "requested_by": HOSTILE}}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    app.accounts(_args("--action", "reset-second-factor", "--username", "evil", "--confirm-username", "evil",
                       "--non-interactive"))
    app.accounts(_args("--action", "list", "--non-interactive"))
    app.accounts(_args("--action", "approve", "--request-id", "r1", "--confirm-username", "evil",
                       "--non-interactive"))
    out = capsys.readouterr().out
    assert "evil" in out and "r1" in out
    assert _no_control(out), repr(out)


def test_a_refusal_from_the_server_cannot_act_on_the_terminal(app, monkeypatch, capsys):
    tool = _Tool({"lookup": {"ok": False, "error": f"No account {HOSTILE}."}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    with pytest.raises(SystemExit):
        app.accounts(_args("--action", "reset-password", "--username", "evil", "--non-interactive"))
    out = capsys.readouterr().out
    assert "No account evil" in out and _no_control(out), repr(out)


def test_the_user_managers_listing_only_reads_and_says_how_each_permission_was_given(app, monkeypatch, capsys):
    # Accounts that may view or manage users without being administrators: an administrator's defaults
    # kept by an account demoted before 0.33.0 have no granter; a permission granted on purpose names who.
    tool = _Tool({"user-managers": {"ok": True, "accounts": [
        {"username": "bob", "role": "user", "active": True, "permissions": [
            {"group": "USER_MANAGE", "granted_by": None, "granted_at": "2026-08-01T10:00:00Z"},
            {"group": "USER_VIEW", "granted_by": None, "granted_at": "2026-08-01T10:00:00Z"}]},
        {"username": HOSTILE, "role": "user", "active": False, "permissions": [
            {"group": "USER_MANAGE", "granted_by": "alice", "granted_at": "2026-09-01T09:00:00Z"}]}]}})
    monkeypatch.setattr(app, "_run_account_tool", tool)
    app.accounts(_args("--action", "user-managers", "--non-interactive"))
    assert tool.calls == [["user-managers"]], "one read, nothing else"
    out = capsys.readouterr().out
    bob = out[out.index("  bob  (user)"):out.index("evil")]
    assert bob.count("no granter recorded: kept from when the account was an administrator") == 2, bob
    evil = out[out.index("evil"):]
    assert "granted by alice on 2026-09-01" in evil and "no granter" not in evil, evil
    assert "deactivated" in evil and _no_control(out), repr(out)
    assert app.shown == [], "nothing secret to show"


def test_the_user_managers_listing_says_when_there_is_nobody(app, monkeypatch, capsys):
    monkeypatch.setattr(app, "_run_account_tool", _Tool({"user-managers": {"ok": True, "accounts": []}}))
    app.accounts(_args("--action", "user-managers", "--non-interactive"))
    assert "Only administrators may view or manage users." in capsys.readouterr().out
