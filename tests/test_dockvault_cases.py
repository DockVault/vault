"""`dockvault.py cases`: compliance access from the host, run through the compliance tool inside the deployment's
web container (python -m app.core.host_compliance).

Offline: the container is replaced by a stand-in that records what it was asked and answers as the tool does.
What must hold: the menu and the command exist; an auditor right is approved only with the account's username
typed again and a case only with its reference typed again, both checked before the container is asked to
change anything; a refusal stops with its reason; text from the server cannot act on the terminal; the tool runs
in the web service of either layout. test_host_compliance_live.py runs the tool on a running stack.
"""
import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("dockvault_cases_mod", ROOT / "dockvault.py")
dv = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(dv)

GRANT = {"id": "g-1", "username": "uma", "status": "proposed", "proposed_by": "ada",
         "proposed_at": "2026-10-06T10:00:00Z", "lapses_at": "2026-10-13T10:00:00Z", "approved_by": None,
         "provenance": {"created_at": "2026-01-01T00:00:00Z", "created_by": "ada", "password_set_by_other": False,
                        "authenticator": {"since": "x"}},
         "problems": [], "independent_approvers": [], "host_may_approve": True}
CASE = {"id": "c-1", "reference": "3f2a9c1b", "number": None, "status": "pending", "auditor": "uma",
        "requested_at": "2026-10-06T10:00:00Z", "purpose": "investigation", "legal_basis": "legitimate",
        "vaults": 1, "independent_approvers": [], "host_may_approve": True}


class _Tool:
    """Stands in for the compliance tool in the container: records each call, answers from a script."""

    def __init__(self, answers):
        self.calls = []
        self.answers = answers

    def __call__(self, *tool_args):
        self.calls.append(list(tool_args))
        return self.answers[tool_args[0]]


@pytest.fixture
def app():
    return dv.DockVault(dv.Palette(False))


def _args(*argv):
    return dv.build_parser().parse_args(["cases", *argv])


def test_the_menu_and_the_command_exist():
    assert "cases" in {k for k, _ in dv.MENU}
    assert all(ord(ch) < 128 for ch in dict(dv.MENU)["cases"]), "menu labels stay ASCII"
    assert {k for k, _ in dv.CASE_ACTIONS} == {"list", "show", "grant-approve", "revoke-auditor", "approve", "reject",
                                                "confirm-hold", "downgrade-blockers"}
    args = _args("--action", "approve", "--case", "c-1", "--confirm-case", "3f2a9c1b", "--non-interactive")
    assert (args.case_action, args.case, args.confirm_case) == ("approve", "c-1", "3f2a9c1b")


def test_approving_a_right_passes_the_username_typed_again(app, monkeypatch, capsys):
    tool = _Tool({"show": {"ok": True, "grant": GRANT},
                  "grant-approve": {"ok": True, "granted": dict(GRANT, status="active", expires_at="2027-10-06Z")}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    app.cases(_args("--action", "grant-approve", "--grant", "g-1", "--confirm-username", "uma", "--non-interactive"))
    assert tool.calls == [["show", "--grant", "g-1"], ["grant-approve", "--grant", "g-1", "--confirm-username", "uma"]]
    out = capsys.readouterr().out
    assert "Approved: uma holds the auditor right until 2027-10-06" in out and "host operator" in out


def test_approving_a_right_without_the_username_asks_nothing_of_the_container_to_change(app, monkeypatch):
    tool = _Tool({"show": {"ok": True, "grant": GRANT}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    with pytest.raises(SystemExit):
        app.cases(_args("--action", "grant-approve", "--grant", "g-1", "--non-interactive"))
    assert [c[0] for c in tool.calls] == ["show"]


def test_a_case_step_needs_its_reference_typed_again_before_the_container_changes_anything(app, monkeypatch):
    tool = _Tool({"show": {"ok": True, "case": CASE}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    with pytest.raises(SystemExit):
        app.cases(_args("--action", "approve", "--case", "c-1", "--non-interactive"))
    assert [c[0] for c in tool.calls] == ["show"]


def test_approving_a_case_passes_the_reference(app, monkeypatch, capsys):
    tool = _Tool({"show": {"ok": True, "case": CASE}, "approve": {"ok": True, "case": dict(CASE, status="active")}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    app.cases(_args("--action", "approve", "--case", "c-1", "--confirm-case", "3f2a9c1b", "--non-interactive"))
    assert tool.calls[-1] == ["approve", "--case", "c-1", "--confirm-case", "3f2a9c1b"]
    assert "recorded as the host operator's" in capsys.readouterr().out


HOLD_CASE = dict(CASE, id="c-2", reference="7d1e0a42", number="C-2026-0001", status="hold_only",
                 independent_approvers=[], host_may_approve=False)


@pytest.mark.parametrize("confirmers, may", [([], True), (["bob"], False)])
def test_list_and_show_say_whether_the_host_may_confirm_a_legal_hold(app, monkeypatch, capsys, confirmers, may):
    case = dict(HOLD_CASE, holds_to_confirm=2, independent_confirmers=confirmers, host_may_confirm=may)
    tool = _Tool({"list": {"ok": True, "grants": [], "cases": [case]}, "show": {"ok": True, "case": case},
                  "confirm-hold": {"ok": False, "error": "An independent administrator can confirm this hold (bob)"}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    app.cases(_args("--action", "list", "--non-interactive"))
    out = capsys.readouterr().out
    assert ("(the host may confirm its legal hold)" in out) is may
    with pytest.raises(SystemExit):
        app.cases(_args("--action", "confirm-hold", "--case", "c-2", "--confirm-case", "7d1e0a42",
                        "--non-interactive"))
    out = capsys.readouterr()
    assert "2 vault(s) wait for a confirmation" in out.out
    assert ("an administrator can confirm it: bob" in out.out) is (not may)
    assert [c[0] for c in tool.calls] == ["list", "show", "confirm-hold"]


def test_turning_a_case_down_needs_a_reason(app, monkeypatch):
    tool = _Tool({"show": {"ok": True, "case": CASE}, "reject": {"ok": True, "case": CASE}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    with pytest.raises(SystemExit):
        app.cases(_args("--action", "reject", "--case", "c-1", "--confirm-case", "3f2a9c1b", "--non-interactive"))
    app.cases(_args("--action", "reject", "--case", "c-1", "--confirm-case", "3f2a9c1b", "--reason", "Out of scope",
                    "--non-interactive"))
    assert tool.calls[-1] == ["reject", "--case", "c-1", "--confirm-case", "3f2a9c1b", "--reason", "Out of scope"]


def test_revoking_needs_the_username_twice(app, monkeypatch):
    tool = _Tool({"revoke-auditor": {"ok": True, "revoked": GRANT}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    with pytest.raises(SystemExit):
        app.cases(_args("--action", "revoke-auditor", "--username", "uma", "--confirm-username", "um",
                        "--non-interactive"))
    assert tool.calls == []
    app.cases(_args("--action", "revoke-auditor", "--username", "uma", "--confirm-username", "uma",
                    "--non-interactive"))
    assert tool.calls == [["revoke-auditor", "--username", "uma", "--confirm-username", "uma"]]


def test_a_refusal_from_the_container_stops_with_its_reason(app, monkeypatch, capsys):
    tool = _Tool({"show": {"ok": True, "grant": GRANT},
                  "grant-approve": {"ok": False, "error": "An independent administrator can approve this auditor "
                                                          "right (bob), so the server's operator may not"}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    with pytest.raises(SystemExit):
        app.cases(_args("--action", "grant-approve", "--grant", "g-1", "--confirm-username", "uma",
                        "--non-interactive"))
    assert "An independent administrator can approve this auditor right (bob)" in capsys.readouterr().out


def test_text_from_the_server_cannot_act_on_the_terminal(app, monkeypatch, capsys):
    hostile = dict(GRANT, username="uma\x1b]0;owned\x07", proposed_by="ada\x1b[2J")
    tool = _Tool({"list": {"ok": True, "grants": [hostile], "cases": [dict(CASE, auditor="x\x1b[31m")]}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    app.cases(_args("--action", "list", "--non-interactive"))
    out = capsys.readouterr().out
    assert "\x1b" not in out and "uma" in out and "(the host may approve it)" in out


def test_downgrade_blockers_are_listed(app, monkeypatch, capsys):
    tool = _Tool({"downgrade-blockers": {"ok": True, "blockers": [
        {"key": "holds", "requires_at_least": "0.34.0", "reason": "Legal holds keep files", "undo": "Release them"}]}})
    monkeypatch.setattr(app, "_run_case_tool", tool)
    app.cases(_args("--action", "downgrade-blockers", "--target", "0.33.2", "--non-interactive"))
    out = capsys.readouterr().out
    assert "needs 0.34.0 or later: Legal holds keep files" in out and "Release them" in out


class _Proc:
    def __init__(self, returncode, stdout="", stderr=""):
        self.returncode, self.stdout, self.stderr = returncode, stdout, stderr


def test_the_tool_runs_in_the_web_service_of_either_layout(app, monkeypatch):
    monkeypatch.setattr(dv, "docker_available", lambda: (True, ""))
    asked = []

    def run_dc(*argv, **kw):
        asked.append(argv)
        if argv[2] == "vault":
            return _Proc(1, "", "service \"vault\" is not running")
        return _Proc(0, "noise\n{\"ok\": true, \"grants\": [], \"cases\": []}\n")

    monkeypatch.setattr(app, "_run_dc", run_dc)
    assert app._run_case_tool("list") == {"ok": True, "grants": [], "cases": []}
    assert [a[2] for a in asked] == ["vault", "vault-api"]
    assert asked[0][3:] == ("python", "-m", "app.core.host_compliance", "list")
