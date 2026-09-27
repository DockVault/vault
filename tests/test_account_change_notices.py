"""An administrator's change to someone's account is told to that person, offline.

Every change to a user's credentials or standing by an administrator (a password, a reset link, a
second-factor reset, an email address, an SSH key, a lock or unlock, a deactivation or reactivation,
a role change) notifies the user in the app and, when email is configured and there is an address,
by email through the account_changed_by_admin action. The notice says what changed, when, by whom,
and what to do if it was not expected; an email change is told to the OLD address.

test_account_change_notices_live.py drives the same through the routes on a running stack.
"""
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.core import credential_changes as cc  # noqa: E402
from app.core import email_actions as ea  # noqa: E402

pytestmark = pytest.mark.unit

USER = SimpleNamespace(id="u-1", username="carol", email="carol@example.com")


@pytest.fixture
def sent(monkeypatch):
    """What reached the user: the in-app rows and the emails, recorded instead of written or sent."""
    out = {"app": [], "email": []}
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title, body=None, target=None, **_k:
                        out["app"].append({"ids": ids, "type": ntype, "title": title, "body": body}))
    monkeypatch.setattr(api, "_fire_action_email", lambda db, key, *, email, username=None, action_context=None:
                        out["email"].append({"key": key, "email": email, "context": action_context}))
    return out


def test_a_notice_says_what_when_by_whom_and_what_to_do(sent):
    api._notify_account_change(None, USER, ntype="account_changed", title="Your password was changed",
                               change="An administrator set a new password.", by="alice")
    (row,) = sent["app"]
    assert row["ids"] == ["u-1"] and row["title"] == "Your password was changed"
    body = row["body"]
    assert "An administrator set a new password." in body and "By: alice" in body
    assert "UTC" in body and "If you did not expect this" in body
    (mail,) = sent["email"]
    assert (mail["key"], mail["email"]) == ("account_changed_by_admin", "carol@example.com")
    assert mail["context"]["change"] == "An administrator set a new password."
    assert mail["context"]["by"] == "alice" and mail["context"]["when"].endswith("UTC")


@pytest.mark.parametrize("kind,result,words", [
    (cc.PASSWORD, {}, "set a new password"),
    (cc.RESET_LINK, {"reset_link": "x"}, "created a password reset link"),
    (cc.RESET_LINK, {"email_sent": True}, "emailed you a password reset link"),
    (cc.SECOND_FACTOR, {"had_second_factor": True}, "reset your second factor"),
    (cc.EMAIL, {"old_email": "old@example.com", "new_email": "new@example.com"},
     "from old@example.com to new@example.com"),
    (cc.SSH_KEY, {"ssh_key": SimpleNamespace(name="laptop", fingerprint="SHA256:abc")}, '"laptop" (SHA256:abc)'),
])
def test_each_credential_change_says_what_changed(sent, kind, result, words):
    api._notify_credential_change(None, kind, USER, result, by_name="alice")
    (row,) = sent["app"]
    assert words in row["body"] and "By: alice" in row["body"]
    assert row["type"] == "account_changed"


def test_an_email_change_is_told_to_the_old_address(sent):
    api._notify_credential_change(None, cc.EMAIL, USER, {"old_email": "old@example.com",
                                                         "new_email": "new@example.com"}, by_name="alice")
    assert [m["email"] for m in sent["email"]] == ["old@example.com"]


def test_an_address_added_where_there_was_none_is_emailed_nowhere(sent):
    api._notify_credential_change(None, cc.EMAIL, USER, {"old_email": None, "new_email": "new@example.com"},
                                  by_name="alice")
    assert [m["email"] for m in sent["email"]] == [""], "no address to warn, so no mail goes out"
    assert len(sent["app"]) == 1


def test_the_host_operator_and_an_approval_are_named(sent):
    api._notify_credential_change(None, cc.SECOND_FACTOR, USER, {}, by_name=cc.HOST_OPERATOR)
    api._notify_credential_change(None, cc.PASSWORD, USER, {}, by_name="alice", approved_by="bob",
                                  ntype="credential_change_approved")
    first, second = sent["app"]
    assert "The server's operator reset your second factor" in first["body"]
    assert "the server's operator, on the host" in first["body"]
    assert "By: alice, approved by bob" in second["body"] and second["type"] == "credential_change_approved"


@pytest.mark.parametrize("kw,title", [
    ({"locked": (False, True)}, "Your account was locked"),
    ({"locked": (True, False)}, "Your account was unlocked"),
    ({"active": (True, False)}, "Your account was deactivated"),
    ({"active": (False, True)}, "Your account was reactivated"),
    ({"role": ("user", "admin")}, "Your role was changed"),
])
def test_each_change_of_standing_is_told(sent, kw, title):
    api._notify_account_status_changes(None, USER, by_name="alice", **kw)
    assert [r["title"] for r in sent["app"]] == [title]
    assert len(sent["email"]) == 1


def test_nothing_is_told_when_nothing_changed(sent):
    api._notify_account_status_changes(None, USER, by_name="alice", locked=(True, True),
                                       active=(False, False), role=("user", "user"))
    api._notify_account_status_changes(None, USER, by_name="alice")
    assert sent == {"app": [], "email": []}


def test_the_email_is_a_system_action_that_must_say_what_changed():
    spec = ea.SPEC_BY_KEY["account_changed_by_admin"]
    assert spec["category"] == ea.SYSTEM
    for token in ("{{action.change}}", "{{action.when}}", "{{action.by}}"):
        assert token in spec["default_body_html"]
    # A customised body that drops what changed falls back to the built-in one.
    assert ea._fallback_body_if_missing_required_token(ea.SYSTEM, "<p>Hello</p>", spec) == spec["default_body_html"]
