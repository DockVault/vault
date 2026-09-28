"""A change to someone's sign-in details that will be held is said to be held BEFORE it is confirmed.

An administrator may change someone else's sign-in details once in 14 days; a second change waits for
another administrator. The Users page knows the last change (its `credential_change`), yet it asked
"Create a one-time password-reset link for X? ... It is shown once" and only then, in a warning,
said the change was held, "changed by an administrator" (even when that was the asker) "on
2026-10-05". Now the confirmation itself asks for approval, says who made the first change ("You"
when it was the viewer) and when, in the viewer's own date format; and the warning after a held change
is worded the same way.

Driven in Node against the shipped functions from static/js/app.js. The server's own wording (for
other clients) is checked in the unit tests of _held_body below.
"""
import json
import shutil
import subprocess
from datetime import datetime
from pathlib import Path
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

APP_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"
_SHIPPED = ("parseServerTime", "formatDayMonth", "_changedBy", "pendingApproval", "confirmCredentialChange",
            "_heldText")


def _function(js, name):
    head = f"\nfunction {name}("
    start = js.index(head) + 1
    first = js[start:js.index("\n", start)]
    if first.rstrip().endswith("}"):
        return first + "\n"
    return js[start:js.index("\n}\n", start) + 3]


def _run(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the shipped page code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    harness = ("let currentUser = { id: 'me', username: 'alice' };\n"
               "const asked = [];\n"
               "const showConfirm = async (...args) => { asked.push(args); return true; };\n"
               + "".join(_function(js, n) for n in _SHIPPED)
               + "(async () => { const out = {};\n" + scenario
               + "\nprocess.stdout.write(JSON.stringify(out)); })();\n")
    done = subprocess.run([node, "-"], input=harness, capture_output=True, text=True, encoding="utf-8",
                          timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


_SCENARIO = """
const day = 86400000, soon = new Date(Date.now() + 10 * day).toISOString(), gone = new Date(Date.now() - day).toISOString();
const at = new Date(Date.now() - 4 * day).toISOString();
const local = (v) => new Date(v).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
out.day = local(at);
out.expires = local(soon);
const carol = (by, ends) => ({ id: 'c', username: 'carol', credential_change: { by, at, window_ends: ends } });
await confirmCredentialChange(carol('alice', soon), 'This link is created', 'Create a link?', 'Create reset link');
await confirmCredentialChange(carol('bob', soon), 'The key is added', 'Add?', 'Add key');
await confirmCredentialChange(carol('operator@host', soon), 'The second factor is reset', 'Reset?', 'Reset');
await confirmCredentialChange(carol('bob', gone), 'This link is created', 'Create a link?', 'Create reset link');
await confirmCredentialChange({ id: 'me', username: 'alice', credential_change: { by: 'bob', at, window_ends: soon } },
                              'This link is created', 'My own?', 'Mine');
out.asked = asked;
out.held = _heldText({ message: 'fallback', request: { target_username: 'carol', expires_at: soon },
                       previous: { by: 'alice', at } });
out.heldOther = _heldText({ message: 'fallback', request: { target_username: 'carol', expires_at: soon },
                            previous: { by: 'bob', at } });
out.heldOld = _heldText({ message: 'the server said so' });
"""


def test_a_change_that_will_be_held_asks_for_approval_before_it_is_sent():
    out = _run(_SCENARIO)
    day = out["day"]
    mine, other, host, lapsed, own = out["asked"]
    assert mine == [f"You already changed carol’s sign-in details on {day}. This link is created only when "
                    "another administrator approves it.", "Ask for approval?", None, "Send for approval"]
    assert other[0].startswith(f"bob already changed carol’s sign-in details on {day}. The key is added only")
    assert host[0].startswith("The server’s operator already changed carol’s")
    # The window is over, or it is the viewer's own account: the plain confirmation, as before.
    assert lapsed == ["Create a link?", "Create reset link"]
    assert own == ["My own?", "Mine"]


def test_the_warning_after_a_held_change_says_who_and_when_in_words():
    out = _run(_SCENARIO)
    assert out["held"] == (f"Waiting for approval. You already changed carol’s sign-in details on {out['day']}, so "
                           "another administrator must approve this change. It expires on "
                           f"{out['expires']} if nobody decides.")
    assert out["heldOther"].startswith("Waiting for approval. bob already changed carol’s")
    assert out["heldOld"] == "the server said so"          # an older server's reply: its own words


def _outcome(last_by_id, last_by_name):
    last = SimpleNamespace(requested_by_id=last_by_id, requested_by_name=last_by_name,
                           applied_at=datetime(2026, 9, 28, 5, 47))
    change = SimpleNamespace(id="r-1", kind="reset_link", status="held", target_user_id="c",
                             summary="A link to copy", requested_by_name="alice", requested_by_id="me",
                             requested_at=datetime(2026, 10, 1, 9, 0), expires_at=datetime(2026, 10, 8, 9, 0))
    return SimpleNamespace(change=change, last=last)


def test_the_servers_own_words_name_who_made_the_first_change_and_write_dates_out():
    target = SimpleNamespace(username="carol")
    mine = api._held_body(_outcome("me", "alice"), target, "me")
    other = api._held_body(_outcome("b", "bob"), target, "me")
    host = api._held_body(_outcome(None, "operator@host"), target, "me")
    assert mine["message"].startswith("You already changed carol's sign-in details on 28 September 2026")
    assert "expires on 8 October 2026" in mine["message"]
    assert other["message"].startswith("bob already changed carol's")
    assert host["message"].startswith("The server's operator already changed carol's")
    for body in (mine, other, host):
        assert "by an administrator" not in body["message"] and "2026-" not in body["message"]
    assert mine["previous"] == {"by": "alice", "at": "2026-09-28T05:47:00Z"}


@pytest.mark.parametrize("kind, facts, line", [
    ("email", {"new_email": "carol@new.example"}, "New address: carol@new.example"),
    ("email", {"new_email": None}, "The address is removed"),
    ("reset_link", {"delivery": "copy"}, "A link to copy"),
    ("reset_link", {"delivery": "email"}, "Sent to their email address"),
    ("ssh_key", {"key_name": "laptop", "fingerprint": "SHA256:abc"}, 'Key "laptop" (SHA256:abc)'),
    ("second_factor", {}, None),
])
def test_a_request_row_says_only_what_its_heading_does_not(kind, facts, line):
    """A waiting request reads "Change the email address for carol" and, under it, only what differs:
    "New address: ...", not "Change the email address to ..." again; a second-factor reset has nothing
    to add."""
    from app.core import credential_changes as cc
    summary = api._request_summary(kind, **facts)
    assert summary == line
    if summary:
        assert not summary.lower().startswith(cc.request_label(kind).lower()[:12])


def test_the_note_on_an_account_says_what_was_done_by_whom_and_when():
    """The note in an account's details read "Password reset link by admin on 28/09/2026, 08:47:01":
    now "Password reset link created by admin on 28 Sep", "by you" when it was the viewer, with the
    dates in the viewer's own format and no time of day."""
    js = APP_JS.read_text(encoding="utf-8")
    start = js.index("\nconst _CHANGE_MADE = {") + 1
    const = js[start:js.index("\n};\n", start) + 4]
    node = shutil.which("node")
    assert node, "Node is required: the shipped page code must not be skipped"
    harness = ("let currentUser = { id: 'me', username: 'alice' };\n" + const
               + "".join(_function(js, n) for n in ("parseServerTime", "formatDayMonth", "credentialChangeNoteText"))
               + """
const at = new Date(Date.now() - 4 * 86400000).toISOString(), ends = new Date(Date.now() + 10 * 86400000).toISOString();
const local = (v) => new Date(v).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
process.stdout.write(JSON.stringify({ day: local(at), end: local(ends),
    other: credentialChangeNoteText({ kind: 'reset_link', label: 'Password reset link', by: 'bob', at, window_ends: ends }),
    mine: credentialChangeNoteText({ kind: 'email', label: 'Email address change', by: 'alice', at, window_ends: ends }),
    host: credentialChangeNoteText({ kind: 'second_factor', label: 'Second factor reset', by: 'operator@host', at, window_ends: ends }) }));
""")
    done = subprocess.run([node, "-"], input=harness, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    out = json.loads(done.stdout)
    assert out["other"] == (f"Password reset link created by bob on {out['day']}. Until {out['end']}, another change "
                            "to this account’s sign-in details needs a second administrator’s approval.")
    assert out["mine"].startswith(f"Email address changed by you on {out['day']}.")
    assert out["host"].startswith("Second factor reset by the server’s operator on ")


def test_an_address_change_that_will_be_held_says_the_rest_is_saved_now():
    out = _run("""
const soon = new Date(Date.now() + 10 * 86400000).toISOString(), at = new Date().toISOString();
await confirmCredentialChange({ id: 'c', username: 'carol', credential_change: { by: 'bob', at, window_ends: soon } },
                              'The new address is saved', null, null, 'Your other changes are saved now.');
out.asked = asked;
""")
    (message, title, _input, button), = out["asked"]
    assert message.endswith("The new address is saved only when another administrator approves it. "
                            "Your other changes are saved now.")
    assert (title, button) == ("Ask for approval?", "Send for approval")
