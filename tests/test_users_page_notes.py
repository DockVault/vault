"""The notes in an account's details on the Users page say what is true of that account, and what the
administrator reading them can do about it.

An address the vault has not confirmed is one a provider that links by email does not find the account by. Who
typed it is not known (an account an administrator made before addresses were confirmed starts unconfirmed too),
so the note does not say; and whether the person can confirm it themselves depends on whether the vault sends
email, which the page reads from GET /settings after it has drawn the list, so the notes are filled again then.

The page's own functions are run by Node on the small document of tests/js/mini_dom.js.
"""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"
_SHIPPED = ("parseServerTime", "formatDayMonth", "formatServerTime", "_el", "credentialChangeNoteText",
            "_ssoStanding", "_ssoStandingNote", "fillCredentialChangeNotes")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    assert found, name
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


def _const(js, name):
    start = js.index(f"\nconst {name} = {{") + 1
    return js[start:js.index("\n};\n", start) + 4]


PRELUDE = r"""
const _RealDate = Date, _FIXED_NOW = _RealDate.parse('2026-06-15T12:00:00Z');
globalThis.Date = class extends _RealDate {
  constructor(...a) { super(...(a.length ? a : [_FIXED_NOW])); }
  static now() { return _FIXED_NOW; }
};
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
var currentUser = { id: 'me', username: 'alice', role: 'admin' };
var currentSettings = {};
var isScopedTemp = false;
const carol = { id: 'u-carol', username: 'carol', role: 'user', groups: [], is_active: true, email: 'carol@example.test' };
var usersView = { users: [carol], groups: [], expanded: new Set() };
const asked = [], confirms = [], toasts = [];
let answers = {};
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET' });
    const answer = Object.prototype.hasOwnProperty.call(answers, path) ? answers[path] : new Error('Not arranged.');
    if (answer instanceof Error) throw answer;
    return answer;
};
const showConfirm = async (message, title, input, label) => { confirms.push([message, title, label || null]); return false; };
const showSuccess = (m) => toasts.push(['success', m]);
const showError = (m) => toasts.push(['error', m]);
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const note = document.createElement('div');
note.className = 'credential-change-note';
note.setAttribute('data-user-id', 'u-carol');
document.body.appendChild(note);
const lines = () => (note.hidden ? null : note.children.map((c) => c.textContent));
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(scenario, more=()):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + _const(js, "_CHANGE_MADE") + "".join(_function(js, n) for n in _SHIPPED + tuple(more))
              + "(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


# --------------------------------------------------------------------------- an address not confirmed

UNCONFIRMED = "Email address not confirmed, so your organisation’s sign-in does not find this account by it."


def test_an_unconfirmed_address_says_who_can_confirm_it_on_this_vault():
    got = _node(r"""
carol.email_confirm_wanted = true;
const seen = {};
for (const [name, settings] of [['mail', { smtp_configured: true }], ['none', { smtp_configured: false }],
                                ['unknown', {}]]) {
    currentSettings = settings;
    fillCredentialChangeNotes();
    seen[name] = lines();
}
out(seen);
""")
    assert got["mail"] == [UNCONFIRMED + " They can confirm it under Your account with a code sent to it, or you "
                                         "can, with Confirm address."]
    assert got["none"] == [UNCONFIRMED + " This vault sends no email, so they cannot confirm it themselves; you can, "
                                         "with Confirm address."]
    assert got["unknown"] == [UNCONFIRMED + " You can confirm it with Confirm address."]
    for said in got.values():
        assert "typed it themselves" not in said[0]


def test_the_notes_are_filled_again_once_the_page_knows_whether_the_vault_sends_email():
    """The list is drawn (and its notes filled) before GET /settings answers: the notes are filled again after."""
    got = _node(r"""
carol.email_confirm_wanted = true;
answers['/users'] = [carol];
answers['/groups'] = [];
answers['/settings'] = { smtp_configured: true };
const noop = () => {};
globalThis.populateUsersGroupFilter = noop; globalThis.updateActionButtonPermissions = noop;
globalThis.loadInvites = noop; globalThis.loadCredentialRequests = noop; globalThis.loadSsoAdminRequests = noop;
globalThis.renderUsersTable = () => fillCredentialChangeNotes();      // as attachUserListeners does
const list = document.createElement('div');
list.id = 'users-list';
document.body.appendChild(list);
await loadUsers();
out({ lines: lines(), asked: asked.map((a) => a.path) });
""", ("loadUsers",))
    assert got["lines"] == [UNCONFIRMED + " They can confirm it under Your account with a code sent to it, or you "
                                          "can, with Confirm address."]
    assert got["asked"][-1] == "/settings"


# --------------------------------------------------------------------------- the passkey requirement lifted

def test_an_account_the_passkey_requirement_was_lifted_for_says_so_and_when_it_ends():
    got = _node(r"""
globalThis.iconSvg = () => ''; globalThis.escapeHtml = (s) => String(s); globalThis.groupChip = () => '';
globalThis.People = { placeholder: () => '', whenPlaceholder: () => '' };
const day = new Date('2026-05-02T09:00:00Z').toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
const before = { lines: (fillCredentialChangeNotes(), lines()), badge: renderUserRow(carol).includes('Passkey requirement lifted') };
carol.passkey_requirement_cleared_at = '2026-05-02T09:00:00Z';
fillCredentialChangeNotes();
out({ before, lines: lines(), badge: renderUserRow(carol).includes('Passkey requirement lifted'), day });
""", ("signInMethods", "signInMethodBadges", "_holdsAFactor", "_passkeysHeld", "_passkeysShownFor", "renderUserDetail",
      "renderUserRow"))
    assert got["before"] == {"lines": None, "badge": False}
    assert got["lines"] == [f"The server’s operator lifted the passkey requirement for this account on {got['day']}: it "
                            "signs in without a passkey although its role must hold one. That ends when the account "
                            "adds a passkey, when its role changes, or when the server’s operator puts it back."]
    assert got["badge"] is True


# --------------------------------------------------------------------------- a password for an account that never had one

NEVER = ("carol was made at its first sign-in through Okta and has never had a password. With one, this account "
         "keeps a password from now on, also if Okta later stops letting the accounts it makes set one.")

_DIALOG = r"""
for (const id of ['change-password-user-id', 'change-password-new', 'change-password-confirm', 'change-password-modal',
                  'change-password-note']) {
    const el = document.createElement(id === 'change-password-note' ? 'p' : 'input');
    el.id = id;
    document.body.appendChild(el);
}
const shown = () => { const n = document.getElementById('change-password-note');
    return { text: n.textContent, hidden: n.hidden, display: n.style.display || '' }; };
"""


def test_the_change_password_dialog_says_what_a_password_means_for_an_account_that_never_had_one():
    got = _node(_DIALOG + r"""
const dave = { id: 'u-dave', username: 'dave', role: 'user', groups: [] };
usersView.users.push(dave);
carol.password_set_note = '""" + NEVER + r"""';
showChangePasswordModal('u-carol');
const withNote = shown();
showChangePasswordModal('u-dave');
out({ withNote, without: shown(), open: document.getElementById('change-password-modal').classList.contains('active') });
""", ("showChangePasswordModal",))
    assert got["withNote"] == {"text": NEVER, "hidden": False, "display": ""}
    assert got["without"] == {"text": "", "hidden": True, "display": "none"}
    assert got["open"] is True


def test_a_reset_link_for_an_account_that_never_had_a_password_says_what_the_password_it_sets_means():
    got = _node(r"""
carol.password_set_note = '""" + NEVER + r"""';
for (const cls of ['copy-reset-link-btn', 'send-reset-link-btn']) {
    const b = document.createElement('button');
    b.className = cls;
    b.setAttribute('data-user-id', 'u-carol');
    b.setAttribute('data-username', 'carol');
    document.body.appendChild(b);
}
attachUserListeners();
document.querySelector('.copy-reset-link-btn').click();
await tick();
document.querySelector('.send-reset-link-btn').click();
await tick();
// A change that will wait for another administrator says it too.
carol.credential_change = { by: 'bob', at: '2026-06-13T10:00:00Z', window_ends: '2026-06-27T10:00:00Z' };
document.querySelector('.copy-reset-link-btn').click();
await tick();
out({ confirms, asked: asked.map((a) => a.path) });
""", ("_changedBy", "pendingApproval", "confirmCredentialChange", "fillSsoStandingBadges", "attachUserListeners"))
    copy, send, held = got["confirms"]
    assert copy[0].startswith("Create a one-time password-reset link for carol? Anyone with the link can set a new "
                              "password for this account.")
    assert copy[0].endswith(" " + NEVER) and copy[1:] == ["Create reset link", None]
    assert send[0] == "Email a password-reset link to carol? " + NEVER
    assert held[0].endswith("This link is created only when another administrator approves it. " + NEVER)
    assert got["asked"] == []            # each confirmation was declined: nothing was sent
