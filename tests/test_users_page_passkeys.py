"""An administrator removes someone's passkey from the Users page (static/js/app.js): the account's details list its
passkeys from GET /users/{id}/passkeys, each with "Remove", and a removal (DELETE /users/{id}/passkeys/{passkey_id},
under the step-up of managing users) is confirmed first with what it does: the key no longer signs the person in,
every session of the account ends, and it counts as a change to the account's sign-in details, so a second one
within 14 days waits for another administrator, and the confirmation says so before it is sent. Never for the
administrator's own account (its passkeys are managed under Your account, and the server refuses them there), and
only for an administrator.

The page is driven in Node against the shipped functions, on the small document of tests/js/mini_dom.js. The two
routes are held to an interactive administrator offline: the read the page depends on, and the removal with its
step-up.
"""
import json
import os
import re
import shutil
import subprocess
import types
import uuid
from datetime import datetime
from pathlib import Path

import pytest

from test_passkey_routes import Harness, _call, _user

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = ROOT / "static" / "js" / "app.js"
_SHIPPED = ("_el", "parseServerTime", "formatDayMonth", "_changedBy", "pendingApproval", "confirmCredentialChange",
            "_passkeysShownFor", "loadUserPasskeys", "renderUserPasskeys", "removeUserPasskey", "renderUserDetail")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    assert found, name
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


# The scenarios read a fixed clock, as the credential-change confirmation's own test does: a date within the year
# is written without its year.
PRELUDE = r"""
const _RealDate = Date, _FIXED_NOW = _RealDate.parse('2026-06-15T12:00:00Z');
globalThis.Date = class extends _RealDate {
  constructor(...a) { super(...(a.length ? a : [_FIXED_NOW])); }
  static now() { return _FIXED_NOW; }
};
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
var currentUser = { id: 'me', username: 'alice', role: 'admin' };
var isScopedTemp = false;
const asked = [], confirms = [], toasts = [], reloads = [];
let answers = {};
let confirmAnswer = true;
const carol = { id: 'u-carol', username: 'carol', role: 'user', groups: [], is_active: true };
var usersView = { users: [carol], groups: [], expanded: new Set() };
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET' });
    const answer = Object.prototype.hasOwnProperty.call(answers, path) ? answers[path] : new Error('Not arranged.');
    if (answer instanceof Error) throw answer;
    return answer;
};
const showConfirm = async (message, title, input, label) => { confirms.push([message, title, label || null]); return confirmAnswer; };
const showSuccess = (m) => toasts.push(['success', m]);
const showError = (m) => toasts.push(['error', m]);
const showHeldChange = (r) => toasts.push(['held', r.message]);
const loadUsers = async () => { reloads.push(1); };
const svgUseIcon = () => document.createElement('svg');
const iconSvg = () => '';
const escapeHtml = (s) => String(s);
const groupChip = () => '';
const People = { whenPlaceholder: () => '' };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const host = document.createElement('div');
host.className = 'user-passkeys-list';
host.setAttribute('data-user-id', 'u-carol');
document.body.appendChild(host);
const KEYS = { passkeys: [
    { id: 'k-1', label: 'yubikey', created_at: '2026-03-02T10:00:00Z', last_used_at: '2026-06-01T10:00:00Z',
      synced: false, provisional: false, provisional_until: null },
    { id: 'k-2', label: '', created_at: '2026-06-10T10:00:00Z', last_used_at: null, synced: true, provisional: true,
      provisional_until: '2026-06-24T10:00:00Z' }], limit: 20 };
const items = () => host.querySelectorAll('.user-passkey-item').map((item) => ({
    id: item.dataset.passkeyId, text: item.children[0].textContent,
    remove: [item.children[1].textContent, item.children[1].getAttribute('aria-label')] }));
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + "".join(_function(js, n) for n in _SHIPPED) + "(async () => {\n" + scenario
              + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_an_accounts_details_list_its_passkeys_for_an_administrator_only_and_never_their_own():
    got = _node(r"""
const shown = (user) => renderUserDetail(user).includes('class="user-passkeys-list" data-user-id="' + user.id + '"');
const seen = { other: shown(carol), own: shown({ id: 'me', username: 'alice', role: 'admin', groups: [] }) };
currentUser = { id: 'me', username: 'alice', role: 'user' };            // a user who may manage users
seen.manager = shown(carol);
currentUser = { id: 'me', username: 'alice', role: 'admin' };
isScopedTemp = true;
seen.temporary = shown(carol);
out(seen);
""")
    assert got == {"other": True, "own": False, "manager": False, "temporary": False}


def test_the_passkeys_are_listed_with_when_they_were_added_and_used_and_how_they_are_kept():
    got = _node(r"""
answers['/users/u-carol/passkeys'] = KEYS;
await loadUserPasskeys('u-carol');
const listed = items();
answers['/users/u-carol/passkeys'] = { passkeys: [], limit: 20 };
await loadUserPasskeys('u-carol');
const none = host.textContent;
answers['/users/u-carol/passkeys'] = new Error('Admin privileges required');
await loadUserPasskeys('u-carol');
// The dates as the viewer's own locale writes them, for the expected lines.
const day = (v) => new Date(v).toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
const days = ['2026-03-02T10:00:00Z', '2026-06-01T10:00:00Z', '2026-06-10T10:00:00Z', '2026-06-24T10:00:00Z'].map(day);
out({ listed, none, failed: host.textContent, asked: asked.map((a) => a.path), days });
""")
    first, second = got["listed"]
    added, used, added2, until = got["days"]
    assert first == {"id": "k-1", "text": f"yubikeyadded {added} · last used {used} · bound to one device",
                     "remove": ["Remove", "Remove the passkey yubikey"]}
    assert second == {"id": "k-2", "text": f"Unnamed passkeyadded {added2} · never used · synced between devices · "
                                           f"provisional until {until}",
                      "remove": ["Remove", "Remove the passkey with no name"]}
    assert got["none"] == "No passkeys." and got["failed"] == "Could not load the passkeys."
    assert got["asked"] == ["/users/u-carol/passkeys"] * 3


def test_a_removal_says_what_it_does_before_it_is_sent_and_the_list_is_read_again():
    got = _node(r"""
answers['/users/u-carol/passkeys'] = KEYS;
answers['/users/u-carol/passkeys/k-1'] = { removed: true };
await loadUserPasskeys('u-carol');
confirmAnswer = false;
host.querySelector('.user-passkey-remove-btn').click();
await tick(); await tick();
const declined = asked.filter((a) => a.method === 'DELETE').length;
confirmAnswer = true;
host.querySelector('.user-passkey-remove-btn').click();
await tick(); await tick(); await tick();
out({ declined, confirm: confirms[1], deletes: asked.filter((a) => a.method === 'DELETE').map((a) => a.path),
      toasts, reloads: reloads.length });
""")
    assert got["declined"] == 0
    message, title, label = got["confirm"]
    assert title == "Remove the passkey?" and label is None
    assert message.startswith("Remove the passkey “yubikey” from carol’s account? It no longer signs them in or "
                              "confirms it is them. All of carol’s sessions end, everywhere,")
    assert "if it was the last second factor it held, they set one up again at their next sign-in" in message
    assert "It counts as a change to their sign-in details: for 14 days another change needs a second administrator" in message
    assert got["deletes"] == ["/users/u-carol/passkeys/k-1"]
    assert got["toasts"] == [["success", "Passkey removed. carol was signed out everywhere."]]
    assert got["reloads"] == 1


def test_a_removal_that_will_wait_for_another_administrator_says_so_first_and_after():
    got = _node(r"""
const day = 86400000;
carol.credential_change = { by: 'bob', at: new Date(Date.now() - 2 * day).toISOString(),
                            window_ends: new Date(Date.now() + 12 * day).toISOString() };
answers['/users/u-carol/passkeys'] = KEYS;
answers['/users/u-carol/passkeys/k-2'] = { held: true, message: 'Waiting for approval.' };
await loadUserPasskeys('u-carol');
host.querySelectorAll('.user-passkey-remove-btn')[1].click();
await tick(); await tick(); await tick();
const on = new Date(carol.credential_change.at).toLocaleDateString(undefined, { day: 'numeric', month: 'short' });
out({ confirm: confirms[0], toasts, on });
""")
    message, title, label = got["confirm"]
    assert title == "Ask for approval?" and label == "Send for approval"
    assert message.startswith(f"bob already changed carol’s sign-in details on {got['on']}. The passkey is removed "
                              "only when another administrator approves it.")
    assert got["toasts"] == [["held", "Waiting for approval."]]


def test_a_refused_removal_is_said_and_the_list_is_read_again():
    got = _node(r"""
answers['/users/u-carol/passkeys'] = KEYS;
answers['/users/u-carol/passkeys/k-1'] = new Error('That passkey was not found.');
await loadUserPasskeys('u-carol');
host.querySelector('.user-passkey-remove-btn').click();
await tick(); await tick(); await tick();
out({ toasts, reloads: reloads.length, disabled: host.querySelector('.user-passkey-remove-btn').disabled });
""")
    assert got == {"toasts": [["error", "Could not remove the passkey: That passkey was not found."]], "reloads": 1,
                   "disabled": False}


# --------------------------------------------------------------------------- the routes the page uses

def _world(monkeypatch, viewer):
    admin = _user("root", role="admin")
    h = Harness(monkeypatch, admin)
    from app.core.models import User
    target = _user("carol")
    h.db.rows_of(User).append(target)
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, credential_id=b"c", retired_at=None,
                                provisional_until=None, created_at=datetime.utcnow(), transports=["usb"],
                                label="yubikey", backup_eligible=False, cose_alg=-7, last_used_at=None)
    h.rows().append(key)
    # The real administrator check, for the viewer (None: no session at all).
    h.S.app.dependency_overrides.pop(h.S.require_interactive_admin, None)
    if viewer is None:
        h.S.app.dependency_overrides.pop(h.S.get_current_user, None)
    else:
        monkeypatch.setitem(h.S.app.dependency_overrides, h.S.get_current_user, lambda: viewer)
    return h, target, key


def _auditor():
    return _user("auditor")


@pytest.mark.parametrize("who", ["user", "external", "auditor", "temporary administrator", "nobody"])
def test_only_an_interactive_administrator_reads_or_removes_someones_passkeys(monkeypatch, who):
    viewer = {"user": lambda: _user("someone"), "external": lambda: _user("guest", role="external"),
              "auditor": _auditor, "temporary administrator": lambda: _user("root-temp", role="admin",
                                                                              _is_temp_session=True),
              "nobody": lambda: None}[who]()
    h, target, key = _world(monkeypatch, viewer)
    if who == "auditor":
        from app.core.models import AuditorGrant
        h.db.rows_of(AuditorGrant).append(types.SimpleNamespace(id=uuid.uuid4(), user_id=viewer.id, status="active"))
    status, out = _call(h.S, "GET", f"/users/{target.id}/passkeys")
    assert status == (401 if who == "nobody" else 403) and "yubikey" not in str(out)
    status, out = _call(h.S, "DELETE", f"/users/{target.id}/passkeys/{key.id}")
    assert status == (401 if who == "nobody" else 403) and key.retired_at is None


def test_the_removal_asks_the_step_up_of_managing_users(monkeypatch):
    from fastapi import HTTPException
    h, target, key = _world(monkeypatch, _user("root2", role="admin"))
    asked = []

    def step_up(db, user, request, action):
        asked.append(action)
        raise HTTPException(status_code=403, detail={"second_factor_required": True, "action": action,
                                                     "reason": "step_up_required", "methods": ["password"]})
    monkeypatch.setattr(h.S, "_enforce_step_up", step_up)
    status, out = _call(h.S, "DELETE", f"/users/{target.id}/passkeys/{key.id}")
    assert status == 403 and out["detail"]["action"] == "admin.user.manage" and asked == ["admin.user.manage"]
    assert key.retired_at is None
    assert "admin.user.manage" in h.S.GUARDED_STEP_UP_ACTIONS
