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
            "_passkeysShownFor", "loadUserPasskeys", "renderUserPasskeys", "removeUserPasskey", "_passkeysHeld",
            "renderUserDetail")


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


def _node(scenario, more=()):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + "".join(_function(js, n) for n in _SHIPPED + tuple(more)) + "(async () => {\n" + scenario
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



# --------------------------------------------------------------------------- a reset of the second factor

# A reset retires every passkey the account holds, whether it can sign in with it now or not, as well as the
# authenticator app and its recovery codes; the row, the button, the confirmation and the toast say so.
_RESET = ("signInMethods", "signInMethodBadges", "_holdsAFactor", "_resetEnds", "_ssoStanding", "renderUserRow",
          "resetUserSecondFactor")


def test_a_passkey_is_a_second_factor_in_the_row_and_any_held_passkey_can_be_reset():
    got = _node(r"""
People.placeholder = () => '';
const row = (extra) => Object.assign({ id: 'u-dave', username: 'dave', role: 'user', groups: [], is_active: true,
                                       second_factor_enabled: false, passkey_count: 0, passkey_unusable_count: 0 }, extra);
const seen = (u) => { const html = renderUserRow(u);
    return { on: html.includes(' On</span>'), off: html.includes('Off</span>'),
             reset: html.includes('reset-second-factor-btn') }; };
out({ passkey: seen(row({ passkey_count: 1 })), app: seen(row({ second_factor_enabled: true })),
      unusable: seen(row({ passkey_unusable_count: 1 })), none: seen(row({})),
      own: seen(row({ id: 'me', username: 'alice', role: 'admin', passkey_count: 2 })) });
""", _RESET)
    assert got["passkey"] == {"on": True, "off": False, "reset": True}
    assert got["app"] == {"on": True, "off": False, "reset": True}
    # A key that is no factor now is not a way in, yet the reset retires it: the button is offered.
    assert got["unusable"] == {"on": False, "off": True, "reset": True}
    assert got["none"] == {"on": False, "off": True, "reset": False}
    assert got["own"]["on"] is True and got["own"]["reset"] is False


def test_the_reset_says_what_stops_working_and_how_the_person_sets_a_new_factor_up():
    got = _node(r"""
const path = '/users/u-carol/second-factor/reset';
const reset = async (extra, answer) => {
    Object.assign(carol, { second_factor_enabled: false, passkey_count: 0, passkey_unusable_count: 0,
                           password_to_type: true }, extra);
    answers[path] = answer;
    confirms.length = 0; toasts.length = 0;
    await resetUserSecondFactor('u-carol');
    return { confirm: confirms[0], toasts: toasts.slice() };
};
out({
    both: await reset({ second_factor_enabled: true, passkey_count: 2, password_to_type: false },
                      { reset: true, passkeys_retired: 2, own_password: false }),
    app: await reset({ second_factor_enabled: true }, { reset: true, passkeys_retired: 0, own_password: true }),
    one: await reset({ passkey_unusable_count: 1 }, { reset: true, passkeys_retired: 1, own_password: true }),
    keys: await reset({ passkey_count: 1, passkey_unusable_count: 2 }, { reset: true }),
    posted: asked.filter((a) => a.method === 'POST').map((a) => a.path),
});
""", _RESET)
    message, title, label = got["both"]["confirm"]
    assert (title, label) == ("Reset the second factor?", None)
    assert message == ("carol will be signed out everywhere. Their authenticator app, its recovery codes and their 2 "
                       "passkeys stop working. They set up a new second factor at their next sign-in through your "
                       "organisation.")
    assert got["both"]["toasts"] == [["success", "Second factor reset and 2 passkeys retired. carol sets one up "
                                                 "again at the next sign-in."]]
    assert got["app"]["confirm"][0] == ("carol will be signed out everywhere. Their authenticator app and its "
                                        "recovery codes stop working. They set up a new second factor at their next "
                                        "sign-in, with their own password.")
    assert got["app"]["toasts"] == [["success", "Second factor reset. carol sets one up again at the next sign-in."]]
    assert got["one"]["confirm"][0] == ("carol will be signed out everywhere. Their passkey stops working. They set "
                                        "up a new second factor at their next sign-in, with their own password.")
    assert got["one"]["toasts"] == [["success", "Second factor reset and 1 passkey retired. carol sets one up again "
                                                "at the next sign-in."]]
    assert got["keys"]["confirm"][0].startswith("carol will be signed out everywhere. Their 3 passkeys stop working.")
    assert got["keys"]["toasts"] == [["success", "Second factor reset. carol sets one up again at the next sign-in."]]
    assert got["posted"] == ["/users/u-carol/second-factor/reset"] * 4


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


def test_a_reset_answers_how_many_passkeys_it_retired_and_whether_the_account_has_a_password_to_type(monkeypatch):
    """An account made at its first sign-in through a provider holds a password nobody knows; its passkey is its
    only factor. The reset retires the passkey and says so, and that the account has no password anybody can type,
    so the page can tell the administrator how the person sets a new factor up."""
    from app.core import password_origin
    from app.core.models import User
    admin = _user("root", role="admin")
    h = Harness(monkeypatch, admin)
    target = _user("carol", password_hash="random-bytes", had_a_password_at=None)
    password_origin.mark_nobody_knows(target)
    h.db.rows_of(User).append(target)
    key = types.SimpleNamespace(id=uuid.uuid4(), user_id=target.id, credential_id=b"c", retired_at=None,
                                uv_initialized=True, cose_alg=-7)
    h.rows().append(key)
    monkeypatch.setattr(h.S, "_revoke_sessions", lambda db, **kw: None)
    from app.core import auditor_rights, legal_holds
    monkeypatch.setattr(auditor_rights, "after_credential_change", lambda *a, **k: None)
    monkeypatch.setattr(legal_holds, "after_starter_change", lambda *a, **k: None)
    status, out = _call(h.S, "POST", f"/users/{target.id}/second-factor/reset", headers={"X-Second-Factor": "ok"})
    assert status == 200, out
    assert out == {"reset": True, "passkeys_retired": 1, "own_password": False}
    assert key.retired_at is not None and target.second_factor_reset_at is not None


def test_the_users_list_says_whether_each_account_has_a_password_somebody_can_type():
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    answer = source[source.index("class UserResponse("):]
    answer = answer[:answer.index("\nclass ")]
    assert "password_to_type: bool = False" in answer
    listing = source[source.index("async def list_users("):]
    listing = listing[:listing.index("\n@app.")]
    assert "item.password_to_type = sign_in.has_a_password_it_can_type(user)" in listing
