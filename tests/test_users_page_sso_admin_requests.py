"""The Users page lists the administrator roles a provider's sign-in asked for (GET /admin/sso/admin-requests).

A provider that maps a group to the administrator role does not grant it at a sign-in: the sign-in raises a request
that waits seven days for an administrator's approval, and the administrators' notice sends them to the Users page.
The page shows the waiting requests, with Approve and Deny for an administrator who may decide one and the reason
in their place for one who may not, and the decided ones (the last fifty) folded away. An approval that took back a
password someone else had set hands its reset link over as a promotion does. Nothing shows when there is nothing.

Driven in Node against the page's own functions, on the small document of tests/js/mini_dom.js.
tests/test_ui_sso_admin_requests.py drives the same card in a browser.
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
_SHIPPED = ("parseServerTime", "formatServerTime", "_el", "loadSsoAdminRequests", "_ssoAdminDecidedText",
            "renderSsoAdminRequests", "decideSsoAdminRequest")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    assert found, name
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


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
const asked = [], confirms = [], toasts = [], links = [], reloads = [];
let answers = {};
let confirmAnswer = true;
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET' });
    const answer = Object.prototype.hasOwnProperty.call(answers, path) ? answers[path] : new Error('Not arranged.');
    if (answer instanceof Error) throw answer;
    return answer;
};
const showConfirm = async (message, title, input, label) => { confirms.push([message, title, label || null]); return confirmAnswer; };
const showSuccess = (m) => toasts.push(['success', m]);
const showError = (m) => toasts.push(['error', m]);
const _showResetLinkModal = (link, username, ttl) => links.push([link, username, ttl]);
const loadUsers = async () => { reloads.push(1); };
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const make = (tag, id, parent) => { const el = document.createElement(tag); el.id = id; (parent || document.body).appendChild(el); return el; };
const block = make('div', 'sso-admin-requests');
const list = make('div', 'sso-admin-requests-list', block);
const decidedBox = make('details', 'sso-admin-requests-decided', block);
const decidedList = make('div', 'sso-admin-requests-decided-list', decidedBox);
const PATH = '/admin/sso/admin-requests';
const HELD = [
    { id: 'r-1', username: 'bob', provider: 'Contoso', provider_group: 'vault-admins', requested_at: '2026-06-14T09:00:00Z',
      expires_at: '2026-06-21T09:00:00Z', state: 'held', decided_by: null, decided_at: null, you_may_decide: true,
      refusal: null },
    { id: 'r-2', username: 'carol', provider: 'Contoso', provider_group: 'vault-admins',
      requested_at: '2026-06-13T09:00:00Z', expires_at: '2026-06-20T09:00:00Z', state: 'held', decided_by: null,
      decided_at: null, you_may_decide: false,
      refusal: "You made or approved a change to this account's sign-in details in the last 14 days." }];
const DECIDED = [
    { id: 'r-3', username: 'dan', provider: 'Contoso', provider_group: 'vault-admins', requested_at: '2026-06-01T09:00:00Z',
      expires_at: '2026-06-08T09:00:00Z', state: 'approved', decided_by: 'erin', decided_at: '2026-06-02T09:00:00Z',
      you_may_decide: false, refusal: null },
    { id: 'r-4', username: 'fay', provider: 'Contoso', provider_group: 'vault-admins', requested_at: '2026-05-01T09:00:00Z',
      expires_at: '2026-05-08T09:00:00Z', state: 'expired', decided_by: null, decided_at: '2026-06-10T09:00:00Z',
      you_may_decide: false, refusal: null }];
const rows = (host) => host.querySelectorAll('.credential-request-row').map((row) => ({
    id: row.getAttribute('data-request-id'),
    text: row.children[0].children.map((c) => c.textContent),
    actions: row.children[1].children.map((c) => [c.localName, c.textContent, c.getAttribute('aria-label')]) }));
// A request's button by its accessible name, as a person using a screen reader finds it.
const button = (label) => list.querySelectorAll('button').find((b) => b.getAttribute('aria-label') === label);
const when = (v) => new Date(v).toLocaleString();
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


def test_the_card_lists_the_waiting_requests_and_the_decided_ones():
    got = _node(r"""
answers[PATH] = { held: HELD, decided: DECIDED };
await loadSsoAdminRequests();
out({ shown: block.style.display || '', held: rows(list), decided: rows(decidedList),
      decidedShown: decidedBox.style.display || '',
      times: [HELD[0].requested_at, HELD[0].expires_at, HELD[1].requested_at, HELD[1].expires_at,
              DECIDED[0].decided_at, DECIDED[1].expires_at].map(when) });
""")
    t = got["times"]
    assert got["shown"] == "" and got["decidedShown"] == ""
    bob, carol = got["held"]
    assert bob == {"id": "r-1", "text": ["bob signed in through Contoso in the group vault-admins, which is mapped to "
                                         "the administrator role.", f"Requested {t[0]} · expires {t[1]}"],
                   "actions": [["button", "Approve", "Approve bob"], ["button", "Deny", "Deny bob"]]}
    # One this administrator may not decide: the reason in place of the buttons.
    assert carol == {"id": "r-2", "text": ["carol signed in through Contoso in the group vault-admins, which is "
                                           "mapped to the administrator role.", f"Requested {t[2]} · expires {t[3]}"],
                     "actions": [["span", "You made or approved a change to this account's sign-in details in the "
                                          "last 14 days.", None]]}
    dan, fay = got["decided"]
    assert dan["text"] == ["dan, through Contoso (group vault-admins)", f"Approved by erin, {t[4]}."]
    assert fay["text"] == ["fay, through Contoso (group vault-admins)",
                           f"Expired {t[5]}: nobody decided within 7 days."]
    assert dan["actions"] == [] and fay["actions"] == []


def test_nothing_shows_when_nothing_was_asked_or_the_list_cannot_be_read():
    got = _node(r"""
answers[PATH] = { held: [], decided: [] };
await loadSsoAdminRequests();
const empty = block.style.display;
answers[PATH] = { held: HELD, decided: [] };
await loadSsoAdminRequests();
const held = [block.style.display || '', decidedBox.style.display];
answers[PATH] = new Error('Admin privileges required');
await loadSsoAdminRequests();
const failed = block.style.display;
currentUser = { id: 'me', username: 'alice', role: 'user' };
const before = asked.length;
await loadSsoAdminRequests();
out({ empty, held, failed, user: block.style.display, askedByUser: asked.length - before });
""")
    assert got == {"empty": "none", "held": ["", "none"], "failed": "none", "user": "none", "askedByUser": 0}


def test_an_approval_is_confirmed_first_and_hands_a_reset_link_over():
    got = _node(r"""
answers[PATH] = { held: HELD, decided: [] };
answers[PATH + '/r-1/approve'] = { request: Object.assign({}, HELD[0], { state: 'approved' }), username: 'bob',
    handed_over: { emailed: false, reset_link: '/reset-password?token=abc', expires_in_minutes: 30 } };
await loadSsoAdminRequests();
confirmAnswer = false;
button('Approve bob').click();
await tick(); await tick();
const declined = asked.filter((a) => a.method === 'POST').length;
confirmAnswer = true;
button('Approve bob').click();
await tick(); await tick(); await tick();
out({ declined, confirm: confirms[1], posts: asked.filter((a) => a.method === 'POST').map((a) => a.path), toasts,
      links, reloads: reloads.length });
""")
    assert got["declined"] == 0
    assert got["confirm"] == ["Make bob an administrator? Their sign-in through Contoso put them in a group mapped to "
                              "the administrator role. They and the other administrators are told.",
                              "Approve the administrator role?", "Approve"]
    assert got["posts"] == ["/admin/sso/admin-requests/r-1/approve"]
    assert got["toasts"] == [["success", "bob is now an administrator."]]
    assert got["links"] == [["/reset-password?token=abc", "bob", 30]]
    assert got["reloads"] == 1


def test_an_approval_that_emailed_the_link_or_could_make_none_says_so():
    got = _node(r"""
answers[PATH] = { held: HELD, decided: [] };
await loadSsoAdminRequests();
const said = {};
for (const [name, handed] of [['emailed', { emailed: true, reset_link: null, expires_in_minutes: null }],
                              ['none', { emailed: false, reset_link: null, expires_in_minutes: null }],
                              ['own', null]]) {
    answers[PATH + '/r-1/approve'] = { username: 'bob', handed_over: handed };
    toasts.length = 0;
    button('Approve bob').click();
    await tick(); await tick(); await tick();
    said[name] = toasts.slice();
}
out(said);
""")
    assert got["emailed"] == [["success", "bob is now an administrator."],
                              ["success", "Their password was reset: a link to choose a new one was emailed to them."]]
    assert got["none"] == [["success", "bob is now an administrator."],
                           ["error", "Their password was reset, and no reset link could be made: set a new password "
                                     "for them."]]
    assert got["own"] == [["success", "bob is now an administrator."]]


def test_a_denial_is_confirmed_and_a_refused_decision_is_said_in_the_servers_words():
    got = _node(r"""
answers[PATH] = { held: HELD, decided: [] };
answers[PATH + '/r-1/deny'] = { request: Object.assign({}, HELD[0], { state: 'denied' }) };
await loadSsoAdminRequests();
button('Deny bob').click();
await tick(); await tick(); await tick();
const denied = { confirm: confirms[0], toasts: toasts.slice() };
toasts.length = 0;
answers[PATH + '/r-1/approve'] = new Error('The request changed meanwhile; look again.');
button('Approve bob').click();
await tick(); await tick(); await tick();
out({ denied, refused: toasts, posts: asked.filter((a) => a.method === 'POST').map((a) => a.path),
      reloads: reloads.length });
""")
    assert got["denied"]["confirm"] == ["bob stays as they are, and is told the administrator role was not granted.",
                                        "Deny the administrator role?", "Deny"]
    assert got["denied"]["toasts"] == [["success", "bob was not made an administrator; they are told."]]
    assert got["refused"] == [["error", "The request changed meanwhile; look again."]]
    assert got["posts"] == ["/admin/sso/admin-requests/r-1/deny", "/admin/sso/admin-requests/r-1/approve"]
    assert got["reloads"] == 2                 # the list is read again after each, decided or refused
