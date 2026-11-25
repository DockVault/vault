"""The page and a busy answer (static/js/app.js and static/js/session-watch.js, run in Node with stand-ins).

A request whose wait for a lock ran out is answered 503 with the server's sentence ("The vault is busy with this
right now. Try again in a moment.") and Retry-After: 5. The wait is for the person: the page shows the sentence where
it would have shown its own words, and sends nothing again by itself. Stay signed in says it too and keeps the
token it has (a renewal mints a new token: it is never sent twice behind the person's back), and a page whose sign-in
check at the load is answered so shows the sign-in screen with the sentence. Where no answer came at all (offline),
or the error is the page's own, the page's words stay. A sentence apiRequest has shown already (a refusal of
permission, a rate limit) is not shown twice: the caller's own words follow it, as before.

The sign-in screen's own busy answers (a provider's sign-in refused as busy, a finish answered 503) are said in the
server's words, and the finish is not sent again.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

from _js_source import strip_comments
from test_session_told_renewal_and_retry import REQUESTS
from test_session_watch_refusals import _node as _session_watch
from test_sso_sign_in_screen import _node as _sign_in_screen, _server_reasons

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

BUSY = "The vault is busy with this right now. Try again in a moment."


def _function(name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", APP)
    assert found, name
    start = found.start() + 1
    return APP[start:APP.index("\n}\n", start) + 3]


def _state(name):
    found = re.search(rf"^let {re.escape(name)} = [^;]*;", APP, re.M)
    assert found, name
    return found.group(0) + "\n"


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const print = console.log.bind(console);
console.log = () => {}; console.error = () => {}; console.warn = () => {};
var API_BASE = '/api';
var authToken = 'the-token';
var currentUser = { id: 'me', username: 'dana', role: 'admin' };
var userPermissions = [];
const toasts = [];
function showToast(m, t) { toasts.push([t, m]); }
function showError(m) { toasts.push(['error', m]); }
function showSuccess(m) { toasts.push(['success', m]); }
function showWarning(m) { toasts.push(['warning', m]); }
function showInfo(m) { toasts.push(['info', m]); }
function showPermissionDenied(m) { toasts.push(['denied', m]); }
function logout(how, reason) { toasts.push(['signed out', how === undefined ? null : how, reason === undefined ? null : reason]); }
async function requestStepUpReceipt() { return null; }
async function showConfirm() { return true; }
// Nothing waits here: a request sent again after a wait would be sent at once, and counted.
const realSetTimeout = setTimeout;
const waits = [];
globalThis.setTimeout = (fn, ms) => { waits.push(ms); return realSetTimeout(fn, 0); };
const settle = async () => { for (let i = 0; i < 30; i += 1) await new Promise((r) => setImmediate(r)); };
const sent = [];
let ANSWER = null;          // { status, body } answered to every request, or 'offline' (no answer at all)
globalThis.fetch = async (url, opts) => {
    sent.push({ url, method: (opts && opts.method) || 'GET' });
    if (ANSWER === 'offline') throw new TypeError('Failed to fetch');
    const { status, body } = ANSWER;
    const named = { 'content-type': 'application/json', 'retry-after': status === 503 ? '5' : null };
    return { status, ok: status >= 200 && status < 300, statusText: 'Service Unavailable',
             headers: { get: (h) => named[String(h).toLowerCase()] || null },
             text: async () => JSON.stringify(body), json: async () => body };
};
const out = (value) => print(JSON.stringify(value));
"""

# Each caller of apiRequest that shows its own words for a failure: those words, what the page holds for it (stand-ins
# of what it calls, its elements; READ is the text it writes into the page, when it writes there), and the call.
CALLERS = {
    "saveLogFlag": ("Could not update log access", r"""
window._logSettings = { flags: {} };
function loadLogSettings() {}
""", "await saveLogFlag('web', true);"),
    "saveLogStealth": ("Could not update log visibility", r"""
window._logSettings = { flags: {} };
function loadLogSettings() {}
""", "await saveLogStealth(true);"),
    "disableLogToken": ("Could not disable token", r"""
function loadLogSettings() {}
""", "await disableLogToken('t-1');"),
    "generateLogToken": ("Could not create token", r"""
window._logSettings = { ceiling: true };
const nameField = document.createElement('input'); nameField.id = 'log-token-name'; nameField.value = 'monitor';
document.body.appendChild(nameField);
const everyMatch = document.querySelectorAll.bind(document);
document.querySelectorAll = (sel) => (sel === '#log-token-scope input[type=checkbox]:checked' ? [{ value: 'web' }]
                                                                                                 : everyMatch(sel));
""", "await generateLogToken();"),
    "checkForUpdatesNow": ("Could not check for updates", r"""
const checkButton = document.createElement('button'); checkButton.id = 'update-check-now-btn';
document.body.appendChild(checkButton);
function renderUpdateStatus() {}
""", "await checkForUpdatesNow();"),
    "saveUpdateInterval": ("Could not save the update interval", r"""
const intervalField = document.createElement('input'); intervalField.id = 'update-interval-input'; intervalField.value = '60';
document.body.appendChild(intervalField);
function scheduleUpdatePoll() {}
""", "await saveUpdateInterval();"),
    "openGroupMembersModal": ("Could not load department members.", "", "await openGroupMembersModal('g-1', 'Sales');"),
    "loadUsersForPermission": ("Failed to load users for permissions", "", "await loadUsersForPermission();"),
    "renameVaultItem": ("Failed to rename item", r"""
const state = { currentFiles: [], currentVault: { id: 'v-1', has_password: false } };
async function showRenameDialog() { return 'new name.txt'; }
function isZkVault() { return false; }
async function loadVaultFiles() {}
""", "await renameVaultItem('f-1', 'old name.txt', 'file');"),
    "loadEmailProfiles": ("Could not load sending profiles.", r"""
const grid = document.createElement('div'); grid.id = 'email-profiles-grid'; document.body.appendChild(grid);
READ = () => grid.textContent;
""", "await loadEmailProfiles();"),
    "loadUserSshKeys": ("Could not load SSH keys.", r"""
const keysHost = document.createElement('div'); keysHost.className = 'ssh-keys-list';
keysHost.setAttribute('data-user-id', 'u-1'); document.body.appendChild(keysHost);
READ = () => keysHost.textContent;
""", "await loadUserSshKeys('u-1');"),
    "loadRecentEvents": ("Couldn't load recent events.", r"""
const feed = document.createElement('div'); feed.id = 'events-feed'; document.body.appendChild(feed);
function _dashboardSessionGone(who) { return !who || authToken !== who; }
READ = () => feed.textContent;
""", "await loadRecentEvents();"),
    "showGrantRecipientKey": ("Their encryption key could not be looked up.", r"""
const keyBox = document.createElement('div'); document.body.appendChild(keyBox);
READ = () => keyBox.textContent;
""", "await showGrantRecipientKey('u-1', keyBox);"),
    "loadSftpPolicyGroups": ("Could not load departments — the confidentiality policies are read-only and will not "
                             "be changed on save.", r"""
function renderSftpGroupPicker() {}
function renderStandardWhitelistPicker() {}
""", "await loadSftpPolicyGroups();"),
}


def _caller(name: str, answer) -> dict:
    """Run one caller as the page runs it, its request answered `answer` (or not at all: 'offline'): the toasts, the
    text it wrote into the page, how many requests went out and every wait asked for."""
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    _fixed, setup, call = CALLERS[name]
    helper = _function("serverSaid") if re.search(r"\nfunction serverSaid\(", APP) else ""
    script = (PRELUDE + "let READ = null;\n" + REQUESTS + "\n"
              + _state("settingsAllGroups") + _state("settingsGroupsLoaded")
              + "".join(_function(n) for n in ("_el", name)) + helper + setup
              + "(async () => {\nANSWER = " + json.dumps(answer) + ";\n" + call + "\nawait settle();\n"
              + "out({ toasts, page: READ ? READ() : null, sent: sent.length, waits });\n"
              + "})().catch((e) => { print(String(e && e.stack)); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


READS_THE_PAGE = {"loadEmailProfiles", "loadUserSshKeys", "loadRecentEvents", "showGrantRecipientKey"}


def _said(name: str, got: dict):
    """What the person reads, and any other error or warning shown: the text the caller wrote into the page, or the
    toasts of an error or a warning."""
    warned = [t[1] for t in got["toasts"] if t[0] in ("error", "warning")]
    if name in READS_THE_PAGE:
        return [got["page"]], warned
    return warned, []


@pytest.mark.parametrize("name", sorted(CALLERS))
def test_a_busy_answer_is_shown_in_the_servers_words_and_not_sent_again(name):
    fixed = CALLERS[name][0]
    got = _caller(name, {"status": 503, "body": {"detail": BUSY}})
    said, other = _said(name, got)
    if name == "loadSftpPolicyGroups":
        # The server's sentence first, then what the page does about it: the policies stay as they are.
        assert said == [BUSY + " " + fixed], got
    else:
        assert said == [BUSY], got
    assert other == [] and got["sent"] == 1 and got["waits"] == [], got


@pytest.mark.parametrize("name", sorted(CALLERS))
def test_no_answer_at_all_keeps_the_pages_own_words(name):
    fixed = CALLERS[name][0]
    got = _caller(name, "offline")
    said, other = _said(name, got)
    assert said == [fixed] and other == [] and got["sent"] == 1, got


def test_a_sentence_the_request_has_shown_is_not_shown_twice():
    """A refusal of permission is shown by the request itself (a caller that is not silent): the caller's own words
    follow it, as they did. Any other refusal the server words is the caller's sentence."""
    denied = _caller("saveLogFlag", {"status": 403, "body": {"detail": "Administrators only."}})
    assert denied["toasts"] == [["denied", "Administrators only."], ["error", "Could not update log access"]], denied
    refused = _caller("saveLogFlag", {"status": 409, "body": {"detail": "Another administrator changed this."}})
    assert refused["toasts"] == [["error", "Another administrator changed this."]], refused
    # A silent caller's refusal of permission was not shown: its sentence is the caller's.
    quiet = _caller("loadUserSshKeys", {"status": 403, "body": {"detail": "Not your keys."}})
    assert quiet["page"] == "Not your keys." and quiet["toasts"] == [], quiet


def test_only_an_answer_of_the_server_replaces_the_pages_words():
    node = shutil.which("node")
    assert node
    script = PRELUDE + _function("serverSaid") + r"""
const said = (e) => serverSaid(e, 'fixed');
const answered = (status, message) => Object.assign(new Error(message), { status });
out([
    said(answered(503, 'Busy.')), said(answered(400, 'Bad.')), said(answered(500, 'Broke.')),
    said(answered(503, '')), said(answered(200, 'Fine.')), said(new Error('local failure')),
    said(new TypeError('Failed to fetch')), said(null), said(undefined), said('text'),
    said(Object.assign(answered(429, 'Slow down.'), { shown: true })),
    said(Object.assign(new Error('x'), { status: '503' })),
]);
"""
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    got = json.loads(done.stdout.strip().splitlines()[-1])
    assert got == ["Busy.", "Bad.", "Broke.", "fixed", "fixed", "fixed", "fixed", "fixed", "fixed", "fixed", "fixed",
                   "fixed"]


# --------------------------------------------------------------------------- Stay signed in

def test_stay_signed_in_answered_busy_says_so_keeps_the_token_and_sends_once():
    out = _session_watch(f"""
route = () => Promise.resolve({{ status: 503, ok: false, headers: {{ get: (h) => (h === 'Retry-After' ? '5' : null) }},
                                json: async () => ({{ detail: {json.dumps(BUSY)} }}) }});
await stay();
out({{ toasts, held: authToken === mine, stored: store.get('authToken') === mine, sent: sent.length, logouts }});
""")
    assert out["toasts"] == [["error", BUSY]], out
    assert out["held"] is True and out["stored"] is True and out["sent"] == 1 and out["logouts"] == 0, out


def test_stay_signed_in_with_no_answer_or_no_sentence_keeps_its_own_words():
    for route in ("() => Promise.reject(new TypeError('Failed to fetch'))",
                  "() => Promise.resolve({ status: 502, ok: false, headers: { get: () => null }, "
                  "json: async () => { throw new SyntaxError('not json'); } })"):
        out = _session_watch(f"""
route = {route};
await stay();
out({{ toasts, held: authToken === mine, sent: sent.length, logouts }});
""")
        assert out == {"toasts": [["error", "Could not extend the session right now. Try again, or sign in again when "
                                            "it ends."]], "held": True, "sent": 1, "logouts": 0}, out


# --------------------------------------------------------------------------- the sign-in check at the load

def _sign_in_check(status: int, body) -> list:
    node = shutil.which("node")
    assert node
    script = PRELUDE + _state("_sessionsEnded") + r"""
const SIGN_OUT_THIS_TAB = 'this-tab';
const storage = { setItem() {}, getItem() { return null; }, removeItem() {} };
async function applyServerPreferences() { return true; }      // the page reloads here: nothing more is drawn
""" + _function("_refusesTheSession") + _function("enterAuthedSession") + f"""
(async () => {{
    globalThis.fetch = async (url) => {{ sent.push({{ url }}); return {{ status: {status}, ok: {str(200 <= status < 300).lower()},
        headers: {{ get: () => null }}, json: async () => {{ const b = {json.dumps(body)}; if (b === null) throw new SyntaxError('html'); return b; }} }}; }};
    const fell = await enterAuthedSession();
    out({{ toasts, sent: sent.length, fell: fell === undefined ? null : fell }});
}})();
"""
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_busy_sign_in_check_at_the_load_signs_this_tab_out_with_the_servers_sentence():
    # The check says why it fell to the sign-in screen: what a provider's answer that came back with the load is then
    # told turns on it (a session refused ended; one the check could not answer did not).
    got = _sign_in_check(503, {"detail": BUSY})
    assert got == {"toasts": [["signed out", "this-tab", BUSY]], "sent": 1, "fell": "unanswered"}, got
    # A 503 that is not the vault's (a proxy's page while it restarts) has no sentence: none is shown, as before.
    assert _sign_in_check(503, None) == {"toasts": [["signed out", "this-tab", None]], "sent": 1, "fell": "unanswered"}
    assert _sign_in_check(500, None) == {"toasts": [["signed out", "this-tab", None]], "sent": 1, "fell": "unanswered"}
    # A refusal of the session is as before.
    assert _sign_in_check(401, {"detail": "Session expired"}) == {"toasts": [["signed out", None, None]], "sent": 1,
                                                                   "fell": "refused"}


# --------------------------------------------------------------------------- nothing waits and sends again by itself

DECL = re.compile(r"^( *)(?:async )?function ([A-Za-z_$][\w$]*)\(", re.M)


def _enclosing(code: str, at: int):
    """The function declared on a line of its own before `at` whose closing brace, on a line of its own at the
    declaration's indent, comes after it: (name, body)."""
    best = None
    for m in DECL.finditer(code, 0, at):
        end = code.find("\n" + m.group(1) + "}", m.end())
        if end > at:
            best = (m.group(2), code[m.start():end])
    return best


def test_no_script_waits_and_sends_again_on_a_busy_answer():
    """Every comparison of a status with 429 or 503 in the page's scripts, and the function it is in. The ones that
    wait and send again by themselves are two: a paste, which waits for the person's own earlier copy or move on a 429
    only, and the sign-out, which must reach the server and is owed until it does (it waits on a 429 or any server
    error). No 503 leads to a wait, and nothing after one sends a request again unless the person asks for it."""
    seen, resends = [], set()
    for path in sorted((ROOT / "static" / "js").glob("*.js")):
        code = strip_comments(path.read_text(encoding="utf-8"))
        for m in re.finditer(r"status\s*===?\s*(429|503)\b", code):
            name, body = _enclosing(code, m.start()) or ("", "")
            assert name, (path.name, code[m.start() - 80:m.end()])
            seen.append((path.name, name, m.group(1)))
            if "setTimeout(" in body or "setInterval(" in body or "_signOutAgain(" in body:
                resends.add((path.name, name))
            if m.group(1) == "503":
                assert "setTimeout(" not in body and "setInterval(" not in body, (path.name, name)
                after = body[body.index(m.group(0)):]
                sends = [s.start() for s in re.finditer(rf"\b(?:fetch|apiRequest|{re.escape(name)})\(", after)]
                if sends:
                    assert "showConfirm(" in after[:min(sends)], (path.name, name, after[:400])
    assert resends == {("app.js", "_pasteOne"), ("app.js", "_sendSignOut")}, resends
    assert [s for s in seen if s[1] == "_pasteOne"] == [("app.js", "_pasteOne", "429")]
    assert any(s[2] == "503" for s in seen)          # the scan reads what it is meant to
    # The request code itself never sends again on a 503: it compares no status with it, and a busy answer leaves
    # by the branch every other refusal takes.
    requests = strip_comments(_function("_apiRequestNow"))
    assert "503" not in requests and ">= 500" not in requests


# --------------------------------------------------------------------------- the sign-in screen

def test_a_provider_sign_in_refused_as_busy_says_so_on_the_sign_in_screen():
    reasons = _server_reasons()
    got = _sign_in_screen(r"""
answers['GET /api/auth/sso/reasons'] = { status: 200, json: { reasons: REASONS } };
await _ssoOnSignInScreen(arrive('#sso-error=busy'));
out(note());
""", reasons)
    assert got == {"text": "Signing in is busy right now. Try again in a moment.", "shown": True}
    assert reasons["busy"] == got["text"]


def test_a_finish_answered_busy_is_said_and_not_sent_again():
    from app.services import sign_in
    said = sign_in.BUSY_START_AGAIN
    assert said == "Signing in is busy right now. Start the sign-in again in a moment."
    got = _sign_in_screen(r"""
store.dv_sso_flow = JSON.stringify({ purpose: 'sign_in', provider: 'p-1', verifier: 'the-verifier', at: Date.now() });
answers['POST /api/auth/finish'] = { status: 503, json: { detail: SAID } };
await _ssoOnSignInScreen(arrive('#sso=code-1'));
await settle();
out({ note: note(), finishes: sent.filter((s) => s.url === '/api/auth/finish').map((s) => s.body), passkey });
""".replace("SAID", json.dumps(said)))
    assert got["note"] == {"text": said, "shown": True}, got
    assert got["finishes"] == [{"code": "code-1", "verifier": "the-verifier"}], got
    assert got["passkey"] == ["stop", "hold", "go"], got
