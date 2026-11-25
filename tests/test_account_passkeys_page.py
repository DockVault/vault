"""Your account's passkeys (static/js/app.js, renderAccountPasskeys): what each row says of its key beyond its dates.

GET /users/me/passkeys says of every key whether it is a factor now (``usable``), why not (``not_usable_because``),
until when its signature algorithm is still accepted (``accepted_until``) and whether it ever checked the person
(``user_verified``). A key that no longer signs its owner in must not look like one that does: its row says why, and
what the owner can do about it; a key whose algorithm was removed says the day it stops. The usable key's row says
nothing more.

The page's own functions run in Node on the small document of tests/js/mini_dom.js, against a stand-in for the
server (the server's side has its own tests).
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
# Your account's passkeys, as shipped; a name that is not in app.js is left out (and its test fails on what the page
# does, not on a missing name).
_SHIPPED = ("_el", "parseServerTime", "_passkeyWhen", "_passkeyStateText", "_addressFixable", "renderAccountPasskeys",
            "_addPasskey")


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    if not found:
        return ""
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const section = document.createElement('div'); section.id = 'us-passkeys-section'; document.body.appendChild(section);
const body = document.createElement('div'); body.id = 'us-passkeys-body'; section.appendChild(body);
global.location = { origin: 'https://vault.example.test', hostname: 'vault.example.test', protocol: 'https:' };
var currentUser = { id: 'me', username: 'alice', role: 'user' };
const asked = [], toasts = [];
let answers = {};
global.apiRequest = async (path, options) => {
    const method = (options || {}).method || 'GET';
    asked.push({ path, method, body: (options || {}).body || null });
    const key = method + ' ' + path;
    const answer = Object.prototype.hasOwnProperty.call(answers, key) ? answers[key] : new Error('Not arranged: ' + key);
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer() : answer;
};
const showSuccess = (m) => toasts.push(['success', m]);
const showError = (m) => toasts.push(['error', m]);
let promptAnswer = null;
const showPrompt = async () => promptAnswer;
const showConfirm = async () => true;
const storage = { getItem: () => null, setItem() {}, removeItem() {} };
const PASSKEY_USED_HERE = 'passkeyUsedHere';
function _markPasskeyUsedHere() {}
global.Passkeys = { supported: () => true, create: async () => ({ id: 'made' }), cancelled: () => false,
                    failureText: (e) => String(e) };
let _passkeyFirstProof = null;
let _passkeyAddConfirmed = false;
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const day = (v) => new Date(v).toLocaleDateString();
// Each row: its key, the lines of its text column, the class of each line, and its buttons.
const rows = () => body.querySelectorAll('.passkey-row').map((row) => ({
    id: row.dataset.passkeyId,
    lines: row.children[0].children.map((c) => c.textContent),
    classes: row.children[0].children.map((c) => c.className),
    buttons: row.querySelectorAll('button').map((b) => b.textContent) }));
const LIST = (passkeys, more) => Object.assign({ passkeys, limit: 20, enabled: true, origin: 'https://vault.example.test',
    requirement: {}, first_proof: { kind: 'step_up', providers: [] }, provider_only: null, attestation: 'none' }, more || {});
const KEY = (id, more) => Object.assign({ id, label: id, created_at: '2026-03-02T10:00:00Z', last_used_at: null,
    synced: false, usable: true, not_usable_because: null, accepted_until: null, algorithm: 'ES256',
    user_verified: true, provisional: false, provisional_until: null }, more || {});
const out = (value) => console.log(JSON.stringify(value));
"""


def account_node(scenario: str):
    """Runs ``scenario`` after the shipped functions of Your account's passkeys, and returns what it printed last."""
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + "".join(_function(js, n) for n in _SHIPPED)
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_key_that_no_longer_signs_its_owner_in_says_why_and_what_to_do():
    """One usable key, one key for each reason a key is no factor while passkeys are on (turned off, the section is
    not shown at all), and one whose algorithm was removed and still runs out its days: each sentence on its own
    row, and nothing more on the usable one."""
    got = account_node(r"""
answers['GET /users/me/passkeys'] = LIST([
    KEY('works'),
    KEY('moved', { usable: false, not_usable_because: 'passkeys_at_another_address' }),
    KEY('old-alg', { usable: false, not_usable_because: 'passkeys_no_longer_accepted', algorithm: 'RS256' }),
    KEY('no-pin', { usable: false, not_usable_because: 'passkeys_without_verification', user_verified: false }),
    KEY('ending', { accepted_until: '2026-07-01T09:00:00Z', algorithm: 'RS256' })]);
await renderAccountPasskeys();
out({ rows: rows(), ending: day('2026-07-01T09:00:00Z') });
""")
    by_id = {row["id"]: row for row in got["rows"]}
    assert set(by_id) == {"works", "moved", "old-alg", "no-pin", "ending"}
    assert len(by_id["works"]["lines"]) == 2, by_id["works"]          # its name and its dates, nothing more
    said = {
        "moved": ("Made at another address than this vault has now: it no longer signs you in or confirms it is "
                  "you here. Remove it and add a new one.", "passkey-not-usable"),
        "old-alg": ("Uses RS256, which this vault no longer accepts: it no longer signs you in or confirms it is "
                    "you. Remove it and add a new one.", "passkey-not-usable"),
        "no-pin": ("This vault now asks a passkey to check your PIN, fingerprint or face, and this one has not: it "
                   "does not sign you in or confirm it is you until it does. Set that up on it and use it once, or "
                   "remove it and add another.", "passkey-not-usable"),
        "ending": (f"Uses RS256, which this vault stops accepting on {got['ending']}: add a new passkey before "
                   "then, then remove this one.", "passkey-accepted-until"),
    }
    for key, (sentence, marker) in said.items():
        row = by_id[key]
        assert row["lines"][2:] == [sentence], row
        # Right under the key's dates, in the colour of a warning.
        assert row["classes"][2].split() == ["text-warning", "text-xs", marker], row
        assert row["buttons"] == ["Rename", "Remove"], row
    for other in by_id.values():
        assert sum(sentence in line for line in other["lines"] for sentence, _ in said.values()) == (
            0 if other["id"] == "works" else 1), other


def test_the_words_for_each_reason_are_the_owners_or_the_administrators_and_an_unknown_one_says_nothing():
    got = account_node(r"""
const reasons = ['passkeys_turned_off', 'passkeys_at_another_address', 'passkeys_no_longer_accepted',
                 'passkeys_without_verification', 'something_new'];
const said = {};
for (const owner of [true, false]) {
    said[owner ? 'owner' : 'administrator'] = reasons.map((why) =>
        _passkeyStateText(KEY('k', { usable: false, not_usable_because: why, algorithm: 'RS256' }), owner));
}
said.usable = [true, false].map((owner) => _passkeyStateText(KEY('k'), owner));
out(said);
""")
    owner, admin = got["owner"], got["administrator"]
    assert owner[0] == {"text": "Passkeys are turned off on this vault: it counts again if they are turned back on.",
                        "cls": "text-warning text-xs passkey-not-usable"}
    assert admin[0] == {"text": "Not usable: passkeys are turned off on this vault.",
                        "cls": "text-warning text-xs passkey-not-usable"}
    assert [a["text"] for a in admin[1:4]] == [
        "Not usable: it was made at another address than this vault has now.",
        "Not usable: its signature algorithm (RS256) is no longer accepted here.",
        "Not usable: it has never checked the person with a PIN, fingerprint or face, and this vault asks for that."]
    assert owner[4] is None and admin[4] is None
    assert got["usable"] == [None, None]
