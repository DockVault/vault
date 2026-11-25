"""Why a sign-in sets a second factor up again (static/js/app.js, beginSecondFactor and _SET_UP_AGAIN).

A sign-in held for a set-up carries ``set_up_again`` when the account holds passkeys of which none can be used: the
reasons of app/core/webauthn_settings.py, why_none_can_be_used. The card says why in words for each of them, so an
account whose passkeys stopped counting knows what happened to them; a reason the page does not know says nothing.

The page's own function runs in Node on the small document of tests/js/mini_dom.js; what it hands to the set-up it
opens is recorded.
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
SETTINGS = ROOT / "app" / "core" / "webauthn_settings.py"

WHY = {
    "passkeys_at_another_address": "Your passkeys cannot be used at the address this vault has now, so you set a "
                                   "second factor up again here.",
    "passkeys_no_longer_accepted": "Your passkeys are of a kind this vault no longer accepts, so you set a second "
                                   "factor up again here.",
    "passkeys_without_verification": "Your passkeys that work here have never checked a PIN, a fingerprint or a "
                                     "face, which this vault now asks for, so you set a second factor up again here.",
    "passkeys_turned_off": "Passkeys are turned off on this vault, so you set a second factor up again here. Your "
                           "passkeys are kept, and count again if passkeys are turned back on.",
}


def _function(js, name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", js)
    if not found:
        return ""
    start = found.start() + 1
    return js[start:js.index("\n}\n", start) + 3]


def _words(js):
    """The page's table of reasons, as shipped, or "" when there is none."""
    found = re.search(r"\nconst _SET_UP_AGAIN = \{\n.*?\n\};\n", js, re.S)
    return found.group(0) if found else ""


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const form = document.createElement('form'); form.id = 'login-form'; form.reset = () => {};
document.body.appendChild(form);
const password = document.createElement('input'); password.id = 'password'; password.value = 'pw';
form.appendChild(password);
const box = document.createElement('div'); box.id = 'login-second-factor'; document.body.appendChild(box);
function _sfBox() { return document.getElementById('login-second-factor'); }
global.Passkeys = { supported: () => true };
// The set-up each answer opens, and what it was told.
const opened = [];
function renderPasskeyEnrollment(_box, opts) { opened.push(['passkey', opts.why]); }
function renderEnrollmentWizard(_box, opts) { opened.push(['authenticator', opts.why]); }
function renderVerifyCard(_box, opts) { opened.push(['verify', null]); }
const out = (value) => console.log(JSON.stringify(value));
"""


def sign_in_node(scenario: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    script = (PRELUDE + _words(js) + _function(js, "beginSecondFactor")
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_each_reason_the_server_gives_is_said_in_words_and_an_unknown_one_says_nothing():
    """Passkeys turned off: the server offers no passkey to make, so the authenticator app is what is set up, and
    the reason goes with it. The other reasons go with the passkey the server offers."""
    got = sign_in_node(r"""
const reasons = REASONS;
for (const why of reasons) {
    beginSecondFactor({ pre_auth_token: 'held-1', enrollment_required: true, set_up_again: why,
                        enrollment_methods: why === 'passkeys_turned_off' ? ['totp'] : ['passkey'] });
}
for (const why of [undefined, null, 'something_new', 'toString', 'constructor', '__proto__']) {
    beginSecondFactor({ pre_auth_token: 'held-1', enrollment_required: true, set_up_again: why,
                        enrollment_methods: ['totp'] });
}
out(opened);
""".replace("REASONS", json.dumps(list(WHY))))
    assert got[:len(WHY)] == [["authenticator" if why == "passkeys_turned_off" else "passkey", words]
                              for why, words in WHY.items()], got
    assert got[len(WHY):] == [["authenticator", ""]] * 6, got


def test_every_reason_the_server_can_give_has_its_words_on_the_page():
    """The reasons are the PASSKEYS_* values of app/core/webauthn_settings.py; each is a key of the page's table, and
    the table holds nothing else."""
    reasons = set(re.findall(r'^PASSKEYS_[A-Z_]+ = "([a-z_]+)"$', SETTINGS.read_text(encoding="utf-8"), re.M))
    assert reasons == set(WHY)
    table = _words(APP_JS.read_text(encoding="utf-8"))
    assert table, "app.js has no _SET_UP_AGAIN table"
    keys = set(re.findall(r"^    ([a-z_]+): ", table, re.M))
    assert keys == reasons, (keys, reasons)
