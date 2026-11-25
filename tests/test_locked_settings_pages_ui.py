"""The Settings pages under SETTINGS_LOCKED_KEYS, driven in Node against the shipped scripts on the small document of
tests/js/mini_dom.js.

Settings -> Sign-in (static/js/settings-signin.js) shows a locked passkey setting read-only, and says where its value
comes from: a setting a .env line sets is set by the provider; one no line sets keeps its default.

The levels (static/js/settings-levels.js) take a locked setting out of its place and list it, with its value and
reason, under "Set by your provider (N)" at the foot of its page. A container marked data-setting-shows-lock (the
single sign-on card, whose own page shows the lock and stays readable) stays where it is, is listed all the same,
and counts neither as an essential setting nor as an advanced one.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
SIGN_IN = ROOT / "static" / "js" / "settings-signin.js"
LEVELS = ROOT / "static" / "js" / "settings-levels.js"

PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
global.location = { origin: 'https://vault.example.test' };
var currentUser = { id: 'root-id', username: 'root', role: 'admin' };
let answers = {};
global.apiRequest = async (path) => {
    if (!Object.prototype.hasOwnProperty.call(answers, path)) throw new Error('Not arranged: ' + path);
    return answers[path];
};
global.showToast = () => {};
const byId = (id) => document.getElementById(id);
const out = (value) => console.log(JSON.stringify(value));
"""


def _node(script_path, setup, scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (PRELUDE + setup + "\n" + script_path.read_text(encoding="utf-8") + "\n(async () => {\n" + scenario
              + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _row(key, kind, value, env, **more):
    row = {"key": key, "label": key, "help": "", "kind": kind, "value": value, "choices": [], "min": None,
           "max": None, "unit": None, "stored": None, "locked": True, "source": "locked", "env": env}
    row.update(more)
    return row


def test_a_locked_passkey_setting_says_whether_the_provider_set_it_or_it_keeps_its_default():
    rows = [_row("webauthn_mode", "enum", "off", "WEBAUTHN_MODE", choices=["off", "optional", "required_for_roles"]),
            _row("webauthn_attestation", "enum", "none", None, choices=["none", "direct"])]
    got = _node(SIGN_IN, r"""
const box = document.createElement('div'); box.id = 'signin-passkey-settings'; document.body.appendChild(box);
""", r"""
answers['/settings/sign-in'] = { settings: %s, readiness: { usable: true, origin: location.origin } };
await window.SignInSettings.load();
out(document.querySelectorAll('.signin-setting').map((item) => ({
    key: item.dataset.setting, said: item.querySelector('.signin-setting-said').textContent,
    disabled: item.querySelectorAll('input, select, textarea, button').every((n) => n.disabled === true) })));
""" % json.dumps(rows))
    assert got == [
        {"key": "webauthn_mode", "said": "Set by your provider.", "disabled": True},
        {"key": "webauthn_attestation", "said": "Kept at its default by your provider (locked): it cannot be changed "
                                                "here.", "disabled": True},
    ]


# The small document knows no [id^="..."] selector and no Element.after: every page here is a settings-tab-* page,
# so the prefix test is left out, and after() is placed by the small document's own insertBefore.
_LEVELS_SETUP = r"""
const PREFIX = '[id^="settings-tab-"]';
const plain = (sel) => sel.split(PREFIX).join('');
for (const proto of [dom.Element.prototype, dom.Document.prototype]) {
    const all = proto.querySelectorAll;
    proto.querySelectorAll = function (sel) { return all.call(this, plain(sel)); };
    proto.querySelector = function (sel) { return this.querySelectorAll(sel)[0] || null; };
}
const matches = dom.Element.prototype.matches;
dom.Element.prototype.matches = function (sel) { return matches.call(this, plain(sel)); };
dom.Element.prototype.after = function (node) { this.parentNode.insertBefore(node, this.nextSibling()); };
global.requestAnimationFrame = (fn) => setTimeout(fn, 0);
const section = document.createElement('div');
section.id = 'settings-section'; section.className = 'active';
document.body.appendChild(section);
const signin = document.createElement('div');
signin.id = 'settings-tab-signin'; signin.className = 'settings-tab-content';
section.appendChild(signin);
function card(key, title, showsLock) {
    const node = document.createElement('div');
    node.className = 'card'; node.dataset.setting = key;
    if (showsLock) node.setAttribute('data-setting-shows-lock', '');
    const head = document.createElement('div'); head.className = 'card-header';
    const h3 = document.createElement('h3'); h3.textContent = title;
    head.appendChild(h3); node.appendChild(head);
    signin.appendChild(node);
    return node;
}
const sso = card('sso', 'Single sign-on', true);
const mode = card('webauthn_mode', 'Passkeys', false);
const algs = card('webauthn_allowed_algs', 'Signature algorithms', false);
"""


def test_a_locked_card_that_shows_its_own_lock_stays_listed_and_uncounted():
    catalogue = {"entries": [
        {"key": "sso", "kind": "group", "page": "signin", "level": "essential", "since": "0.36.0", "new": False,
         "label": "Single sign-on providers", "help": "", "locked": True,
         "value": "The providers are kept as they are.", "reason": "Locked in the deployment."},
        {"key": "webauthn_mode", "kind": "setting", "page": "signin", "level": "essential", "since": "0.36.0",
         "new": False, "label": "Passkeys", "help": "", "locked": True, "value": "off",
         "reason": "Set by your provider."},
        {"key": "webauthn_allowed_algs", "kind": "setting", "page": "signin", "level": "advanced", "since": "0.36.0",
         "new": False, "label": "Signature algorithms", "help": "", "locked": False},
    ]}
    # The catalogue is there before the script starts: opening Settings reads it at once.
    got = _node(LEVELS, _LEVELS_SETUP + "answers['/settings/catalogue'] = %s;" % json.dumps(catalogue), r"""
await window.SettingsLevels.load();
const fold = signin.querySelector(':scope > .settings-provider-fold');
const bar = signin.querySelector(':scope > .settings-level-bar');
out({ sso: sso.className, mode: mode.className, algs: algs.className,
      summary: fold.querySelector('summary').textContent, hidden: fold.hidden,
      listed: fold.querySelectorAll('.settings-provider-item').map((item) => [item.dataset.foldKey,
          item.querySelector('strong').textContent]),
      toggle: bar.querySelector('.settings-advanced-toggle').textContent,
      allAdvanced: !bar.querySelector('.settings-level-note').hidden });
""")
    # The single sign-on card stays in its place; the other locked setting leaves for the list.
    assert "setting-folded" not in got["sso"].split() and "setting-level-hidden" not in got["sso"].split()
    assert "setting-folded" in got["mode"].split()
    assert got["hidden"] is False and got["summary"] == "Set by your provider (2)"
    assert got["listed"] == [["sso", "Single sign-on providers"], ["webauthn_mode", "Passkeys"]]
    # Neither locked one is counted: the page's one counted setting is advanced, and the page says so.
    assert got["toggle"] == "Show advanced settings (1)" and got["allAdvanced"] is True
