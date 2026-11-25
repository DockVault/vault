"""The Settings pages under SETTINGS_LOCKED_KEYS, driven in Node against the shipped scripts on the small document of
tests/js/mini_dom.js.

Settings -> Sign-in (static/js/settings-signin.js) shows a locked passkey setting read-only, and says where its value
comes from: a setting a .env line sets is set by the provider; one no line sets keeps its default.
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
