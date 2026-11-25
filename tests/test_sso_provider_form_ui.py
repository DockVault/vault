"""The pages of a single sign-on provider's dialog that hold its settings, in Settings, Sign-in
(static/js/settings-sso.js): what the help beside a field says, and what a page's Save sends.

Driven in Node against the shipped module, on the small document of tests/js/mini_dom.js, by the clicks a person
makes: open the provider, open one of its pages, change a field, press Save.
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
PAGE = ROOT / "static" / "js" / "settings-sso.js"
INDEX = ROOT / "static" / "index.html"

PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
// A textarea's rows is its height in lines (the small document knows only a table's rows).
const tableRows = Object.getOwnPropertyDescriptor(dom.Element.prototype, 'rows');
Object.defineProperty(dom.Element.prototype, 'rows', { configurable: true,
    get() { return this.localName === 'textarea' ? this._lines : tableRows.get.call(this); },
    set(value) { this._lines = value; } });
for (const id of ['signin-sso-providers', 'signin-sso-address', 'sso-provider-modal']) {
    const el = document.createElement('div'); el.id = id; document.body.appendChild(el);
}
for (const id of ['sso-provider-title', 'sso-provider-body']) {
    const el = document.createElement('div'); el.id = id; document.getElementById('sso-provider-modal').appendChild(el);
}
const add = document.createElement('button'); add.id = 'signin-sso-add'; document.body.appendChild(add);
global.location = { origin: 'https://vault.example.test' };
var currentUser = { id: 'root-id', username: 'root', role: 'admin' };
const asked = [], toasts = [];
let answers = {};
const PROVIDER = { id: 'p-1', name: 'contoso', label: 'Contoso', state: 'disabled', configured: true, tested: true,
                   identities: 0, issuer: 'https://login.example.test', policy: {}, claims: {}, addresses: null,
                   last_test: null, sso_only_accounts: 0, only_way_in_accounts: 0, icon: 'generic', sort_order: 0,
                   show_on_sign_in: true, scopes: 'openid', token_auth: 'client_secret_basic', group_mappings: 0 };
answers['/admin/sso/providers'] = { providers: [PROVIDER], presets: [], icons: ['generic'], limit: 20,
                                    address: { usable: true, base: 'https://vault.example.test' } };
answers['/admin/sso/providers/p-1'] = { provider: PROVIDER };
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET', body: (options || {}).body });
    const answer = Object.prototype.hasOwnProperty.call(answers, path) ? answers[path] : new Error('Not arranged: ' + path);
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer() : answer;
};
global.openModal = () => {};
global.closeModal = () => {};
global.showToast = (message, kind) => { toasts.push([message, kind]); };
global.showConfirm = async () => true;
global._el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const byId = (id) => document.getElementById(id);
// The help under a field: the paragraph that follows it in its form group.
const helpOf = (id) => {
    const group = byId(id).closest('.form-group');
    const help = group.querySelectorAll('p');
    return help.length ? help[help.length - 1].textContent : null;
};
const out = (value) => console.log(JSON.stringify(value));
async function openPage(name) {
    await window.SsoSettings.load();
    document.querySelector('.sso-provider-row button').click();
    await tick(); await tick();
    if (name !== 'connection') { byId('sso-tab-' + name).click(); await tick(); }
}
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (PRELUDE + PAGE.read_text(encoding="utf-8") + "\n(async () => {\n" + scenario
              + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_sign_up_domain_tick_says_what_each_mode_of_the_list_does():
    """The tick holds people to the sign-up domain list of the Accounts & Access page, named as that page names it:
    an allow-list admits only its domains and is what opens accounts made at a first sign-in and the link by email;
    a deny-list keeps its domains out and opens neither; either way a person whose domain the provider does not
    vouch for is kept out; set to Off, the tick does nothing."""
    got = _node(r"""
await openPage('access');
out({ help: helpOf('sso-signup-domains'), intro: byId('sso-page-access').children[0].textContent });
""")
    help_ = got["help"]
    setting = re.search(r'<label for="setting-signup-domain-mode">([^<]+)</label>',
                        INDEX.read_text(encoding="utf-8")).group(1)
    assert help_.startswith(f"The {setting} on the Accounts & Access page, when it is on.")
    assert "An allow-list admits only its domains" in help_
    assert "a deny-list keeps its domains out and does not count" in help_
    assert "(no verified address, or at a provider with an organisation-domain claim, no such claim) is kept out" in help_
    assert help_.endswith("Set to Off there, this does nothing.")
    # The page's first lines count the tick among what says who may sign in.
    assert got["intro"] == ("Who may sign in through this provider. With none of the three lists, and the sign-up "
                            "domain list not held to below, anyone the provider signs in may try; accounts are then "
                            "made only by invitation.")


def test_the_page_names_the_accounts_and_access_page_as_the_settings_show_it():
    """The Settings tab is "Accounts & Access": no help on these pages sends anyone to an "Accounts page"."""
    source = PAGE.read_text(encoding="utf-8")
    assert "the Accounts page" not in source and "Accounts & Access" in source
