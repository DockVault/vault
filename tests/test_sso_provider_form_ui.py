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
// The policy as the server shows it: every setting, at its default (app/core/sso_policy.py, DEFAULTS).
const POLICY = { sso_account_creation: 'invite_only', sso_default_role: 'user', sso_password_login: 'allowed',
                 sso_link_by_email: false, sso_admin_mapping: false, sso_use_signup_domains: false,
                 sso_backchannel_logout: true, sso_idp_logout: false, sso_trust_idp_mfa: false, sso_accepted_amr: [],
                 sso_accepted_acr: [], sso_requested_acr: '', sso_allowed_tenants: [], sso_allowed_domains: [],
                 sso_required_groups: [], sso_freshness_days: 30, sso_refusal_ends_access: true,
                 sso_jit_password: false, sso_lapse_ends_sign_in: true };
const PROVIDER = { id: 'p-1', name: 'contoso', label: 'Contoso', state: 'disabled', configured: true, tested: true,
                   identities: 0, issuer: 'https://login.example.test', policy: POLICY, claims: {}, addresses: null,
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


SAVE_ECHOES = r"""
// The server keeps what a save sends and answers with the provider as it now stands.
answers['/admin/sso/providers/p-1'] = () => {
    const last = asked[asked.length - 1];
    if (last.method === 'PATCH') {
        const sent = JSON.parse(last.body);
        PROVIDER.policy = Object.assign({}, PROVIDER.policy, sent.policy || {});
        return { provider: PROVIDER };
    }
    return { provider: PROVIDER };
};
const patches = () => asked.filter((a) => a.method === 'PATCH').map((a) => JSON.parse(a.body));
"""

DN_GROUP = "CN=Vault Users,OU=Groups,DC=example,DC=org"


def test_a_required_group_whose_name_holds_a_comma_is_saved_whole():
    """Groups are one on each line: a comma is part of a group's name (a distinguished name has several), and the
    group is matched letter for letter, so it is never cut at a comma."""
    got = _node(SAVE_ECHOES + r"""
await openPage('access');
const help = helpOf('sso-groups');
byId('sso-groups').value = %s + '\nFinance';
byId('sso-save').click();
await tick(); await tick();
out({ help, sent: patches(), shown: byId('sso-groups').value.split('\n') });
""" % json.dumps(DN_GROUP))
    assert got["help"] == ("A person must be in at least one of these groups. One on each line, written as the "
                           "provider sends it: a comma is part of the name.")
    assert got["sent"] == [{"policy": {"sso_required_groups": [DN_GROUP, "Finance"]}}]
    assert got["shown"] == [DN_GROUP, "Finance"]          # the page drawn again after the save: two lines


def test_a_stored_group_with_a_comma_is_left_alone_by_a_save_of_another_field():
    got = _node(SAVE_ECHOES + r"""
PROVIDER.policy = Object.assign({}, POLICY, { sso_required_groups: [%s, 'Finance'] });
await openPage('access');
byId('sso-tenants').value = 't-1';
byId('sso-save').click();
await tick(); await tick();
out(patches());
""" % json.dumps(DN_GROUP))
    assert got == [{"policy": {"sso_allowed_tenants": ["t-1"]}}]


def test_a_provider_without_a_button_is_still_linked_under_your_account():
    """The sign-in page's button is about the sign-in page only: a person still links the provider under Your
    account, which offers every provider that can be linked."""
    got = _node(r"""
await openPage('connection');
out(helpOf('sso-show'));
""")
    assert got == "Without the button, people use the sign-in link above, or link it under Your account."


def test_the_name_is_for_administrators_and_the_button_text_is_what_people_see():
    """People see the button text: on the sign-in page's button, and as the provider's name in their notices and
    emails. The name is the administrators': this list, their notices, the records."""
    got = _node(r"""
await openPage('connection');
const form = { name: helpOf('sso-name'), label: helpOf('sso-label') };
document.listeners.click.forEach((f) => f({ target: byId('signin-sso-add') }));
await tick();
out(Object.assign(form, { adding: helpOf('sso-new-name') }));
""")
    assert got["name"] == "For administrators: in this list, in their notices and in the records."
    assert got["label"] == ("What people see: the sign-in page's button, under “Sign in with your organisation”, and "
                            "the name in their notices and emails. Write the name people know, such as Contoso. "
                            "Empty: the name.")
    assert "notices and emails" in got["label"]
    assert got["adding"] == "For administrators. People see the button text, which you can set after adding."
