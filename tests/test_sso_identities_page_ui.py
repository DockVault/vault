"""The Identities page of a provider in Settings, Sign-in (static/js/settings-sso.js): the provider's dialog has a page
that lists the accounts linked to it, from GET /admin/sso/providers/{id}/identities, with where each stands and the
dates the vault keeps; says on the page what a refusal and a hold are and how each is lifted; offers "Lift refusal"
(POST /admin/sso/identities/{id}/clear-refusal) for a refused or held account that is not the administrator's own,
after a confirmation that says what lifting does; reads the list again afterwards; and pages through a long list.

Driven in Node against the shipped module, on the small document of tests/js/mini_dom.js, by the clicks a person
makes: open the provider, open its Identities page.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
PAGE = ROOT / "static" / "js" / "settings-sso.js"

PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
for (const id of ['signin-sso-providers', 'signin-sso-address', 'sso-provider-modal']) {
    const el = document.createElement('div'); el.id = id; document.body.appendChild(el);
}
for (const id of ['sso-provider-title', 'sso-provider-body']) {
    const el = document.createElement('div'); el.id = id; document.getElementById('sso-provider-modal').appendChild(el);
}
const add = document.createElement('button'); add.id = 'signin-sso-add'; document.body.appendChild(add);
global.location = { origin: 'https://vault.example.test' };
var currentUser = { id: 'root-id', username: 'root', role: 'admin' };
const asked = [], toasts = [], confirms = [];
let answers = {};
let confirmAnswer = true;
const PROVIDER = { id: 'p-1', name: 'contoso', label: 'Contoso', state: 'enabled', configured: true, tested: true,
                   identities: 3, issuer: 'https://login.example.test', policy: {}, claims: {}, addresses: null,
                   last_test: null, sso_only_accounts: 0, only_way_in_accounts: 0, icon: 'generic', sort_order: 0,
                   show_on_sign_in: true, scopes: 'openid', token_auth: 'client_secret_basic' };
answers['/admin/sso/providers'] = { providers: [PROVIDER], presets: [], icons: ['generic'], limit: 20,
                                    address: { usable: true, base: 'https://vault.example.test' } };
answers['/admin/sso/providers/p-1'] = { provider: PROVIDER };
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET' });
    const answer = Object.prototype.hasOwnProperty.call(answers, path) ? answers[path] : new Error('Not arranged: ' + path);
    if (answer instanceof Error) throw answer;
    return typeof answer === 'function' ? answer() : answer;
};
global.openModal = () => {};
global.closeModal = () => {};
global.showToast = (message, kind) => { toasts.push([message, kind]); };
global.showConfirm = async (message, title, input, label) => { confirms.push([message, title, label]); return confirmAnswer; };
global._el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
};
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const byId = (id) => document.getElementById(id);
const rows = () => document.querySelectorAll('.sso-identity-row').map((row) => ({
    id: row.dataset.identity,
    name: row.children[0].children[0].childNodes[0].textContent,
    state: row.querySelector('.sso-identity-state').textContent,
    bits: row.children[0].children[1].textContent,
    action: row.children.length > 1 ? row.children[1].textContent : null,
}));
const out = (value) => console.log(JSON.stringify(value));
const IDS = '/admin/sso/providers/p-1/identities?skip=0&limit=50';
const LIST = { provider_id: 'p-1', total: 3, skip: 0, limit: 50, counts: { refused: 2, lapsed: 1, linked: 0 },
    identities: [
        { id: 'i-carol', user_id: 'u-carol', username: 'carol', linked_by: 'self', linked_at: '2026-09-01T10:00:00Z',
          last_sign_in_at: '2026-10-01T10:00:00Z', state: 'refused', refused_at: '2026-10-20T10:00:00Z',
          due_at: '2026-10-31T10:00:00Z', holds_sign_in: true, own: false },
        { id: 'i-root', user_id: 'root-id', username: 'root', linked_by: 'self', linked_at: '2026-09-01T10:00:00Z',
          last_sign_in_at: null, state: 'refused', refused_at: '2026-10-20T10:00:00Z', due_at: null,
          holds_sign_in: false, own: true },
        { id: 'i-bob', user_id: 'u-bob', username: 'bob', linked_by: 'email', linked_at: '2026-08-01T10:00:00Z',
          last_sign_in_at: '2026-08-02T10:00:00Z', state: 'lapsed', refused_at: null,
          due_at: '2026-09-01T10:00:00Z', holds_sign_in: true, own: false }] };
async function openIdentities() {
    await window.SsoSettings.load();
    document.querySelector('.sso-provider-row button').click();
    await tick(); await tick();
    byId('sso-tab-identities').click();
    await tick(); await tick();
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


def test_the_provider_dialog_has_an_identities_page_that_lists_where_each_account_stands():
    got = _node(r"""
answers[IDS] = LIST;
await openIdentities();
out({ tab: byId('sso-tab-identities').textContent, selected: byId('sso-tab-identities').getAttribute('aria-selected'),
      panel: byId('sso-page-identities') !== null, about: byId('sso-identities-about').textContent,
      counts: byId('sso-identities-counts').textContent, rows: rows(), read: asked.filter((a) => a.path === IDS).length });
""")
    assert got["tab"] == "Identities" and got["selected"] == "true" and got["panel"] is True
    assert got["read"] == 1
    # What a refusal and a hold are, that the vault keeps only the date, and how each is lifted, said on the page.
    about = got["about"]
    assert "the provider refused the person when they last signed in there" in about
    assert "turned off or was to be removed" in about and "The vault keeps the date of either" in about
    assert "a sign-in the provider admits lifts it, or you lift it here" in about
    assert "Days run out: only a sign-in through the provider ends that." in about
    assert got["counts"] == "3 linked accounts: 2 refused or held, 1 with their days run out."
    carol, root, bob = got["rows"]
    assert carol["name"] == "carol" and carol["state"] == "Refused or held" and carol["action"] == "Lift refusal"
    assert carol["bits"].startswith("Account u-carol · Linked by its owner on ")
    assert "refused or held since " in carol["bits"] and "its password and passkeys do not sign it in now" in carol["bits"]
    # The administrator's own refusal is another administrator's to lift.
    assert root["state"] == "Refused or held" and root["action"] == "Your own: another administrator lifts it."
    assert "never signed in through it" in root["bits"]
    # Days run out: nothing to lift here.
    assert bob["state"] == "Days run out" and bob["action"] is None
    assert "Linked by its verified email address" in bob["bits"] and "its days ran out on " in bob["bits"]


def test_lifting_a_refusal_asks_first_says_what_it_does_and_reads_the_list_again():
    got = _node(r"""
answers[IDS] = LIST;
answers['/admin/sso/identities/i-carol/clear-refusal'] = { cleared: true };
await openIdentities();
confirmAnswer = false;
document.querySelector('.sso-identity-row button').click();
await tick(); await tick();
const declined = asked.filter((a) => a.method === 'POST').length;
confirmAnswer = true;
answers[IDS] = Object.assign({}, LIST, { counts: { refused: 1, lapsed: 1, linked: 1 }, identities: [
    Object.assign({}, LIST.identities[0], { state: 'linked', refused_at: null, holds_sign_in: false }),
    LIST.identities[1], LIST.identities[2]] });
document.querySelector('.sso-identity-row button').click();
await tick(); await tick(); await tick();
out({ declined, confirm: confirms[0], posts: asked.filter((a) => a.method === 'POST').map((a) => a.path),
      reads: asked.filter((a) => a.path === IDS).length, toasts, rows: rows().map((r) => [r.name, r.state, r.action]),
      providersRead: asked.filter((a) => a.path === '/admin/sso/providers').length });
""")
    assert got["declined"] == 0                              # nothing is sent before the person says yes
    message, title, label = got["confirm"]
    assert title == "Lift refusal" and label == "Lift refusal"
    assert message.startswith("Lift the refusal or hold on carol? Their SSH keys, temporary credentials and devices "
                              "work again, unless another rule pauses them")
    assert got["posts"] == ["/admin/sso/identities/i-carol/clear-refusal"]
    assert got["toasts"] == [["The refusal on carol was lifted.", "success"]]
    assert got["reads"] == 2 and got["providersRead"] == 2   # the list, and the card's counts, read again
    assert got["rows"][0] == ["carol", "Linked", None]


def test_a_lift_the_server_refuses_says_why_and_still_reads_the_list_again():
    got = _node(r"""
answers[IDS] = LIST;
answers['/admin/sso/identities/i-carol/clear-refusal'] = new Error('No refusal holds this identity.');
await openIdentities();
document.querySelector('.sso-identity-row button').click();
await tick(); await tick(); await tick();
out({ toasts, reads: asked.filter((a) => a.path === IDS).length });
""")
    assert got == {"toasts": [["No refusal holds this identity.", "error"]], "reads": 2}


def test_a_long_list_is_paged_and_an_empty_one_says_so():
    got = _node(r"""
const page = (skip, count, total) => ({ provider_id: 'p-1', total, skip, limit: 50, counts: { refused: 0, lapsed: 0, linked: total },
    identities: Array.from({ length: count }, (_, i) => ({ id: 'i-' + (skip + i), user_id: 'u-' + (skip + i),
        username: 'user' + (skip + i), linked_by: 'self', linked_at: null, last_sign_in_at: null, state: 'linked',
        refused_at: null, due_at: null, holds_sign_in: false, own: false })) });
answers[IDS] = page(0, 50, 70);
answers['/admin/sso/providers/p-1/identities?skip=50&limit=50'] = page(50, 20, 70);
await openIdentities();
const pager = () => document.querySelector('.sso-identities-pager');
const first = { rows: rows().length, said: pager().children[1].textContent, prev: pager().children[0].disabled,
                next: pager().children[2].disabled };
pager().children[2].click();
await tick(); await tick();
const second = { rows: rows().length, said: pager().children[1].textContent, prev: pager().children[0].disabled,
                 next: pager().children[2].disabled, first: rows()[0].name };
answers[IDS] = page(0, 0, 0);
pager().children[0].click();
await tick(); await tick();
out({ first, second, empty: byId('sso-identities').textContent, pager: pager() === null });
""")
    assert got["first"] == {"rows": 50, "said": "1 to 50 of 70", "prev": True, "next": False}
    assert got["second"] == {"rows": 20, "said": "51 to 70 of 70", "prev": False, "next": True, "first": "user50"}
    assert got["empty"] == "0 linked accountsNo account is linked to this provider." and got["pager"] is True


def test_an_answer_for_a_page_no_longer_shown_draws_nothing():
    got = _node(r"""
let release;
answers[IDS] = () => new Promise((resolve) => { release = () => resolve(LIST); });
await window.SsoSettings.load();
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
byId('sso-tab-identities').click();
await tick();
byId('sso-tab-connection').click();          // the person moved on before the list came
await tick();
release();
await tick(); await tick();
out({ rows: rows().length, identities: byId('sso-identities') === null, connection: byId('sso-page-connection') !== null });
""")
    assert got == {"rows": 0, "identities": True, "connection": True}
