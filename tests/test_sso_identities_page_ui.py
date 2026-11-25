"""The Identities page of a provider in Settings, Sign-in (static/js/settings-sso.js): the provider's dialog has a page
that lists the accounts linked to it, from GET /admin/sso/providers/{id}/identities, with where each stands and the
dates the vault keeps; says on the page what a refusal and a hold are and how each is lifted; offers "Lift refusal"
(POST /admin/sso/identities/{id}/clear-refusal) for a refused or held account that is not the administrator's own,
after a confirmation that says what lifting does; offers "Unlink" (DELETE /admin/sso/identities/{id}) for every
account that is not the administrator's own, after a confirmation that says what the unlink ends; reads the list
again after either; and pages through a long list.

The card and the dialog under SETTINGS_LOCKED_KEYS: they say so in the server's words and offer nothing that would
change a provider, while what only reads or tests stays. Each provider's Open button names the provider it opens.

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
// The page's clock, frozen: a date the list gives is before or after it whatever day the test runs on.
const NOW = Date.parse('2026-10-25T10:00:00Z');
Date.now = () => NOW;
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
    asked.push({ path, method: (options || {}).method || 'GET', body: (options || {}).body });
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
    actions: row.children.slice(1).map((node) => node.textContent),
}));
const out = (value) => console.log(JSON.stringify(value));
const IDS = '/admin/sso/providers/p-1/identities?skip=0&limit=50';
const LIST = { provider_id: 'p-1', total: 3, skip: 0, limit: 50, counts: { refused: 2, lapsed: 1, linked: 0 },
    identities: [
        { id: 'i-carol', user_id: 'u-carol', username: 'carol', linked_by: 'self', linked_at: '2026-09-01T10:00:00Z',
          last_sign_in_at: '2026-10-01T10:00:00Z', state: 'refused', refused_at: '2026-10-20T10:00:00Z',
          due_at: '2026-10-31T10:00:00Z', holds_sign_in: true, own: false,
          after_lift: { state: 'linked', holds_sign_in: false } },
        { id: 'i-root', user_id: 'root-id', username: 'root', linked_by: 'self', linked_at: '2026-09-01T10:00:00Z',
          last_sign_in_at: null, state: 'refused', refused_at: '2026-10-20T10:00:00Z', due_at: null,
          holds_sign_in: false, own: true, after_lift: { state: 'linked', holds_sign_in: false } },
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
    assert "Days run out: only a sign-in through the provider ends that, or you unlink the account here." in about
    assert got["counts"] == "3 linked accounts: 2 refused or held, 1 with their days run out."
    carol, root, bob = got["rows"]
    assert carol["name"] == "carol" and carol["state"] == "Refused or held"
    assert carol["actions"] == ["Lift refusal", "Unlink"]
    assert carol["bits"].startswith("Account u-carol · Linked by its owner on ")
    assert "refused or held since " in carol["bits"] and "its password and passkeys do not sign it in now" in carol["bits"]
    assert "its days run out on " in carol["bits"] and "ran out" not in carol["bits"]      # still to come
    # The administrator's own refusal is another administrator's to lift or unlink.
    assert root["state"] == "Refused or held" and root["actions"] == ["Your own: another administrator lifts or unlinks it."]
    assert "never signed in through it" in root["bits"]
    # Days run out: nothing to lift here, and the account can be unlinked.
    assert bob["state"] == "Days run out" and bob["actions"] == ["Unlink"]
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
      reads: asked.filter((a) => a.path === IDS).length, toasts, rows: rows().map((r) => [r.name, r.state, r.actions]),
      providersRead: asked.filter((a) => a.path === '/admin/sso/providers').length });
""")
    assert got["declined"] == 0                              # nothing is sent before the person says yes
    message, title, label = got["confirm"]
    assert title == "Lift refusal" and label == "Lift refusal"
    assert message == ("Lift the refusal or hold on carol? Their SSH keys, temporary credentials and devices work "
                       "again, unless another rule pauses them. Their password and passkeys sign them in again. They "
                       "and the other administrators are told. Lift it when the refusal was a mistake the provider "
                       "cannot answer.")
    assert got["posts"] == ["/admin/sso/identities/i-carol/clear-refusal"]
    assert got["toasts"] == [["The refusal on carol was lifted.", "success"]]
    assert got["reads"] == 2 and got["providersRead"] == 2   # the list, and the card's counts, read again
    assert got["rows"][0] == ["carol", "Linked", ["Unlink"]]


@pytest.mark.parametrize("case", ["provider on", "provider off", "keys only"])
def test_a_hold_whose_days_ran_out_says_so_in_the_past_and_its_lift_says_the_keys_stay_paused(case):
    """A hold the vault wrote when the provider was turned off, after the person's days there had run out: the row
    says the days ran out (in the past, whatever the state), and the confirmation says what the lift gives as the
    server says it: the keys stay paused until the person signs in through the provider; their password back while
    the provider is off, and nothing they can do while it is on. Nobody can sign in through a provider that is off:
    there the confirmation says so, and what ends the pause instead. Where the provider's days pause the keys only,
    the password signed the person in all along, and the confirmation does not say it comes back."""
    holds_now, holds_after = {"provider on": (True, True), "provider off": (True, False),
                              "keys only": (False, False)}[case]
    got = _node(r"""
PROVIDER.state = %s;
const held = { id: 'i-bob', user_id: 'u-bob', username: 'bob', linked_by: 'email', linked_at: '2026-08-01T10:00:00Z',
    last_sign_in_at: '2026-08-02T10:00:00Z', state: 'refused', refused_at: '2026-10-20T10:00:00Z',
    due_at: '2026-09-01T10:00:00Z', holds_sign_in: %s, own: false,
    after_lift: { state: 'lapsed', holds_sign_in: %s } };
answers[IDS] = { provider_id: 'p-1', total: 1, skip: 0, limit: 50, counts: { refused: 1, lapsed: 0, linked: 0 },
                 identities: [held] };
await openIdentities();
confirmAnswer = false;
document.querySelector('.sso-identity-row button').click();
await tick(); await tick();
out({ row: rows()[0], confirm: confirms[0][0] });
""" % (json.dumps("disabled" if case == "provider off" else "enabled"), json.dumps(holds_now), json.dumps(holds_after)))
    row = got["row"]
    assert row["state"] == "Refused or held" and row["actions"] == ["Lift refusal", "Unlink"]
    assert "refused or held since " in row["bits"] and "its days ran out on " in row["bits"]
    assert "run out on" not in row["bits"]
    start = ("Lift the refusal or hold on bob? Their days without a sign-in through this provider have run out all the "
             "same, so their SSH keys, temporary credentials and devices stay paused until they sign in through it")
    if case == "provider on":
        assert got["confirm"] == start + (", and their password and passkeys still do not sign them in: until then, "
                                          "lifting it changes nothing they can do. They and the other administrators "
                                          "are told.")
    elif case == "provider off":
        assert got["confirm"] == start + (", which nobody can while this provider is turned off: turn it on so they "
                                          "can, or unlink the account here, which ends the pause. Their password and "
                                          "passkeys sign them in again. They and the other administrators are told.")
    else:
        assert got["confirm"] == start + ". They and the other administrators are told."
    assert "work again" not in got["confirm"]


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


UNLINK_TAIL = (" If Contoso is what keeps the account from holding a password, it may hold one again, and has none "
               "anybody can type until it sets one. The vault refuses an unlink that would leave the account no way to "
               "sign in, and says what to do first. {name} and the other administrators are told.")


def test_unlinking_an_account_asks_first_says_what_it_ends_and_reads_the_list_again():
    """Unlink (DELETE /admin/sso/identities/{id}) on an account whose days ran out: the confirmation says what the
    unlink ends, that the vault refuses one that leaves no way in, and who is told; the answer's sessions and paused
    keys are said; the list and the card are read again."""
    got = _node(r"""
answers[IDS] = LIST;
answers['/admin/sso/identities/i-bob'] = { removed: true, sessions_ended: 2, held: false, keys_paused: true };
await openIdentities();
const unlink = () => document.querySelector('.sso-identity-row[data-identity="i-bob"] .sso-identity-unlink');
const label = unlink().getAttribute('aria-label');
confirmAnswer = false;
unlink().click();
await tick(); await tick();
const declined = asked.filter((a) => a.method === 'DELETE').length;
confirmAnswer = true;
unlink().click();
await tick(); await tick(); await tick();
out({ label, declined, confirms, deletes: asked.filter((a) => a.method === 'DELETE').map((a) => a.path), toasts,
      reads: asked.filter((a) => a.path === IDS).length,
      providersRead: asked.filter((a) => a.path === '/admin/sso/providers').length });
""")
    assert got["label"] == "Unlink bob from Contoso"
    assert got["declined"] == 0                              # nothing is sent before the person says yes
    message, title, label = got["confirms"][1]
    assert title == "Unlink" and label == "Unlink"
    assert message == ("Unlink bob from Contoso? The account can no longer sign in through Contoso, and its sessions "
                       "that came through Contoso end. Its days without a sign-in through Contoso end with the link."
                       + UNLINK_TAIL.format(name="bob"))
    assert got["deletes"] == ["/admin/sso/identities/i-bob"]
    assert got["toasts"] == [["bob was unlinked from Contoso. 2 session(s) that came through it ended. The pause "
                              "Contoso had on its SSH keys, temporary credentials and devices ended with the link.",
                              "success"]]
    assert got["reads"] == 2 and got["providersRead"] == 2   # the list, and the card's counts, read again


def test_unlinking_says_what_ends_with_a_refusal_and_a_hold_and_that_a_password_may_be_set_again():
    got = _node(r"""
answers[IDS] = LIST;
answers['/admin/sso/identities/i-carol'] = { removed: true, sessions_ended: 0, held: true, keys_paused: false,
                                             may_set_password: true };
await openIdentities();
document.querySelector('.sso-identity-row[data-identity="i-carol"] .sso-identity-unlink').click();
await tick(); await tick(); await tick();
out({ confirm: confirms[0][0], toasts });
""")
    assert got["confirm"] == ("Unlink carol from Contoso? The account can no longer sign in through Contoso, and its "
                              "sessions that came through Contoso end. The refusal or hold Contoso had on it ends with "
                              "the link." + UNLINK_TAIL.format(name="carol"))
    [[told, kind]] = got["toasts"]
    assert kind == "success"
    assert told == ("carol was unlinked from Contoso. Contoso held that account to its own sign-in: the hold ended "
                    "with the link. The account may hold a password again: it has none anybody can type until it sets "
                    "one. You can make it a reset link on the Users page.")
    # The sign-in page's own reset is off by default: the account is not sent there.
    assert "sign-in page" not in told


def test_an_unlink_the_server_refuses_says_why_and_still_reads_the_list_again():
    got = _node(r"""
answers[IDS] = LIST;
const refused = new Error('This is the only way bob can sign in: the account has no password anybody can type. Make a '
    + 'reset link for it first (Users), so that it can set a password, then unlink.');
refused.status = 409; refused.reason = 'no_way_in_left';
answers['/admin/sso/identities/i-bob'] = refused;
await openIdentities();
document.querySelector('.sso-identity-row[data-identity="i-bob"] .sso-identity-unlink').click();
await tick(); await tick(); await tick();
out({ toasts, reads: asked.filter((a) => a.path === IDS).length,
      providersRead: asked.filter((a) => a.path === '/admin/sso/providers').length });
""")
    assert got["toasts"] == [["This is the only way bob can sign in: the account has no password anybody can type. "
                              "Make a reset link for it first (Users), so that it can set a password, then unlink.",
                              "error"]]
    assert got["reads"] == 2 and got["providersRead"] == 2


@pytest.mark.parametrize("state, said", [
    ("refused", "Your own: another administrator lifts or unlinks it."),
    ("lapsed", "Your own: sign in through it again before you unlink it under Your account, or another "
               "administrator unlinks it."),
    ("linked", "Your own: unlink it under Your account."),
])
def test_the_administrators_own_account_offers_no_unlink_and_says_where_it_is_unlinked(state, said):
    """The server refuses an administrator's unlink of their own identity: their row says where it is done instead,
    as the owner's own unlink allows it (not while a refusal, a hold or days run out stand)."""
    got = _node(r"""
const mine = Object.assign({}, LIST.identities[1], { state: %s, refused_at: null });
answers[IDS] = { provider_id: 'p-1', total: 1, skip: 0, limit: 50, counts: { refused: 0, lapsed: 0, linked: 1 },
                 identities: [mine] };
await openIdentities();
out({ row: rows()[0], unlink: document.querySelectorAll('.sso-identity-unlink').length,
      buttons: document.querySelectorAll('.sso-identity-row button').length });
""" % json.dumps(state))
    assert got["row"]["actions"] == [said]
    assert got["unlink"] == 0 and got["buttons"] == 0


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


def test_an_answer_that_comes_after_a_later_one_draws_nothing():
    """The person pages on, and back, faster than the server answers: the list shows the page asked for last, whatever
    order the answers come in."""
    got = _node(r"""
const page = (skip, count, total) => ({ provider_id: 'p-1', total, skip, limit: 50, counts: { refused: 0, lapsed: 0, linked: total },
    identities: Array.from({ length: count }, (_, i) => ({ id: 'i-' + (skip + i), user_id: 'u-' + (skip + i),
        username: 'user' + (skip + i), linked_by: 'self', linked_at: null, last_sign_in_at: null, state: 'linked',
        refused_at: null, due_at: null, holds_sign_in: false, own: false })) });
answers[IDS] = page(0, 50, 70);
await openIdentities();
const pager = () => document.querySelector('.sso-identities-pager');
let releaseSecond;
answers['/admin/sso/providers/p-1/identities?skip=50&limit=50'] = () => new Promise((resolve) => {
    releaseSecond = () => resolve(page(50, 20, 70)); });
pager().children[2].click();                 // the second page is asked for, and is slow to come
await tick();
let releaseFirst;
answers[IDS] = () => new Promise((resolve) => { releaseFirst = () => resolve(page(0, 50, 70)); });
pager().children[0].click();                 // and the first again, before it came
await tick();
releaseFirst();
await tick(); await tick();
releaseSecond();                             // the slow answer comes last
await tick(); await tick();
out({ first: rows()[0].name, count: rows().length, said: pager().children[1].textContent });
""")
    assert got == {"first": "user0", "count": 50, "said": "1 to 50 of 70"}


LOCKED = ("Single sign-on is locked in this deployment (SETTINGS_LOCKED_KEYS): the providers are kept as they are and "
          "nothing can be changed here. Whoever runs the vault lifts the lock to change them.")


@pytest.mark.parametrize("locked", [True, False])
def test_under_the_lock_the_card_and_the_dialog_say_so_and_offer_no_change(locked):
    """SETTINGS_LOCKED_KEYS naming sso: the card says so in the server's words and offers no "Add a provider"; a
    provider still opens, its dialog says so first and offers no Turn on or off, Turn off again, Remove or Save, and
    its fields are read-only. What changes nothing stays: Open, the test sign-in, the addresses to copy; and the Identities page's
    Lift and Unlink, whose routes the lock does not stop. Without the lock all of it is offered."""
    got = _node(r"""
const LOCK = %s;
PROVIDER.state = 'disabled';
PROVIDER.addresses = { redirect_uri: 'https://vault.example.test/r', backchannel_logout_uri: 'https://vault.example.test/b',
                       post_logout_redirect_uri: 'https://vault.example.test/p', sign_in_link: 'https://vault.example.test/s' };
answers['/admin/sso/providers'].locked = LOCK;
answers['/admin/sso/providers'].locked_message = LOCK ? %s : null;
answers[IDS] = LIST;
await window.SsoSettings.load();
const line = byId('signin-sso-locked');
const card = { add: !!byId('signin-sso-add').disabled, open: !!document.querySelector('.sso-provider-row button').disabled,
               line: line && !line.hidden ? [line.textContent, line.className, line.getAttribute('role')] : null };
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
const said = byId('sso-locked-line');
const fields = byId('sso-page-connection').querySelectorAll('input, select, textarea');
const dialog = { toggle: !!byId('sso-toggle').disabled, save: !!byId('sso-save').disabled,
                 remove: !!byId('sso-remove').disabled, test: !!byId('sso-test').disabled,
                 end: !!byId('sso-end-sessions').disabled,
                 line: said ? said.textContent : null, first: byId('sso-provider-body').children[0] === said,
                 editable: fields.filter((n) => !n.readOnly).every((n) => !!n.disabled),
                 copies: fields.filter((n) => n.readOnly).map((n) => !!n.disabled),
                 copyButtons: byId('sso-page-connection').querySelectorAll('button')
                     .filter((b) => (b.getAttribute('aria-label') || '').startsWith('Copy ')).map((b) => !!b.disabled) };
byId('sso-name').value = 'renamed';
byId('sso-save').click();
await tick(); await tick();
const patches = asked.filter((a) => a.method === 'PATCH').length;
byId('sso-tab-identities').click();
await tick(); await tick();
const lift = !!document.querySelector('.sso-identity-row button').disabled;
const unlink = !!document.querySelector('.sso-identity-unlink').disabled;
document.listeners.click.forEach((f) => f({ target: byId('signin-sso-add') }));
await tick();
out({ card, dialog, patches, lift, unlink, wizardAdd: !!byId('sso-new-add').disabled });
""" % (json.dumps(locked), json.dumps(LOCKED)))
    card, dialog = got["card"], got["dialog"]
    assert card["open"] is False and dialog["test"] is False and got["lift"] is False and got["unlink"] is False
    assert dialog["copies"] == [False] * 4 and dialog["copyButtons"] == [False] * 4
    if locked:
        assert card["add"] is True and card["line"] == [LOCKED, "alert alert-info mb-md", "status"]
        assert dialog["toggle"] is True and dialog["save"] is True and dialog["remove"] is True and dialog["end"] is True
        assert dialog["line"] == LOCKED and dialog["first"] is True and dialog["editable"] is True
        assert got["patches"] == 0 and got["wizardAdd"] is True
    else:
        assert card["add"] is False and card["line"] is None
        assert dialog["toggle"] is False and dialog["save"] is False and dialog["remove"] is False and dialog["end"] is False
        assert dialog["line"] is None and dialog["editable"] is False
        assert got["patches"] == 1 and got["wizardAdd"] is False


def test_each_open_button_names_the_provider_it_opens():
    """A screen reader hears which provider each "Open" opens: its button text, and its name where the two differ
    (two providers may share a button text, never a name)."""
    got = _node(r"""
answers['/admin/sso/providers'].providers = [PROVIDER,
    Object.assign({}, PROVIDER, { id: 'p-2', name: 'okta-prod', label: null }),
    Object.assign({}, PROVIDER, { id: 'p-3', name: 'acme', label: 'acme' })];
await window.SsoSettings.load();
out(document.querySelectorAll('.sso-provider-row button').map((b) => [b.textContent, b.getAttribute('aria-label')]));
""")
    assert got == [["Open", "Open Contoso (contoso)"], ["Open", "Open okta-prod"], ["Open", "Open acme"]]


REMOVE = r"""
PROVIDER.state = 'disabled';
PROVIDER.group_mappings = %s;
const READ = answers['/admin/sso/providers/p-1'];
let refusal = null;
answers['/admin/sso/providers/p-1'] = () => {
    if (asked[asked.length - 1].method === 'DELETE') throw refusal;
    return READ;
};
answers[IDS] = LIST;
await window.SsoSettings.load();
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
const listed = () => asked.filter((a) => a.path === '/admin/sso/providers').length;
const providerRead = () => asked.filter((a) => a.path === '/admin/sso/providers/p-1' && a.method === 'GET').length;
const before = { listed: listed(), read: providerRead() };
refusal = new Error(%s);
refusal.status = 409; refusal.reason = %s;
byId('sso-remove').click();
await tick(); await tick(); await tick(); await tick();
const note = byId('sso-identities-note');
const landed = { page: document.querySelector('[role="tab"][aria-selected="true"]').id,
                 note: note ? [note.textContent, note.className, note.getAttribute('role')] : null,
                 noteFirst: note ? byId('sso-page-identities').children[0] === note : null,
                 listedAgain: listed() - before.listed, readAgain: providerRead() - before.read,
                 deletes: asked.filter((a) => a.method === 'DELETE').map((a) => a.path) };
byId('sso-tab-connection').click();
await tick();
byId('sso-tab-identities').click();
await tick(); await tick();
out({ confirm: confirms[0], toasts, landed, noteAgain: byId('sso-identities-note') !== null });
"""


@pytest.mark.parametrize("reason", ["refusals_in_force", "days_ran_out"])
def test_a_removal_refused_for_accounts_held_or_past_their_days_opens_the_identities_page_with_the_reason(reason):
    """The removal is refused because accounts are held, or held a moment ago, or past their days: the sentence sends
    the administrator to the provider's Identities page, so the dialog opens it, with the sentence first on it,
    once; the provider and the list are read again (a refusal after the step-up may have just held accounts)."""
    said = ("2 accounts have not signed in through this provider within its days. They are held now, so that removing "
            "the provider does not give them their SSH keys, temporary credentials and devices back unseen. Lift each "
            "on this provider's Identities page when they should have them back, then remove the provider again.")
    got = _node(REMOVE % ("0", json.dumps(said), json.dumps(reason)))
    landed = got["landed"]
    assert landed["deletes"] == ["/admin/sso/providers/p-1"]
    assert landed["page"] == "sso-tab-identities"
    assert landed["note"] == [said, "alert alert-warning mb-sm", "alert"] and landed["noteFirst"] is True
    assert landed["listedAgain"] == 1 and landed["readAgain"] == 1
    assert got["toasts"] == []                               # said on the page, where it stays
    assert got["noteAgain"] is False                         # once: the page shown again does not repeat it


def test_a_removal_refused_for_another_reason_says_it_and_reads_the_list_again():
    got = _node(REMOVE % ("0", json.dumps("Turn the provider off before removing it."), json.dumps("still_on")))
    landed = got["landed"]
    assert got["toasts"] == [["Turn the provider off before removing it.", "error"]]
    assert landed["page"] == "sso-tab-connection" and landed["note"] is None
    assert landed["listedAgain"] == 1 and landed["readAgain"] == 0


@pytest.mark.parametrize("mappings, said", [
    (3, "Remove contoso? Its 3 link(s) to accounts are removed with it, and its 3 group mapping(s); the accounts "
        "stay."),
    (0, "Remove contoso? Its 3 link(s) to accounts are removed with it; the accounts stay."),
])
def test_the_removal_confirmation_names_the_group_mappings_removed_with_the_provider(mappings, said):
    got = _node(REMOVE % (json.dumps(mappings), json.dumps("Turn the provider off before removing it."),
                          json.dumps("still_on")))
    message, title, label = got["confirm"]
    assert message == said and title == "Remove the provider" and label == "Remove"


STANDS = ("{n} that came through {it} could not be ended and stand until they run out: use \"Turn off again\" to end "
          "them, or end its linked accounts' sessions with \"Terminate Sessions\" on the Users page.")


def test_a_turn_off_says_what_it_ended_held_and_left_standing_and_turn_off_again_ends_what_stands():
    """POST .../state disabled answers how many sessions that came through the provider it ended, how many still stand
    (they could not be ended), and how many accounts whose days had run out stay held. The dialog says what still
    stands until it is ended, and "Turn off again" asks the server to end it (an off provider answers changed:false)."""
    got = _node(r"""
const OFF = Object.assign({}, PROVIDER, { state: 'disabled' });
const STATE = '/admin/sso/providers/p-1/state';
answers[STATE] = { provider: OFF, changed: true, sessions_ended: 3, sessions_not_ended: 2, held: 1 };
await window.SsoSettings.load();
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
const on = { end: byId('sso-end-sessions') !== null, line: byId('sso-sessions-standing') !== null };
byId('sso-toggle').click();
await tick(); await tick(); await tick();
const line = () => byId('sso-sessions-standing');
const end = byId('sso-end-sessions');
const off = { toast: toasts[toasts.length - 1], line: line() && [line().textContent, line().className],
              aboveTabs: line() && line().nextElementSibling.getAttribute('role') === 'tablist',
              end: end && [end.textContent, end.getAttribute('aria-label'), !!end.disabled] };
answers[STATE] = { provider: OFF, changed: false, sessions_ended: 2, sessions_not_ended: 0 };
byId('sso-end-sessions').click();
await tick(); await tick(); await tick();
const again = { toast: toasts[toasts.length - 1], line: line() !== null };
answers[STATE] = { provider: OFF, changed: false };
byId('sso-end-sessions').click();
await tick(); await tick(); await tick();
out({ on, off, again, nothing: toasts[toasts.length - 1], line: line() !== null,
      sent: asked.filter((a) => a.path === STATE).map((a) => [a.method, JSON.parse(a.body)]) });
""")
    assert got["on"] == {"end": False, "line": False}                 # a provider that is on offers no "Turn off again"
    toast, kind = got["off"]["toast"]
    assert kind == "warning"
    assert toast == ("The provider is off. 3 session(s) that came through it were ended. 1 account(s) whose days there "
                     "had run out stay held: lift each on the Identities page when it should have its keys back. "
                     + STANDS.format(n="2 session(s)", it="it"))
    assert got["off"]["line"] == [STANDS.format(n="2 session(s)", it="this provider"), "alert alert-warning mb-md"]
    assert got["off"]["aboveTabs"] is True
    assert got["off"]["end"] == ["Turn off again", "Turn Contoso off again to end the sessions that still stand", False]
    assert got["again"] == {"toast": ["2 session(s) that came through it were ended.", "success"], "line": False}
    assert got["nothing"] == ["No session that came through it still stands.", "success"] and got["line"] is False
    assert got["sent"] == [["POST", {"state": "disabled"}]] * 3


def test_a_turn_off_whose_sessions_could_not_be_counted_says_so():
    got = _node(r"""
answers['/admin/sso/providers/p-1/state'] = { provider: Object.assign({}, PROVIDER, { state: 'disabled' }),
                                             changed: true, sessions_ended: 0, sessions_not_ended: null, held: 0 };
await window.SsoSettings.load();
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
byId('sso-toggle').click();
await tick(); await tick(); await tick();
out({ toast: toasts[toasts.length - 1], line: byId('sso-sessions-standing').textContent });
""")
    assert got["toast"] == ["The provider is off. " + STANDS.format(n="Sessions", it="it"), "warning"]
    assert got["line"] == STANDS.format(n="Sessions", it="this provider")


def test_a_turn_on_says_whom_its_days_hold_and_a_state_already_reached_says_so():
    """POST .../state enabled answers how many linked accounts its days hold to a sign-in through it. A turn-off of a
    provider somebody else turned off meanwhile changes nothing, and is said so. "Turn off again" is offered for a
    provider that is off, not for one that is on, nor for a draft that never was."""
    got = _node(r"""
PROVIDER.state = 'disabled';
const ON = Object.assign({}, PROVIDER, { state: 'enabled' });
const STATE = '/admin/sso/providers/p-1/state';
answers['/admin/sso/providers'].providers = [PROVIDER, { id: 'p-2', name: 'draft', label: null, state: 'disabled',
    configured: false, tested: false, identities: 0, issuer: null }];
answers['/admin/sso/providers/p-2'] = { provider: Object.assign({}, PROVIDER, { id: 'p-2', name: 'draft', label: null,
    configured: false, tested: false, identities: 0, issuer: null }) };
answers[STATE] = { provider: ON, changed: true, due: 4 };
await window.SsoSettings.load();
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
const offered = byId('sso-end-sessions') !== null;
byId('sso-toggle').click();
await tick(); await tick(); await tick();
const on = { toast: toasts[toasts.length - 1], end: byId('sso-end-sessions') !== null };
answers[STATE] = { provider: PROVIDER, changed: false };
byId('sso-toggle').click();
await tick(); await tick(); await tick();
const already = { toast: toasts[toasts.length - 1], end: byId('sso-end-sessions') !== null,
                  line: byId('sso-sessions-standing') !== null };
document.querySelectorAll('.sso-provider-row button')[1].click();
await tick(); await tick();
out({ offered, on, already, draft: byId('sso-end-sessions') !== null, title: byId('sso-provider-title').textContent });
""")
    assert got["offered"] is True
    assert got["on"] == {"toast": ["The provider is on. 4 linked account(s) have not signed in through it within its "
                                   "days: their password and passkeys do not sign them in until they have.", "success"],
                         "end": False}
    assert got["already"] == {"toast": ["It was already off.", "success"], "end": True, "line": False}
    assert got["title"] == "draft" and got["draft"] is False


SAVE = r"""
const READ = answers['/admin/sso/providers/p-1'];
let patched = null;
answers['/admin/sso/providers/p-1'] = () => asked[asked.length - 1].method === 'PATCH' ? patched : READ;
const answer = (more) => Object.assign({ provider: PROVIDER, changed: ['name'], connection_changed: false,
    turned_off: false, secret_cleared: false, made_sso_only: [], restored: [], sessions_ended: 0,
    sessions_not_ended: 0, held: 0, owners_told: 0, held_by_its_days: 0, newly_held: 0 }, more);
await window.SsoSettings.load();
document.querySelector('.sso-provider-row button').click();
await tick(); await tick();
async function save(field, value, more) {
    patched = answer(more);
    byId(field).value = value;
    byId('sso-save').click();
    await tick(); await tick(); await tick();
    return toasts[toasts.length - 1];
}
"""


def test_a_save_that_turned_the_provider_off_says_what_it_ended_held_left_standing_and_told():
    """PATCH answers what a change of the connection did to a provider that was on: the sessions it ended, those it
    could not end, the accounts whose days had run out that stay held, and the linked accounts told it was pointed
    somewhere else. What still stands is said on the dialog until it is ended; a later save, which turns nothing
    off, does not take that away."""
    got = _node(SAVE + r"""
const OFF = Object.assign({}, PROVIDER, { state: 'disabled' });
const first = await save('sso-issuer', 'https://elsewhere.example.test', { provider: OFF, changed: ['issuer'],
    connection_changed: true, turned_off: true, sessions_ended: 2, sessions_not_ended: 1, held: 1, owners_told: 2 });
const line = () => byId('sso-sessions-standing');
const after = { line: line() && line().textContent, end: byId('sso-end-sessions') !== null };
const second = await save('sso-name', 'contoso-2', { provider: OFF });
out({ first, after, second, still: line() && line().textContent });
""")
    toast, kind = got["first"]
    assert kind == "warning"
    assert toast == ("Saved. The connection changed, so the provider was turned off: run a test sign-in, then turn it "
                     "on again. 2 session(s) that came through it were ended. 1 account(s) whose days there had run "
                     "out stay held: lift each on the Identities page when it should have its keys back. "
                     + STANDS.format(n="1 session(s)", it="it")
                     + " The 2 account(s) linked to it were told it was pointed somewhere else.")
    assert got["after"] == {"line": STANDS.format(n="1 session(s)", it="this provider"), "end": True}
    assert got["second"] == ["Saved.", "success"]
    assert got["still"] == STANDS.format(n="1 session(s)", it="this provider")


def test_a_save_whose_sessions_could_not_be_counted_says_so():
    got = _node(SAVE + r"""
out(await save('sso-issuer', 'https://elsewhere.example.test', { provider: Object.assign({}, PROVIDER, { state: 'disabled' }),
    changed: ['issuer'], connection_changed: true, turned_off: true, sessions_not_ended: null }));
""")
    assert got == ["Saved. The connection changed, so the provider was turned off: run a test sign-in, then turn it on "
                   "again. " + STANDS.format(n="Sessions", it="it"), "warning"]


def test_a_save_of_the_days_says_whom_they_hold_now():
    """A save of the provider's days, or of what they end, answers how many linked accounts it holds from now on and
    how many its days hold in all: the administrator is told both, as the other administrators are."""
    got = _node(SAVE + r"""
byId('sso-tab-sessions').click();
await tick();
const more = await save('sso-freshness', '30', { changed: ['policy.sso_freshness_days'], held_by_its_days: 3,
                                                 newly_held: 2 });
const none = await save('sso-freshness', '60', { changed: ['policy.sso_freshness_days'], held_by_its_days: 3,
                                                 newly_held: 0 });
out({ more, none });
""")
    assert got["more"] == ["Saved. 2 more linked account(s) have not signed in through it within its days as they are "
                           "now: their password and passkeys do not sign them in until they have. They were told. 3 "
                           "account(s) are held so in all.", "success"]
    assert got["none"] == ["Saved. 3 linked account(s) are held to a sign-in through it by its days.", "success"]


def test_a_save_that_lets_accounts_hold_a_password_again_says_how_they_get_one_on_this_vault():
    """Password sign-in allowed again for a provider: the accounts it held to none may hold one again, and have none
    yet. "Forgot your password?" on the sign-in page sends a link only where the vault offers it (the server says so
    in self_service_reset) and to an account with an email address; otherwise an administrator makes the link."""
    got = _node(SAVE + r"""
const offered = await save('sso-name', 'contoso-2', { restored: ['a', 'b'], self_service_reset: true });
const not = await save('sso-name', 'contoso-3', { restored: ['a'] });
out({ offered, not });
""")
    assert got["offered"] == ["Saved. 2 linked account(s) may hold a password again and have none yet: each that has "
                              "an email address can set one with \"Forgot your password?\" on the sign-in page, and "
                              "you can make a reset link for any of them on the Users page.", "success"]
    assert got["not"] == ["Saved. 1 linked account(s) may hold a password again and have none yet: make each a reset "
                          "link on the Users page.", "success"]
    assert "sign-in page" not in got["not"][0]
