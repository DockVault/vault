"""The Groups page of a single sign-on provider in Settings, Sign-in (static/js/settings-sso.js): the provider's
groups mapped to departments and roles (GET /admin/sso/providers/{id}/group-mappings), each with what it gives and
whether it does anything now; a mapping is added (POST), changed (PATCH, sending only what changed) and removed
(DELETE, after a confirmation that says what removing changes and what it does not); the page reads the list again
after each, says a refusal where it belongs, and offers nothing that would change a mapping under the deployment's
lock or at the limit of mappings.

Driven in Node against the shipped module, on the small document of tests/js/mini_dom.js, by the clicks a person
makes: open the provider, open its Groups page.
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

WHY_NOT = "Contoso may not raise administrator requests. Turn on “Administrator group” on its Access page first."

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
const asked = [], toasts = [], confirms = [];
let answers = {};
let confirmAnswer = true;
const POLICY = { sso_account_creation: 'invite_only', sso_default_role: 'user', sso_password_login: 'allowed',
                 sso_link_by_email: false, sso_admin_mapping: false, sso_use_signup_domains: false,
                 sso_backchannel_logout: true, sso_idp_logout: false, sso_trust_idp_mfa: false, sso_accepted_amr: [],
                 sso_accepted_acr: [], sso_requested_acr: '', sso_allowed_tenants: [], sso_allowed_domains: [],
                 sso_required_groups: ['staff'], sso_freshness_days: 30, sso_refusal_ends_access: true,
                 sso_jit_password: false, sso_lapse_ends_sign_in: true };
const PROVIDER = { id: 'p-1', name: 'contoso', label: 'Contoso', state: 'enabled', configured: true, tested: true,
                   identities: 3, issuer: 'https://login.example.test', policy: POLICY, claims: {}, addresses: null,
                   last_test: null, sso_only_accounts: 0, only_way_in_accounts: 0, icon: 'generic', sort_order: 0,
                   show_on_sign_in: true, scopes: 'openid', token_auth: 'client_secret_basic', group_mappings: 3 };
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
const settle = async () => { for (let i = 0; i < 6; i += 1) await tick(); };
const byId = (id) => document.getElementById(id);
const out = (value) => console.log(JSON.stringify(value));
const MAPS = '/admin/sso/providers/p-1/group-mappings';
const WHY_NOT = %s;
const MAPPINGS = [
    { id: 'm-1', provider_group: 'Contractors', department: null, role: 'external', does_nothing: null },
    { id: 'm-2', provider_group: 'Finance', department: { id: 'd-fin', name: 'Finance' }, role: 'user', does_nothing: null },
    { id: 'm-3', provider_group: 'Vault Admins', department: { id: 'd-staff', name: 'Staff' }, role: 'admin',
      does_nothing: { reason: 'admin_mapping_off', message: WHY_NOT } }];
const DEPARTMENTS = [{ id: 'd-fin', name: 'Finance', parent_id: null },
                     { id: 'd-staff', name: 'Staff', parent_id: null },
                     { id: 'd-staff-2', name: 'Staff', parent_id: 'd-fin' }];
const LISTING = (more) => Object.assign({ provider: { id: 'p-1', name: 'contoso', label: 'Contoso', state: 'enabled' },
    mappings: MAPPINGS, departments: DEPARTMENTS, roles: ['user', 'external', 'admin'],
    admin_role: { allowed: false, why_not: { reason: 'admin_mapping_off', message: WHY_NOT } },
    groups_claim: 'groups', seen_at_last_test: ['Contractors', 'Finance', 'Interns'], limit: 200, locked: false,
    step_up: 'admin.auth_policy.write' }, more || {});
const rows = () => document.querySelectorAll('.sso-group-row').map((row) => ({
    id: row.dataset.mapping,
    group: row.querySelector('.sso-group-name').textContent,
    gives: row.querySelector('.sso-group-gives').textContent,
    idle: row.querySelector('.sso-group-idle') ? row.querySelector('.sso-group-idle').textContent : null,
    why: row.querySelector('.sso-group-why') ? row.querySelector('.sso-group-why').textContent : null,
    actions: row.querySelectorAll('button').map((b) => [b.textContent, b.getAttribute('aria-label'), !!b.disabled]),
}));
const row = (id) => document.querySelector('.sso-group-row[data-mapping="' + id + '"]');
const button = (id, text) => row(id).querySelectorAll('button').find((b) => b.textContent === text);
const options = (id) => byId(id).options.map((o) => [o.value, o.textContent, !!o.disabled]);
const errorOf = (id) => {
    const shown = byId(id).closest('.form-group').querySelector('.sso-group-error');
    return shown && !shown.hidden ? shown.textContent : null;
};
const sent = (method) => asked.filter((a) => a.method === method).map((a) => [a.path, a.body ? JSON.parse(a.body) : null]);
async function openGroups() {
    await window.SsoSettings.load();
    document.querySelector('.sso-provider-row button').click();
    await tick(); await tick();
    byId('sso-tab-groups').click();
    await settle();
}
""" % json.dumps(WHY_NOT)


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (PRELUDE + PAGE.read_text(encoding="utf-8") + "\n(async () => {\n" + scenario
              + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_groups_page_lists_each_mapping_with_what_it_gives():
    got = _node(r"""
answers[MAPS] = LISTING();
await openGroups();
out({ tabs: document.querySelectorAll('.sso-tabs button').map((b) => b.textContent),
      selected: byId('sso-tab-groups').getAttribute('aria-selected'), panel: byId('sso-page-groups') !== null,
      about: byId('sso-groups-about').textContent, claim: byId('sso-groups-claim').textContent,
      seen: byId('sso-groups-seen').textContent, rows: rows(), count: byId('sso-groups-count').textContent,
      reads: asked.filter((a) => a.path === MAPS).length,
      listed: document.querySelector('.sso-provider-row').children[0].children[1].textContent });
""")
    assert got["tabs"] == ["Connection", "Access", "Groups", "Second factor", "Sessions", "Identities"]
    assert got["selected"] == "true" and got["panel"] is True and got["reads"] == 1
    about = got["about"]
    assert about.startswith("Groups the provider sends, each given a department, a role, or both.")
    assert ("a person in a mapped group joins its department, and leaves it at the first sign-in whose token names "
            "no group mapped to it") in about
    assert "departments no mapping names are never touched" in about
    assert "The role User or External is given at the sign-in (with both, User), and never lowers an administrator." in about
    assert "The administrator role is never given by a sign-in" in about
    assert "a request another administrator decides within 7 days" in about
    assert "unless they are the last administrator able to act" in about
    assert about.endswith("A change here applies from each person's next sign-in; removing a mapping moves nobody.")
    assert got["claim"] == ('Groups are read from the token\'s "groups" claim. Write each group exactly as the provider '
                            "sends it, letter for letter and case included.")
    assert got["seen"] == "The last test sign-in carried: Contractors, Finance, Interns."
    contractors, finance, admins = got["rows"]
    assert contractors["group"] == "Contractors" and contractors["gives"] == "Gives the role External."
    assert contractors["idle"] is None and contractors["why"] is None
    assert contractors["actions"] == [["Change", "Change the mapping of Contractors", False],
                                      ["Remove", "Remove the mapping of Contractors", False]]
    assert finance["gives"] == "Gives the department Finance and the role User."
    assert admins["gives"] == ("Gives the department Staff and a request for the administrator role, which another "
                               "administrator decides.")
    assert admins["idle"] == "Does nothing now" and admins["why"] == WHY_NOT
    assert got["count"] == "3 of at most 200 mappings."
    # The providers list says how many groups each provider maps.
    assert "3 group mapping(s)" in got["listed"]


@pytest.mark.parametrize("seen, said", [
    (None, "The last test sign-in did not pass, or none has run: run one on the Connection page to see the groups the "
           "provider sends."),
    ([], 'The last test sign-in\'s token named no group in "roles": check that the provider sends groups, or the '
         "claim's name on the Connection page."),
])
def test_the_page_says_when_no_test_sign_in_showed_the_groups(seen, said):
    got = _node(r"""
answers[MAPS] = LISTING({ seen_at_last_test: %s, groups_claim: 'roles', mappings: [] });
await openGroups();
out({ seen: byId('sso-groups-seen').textContent, rows: rows().length, count: byId('sso-groups-count').textContent,
      claim: byId('sso-groups-claim').textContent, list: byId('sso-group-seen') });
""" % json.dumps(seen))
    assert got["seen"] == said and got["rows"] == 0 and got["count"] == "0 of at most 200 mappings."
    assert '"roles" claim' in got["claim"] and got["list"] is None


def test_the_add_form_offers_the_departments_the_roles_and_the_groups_not_mapped_yet():
    got = _node(r"""
answers[MAPS] = LISTING();
await openGroups();
const seen = byId('sso-group-seen');
out({ departments: options('sso-group-department'), roles: options('sso-group-role'),
      roleHelp: byId('sso-group-role').closest('.form-group').querySelectorAll('p')
          .filter((p) => !p.classList.contains('sso-group-error')).map((p) => p.textContent),
      list: byId('sso-group-name').getAttribute('list'), seen: seen.children.map((o) => o.value),
      add: [byId('sso-group-add').textContent, !!byId('sso-group-add').disabled] });
""")
    # Two departments of one name are told apart by the one each is in.
    assert got["departments"] == [["", "No department", False], ["d-fin", "Finance", False],
                                  ["d-staff", "Staff (top level)", False], ["d-staff-2", "Staff (in Finance)", False]]
    assert got["roles"] == [["", "No role", False], ["user", "User", False], ["external", "External", False],
                            ["admin", "Administrator (a request another administrator decides)", True]]
    assert got["roleHelp"] == [WHY_NOT]
    assert got["list"] == "sso-group-seen" and got["seen"] == ["Interns"]
    assert got["add"] == ["Add mapping", False]


def test_with_the_administrator_role_allowed_its_choice_is_offered():
    got = _node(r"""
answers[MAPS] = LISTING({ admin_role: { allowed: true, why_not: null } });
await openGroups();
out({ roles: options('sso-group-role'), help: byId('sso-group-role').closest('.form-group').querySelectorAll('p')
          .filter((p) => !p.classList.contains('sso-group-error')).length });
""")
    assert got["roles"][-1] == ["admin", "Administrator (a request another administrator decides)", False]
    assert got["help"] == 0


@pytest.mark.parametrize("department, role, body", [
    ("d-staff", "", {"provider_group": "Interns", "department_id": "d-staff"}),
    ("", "external", {"provider_group": "Interns", "role": "external"}),
    ("d-fin", "user", {"provider_group": "Interns", "department_id": "d-fin", "role": "user"}),
])
def test_add_sends_the_mapping_trimmed_without_empty_fields_and_reads_the_list_again(department, role, body):
    got = _node(r"""
answers[MAPS] = () => (asked[asked.length - 1].method === 'POST'
    ? { mapping: { id: 'm-4', provider_group: 'Interns', department: null, role: null, does_nothing: null } }
    : LISTING());
await openGroups();
byId('sso-group-name').value = '  Interns ';
byId('sso-group-department').value = %s;
byId('sso-group-role').value = %s;
byId('sso-group-add').click();
await settle();
out({ posts: sent('POST'), reads: asked.filter((a) => a.path === MAPS && a.method === 'GET').length,
      listed: asked.filter((a) => a.path === '/admin/sso/providers').length, toasts });
""" % (json.dumps(department), json.dumps(role)))
    assert got["posts"] == [["/admin/sso/providers/p-1/group-mappings", body]]
    assert got["reads"] == 2 and got["listed"] == 2         # the mappings and the providers list, read again
    assert got["toasts"] == [["The group Interns is mapped. It applies from each person's next sign-in through this "
                              "provider.", "success"]]


def test_a_refused_add_is_said_under_the_field_it_names_or_beside_the_button():
    got = _node(r"""
answers[MAPS] = () => {
    if (asked[asked.length - 1].method !== 'POST') return LISTING();
    throw refusal;
};
let refusal = Object.assign(new Error("Name the provider's group."), { status: 400, reason: 'invalid', field: 'provider_group' });
await openGroups();
byId('sso-group-add').click();
await settle();
const first = { name: errorOf('sso-group-name'), role: errorOf('sso-group-role'), said: byId('sso-group-said').textContent,
                reads: asked.filter((a) => a.path === MAPS && a.method === 'GET').length, add: !!byId('sso-group-add').disabled };
refusal = Object.assign(new Error('One of user, external or admin, or none.'), { status: 400, reason: 'invalid', field: 'role' });
byId('sso-group-add').click();
await settle();
const second = { name: errorOf('sso-group-name'), role: errorOf('sso-group-role') };
refusal = Object.assign(new Error('This group is mapped already. Change that mapping instead.'), { status: 409, reason: 'group_mapped' });
byId('sso-group-name').value = 'Finance';
byId('sso-group-add').click();
await settle();
const third = { name: errorOf('sso-group-name'), said: byId('sso-group-said').textContent };
refusal = Object.assign(new Error('The vault is busy with this right now. Try again in a moment.'), { status: 503 });
byId('sso-group-add').click();
await settle();
out({ first, second, third, busy: byId('sso-group-said').textContent });
""")
    assert got["first"] == {"name": "Name the provider's group.", "role": None, "said": "", "reads": 1, "add": False}
    assert got["second"] == {"name": None, "role": "One of user, external or admin, or none."}
    assert got["third"] == {"name": None, "said": "This group is mapped already. Change that mapping instead."}
    assert got["busy"] == "The vault is busy with this right now. Try again in a moment."


def test_change_sends_only_what_differs_and_null_for_what_is_taken_away():
    got = _node(r"""
answers[MAPS] = LISTING();
answers[MAPS + '/m-2'] = () => ({ mapping: MAPPINGS[1], changed: ['role'] });
await openGroups();
button('m-2', 'Change').click();
await tick();
const editing = row('m-2');
const field = (cls) => editing.querySelector(cls);
const shown = { name: field('.sso-group-edit-name').value, department: field('.sso-group-edit-department').value,
                role: field('.sso-group-edit-role').value,
                buttons: editing.querySelectorAll('button').map((b) => b.textContent) };
// Saved as it was: nothing is sent.
editing.querySelectorAll('button').find((b) => b.textContent === 'Save').click();
await settle();
const untouched = { patches: sent('PATCH').length, said: editing.querySelector('.sso-said').textContent };
field('.sso-group-edit-role').value = '';
editing.querySelectorAll('button').find((b) => b.textContent === 'Save').click();
await settle();
const first = sent('PATCH');
const firstToasts = toasts.slice();
button('m-2', 'Change').click();
await tick();
row('m-2').querySelector('.sso-group-edit-department').value = 'd-staff-2';
row('m-2').querySelector('.sso-group-edit-name').value = ' Finance EU ';
answers[MAPS + '/m-2'] = () => ({ mapping: MAPPINGS[1], changed: [] });
row('m-2').querySelectorAll('button').find((b) => b.textContent === 'Save').click();
await settle();
out({ shown, untouched, first, firstToasts, second: sent('PATCH').slice(1), toasts: toasts.slice(firstToasts.length),
      reads: asked.filter((a) => a.path === MAPS && a.method === 'GET').length });
""")
    assert got["shown"] == {"name": "Finance", "department": "d-fin", "role": "user", "buttons": ["Save", "Cancel"]}
    assert got["untouched"] == {"patches": 0, "said": "Nothing was changed."}
    assert got["first"] == [["/admin/sso/providers/p-1/group-mappings/m-2", {"role": None}]]
    assert got["firstToasts"] == [["The mapping of the group Finance was changed. It applies from each person's next "
                                   "sign-in through this provider.", "success"]]
    assert got["second"] == [["/admin/sso/providers/p-1/group-mappings/m-2",
                              {"provider_group": "Finance EU", "department_id": "d-staff-2"}]]
    assert got["toasts"] == [["Nothing was changed.", "info"]]
    assert got["reads"] == 3


def test_change_keeps_the_administrator_role_of_a_mapping_that_has_it_and_cancel_puts_the_row_back():
    got = _node(r"""
answers[MAPS] = LISTING();
await openGroups();
button('m-3', 'Change').click();
await tick();
const admin = row('m-3').querySelector('.sso-group-edit-role').options.find((o) => o.value === 'admin');
const kept = { value: row('m-3').querySelector('.sso-group-edit-role').value, disabled: !!admin.disabled };
row('m-3').querySelectorAll('button').find((b) => b.textContent === 'Cancel').click();
await tick();
out({ kept, back: rows().map((r) => r.group), patches: sent('PATCH').length });
""")
    assert got["kept"] == {"value": "admin", "disabled": False}
    assert got["back"] == ["Contractors", "Finance", "Vault Admins"] and got["patches"] == 0


@pytest.mark.parametrize("mapping, said", [
    ("m-2", "Remove the mapping of the group Finance? Nobody's department or role changes: people who joined Finance "
            "through it stay until an administrator takes them out, and a role it gave stays. The other "
            "administrators are told."),
    ("m-3", "Remove the mapping of the group Vault Admins? Nobody's department or role changes: people who joined "
            "Staff through it stay until an administrator takes them out. A request for the administrator role it "
            "opened can no longer be approved. The other administrators are told."),
    ("m-1", "Remove the mapping of the group Contractors? Nobody's department or role changes: a role it gave stays. "
            "The other administrators are told."),
])
def test_remove_asks_first_says_what_it_changes_and_reads_the_list_again(mapping, said):
    got = _node(r"""
answers[MAPS] = LISTING();
answers[MAPS + '/' + %s] = { removed: true, mapping: MAPPINGS[0] };
await openGroups();
confirmAnswer = false;
button(%s, 'Remove').click();
await settle();
const declined = sent('DELETE').length;
confirmAnswer = true;
button(%s, 'Remove').click();
await settle();
out({ declined, confirm: confirms[0], deletes: sent('DELETE').map((d) => d[0]), toasts,
      reads: asked.filter((a) => a.path === MAPS && a.method === 'GET').length,
      listed: asked.filter((a) => a.path === '/admin/sso/providers').length });
""" % (json.dumps(mapping), json.dumps(mapping), json.dumps(mapping)))
    assert got["declined"] == 0                          # nothing is sent before the person says yes
    message, title, label = got["confirm"]
    assert message == said and title == "Remove the mapping" and label == "Remove"
    assert got["deletes"] == [f"/admin/sso/providers/p-1/group-mappings/{mapping}"]
    assert got["toasts"][0][1] == "success" and got["toasts"][0][0].startswith("The mapping of the group ")
    assert got["reads"] == 2 and got["listed"] == 2


def test_add_is_offered_below_the_limit_only():
    got = _node(r"""
answers[MAPS] = LISTING({ limit: 3 });
await openGroups();
out({ add: !!byId('sso-group-add').disabled, said: byId('sso-group-said').textContent,
      count: byId('sso-groups-count').textContent, change: !!button('m-1', 'Change').disabled });
""")
    assert got == {"add": True, "said": "A provider holds at most 3 group mappings. Remove one first.",
                   "count": "3 of at most 3 mappings.", "change": False}


def test_under_the_lock_nothing_that_changes_a_mapping_is_offered():
    got = _node(r"""
answers['/admin/sso/providers'].locked = true;
answers['/admin/sso/providers'].locked_message = 'Single sign-on is locked in this deployment.';
answers[MAPS] = LISTING({ locked: true });
await openGroups();
byId('sso-group-name').value = 'Interns';
byId('sso-group-add').click();
await settle();
out({ add: !!byId('sso-group-add').disabled, fields: ['sso-group-name', 'sso-group-department', 'sso-group-role']
          .map((id) => !!byId(id).disabled),
      buttons: rows().map((r) => r.actions.map((a) => a[2])), posts: sent('POST').length,
      line: byId('sso-locked-line') ? byId('sso-locked-line').textContent : null, rows: rows().length });
""")
    assert got["add"] is True and got["fields"] == [True, True, True] and got["posts"] == 0
    assert got["buttons"] == [[True, True]] * 3 and got["rows"] == 3
    assert got["line"] == "Single sign-on is locked in this deployment."


def test_an_answer_that_comes_after_a_later_one_draws_nothing():
    """Two removals in a row: the list read after the first is slow to come, and comes after the one read after the
    second. The page shows the list as it was read last, whatever order the answers come in."""
    got = _node(r"""
answers[MAPS] = LISTING();
answers[MAPS + '/m-1'] = { removed: true, mapping: MAPPINGS[0] };
answers[MAPS + '/m-2'] = { removed: true, mapping: MAPPINGS[1] };
await openGroups();
let releaseFirst;
answers[MAPS] = () => new Promise((resolve) => {
    releaseFirst = () => resolve(LISTING({ mappings: [MAPPINGS[1], MAPPINGS[2]] })); });
button('m-1', 'Remove').click();
await settle();
answers[MAPS] = LISTING({ mappings: [MAPPINGS[2]] });
button('m-2', 'Remove').click();
await settle();
const before = rows().map((r) => r.group);
releaseFirst();                                       // the slow answer comes last
await settle();
out({ before, after: rows().map((r) => r.group), count: byId('sso-groups-count').textContent });
""")
    assert got == {"before": ["Vault Admins"], "after": ["Vault Admins"], "count": "1 of at most 200 mappings."}
