"""The settings save and the single sign-on providers that rely on the sign-up allow-list (static/js/app.js,
saveAllSettings with collectAccountsPolicy).

A provider with "Also hold people to the sign-up domain list" ticked counts as saying who may sign in only while that
list is an allow-list with a domain on it (app/core/sso_policy.py, is_restricted). Where it has no tenant, domain or
required group of its own, and makes accounts at a first sign-in or links accounts by email, a save that turns the
allow-list off, into a deny-list or empty stops it doing that. The save asks first, naming the providers, and sends
nothing on a no. Nothing is asked where no enabled provider relies on the list, where the list was not an allow-list,
or where the providers cannot be read.

Driven in Node against the page's own functions, on the small document of tests/js/mini_dom.js, with the server's
answers stood in for (the server's side has its own tests: tests/test_sso_policy.py). Offline."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", APP)
    assert found, name
    start = found.start() + 1
    return APP[start:APP.index("\n}\n", start) + 3]


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const print = console.log.bind(console);
console.log = () => {}; console.error = () => {}; console.warn = () => {};
// The Settings page's fields: every one the save reads is there, empty, unless a scenario fills it.
const fields = {};
const byId = document.getElementById.bind(document);
document.getElementById = (id) => byId(id) || fields[id] || (fields[id] = (() => {
    const el = document.createElement('input'); el.id = id; return el; })());
const asked = [], confirms = [], toasts = [], sent = [];
let answers = {};                       // 'METHOD path' -> what apiRequest answers (an Error is thrown)
let confirmAnswer = true;
async function apiRequest(path, options) {
    const o = options || {};
    const key = (o.method || 'GET') + ' ' + path;
    asked.push(key);
    if (key === 'PUT /settings') { sent.push(JSON.parse(o.body)); return {}; }
    if (!Object.prototype.hasOwnProperty.call(answers, key)) throw new Error('Not arranged: ' + key);
    if (answers[key] instanceof Error) throw answers[key];
    return answers[key];
}
async function showConfirm(message, title, input, label) { confirms.push({ message, title, label }); return confirmAnswer; }
function showSuccess(m) { toasts.push(['success', m]); }
function showError(m) { toasts.push(['error', m]); }
const BRAND_SETTING_FIELDS = {};
let settingsGroupsLoaded = false;
let accountsSmtpConfigured = false;
let accountsDomains = [];
let currentSettings = {};
const out = (value) => print(JSON.stringify(value));
// What the page loaded (GET /settings), then what the administrator changed in the form.
function loaded(mode, domains) {
    currentSettings = { signup_email_domain_mode: mode, signup_email_domains: domains.slice() };
    accountsDomains = domains.slice();
    document.getElementById('setting-signup-domain-mode').value = mode;
}
function changed(mode, domains) {
    document.getElementById('setting-signup-domain-mode').value = mode;
    accountsDomains = domains.slice();
}
const PROVIDERS = 'GET /admin/sso/providers';
function provider(name, policy, state) {
    return { id: 'p-' + name, name, label: 'Sign in with ' + name, state: state || 'enabled',
             policy: Object.assign({ sso_use_signup_domains: true, sso_account_creation: 'jit', sso_link_by_email: false,
                                     sso_allowed_tenants: [], sso_allowed_domains: [], sso_required_groups: [] },
                                   policy || {}) };
}
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    helpers = "\n".join(_function(n) for n in ("collectAccountsPolicy", "_confirmSignUpListChange",
                                                 "saveAllSettings"))
    script = (PRELUDE + helpers + "\n(async () => {\n" + scenario
              + "\nout({ asked, confirms, toasts,"
              + " sent: sent.map((s) => [s.signup_email_domain_mode, s.signup_email_domains]) });"
              + "\n})().catch((e) => { print('FAILED ' + e.stack); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


ONE = ("The single sign-on provider “Contoso” makes accounts at a first sign-in only because the sign-up allow-list "
       "on Accounts & Access says who may sign in through it. Saved this way, it stops making accounts at a first "
       "sign-in until it says who may sign in another way: Tenants, Domains or Required groups on its Access page, "
       "under Settings, Sign-in methods.")
TITLE = "Single sign-on depends on the sign-up list"
PROVIDERS_ASKED = "GET /admin/sso/providers"


def test_turning_the_allow_list_off_asks_first_and_a_no_sends_nothing():
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = { providers: [provider('Contoso')] };
changed('off', ['example.com']);
confirmAnswer = false;
await saveAllSettings();
""")
    assert got["confirms"] == [{"message": ONE, "title": TITLE, "label": "Save anyway"}]
    assert "PUT /settings" not in got["asked"]
    assert got["sent"] == [] and got["toasts"] == []


def test_a_yes_saves_the_list_as_changed():
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = { providers: [provider('Contoso')] };
changed('off', ['example.com']);
await saveAllSettings();
""")
    assert len(got["confirms"]) == 1
    assert got["sent"] == [["off", ["example.com"]]]
    assert got["toasts"] == [["success", "Settings saved successfully"]]


def test_a_deny_list_or_an_empty_allow_list_asks_too():
    for mode, domains in (("denylist", ["example.com"]), ("allowlist", [])):
        got = _node(f"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = {{ providers: [provider('Contoso')] }};
changed({json.dumps(mode)}, {json.dumps(domains)});
confirmAnswer = false;
await saveAllSettings();
""")
        assert [c["message"] for c in got["confirms"]] == [ONE], mode
        assert got["sent"] == [], mode


def test_several_providers_are_named_together_with_what_each_does():
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = { providers: [
    provider('Contoso'),
    provider('Fabrikam', { sso_account_creation: 'invite_only', sso_link_by_email: true }),
    provider('Northwind', { sso_link_by_email: true })] };
changed('off', []);
confirmAnswer = false;
await saveAllSettings();
""")
    assert [c["message"] for c in got["confirms"]] == [
        "The single sign-on providers “Contoso”, “Fabrikam” and “Northwind” make accounts at a first sign-in or link "
        "accounts by email only because the sign-up allow-list on Accounts & Access says who may sign in through "
        "them. Saved this way, they stop making accounts at a first sign-in and linking accounts by email until they "
        "say who may sign in another way: Tenants, Domains or Required groups on their Access page, under Settings, "
        "Sign-in methods."]


def test_a_provider_that_only_links_by_email_is_said_to_link():
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = { providers: [
    provider('Fabrikam', { sso_account_creation: 'invite_only', sso_link_by_email: true })] };
changed('off', []);
confirmAnswer = false;
await saveAllSettings();
""")
    assert [c["message"] for c in got["confirms"]] == [
        "The single sign-on provider “Fabrikam” links accounts by email only because the sign-up allow-list on "
        "Accounts & Access says who may sign in through it. Saved this way, it stops linking accounts by email until "
        "it says who may sign in another way: Tenants, Domains or Required groups on its Access page, under Settings, "
        "Sign-in methods."]


def test_no_provider_relying_on_the_list_saves_without_asking():
    """Off, unticked, invite-only without linking, or with a rule of its own: none of them depends on the list."""
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = { providers: [
    provider('Off', {}, 'disabled'),
    provider('Draft', {}, 'draft'),
    provider('Unticked', { sso_use_signup_domains: false }),
    provider('Invited', { sso_account_creation: 'invite_only' }),
    provider('Tenant', { sso_allowed_tenants: ['t-1'] }),
    provider('Domain', { sso_allowed_domains: ['example.com'] }),
    provider('Group', { sso_required_groups: ['staff'] })] };
changed('off', []);
await saveAllSettings();
""")
    assert PROVIDERS_ASKED in got["asked"]
    assert got["confirms"] == []
    assert got["sent"] == [["off", []]]



def test_providers_that_cannot_be_read_do_not_stop_the_save():
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = new Error('Forbidden');
changed('off', []);
await saveAllSettings();
""")
    assert got["confirms"] == []
    assert got["sent"] == [["off", []]]


def test_a_save_that_keeps_an_allow_list_or_had_none_asks_nothing():
    for before, after in ((("allowlist", ["example.com"]), ("allowlist", ["example.org"])),
                          (("off", []), ("off", [])),
                          (("denylist", ["example.com"]), ("off", [])),
                          (("allowlist", []), ("off", []))):
        got = _node(f"""
loaded({json.dumps(before[0])}, {json.dumps(before[1])});
answers[PROVIDERS] = {{ providers: [provider('Contoso')] }};
changed({json.dumps(after[0])}, {json.dumps(after[1])});
await saveAllSettings();
""")
        assert PROVIDERS_ASKED not in got["asked"], (before, after)
        assert got["confirms"] == [], (before, after)
        assert got["sent"] == [[after[0], after[1]]], (before, after)


def test_after_a_save_the_list_saved_is_the_one_compared():
    """Once the list is saved as off, a later save of other settings does not ask again."""
    got = _node(r"""
loaded('allowlist', ['example.com']);
answers[PROVIDERS] = { providers: [provider('Contoso')] };
changed('off', []);
await saveAllSettings();
await saveAllSettings();
""")
    assert len(got["confirms"]) == 1
    assert got["sent"] == [["off", []], ["off", []]]


def test_the_domain_lists_help_says_a_provider_can_be_held_to_it():
    html = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
    start = html.index('<div data-setting="signup_domain_mode"')
    field = html[start:html.index("</div>", start)]
    help_text = re.search(r'<p class="text-secondary text-sm mt-sm">([^<]*)</p>', field).group(1)
    assert help_text == (
        "Restrict which email domains may sign up or accept an invitation. A single sign-on provider with “Also hold "
        "people to the sign-up domain list” ticked is held to it too; for such a provider only an allow-list with a "
        "domain on it counts as saying who may sign in.")
