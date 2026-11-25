"""Settings -> Sign-in as an administrator reads it (static/js/settings-signin.js): what the counts the server reads
mean under the rows they concern, and that a save which applies reads the page again for them; the alert while
direct attestation has no trust anchors; the note while 'Required for roles' names no role; and the accounts the
server's operator lifted the requirement for, listed as text. With the single sign-on card's address line
(static/js/settings-sso.js): what to change when the page was opened at another address than the vault's.

Driven in Node against the shipped script, on the small document of tests/js/mini_dom.js, with the server's answer
built from the passkey settings as they are registered (app/core/webauthn_settings.py).
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
SIGN_IN = ROOT / "static" / "js" / "settings-signin.js"

# The Sign-in tab's passkey card as static/index.html has it.
PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
// A textarea's rows is its height in lines (the small document knows only a table's rows).
const tableRows = Object.getOwnPropertyDescriptor(dom.Element.prototype, 'rows');
Object.defineProperty(dom.Element.prototype, 'rows', { configurable: true,
    get() { return this.localName === 'textarea' ? this._lines : tableRows.get.call(this); },
    set(value) { this._lines = value; } });
const tab =document.createElement('div'); tab.id = 'settings-tab-signin'; document.body.appendChild(tab);
const card = document.createElement('div'); card.id = 'signin-passkeys-card'; tab.appendChild(card);
const inner = document.createElement('div'); inner.className = 'p-lg'; card.appendChild(inner);
for (const [tag, id, hidden] of [['div', 'signin-passkey-readiness', true], ['p', 'signin-passkey-older', true],
                                 ['div', 'signin-passkey-settings', false]]) {
    const node = document.createElement(tag); node.id = id; node.hidden = hidden; inner.appendChild(node);
}
global.location = %(location)s;
var currentUser = { id: 'root-id', username: 'root', role: 'admin' };
const asked = [];
let answers = {};
global.apiRequest = async (path, options) => {
    asked.push({ path, method: (options || {}).method || 'GET', body: (options || {}).body });
    if (!Object.prototype.hasOwnProperty.call(answers, path)) throw new Error('Not arranged: ' + path);
    const answer = answers[path];
    return typeof answer === 'function' ? answer() : answer;
};
global.showToast = () => {};
const tick = () => new Promise((resolve) => setTimeout(resolve, 0));
const byId = (id) => document.getElementById(id);
const rowOf = (key) => document.querySelector(`#signin-passkey-settings [data-setting="${key}"]`);
const textOf = (node) => (node ? node.textContent : null);
const out = (value) => console.log(JSON.stringify(value));
"""

HERE = {"origin": "https://vault.example.test", "hostname": "vault.example.test", "protocol": "https:"}


def _answer(values=None, **changes):
    """The server's answer of GET /settings/sign-in for a vault where passkeys can be made at its address, with the
    values in force of ``values`` and the rest of the answer changed by ``changes``."""
    set_bare_api_env()
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as wss
    registry.all_specs()
    body = {"settings": registry.describe(wss.KEYS),
            "readiness": {"usable": True, "rp_id": HERE["hostname"], "origin": HERE["origin"], "reason": "ok"},
            "why_not": "", "requirement_paused": False, "unattested_passkeys": None,
            "passkeys_without_verification": 0, "accounts_with_only_such_passkeys": 0,
            "requirement_lifted_for": [], "accounts_with_only_a_passkey": 0, "administrators_with_only_a_passkey": 0,
            "trust_anchors": 0, "trust_anchors_problem": "WEBAUTHN_ATTESTATION_ROOTS is not set in .env",
            "step_up": wss.STEP_UP_ACTION}
    for row in body["settings"]:
        if row["key"] in (values or {}):
            row["value"] = values[row["key"]]
    body.update(changes)
    return body


def _node(scenario, location=None):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (PRELUDE % {"location": json.dumps(location or HERE)} + SIGN_IN.read_text(encoding="utf-8")
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _loaded(answer, then="", location=None):
    return _node("answers['/settings/sign-in'] = %s;\nawait window.SignInSettings.load();\n%s"
                 % (json.dumps(answer), then), location)


NOTES = r"""
out({ verify: textOf(rowOf('webauthn_require_uv').querySelector('.signin-setting-note')),
      mode: textOf(rowOf('webauthn_mode').querySelector('.signin-setting-note')),
      notes: document.querySelectorAll('#signin-passkey-settings .signin-setting-note').length });
"""


def test_the_rule_on_verifying_the_person_says_how_many_passkeys_never_did_and_what_it_does_to_them():
    got = _loaded(_answer({"webauthn_require_uv": True}, passkeys_without_verification=3,
                          accounts_with_only_such_passkeys=1), NOTES)
    assert got["verify"] == ("3 passkeys in use never checked a PIN, fingerprint or face: while this is on, they count "
                             "as no second factor and are refused at any use that does not check one. 1 account "
                             "holds no passkey that did: without an authenticator app, it sets a second factor up "
                             "again at its next sign-in.")
    got = _loaded(_answer({"webauthn_require_uv": False}, passkeys_without_verification=1,
                          accounts_with_only_such_passkeys=2), NOTES)
    assert got["verify"] == ("1 passkey in use never checked a PIN, fingerprint or face: turned on, this makes it "
                             "count as no second factor and refuses it at any use that does not check one; 2 accounts "
                             "hold no passkey that did.")


def test_the_passkeys_switch_says_how_many_accounts_have_a_passkey_as_their_only_second_factor():
    got = _loaded(_answer({"webauthn_mode": "optional"}, accounts_with_only_a_passkey=2,
                          administrators_with_only_a_passkey=1), NOTES)
    assert got["mode"] == ("2 accounts (1 of them an administrator) have a passkey as their only second factor. "
                           "With Passkeys set to Off, they set an authenticator app up at their next sign-in.")
    got = _loaded(_answer({"webauthn_mode": "off"}, accounts_with_only_a_passkey=1,
                          administrators_with_only_a_passkey=1), NOTES)
    assert got["mode"] == ("1 account (an administrator) had a passkey as its only second factor: it sets an "
                           "authenticator app up at its next sign-in, and the passkeys count again when passkeys are "
                           "turned back on.")


def test_nothing_is_said_under_the_rows_where_every_count_is_nought():
    got = _loaded(_answer({"webauthn_require_uv": True, "webauthn_mode": "optional"}), NOTES)
    assert got == {"verify": None, "mode": None, "notes": 0}


def test_a_save_that_applies_reads_the_page_again_and_leaves_the_other_rows_as_they_are():
    """The saved row is drawn from the save's answer; the page is read once more, and a count that changed is
    said; a row with an unsaved edit keeps it."""
    first = _answer({"webauthn_require_uv": True}, passkeys_without_verification=3)
    second = _answer({"webauthn_require_uv": False}, passkeys_without_verification=4)
    saved = next(row for row in second["settings"] if row["key"] == "webauthn_require_uv")
    got = _loaded(first, r"""
const grace = rowOf('webauthn_enrollment_grace_days').querySelector('input');
grace.value = '30';
answers['/settings/sign-in'] = %s;
answers['/settings/sign-in/webauthn_require_uv'] = { status: 'applied', setting: %s };
const box = rowOf('webauthn_require_uv').querySelector('input');
box.checked = false;
rowOf('webauthn_require_uv').dispatch('change');
rowOf('webauthn_require_uv').querySelector('button').click();
for (let i = 0; i < 10; i += 1) await tick();
out({ reads: asked.filter((a) => a.path === '/settings/sign-in' && a.method === 'GET').length,
      verify: textOf(rowOf('webauthn_require_uv').querySelector('.signin-setting-note')),
      grace: rowOf('webauthn_enrollment_grace_days').querySelector('input').value });
""" % (json.dumps(second), json.dumps(saved)))
    assert got["reads"] == 2
    assert got["verify"].startswith("4 passkeys in use never checked a PIN, fingerprint or face: turned on, ")
    assert got["grace"] == "30"


ANCHORS = r"""
const alert = byId('signin-passkey-anchors');
const ready = byId('signin-passkey-readiness');
out({ shown: !!alert && !alert.hidden, text: textOf(alert), role: alert ? alert.getAttribute('role') : null,
      after: !!alert && ready.nextElementSibling === alert, readiness: textOf(ready), kind: ready.className });
"""
DIRECT_WITHOUT_ANCHORS = ("Direct attestation is on, but the server finds no trust anchors: every passkey anyone "
                          "tries to add is refused, and the passkeys already added keep signing in. ")
WAYS_OUT = ("Point WEBAUTHN_ATTESTATION_ROOTS in .env at a readable PEM bundle of root certificates and restart the "
            "vault (python dockvault.py restart; a plain docker restart keeps the old .env), or set Attestation (an "
            "advanced setting) to None to let passkeys be added again.")


def test_direct_attestation_with_no_trust_anchors_is_said_with_the_reason_and_the_ways_out():
    """Every registration is refused then (attestation_unverifiable), while the address works: the line above the
    settings no longer says passkeys can be made there, and an alert under it says why none can be added."""
    got = _loaded(_answer({"webauthn_attestation": "direct", "webauthn_mode": "required_for_roles",
                           "webauthn_required_roles": ["admin"]}, trust_anchors=0, requirement_paused=False,
                          trust_anchors_problem="the server finds no file where WEBAUTHN_ATTESTATION_ROOTS points"),
                  ANCHORS)
    assert got["shown"] and got["role"] == "alert" and got["after"]
    assert got["text"] == (DIRECT_WITHOUT_ANCHORS + "The server finds no file where WEBAUTHN_ATTESTATION_ROOTS "
                           "points. " + WAYS_OUT + " The passkey requirement keeps running meanwhile: people in the "
                           "roles it names who hold no passkey are asked for one they cannot add.")
    assert got["readiness"] == ("Passkeys work at https://vault.example.test: those already added sign in there. "
                                "None can be added now (see below).")
    assert "alert-warning" in got["kind"]
    # No requirement on any role: nothing is said of one.
    got = _loaded(_answer({"webauthn_attestation": "direct", "webauthn_mode": "optional"}, trust_anchors=0,
                          trust_anchors_problem="WEBAUTHN_ATTESTATION_ROOTS is not set in .env"), ANCHORS)
    assert got["text"] == (DIRECT_WITHOUT_ANCHORS + "WEBAUTHN_ATTESTATION_ROOTS is not set in .env. " + WAYS_OUT)
    # Opened at another address than the vault's: passkeys are used there, and none can be added there either.
    got = _loaded(_answer({"webauthn_attestation": "direct"}, trust_anchors=0), ANCHORS,
                  location={"origin": "http://10.0.0.5:8200", "hostname": "10.0.0.5", "protocol": "http:"})
    assert "can be made" not in got["readiness"] and "None can be added now (see below)." in got["readiness"]


def test_the_anchors_alert_stays_away_while_there_are_anchors_or_attestation_is_not_direct():
    """...and while passkeys are off: none is added or used then, and the passkeys already added sign in nowhere."""
    for answer in (_answer({"webauthn_attestation": "direct"}, trust_anchors=1, trust_anchors_problem=None),
                   _answer({"webauthn_attestation": "none"}, trust_anchors=0),
                   _answer({"webauthn_attestation": "direct", "webauthn_mode": "off"}, trust_anchors=0)):
        got = _loaded(answer, ANCHORS)
        assert not got["shown"]
        assert got["readiness"].startswith("Passkeys can be made at https://vault.example.test")


ROLES_NOTE = r"""
const notes = rowOf('webauthn_mode').querySelectorAll('.signin-roles-note');
out({ notes: notes.length, text: notes.length ? notes[0].textContent : null,
      kind: notes.length ? notes[0].className : null });
"""


def test_required_for_roles_with_no_role_chosen_says_that_nobody_is_required():
    got = _loaded(_answer({"webauthn_mode": "required_for_roles", "webauthn_required_roles": []}), ROLES_NOTE)
    assert got["notes"] == 1 and "alert-warning" in got["kind"]
    assert got["text"] == ("No role is chosen under “Roles that must have a passkey”: nobody is required to "
                           "hold a passkey.")
    for values in ({"webauthn_mode": "required_for_roles", "webauthn_required_roles": ["user"]},
                   {"webauthn_mode": "optional", "webauthn_required_roles": []}):
        assert _loaded(_answer(values), ROLES_NOTE)["notes"] == 0


def test_the_note_on_no_role_and_the_counts_are_drawn_apart():
    """The counts under the switch are drawn again on each read; the note on the roles is its own, and neither
    takes the other away."""
    got = _loaded(_answer({"webauthn_mode": "required_for_roles", "webauthn_required_roles": []},
                          accounts_with_only_a_passkey=2), r"""
answers['/settings/sign-in/webauthn_enrollment_grace_days'] = { status: 'applied', setting: %s };
const grace = rowOf('webauthn_enrollment_grace_days');
grace.querySelector('input').value = '20';
grace.dispatch('input');
grace.querySelector('button').click();
for (let i = 0; i < 10; i += 1) await tick();
out({ roles: rowOf('webauthn_mode').querySelectorAll('.signin-roles-note').length,
      counts: rowOf('webauthn_mode').querySelectorAll('.signin-setting-note').length });
""" % json.dumps(next(row for row in _answer()["settings"] if row["key"] == "webauthn_enrollment_grace_days")))
    assert got == {"roles": 1, "counts": 1}


LIFTED = r"""
const box = byId('signin-passkey-lifted');
out({ shown: !!box && !box.hidden, text: textOf(box), said: box ? textOf(box.querySelector('p')) : null,
      items: box ? box.querySelectorAll('li').map((li) => li.textContent) : [],
      images: box ? box.querySelectorAll('img').length : 0,
      placed: !!box && byId('signin-passkey-settings').nextElementSibling === box });
"""


def test_the_accounts_the_requirement_was_lifted_for_are_listed_as_text_under_the_settings():
    got = _loaded(_answer(requirement_lifted_for=[
        {"username": "<img src=x onerror=alert(1)>", "role": "user", "lifted_at": "2026-11-20T10:00:00Z"},
        {"username": "bob", "role": "admin", "lifted_at": "2026-11-21T10:00:00Z"}]), LIFTED)
    assert got["shown"] and got["placed"] and got["images"] == 0
    assert got["said"] == ("The server's operator lifted the passkey requirement for 2 accounts: none of them is "
                           "asked for the passkey a role requires. It stays lifted for an account until the account "
                           "adds a passkey or its role changes, or until the operator puts it back (python "
                           "dockvault.py accounts, restore-passkey-requirement).")
    assert len(got["items"]) == 2
    assert got["items"][0].startswith("<img src=x onerror=alert(1)> (Users), since ") and "2026" in got["items"][0]
    assert got["items"][1].startswith("bob (Administrators), since ")


def test_the_list_of_lifted_accounts_says_when_it_shows_only_the_first_500_and_hides_when_empty():
    many = [{"username": "user%03d" % i, "role": "user", "lifted_at": "2026-11-20T10:00:00Z"} for i in range(500)]
    got = _loaded(_answer(requirement_lifted_for=many), LIFTED)
    assert got["said"].startswith("The server's operator lifted the passkey requirement for 500 accounts or more: ")
    assert got["said"].endswith(" The first 500 by name are listed.") and len(got["items"]) == 500
    got = _loaded(_answer(requirement_lifted_for=[
        {"username": "ann", "role": "external", "lifted_at": "2026-11-20T10:00:00Z"}]), LIFTED)
    assert got["said"].startswith("The server's operator lifted the passkey requirement for 1 account: it is not "
                                  "asked for the passkey a role requires.")
    assert got["items"][0].startswith("ann (External people), since ")
    assert not _loaded(_answer(), LIFTED)["shown"]


# --------------------------------------------------------------------------- opened at another address

SSO = ROOT / "static" / "js" / "settings-sso.js"
SSO_PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
for (const id of ['signin-sso-address', 'signin-sso-providers']) {
    const node = document.createElement('div'); node.id = id; document.body.appendChild(node);
}
const add = document.createElement('button'); add.id = 'signin-sso-add'; document.body.appendChild(add);
global.location = %(location)s;
var currentUser = { id: 'root-id', username: 'root', role: 'admin' };
global.apiRequest = async (path) => {
    if (path !== '/admin/sso/providers') throw new Error('Not arranged: ' + path);
    return { providers: [], presets: [], icons: ['generic'], limit: 20,
             address: { usable: true, base: 'https://vault.example.test' } };
};
global.showToast = () => {};
global._el = (tag, cls, text) => {
    const e = document.createElement(tag);
    if (cls) e.className = cls;
    if (text != null) e.textContent = text;
    return e;
};
"""

ELSEWHERE = {"usable": True, "rp_id": "vault.example.test", "origin": "https://vault.example.test", "reason": "ok"}
OPENED_AT = [
    ({"origin": "http://localhost:8200", "hostname": "localhost", "protocol": "http:"}, True),
    ({"origin": "https://vault.example.com:8443", "hostname": "vault.example.com", "protocol": "https:"}, True),
    ({"origin": "https://10.0.0.5:8443", "hostname": "10.0.0.5", "protocol": "https:"}, False),
    ({"origin": "https://[::1]:8443", "hostname": "[::1]", "protocol": "https:"}, False),
    ({"origin": "http://vault.lan:8200", "hostname": "vault.lan", "protocol": "http:"}, False),
]


def _fix(origin):
    return (f" If people open the vault at {origin}, put that address first in ALLOWED_HOSTS in .env and run python "
            "dockvault.py restart.")


@pytest.mark.parametrize("location, can_serve", OPENED_AT)
def test_the_passkey_line_opened_at_another_address_says_that_allowed_hosts_may_be_what_is_wrong(location, can_serve):
    """Passkeys are made at the first ALLOWED_HOSTS entry. Where the page's own address could carry them (a host
    name over https, or this computer by name), the vault may simply have the wrong address first: the line says how
    to put this one there. An address reached by IP, or plain http on another name, could not carry them."""
    got = _loaded(_answer(readiness=ELSEWHERE), "out(textOf(byId('signin-passkey-readiness')));", location)
    said = ("Passkeys can be made at https://vault.example.test, which is not the address this page was opened at "
            f"({location['origin']}). Open the vault there to add or use one: here the browser refuses.")
    assert got == said + (_fix(location["origin"]) if can_serve else "")
    # Also while no passkey can be added there.
    got = _loaded(_answer({"webauthn_attestation": "direct"}, readiness=ELSEWHERE, trust_anchors=0),
                  "out(textOf(byId('signin-passkey-readiness')));", location)
    assert got.endswith("None can be added now (see below)." + (_fix(location["origin"]) if can_serve else ""))


@pytest.mark.parametrize("location, can_serve", OPENED_AT)
def test_the_single_sign_on_line_opened_at_another_address_says_that_allowed_hosts_may_be_what_is_wrong(location,
                                                                                                      can_serve):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = (SSO_PRELUDE % {"location": json.dumps(location)} + SSO.read_text(encoding="utf-8")
              + "\n(async () => {\nawait window.SsoSettings.load();\n"
              + "console.log(JSON.stringify(document.getElementById('signin-sso-address').textContent));\n"
              + "})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    got = json.loads(done.stdout.strip().splitlines()[-1])
    said = ("Providers send people back to https://vault.example.test, which is not the address this page was opened "
            f"at ({location['origin']}). A sign-in, a link or a test started here does not come back here: open the "
            "vault there.")
    assert got == said + (_fix(location["origin"]) if can_serve else "")
