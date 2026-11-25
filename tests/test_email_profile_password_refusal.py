"""The sending-profile form says beside its password field when the server asks for the SMTP password again.

A save or a test send that would send the stored SMTP password to another server, port or username, or with the
certificate check turned off, is refused unless it carries the password (400, reason smtp_password_required,
app/core/mail_relay.py). The form shows that sentence beside the password field, marks the field and puts the
cursor in it; any other failure stays on the form's result line. Typing a password, opening the form again, a
later failure of another kind or a test send that goes through takes the sentence away. The test send tests the form as it shows it, the certificate check's box included.

Driven in Node against the shipped functions from static/js/app.js, with stand-ins for the page's elements and
for apiRequest. The step-up the save and the test send also ask for is answered inside apiRequest, as every
step-up is (test_mail_relay_step_up.py holds the server side).
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
APP_JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
INDEX = (ROOT / "static" / "index.html").read_text(encoding="utf-8")
SENTENCE = "Re-enter the SMTP password to use a different server, port or username, or to stop checking the server's certificate."
_SHIPPED = ("openEmailProfileModal", "closeEmailProfileModal", "_emailProfilePasswordRefusal", "_emailProfileFailed",
            "_collectEmailProfileForm", "saveEmailProfile", "sendEmailProfileTest")


def _function(name):
    for head in (f"\nasync function {name}(", f"\nfunction {name}("):
        if head in APP_JS:
            start = APP_JS.index(head) + 1
            return APP_JS[start:APP_JS.index("\n}\n", start) + 3]
    raise AssertionError(f"{name} is not in app.js")


def _constant(name):
    head = f"\nconst {name} = "
    start = APP_JS.index(head) + 1
    return APP_JS[start:APP_JS.index("\n", start) + 1]


STUBS = """
class Node {
    constructor(id) { this.id = id; this.value = ''; this.checked = false; this.textContent = ''; this.hidden = false;
                      this.disabled = false; this.attrs = {}; this.dataset = {}; this.style = {}; this.handlers = {};
                      const classes = new Set(); this.classList = { add: (c) => classes.add(c), remove: (c) => classes.delete(c),
                                                                  contains: (c) => classes.has(c) }; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    removeAttribute(k) { delete this.attrs[k]; }
    getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; }
    addEventListener(type, fn) { (this.handlers[type] = this.handlers[type] || []).push(fn); }
    focus() { focused = this.id; }
    set innerHTML(v) { throw new Error('innerHTML written on ' + this.id); }
}
let focused = null;
const nodes = {};
const document = { getElementById: (id) => (nodes[id] = nodes[id] || new Node(id)) };
const calls = [];
let ANSWER = null;          // what apiRequest does: a value to return, or an error to throw
const apiRequest = async (path, opts) => {
    calls.push({ path, method: opts.method, body: JSON.parse(opts.body) });
    if (ANSWER instanceof Error) throw ANSWER;
    return ANSWER;
};
const refusal = (message, status, reason) => Object.assign(new Error(message), { status, reason });
const loadEmailProfiles = async () => {};
const showSuccess = () => {};
let _editingEmailProfileId = null;
const field = (id) => document.getElementById(id);
const state = () => ({
    said: field('ep-password-error').textContent, hidden: field('ep-password-error').hidden,
    invalid: field('ep-password').getAttribute('aria-invalid'), focused,
    result: field('email-profile-result').textContent, open: field('email-profile-modal').classList.contains('active'),
});
const PROFILE = { id: 'p-1', name: 'Relay', smtp_server: 'mail.example.test', smtp_port: 587, smtp_username: 'relay-user',
                  from_email: 'vault@example.test', has_password: true, smtp_allow_insecure_tls: false };
"""


def _run(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the shipped page code must not be skipped"
    harness = (STUBS + _constant("_SMTP_PASSWORD_REQUIRED") + "".join(_function(n) for n in _SHIPPED)
               + "(async () => { const out = {};\n" + scenario + "\nprocess.stdout.write(JSON.stringify(out)); })()"
               + ".catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=harness, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


def test_the_page_has_a_place_beside_the_password_field_for_the_sentence():
    field = INDEX[INDEX.index('id="ep-password"') - 40:INDEX.index('id="ep-password-error"') + 80]
    assert 'aria-describedby="ep-password-hint ep-password-error"' in field
    assert '<small class="text-error" id="ep-password-error" role="alert" hidden></small>' in field


@pytest.mark.parametrize("action,path", [("saveEmailProfile", "/email/profiles/p-1"),
                                         ("sendEmailProfileTest", "/email/profiles/test")])
def test_the_refusal_is_shown_beside_the_password_field(action, path):
    out = _run(f"""
openEmailProfileModal(PROFILE);
field('ep-server').value = 'elsewhere.example';
ANSWER = refusal({json.dumps(SENTENCE)}, 400, 'smtp_password_required');
await {action}();
out.state = state();
out.path = calls[0].path;
""")
    assert out["path"] == path
    assert out["state"] == {"said": SENTENCE, "hidden": False, "invalid": "true", "focused": "ep-password",
                            "result": "", "open": True}


@pytest.mark.parametrize("action,fallback", [("saveEmailProfile", "Save failed"), ("sendEmailProfileTest", "Test failed")])
def test_any_other_failure_stays_on_the_result_line(action, fallback):
    out = _run(f"""
openEmailProfileModal(PROFILE);
ANSWER = refusal('From address must be a valid email address.', 400, undefined);
await {action}();
out.other = state();
ANSWER = refusal('', 502, undefined);
await {action}();
out.empty = state().result;
""")
    assert out["other"]["said"] == "" and out["other"]["hidden"] is True and out["other"]["invalid"] is None
    assert out["other"]["result"] == "✗ From address must be a valid email address."
    assert out["empty"] == f"✗ {fallback}"


def test_typing_a_password_or_opening_the_form_again_takes_the_sentence_away():
    out = _run(f"""
openEmailProfileModal(PROFILE);
ANSWER = refusal({json.dumps(SENTENCE)}, 400, 'smtp_password_required');
await saveEmailProfile();
field('ep-password').value = 'the-relay-password';
field('ep-password').handlers.input.forEach((fn) => fn());
out.typed = state();
await saveEmailProfile();
closeEmailProfileModal();
openEmailProfileModal(PROFILE);
out.reopened = state();
out.wired = field('ep-password').handlers.input.length;
""")
    for when in ("typed", "reopened"):
        assert out[when]["said"] == "" and out[when]["hidden"] is True and out[when]["invalid"] is None, out[when]
    assert out["wired"] == 1, "the form's password field is listened to once, however often it opens"


@pytest.mark.parametrize("action", ["saveEmailProfile", "sendEmailProfileTest"])
def test_a_later_failure_takes_the_sentence_away(action):
    out = _run(f"""
openEmailProfileModal(PROFILE);
field('ep-server').value = 'elsewhere.example';
ANSWER = refusal({json.dumps(SENTENCE)}, 400, 'smtp_password_required');
await {action}();
out.refused = state();
ANSWER = refusal('The mail server could not be reached.', 502, undefined);
await {action}();
out.failed = state();
""")
    assert out["refused"]["said"] == SENTENCE and out["refused"]["hidden"] is False
    assert out["failed"]["said"] == "" and out["failed"]["hidden"] is True and out["failed"]["invalid"] is None
    assert out["failed"]["result"] == "✗ The mail server could not be reached."


def test_a_test_send_that_goes_through_takes_the_sentence_away():
    # The administrator puts the server back instead of typing a password, and the test send goes through.
    out = _run(f"""
openEmailProfileModal(PROFILE);
field('ep-server').value = 'elsewhere.example';
ANSWER = refusal({json.dumps(SENTENCE)}, 400, 'smtp_password_required');
await sendEmailProfileTest();
out.refused = state();
field('ep-server').value = 'mail.example.test';
ANSWER = {{ message: 'Test email sent to ada@example.test' }};
await sendEmailProfileTest();
out.sent = state();
""")
    assert out["refused"]["said"] == SENTENCE and out["refused"]["hidden"] is False
    assert out["sent"]["said"] == "" and out["sent"]["hidden"] is True and out["sent"]["invalid"] is None
    assert out["sent"]["result"] == "✓ Test email sent to ada@example.test"


def test_the_test_send_tests_the_form_as_it_shows_it():
    out = _run("""
openEmailProfileModal(PROFILE);
field('ep-insecure-tls').checked = true;
ANSWER = { message: 'Test email sent to ada@example.test' };
await sendEmailProfileTest();
out.without = calls[0].body;
field('ep-password').value = 'the-relay-password';
await sendEmailProfileTest();
out.with = calls[1].body;
out.result = state().result;
""")
    assert out["without"] == {"profile_id": "p-1", "smtp_server": "mail.example.test", "smtp_port": 587,
                              "smtp_username": "relay-user", "from_email": "vault@example.test", "from_name": "",
                              "smtp_allow_insecure_tls": True}
    assert out["with"] == {**out["without"], "smtp_password": "the-relay-password"}
    assert out["result"] == "✓ Test email sent to ada@example.test"
