"""Send test on a sending profile asks for the step-up and sends the same test again, with no mail sink.

The test send (POST /email/profiles/test) is guarded like a save: the server answers 403 second_factor_required for
the action admin.mail_relay.write until the request carries a receipt (test_mail_relay_step_up.py holds the server
side). The page's own request code then asks the person to confirm it is them, and sends the same test once more with
the receipt; a person who cancels the prompt is told the test needs that confirmation, and nothing more is sent. The
browser test of the delivery needs a Mailpit sink; this one stops where the server answers, so it runs everywhere.

Driven in Node against the shipped functions of static/js/app.js (the form's own, and apiRequest with what it
calls), with the stand-ins of test_session_watch_refusals for the page and the server.
"""
import json

import pytest

from test_email_profile_password_refusal import _constant, _function
from test_session_told_renewal_and_retry import REQUESTS, _node

pytestmark = pytest.mark.unit

# The form, as shipped: the profile being edited, and what the test send reads and writes.
FORM = ("let _editingEmailProfileId = null;\n" + _constant("_SMTP_PASSWORD_REQUIRED")
        + "".join(_function(n) for n in ("openEmailProfileModal", "_emailProfilePasswordRefusal",
                                         "_emailProfileFailed", "_collectEmailProfileForm", "sendEmailProfileTest")))

ACTION = "admin.mail_relay.write"
SENT = "Test email sent to admin@example.test"

SCENARIO = r"""
// The page's elements, with what the form reads and writes on them.
const plain = document.getElementById;
document.getElementById = (id) => {
    const e = plain(id);
    if (!e.dataset) Object.assign(e, { value: '', checked: false, hidden: false, dataset: {},
        removeAttribute(k) { delete this.attrs[k]; }, getAttribute(k) { return k in this.attrs ? this.attrs[k] : null; },
        focus() {} });
    return e;
};
// The server: the step-up refusal first, then the answer to the test sent again with its receipt.
const json = (status, body) => ({ ...answer(status, body),
    headers: { get: (h) => (h.toLowerCase() === 'content-type' ? 'application/json' : null) } });
const requests = [];
let replies = [[403, { detail: { second_factor_required: true, action: ACTION, reason: 'step_up_required',
                                 methods: ['password'] } }],
               [200, { message: SENT }]];
globalThis.fetch = async (url, init) => {
    requests.push({ url, method: init.method, receipt: init.headers['X-Second-Factor'] || null,
                    body: JSON.parse(init.body) });
    const [status, body] = replies.shift();
    return json(status, body);
};
// The step-up prompt: what it was asked for, and the person's answer (a receipt, or null for Cancel).
const prompts = [];
globalThis.requestStepUpReceipt = async (action, methods) => { prompts.push({ action, methods }); return RECEIPT; };
vm.runInThisContext(FORM_SRC, { filename: 'app-email-form.js' });
openEmailProfileModal({ id: 'p-1', name: 'Relay', smtp_server: 'mail.example.test', smtp_port: 587,
                        smtp_username: 'relay-user', from_email: 'vault@example.test', has_password: true,
                        smtp_allow_insecure_tls: false });
await sendEmailProfileTest();
await settle();
out({ requests, prompts, result: document.getElementById('email-profile-result').textContent,
      disabled: document.getElementById('ep-send-test').disabled, signed_out: logouts });
"""


def _send(receipt):
    return _node(SCENARIO.replace("RECEIPT", json.dumps(receipt)).replace("FORM_SRC", json.dumps(FORM))
                 .replace("ACTION", json.dumps(ACTION)).replace("SENT", json.dumps(SENT)), REQUESTS)


BODY = {"profile_id": "p-1", "smtp_server": "mail.example.test", "smtp_port": 587, "smtp_username": "relay-user",
        "from_email": "vault@example.test", "from_name": "", "smtp_allow_insecure_tls": False}


def test_the_test_send_asks_for_the_step_up_and_sends_the_same_test_again_with_the_receipt():
    out = _send("receipt-1")
    assert out["prompts"] == [{"action": ACTION, "methods": ["password"]}]
    assert [(r["url"], r["method"], r["receipt"]) for r in out["requests"]] == [
        ("/email/profiles/test", "POST", None), ("/email/profiles/test", "POST", "receipt-1")]
    # The same test, and nothing saved: the stored password stays on the server (no password field is sent).
    assert out["requests"][0]["body"] == out["requests"][1]["body"] == BODY
    assert out["result"] == "✓ " + SENT and out["disabled"] is False and out["signed_out"] == 0


def test_a_cancelled_step_up_says_the_test_needs_it_and_sends_nothing_more():
    out = _send(None)
    assert out["prompts"] == [{"action": ACTION, "methods": ["password"]}]
    assert [r["receipt"] for r in out["requests"]] == [None]
    assert out["result"] == "✗ This action needs an extra confirmation."
    assert out["disabled"] is False and out["signed_out"] == 0
