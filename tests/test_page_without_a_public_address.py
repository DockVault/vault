"""What the page says when this server has no public address (ALLOWED_HOSTS), run as shipped under Node.

CI sets the address, so its UI tests take the address-set branch only. These run the page's own functions with a
stand-in document, both ways: the Settings note beside the reset switch, the invitation dialog's sentence before
anything is sent, and the result step's "It was not emailed".
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
PAGE = (ROOT / "static" / "index.html").read_text(encoding="utf-8")

NO_ADDRESS = "this server’s public address (ALLOWED_HOSTS)"

_HARNESS = """
const els = {};
const document = { getElementById(id) {
    if (!(id in els)) els[id] = { id, style: {}, textContent: '', value: '', checked: false, disabled: false };
    return els[id];
} };
const window = { location: { origin: 'https://vault.lan' } };
let currentSettings = {};
let accountsSmtpConfigured = false;
let accountsPublicAddress = true;
const formatServerTime = t => t;
function renderLoginIdentifierWarning() {}
function updateAccountsSummary() {}
"""


def _function(name: str) -> str:
    start = APP.index(f"function {name}(")
    return APP[start:APP.index("\n}\n", start) + 3]


def _run(body: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = _HARNESS + "".join(_function(n) for n in (
        "_linkFromThisPage", "updateInviteSendNote", "showInviteLink", "refreshAccountsPolicyUI")) + body
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stderr
    return json.loads(done.stdout)


@pytest.mark.parametrize("smtp, address, says", [
    (True, False, "Emailed links need " + NO_ADDRESS + ", which is not set, so you copy the invitation link"),
    (True, True, "The invitation will be emailed to ann@example.com."),
    (True, None, "The invitation will be emailed to ann@example.com."),     # a server that does not say
    (False, False, "Email is not set up here"),
    (False, True, "Email is not set up here"),
])
def test_the_invitation_dialog_says_before_sending_whether_it_is_emailed(smtp, address, says):
    settings = {"smtp_configured": smtp, **({} if address is None else {"public_address_configured": address})}
    got = _run(f"""
currentSettings = {json.dumps(settings)};
document.getElementById('invite-email').value = 'ann@example.com';
updateInviteSendNote();
process.stdout.write(JSON.stringify(document.getElementById('invite-send-note').textContent));""")
    assert got.startswith(says), got
    assert (NO_ADDRESS in got) == (smtp and address is False), got


@pytest.mark.parametrize("res, says", [
    ({"email": "ann@example.com", "email_sent": False, "public_address_configured": False},
     " It was not emailed: emailed links need " + NO_ADDRESS + ", which is not set. Copy the link above"),
    ({"email": "ann@example.com", "email_sent": False, "public_address_configured": True},
     " We couldn’t email it"),
    ({"email": "ann@example.com", "email_sent": False}, " We couldn’t email it"),
    ({"email": "ann@example.com", "email_sent": True, "public_address_configured": True},
     " We emailed the invitation to ann@example.com."),
])
def test_the_invitation_result_says_why_it_was_not_emailed(res, says):
    res = {"invite_url": "/?invite=abc", "token": "abc", "expires_at": "tomorrow", **res}
    got = _run(f"""
showInviteLink({json.dumps(res)}, null);
process.stdout.write(JSON.stringify([document.getElementById('invite-link-expiry').textContent,
                                     document.getElementById('invite-link-value').textContent]));""")
    assert got[0].startswith("This link expires tomorrow." + says), got
    assert (NO_ADDRESS in got[0]) == (res.get("public_address_configured") is False), got
    assert got[1] == "https://vault.lan/?invite=abc"


@pytest.mark.parametrize("address, reset_on, display, says", [
    (False, False, "", "No reset email is sent while " + NO_ADDRESS + " is not set"),
    (False, True, "", "This is on, but no reset email is sent: " + NO_ADDRESS + " is not set"),
    (True, True, "none", None),
    (True, False, "none", None),
])
def test_the_reset_switch_says_exactly_when_no_address_is_set(address, reset_on, display, says):
    got = _run(f"""
accountsPublicAddress = {json.dumps(address)};
document.getElementById('setting-password-reset-enabled').checked = {json.dumps(reset_on)};
refreshAccountsPolicyUI();
const note = document.getElementById('password-reset-address-note');
process.stdout.write(JSON.stringify([note.style.display, note.textContent]));""")
    assert got[0] == display, got
    if says:
        assert got[1].startswith(says) and "Set it in .env (python dockvault.py setup sets it)" in got[1], got


def test_the_page_reads_the_flag_and_has_the_places_it_writes_to():
    assert "accountsPublicAddress = settings.public_address_configured !== false;" in APP
    for element in ('id="password-reset-address-note"', 'id="invite-send-note"', 'id="invite-link-expiry"'):
        assert element in PAGE, element
