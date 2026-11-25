"""What a failed passkey ceremony shows (static/js/passkeys.js, cancelled and failureText).

The person cancelling, the browser's own timeout and a ceremony the page aborted show nothing. A browser that refuses
passkeys on a page whose certificate it does not trust (Chrome and Edge do, on a self-signed certificate that was
clicked through) reports that as a NotAllowedError too, naming the certificate. Taken as a cancel, adding a passkey,
setting one up at the sign-in, signing in with one and confirming it is you with one did nothing at all, and nothing
said why. Every caller shows failureText for what is not a cancel.

passkeys.js runs in Node, with the browser's DOMException.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
PASSKEYS_JS = ROOT / "static" / "js" / "passkeys.js"
APP_JS = ROOT / "static" / "js" / "app.js"

CERTIFICATE = ("Passkeys need this vault's certificate to be trusted by this browser. Ask whoever runs the vault for a "
               "certificate your browser trusts.")


def passkeys_node(scenario: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    script = ("global.window = global;\n" + PASSKEYS_JS.read_text(encoding="utf-8")
              + "\nconst out = (value) => console.log(JSON.stringify(value));\n"
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { console.error(e); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_a_ceremony_refused_for_the_certificate_is_no_cancel_and_says_why():
    got = passkeys_node(r"""
const errors = {
    certificate: new DOMException('WebAuthn is not supported on sites with TLS certificate errors.', 'NotAllowedError'),
    certificate_worded_otherwise: new DOMException('The page has a Certificate error.', 'NotAllowedError'),
    cancelled: new DOMException('The operation either timed out or was not allowed.', 'NotAllowedError'),
    no_words: new DOMException('', 'NotAllowedError'),
    aborted: new DOMException('signal is aborted without reason', 'AbortError'),
    other: new DOMException('Something else.', 'UnknownError'),
};
const seen = {};
for (const [name, error] of Object.entries(errors)) {
    seen[name] = { cancelled: Passkeys.cancelled(error), text: Passkeys.failureText(error) };
}
seen.nothing = { cancelled: Passkeys.cancelled(null), text: Passkeys.failureText(null) };
out(seen);
""")
    for name in ("certificate", "certificate_worded_otherwise"):
        assert got[name] == {"cancelled": False, "text": CERTIFICATE}, got[name]
    for name in ("cancelled", "no_words", "aborted"):
        assert got[name]["cancelled"] is True, got[name]
        assert got[name]["text"] != CERTIFICATE, got[name]
    assert got["other"] == {"cancelled": False, "text": "The passkey did not work. Try again."}
    assert got["nothing"] == {"cancelled": False, "text": "The passkey did not work. Try again."}


def test_every_caller_shows_the_sentence_for_what_is_not_a_cancel():
    """Adding a passkey, setting one up at the sign-in, the second factor and a step-up with a passkey, and the
    sign-in with a passkey: each shows failureText where cancelled says no."""
    js = APP_JS.read_text(encoding="utf-8")
    calls = [m.start() for m in re.finditer(r"Passkeys\.cancelled\(", js)]
    assert len(calls) >= 5, calls
    for at in calls:
        nearby = js[at:at + 200]
        assert "Passkeys.failureText(" in nearby, nearby
