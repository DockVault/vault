"""What the web app says about a vault's file expiry is what the server does.

A deadline is stamped on each file at upload. Changing a vault's "expire files after" value does not
move a deadline a file already has; setting it to 0 turns expiry off and takes the deadline off every
file in the vault (tests/test_file_expiry_off.py). The dialog used to say "Files older than this will
be automatically deleted", which described neither, and the settings panel printed "30 days" for a
vault set to 30 minutes.

The panel text comes from ``describeFileExpiry`` in static/js/app.js, lifted verbatim into Node and
run here; the dialog's help text is static HTML.
"""
import html
import json
import re
from pathlib import Path

import pytest

from test_upload_guards_driven import _function
from test_upload_tray_controls import _node

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP_JS = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
INDEX = (ROOT / "static" / "index.html").read_text(encoding="utf-8")


def _describe(cases):
    lifted = "".join(_function(APP_JS, head) for head in (
        "function fileExpiryEnforced() {", "function fileExpiryNotEnforcedSuffix() {",
        "function describeFileExpiry(vault) {"))
    return _node("const state = {};\n" + lifted + "\nconst cases = " + json.dumps(cases) + ";\n"
                 "console.log(JSON.stringify(cases.map((v) => describeFileExpiry(v))));\n")


def test_the_panels_describe_new_uploads_in_the_unit_the_vault_uses():
    got = _describe([
        {"expire_files_after_days": 30, "expire_files_unit": "minutes"},
        {"expire_files_after_days": 1, "expire_files_unit": "hours"},
        {"expire_files_after_days": 7, "expire_files_unit": "days"},
        {"expire_files_after_days": 7},
        {"expire_files_after_days": None, "expire_files_unit": "days"},
        {"expire_files_after_days": 0, "expire_files_unit": "days"},
        None,
    ])
    assert got == ["30 minutes after upload", "1 hour after upload", "7 days after upload",
                   "7 days after upload", "Never", "Never", "Never"]


def test_both_panels_use_it():
    assert APP_JS.count("setText('info-file-expiration', describeFileExpiry(vault));") == 1
    assert APP_JS.count("expiryEl.textContent = describeFileExpiry(vault);") == 1


def _help_text():
    m = re.search(r'<small[^>]*id="expire-files-help"[^>]*>(.*?)</small>', INDEX, re.S)
    assert m, "the expiry dialog lost its help text"
    return " ".join(html.unescape(re.sub(r"<[^>]+>", "", m.group(1))).split())


def test_the_dialog_says_what_a_change_does_to_the_files_already_there():
    text = _help_text()
    assert "New files are deleted this long after upload." in text
    assert "Files already in the vault keep their current deadline." in text
    # Copy and a move between vaults upload the file afresh (tests/test_file_expiry_copy_move_live.py).
    assert "A copy, or a file moved in from another vault, counts as a new file from the moment it "            "arrives." in text
    assert "0 turns expiry off and removes the deadline from every file in the vault." in text
    assert "older than" not in INDEX.lower().split('id="set-expiry-modal"')[1].split("</form>")[0]


# ---------------------------------------------------------------------------------------------
# ENFORCE_FILE_EXPIRY=false: the web app must not promise a deletion that is not happening
# ---------------------------------------------------------------------------------------------

# The notes the interface shows beside a retention when this server is not deleting anything.
NOTES = {
    "expire-files-not-enforced": "showFileExpiryNotice('expire-files-not-enforced');\n"
                                 "                openModal('set-expiry-modal');",
    "rc-retention-not-enforced": "showFileExpiryNotice('rc-retention-not-enforced');\n"
                                 "    openModal('receiver-create-modal');",
    "rt-tag-retention-not-enforced": "showFileExpiryNotice('rt-tag-retention-not-enforced');\n"
                                     "    ed.style.display = '';",
}

HELPERS = ("function fileExpiryEnforced() {", "function fileExpiryNotEnforcedSuffix() {",
           "function showFileExpiryNotice(id) {", "function describeFileExpiry(vault) {")


def _run(scenario):
    lifted = "".join(_function(APP_JS, head) for head in HELPERS)
    return _node("""
const els = {};
const document = { getElementById: (id) => (els[id] = els[id] || { style: { display: 'none' } }) };
const state = {};
const out = {};
""" + lifted + scenario + "\nconsole.log(JSON.stringify(out));\n")


def test_every_retention_the_interface_shows_says_when_nothing_is_being_deleted():
    out = _run("""
const vault = { expire_files_after_days: 3, expire_files_unit: 'hours' };
for (const [key, flag] of [['unknown', undefined], ['on', true], ['off', false]]) {
    state.fileExpiryEnforced = flag;
    showFileExpiryNotice('note');
    out[key] = { panel: describeFileExpiry(vault), never: describeFileExpiry({}),
                 suffix: fileExpiryNotEnforcedSuffix(), note: els.note.style.display };
}
""")
    # Not known yet counts as enforced: the interface never says files are kept when they may not be.
    for key in ("unknown", "on"):
        assert out[key] == {"panel": "3 hours after upload", "never": "Never", "suffix": "",
                            "note": "none"}, key
    off = out["off"]
    assert off["panel"] == "3 hours after upload (not enforced on this server: no files are being deleted)"
    assert off["never"] == "Never", "a vault without expiry has nothing to qualify"
    assert off["suffix"] and off["note"] == "", "the note is shown"


def test_the_notes_exist_hidden_and_each_is_shown_where_it_is_needed():
    for note_id, opener in NOTES.items():
        m = re.search(r'<p [^>]*id="%s"[^>]*>(.*?)</p>' % note_id, INDEX, re.S)
        assert m, f"{note_id} is missing"
        assert 'style="display:none;"' in m.group(0), f"{note_id} must start hidden"
        assert "no files are being deleted" in m.group(1) or "uploads are not deleted" in m.group(1)
        assert APP_JS.count(opener) == 1, f"{note_id} is not shown when its dialog opens"
    # An upload link's details carry the same qualifier as a vault's panels.
    assert APP_JS.count("(r.retention_days + ' days' + fileExpiryNotEnforcedSuffix())") == 1


def test_the_flag_is_read_at_sign_in_with_the_rest_of_the_policy():
    assert APP_JS.count(
        "state.fileExpiryEnforced = !(zk && zk.file_expiry_enforced === false);") == 1
