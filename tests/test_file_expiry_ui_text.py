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
    lifted = _function(APP_JS, "function describeFileExpiry(vault) {")
    return _node(lifted + "\nconst cases = " + json.dumps(cases) + ";\n"
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
    assert "0 turns expiry off and removes the deadline from every file in the vault." in text
    assert "older than" not in INDEX.lower().split('id="set-expiry-modal"')[1].split("</form>")[0]
