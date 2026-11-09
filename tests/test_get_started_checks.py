"""The Get-started list's backup item says what it is, offline (static/js/dashboard-actions.js).

The vault keeps no record of backup runs: the item is ticked on the administrator's word, and its text says so
rather than claiming a backup was recorded.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

JS = (Path(__file__).resolve().parents[1] / "static" / "js" / "dashboard-actions.js").read_text(encoding="utf-8")


def _backup_entry() -> str:
    match = re.search(r"\{ key: 'backup',(.*?)\},\n", JS, re.S)
    assert match, "no backup item in the Get-started list"
    return match.group(1)


def test_the_backup_item_is_set_up_on_the_administrators_word():
    entry = _backup_entry()
    assert "label: 'Backups set up'" in entry
    assert "ackLabel: 'I have set up backups'" in entry
    hint = "".join(re.findall(r"'([^']*)'", entry[entry.index("hint:"):entry.index("ack:")]))
    assert "dockvault.py backup" in hint
    assert "DockVault cannot see backups taken on the host" in hint and "on your word" in hint
    assert "recorded" not in entry.replace("backup_recorded", "")
