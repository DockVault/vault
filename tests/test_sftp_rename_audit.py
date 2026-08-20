"""The SFTP rename handler must audit its mutation, like every other SFTP write.

SFTP is the temp-credential / contractor-facing surface for Standard vaults, and the audit trail's
whole purpose is to attribute what a handed-out credential actually did (the row carries the
credential id). Every other SFTP mutation records an audit row -- download, upload, delete,
folder-create, folder-delete -- and so does the REST rename twin (`action='file_rename'`). Rename
over SFTP silently did not: a credential scoped to `file.rename` could rename in-scope files and
folders with no trace, defeating attribution on exactly the surface the audit trail exists for.

Static, so a future edit cannot drop the audit again and cannot regress it in the offline lane
(the live proof is the SFTP integration suite; this is the guard that scales).
"""

import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_SRC = (
    Path(__file__).resolve().parent.parent / "app" / "sftp" / "sftp_server.py"
).read_text(encoding="utf-8")


def _method_body(name: str) -> str:
    """One method's source, from its `def` to the next method at the same (4-space) indent."""
    match = re.search(rf"\n    def {name}\(", _SRC)
    assert match, f"method {name} not found in sftp_server.py"
    start = match.start()
    nxt = re.search(r"\n    def ", _SRC[start + 1:])
    return _SRC[start:start + 1 + nxt.start()] if nxt else _SRC[start:]


def test_sftp_rename_audits_the_mutation():
    body = _method_body("rename")
    assert "self._audit(" in body, (
        "SFTP rename must emit an audit row like every other SFTP mutation"
    )
    # A file rename and a folder rename are distinct actions so _audit's resource_type
    # ("folder" if "folder" in action else "file") resolves correctly for each.
    assert '"file_rename"' in body
    assert '"folder_rename"' in body


def test_sftp_rename_audit_is_on_the_success_path():
    """The audit must fire after a successful rename and before SFTP_OK -- not on a failure path."""
    body = _method_body("rename")
    i_rename = body.index("rename_file(")
    i_audit = body.index("self._audit(")
    i_ok = body.rindex("SFTP_OK")
    assert i_rename < i_audit < i_ok, (
        "the audit call must come after rename_file and before the success return"
    )
