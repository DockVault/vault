"""Source-pinned wiring of the in-flight upload markers into the WEB file listing.

The behaviour (a real SFTP upload's marker shows as an "uploading by <member>" row, scoped and
member-gated) is proven in the live and UI lanes against a running stack. This offline contract pins
the listing wiring that can't run without the full app + DB + Redis: the listing UNIONs markers for
Standard vaults only, gated by the same folder file-scope real files use, names the uploader only to
a member-grade viewer, is best-effort (empty on an outage), and the SPA renders the row disabled.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"
APPJS = ROOT / "static" / "js" / "app.js"


def _list_vault_files_src():
    s = API.read_text(encoding="utf-8")
    start = s.index("async def list_vault_files(")
    end = s.index("\ndef _member_grade_principal(", start)
    return s[start:end]


def test_the_listing_unions_markers_only_for_standard_vaults():
    body = _list_vault_files_src()
    union = body[body.index("In-flight upload markers"):]
    # Guarded to Standard vaults (SFTP never serves zero-knowledge), just after the comment block.
    assert "\n        if not is_zk:\n" in union, "the marker union must be guarded to Standard vaults"
    assert "upload_marker" in union and "list_folder(vault_id, folder_uuid)" in union
    # The final name is decrypted server-side (Standard filename key), bound to (vault, folder).
    assert "decrypt_upload_marker_name" in union and "_dec_marker(vault_id, folder_uuid" in union


def test_the_marker_rows_are_scope_gated_and_member_gated():
    body = _list_vault_files_src()
    union = body[body.index("In-flight upload markers"):]
    # A scoped principal sees a marker only where it may see this folder's files (folder in scope).
    assert "_folder_visible" in union and "id_in_scope" in union and "folder_ancestry(db, vault_id, folder_uuid)" in union
    # The listing is only reached with vault.see_files; a scoped principal that fails _folder_visible gets [].
    assert "if _folder_visible else []" in union
    # The uploader identity is revealed only to a member-grade principal, mirroring modified_by_name.
    assert "if _show_actor else None" in union
    # The row is flagged in_progress and carries no real file id (synthetic 'upload:' id).
    assert "'in_progress': True" in union
    assert "'upload:'" in union


def test_the_marker_union_is_best_effort_no_percentage():
    body = _list_vault_files_src()
    union = body[body.index("In-flight upload markers"):]
    assert "'size': 0" in union            # no percentage / size for an in-flight row
    # list_folder is the best-effort (guarded) call; a decrypt failure skips that one row.
    assert "continue" in union


def test_the_spa_renders_an_in_flight_row_disabled_and_unselectable():
    js = APPJS.read_text(encoding="utf-8")
    # Both the table and grid renderers short-circuit an in_progress row to a disabled render.
    assert js.count("if (item.in_progress) {") == 2
    assert "is-uploading" in js and "aria-disabled=\"true\"" in js
    assert "item.uploading_by" in js
    # In-flight rows are excluded from selection (synthetic id, no checkbox).
    assert js.count("!i.in_progress") == 2
