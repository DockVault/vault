"""Source-pinned: a rename cannot land on a name a live upload is about to take.

The rename clash check queries COMMITTED File rows, so an in-flight upload (which has no row yet) is
invisible to it -- a rename onto that name would slip through and then collide at the upload's
commit. The rename now also consults the in-flight marker. Behaviour is proven in the live lane
(rename during a real upload); this pins the wiring, which can't run without the full DB.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

VS = Path(__file__).resolve().parents[1] / "app" / "services" / "vault_service.py"


def test_rename_consults_the_inflight_marker_after_the_committed_clash_check():
    s = VS.read_text(encoding="utf-8")
    # The in-flight refusal exists and sits AFTER a committed-row clash check (the marker closes the
    # window the committed-rows-only query cannot see).
    refuse = "is currently being uploaded in this location"
    assert refuse in s
    seg = s[s.index(refuse) - 500:s.index(refuse) + 100]
    assert "upload_marker" in seg
    assert "holder(file.vault_id, file.folder_id, new_name)" in seg
    assert "isinstance(" in seg  # a holder id (str) -> refuse; None/SKIPPED (free / outage) -> allow
    # It follows a committed-row clash raise, not replaces it.
    assert "already exists in this location" in s[:s.index(refuse)]
