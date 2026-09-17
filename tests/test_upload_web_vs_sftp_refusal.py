"""Source pins for the web-vs-SFTP same-name upload guard and the client whole-file upload refusal.

The web upload init consults the in-flight SFTP upload marker and refuses a name a live SFTP upload
is streaming into the same (vault, folder) -- the mirror of the SFTP-side same-name lock -- for
standard vaults only (SFTP never serves zero-knowledge, and a ZK name is server-invisible), best-effort
and fail-open. The client refuses a legacy-ZK whole-file encrypt above the in-memory threshold rather
than reading a multi-GB file into the tab. The live behaviour is the live lane.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
API = ROOT / "app" / "api" / "api_server.py"
APPJS = ROOT / "static" / "js" / "app.js"


def _init_upload_src():
    s = API.read_text(encoding="utf-8")
    start = s.index("async def init_chunked_upload(")
    return s[start:s.index("\n@app.", start)]


def test_web_upload_init_refuses_a_name_a_live_sftp_upload_holds():
    body = _init_upload_src()
    seg = body[body.index("WEB-vs-SFTP same-name guard"):]
    assert "upload_marker" in seg and "holder(vault_id, folder_uuid, body.file_name)" in seg
    # Standard vaults only, and only when a plaintext name is present.
    assert "if not is_zk and body.file_name:" in body
    # A live holder (str) -> 409 naming the member with the member-grade wording.
    assert "isinstance(_holder, str)" in seg
    assert "is currently being uploaded by" in seg
    assert "status.HTTP_409_CONFLICT" in seg


def test_the_guard_is_fail_open_and_member_grade():
    body = _init_upload_src()
    seg = body[body.index("WEB-vs-SFTP same-name guard"):]
    # holder() returns SKIPPED on an outage (not a str) -> the isinstance(str) refusal is skipped ->
    # the upload proceeds. The comment states fail-open; the code shape enforces it.
    assert "fail-OPEN" in seg
    # The member name falls back to the neutral "another member", never leaks more than the username.
    assert '"another member"' in seg
    assert 'getattr(_u, "username", None) or "another member"' in seg


def test_the_client_refuses_a_legacy_zk_whole_file_encrypt_above_the_threshold():
    js = APPJS.read_text(encoding="utf-8")
    # The legacy-ZK branch (no chunked writer) guards the whole-file read with the in-memory
    # threshold. (mutation: drop the size guard -> a multi-GB legacy-ZK upload reads the whole file.)
    legacy = js[js.index("The legacy writer takes the whole plaintext"):]
    legacy = legacy[:legacy.index("encryptFile(await entry.file.arrayBuffer()") + 60]
    assert "entry.file.size > MAX_BUFFERED_DOWNLOAD_BYTES" in legacy
    assert "too large to encrypt in this browser" in legacy
    assert "return;" in legacy   # refuses, does not proceed to the whole-file read
