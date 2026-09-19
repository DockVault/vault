"""Source pins for the web-vs-SFTP same-name upload guard and the client whole-file upload refusal.

The web upload init consults the in-flight SFTP upload marker and refuses a name a live SFTP upload
is streaming into the same (vault, folder) -- the mirror of the SFTP-side same-name lock -- for
standard vaults only (SFTP never serves zero-knowledge, and a ZK name is server-invisible), best-effort
and fail-open. The client refuses a legacy-ZK whole-file encrypt above the in-memory threshold rather
than reading a multi-GB file into the tab. The live behaviour is the live lane.
"""
import re
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


def _strip_line_comments(s: str) -> str:
    # Assert on CODE, not comments: the guard and closure carry comments that themselves discuss the
    # streaming sink and SFTP, so a raw search would pass on the prose even if the code regressed.
    return "\n".join(ln for ln in s.splitlines() if not ln.lstrip().startswith("//"))


def _zk_upload_block(js: str) -> str:
    start = js.index("if (lib.ZK_CONTENT_WRITE_V2) {")
    return js[start:js.index("entry.keyVersion = keyVersion;", start)]


def _refuse_download_closure(js: str) -> str:
    start = js.index("const _refuseTooLarge = () => {")
    # Ends just before the call site that invokes it; that boundary line is code, not a comment.
    return js[start:js.index("if (state.downloadSink !== 'streaming' && _fsize", start)]


# The whole guard, matched as one exact shape rather than as loose substrings. Two substrings pass
# against a dead guard (`if (false && <substrings>) {`) and against a reversed comparison whenever
# another line in the slice happens to spell `> MAX_BUFFERED_DOWNLOAD_BYTES` -- which the legacy
# branch's OWN refusal does. Matching the full `if (...) {` closes both, and the slice below stops
# before the legacy branch so its refusal cannot stand in for this one.
_UPLOAD_GUARD = re.compile(
    r"if \(state\.downloadSink !== 'streaming'\s*"
    r"&& entry\.file\.size > MAX_BUFFERED_DOWNLOAD_BYTES\) \{")


def test_the_v2_zk_upload_refuses_over_threshold_before_encrypting_when_buffered():
    # With the v2 content writer on, a file that could not be DOWNLOADED here must not be created
    # here: when the uploader's context cannot stream (state.downloadSink !== 'streaming'), an
    # over-threshold ZK upload is refused BEFORE any encryption, and a streaming sink is unrestricted.
    js = APPJS.read_text(encoding="utf-8")
    start = js.index("if (lib.ZK_CONTENT_WRITE_V2) {")
    # Cut at the legacy branch's OWN comment, BEFORE stripping comments, so the legacy refusal (which
    # also spells `> MAX_BUFFERED_DOWNLOAD_BYTES`) is not inside the v2 slice and cannot satisfy this
    # pin for it.
    end = js.index("// The legacy writer takes the whole plaintext", start)
    v2 = _strip_line_comments(js[start:end])
    # Exactly one guard, matched whole: a dead `false &&` guard or a reversed `<` comparison is no
    # longer this shape, so the count drops to zero. (mutation: `false &&` the guard -> 0 matches ->
    # red; reverse the comparison to `<` -> 0 matches -> red; drop the guard -> 0 matches -> red.)
    guards = list(_UPLOAD_GUARD.finditer(v2))
    assert len(guards) == 1, f"expected exactly one over-threshold guard in the v2 branch, found {len(guards)}"
    # Refuses BEFORE encryption: the guard's return follows it, and no encryptBlobV2 call precedes it.
    # (mutation: move the writer above the guard -> the ordering assert reds.)
    guard_end = guards[0].end()
    return_at = v2.index("return;", guard_end)
    writer_at = v2.index("encryptBlobV2(")
    assert return_at < writer_at, "the over-threshold refusal must return before encryptBlobV2"
    assert "encryptBlobV2(" not in v2[:guards[0].start()], "encryption is reached before the refusal guard"
    # A failed/slow policy read leaves the sink unresolved; that case gets its own retry wording
    # rather than blaming the browser.
    assert "state.downloadSink === undefined" in v2


def test_no_zero_knowledge_refusal_path_names_the_sftp_sync_path():
    # SFTP cannot serve a zero-knowledge vault, so no ZK refusal may send the user there.
    js = APPJS.read_text(encoding="utf-8")
    block = _strip_line_comments(_zk_upload_block(js))
    assert "SFTP" not in block, "a zero-knowledge upload refusal names the SFTP sync path"
    # The shared download refusal closure branches on the vault kind: the ZK ending names no SFTP;
    # the Standard ending still offers it. (mutation: drop the isZkVault branch -> the ZK arm carries
    # the SFTP tail -> red.)
    closure = _strip_line_comments(_refuse_download_closure(js))
    # The unresolved-sink branch (policy read failed / not yet landed) gets its own retry wording
    # instead of blaming the browser, the same as the upload twin. (mutation: delete this branch ->
    # red.)
    assert "state.downloadSink === undefined" in closure
    assert "isZkVault(state.currentVault)" in closure
    tail = closure[closure.index("isZkVault(state.currentVault)"):]
    zk_arm = tail[tail.index("?"):tail.index(":")]
    std_arm = tail[tail.index(":"):tail.index("showError", tail.index(":"))]
    assert "SFTP" not in zk_arm, "the zero-knowledge download refusal names SFTP"
    assert "SFTP" in std_arm, "the Standard download refusal no longer offers the SFTP path"
