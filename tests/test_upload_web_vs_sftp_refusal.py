"""Source pins for the web-vs-SFTP same-name upload guard and the client whole-file upload refusal.

The web upload init consults the in-flight SFTP upload marker and refuses a name a live SFTP upload
is streaming into the same (vault, folder) -- the mirror of the SFTP-side same-name lock -- for
standard vaults only (SFTP never serves zero-knowledge, and a ZK name is server-invisible), best-effort
and fail-open. The client refuses a legacy-ZK whole-file encrypt above the in-memory threshold rather
than reading a multi-GB file into the tab. The live behaviour is the live lane.
"""
import json
import re
import shutil
import subprocess
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


# The guard is pinned as ONE exact string -- the call, the `=== 'refuse'` comparison, and the three
# arguments in their exact order. Looser checks pass against an inverted comparison (`!== 'refuse'`
# seals over-threshold files), a swapped argument order (refuse when the threshold exceeds the file),
# a shadow threshold, a different sink source, or an inlined literal that leaves the helper dead.
_UPLOAD_GUARD_CALL = (
    "if (zkUploadDecision(entry.file.size, state.downloadSink, MAX_BUFFERED_DOWNLOAD_BYTES) "
    "=== 'refuse') {")


def _zk_upload_decision_src(js: str) -> str:
    # The whole pure helper, body and all. Its body has no braces (one return), so a non-greedy
    # brace-free match lands on exactly this function.
    m = re.search(r"function zkUploadDecision\([^)]*\)\s*\{[^{}]*\}", js)
    assert m, "zkUploadDecision() not found in app.js"
    return m.group(0)


def _upload_files_src(js: str) -> str:
    start = js.index("async function uploadFiles(files) {")
    return js[start:js.index("function setupFileDragDrop(", start)]


def test_the_v2_zk_upload_refuses_over_threshold_before_encrypting_when_buffered():
    # With the v2 content writer on, a file that could not be DOWNLOADED here must not be created
    # here: the pure decision refuses when the uploader's context cannot stream and the file is over
    # the ceiling, it refuses BEFORE any encryption, and it does so PER ENTRY without abandoning the
    # batch.
    js = APPJS.read_text(encoding="utf-8")
    start = js.index("if (lib.ZK_CONTENT_WRITE_V2) {")
    # Cut at the legacy branch's OWN comment, before stripping comments, so the legacy refusal is not
    # inside the v2 slice and cannot satisfy this pin for it.
    end = js.index("// The legacy writer takes the whole plaintext", start)
    v2 = _strip_line_comments(js[start:end])
    # The exact guard call, exactly once (an inverted comparison, a swapped arg order, a shadow
    # threshold or an inlined literal is no longer this string), and only one call to the helper.
    assert v2.count(_UPLOAD_GUARD_CALL) == 1, "the exact over-threshold guard call is not present exactly once"
    assert v2.count("zkUploadDecision(") == 1, "more than one call to the decision helper in the v2 branch"
    guard_at = v2.index(_UPLOAD_GUARD_CALL)
    guard_end = guard_at + len(_UPLOAD_GUARD_CALL)
    # Refuses BEFORE encryption.
    assert "encryptBlobV2(" not in v2[:guard_at], "encryption is reached before the refusal guard"
    # The per-entry exit is `continue;`, NOT `return;` (a return abandons the whole batch, discarding
    # files already sealed), and it comes before the writer call.
    continue_at = v2.index("continue;", guard_end)
    writer_at = v2.index("encryptBlobV2(")
    assert continue_at < writer_at, "the per-entry refusal must `continue` before encryptBlobV2"
    guard_block = v2[guard_at:continue_at]
    assert "return;" not in guard_block, "the guard exits with `return;` -- that abandons the batch"
    # It RECORDS the refusal and never touches the array the for-of is walking (a splice would skip
    # the next entry and leave it unsealed in the batch).
    assert "refused.add(entry)" in guard_block, "the guard does not record the refusal"
    assert "toUpload" not in guard_block, "the guard writes to the batch it is walking"
    # The distinct unresolved-policy wording is still present.
    assert "state.downloadSink === undefined" in v2


def test_the_zk_upload_decision_is_a_pure_parameter_only_predicate():
    # The decision reads ONLY its parameters -- never `state` or a module constant -- so the binding
    # the call site passes is what the pin and a reviewer see, and a later change that reads state
    # internally reds here. (mutation: `false &&`, a reversed comparison, or a hard-coded threshold
    # inside the helper -> red, on this pin and on the table below.)
    body = _strip_line_comments(_zk_upload_decision_src(APPJS.read_text(encoding="utf-8")))
    # The WHOLE return, exactly -- not the condition as a substring, which `false &&` and a reversed
    # comparison both leave intact. This is the shape the table exercises.
    assert "return (sink !== 'streaming' && size > threshold) ? 'refuse' : 'seal';" in body, (
        "the decision predicate changed shape")
    assert "state" not in body, "the decision reads global state instead of its arguments"
    assert "MAX_BUFFERED_DOWNLOAD_BYTES" not in body, "the decision hard-codes the threshold instead of taking it"


def test_the_zk_upload_decision_table():
    # The pure function's truth table, run offline. Extracted from the shipped source and evaluated
    # under Node, so a mutation to its body reds here as well as on the source pin.
    node = shutil.which("node")
    assert node, "Node is required: the decision must not be skipped"
    fn = _zk_upload_decision_src(APPJS.read_text(encoding="utf-8"))
    harness = fn + """
const T = 268435456;   // 256 MiB, the shipped threshold value (the function takes it as an argument)
const cases = {
    'undefined-over': zkUploadDecision(T + 1, undefined, T),
    'buffered-over':  zkUploadDecision(T + 1, 'buffered', T),
    'streaming-over': zkUploadDecision(T + 1, 'streaming', T),
    'streaming-huge': zkUploadDecision(T * 100, 'streaming', T),
    'buffered-under': zkUploadDecision(T - 1, 'buffered', T),
    'buffered-at':    zkUploadDecision(T, 'buffered', T),
    'undefined-under': zkUploadDecision(1, undefined, T),
    'nan-buffered':   zkUploadDecision(NaN, 'buffered', T),
    'null-over':      zkUploadDecision(T + 1, null, T),
};
process.stdout.write(JSON.stringify(cases));
"""
    done = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    r = json.loads(done.stdout)
    assert r["undefined-over"] == "refuse"          # sink not resolved -> not 'streaming' -> refuse
    assert r["buffered-over"] == "refuse"
    assert r["streaming-over"] == "seal"            # 'streaming' never refuses, at any size
    assert r["streaming-huge"] == "seal"
    assert r["buffered-under"] == "seal"
    assert r["buffered-at"] == "seal"               # strictly greater-than: a file exactly at the ceiling fits
    assert r["undefined-under"] == "seal"
    # NaN > T is false -> 'seal' here; the writer's own safe-integer check (ecc_crypto.js ~:2206)
    # then refuses a non-finite size with INVALID_INPUT, so this is not a hole.
    assert r["nan-buffered"] == "seal"
    assert r["null-over"] == "refuse"               # null !== 'streaming' -> refuse


def test_a_refused_entry_and_its_destructive_steps_are_dropped_before_the_enqueue():
    # The refusal record is enacted ONCE, after the seal loop and before the single enqueue, keyed by
    # ENTRY IDENTITY: refused entries leave toUpload, their overwrite deletes leave toDelete, and
    # their in-flight cancels are pruned from cancelVictims. Order: filter -> cancels -> deletes ->
    # enqueue, so nothing destructive runs before the batch is sealed-and-filtered and the enqueue is
    # last.
    code = _strip_line_comments(_upload_files_src(APPJS.read_text(encoding="utf-8")))
    assert "toUpload = toUpload.filter(e => !refused.has(e))" in code, "refused entries are not removed from the batch"
    assert "toDelete = toDelete.filter(t => !refused.has(t.entry))" in code, "a refused overwrite's delete is not dropped by entry"
    assert "cancelVictims.filter(v => !refused.has(v.entry))" in code, "a refused replacement's in-flight cancel is not pruned by entry"
    seal_loop = code[code.index("for (const entry of toUpload)"):
                     code.index("toUpload = toUpload.filter(e => !refused.has(e))")]
    assert ".splice(" not in seal_loop, "the seal loop splices the array it is walking"
    filter_at = code.index("toUpload = toUpload.filter(e => !refused.has(e))")
    cancel_at = code.index("uploadManager.cancel(v.itemId)")
    delete_at = code.index("/files/${target.id}/delete")
    enqueue_at = code.index("uploadManager.enqueueNamed(toUpload)")
    assert filter_at < cancel_at < delete_at < enqueue_at, (
        "destructive steps must run after the refusal filter and before the single enqueue")


def test_destructive_steps_are_keyed_by_entry_identity_not_name():
    # One drop can carry two files of the same name (both take the overwrite branch over one committed
    # original). Keying the refusal / stuck filters by NAME would drop both originals' steps while a
    # replacement still uploaded -- two rows under one name in a vault whose names the server cannot
    # see. Every destructive record carries its ENTRY and is filtered by identity.
    # (mutation: filter toDelete or the stuck set by `.name` -> red.)
    code = _strip_line_comments(_upload_files_src(APPJS.read_text(encoding="utf-8")))
    assert "toDelete.push({ id, name: file.name, entry })" in code, "the overwrite delete is not tied to its entry"
    assert "toCancelReq.push({ name: file.name, entry })" in code, "the in-flight cancel request is not tied to its entry"
    assert "toDelete = toDelete.filter(t => !refused.has(t.entry))" in code
    # The failed-delete 'stuck' set drops replacements by ENTRY too, not by name.
    assert "new Set(survived.map(t => t.entry))" in code, "the failed-delete stuck set is keyed by name, not entry"
    assert "toUpload.filter(e => !stuck.has(e))" in code


def test_in_flight_cancel_victims_are_resolved_before_sealing():
    # RACE (a): sealing is async, so a second drop of the same name can enqueue a NEW live item while
    # we seal. Resolving victims to item IDS (stable identities) happens BEFORE the seal loop; only
    # the cancel CALLS are deferred. A name-matched scan run after the loop would cancel that
    # bystander. (mutation: move the cancelVictims scan below the seal loop -> red.)
    code = _strip_line_comments(_upload_files_src(APPJS.read_text(encoding="utf-8")))
    scan_at = code.index("cancelVictims.push({ itemId: it.id")
    seal_at = code.index("for (const entry of toUpload)")
    call_at = code.index("uploadManager.cancel(v.itemId)")
    assert scan_at < seal_at, "the in-flight victim scan must resolve item ids before the seal loop"
    assert seal_at < call_at, "the cancel calls must be deferred until after sealing"


def test_a_victim_that_completed_during_sealing_drops_its_replacement():
    # RACE (b): a victim that finished while we sealed can no longer be cancelled without deleting a
    # file that already landed. Treat it like a failed overwrite delete -- drop that replacement so
    # both copies do not land. (mutation: drop the stuck handling -> a completed victim's replacement
    # stays in the batch -> red.)
    code = _strip_line_comments(_upload_files_src(APPJS.read_text(encoding="utf-8")))
    assert "if (!it || !_pendingUpload(it)) { cancelStuck.add(v.entry); continue; }" in code, (
        "a no-longer-pending victim is not detected")
    assert "catch (_) { cancelStuck.add(v.entry); }" in code, "a failed cancel is not treated as stuck"
    assert "toUpload = toUpload.filter(e => !cancelStuck.has(e))" in code, "stuck replacements are not dropped from the batch"


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


def test_the_buffered_download_threshold_is_one_declaration_pinned_to_256_mib():
    # One number governs every bounded-memory refusal: the v2 upload guard, the download pre-fetch
    # refusal, the two post-streaming-failure refusals, the final backstop and the legacy encrypt
    # refusal all read MAX_BUFFERED_DOWNLOAD_BYTES. Raising it reopens uploads-that-cannot-be-
    # downloaded and lets a buffered download pull gigabytes into the tab, and no other test notices.
    code = _strip_line_comments(APPJS.read_text(encoding="utf-8"))
    # Exactly one declaration -- a second, shadowing one inside a function could feed the guards a
    # different value. (mutation: add a shadow `const MAX_BUFFERED_DOWNLOAD_BYTES = ...` inside
    # _downloadFile -> count 2 -> red.)
    assert code.count("const MAX_BUFFERED_DOWNLOAD_BYTES") == 1, "shadow threshold declaration"
    # And its exact value, up to the semicolon so a trailing-comment edit cannot red it.
    # (mutation: multiply the value by 1024 -> the `* 1024;` breaks this substring -> red.)
    assert "const MAX_BUFFERED_DOWNLOAD_BYTES = 256 * 1024 * 1024;" in code


def test_the_state_literal_does_not_initialise_the_download_sink():
    # state.downloadSink is written once, by the boot policy read; leaving it uninitialised is what
    # makes a failed or not-yet-completed read fail CLOSED -- undefined !== 'streaming', so every
    # bounded-memory guard refuses until the real policy lands. An initialised default of 'streaming'
    # would fail OPEN: the guards would pass before the policy is known. The object-literal form
    # `downloadSink:` occurs nowhere today (the one write is `state.downloadSink = ...`, and the
    # server field is snake_case), so its absence is the pin. (mutation: add `downloadSink:
    # 'streaming',` to the state literal -> red.)
    code = _strip_line_comments(APPJS.read_text(encoding="utf-8"))
    assert "downloadSink:" not in code, (
        "the download sink is initialised as an object-literal field; a default defeats the "
        "fail-closed guard")
