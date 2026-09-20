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
    # Refuses BEFORE encryption. The file is now sealed as it uploads, so this branch seals NOTHING:
    # no writer is called here at all, nothing is read, no whole ciphertext is built and no attempt
    # token is minted out here (the uploader's writer session mints it). What is left to order is
    # the hand-off to the uploader, which must come after the refusal's exit.
    for never in ("encryptBlobV2(", "startContentV2Encryption(", "encryptFile(", ".arrayBuffer(",
                  "new File(", "zkNewBlobId(", "entry.blobId"):
        assert never not in v2, f"the v2 upload branch still does work up front: {never}"
    # The per-entry exit is `continue;`, NOT `return;` (a return abandons the whole batch), and it
    # comes before the entry is handed to the uploader.
    continue_at = v2.index("continue;", guard_end)
    writer_at = v2.index("entry.zkPlain = {")
    assert v2.count("entry.zkPlain = {") == 1
    assert continue_at < writer_at, "the per-entry refusal must `continue` before the entry is handed on"
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


def _uploader_method(js: str, name: str) -> str:
    # One method of the upload manager, comment-stripped: from its definition to the next method at
    # the same indentation.
    start = js.index(f"    {name}(")
    m = re.search(r"\n    (?:async )?_?[A-Za-z]\w*\([^)]*\) \{\n", js[start + 1:])
    assert m, f"could not find the end of {name}"
    return _strip_line_comments(js[start:start + 1 + m.start()])


def test_upload_files_does_nothing_destructive_and_drops_a_refused_entry_before_the_enqueue():
    # DELIBERATE RE-PIN. This used to pin an ORDER inside uploadFiles (filter, then cancels, then
    # deletes, then the enqueue), because "ready" meant "sealed" and the batch was sealed up front.
    # Files are now sealed as they upload, so that order would pass while a transfer that died
    # halfway had already cost its original. The guarantee is restated per entry: uploadFiles does
    # NOTHING destructive at all -- each entry carries what it replaces, and the uploader fires it
    # for that entry alone (pinned below). What stays here is the smoke alarm.
    code = _strip_line_comments(_upload_files_src(APPJS.read_text(encoding="utf-8")))
    for destructive in ("/delete", "uploadManager.cancel(", ".cancel("):
        assert destructive not in code, f"uploadFiles performs a destructive step again: {destructive}"
    # The refusal record is enacted ONCE, after the loop and before the single enqueue, by entry
    # identity; the loop never splices the array it walks. (mutation: drop the filter, or move it
    # below the enqueue -> red; splice inside the loop -> red.)
    drop = "if (refused.size) toUpload = toUpload.filter(e => !refused.has(e));"
    assert code.count(drop) == 1, "refused entries are not removed from the batch exactly once"
    assert code.count("uploadManager.enqueueNamed(toUpload)") == 1
    assert code.index(drop) < code.index("uploadManager.enqueueNamed(toUpload)")
    seal_loop = code[code.index("for (const entry of toUpload) {\n                    const mime"):code.index(drop)]
    assert ".splice(" not in seal_loop, "the loop splices the array it is walking"


def test_what_an_entry_replaces_travels_on_the_entry_and_each_entry_resolves_its_own_victims():
    # One drop can carry two files of the same name. Anything keyed by NAME makes them share a
    # fate, so what an entry replaces is recorded on the entry object itself -- a refused entry is
    # never enqueued, and its destructive step leaves with it by construction.
    code = _strip_line_comments(_upload_files_src(APPJS.read_text(encoding="utf-8")))
    assert code.count("entry.replaces = id ? { deleteId: id } : { inFlightName: file.name };") == 1
    # Every entry resolves ALL the live uploads of its name, by item id, itself. Binding a victim to
    # the FIRST matching request (`find`) loses the second entry's cancel when the first is refused.
    # (mutation: restore a `find` that pairs one victim to one request -> red.)
    resolve = code[code.index("for (const entry of toUpload) {\n        if (!entry.replaces"):]
    resolve = resolve[:resolve.index("\n    }\n") + 6]
    assert "entry.replaces.cancelItemIds = [...uploadManager.items.values()]" in resolve
    assert ".filter(it =>" in resolve and ".map(it => it.id)" in resolve
    assert ".find(" not in resolve, "a victim is paired to a single request again"
    # RACE: ids are resolved BEFORE any async sealing work, so a later drop of the same name is never
    # mistaken for the upload the user chose to replace. (mutation: move the resolution below the
    # loop -> red.)
    assert code.index("entry.replaces.cancelItemIds =") < code.index("for (const entry of toUpload) {\n                    const mime")


def test_every_live_upload_of_the_name_is_a_victim_run_against_the_shipped_scan():
    # The textual pin above catches a `.find`, but not a truncation that keeps `.filter` (say
    # `.slice(0, 1)`): the ALL-matches property has to be shown, not spelled. So the shipped scan is
    # lifted out of uploadFiles verbatim, with the shipped pending-predicate, and run under Node over
    # a tray holding TWO live uploads of one name. Both must become victims of EVERY entry that
    # replaces that name -- and nothing else may: not another name, not a finished or cancelled
    # upload, not another vault or folder. (mutation: `.slice(0, 1)` -> red; `.find` -> red.)
    node = shutil.which("node")
    assert node, "Node is required: the victim scan must not be skipped"
    js = APPJS.read_text(encoding="utf-8")
    pending = re.search(r"const _pendingUpload = \(it\) => [^\n]*;", js)
    assert pending, "the pending-upload predicate moved"
    start = js.index("    for (const entry of toUpload) {\n        if (!entry.replaces || !entry.replaces.inFlightName) continue;")
    scan = js[start:js.index("\n    }\n", start) + 6]
    harness = """
const state = { currentVault: { id: 'V' } };
const _curFolder = null;
""" + pending.group(0) + """
const mk = (id, name, extra) => Object.assign(
    { id, vaultId: 'V', folderId: null, fileName: name, status: 'uploading', cancelled: false }, extra || {});
const uploadManager = { items: new Map([
    ['a', mk('a', 'X')], ['b', mk('b', 'X', { status: 'queued' })],   // two LIVE uploads of X
    ['c', mk('c', 'Y')],                                              // another name
    ['d', mk('d', 'X', { status: 'done' })],                          // finished
    ['e', mk('e', 'X', { status: 'error' })],                         // failed
    ['f', mk('f', 'X', { cancelled: true })],                         // cancelled
    ['g', mk('g', 'X', { vaultId: 'OTHER' })],                        // another vault
    ['h', mk('h', 'X', { folderId: 'F2' })],                          // another folder
]) };
const toUpload = [
    { name: 'X', replaces: { inFlightName: 'X' } },
    { name: 'X', replaces: { inFlightName: 'X' } },                   // a second entry of the same name
    { name: 'Z', replaces: { deleteId: '1' } },                       // replaces a committed row: no scan
    { name: 'Q' },                                                    // replaces nothing
];
""" + scan + """
process.stdout.write(JSON.stringify(
    toUpload.map(e => (e.replaces && e.replaces.cancelItemIds) ? e.replaces.cancelItemIds : null)));
"""
    done = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    first, second, committed, plain = json.loads(done.stdout)
    assert sorted(first) == ["a", "b"], f"not every live upload of the name is a victim: {first}"
    # The second entry of the same name resolves its OWN full list: refusing the first must not
    # cost the second its cancel.
    assert sorted(second) == ["a", "b"], second
    assert committed is None and plain is None


def test_the_destructive_step_fires_per_entry_only_when_the_server_holds_everything():
    # THE FIRE POINT. An original is deleted, and an in-flight upload cancelled, only when the server
    # holds EVERY chunk and exactly the declared bytes -- after the last chunk, before the commit.
    # (mutation: fire before the send loop -> red; fire after /complete -> red; drop the
    # holds-everything check -> red.)
    js = APPJS.read_text(encoding="utf-8")
    run = _uploader_method(js, "async _run")
    send_at = run.index("/chunks/${i}`")
    holds_at = run.index("if (!(await this._serverHoldsAll(it))) {")
    fire_at = run.index("if (!(await this._fireReplacement(it))) return;")
    complete_at = run.index("/complete`")
    assert send_at < holds_at < fire_at < complete_at, "the destructive step is not at the fire point"
    assert run.count("this._fireReplacement(it)") == 1 and js.count("this._fireReplacement(it)") == 1
    assert "if (it.replaces && !it.replacesFired) {" in run
    # "Holds everything" is the server's OWN count: every chunk, and exactly the declared bytes.
    holds = _uploader_method(js, "async _serverHoldsAll")
    assert "return !!s.complete && s.bytes_received === it.totalSize;" in holds


def test_a_dropped_replacement_names_the_file_and_says_what_did_not_happen():
    # Never a bare count, never silence: each message names the file, says which copy is on the
    # server now, and what did not happen. (mutation: a count-only toast -> red.)
    fire = _uploader_method(APPJS.read_text(encoding="utf-8"), "async _fireReplacement")
    messages = re.findall(r"_dropReplacement\(it, `(.*?)`\);", fire, re.S)
    # Three ways: the old file could not be removed, the earlier upload finished first, and the
    # earlier upload could not be cancelled (the server did not confirm it).
    assert len(messages) == 3, "expected one drop message per way a replacement can fail"
    for msg in messages:
        assert '"${name}"' in msg, f"a dropped replacement does not name the file: {msg}"
        assert "not uploaded" in msg, f"the message does not say what did not happen: {msg}"
        assert ".size" not in msg and ".length" not in msg, f"the message is a bare count: {msg}"
    # A victim that FINISHED FIRST is told apart from one that was cancelled (both leave the tray):
    # the landed set is the difference, and landing first drops the replacement, not the landed file.
    assert "if (this._landed.has(vid)) {" in fire
    assert fire.index("if (this._landed.has(vid)) {") < fire.index("if (!(await this.cancel(vid))) {")
    assert 'showInfo(`The earlier upload of "${name}" was cancelled and replaced by this one.`)' in fire


def test_a_file_sealed_as_it_uploads_has_no_raw_file_to_send_and_one_session_per_transfer():
    js = APPJS.read_text(encoding="utf-8")
    # FAIL CLOSED by construction: `file` is what the send loop slices and sends verbatim, and for a
    # sealed-as-it-uploads item the only handle there is is the PLAINTEXT -- so it is never put there.
    # (mutation: keep `file` for such an item -> red.)
    enqueue = _uploader_method(js, "enqueueNamed")
    assert "file: zkPlain ? null : file," in enqueue
    assert "zkPlain: zkPlain || null, zkPipelined: !!zkPlain, zkStream: null, frameMacs: null," in enqueue
    run = _uploader_method(js, "async _run")
    raw = run.index("const blob = it.file.slice(start, Math.min(start + it.chunkSize, it.file.size));")
    branch = run.index("if (it.zkPipelined) {\n")
    assert branch < run.index("} else {", branch) < raw, "the raw slice is not the non-pipelined branch"
    # ONE writer session per in-flight upload: opened when THAT transfer starts, never per file in
    # the drop, and only ever by STARTING an encryption (a continued one goes through the MAC-checked
    # reopen). (mutation: open sessions in uploadFiles -> red; let _openZkStream resume -> red.)
    assert js.count("startContentV2Encryption(") == 1
    opener = _uploader_method(js, "async _openZkStream")
    assert "it.zkStream = await lib.startContentV2Encryption(it.zkPlain.file, dek, ctx);" in opener
    assert "resumeContentV2Encryption(" not in opener
    assert opener.index("if (it.sessionId) {") < opener.index("startContentV2Encryption(")
    assert "if (it.zkPipelined && !it.zkStream) await this._openZkStream(it);" in run
    assert js.count("this._openZkStream(it)") == 1
    # The attempt token declared to the server IS the session's -- one mint, read once.
    assert "it.blobId = it.zkStream.blobId;" in opener
    # And the session ends with its transfer.
    assert "it.zkStream = null; it.zkPlain = null;" in run


def test_an_upload_chunk_is_sealed_whole_and_its_macs_are_on_disk_before_it_is_sent():
    js = APPJS.read_text(encoding="utf-8")
    run = _uploader_method(js, "async _run")
    # An UPLOAD CHUNK is the unit of sealing and re-sealing: sealed whole, in one call, every time it
    # is sent -- a retry never re-seals part of an index. sealFrame is called nowhere else.
    seal = "buf = await this._sealUploadChunk(it, i);"
    assert run.count(seal) == 1 and js.count("this._sealUploadChunk(") == 1
    assert js.count(".sealFrame(") == 1
    chunk = _uploader_method(js, "async _sealUploadChunk")
    assert "const [first, last] = zkUploadChunkFrames(index, it.zkStream.totalChunks, ZK_FRAMES_PER_UPLOAD_CHUNK);" in chunk
    assert "const parts = index === 0 ? [it.zkStream.header()] : [];" in chunk
    assert "for (let f = first; f < last; f++) {" in chunk and "it.frameMacs[f] = sealed.mac;" in chunk
    # ORDER: each frame's MAC is persisted BEFORE its bytes go out, so the server never holds a frame
    # the record cannot vouch for. (mutation: move the persist after the send -> red.)
    persist = "await this._persistResume(it);"
    assert run.count(persist) == 1
    assert run.index(seal) < run.index(persist) < run.index("/chunks/${i}`")


def test_a_continued_upload_rereads_every_held_frame_and_anything_unverified_is_a_new_attempt():
    reopen = _uploader_method(APPJS.read_text(encoding="utf-8"), "async _reopenPipelined")
    # The FULL stored record goes to the writer (state and MAC list together, from one record).
    assert "const st = it.zkResume;" in reopen
    assert "resumeContentV2Encryption(file, dek," in reopen and "dekEpoch: it.zkKeyVersion }, st);" in reopen
    # Every frame the SERVER holds is read again and held to its stored MAC; a held frame with NO
    # stored MAC is a MISMATCH, never a skip. (mutation: `if (want && ...)` -> a skip -> red.)
    assert "for (const index of held) {" in reopen
    assert "if (!want || (await session.frameMac(f)) !== want) {" in reopen
    # No list, a different size, a refused state or a changed frame: a NEW attempt, never a merge.
    assert "if (!st || !Array.isArray(st.frameMacs) || file.size !== st.totalPlaintext) {" in reopen
    assert reopen.count("this._restartAsNewAttempt(it, file)") == 3
    # And never a comparison of a freshly computed ciphertext digest with a stored one.
    assert "sha256Hex" not in reopen and "chunk_checksums" not in reopen
    restart = _uploader_method(APPJS.read_text(encoding="utf-8"), "async _restartAsNewAttempt")
    assert "method: 'DELETE'" in restart and "await zkUploadStore.delete(it.sessionId);" in restart
    assert "it.sessionId = null; it.zkResume = null; it.zkStream = null; it.frameMacs = null;" in restart


def test_upload_chunks_are_whole_frames_and_add_up_to_the_declared_length():
    # The alignment, run offline: every upload chunk is a whole number of sealed frames -- chunk 0
    # the 28-byte header plus frames, later chunks frames only, the last short -- and the chunks add
    # up to exactly the ciphertext length the session declares. (mutation: change the chunk size by
    # one byte -> red.)
    node = shutil.which("node")
    assert node, "Node is required: the upload plan must not be skipped"
    js = APPJS.read_text(encoding="utf-8")
    fns = []
    for name in ("zkUploadPlan", "zkUploadChunkFrames"):
        m = re.search(r"function " + name + r"\([^)]*\) \{.*?\n\}", js, re.S)
        assert m, name
        fns.append(m.group(0))
    m = re.search(r"const ZK_FRAMES_PER_UPLOAD_CHUNK = (\d+);", js)
    assert m and int(m.group(1)) == 4
    harness = "\n".join(fns) + """
const M = 4, CHUNK = 1048576, OVER = 28, HEADER = 28, FRAME = CHUNK + OVER;
const out = [];
for (const plain of [0, 1, CHUNK - 1, CHUNK, CHUNK + 1, 4 * CHUNK, 4 * CHUNK + 1, 9 * CHUNK + 123]) {
    const frames = Math.max(1, Math.ceil(plain / CHUNK));
    const cipher = HEADER + plain + OVER * frames;
    const plan = zkUploadPlan(FRAME, frames, cipher, M);
    let sum = 0, seen = 0; const lens = [];
    for (let i = 0; i < plan.totalChunks; i++) {
        const [first, last] = zkUploadChunkFrames(i, frames, M);
        let len = i === 0 ? HEADER : 0;
        for (let f = first; f < last; f++) len += OVER + (Math.min((f + 1) * CHUNK, plain) - f * CHUNK);
        seen += last - first; sum += len; lens.push(len);
    }
    out.push({ plain, plan, sum, cipher, seen, frames, lens });
}
process.stdout.write(JSON.stringify(out));
"""
    done = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    for row in json.loads(done.stdout):
        plan = row["plan"]
        assert plan["chunkSize"] == 4 * (1048576 + 28) == 4194416      # an exact multiple of one frame
        assert plan["totalSize"] == row["cipher"] == row["sum"], row   # the chunks ARE the declared file
        assert row["seen"] == row["frames"], row                        # every frame, exactly once
        lens = row["lens"]
        assert len(lens) == plan["totalChunks"]
        if len(lens) > 1:
            assert lens[0] == 4194416 + 28 == 4194444                   # chunk 0 carries the header too
            assert all(n == 4194416 for n in lens[1:-1])
            assert 0 < lens[-1] <= 4194416
    # And the uploader takes its declared shape from that plan, with the writer's own overhead.
    opener = _uploader_method(js, "async _openZkStream")
    assert "zkUploadPlan(it.zkStream.chunkSize + lib.V2_CONTENT_CHUNK_OVERHEAD," in opener
    assert "it.zkStream.totalChunks, it.zkStream.ciphertextLength, ZK_FRAMES_PER_UPLOAD_CHUNK);" in opener


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
