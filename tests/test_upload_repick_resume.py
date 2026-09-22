"""A Standard-vault upload continued with a re-picked file verifies what the server holds.

The handle the user picks is not the file: the bytes can have been edited since the first attempt
while the size still matches. The run has had a check for exactly that -- every chunk the server
reports is held to the digest the server recorded when it arrived, and a chunk that no longer
matches is sent again -- but that check ran only for a row restored across a reload. The re-pick
path fetched the server's list itself and started with it, so a file edited to the same length was
spliced onto the previous attempt's chunks and committed with a 200: half old, half new, silently.

These tests drive the shipped ``_continueWith`` and ``_run`` in the Node harness, with a server that
holds two chunks and their digests, and a re-picked file whose second half differs. The chunk that
changed is sent again; the chunk that did not is not; an unedited file sends nothing and commits.
"""
import hashlib
import json

import pytest

pytestmark = pytest.mark.unit

from _js_source import strip_comments  # noqa: E402
from test_upload_tray_controls import APP_JS, _method, _serve  # noqa: E402

A, B, Z = b"AAAAAAAAAA", b"BBBBBBBBBB", b"ZZZZZZZZZZ"
SHA = {name: hashlib.sha256(chunk).hexdigest() for name, chunk in (("A", A), ("B", B), ("Z", Z))}


def _repick(second_half: bytes, held=(0, 1), digests=None) -> dict:
    digests = SHA if digests is None else digests
    return _serve("""
    globalThis.isZkVault = () => false;
    const crypto = require('crypto');
    globalThis.sha256Hex = async (buf) => crypto.createHash('sha256').update(Buffer.from(buf)).digest('hex');
    const CHUNK_SIZE = 10;
    const bytes = (s) => new TextEncoder().encode(s);
    // The row the tray shows for an interrupted Standard upload: its session is on the server,
    // its file is not in hand -- the user is asked to pick it again.
    const it = { id: 'r', order: 1, vaultId: 'V', folderId: null, sessionId: 'r-sess', fileName: 'edited.bin', file: null,
        isZk: false, totalSize: 20, totalChunks: 2, chunkSize: 10, received: new Set(), lastPut: null,
        status: 'needs-file', error: null, paused: false, cancelled: false, replaces: null };
    fresh(it);
    // What the server holds: both chunks, with the digests recorded when they arrived.
    server.held = { received_chunks: %s, bytes_received: 20,
        chunk_checksums: { 0: %s, 1: %s } };
    server.puts = [{ ok: true, status: 200, json: async () => ({ complete: true, bytes_received: 20 }) }];
    const picked = new Blob([bytes('AAAAAAAAAA'), bytes('%s')]);
    Object.defineProperty(picked, 'name', { value: 'edited.bin' });
    // The re-pick: what the file picker hands to the tray. `_start` queues the run; drive it.
    await um._continueWith(it, picked);
    await um.lastRun;
    out.log = log.slice(); out.status = it.status; out.error = it.error || null;
    out.changed = it.changedLocally || 0; out.received = [...it.received].sort();
    """ % (list(held), json.dumps(digests.get("A")), json.dumps(digests.get("B")), second_half.decode()), extra=("async _continueWith(it, file) {",))


def test_a_re_picked_file_edited_to_the_same_length_has_its_changed_chunk_sent_again():
    out = _repick(Z)
    # (mutation: `_continueWith` fetches the list itself and starts, as it used to -> no PUT, the
    #  server's chunk 1 (BBBB...) is committed under the edited file's name -> red.)
    puts = [e for e in out["log"] if e.startswith("PUT ")]
    assert puts == ["PUT /vaults/V/uploads/r-sess/chunks/1"], out["log"]
    assert out["changed"] == 1, out
    assert out["status"] == "done" and out["error"] is None, out
    assert "POST /vaults/V/uploads/r-sess/complete" in out["log"]


def test_a_re_picked_file_that_is_unchanged_sends_nothing_and_commits():
    out = _repick(B)
    assert not any(e.startswith("PUT ") for e in out["log"]), out["log"]
    assert out["changed"] == 0 and out["status"] == "done", out
    assert out["received"] == [0, 1]


def test_a_held_chunk_the_server_has_no_digest_for_is_sent_again_rather_than_trusted():
    # The degraded case: chunks stored before digests were recorded. Nothing can vouch for them,
    # so they go again -- both of them here, since neither has a digest.
    out = _repick(B, digests={})
    puts = sorted(e for e in out["log"] if e.startswith("PUT "))
    assert puts == ["PUT /vaults/V/uploads/r-sess/chunks/0", "PUT /vaults/V/uploads/r-sess/chunks/1"], out["log"]


def test_the_re_pick_path_defers_to_the_runs_check_instead_of_trusting_the_list():
    # Smoke alarm on comment-free code: the re-pick sets the flag the run's sync branch reads, and
    # no longer fetches the list on its own.
    js = APP_JS.read_text(encoding="utf-8")
    cont = strip_comments(_method(js, "async _continueWith(it, file) {"))
    assert "it.needsServerSync = true;" in cont and "fetch(" not in cont and "_send(" not in cont
    assert cont.index("it.needsServerSync = true;") < cont.index("this._start(it);")
    run = strip_comments(_method(js, "async _run(id) {"))
    assert run.index("} else if (it.needsServerSync) {") < run.index("chunk_checksums") < run.index("sha256Hex(")
