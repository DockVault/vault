"""An upload run does not outlive the account that started it.

``reset()`` runs at sign-out and used to clear the tray and bump an epoch -- and abort nothing. Every
request a run makes carries the LIVE token, the run first looked at its epoch only AFTER the fire
point and the commit, and the fire point's "does the server hold everything" answer is cached from
the last chunk. So a run whose last chunk was in flight when its account signed out went on: on a
shared tab, with the next member signed in before it resolved, it deleted the first account's
original UNDER THE SECOND ACCOUNT'S TOKEN, audited as them; with nobody signed in, it put a toast
naming the first account's file on the sign-in screen, and re-wrote that account's resume record
into a store that sign-out had just cleared.

Two things now stop it, and both are needed because each covers only half. Every request a run
makes is sent through one gate that refuses it when the account has changed -- that covers a request
not yet made. And each run has an AbortController that ``reset()`` aborts -- that covers a request
already on the wire, whose answer must not be acted on. Every toast on the run's path is gated the
same way. These tests drive the shipped send loop, fire point and cancel in the Node harness with a
real ``reset()`` in the middle, and assert what LEAVES: no request, no word, no record.
"""
import pytest

pytestmark = pytest.mark.unit

from test_upload_tray_controls import (  # noqa: E402
    _serve, COMPLETE, DEL_OLD, DEL_NEW, DEL_FILE, CANCELLED_ONLY, REPLACED,
)


def test_a_sign_out_before_the_fire_point_lets_no_delete_leave_and_says_nothing():
    # The earlier upload is finalising, so the fire point waits on a timer before cancelling it.
    # The account signs out during that wait. On the next turn nothing leaves: not the DELETE of
    # the earlier upload, not the delete of the original, not the commit -- and no toast.
    out = _serve("""
    fresh(victim({ status: 'completing' }), ours({ replaces: chose('F') }));
    const run = um._run('o'); await settle();
    out.beforeSignOut = snap();
    um.reset();                                   // the account signs out mid-wait
    flush(); await settle(); await run;
    out.after = snap();
    out.controllerAborted = !!(um._aborts.size === 0);
    """)
    b = out["beforeSignOut"]
    assert b["log"] == [], b                                  # still waiting: nothing has left yet
    a = out["after"]
    # (mutation: `withdrawn` no longer reads the epoch -> DEL_OLD, DEL_FILE and COMPLETE leave under
    #  the next account's token -> red.)
    assert a["log"] == [], "a signed-out run went on: %r" % a["log"]
    assert a["records"] == []
    # The tray is the next account's now: nothing of this run is written into it.
    assert a["o"] is None and a["v"] is None
    assert out["controllerAborted"] is True


def test_a_stale_run_at_the_fire_point_does_not_touch_the_next_accounts_rows():
    # The first account's run is waiting at the fire point when the account signs out; the next
    # account signs in and drops a file of the SAME NAME into the same folder. When the wait ends,
    # the stale run must not resolve that row as "an earlier upload to cancel": even with the
    # request refused, a cancel marks the row cancelled and then errored -- the next account's
    # upload wrecked by a run that was never theirs. It stops at the top of its turn instead.
    out = _serve("""
    fresh(victim({ status: 'completing' }), ours({ replaces: chose('F') }));
    const run = um._run('o'); await settle();
    um.reset();                                   // the first account signs out mid-wait
    // The next account's upload of the same name, in the same place, dropped BEFORE ours in its
    // tray's order -- everything the resolver needs to call it a rival.
    const theirs = sent('b', 'b-sess', { order: 1, replaces: null });
    um.items = new Map([['b', theirs]]);
    flush(); await settle(); await run;
    out.theirs = { status: theirs.status, cancelled: theirs.cancelled, paused: theirs.paused, error: theirs.error || null };
    out.log = log.slice();
    """)
    # Held by two things together: the fire point cancels only rows the user was SHOWN when they
    # answered (the next account's row never is), and every request behind that is refused by the
    # gate. The early read of the epoch in `withdrawn` is a third, and on its own it changes where
    # the run stops, not what leaves -- so removing it is not observable here, and is not claimed.
    assert out["theirs"] == {"status": "uploading", "cancelled": False, "paused": False, "error": None}, out
    assert out["log"] == [], out["log"]


def test_a_delete_already_on_the_wire_at_sign_out_is_aborted_and_its_answer_is_not_acted_on():
    # The DELETE of the earlier upload has LEFT when the account signs out. Two layers, each shown
    # on its own: the request is aborted by the run's controller (the signal it was sent with is
    # aborted); and even where the answer still arrives -- a fetch that ignores the signal --
    # nothing that follows it leaves.
    out = _serve("""
    // Layer 1: the request on the wire is torn down.
    fresh(victim(), ours({ replaces: chose('F') })); server.park.add('old-sess');
    let run = um._run('o'); await settle();
    out.left = log.slice();
    um.reset(); await settle();
    out.signalAborted = !!(signals[0] && signals[0].aborted);
    server.parked.get('old-sess')({ ok: true, status: 204 });   // the server answers anyway
    await settle(); await run;
    out.torn = snap();

    // Layer 2: the answer arrives (this fetch does not honour the signal) -- the next request is
    // refused by the epoch, so the original is not deleted and nothing is committed.
    fresh(victim(), ours({ replaces: chose('F') })); server.park.add('old-sess');
    run = um._run('o'); await settle();
    const answer = server.parked.get('old-sess');
    um._aborts.forEach(c => { c.abort = () => {}; });        // as if the abort had no effect
    um.reset(); await settle();
    answer({ ok: true, status: 204 });
    await settle(); await run;
    out.answered = snap();
    """)
    assert out["left"] == [DEL_OLD], out["left"]
    # (mutation: reset() does not abort -> signalAborted false -> red. mutation: the request is
    #  sent without the run's signal -> red.)
    assert out["signalAborted"] is True, "the DELETE on the wire was not aborted at sign-out"
    t = out["torn"]
    assert t["log"] == [DEL_OLD], t                                   # nothing after it
    a = out["answered"]
    # (mutation: no epoch check in front of the file delete -> DEL_FILE leaves -> red.)
    assert a["log"] == [DEL_OLD], "after the answer, something left: %r" % a["log"]
    assert DEL_FILE not in a["log"] and COMPLETE not in a["log"] and DEL_NEW not in a["log"]
    assert not any(e.startswith("toast") for e in a["log"])


def test_no_toast_after_sign_out_on_any_way_out_of_the_fire_point():
    # Every sentence the fire point can say -- a cancel that happened, a replacement dropped, a
    # rival left in progress -- is silenced once the account has gone. The scenarios below reach
    # each of them, with the sign-out landing just before the sentence.
    out = _serve("""
    // "The earlier upload was cancelled": the cancel is confirmed, the sign-out lands before
    // the file delete that follows it.
    fresh(victim(), ours({ replaces: chose('F') }));
    server.onRequest = async (m, url) => { if (m === 'DELETE' && url.endsWith('old-sess')) um.reset(); };
    let run = um._run('o'); await settle(); await run;
    out.cancelled = snap();

    // "Could not cancel the earlier upload": the refusal comes back after the sign-out.
    fresh(victim(), ours({ replaces: chose('F') })); server.park.add('old-sess');
    run = um._run('o'); await settle();
    const refuse = server.parked.get('old-sess');
    um._aborts.forEach(c => { c.abort = () => {}; });
    um.reset(); await settle();
    refuse({ ok: false, status: 500 });
    await settle(); await run;
    out.refused = snap();

    // "Another upload is still in progress": no rival to cancel, one that is not ours to cancel,
    // the sign-out lands during the delete of the original.
    fresh(sent('x', 'x-sess', { order: 1, replaces: null }), ours({ replaces: { deleteId: 'F', known: { sessions: [], items: [] } } }));
    server.onRequest = async (m, url) => { if (url.endsWith('/delete')) um.reset(); };
    run = um._run('o'); await settle(); await run;
    out.warned = snap();
    """)
    for key in ("cancelled", "refused", "warned"):
        r = out[key]
        toasts = [e for e in r["log"] if e.startswith("toast")]
        # (mutation: any one toast not gated -> that sentence renders on the sign-in screen -> red.)
        assert toasts == [], (key, toasts)
        assert COMPLETE not in r["log"], (key, r["log"])


@pytest.mark.parametrize("abort_layer", ["honoured", "ignored"])
def test_a_run_that_signs_out_mid_transfer_persists_no_record_and_sends_no_more_chunks(abort_layer):
    # A sealed-as-it-uploads upload, three chunks; the account signs out while the first chunk's
    # PUT is out. No further chunk leaves, and the resume record is not written back into the
    # store that sign-out cleared. Run twice: with the abort torn down as a browser would, and
    # with the abort having no effect -- so the epoch gate is shown to hold on its own.
    out = _serve("""
    const abortIgnored = ABORT_IGNORED;
    function zkUploadChunkFrames(index, totalFrames, framesPerChunk) {
        const first = index * framesPerChunk; return [first, Math.min(first + framesPerChunk, totalFrames)]; }
    const ZK_FRAMES_PER_UPLOAD_CHUNK = 1;
    um._openZkStream = async () => {};
    um._sealUploadChunk = async (it, i) => { it.frameMacs[i] = 'mac' + i; return new Blob([new Uint8Array(4)]); };
    // The REAL persist (lifted below), writing into the harness store; only the record's shape is stubbed.
    um._resumeRecord = (it) => ({ sessionId: it.sessionId });
    um._noteResumePersistence = () => {};
    const stream = { totalChunks: 3 };
    const it = sent('z', 'z-sess', { isZk: true, zkPipelined: true, zkStream: stream, frameMacs: [],
        clientFileId: 'obj', totalChunks: 3, chunkSize: 4, received: new Set(), lastPut: null, replaces: null });
    fresh(it);
    server.puts = [0, 1, 2].map(i => ({ ok: true, status: 200, json: async () => ({ complete: i === 2, bytes_received: 12 }) }));
    server.onRequest = async (m, url) => { if (m === 'PUT' && url.endsWith('/chunks/0')) {
        if (abortIgnored) um._aborts.forEach(c => { c.abort = () => {}; });
        um.reset(); } };
    await um._run('z');
    out.log = log.slice(); out.records = records.slice(); out.status = it.status; out.error = it.error || null;
    """.replace("ABORT_IGNORED", "true" if abort_layer == "ignored" else "false"))
    puts = [e for e in out["log"] if e.startswith("PUT ")]
    # The record for chunk 0 was written before its PUT (the order the send loop keeps); after the
    # sign-out nothing more is written and nothing more is sent.
    # (mutation: the persist not gated -> a second 'put z-sess' -> red. mutation: the PUT not sent
    #  through the gate -> chunk 1 leaves -> red.)
    assert puts == ["PUT /vaults/V/uploads/z-sess/chunks/0"], out["log"]
    assert out["records"] == ["put z-sess"], out["records"]
    assert COMPLETE.replace("new-sess", "z-sess") not in out["log"]
    # ... and the row is not marked as an error: there is no row, and no account, to tell.
    assert out["status"] != "error" and out["error"] is None, out
    assert not any(e.startswith("toast") for e in out["log"])


def test_the_next_account_uploads_normally_and_the_first_accounts_run_is_gone():
    # Sign-out and sign-in: a run started afterwards is that account's and goes all the way. A
    # sign-out does not wedge the tray for whoever comes next.
    out = _serve("""
    fresh(victim(), ours({ replaces: chose() }));
    server.park.add('old-sess');
    const stale = um._run('o'); await settle();
    um.reset(); await settle(); await stale;
    // The next account signs in and uploads the same name, replacing an earlier upload of its own.
    um.items = new Map([['v2', victim({ id: 'v2', sessionId: 'old-sess-2' })],
        ['o2', ours({ id: 'o2', sessionId: 'new-sess-2', replaces: { deleteId: null, known: { sessions: ['old-sess-2'], items: ['v2'] } } })]]);
    log.length = 0;
    await um._run('o2');
    out.next = snap(); out.nextStatus = um.items.get('o2') && um.items.get('o2').status;
    """)
    n = out["next"]
    assert n["log"] == ["DELETE /vaults/V/uploads/old-sess-2", CANCELLED_ONLY, "POST /vaults/V/uploads/new-sess-2/complete", REPLACED], n
    assert out["nextStatus"] == "done"


def test_the_gate_and_the_controller_are_the_only_way_a_run_reaches_the_network():
    # The source half, as a smoke alarm beside the driven tests above: on comment-free code, the
    # run's path has no bare fetch left, and every request goes through the one gate.
    from pathlib import Path
    from _js_source import strip_comments
    from test_upload_tray_controls import _method, APP_JS
    js = APP_JS.read_text(encoding="utf-8")
    for head in ("async _run(id) {", "async _serverHoldsAll(it) {", "async _fireReplacement(it) {",
                 "async cancel(id, forReplacement) {", "async _abandonSession(it) {", "async _init(it) {"):
        body = strip_comments(_method(js, head))
        assert "await fetch(" not in body and " fetch(" not in body.replace("this._send(", ""), head
    send = strip_comments(_method(js, "_send(it, url, opts, onBehalfOf) {"))
    assert send.index("if (this._stale(run)) throw") < send.index("return fetch(")
    reset = strip_comments(_method(js, "reset() {"))
    assert reset.index("this._epoch = (this._epoch || 0) + 1;") < reset.index("ctl.abort()") < reset.index("this.items.clear()")
