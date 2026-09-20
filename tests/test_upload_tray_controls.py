"""What the upload tray OFFERS for an interrupted upload, and what a refused cancel does.

Two defects were found by running the page, and neither was visible to a pin on the code's shape:

* A zero-knowledge upload sealed as it uploads IS continued by picking the file again -- the resume was
  written and worked when driven by hand -- but the tray asked `!it.isZk` in three separate places, so
  the row showed Cancel alone beside a sentence telling the user to cancel. Cancel destroys the upload.
* `cancel()` never read the status of its DELETE. A refused cancel looked like a cancel, so an upload
  replacing an in-flight one went on to commit while the earlier one was still alive -- and an
  earlier upload that finishes later replaces the newer file by name. The harm is the user's newer
  pick silently overwritten with the older bytes, and nothing was said.

So these tests run the SHIPPED methods -- lifted out of ``app.js`` verbatim -- under Node: the tray
methods against a minimal DOM, and the send loop's tail, the fire point, the cancel and the drop
against a stubbed server that can refuse either DELETE, or both, and then recover. What the browser
draws and sends beyond that is the live lane.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP_JS = ROOT / "static" / "js" / "app.js"


def _method(js: str, head: str) -> str:
    """One method of the upload manager, verbatim, from its head to its closing `},`."""
    start = js.index("    " + head)
    return js[start:js.index("\n    },\n", start) + 7]


def _node(harness: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the shipped tray code must not be skipped"
    # Through stdin as UTF-8: the shipped strings carry an ellipsis and a dash, which must survive.
    done = subprocess.run([node, "-"], input=harness, capture_output=True, text=True,
                          encoding="utf-8", timeout=60, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


CONTINUE = "Paused — click Resume and pick the file again to continue this encrypted upload"
NOT_HERE = "Encrypted data isn't on this device — cancel and upload again"
RESELECT = "Paused — click Resume and re-select the file"


def test_the_tray_offers_the_resume_a_sealed_as_it_uploads_item_can_actually_do():
    js = APP_JS.read_text(encoding="utf-8")
    methods = "".join(_method(js, h) for h in (
        "_canRepick(it) {", "_controlSig(it) {", "_buildControls(el, it) {", "_renderSub(sub, it) {"))
    out = _node("""
const mkEl = () => ({ attrs: {}, children: [], className: '', textContent: '', title: '',
    setAttribute(k, v) { this.attrs[k] = v; }, addEventListener(ev, fn) { this.on = fn; },
    appendChild(c) { this.children.push(c); }, replaceChildren(...c) { this.children = c; } });
const document = { createElement: mkEl, createTextNode: (s) => ({ text: s }) };
const formatBytes = (n) => n + ' B';
const um = {
""" + methods + """
    _percent() { return 0; }, _statusLabel(s) { return s; }, _iconEl(n) { return { icon: n }; },
    pause() {}, cancel(id) { this.cancelledId = id; }, resume(id) { this.resumedId = id; },
};
const look = (it) => {
    const el = mkEl(); um._buildControls(el, it);
    const sub = mkEl(); um._renderSub(sub, it);
    um.resumedId = null;
    const resume = el.children.find(b => b.attrs['data-up-action'] === 'resume');
    if (resume) resume.on();
    return { actions: el.children.map(b => b.attrs['data-up-action'] + (b.textContent ? ':' + b.textContent : '')),
             sig: um._controlSig(it), text: sub.children[0].text, clickResumes: um.resumedId === it.id };
};
const base = { status: 'needs-file', totalSize: 10, error: null };
process.stdout.write(JSON.stringify({
    pipelined: look({ ...base, id: 'p', isZk: true, zkPipelined: true }),
    sealedUpFront: look({ ...base, id: 'l', isZk: true, zkPipelined: false }),
    sealedUpFrontNoFlag: look({ ...base, id: 'n', isZk: true }),
    standard: look({ ...base, id: 's', isZk: false }),
    paused: look({ ...base, id: 'q', status: 'paused', isZk: true, zkPipelined: true }),
}));
""")
    # Sealed as it uploaded: it CAN be continued, so the row offers it, says so, and the button
    # really resumes. (mutation: drop the pipelined case from any ONE of the three gates -> red.)
    p = out["pipelined"]
    assert p["actions"] == ["resume:Resume…", "cancel"], p
    assert p["sig"] == "resume-text,cancel"
    assert p["text"] == CONTINUE and "cancel and upload again" not in p["text"]
    assert p["clickResumes"] is True
    # Sealed up front, ciphertext not on this device: Cancel only, and the old sentence -- which is
    # true of THIS case and only this one. (mutation: swap the sentences -> red.)
    for key in ("sealedUpFront", "sealedUpFrontNoFlag"):
        legacy = out[key]
        assert legacy["actions"] == ["cancel"] and legacy["sig"] == "cancel", legacy
        assert legacy["text"] == NOT_HERE
    # A Standard upload is unchanged.
    s = out["standard"]
    assert s["actions"] == ["resume:Resume…", "cancel"] and s["sig"] == "resume-text,cancel"
    assert s["text"] == RESELECT
    # And a row that is merely paused is not a re-pick row.
    assert out["paused"]["actions"] == ["resume", "cancel"] and out["paused"]["sig"] == "resume,cancel"


def test_the_three_gates_share_one_answer():
    # They drifted apart once because each asked the question on its own. Now there is one
    # predicate and each gate calls it; none spells `!it.isZk` for itself any more.
    js = APP_JS.read_text(encoding="utf-8")
    for head in ("_controlSig(it) {", "_buildControls(el, it) {", "_renderSub(sub, it) {"):
        body = "\n".join(ln for ln in _method(js, head).splitlines() if not ln.lstrip().startswith("//"))
        assert body.count("this._canRepick(it)") == 1, f"{head} does not ask the shared predicate"
        assert "!it.isZk" not in body, f"{head} decides re-pick on its own again"


SERVER = """
const API_BASE = '';
const state = { currentVault: null };
const log = [];                                  // requests AND toasts, in the order they happened
const server = { refuse: new Set(), unreachable: new Set(), stalled: new Set(), onGet: null,
    park: new Set(), parked: new Map(), puts: [], held: null };
const calls = () => log.filter(e => !e.startsWith('toast'));
const toasts = () => log.filter(e => e.startsWith('toast'));
const fetch = async (url, opts) => {
    const method = (opts && opts.method) || 'GET';
    log.push(method + ' ' + url);
    const sess = url.split('/uploads/')[1] || '';
    if (method === 'DELETE') {
        if (server.unreachable.has(sess)) throw new Error('network');
        if (server.stalled.has(sess)) return new Promise(() => {});      // never answers
        if (server.park.has(sess)) return new Promise(res => server.parked.set(sess, res));  // answered by hand
        return server.refuse.has(sess) ? { ok: false, status: 500 } : { ok: true, status: 204 };
    }
    if (method === 'GET') {
        if (server.onGet) server.onGet();
        return { ok: true, status: 200, json: async () => (server.held || { received_chunks: [0], bytes_received: 10 }) };
    }
    if (method === 'PUT') {
        return server.puts.shift() || { ok: true, status: 200, json: async () => ({ complete: true, bytes_received: 10 }) };
    }
    if (url.endsWith('/delete')) {
        if (server.park.has('file')) return new Promise(res => server.parked.set('file', res));
        return server.refuse.has('file') ? { ok: false, status: 500 } : { ok: true, status: 200 };
    }
    return { ok: true, status: 200, json: async () => ({}) };
};
const timers = [];                               // the fire point's wait, released by hand
const setTimeout = (fn) => { timers.push(fn); };
const flush = () => { while (timers.length) timers.shift()(); };
const settle = () => new Promise(r => setImmediate(r));
const records = [];
const zkUploadStore = { delete: async (id) => { records.push(id); } };
const showError = (m) => log.push('toast error ' + m);
const showInfo = (m) => log.push('toast info ' + m);
const loadVaultFiles = async () => {};
const um = {
    items: new Map(), _landed: [], seq: 100, _vaultHeaders() { return {}; }, render() {},
    run(id) { return this._run(id); },
    async _init(it) { log.push('init'); it.sessionId = 'renewed-sess'; },   // a fresh session after a 410
%s
};
// An upload with every chunk already on the server: the next thing its run does is the fire point.
const sent = (id, sessionId, extra) => ({ id, order: 50, vaultId: 'V', folderId: null, sessionId, fileName: 'X', file: {}, isZk: false,
    totalChunks: 1, totalSize: 10, received: new Set([0]), lastPut: { complete: true, bytes_received: 10 },
    status: 'uploading', cancelled: false, paused: false, ...extra });
// The earlier upload was dropped first (order 1); ours after it (order 2).
const victim = (extra) => sent('v', 'old-sess', { order: 1, ...extra });
const ours = (extra) => sent('o', 'new-sess', { order: 2, replaces: { deleteId: null }, ...extra });
const fresh = (...its) => { log.length = 0; records.length = 0; timers.length = 0; um._landed = []; um.seq = 100;
    server.refuse = new Set(); server.unreachable = new Set(); server.stalled = new Set(); server.onGet = null;
    server.park = new Set(); server.parked = new Map(); server.puts = []; server.held = null;
    um.items = new Map(its.map(it => [it.id, it])); };
const row = (id) => { const it = um.items.get(id);
    return it ? { status: it.status, cancelled: it.cancelled, error: it.error || null } : null; };
const halted = (id) => { const it = um.items.get(id); return !!(it && it.cancelled && it.paused); };
const snap = () => ({ log: log.slice(), records: records.slice(), v: row('v'), o: row('o') });
const out = {};
(async () => {
%s
    process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""

LIFTED = ("async _run(id) {", "async _serverHoldsAll(it) {", "async _fireReplacement(it) {",
          "async _dropReplacement(it, message) {", "async cancel(id, forReplacement) {",
          "_nameKeys(it) {", "_sameName(a, b) {", "_samePlace(a, b) {", "_holdsName(o) {",
          "_sameNameRows(probe) {", "_earlier(o, it) {", "_liveRivals(it) {",
          "_noteLanded(it) {", "_landedSince(it) {")

DEL_OLD, DEL_NEW = "DELETE /vaults/V/uploads/old-sess", "DELETE /vaults/V/uploads/new-sess"
COMPLETE = "POST /vaults/V/uploads/new-sess/complete"
DROPPED = 'toast error Could not cancel the earlier upload of "X"; the new copy was not uploaded.'
REPLACED = 'toast info The earlier upload of "X" was cancelled and replaced by this one.'
REFUSED_ROW = "Could not cancel this upload — the server did not confirm it. Try again."
# ... and when it was a newer upload asking, not the user, the row does not report a cancel they never made.
REPLACER_REFUSED_ROW = ("A newer upload of this name tried to replace this one, but the server did not "
                        "confirm the cancel.")
STRANDED_ROW = ("Not uploaded, but its data could not be removed from the server — "
                "Cancel to remove it, or Resume to try replacing again.")
REMOVING_ROW = "Not uploaded — removing its data from the server…"
DEL_FILE = "POST /vaults/V/files/F/delete"
CANCELLED_ONLY = 'toast info The earlier upload of "X" was cancelled.'
NOT_REPLACED = ('toast error Could not replace "X": the existing file could not be removed, so it is '
                'unchanged and the new copy was not uploaded.')


def _serve(scenarios: str) -> dict:
    js = APP_JS.read_text(encoding="utf-8")
    return _node(SERVER % ("".join(_method(js, h) for h in LIFTED), scenarios))


def test_a_cancel_the_server_refused_drops_the_replacement_by_name_and_never_commits():
    out = _serve("""
    for (const [key, how] of [['refused', 'refuse'], ['network', 'unreachable']]) {
        fresh(victim(), ours()); server[how].add('old-sess');
        await um._run('o'); out[key] = snap();
    }
    fresh(victim(), ours()); await um._run('o'); out.confirmed = snap();
    fresh(sent('n', null)); out.noSession = await um.cancel('n');
    out.noSuchItem = await um.cancel('nope');
    """)
    for key in ("refused", "network"):
        r = out[key]
        # The victim's cancel was not confirmed, so the run STOPS: no commit. The earlier upload is
        # alive and would later overwrite this one by name. (mutation: skip the drop path -> the
        # commit is in the log -> red.)
        assert COMPLETE not in r["log"], r
        # Said by name, and said BEFORE our own session is removed: that DELETE is a round trip
        # with no bound on it. (mutation: say it after -> red on the order.)
        assert r["log"] == [DEL_OLD, DROPPED, DEL_NEW], r
        # The victim's row STAYS, as an error, with its saved record -- that record is still what
        # could continue it. (mutation: drop the status check -> row and record thrown away -> red.)
        # (mutation: report it as the user's own cancel again -> red.)
        assert r["v"] == {"status": "error", "cancelled": False, "error": REPLACER_REFUSED_ROW}, r
        # OUR upload is what is dropped.
        assert r["o"] is None
    ok = out["confirmed"]
    assert ok["log"] == [DEL_OLD, REPLACED, COMPLETE] and ok["v"] is None and ok["o"]["status"] == "done", ok
    # Nothing to cancel on the server is a cancel that worked.
    assert out["noSession"] is True and out["noSuchItem"] is True


def test_already_gone_is_gone():
    js = APP_JS.read_text(encoding="utf-8")
    harness = (SERVER % ("".join(_method(js, h) for h in LIFTED), """
    fresh(victim(), ours()); await um._run('o'); out.gone = snap();
    """)).replace("server.refuse.has(sess) ? { ok: false, status: 500 }",
                  "sess === 'old-sess' ? { ok: false, status: 404 }")
    gone = _node(harness)["gone"]
    # (mutation: 404 no longer counts -> the replacement is dropped -> red.)
    assert gone["log"] == [DEL_OLD, REPLACED, COMPLETE] and gone["v"] is None, gone


def test_a_retry_after_BOTH_cancels_were_refused_never_commits_past_a_live_victim():
    # The two DELETEs go out moments apart, so the fault that refuses the victim's refuses ours too.
    # That leaves OUR row in the tray, offering Resume, beside the victim's -- and the victim is now
    # in 'error'. The fire point used to pass an errored victim over, so that Resume committed
    # straight past a victim whose server session was still open.
    out = _serve("""
    fresh(victim(), ours()); server.refuse.add('old-sess'); server.refuse.add('new-sess');
    await um._run('o'); out.first = snap();
    log.length = 0; await um._run('o'); out.retryStillDown = snap();          // the user clicks Resume
    log.length = 0; server.refuse.clear();
    await um._run('o'); out.retryRecovered = snap();                          // ... and again, later
    """)
    first = out["first"]
    assert first["log"] == [DEL_OLD, DROPPED, DEL_NEW] and COMPLETE not in first["log"], first
    assert first["v"]["status"] == "error"
    # Our row stays, because our data is still on the server, and says what is true of it.
    assert first["o"] == {"status": "error", "cancelled": False, "error": STRANDED_ROW}, first
    assert first["records"] == []
    # THE RETRY. The victim is in 'error' with a live session: it is cancelled AGAIN, not passed
    # over; refused again, so dropped again, by name again, and nothing is committed.
    # (mutation: restore the errored-victim skip -> the log is [COMPLETE] -> red.)
    again = out["retryStillDown"]
    assert again["log"] == [DEL_OLD, DROPPED, DEL_NEW], again
    assert again["v"]["status"] == "error" and again["o"]["error"] == STRANDED_ROW
    # The server recovers: now the victim really is cancelled FIRST, and only then the commit.
    healed = out["retryRecovered"]
    assert healed["log"] == [DEL_OLD, REPLACED, COMPLETE], healed
    assert healed["v"] is None and healed["o"]["status"] == "done"


def test_our_own_cancel_that_never_answers_still_says_what_happened_and_never_commits():
    # The other shape of the same fault, seen live: the DELETE for OUR session is not refused, it
    # simply never comes back (fetch has no timeout). The message used to wait on that round trip,
    # so the tray showed two rows for one name and not a word about either.
    out = _serve("""
    fresh(victim(), ours()); server.refuse.add('old-sess'); server.stalled.add('new-sess');
    um._run('o');                                          // never settles: not awaited
    await settle(); await settle();
    out.stalled = snap(); out.halted = halted('o');
    """)
    r = out["stalled"]
    # Said already, by name, with our DELETE still outstanding. (mutation: say it after -> the log
    # ends at the DELETE and there is no message at all -> red.)
    assert r["log"] == [DEL_OLD, DROPPED, DEL_NEW], r
    assert COMPLETE not in r["log"]
    # The victim's row says its cancel failed. OURS already says what happened to it -- set BEFORE
    # the round trip, not after: it used to read "Uploading 100%" with Pause and Cancel for as long
    # as the DELETE took, which here is for ever. It is marked cancelled and halted as well, so
    # neither the send loop nor the fire point can carry it to a commit if Resume is clicked.
    # (mutation: set the row's state after the await again -> 'uploading' here -> red.)
    assert r["v"] == {"status": "error", "cancelled": False, "error": REPLACER_REFUSED_ROW}, r
    assert r["o"] == {"status": "error", "cancelled": True, "error": REMOVING_ROW} and out["halted"] is True, r
    assert r["records"] == []


def test_which_victims_are_cancelled_and_which_are_passed_over():
    out = _serve("""
    fresh(victim({ status: 'error', sessionId: null }), ours()); await um._run('o'); out.erroredNoSession = snap();
    fresh(victim({ status: 'error', cancelled: true, sessionId: null }), ours()); await um._run('o'); out.alreadyCancelled = snap();
    fresh(ours()); await um._run('o'); out.goneFromTray = snap();
    fresh(victim({ status: 'done' }), ours()); um._noteLanded(um.items.get('v')); await um._run('o'); out.landed = snap();
    // ... but one that landed BEFORE ours was dropped is the committed file the user chose to replace.
    fresh(victim({ status: 'done' }), ours({ order: 900, replaces: { deleteId: 'F' } }));
    um._noteLanded(um.items.get('v')); await um._run('o'); out.landedBeforeOurDrop = snap();
    fresh(victim({ status: 'paused', paused: true }), ours()); await um._run('o'); out.paused = snap();
    fresh(victim({ status: 'needs-file', file: null, restored: true, order: 7000 }), ours()); await um._run('o'); out.waiting = snap();
    """)
    # An errored upload that never opened a session can still be resumed into one: its row goes.
    e = out["erroredNoSession"]
    assert e["log"] == [REPLACED, COMPLETE] and e["v"] is None, e
    # Already cancelled (its session is gone and it can never run again), or no longer in the tray.
    for key in ("alreadyCancelled", "goneFromTray"):
        assert out[key]["log"] == [COMPLETE], out[key]
    assert out["alreadyCancelled"]["v"]["cancelled"] is True
    # Finished first: the landed file stands and OUR copy is dropped.
    landed = out["landed"]
    assert COMPLETE not in landed["log"] and DEL_OLD not in landed["log"], landed
    assert landed["log"][0].startswith('toast error "X" was already uploaded by the earlier transfer')
    assert landed["log"][1:] == [DEL_NEW] and landed["o"] is None
    assert out["landedBeforeOurDrop"]["log"] == [DEL_FILE, COMPLETE], out["landedBeforeOurDrop"]
    # Paused, or waiting for its file (rebuilt from the server, so its `order` says nothing): live.
    for key in ("paused", "waiting"):
        assert out[key]["log"] == [DEL_OLD, REPLACED, COMPLETE] and out[key]["v"] is None, out[key]


def test_a_replacement_the_user_cancelled_fires_nothing_on_its_way_out():
    # Its row keeps Cancel for the whole of the fire step, and the step can wait many seconds on a
    # victim that is finalising. A replacement cancelled in that window used to go on and cancel
    # the victim anyway -- on behalf of an upload the user had just withdrawn.
    out = _serve("""
    for (const [key, refuseOurs] of [['cancelled', false], ['cancelRefused', true]]) {
        fresh(victim({ status: 'completing' }), ours());
        if (refuseOurs) server.refuse.add('new-sess');
        const running = um._run('o');
        await settle();                                   // parked in the wait on the victim
        out[key + 'Parked'] = timers.length;
        await um.cancel('o');                             // the user clicks Cancel on OUR row
        um.items.get('v').status = 'uploading';           // the victim's commit did not land
        flush(); await running;
        out[key] = snap();
    }
    // ... and the other destructive step, an original file to delete: withdrawn while the run was
    // still confirming what the server holds.
    fresh(ours({ lastPut: null, replaces: { deleteId: 'F' } }));
    server.onGet = () => { um.items.get('o').cancelled = true; };
    await um._run('o'); out.beforeDelete = snap();
    """)
    for key in ("cancelled", "cancelRefused"):
        r = out[key]
        assert out[key + "Parked"] == 1, "the run never reached the wait, so this proved nothing"
        # Only OUR session was touched. (mutation: remove the re-check after the wait -> the
        # victim's DELETE is in the log -> red. For the refused half: read only `cancelled` -> red.)
        assert r["log"][0] == DEL_NEW and DEL_OLD not in r["log"] and COMPLETE not in r["log"], r
        assert r["v"] == {"status": "uploading", "cancelled": False, "error": None}, r
    assert out["cancelled"]["o"] is None
    assert out["cancelRefused"]["o"]["status"] == "error"
    b = out["beforeDelete"]
    assert b["log"] == ["GET /vaults/V/uploads/new-sess"], b     # no file delete, no commit


def test_a_row_rebuilt_under_a_new_id_is_still_cancelled():
    # Every row that is waiting for its file is deleted and re-added under a NEW id each time the
    # tray refreshes from the server -- after every commit, and whenever the window regains focus.
    # An id noted when the file was dropped then finds nothing, "gone from the tray" reads as
    # cancelled, and the replacement commits past a session that is as alive as ever.
    out = _serve("""
    const rekey = (from, to) => { const it = um.items.get(from); um.items.delete(from);
        um.items.set(to, { ...it, id: to, order: ++um.seq }); };
    const waiting = (id, sess) => sent(id, sess, { status: 'needs-file', file: null, restored: true, order: 60 });
    // Re-keyed between the drop and the fire point (here: while the run confirms what the server holds).
    fresh(waiting('k1', 'old-sess'), ours({ lastPut: null }));
    server.onGet = () => rekey('k1', 'k2');
    await um._run('o'); out.beforeFire = snap(); out.beforeFireRows = [...um.items.keys()];
    // Re-keyed DURING the fire step's wait on another rival that is finalising.
    fresh(sent('a', 'a-sess', { order: 1, status: 'completing' }), waiting('k1', 'old-sess'), ours());
    const running = um._run('o');
    await settle(); out.parked = timers.length;
    rekey('k1', 'k2'); um.items.get('a').status = 'uploading';
    flush(); await running; out.duringWait = snap(); out.duringWaitRows = [...um.items.keys()];
    """)
    # (mutation: resolve the rivals once, before the loop, and look them up by id -> the re-keyed
    # row is never cancelled and the log is the commit alone -> red.)
    b = out["beforeFire"]
    assert b["log"] == ["GET /vaults/V/uploads/new-sess", DEL_OLD, REPLACED, COMPLETE], b
    assert out["beforeFireRows"] == ["o"]
    assert out["parked"] == 1, "the run never reached the wait, so this proved nothing"
    d = out["duringWait"]
    assert d["log"] == ["DELETE /vaults/V/uploads/a-sess", DEL_OLD, REPLACED, COMPLETE], d
    assert out["duringWaitRows"] == ["o"]


def test_a_committed_file_and_an_upload_in_flight_are_both_dealt_with_uploads_first():
    # One name, held twice: a committed file AND an upload still in flight. The entry used to name
    # the file alone, so the upload in flight was nobody's victim and whichever finished last won.
    # And the ORDER matters now that both steps can apply: the earlier upload first, the file after.
    out = _serve("""
    const both = () => fresh(victim(), ours({ replaces: { deleteId: 'F' } }));
    both(); await um._run('o'); out.ok = snap();
    both(); server.refuse.add('old-sess'); await um._run('o'); out.cancelRefused = snap();
    both(); server.refuse.add('file'); await um._run('o'); out.deleteRefused = snap();
    """)
    assert out["ok"]["log"] == [DEL_OLD, DEL_FILE, REPLACED, COMPLETE], out["ok"]
    # A refused cancel costs NOTHING: no delete request was ever made, so the original stands.
    # (mutation: delete the file first again -> the delete is in this log -> red.)
    assert out["cancelRefused"]["log"] == [DEL_OLD, DROPPED, DEL_NEW], out["cancelRefused"]
    # A refused delete: "the existing file is unchanged" is true, and the cancel that did happen
    # is said too -- nothing is left for the user to find out later.
    assert out["deleteRefused"]["log"] == [DEL_OLD, DEL_FILE, CANCELLED_ONLY, NOT_REPLACED, DEL_NEW], out["deleteRefused"]
    for key in ("cancelRefused", "deleteRefused"):
        assert COMPLETE not in out[key]["log"] and out[key]["o"] is None


def test_an_earlier_upload_whose_own_cancel_is_in_flight_is_not_taken_for_gone():
    # cancel() marks the row cancelled BEFORE its DELETE goes out. Read then, the row looks dealt
    # with -- and if that DELETE is refused a moment later, it is live and resumable again, with the
    # replacement already committed past it.
    out = _serve("""
    const midCancel = () => fresh(victim({ cancelled: true, paused: true }), ours());
    // ... refused: the row comes back to life, and OUR cancel of it is refused as well.
    midCancel(); server.refuse.add('old-sess');
    let running = um._run('o'); await settle(); out.parkedRefused = timers.length;
    Object.assign(um.items.get('v'), { cancelled: false, status: 'error' });
    flush(); await running; out.refused = snap();
    // ... confirmed: its row goes, and only then is there nothing left to wait for.
    midCancel();
    running = um._run('o'); await settle(); out.parkedConfirmed = timers.length;
    um.items.delete('v'); flush(); await running; out.confirmed = snap();
    // ... never settles: past the wait it gets our own cancel, the same idempotent DELETE.
    midCancel();
    running = um._run('o');
    for (let k = 0; k < 200; k++) { await settle(); flush(); }
    await running; out.neverSettles = snap();
    """)
    assert out["parkedRefused"] == 1 and out["parkedConfirmed"] == 1, "the run never waited"
    # (mutation: pass over a row that reads `cancelled` again -> no wait, and the log is the commit
    # alone -> red on the parked count and on every log below.)
    assert out["refused"]["log"] == [DEL_OLD, DROPPED, DEL_NEW], out["refused"]
    assert out["confirmed"]["log"] == [COMPLETE], out["confirmed"]
    assert out["neverSettles"]["log"] == [DEL_OLD, REPLACED, COMPLETE], out["neverSettles"]


def test_after_a_reload_the_newer_of_two_rows_of_one_name_still_cancels_the_older():
    # What an upload replaces is not kept across a reload: a replacement and the upload it was
    # replacing both come back as plain rows waiting for their files. Continue the newer one and it
    # used to commit beside the older one's open session -- which overwrites it by name whenever it
    # is continued later. So the fire point is for EVERY upload, not only one with a choice on it.
    out = _serve("""
    // The server lists sessions newest first, so the rebuild gives the NEWER row the lower order:
    // only when each session was opened says which is the earlier.
    const pair = () => fresh(
        sent('v', 'old-sess', { status: 'needs-file', file: null, restored: true, order: 61, startedAt: 1000 }),
        sent('o', 'new-sess', { status: 'needs-file', file: null, restored: true, order: 60, startedAt: 2000 }));
    pair(); um.items.get('o').file = {}; await um._run('o'); out.newerContinued = snap();
    pair(); um.items.get('v').file = {}; await um._run('v'); out.olderContinued = snap();
    // An upload with nothing to fire goes straight on -- no confirming GET, nothing but its commit.
    fresh(sent('o', 'new-sess', { lastPut: null })); await um._run('o'); out.alone = snap();
    // Nobody chose "replace" for this row, so it does not stand aside for one that landed -- it
    // still cancels the earlier upload that is alive (which is what brings it to the fire step).
    fresh(victim({ status: 'done' }), sent('w', 'w-sess', { order: 1, status: 'paused' }), sent('o', 'new-sess', { order: 2 }));
    um._noteLanded(um.items.get('v')); await um._run('o'); out.noChoiceLanded = snap();
    """)
    # One file, the newer bytes, and said by name. (mutation: fire only for a row with `replaces`
    # again -> the log is the commit alone, with the older session still open -> red.)
    assert out["newerContinued"]["log"] == [DEL_OLD, REPLACED, COMPLETE], out["newerContinued"]
    assert out["newerContinued"]["v"] is None
    # The older one continued first is nobody's replacement: it commits, the newer row stays, and
    # continuing THAT later replaces it by name -- the newer pick still wins.
    older = out["olderContinued"]
    assert older["log"] == ["POST /vaults/V/uploads/old-sess/complete"] and older["o"]["status"] == "needs-file", older
    assert out["alone"]["log"] == [COMPLETE], out["alone"]
    # (mutation: make it stand aside like a chosen replacement -> dropped, no commit -> red.)
    assert out["noChoiceLanded"]["log"] == ["DELETE /vaults/V/uploads/w-sess", REPLACED, COMPLETE], out["noChoiceLanded"]


def test_a_row_re_picked_while_its_cancel_was_out_is_still_driveable_when_the_cancel_is_refused():
    # A row waiting for its file keeps its re-pick control while a Cancel is in flight, and that
    # request has no bound on it. Re-picked meanwhile, the run starts and stops at once on
    # `cancelled`, leaving the row 'uploading' with nothing driving it. If the refusal is then
    # handled by what the row WAS when the cancel began, it is left like that: no Resume, for ever.
    out = _serve("""
    fresh(sent('w', 'wait-sess', { status: 'needs-file', file: null, paused: true }));
    server.park.add('wait-sess');
    const cancelling = um.cancel('w'); await settle();
    um.items.get('w').file = {}; await um._run('w');          // the user picks the file again
    out.during = row('w');
    server.parked.get('wait-sess')({ ok: false, status: 500 });
    out.answer = await cancelling; out.after = row('w'); out.toasts = toasts();
    server.park.clear(); log.length = 0;
    await um._run('w'); out.resumed = snap();                  // ... and clicks Resume
    """)
    assert out["during"] == {"status": "uploading", "cancelled": True, "error": None}, out["during"]
    assert out["answer"] is False
    # Decided on what the row is at REFUSAL time: an error row, whose Resume drives it.
    # (mutation: decide on a snapshot taken when the cancel began -> it stays 'uploading' -> red.)
    assert out["after"] == {"status": "error", "cancelled": False, "error": REFUSED_ROW}, out["after"]
    assert out["toasts"] == []
    assert out["resumed"]["log"] == ["POST /vaults/V/uploads/wait-sess/complete"], out["resumed"]


def test_a_cancel_clicked_during_the_last_destructive_request_is_not_answered_with_a_commit():
    out = _serve("""
    fresh(victim(), ours()); server.park.add('old-sess');
    const running = um._run('o'); await settle();              // the earlier upload's DELETE is out
    await um.cancel('o');                                       // the user cancels OURS meanwhile
    server.parked.get('old-sess')({ ok: true, status: 204 }); await running;
    out.duringRivalCancel = snap();
    // ... and during the LAST one there is: the delete of the committed file. No turn of the loop
    // follows it, so nothing reads the withdrawal again unless it is read there on purpose.
    fresh(ours({ replaces: { deleteId: 'F' } })); server.park.add('file');
    const last = um._run('o'); await settle();
    await um.cancel('o');
    server.parked.get('file')({ ok: true, status: 200 }); await last;
    out.duringFileDelete = snap();
    """)
    # Held by the read at the top of the next turn.
    r = out["duringRivalCancel"]
    assert r["log"] == [DEL_OLD, DEL_NEW] and r["o"] is None, r
    # (mutation: drop BOTH re-reads -- the one after the last step and the one before the commit --
    # and the commit is in this log. Either alone still holds it, so each has its source pin below.)
    f = out["duringFileDelete"]
    assert f["log"] == [DEL_FILE, DEL_NEW] and f["o"] is None, f


def test_the_fire_point_under_the_conditions_nothing_else_exercised():
    out = _serve("""
    // A session the server had expired: restarted under a new one, and the step still fires whole.
    fresh(victim(), ours({ received: new Set(), lastPut: null, chunkSize: 10, replaces: { deleteId: 'F' },
        file: { size: 10, slice: () => ({ arrayBuffer: async () => new ArrayBuffer(10) }) } }));
    server.puts = [{ ok: false, status: 410 }];
    await um._run('o'); out.expiredOnce = snap();
    // The server does NOT hold everything: nothing is fired, nothing is committed.
    fresh(victim(), ours({ lastPut: null })); server.held = { received_chunks: [], bytes_received: 0 };
    await um._run('o'); out.notAllHeld = snap();
    // A committed file alone: removed, then the commit; refused, and nothing is uploaded.
    fresh(ours({ replaces: { deleteId: 'F' } })); await um._run('o'); out.fileRemoved = snap();
    fresh(ours({ replaces: { deleteId: 'F' } })); server.refuse.add('file'); await um._run('o'); out.fileRefused = snap();
    // A PAUSE is not a withdrawal: every byte is already up, and the commit is what Resume would do.
    fresh(victim({ status: 'completing' }), ours());
    const running = um._run('o'); await settle();
    Object.assign(um.items.get('o'), { paused: true, status: 'pausing' });
    um.items.get('v').status = 'uploading'; flush(); await running; out.pausedMeanwhile = snap();
    """)
    # (mutation: the restart drops what the upload replaces -> the file delete is missing -> red.)
    assert out["expiredOnce"]["log"] == [
        "PUT /vaults/V/uploads/new-sess/chunks/0", "init", "PUT /vaults/V/uploads/renewed-sess/chunks/0",
        DEL_OLD, DEL_FILE, REPLACED, "POST /vaults/V/uploads/renewed-sess/complete"], out["expiredOnce"]
    # (mutation: go on when the server does not hold everything -> the DELETE is in this log -> red.)
    held = out["notAllHeld"]
    assert held["log"] == ["GET /vaults/V/uploads/new-sess"], held
    assert held["o"]["status"] == "error" and held["o"]["error"].startswith("Could not confirm that the whole upload arrived")
    assert held["v"]["status"] == "uploading"
    assert out["fileRemoved"]["log"] == [DEL_FILE, COMPLETE], out["fileRemoved"]
    assert out["fileRefused"]["log"] == [DEL_FILE, NOT_REPLACED, DEL_NEW], out["fileRefused"]
    assert out["pausedMeanwhile"]["log"] == [DEL_OLD, REPLACED, COMPLETE], out["pausedMeanwhile"]


def test_a_refused_cancel_leaves_a_row_that_is_waiting_for_its_file_as_it_was():
    # An 'error' row swaps the re-pick control for a plain Resume, which cannot work without the
    # file. The row is left alone and the refusal is said beside it, by name.
    out = _serve("""
    for (const [key, extra] of [['standard', {}], ['sealedAsItUploads', { isZk: true, zkPipelined: true }]]) {
        fresh(sent('w', 'wait-sess', { status: 'needs-file', file: null, ...extra }));
        server.refuse.add('wait-sess');
        out[key] = { answer: await um.cancel('w'), row: row('w'), log: log.slice(), records: records.slice() };
    }
    """)
    for key in ("standard", "sealedAsItUploads"):
        r = out[key]
        assert r["answer"] is False
        # (mutation: make every refusal an 'error' row again -> red.)
        assert r["row"] == {"status": "needs-file", "cancelled": False, "error": None}, r
        assert r["log"] == ["DELETE /vaults/V/uploads/wait-sess",
                            'toast error Could not cancel "X" — the server did not confirm it. Try again.'], r
        assert r["records"] == []


def _code(js: str, head: str) -> str:
    return "\n".join(ln for ln in _method(js, head).splitlines() if not ln.lstrip().startswith("//"))


def test_the_source_half_on_code_only():
    js = APP_JS.read_text(encoding="utf-8")
    cancel = _code(js, "async cancel(id, forReplacement) {")
    assert cancel.count("gone = r.ok || r.status === 404;") == 1
    assert "if (!gone) {" in cancel and cancel.index("if (!gone) {") < cancel.index("this.items.delete(id);")
    assert cancel.index("return false;") < cancel.index("await zkUploadStore.delete(it.sessionId);")
    fire = _code(js, "async _fireReplacement(it) {")
    # No row is passed over for what its status says: the resolver decides who is a rival, and the
    # only thing the fire step asks of one is whether it is still settling.
    assert "victim" not in fire and "cancelItemIds" not in fire and "this.items.get(" not in fire
    assert fire.count("const rival = this._liveRivals(it)[0];") == 1
    assert fire.count("if (turn >= 1000 || !(await this.cancel(rival.id, true))) {") == 1
    assert fire.count("const settling = rival.status === 'completing' || (rival.cancelled && !!rival.sessionId);") == 1
    # Withdrawn is read at the top of EVERY turn -- so before each cancel, after each wait, and,
    # on the turn that finds no rival left, before the file delete, with no await in between.
    assert fire.count("const withdrawn = () => it.cancelled || it.status === 'error';") == 1
    # ... once per turn, and once more after the last destructive request.
    assert fire.count("if (withdrawn()) return false;") == 2
    assert fire.rindex("if (withdrawn()) return false;") > fire.index("/delete`")
    assert fire.rindex("if (withdrawn()) return false;") < fire.index("return true;")
    loop = fire.index("for (let turn = 0; ; turn++) {")
    assert loop < fire.index("if (withdrawn()) return false;") < fire.index("if (it.replaces && this._landedSince(it)) {") \
        < fire.index("const rival = this._liveRivals(it)[0];") < fire.index("if (!rival) break;") \
        < fire.index("await this.cancel(rival.id, true)") < fire.index("if (r.deleteId) {")
    # `break` is the ONLY way out of the loop that goes on, and nothing is awaited between the
    # loop's end and the delete request -- so the read at the top of that last turn still holds.
    assert fire.count("break;") == 1
    after_loop = fire[fire.index("            cancelled = true;\n        }\n"):fire.index("/delete`")]
    assert after_loop.count("await ") == 1 and "await fetch(" in after_loop
    drop = _code(js, "async _dropReplacement(it, message) {")
    assert drop.index("showError(message);") < drop.index("it.status = 'error';") \
        < drop.index("if (!(await this.cancel(it.id))) {")
    # A refused cancel leaves `paused` set so the send loop stops. The loop must not then relabel
    # the row "paused": that would wipe the one sentence saying the cancel failed.
    run = _code(js, "async _run(id) {")
    assert run.count("if (it.paused) { if (it.status !== 'error') it.status = 'paused'; this.render(); return; }") == 1
    assert "if (it.paused) { it.status = 'paused';" not in run
    # And a dropped or withdrawn replacement returns before the commit -- read once more by the
    # run itself, after the step and before the commit.
    assert run.count("if (!(await this._fireReplacement(it))) return;") == 1
    assert run.count("if (it.cancelled || it.status === 'error') return;") == 1
    assert run.index("if (!(await this._fireReplacement(it))) return;") \
        < run.index("if (it.cancelled || it.status === 'error') return;") < run.index("/complete`")
    # The refusal is decided on the row as it is THEN; no snapshot of it is taken at entry.
    assert "waitingForFile" not in cancel and cancel.count("if (it.status === 'needs-file') {") == 1
    assert cancel.index("it.cancelled = false;") < cancel.index("if (it.status === 'needs-file') {")
