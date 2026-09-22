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

from _js_source import strip_comments  # noqa: E402

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
    assert done.stdout.strip(), ("the harness ended without writing its result: a run it was waiting on "
                                 "never settled (parked on a timer or a request nothing released)")
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
        body = strip_comments(_method(js, head))
        assert body.count("this._canRepick(it)") == 1, f"{head} does not ask the shared predicate"
        assert "!it.isZk" not in body, f"{head} decides re-pick on its own again"


SERVER = """
const API_BASE = '';
const state = { currentVault: null };
const log = [];                                  // requests AND toasts, in the order they happened
const server = { refuse: new Set(), unreachable: new Set(), stalled: new Set(), onGet: null,
    park: new Set(), parked: new Map(), puts: [], held: null, onInit: null, completes: [] };
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
    if (url.endsWith('/complete') && server.completes.length) return server.completes.shift();
    return { ok: true, status: 200, json: async () => ({}) };
};
const timers = [];                               // the fire point's wait, released by hand
const setTimeout = (fn) => { timers.push(fn); };
const flush = () => { while (timers.length) timers.shift()(); };
const settle = () => new Promise(r => setImmediate(r));
const records = [];
const zkUploadStore = { delete: async (id) => { records.push(id); } };
const document = { getElementById: () => null };
const showError = (m) => log.push('toast error ' + m);
const showInfo = (m) => log.push('toast info ' + m);
const showWarning = (m) => log.push('toast warning ' + m);
const loadVaultFiles = async () => {};
const um = {
    items: new Map(), _landed: [], seq: 100, _vaultHeaders() { return {}; }, render() {},
    run(id) { return (this.lastRun = this._run(id)); },
    async _init(it) { log.push('init'); if (server.onInit) await server.onInit(it); it.sessionId = it.sessionId || 'renewed-sess'; },
    _reselect(id) { log.push('reselect ' + id); },
%s
};
// An upload with every chunk already on the server: the next thing its run does is the fire point.
const sent = (id, sessionId, extra) => ({ id, order: 50, vaultId: 'V', folderId: null, sessionId, fileName: 'X', file: {}, isZk: false,
    totalChunks: 1, totalSize: 10, received: new Set([0]), lastPut: { complete: true, bytes_received: 10 },
    status: 'uploading', cancelled: false, paused: false, ...extra });
// The earlier upload was dropped first (order 1); ours after it (order 2).
const victim = (extra) => sent('v', 'old-sess', { order: 1, ...extra });
// What the tray SHOWED the user when they chose to replace: only these may be cancelled for ours.
const SHOWN = { sessions: ['old-sess', 'a-sess', 'w-sess', 's1', 's2', 's3'], items: ['v', 'q'] };
const chose = (deleteId) => ({ deleteId: deleteId || null, known: SHOWN });
const ours = (extra) => sent('o', 'new-sess', { order: 2, replaces: chose(), ...extra });
const fresh = (...its) => { log.length = 0; records.length = 0; timers.length = 0; um._landed = []; um.seq = 100;
    server.refuse = new Set(); server.unreachable = new Set(); server.stalled = new Set(); server.onGet = null;
    server.park = new Set(); server.parked = new Map(); server.puts = []; server.held = null;
    server.onInit = null; server.completes = [];
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
          "_noteLanded(it, epoch) {", "_landedSince(it) {",
          "_knownFrom(rows) {", "_isKnown(it, o) {", "_adoptRivals(it) {", "_rivalsToCancel(it) {",
          "async _abandonSession(it) {", "resume(id) {", "reset() {", "_canRepick(it) {", "_controlSig(it) {",
          "_start(it) {", "_rowForPick(was) {")

DEL_OLD, DEL_NEW = "DELETE /vaults/V/uploads/old-sess", "DELETE /vaults/V/uploads/new-sess"
COMPLETE = "POST /vaults/V/uploads/new-sess/complete"
DROPPED = 'toast error Could not cancel the earlier upload of "X"; the new copy was not uploaded.'
# Said only AFTER a commit that succeeded -- never at the step that cancels, which comes before it.
REPLACED = 'toast info The earlier upload of "X" was replaced by this one.'
REPLACED_2 = 'toast info 2 earlier uploads of "X" were replaced by this one.'
CANCELLED_2 = 'toast info 2 earlier uploads of "X" were cancelled.'
WARN_OTHER = 'toast warning Another upload of "X" is still in progress and may replace this copy when it finishes.'
REFUSED_ROW = "Could not cancel this upload — the server did not confirm it. Try again."
# ... and when it was a newer upload asking, not the user, the row does not report a cancel they never made.
REPLACER_REFUSED_ROW = ("A newer upload of this name tried to replace this one, but the server did not "
                        "confirm the cancel.")
STRANDED_ROW = ("Not uploaded, but its data could not be removed from the server — "
                "Cancel to remove it, or Resume to try replacing again.")
DROPPED_ANOTHER = ('toast error Another earlier upload of "X" could not be cancelled and is still in progress, '
                   'so the new copy was not uploaded.')
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
    assert ok["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED] and ok["v"] is None and ok["o"]["status"] == "done", ok
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
    assert gone["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED] and gone["v"] is None, gone


def test_a_retry_after_BOTH_cancels_were_refused_never_commits_past_a_live_victim():
    # The two DELETEs go out moments apart, so the fault that refuses the victim's refuses ours too.
    # That leaves OUR row in the tray, offering Resume, beside the victim's -- and the victim is now
    # in 'error'. The fire point used to pass an errored victim over, so that Resume committed
    # straight past a victim whose server session was still open.
    out = _serve("""
    fresh(victim(), ours()); server.refuse.add('old-sess'); server.refuse.add('new-sess');
    await um._run('o'); out.first = snap();
    log.length = 0; um.resume('o'); await um.lastRun; out.retryStillDown = snap();   // the user clicks Resume
    log.length = 0; server.refuse.clear();
    um.resume('o'); await um.lastRun; out.retryRecovered = snap();            // ... and again, later
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
    assert healed["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED], healed
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
    // A row's `order` and a landing's stamp are minted from ONE counter, and that is the whole of
    // how "landed after our drop" is known. So here ours is minted FROM the counter -- the last
    // row the tray made -- and the landing follows at once, with nothing minted in between.
    fresh(victim({ status: 'done' })); um.items.set('o', ours({ order: ++um.seq }));
    um._noteLanded(um.items.get('v')); await um._run('o'); out.landedRightAfterOurDrop = snap();
    // ... but one that landed BEFORE ours was dropped is the committed file the user chose to replace.
    fresh(victim({ status: 'done' }), ours({ order: 900, replaces: chose('F') }));
    um._noteLanded(um.items.get('v')); await um._run('o'); out.landedBeforeOurDrop = snap();
    fresh(victim({ status: 'paused', paused: true }), ours()); await um._run('o'); out.paused = snap();
    fresh(victim({ status: 'needs-file', file: null, restored: true, order: 7000 }), ours()); await um._run('o'); out.waiting = snap();
    """)
    # An errored upload that never opened a session can still be resumed into one: its row goes.
    e = out["erroredNoSession"]
    assert e["log"] == [CANCELLED_ONLY, COMPLETE, REPLACED] and e["v"] is None, e
    # Already cancelled (its session is gone and it can never run again), or no longer in the tray.
    for key in ("alreadyCancelled", "goneFromTray"):
        assert out[key]["log"] == [COMPLETE], out[key]
    assert out["alreadyCancelled"]["v"]["cancelled"] is True
    # Finished first: the landed file stands and OUR copy is dropped.
    landed = out["landed"]
    assert COMPLETE not in landed["log"] and DEL_OLD not in landed["log"], landed
    assert landed["log"][0].startswith('toast error "X" was already uploaded by the earlier transfer')
    assert landed["log"][1:] == [DEL_NEW] and landed["o"] is None
    # A landing must be stamped with a NEW tick of the counter, not the current one: stamped with
    # the current one it equals the `order` of the row minted last, reads as "not after", and a
    # chosen replacement commits past the file that landed first. Every other case here hand-picks
    # orders far from the counter, which is how that survived. (mutation: `at: this.seq` -> red.)
    right_after = out["landedRightAfterOurDrop"]
    assert COMPLETE not in right_after["log"] and right_after["log"][1:] == [DEL_NEW], right_after
    assert right_after["log"][0].startswith('toast error "X" was already uploaded by the earlier transfer')
    assert out["landedBeforeOurDrop"]["log"] == [DEL_FILE, COMPLETE], out["landedBeforeOurDrop"]
    # Paused, or waiting for its file (rebuilt from the server, so its `order` says nothing): live.
    for key in ("paused", "waiting"):
        assert out[key]["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED] and out[key]["v"] is None, out[key]


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
    fresh(ours({ lastPut: null, replaces: chose('F') }));
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
    assert b["log"] == ["GET /vaults/V/uploads/new-sess", DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED], b
    assert out["beforeFireRows"] == ["o"]
    assert out["parked"] == 1, "the run never reached the wait, so this proved nothing"
    d = out["duringWait"]
    assert d["log"] == ["DELETE /vaults/V/uploads/a-sess", DEL_OLD, CANCELLED_2, COMPLETE, REPLACED_2], d
    assert out["duringWaitRows"] == ["o"]


def test_a_committed_file_and_an_upload_in_flight_are_both_dealt_with_uploads_first():
    # One name, held twice: a committed file AND an upload still in flight. The entry used to name
    # the file alone, so the upload in flight was nobody's victim and whichever finished last won.
    # And the ORDER matters now that both steps can apply: the earlier upload first, the file after.
    out = _serve("""
    const both = () => fresh(victim(), ours({ replaces: chose('F') }));
    both(); await um._run('o'); out.ok = snap();
    both(); server.refuse.add('old-sess'); await um._run('o'); out.cancelRefused = snap();
    both(); server.refuse.add('file'); await um._run('o'); out.deleteRefused = snap();
    """)
    assert out["ok"]["log"] == [DEL_OLD, DEL_FILE, CANCELLED_ONLY, COMPLETE, REPLACED], out["ok"]
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
    assert out["neverSettles"]["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED], out["neverSettles"]


def test_after_a_reload_the_newer_of_two_rows_of_one_name_still_cancels_the_older():
    # What an upload replaces is not kept across a reload: a replacement and the upload it was
    # replacing both come back as plain rows waiting for their files. When the USER continues the
    # newer one, the tray is showing them the older one beside it -- that is the moment it becomes
    # a replacement, for exactly the rows shown. An automatic resume adopts nothing.
    out = _serve("""
    // The server lists sessions newest first, so the rebuild gives the NEWER row the lower order:
    // only when each session was opened says which is the earlier.
    const pair = () => fresh(
        sent('v', 'old-sess', { status: 'needs-file', file: null, restored: true, order: 61, startedAt: 1000 }),
        sent('o', 'new-sess', { status: 'needs-file', file: null, restored: true, order: 60, startedAt: 2000 }));
    pair(); um.resume('o'); out.adopted = um.items.get('o').replaces;          // the user clicks Resume...
    um.items.get('o').file = {}; await um._run('o'); out.newerContinued = snap();   // ... and picks the file
    pair(); um.resume('v'); out.olderAdopted = um.items.get('v').replaces || null;
    um.items.get('v').file = {}; await um._run('v'); out.olderContinued = snap();
    pair(); um.items.get('o').file = {}; await um.run('o'); out.autoResumed = snap();   // nobody was shown anything
    fresh(sent('o', 'new-sess', { lastPut: null })); await um._run('o'); out.alone = snap();
    """)
    # (mutation: do not adopt at the user's Resume -> the older row survives the pair -> red.)
    assert out["adopted"] == {"deleteId": None, "known": {"sessions": ["old-sess"], "items": ["v"]}}, out["adopted"]
    assert out["newerContinued"]["log"] == ["reselect o", DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED], out["newerContinued"]
    assert out["newerContinued"]["v"] is None
    # The older one is nobody's replacement: it commits, the newer row stays, and continuing THAT
    # later replaces it by name -- the newer pick still wins.
    older = out["olderContinued"]
    assert out["olderAdopted"] is None
    assert older["log"] == ["reselect v", "POST /vaults/V/uploads/old-sess/complete"] and older["o"]["status"] == "needs-file", older
    assert out["autoResumed"]["log"] == [COMPLETE] and out["autoResumed"]["v"]["status"] == "needs-file", out["autoResumed"]
    # An upload with nothing to fire goes straight on -- no confirming GET, nothing but its commit.
    assert out["alone"]["log"] == [COMPLETE], out["alone"]


def test_only_a_row_the_tray_showed_the_user_is_ever_cancelled():
    # A session of this account opened somewhere else -- another tab, another device -- is restored
    # into this tray by a refresh. The user never saw it when they chose to replace, so it is not
    # cancelled, not waited for, and nothing is said about it; whatever its clock says.
    out = _serve("""
    const late = (startedAt) => sent('x', 'elsewhere-sess', { status: 'needs-file', file: null, restored: true, order: 900, startedAt });
    fresh(victim(), ours()); um.items.set('x', late(5)); await um._run('o'); out.olderElsewhere = snap(); out.xOlder = row('x');
    fresh(ours({ startedAt: 1000 })); um.items.set('x', late(2000)); await um._run('o'); out.laterElsewhere = snap(); out.xLater = row('x');
    // Known by ROW where it had no session yet when the question was answered -- and it still
    // matches once its session exists.
    fresh(sent('q', 'q-sess', { order: 1 }), ours({ replaces: { deleteId: null, known: { sessions: [], items: ['q'] } } }));
    await um._run('o'); out.knownByRow = snap();
    // Our OWN session, rebuilt as a second row by a refresh that ran while it was being opened.
    fresh(ours({ replaces: { deleteId: null, known: { sessions: ['new-sess'], items: [] } } }),
          sent('twin', 'new-sess', { status: 'needs-file', file: null, restored: true, order: 900 }));
    await um._run('o'); out.ownTwin = snap();
    """)
    # (mutation: drop the shown-to-the-user filter -> the session opened elsewhere is DELETEd -> red.)
    # ... but not left unmentioned: it can finish later and replace the copy being committed.
    # (mutation: say nothing about an earlier upload that was not ours to cancel -> red.)
    assert out["olderElsewhere"]["log"] == [DEL_OLD, CANCELLED_ONLY, WARN_OTHER, COMPLETE, REPLACED], out["olderElsewhere"]
    assert out["laterElsewhere"]["log"] == [COMPLETE], out["laterElsewhere"]
    for key in ("xOlder", "xLater"):
        assert out[key] == {"status": "needs-file", "cancelled": False, "error": None}, out[key]
    assert out["knownByRow"]["log"] == ["DELETE /vaults/V/uploads/q-sess", CANCELLED_ONLY, COMPLETE, REPLACED], out["knownByRow"]
    # (mutation: remove the same-session test from the resolver -> our own session is DELETEd, or
    # ours is dropped -> red.) One commit, and no DELETE of the session it commits.
    assert out["ownTwin"]["log"] == [COMPLETE], out["ownTwin"]


def test_a_row_whose_cancel_is_out_offers_no_resume_and_gets_it_back_when_the_cancel_is_refused():
    # The cancel request has no bound on it. A row that kept its re-pick control all that time could
    # be re-picked into a run that stops at once on `cancelled`, and then be left 'uploading' with
    # nothing driving it and no control that worked. That shape is now impossible by construction:
    # while the DELETE is out the row offers Cancel and nothing else, a Resume that reaches it
    # anyway does nothing, and a run leaves the row exactly as it is.
    out = _serve("""
    fresh(sent('w', 'wait-sess', { status: 'needs-file', file: null, paused: true }));
    server.park.add('wait-sess');
    out.before = um._controlSig(um.items.get('w'));
    const cancelling = um.cancel('w'); await settle();
    out.during = um._controlSig(um.items.get('w'));
    um.resume('w'); um.items.get('w').file = {}; await um._run('w'); um.items.get('w').file = null;
    out.rowDuring = row('w'); out.logDuring = log.slice();
    server.parked.get('wait-sess')({ ok: false, status: 500 });
    out.answer = await cancelling; out.after = um._controlSig(um.items.get('w')); out.rowAfter = row('w');
    server.park.clear(); log.length = 0;
    um.resume('w'); um.items.get('w').file = {}; um._start(um.items.get('w')); await um.lastRun; out.resumed = snap();
    """)
    assert out["before"] == "resume-text,cancel"
    # (mutations: offer the re-pick while the cancel is out -> red; let a run touch a cancelled
    # row -> its status becomes 'uploading' -> red; let resume() act on it -> 'reselect w' -> red.)
    assert out["during"] == "cancel", out["during"]
    assert out["rowDuring"] == {"status": "needs-file", "cancelled": True, "error": None}, out["rowDuring"]
    assert out["logDuring"] == ["DELETE /vaults/V/uploads/wait-sess"], out["logDuring"]
    # Refused: the row is what it was, with its control back, and the refusal said beside it.
    assert out["answer"] is False and out["after"] == "resume-text,cancel"
    assert out["rowAfter"] == {"status": "needs-file", "cancelled": False, "error": None}, out["rowAfter"]
    assert out["resumed"]["log"] == ["reselect w", "POST /vaults/V/uploads/wait-sess/complete"], out["resumed"]


def test_a_cancel_clicked_during_the_last_destructive_request_is_not_answered_with_a_commit():
    out = _serve("""
    fresh(victim(), ours()); server.park.add('old-sess');
    const running = um._run('o'); await settle();              // the earlier upload's DELETE is out
    await um.cancel('o');                                       // the user cancels OURS meanwhile
    server.parked.get('old-sess')({ ok: true, status: 204 }); await running;
    out.duringRivalCancel = snap();
    // ... and during the LAST one there is: the delete of the committed file. No turn of the loop
    // follows it, so nothing reads the withdrawal again unless it is read there on purpose.
    fresh(ours({ replaces: chose('F') })); server.park.add('file');
    const last = um._run('o'); await settle();
    await um.cancel('o');
    server.parked.get('file')({ ok: true, status: 200 }); await last;
    out.duringFileDelete = snap();
    """)
    # Held by the read at the top of the next turn.
    r = out["duringRivalCancel"]
    assert r["log"] == [DEL_OLD, DEL_NEW, CANCELLED_ONLY] and r["o"] is None, r
    # (mutation: drop BOTH re-reads -- the one after the last step and the one before the commit --
    # and the commit is in this log. Either alone still holds it, so each has its source pin below.)
    f = out["duringFileDelete"]
    assert f["log"] == [DEL_FILE, DEL_NEW] and f["o"] is None, f


def test_the_fire_point_under_the_conditions_nothing_else_exercised():
    out = _serve("""
    // A session the server had expired: restarted under a new one, and the step still fires whole.
    fresh(victim(), ours({ received: new Set(), lastPut: null, chunkSize: 10, replaces: chose('F'),
        file: { size: 10, slice: () => ({ arrayBuffer: async () => new ArrayBuffer(10) }) } }));
    server.puts = [{ ok: false, status: 410 }];
    await um._run('o'); out.expiredOnce = snap();
    // The server does NOT hold everything: nothing is fired, nothing is committed.
    fresh(victim(), ours({ lastPut: null })); server.held = { received_chunks: [], bytes_received: 0 };
    await um._run('o'); out.notAllHeld = snap();
    // A committed file alone: removed, then the commit; refused, and nothing is uploaded.
    fresh(ours({ replaces: chose('F') })); await um._run('o'); out.fileRemoved = snap();
    fresh(ours({ replaces: chose('F') })); server.refuse.add('file'); await um._run('o'); out.fileRefused = snap();
    // A PAUSE is not a withdrawal -- nothing is said, nothing of ours is dropped -- but it is
    // honoured: no destructive step after it, the row waits as 'paused', and Resume finishes.
    fresh(victim({ status: 'completing' }), ours());
    const running = um._run('o'); await settle();
    Object.assign(um.items.get('o'), { paused: true, status: 'pausing' });
    um.items.get('v').status = 'uploading'; flush(); await running; out.pausedMeanwhile = snap();
    log.length = 0; um.resume('o'); await um.lastRun; out.pausedThenResumed = snap();
    // Paused while the LAST destructive request is out: that request is not undone, but no commit.
    fresh(victim(), ours({ replaces: chose('F') })); server.park.add('file');
    const last = um._run('o'); await settle(); await settle();
    Object.assign(um.items.get('o'), { paused: true, status: 'pausing' });
    server.parked.get('file')({ ok: true, status: 200 }); await last; out.pausedDuringDelete = snap();
    // NO LATCH ACROSS RUNS: the commit fails; Resume resolves everything again and commits.
    fresh(ours({ lastPut: null, replaces: chose('F') }));
    server.completes = [{ ok: false, status: 503, json: async () => ({ detail: 'try later' }) }];
    await um._run('o'); out.commitFailed = snap();
    log.length = 0; um.resume('o'); await um.lastRun; out.thenResumed = snap();
    // ONE RUN PER ROW: a second entry returns at once, while the first is still out, and only one
    // commit is ever sent. (Without the mark the second entry is a full run of its own: it finds
    // the earlier upload mid-cancel and WAITS for it -- so it is given every chance to finish here,
    // rather than being left parked, which would end the harness with nothing written.)
    fresh(victim(), ours({ lastPut: null })); server.park.add('old-sess');
    const firstRun = um._run('o'); await settle();
    let secondReturned = false; const secondRun = um._run('o').then(() => { secondReturned = true; });
    await settle(); out.secondReturnedAtOnce = secondReturned; out.whileFirstIsOut = log.slice();
    server.parked.get('old-sess')({ ok: true, status: 204 });
    for (let k = 0; k < 6; k++) { await settle(); flush(); }
    await firstRun; await secondRun; out.twice = snap();
    // (f) The commit is REFUSED after the earlier upload was really cancelled: an error row with the
    // server's reason, no crash, and Resume goes through the step again.
    fresh(victim(), ours({ lastPut: null }));
    server.completes = [{ ok: false, status: 409, json: async () => ({ detail: 'name rule' }) },
                        { ok: false, status: 410, json: async () => ({ detail: { message: 'session expired' } }) }];
    await um._run('o'); out.refused409 = snap();
    log.length = 0; um.resume('o'); await um.lastRun; out.refused410 = snap();
    log.length = 0; um.resume('o'); await um.lastRun; out.thenAccepted = snap();
    // (c) An upload with NOTHING to fire, cancelled while its last chunk's answer is being read.
    fresh(sent('o', 'new-sess', { received: new Set(), lastPut: null, chunkSize: 10,
        file: { size: 10, slice: () => ({ arrayBuffer: async () => new ArrayBuffer(10) }) } }));
    server.puts = [{ ok: true, status: 200, json: async () => { await um.cancel('o'); return { complete: true, bytes_received: 10 }; } }];
    await um._run('o'); out.cancelledInLastPut = snap();
    """)
    # (mutation: the restart drops what the upload replaces -> the file delete is missing -> red.)
    assert out["expiredOnce"]["log"] == [
        "PUT /vaults/V/uploads/new-sess/chunks/0", "init", "PUT /vaults/V/uploads/renewed-sess/chunks/0",
        DEL_OLD, DEL_FILE, CANCELLED_ONLY, "POST /vaults/V/uploads/renewed-sess/complete", REPLACED], out["expiredOnce"]
    # (mutation: go on when the server does not hold everything -> the DELETE is in this log -> red.)
    held = out["notAllHeld"]
    assert held["log"] == ["GET /vaults/V/uploads/new-sess"], held
    assert held["o"]["status"] == "error" and held["o"]["error"].startswith("Could not confirm that the whole upload arrived")
    assert held["v"]["status"] == "uploading"
    assert out["fileRemoved"]["log"] == [DEL_FILE, COMPLETE], out["fileRemoved"]
    assert out["fileRefused"]["log"] == [DEL_FILE, NOT_REPLACED, DEL_NEW], out["fileRefused"]
    # (mutation: stop reading the pause at the fire point -> the DELETE and the commit are in the
    # first log -> red.)
    paused = out["pausedMeanwhile"]
    assert paused["log"] == [] and paused["o"]["status"] == "paused" and paused["v"]["status"] == "uploading", paused
    assert out["pausedThenResumed"]["log"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED], out["pausedThenResumed"]
    # The cancel that happened is said; nothing is committed and nothing is claimed as replaced.
    # (mutation: stop reading the pause after the last destructive request -> the commit -> red.)
    assert out["pausedDuringDelete"]["log"] == [DEL_OLD, DEL_FILE, CANCELLED_ONLY], out["pausedDuringDelete"]
    assert out["pausedDuringDelete"]["o"]["status"] == "paused"
    failed = out["commitFailed"]
    assert failed["log"] == ["GET /vaults/V/uploads/new-sess", DEL_FILE, COMPLETE], failed
    assert failed["o"] == {"status": "error", "cancelled": False, "error": "try later"}, failed
    # (mutation: a latch that remembers the step has fired -> the second pass skips the GET and the
    # delete -> red.) The file is already gone by then; "gone" is an answer, not a failure.
    assert out["thenResumed"]["log"] == ["GET /vaults/V/uploads/new-sess", DEL_FILE, COMPLETE], out["thenResumed"]
    assert out["thenResumed"]["o"]["status"] == "done"
    # (mutation: remove the in-flight mark -> the second entry does not return, and sends a GET of
    # its own -> red here, and two commits below.)
    assert out["secondReturnedAtOnce"] is True
    assert out["whileFirstIsOut"] == ["GET /vaults/V/uploads/new-sess", DEL_OLD], out["whileFirstIsOut"]
    assert out["twice"]["log"] == ["GET /vaults/V/uploads/new-sess", DEL_OLD, CANCELLED_ONLY, COMPLETE, REPLACED], out["twice"]
    r409 = out["refused409"]
    # (mutation: claim the replacement at the step, before the commit -> "replaced by this one"
    # beside an error row -> red.)
    assert r409["log"] == ["GET /vaults/V/uploads/new-sess", DEL_OLD, CANCELLED_ONLY, COMPLETE], r409
    assert r409["o"] == {"status": "error", "cancelled": False, "error": "name rule"} and r409["v"] is None, r409
    assert out["refused410"]["log"] == ["GET /vaults/V/uploads/new-sess", COMPLETE], out["refused410"]
    assert out["refused410"]["o"]["error"] == "session expired"
    # ... said exactly once, by the pass whose commit succeeded -- two passes after the cancel.
    assert out["thenAccepted"]["log"] == ["GET /vaults/V/uploads/new-sess", COMPLETE, REPLACED] and out["thenAccepted"]["o"]["status"] == "done"
    # (mutation: remove the send loop's own read before the commit -> the commit is sent -> red.
    # The fire step never runs for this row, so nothing else could hold it.)
    last = out["cancelledInLastPut"]
    assert last["log"] == ["PUT /vaults/V/uploads/new-sess/chunks/0", DEL_NEW] and last["o"] is None, last


def test_every_way_out_says_the_cancels_that_happened_and_counts_them():
    out = _serve("""
    const three = () => [sent('a', 's1', { order: 1 }), sent('b', 's2', { order: 1.5 }), sent('c', 's3', { order: 1.7 })];
    fresh(...three(), ours()); await um._run('o'); out.three = snap();
    fresh(...three().slice(0, 2), ours()); server.refuse.add('s2'); await um._run('o'); out.secondRefused = snap();
    // Ours is cancelled by the user while it waits on the SECOND rival, after the first was cancelled.
    fresh(sent('a', 's1', { order: 1 }), sent('b', 's2', { order: 1.5, status: 'completing' }), ours());
    const running = um._run('o'); await settle(); await settle();
    await um.cancel('o'); um.items.get('b').status = 'uploading'; flush(); await running; out.withdrawnAfterOne = snap();
    // A dropped row whose own DELETE is still out: Resume must not touch it.
    fresh(victim(), ours()); server.refuse.add('old-sess'); server.park.add('new-sess');
    const dropping = um._run('o'); await settle(); await settle();
    log.length = 0; um.resume('o'); await settle();
    out.resumeWhileRemoving = { log: log.slice(), row: row('o'), sig: um._controlSig(um.items.get('o')) };
    """)
    S = lambda n: f"DELETE /vaults/V/uploads/s{n}"
    assert out["three"]["log"] == [S(1), S(2), S(3), 'toast info 3 earlier uploads of "X" were cancelled.', COMPLETE,
                                   'toast info 3 earlier uploads of "X" were replaced by this one.'], out["three"]
    # (mutation: say nothing about a cancel that happened on the way out -> red.)
    # ... and the two sentences are not both about "the earlier upload": one WAS cancelled, ANOTHER
    # could not be. (mutation: the single-refusal wording here too -> red.)
    assert out["secondRefused"]["log"] == [S(1), S(2), CANCELLED_ONLY, DROPPED_ANOTHER, DEL_NEW], out["secondRefused"]
    assert out["withdrawnAfterOne"]["log"] == [S(1), DEL_NEW, CANCELLED_ONLY], out["withdrawnAfterOne"]
    # (mutation: let a run start on a cancelled row -> its text is wiped -> red.)
    r = out["resumeWhileRemoving"]
    assert r["log"] == [] and r["sig"] == "cancel", r
    assert r["row"] == {"status": "error", "cancelled": True, "error": REMOVING_ROW}, r


def test_a_rival_cancelled_while_its_session_is_being_opened_leaves_no_orphan_session():
    out = _serve("""
    let opened;                                            // the rival's session is still being opened
    const holdInit = () => { server.onInit = (it) => it.id === 'q'
        ? new Promise(res => { opened = () => { it.sessionId = 'q-sess'; res(); }; }) : null; };
    fresh(sent('q', null, { order: 1, status: 'queued', received: new Set(), lastPut: null }),
          ours({ replaces: { deleteId: null, known: { sessions: [], items: ['q'] } } }));
    holdInit();
    const rival = um._run('q'); await settle();
    const running = um._run('o'); await settle(); out.parked = timers.length;       // ours waits: nothing to delete yet
    opened(); await rival; flush(); await running; out.openedInTime = snap();
    // ... and one cancelled outright while its session is being opened: the session that then
    // arrives is deleted by the run that opened it.
    fresh(sent('q', null, { order: 1, status: 'queued', received: new Set(), lastPut: null }));
    holdInit();
    const again = um._run('q'); await settle();
    out.cancelAnswer = await um.cancel('q'); opened(); await again; out.cancelledDuringInit = snap();
    // The same for a ZERO-KNOWLEDGE row: the record `_init` saved for that session goes with it.
    fresh(sent('q', null, { order: 1, status: 'queued', received: new Set(), lastPut: null, isZk: true }));
    holdInit(); const zkRun = um._run('q'); await settle();
    await um.cancel('q'); opened(); await zkRun; out.zkCancelledDuringInit = snap();
    // ... and when the server REFUSES that delete, the session is alive: the row comes BACK.
    fresh(sent('q', null, { order: 1, status: 'queued', received: new Set(), lastPut: null }));
    holdInit(); server.refuse.add('q-sess'); const refusedRun = um._run('q'); await settle();
    await um.cancel('q'); out.goneMeanwhile = row('q'); opened(); await refusedRun;
    out.abandonRefused = { log: log.slice(), row: row('q') };
    // A rival whose session NEVER finishes opening: past the wait it is not "cancelled" by taking
    // its row away -- nothing was deleted, and the session will exist a moment later.
    fresh(sent('q', null, { order: 1, status: 'queued', received: new Set(), lastPut: null }),
          ours({ replaces: { deleteId: null, known: { sessions: [], items: ['q'] } } }));
    holdInit(); um._run('q'); await settle();
    const stuck = um._run('o');
    for (let k = 0; k < 220; k++) { await settle(); flush(); }
    await stuck; out.stuckInit = snap(); out.stuckRival = row('q');
    """)
    assert out["zkCancelledDuringInit"]["log"] == ["init", "DELETE /vaults/V/uploads/q-sess"]
    assert out["zkCancelledDuringInit"]["records"] == ["q-sess"], out["zkCancelledDuringInit"]
    # (mutation: do not read the abandon's answer -> the row stays gone while its session lives -> red.)
    assert out["goneMeanwhile"] is None
    assert out["abandonRefused"] == {"log": ["init", "DELETE /vaults/V/uploads/q-sess"],
                                     "row": {"status": "error", "cancelled": False, "error": REFUSED_ROW}}, out["abandonRefused"]
    # (mutation: count a rival with no session as cancelled -> its row is taken away, "was cancelled"
    # is said with no request behind it, and ours commits -> red.)
    stuck = out["stuckInit"]
    assert stuck["log"] == ["init", DROPPED, DEL_NEW], stuck
    assert out["stuckRival"] == {"status": "uploading", "cancelled": False, "error": None} and stuck["o"] is None
    assert out["parked"] == 1, "ours did not wait for the rival's session to exist"
    # Our wait ends once the session exists; then it gets a REAL delete. (The rival's own run then
    # fails in this harness, which gives it no file to slice: an error row WITH a session -- which
    # is still a rival, and still gets the delete.)
    assert "DELETE /vaults/V/uploads/q-sess" in out["openedInTime"]["log"], out["openedInTime"]
    assert out["openedInTime"]["log"][-3:] == [CANCELLED_ONLY, COMPLETE, REPLACED]
    # (mutation: do not read `cancelled` after the session is opened -> no DELETE, an orphan -> red.)
    assert out["cancelAnswer"] is True
    assert out["cancelledDuringInit"]["log"] == ["init", "DELETE /vaults/V/uploads/q-sess"], out["cancelledDuringInit"]


def test_what_landed_is_forgotten_at_sign_out_but_never_while_an_answer_is_owed():
    out = _serve("""
    fresh(victim({ status: 'done' }), ours());
    um._noteLanded(um.items.get('v'));
    for (let k = 0; k < 260; k++) um._noteLanded({ vaultId: 'V', folderId: null, fileName: 'other-' + k });
    out.kept = um._landed.length; out.stillThere = um._landedSince(um.items.get('o'));
    await um._run('o'); out.standsAside = snap();
    // With no replacement waiting on them, old landings are bounded.
    fresh(); for (let k = 0; k < 260; k++) um._noteLanded({ vaultId: 'V', folderId: null, fileName: 'other-' + k });
    out.bounded = um._landed.length;
    um.items.set('z', sent('z', 'z-sess')); um.reset(); out.afterReset = { landed: um._landed.length, items: um.items.size, seq: um.seq > 100 };
    """)
    # (mutation: a flat shift at 200 -> the landing our replacement still has to ask about is
    # evicted, and it commits past the file that landed first -> red.)
    assert out["stillThere"] is True and out["kept"] == 261, out
    assert COMPLETE not in out["standsAside"]["log"], out["standsAside"]
    assert out["bounded"] == 200
    # (mutation: reset leaves what landed -> the next account's tray knows the last one's names -> red.)
    assert out["afterReset"] == {"landed": 0, "items": 0, "seq": True}, out["afterReset"]


def test_two_resume_clicks_behind_a_full_gate_are_one_run_and_a_landed_row_is_never_run_again():
    # The in-flight mark guards two runs that are both STARTED. Behind a full transfer gate neither
    # has started: two Resume clicks used to queue two runs, the first committed, and the second
    # then started on a row that had already landed -- a GET for a finalised session, and an error
    # row for a file that was safely there.
    js = APP_JS.read_text(encoding="utf-8")
    shipped_run = _method(js, "async run(id) {").replace("    async run(id) {", "    async shippedRun(id) {", 1)
    out = _node(SERVER % ("".join(_method(js, h) for h in LIFTED) + shipped_run, """
    globalThis.transferGate = { q: [], run(fn) { return new Promise(res => this.q.push(() => fn().then(res))); } };
    um.run = um.shippedRun;
    fresh(ours({ status: 'paused', paused: true, lastPut: null }));
    um.resume('o'); um.resume('o');                              // two clicks while the gate is full
    out.queued = transferGate.q.length;
    for (const start of transferGate.q.splice(0)) await start();
    out.twoClicks = snap();
    log.length = 0; await um._run('o'); out.runOnALandedRow = { log: log.slice(), row: row('o') };
    // ... and the mark is given back, so a row that fails can be resumed again.
    fresh(ours({ status: 'paused', paused: true }));
    server.completes = [{ ok: false, status: 503, json: async () => ({ detail: 'later' }) }];
    um.resume('o'); for (const start of transferGate.q.splice(0)) await start();
    um.resume('o'); out.requeued = transferGate.q.length;
    for (const start of transferGate.q.splice(0)) await start(); out.secondAttempt = row('o');
    """))
    # (mutation: no mark on a QUEUED run -> two are queued -> red.)
    assert out["queued"] == 1, out["queued"]
    assert out["twoClicks"]["log"] == ["GET /vaults/V/uploads/new-sess", COMPLETE], out["twoClicks"]
    assert out["twoClicks"]["o"]["status"] == "done"
    # (mutation: let a run start on a landed row -> a second GET and a second commit -> red.)
    assert out["runOnALandedRow"] == {"log": [], "row": {"status": "done", "cancelled": False, "error": None}}, out["runOnALandedRow"]
    assert out["requeued"] == 1 and out["secondAttempt"]["status"] == "done", out


DRAWN = ("render() {", "_patchRow(row, it) {", "_buildRow(it) {", "_renderSub(sub, it) {", "_buildControls(el, it) {",
         "_percent(it) {", "_statusLabel(status) {")

MINI_DOM = """
    // A DOM just big enough for the shipped render(): what is asserted below is what is DRAWN.
    const mk = (tag) => { const e = { tag, children: [], attrs: {}, className: '', textContent: '', style: {}, title: '',
        classList: { add(c) { e.className = (e.className + ' ' + c).trim(); },
                     remove(c) { e.className = e.className.split(' ').filter(x => x !== c).join(' '); } },
        setAttribute(k, v) { e.attrs[k] = String(v); }, getAttribute(k) { return e.attrs[k]; },
        appendChild(c) { e.children.push(c); c.parent = e; return c; }, append(...cs) { cs.forEach(c => e.appendChild(c)); },
        replaceChildren(...cs) { e.children = []; cs.forEach(c => e.appendChild(c)); },
        remove() { if (e.parent) e.parent.children = e.parent.children.filter(x => x !== e); },
        addEventListener(ev, fn) { e.on = fn; },
        querySelector(sel) { const wanted = sel.split('data-up-row="')[1].split('"')[0];
            return e.children.find(c => c.attrs && c.attrs['data-up-row'] === wanted) || null; },
        querySelectorAll() { return e.children.filter(c => (c.className || '').split(' ').includes('up-row')); } };
        return e; };
    let tray = null;
    Object.assign(document, { createElement: mk, createTextNode: (text) => ({ text }),
        body: { appendChild(t) { tray = t; } }, getElementById: (id) => (id === 'upload-tray' ? tray : null) });
    globalThis.window = {}; globalThis.formatBytes = undefined;
    um._iconEl = (name) => ({ icon: name });
    const drawn = (id) => { const r = tray && tray._body && tray._body.children.find(c => c.attrs['data-up-row'] === id);
        return r ? { buttons: r._controls.children.map(b => b.attrs['data-up-action'] + (b.textContent ? ':' + b.textContent : '')),
                     sub: r._sub.children.map(c => c.text).join(''),
                     click: (action) => { const b = r._controls.children.find(x => x.attrs['data-up-action'] === action); if (b) b.on(); return !!b; } } : null; };
    const seen = (id) => { const d = drawn(id); return d ? { buttons: d.buttons, sub: d.sub } : null; };
"""


def test_a_row_whose_cancel_is_out_is_DRAWN_that_way_at_once():
    # Found by clicking: the state of a row whose cancel was out was right, and what was on the
    # screen was not. cancel() marked the row and then waited for the server without drawing it, and
    # a row waiting for its file gets no other render -- so it kept the Resume it had before, a
    # button that did nothing, for as long as the request hung. The model was already pinned; this
    # reads the tray as the shipped render() draws it.
    js = APP_JS.read_text(encoding="utf-8")
    out = _node(SERVER % ("".join(_method(js, h) for h in LIFTED + DRAWN), MINI_DOM + """
    fresh(sent('w', 'wait-sess', { status: 'needs-file', file: null, paused: true }));
    um.render(); out.before = seen('w');
    server.park.add('wait-sess');
    const cancelling = um.cancel('w'); await settle();
    out.during = seen('w'); out.resumeWasThere = drawn('w').click('resume'); out.logDuring = log.slice();
    server.parked.get('wait-sess')({ ok: false, status: 500 }); await cancelling;
    out.refused = seen('w'); out.toasts = toasts();
    out.pickerWorksAgain = drawn('w').click('resume'); out.logAfter = log.slice(-1);
    // A row that is uploading, cancelled by the user, the request hanging: the same.
    fresh(sent('u', 'u-sess', { received: new Set() })); um.render(); server.park.add('u-sess');
    const c2 = um.cancel('u'); await settle(); out.uploadingDuring = seen('u');
    server.parked.get('u-sess')({ ok: true, status: 204 }); await c2; out.uploadingAfter = seen('u');
    // A DROPPED replacement says more about itself than "Cancelling", and keeps saying it.
    fresh(victim(), ours()); um.render(); server.refuse.add('old-sess'); server.park.add('new-sess');
    um._run('o'); await settle(); await settle(); out.dropped = seen('o');
    // A row that is `cancelled` for good with NO request out (its session is already gone: the
    // vault key changed under it) keeps saying why -- nothing is being cancelled any more.
    fresh(sent('k', null, { status: 'error', cancelled: true, error: 'The vault key changed during upload' }));
    um.render(); out.keyChanged = seen('k');
    """))
    # (mutation: say "Cancelling" for every cancelled row, request or none -> it would say so for ever -> red.)
    assert out["keyChanged"] == {"buttons": ["cancel"], "sub": "The vault key changed during upload"}, out["keyChanged"]
    sentence = "Paused — click Resume and re-select the file"
    assert out["before"] == {"buttons": ["resume:Resume…", "cancel"], "sub": sentence}, out["before"]
    # (mutation: do not draw the row when it is marked -> the stale Resume is still in the tray,
    # under the old sentence -> red.)
    assert out["during"] == {"buttons": ["cancel"], "sub": "Cancelling…"}, out["during"]
    assert out["resumeWasThere"] is False and out["logDuring"] == ["DELETE /vaults/V/uploads/wait-sess"]
    # Refused: the picker and its sentence are back on the screen, and the refusal is said.
    assert out["refused"] == {"buttons": ["resume:Resume…", "cancel"], "sub": sentence}, out["refused"]
    assert out["toasts"] == ['toast error Could not cancel "X" — the server did not confirm it. Try again.']
    assert out["pickerWorksAgain"] is True and out["logAfter"] == ["reselect w"]
    assert out["uploadingDuring"] == {"buttons": ["cancel"], "sub": "Cancelling…"}, out["uploadingDuring"]
    assert out["uploadingAfter"] is None
    # (mutation: say "Cancelling" on a dropped row too -> red.)
    assert out["dropped"] == {"buttons": ["cancel"], "sub": REMOVING_ROW}, out["dropped"]


def test_an_earlier_upload_stays_known_when_its_session_is_re_opened():
    # The server expires a session; the row that owns it opens another under a new id. A row known
    # to a replacement only by its SESSION stopped being known at that moment, and the replacement
    # committed straight past a live earlier upload of the name -- the one thing this step is for.
    out = _serve("""
    const pairKnownAsTheProductRecordsIt = () => { fresh(victim(), ours());
        um.items.get('o').replaces = { deleteId: null, known: um._knownFrom([um.items.get('v')]) }; };
    pairKnownAsTheProductRecordsIt(); out.recorded = um.items.get('o').replaces.known;
    const a = um.items.get('v'); a.sessionId = null; await um._init(a);        // as the 410 restart does
    out.stillToCancel = um._rivalsToCancel(um.items.get('o')).map(r => r.id);
    log.length = 0; await um._run('o'); out.afterRestart = snap();
    """)
    assert out["recorded"] == {"sessions": ["old-sess"], "items": ["v"]}, out["recorded"]
    # (mutation: keep only the session for a row that has one -> [] here, and the commit alone below -> red.)
    assert out["stillToCancel"] == ["v"]
    assert out["afterRestart"]["log"] == ["DELETE /vaults/V/uploads/renewed-sess", CANCELLED_ONLY, COMPLETE, REPLACED], out["afterRestart"]


def _gated(js: str, scenarios: str, extra=()) -> dict:
    # The SHIPPED run() and pause(), so the transfer gate is really in the path.
    shipped = _method(js, "async run(id) {").replace("    async run(id) {", "    async shippedRun(id) {", 1)
    methods = "".join(_method(js, h) for h in LIFTED + ("pause(id) {",) + tuple(extra)) + shipped
    return _node(SERVER % (methods, "    um.run = um.shippedRun;\n" + scenarios))


def test_a_commit_that_reports_parts_missing_is_retried_in_the_slot_it_holds_and_not_for_ever():
    # The retry used to ask the gate for ANOTHER slot from inside the one it held. The outer slot is
    # not given back until the inner run settles, so each round nested one deeper; a handful of
    # uploads doing that at once left the whole tab -- downloads too -- with no slot to give.
    js = APP_JS.read_text(encoding="utf-8")
    out = _gated(js, """
    globalThis.transferGate = { active: 0, deepest: 0, async run(fn) { this.active++;
        this.deepest = Math.max(this.deepest, this.active); try { return await fn(); } finally { this.active--; } } };
    const missing = () => ({ ok: false, status: 409, json: async () => ({ detail: { missing_chunks: [0] } }) });
    const whole = () => sent('o', 'new-sess', { chunkSize: 10, file: { size: 10, slice: () => ({ arrayBuffer: async () => new ArrayBuffer(10) }) } });
    fresh(whole()); server.completes = [missing()];
    await um.run('o'); out.once = snap(); out.onceDeepest = transferGate.deepest;
    transferGate.deepest = 0;
    fresh(whole()); server.completes = [missing(), missing(), missing(), missing(), missing()];
    await um.run('o'); out.always = snap(); out.alwaysDeepest = transferGate.deepest; out.activeAfter = transferGate.active;
    out.resumable = !um.items.get('o')._pending && !um.items.get('o')._running;
    """)
    PUT = "PUT /vaults/V/uploads/new-sess/chunks/0"
    assert out["once"]["log"] == [COMPLETE, PUT, COMPLETE] and out["once"]["o"]["status"] == "done", out["once"]
    # (mutation: retry through the gate again -> two slots deep -> red. The LOG is identical either
    # way, which is how this went unseen: it is the nesting that is asserted.)
    assert out["onceDeepest"] == 1 and out["alwaysDeepest"] == 1, out
    # Bounded: three refills, then a row the user can act on -- never left 'completing'.
    always = out["always"]
    assert always["log"] == [COMPLETE, PUT, COMPLETE, PUT, COMPLETE, PUT, COMPLETE], always
    assert always["o"]["status"] == "error" and always["o"]["error"].startswith("The server kept reporting parts"), always
    assert out["activeAfter"] == 0 and out["resumable"] is True


def test_pause_on_a_row_that_is_still_queued_holds_when_its_slot_comes():
    # Pause left a queued row's status alone, and the run cleared `paused` as it started -- so the
    # button did nothing and the file went up anyway.
    js = APP_JS.read_text(encoding="utf-8")
    out = _gated(js, """
    globalThis.transferGate = { q: [], run(fn) { return new Promise(res => this.q.push(() => fn().then(res))); } };
    const drain = async () => { for (const start of transferGate.q.splice(0)) await start(); };
    fresh(sent('o', 'new-sess', { status: 'queued', received: new Set(), lastPut: null, chunkSize: 10,
        file: { size: 10, slice: () => ({ arrayBuffer: async () => new ArrayBuffer(10) }) } }));
    um.run('o'); um.pause('o'); out.whileQueued = row('o'); out.offers = um._controlSig(um.items.get('o'));
    await drain(); out.slotCame = snap();
    um.resume('o'); await drain(); out.resumed = snap();
    // Paused while queued AND resumed while still queued: the run already in the queue is the one
    // that goes -- nothing new is queued -- and it must find the row un-paused when its slot comes.
    fresh(sent('o', 'new-sess', { status: 'queued', received: new Set(), lastPut: null, chunkSize: 10,
        file: { size: 10, slice: () => ({ arrayBuffer: async () => new ArrayBuffer(10) }) } }));
    um.run('o'); um.pause('o'); um.resume('o');
    out.stillQueued = { queued: transferGate.q.length, row: row('o'), offers: um._controlSig(um.items.get('o')) };
    await drain(); out.ranWhenTheSlotCame = snap();
    """)
    # Paused at once, so that the row SHOWS Resume: left 'queued' it went on offering only Pause.
    # (mutation: leave a queued row's status alone -> 'queued', offering 'pause,cancel' -> red.)
    assert out["whileQueued"]["status"] == "paused" and out["offers"] == "resume,cancel", out
    # (mutation: Resume on a row whose run is queued does nothing at all -> the slot comes, the row
    # is still paused, and the log is empty -> red.)
    assert out["stillQueued"] == {"queued": 1, "row": {"status": "queued", "cancelled": False, "error": None},
                                  "offers": "pause,cancel"}, out["stillQueued"]
    assert out["ranWhenTheSlotCame"]["log"] == ["PUT /vaults/V/uploads/new-sess/chunks/0", COMPLETE], out["ranWhenTheSlotCame"]
    # (mutation: clear `paused` when the run starts -> the PUT and the commit are in this log -> red.)
    assert out["slotCame"]["log"] == [] and out["slotCame"]["o"]["status"] == "paused", out["slotCame"]
    assert out["resumed"]["log"] == ["PUT /vaults/V/uploads/new-sess/chunks/0", COMPLETE] and out["resumed"]["o"]["status"] == "done"


def test_a_picked_file_goes_to_the_row_that_holds_the_session_now():
    # The chooser stays open as long as the user likes, and the tray is rebuilt from the server
    # meanwhile: every row waiting for its file comes back under a NEW id. The pick used to be
    # handed to the row the chooser was opened for -- by then an object in no list -- and nothing
    # happened, silently.
    js = APP_JS.read_text(encoding="utf-8")
    out = _node(SERVER % ("".join(_method(js, h) for h in LIFTED + ("_reselect(id) {", "async _continueWith(it, file) {")), """
    const input = { style: {}, value: '', click() {} };
    Object.assign(document, { getElementById: (id) => (id === 'upload-reselect-input' ? input : null) });
    globalThis.isZkVault = () => false;
    const waiting = (id) => sent(id, 'old-sess', { status: 'needs-file', file: null, restored: true, paused: true });
    const pick = () => input.onchange({ target: { files: [{ name: 'X', size: 10 }] } });
    // Rebuilt under a new id between the click and the pick.
    fresh(waiting('k1')); um._reselect('k1');
    const old = um.items.get('k1'); um.items.delete('k1'); um.items.set('k2', { ...old, id: 'k2' });
    await pick(); await um.lastRun; out.rebuilt = { log: log.slice(), rows: [...um.items.keys()], status: um.items.get('k2').status };
    // Gone altogether (its session finished or was cancelled elsewhere): said, not swallowed.
    fresh(waiting('k1')); um._reselect('k1'); um.items.delete('k1');
    await pick(); out.gone = { log: log.slice(), rows: [...um.items.keys()] };
    // Untouched meanwhile: the row the chooser was opened for.
    fresh(waiting('k1')); um._reselect('k1'); await pick(); await um.lastRun; out.same = log.slice();
    out.pickingCleared = !um.items.get('k1').picking;
    """))
    ran = ["GET /vaults/V/uploads/old-sess", "POST /vaults/V/uploads/old-sess/complete"]
    # (mutation: hand the pick to the row the chooser was opened for -> nothing happens -> red.)
    assert out["rebuilt"] == {"log": ran, "rows": ["k2"], "status": "done"}, out["rebuilt"]
    assert out["gone"]["rows"] == [] and len(out["gone"]["log"]) == 1, out["gone"]
    assert out["gone"]["log"][0].startswith('toast error "X" is no longer in the upload list, so nothing was uploaded.')
    assert out["same"] == ran and out["pickingCleared"] is True


def test_a_commit_that_outlives_a_sign_out_writes_nothing_into_the_next_tray():
    out = _serve("""
    fresh(sent('o', 'new-sess'));
    let answer; server.completes = [new Promise(res => { answer = res; })];
    const running = um._run('o'); await settle();               // the commit is out
    um.reset();                                                  // the account signs out
    answer({ ok: true, status: 200, json: async () => ({}) }); await running;
    out.afterSignOut = { landed: um._landed.length, log: log.slice() };
    fresh(sent('o', 'new-sess')); await um._run('o'); out.ordinary = um._landed.map(l => l.fileName);
    // A REPLACEMENT: what it replaced is said after its commit -- but not to the next person. And
    // the tray is not drawn again for a row that is no longer anyone's.
    let renders = 0; um.render = () => { renders++; };
    fresh(victim(), ours());
    let late; server.completes = [new Promise(res => { late = res; })];
    const replacing = um._run('o'); await settle(); await settle();
    um.reset(); renders = 0; const said = log.length;
    late({ ok: true, status: 200, json: async () => ({}) }); await replacing;
    out.replacement = { landed: um._landed.length, saidAfter: log.slice(said), renders, before: log.slice(0, said) };
    // The same for a commit that FAILS after the sign-out: its error row is nobody's to draw.
    fresh(sent('o', 'new-sess'));
    let failing; server.completes = [new Promise(res => { failing = res; })];
    const doomed = um._run('o'); await settle();
    um.reset(); renders = 0;
    failing({ ok: false, status: 503, json: async () => ({ detail: 'later' }) }); await doomed;
    out.failedAfter = renders;
    // The landing's OWN check, asked directly: a stale epoch records nothing, the current one does.
    fresh(); um._noteLanded({ vaultId: 'V', fileName: 'stale' }, (um._epoch || 0) - 1); out.staleNoted = um._landed.length;
    um._noteLanded({ vaultId: 'V', fileName: 'now' }, um._epoch || 0); out.currentNoted = um._landed.length;
    """)
    # (mutation: record the landing whatever has happened since -> the next account's tray knows a
    # file name of the last one -> red.)
    assert out["afterSignOut"] == {"landed": 0, "log": [COMPLETE]}, out["afterSignOut"]
    assert out["ordinary"] == ["X"]
    r = out["replacement"]
    assert r["before"] == [DEL_OLD, CANCELLED_ONLY, COMPLETE], r
    # (mutation: only the landing looks at the sign-out -> "...was replaced by this one", naming the
    # last account's file, on the next person's screen, and a render -> red.)
    assert r["saidAfter"] == [] and r["renders"] == 0 and r["landed"] == 0, r
    assert out["failedAfter"] == 0
    assert out["staleNoted"] == 0 and out["currentNoted"] == 1


def test_an_older_upload_continued_after_a_newer_one_of_the_name_landed_stands_aside():
    # After a reload both come back as rows waiting for their files. The user continues the NEWER
    # one and it lands. Continuing the OLDER one afterwards used to commit it, and the server
    # replaced the newer file with it by name: the older bytes winning, silently.
    out = _serve("""
    const pair = () => fresh(
        sent('v', 'old-sess', { status: 'needs-file', file: null, restored: true, order: 61, startedAt: 1000 }),
        sent('o', 'new-sess', { status: 'needs-file', file: null, restored: true, order: 60, startedAt: 2000 }));
    pair(); um.items.delete('v'); um.items.get('o').file = {}; await um._run('o');   // the newer one lands, alone
    um.items.set('v', sent('v', 'old-sess', { status: 'needs-file', file: null, restored: true, order: 900, startedAt: 1000 }));
    log.length = 0; um.resume('v'); out.adopted = !!um.items.get('v').replaces;
    um.items.get('v').file = {}; await um._run('v'); out.olderAfterNewer = snap();
    // The other way round is the ordinary case: the older landed, the newer is continued, and wins.
    fresh(sent('v', 'old-sess', { restored: true, order: 61, startedAt: 1000 })); await um._run('v');
    um.items.set('o', sent('o', 'new-sess', { status: 'needs-file', file: null, restored: true, order: 900, startedAt: 2000 }));
    log.length = 0; um.resume('o'); um.items.get('o').file = {}; await um._run('o'); out.newerAfterOlder = snap();
    """)
    # (mutation: never ask what landed for a row rebuilt from the server -> the older one commits -> red.)
    assert out["adopted"] is True
    assert out["olderAfterNewer"]["log"] == [
        "reselect v", 'toast error A newer upload of "X" has already finished, so this older copy was not uploaded.',
        DEL_OLD], out["olderAfterNewer"]
    assert out["newerAfterOlder"]["log"] == ["reselect o", COMPLETE], out["newerAfterOlder"]


def test_two_files_of_one_name_in_one_drop_end_as_one_file_whichever_gets_there_first():
    # The second of the pair knows the first (it is added when the batch is enqueued); the first does
    # not know the second, and must not: a relation that ran both ways would have each cancel the
    # other. One direction is enough, because the second cannot LAND while the first is alive --
    # every order below ends with exactly one commit, and says which.
    out = _serve("""
    const E1 = () => sent('e1', 'e1-sess', { order: 1, replaces: chose('F') });
    const E2 = () => sent('e2', 'e2-sess', { order: 2, replaces: { deleteId: 'F', known: { sessions: [], items: ['e1'] } } });
    const commits = () => log.filter(e => e.endsWith('/complete'));
    fresh(E1(), E2()); await um._run('e2'); await um._run('e1'); out.secondFirst = { log: log.slice(), commits: commits() };
    fresh(E1(), E2()); await um._run('e1'); await um._run('e2'); out.firstFirst = { log: log.slice(), commits: commits() };
    fresh(E1(), E2()); um.items.get('e1').status = 'completing';               // the first is mid-commit
    const waiting = um._run('e2'); await settle(); out.parked = timers.length;
    um._noteLanded(um.items.get('e1')); um.items.get('e1').status = 'done'; flush(); await waiting;
    out.together = { log: log.slice(), commits: commits() };
    """)
    C1, C2 = "POST /vaults/V/uploads/e1-sess/complete", "POST /vaults/V/uploads/e2-sess/complete"
    assert out["secondFirst"]["commits"] == [C2] and out["secondFirst"]["log"][0] == "DELETE /vaults/V/uploads/e1-sess"
    overtaken = 'toast error "X" was already uploaded by the earlier transfer, which finished first; the new copy was not uploaded.'
    assert out["firstFirst"]["commits"] == [C1] and overtaken in out["firstFirst"]["log"], out["firstFirst"]
    assert out["firstFirst"]["log"].count(DEL_FILE) == 1                       # the original is deleted once
    assert out["parked"] == 1 and out["together"]["commits"] == [] and overtaken in out["together"]["log"], out["together"]


def test_a_refused_cancel_leaves_a_row_that_is_waiting_for_its_file_as_it_was():
    # An 'error' row swaps the re-pick control for a plain Resume, which cannot work without the
    # file. The row is left alone and the refusal is said beside it, by name.
    out = _serve("""
    for (const [key, extra] of [['standard', {}], ['sealedAsItUploads', { isZk: true, zkPipelined: true }]]) {
        fresh(sent('w', 'wait-sess', { status: 'needs-file', file: null, ...extra }));
        server.refuse.add('wait-sess');
        out[key] = { answer: await um.cancel('w'), row: row('w'), log: log.slice(), records: records.slice() };
    }
    fresh(sent('w', 'wait-sess', { status: 'needs-file', file: null })); server.refuse.add('wait-sess');
    out.askedByANewerUpload = { answer: await um.cancel('w', true), row: row('w'), log: log.slice() };
    """)
    by = out["askedByANewerUpload"]
    # (mutation: report it as the user's own cancel on this branch too -> red.)
    assert by["answer"] is False and by["row"] == {"status": "needs-file", "cancelled": False, "error": None}, by
    assert by["log"][1] == 'toast error A newer upload of "X" could not cancel this one — the server did not confirm it.', by
    for key in ("standard", "sealedAsItUploads"):
        r = out[key]
        assert r["answer"] is False
        # (mutation: make every refusal an 'error' row again -> red.)
        assert r["row"] == {"status": "needs-file", "cancelled": False, "error": None}, r
        assert r["log"] == ["DELETE /vaults/V/uploads/wait-sess",
                            'toast error Could not cancel "X" — the server did not confirm it. Try again.'], r
        assert r["records"] == []


def _code(js: str, head: str) -> str:
    return strip_comments(_method(js, head))


def test_the_source_half_on_code_only():
    js = APP_JS.read_text(encoding="utf-8")
    # What landed is a LIST of records (name, place, when) -- a set of row ids cannot answer "did
    # this NAME land after I was dropped", and `.some` on a Set is a crash at the fire point.
    manager = js[js.index("const uploadManager = {"):js.index("    reset() {")]
    assert manager.count("    _landed: [],\n") == 1 and "new Set()" not in manager
    cancel = _code(js, "async cancel(id, forReplacement) {")
    assert cancel.count("gone = r.ok || r.status === 404;") == 1
    assert "if (!gone) {" in cancel and cancel.index("if (!gone) {") < cancel.index("this.items.delete(id);")
    assert cancel.index("return false;") < cancel.index("await zkUploadStore.delete(it.sessionId);")
    fire = _code(js, "async _fireReplacement(it) {")
    # No row is passed over for what its status says: the resolver decides who is a rival, and the
    # only thing the fire step asks of one is whether it is still settling.
    assert "victim" not in fire and "cancelItemIds" not in fire and "this.items.get(" not in fire
    assert fire.count("const rival = this._rivalsToCancel(it)[0];") == 1
    # The WIDER list is read once, at the very end, and only to SAY that an earlier upload which was
    # not ours to cancel is still there -- never to decide what is cancelled.
    assert fire.count("this._liveRivals(it)") == 1
    assert fire.index("this._liveRivals(it)") > fire.index("/delete`") and "showWarning(" in fire
    assert fire.count("|| !(await this.cancel(rival.id, true))) {") == 1
    assert fire.count("(rival.sessionId && rival.sessionId === it.sessionId)") == 1
    assert "replacesFired" not in js
    # Withdrawn is read at the top of EVERY turn -- so before each cancel, after each wait, and,
    # on the turn that finds no rival left, before the file delete, with no await in between.
    assert fire.count("const withdrawn = () => it.cancelled || it.status === 'error';") == 1
    # ... once per turn, and once more after the last destructive request.
    W, H = "if (withdrawn()) { sayCancelled(); return false; }", "if (held()) { sayCancelled(); return false; }"
    # Nothing in this step claims a REPLACEMENT: the commit comes after it and can still fail.
    assert "replaced by this one" not in fire and fire.count("return { cancelled };") == 1
    assert fire.count(W) == 2 and fire.count(H) == 2
    assert fire.rindex(W) > fire.index("/delete`") and fire.rindex(H) > fire.rindex(W)
    assert fire.rindex(H) < fire.index("return { cancelled };")
    loop = fire.index("for (let turn = 0; ; turn++) {")
    assert loop < fire.index(W) < fire.index(H) < fire.index("if (this._landedSince(it)) {") \
        < fire.index("const rival = this._rivalsToCancel(it)[0];") < fire.index("if (!rival) break;") \
        < fire.index("await this.cancel(rival.id, true)") < fire.index("if (r.deleteId) {")
    # `break` is the ONLY way out of the loop that goes on, and nothing is awaited between the
    # loop's end and the delete request -- so the read at the top of that last turn still holds.
    assert fire.count("break;") == 1
    after_loop = fire[fire.index("            cancelled++;\n        }\n"):fire.index("/delete`")]
    assert after_loop.count("await ") == 1 and "await fetch(" in after_loop
    drop = _code(js, "async _dropReplacement(it, message) {")
    assert drop.index("showError(message);") < drop.index("it.status = 'error';") \
        < drop.index("if (!(await this.cancel(it.id))) {")
    # A refused cancel leaves `paused` set so the send loop stops. The loop must not then relabel
    # the row "paused": that would wipe the one sentence saying the cancel failed.
    run = _code(js, "async _run(id) {")
    assert run.count("if (it.paused) { if (it.status !== 'error') it.status = 'paused'; this.render(); return; }") == 1
    # (The bare form exists once, AFTER the fire step, where a pause is honoured before the commit;
    # the send loop's own read is the guarded one above.)
    assert run.index("if (it.paused) { if (it.status !== 'error')") < run.index("/chunks/${i}`")
    # And a dropped or withdrawn replacement returns before the commit -- read once more by the
    # run itself, after the step and before the commit.
    FIRED = "const fired = await this._fireReplacement(it);"
    assert run.count(FIRED) == 1 and run.count("if (!fired) return;") == 1
    # ... and the claim is made only after the commit: past `/complete`, past the landing.
    assert run.index("/complete`") < run.index("this._noteLanded(it, epoch);") < run.index("replaced by this one.")
    assert run.count("if (it.cancelled || it.status === 'error') return;") == 1
    # Twice: at the run's entry (a row paused while it waited for a slot stays paused -- and the flag
    # is NOT cleared there, or Pause on a queued row would do nothing), and after the fire step.
    assert run.count("if (it.paused) { it.status = 'paused'; this.render(); return; }") == 2 and "it.paused = false" not in run
    assert run.index("if (it.paused) { it.status = 'paused'; this.render(); return; }") < run.index("it._running = true;")
    assert run.index(FIRED) \
        < run.index("if (it.cancelled || it.status === 'error') return;") \
        < run.rindex("if (it.paused) { it.status = 'paused'; this.render(); return; }") < run.index("/complete`")
    # resume() stands down for a row that is running or being cancelled. For one whose run is QUEUED
    # it queues nothing more -- but it lifts a pause, so the queued run goes when its slot comes
    # (behaviourally pinned in the queued-pause test). The send loop's read of `cancelled` before
    # the commit is source-only by construction: every cancel also sets `paused`, read on the next line.
    resume = _code(js, "resume(id) {")
    assert resume.count("if (it._running || it.cancelled) return;") == 1 and resume.count("if (it._pending) {") == 1
    assert resume.index("if (it._pending) {") < resume.index("this._adoptRivals(it);")
    ENTRY = "if (it.cancelled || it._running || it.status === 'done') return;"
    assert run.count(ENTRY) == 1 and run.index("it._pending = false;") < run.index(ENTRY) < run.index("it.status = 'uploading';")
    assert run.count("if (it.cancelled) { await this._abandonSession(it); return; }") == 2
    # The run re-enters ITSELF when the commit reports missing chunks; the mark is given up first,
    # or that retry would be turned away by the guard meant for a second, foreign entry.
    # ... and it is retried IN THE SLOT THIS RUN HOLDS: never through the gate again from inside it.
    assert "this.run(id)" not in run
    retry = run.index("return await this._run(id);")
    assert run.rindex("it._running = false;", 0, retry) > run.index("missing_chunks")
    assert run.count("} finally {\n            it._running = false;\n        }") == 1
    # The refusal is decided on the row as it is THEN; no snapshot of it is taken at entry.
    assert "waitingForFile" not in cancel and cancel.count("if (it.status === 'needs-file') {") == 1
    assert cancel.index("it.cancelled = false;") < cancel.index("if (it.status === 'needs-file') {")
