"""What the upload tray OFFERS for an interrupted upload, and what a refused cancel does.

Two defects were found by running the page, and neither was visible to a pin on the code's shape:

* A zero-knowledge upload sealed as it uploads IS continued by picking the file again -- the resume was
  written and worked when driven by hand -- but the tray asked `!it.isZk` in three separate places, so
  the row showed Cancel alone beside a sentence telling the user to cancel. Cancel destroys the upload.
* `cancel()` never read the status of its DELETE. A refused cancel looked like a cancel, so an upload
  replacing an in-flight one went on to commit beside it, and nothing was said.

So these tests run the SHIPPED methods -- lifted out of ``app.js`` verbatim -- under Node: the tray
methods against a minimal DOM, and the cancel / replacement methods against a stubbed ``fetch`` that
refuses. What the browser draws and sends beyond that is the live lane.
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


FIRE = """
const API_BASE = '';
const calls = [], toasts = [], deleted = [];
let responses = [];
const fetch = async (url, opts) => {
    calls.push((opts && opts.method || 'GET') + ' ' + url);
    const r = responses.shift();
    if (r === 'throw') throw new Error('network');
    return r;
};
const zkUploadStore = { delete: async (id) => { deleted.push(id); } };
const showError = (m) => toasts.push(['error', m]);
const showInfo = (m) => toasts.push(['info', m]);
const um = {
    items: new Map(), _landed: new Set(), _vaultHeaders() { return {}; }, render() {},
%s
};
const scenario = async (victimReply) => {
    calls.length = 0; toasts.length = 0; deleted.length = 0;
    um.items = new Map([
        ['v', { id: 'v', vaultId: 'V', sessionId: 'old-sess', status: 'uploading', cancelled: false, isZk: true, fileName: 'X' }],
        ['o', { id: 'o', vaultId: 'V', sessionId: 'new-sess', status: 'uploading', cancelled: false, isZk: true,
                fileName: 'X', replaces: { cancelItemIds: ['v'] } }],
    ]);
    responses = [victimReply, { ok: true, status: 204 }];
    const fired = await um._fireReplacement(um.items.get('o'));
    const v = um.items.get('v');
    return { fired, toasts: toasts.slice(), calls: calls.slice(), deleted: deleted.slice(),
             victim: v ? { status: v.status, cancelled: v.cancelled, error: v.error } : null,
             oursStillThere: um.items.has('o') };
};
(async () => {
    const out = {
        refused: await scenario({ ok: false, status: 500 }),
        network: await scenario('throw'),
        confirmed: await scenario({ ok: true, status: 204 }),
        alreadyGone: await scenario({ ok: false, status: 404 }),
    };
    um.items = new Map([['n', { id: 'n', vaultId: 'V', sessionId: null, status: 'queued' }]]);
    out.noSession = await um.cancel('n');
    out.noSuchItem = await um.cancel('nope');
    process.stdout.write(JSON.stringify(out));
})().catch(e => { process.stderr.write(String(e && e.stack || e)); process.exit(1); });
"""


def test_a_cancel_the_server_refused_drops_the_replacement_by_name_instead_of_committing_beside_it():
    js = APP_JS.read_text(encoding="utf-8")
    methods = "".join(_method(js, h) for h in (
        "async cancel(id) {", "async _fireReplacement(it) {", "async _dropReplacement(it, message) {"))
    out = _node(FIRE % methods)

    for key in ("refused", "network"):
        r = out[key]
        # NOT fired: the caller returns on this and never reaches the commit. The earlier upload is
        # still alive, so committing beside it is the both-copies outcome the step exists to prevent.
        # (mutation: skip the drop path on a failed cancel -> fired is true -> red.)
        assert r["fired"] is False, r
        # Said, by name: which file, and what did not happen. (It used to say nothing at all.)
        assert r["toasts"] == [["error", 'Could not cancel the earlier upload of "X"; the new copy was not uploaded.']], r
        # The victim's row STAYS, as an error that can be retried, and its saved record is kept --
        # that record is still what could continue it. (mutation: drop the status check -> the row
        # and the record are thrown away as if the cancel had worked -> red.)
        assert r["victim"] == {"status": "error", "cancelled": False,
                               "error": "Could not cancel this upload — the server did not confirm it. Try again."}, r
        assert "old-sess" not in r["deleted"]
        # OUR upload is what is dropped: its own session deleted, its row and record gone.
        assert r["calls"] == ["DELETE /vaults/V/uploads/old-sess", "DELETE /vaults/V/uploads/new-sess"], r
        assert r["deleted"] == ["new-sess"] and r["oursStillThere"] is False
        assert not any("/complete" in c for c in r["calls"])

    for key in ("confirmed", "alreadyGone"):        # 2xx, and 404: already gone is gone
        r = out[key]
        assert r["fired"] is True and r["victim"] is None and r["oursStillThere"] is True, r
        assert r["toasts"] == [["info", 'The earlier upload of "X" was cancelled and replaced by this one.']]
        assert r["calls"] == ["DELETE /vaults/V/uploads/old-sess"] and r["deleted"] == ["old-sess"]

    # Nothing to cancel on the server is a cancel that worked.
    assert out["noSession"] is True and out["noSuchItem"] is True


def test_cancel_reads_the_status_of_its_delete():
    # The source half, on code only: the DELETE's answer decides, and only a confirmed cancel
    # removes the row. (mutation: remove the status check -> red here and in the run above.)
    js = APP_JS.read_text(encoding="utf-8")
    body = "\n".join(ln for ln in _method(js, "async cancel(id) {").splitlines()
                     if not ln.lstrip().startswith("//"))
    assert body.count("gone = r.ok || r.status === 404;") == 1
    assert "if (!gone) {" in body and body.index("if (!gone) {") < body.index("this.items.delete(id);")
    assert body.index("return false;") < body.index("await zkUploadStore.delete(it.sessionId);")
    fire = "\n".join(ln for ln in _method(js, "async _fireReplacement(it) {").splitlines()
                     if not ln.lstrip().startswith("//"))
    assert fire.count("if (!(await this.cancel(vid))) {") == 1
    # A refused cancel leaves `paused` set so the send loop stops. The loop must not then relabel
    # the row "paused": that would wipe the one sentence saying the cancel failed.
    run = "\n".join(ln for ln in _method(js, "async _run(id) {").splitlines()
                    if not ln.lstrip().startswith("//"))
    assert run.count("if (it.paused) { if (it.status !== 'error') it.status = 'paused'; this.render(); return; }") == 1
    assert "if (it.paused) { it.status = 'paused';" not in run
