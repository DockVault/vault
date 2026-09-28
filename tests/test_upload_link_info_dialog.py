"""An upload link's details, as the page shows them: the Info dialog and the drop-vault card.

Driven in Node against the shipped functions from static/js/app.js, with a small stand-in for the
DOM they build with createElement, so what is asserted is the text and attributes the page
actually produces.

1. Storage for an empty drop vault read " / 10 MB": _mbFromBytes gives '' for 0 bytes -- right for a
   form field left empty, wrong in "0 / 10 MB". The Info dialog and the card now show 0.
2. The retention form's error line appeared silently: a screen reader was not told that Save had been
   refused. It is an alert now, for the page's own check and for the server's refusal alike.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

APP_JS = Path(__file__).resolve().parent.parent / "static" / "js" / "app.js"
MB = 1048576


def _function(js, name):
    """One top-level function of app.js, verbatim: its one line, or its head to its closing brace."""
    for head in (f"\nasync function {name}(", f"\nfunction {name}("):
        start = js.find(head)
        if start < 0:
            continue
        start += 1
        first = js[start:js.index("\n", start)]
        if first.rstrip().endswith("}"):
            return first + "\n"
        return js[start:js.index("\n}\n", start) + 3]
    raise AssertionError(f"no function {name} in app.js")


def _const(js, name):
    start = js.index(f"\nconst {name} =") + 1
    return js[start:js.index("\n", start) + 1]


_DOM = """
class El {
    constructor(tag) {
        this.tagName = String(tag).toUpperCase(); this.children = []; this.attrs = {}; this.style = {};
        this.className = ''; this.id = ''; this.hidden = false; this.value = ''; this.disabled = false;
        this.checked = false; this.type = ''; this.on = {}; this._text = '';
    }
    set textContent(v) { this._text = v == null ? '' : String(v); this.children = []; }
    get textContent() { return this._text + this.children.map(c => c.textContent).join(''); }
    appendChild(c) { this.children.push(c); return c; }
    replaceChildren(...c) { this.children = c; }
    setAttribute(k, v) { this.attrs[k] = String(v); }
    getAttribute(k) { return Object.prototype.hasOwnProperty.call(this.attrs, k) ? this.attrs[k] : null; }
    addEventListener(t, f) { (this.on[t] = this.on[t] || []).push(f); }
    dispatchEvent(ev) { (this.on[ev.type] || []).forEach(f => f(ev)); return true; }
    click() { return Promise.all((this.on.click || []).map(f => f({ target: this }))); }
    remove() { document.body.children = document.body.children.filter(c => c !== this); }
    focus() {}
    querySelector() { return all(this).find(e => e.tagName === 'INPUT' && e.type === 'number') || null; }
}
function all(root) { const out = []; const walk = (e) => { out.push(e); e.children.forEach(walk); }; walk(root); return out; }
const document = {
    body: new El('body'),
    createElement: (t) => new El(t),
    createTextNode: (t) => { const e = new El('#text'); e.textContent = t; return e; },
    querySelectorAll: () => [],
    getElementById: (id) => all(document.body).find(e => e.id === id) || null,
};
class CustomEvent { constructor(type) { this.type = type; } }
const fileExpiryEnforced = () => true;
const fileExpiryNotEnforcedSuffix = () => '';
const showSuccess = () => {};
let apiAnswer = null;
const apiRequest = async () => { if (apiAnswer) throw apiAnswer; return {}; };
const loadMyReceivers = async () => {};
const openVault = () => {};
const rcCopyUrl = () => {};
const rcReplaceLink = () => {};
const rcSessionUrls = Object.create(null);
const host = new El('div');
const _rcEl = () => host;
function infoModal(r) {
    openReceiverInfoModal(r);
    return document.body.children[document.body.children.length - 1];
}
function infoRow(r, key) {
    const grid = all(infoModal(r)).find(e => e.className === 'audit-detail-fields');
    const i = grid.children.findIndex(e => e.className === 'audit-detail-key' && e.textContent === key);
    return grid.children[i + 1].textContent;
}
function cardUsage(r) {
    renderReceiverVaults([r]);
    return all(host).filter(e => e.className === 'text-tertiary text-xs').map(e => e.textContent)
        .find(t => t.includes('MB'));
}
function link(extra) {
    return Object.assign({ id: 'R', vault_id: 'V', label: 'Drop', tag_name: 'Normal', status: 'active',
        secret_kind: null, expires_at: null, max_uploads: null, upload_count: 0, retention_days: 7,
        retention_limit_days: 30, retention_may_keep: false }, extra);
}
"""

_SHIPPED = ("_el", "_mbFromBytes", "_mbShown", "_rcExpiryText", "_rcRetentionText",
            "_rcRetentionEditor", "openReceiverInfoModal", "renderReceiverVaults")


def _run(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the shipped page code must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    harness = (_DOM + _const(js, "_MB") + _const(js, "_RC_STATUS_LABEL")
               + "".join(_function(js, n) for n in _SHIPPED)
               + "(async () => { const out = {};\n" + scenario
               + "\nprocess.stdout.write(JSON.stringify(out)); })();\n")
    done = subprocess.run([node, "-"], input=harness, capture_output=True, text=True,
                          encoding="utf-8", timeout=60)
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


def test_an_empty_drop_vault_shows_0_mb_of_its_budget():
    out = _run(f"""
    out.infoEmpty = infoRow(link({{ max_total_bytes: 10 * {MB}, stored_bytes: 0 }}), 'Storage');
    out.infoUnknown = infoRow(link({{ max_total_bytes: 10 * {MB}, stored_bytes: null }}), 'Storage');
    out.infoNoBudget = infoRow(link({{ max_total_bytes: null, stored_bytes: 0 }}), 'Storage');
    out.infoSome = infoRow(link({{ max_total_bytes: 10 * {MB}, stored_bytes: 3 * {MB} }}), 'Storage');
    out.cardEmpty = cardUsage(link({{ max_total_bytes: 10 * {MB}, stored_bytes: 0 }}));
    out.cardNoBudget = cardUsage(link({{ max_total_bytes: null, stored_bytes: 0 }}));
    """)
    assert out == {
        "infoEmpty": "0 / 10 MB", "infoUnknown": "0 / 10 MB", "infoNoBudget": "0 MB used",
        "infoSome": "3 / 10 MB", "cardEmpty": "0 / 10 MB", "cardNoBudget": "0 MB used",
    }


def test_a_refused_retention_change_is_announced():
    """Change, then Save with no number (the page refuses it), then with one the server refuses:
    each time the refusal appears in an alert."""
    out = _run(f"""
    const els = all(infoModal(link({{ max_total_bytes: 10 * {MB}, stored_bytes: 0, retention_days: null }})));
    const byId = (id) => els.find(e => e.id === id);
    const said = () => els.filter(e => !e.hidden && /^(Enter the number|The server says)/.test(e._text))
        .map(e => ({{ text: e._text, role: e.getAttribute('role') }}));
    await byId('rc-info-retention-change').click();
    byId('rc-info-retention-days').value = '';
    await byId('rc-info-retention-save').click();
    out.page = said();
    byId('rc-info-retention-days').value = '5';
    apiAnswer = new Error('The server says no.');
    await byId('rc-info-retention-save').click();
    out.server = said();
    """)
    assert out["page"] == [{"text": "Enter the number of days to keep uploads: a whole number, 1 or more.",
                            "role": "alert"}]
    assert out["server"] == [{"text": "The server says no.", "role": "alert"}]


def test_the_retention_editor_says_only_what_applies_and_refuses_beside_the_field():
    """A type with a longest retention says "At most N days." and nothing about keeping uploads, which it
    does not offer; a type with none offers keeping and does not quote the server's ten-year cap. The
    refusal sits right under the number, in the theme's own red."""
    out = _run(f"""
    const editor = (r) => {{
        const els = all(infoModal(Object.assign(link(r), {{ max_total_bytes: 10 * {MB}, stored_bytes: 0 }})));
        const byId = (id) => els.find(e => e.id === id);
        const input = byId('rc-info-retention-days'), err = byId('rc-info-retention-error');
        const group = els.find(e => e.className === 'form-group' && e.children.includes(input));
        return {{ text: byId('rc-info-retention-editor').textContent,
                 errAfterInput: group.children.indexOf(err) === group.children.indexOf(input) + 1,
                 red: err.style.color, keep: !!byId('rc-info-retention-keep') }};
    }};
    out.capped = editor({{ retention_limit_days: 30, retention_may_keep: false }});
    out.open = editor({{ retention_limit_days: 3650, retention_may_keep: true }});
    """)
    capped, open_ = out["capped"], out["open"]
    assert "At most 30 days." in capped["text"] and "Keeping uploads" not in capped["text"]
    assert capped["keep"] is False
    assert "At most" not in open_["text"] and "3650" not in open_["text"]
    assert "Keeping uploads removes the date" in open_["text"] and open_["keep"] is True
    for e in (capped, open_):
        assert e["errAfterInput"] is True and e["red"] == "var(--error)"
