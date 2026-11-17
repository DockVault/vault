"""The share dialog after the server refuses what it showed, run as shipped.

The dialog's section of ``static/js/app.js`` (from ``const _shareCreate = {`` to the end of ``submitCreateShare``) runs
under Node against a small stand-in page. When the server refuses a share with 409 because the tag changed while the
dialog was open, the dialog reads the tags again and keeps what the maker picked wherever the tag still offers it: the
tag, who to share with, and the people or departments. Pressing Create share again then sends what the dialog shows.
The live counterpart is in tests/test_ui_view_only_preview.py.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")

CHANGED = "This tag changed while the dialog was open. Check the share's settings and press Create share again."
TAG_GONE = "That tag is no longer available. Pick a tag and press Create share again."
AUDIENCE_GONE = ("This tag no longer allows sharing with the people you picked. "
                 "Pick who to share with and press Create share again.")


def _section() -> str:
    start = APP.index("const _shareCreate = {")
    head = APP.index("async function submitCreateShare() {", start)
    return APP[start:APP.index("\n}\n", head) + 3]


PAGE = r"""
class El {
    constructor(id, tag) { this.id = id; this.tagName = tag; this.style = { display: '' }; this.children = [];
        this.textContent = ''; this.disabled = false; this.checked = false; this._value = undefined; this.type = '';
        this.classList = { add() {}, remove() {}, toggle() {} }; this.listeners = {}; }
    addEventListener(t, f) { (this.listeners[t] = this.listeners[t] || []).push(f); }
    replaceChildren(...c) { this.children = c; if (this.tagName === 'select') this._value = c.length ? c[0].value : ''; }
    appendChild(c) { this.children.push(c); }
    setAttribute() {}
    get options() { return this.children; }
    get value() {
        if (this.tagName === 'option') return this._value !== undefined ? this._value : this.textContent;
        return this._value === undefined ? '' : this._value;
    }
    set value(v) {
        if (this.tagName === 'select') this._value = this.children.some(o => o.value === v) ? v : '';
        else this._value = v;
    }
}
const els = {};
const SELECTS = new Set(['share-tag-select', 'share-audience-select']);
const document = { getElementById(id) { if (!els[id]) els[id] = new El(id, SELECTS.has(id) ? 'select' : 'div'); return els[id]; } };
function _el(tag, cls, text) { const e = new El(null, tag); if (text != null) e.textContent = text; return e; }
function _svgIcon() { return new El(null, 'svg'); }
let deptPickerDrawn = null;   // the departments the picker was last drawn with
function _renderGroupPickerInto(hostId, get) { deptPickerDrawn = get().slice(); }
function openModal() {}
function showToast() {}
async function loadSftpPolicyGroups() {}
const state = { currentVault: { id: 'v1', name: 'V', type: 'standard' } };
const navigator = { clipboard: { writeText: async () => {} } };
let policyAnswer = null;      // what GET /share-policy answers next (an Error to fail)
let shareAnswers = [];        // what each POST /shares answers, in order (an object with status to refuse)
let policyReads = 0;
const posted = [];
async function apiRequest(path, opts) {
    if (path === '/share-policy') {
        policyReads += 1;
        const a = policyAnswer;
        if (a instanceof Error) throw a;
        return JSON.parse(JSON.stringify(a));
    }
    if (path === '/shares') {
        posted.push(JSON.parse(opts.body));
        const a = shareAnswers.shift();
        if (a && a.status) { const e = new Error(a.detail || 'refused'); e.status = a.status; throw e; }
        return a || { link_token: 'tok' };
    }
    throw new Error('unexpected ' + path);
}
"""

SCENARIOS = r"""
function tag(id, over) {
    return Object.assign({ id, name: id, allowed_audiences: ['anyone_internal', 'users', 'departments'],
        allow_view_only: true, default_view_only: false, force_view_only: false, view_only_preview: true,
        allow_custom: true, max_lifetime_minutes: 129600 }, over || {});
}
function snap() {
    return { tag: els['share-tag-select'].value, audience: els['share-audience-select'].value,
             users: _shareCreate.userIds.slice(), depts: _shareCreate.deptIds.slice(),
             chips: (els['share-user-chips'] ? els['share-user-chips'].children : []).map(c => c.textContent),
             usersShown: els['share-users-group'].style.display !== 'none',
             deptsShown: els['share-depts-group'].style.display !== 'none',
             error: els['share-create-error'].textContent, submitDisabled: els['share-create-submit'].disabled,
             voChecked: els['share-view-only'].checked, voShown: els['share-viewonly-group'].style.display !== 'none' };
}
function post(p) {
    return p ? { aud: p.claim_audience, users: p.audience_user_ids || null, depts: p.audience_department_ids || null,
                 vo: p.view_only_shown, voSent: p.view_only === undefined ? null : p.view_only } : null;
}
async function open(tags) {
    policyAnswer = { sharing_enabled: true, tags };
    await openCreateShareModal('file', 'f1', 'F');
}
function pick(tagId, aud) {
    els['share-tag-select'].value = tagId; onShareTagChange();
    els['share-audience-select'].value = aud; onShareAudienceChange();
}
async function refused(tags, reloadTags, setup, enabled) {
    posted.length = 0;
    await open(tags);
    setup();
    shareAnswers = [{ status: 409, detail: 'this tag does not allow view-only shares' }, null];
    policyAnswer = { sharing_enabled: enabled !== false, tags: reloadTags };
    await submitCreateShare();
    const after = snap();
    const reads = policyReads;
    await submitCreateShare();          // "press Create share again"
    return { after, first: post(posted[0]), second: post(posted[1]), reads };
}
const noVo = { allow_view_only: false };
(async () => {
    const out = {};
    // The maker picked "Specific users" with one person on a tag whose audiences start with anyone_internal, and
    // ticked view-only; the tag then stops allowing view-only.
    out.users = await refused([tag('Normal')], [tag('Normal', noVo)], () => {
        pick('Normal', 'users');
        _shareCreate.userIds.push('u1'); _shareCreate.usersById.u1 = 'alice';
        els['share-view-only'].checked = true;
    });
    // The same with departments.
    out.depts = await refused([tag('Normal')], [tag('Normal', noVo)], () => {
        pick('Normal', 'departments');
        _shareCreate.deptIds.push('d1');
        els['share-view-only'].checked = true;
    });
    // The tag no longer offers sharing with named people.
    out.audience_gone = await refused([tag('Normal')], [tag('Normal', { allow_view_only: false,
        allowed_audiences: ['anyone_internal'] })], () => {
        pick('Normal', 'users');
        _shareCreate.userIds.push('u1'); _shareCreate.usersById.u1 = 'alice';
        els['share-view-only'].checked = true;
    });
    // The tag picked is no longer offered.
    out.tag_gone = await refused([tag('Alpha'), tag('Picked', { force_view_only: true, default_view_only: true })],
        [tag('Alpha')], () => { pick('Picked', 'anyone_internal'); });
    // Sharing was turned off: the dialog's own sentence stays, and the button stays off.
    out.sharing_off = await refused([tag('Forced', { force_view_only: true, default_view_only: true })], [],
        () => { pick('Forced', 'users'); _shareCreate.userIds.push('u1'); }, false);
    // The tags cannot be read: everything stays as it was.
    posted.length = 0;
    await open([tag('Forced', { force_view_only: true, default_view_only: true })]);
    pick('Forced', 'users'); _shareCreate.userIds.push('u1'); _shareCreate.usersById.u1 = 'alice';
    shareAnswers = [{ status: 409 }];
    policyAnswer = new Error('down');
    await submitCreateShare();
    out.unreadable = snap();
    // Any other refusal reads nothing again and shows the server's sentence.
    posted.length = 0;
    await open([tag('Normal')]);
    pick('Normal', 'users'); _shareCreate.userIds.push('u1');
    const readsBefore = policyReads;
    shareAnswers = [{ status: 400, detail: 'max_downloads exceeds the cap' }];
    await submitCreateShare();
    out.other = { reads: policyReads - readsBefore, after: snap() };
    process.stdout.write(JSON.stringify(out));
})().catch(e => { console.error(e); process.exit(1); });
"""


def _run(section: str):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=PAGE + section + SCENARIOS, capture_output=True, text=True,
                          encoding="utf-8", timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout)


@pytest.fixture(scope="module")
def out():
    return _run(_section())


def test_people_picked_stay_picked_and_the_second_press_shares_with_them(out):
    users = out["users"]
    assert users["first"] == {"aud": "users", "users": ["u1"], "depts": None, "vo": True, "voSent": True}, users
    after = users["after"]
    assert after["tag"] == "Normal" and after["audience"] == "users" and after["users"] == ["u1"], after
    assert after["chips"] == ["alice"] and after["usersShown"] is True, after
    assert after["error"] == CHANGED and after["submitDisabled"] is False, after
    assert after["voChecked"] is False and after["voShown"] is False, after
    assert users["second"] == {"aud": "users", "users": ["u1"], "depts": None, "vo": False, "voSent": None}, users


def test_departments_picked_stay_picked(out):
    depts = out["depts"]
    after = depts["after"]
    assert after["audience"] == "departments" and after["depts"] == ["d1"] and after["deptsShown"] is True, after
    assert after["error"] == CHANGED and after["submitDisabled"] is False, after
    assert depts["second"] == {"aud": "departments", "users": None, "depts": ["d1"], "vo": False, "voSent": None}


def test_who_to_share_with_no_longer_offered_is_said_and_not_carried_over(out):
    gone = out["audience_gone"]
    after = gone["after"]
    assert after["tag"] == "Normal" and after["audience"] == "anyone_internal" and after["users"] == [], after
    assert after["error"] == AUDIENCE_GONE and after["submitDisabled"] is False, after


def test_a_tag_no_longer_offered_is_said(out):
    after = out["tag_gone"]["after"]
    assert after["tag"] == "Alpha" and after["error"] == TAG_GONE and after["submitDisabled"] is False, after


def test_sharing_turned_off_keeps_the_dialogs_own_sentence_and_the_button_off(out):
    off = out["sharing_off"]
    assert off["after"]["error"] == "Sharing is not enabled on this deployment.", off
    assert off["after"]["submitDisabled"] is True, off


def test_tags_that_cannot_be_read_leave_everything_as_it_was(out):
    after = out["unreadable"]
    assert after["tag"] == "Forced" and after["audience"] == "users" and after["users"] == ["u1"], after
    assert after["error"] == CHANGED and after["submitDisabled"] is False, after


def test_any_other_refusal_reads_nothing_again(out):
    other = out["other"]
    assert other["reads"] == 0, other
    assert other["after"]["error"] == "max_downloads exceeds the cap" and other["after"]["users"] == ["u1"], other
