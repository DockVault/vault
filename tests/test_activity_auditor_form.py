"""The auditor's "Show names in this case" form on the Activity page, run under Node.

The form asks for a vault's password inside the selected case, and only where the server says the case would name
the event's item once the vault is unlocked in it (``unlock_in_case``, app/services/activity_case.py): whether the
auditor is a member of the vault or not, and never because of the words the item reads alone. The password goes to
the case's own unlock route (the same rules and receipt as the case workspace), and the details are read again
afterwards, on their own when the event is not on the list's page. Another row or case chosen while that read, or the
read of an event opened from a link, is under way stands. The tests run the SHIPPED functions, lifted out
of ``static/js/activity.js`` verbatim, against stand-ins for the page; test_ui_activity_case_unlock.py runs the form
in a browser.
"""
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "activity.js").read_text(encoding="utf-8")
HIDDEN = "Name hidden: the vault has a password"


def _fn(name: str) -> str:
    """One function of the page, verbatim, up to its closing brace."""
    head = f"\n    async function {name}(" if f"\n    async function {name}(" in JS else f"\n    function {name}("
    start = JS.index(head) + 1
    return JS[start:JS.index("\n    }\n", start) + 7]


def _node(body: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ))
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


STUBS = """
class N {
    constructor(tag, cls, text) { this.tag = tag; this.className = cls || ''; this.textContent = text || '';
                                  this.children = []; this.attrs = {}; this.handlers = {}; this.disabled = false; }
    append(...kids) { this.children.push(...kids); }
    appendChild(kid) { this.children.push(kid); return kid; }
    setAttribute(k, v) { this.attrs[k] = v; }
    addEventListener(type, fn) { this.handlers[type] = fn; }
}
const el = (tag, cls, text) => new N(tag, cls, text);
const button = (cls, text) => new N('button', cls, text);
const calls = [];
const window = {
    complianceUnlockCaseVault: async (caseId, vid, password) => {
        calls.push(['unlock', caseId, vid, password]);
        if (password === 'wrong') throw new Error('That is not the vault password.');
        return { receipt: 'r', expires_at: '2026-10-10T12:00:00Z' };
    },
    openRevealDialog: () => {}, openNewCaseFor: () => {},
};
let S = { caseId: 'case-1', detailOpen: true, selectedId: 'ev-1', detail: { id: 'ev-1', old: true },
          rows: [{ id: 'ev-1' }] };
const reloadList = async (o) => { calls.push(['reloadList', o && o.keepSelection]); };
const renderDetail = () => { calls.push(['renderDetail', S.detail && S.detail.old ? 'old' : 'new']); };
let FAIL_GET = false;          // true: the read fails; a number: it fails with that status
let DURING_GET = null;         // what the user does while a read is under way
const get = async (path) => {
    calls.push(['get', path]);
    if (DURING_GET) { await null; DURING_GET(); }
    if (FAIL_GET) throw Object.assign(new Error('down'), { status: FAIL_GET === true ? 500 : FAIL_GET });
    return { id: decodeURIComponent(path.split('?')[0].split('/').pop()), old: false };
};
// A click on another row, while a read is under way: it selects that row and draws its details.
const CLICK = () => { calls.push(['click']); S.selectedId = 'ev-2'; S.detail = { id: 'ev-2', clicked: true }; };
const select = (id, o) => { calls.push(['select', id, !!(o && o.open)]); S.selectedId = id; };
const openDetail = () => { calls.push(['openDetail', S.detail && S.detail.id]); };
const showError = (text) => { calls.push(['showError', text]); };
const forms = (box) => box.children.filter((c) => c.tag === 'form');
"""


def _page() -> str:
    """The stand-ins, then the two shipped functions (read when a test runs, so a missing one fails that test)."""
    return STUBS + _fn("selectedTime") + _fn("eventPath") + _fn("reloadAfterUnlock") + _fn("auditorActions")


def _offered(ev: dict, case="'case-1'", extra="") -> bool:
    out = _node(_page() + f"""
S.caseId = {case};
{extra}
const box = auditorActions({json.dumps(ev)}, 'vault-1', {json.dumps(ev.get("names", {}))});
console.log(JSON.stringify({{ forms: forms(box).length }}));
""")
    return out["forms"] == 1


def test_the_form_is_offered_where_the_server_says_the_case_would_name_the_item():
    assert _offered({"id": "ev-1", "unlock_in_case": True, "names": {"item": HIDDEN}})


@pytest.mark.parametrize("ev,case,extra", [
    # The words alone, as a member of the vault reads them where the case would not name the item (or gives no access).
    ({"id": "ev-1", "names": {"item": HIDDEN}}, "'case-1'", ""),
    ({"id": "ev-1", "unlock_in_case": False, "names": {"item": HIDDEN}}, "'case-1'", ""),
    # Anything but the server's true.
    ({"id": "ev-1", "unlock_in_case": "true", "names": {"item": HIDDEN}}, "'case-1'", ""),
    ({"id": "ev-1", "unlock_in_case": 1, "names": {"item": HIDDEN}}, "'case-1'", ""),
    # No case selected.
    ({"id": "ev-1", "unlock_in_case": True, "names": {"item": HIDDEN}}, "null", ""),
    # The compliance screens did not load.
    ({"id": "ev-1", "unlock_in_case": True, "names": {"item": HIDDEN}}, "'case-1'",
     "delete window.complianceUnlockCaseVault;"),
])
def test_the_form_is_offered_nowhere_else(ev, case, extra):
    assert not _offered(ev, case, extra)


def test_the_password_goes_to_the_cases_unlock_and_the_details_are_read_again():
    out = _node(_page() + """
(async () => {
    const box = auditorActions({ id: 'ev-1', unlock_in_case: true }, 'vault-1', { item: 'x' });
    const form = forms(box)[0];
    const input = form.children[0], go = form.children[1], msg = form.children[2];
    const steps = [];
    const submit = (password) => {
        input.value = password;
        return form.handlers.submit({ preventDefault: () => steps.push(['prevented', calls.length]) });
    };
    await submit('wrong');
    const failed = { msg: msg.textContent, disabled: go.disabled, cleared: input.value };
    await submit('right');
    console.log(JSON.stringify({ calls, steps, failed, label: go.textContent, type: go.type,
                                 inputType: input.type, cleared: input.value }));
})();
""")
    assert out["label"] == "Show names in this case" and out["type"] == "submit" and out["inputType"] == "password"
    assert out["failed"] == {"msg": "That is not the vault password.", "disabled": False, "cleared": ""}
    assert out["steps"] == [["prevented", 0], ["prevented", 1]], "the browser's own submission stopped first"
    assert out["calls"] == [["unlock", "case-1", "vault-1", "wrong"], ["unlock", "case-1", "vault-1", "right"],
                            ["reloadList", True], ["renderDetail", "old"]]
    assert out["cleared"] == ""


@pytest.mark.parametrize("state,expected", [
    # On the list's page: the list's read refreshes the details (afterListRead); nothing more is asked for.
    ("", [["reloadList", True], ["renderDetail", "old"]]),
    # Opened from a link, not on the page: read again on its own, under the case.
    ("S.rows = [{ id: 'ev-2' }];",
     [["reloadList", True], ["get", "/activity/events/ev-1?case=case-1"], ["renderDetail", "new"]]),
    ("S.rows = []; S.caseId = null;",
     [["reloadList", True], ["get", "/activity/events/ev-1"], ["renderDetail", "new"]]),
    ("S.rows = []; S.selectedId = 'a b/c';",
     [["reloadList", True], ["get", "/activity/events/a%20b%2Fc?case=case-1"], ["renderDetail", "new"]]),
    # A read that fails leaves the details as they were, still drawn.
    ("S.rows = []; FAIL_GET = true;",
     [["reloadList", True], ["get", "/activity/events/ev-1?case=case-1"], ["renderDetail", "old"]]),
    # The details closed (the list's read found the event no longer matches): nothing is read.
    ("S.rows = []; S.detailOpen = false;", [["reloadList", True], ["renderDetail", "old"]]),
])
def test_after_an_unlock_the_details_never_keep_what_they_showed_before(state, expected):
    out = _node(_page() + state + """
(async () => {
    await reloadAfterUnlock();
    console.log(JSON.stringify({ calls }));
})();
""")
    assert out["calls"] == expected


@pytest.mark.parametrize("during,expected,detail", [
    # Nothing chosen meanwhile (the control): the event read again is drawn.
    ("() => {}", [["get", "/activity/events/ev-1?case=case-1"], ["renderDetail", "new"]], {"id": "ev-1", "old": False}),
    # Another row clicked: its details stand; the earlier event is neither kept nor drawn.
    ("CLICK", [["get", "/activity/events/ev-1?case=case-1"], ["click"]], {"id": "ev-2", "clicked": True}),
    # Another case chosen: what was read under the earlier case is not drawn under it.
    ("() => { S.caseId = 'case-2'; }", [["get", "/activity/events/ev-1?case=case-1"]], {"id": "ev-1", "old": True}),
    ("() => { S.caseId = null; }", [["get", "/activity/events/ev-1?case=case-1"]], {"id": "ev-1", "old": True}),
])
@pytest.mark.parametrize("fails", [False, True])
def test_a_choice_made_while_the_details_are_read_again_stands(during, expected, detail, fails):
    if fails and during == "() => {}":
        expected, detail = [expected[0], ["renderDetail", "old"]], {"id": "ev-1", "old": True}
    out = _node(_page() + f"""
S.rows = [{{ id: 'ev-2' }}];
DURING_GET = {during};
FAIL_GET = {'true' if fails else 'false'};
(async () => {{
    await reloadAfterUnlock();
    console.log(JSON.stringify({{ calls, detail: S.detail }}));
}})();
""")
    assert out["calls"] == [["reloadList", True]] + expected
    assert out["detail"] == detail


def _linked(state: str, during: str = "null", event: str = "ev-9", at=None) -> dict:
    return _node(STUBS + _fn("selectedTime") + _fn("eventPath") + _fn("openLinkedEvent") + f"""
S.rows = [{{ id: 'ev-2' }}];
{state}
DURING_GET = {during};
(async () => {{
    await openLinkedEvent({json.dumps(event)}, {json.dumps(at)});
    console.log(JSON.stringify({{ calls, detail: S.detail, selected: S.selectedId,
                                  missing: S.detailMissing === undefined ? null : S.detailMissing }}));
}})();
""")


@pytest.mark.parametrize("state,during,expected", [
    # Nothing chosen meanwhile (the controls): opened, said to be missing, or the error shown.
    ("", "null", {"calls": [["openDetail", "ev-9"]], "detail": {"id": "ev-9", "old": False}, "selected": "ev-9",
                  "missing": False}),
    ("FAIL_GET = 404;", "null", {"calls": [["openDetail", None]], "detail": None, "selected": "ev-9",
                                 "missing": True}),
    ("FAIL_GET = 500;", "null", {"calls": [["showError", "The event could not be loaded: down"]], "detail": None,
                                 "selected": "ev-9", "missing": False}),
    # Another row clicked meanwhile: that choice stands, read or not, and nothing more is shown.
    ("", "CLICK", {"calls": [["click"]], "detail": {"id": "ev-2", "clicked": True}, "selected": "ev-2",
                   "missing": None}),
    ("FAIL_GET = 404;", "CLICK", {"calls": [["click"]], "detail": {"id": "ev-2", "clicked": True}, "selected": "ev-2",
                                  "missing": None}),
    ("FAIL_GET = 500;", "CLICK", {"calls": [["click"]], "detail": {"id": "ev-2", "clicked": True}, "selected": "ev-2",
                                  "missing": None}),
    # Another case chosen meanwhile: the event read under the earlier one is not opened.
    ("", "() => { S.caseId = 'case-2'; }", {"calls": [], "detail": None, "selected": "ev-9", "missing": None}),
    ("FAIL_GET = 404;", "() => { S.caseId = null; }", {"calls": [], "detail": None, "selected": "ev-9",
                                                       "missing": None}),
])
def test_a_linked_event_is_not_opened_over_a_choice_made_while_it_is_read(state, during, expected):
    out = _linked(state, during)
    assert out["calls"][0] == ["get", "/activity/events/ev-9?case=case-1"]
    out["calls"] = out["calls"][1:]
    assert out == expected


@pytest.mark.parametrize("state,event,path", [
    ("", "a b/c", "/activity/events/a%20b%2Fc?case=case-1"),
    ("S.caseId = null;", "ev-9", "/activity/events/ev-9"),
])
def test_a_linked_event_is_read_by_its_id_under_the_selected_case(state, event, path):
    out = _linked(state, event=event)
    assert out["calls"] == [["get", path], ["openDetail", event]] and out["selected"] == event


TS = "2026-07-30T03:17:00.123456+00:00"
AT = "at=2026-07-30T03%3A17%3A00.123456%2B00%3A00"


@pytest.mark.parametrize("state,path", [
    ("", f"/activity/events/ev-9?{AT}&case=case-1"),
    ("S.caseId = null;", f"/activity/events/ev-9?{AT}"),
])
def test_a_linked_event_is_read_with_the_time_its_link_gives(state, path):
    """An event of a day the archive keeps is no row any more: the server finds it by its time. The link's time goes
    with the read, and stays with the event while it is shown, for a link to it and for its next read."""
    out = _node(STUBS + _fn("selectedTime") + _fn("eventPath") + _fn("openLinkedEvent") + f"""
S.rows = [{{ id: 'ev-2' }}];
{state}
(async () => {{
    await openLinkedEvent('ev-9', {json.dumps(TS)});
    S.detail = null;
    console.log(JSON.stringify({{ calls, at: selectedTime() }}));
}})();
""")
    assert out == {"calls": [["get", path], ["openDetail", "ev-9"]], "at": TS}


@pytest.mark.parametrize("state,path", [
    # Opened from a link, read again after the unlock with the time its details show.
    ("S.rows = []; S.detail = { id: 'ev-1', old: true, timestamp: TS };", f"/activity/events/ev-1?{AT}&case=case-1"),
    # Its details not read (the link's read failed): the time the link gave.
    ("S.rows = []; S.detail = null; S.linkedAt = { id: 'ev-1', at: TS };", f"/activity/events/ev-1?{AT}&case=case-1"),
    # A link's time for another event is not this one's.
    ("S.rows = []; S.detail = null; S.linkedAt = { id: 'ev-0', at: TS };", "/activity/events/ev-1?case=case-1"),
])
def test_after_an_unlock_the_event_is_read_again_with_its_time(state, path):
    out = _node(_page() + f"""
const TS = {json.dumps(TS)};
{state}
(async () => {{
    await reloadAfterUnlock();
    console.log(JSON.stringify({{ calls }}));
}})();
""")
    assert out["calls"][:2] == [["reloadList", True], ["get", path]]


def test_a_linked_event_on_the_page_is_selected_there_without_a_read():
    out = _node(STUBS + _fn("openLinkedEvent") + """
S.rows = [{ id: 'ev-2' }];
(async () => {
    await openLinkedEvent('ev-2');
    console.log(JSON.stringify({ calls, selected: S.selectedId }));
})();
""")
    assert out == {"calls": [["select", "ev-2", True]], "selected": "ev-2"}


def test_the_administrators_unlock_reads_the_details_again_the_same_way():
    unlock = _fn("unlockVault")
    assert unlock.count("await reloadAfterUnlock();") == 1 and "renderDetail" not in unlock
    actions = _fn("auditorActions")
    assert actions.count("await reloadAfterUnlock();") == 1 and "reloadList" not in actions
