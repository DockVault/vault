"""The auditor's "Show names in this case" form on the Activity page, run under Node.

The form asks for a vault's password inside the selected case, and only where the server says the case would name
the event's item once the vault is unlocked in it (``unlock_in_case``, app/services/activity_case.py): whether the
auditor is a member of the vault or not, and never because of the words the item reads alone. The password goes to
the case's own unlock route (the same rules and receipt as the case workspace), and the details are read again
afterwards, on their own when the event is not on the list's page. The tests run the SHIPPED functions, lifted out
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


PAGE = """
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
let FAIL_GET = false;
const get = async (path) => {
    calls.push(['get', path]);
    if (FAIL_GET) throw new Error('down');
    return { id: S.selectedId, old: false };
};
const forms = (box) => box.children.filter((c) => c.tag === 'form');
""" + _fn("reloadAfterUnlock") + _fn("auditorActions")


def _offered(ev: dict, case="'case-1'", extra="") -> bool:
    out = _node(PAGE + f"""
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
    out = _node(PAGE + """
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
    out = _node(PAGE + state + """
(async () => {
    await reloadAfterUnlock();
    console.log(JSON.stringify({ calls }));
})();
""")
    assert out["calls"] == expected


def test_the_administrators_unlock_reads_the_details_again_the_same_way():
    unlock = _fn("unlockVault")
    assert unlock.count("await reloadAfterUnlock();") == 1 and "renderDetail" not in unlock
    actions = _fn("auditorActions")
    assert actions.count("await reloadAfterUnlock();") == 1 and "reloadList" not in actions
