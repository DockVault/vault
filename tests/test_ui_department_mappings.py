"""A department that single sign-on group mappings name (static/js/app.js, openGroupDetail and deleteGroup): its page
counts the mappings, the question before its deletion says that they go with it, and the toast after says how many
went, from the answers of GET and DELETE /groups/{id}. A department no mapping names reads as before.

Driven in Node against the page's own functions, on the small document of tests/js/mini_dom.js, with the server's
answers stood in for (the server's side has its own tests: tests/test_sso_group_mappings.py). Offline."""
import json
import os
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")


def _function(name):
    found = re.search(rf"\n(?:async )?function {re.escape(name)}\(", APP)
    assert found, name
    start = found.start() + 1
    return APP[start:APP.index("\n}\n", start) + 3]


PRELUDE = r"""
const dom = require('./tests/js/mini_dom.js');
const { document } = dom.install();
const print = console.log.bind(console);
console.log = () => {}; console.error = () => {}; console.warn = () => {};
const asked = [], confirms = [], toasts = [];
let answers = {};                       // 'METHOD path' -> what apiRequest answers
let confirmAnswer = true;
async function apiRequest(path, options) {
    const key = ((options || {}).method || 'GET') + ' ' + path;
    asked.push(key);
    if (!Object.prototype.hasOwnProperty.call(answers, key)) throw new Error('Not arranged: ' + key);
    return answers[key];
}
async function showConfirm(message, title) { confirms.push({ message, title }); return confirmAnswer; }
function showSuccess(m) { toasts.push(['success', m]); }
function showError(m) { toasts.push(['error', m]); }
const groupsView = { selectedId: null, groups: [], users: [], currentMemberIds: new Set() };
async function loadGroups() {}
function renderGroupTree() {}
function groupPath() { return ['Sales']; }
function chipColorValue() { return 'gray'; }
function iconSvg() { return ''; }
function escapeHtml(s) { return String(s); }
const People = { placeholder: () => '' };
function openGroupModal() {} function openAddMembersModal() {} function removeGroupMember() {}
// The detail pane's markup is written as a string: the browser parses it, mini_dom does not. This stands in for the
// parser with the elements the page looks up afterwards: the stats row and the buttons by their ids.
const detail = document.createElement('div'); detail.id = 'group-detail'; document.body.appendChild(detail);
Object.defineProperty(detail, 'innerHTML', {
    set(html) {
        this.replaceChildren();
        this._html = html;
        for (const m of html.matchAll(/<(div|span|button)[^>]*\bclass="([^"]*)"[^>]*>/g)) {
            if (m[2].split(/\s+/).includes('group-stats')) {
                const stats = document.createElement('div'); stats.className = 'group-stats'; this.appendChild(stats);
            }
        }
        for (const m of html.matchAll(/\sid="([\w-]+)"/g)) {
            const b = document.createElement('button'); b.id = m[1]; this.appendChild(b);
        }
    },
    get() { return this._html || ''; },
});
const settle = async () => { for (let i = 0; i < 20; i += 1) await new Promise((r) => setImmediate(r)); };
const out = (value) => print(JSON.stringify(value));
"""


def _node(scenario):
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    helpers = "\n".join(_function(n) for n in ("_el", "_svgIcon", "openGroupDetail", "_groupMappingsText",
                                                         "deleteGroup"))
    script = (PRELUDE + "const _SVGNS = 'http://www.w3.org/2000/svg';\n" + helpers
              + "\n(async () => {\n" + scenario + "\n})().catch((e) => { print('FAILED ' + e.stack); process.exit(1); });\n")
    done = subprocess.run([node, "-"], input=script, capture_output=True, text=True, encoding="utf-8", timeout=60,
                          cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def _department(mapped):
    return {"id": "g-1", "name": "Sales", "description": None, "color": None, "member_count": 0, "child_count": 0,
            "members": [], "children": [], "sso_group_mappings": mapped}


def _stats(mapped):
    return _node(f"""
answers['GET /groups/g-1'] = {json.dumps(_department(mapped))};
await openGroupDetail('g-1');
const stats = detail.querySelector('.group-stats');
out({{ items: stats ? stats.querySelectorAll('.meta-item').map((i) => [
          i.querySelector('.meta-label').textContent, i.querySelector('.meta-value').textContent]) : null,
      failed: detail.innerHTML.includes('Failed to load department') }});
""")


def test_the_departments_page_counts_the_mappings_that_name_it():
    got = _stats(2)
    assert got["failed"] is False
    assert got["items"] == [["Single sign-on group mappings", "2"]]


def test_a_department_no_mapping_names_shows_no_count():
    got = _stats(0)
    assert got["failed"] is False
    assert got["items"] == []


def _delete(mapped, removed, *, yes=True):
    g = _department(mapped)
    return _node(f"""
confirmAnswer = {json.dumps(yes)};
answers['DELETE /groups/g-1'] = {{ message: "Group 'Sales' deleted", sso_group_mappings_removed: {removed} }};
await deleteGroup({json.dumps(g)});
await settle();
out({{ confirms, toasts, asked }});
""")


KEPT = "Delete department “Sales”? Members are kept; any sub-groups move up to its parent."


def test_the_question_before_a_deletion_says_the_mappings_go_with_the_department():
    got = _delete(2, 2)
    message = got["confirms"][0]["message"]
    assert message == (KEPT + " 2 single sign-on group mappings name this department and are removed with it, any "
                       "role they give included. You find them on their provider's Groups page, under Settings, "
                       "Sign-in methods.")
    assert got["asked"] == ["DELETE /groups/g-1"]
    assert got["toasts"] == [["success", "Department deleted, with 2 single sign-on group mappings"]]


def test_one_mapping_is_named_in_the_singular():
    got = _delete(1, 1)
    assert got["confirms"][0]["message"] == (KEPT + " 1 single sign-on group mapping names this department and is "
                                             "removed with it, any role it gives included. You find it on its "
                                             "provider's Groups page, under Settings, Sign-in methods.")
    assert got["toasts"] == [["success", "Department deleted, with 1 single sign-on group mapping"]]


def test_a_department_no_mapping_names_is_deleted_as_before():
    got = _delete(0, 0)
    assert got["confirms"][0]["message"] == KEPT
    assert got["toasts"] == [["success", "Department deleted"]]


def test_the_toast_counts_what_the_server_removed():
    """The server counts again when it deletes: a mapping added or removed since the page was drawn is in its answer."""
    got = _delete(2, 3)
    assert got["toasts"] == [["success", "Department deleted, with 3 single sign-on group mappings"]]


def test_no_answer_to_the_question_deletes_nothing():
    got = _delete(2, 2, yes=False)
    assert got["asked"] == []
    assert got["toasts"] == []
