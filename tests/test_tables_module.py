"""The tables library (static/js/tables.js) and the two preferences it keeps.

The library sorts, searches and sets the density with DOM calls only; the server stores the sort each table was
left in and the density under two whitelisted preference keys, for the account that set them.
"""
import re
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
JS = (ROOT / "static" / "js" / "tables.js").read_text(encoding="utf-8")
API = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
HTML = (ROOT / "static" / "index.html").read_text(encoding="utf-8")


def test_the_library_builds_dom_and_never_assigns_markup():
    assert "innerHTML" not in JS and "insertAdjacentHTML" not in JS and "outerHTML" not in JS


def test_sorting_announces_itself_to_assistive_technology():
    assert "aria-sort" in JS and "'ascending'" in JS and "'descending'" in JS
    assert "setAttribute('tabindex', '0')" in JS and "e.key === 'Enter'" in JS


def test_the_two_preferences_are_whitelisted_on_the_server():
    assert '"density": {"comfortable", "compact"}' in API
    assert '_PREF_CHECKS = {"tables": _tables_preference_ok}' in API, "the tables key is checked as the JSON its reader expects"
    assert "    density: Optional[str] = None\n    tables: Optional[str] = None" in API


def test_the_density_switch_sits_beside_the_interface_switch():
    assert HTML.index('data-ui-choice="v2"') < HTML.index('data-density="compact"')
    assert 'aria-label="Table density"' in HTML


def test_the_users_table_has_its_two_new_columns_and_the_detail_row_spans_them():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    head = app[app.index("function renderUsersTable() {"):]
    head = head[:head.index("\nfunction ")]
    assert len(re.findall(r"<th[ >]", head)) == 8, re.findall(r"<th[ >]", head)
    assert '<th data-col="last-signin">Last sign-in</th>' in head and '<th data-col="created">Created</th>' in head
    assert 'colspan="8"' in app[app.index("function renderUserRow(u) {"):app.index("function renderUserDetail(u) {")]


def test_the_stylesheets_keep_their_order():
    links = re.findall(r'<link rel="stylesheet" href="/static/css/([a-z0-9-]+)\.css', HTML)
    assert links.index("tables") < links.index("mobile")


# ---- the library's behaviour, run under Node on a small document (tests/js/mini_dom.js) ---------------------

import json
import os
import shutil
import subprocess

PRELUDE = """
const dom = require('./tests/js/mini_dom.js');
const env = dom.install();
const fs = require('fs');
const vm = require('vm');
vm.runInThisContext(fs.readFileSync('static/js/tables.js', 'utf8'), { filename: 'tables.js' });
vm.runInThisContext(fs.readFileSync('static/js/people.js', 'utf8'), { filename: 'people.js' });
const { saved, store } = env;   // `document` is the global the helper installed
const T = (headers, rows, o) => dom.table(document, headers, rows, o);
const col = dom.column;
const header = (t, text) => t.tHead.rows[0].cells.find((th) => th.textContent === text);
const sorts = (t) => t.tHead.rows[0].cells.map((th) => th.getAttribute('aria-sort'));
const when = (iso, o) => People.time(iso, o);
"""


def _node(body: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the library's own code must not be skipped"
    done = subprocess.run([node, "-"], input=PRELUDE + body, capture_output=True, text=True, encoding="utf-8",
                          timeout=60, cwd=str(ROOT), env=dict(os.environ, TZ="UTC"))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads(done.stdout.strip().splitlines()[-1])


def test_the_next_account_on_the_tab_does_not_inherit_the_last_ones_sorts():
    """Account A saved a sort and signed out (the app forgets the browser copy and calls reset); account B, who never
    sorted, signs in: B's table is drawn in server order, and B's first click saves B's entry alone."""
    out = _node("""
Tables.applyPreferences({ tables: JSON.stringify({ users: { col: 'name', dir: 'desc' } }) });
Tables.reset();                 // sign-out
Tables.applyPreferences({});    // B's preferences hold no saved sort
const t = T(['Name', 'Role'], [['ann', 'user'], ['bob', 'admin'], ['cid', 'user']]);
Tables.enhance(t, { key: 'users' });
const before = { names: col(t, 0), sorts: sorts(t) };
header(t, 'Role').click();
console.log(JSON.stringify({ before, saved, store: store.dv_tables }));
""")
    assert out["before"] == {"names": ["ann", "bob", "cid"], "sorts": ["none", "none"]}
    assert out["saved"] == [{"tables": json.dumps({"users": {"col": "role", "dir": "asc"}}, separators=(",", ":"))}]
    assert json.loads(out["store"]) == {"users": {"col": "role", "dir": "asc"}}


def test_preferences_without_a_saved_sort_clear_what_was_remembered_even_without_a_reset():
    out = _node("""
Tables.applyPreferences({ tables: JSON.stringify({ users: { col: 'name', dir: 'desc' } }) });
Tables.applyPreferences({ density: 'compact' });
const t = T(['Name'], [['ann'], ['bob']]);
Tables.enhance(t, { key: 'users' });
console.log(JSON.stringify({ names: col(t, 0), sorts: sorts(t), store: store.dv_tables === undefined }));
""")
    assert out == {"names": ["ann", "bob"], "sorts": ["none"], "store": True}


def test_a_saved_sort_is_keyed_by_the_columns_id_and_survives_a_column_added_before_it():
    out = _node("""
const t1 = T([{ label: 'User', col: 'user' }, { label: 'Created', col: 'created' }],
             [['zed', when('2026-03-01T10:00:00Z')], ['amy', when('2026-01-01T10:00:00Z')]]);
Tables.enhance(t1, { key: 'users' });
header(t1, 'Created').click();
const first = { saved: saved[saved.length - 1], order: col(t1, 0) };
// Drawn again with a column added between: the remembered sort still lands on Created.
const t2 = T([{ label: 'User', col: 'user' }, { label: 'Sign-in methods', col: 'methods' }, { label: 'Created', col: 'created' }],
             [['zed', 'password', when('2026-03-01T10:00:00Z')], ['amy', 'passkey', when('2026-01-01T10:00:00Z')]]);
Tables.enhance(t2, { key: 'users' });
console.log(JSON.stringify({ first, order: col(t2, 0), sorts: sorts(t2), ids: t2.tHead.rows[0].cells.map((th) => th.getAttribute('data-col')) }));
""")
    assert json.loads(out["first"]["saved"]["tables"]) == {"users": {"col": "created", "dir": "asc"}}
    assert out["first"]["order"] == ["amy", "zed"]
    assert out["order"] == ["amy", "zed"]
    assert out["sorts"] == ["none", "none", "ascending"]
    assert out["ids"] == ["user", "methods", "created"]


def test_a_header_without_an_id_gets_a_slug_of_its_title_and_an_old_index_is_not_read():
    out = _node("""
store.dv_tables = JSON.stringify({ users: { col: 1, dir: 'desc' }, other: { col: 'name', dir: 'asc' } });
const t = T(['User', 'Last sign-in'], [['ann', 'x'], ['bob', 'y']]);
Tables.enhance(t, { key: 'users' });
console.log(JSON.stringify({ ids: t.tHead.rows[0].cells.map((th) => th.getAttribute('data-col')), sorts: sorts(t), order: col(t, 0),
                             kept: JSON.parse(store.dv_tables) }));
""")
    assert out["ids"] == ["user", "last-sign-in"]
    assert out["sorts"] == ["none", "none"] and out["order"] == ["ann", "bob"]
    assert out["kept"] == {"other": {"col": "name", "dir": "asc"}}


def test_missing_values_sort_last_whichever_way_the_column_goes():
    out = _node("""
const rows = () => [['ann', when(null, { fallback: 'Never' })], ['bob', when('2026-02-01T00:00:00Z')],
                    ['cid', when('2026-01-01T00:00:00Z')], ['dee', when(null)]];
const t = T([{ label: 'User', col: 'user' }, { label: 'Last sign-in', col: 'last-signin' }], rows());
Tables.enhance(t, { key: 'k' });
header(t, 'Last sign-in').click();
const asc = col(t, 0);
header(t, 'Last sign-in').click();
const desc = col(t, 0);
const n = T([{ label: 'Name', col: 'name' }, { label: 'Uses', col: 'uses' }], [['a', '—'], ['b', '7'], ['c', ''], ['d', '12']]);
Tables.enhance(n, { key: 'n' });
header(n, 'Uses').click(); const nAsc = col(n, 0);
header(n, 'Uses').click(); const nDesc = col(n, 0);
console.log(JSON.stringify({ asc, desc, nAsc, nDesc }));
""")
    assert out["asc"] == ["cid", "bob", "ann", "dee"]
    assert out["desc"] == ["bob", "cid", "ann", "dee"]
    assert out["nAsc"] == ["b", "d", "a", "c"]
    assert out["nDesc"] == ["d", "b", "a", "c"]


def test_a_cell_holding_a_select_sorts_by_the_chosen_option():
    out = _node("""
const pick = (label) => { const s = document.createElement('select');
    ['Read only', 'Read & write', 'Manager'].forEach((o, i) => { const op = document.createElement('option'); op.textContent = o; s.appendChild(op); if (o === label) s.selectedIndex = i; });
    return s; };
const t = T([{ label: 'User', col: 'user' }, { label: 'Permission Level', col: 'level' }],
            [['ann', pick('Read only')], ['bob', pick('Manager')], ['cid', pick('Read & write')]]);
Tables.enhance(t, { key: 'm' });
header(t, 'Permission Level').click();
console.log(JSON.stringify({ order: col(t, 0) }));
""")
    assert out["order"] == ["bob", "cid", "ann"]   # Manager, Read & write, Read only


def test_a_moment_to_come_within_a_week_is_said_in_words():
    out = _node("""
const now = Date.now();
const at = (ms) => when(new Date(now + ms).toISOString()).textContent;
console.log(JSON.stringify({ h23: at(23 * 3600 * 1000 + 30000), d3: at(3 * 86400 * 1000 + 30000), d1: at(86400 * 1000 + 30000),
    m12: at(12 * 60 * 1000 + 30000), soon: at(10 * 1000), ago: at(-3 * 3600 * 1000), beyond: at(10 * 86400 * 1000),
    title: when(new Date(now + 3600 * 1000).toISOString()).title.includes('UTC') }));
""")
    assert out["h23"] == "in 23 h" and out["d3"] == "in 3 days" and out["d1"] == "in 1 day"
    assert out["m12"] == "in 12 min" and out["soon"] == "in a moment" and out["ago"] == "3 h ago"
    assert "in " not in out["beyond"] and out["title"] is True


def test_a_facet_lists_the_columns_values_and_narrows_the_rows_together_with_the_search():
    out = _node("""
const rows = [['ann', 'Active', 'Drop vault'], ['bob', 'Revoked', 'Drop vault'], ['cid', 'Active', 'Confidential inbox'], ['dee', 'Paused', '—']];
const t = T([{ label: 'Owner', col: 'owner' }, { label: 'Status', col: 'status' }, { label: 'Type', col: 'tag' }], rows);
Tables.enhance(t, { key: 'links', search: true, facets: [{ col: 'status', label: 'Status' }, { col: 'tag', label: 'Type' }] });
const host = t.parentNode;
const controls = host.children.map((c) => c.localName + (c.getAttribute('data-facet-col') ? '[' + c.getAttribute('data-facet-col') + ']' : ''));
const status = host.querySelector('select[data-facet-col="status"]');
const options = (s) => s.options.map((o) => o.textContent);
status.value = 'Active'; status.dispatch('change');
const active = col(t, 0);
const search = host.querySelector('input.table-search');
search.value = 'cid'; search.dispatch('input');
const both = col(t, 0);
search.value = 'nobody'; search.dispatch('input');
const none = { rows: col(t, 0), empty: host.querySelector('.table-search-empty') && !host.querySelector('.table-search-empty').hidden };
search.value = ''; search.dispatch('input');
status.value = ''; status.dispatch('change');
console.log(JSON.stringify({ controls, statusOptions: options(status), typeOptions: options(host.querySelector('select[data-facet-col="tag"]')),
    label: status.getAttribute('aria-label'), active, both, none, all: col(t, 0) }));
""")
    assert out["controls"] == ["input", "select[status]", "select[tag]", "table"]
    assert out["statusOptions"] == ["Status: all", "Active", "Paused", "Revoked"]
    assert out["typeOptions"] == ["Type: all", "Confidential inbox", "Drop vault"]      # a dash is not a value
    assert out["label"] == "Filter by Status"
    assert out["active"] == ["ann", "cid"]
    assert out["both"] == ["cid"]
    assert out["none"] == {"rows": [], "empty": True}
    assert out["all"] == ["ann", "bob", "cid", "dee"]


def test_a_chosen_facet_survives_the_table_being_drawn_again_and_follows_the_new_table():
    """The administrators' link tables are built anew on every load, under the same host; the facet select stays,
    keeps its choice while the column still holds that value, and narrows the new table, not the old one."""
    out = _node("""
const t1 = T([{ label: 'Owner', col: 'owner' }, { label: 'Status', col: 'status' }], [['ann', 'Active'], ['bob', 'Revoked']]);
Tables.enhance(t1, { key: 'links', search: true, facets: [{ col: 'status', label: 'Status' }] });
const host = t1.parentNode;
const status = host.querySelector('select[data-facet-col="status"]');
status.value = 'Active'; status.dispatch('change');
// Drawn again: the app empties the host and puts a new table in it, then enhances it.
host.replaceChildren();
const t2 = T([{ label: 'Owner', col: 'owner' }, { label: 'Status', col: 'status' }], [['ann', 'Active'], ['bob', 'Revoked'], ['cid', 'Active']]);
host.appendChild(t2);   // into the same host (its own empty wrapper stays behind)
Tables.enhance(t2, { key: 'links', search: true, facets: [{ col: 'status', label: 'Status' }] });
const fresh = host.querySelector('select[data-facet-col="status"]');
const afterRedraw = { value: fresh.value, rows: col(t2, 0), selects: host.querySelectorAll('select').length, inputs: host.querySelectorAll('input').length };
fresh.value = 'Revoked'; fresh.dispatch('change');
console.log(JSON.stringify({ afterRedraw, revoked: col(t2, 0) }));
""")
    # the host was emptied, so the controls are new ones, and a new choice narrows the new table
    assert out["afterRedraw"]["selects"] == 1 and out["afterRedraw"]["inputs"] == 1
    assert out["afterRedraw"]["rows"] == ["ann", "bob", "cid"] and out["afterRedraw"]["value"] == ""
    assert out["revoked"] == ["bob"]


def test_a_facet_on_a_persisting_table_keeps_its_choice_when_only_the_rows_are_drawn_again():
    """A vault's members table keeps its header; its body is drawn again on every change, and enhance runs again."""
    out = _node("""
const pick = (label) => { const s = document.createElement('select');
    ['Read only', 'Read & write', 'Manager'].forEach((o, i) => { const op = document.createElement('option'); op.textContent = o; s.appendChild(op); if (o === label) s.selectedIndex = i; });
    return s; };
const t = T([{ label: 'User', col: 'user' }, { label: 'Permission Level', col: 'level' }], [['ann', pick('Read only')], ['bob', pick('Manager')]]);
const opts = { key: 'vault-members', search: true, facets: [{ col: 'level', label: 'Level' }] };
Tables.enhance(t, opts);
const level = t.parentNode.querySelector('select[data-facet-col="level"]');
level.value = 'Manager'; level.dispatch('change');
const first = col(t, 0);
// The body is drawn again (a grant): the same table, new rows, enhance again.
const tbody = t.tBodies[0]; tbody.replaceChildren();
[['ann', pick('Read only')], ['bob', pick('Manager')], ['cid', pick('Manager')]].forEach((cells) => { const tr = document.createElement('tr');
    cells.forEach((c) => { const td = document.createElement('td'); if (c.nodeType) td.appendChild(c); else td.textContent = c; tr.appendChild(td); }); tbody.appendChild(tr); });
Tables.enhance(t, opts);
console.log(JSON.stringify({ first, value: level.value, rows: col(t, 0), options: level.options.map((o) => o.textContent),
    selects: t.parentNode.querySelectorAll('select.table-facet').length }));
""")
    assert out["first"] == ["bob"]
    assert out["value"] == "Manager" and out["rows"] == ["bob", "cid"]
    assert out["options"] == ["Level: all", "Manager", "Read only"]
    assert out["selects"] == 1


def test_the_pending_invitations_are_a_table_the_library_enhances_and_leave_revoked_ones_out():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    body = app[app.index("function renderInvites(invites) {"):app.index("function _refocusInviteResend(")]
    assert "invites.filter(inv => inv.status !== 'revoked')" in body
    assert "Tables.enhance(table, { key: 'invites-table', search: true })" in body
    assert "['Invited by', 'invited-by'], ['Sent', 'sent'], ['Expires', 'expires']" in body.replace("\n        ", " ")
    assert "_inviteResentAt[inv.id] || inv.created_at" in body
    assert "innerHTML" not in body


def test_send_again_is_offered_to_the_administrator_who_sent_the_invitation_only():
    # The server refuses a resend by anyone else; the row offers it to the maker alone, and Revoke to every
    # administrator who may manage users.
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    body = app[app.index("function _inviteRow(inv, canManage) {"):app.index("function _refocusInviteResend(")]
    mine = body.index("String(inv.created_by) === String(currentUser.id)")
    guard = body.index("if (mine) {", mine)
    resend = body.index("invite-resend", guard)
    revoke = body.index("invite-revoke")
    assert body.count("invite-resend") == 1
    assert mine < guard < resend < revoke
    # Revoke is outside the maker's branch: it follows the branch's closing brace.
    assert body.index("        }\n", resend) < revoke


def test_the_upload_links_admin_table_shows_when_each_link_was_last_used():
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    body = app[app.index("function renderAdminReceivers(data) {"):]
    body = body[:body.index("\n}\n") + 3]
    assert "['Created', 'created'], ['Last used', 'last-used']" in body
    assert "_whenCell(r.last_upload_at)" in body
    assert "facets: _LINK_TABLE_FACETS" in body


def test_placeholders_become_chips_and_times_before_a_remembered_sort_or_a_search_reads_the_rows():
    """A list drawn from a template holds People placeholders (an empty span with the time or the name in its
    attributes) until the page's watcher runs, after the script that drew it. The library hydrates them first,
    so a remembered sort on such a column orders the rows and a search for a name keeps its row on a redraw."""
    out = _node("""
const ph = (attrs) => { const s = document.createElement('span'); Object.keys(attrs).forEach((k) => s.setAttribute(k, attrs[k])); return s; };
const rows = () => [
    [ph({ 'data-person': '1', 'data-person-id': 'u1', 'data-person-name': 'zed' }), ph({ 'data-when': '2026-03-01T10:00:00Z' })],
    [ph({ 'data-person': '1', 'data-person-id': 'u2', 'data-person-name': 'amy' }), ph({ 'data-when': '2026-01-01T10:00:00Z' })],
    [ph({ 'data-person': '1', 'data-person-id': 'u3', 'data-person-name': 'bob' }), ph({ 'data-when': '', 'data-when-fallback': 'Never' })],
];
Tables.applyPreferences({ tables: JSON.stringify({ users: { col: 'last-signin', dir: 'desc' } }) });
const t = T([{ label: 'User', col: 'user' }, { label: 'Last sign-in', col: 'last-signin' }], rows(), { id: 'users' });
Tables.enhance(t, { key: 'users', search: true });
const sorted = { names: col(t, 0), sorts: sorts(t), chips: t.querySelectorAll('tbody .person-chip').length, times: t.querySelectorAll('tbody time.when').length,
                 left: t.querySelectorAll('span[data-person], span[data-when]').length };
// The box holds a name and the body is drawn again (a grant, a failed change): the row still shows.
const search = t.parentNode.querySelector('input.table-search');
search.value = 'amy'; search.dispatch('input');
const tbody = t.tBodies[0]; tbody.replaceChildren();
rows().forEach((cells) => { const tr = document.createElement('tr'); cells.forEach((c) => { const td = document.createElement('td'); td.appendChild(c); tr.appendChild(td); }); tbody.appendChild(tr); });
Tables.enhance(t, { key: 'users', search: true });
console.log(JSON.stringify({ sorted, redrawn: col(t, 0), empty: !!t.parentNode.querySelector('.table-search-empty') && !t.parentNode.querySelector('.table-search-empty').hidden }));
""")
    assert out["sorted"]["names"] == ["zed", "amy", "bob"]        # newest first, never-signed-in last
    assert out["sorted"]["sorts"] == ["none", "descending"]
    assert out["sorted"]["chips"] == 3 and out["sorted"]["times"] == 2 and out["sorted"]["left"] == 0
    assert out["redrawn"] == ["amy"] and out["empty"] is False
