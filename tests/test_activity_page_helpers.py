"""The Activity page's own arithmetic, run under Node: where a live row goes, which page numbers show,
what a link or a saved search holds, and where a time range starts.

Each of these decides something a person sees without the server being asked again: a late row put
out of order, a total that counts a row twice, a page number the server cannot open, a copied link
that restores different filters, a saved search that loads as something else. So the tests run the
SHIPPED functions, lifted out of ``static/js/activity.js`` verbatim, against a small stand-in for the
page's state. What the browser draws is the UI lane (``test_ui_activity*.py``).
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


def _fn(name: str) -> str:
    """One function of the page, verbatim: a one-line body, or up to its closing brace."""
    head = f"\n    async function {name}(" if f"\n    async function {name}(" in JS else f"\n    function {name}("
    start = JS.index(head) + 1
    line = JS[start:JS.index("\n", start)]
    if line.rstrip().endswith("}") and line.count("{") == line.count("}"):
        return line + "\n"
    return JS[start:JS.index("\n    }\n", start) + 7]


def _line(head: str) -> str:
    start = JS.index("\n    " + head) + 1
    return JS[start:JS.index("\n", start) + 1]


VOCABULARY = JS[JS.index("    const CHANNELS"):JS.index("    // ---- state")]


def _node(body: str, tz: str = "UTC") -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the page's own code must not be skipped"
    env = dict(os.environ, TZ=tz)
    done = subprocess.run([node, "-"], input=body, capture_output=True, text=True, encoding="utf-8",
                          timeout=60, cwd=str(ROOT), env=env)
    assert done.returncode == 0, done.stdout + done.stderr
    assert done.stdout.strip(), "the harness wrote nothing"
    return json.loads(done.stdout)


# ---- where a live row goes -----------------------------------------------------------------------

ARRIVE = "".join(_fn(n) for n in ("rowKey", "noteNewest", "arrive", "insertRows")) + _line("const newerFirst =")
ARRIVE_STUBS = """
let HOLD = null;
const calls = { highlighted: null, burst: null, pill: 0 };
const holdReason = () => HOLD;
const renderPill = () => { calls.pill++; };
const renderCount = () => {}, renderPager = () => {}, watchHeld = () => {}, renderDetail = () => {};
const announceNew = () => {};
const burstReload = (n) => { calls.burst = n; };
const renderList = (light) => { calls.highlighted = light ? Array.from(light) : null; };
const row = (id, t) => ({ id, timestamp: t, cursor: 'c-' + id });
// Page 1 of 25 rows, one a second from 10:00:25 down to 10:00:01; 60 rows match in all.
const page = () => Array.from({ length: 25 }, (_, i) => row('r' + (25 - i), `2026-09-28T10:00:${String(25 - i).padStart(2, '0')}+00:00`));
let S = { rows: page(), total: 60, pages: 3, pageSize: '25', page: 1, allDone: true, held: [], heldExtra: 0,
          heldIds: new Set(), heldBurst: false, detailOpen: false, selectedId: null, detail: null,
          newestRow: null, newestCursor: null, highlightOff: false };
noteNewest(S.rows);
const ids = () => S.rows.map((r) => r.id);
"""


def test_a_new_row_goes_on_top_a_late_one_in_its_place_and_an_older_one_only_counts():
    """The page keeps its size, the total counts all three, and only the two that belong on it go in."""
    out = _node(ARRIVE + ARRIVE_STUBS + """
arrive([row('new', '2026-09-28T10:01:00+00:00'),
        row('late', '2026-09-28T10:00:12.5+00:00'),       // committed late: older than rows on screen
        row('old', '2026-09-28T09:00:00+00:00')]);        // belongs to a later page
console.log(JSON.stringify({ ids: ids(), total: S.total, pages: S.pages, lit: calls.highlighted,
                              newest: S.newestCursor }));
""")
    assert out["ids"][0] == "new"
    assert out["ids"][:14] == ["new"] + [f"r{n}" for n in range(25, 12, -1)]
    assert out["ids"][14] == "late" and out["ids"][15] == "r12"
    assert len(out["ids"]) == 25 and "old" not in out["ids"]          # the page keeps its size
    assert out["ids"][-1] == "r3"                                     # r2 and r1 moved to page 2
    assert out["total"] == 63
    assert sorted(out["lit"]) == ["late", "new"]
    assert out["newest"] == "c-new"


@pytest.mark.parametrize("why", ["detail", "scroll", "pointer", "keys"])
def test_while_someone_is_reading_new_rows_wait_behind_the_pill(why):
    out = _node(ARRIVE + ARRIVE_STUBS + f"""
HOLD = '{why}';
const before = ids();
arrive([row('new', '2026-09-28T10:01:00+00:00')]);
console.log(JSON.stringify({{ same: JSON.stringify(before) === JSON.stringify(ids()), held: S.held.map((r) => r.id),
                              total: S.total, pill: calls.pill }}));
""")
    assert out == {"same": True, "held": ["new"], "total": 61, "pill": 1}


def test_on_a_later_page_new_rows_are_only_counted():
    out = _node(ARRIVE + ARRIVE_STUBS + """
S.page = 2;
const before = ids();
arrive([row('new', '2026-09-28T10:01:00+00:00')]);
console.log(JSON.stringify({ same: JSON.stringify(before) === JSON.stringify(ids()),
                              heldIds: Array.from(S.heldIds), extra: S.heldExtra, total: S.total }));
""")
    assert out == {"same": True, "heldIds": ["new"], "extra": 1, "total": 61}


def test_the_safety_poll_overlap_does_not_count_a_row_twice():
    """The poll reads two minutes back from the newest row held. A row it returns that is older than
    that and below the rows on screen was counted when it came (it is on a later page); one that falls
    among the rows on screen was committed late and is new."""
    out = _node(ARRIVE + ARRIVE_STUBS + """
arrive([row('r25', '2026-09-28T10:00:25+00:00'),              // already on screen
        row('late', '2026-09-28T10:00:20.5+00:00'),          // among the rows on screen: new
        row('below', '2026-09-28T09:59:00+00:00')], { fromPoll: true });
console.log(JSON.stringify({ total: S.total, lit: calls.highlighted, has: ids().includes('below') }));
""")
    assert out == {"total": 61, "lit": ["late"], "has": False}


def test_more_new_rows_than_the_page_holds_read_page_one_again():
    out = _node(ARRIVE + ARRIVE_STUBS + """
const many = Array.from({ length: 30 }, (_, i) => row('n' + i, `2026-09-28T10:0${1 + Math.floor(i / 10)}:${String(i % 10).padStart(2, '0')}+00:00`));
arrive(many);
console.log(JSON.stringify({ burst: calls.burst, lit: calls.highlighted, first: ids()[0] }));
""")
    assert out == {"burst": 30, "lit": None, "first": "r25"}


def test_rows_are_ordered_by_time_then_id_whatever_the_fraction():
    out = _node(_fn("rowKey") + _line("const newerFirst =") + """
const rows = [
  { id: 'b', timestamp: '2026-09-28T10:00:00+00:00' },
  { id: 'a', timestamp: '2026-09-28T10:00:00+00:00' },
  { id: 'c', timestamp: '2026-09-28T10:00:00.5+00:00' },
  { id: 'd', timestamp: '2026-09-28T10:00:00.123456+00:00' },
  { id: 'e', timestamp: '2026-09-28T10:00:01+00:00' },
  { id: 'f', timestamp: '2026-09-28T10:00:00.050000+00:00' },
];
console.log(JSON.stringify(rows.slice().sort(newerFirst).map((r) => r.id)));
""")
    assert out == ["e", "c", "d", "f", "b", "a"]


# ---- page numbers ---------------------------------------------------------------------------------

PAGES = _line("const MAX_OFFSET") + _fn("pageNumbers")


@pytest.mark.parametrize("size,total,current,last,want", [
    ("25", 1284, 1, 52, [1, 2, 3, None, 52]),
    ("25", 1284, 26, 52, [1, None, 24, 25, 26, 27, 28, None, 52]),
    ("25", 1284, 52, 52, [1, None, 50, 51, 52]),
    ("50", 120, 2, 3, [1, 2, 3]),
    # A million rows at 100 a page: the pages beside the current one are more than 100,000 rows from
    # both ends, which the server does not open by number, so only "…" stands for them.
    ("100", 1_000_000, 5000, 10000, [1, None, 5000, None, 10000]),
])
def test_page_numbers_show_the_ends_the_neighbours_and_only_pages_the_server_opens(size, total, current, last, want):
    out = _node(PAGES + f"""
const S = {{ pageSize: '{size}', total: {total} }};
console.log(JSON.stringify(pageNumbers({current}, {last})));
""")
    assert out == want


# ---- addresses ------------------------------------------------------------------------------------

def test_the_network_of_an_address():
    out = _node(_fn("cidrOf") + _fn("expandV6") + """
console.log(JSON.stringify(['203.0.113.7', '2001:db8::1', '2001:0db8:0000:0042:0000:8a2e:0370:7334', '::1',
  'fe80::1%eth0', '::ffff:192.0.2.1', 'nonsense', ''].map(cidrOf)));
""")
    assert out == ["203.0.113.0/24", "2001:db8:0:0::/64", "2001:db8:0:42::/64", "0:0:0:0::/64",
                   "fe80:0:0:0::/64", None, None, None]


@pytest.mark.parametrize("value,ok", [
    ("203.0.113.7", True), ("203.0.113.0/24", True), ("0.0.0.0/0", True), ("256.1.1.1", False),
    ("203.0.113.7/33", False), ("2001:db8::1", True), ("2001:db8::/32", True), ("::1", True),
    ("::ffff:192.0.2.1", True), ("1:2:3:4:5:6:7:8", True), ("1:2:3", False), ("2001:db8::1/129", False),
    ("1::2::3", False), ("2001:db8:::1", False), (":1::2", False), ("1::2:", False),
    ("1::2:3:4:5:6:7:8", False), ("::", True), ("1:2:3:4:5:6:192.0.2.1", True), ("::ffff:192.0.2.256", False),
    ("alex", False), ("203.0.113", False), ("", False),
])
def test_an_address_is_checked_before_anything_is_sent(value, ok):
    out = _node(_fn("validAddress") + f"console.log(JSON.stringify(validAddress({json.dumps(value)})));")
    assert out is ok


# ---- the URL hash ---------------------------------------------------------------------------------

HASH = VOCABULARY + _fn("emptyFilters") + _fn("toDate") + _line("const list = ") + _fn("hashParams") + _fn("readHash")


def test_a_link_restores_the_state_it_was_copied_from():
    out = _node(HASH + """
const f = Object.assign(emptyFilters(), {
  cat: ['sign_in', 'files'], act: ['vault_created'], status: ['failed', 'authorized'], ch: ['sftp', 'web'],
  user: 'alex & co', userMatch: 'exact', ip: '203.0.113.0/24', tcId: '7c1e', tcName: 'Acme audit',
  vault: 'f00d', q: 'invoice #3', time: { from: '2026-09-25T12:00:00.000Z', to: '2026-09-25T18:00:00.000Z' } });
const S = { range: { kind: 'custom', from: '2026-09-20T00:00:00.000Z', to: '2026-09-27T00:00:00.000Z' }, f,
            pageSize: '25', page: 3, selectedId: 'ev-1' };
const back = readHash('#activity?' + hashParams(true).toString());
console.log(JSON.stringify({ back, same: JSON.stringify(back.f) === JSON.stringify(f) }));
""")
    back = out["back"]
    assert out["same"], back["f"]
    assert back["range"] == {"kind": "custom", "from": "2026-09-20T00:00:00.000Z", "to": "2026-09-27T00:00:00.000Z"}
    assert back["page"] == 3 and back["ev"] == "ev-1"


def test_a_hand_made_link_is_read_as_what_the_page_offers_and_no_more():
    out = _node(HASH + """
const long = 'x'.repeat(500);
console.log(JSON.stringify([
  readHash('#activity?range=forever&status=failed,deleted&ch=carrier,sftp&user=' + long + '&page=-4&t=soon~later'),
  readHash('#activity?range=custom&to=2026-09-27T00:00:00Z'),
  readHash('#activity?noAccount=1&user=alex'),
  readHash('#vaults'),
]));
""")
    odd, no_start, no_account, other = out
    assert odd["range"]["kind"] == "7d"
    assert odd["f"]["status"] == ["failed"] and odd["f"]["ch"] == ["sftp"]
    assert len(odd["f"]["user"]) == 128 and odd["page"] == 1 and odd["f"]["time"] is None
    assert no_start["range"] == {"kind": "all", "from": None, "to": "2026-09-27T00:00:00Z"}
    assert no_account["f"]["noAccount"] is True and no_account["f"]["user"] == ""
    assert other is None


# ---- the filters as the API reads them ----------------------------------------------------------

CATALOG = """
const S = { catalog: { categories: [
  { key: 'sign_in', actions: [{ name: 'login_success' }, { name: 'login_failure' }] },
  { key: 'files', actions: [{ name: 'file_upload' }, { name: 'file_download' }] } ] },
  actionInfo: { login_success: { category: 'sign_in' }, login_failure: { category: 'sign_in' },
                file_upload: { category: 'files' }, file_download: { category: 'files' } } };
"""


def test_a_whole_category_and_single_events_from_another_are_either_or():
    """The API narrows by categories AND events; the page means "this category, or these events", so it
    widens each list by the other's members."""
    out = _node(CATALOG + _fn("actionCategory") + _fn("actionsOf") + _fn("catActInto") + """
const both = new URLSearchParams(); catActInto(both, { cat: ['files'], act: ['login_failure'] });
const one = new URLSearchParams(); catActInto(one, { cat: ['files'], act: [] });
console.log(JSON.stringify({ cat: both.getAll('category'), act: both.getAll('action'),
                              oneCat: one.getAll('category'), oneAct: one.getAll('action') }));
""")
    assert out == {"cat": ["files", "sign_in"], "act": ["login_failure", "file_upload", "file_download"],
                   "oneCat": ["files"], "oneAct": []}


# ---- saved searches -------------------------------------------------------------------------------

SAVED = VOCABULARY + _fn("emptyFilters") + _fn("savedFilters") + _fn("stateFromSaved")


def test_a_saved_search_loads_as_the_state_it_was_saved_from():
    out = _node(SAVED + """
const cases = [
  [{ kind: '30d', from: null, to: null }, Object.assign(emptyFilters(), { cat: ['sign_in'], status: ['failed'], user: 'alex', userMatch: 'exact' })],
  [{ kind: 'custom', from: '2026-09-20T00:00:00.000Z', to: null }, Object.assign(emptyFilters(), { noAccount: true, ip: '203.0.113.7', q: 'x' })],
  [{ kind: 'all', from: null, to: '2026-09-01T00:00:00.000Z' }, Object.assign(emptyFilters(), { vault: 'f00d', tcId: '7c', tcName: 'Acme', ch: ['sftp'], act: ['login_failure'] })],
];
console.log(JSON.stringify(cases.map(([range, f]) => {
  const saved = savedFilters(range, f);
  const back = stateFromSaved(JSON.parse(JSON.stringify(saved)));
  return { saved, range: back.range, same: JSON.stringify(back.f) === JSON.stringify(f) };
})));
""")
    assert [c["same"] for c in out] == [True, True, True]
    assert out[0]["range"] == {"kind": "30d", "from": None, "to": None}
    assert out[1]["range"] == {"kind": "custom", "from": "2026-09-20T00:00:00.000Z", "to": None}
    assert out[2]["range"] == {"kind": "all", "from": None, "to": "2026-09-01T00:00:00.000Z"}
    # A vault is saved by its id: a saved search is stored in the clear and never holds a vault name.
    assert out[2]["saved"]["vault_id"] == "f00d" and "vault" not in out[2]["saved"]


def test_a_suggested_name_never_holds_a_vault_name():
    out = _node(VOCABULARY + _fn("emptyFilters") + _fn("plusMore") + _fn("channelLabel") + """
const actionLabel = (n) => n, catLabel = (k) => k, customShort = () => '';
const S = { range: { kind: '7d' }, f: Object.assign(emptyFilters(), { status: ['failed'], user: 'alex', vault: 'f00d' }) };
""" + _fn("suggestName") + "console.log(JSON.stringify(suggestName()));")
    assert out == "Failed or refused · alex · one vault"


# ---- where a time range starts ------------------------------------------------------------------

def test_a_preset_starts_on_its_first_whole_bucket_in_the_viewers_zone():
    """24 h from the top of the hour 23 hours ago, 7 d from the six-hour block 27 blocks ago, 30 d from
    midnight 29 days ago: the band then has exactly 24, 28 and 30 columns, the last one partial."""
    out = _node(_fn("presetStart") + """
const at = (s) => new Date(s).getTime();
const now = at('2026-09-28T10:37:12+03:00');
const late = at('2026-11-10T10:37:12+02:00');           // winter time; the start is in summer time
console.log(JSON.stringify(['24h', '7d', '30d'].map((k) => presetStart(k, now).toISOString())
  .concat([presetStart('30d', late).toISOString()])));
""", tz="Europe/Athens")
    assert out == ["2026-09-27T08:00:00.000Z",     # 11:00 local, 27 Sep
                   "2026-09-21T09:00:00.000Z",     # 12:00 local, 21 Sep
                   "2026-08-29T21:00:00.000Z",     # midnight local, 30 Aug
                   "2026-10-11T21:00:00.000Z"]     # midnight local, 12 Oct, still summer time


def test_the_chart_ceiling_is_a_round_number():
    out = _node(_fn("niceCeil") + "console.log(JSON.stringify([0, 1, 2, 3, 7, 10, 11, 312, 999, 1001].map(niceCeil)));")
    assert out == [1, 1, 2, 5, 10, 10, 20, 500, 1000, 2000]


def test_a_vault_list_that_arrives_after_a_sign_out_is_dropped():
    """The list is read with the session that asked. If that person signs out and someone else signs in
    on the same tab before it arrives, it must not become the next person's list: a vault chip is named
    from it."""
    out = _node(_fn("vaultList") + """
let answer;
const apiRequest = () => new Promise((resolve) => { answer = resolve; });
let S = { vaultList: null };
(async () => {
  const pending = vaultList();
  S = { vaultList: null };                      // signed out, and the next person's page began
  answer([{ id: 'v1', name: 'Payroll' }]);
  const got = await pending;
  const again = vaultList();
  answer([{ id: 'v2', name: 'Mine' }]);
  const own = (await again).map((v) => v.name);
  console.log(JSON.stringify({ got, kept: S.vaultList && S.vaultList.map((v) => v.name), own }));
})();
""")
    assert out == {"got": [], "kept": ["Mine"], "own": ["Mine"]}


# ---- the band's total and the list's -------------------------------------------------------------

RECONCILE = _line("let reconcileTimer") + _fn("reconcileTotals") + """
const timers = [];
const setTimeout = (fn, ms) => { timers.push({ fn, ms }); return timers.length; };
const reads = [];
const loadBand = (live) => { reads.push(live); };
let S = { band: { total: 100, fresh_seconds: 3.2 }, listLoaded: true, total: 101, f: { time: null },
          paused: false, active: true };
"""


def test_a_band_behind_the_list_is_read_again_once_the_server_counts_afresh():
    """A row written just after the shared band was counted: the list says 101, the band 100. The band is
    read again once, when the server's counts are fresh, and not again for the same pair of totals."""
    out = _node(RECONCILE + """
reconcileTotals();
const first = timers.map((t) => t.ms);
reconcileTotals();                                  // a timer is waiting: nothing more
timers[0].fn();                                     // it fires
S.band = { total: 100, fresh_seconds: 0 };          // the same stale count came back
reconcileTotals();                                  // the same pair: not read a third time
const afterSame = timers.length;
S.total = 102;                                      // a new row: a new pair
reconcileTotals();
S.f.time = { from: 'a', to: 'b' };                   // a time on the chart: the totals differ on purpose
S.total = 103;
reconcileTotals();
console.log(JSON.stringify({ first, afterSame, timers: timers.length, reads, last: timers[timers.length - 1].ms }));
""")
    assert out == {"first": [3450], "afterSame": 1, "timers": 2, "reads": [True], "last": 250}


def test_equal_totals_ask_for_nothing():
    out = _node(RECONCILE + """
S.total = 100;
reconcileTotals();
console.log(JSON.stringify({ timers: timers.length }));
""")
    assert out == {"timers": 0}


def test_the_server_operator_is_named_so_not_by_its_internal_name():
    out = _node(_fn("whoText") + """
console.log(JSON.stringify({
    host: whoText({ host_operator: true, username: 'operator@host', channel: 'unknown' }),
    person: whoText({ username: 'alice', channel: 'web' }),
}));
""")
    assert out["host"]["text"] == "Server operator" and out["host"]["quiet"] is True
    assert "operator@host" in out["host"]["title"]
    assert out["person"] == {"text": "alice", "quiet": False}
