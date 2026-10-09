"""The Activity page for an auditor on a running stack (app/api/activity_viewer.py, app/services/activity_case.py).

An auditor whose right is in force reads the log (the events, one event, the summary without what is happening now,
the typeahead, saved searches, the export) and not the live views; their reading is recorded once in ten minutes.
Their socket hears the live signal (an id and a category, nothing more) until the right ends. With their case
selected, the events are the case's own and those on its vaults, a file's name shows because of the case, and N
fetches of the same page write one ``case_names_viewed`` row. Anyone else, and an administrator the case concerns,
is answered that there is no such case. test_activity_auditor.py covers the rules offline.
"""
import json
import time

import pytest

from _account_change_helpers import psql
from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import approved_case, forget_cases, owner_with_vault, wait_for
from conftest import ApiClient, unique

websocket = pytest.importorskip("websocket")  # websocket-client

pytestmark = pytest.mark.integration


@pytest.fixture
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        made, vaults = [], [vid]
        try:
            yield {"admins": admins, "admin": admin, "uma": (uma, uma_c, codes), "olga": (olga, olga_c, vid),
                   "cases": made, "vaults": vaults}
        finally:
            forget_cases(made, vaults)
            forget_grants(uma["id"])


def _viewed(uid):
    return int(psql(f"SELECT count(*) FROM audit_logs WHERE action = 'auditor_events_viewed' AND user_id = '{uid}'"))


def test_an_auditor_reads_the_log_but_not_the_live_views_and_is_recorded_once(world):
    uma, uma_c, _codes = world["uma"]
    _olga, olga_c, _vid = world["olga"]
    events = uma_c.get("/activity/events", params={"limit": 5})
    assert events.status_code == 200, events.text
    first = events.json()["events"][0]["id"]
    for path, params in (("/activity/catalog", None), (f"/activity/events/{first}", None),
                         ("/activity/usernames", {"q": "a"}), ("/activity/saved-searches", None),
                         ("/activity/export", {"format": "ndjson", "category": "compliance"})):
        r = uma_c.get(path, params=params)
        assert r.status_code == 200, (path, r.text[:200])
    summary = uma_c.get("/activity/summary")
    assert summary.status_code == 200 and summary.json()["now"] is None, "live sessions are an administrator's"
    assert uma_c.post("/activity/events/search", json={"category": ["compliance"]}).status_code == 200
    saved = uma_c.post("/activity/saved-searches", json={"name": unique("mine"), "filters": {"category": ["files"]}})
    assert saved.status_code in (200, 201), saved.text
    for path in ("/activity/now", "/activity/temp-credentials"):
        assert uma_c.get(path, params={"q": "ab"}).status_code == 403, path
    assert _viewed(uma["id"]) == 1, "one row for every read within ten minutes"
    assert olga_c.get("/activity/events").status_code == 403
    ada, ada_c, _ = world["admins"]["ada"]
    assert ada_c.delete(f"/users/{uma['id']}/auditor", json={"reason": "Ended."}).status_code == 200
    assert uma_c.get("/activity/events").status_code == 403, "the right ends access at once"


def _ws(base_url, token):
    ws = websocket.create_connection(base_url.replace("http://", "ws://") + "/ws/monitor", timeout=10)
    ws.send(json.dumps({"type": "auth", "token": token}))
    ws.settimeout(8)
    assert json.loads(ws.recv()).get("type") == "connected"
    return ws


def _signalled(ws, seconds, until=None):
    ws.settimeout(0.5)
    out, deadline = [], time.time() + seconds
    while time.time() < deadline:
        try:
            raw = ws.recv()
        except websocket.WebSocketTimeoutException:
            continue
        data = json.loads(raw) if raw else {}
        if data.get("type") == "activity":
            out.append(raw)
            if until and until(out):
                break
    return out


def test_an_auditors_socket_hears_the_signal_until_the_right_ends(world, base_url):
    uma, uma_c, _codes = world["uma"]
    ws = _ws(base_url, uma_c.token)
    try:
        name = unique("signal")
        ApiClient().post("/auth/login", json={"username": name, "password": "not-the-password-1"})
        row = wait_for(lambda: psql(f"SELECT id FROM audit_logs WHERE username = '{name}' LIMIT 1") or None)
        frames = _signalled(ws, 8, until=lambda fs: any(row in f for f in fs))
        hits = [e for f in frames for e in json.loads(f)["events"] if e["id"] == row]
        assert hits == [{"id": row, "category": "sign_in"}], frames
        assert not any(name in f for f in frames)
        ada, ada_c, _ = world["admins"]["ada"]
        assert ada_c.delete(f"/users/{uma['id']}/auditor", json={"reason": "Ended."}).status_code == 200
        _signalled(ws, 7)                          # the socket re-checks its session every ~5 s
        ApiClient().post("/auth/login", json={"username": unique("signal"), "password": "not-the-password-1"})
        assert _signalled(ws, 3) == []
    finally:
        ws.close()


def test_a_case_selected_shows_its_names_and_a_page_fetched_again_writes_no_more(world):
    uma, uma_c, _codes = world["uma"]
    olga, olga_c, vid = world["olga"]
    other = olga_c.create_vault(name=unique("elsewhere"))["id"]
    world["vaults"].append(other)
    name = f"{unique('board')}.txt"
    up = olga_c.post(f"/vaults/{vid}/files", files=[("files", (name, b"minutes", "text/plain"))])
    assert up.status_code in (200, 201), up.text
    fid = up.json()["files"][0]["id"]
    assert olga_c.post(f"/vaults/{other}/files",
                       files=[("files", ("x.txt", b"x", "text/plain"))]).status_code in (200, 201)
    case = approved_case(world["admins"], world["uma"], [vid])
    world["cases"].append(case["id"])

    def page():
        r = uma_c.get("/activity/events", params={"case": case["id"], "limit": 100})
        assert r.status_code == 200, r.text[:300]
        return r.json()["events"]
    events = page()
    vaults = {(e.get("details") or {}).get("vault_id") for e in events} - {None}
    assert vaults <= {vid}, "only the case's vaults"
    mine = [e for e in events if e.get("resource_id") == fid]
    assert mine and all(e["names"]["item"] == name and "item" in e.get("shown_by_case", []) for e in mine)
    rows = int(psql(f"SELECT count(*) FROM audit_logs WHERE action = 'case_names_viewed' AND case_id = '{case['id']}'"))
    for _ in range(4):
        page()
    after = int(psql(f"SELECT count(*) FROM audit_logs WHERE action = 'case_names_viewed' "
                     f"AND case_id = '{case['id']}'"))
    assert rows >= 1 and after == rows, "the same page again writes no row: the list does not feed itself"
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'case_names_viewed' AND case_id = '{case['id']}' "
                f"AND audit_logs::text LIKE '%{name}%'") == "0"
    # An administrator selecting the case reads the names they would anyway: none here.
    _ada, ada_c, _ = world["admins"]["ada"]
    theirs = ada_c.get("/activity/events", params={"case": case["id"], "limit": 100}).json()["events"]
    assert all(e["names"]["item"] != name for e in theirs if e.get("resource_id") == fid)
    # The owner, who is no auditor, reads no log at all; an unknown case is not found.
    assert olga_c.get("/activity/events", params={"case": case["id"]}).status_code == 403
    assert uma_c.get("/activity/events", params={"case": "00000000-0000-0000-0000-000000000000"}).status_code == 404
