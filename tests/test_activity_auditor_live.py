"""The Activity page for an auditor on a running stack (app/api/activity_viewer.py, app/services/activity_case.py).

An auditor whose right is in force reads the log (the events, one event, the summary without what is happening now,
the typeahead, saved searches, the export) and not the live views; their reading is recorded once in ten minutes.
Their socket hears the live signal (an id and a category, nothing more) until the right ends. With their case
selected, the events are the case's own and those on its vaults, a file's name shows because of the case, and N
fetches of the same page write one ``case_names_viewed`` row. In a vault with a vault password the auditor is no
member of, the case's event says the password hides the file's name and offers it, and the password given in the
case shows it; with a case on one folder for a time range, only where the case names the item. Anyone else, and an
administrator the case concerns, is answered that there is no such case. test_activity_auditor.py covers the rules
offline.
"""
import json
import time
from datetime import datetime, timedelta, timezone

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


HIDDEN = "Name hidden: the vault has a password"
NOT_SHOWN = "Not shown: you are not a member of this vault"


def test_a_password_vault_in_the_case_is_offered_its_password_and_named_once_given(world):
    """uma is no member of olga's vault with a vault password. With her case on it selected, the event of a file in it
    says the password hides the name and offers it (unlock_in_case); without the case, or to an administrator
    selecting it, nothing is offered. The password given in the case (its own route and receipt) shows the name."""
    _uma, uma_c, _codes = world["uma"]
    _olga, olga_c, _vid = world["olga"]
    password = "Vault-Pass-2026!"
    pv = olga_c.create_vault(name=unique("locked"), password=password)["id"]
    case = None
    try:
        name = f"{unique('plan')}.txt"
        up = olga_c.post(f"/vaults/{pv}/files", files=[("files", (name, b"the plan", "text/plain"))],
                         headers={"X-Vault-Password": password})
        assert up.status_code in (200, 201), up.text
        fid = up.json()["files"][0]["id"]
        case = approved_case(world["admins"], world["uma"], [pv])

        def about_the_file(client, params, headers=None):
            r = client.get("/activity/events", params={"limit": 100, **params}, headers=headers or {})
            assert r.status_code == 200, r.text[:300]
            found = [e for e in r.json()["events"] if e.get("resource_id") == fid]
            assert found, "the upload's event is listed"
            return found

        mine = about_the_file(uma_c, {"case": case["id"]})
        assert all(e["names"]["item"] == HIDDEN and e.get("unlock_in_case") is True for e in mine), mine
        assert all(e["names"]["vault"] != NOT_SHOWN for e in mine), "the case shows its vault's name"
        plain = about_the_file(uma_c, {"vault_id": pv})
        assert all(e["names"]["item"] == NOT_SHOWN and "unlock_in_case" not in e for e in plain), plain
        _ada, ada_c, _ = world["admins"]["ada"]
        theirs = about_the_file(ada_c, {"case": case["id"]})
        assert all("unlock_in_case" not in e and e["names"]["item"] != name for e in theirs), theirs
        unlock = f"/compliance/cases/{case['id']}/vaults/{pv}/unlock"
        assert uma_c.post(unlock, json={"password": "not the password"}).status_code == 403
        r = uma_c.post(unlock, json={"password": password})
        assert r.status_code == 200, r.text
        given = {"X-Case-Unlock": f"{pv}={r.json()['receipt']}"}
        named = about_the_file(uma_c, {"case": case["id"]}, given)
        assert all(e["names"]["item"] == name and "unlock_in_case" not in e for e in named), named
        one = uma_c.get(f"/activity/events/{named[0]['id']}", params={"case": case["id"]}, headers=given)
        assert one.status_code == 200 and one.json()["names"]["item"] == name, one.text[:300]
        # The receipt opens the vault in this case only: in the list without the case, the name stays hidden.
        assert all(e["names"]["item"] == NOT_SHOWN for e in about_the_file(uma_c, {"vault_id": pv}, given))
    finally:
        if case is not None:
            forget_cases([case["id"]], [pv])
        olga_c.delete_vault(pv, vault_password=password)


def test_a_case_on_one_folder_offers_the_password_only_where_it_would_name_the_item(world):
    """A case on one folder of olga's vault with a vault password, for files changed in the last 30 days; uma is no
    member of the vault. The password is offered, and once given in the case the names show, exactly where the case
    names the item: the folder, a new file in it, and an old file in it changed in the range. Never an old file in it
    left alone, a file in the folder beside it, a file at the top of the vault or the folder beside it; never to an
    administrator selecting the case."""
    _uma, uma_c, _codes = world["uma"]
    _olga, olga_c, _vid = world["olga"]
    password = "Vault-Pass-2026!"
    pv = olga_c.create_vault(name=unique("folders"), password=password)["id"]
    sent = {"X-Vault-Password": password}
    case = None
    try:
        def folder(name):
            r = olga_c.post(f"/vaults/{pv}/folders", json={"name": name, "parent_folder_id": None}, headers=sent)
            assert r.status_code in (200, 201), r.text
            return r.json()["folder"]["id"]

        def upload(name, folder_id=None):
            r = olga_c.post(f"/vaults/{pv}/files", files=[("files", (name, b"x", "text/plain"))],
                            params={"folder_id": folder_id} if folder_id else None, headers=sent)
            assert r.status_code in (200, 201), r.text
            return r.json()["files"][0]["id"]

        inside, beside = folder("Inside"), folder("Beside")
        names = {key: f"{unique(key)}.txt" for key in ("new", "changed", "old", "beside", "top")}
        ids = {"new": upload(names["new"], inside), "changed": upload(names["changed"], inside),
               "old": upload(names["old"], inside), "beside": upload(names["beside"], beside),
               "top": upload(names["top"]), "inside": inside, "beside_folder": beside}
        long_ago = "(now() at time zone 'utc') - interval '400 days'"
        psql(f"UPDATE files SET created_at = {long_ago}, updated_at = {long_ago} WHERE id = '{ids['old']}'")
        psql(f"UPDATE files SET created_at = {long_ago}, updated_at = (now() at time zone 'utc') - interval '2 days' "
             f"WHERE id = '{ids['changed']}'")
        since = (datetime.now(timezone.utc) - timedelta(days=30)).isoformat()
        case = approved_case(world["admins"], world["uma"], [], scope=[{"kind": "folder", "target_id": inside}],
                             files_from=since)

        def read(client, headers=None):
            r = client.get("/activity/events", params={"case": case["id"], "vault_id": pv, "limit": 200},
                           headers=headers or {})
            assert r.status_code == 200, r.text[:300]
            got, events = {}, {}
            for e in r.json()["events"]:
                for key, rid in ids.items():
                    if e.get("resource_id") == rid:
                        got.setdefault(key, set()).add((e["names"]["item"], e.get("unlock_in_case")))
                        events[key] = e["id"]
            assert set(got) == set(ids), got
            return got, events

        offered = {"new", "changed", "inside"}
        locked, events = read(uma_c)
        assert locked == {key: {(HIDDEN, True) if key in offered else (NOT_SHOWN, None)} for key in ids}, locked
        one = uma_c.get(f"/activity/events/{events['changed']}", params={"case": case["id"]})
        assert one.status_code == 200 and one.json().get("unlock_in_case") is True, one.text[:300]
        _ada, ada_c, _ = world["admins"]["ada"]
        theirs, _events = read(ada_c)
        assert not any(mark for got in theirs.values() for _name, mark in got), theirs
        r = uma_c.post(f"/compliance/cases/{case['id']}/vaults/{pv}/unlock", json={"password": password})
        assert r.status_code == 200, r.text
        named, _events = read(uma_c, {"X-Case-Unlock": f"{pv}={r.json()['receipt']}"})
        shown = {"new": names["new"], "changed": names["changed"], "inside": "Inside"}
        assert named == {key: {(shown[key], None)} if key in offered else {(NOT_SHOWN, None)} for key in ids}, named
    finally:
        if case is not None:
            forget_cases([case["id"]], [pv])
        olga_c.delete_vault(pv, vault_password=password)
