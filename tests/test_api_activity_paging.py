"""API: the Events list's numbered pages, its live reads (newer rows, specific rows), the temporary
credential filter by name and the username typeahead, against a running vault.

Each test makes its own rows (failed sign-ins under fresh names) and filters to them, so it does not
depend on what else the log holds."""
import time

import pytest

from conftest import ApiClient, unique


def _events(client, **params):
    r = client.get("/activity/events", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _failed_sign_ins(prefix, n):
    anon = ApiClient()
    for i in range(n):
        r = anon.post("/auth/login", json={"username": f"{prefix}-{i}", "password": "not-the-password-1"})
        assert r.status_code in (401, 403, 429), r.text


def _wait_for(client, want, **params):
    for _ in range(25):
        body = _events(client, **params)
        if (body["total"] if body.get("total") is not None else len(body["events"])) >= want:
            return body
        time.sleep(0.2)
    raise AssertionError(f"fewer than {want} rows for {params}")


def test_numbered_pages_hold_every_row_once_whichever_way_they_are_reached(admin):
    prefix = unique("pages")
    _failed_sign_ins(prefix, 5)
    first = _wait_for(admin, 5, user=prefix, page=1, limit=2)
    assert (first["total"], first["pages"], first["page"], first["page_size"]) == (5, 3, 1, 2)
    assert len(first["events"]) == 2 and first["next_cursor"]
    # Page 2 reached by its number (the rows before it skipped) and by the cursor from page 1.
    by_number = _events(admin, user=prefix, page=2, limit=2)
    by_cursor = _events(admin, user=prefix, page=2, limit=2, cursor=first["next_cursor"])
    assert [e["id"] for e in by_number["events"]] == [e["id"] for e in by_cursor["events"]]
    assert by_cursor["total"] == 5 and by_cursor["pages"] == 3
    last = _events(admin, user=prefix, page=3, limit=2, cursor=by_cursor["next_cursor"])
    assert len(last["events"]) == 1 and last["next_cursor"] is None
    ids = [e["id"] for p in (first, by_cursor, last) for e in p["events"]]
    assert len(ids) == len(set(ids)) == 5
    stamps = [e["timestamp"] for p in (first, by_cursor, last) for e in p["events"]]
    assert stamps == sorted(stamps, reverse=True)             # newest first across the pages
    # A page past the end is empty rather than an error.
    assert _events(admin, user=prefix, page=9, limit=2)["events"] == []


def test_a_page_past_the_end_is_empty(admin):
    # (A page far from both ends of a long list is refused; tests/test_activity_events_paging.py
    # covers that, since it takes more than 200,000 rows.)
    body = _events(admin, page=5000, limit=100)
    assert body["events"] == [] and body["page"] == 5000 and body["next_cursor"] is None


def test_newer_rows_are_the_ones_after_the_row_the_list_shows(admin):
    prefix = unique("after")
    _failed_sign_ins(prefix, 1)
    shown = _wait_for(admin, 1, user=prefix)["events"][0]["id"]
    _failed_sign_ins(prefix + "-n", 2)
    body = None
    for _ in range(25):
        body = _events(admin, user=prefix, after=shown)
        if len(body["events"]) >= 2:
            break
        time.sleep(0.2)
    # The nearest first: the rows next to the one shown, in time order.
    assert [e["username"] for e in body["events"]] == [f"{prefix}-n-0", f"{prefix}-n-1"]
    assert body["more"] is False and body["total"] is None
    assert body["head_cursor"] == body["events"][-1]["cursor"]
    # More new rows than asked for: the nearest one, and `more` says others follow.
    one = _events(admin, user=prefix, after=shown, limit=1)
    assert [e["username"] for e in one["events"]] == [f"{prefix}-n-0"] and one["more"] is True
    # From that row's cursor, the next one: how Newer walks from any event.
    step = _events(admin, user=prefix, after=one["events"][0]["cursor"], limit=1)
    assert [e["username"] for e in step["events"]] == [f"{prefix}-n-1"]
    # The newest row has nothing after it.
    newest = body["events"][-1]["id"]
    assert _events(admin, user=prefix, after=newest) == {"events": [], "next_cursor": None, "total": None,
                                                        "more": False, "head_cursor": None}
    # A safety poll reaching back two minutes also returns the rows just before its starting point.
    polled = _events(admin, user=prefix, after=newest, overlap=120)
    assert {e["username"] for e in polled["events"]} == {prefix + "-0", f"{prefix}-n-0", f"{prefix}-n-1"}
    assert _events(admin, user=prefix, after=shown, count_only="true") == {"count": 2}


def test_a_row_the_list_no_longer_knows_means_reload(admin):
    import uuid
    body = _events(admin, after=str(uuid.uuid4()))
    assert body["events"] == [] and body["more"] is True
    assert _events(admin, after="not-an-id")["more"] is True


def test_rows_named_by_the_signal_come_back_only_if_they_match_the_filters(admin):
    prefix = unique("ids")
    _failed_sign_ins(prefix, 2)
    rows = _wait_for(admin, 2, user=prefix)["events"]
    ids = [e["id"] for e in rows]
    both = _events(admin, ids=ids)
    assert sorted(e["id"] for e in both["events"]) == sorted(ids)
    assert "names" in both["events"][0]                   # the same per-viewer view as the list
    only = _events(admin, ids=ids, user=f"{prefix}-1")
    assert [e["username"] for e in only["events"]] == [f"{prefix}-1"]
    assert _events(admin, ids=ids, category="files")["events"] == []
    # Comma-separated, as the page sends a batch, and counted without the rows.
    assert sorted(e["id"] for e in _events(admin, ids=",".join(ids))["events"]) == sorted(ids)
    assert _events(admin, ids=",".join(ids), user=f"{prefix}-1", count_only="true") == {"count": 1}


def test_one_event_opens_by_its_id(admin):
    prefix = unique("one")
    _failed_sign_ins(prefix, 1)
    row = _wait_for(admin, 1, user=prefix)["events"][0]
    r = admin.get(f"/activity/events/{row['id']}")
    assert r.status_code == 200, r.text
    got = r.json()
    assert got["id"] == row["id"] and got["username"] == f"{prefix}-0" and "names" in got
    import uuid
    assert admin.get(f"/activity/events/{uuid.uuid4()}").status_code == 404
    assert admin.get("/activity/events/not-an-id").status_code == 404


def test_the_filters_the_page_asks_for(admin, temp_vault):
    prefix = unique("filters")
    _failed_sign_ins(prefix, 2)
    _wait_for(admin, 2, user=prefix)
    # By event name, and by the label the page shows.
    assert _events(admin, user=prefix, action="login_failure")["total"] == 2
    assert _events(admin, user=prefix, action="file_uploaded")["total"] == 0
    assert _events(admin, user=prefix, q="Sign-in failed")["total"] == 2
    # A user exactly, not every name containing it.
    assert _events(admin, user=f"{prefix}-1", user_match="exact")["total"] == 1
    assert _events(admin, user=prefix, user_match="exact")["total"] == 0
    # Names no account had.
    assert _events(admin, user=prefix, no_account="true")["total"] == 2
    # A vault: its own rows and the rows of what is in it.
    vid = temp_vault["id"]
    up = admin.post(f"/vaults/{vid}/files", files=[("files", (unique("f") + ".txt", b"x", "text/plain"))])
    assert up.status_code in (200, 201), up.text
    in_vault = None
    for _ in range(25):
        in_vault = _events(admin, vault_id=vid)
        if in_vault["total"] >= 1:
            break
        time.sleep(0.2)
    assert in_vault["total"] >= 1
    assert all(e["resource_id"] == vid or (e["details"] or {}).get("vault_id") == vid for e in in_vault["events"])
    assert _events(admin, vault_id="not-an-id")["total"] == 0


def test_a_numbered_page_says_where_its_neighbours_start(admin):
    prefix = unique("cursors")
    _failed_sign_ins(prefix, 3)
    first = _wait_for(admin, 3, user=prefix, page=1, limit=2)
    assert first["prev_cursor"] == first["events"][0]["cursor"]
    assert first["next_cursor"] == first["events"][-1]["cursor"]
    assert first["head_cursor"] == first["events"][0]["cursor"]
    # Older from any event: the cursor continues after it.
    older = _events(admin, user=prefix, cursor=first["events"][0]["cursor"], limit=1)
    assert older["events"][0]["id"] == first["events"][1]["id"]


def test_a_temporary_credential_is_found_by_its_name_even_after_it_is_deleted(admin, temp_user):
    uc = ApiClient()
    uc.login(temp_user["_username"], temp_user["_password"])
    tc = uc.post("/auth/temp-credentials", json={"note": unique("named")}).json()
    name = tc["temp_username"]
    ApiClient().login(name, tc["credential"])
    body = _wait_for(admin, 1, temp_credential=name, category="sign_in")
    ev = body["events"][0]
    assert ev["temp_credential_name"] == name and ev["username"] == temp_user["_username"]
    assert _events(admin, temp_credential=name[:-2], category="sign_in")["total"] >= 1   # part of it
    assert uc.post(f"/temp-creds/{name}/delete").status_code == 200
    after = _events(admin, temp_credential=name, category="sign_in")
    assert after["total"] >= 1 and after["events"][0]["temp_credential_name"] == name
    assert _events(admin, temp_credential=unique("nobody"))["total"] == 0


def test_the_typeahead_offers_accounts_and_names_only_the_log_has_seen(admin, temp_user):
    stem = unique("ta").lower()
    typed = f"{stem}-Typed"
    ApiClient().post("/auth/login", json={"username": typed, "password": "not-the-password-1"})
    user = admin.create_user(username=f"{stem}-account")
    try:
        got = None
        for _ in range(25):
            got = admin.get("/activity/usernames", params={"q": stem}).json()["usernames"]
            if len(got) >= 2:
                break
            time.sleep(0.2)
        assert got == [{"username": f"{stem}-account", "account": True, "active": True},
                       {"username": typed, "account": False}]            # in name order, as typed
        upper = admin.get("/activity/usernames", params={"q": stem.upper()}).json()["usernames"]
        assert upper == got                                                # any case finds them
        assert admin.get("/activity/usernames", params={"q": stem, "limit": 1}).json()["usernames"] == got[:1]
        assert admin.get("/activity/usernames", params={"q": ""}).json() == {"usernames": []}
        assert admin.get("/activity/usernames", params={"q": stem, "limit": 21}).status_code == 422
    finally:
        admin.delete_user(user["id"])


def test_only_an_administrator_gets_the_typeahead(temp_user_client):
    assert temp_user_client.get("/activity/usernames", params={"q": "a"}).status_code == 403
    assert temp_user_client.get("/activity/temp-credentials", params={"q": "temp_"}).status_code == 403


def test_the_typeahead_can_offer_accounts_only(admin):
    stem = unique("tb").lower()
    ApiClient().post("/auth/login", json={"username": f"{stem}-typed", "password": "not-the-password-1"})
    user = admin.create_user(username=f"{stem}-account")
    try:
        got = None
        for _ in range(25):
            got = admin.get("/activity/usernames", params={"q": stem}).json()["usernames"]
            if len(got) >= 2:
                break
            time.sleep(0.2)
        assert len(got) == 2
        only = admin.get("/activity/usernames", params={"q": stem, "accounts_only": "true"}).json()["usernames"]
        assert only == [{"username": f"{stem}-account", "account": True, "active": True}]
    finally:
        admin.delete_user(user["id"])


def test_the_credential_typeahead_names_state_and_expiry_but_never_the_note(admin):
    note = unique("secret-note")
    tc = admin.post("/auth/temp-credentials", json={"note": note}).json()
    name = tc["temp_username"]
    try:
        r = admin.get("/activity/temp-credentials", params={"q": name})
        assert r.status_code == 200, r.text
        got = r.json()["temp_credentials"]
        assert [c["name"] for c in got] == [name]
        assert got[0]["state"] == "active" and got[0]["expires_at"].endswith("+00:00")
        assert set(got[0]) == {"id", "name", "state", "expires_at"} and note not in r.text
        assert admin.get("/activity/temp-credentials", params={"q": "t"}).json() == {"temp_credentials": []}
    finally:
        admin.post(f"/temp-creds/{name}/delete")
