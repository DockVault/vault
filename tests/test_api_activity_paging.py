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


def test_a_page_too_far_in_to_open_directly_says_so(admin):
    r = admin.get("/activity/events", params={"page": 5000, "limit": 100})
    assert r.status_code == 400
    assert "a page at a time" in r.json()["detail"]


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
    assert [e["username"] for e in body["events"]] == [f"{prefix}-n-1", f"{prefix}-n-0"]
    assert body["more"] is False and body["total"] is None
    # More new rows than asked for: the list is told to reload rather than patch in part of them.
    assert _events(admin, user=prefix, after=shown, limit=1)["more"] is True
    # The newest row has nothing after it.
    newest = body["events"][0]["id"]
    assert _events(admin, user=prefix, after=newest) == {"events": [], "next_cursor": None, "total": None,
                                                        "more": False}


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
        assert got == [{"username": f"{stem}-account", "account": True},
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
