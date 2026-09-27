"""API: the Activity page's summary band, against a running vault.

Each test filters the band to rows it made itself (a fresh username), so the counts are exact whatever
else the log holds; the band is then the same rows the Events list shows for that filter."""
import time

import pytest

from conftest import ApiClient, unique


def _summary(client, **params):
    r = client.get("/activity/summary", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def _failed_sign_in(name):
    r = ApiClient().post("/auth/login", json={"username": name, "password": "not-the-password-1"})
    assert r.status_code in (401, 403, 429), r.text


def _settled(client, want, **params):
    for _ in range(25):
        body = _summary(client, **params)
        if body["total"] >= want:
            return body
        time.sleep(0.2)
    raise AssertionError(f"the band never counted {want} rows for {params}")


def test_the_band_counts_the_rows_the_events_list_shows(admin):
    name = unique("band")
    _failed_sign_in(name)
    _failed_sign_in(name)
    band = _settled(admin, 2, range="24h", user=name)
    assert band["range"] == "24h" and band["bucket_seconds"] == 3600 and len(band["buckets"]) == 24
    assert band["total"] == 2 == sum(b["total"] for b in band["buckets"])
    assert band["buckets"][-1]["counts"] == {"sign_in": 2}        # the hour in progress
    assert band["categories"] == [{"key": "sign_in", "label": "Sign-in and sessions", "count": 2}]
    assert band["sign_ins"] == {"succeeded": 0, "failed": 2, "locked": 0}
    assert band["top_users"] == [{"username": name, "count": 2}]
    ip = admin.get("/activity/events", params={"user": name}).json()["events"][0]["ip_address"]
    assert band["top_addresses"] == [{"ip_address": ip, "count": 2}]
    events = admin.get("/activity/events", params={"user": name, "from_date": band["from"]}).json()
    assert events["total"] == band["total"]


@pytest.mark.parametrize("range_key,buckets", [("7d", 28), ("30d", 30)])
def test_the_longer_ranges_have_their_buckets(admin, range_key, buckets):
    name = unique("band")
    _failed_sign_in(name)
    band = _settled(admin, 1, range=range_key, user=name, tz_offset=120)
    assert len(band["buckets"]) == buckets
    assert band["buckets"][-1]["total"] == 1


def test_what_is_happening_now_counts_this_session(admin):
    now = _summary(admin)["now"]
    assert set(now) == {"as_of", "sessions", "people", "temporary_credentials",
                        "transfers_in_progress", "transfers_waiting"}
    assert now["sessions"] >= 1 and now["people"] >= 1


def test_an_administrator_who_cannot_read_a_vault_sees_no_name_from_it(admin, temp_user, temp_user_client):
    # The user's own vault, which the administrator is not a member of, and a file in it.
    vault_name = unique("private-vault")
    file_name = unique("private-file") + ".txt"
    vault = temp_user_client.create_vault(name=vault_name)
    try:
        up = temp_user_client.post(f"/vaults/{vault['id']}/files",
                                   files=[("files", (file_name, b"secret contents", "text/plain"))])
        assert up.status_code in (200, 201), up.text
        band = _settled(admin, 2, range="24h", user=temp_user["_username"])
        assert band["categories"], band
        text = str(band)
        assert vault_name not in text and file_name not in text and "private-" not in text
        # Control: the Events list for the same rows withholds the names the same way.
        events = admin.get("/activity/events", params={"user": temp_user["_username"]}).json()["events"]
        assert vault_name not in str(events) and file_name not in str(events)
    finally:
        temp_user_client.delete_vault(vault["id"])


def test_only_an_administrators_own_session_reads_the_band(admin, temp_user_client):
    assert temp_user_client.get("/activity/summary").status_code == 403
    tc = admin.post("/auth/temp-credentials", json={"note": unique("band")}).json()
    tclient = ApiClient()
    tclient.login(tc["temp_username"], tc["credential"])
    try:
        assert tclient.get("/activity/summary").status_code == 403
    finally:
        admin.post(f"/temp-creds/{tc['temp_username']}/delete")


def test_a_range_or_clock_it_does_not_offer_is_refused(admin):
    assert admin.get("/activity/summary", params={"range": "90d"}).status_code == 422
    assert admin.get("/activity/summary", params={"tz_offset": 900}).status_code == 422
