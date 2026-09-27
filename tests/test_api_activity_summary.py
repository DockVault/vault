"""API: the Activity page's summary band, against a running vault.

Each test filters the band to rows it made itself (a fresh name, as the text search `q`, which every block
of the band keeps), so the counts are exact whatever else the log holds; the band is then the same rows
the Events list shows for that filter. A filter on a block's own dimension (a person, an event, an
address, a time picked on the chart) is left out of that block, which is what the crossfilter test
checks."""
import time
from datetime import datetime, timedelta, timezone

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


def _listed(client, **params):
    r = client.get("/activity/events", params=params)
    assert r.status_code == 200, r.text
    return r.json()


def test_the_band_counts_the_rows_the_events_list_shows(admin):
    name = unique("band")
    _failed_sign_in(name)
    _failed_sign_in(name)
    band = _settled(admin, 2, range="24h", q=name)
    assert band["range"] == "24h" and band["bucket_seconds"] == 3600 and len(band["buckets"]) == 24
    assert band["total"] == 2 == sum(b["total"] for b in band["buckets"])
    assert band["buckets"][-1]["counts"] == {"sign_in": 2}        # the hour in progress
    assert band["buckets"][-1]["failed"] == 2 and band["failed"] == 2
    assert band["categories"] == [{"key": "sign_in", "label": "Sign-in and sessions", "count": 2, "failed": 2}]
    assert band["sign_ins"] == {"succeeded": 0, "failed": 2, "locked": 0}
    # A name no account has is counted, never listed: people type passwords into the username box.
    assert band["top_users"] == [] and band["no_account"] == {"total": 2, "failed": 2}
    assert name not in str(band)
    ip = _listed(admin, q=name)["events"][0]["ip_address"]
    assert band["top_addresses"] == [{"ip_address": ip, "count": 2, "failed": 2}]
    assert _listed(admin, q=name, from_date=band["from"])["total"] == band["total"]
    # The catalog says which events each sign-in outcome counts; the list filtered to them agrees.
    outcomes = admin.get("/activity/catalog").json()["sign_in_outcomes"]
    for outcome, actions in outcomes.items():
        assert _listed(admin, q=name, action=actions)["total"] == band["sign_ins"][outcome], outcome


def test_the_most_active_people_are_accounts(admin, temp_user):
    for _ in range(2):
        ApiClient().login(temp_user["_username"], temp_user["_password"])
    band = _settled(admin, 2, range="24h", q=temp_user["_username"], category="sign_in")
    assert band["top_users"][0]["username"] == temp_user["_username"]
    assert band["top_users"][0]["count"] >= 2 and band["top_users"][0]["failed"] == 0
    assert band["sign_ins"]["succeeded"] >= 2
    # Only names with no account: the Events block is empty, and the people, which leave that filter
    # out, still rank the account.
    typed = _summary(admin, range="24h", q=temp_user["_username"], category="sign_in", no_account="true")
    assert typed["total"] == 0 and typed["top_users"] == band["top_users"]


@pytest.mark.parametrize("range_key,buckets", [("7d", 28), ("30d", 30)])
def test_the_longer_ranges_have_their_buckets(admin, range_key, buckets):
    name = unique("band")
    _failed_sign_in(name)
    band = _settled(admin, 1, range=range_key, user=name, tz_offset=120)
    assert len(band["buckets"]) == buckets
    assert band["buckets"][-1]["total"] == 1
    assert [b["end"] for b in band["buckets"][:-1]] == [b["start"] for b in band["buckets"][1:]]


def test_each_panel_counts_under_every_filter_but_its_own(admin):
    """The page asks for the whole band at once. Each block leaves out its own filter, so its panel keeps
    showing what could be picked next, and a filter on another dimension still narrows it."""
    name = unique("cross")
    _failed_sign_in(name)
    _failed_sign_in(name)
    whole = _settled(admin, 2, range="24h", q=name)
    none = {"succeeded": 0, "failed": 0, "locked": 0}
    # A category none of the rows is in: the category mix still shows theirs, and the sign-ins, which
    # keep the category filter, are empty like the Events block.
    band = _summary(admin, range="24h", q=name, category="files")
    assert band["total"] == 0 and band["categories"] == whole["categories"] and band["sign_ins"] == none
    # An event: the category mix and the sign-ins leave it out; the addresses keep it.
    band = _summary(admin, range="24h", q=name, action="login_success")
    assert band["total"] == 0 and band["categories"] == whole["categories"]
    assert band["sign_ins"] == whole["sign_ins"] and band["top_addresses"] == []
    # A person: the people leave it out (the two typed names are counted, never named); the rest keep it.
    band = _summary(admin, range="24h", q=name, user=unique("nobody"), user_match="exact")
    assert band["total"] == 0 and band["no_account"] == {"total": 2, "failed": 2} and band["top_users"] == []
    assert band["categories"] == [] and band["top_addresses"] == []
    # An address: the addresses leave it out; the people keep it.
    band = _summary(admin, range="24h", q=name, ip="192.0.2.1")
    assert band["total"] == 0 and band["top_addresses"] == whole["top_addresses"]
    assert band["no_account"] == {"total": 0, "failed": 0}
    # A time picked on the chart, before the rows: the Events block leaves it out and keeps its buckets;
    # every other block counts only inside it, as the list does.
    picked = (datetime.now(timezone.utc) - timedelta(hours=2)).isoformat()
    band = _summary(admin, range="24h", q=name, to_date=picked)
    assert band["total"] == 2 and len(band["buckets"]) == 24 and band["sign_ins"] == none
    assert band["categories"] == [] and band["no_account"]["total"] == 0 and band["top_addresses"] == []
    assert _listed(admin, q=name, to_date=picked)["total"] == 0


def test_a_chosen_range_and_all_time(admin):
    name = unique("band")
    _failed_sign_in(name)
    _failed_sign_in(name)
    now = datetime.now(timezone.utc)
    start = (now - timedelta(hours=3)).isoformat()
    band = _settled(admin, 2, range="custom", range_from=start, user=name, user_match="exact")
    assert band["range"] == "custom" and band["bucket_seconds"] == 3600 and len(band["buckets"]) in (3, 4)
    assert band["from"] == start and band["buckets"][0]["start"] <= band["from"]
    assert band["total"] == 2 and band["buckets"][-1]["total"] == 2
    listed = _listed(admin, user=name, user_match="exact", from_date=band["from"])
    assert listed["total"] == band["total"]
    # A chosen end before the rows: nothing after it counts, and the band ends there.
    end = (now - timedelta(hours=1)).isoformat()
    early = _summary(admin, range="custom", range_from=start, range_to=end, user=name, user_match="exact")
    assert early["total"] == 0 and early["to"] == end and early["buckets"][-1]["end"] >= end
    # All time is charted from the oldest row these filters match: this test's first sign-in.
    whole = _settled(admin, 2, range="all", user=name, user_match="exact")
    assert whole["total"] == 2 and whole["from"] == listed["events"][-1]["timestamp"]
    assert whole["buckets"][0]["start"] <= whole["from"] and len(whole["buckets"]) <= 48
    # A time picked on the chart does not move where all time starts.
    picked = _summary(admin, range="all", user=name, user_match="exact", from_date=now.isoformat())
    assert picked["buckets"][0]["start"] == whole["buckets"][0]["start"] and picked["categories"] == []


def test_a_chosen_range_that_cannot_be_charted_is_refused(admin):
    def refused(**params):
        return admin.get("/activity/summary", params={"range": "custom", **params}).status_code == 422
    assert refused()                                                   # no start
    assert refused(range_from="not a date")
    assert refused(range_from="2026-09-20T00:00:00+00:00", range_to="2026-09-19T00:00:00+00:00")
    assert refused(range_from="2026-09-20T00:00:00+00:00", range_to="soon")
    assert refused(range_from="1950-01-01")                            # more than 48 years
    assert refused(range_from="0001-01-01T00:00:00+01:00")             # off the calendar in UTC
    assert admin.get("/activity/summary", params={"range": "all", "range_to": "soon"}).status_code == 422


def test_what_is_happening_now_counts_this_session(admin):
    now = _summary(admin)["now"]
    assert set(now) == {"as_of", "sessions", "people", "temporary_credentials", "transfers_in_progress",
                        "transfers_in_flight", "transfers_waiting", "transfer_limit"}
    assert now["sessions"] >= 1 and now["people"] >= 1
    assert isinstance(now["transfer_limit"], int) and now["transfer_limit"] >= 1


def test_who_is_online_lists_people_and_credentials_in_use(admin, temp_user):
    person = ApiClient()
    person.login(temp_user["_username"], temp_user["_password"])
    tc = person.post("/auth/temp-credentials", json={"note": unique("now")}).json()
    ApiClient().login(tc["temp_username"], tc["credential"])
    try:
        r = admin.get("/activity/now")
        assert r.status_code == 200, r.text
        now = r.json()
        me = next(p for p in now["online_people"] if p["username"] == temp_user["_username"])
        assert me["sessions"] >= 1 and me["last_active"].endswith("+00:00") and me["ip_address"]
        cred = next(c for c in now["temp_in_use"] if c["name"] == tc["temp_username"])
        assert cred["owner"] == temp_user["_username"]
        assert now["online_total"] >= len(now["online_people"]) >= 2          # this admin too
        assert now["sessions"] >= 2 and now["temporary_credentials"] >= 1
        # Nothing about the credential beyond its name: not its note.
        assert set(cred) == {"name", "owner", "last_active"}
    finally:
        person.post(f"/temp-creds/{tc['temp_username']}/delete")


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
    assert temp_user_client.get("/activity/now").status_code == 403
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
