"""The Activity page's summary band, without a database: its window and buckets, how grouped counts
become the band, what the band may contain, and how long a band is reused."""
from datetime import datetime, timedelta

import pytest

from app.core import audit_catalog
from app.services import activity_summary as s

pytestmark = pytest.mark.unit

NOW = datetime(2026, 9, 27, 18, 40, 12, 345678)       # naive UTC, as the log stores time


@pytest.mark.parametrize("range_key,buckets,size", [("24h", 24, 3600), ("7d", 28, 21600), ("30d", 30, 86400)])
def test_a_window_has_its_buckets_and_the_last_holds_now(range_key, buckets, size):
    w = s.window(range_key, NOW)
    assert (w.buckets, w.size, w.end) == (buckets, size, NOW)
    last = w.bucket_start(buckets - 1)
    assert last <= NOW < last + timedelta(seconds=size)
    assert w.bucket_of(NOW) == buckets - 1
    assert w.bucket_of(w.start) == 0
    assert w.bucket_of(w.start - timedelta(microseconds=1)) is None


def test_days_start_at_the_viewers_midnight():
    # Two hours east of UTC: the viewer's day starts at 22:00 UTC the day before.
    w = s.window("30d", NOW, tz_offset_minutes=120)
    assert w.bucket_start(29) == datetime(2026, 9, 26, 22, 0, 0)
    west = s.window("30d", NOW, tz_offset_minutes=-300)
    assert west.bucket_start(29) == datetime(2026, 9, 27, 5, 0, 0)


def test_quarter_days_start_on_the_viewers_clock():
    w = s.window("7d", NOW, tz_offset_minutes=-300)     # 13:40 for the viewer
    assert w.bucket_start(27) == datetime(2026, 9, 27, 17, 0, 0)   # 12:00 for the viewer


def test_hours_follow_a_half_hour_zone():
    w = s.window("24h", NOW, tz_offset_minutes=330)     # 00:10 for the viewer
    assert w.bucket_start(23) == datetime(2026, 9, 27, 18, 30, 0)


def test_an_unknown_range_is_the_default_and_an_absurd_clock_is_clamped():
    assert s.window("90d", NOW).buckets == 24
    assert s.window("24h", NOW, 99999).offset == 14 * 3600


@pytest.mark.parametrize("span, size, buckets", [
    (timedelta(hours=5, minutes=30), 3600, 6),            # 12:30-18:00 in hours: 12, 13, ... 17
    (timedelta(days=3), 6 * 3600, 13),                    # more than 48 hours: six-hour blocks
    (timedelta(days=20), 86400, 21),                      # more than 12 days: days
    (timedelta(days=200), 7 * 86400, 29),                 # more than 48 days: weeks
    (timedelta(days=1200), 30 * 86400, 41),               # more than 48 weeks: 30-day blocks
])
def test_a_chosen_range_takes_the_smallest_bucket_that_fits(span, size, buckets):
    start = datetime(2026, 3, 2, 12, 30, 0)
    w = s.custom_window(start, start + span)
    assert (w.size, w.buckets) == (size, buckets)
    assert w.buckets <= s.MAX_BUCKETS
    assert w.start <= start < w.start + timedelta(seconds=size)       # the first bucket holds the start
    assert w.bucket_of(start + span - timedelta(microseconds=1)) == w.buckets - 1


def test_a_chosen_range_starts_on_the_viewers_hour_and_midnight():
    start = datetime(2026, 3, 2, 12, 40, 0)                            # 14:40 two hours east of UTC
    hours = s.custom_window(start, start + timedelta(hours=6), tz_offset_minutes=120)
    assert hours.start == datetime(2026, 3, 2, 12, 0, 0)              # 14:00 for the viewer
    days = s.custom_window(start, start + timedelta(days=20), tz_offset_minutes=120)
    assert days.start == datetime(2026, 3, 1, 22, 0, 0)               # the viewer's midnight, 2 March
    weeks = s.custom_window(start, start + timedelta(days=200), tz_offset_minutes=120)
    assert weeks.start == days.start                                   # weeks count from that midnight


def test_an_empty_or_endless_range_has_no_window():
    start = datetime(2026, 3, 2, 12, 0, 0)
    assert s.custom_window(start, start) is None
    assert s.custom_window(start, start - timedelta(hours=1)) is None
    assert s.custom_window(datetime(1900, 1, 1), NOW) is None          # beyond 48 years
    # Refused before any date is worked out: the first day of the calendar, an hour west of UTC, is
    # a day no datetime can hold.
    assert s.custom_window(datetime(1, 1, 1), NOW, tz_offset_minutes=-60) is None


def test_each_bucket_ends_where_the_next_starts():
    for w in (s.window("7d", NOW, tz_offset_minutes=180),
              s.custom_window(datetime(2026, 3, 2, 12, 30), datetime(2026, 3, 9, 1, 0))):
        assert [w.bucket_end(i) for i in range(w.buckets - 1)] == [w.bucket_start(i + 1) for i in range(w.buckets - 1)]
        assert w.bucket_start(w.buckets - 1) < w.end <= w.bucket_end(w.buckets - 1)
        assert w.bucket_of(w.bucket_end(w.buckets - 1)) is None


def test_all_time_starts_at_the_oldest_row_and_is_always_charted():
    w = s.all_time(datetime(2026, 9, 1, 8, 15), NOW, tz_offset_minutes=120)
    assert (w.size, w.start) == (86400, datetime(2026, 8, 31, 22, 0))  # the viewer's midnight, 1 September
    assert w.bucket_of(datetime(2026, 9, 1, 8, 15)) == 0 and w.end == NOW
    # No row: the hour before now. A row dated decades ago still gives a chart, cut to the longest one.
    assert s.all_time(None, NOW).bucket_of(NOW - timedelta(minutes=59)) is not None
    ancient = s.all_time(datetime(1970, 1, 1), NOW)
    assert ancient is not None and ancient.buckets <= s.MAX_BUCKETS and ancient.end == NOW


def test_each_block_counts_under_every_filter_but_its_own():
    every = dict(categories=["files"], channels=["web"], statuses=["failed"], actions=["login_failure"],
                 username="maria", user_exact=True, no_account=True, ip="203.0.113.9", text="x",
                 temp_credential_id="id", temp_credential="temp_", vault_id="v",
                 start=datetime(2026, 9, 1), end=datetime(2026, 9, 2))
    left_out = {block: sorted(set(every) - set(kept)) for block, kept in s.block_filters(every).items()}
    assert left_out == {
        "events": ["end", "start"],                              # the time picked on the chart
        "categories": ["actions", "categories"],
        "sign_ins": ["actions"],
        "people": ["no_account", "user_exact", "username"],
        "addresses": ["ip"],
    }


def test_filters_spelled_differently_are_the_same_filters():
    spelled = s.signature({"categories": ["b", "a"], "ip": None, "no_account": False, "text": ""})
    assert spelled == s.signature({"categories": ["a", "b"]})
    assert s.signature({"categories": ["a"]}) != s.signature({"categories": ["a"], "no_account": True})
    assert s.signature({"start": datetime(2026, 9, 1)}) != s.signature({"start": datetime(2026, 9, 2)})


def _grouped(*rows):
    return list(rows)


def test_grouped_counts_become_buckets_categories_and_sign_in_outcomes():
    # (bucket, stored action, rows, failed, under no account, failed under no account)
    w = s.window("24h", NOW)
    band = s.shape(w, _grouped(
        (23, "login_success", 4, 0, 0, 0), (23, "login_failure", 2, 2, 2, 2),
        (22, "second_factor_failed", 1, 1, 0, 0), (0, "account_auto_locked", 1, 0, 0, 0),
        (23, "file_uploaded", 3, 0, 0, 0), (23, "file_upload", 2, 0, 0, 0),
        (10, "a_name_no_release_wrote", 5, 0, 0, 0),
    ), [("maria", 7, 1)], [("203.0.113.9", 6, 2)])
    assert (band["total"], band["failed"]) == (18, 3)
    assert band["buckets"][23]["counts"] == {"sign_in": 6, "files": 5}
    assert (band["buckets"][23]["total"], band["buckets"][23]["failed"]) == (11, 2)
    assert band["buckets"][10]["counts"] == {"legacy": 5}
    assert band["buckets"][5] == {"start": band["buckets"][5]["start"], "end": band["buckets"][6]["start"],
                                  "total": 0, "failed": 0, "counts": {}}
    assert band["sign_ins"] == {"succeeded": 4, "failed": 3, "locked": 1}
    assert [c["key"] for c in band["categories"]] == ["sign_in", "files", "legacy"]   # catalog order
    assert band["categories"][0] == {"key": "sign_in", "label": "Sign-in and sessions", "count": 8, "failed": 3}
    assert band["categories"][-1]["label"] == audit_catalog.LEGACY_LABEL
    # A name no account had is counted, never named.
    assert band["no_account"] == {"total": 2, "failed": 2}
    assert band["top_users"] == [{"username": "maria", "count": 7, "failed": 1}]
    assert band["top_addresses"] == [{"ip_address": "203.0.113.9", "count": 6, "failed": 2}]


def test_a_block_under_other_filters_is_counted_from_its_own_rows():
    # A category filter narrowed the Events block to files; the category mix, the sign-ins and the
    # people were counted without it (their rows carry no bucket).
    w = s.window("24h", NOW)
    band = s.shape(w, [(23, "file_uploaded", 3, 0, 0, 0)], [], [], apart={
        "categories": [(None, "file_uploaded", 3, 0, 0, 0), (None, "login_failure", 2, 2, 2, 2)],
        "sign_ins": [(None, "login_failure", 2, 2, 2, 2)],
        "people": [(None, "file_uploaded", 3, 0, 0, 0), (None, "login_failure", 2, 2, 2, 2)],
    })
    assert (band["total"], band["failed"], band["buckets"][23]["counts"]) == (3, 0, {"files": 3})
    assert [(c["key"], c["count"]) for c in band["categories"]] == [("sign_in", 2), ("files", 3)]
    assert band["sign_ins"]["failed"] == 2 and band["no_account"] == {"total": 2, "failed": 2}
    # A block not named in it is counted from the Events block's rows.
    alone = s.shape(w, [(23, "login_failure", 2, 2, 2, 2)], [], [], apart={"categories": []})
    assert alone["categories"] == [] and alone["sign_ins"]["failed"] == 2 and alone["no_account"]["total"] == 2


def test_a_chosen_start_is_the_start_the_band_states():
    w = s.custom_window(datetime(2026, 3, 2, 12, 30), datetime(2026, 3, 2, 18, 0))
    band = s.shape(w, [], [], [], since=datetime(2026, 3, 2, 12, 30))
    assert band["from"] == "2026-03-02T12:30:00+00:00" and band["buckets"][0]["start"] == "2026-03-02T12:00:00+00:00"


def test_a_count_outside_the_window_is_left_out():
    w = s.window("24h", NOW)
    band = s.shape(w, [(None, "login_success", 3, 0, 0, 0), (24, "login_success", 2, 0, 0, 0),
                       (-1, "login_success", 1, 0, 0, 0)], [], [])
    assert band["total"] == 0 and band["sign_ins"]["succeeded"] == 0


def test_bucket_times_are_utc_and_the_window_is_stated():
    w = s.window("24h", NOW)
    band = s.shape(w, [], [], [])
    assert band["from"] == "2026-09-26T19:00:00+00:00"
    assert band["to"].startswith("2026-09-27T18:40:12") and band["to"].endswith("+00:00")
    assert band["buckets"][0]["start"] == band["from"]
    assert band["bucket_seconds"] == 3600


def test_the_band_holds_counts_names_of_people_and_addresses_and_nothing_else():
    # No vault, file or folder name, no details: only what these keys hold.
    band = s.shape(s.window("24h", NOW), [(1, "file_uploaded", 1, 0, 0, 0)], [("maria", 1, 0)],
                   [("203.0.113.9", 1, 0)])
    assert set(band) == {"from", "to", "bucket_seconds", "buckets", "total", "failed", "categories",
                         "sign_ins", "top_users", "no_account", "top_addresses"}
    assert set(band["buckets"][1]) == {"start", "end", "total", "failed", "counts"}
    assert set(band["top_users"][0]) == {"username", "count", "failed"}
    assert set(band["top_addresses"][0]) == {"ip_address", "count", "failed"}
    assert set(band["no_account"]) == {"total", "failed"}


def test_every_sign_in_outcome_names_an_action_the_catalog_files_under_sign_in():
    for name in s.SIGN_IN_OUTCOMES:
        assert audit_catalog.lookup(name).category == "sign_in", name


@pytest.fixture
def clock(monkeypatch):
    now = {"t": 1000.0}
    monkeypatch.setattr(s.time, "monotonic", lambda: now["t"])
    monkeypatch.setattr(s, "_cache", s.OrderedDict())
    return now


def test_a_band_is_reused_for_its_range_seconds_then_computed_again(clock):
    calls = []

    def compute():
        calls.append(1)
        return {"n": len(calls)}

    assert s.cached(("k",), "30d", compute) == ({"n": 1}, 0.0)
    clock["t"] += s.CACHE_SECONDS["30d"] - 1
    assert s.cached(("k",), "30d", compute)[0] == {"n": 1}
    clock["t"] += 2
    assert s.cached(("k",), "30d", compute)[0] == {"n": 2}


def test_different_filters_are_different_bands(clock):
    assert s.cached(("a",), "24h", lambda: 1)[0] == 1
    assert s.cached(("b",), "24h", lambda: 2)[0] == 2
    assert s.cached(("a",), "24h", lambda: 3)[0] == 1


def test_only_so_many_bands_are_kept(clock):
    for i in range(s.CACHE_ENTRIES + 3):
        s.cached((i,), "30d", lambda i=i: i)
    assert len(s._cache) == s.CACHE_ENTRIES
    assert s.cached((0,), "30d", lambda: "again")[0] == "again"      # the oldest went first
