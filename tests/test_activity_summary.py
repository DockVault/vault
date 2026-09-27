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


def _grouped(*rows):
    return list(rows)


def test_grouped_counts_become_buckets_categories_and_sign_in_outcomes():
    w = s.window("24h", NOW)
    band = s.shape(w, _grouped(
        (23, "login_success", 4), (23, "login_failure", 2), (22, "second_factor_failed", 1),
        (0, "account_auto_locked", 1), (23, "file_uploaded", 3), (23, "file_upload", 2),
        (10, "a_name_no_release_wrote", 5),
    ), [("maria", 7), ("203.0.113.9-typed-name", 2)], [("203.0.113.9", 6)])
    assert band["total"] == 18
    assert band["buckets"][23]["counts"] == {"sign_in": 6, "files": 5}
    assert band["buckets"][23]["total"] == 11
    assert band["buckets"][10]["counts"] == {"legacy": 5}
    assert band["buckets"][5] == {"start": band["buckets"][5]["start"], "total": 0, "counts": {}}
    assert band["sign_ins"] == {"succeeded": 4, "failed": 3, "locked": 1}
    assert [c["key"] for c in band["categories"]] == ["sign_in", "files", "legacy"]   # catalog order
    assert band["categories"][0] == {"key": "sign_in", "label": "Sign-in and sessions", "count": 8}
    assert band["categories"][-1]["label"] == audit_catalog.LEGACY_LABEL
    assert band["top_users"][0] == {"username": "maria", "count": 7}
    assert band["top_addresses"] == [{"ip_address": "203.0.113.9", "count": 6}]


def test_a_count_outside_the_window_is_left_out():
    w = s.window("24h", NOW)
    band = s.shape(w, [(None, "login_success", 3), (24, "login_success", 2), (-1, "login_success", 1)], [], [])
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
    band = s.shape(s.window("24h", NOW), [(1, "file_uploaded", 1)], [("maria", 1)], [("203.0.113.9", 1)])
    assert set(band) == {"from", "to", "bucket_seconds", "buckets", "total", "categories", "sign_ins",
                         "top_users", "top_addresses"}
    assert set(band["buckets"][1]) == {"start", "total", "counts"}
    assert set(band["top_users"][0]) == {"username", "count"}
    assert set(band["top_addresses"][0]) == {"ip_address", "count"}


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
