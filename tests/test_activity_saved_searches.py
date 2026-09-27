"""What a saved search on the Activity page may hold, and its name, without a database.

A stored search is loaded back into the Events filters, so it may hold only what the Events API takes:
the listed keys, each with a value the page offers. Anything else is refused with a message naming it."""
from datetime import datetime
from types import SimpleNamespace

import pytest

from app.services import activity_saved_searches as rules

pytestmark = pytest.mark.unit


def test_a_full_filter_set_is_kept_as_given():
    filters = {"category": ["sign_in", "security"], "channel": ["web", "sftp"], "status": ["failed"],
               "user": "maria", "ip": "203.0.113.0/24", "q": "wrong password",
               "temp_credential": "temp_contractor", "range": "7d"}
    assert rules.clean_filters(filters) == filters


def test_fixed_dates_are_kept():
    got = rules.clean_filters({"from_date": "2026-09-01", "to_date": "2026-09-27T12:00:00Z"})
    assert got == {"from_date": "2026-09-01", "to_date": "2026-09-27T12:00:00Z"}


def test_empty_values_are_left_out_and_text_is_trimmed():
    got = rules.clean_filters({"category": [], "user": "  maria  ", "ip": "", "q": None, "status": "failed"})
    assert got == {"user": "maria", "status": ["failed"]}


def test_repeated_choices_are_kept_once():
    assert rules.clean_filters({"channel": ["web", "web", "sftp"]}) == {"channel": ["web", "sftp"]}


@pytest.mark.parametrize("filters,says", [
    ({"vault": "x"}, "cannot hold vault"),
    ({"limit": 100}, "cannot hold limit"),
    ({"category": ["files", "cats"]}, "does not offer: cats"),
    ({"channel": ["telnet"]}, "does not offer: telnet"),
    ({"status": ["maybe"]}, "does not offer: maybe"),
    ({"category": "files, security"}, "does not offer"),
    ({"category": [1, 2]}, "list of names"),
    ({"range": "90d"}, "must be one of 24h, 7d, 30d"),
    ({"user": ["maria"]}, "user must be text"),
    ({"q": "x" * 129}, "at most 128 characters"),
    ({"range": "24h", "from_date": "2026-09-01"}, "either a range or dates"),
])
def test_anything_else_is_refused_with_a_message_naming_it(filters, says):
    with pytest.raises(rules.InvalidSearch) as err:
        rules.clean_filters(filters)
    assert says in str(err.value)


def test_filters_must_be_an_object():
    with pytest.raises(rules.InvalidSearch):
        rules.clean_filters(["category", "files"])
    assert rules.clean_filters(None) == {}


def test_every_choice_the_events_api_takes_can_be_saved():
    from app.core import audit_catalog
    from app.services import activity_events as ev
    assert set(rules._known("category")) == {k for k, _ in audit_catalog.CATEGORIES} | {ev.LEGACY_CATEGORY}
    assert set(rules._known("channel")) == set(ev.CHANNEL_CHOICES)
    assert set(rules._known("status")) == set(ev.STATUS_GROUPS)


@pytest.mark.parametrize("name,expected", [
    ("Failed sign-ins", "Failed sign-ins"),
    ("  Maria   at   night ", "Maria at night"),
    ("x" * 80, "x" * 80),
])
def test_a_name_is_trimmed_and_kept(name, expected):
    assert rules.clean_name(name) == expected


@pytest.mark.parametrize("name,says", [
    ("", "Give the search a name."),
    ("   ", "Give the search a name."),
    (None, "Give the search a name."),
    ("x" * 81, "at most 80 characters"),
    ("tab​hidden", "control characters"),
    ("bell\x07", "control characters"),
])
def test_a_name_that_cannot_be_used_is_refused(name, says):
    with pytest.raises(rules.InvalidSearch) as err:
        rules.clean_name(name)
    assert says in str(err.value)


def test_a_saved_search_is_returned_with_utc_times():
    row = SimpleNamespace(id="1", name="n", filters={"status": ["failed"]}, is_default=True,
                          created_at=datetime(2026, 9, 27, 8, 0, 0), updated_at=datetime(2026, 9, 27, 9, 0, 0))
    assert rules.view(row) == {"id": "1", "name": "n", "filters": {"status": ["failed"]}, "is_default": True,
                               "created_at": "2026-09-27T08:00:00+00:00",
                               "updated_at": "2026-09-27T09:00:00+00:00"}
