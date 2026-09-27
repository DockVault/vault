"""The preferences kept on the account for the Notes and Activity pages: which values are kept, and
which a temporary credential's session may not change. The server is the only place they are kept, so
a value it would not keep here is one the page never gets back."""
import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    return S


@pytest.mark.parametrize("key,values", [
    ("hide_note_text", ("on", "off")),
    ("activity_page_size", ("25", "50", "100", "all")),
    ("activity_live", ("on", "off")),
    ("activity_range", ("24h", "7d", "30d", "all")),
])
def test_the_values_the_pages_offer_are_kept(key, values):
    S = _api()
    for v in values:
        assert S._sanitize_preferences({key: v}) == {key: v}


@pytest.mark.parametrize("key,value", [
    ("hide_note_text", True), ("hide_note_text", "1"), ("activity_page_size", 50),
    ("activity_page_size", "200"), ("activity_live", "yes"),
])
def test_anything_else_is_dropped(key, value):
    assert _api()._sanitize_preferences({key: value}) == {}


def test_the_update_model_accepts_each_key():
    S = _api()
    body = S.PreferencesUpdate(hide_note_text="on", activity_page_size="all", activity_live="off")
    assert S._sanitize_preferences(body.model_dump(exclude_none=True)) == {
        "hide_note_text": "on", "activity_page_size": "all", "activity_live": "off"}


def test_a_temporary_session_cannot_change_the_notes_or_activity_choices():
    S = _api()
    assert S._PREF_NOT_FOR_TEMP_SESSIONS == {"hide_note_text", "activity_page_size", "activity_live",
                                             "activity_range"}
    assert S._PREF_NOT_FOR_TEMP_SESSIONS <= set(S._PREF_ALLOWED)
