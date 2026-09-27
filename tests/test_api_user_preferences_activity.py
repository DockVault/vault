"""API: the preferences kept on the account for the Notes and Activity pages, against a running vault.

"Hide note text" used to live in the browser; it is on the account now, so it stays on after signing
out and in a new sign-in until the person turns it off. The Activity page's page size and live updates
are kept the same way. A temporary credential's session cannot change them for the account."""
import pytest

from conftest import ApiClient, unique

PATH = "/users/me/preferences"


@pytest.fixture
def person(admin):
    user = admin.create_user(role="user")
    yield user
    admin.delete_user(user["id"])


def _signed_in(user):
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


def test_hide_note_text_stays_on_after_signing_out_and_in_again(person):
    first = _signed_in(person)
    assert first.get(PATH).json().get("hide_note_text") is None          # nothing chosen yet
    r = first.put(PATH, json={"hide_note_text": "on"})
    assert r.status_code == 200 and r.json()["hide_note_text"] == "on"
    assert first.post("/api/logout").status_code == 200
    assert first.get(PATH).status_code == 401                             # that session is over
    again = _signed_in(person)
    assert again.get(PATH).json()["hide_note_text"] == "on"
    # Until the person turns it off.
    again.put(PATH, json={"hide_note_text": "off"})
    assert _signed_in(person).get(PATH).json()["hide_note_text"] == "off"


def test_the_activity_page_choices_are_kept(admin, person):
    c = _signed_in(person)
    got = c.put(PATH, json={"activity_page_size": "100", "activity_live": "off"}).json()
    assert (got["activity_page_size"], got["activity_live"]) == ("100", "off")
    got = c.put(PATH, json={"activity_page_size": "all"}).json()
    assert (got["activity_page_size"], got["activity_live"]) == ("all", "off")   # a change keeps the rest


@pytest.mark.parametrize("key,value", [
    ("hide_note_text", "yes"), ("hide_note_text", "ON"), ("activity_page_size", "1000"),
    ("activity_page_size", "10"), ("activity_live", "true"),
])
def test_a_value_the_pages_do_not_offer_is_not_kept(person, key, value):
    c = _signed_in(person)
    c.put(PATH, json={key: value})
    assert key not in c.get(PATH).json()


def test_a_temporary_credential_cannot_change_them_for_the_account(person):
    owner = _signed_in(person)
    owner.put(PATH, json={"hide_note_text": "on", "activity_live": "on"})
    tc = owner.post("/auth/temp-credentials", json={"note": unique("prefs")}).json()
    temp = ApiClient()
    temp.login(tc["temp_username"], tc["credential"])
    try:
        temp.put(PATH, json={"hide_note_text": "off", "activity_live": "off", "theme": "dark"})
        kept = owner.get(PATH).json()
        assert (kept["hide_note_text"], kept["activity_live"]) == ("on", "on")
        assert kept["theme"] == "dark"      # control: the same request reached the server and was applied
    finally:
        owner.post(f"/temp-creds/{tc['temp_username']}/delete")
