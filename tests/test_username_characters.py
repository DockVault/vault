"""A new username may not carry control, format or other invisible characters (Unicode category C),
offline.

An escape byte in a username acts on the terminal of whoever prints it (dockvault.py accounts, a log
viewer), and an invisible one (a zero-width space, a right-to-left override) makes two usernames look
alike. Account creation, invitations and self-signup share the one rule."""
import pytest
from pydantic import ValidationError

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402

pytestmark = pytest.mark.unit

BAD = [
    "ev" + chr(27) + "[31mil",     # ESC: a terminal escape sequence (Cc)
    "tab" + chr(9) + "name",        # a tab (Cc)
    "bell" + chr(7) + "x",          # BEL (Cc)
    "c1" + chr(0x9b) + "x",         # a C1 control (Cc)
    "zero" + chr(0x200b) + "width",  # zero-width space (Cf)
    "rtl" + chr(0x202e) + "gpj",    # right-to-left override (Cf)
    "pua" + chr(0xe000) + "x",      # private use (Co)
]


def _create(model, username):
    fields = {"username": username}
    if model is not api.InviteCreate:
        fields["password"] = "LongEnough-1!"
    return model(**fields)


@pytest.mark.parametrize("model", [api.UserCreate, api.InviteCreate, api.SignupRequest])
@pytest.mark.parametrize("username", BAD, ids=[f"U+{ord(next(c for c in b if not c.isalnum() and c not in '[')):04X}"
                                              for b in BAD])
def test_a_username_with_an_invisible_or_control_character_is_refused(model, username):
    with pytest.raises(ValidationError) as refused:
        _create(model, username)
    assert "control or invisible" in str(refused.value)


@pytest.mark.parametrize("username", ["alice", "José-Müller", "ænne_ø.1", "名前テスト", "o'brien", "a b c"])
def test_ordinary_names_in_any_script_are_still_accepted(username):
    assert _create(api.UserCreate, username).username == username
