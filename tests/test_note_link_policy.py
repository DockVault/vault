"""Offline unit tests for the public-note-link policy helpers (no app boot / DB / network)."""
import pytest

from app.core import note_link_policy as nlp

pytestmark = pytest.mark.unit


def _valid_tag():
    return {"name": "T", "min_token_len": 10, "require_secret": "none", "min_pin_len": 4,
            "password_min_len": 8, "password_require_alnum": False,
            "default_ttl_hours": None, "max_ttl_hours": None, "max_uses_cap": None}


def test_valid_tag_passes():
    nlp.validate_tag_fields(_valid_tag())


@pytest.mark.parametrize("mut", [
    {"name": ""},                       # empty name
    {"min_token_len": 5},               # below the 6 floor
    {"min_token_len": 999},             # above max
    {"require_secret": "otp"},          # not a known kind
    {"min_pin_len": 5},                 # not in {4,6,8}
    {"password_min_len": 0},            # too small
    {"default_ttl_hours": 48, "max_ttl_hours": 24},  # default exceeds max
    {"max_uses_cap": 0},                # non-positive cap
])
def test_invalid_tag_rejected(mut):
    t = _valid_tag(); t.update(mut)
    with pytest.raises(ValueError):
        nlp.validate_tag_fields(t)


def test_partial_only_checks_present_keys():
    # A PATCH that only bumps password length must not trip on omitted required keys.
    nlp.validate_tag_fields({"password_min_len": 12}, partial=True)
    with pytest.raises(ValueError):
        nlp.validate_tag_fields({"min_token_len": 3}, partial=True)


def test_settings_validation():
    nlp.validate_settings({"public_note_links_enabled": True, "public_note_link_user_cap": 50})
    nlp.validate_settings({})  # absent keys ok
    for bad in ({"public_note_links_enabled": "yes"}, {"public_note_link_user_cap": 0},
                {"public_note_link_user_cap": True}, {"public_note_link_user_cap": nlp.MAX_USER_CAP + 1}):
        with pytest.raises(ValueError):
            nlp.validate_settings(bad)


def test_user_cap_reader_defaults_and_clamps():
    assert nlp.public_note_link_user_cap({}) == nlp.DEFAULT_USER_CAP
    assert nlp.public_note_link_user_cap({"public_note_link_user_cap": 7}) == 7
    assert nlp.public_note_link_user_cap({"public_note_link_user_cap": 0}) == nlp.DEFAULT_USER_CAP
    assert nlp.public_note_link_user_cap({"public_note_link_user_cap": "x"}) == nlp.DEFAULT_USER_CAP
    assert nlp.public_note_links_enabled({}) is False
    assert nlp.public_note_links_enabled({"public_note_links_enabled": True}) is True


def test_default_catalog_shape():
    names = [t["name"] for t in nlp.DEFAULT_NOTE_LINK_TAGS]
    assert names == ["Open", "Restricted", "Confidential"]
    conf = next(t for t in nlp.DEFAULT_NOTE_LINK_TAGS if t["name"] == "Confidential")
    assert conf["require_secret"] == "password" and conf["max_uses_cap"] == 1
    opent = next(t for t in nlp.DEFAULT_NOTE_LINK_TAGS if t["name"] == "Open")
    assert opent["min_token_len"] == 6 and opent["require_secret"] == "none"
    # Every seeded tag must itself pass validation.
    for t in nlp.DEFAULT_NOTE_LINK_TAGS:
        nlp.validate_tag_fields(dict(t))


def test_should_seed_only_on_fresh_deployment():
    assert nlp.should_seed_default_note_link_tags(False, False) is True
    assert nlp.should_seed_default_note_link_tags(True, False) is False    # tags exist
    assert nlp.should_seed_default_note_link_tags(False, True) is False    # already enabled
