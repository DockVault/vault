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
    assert nlp.public_note_links_enabled({}) is True   # unset -> ON (default)
    assert nlp.public_note_links_enabled({"public_note_links_enabled": True}) is True
    assert nlp.public_note_links_enabled({"public_note_links_enabled": False}) is False  # explicit off


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


# --- resolve_link_policy: the "tighten only" chokepoint -------------------------------------------
def _floor(**over):
    t = {"min_token_len": 10, "require_secret": "none", "min_pin_len": 4, "password_min_len": 8,
         "password_require_alnum": False, "default_ttl_hours": None, "max_ttl_hours": None,
         "max_uses_cap": None}
    t.update(over)
    return t


def test_resolve_defaults_from_tag():
    p = nlp.resolve_link_policy(_floor(min_token_len=12, default_ttl_hours=48, max_ttl_hours=168))
    assert p == {"token_len": 12, "secret_kind": "none", "secret_value": None,
                 "ttl_hours": 48, "max_uses": None}


def test_resolve_token_len_may_grow_not_shrink():
    assert nlp.resolve_link_policy(_floor(min_token_len=10), {"token_len": 20})["token_len"] == 20
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(min_token_len=10), {"token_len": 8})


def test_resolve_secret_may_strengthen_not_weaken():
    # floor none -> user adds a pin
    p = nlp.resolve_link_policy(_floor(require_secret="none"), {"secret_kind": "pin", "pin": "1234"})
    assert p["secret_kind"] == "pin" and p["secret_value"] == "1234"
    # floor password -> user tries to drop to none/pin -> rejected
    for weak in ("none", "pin"):
        with pytest.raises(nlp.PolicyViolation):
            nlp.resolve_link_policy(_floor(require_secret="password"),
                                    {"secret_kind": weak, "password": "abcd1234"})


def test_resolve_pin_rules():
    # PIN must be digits, an allowed length, and >= the tag minimum.
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(require_secret="pin"), {"pin": "12a4"})       # non-digit
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(require_secret="pin"), {"pin": "12345"})      # len 5 not allowed
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(require_secret="pin", min_pin_len=6), {"pin": "1234"})  # below tag min
    p = nlp.resolve_link_policy(_floor(require_secret="pin", min_pin_len=6), {"pin": "123456"})
    assert p["secret_value"] == "123456"


def test_resolve_password_rules():
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(require_secret="password", password_min_len=8), {"password": "short"})
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(require_secret="password", password_require_alnum=True),
                                {"password": "onlyletters"})   # needs a digit too
    p = nlp.resolve_link_policy(_floor(require_secret="password", password_require_alnum=True),
                                {"password": "letters123"})
    assert p["secret_kind"] == "password" and p["secret_value"] == "letters123"


def test_resolve_ttl_ceiling_and_no_expiry_rule():
    # user may shorten within the ceiling
    assert nlp.resolve_link_policy(_floor(max_ttl_hours=168), {"ttl_hours": 24})["ttl_hours"] == 24
    # user may not exceed the ceiling
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(max_ttl_hours=168), {"ttl_hours": 200})
    # "no expiry" only when the tag sets no ceiling
    assert nlp.resolve_link_policy(_floor(max_ttl_hours=None), {"ttl_hours": None})["ttl_hours"] is None
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(max_ttl_hours=168), {"ttl_hours": None})
    # a ceiling with no default -> default to the ceiling, not "no expiry"
    assert nlp.resolve_link_policy(_floor(max_ttl_hours=72))["ttl_hours"] == 72


def test_resolve_max_uses_cap_and_unlimited_rule():
    assert nlp.resolve_link_policy(_floor(max_uses_cap=10), {"max_uses": 3})["max_uses"] == 3
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(max_uses_cap=10), {"max_uses": 50})       # over cap
    with pytest.raises(nlp.PolicyViolation):
        nlp.resolve_link_policy(_floor(max_uses_cap=1), {"max_uses": None})      # unlimited not allowed
    # capped tag with no override -> default to the cap
    assert nlp.resolve_link_policy(_floor(max_uses_cap=1))["max_uses"] == 1
    # uncapped tag -> unlimited default
    assert nlp.resolve_link_policy(_floor(max_uses_cap=None))["max_uses"] is None


def test_resolve_confidential_seed_end_to_end():
    conf = next(t for t in nlp.DEFAULT_NOTE_LINK_TAGS if t["name"] == "Confidential")
    p = nlp.resolve_link_policy(conf, {"password": "hunter22"})
    assert p["secret_kind"] == "password" and p["max_uses"] == 1 and p["ttl_hours"] == 24
    assert p["token_len"] == 20
