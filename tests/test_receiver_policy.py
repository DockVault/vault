"""Unit tests for app/core/receiver_policy (pure; no live deployment).

The receiver policy is the inbound twin of note_link_policy: an admin ReceiverTag is a security FLOOR
and a user creating a receiver may only TIGHTEN each axis. These tests pin the tighten-only rules and
the settings/tag validators without any DB or hashing.
"""
import importlib.util
import os

import pytest

_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "app", "core", "receiver_policy.py")
_spec = importlib.util.spec_from_file_location("receiver_policy", _PATH)
rp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(rp)

pytestmark = pytest.mark.unit


# --- settings ---------------------------------------------------------------------------------------
def test_master_switch_defaults_off():
    assert rp.public_receivers_enabled({}) is False
    assert rp.public_receivers_enabled({"public_receivers_enabled": True}) is True
    assert rp.public_receivers_enabled({"public_receivers_enabled": "yes"}) is False  # non-bool -> off


def test_user_cap_defaults_and_clamps():
    assert rp.public_receiver_user_cap({}) == rp.DEFAULT_USER_CAP
    assert rp.public_receiver_user_cap({"public_receiver_user_cap": 5}) == 5
    assert rp.public_receiver_user_cap({"public_receiver_user_cap": 0}) == rp.DEFAULT_USER_CAP
    assert rp.public_receiver_user_cap({"public_receiver_user_cap": "x"}) == rp.DEFAULT_USER_CAP


def test_validate_settings():
    rp.validate_settings({"public_receivers_enabled": True, "public_receiver_user_cap": 10})
    for bad in ({"public_receivers_enabled": "x"}, {"public_receiver_user_cap": 0},
                {"public_receiver_user_cap": True}):
        with pytest.raises(ValueError):
            rp.validate_settings(bad)


# --- tag validation ---------------------------------------------------------------------------------
def _base_tag(**over):
    t = {"name": "T", "min_token_len": 10, "require_secret": "none", "min_pin_len": 4,
         "password_min_len": 8, "kind_floor": "standard"}
    t.update(over)
    return t


def test_valid_tag_passes():
    rp.validate_tag_fields(_base_tag(max_file_bytes_cap=100, max_total_bytes_cap=1000,
                                     retention_max_days=30, retention_default_days=7))


@pytest.mark.parametrize("mut", [
    {"name": ""},
    {"min_token_len": 3},                       # below the floor
    {"require_secret": "bogus"},
    {"min_pin_len": 5},
    {"kind_floor": "bogus"},
    {"max_file_bytes_cap": 0},
    {"retention_default_days": 40, "retention_max_days": 30},   # default > max
    {"default_ttl_hours": 200, "max_ttl_hours": 100},           # default > max
])
def test_invalid_tag_rejected(mut):
    with pytest.raises(ValueError):
        rp.validate_tag_fields(_base_tag(**mut))


def test_partial_only_checks_present_keys():
    rp.validate_tag_fields({"retention_max_days": 5}, partial=True)   # nothing else required
    with pytest.raises(ValueError):
        rp.validate_tag_fields({"kind_floor": "bogus"}, partial=True)


# --- resolve_receiver_policy (tighten-only) ---------------------------------------------------------
def test_defaults_from_tag():
    tag = _base_tag(default_ttl_hours=24, max_ttl_hours=48, max_uploads_cap=10,
                    max_file_bytes_cap=1000, max_total_bytes_cap=100000,
                    retention_default_days=7, retention_max_days=30)
    p = rp.resolve_receiver_policy(tag, {})
    assert p["token_len"] == 10 and p["secret_kind"] == "none" and p["kind"] == "standard"
    assert p["ttl_hours"] == 24 and p["max_uploads"] == 10
    assert p["max_file_bytes"] == 1000 and p["max_total_bytes"] == 100000
    assert p["retention_days"] == 7


def test_token_len_may_grow_not_shrink():
    tag = _base_tag(min_token_len=12)
    assert rp.resolve_receiver_policy(tag, {"token_len": 20})["token_len"] == 20
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(tag, {"token_len": 8})


def test_secret_may_strengthen_not_weaken():
    ptag = _base_tag(require_secret="password", password_min_len=8)
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(ptag, {"secret_kind": "none"})
    otag = _base_tag(require_secret="none")
    p = rp.resolve_receiver_policy(otag, {"secret_kind": "pin", "pin": "1234"})
    assert p["secret_kind"] == "pin" and p["secret_value"] == "1234"


def test_kind_may_strengthen_not_weaken():
    # standard floor -> a user may make it confidential (stronger)...
    p = rp.resolve_receiver_policy(_base_tag(kind_floor="standard"), {"kind": "confidential"})
    assert p["kind"] == "confidential"
    # ...but a confidential floor cannot be downgraded to standard.
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(_base_tag(kind_floor="confidential"), {"kind": "standard"})
    # confidential floor with no override stays confidential.
    assert rp.resolve_receiver_policy(_base_tag(kind_floor="confidential"), {})["kind"] == "confidential"


def test_byte_caps_tighten_not_loosen():
    tag = _base_tag(max_file_bytes_cap=1000, max_total_bytes_cap=100000, max_uploads_cap=10)
    # smaller is allowed
    p = rp.resolve_receiver_policy(tag, {"max_file_bytes": 500, "max_total_bytes": 50000, "max_uploads": 3})
    assert p["max_file_bytes"] == 500 and p["max_total_bytes"] == 50000 and p["max_uploads"] == 3
    # larger than the cap is rejected
    for over in ({"max_file_bytes": 2000}, {"max_total_bytes": 200000}, {"max_uploads": 20}):
        with pytest.raises(rp.PolicyViolation):
            rp.resolve_receiver_policy(tag, over)
    # 'unlimited' (None) is refused when the tag sets a cap
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(tag, {"max_total_bytes": None})
    # ...but allowed when the tag leaves it open
    open_tag = _base_tag()
    assert rp.resolve_receiver_policy(open_tag, {"max_total_bytes": None})["max_total_bytes"] is None


def test_retention_ceiling_and_no_expiry_rule():
    tag = _base_tag(retention_max_days=30, retention_default_days=30)
    assert rp.resolve_receiver_policy(tag, {"retention_days": 7})["retention_days"] == 7
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(tag, {"retention_days": 60})           # over the ceiling
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(tag, {"retention_days": None})         # "keep forever" under a cap
    # a tag with no ceiling but a default: default applies, and 'keep forever' is allowed
    open_tag = _base_tag(retention_default_days=14)
    assert rp.resolve_receiver_policy(open_tag, {})["retention_days"] == 14
    assert rp.resolve_receiver_policy(open_tag, {"retention_days": None})["retention_days"] is None


def test_ttl_ceiling():
    tag = _base_tag(default_ttl_hours=24, max_ttl_hours=48)
    assert rp.resolve_receiver_policy(tag, {"ttl_hours": 12})["ttl_hours"] == 12
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(tag, {"ttl_hours": 96})
    with pytest.raises(rp.PolicyViolation):
        rp.resolve_receiver_policy(tag, {"ttl_hours": None})   # never-expiring under a ttl ceiling


def test_default_catalog_shape():
    names = {t["name"] for t in rp.DEFAULT_RECEIVER_TAGS}
    assert names == {"Drop box", "Confidential inbox"}
    conf = next(t for t in rp.DEFAULT_RECEIVER_TAGS if t["name"] == "Confidential inbox")
    assert conf["kind_floor"] == "confidential" and conf["require_secret"] == "password"
    assert conf["auto_enroll_new_users"] is False
    dropbox = next(t for t in rp.DEFAULT_RECEIVER_TAGS if t["name"] == "Drop box")
    assert dropbox["kind_floor"] == "standard" and dropbox["auto_enroll_new_users"] is True


def test_should_seed_only_on_fresh_deployment():
    assert rp.should_seed_default_receiver_tags(has_existing_tags=False, receivers_already_enabled=False)
    assert not rp.should_seed_default_receiver_tags(has_existing_tags=True, receivers_already_enabled=False)
    assert not rp.should_seed_default_receiver_tags(has_existing_tags=False, receivers_already_enabled=True)
