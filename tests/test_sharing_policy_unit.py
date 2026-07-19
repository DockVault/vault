"""Pure Sharing policy resolver/evaluator (app/core/sharing_policy.py).

Pins the fail-closed defaults + the create-allowlist evaluation independent of any running instance
(the HTTP suite can't cheaply reach the feature-off / not-allowed states on a persistent deployment).
No app import beyond the pure module, no running vault — mirrors test_temp_passcode_policy_unit.py.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import sharing_policy as sp  # noqa: E402


def test_master_switch_fail_closed_default_and_strict_bool():
    assert sp.sharing_enabled({}) is False            # unset -> OFF
    assert sp.sharing_enabled(None) is False
    assert sp.sharing_enabled({"sharing_enabled": True}) is True
    # a truthy NON-bool stored value must NOT turn sharing on (fail closed, strict `is True`)
    for bad in ("true", "false", 1, "on", [1]):
        assert sp.sharing_enabled({"sharing_enabled": bad}) is False


def test_audiences_normalize_drops_unknown_and_dedupes_order_stable():
    assert sp.normalize_audiences(["users", "departments", "anyone_internal"]) == \
        ["users", "departments", "anyone_internal"]
    # unknown token dropped; duplicates collapsed; original order kept
    assert sp.normalize_audiences(["users", "bogus", "users", "anyone_internal"]) == \
        ["users", "anyone_internal"]
    # non-list / empty -> [] (fail closed: no audience silently widened)
    assert sp.normalize_audiences(None) == []
    assert sp.normalize_audiences("users") == []
    assert sp.normalize_audiences([]) == []


def _tag(**over):
    base = {
        "is_active": True,
        "blocked_user_ids": [],
        "allowed_user_ids": [],
        "allowed_department_ids": [],
        "auto_enroll_new_users": False,
    }
    base.update(over)
    return base


def test_create_allowlist_fail_closed_and_precedence():
    # Fresh tag (empty lists, no auto-enroll) grants NO ONE -> fail closed.
    assert sp.user_can_create_with_tag(_tag(), "u1", []) is False
    # Explicit user allow.
    assert sp.user_can_create_with_tag(_tag(allowed_user_ids=["u1"]), "u1", []) is True
    # Department allow (any of the user's groups in the allowed departments).
    assert sp.user_can_create_with_tag(_tag(allowed_department_ids=["g1"]), "u1", ["g1", "g2"]) is True
    assert sp.user_can_create_with_tag(_tag(allowed_department_ids=["g1"]), "u1", ["g9"]) is False
    # Auto-enroll allows everyone not blocked.
    assert sp.user_can_create_with_tag(_tag(auto_enroll_new_users=True), "u1", []) is True
    # Blocklist WINS over allow-user, allowed-dept, and auto-enroll.
    assert sp.user_can_create_with_tag(
        _tag(blocked_user_ids=["u1"], allowed_user_ids=["u1"]), "u1", []) is False
    assert sp.user_can_create_with_tag(
        _tag(blocked_user_ids=["u1"], allowed_department_ids=["g1"]), "u1", ["g1"]) is False
    assert sp.user_can_create_with_tag(
        _tag(blocked_user_ids=["u1"], auto_enroll_new_users=True), "u1", []) is False
    # Inactive tag is never creatable, even with auto-enroll.
    assert sp.user_can_create_with_tag(_tag(is_active=False, auto_enroll_new_users=True), "u1", []) is False


def test_create_allowlist_tolerates_uuid_and_str_ids_and_bad_fields():
    import uuid
    uid = uuid.uuid4()
    # ids compared as strings regardless of whether they arrive as UUID or str
    assert sp.user_can_create_with_tag(_tag(allowed_user_ids=[str(uid)]), uid, []) is True
    assert sp.user_can_create_with_tag(_tag(allowed_user_ids=[uid]), str(uid), []) is True
    # a malformed (non-list) allowlist field fails CLOSED (matches nothing), never raises
    assert sp.user_can_create_with_tag(_tag(allowed_user_ids="u1"), "u1", []) is False
    assert sp.user_can_create_with_tag(_tag(blocked_user_ids="u1", auto_enroll_new_users=True), "u1", []) is True


def test_effective_limits_clamp_defaults_within_caps_and_lifetime():
    eff = sp.tag_effective_limits({
        "max_lifetime_minutes": 100, "default_lifetime_minutes": 200,   # default above ceiling -> clamp to 100
        "max_recipients_cap": 5, "max_recipients_default": 9,           # default above cap -> clamp to 5
        "max_downloads_cap": None, "max_downloads_default": 3,          # cap None (unlimited) -> default stands
    })
    assert eff["max_lifetime_minutes"] == 100
    assert eff["default_lifetime_minutes"] == 100
    assert eff["max_recipients_cap"] == 5
    assert eff["max_recipients_default"] == 5
    assert eff["max_downloads_cap"] is None
    assert eff["max_downloads_default"] == 3
    # A NULL default under a cap -> clamped to the cap (never 'unlimited' when a cap exists).
    eff2 = sp.tag_effective_limits({"max_lifetime_minutes": 10, "max_recipients_cap": 4,
                                    "max_recipients_default": None})
    assert eff2["max_recipients_default"] == 4
    # Lifetime floored at MIN_LIFETIME_MINUTES (>=1) when unset/zero.
    eff3 = sp.tag_effective_limits({"max_lifetime_minutes": 0, "default_lifetime_minutes": 0})
    assert eff3["max_lifetime_minutes"] >= sp.MIN_LIFETIME_MINUTES
    assert eff3["default_lifetime_minutes"] >= 1
