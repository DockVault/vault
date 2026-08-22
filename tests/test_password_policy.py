"""Pure unit tests for app/core/password_policy.py (no app/DB deps — imported by path)."""
import importlib.util
import pathlib

import pytest

pytestmark = pytest.mark.unit

_p = pathlib.Path(__file__).resolve().parents[1] / "app" / "core" / "password_policy.py"
_spec = importlib.util.spec_from_file_location("password_policy_under_test", _p)
pp = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(pp)


def test_min_length_and_floor():
    assert pp.password_policy_errors("short", {}) != []            # < 8 (the floor)
    assert pp.password_policy_errors("abcdefgh", {}) == []         # exactly 8, no toggles
    assert pp.password_policy_errors("abcdefgh", {"password_min_length": 12}) != []   # < 12
    assert pp.password_policy_errors("abcdefghijkl", {"password_min_length": 12}) == []
    # a stored minimum below the hard floor is clamped up to 8
    assert pp.password_policy_errors("abcdef", {"password_min_length": 4}) != []      # 6 < 8
    assert pp.password_policy_errors("abcdefgh", {"password_min_length": 4}) == []    # 8 ok


def test_complexity_toggles():
    cfg = {"require_uppercase": True, "require_numbers": True, "require_special": True}
    assert pp.password_policy_errors("alllowercasexx", cfg) != []                    # missing all three
    assert pp.password_policy_errors("Abcdefgh1!", cfg) == []                        # upper + num + special
    assert "uppercase" in " ".join(pp.password_policy_errors("abcdefgh1!", cfg))     # names the miss
    # a space is NOT a special character
    assert pp.password_policy_errors("Abcdefgh1 ", {"require_special": True}) != []
    # lowercase toggle
    assert pp.password_policy_errors("ABCDEFGH1", {"require_lowercase": True}) != []


def test_no_toggles_only_floor():
    assert pp.password_policy_errors("Sup3rSecret", {}) == []
    assert pp.password_policy_errors("", {}) != []


def test_view_mirrors_the_enforced_rules():
    # password_policy_view exposes the SAME clamps + toggle semantics the enforcer uses, so the
    # invite-acceptance form can show requirements that never drift from what's enforced.
    v = pp.password_policy_view({})
    assert v["min_length"] == pp.HARD_FLOOR
    assert v == {"min_length": 8, "require_uppercase": False, "require_lowercase": False,
                 "require_numbers": False, "require_special": False}
    # min clamps up to the floor; a strict policy round-trips
    assert pp.password_policy_view({"password_min_length": 4})["min_length"] == 8
    strict = pp.password_policy_view({"password_min_length": 16, "require_uppercase": True,
                                      "require_special": True})
    assert strict["min_length"] == 16 and strict["require_uppercase"] is True
    assert strict["require_special"] is True and strict["require_numbers"] is False


def test_view_toggle_is_strict_true_only():
    # a truthy-but-not-True value (the settings-save 'undefined !== false' hazard) is reported False
    for junk in ("true", 1, "on", "yes"):
        assert pp.password_policy_view({"require_numbers": junk})["require_numbers"] is False
    assert pp.password_policy_view({"require_numbers": True})["require_numbers"] is True


def test_view_non_dict_is_defaults():
    assert pp.password_policy_view(None)["min_length"] == 8
    assert pp.password_policy_view(["x"])["require_uppercase"] is False
