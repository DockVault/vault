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
