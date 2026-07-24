"""Pure Temporary Vault Passcode policy resolver (app/core/temp_passcode_policy.py).

Pins the fail-closed / preserve-today's-behavior defaults independent of any running instance
(the HTTP suite can't reach the key-absent state on a persistent deployment). No app import, no
running vault — mirrors test_log_pull_helpers.py.
"""
import os
import sys

import pytest

pytestmark = pytest.mark.unit

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import temp_passcode_policy as tpp  # noqa: E402


def test_master_switch_fail_closed_default_and_strict_bool():
    assert tpp.passcodes_enabled({}) is False           # unset -> OFF
    assert tpp.passcodes_enabled(None) is False
    assert tpp.passcodes_enabled({"temp_passcodes_enabled": True}) is True
    # a truthy NON-bool stored value must NOT turn the feature on (fail closed, strict `is True`)
    for bad in ("true", "false", 1, "on", [1]):
        assert tpp.passcodes_enabled({"temp_passcodes_enabled": bad}) is False


def test_allow_zk_defaults_true_only_explicit_false_denies():
    assert tpp.allow_zk_vaults({}) is True              # unset -> today's behavior (allow)
    assert tpp.allow_zk_vaults(None) is True
    assert tpp.allow_zk_vaults({"temp_cred_allow_zk_vaults": False}) is False
    assert tpp.allow_zk_vaults({"temp_cred_allow_zk_vaults": True}) is True
    # a non-bool stored value must not accidentally deny — only explicit False denies
    assert tpp.allow_zk_vaults({"temp_cred_allow_zk_vaults": "false"}) is True


def test_min_length_default_and_floor():
    assert tpp.min_length({}) == 16                     # default generated length
    assert tpp.min_length({"temp_passcode_min_length": 24}) == 24
    assert tpp.min_length({"temp_passcode_min_length": 4}) == 8   # floored to 8
    assert tpp.min_length({"temp_passcode_min_length": 0}) == 16
    assert tpp.min_length({"temp_passcode_min_length": "x"}) == 16


def test_max_lifetime_default_and_bad_values():
    assert tpp.max_lifetime_minutes({}) == 0
    assert tpp.max_lifetime_minutes({"temp_passcode_max_lifetime_minutes": 120}) == 120
    assert tpp.max_lifetime_minutes({"temp_passcode_max_lifetime_minutes": -5}) == 0
    assert tpp.max_lifetime_minutes({"temp_passcode_max_lifetime_minutes": "x"}) == 0


def test_decision_defaults_one_time_true_custom_false():
    p = tpp.effective_policy({})
    assert p["temp_passcode_one_time_default"] is True   # one-time by default
    assert p["temp_passcode_allow_custom"] is False      # generated-only by default
    for k in ("temp_passcode_require_uppercase", "temp_passcode_require_lowercase",
              "temp_passcode_require_numbers", "temp_passcode_require_special",
              "temp_passcode_single_vault_only"):
        assert p[k] is False


def test_effective_policy_includes_allow_zk_and_all_keys():
    p = tpp.effective_policy({})
    # ONE call must carry the ZK-in-scope flag so a later caller can't fail open by forgetting it.
    assert p.get("temp_cred_allow_zk_vaults") is True
    for k in ("temp_passcodes_enabled", "temp_passcode_min_length", "temp_passcode_max_lifetime_minutes"):
        assert k in p
    # a non-bool value for a bool key falls back to the default (never coerced)
    assert tpp.effective_policy({"temp_passcode_allow_custom": "yes"})["temp_passcode_allow_custom"] is False
