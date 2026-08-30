"""Pure contracts for the rate-limit override registry: fail-safe resolution, bounds, the
deployment-value-is-read-only convention, and the lockout `0 = permanent` edge case."""
import pytest

from app.core import rate_limit_settings as rls

pytestmark = pytest.mark.unit


def test_absent_or_bad_override_falls_back_to_deployment_default():
    # No blob -> deployment default; a bad/oob/bool override -> deployment default too.
    key = "rate_limit_vault_attempts"
    d = rls.deployment_default(key)
    assert rls.resolve(key, None) == d
    assert rls.resolve(key, {}) == d
    assert rls.resolve(key, {key: 0}) == d          # 0 = clear -> deployment
    assert rls.resolve(key, {key: -5}) == d         # negative -> deployment (never opens the gate)
    assert rls.resolve(key, {key: True}) == d       # bool -> deployment (must not coerce to 1)
    assert rls.resolve(key, {key: "9"}) == d        # string -> deployment
    assert rls.resolve(key, {key: 10**9}) == d      # above ceiling -> deployment
    # A valid, in-bounds override is honoured.
    assert rls.resolve(key, {key: 7}) == 7


def test_a_bad_override_can_never_disable_a_limit():
    # The crux: whatever garbage is stored, the effective value stays a real, positive limit.
    for bad in (0, -1, None, True, False, "x", 10**12, 2.5):
        blob = {"rate_limit_login_attempts": 999999999}  # unrelated key
        eff = rls.resolve("max_login_attempts", {"max_login_attempts": bad})
        assert eff >= 1


def test_validate_override_bounds_and_sentinel():
    # 0 is always accepted (clear the override).
    rls.validate_override("rate_limit_vault_attempts", 0)
    # A valid in-bounds value is accepted.
    rls.validate_override("rate_limit_vault_attempts", 5)
    # Bool / non-int / negative / over-ceiling are refused.
    for bad in (True, 2.0, "5", -1):
        with pytest.raises(ValueError):
            rls.validate_override("rate_limit_vault_attempts", bad)
    with pytest.raises(ValueError):
        rls.validate_override("rate_limit_vault_attempts", rls._BY_KEY["rate_limit_vault_attempts"].maximum + 1)
    # An unknown key is refused (never silently written).
    with pytest.raises(ValueError):
        rls.validate_override("rate_limit_api_enabled", 1)
    with pytest.raises(ValueError):
        rls.validate_override("not_a_limit", 1)


def test_lockout_zero_deployment_is_preserved_but_custom_zero_is_the_sentinel(monkeypatch):
    # A deployment account_lockout_minutes of 0 means "locks are permanent" — it must NOT be clamped
    # up to the custom minimum of 1.
    monkeypatch.setattr(rls.settings, "account_lockout_minutes", 0, raising=False)
    assert rls.deployment_default("lockout_duration") == 0
    assert rls.resolve("lockout_duration", None) == 0
    assert rls.resolve("lockout_duration", {"lockout_duration": 0}) == 0   # custom 0 -> deployment (0)
    # A positive custom sets a real TTL.
    assert rls.resolve("lockout_duration", {"lockout_duration": 30}) == 30


def test_describe_all_shape_and_readonly_deployment():
    rows = rls.describe_all({"rate_limit_vault_attempts": 9})
    by_key = {r["key"]: r for r in rows}
    # Every registry key is present with the full shape.
    assert set(by_key) == set(rls.OVERRIDE_KEYS)
    r = by_key["rate_limit_vault_attempts"]
    assert set(r) >= {"key", "group", "label", "description", "when", "unit",
                      "min", "max", "deployment", "custom", "effective"}
    assert r["custom"] == 9 and r["effective"] == 9
    assert r["deployment"] == rls.deployment_default("rate_limit_vault_attempts")
    # A key with no override reports custom None and effective == deployment.
    r2 = by_key["rate_limit_sftp_key_attempts"]
    assert r2["custom"] is None
    assert r2["effective"] == r2["deployment"]
    # Groups cover the extension surface the auditor asked for.
    assert {row["group"] for row in rows} >= {"login", "vault", "sftp", "api"}


def test_deployment_default_clamps_a_bad_env_value(monkeypatch):
    # An out-of-range env value is clamped into bounds so the effective limit is never out of range.
    spec = rls._BY_KEY["rate_limit_api_default"]
    monkeypatch.setattr(rls.settings, "rate_limit_api_default", spec.maximum + 5000, raising=False)
    assert rls.deployment_default("rate_limit_api_default") == spec.maximum
    monkeypatch.setattr(rls.settings, "rate_limit_api_default", -3, raising=False)
    assert rls.deployment_default("rate_limit_api_default") == spec.minimum
