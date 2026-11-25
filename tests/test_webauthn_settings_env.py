"""The passkey settings' deployment values, offline (app/core/webauthn_settings.py, app/core/config.py).

Seven of the passkey settings take a value from .env under their own name (WEBAUTHN_MODE, WEBAUTHN_REQUIRED_ROLES,
WEBAUTHN_ENROLLMENT_GRACE_DAYS, WEBAUTHN_SIGN_IN, WEBAUTHN_REQUIRE_UV, WEBAUTHN_ALLOWED_ALGS and
WEBAUTHN_DEVICE_BOUND_ROLES), so SETTINGS_LOCKED_KEYS naming them, their group (webauthn) or everything holds
the deployment's value, not only the shipped default. Unset, each resolves to that default. A value the setting
cannot take is reported by the start's contract and the default stays in force. Without a lock, an
administrator's saved value wins over the .env value, as for every other setting. Attestation and the allowed
authenticator makes depend on the trust anchors' file and keep no .env value: a lock holds them at their
defaults.
"""
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import settings_registry as reg  # noqa: E402
from app.core import webauthn_settings as wss  # noqa: E402
from app.core.config import Settings  # noqa: E402

pytestmark = pytest.mark.unit

WITH_ENV = (wss.MODE, wss.REQUIRED_ROLES, wss.GRACE_DAYS, wss.SIGN_IN_ROLES, wss.REQUIRE_UV, wss.ALLOWED_ALGS,
            wss.DEVICE_BOUND_ROLES)


@pytest.fixture
def env(monkeypatch):
    """The deployment's settings at their defaults, which a test changes; no stored values, no WEBAUTHN_* line."""
    reg.all_specs()                                   # loads the spec modules
    settings = Settings.model_construct()
    settings.settings_locked_keys = ""
    monkeypatch.setattr(reg, "_cache", reg._Cache())
    monkeypatch.setattr(reg, "_deployment_settings", lambda: settings)
    for key in wss.KEYS:
        monkeypatch.delenv(key.upper(), raising=False)
    return settings


def _stored(values: dict) -> None:
    reg._cache.rows = {key: (value, number) for number, (key, value) in enumerate(values.items(), start=1)}


def _row(key: str) -> dict:
    return reg.describe([key])[0]


def test_seven_passkey_settings_name_their_own_env_line_and_unset_each_is_its_default(env):
    for key in WITH_ENV:
        spec = reg.spec_for(key)
        assert spec.env == key, key
        assert key in Settings.model_fields, key
        # The configuration's default, read as .env gives it, is the setting's default.
        assert reg._from_env(spec, Settings.model_fields[key].default) == spec.default, key
        row = _row(key)
        assert (row["value"], row["source"], row["env"]) == (spec.default, reg.SOURCE_DEFAULT, key.upper()), key
    assert reg.resolve(wss.MODE) == "optional"
    assert not [p for p in reg.check_contract() if "WEBAUTHN" in p]


def test_a_lock_holds_the_deployments_value_and_drops_a_saved_one(env, monkeypatch):
    env.webauthn_mode = "off"
    env.webauthn_required_roles = "admin, user"
    monkeypatch.setenv("WEBAUTHN_MODE", "off")
    monkeypatch.setenv("WEBAUTHN_REQUIRED_ROLES", "admin, user")
    _stored({wss.MODE: "required_for_roles", wss.REQUIRED_ROLES: ["external"]})
    env.settings_locked_keys = "webauthn"
    assert reg.resolve(wss.MODE) == "off" and _row(wss.MODE)["source"] == reg.SOURCE_LOCKED
    assert reg.resolve(wss.REQUIRED_ROLES) == ["admin", "user"]
    assert wss.enabled() is False


@pytest.mark.parametrize("tokens", ["webauthn_mode", "*"])
def test_the_key_itself_or_everything_locks_it_the_same_way(env, monkeypatch, tokens):
    env.webauthn_mode = "off"
    monkeypatch.setenv("WEBAUTHN_MODE", "off")
    _stored({wss.MODE: "optional"})
    env.settings_locked_keys = tokens
    row = _row(wss.MODE)
    assert (row["value"], row["source"], row["locked"]) == ("off", reg.SOURCE_LOCKED, True)


def test_without_a_lock_the_administrators_saved_value_wins_over_the_env_line(env, monkeypatch):
    env.webauthn_mode = "off"
    monkeypatch.setenv("WEBAUTHN_MODE", "off")
    assert reg.resolve(wss.MODE) == "off" and _row(wss.MODE)["source"] == reg.SOURCE_ENV
    _stored({wss.MODE: "required_for_roles"})
    row = _row(wss.MODE)
    assert (row["value"], row["source"], row["deployment"]) == ("required_for_roles", reg.SOURCE_ADMIN, "off")


@pytest.mark.parametrize("field, value", [("webauthn_sign_in", "admin"), ("webauthn_sign_in", "user, admin"),
                                          ("webauthn_mode", "sometimes"), ("webauthn_allowed_algs", ""),
                                          ("webauthn_allowed_algs", "MD5"), ("webauthn_enrollment_grace_days", 0),
                                          ("webauthn_required_roles", "owner")])
def test_a_value_the_setting_cannot_take_is_reported_at_the_start_and_the_default_stays(env, field, value):
    setattr(env, field, value)
    problems = [p for p in reg.check_contract() if p.startswith(f"{field.upper()} is not valid")]
    assert len(problems) == 1, (field, value, reg.check_contract())
    assert reg.resolve(field) == reg.spec_for(field).default
    with pytest.raises(reg.SettingsContractError, match=field.upper()):
        reg.start(lambda: None, load_now=False)


def test_attestation_and_the_allowed_makes_keep_no_env_line_and_a_lock_holds_their_defaults(env):
    for key in (wss.ATTESTATION, wss.ALLOWED_AAGUIDS):
        assert reg.spec_for(key).env is None, key
        assert key not in Settings.model_fields, key
    _stored({wss.ATTESTATION: "direct", wss.ALLOWED_AAGUIDS: ["00000000-0000-0000-0000-000000000000"]})
    env.settings_locked_keys = "webauthn"
    assert reg.resolve(wss.ATTESTATION) == "none" and reg.resolve(wss.ALLOWED_AAGUIDS) == []
    assert _row(wss.ATTESTATION)["source"] == reg.SOURCE_LOCKED and _row(wss.ATTESTATION)["env"] is None
