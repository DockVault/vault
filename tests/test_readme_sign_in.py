"""The README says what an operator needs for passkeys and single sign-on: where they are set, the address they are
built on, the redirect address a provider is given, who gets in, what happens to people who leave, and how an
administrator gets back in. Offline: it reads the README and the provider presets the wizard offers."""
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
set_bare_api_env()


def _readme() -> str:
    return (ROOT / "README.md").read_text(encoding="utf-8")


def _flat(text: str) -> str:
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    _, found, rest = text.partition(heading + "\n")
    assert found, heading
    return rest.split("\n## ", 1)[0]


def test_the_readme_has_a_section_on_passkeys_and_single_sign_on():
    readme = _readme()
    assert "\n## Passkeys and single sign-on\n" in readme
    # Before the security model, and the features list and the checklist point to it.
    assert readme.index("\n## Passkeys and single sign-on\n") < readme.index("\n## Security model\n")
    flat = _flat(readme)
    assert "see [Passkeys and single sign-on](#passkeys-and-single-sign-on)." in flat
    checklist = _flat(_section(readme, "## Production checklist"))
    assert ("Passkeys and single sign-on are built on the same first entry: see "
            "[Passkeys and single sign-on](#passkeys-and-single-sign-on).") in checklist


def test_the_section_says_where_they_are_set_and_how_to_get_back_in():
    section = _flat(_section(_readme(), "## Passkeys and single sign-on"))
    for said in ("Settings → Sign-in methods", "/auth/sso/<provider id>/callback", "clear-passkey-requirement",
                 "**Test sign-in**", "`ALLOWED_HOSTS`", "python dockvault.py status", "python dockvault.py accounts",
                 "`SETTINGS_LOCKED_KEYS`", "(docs/guides/hardening.md#sign-in-passkeys-and-single-sign-on)"):
        assert said in section, said


def test_the_section_names_every_provider_the_wizard_offers():
    from app.core import sso_presets
    section = _flat(_section(_readme(), "## Passkeys and single sign-on"))
    named = [preset["name"] for preset in sso_presets.PRESETS if preset["id"] != sso_presets.OTHER]
    assert named
    for name in named:
        assert name in section, name
    assert "OpenID Connect" in section


def test_the_defaults_the_section_gives_are_the_codes():
    from app.core import sso_policy
    section = _flat(_section(_readme(), "## Passkeys and single sign-on"))
    assert sso_policy.DEFAULTS["sso_account_creation"] == "invite_only"
    assert sso_policy.DEFAULTS["sso_freshness_days"] == 30 and "After 30 days without a sign-in" in section
    assert all(sso_policy.DEFAULTS[key] is True for key in
               ("sso_backchannel_logout", "sso_refusal_ends_access", "sso_lapse_ends_sign_in"))
