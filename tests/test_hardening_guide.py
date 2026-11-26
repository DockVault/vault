"""The hardening guide says how to set passkeys and single sign-on up safely, under the names the Settings page
shows and with the defaults the code has. Offline: it reads the guide and the settings' own descriptions."""
import re
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]
GUIDE = ROOT / "docs" / "guides" / "hardening.md"
set_bare_api_env()


def _guide() -> str:
    return GUIDE.read_text(encoding="utf-8")


def _flat(text: str) -> str:
    """The text with each run of white space made one space, so a line break never splits what is looked for."""
    return " ".join(text.split())


def _section(text: str, heading: str) -> str:
    """From ``heading`` to the next heading of the same level."""
    _, found, rest = text.partition(heading + "\n")
    assert found, heading
    return rest.split("\n## ", 1)[0]


def test_the_guide_has_a_section_on_passkeys_and_single_sign_on():
    assert "\n## Sign-in: passkeys and single sign-on\n" in _guide()


def test_the_guide_names_each_passkey_setting_as_the_settings_page_shows_it():
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as ws
    section = _flat(_section(_guide(), "## Sign-in: passkeys and single sign-on"))
    for key in (ws.MODE, ws.REQUIRED_ROLES, ws.GRACE_DAYS, ws.SIGN_IN_ROLES, ws.REQUIRE_UV, ws.DEVICE_BOUND_ROLES):
        assert registry.spec_for(key).label in section, key


def test_the_defaults_the_guide_gives_are_the_codes():
    from app.core import settings_registry as registry
    from app.core import sso_policy
    from app.core import webauthn_settings as ws
    section = _flat(_section(_guide(), "## Sign-in: passkeys and single sign-on"))
    assert registry.spec_for(ws.GRACE_DAYS).default == 14 and "(14 by default)" in section
    assert sso_policy.DEFAULTS["sso_freshness_days"] == 30 and "(30; 0 turns it off)" in section
    assert registry.spec_for(ws.SIGN_IN_ROLES).default == ["user", "external"]
    assert "(user and external by default)" in section
    assert registry.spec_for(ws.REQUIRED_ROLES).default == [] and "which is empty by default" in section
    assert registry.spec_for(ws.REQUIRE_UV).default is True and sso_policy.DEFAULTS["sso_trust_idp_mfa"] is False


def test_the_guide_never_calls_the_roles_that_must_have_a_passkey_an_advanced_setting():
    from app.core import settings_registry as registry
    from app.core import webauthn_settings as ws
    label = registry.spec_for(ws.REQUIRED_ROLES).label
    sentences = re.split(r"(?<=[.:;])\s", _flat(_guide()))
    said = [s for s in sentences if label in s]
    assert said
    assert not [s for s in said if "advanced" in s.lower()], said


def test_the_guide_says_what_a_lock_of_each_sign_in_group_does():
    guide = _flat(_guide())
    assert "SETTINGS_LOCKED_KEYS=sso" in guide and "`webauthn`" in guide and "WEBAUTHN_" in guide
    assert ("The groups `sso` and `webauthn` act differently: see "
            "[Sign-in](#sign-in-passkeys-and-single-sign-on).") in guide


def test_the_checklist_says_a_passkey_can_meet_a_compliance_step_up():
    checklist = _flat(_section(_guide(), "## The checklist"))
    # The step-up route holds a passkey to the compliance rules: it must verify the person, and anyone but an
    # administrator acts by the auditor right, for which only a key the right was approved with vouches.
    assert ("an authenticator code, a recovery code or a passkey that verified the person (for an auditor who is not "
            "an administrator, only a passkey their auditor right was approved or last reconfirmed with)") in checklist
    assert "an authenticator or recovery code" not in checklist


def test_the_guide_and_the_readme_say_how_sftp_agrees_its_keys():
    """SFTP agrees the keys of a connection with the hybrid post-quantum exchange where the client offers it, and
    SFTP_KEX_POLICY=pq-required refuses the clients that do not; the container log names each connection that
    agreed a classical one (app/sftp/sftp_server.py), which is how an operator finds who would be refused."""
    from app.sftp import kex_policy
    guide = _flat(_guide())
    readme = _flat((ROOT / "README.md").read_text(encoding="utf-8"))
    for text in (guide, readme):
        assert "SFTP_KEX_POLICY" in text
    assert kex_policy.HYBRID in readme and "`SFTP_KEX_POLICY=pq-required` refuses clients that do not" in readme
    assert kex_policy.POLICIES == ("default", "pq-required") and not hasattr(kex_policy, "PREFERRED")
    assert ("`SFTP_KEX_POLICY` takes two values. `default` (also what you get with no value) agrees the hybrid "
            "ML-KEM exchange with every client that lists it first; the client's order decides") in guide
    assert "`pq-required` refuses clients without it." in guide
    assert "pq-preferred" not in guide and "pq-preferred" not in readme
    assert "kex.agreed.classical" in guide
    assert "in the one-container shape the whole vault stops with it" in guide


def test_the_guide_and_the_readme_keep_from_a_providers_hold_only_an_auditor_right_in_force(monkeypatch):
    """A provider's hold reaches every account but an administrator and the holder of an auditor right in force
    (app/services/sso_freshness.py may_be_held): a right that is only proposed, or is suspended, is held like any
    other account. Both texts say so, and neither says that a holder of the right is never held."""
    import types
    import uuid
    from app.core import auditor_rights
    from app.core.models import RoleEnum
    from app.services import sso_freshness
    said = "auditor right in force (not one that is proposed or suspended)"
    guide = _flat(_guide())
    readme = _flat((ROOT / "README.md").read_text(encoding="utf-8"))
    assert said in guide and said in readme
    assert "holder of the auditor right is ever held" not in readme
    assert "holder of the auditor right is held" not in guide
    grants = {}
    monkeypatch.setattr(auditor_rights, "open_grant", lambda db, user_id: grants.get("now"))
    person = types.SimpleNamespace(id=uuid.uuid4(), role=RoleEnum.USER)
    for status, held in (("active", False), ("suspended", True), ("proposed", True), (None, True)):
        grants["now"] = types.SimpleNamespace(status=status) if status else None
        assert sso_freshness.may_be_held(object(), person) is held, status
    assert sso_freshness.may_be_held(object(), types.SimpleNamespace(id=uuid.uuid4(), role=RoleEnum.ADMIN)) is False
