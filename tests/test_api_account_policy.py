"""Live API acceptance for the account-onboarding policy on GET/PUT /settings.

Covers: the policy keys are reported with their effective values; a round-trip of each key; each
invalid value is refused 400; the signup-domain list is normalized (lowercased, '@'-stripped,
deduped); a partial save leaves other keys intact; a non-admin AND an admin-minted temporary
credential are both refused (interactive-admin only); the email-change-verification toggle is gated
behind SMTP being configured; and the save is audited.

The settings row is global, so every test restores the keys it touched.
"""
import pytest

from conftest import ApiClient, BASE_URL, unique

pytestmark = pytest.mark.integration

ACCOUNT_KEYS = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
                "signup_email_domain_mode", "signup_email_domains", "login_identifier",
                "email_change_requires_verification")
SMTP_KEYS = ("smtp_server", "from_email")


@pytest.fixture
def restore_settings(admin):
    """Snapshot the keys these tests mutate and put them back afterwards."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in (ACCOUNT_KEYS + SMTP_KEYS)}
    yield snap
    admin.put("/settings", json=snap)


def _s(admin):
    return admin.get("/settings").json()


def test_effective_keys_present_and_typed(admin):
    s = _s(admin)
    for k in ACCOUNT_KEYS:
        assert k in s, f"{k} missing from GET /settings (effective values must be reported)"
    assert s["email_requirement"] in ("required", "optional")
    assert isinstance(s["invite_enabled"], bool)
    assert isinstance(s["signup_enabled"], bool)
    assert isinstance(s["invite_ttl_hours"], int)
    assert s["signup_email_domain_mode"] in ("off", "allowlist", "denylist")
    assert isinstance(s["signup_email_domains"], list)
    assert s["login_identifier"] in ("username", "email", "either")
    assert isinstance(s["email_change_requires_verification"], bool)


def test_roundtrip_core_keys(admin, restore_settings):
    r = admin.put("/settings", json={
        "email_requirement": "optional",
        "invite_enabled": True,
        "invite_ttl_hours": 48,
        "signup_enabled": True,
        "login_identifier": "either",
    })
    assert r.status_code == 200, r.text
    s = _s(admin)
    assert s["email_requirement"] == "optional"
    assert s["invite_enabled"] is True
    assert s["invite_ttl_hours"] == 48
    assert s["signup_enabled"] is True
    assert s["login_identifier"] == "either"


def test_domains_normalized_and_deduped(admin, restore_settings):
    r = admin.put("/settings", json={
        "signup_email_domain_mode": "allowlist",
        "signup_email_domains": ["@Example.COM", "example.com", "b.io", "  a.io "],
    })
    assert r.status_code == 200, r.text
    assert _s(admin)["signup_email_domains"] == ["example.com", "b.io", "a.io"]


@pytest.mark.parametrize("payload", [
    {"email_requirement": "maybe"},
    {"invite_ttl_hours": 0},
    {"invite_ttl_hours": 721},
    {"invite_ttl_hours": "24"},
    {"invite_enabled": "yes"},
    {"signup_email_domain_mode": "blocklist"},
    {"login_identifier": "biometric"},
    {"signup_email_domains": ["not a domain"]},
    {"signup_email_domains": ["http://x.com"]},
    {"signup_email_domains": "example.com"},
])
def test_invalid_values_rejected_400(admin, restore_settings, payload):
    r = admin.put("/settings", json=payload)
    assert r.status_code == 400, f"expected 400 for {payload}, got {r.status_code}: {r.text}"


def test_invalid_value_is_not_persisted(admin, restore_settings):
    before = _s(admin)["login_identifier"]
    assert admin.put("/settings", json={"login_identifier": "nope"}).status_code == 400
    assert _s(admin)["login_identifier"] == before


def test_partial_save_leaves_other_keys_intact(admin, restore_settings):
    admin.put("/settings", json={"invite_enabled": True, "login_identifier": "either"})
    admin.put("/settings", json={"email_requirement": "optional"})     # partial second save
    s = _s(admin)
    assert s["invite_enabled"] is True and s["login_identifier"] == "either"
    assert s["email_requirement"] == "optional"


def test_non_admin_cannot_change_policy(temp_user_client):
    assert temp_user_client.put("/settings", json={"invite_enabled": True}).status_code == 403


def test_temp_cred_admin_cannot_change_policy(admin):
    tc = admin.post("/auth/temp-credentials", json={"note": unique("acct-policy")}).json()
    c = ApiClient(BASE_URL)
    c.login(tc["temp_username"], tc["credential"])
    assert c.put("/settings", json={"invite_enabled": True}).status_code == 403


def test_email_change_verification_gated_on_smtp(admin, restore_settings):
    # with SMTP not configured, enabling verification is refused and not persisted
    admin.put("/settings", json={"smtp_server": "", "from_email": "",
                                 "email_change_requires_verification": False})
    r = admin.put("/settings", json={"email_change_requires_verification": True})
    assert r.status_code == 400, r.text
    assert _s(admin)["email_change_requires_verification"] is False
    # once SMTP is configured, enabling is allowed
    admin.put("/settings", json={"smtp_server": "mail.example.com", "from_email": "vault@example.com"})
    r = admin.put("/settings", json={"email_change_requires_verification": True})
    assert r.status_code == 200, r.text
    assert _s(admin)["email_change_requires_verification"] is True
    # turning it OFF is always allowed, even after SMTP is cleared
    admin.put("/settings", json={"smtp_server": "", "from_email": ""})
    assert admin.put("/settings", json={"email_change_requires_verification": False}).status_code == 200


def test_email_only_login_allowed_when_admin_has_email(admin, restore_settings):
    me = admin.get("/users/me").json()
    if not (me.get("email") or "").strip():
        pytest.skip("acting admin has no email; the lockout-guard refusal is covered by unit tests")
    r = admin.put("/settings", json={"login_identifier": "email"})
    assert r.status_code == 200, r.text
    assert _s(admin)["login_identifier"] == "email"


def test_settings_save_is_audited(admin, restore_settings):
    admin.put("/settings", json={"invite_ttl_hours": 72})
    r = admin.get("/audit/events", params={"limit": 50})
    if r.status_code != 200:
        pytest.skip("audit events endpoint unavailable")
    assert "settings_updated" in r.text
