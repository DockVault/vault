"""Unit tests for app/core/account_policy — the organizational onboarding policy validators.

Pure/offline (no DB, no network): every enum, the invite-TTL range, the domain-list normalization
and its bounds, and the email-only-login lockout guard. These pin the rules the PUT /settings
handler delegates to, so a later refactor of the endpoint can't silently loosen them.
"""
import pytest

from app.core.account_policy import (
    DEFAULTS,
    ACCOUNT_POLICY_KEYS,
    MAX_INVITE_TTL_HOURS,
    MIN_INVITE_TTL_HOURS,
    MAX_SIGNUP_DOMAINS,
    MAX_DOMAIN_LENGTH,
    AccountPolicyError,
    effective_account_policy,
    normalize_domains,
    normalize_domains_lenient,
    validate_account_policy,
)

pytestmark = pytest.mark.unit


# ---- effective_account_policy: defaults filled, stored overrides -----------------------------
def test_effective_all_defaults_when_empty():
    eff = effective_account_policy(None)
    assert eff == {**DEFAULTS, "signup_email_domains": []}
    assert set(eff) == set(ACCOUNT_POLICY_KEYS)
    # defaults preserve today's behaviour exactly
    assert eff["email_requirement"] == "required"
    assert eff["invite_enabled"] is False and eff["signup_enabled"] is False
    assert eff["login_identifier"] == "username"


def test_effective_partial_stored_fills_the_rest():
    eff = effective_account_policy({"invite_enabled": True, "invite_ttl_hours": 48})
    assert eff["invite_enabled"] is True and eff["invite_ttl_hours"] == 48
    assert eff["signup_enabled"] is False          # untouched default
    assert eff["login_identifier"] == "username"


def test_effective_normalizes_a_legacy_raw_domain_list_on_read():
    eff = effective_account_policy({"signup_email_domains": ["@Example.COM ", "example.com"]})
    assert eff["signup_email_domains"] == ["example.com"]   # lowercased, @-stripped, deduped


def test_effective_stored_false_and_zeroish_are_respected_not_overwritten():
    eff = effective_account_policy({"email_requirement": "optional"})
    assert eff["email_requirement"] == "optional"


# ---- normalize_domains ------------------------------------------------------------------------
def test_normalize_lowercases_strips_at_and_dedupes_preserving_order():
    assert normalize_domains(["B.com", "@a.com", "a.com", "A.COM"]) == ["b.com", "a.com"]


def test_normalize_accepts_multilabel_and_hyphenated():
    assert normalize_domains(["sub.example.co.uk", "my-corp.io"]) == ["sub.example.co.uk", "my-corp.io"]


@pytest.mark.parametrize("bad", [
    "notadomain",           # single label, no dot
    "bad domain.com",       # space
    "http://example.com",   # scheme
    "example.com/path",     # path
    "*.example.com",        # wildcard
    "-lead.com",            # leading hyphen
    "trail-.com",           # trailing hyphen
    "exam_ple.com",         # underscore
    "a..b.com",             # empty label
    "café.com",             # non-ascii (must be punycode)
])
def test_normalize_rejects_malformed(bad):
    with pytest.raises(AccountPolicyError):
        normalize_domains([bad])


def test_normalize_rejects_empty_entry_and_bare_at():
    with pytest.raises(AccountPolicyError):
        normalize_domains([""])
    with pytest.raises(AccountPolicyError):
        normalize_domains(["@"])


def test_normalize_rejects_non_list_and_non_string_entry():
    with pytest.raises(AccountPolicyError):
        normalize_domains("example.com")          # a bare string, not a list
    with pytest.raises(AccountPolicyError):
        normalize_domains([123])


def test_normalize_enforces_count_and_length_bounds():
    over = [f"d{i}.example.com" for i in range(MAX_SIGNUP_DOMAINS + 1)]
    with pytest.raises(AccountPolicyError):
        normalize_domains(over)
    # a single over-long domain
    long_label = "a" * 63
    too_long = ".".join([long_label] * 5)         # > 253 chars
    assert len(too_long) > MAX_DOMAIN_LENGTH
    with pytest.raises(AccountPolicyError):
        normalize_domains([too_long])


def test_normalize_count_bound_counts_after_dedup():
    # MAX distinct domains plus duplicates of them must PASS (dedup happens before the count check)
    exactly_max = [f"d{i}.example.com" for i in range(MAX_SIGNUP_DOMAINS)]
    assert normalize_domains(exactly_max + exactly_max) == exactly_max


def test_strict_normalize_rejects_an_oversized_raw_list_up_front():
    # a pathologically large raw list is refused before the per-entry loop walks it
    with pytest.raises(AccountPolicyError):
        normalize_domains(["a.io"] * (10 * MAX_SIGNUP_DOMAINS + 1))


# ---- read path is LENIENT: malformed stored data renders clean, never raises ------------------
def test_effective_drops_malformed_stored_domains_instead_of_raising():
    eff = effective_account_policy({"signup_email_domains":
                                    ["Good.com", "not a domain", "@Also.io", 123, "good.com", "*.x.com"]})
    assert eff["signup_email_domains"] == ["good.com", "also.io"]   # valid kept+normalized, junk dropped


def test_effective_coerces_non_list_or_none_domains_to_empty():
    assert effective_account_policy({"signup_email_domains": "example.com"})["signup_email_domains"] == []
    assert effective_account_policy({"signup_email_domains": None})["signup_email_domains"] == []
    assert effective_account_policy({"signup_email_domains": ["localhost"]})["signup_email_domains"] == []


def test_normalize_domains_lenient_drops_invalid_and_dedupes():
    assert normalize_domains_lenient(["A.com", "a.com", "bad domain", "@b.io"]) == ["a.com", "b.io"]
    assert normalize_domains_lenient("nope") == []
    assert normalize_domains_lenient([123, None, "x.io"]) == ["x.io"]


# ---- validate_account_policy: enums -----------------------------------------------------------
@pytest.mark.parametrize("value", ["required", "optional"])
def test_email_requirement_valid(value):
    assert validate_account_policy({"email_requirement": value})["email_requirement"] == value


def test_email_requirement_invalid():
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"email_requirement": "maybe"})


@pytest.mark.parametrize("value", ["username", "email", "either"])
def test_login_identifier_valid_when_no_lockout(value):
    validate_account_policy({"login_identifier": value}, email_login_locks_out_admin=False)


def test_login_identifier_invalid():
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"login_identifier": "biometric"})


@pytest.mark.parametrize("mode", ["off", "allowlist", "denylist"])
def test_domain_mode_valid(mode):
    validate_account_policy({"signup_email_domain_mode": mode})


def test_domain_mode_invalid():
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"signup_email_domain_mode": "blocklist"})


# ---- validate_account_policy: booleans + invite TTL -------------------------------------------
@pytest.mark.parametrize("key", ["invite_enabled", "signup_enabled"])
def test_switches_must_be_bool(key):
    validate_account_policy({key: True})
    validate_account_policy({key: False})
    with pytest.raises(AccountPolicyError):
        validate_account_policy({key: "true"})     # a string must not coerce truthy
    with pytest.raises(AccountPolicyError):
        validate_account_policy({key: 1})


@pytest.mark.parametrize("value", [MIN_INVITE_TTL_HOURS, 24, MAX_INVITE_TTL_HOURS])
def test_invite_ttl_valid_boundaries(value):
    validate_account_policy({"invite_ttl_hours": value})


@pytest.mark.parametrize("value", [0, -1, MAX_INVITE_TTL_HOURS + 1, "24", 24.0, True, None])
def test_invite_ttl_invalid(value):
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"invite_ttl_hours": value})


# ---- the email-only-login lockout guard -------------------------------------------------------
def test_email_login_refused_when_it_would_lock_out_an_admin():
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"login_identifier": "email"}, email_login_locks_out_admin=True)


def test_email_login_allowed_when_no_admin_would_be_locked_out():
    out = validate_account_policy({"login_identifier": "email"}, email_login_locks_out_admin=False)
    assert out == {}          # login_identifier is validated but not among the normalized returns


def test_lockout_guard_only_gates_email_not_either_or_username():
    # 'either' and 'username' keep a username path, so a mail-less admin is not stranded.
    validate_account_policy({"login_identifier": "either"}, email_login_locks_out_admin=True)
    validate_account_policy({"login_identifier": "username"}, email_login_locks_out_admin=True)


# ---- validate returns normalized values + ignores absent keys --------------------------------
def test_validate_returns_normalized_domains_for_persistence():
    out = validate_account_policy(
        {"signup_email_domains": ["@Example.com", "example.com", "b.io"]})
    assert out["signup_email_domains"] == ["example.com", "b.io"]


def test_absent_keys_pass_through_untouched():
    # an unrelated settings payload validates to an empty normalized dict (nothing to persist)
    assert validate_account_policy({"smtp_server": "mail.example.com"}) == {}


def test_partial_payload_validates_only_present_keys():
    # a bad invite_ttl must still be caught even though other keys are absent
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"invite_ttl_hours": 0})


def test_non_dict_payload_rejected():
    with pytest.raises(AccountPolicyError):
        validate_account_policy(["not", "a", "dict"])


# ---- email-change verification: gated behind SMTP being configured ----------------------------
def test_email_change_verification_in_defaults_and_effective():
    assert DEFAULTS["email_change_requires_verification"] is False
    assert effective_account_policy(None)["email_change_requires_verification"] is False
    assert effective_account_policy(
        {"email_change_requires_verification": True})["email_change_requires_verification"] is True


def test_email_change_verification_must_be_bool():
    validate_account_policy({"email_change_requires_verification": False})
    with pytest.raises(AccountPolicyError):
        validate_account_policy({"email_change_requires_verification": "yes"})


def test_enabling_verification_requires_smtp_configured():
    # turning it ON without SMTP is refused...
    with pytest.raises(AccountPolicyError):
        validate_account_policy(
            {"email_change_requires_verification": True}, smtp_configured=False)
    # ...and permitted once SMTP is configured
    validate_account_policy(
        {"email_change_requires_verification": True}, smtp_configured=True)


def test_disabling_verification_never_needs_smtp():
    # turning it OFF must always be allowed, even with no SMTP, so a deployment that loses SMTP can
    # still relax the policy rather than being stuck unable to save.
    validate_account_policy(
        {"email_change_requires_verification": False}, smtp_configured=False)
