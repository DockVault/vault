"""A single sign-on provider's policy (app/core/sso_policy.py): the defaults, what a wrong shape becomes, when a
provider counts as restricted, and the restriction's three verdicts (admits, excludes, cannot tell) for the
tenant, domain, group and sign-up-domain rules. Pure."""
import pytest

from app.core import sso_policy as P

pytestmark = pytest.mark.unit


def test_the_defaults_are_the_designs_and_a_wrong_shape_falls_back_to_them():
    assert P.effective(None) == P.DEFAULTS and P.effective("junk") == P.DEFAULTS and P.effective([]) == P.DEFAULTS
    assert P.effective(None) is not P.DEFAULTS and P.effective(None)["sso_allowed_tenants"] is not P.DEFAULTS["sso_allowed_tenants"]
    got = P.effective({"sso_account_creation": "anyone", "sso_default_role": "admin", "sso_password_login": "never",
                       "sso_link_by_email": "yes", "sso_use_signup_domains": 1, "sso_allowed_tenants": "t1",
                       "sso_allowed_domains": [" Example.TEST ", "", 7, None, "x" * 300], "sso_required_groups": {"a": 1},
                       "something_else": True})
    assert got["sso_account_creation"] == "invite_only" and got["sso_default_role"] == "user"
    assert got["sso_password_login"] == "allowed" and got["sso_link_by_email"] is False and got["sso_use_signup_domains"] is False
    assert got["sso_allowed_tenants"] == [] and got["sso_allowed_domains"] == ["example.test"] and got["sso_required_groups"] == []
    assert "something_else" not in got
    kept = P.effective({"sso_account_creation": "jit", "sso_default_role": "external", "sso_password_login": "disabled",
                        "sso_link_by_email": True, "sso_required_groups": ["Vault Users", 5]})
    assert kept["sso_account_creation"] == "jit" and kept["sso_default_role"] == "external"
    assert kept["sso_password_login"] == "disabled" and kept["sso_link_by_email"] is True
    assert kept["sso_required_groups"] == ["Vault Users"]          # a group is a string; a number is dropped
    assert len(P.effective({"sso_allowed_tenants": ["t"] * 500})["sso_allowed_tenants"]) == P.MAX_LIST_ITEMS


def test_freshness_is_thirty_days_by_default_and_refusal_ends_access_is_on():
    assert P.DEFAULTS["sso_freshness_days"] == 30 and P.DEFAULTS["sso_refusal_ends_access"] is True
    for kept in (0, 1, 30, P.FRESHNESS_DAYS_MAX):
        assert P.effective({"sso_freshness_days": kept})["sso_freshness_days"] == kept
    # A count of days, whole and within a year; anything else is the default, never off by accident.
    for wrong in (-1, P.FRESHNESS_DAYS_MAX + 1, 7.5, "30", None, True, False, [30]):
        assert P.effective({"sso_freshness_days": wrong})["sso_freshness_days"] == 30, wrong
    assert P.effective({"sso_refusal_ends_access": False})["sso_refusal_ends_access"] is False
    assert P.effective({"sso_refusal_ends_access": 0})["sso_refusal_ends_access"] is True


@pytest.mark.parametrize("stored, account_policy, restricted", [
    ({}, None, False),
    ({"sso_allowed_tenants": ["t1"]}, None, True),
    ({"sso_allowed_domains": ["example.test"]}, None, True),
    ({"sso_required_groups": ["g"]}, None, True),
    ({"sso_use_signup_domains": True}, {"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.test"]}, True),
    ({"sso_use_signup_domains": True}, {"signup_email_domain_mode": "denylist", "signup_email_domains": ["evil.test"]}, False),
    ({"sso_use_signup_domains": True}, {"signup_email_domain_mode": "allowlist", "signup_email_domains": []}, False),
    ({"sso_use_signup_domains": True}, {"signup_email_domain_mode": "off", "signup_email_domains": ["example.test"]}, False),
    ({"sso_use_signup_domains": False}, {"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.test"]}, False),
    ({"sso_link_by_email": True, "sso_account_creation": "jit"}, None, False),
])
def test_a_provider_is_restricted_only_by_a_list_that_names_who_gets_in(stored, account_policy, restricted):
    assert P.is_restricted(P.effective(stored), account_policy) is restricted


def _judge(stored, **answer):
    fields = dict(tenant_id=None, email=None, email_verified=False, hosted_domain=None, groups=None, groups_overage=False,
                  account_policy=None)
    fields.update(answer)
    return P.restriction(P.effective(stored), **fields)


def test_no_restriction_admits_everyone():
    assert _judge({}) is None
    assert _judge({}, tenant_id="other", email="x@evil.test", email_verified=True, groups=[]) is None


@pytest.mark.parametrize("answer, verdict", [
    ({"tenant_id": "T-1"}, None),                                   # case does not matter for a tenant id
    ({"tenant_id": "t-2"}, P.RESTRICTED),
    ({"tenant_id": "t-10"}, P.RESTRICTED),                          # the whole id, never a prefix
    ({"tenant_id": None}, P.RESTRICTION_CLAIM_MISSING),
    ({"tenant_id": "  "}, P.RESTRICTION_CLAIM_MISSING),
    ({"tenant_id": 42}, P.RESTRICTION_CLAIM_MISSING),
])
def test_the_tenant_rule(answer, verdict):
    assert _judge({"sso_allowed_tenants": ["t-1"]}, **answer) == verdict


@pytest.mark.parametrize("answer, verdict", [
    ({"hosted_domain": "Example.TEST"}, None),
    ({"hosted_domain": "other.test", "email": "a@example.test", "email_verified": True}, P.RESTRICTED),   # hd wins
    ({"email": "a@example.test", "email_verified": True}, None),
    ({"email": "a@EXAMPLE.test", "email_verified": True}, None),
    ({"email": "a@sub.example.test", "email_verified": True}, P.RESTRICTED),   # exactly the listed domain
    ({"email": "a@gmail.com", "email_verified": True}, P.RESTRICTED),         # a consumer account: no hd, wrong domain
    ({"email": "a@example.test", "email_verified": False}, P.RESTRICTION_CLAIM_MISSING),
    ({}, P.RESTRICTION_CLAIM_MISSING),
    ({"email": "no-at-sign", "email_verified": True}, P.RESTRICTION_CLAIM_MISSING),
    ({"email": "a@evil.test@example.test", "email_verified": True}, P.RESTRICTION_CLAIM_MISSING),   # not an address
])
def test_the_domain_rule(answer, verdict):
    assert _judge({"sso_allowed_domains": ["example.test"]}, **answer) == verdict


@pytest.mark.parametrize("answer, verdict", [
    ({"hosted_domain": "Example.TEST"}, None),
    ({"hosted_domain": "example.test", "email": "a@gmail.com", "email_verified": True}, None),
    ({"hosted_domain": "other.test", "email": "a@example.test", "email_verified": True}, P.RESTRICTED),
    # A consumer account that carries the work address: verified, on the list, and no member of the organisation.
    ({"email": "a@example.test", "email_verified": True}, P.RESTRICTION_CLAIM_MISSING),
    ({"hosted_domain": "  ", "email": "a@example.test", "email_verified": True}, P.RESTRICTION_CLAIM_MISSING),
    ({}, P.RESTRICTION_CLAIM_MISSING),
])
def test_where_the_provider_has_a_hosted_domain_claim_the_address_proves_nothing(answer, verdict):
    assert _judge({"sso_allowed_domains": ["example.test"]}, hosted_domain_only=True, **answer) == verdict


@pytest.mark.parametrize("answer, verdict", [
    ({"hosted_domain": "example.test", "email": "a@gmail.com", "email_verified": True}, None),
    ({"hosted_domain": "other.test", "email": "a@example.test", "email_verified": True}, P.RESTRICTED),
    # The consumer account with the work address again: the sign-up list is asked about the claim, not the address.
    ({"email": "a@example.test", "email_verified": True}, P.RESTRICTION_CLAIM_MISSING),
    ({}, P.RESTRICTION_CLAIM_MISSING),
])
def test_the_sign_up_domain_list_is_asked_about_the_hosted_domain_claim_too(answer, verdict):
    """A provider with a hosted-domain claim, restricted only by the vault's sign-up domain list (no list of its
    own): the same rule as for its own list. Without it the tick box alone let any consumer account in that
    carried an address of the organisation's domain."""
    account_policy = {"signup_email_domain_mode": "allowlist", "signup_email_domains": ["example.test"]}
    assert _judge({"sso_use_signup_domains": True}, hosted_domain_only=True, account_policy=account_policy, **answer) == verdict
    # The control: a provider without such a claim is judged on the verified address, as before.
    plain = _judge({"sso_use_signup_domains": True}, account_policy=account_policy, **answer)
    assert plain == (None if answer.get("email") == "a@example.test" else P.RESTRICTED if answer.get("email") else P.RESTRICTION_CLAIM_MISSING)


def test_a_single_knowledge_factor_is_never_a_second_factor():
    """A password, a PIN or a question is one factor. Such a value is refused at save, with the reason, and counts
    for nothing when a stored list holds it all the same: a sign-in with a password alone is not two factors."""
    for value in ("pwd", "PWD", "pin", "kba"):
        with pytest.raises(P.PolicyInvalid) as refused:
            P.validate({"sso_accepted_amr": ["mfa", value]})
        assert refused.value.key == "sso_accepted_amr" and "one factor, not a second one" in str(refused.value)
    assert P.validate({"sso_accepted_amr": ["mfa", "otp", "hwk", "swk", "fpt", "sms"]})["sso_accepted_amr"] == [
        "mfa", "otp", "hwk", "swk", "fpt", "sms"]
    assert P.validate({"sso_accepted_acr": ["pwd"]}) == {"sso_accepted_acr": ["pwd"]}      # an acr value is a name
    stored = P.effective({"sso_trust_idp_mfa": True, "sso_accepted_amr": ["pwd", "pin", "kba", "mfa"]})
    assert P.mfa_trusted(stored, ["pwd"], None) is False
    assert P.mfa_trusted(stored, ["pwd", "pin", "kba"], None) is False
    assert P.mfa_trusted(stored, ["pwd", "mfa"], None) is True
    # In whatever letters a stored list holds it (a list written by hand, past the save's check).
    shouted = dict(stored, sso_accepted_amr=["PWD", "Pin", " kba ", "mfa"])
    assert P.mfa_trusted(shouted, ["PWD"], None) is False and P.mfa_trusted(shouted, ["Pin", " kba "], None) is False
    assert P.mfa_trusted(shouted, ["PWD", "mfa"], None) is True


@pytest.mark.parametrize("answer, verdict", [
    ({"groups": ["Vault Users", "Other"]}, None),
    ({"groups": [123]}, None),                                      # a numeric group id matches its string
    ({"groups": ["Other"]}, P.RESTRICTED),
    ({"groups": []}, P.RESTRICTED),                                 # the claim is there and names none of them
    ({"groups": None}, P.RESTRICTION_CLAIM_MISSING),
    ({"groups": None, "groups_overage": True}, P.RESTRICTION_CLAIM_MISSING),
    ({"groups": ["Vault Users"], "groups_overage": True}, P.RESTRICTION_CLAIM_MISSING),   # a marker is never trusted
])
def test_the_group_rule_and_the_overage_marker(answer, verdict):
    assert _judge({"sso_required_groups": ["Vault Users", "123"]}, **answer) == verdict


@pytest.mark.parametrize("mode, domains, answer, verdict", [
    ("allowlist", ["example.test"], {"email": "a@example.test", "email_verified": True}, None),
    ("allowlist", ["example.test"], {"email": "a@other.test", "email_verified": True}, P.RESTRICTED),
    ("allowlist", ["example.test"], {"email": "a@example.test", "email_verified": False}, P.RESTRICTION_CLAIM_MISSING),
    ("denylist", ["evil.test"], {"email": "a@x.evil.test", "email_verified": True}, P.RESTRICTED),
    ("denylist", ["evil.test"], {"email": "a@good.test", "email_verified": True}, None),
    ("off", ["example.test"], {}, None),                            # ticked but the list is off: nothing to judge
])
def test_the_sign_up_domain_list_as_a_restriction(mode, domains, answer, verdict):
    pol = {"signup_email_domain_mode": mode, "signup_email_domains": domains}
    assert _judge({"sso_use_signup_domains": True}, account_policy=pol, **answer) == verdict
    assert _judge({"sso_use_signup_domains": False}, account_policy=pol, **answer) is None


@pytest.mark.parametrize("stored, email, admitted", [
    ({}, "a@anywhere.test", True),
    ({"sso_allowed_domains": ["example.test"]}, "a@example.test", True),
    ({"sso_allowed_domains": ["example.test"]}, "a@Example.TEST", True),
    ({"sso_allowed_domains": ["example.test"]}, "a@victim.test", False),
    ({"sso_allowed_domains": ["example.test"]}, "a@sub.example.test", False),
    ({"sso_allowed_domains": ["example.test"]}, "a@evil.test@example.test", False),
    ({"sso_allowed_domains": ["example.test"]}, None, False),
])
def test_an_address_is_admitted_only_from_a_listed_domain(stored, email, admitted):
    assert P.address_admitted(P.effective(stored), email) is admitted


@pytest.mark.parametrize("stored, amr, acr, trusted", [
    ({}, ["pwd", "mfa"], "2", False),                                                    # nothing trusted by default
    ({"sso_trust_idp_mfa": True}, ["pwd", "mfa"], "2", False),                           # trust on, nothing accepted
    ({"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]}, ["pwd", "mfa"], None, True),
    ({"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]}, ["pwd"], None, False),
    ({"sso_trust_idp_mfa": True, "sso_accepted_acr": ["2"]}, [], "2", True),
    ({"sso_trust_idp_mfa": True, "sso_accepted_acr": ["2"]}, [], "1", False),
    ({"sso_trust_idp_mfa": False, "sso_accepted_amr": ["mfa"]}, ["mfa"], None, False),  # values without trust
    ({"sso_trust_idp_mfa": True, "sso_accepted_amr": ["mfa"]}, "mfa", None, False),      # a string is not a list
])
def test_the_providers_mfa_counts_only_when_trusted_and_an_accepted_value_is_there(stored, amr, acr, trusted):
    assert P.mfa_trusted(P.effective(stored), amr, acr) is trusted


def test_the_requested_acr_is_a_bounded_string():
    assert P.effective({"sso_requested_acr": "  urn:mace:incommon:iap:silver "})["sso_requested_acr"] == "urn:mace:incommon:iap:silver"
    assert P.effective({"sso_requested_acr": 7})["sso_requested_acr"] == ""
    assert len(P.effective({"sso_requested_acr": "x" * 400})["sso_requested_acr"]) == P.MAX_ITEM_LENGTH


def test_an_exclusion_wins_over_a_missing_claim():
    stored = {"sso_allowed_tenants": ["t-1"], "sso_required_groups": ["g"]}
    assert _judge(stored, tenant_id="t-2", groups=None) == P.RESTRICTED
    assert _judge(stored, tenant_id=None, groups=["other"]) == P.RESTRICTED
    assert _judge(stored, tenant_id=None, groups=None) == P.RESTRICTION_CLAIM_MISSING
    assert _judge(stored, tenant_id="t-1", groups=["g"]) is None


def test_a_tenant_the_issuer_already_names_restricts_nobody():
    """Entra's issuer names the tenant, and the vault takes tokens from that issuer alone: the same tenant on the
    list admits everybody the tenant lets sign in, guests it invited among them. Such a list is no restriction
    for making accounts or linking them by address; a tenant claim that is not in the issuer is one, and so are
    a domain and a group."""
    T = "8f0d6c3a-1111-4222-8333-444455556666"
    entra = f"https://login.microsoftonline.com/{T}/v2.0"
    external = f"https://contoso.ciamlogin.com/{T.upper()}/v2.0"
    legacy = f"https://sts.windows.net/{T}/"

    def policy(**more):
        return P.effective({"sso_allowed_tenants": [T], **more})
    for issuer in (entra, external, legacy, entra + "/", "  " + entra):
        assert P.tenants_the_issuer_names(policy(), issuer) == [T], issuer
        assert P.is_restricted(policy(), issuer=issuer) is False, issuer
        assert P.is_restricted(policy(sso_required_groups=["vault-users"]), issuer=issuer) is True
        assert P.is_restricted(policy(sso_allowed_domains=["example.org"]), issuer=issuer) is True
    # However the id is written on the list or in the issuer.
    assert P.tenants_the_issuer_names(P.effective({"sso_allowed_tenants": [T.upper()]}), entra) == [T.upper()]
    assert P.is_restricted(P.effective({"sso_allowed_tenants": [T.upper()]}), issuer=entra) is False
    # Another tenant beside it changes nothing: every token of this issuer carries the issuer's own.
    both = P.effective({"sso_allowed_tenants": ["another-tenant", T]})
    assert P.is_restricted(both, issuer=entra) is False
    # A tenant the issuer does not name is a rule of its own (a provider with one issuer for many tenants).
    for issuer in ("https://idp.example.org", "https://idp.example.org/realms/main", None, "", 7,
                   f"https://login.microsoftonline.com/{T[:-1]}/v2.0", f"https://{T}.example.org/v2.0"):
        assert P.tenants_the_issuer_names(policy(), issuer) == [], issuer
        assert P.is_restricted(policy(), issuer=issuer) is True, issuer
    assert P.is_restricted(policy()) is True                       # asked without an issuer: as the list says
    # The check of the person is unchanged: the tenant claim is still compared.
    assert _judge({"sso_allowed_tenants": [T]}, tenant_id="someone-else") == P.RESTRICTED
