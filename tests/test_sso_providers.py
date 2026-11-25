"""The rules of the single sign-on providers an administrator configures (app/services/sso_providers.py,
app/core/sso_policy.validate, app/core/sso_presets.py): what a save may hold, field by field; what the pages are
shown (never the client secret); the fingerprint that says whether the last test sign-in still speaks for the
connection; when a provider may be turned on; when it may be removed; and what turning password sign-in off and on
does to the linked accounts (no reset link is minted for anyone). Offline: a throwaway SQLite database."""
import json
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

pytestmark = pytest.mark.unit

BASE = "https://vault.example.test"
ISSUER = "https://login.example.org/tenant/v2.0"


@pytest.fixture
def P(monkeypatch):
    set_bare_api_env()
    import app.api.api_server  # noqa: F401 -- the models and the secret key are set up as the server sets them
    from app.core import public_url
    from app.services import sso_providers
    monkeypatch.setattr(public_url, "public_base_url", lambda: BASE)
    return sso_providers


@pytest.fixture
def db(P):
    from app.core.models import ExternalIdentity, Group, SsoGroupMapping, SsoProvider, User
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'sso.db'}")
        for model in (User, SsoProvider, ExternalIdentity, Group, SsoGroupMapping):
            model.__table__.create(engine)
        session = sessionmaker(bind=engine, autocommit=False, autoflush=True)()
        yield session
        session.close()
        engine.dispose()


def _user(db, name, role="user", **extra):
    from app.core.models import RoleEnum, User
    user = User(username=name, password_hash="x", role=RoleEnum(role), is_active=True, is_locked=False, **extra)
    db.add(user)
    db.commit()
    return user


def _link(db, user, row, **extra):
    from app.core.models import ExternalIdentity
    identity = ExternalIdentity(user_id=user.id, provider_id=row.id, issuer=ISSUER, subject=uuid.uuid4().hex,
                                subject_source="oidc:sub", linked_by="self", **extra)
    db.add(identity)
    db.commit()
    return identity


def _ready(P, db, name="entra", **extra):
    """A provider with its connection filled in and a test sign-in that passed with it."""
    row = P.create(db, name=name)
    P.apply(db, row, P.clean({"issuer": ISSUER, "client_id": "client-1", "client_secret": "s3cret", **extra}), None)
    row.last_test = {"outcome": "ok", "auth_time_present": True, "config": P.fingerprint(row)}
    db.commit()
    return row


# --------------------------------------------------------------------------- what a save may hold

def test_a_save_takes_only_the_fields_it_knows_each_of_its_own_shape(P):
    good = {"name": "  Entra  ", "label": " Company sign-in ", "icon": "microsoft", "sort_order": 3,
            "show_on_sign_in": False, "private_network": False, "issuer": " " + ISSUER + " ",
            "discovery_url": "https://login.example.org/tenant/v2.0/.well-known/openid-configuration",
            "client_id": " client-1 ", "client_secret": "s3cret", "token_auth": "client_secret_post",
            "scopes": "openid  email profile email", "claims": {"groups": "roles", "tenant": " tid ", "name": ""}}
    assert P.clean(good) == {
        "name": "Entra", "label": "Company sign-in", "icon": "microsoft", "sort_order": 3, "show_on_sign_in": False,
        "private_network": False, "issuer": ISSUER,
        "discovery_url": "https://login.example.org/tenant/v2.0/.well-known/openid-configuration",
        "client_id": "client-1", "client_secret": "s3cret", "token_auth": "client_secret_post",
        "scopes": "openid email profile", "claims": {"groups": "roles", "tenant": "tid"}}
    assert P.clean({}) == {}
    assert P.clean({"label": "  ", "discovery_url": None, "claims": {}, "client_secret": ""}) == {
        "label": None, "discovery_url": None, "claims": None}      # emptied; an empty secret keeps the stored one
    assert P.clean({"icon": None}) == {"icon": None}


@pytest.mark.parametrize("field, value", [
    ("name", ""), ("name", "x" * 61), ("name", 7), ("name", "bad\x00name"), ("label", "x" * 61), ("label", 3),
    ("icon", "skull"), ("sort_order", -1), ("sort_order", 1000), ("sort_order", True), ("sort_order", "1"),
    ("show_on_sign_in", "yes"), ("private_network", 1),
    ("issuer", "http://login.example.org"), ("issuer", "https://localhost/realm"), ("issuer", "https://10.0.0.5/x"),
    ("issuer", "https://user:pw@login.example.org"), ("issuer", "https://login.example.org/x?y=1"),
    ("issuer", "https://login.example.org/x#frag"), ("issuer", ""), ("issuer", "https://" + "a" * 250 + ".org"),
    ("discovery_url", "ftp://login.example.org/doc"), ("discovery_url", "https://idp.internal/doc"),
    ("client_id", ""), ("client_id", "x" * 256), ("client_secret", " padded "), ("client_secret", "x" * 2049),
    ("client_secret", 5), ("token_auth", "private_key_jwt"), ("token_auth", None),
    ("scopes", "profile email"), ("scopes", "openid bad\"scope"), ("scopes", ""), ("scopes", ["openid"]),
    ("claims", ["groups"]), ("claims", {"subject": "sub"}), ("claims", {"groups": "has space"}),
    ("claims", {"groups": 4}),
])
def test_a_value_of_the_wrong_shape_is_refused_by_its_field_name(P, field, value):
    with pytest.raises(P.Invalid) as refused:
        P.clean({field: value})
    assert refused.value.field == field and str(refused.value)


def test_every_field_and_policy_setting_has_a_name_a_refusal_can_say(P):
    from app.core import sso_policy
    wanted = {*P.FIELDS, "preset", *("policy." + key for key in sso_policy.DEFAULTS)} - {"policy"}
    assert set(P.LABELS) == wanted
    assert all(label and label[0].isupper() and not label.endswith(".") for label in P.LABELS.values())
    assert P.Invalid("issuer", "The endpoint must use https.").said == "Issuer: The endpoint must use https."
    assert P.Invalid("made_up", "Unknown field.").said == "Unknown field."


def test_an_unknown_field_is_refused_and_so_is_anything_that_is_not_a_set_of_fields(P):
    for body in ({"client_secret_enc": "x"}, {"state": "enabled"}, {"last_test": {}}, {"id": "1"}, {"kind": "saml"}):
        with pytest.raises(P.Invalid) as refused:
            P.clean(body)
        assert refused.value.field == next(iter(body)) and str(refused.value) == "Unknown field."
    with pytest.raises(P.Invalid):
        P.clean(["name"])


def test_a_provider_inside_the_network_needs_the_setting_and_keeps_needing_it(P, db):
    inside = "https://keycloak.internal/realms/staff"
    with pytest.raises(P.Invalid):
        P.clean({"issuer": inside})
    assert P.clean({"issuer": inside, "private_network": True})["issuer"] == inside
    assert P.clean({"issuer": "https://10.0.0.5/realms/staff", "private_network": True})
    row = P.create(db, name="kc")
    P.apply(db, row, P.clean({"issuer": inside, "private_network": True}), None)
    assert P.clean({"discovery_url": "https://keycloak.internal/doc"}, row=row)      # the row already allows it
    with pytest.raises(P.Invalid) as refused:                                        # turned off under a private issuer
        P.clean({"private_network": False}, row=row)
    assert refused.value.field == "private_network" and "issuer" in str(refused.value)
    assert P.clean({"private_network": False, "issuer": ISSUER}, row=row)            # moved outside in the same save


def test_the_policy_is_checked_strictly_at_a_save(P):
    from app.core import sso_policy
    cleaned = P.clean({"policy": {
        "sso_account_creation": "jit", "sso_default_role": "external", "sso_password_login": "disabled",
        "sso_link_by_email": True, "sso_freshness_days": 0, "sso_requested_acr": "  urn:mfa  ",
        "sso_allowed_tenants": [" T-1 ", "t-1", "", "T-2"], "sso_allowed_domains": ["Example.ORG", "example.org "],
        "sso_required_groups": ["Vault Users", "Vault Users", "staff", "Staff"], "sso_accepted_amr": ["mfa", "hwk"]}})
    assert cleaned["policy"] == {
        "sso_account_creation": "jit", "sso_default_role": "external", "sso_password_login": "disabled",
        "sso_link_by_email": True, "sso_freshness_days": 0, "sso_requested_acr": "urn:mfa",
        "sso_allowed_tenants": ["T-1", "T-2"], "sso_allowed_domains": ["example.org"],
        "sso_required_groups": ["Vault Users", "staff", "Staff"], "sso_accepted_amr": ["mfa", "hwk"]}
    # A group's name is compared exactly with the token's, so two that differ by case are two; a tenant or a
    # domain is one whatever its case.
    bad = [("sso_account_creation", "always"), ("sso_default_role", "admin"), ("sso_password_login", "off"),
           ("sso_link_by_email", "yes"), ("sso_trust_idp_mfa", 1), ("sso_freshness_days", 366),
           ("sso_freshness_days", -1), ("sso_freshness_days", True), ("sso_freshness_days", "30"),
           ("sso_allowed_tenants", "t-1"), ("sso_allowed_tenants", [1]), ("sso_allowed_tenants", ["has space"]),
           ("sso_allowed_domains", ["not a domain"]), ("sso_allowed_domains", ["user@example.org"]),
           ("sso_allowed_domains", ["https://example.org"]), ("sso_required_groups", ["x" * 256]),
           ("sso_required_groups", ["bad\x07group"]), ("sso_accepted_acr", ["a b"]),
           ("sso_allowed_tenants", ["t"] * 0 + [f"t-{i}" for i in range(201)]), ("sso_requested_acr", 5),
           ("sso_made_up", True)]
    for key, value in bad:
        with pytest.raises(P.Invalid) as refused:
            P.clean({"policy": {key: value}})
        assert refused.value.field == "policy." + key, (key, value)
    with pytest.raises(P.Invalid) as refused:
        P.clean({"policy": ["sso_link_by_email"]})
    assert refused.value.field == "policy.policy"
    assert set(sso_policy.validate({k: v for k, v in sso_policy.DEFAULTS.items()})) == set(sso_policy.DEFAULTS)


# --------------------------------------------------------------------------- a draft, and the presets

def test_a_new_provider_is_a_draft_filled_in_from_its_preset(P, db):
    from app.core import sso_presets
    admin = _user(db, "root", role="admin")
    row = P.create(db, name="  Entra ", preset_id="entra", by=admin)
    db.commit()
    assert (row.name, row.state, row.kind, row.icon, row.scopes) == ("Entra", "draft", "oidc", "microsoft",
                                                                     "openid profile email")
    assert row.claims == {"tenant": "tid", "groups": "groups"} and row.policy is None
    assert row.show_on_sign_in is True and row.created_by == admin.id and row.created_by_name == "root"
    assert row.client_secret_enc is None and row.issuer is None
    assert not P.configured(row) and not P.tested(row)
    plain = P.create(db, name="other")
    assert (plain.icon, plain.claims) == ("generic", None)
    okta = P.create(db, name="okta", preset_id="okta")
    assert okta.scopes == "openid profile email groups"
    # A preset's values are copies: a row never changes the list.
    row.claims["tenant"] = "changed"
    assert sso_presets.get("entra")["claims"]["tenant"] == "tid"


def test_a_name_is_taken_once_whatever_its_case_and_a_vault_holds_twenty(P, db):
    P.create(db, name="Entra")
    db.commit()
    for name in ("entra", " ENTRA "):
        with pytest.raises(P.Conflict) as refused:
            P.new(db, name=name)
        assert refused.value.reason == P.NAME_TAKEN
    with pytest.raises(P.Invalid) as refused:
        P.new(db, name="x", preset_id="made-up")
    assert refused.value.field == "preset"
    with pytest.raises(P.Invalid):
        P.new(db, name="")
    for i in range(P.MAX_PROVIDERS - 1):
        P.create(db, name=f"p{i}")
    db.commit()
    with pytest.raises(P.Conflict) as refused:
        P.new(db, name="one too many")
    assert refused.value.reason == P.TOO_MANY


def test_the_presets_are_what_the_wizard_needs(P):
    from app.core import sso_presets
    listed = sso_presets.public()
    assert [p["id"] for p in listed] == ["entra", "google", "okta", "keycloak", "authentik", "oidc"]
    assert sso_presets.IDS == tuple(p["id"] for p in listed) and sso_presets.get("nope") is None
    from app.core import sso_policy
    for preset in listed:
        assert preset["icon"] in P.ICONS and "openid" in preset["scopes"].split()
        assert set(preset["claims"]) <= set(P.CLAIM_KEYS)
        assert preset["restriction"] in ("", *sso_policy._LISTS)
        assert preset["issuer_example"].startswith("https://") and preset["console"] and preset["issuer_help"]
        assert P.clean({"scopes": preset["scopes"], "claims": preset["claims"], "icon": preset["icon"]})
    listed[0]["claims"]["tenant"] = "changed"
    assert sso_presets.get("entra")["claims"]["tenant"] == "tid"


# --------------------------------------------------------------------------- what is written, and what is shown

def test_a_save_writes_the_fields_and_keeps_the_secret_encrypted(P, db):
    from app.core.security import decrypt_secret
    row = P.create(db, name="entra")
    out = P.apply(db, row, P.clean({"issuer": ISSUER, "client_id": "client-1", "client_secret": "s3cret",
                                    "label": "Company sign-in"}), None)
    db.commit()
    assert out == {"changed": ["label", "issuer", "client_id", "client_secret"], "connection_changed": True,
                   "secret_cleared": False, "made_sso_only": [], "restored": []}
    assert row.client_secret_enc and "s3cret" not in row.client_secret_enc
    assert decrypt_secret(row.client_secret_enc) == "s3cret"
    assert P.configured(row)
    # The same values again change nothing; a label or an order is not the connection.
    assert P.apply(db, row, P.clean({"issuer": ISSUER, "client_id": "client-1"}), None)["changed"] == []
    out = P.apply(db, row, P.clean({"label": "Staff", "sort_order": 2, "show_on_sign_in": False}), None)
    assert out["changed"] == ["label", "sort_order", "show_on_sign_in"] and out["connection_changed"] is False


def test_the_page_is_never_shown_the_secret(P, db):
    row = _ready(P, db)
    alice = _user(db, "alice", sso_only=True)
    bob = _user(db, "bob")
    _link(db, alice, row)
    _link(db, bob, row, refused_at=datetime(2026, 11, 1))
    shown = P.public(db, row)
    text = json.dumps(shown)
    assert "s3cret" not in text and row.client_secret_enc not in text and "client_secret_enc" not in text
    assert shown["has_client_secret"] is True and shown["client_id"] == "client-1" and shown["issuer"] == ISSUER
    assert shown["state"] == "draft" and shown["configured"] is True and shown["tested"] is True
    assert shown["last_test"] == {"outcome": "ok", "auth_time_present": True}      # the fingerprint stays inside
    assert shown["addresses"] == {"redirect_uri": f"{BASE}/auth/sso/{row.id}/callback",
                                  "backchannel_logout_uri": f"{BASE}/auth/sso/{row.id}/backchannel-logout",
                                  "post_logout_redirect_uri": f"{BASE}/", "sign_in_link": f"{BASE}/?sso={row.id}"}
    assert (shown["identities"], shown["sso_only_accounts"], shown["refusals"]) == (2, 1, 1)
    assert shown["policy"]["sso_password_login"] == "allowed" and shown["policy"]["sso_freshness_days"] == 30
    assert shown["token_auth"] == "client_secret_basic" and shown["claims"] == {} and shown["created_by"] is None
    assert shown["reauth_offered"] is False                    # a draft confirms nobody


def test_without_an_address_there_are_no_addresses_to_copy(P, db, monkeypatch):
    from app.core import public_url
    row = _ready(P, db)
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    assert P.addresses(row) is None and P.public(db, row)["addresses"] is None


def test_the_fingerprint_follows_the_connection_and_nothing_else(P, db):
    row = _ready(P, db)
    first = P.fingerprint(row)
    assert len(first) == 32 and P.tested(row)
    for change in ({"label": "Staff"}, {"sort_order": 5}, {"show_on_sign_in": False}, {"name": "renamed"}):
        P.apply(db, row, P.clean(change), None)
        assert P.fingerprint(row) == first, change
    row.state = "enabled"
    row.policy = {"sso_freshness_days": 7}
    assert P.fingerprint(row) == first and P.tested(row)
    seen = {first}
    for change in ({"issuer": ISSUER + "/"}, {"discovery_url": "https://login.example.org/doc"},
                   {"private_network": True},
                   {"client_id": "client-2"}, {"client_secret": "another"}, {"token_auth": "client_secret_post"},
                   {"scopes": "openid email"}, {"claims": {"groups": "roles"}}):
        out = P.apply(db, row, P.clean(change, row=row), None)
        assert out["connection_changed"] is True, change
        now = P.fingerprint(row)
        assert now not in seen, change
        seen.add(now)
        assert not P.tested(row)             # the last test spoke for the connection as it was
    # The secret enters only as a digest of its stored form.
    assert "another" not in "".join(seen) and row.client_secret_enc not in "".join(seen)


def test_pointing_a_provider_somewhere_else_drops_the_stored_secret(P, db):
    """The secret was entered for the place the provider was then, and a test sign-in posts it to the token endpoint
    of wherever the provider points now. So a change of the issuer, the discovery address or the private-network
    switch without a new secret drops the stored one: whoever points the provider elsewhere enters it themselves,
    and nobody learns a secret they never entered."""
    from app.core.security import decrypt_secret
    moves = ({"issuer": ISSUER + "/other"},
             {"discovery_url": "https://elsewhere.example.org/.well-known/openid-configuration"},
             {"private_network": True})
    for n, change in enumerate(moves):
        row = _ready(P, db, name=f"moved-{n}")
        out = P.apply(db, row, P.clean(change, row=row), None)
        assert out["secret_cleared"] is True and row.client_secret_enc is None, change
        assert not P.configured(row) and not P.tested(row), change
        assert P.enable_refusal(db, row).reason == P.NOT_CONFIGURED
    # A new secret in the same change is the one kept.
    row = _ready(P, db, name="moved-with-secret")
    out = P.apply(db, row, P.clean({"issuer": ISSUER + "/other", "client_secret": "the-new-one"}, row=row), None)
    assert out["secret_cleared"] is False and decrypt_secret(row.client_secret_enc) == "the-new-one"
    # What does not say where the provider is leaves the secret alone.
    stays = ({"client_id": "client-2"}, {"token_auth": "client_secret_post"}, {"scopes": "openid email"},
             {"claims": {"groups": "roles"}}, {"label": "Staff"}, {"issuer": ISSUER})
    for n, change in enumerate(stays):
        row = _ready(P, db, name=f"stays-{n}")
        out = P.apply(db, row, P.clean(change, row=row), None)
        assert out["secret_cleared"] is False and decrypt_secret(row.client_secret_enc) == "s3cret", change


def test_turning_a_provider_off_holds_the_accounts_whose_sign_in_there_had_lapsed(P, db):
    """Before a provider is turned off, each identity whose window has already run out is recorded as held: the
    provider is not removed while it holds one (a removal would lift the pause unseen), and it is lifted as a refusal
    is. An identity still inside its window, and one already refused, are left as they are; the days of the first go
    on counting while the provider is off, and it is held in its turn when they have run out."""
    from datetime import timedelta
    from app.services import sso_freshness as F
    now = datetime.utcnow()
    row = _ready(P, db)
    row.state = "enabled"
    row.policy = {"sso_freshness_days": 7}
    gone = _link(db, _user(db, "gone"), row, last_sign_in_at=now - timedelta(days=30), linked_at=now - timedelta(days=60))
    here = _link(db, _user(db, "here"), row, last_sign_in_at=now - timedelta(days=1), linked_at=now - timedelta(days=60))
    refused_at = now - timedelta(days=2)
    out = _link(db, _user(db, "out"), row, last_sign_in_at=now - timedelta(days=3), linked_at=now - timedelta(days=60),
                refused_at=refused_at)
    assert F.deadline_of(gone, row).due <= now and not F.deadline_of(gone, row).refused
    assert P.hold_lapsed(db, row, now=now) == 1
    assert gone.refused_at == now and here.refused_at is None and out.refused_at == refused_at
    row.state = "disabled"
    held = F.deadline_of(gone, row)
    assert held is not None and held.refused                    # paused though the provider is off
    inside = F.deadline_of(here, row)                            # inside its window when the provider went off
    assert inside is not None and not inside.refused and now < inside.due <= now + timedelta(days=7)
    assert P.remove_refusal(db, row).reason == P.REFUSALS_IN_FORCE
    assert P.hold_lapsed(db, row, now=now) == 0                  # nothing more to hold today
    later = now + timedelta(days=8)                              # its days ran out while the provider was off
    # Off, and its days close the other ways in: a hold would end a password the days do not end while it is
    # off. None is written, and the count says who stands in the way of a removal.
    assert P.hold_lapsed(db, row, now=later) == 0 and here.refused_at is None
    assert P.days_ran_out(db, row, now=later) == 1 and P.days_ran_out(db, row, now=now) == 0
    # Where the days only pause keys, the hold is written as ever.
    row.policy = {"sso_freshness_days": 7, "sso_lapse_ends_sign_in": False}
    assert P.hold_lapsed(db, row, now=later) == 1 and here.refused_at == later
    assert P.days_ran_out(db, row, now=later) == 0               # held now: counted as a refusal, not twice
    here.refused_at = None
    row.policy = {"sso_freshness_days": 7}
    # A provider that asks for no window holds nobody.
    other = _ready(P, db, name="no-window")
    other.state = "enabled"
    other.policy = {"sso_freshness_days": 0}
    _link(db, _user(db, "anyone"), other, last_sign_in_at=now - timedelta(days=400), linked_at=now - timedelta(days=500))
    assert P.hold_lapsed(db, other, now=now) == 0


def test_tested_means_a_passed_test_of_the_connection_as_it_is(P, db):
    row = _ready(P, db)
    assert P.tested(row)
    for last in (None, {}, "ok", {"outcome": "ok"}, {"outcome": "ok", "config": ""},
                 {"outcome": "refused", "config": P.fingerprint(row)}, {"outcome": "ok", "config": "0" * 32}):
        row.last_test = last
        assert not P.tested(row), last


# --------------------------------------------------------------------------- the policy's rules

def test_accounts_are_made_or_linked_by_email_only_for_a_provider_that_says_who_may_sign_in(P, db):
    row = _ready(P, db)
    for change in ({"sso_account_creation": "jit"}, {"sso_link_by_email": True}):
        with pytest.raises(P.Conflict) as refused:
            P.check(db, row, P.clean({"policy": change}))
        assert refused.value.reason == P.NEEDS_RESTRICTION
        for restriction in ({"sso_allowed_tenants": ["t-1"]}, {"sso_allowed_domains": ["example.org"]},
                            {"sso_required_groups": ["staff"]}):
            stored = P.check(db, row, P.clean({"policy": {**change, **restriction}}))
            assert stored == {**change, **restriction}
    # The sign-up domain allow-list counts when the administrator ticked it, and only an allow-list with entries.
    ticked = P.clean({"policy": {"sso_account_creation": "jit", "sso_use_signup_domains": True}})
    with pytest.raises(P.Conflict):
        P.check(db, row, ticked, account_policy={"signup_email_domain_mode": "denylist", "signup_email_domains": ["x.org"]})
    assert P.check(db, row, ticked, account_policy={"signup_email_domain_mode": "allowlist",
                                                    "signup_email_domains": ["example.org"]})
    # A restriction already stored counts, and taking it away under a rule that needs it is refused.
    P.apply(db, row, {}, {"sso_allowed_tenants": ["t-1"], "sso_account_creation": "jit"})
    assert P.check(db, row, P.clean({"policy": {"sso_link_by_email": True}})) == {
        "sso_allowed_tenants": ["t-1"], "sso_account_creation": "jit", "sso_link_by_email": True}
    with pytest.raises(P.Conflict):
        P.check(db, row, P.clean({"policy": {"sso_allowed_tenants": []}}))
    assert P.check(db, row, P.clean({"label": "x"})) is None        # no policy in the save: nothing to store


def test_password_sign_in_is_turned_off_and_on_for_the_linked_accounts_and_no_link_is_minted(P, db, monkeypatch):
    import app.api.api_server as S
    minted = []
    monkeypatch.setattr(S, "_mint_reset_link", lambda *a, **kw: minted.append(a) or "https://x/?reset=t")
    row = _ready(P, db)
    root, alice, bob = _user(db, "root", role="admin"), _user(db, "alice"), _user(db, "bob")
    carol = _user(db, "carol")                               # not linked: never touched
    for user in (root, alice, bob):
        _link(db, user, row)
    off = P.clean({"policy": {"sso_password_login": "disabled"}})
    with pytest.raises(P.Conflict) as refused:
        P.check(db, row, off)
    assert refused.value.reason == P.PRIVILEGED_LINKED and "root (an administrator)" in str(refused.value)
    assert alice.sso_only in (None, False)                   # judged, nothing changed
    from app.core.models import ExternalIdentity
    db.query(ExternalIdentity).filter(ExternalIdentity.user_id == root.id).delete()
    db.commit()
    out = P.apply(db, row, off, P.check(db, row, off))
    db.commit()
    assert out["changed"] == ["policy.sso_password_login"] and out["connection_changed"] is False
    assert out["made_sso_only"] == ["alice", "bob"] and out["restored"] == []
    assert alice.sso_only is True and bob.sso_only is True and alice.sftp_password_auth is False
    assert alice.password_hash != "x" and carol.sso_only in (None, False) and carol.password_hash == "x"
    # Saved again as it is: nothing to do, and the privileged check is not asked a second time.
    again = P.apply(db, row, off, P.check(db, row, off))
    assert again["changed"] == [] and again["made_sso_only"] == []
    unknown = alice.password_hash
    on = P.clean({"policy": {"sso_password_login": "allowed"}})
    out = P.apply(db, row, on, P.check(db, row, on))
    db.commit()
    assert out["restored"] == ["alice", "bob"] and out["made_sso_only"] == []
    assert alice.sso_only is False and alice.password_hash not in ("x", unknown)
    assert minted == []                                       # each person asks for their own link, or gets one made


# --------------------------------------------------------------------------- on, off, removed

def test_a_provider_is_turned_on_only_configured_tested_and_with_an_address(P, db, monkeypatch):
    from app.core import public_url
    from app.services import sso_sign_in
    draft = P.create(db, name="draft")
    db.commit()
    assert P.enable_refusal(db, draft).reason == P.NOT_CONFIGURED
    row = _ready(P, db)
    assert P.enable_refusal(db, row) is None
    monkeypatch.setattr(public_url, "public_base_url", lambda: "")
    refusal = P.enable_refusal(db, row)
    assert refusal.reason == sso_sign_in.NO_PUBLIC_ADDRESS
    assert str(refusal).startswith("Single sign-on needs the vault's public address. ")
    monkeypatch.setattr(public_url, "public_base_url", lambda: BASE)
    P.apply(db, row, P.clean({"client_id": "client-2"}), None)      # the connection moved on from its test
    refusal = P.enable_refusal(db, row)
    assert refusal.reason == P.NOT_TESTED and "test sign-in" in str(refusal)
    row.last_test = {"outcome": "ok", "config": P.fingerprint(row)}
    assert P.enable_refusal(db, row) is None
    # Password sign-in off for it, and an administrator linked meanwhile: not turned on over them.
    row.policy = {"sso_password_login": "disabled"}
    _link(db, _user(db, "root", role="admin"), row)
    assert P.enable_refusal(db, row).reason == P.PRIVILEGED_LINKED


def test_a_provider_is_removed_only_when_nothing_depends_on_it(P, db):
    row = _ready(P, db)
    row.state = "enabled"
    assert P.remove_refusal(db, row).reason == P.STILL_ON
    row.state = "disabled"
    assert P.remove_refusal(db, row) is None
    alice, bob = _user(db, "alice", sso_only=True), _user(db, "bob")
    link = _link(db, alice, row)
    # The account holds no password because of another provider it is linked to: nothing of this one is in the way.
    assert P.remove_refusal(db, row) is None
    row.policy = {"sso_password_login": "disabled"}
    refusal = P.remove_refusal(db, row)
    assert refusal.reason == P.ONLY_WAY_IN
    assert str(refusal) == ("1 account linked to this provider holds no password because of it. Allow password sign-in "
                            "for this provider first (Access), so they can set one.")
    row.policy = None
    alice.sso_only = False
    held = _link(db, bob, row, refused_at=datetime(2026, 11, 1))
    refusal = P.remove_refusal(db, row)
    assert refusal.reason == P.REFUSALS_IN_FORCE and str(refusal).startswith("1 account is held by a refusal")
    assert P.public(db, row)["refusals"] == 1
    # The person answered it since: the provider admitted a later sign-in. The stamp stays where it is (nothing
    # clears it), and it holds nobody: it is not counted and does not stand in the way. A sign-in from before the
    # refusal, or at the same moment, answers nothing.
    for last, in_force in ((datetime(2026, 10, 1), True), (datetime(2026, 11, 1), True), (datetime(2026, 11, 2), False)):
        held.last_sign_in_at = last
        db.commit()
        refusal = P.remove_refusal(db, row)
        assert (refusal is not None and refusal.reason == P.REFUSALS_IN_FORCE) is in_force, last
        assert P.public(db, row)["refusals"] == (1 if in_force else 0), last
    assert held.refused_at == datetime(2026, 11, 1)
    held.last_sign_in_at = None
    db.commit()
    assert P.remove_refusal(db, row).reason == P.REFUSALS_IN_FORCE
    held.refused_at = None
    db.commit()
    assert P.remove_refusal(db, row) is None and link.id is not None
    for state in ("draft", "disabled"):
        row.state = state
        assert P.remove_refusal(db, row) is None


def test_accounts_are_not_made_or_linked_on_a_tenant_the_issuer_already_names(P, db):
    """The Entra preset as an administrator fills it in: the tenant's id in the issuer and on the tenant list. That
    list keeps nobody out, so it does not open account creation at a first sign-in or the link by address; the
    refusal says why and what does. A required group opens both. A change of the issuer alone is judged too."""
    T = "8f0d6c3a-1111-4222-8333-444455556666"
    row = _ready(P, db)
    row.issuer = f"https://login.microsoftonline.com/{T}/v2.0"
    db.commit()
    for wanted in ({"sso_account_creation": "jit"}, {"sso_link_by_email": True}):
        with pytest.raises(P.Conflict) as refused:
            P.check(db, row, P.clean({"policy": {"sso_allowed_tenants": [T], **wanted}}))
        assert refused.value.reason == P.NEEDS_RESTRICTION
        assert "The tenant entered is the one the issuer already names: it keeps nobody out" in str(refused.value)
        assert "Require a group" in str(refused.value)
        stored = P.check(db, row, P.clean({"policy": {"sso_allowed_tenants": [T], "sso_required_groups": ["staff"],
                                                      **wanted}}))
        assert stored["sso_required_groups"] == ["staff"]
    # A provider whose issuer names no tenant: the tenant list is a rule, as before, and the plain sentence.
    other = _ready(P, db, name="other")
    assert P.check(db, other, P.clean({"policy": {"sso_allowed_tenants": [T], "sso_account_creation": "jit"}}))
    with pytest.raises(P.Conflict) as refused:
        P.check(db, other, P.clean({"policy": {"sso_account_creation": "jit"}}))
    assert "already names" not in str(refused.value)
    # Pointed at the tenant's own issuer afterwards: refused, though the policy is not touched.
    P.apply(db, other, {}, {"sso_allowed_tenants": [T], "sso_account_creation": "jit"})
    db.commit()
    with pytest.raises(P.Conflict) as refused:
        P.check(db, other, {"issuer": f"https://login.microsoftonline.com/{T}/v2.0"})
    assert refused.value.reason == P.NEEDS_RESTRICTION
    assert P.check(db, other, {"issuer": "https://idp.example.org/other"}) is None


def test_the_entra_preset_says_what_keeps_guests_out():
    from app.core import sso_presets
    entra = sso_presets.get("entra")
    assert entra["restriction"] == "sso_required_groups"
    assert "keeps nobody out" in entra["restriction_help"] and "guests" in entra["restriction_help"]
    assert "“Assignment required” to Yes" in entra["console"]
    assert "only your organisation's accounts sign in" not in str(entra)


def test_a_providers_shape_counts_the_groups_it_maps(P, db):
    """How many of its groups are mapped to a department or a role, for the list of providers: its own, counted
    by the database."""
    import types
    from app.core.models import SsoGroupMapping
    by = types.SimpleNamespace(id=None, username="root")
    row, other = P.create(db, name="Contoso", preset_id=None, by=by), P.create(db, name="Fabrikam", preset_id=None, by=by)
    db.flush()
    assert P.public(db, row)["group_mappings"] == 0
    for provider, group in ((row, "staff"), (row, "finance"), (other, "staff")):
        db.add(SsoGroupMapping(id=uuid.uuid4(), provider_id=provider.id, provider_group=group, role="user"))
    db.flush()
    assert P.public(db, row)["group_mappings"] == 2 and P.public(db, other)["group_mappings"] == 1
