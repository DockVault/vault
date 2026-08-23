"""Live API acceptance for public self-signup (POST /auth/signup) and GET /auth/policy.

Covers: signup disabled -> 404; the enabled happy path (a self-signed account is a plain USER,
active, and can immediately log in); username taken; email taken; email case-variant taken;
malformed + multiple-'@' email -> 422; email required-vs-optional (absent creates a NULL-email
account); domain allow/deny incl. subdomain positives/negatives; uppercase-domain + whitespace
normalization; plus-addressing; unicode/IDN rejection (the ASCII decision that closes the homograph
gate mismatch); weak password; mass-assignment ignored (no admin/quota/active escalation from the
body); the per-username rate limit; and the /auth/policy minimal-key negative test (no domain lists,
invite settings, or SMTP/brand leak).

The settings row is global, so every test restores the keys it touches and deletes any account it
creates.
"""
import pytest

from conftest import BASE_URL, unique

pytestmark = pytest.mark.integration

ACCOUNT_KEYS = ("email_requirement", "invite_enabled", "invite_ttl_hours", "signup_enabled",
                "signup_email_domain_mode", "signup_email_domains", "login_identifier",
                "email_change_requires_verification")
PASSWORD_KEYS = ("password_min_length", "require_uppercase", "require_lowercase",
                 "require_numbers", "require_special")

STRONG_PW = "S1gnup-Passw0rd!"


@pytest.fixture
def restore_settings(admin):
    """Snapshot the account + password-policy keys these tests mutate and put them back afterwards."""
    before = admin.get("/settings").json()
    snap = {k: before.get(k) for k in (ACCOUNT_KEYS + PASSWORD_KEYS)}
    yield snap
    admin.put("/settings", json=snap)


def _set(admin, **kw):
    r = admin.put("/settings", json=kw)
    assert r.status_code == 200, r.text


def _enable_signup(admin, **overrides):
    """Turn signup on with a permissive baseline (email optional, username login, domain off)."""
    payload = {"signup_enabled": True, "email_requirement": "optional",
               "login_identifier": "username", "signup_email_domain_mode": "off",
               "signup_email_domains": []}
    payload.update(overrides)
    _set(admin, **payload)


def _cleanup(admin, *usernames):
    rows = admin.get("/users").json()
    by_name = {u.get("username"): u.get("id") for u in rows}
    for name in usernames:
        uid = by_name.get(name)
        if uid:
            admin.delete_user(uid)


def _signup(admin, body):
    return admin.clone_anonymous().post("/auth/signup", json=body)


def _find(admin, username):
    for u in admin.get("/users").json():
        if u.get("username") == username:
            return u
    return None


# ---- GET /auth/policy: minimal public surface --------------------------------------------------
def test_auth_policy_minimal_keys_and_no_leak(admin, restore_settings):
    # deliberately load the settings blob with things that MUST NOT leak to the login screen
    _set(admin, signup_enabled=True, login_identifier="either", email_requirement="required",
         invite_enabled=True, invite_ttl_hours=72,
         signup_email_domain_mode="denylist", signup_email_domains=["evil.com"],
         smtp_server="mail.example.com", from_email="vault@example.com")

    r = admin.clone_anonymous().get("/auth/policy")
    assert r.status_code == 200, r.text
    body = r.json()

    assert body["signup_enabled"] is True
    assert body["login_identifier"] == "either"
    assert body["email_requirement"] == "required"
    pp = body["password_policy"]
    assert isinstance(pp, dict) and "min_length" in pp
    for k in ("require_uppercase", "require_lowercase", "require_numbers", "require_special"):
        assert k in pp

    # NEGATIVE: none of the leak-sensitive keys may ride along (PUT /settings merges freely).
    for leaked in ("invite_enabled", "invite_ttl_hours", "signup_email_domain_mode",
                   "signup_email_domains", "email_change_requires_verification",
                   "smtp_server", "from_email", "smtp_password", "zero_knowledge_enabled",
                   "directory_search_scope", "rate_limit_api_enabled", "sharing_enabled"):
        assert leaked not in body, f"/auth/policy leaked {leaked!r}"


# ---- master switch -----------------------------------------------------------------------------
def test_signup_disabled_returns_404(admin, restore_settings):
    _set(admin, signup_enabled=False)
    r = _signup(admin, {"username": unique("nope"), "password": STRONG_PW})
    assert r.status_code == 404, r.text


# ---- happy path --------------------------------------------------------------------------------
def test_signup_happy_path_creates_active_plain_user(admin, restore_settings):
    _enable_signup(admin)
    name = unique("newbie")
    try:
        r = _signup(admin, {"username": name, "password": STRONG_PW,
                            "email": f"{name}@example.com"})
        assert r.status_code == 200, r.text
        assert r.json()["username"] == name

        # a self-signed account is a plain USER, active, and can log in immediately
        row = _find(admin, name)
        assert row is not None
        assert str(row.get("role")).lower() == "user"
        assert row.get("is_active") is True
        assert row.get("is_locked") in (False, None)

        anon = admin.clone_anonymous()
        assert anon.login(name, STRONG_PW), "self-signed account cannot log in"
    finally:
        _cleanup(admin, name)


def test_signup_email_absent_when_optional_creates_null_email(admin, restore_settings):
    _enable_signup(admin, email_requirement="optional", login_identifier="username")
    name = unique("noemail")
    try:
        r = _signup(admin, {"username": name, "password": STRONG_PW})
        assert r.status_code == 200, r.text
        row = _find(admin, name)
        assert row is not None
        assert not (row.get("email") or "")   # created with NO email
    finally:
        _cleanup(admin, name)


# ---- uniqueness --------------------------------------------------------------------------------
def test_signup_username_taken(admin, restore_settings):
    _enable_signup(admin)
    existing = admin.create_user(role="user")
    try:
        r = _signup(admin, {"username": existing["_username"], "password": STRONG_PW,
                            "email": f"{unique('e')}@example.com"})
        assert r.status_code == 400, r.text
    finally:
        _cleanup(admin, existing["_username"])


def test_signup_email_taken_including_case_variant(admin, restore_settings):
    _enable_signup(admin)
    addr = f"{unique('owner')}@example.com"
    existing = admin.create_user(role="user", email=addr)
    name = unique("dup")
    try:
        # exact
        r = _signup(admin, {"username": unique("d1"), "password": STRONG_PW, "email": addr})
        assert r.status_code == 400, r.text
        # case-variant of the SAME address collides through the folded uniqueness check
        variant = addr.upper()
        r2 = _signup(admin, {"username": name, "password": STRONG_PW, "email": variant})
        assert r2.status_code == 400, r2.text
    finally:
        _cleanup(admin, existing["_username"], name)


# ---- email shape (schema layer) ----------------------------------------------------------------
@pytest.mark.parametrize("bad_email", ["not-an-email", "a@b@example.com", "user@example"])
def test_signup_malformed_email_422(admin, restore_settings, bad_email):
    _enable_signup(admin)
    r = _signup(admin, {"username": unique("mal"), "password": STRONG_PW, "email": bad_email})
    assert r.status_code == 422, f"{bad_email!r} -> {r.status_code}: {r.text}"


def test_signup_email_required_missing_400(admin, restore_settings):
    _enable_signup(admin, email_requirement="required")
    r = _signup(admin, {"username": unique("req"), "password": STRONG_PW})
    assert r.status_code == 400, r.text


def test_signup_email_required_when_login_is_email(admin, restore_settings):
    # even with email_requirement 'optional', email login needs an address to sign in with
    _enable_signup(admin, email_requirement="optional", login_identifier="email")
    r = _signup(admin, {"username": unique("emx"), "password": STRONG_PW})
    assert r.status_code == 400, r.text


# ---- domain gate -------------------------------------------------------------------------------
def test_signup_denylist_blocks_domain_and_subdomain(admin, restore_settings):
    _enable_signup(admin, signup_email_domain_mode="denylist", signup_email_domains=["evil.com"])
    ok = unique("d_ok")
    try:
        assert _signup(admin, {"username": unique("d1"), "password": STRONG_PW,
                               "email": "x@evil.com"}).status_code == 400            # exact domain blocked
        assert _signup(admin, {"username": unique("d2"), "password": STRONG_PW,
                               "email": "x@sub.evil.com"}).status_code == 400        # subdomain blocked
        # notevil.com is NOT a subdomain of evil.com (the '.' boundary matters) -> allowed
        r = _signup(admin, {"username": ok, "password": STRONG_PW, "email": f"{ok}@notevil.com"})
        assert r.status_code == 200, r.text
    finally:
        _cleanup(admin, ok)


def test_signup_allowlist_is_exact_no_subdomains(admin, restore_settings):
    _enable_signup(admin, signup_email_domain_mode="allowlist", signup_email_domains=["acme.com"])
    hit, miss, sub = unique("a_hit"), unique("a_miss"), unique("a_sub")
    try:
        assert _signup(admin, {"username": hit, "password": STRONG_PW,
                               "email": f"{hit}@acme.com"}).status_code == 200
        assert _signup(admin, {"username": miss, "password": STRONG_PW,
                               "email": f"{miss}@other.com"}).status_code == 400
        assert _signup(admin, {"username": sub, "password": STRONG_PW,
                               "email": f"{sub}@sub.acme.com"}).status_code == 400   # subdomain NOT covered
    finally:
        _cleanup(admin, hit, miss, sub)


def test_signup_domain_uppercase_and_whitespace_normalized(admin, restore_settings):
    _enable_signup(admin, signup_email_domain_mode="allowlist", signup_email_domains=["acme.com"])
    name = unique("norm")
    try:
        r = _signup(admin, {"username": name, "password": STRONG_PW,
                            "email": f"  {name}@ACME.COM "})
        assert r.status_code == 200, r.text
    finally:
        _cleanup(admin, name)


def test_signup_plus_addressing_allowed(admin, restore_settings):
    _enable_signup(admin, signup_email_domain_mode="allowlist", signup_email_domains=["acme.com"])
    name = unique("plus")
    try:
        r = _signup(admin, {"username": name, "password": STRONG_PW,
                            "email": f"{name}+tag@acme.com"})
        assert r.status_code == 200, r.text
    finally:
        _cleanup(admin, name)


@pytest.mark.parametrize("idn_email", ["x@bücher.de", "x@evіl.com"])  # unicode IDN + Cyrillic homograph
def test_signup_unicode_idn_email_rejected_400(admin, restore_settings, idn_email):
    # ASCII-only signup: a unicode domain would slip the ASCII/punycode allow/deny gate. Homograph
    # of a denylisted domain must not get through either. EmailStr accepts these, so it is the
    # handler's ASCII gate that returns 400 (not a 422 schema rejection).
    _enable_signup(admin, signup_email_domain_mode="denylist", signup_email_domains=["evil.com"])
    r = _signup(admin, {"username": unique("idn"), "password": STRONG_PW, "email": idn_email})
    assert r.status_code == 400, f"{idn_email!r} -> {r.status_code}: {r.text}"


# ---- password policy ---------------------------------------------------------------------------
def test_signup_weak_password_400(admin, restore_settings):
    _enable_signup(admin)
    _set(admin, require_uppercase=True, require_numbers=True, password_min_length=10)
    # >= 8 chars (so it clears the schema floor) but violates the org policy
    r = _signup(admin, {"username": unique("weak"), "password": "alllowercase",
                        "email": f"{unique('w')}@example.com"})
    assert r.status_code == 400, r.text


def test_signup_short_password_422(admin, restore_settings):
    _enable_signup(admin)
    r = _signup(admin, {"username": unique("short"), "password": "a1B!",
                        "email": f"{unique('s')}@example.com"})
    assert r.status_code == 422, r.text   # under the model's 8-char floor


# ---- mass-assignment ---------------------------------------------------------------------------
def test_signup_mass_assignment_ignored(admin, restore_settings):
    _enable_signup(admin)
    name = unique("massass")
    try:
        r = _signup(admin, {
            "username": name, "password": STRONG_PW, "email": f"{name}@example.com",
            # none of these may take effect — they aren't fields on SignupRequest
            "role": "admin", "is_active": False, "is_locked": True,
            "storage_quota_gb": 999999, "created_by": "00000000-0000-0000-0000-000000000000",
        })
        assert r.status_code == 200, r.text
        row = _find(admin, name)
        assert row is not None
        assert str(row.get("role")).lower() == "user", "signup minted a non-user role"
        assert row.get("is_active") is True, "signup honored a body is_active=false"
        assert row.get("is_locked") in (False, None), "signup honored a body is_locked=true"
    finally:
        _cleanup(admin, name)


# ---- rate limit (per-username hard cap of 5/60s, testable even with the round's inflated caps) --
def test_signup_rate_limited_per_username(admin, restore_settings):
    _enable_signup(admin)
    name = unique("rl")
    codes = []
    try:
        for _ in range(6):
            codes.append(_signup(admin, {"username": name, "password": STRONG_PW,
                                         "email": f"{unique('rl')}@example.com"}).status_code)
        assert codes[0] == 200, codes
        assert 429 in codes, f"per-username throttle never fired: {codes}"
    finally:
        _cleanup(admin, name)


# ---- audit -------------------------------------------------------------------------------------
def test_signup_outcomes_are_audited(admin, restore_settings):
    _enable_signup(admin)
    name = unique("aud")
    try:
        assert _signup(admin, {"username": name, "password": STRONG_PW,
                               "email": f"{name}@example.com"}).status_code == 200
        _set(admin, signup_enabled=False)
        _signup(admin, {"username": unique("audx"), "password": STRONG_PW})  # a disabled failure
        r = admin.get("/audit/events", params={"limit": 100})
        if r.status_code != 200:
            pytest.skip("audit events endpoint unavailable")
        assert "account_self_signup" in r.text
    finally:
        _cleanup(admin, name)
