"""An account may have no email; an address that IS present is strict, canonical, and unambiguous.

Three properties are under test, and they pull in different directions:

* **Optional** — an account can be created, read, listed and logged into with no address at all.
* **Strict** — anything actually supplied is a real address; "" and "nope" are refused.
* **Unambiguous** — `BOB@x.com` cannot coexist with `bob@x.com`, because once an address can
  identify a login, two accounts sharing one address is an impersonation vector.

Several tests here would pass trivially against the old code, so each says in its docstring what
makes it non-vacuous. The recurring trap in this area is a test that "creates an email-less user"
through a helper that quietly generates an address — the shared `create_user` helper did exactly
that until this change, so a passing suite proved nothing.
"""
import uuid

import pytest

from conftest import ApiClient

pytestmark = pytest.mark.integration

PASSWORD = "TestPassw0rd!123"


@pytest.fixture
def sweeper(admin):
    """Deletes every user a test created, even when the test fails midway."""
    created = []

    def track(user):
        if user and user.get("id"):
            created.append(user["id"])
        return user

    yield track

    for user_id in reversed(created):
        try:
            admin.delete_user(user_id)
        except Exception:
            pass


def _is_an_address_validation_refusal(response):
    """Whether the server refused the ADDRESS, as opposed to failing for any other reason.

    `email` is declared Optional[EmailStr], so a local part the validator will not accept comes
    back as a pydantic 422 whose error locations name the email field. Nothing else qualifies:
    a 400 is a business rule and a 500 is a defect, and reporting either as "this deployment
    cannot run the check" is how the case this test exists for would go unnoticed.
    """
    if response.status_code != 422:
        return False
    try:
        detail = response.json().get("detail")
    except ValueError:
        return False
    if not isinstance(detail, list):
        return False
    return any("email" in [str(part) for part in (entry.get("loc") or [])]
               for entry in detail if isinstance(entry, dict))


def _name(prefix="eo"):
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


# ---------------------------------------------------------------------------
# Optional
# ---------------------------------------------------------------------------

def test_a_user_can_be_created_with_no_email(admin, sweeper):
    """The headline behaviour.

    Non-vacuous because it asserts the STORED value is null, not merely that the request
    succeeded: a backend that silently substituted a placeholder address would still return 200.
    """
    user = sweeper(admin.create_user(email=None))
    assert user["email"] is None, f"expected no address, got {user['email']!r}"

    fetched = admin.get(f"/users/{user['id']}")
    assert fetched.status_code == 200
    assert fetched.json()["email"] is None, "the address came back non-null on re-read"


def test_two_email_less_accounts_can_coexist(admin, sweeper):
    """The regression that matters most on the create path.

    The duplicate check used to be one `or_(User.username == u, User.email == e)`. SQLAlchemy
    renders `col == None` as `IS NULL`, so with no address that clause matched the FIRST
    email-less row and the SECOND account was refused with "Email 'None' already exists".

    Creating ONE email-less user cannot catch that — the bug only appears from the second onward,
    which is exactly why this test creates two.
    """
    first = sweeper(admin.create_user(email=None))
    second = sweeper(admin.create_user(email=None))

    assert first["id"] != second["id"]
    assert first["email"] is None and second["email"] is None


def test_an_email_less_user_can_log_in(admin, sweeper):
    """Optional is worthless if the account cannot then be used.

    Username still identifies the account, so login must be unaffected by the absent address.
    """
    username = _name()
    sweeper(admin.create_user(username=username, email=None, password=PASSWORD))

    client = ApiClient()
    client.login(username, PASSWORD)
    assert client.get("/users/me").status_code == 200
    assert client.get("/users/me").json()["email"] is None


# ---------------------------------------------------------------------------
# Strict + canonical
# ---------------------------------------------------------------------------

def test_a_supplied_address_is_stored_lowercased(admin, sweeper):
    """Normalization on write.

    Asserting only that creation succeeds would pass without any normalization at all, so this
    pins the exact stored bytes.

    Scoped to LOWERCASING on purpose. The padding in the input is stripped by `EmailStr` before
    `normalize_email` ever sees it, so this cannot prove the trim -- the direct test below does.
    """
    user = sweeper(admin.create_user(email="  MiXeD.Case@Example.COM  "))
    assert user["email"] == "mixed.case@example.com", (
        f"address was not canonicalized on write: {user['email']!r}"
    )


@pytest.mark.parametrize("bad", ["not-an-email", "@example.com", "a@", "a b@example.com", ""])
def test_a_malformed_address_is_refused_on_create(admin, bad):
    """Optional must not become "anything goes".

    The empty string is in this list deliberately: it is the value a blank form field would send,
    and it must be refused rather than stored as an address that is neither absent nor valid.
    """
    r = admin.post("/users", json={
        "username": _name(), "email": bad, "password": PASSWORD, "role": "user",
    })
    assert r.status_code == 422, f"{bad!r} was accepted as an address ({r.status_code})"


def test_a_malformed_address_is_refused_on_self_update(admin):
    r = admin.patch("/users/me", json={"email": "not-an-email", "current_password": "x"})
    assert r.status_code == 422


def test_a_malformed_address_is_refused_on_admin_update(admin, sweeper):
    user = sweeper(admin.create_user())
    r = admin.patch(f"/users/{user['id']}", json={"email": "not-an-email"})
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# Unambiguous
# ---------------------------------------------------------------------------

def test_an_exact_duplicate_is_refused(admin, sweeper):
    address = f"{_name()}@example.com"
    sweeper(admin.create_user(email=address))

    r = admin.post("/users", json={
        "username": _name(), "email": address, "password": PASSWORD, "role": "user",
    })
    assert r.status_code == 400, f"an exact duplicate was accepted ({r.status_code})"


def test_a_case_variant_duplicate_is_refused(admin, sweeper):
    """The impersonation guard.

    Before this change `BOB@x.com` and `bob@x.com` were two accounts, because both the application
    check and the plain UNIQUE constraint compare case-sensitively. That is harmless while login is
    username-only and becomes an impersonation vector the moment an address can identify a login.
    """
    local = _name()
    sweeper(admin.create_user(email=f"{local}@example.com"))

    r = admin.post("/users", json={
        "username": _name(), "email": f"{local.upper()}@EXAMPLE.COM",
        "password": PASSWORD, "role": "user",
    })
    assert r.status_code == 400, (
        f"a case-variant duplicate was accepted ({r.status_code}) — two accounts now share one "
        f"address"
    )


def test_a_whitespace_padded_duplicate_is_refused(admin, sweeper):
    """A padded duplicate must not slip past the uniqueness check.

    Honest about what this proves: `EmailStr` strips before any of our code runs, so this exercises
    the schema and the check together, NOT our trimming -- removing `.strip()` from
    `normalize_email` leaves it green. The trim is still load-bearing for values that never pass
    through `EmailStr` (the seeded admin address), which is what the unit test below covers.
    """
    address = f"{_name()}@example.com"
    sweeper(admin.create_user(email=address))

    r = admin.post("/users", json={
        "username": _name(), "email": f"   {address}  ", "password": PASSWORD, "role": "user",
    })
    assert r.status_code in (400, 422), f"a padded duplicate was accepted ({r.status_code})"


def test_an_admin_update_cannot_mint_a_duplicate(admin, sweeper):
    """PATCH /users/{id} had NO uniqueness check at all — a pre-existing defect.

    The duplicate reached the database and surfaced as an uncaught IntegrityError 500. Asserting
    "not 200" would be satisfied by that 500, so this pins 400 specifically: the difference between
    a handled rejection and a crash is the whole point.
    """
    taken = f"{_name()}@example.com"
    sweeper(admin.create_user(email=taken))
    other = sweeper(admin.create_user())

    r = admin.patch(f"/users/{other['id']}", json={"email": taken})
    assert r.status_code == 400, f"expected a clean 400, got {r.status_code}"


def test_an_admin_update_cannot_mint_a_case_variant_duplicate(admin, sweeper):
    taken = f"{_name()}@example.com"
    sweeper(admin.create_user(email=taken))
    other = sweeper(admin.create_user())

    r = admin.patch(f"/users/{other['id']}", json={"email": taken.upper()})
    assert r.status_code == 400, f"a case-variant duplicate was accepted on update ({r.status_code})"


def test_reusing_an_accounts_own_address_is_not_a_self_collision(admin, sweeper):
    """The exclude-self leg of the uniqueness check.

    Without it, saving a profile without touching the address would reject itself — a check that is
    too strict is as broken as one that is too loose, and only this direction catches it.
    """
    user = sweeper(admin.create_user())
    r = admin.patch(f"/users/{user['id']}", json={"email": user["email"]})
    assert r.status_code == 200, f"an account collided with itself ({r.status_code})"


# ---------------------------------------------------------------------------
# Omit versus explicit null
# ---------------------------------------------------------------------------

def test_omitting_email_leaves_the_address_alone(admin, sweeper):
    """The control for the clearing test below.

    Without this pair, a backend that cleared the address on EVERY update would still pass the
    "explicit null clears it" test.
    """
    user = sweeper(admin.create_user())
    original = user["email"]

    r = admin.patch(f"/users/{user['id']}", json={"role": "user"})
    assert r.status_code == 200
    assert r.json()["email"] == original, "an unrelated update destroyed the address"


def test_an_explicit_null_clears_the_address(admin, sweeper):
    """Both handlers previously keyed on `is not None`, collapsing omit and null into one case, so
    an address could be replaced but never removed."""
    user = sweeper(admin.create_user())
    assert user["email"] is not None

    r = admin.patch(f"/users/{user['id']}", json={"email": None})
    assert r.status_code == 200, f"clearing was refused ({r.status_code}): {r.text[:200]}"
    assert r.json()["email"] is None

    assert admin.get(f"/users/{user['id']}").json()["email"] is None, "the clear did not persist"


def test_a_user_can_clear_their_own_address(admin, sweeper):
    """Self-service clearing, which is allowed while a username still identifies the account."""
    username = _name()
    sweeper(admin.create_user(username=username, password=PASSWORD))

    client = ApiClient()
    client.login(username, PASSWORD)

    r = client.patch("/users/me", json={"email": None, "current_password": PASSWORD})
    assert r.status_code == 200, f"self-clear refused ({r.status_code}): {r.text[:200]}"
    assert r.json()["email"] is None
    assert client.get("/users/me").json()["email"] is None


# ---------------------------------------------------------------------------
# Every read surface tolerates an absent address
# ---------------------------------------------------------------------------

def test_read_surfaces_do_not_500_on_an_email_less_account(admin, sweeper):
    """Six response models declared `email` as a required `str`.

    Pydantic does not coerce None into a bare `str`; it raises, and the raise is uncaught, so each
    of these endpoints returned 500 for an account with no address. A test that only created the
    user would never notice — the failure is on READ.
    """
    user = sweeper(admin.create_user(email=None))
    uid = user["id"]

    for label, response in [
        ("user detail", admin.get(f"/users/{uid}")),
        ("user list", admin.get("/users")),
        ("permissions view", admin.get(f"/permissions/users/{uid}")),
        ("management list", admin.get("/api/user-management/users")),
        ("management detail", admin.get(f"/api/user-management/users/{uid}")),
    ]:
        assert response.status_code != 500, (
            f"{label} returned 500 for an email-less account: {response.text[:200]}"
        )
        assert response.status_code < 400, f"{label} failed with {response.status_code}"


def test_the_email_less_account_actually_appears_in_the_list(admin, sweeper):
    """Guards the lazy fix for the test above.

    Filtering email-less accounts OUT of the listing would make every "does not 500" assertion
    pass while quietly hiding real users from the admin.
    """
    user = sweeper(admin.create_user(email=None))

    listed = admin.get("/users").json()
    ids = {row["id"] for row in listed}
    assert user["id"] in ids, "the email-less account was hidden from the user list"

    row = next(r for r in listed if r["id"] == user["id"])
    assert row["email"] is None


def test_normalize_email_trims_values_that_bypass_the_schema():
    """The trim only matters where `EmailStr` is not in the way.

    The seeded admin address is read straight from configuration and validated by nothing, so this
    is the path where trimming genuinely applies. Unlike the HTTP tests above, deleting `.strip()`
    makes this one fail.
    """
    from app.core.email_identity import normalize_email

    assert normalize_email("  Padded@Example.COM  ") == "padded@example.com"
    assert normalize_email("   ") is None, "whitespace-only must collapse to no-email, not to ''"
    assert normalize_email("") is None


def test_a_dotted_capital_i_cannot_create_a_twin_of_an_existing_address(admin, sweeper):
    """Python and Postgres do not fold U+0130 the same way, and that gap is exploitable.

    `'İ'.lower()` in Python is `i` PLUS a combining dot above (U+0307); Postgres's `lower()` gives
    a bare `i`. Fold the candidate in Python and the stored column in SQL and the two never match,
    so the duplicate check passes and the unique index -- keyed on the database's fold -- sees two
    different keys. Result: two accounts holding one address as printed, which is the exact
    impersonation case this whole area exists to prevent.

    Non-vacuous: revert `email_in_use` to comparing a Python-folded candidate against
    `func.lower(User.email)` and the second create returns 200 instead of 400.
    """
    local = f"{_name()}İx"
    first = admin.post("/users", json={
        "username": _name(), "email": f"{local}@example.com",
        "password": PASSWORD, "role": "user",
    })
    if _is_an_address_validation_refusal(first):
        pytest.skip(f"the address validator rejects this local part outright: {first.text[:120]}")
    assert first.status_code < 400, (
        "creating the first account failed for a reason that is not the address validator "
        "refusing this local part, so the fold below was never exercised. A 5xx here is the "
        f"impersonation path erroring out rather than being tested: {first.status_code} "
        f"{first.text[:200]}")
    sweeper(first.json())

    second = admin.post("/users", json={
        "username": _name(), "email": f"{local}@example.com",
        "password": PASSWORD, "role": "user",
    })
    assert second.status_code == 400, (
        f"a second account was created on the same printed address ({second.status_code}) -- the "
        f"two case-folding implementations disagree"
    )


# ---------------------------------------------------------------------------
# The user-management update path, which had no coverage at all
# ---------------------------------------------------------------------------

def test_the_management_update_path_reports_success_when_it_succeeds(admin, sweeper):
    """It committed the change and then returned 401.

    `get_user_detail` is wrapped by a permission decorator that reads `current_user` and `db` out
    of `**kwargs`; it was called positionally, so the wrapper saw None for both and raised 401 --
    after the update had already been written. A caller could not tell a real failure from this
    one, and nothing in the suite noticed because nothing tested this endpoint.
    """
    user = sweeper(admin.create_user())
    fresh = f"{_name()}@example.com"

    r = admin.put(f"/api/user-management/users/{user['id']}", json={"email": fresh})
    assert r.status_code == 200, (
        f"the management update returned {r.status_code} for a change that succeeded: "
        f"{r.text[:200]}"
    )
    assert r.json()["email"] == fresh
    assert admin.get(f"/users/{user['id']}").json()["email"] == fresh


def test_the_management_update_path_refuses_a_case_variant_duplicate(admin, sweeper):
    taken = f"{_name()}@example.com"
    sweeper(admin.create_user(email=taken))
    other = sweeper(admin.create_user())

    r = admin.put(f"/api/user-management/users/{other['id']}", json={"email": taken.upper()})
    assert r.status_code == 400, (
        f"the management path accepted a case-variant duplicate ({r.status_code})"
    )


def test_the_management_update_path_clears_on_an_explicit_null(admin, sweeper):
    user = sweeper(admin.create_user())
    assert user["email"] is not None

    r = admin.put(f"/api/user-management/users/{user['id']}", json={"email": None})
    assert r.status_code == 200, f"clearing was refused ({r.status_code}): {r.text[:200]}"
    assert admin.get(f"/users/{user['id']}").json()["email"] is None


def test_an_explicit_null_in_the_create_body_is_accepted(admin, sweeper):
    """The helper OMITS the key for an email-less account, so nothing else sends a literal null."""
    username = _name()
    r = admin.post("/users", json={
        "username": username, "email": None, "password": PASSWORD, "role": "user",
    })
    assert r.status_code < 400, f"an explicit null was rejected on create: {r.text[:200]}"
    sweeper(r.json())
    assert r.json()["email"] is None
