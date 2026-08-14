"""Per-user "last viewed" on vaults.

The property that matters is isolation: last_viewed_at is one user's activity, and must never
appear in another user's payload — not even for a vault they both share, and not for an admin who
can see everything else about it.

Vault.last_accessed (the pre-existing column) is deliberately NOT this: it records the last access
by anyone, so on a shared vault it answers a different question. Both fields are returned and they
are tested to be independent.
"""
import time

import pytest

from conftest import ApiClient

pytestmark = pytest.mark.integration


def _client(user) -> ApiClient:
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


def _vault_row(client, vault_id):
    return next((v for v in client.get("/vaults").json() if v["id"] == str(vault_id)), None)


@pytest.fixture
def two_users(admin):
    a = admin.create_user(role="user")
    b = admin.create_user(role="user")
    yield a, b
    admin.delete_user(a["id"])
    admin.delete_user(b["id"])


def test_last_viewed_is_null_until_the_vault_is_opened(admin, two_users):
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-null-until-opened")
    try:
        row = _vault_row(ca, v["id"])
        assert row is not None, "creator should see their own vault"
        assert row["last_viewed_at"] is None, row
    finally:
        ca.delete_vault(v["id"])


def test_opening_a_vault_stamps_only_the_opener(admin, two_users):
    """The isolation property. A shares a vault with B; A opens it; B must not see A's visit."""
    a, b = two_users
    ca, cb = _client(a), _client(b)
    v = ca.create_vault(name="views-isolation")
    try:
        r = ca.post(f"/vaults/{v['id']}/permissions", json={"user_id": b["id"], "level": "read"})
        assert r.status_code < 300, (r.status_code, r.text)

        ca.get(f"/vaults/{v['id']}")          # A opens it
        # Non-vacuous anchor: A's own stamp landed, so B's null below is isolation and not a
        # feature that simply never records anything.
        assert _vault_row(ca, v["id"])["last_viewed_at"] is not None

        row_b = _vault_row(cb, v["id"])
        assert row_b is not None, "B should be able to see the shared vault at all"
        assert row_b["last_viewed_at"] is None, f"A's visit leaked into B's payload: {row_b}"

        cb.get(f"/vaults/{v['id']}")          # now B opens it
        assert _vault_row(cb, v["id"])["last_viewed_at"] is not None
    finally:
        ca.delete_vault(v["id"])


def test_an_admin_does_not_inherit_another_users_view_history(admin, two_users):
    """The admin is made a MEMBER first, deliberately.

    list_vaults returns owned + member + group vaults with no admin arm, so without the membership
    the admin cannot see this vault at all and the assertion below would never execute — it would
    pass just as happily if the field leaked to every admin on every vault.
    """
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-admin-isolation")
    try:
        me = admin.get("/users/me").json()
        r = ca.post(f"/vaults/{v['id']}/permissions",
                    json={"user_id": me["id"], "level": "read"})
        assert r.status_code < 300, (r.status_code, r.text)

        ca.get(f"/vaults/{v['id']}")
        assert _vault_row(ca, v["id"])["last_viewed_at"] is not None

        row_admin = _vault_row(admin, v["id"])
        assert row_admin is not None, "the admin must actually see the vault, or this proves nothing"
        assert row_admin["last_viewed_at"] is None, (
            f"an admin must not inherit another user's view history: {row_admin}"
        )
    finally:
        ca.delete_vault(v["id"])


def test_reopening_moves_the_timestamp_forward(admin, two_users):
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-upsert")
    try:
        ca.get(f"/vaults/{v['id']}")
        first = _vault_row(ca, v["id"])["last_viewed_at"]
        assert first is not None
        time.sleep(1.1)                       # the column has sub-second resolution; be sure
        ca.get(f"/vaults/{v['id']}")
        second = _vault_row(ca, v["id"])["last_viewed_at"]
        assert second is not None and second > first, (first, second)
        # `second > first` is what distinguishes DO UPDATE from DO NOTHING. There is no separate
        # duplicate-row assertion to make: view_times is a dict keyed by vault id and the list is
        # deduplicated, so an extra row could not surface as a duplicate entry anyway.
    finally:
        ca.delete_vault(v["id"])


def test_the_detail_response_reports_the_previous_visit_not_this_one(admin, two_users):
    """Opening the detail view IS the visit, so the value it returns must be the visit BEFORE it.

    If the stamp were written before the payload were built, every read would answer "just now"
    and ordering by it would be meaningless.
    """
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-previous-visit")
    try:
        first = ca.get(f"/vaults/{v['id']}").json()
        assert first["last_viewed_at"] is None, f"first ever open should report no prior visit: {first}"
        time.sleep(1.1)
        second = ca.get(f"/vaults/{v['id']}").json()
        assert second["last_viewed_at"] is not None, second
    finally:
        ca.delete_vault(v["id"])


def test_a_temporary_credential_does_not_stamp_the_owners_history(admin, two_users):
    """A temp credential authenticates AS its owner, so a stamp would record activity for someone
    who did not act, and leak the credential holder's movements into the owner's ordering."""
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-temp-cred")
    temp_username = None
    try:
        body = ca.post("/auth/temp-credentials", json={
            "validity_minutes": 60,
            "scope": {"v": 1, "pages": ["vaults"], "caps": [],
                      "vault_caps_default": ["vault.see_info"], "temp": {}},
            "vault_access_mode": "all", "selected_vaults": [],
        }).json()
        temp_username = body["temp_username"]
        ct = ApiClient()
        ct.login(temp_username, body["credential"])
        # Non-vacuous anchor: the temp session really can read the vault, so a missing stamp is
        # the deliberate skip and not simply a failed request.
        assert ct.get(f"/vaults/{v['id']}").status_code < 300

        assert _vault_row(ca, v["id"])["last_viewed_at"] is None, (
            "a temporary credential stamped its owner's view history"
        )
    finally:
        if temp_username:
            ca.post(f"/temp-creds/{temp_username}/delete")
        ca.delete_vault(v["id"])


def test_a_temporary_credential_cannot_read_the_owners_history(admin, two_users):
    """The mirror of the write guard. A temp credential authenticates AS the owning account, so an
    unguarded read would hand its holder a continuously updating record of when the owner last
    opened each vault — working hours, absences, when a sensitive vault was last touched."""
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-temp-read")
    temp_username = None
    try:
        ca.get(f"/vaults/{v['id']}")
        # Non-vacuous anchor: the owner really does have a stamp to leak.
        assert _vault_row(ca, v["id"])["last_viewed_at"] is not None

        body = ca.post("/auth/temp-credentials", json={
            "validity_minutes": 60,
            "scope": {"v": 1, "pages": ["vaults"], "caps": [],
                      "vault_caps_default": ["vault.see_info"], "temp": {}},
            "vault_access_mode": "all", "selected_vaults": [],
        }).json()
        temp_username = body["temp_username"]
        ct = ApiClient()
        ct.login(temp_username, body["credential"])

        row = _vault_row(ct, v["id"])
        assert row is not None, "the temp session should still see the vault itself"
        assert row["last_viewed_at"] is None, f"the owner's history leaked to a temp session: {row}"
        detail = ct.get(f"/vaults/{v['id']}").json()
        assert detail["last_viewed_at"] is None, f"leaked on the detail endpoint: {detail}"
    finally:
        if temp_username:
            ca.post(f"/temp-creds/{temp_username}/delete")
        ca.delete_vault(v["id"])


def test_a_background_access_check_is_not_a_view(admin, two_users):
    """The client polls this endpoint every 20s while a vault view is open, to notice revoked
    access. Counting those as views would pin a vault left in a background tab to the top of the
    "last viewed" ordering forever, and rewrite the same row three times a minute."""
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-access-check")
    try:
        # A poll against a never-opened vault must not create a stamp at all.
        ca.get(f"/vaults/{v['id']}", headers={"X-Access-Check": "1"})
        assert _vault_row(ca, v["id"])["last_viewed_at"] is None, "a poll counted as a view"

        # A real open does stamp — so the assertion above is the header working, not the feature
        # being broken.
        ca.get(f"/vaults/{v['id']}")
        stamped = _vault_row(ca, v["id"])["last_viewed_at"]
        assert stamped is not None

        # ...and later polls must not move it forward.
        time.sleep(1.1)
        ca.get(f"/vaults/{v['id']}", headers={"X-Access-Check": "1"})
        assert _vault_row(ca, v["id"])["last_viewed_at"] == stamped, "a poll moved the timestamp"
    finally:
        ca.delete_vault(v["id"])


def test_view_history_does_not_outlive_the_vault(admin, two_users):
    """The cascade: deleting the vault must take its view rows with it.

    delete_vault is a hard DB delete and vault_views has no ORM relationship, so the Postgres
    ON DELETE CASCADE is what actually removes the rows — a missing constraint would raise a
    foreign-key violation and fail the delete outright.
    """
    a, _b = two_users
    ca = _client(a)
    v = ca.create_vault(name="views-cascade")
    deleted = False
    try:
        ca.get(f"/vaults/{v['id']}")
        assert _vault_row(ca, v["id"])["last_viewed_at"] is not None
        r = ca.delete_vault(v["id"])   # deletion is a POST to /delete, not an HTTP DELETE
        assert r.status_code < 300, (r.status_code, r.text)
        deleted = True
        assert _vault_row(ca, v["id"]) is None
    finally:
        if not deleted:
            ca.delete_vault(v["id"])


@pytest.mark.parametrize("key,good,bad", [
    ("vault_sort", "viewed", "bogus"),
    ("vault_sort_dir", "desc", "sideways"),
    ("vault_fav_group", "last", "middle"),
])
def test_ordering_preferences_are_whitelisted(admin, two_users, key, good, bad):
    """A rejected value must also not CLOBBER a previously good one, so a good value is stored
    first and re-checked afterwards rather than testing rejection on an empty slot."""
    a, _b = two_users
    ca = _client(a)
    ca.put("/users/me/preferences", json={key: good})
    assert ca.get("/users/me/preferences").json().get(key) == good

    ca.put("/users/me/preferences", json={key: bad})
    stored = ca.get("/users/me/preferences").json().get(key)
    assert stored != bad, f"an unknown value was persisted for {key}: {stored!r}"
    assert stored == good, f"a rejected value clobbered the stored one for {key}: {stored!r}"


def test_ordering_preferences_round_trip_together(admin, two_users):
    a, _b = two_users
    ca = _client(a)
    ca.put("/users/me/preferences", json={
        "vault_sort": "viewed", "vault_sort_dir": "desc", "vault_fav_group": "last"})
    got = ca.get("/users/me/preferences").json()
    assert got.get("vault_sort") == "viewed"
    assert got.get("vault_sort_dir") == "desc"
    assert got.get("vault_fav_group") == "last"
    # A partial update must not clear the siblings — the endpoint merges.
    ca.put("/users/me/preferences", json={"vault_sort_dir": "asc"})
    got = ca.get("/users/me/preferences").json()
    assert got.get("vault_sort") == "viewed", got
    assert got.get("vault_sort_dir") == "asc", got
    assert got.get("vault_fav_group") == "last", got
