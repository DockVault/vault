"""Per-account storage quotas: the deployment default, and the override an admin sets per user.

An account's quota is spent by ALLOCATING storage to vaults (and refunded when that storage is
reclaimed), so the override answers "how much may this person hand out", not "how much may they
store". Three states matter and are genuinely different: inherit the deployment default, an exact
budget, or exempt. Only an administrator may set any of them.
"""
import pytest

from conftest import ApiClient, unique

GIB = 1024 ** 3


def _client_for(user) -> ApiClient:
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


def _set_default_quota(admin, gb):
    r = admin.put("/settings", json={"default_user_quota": gb})
    assert r.status_code in (200, 204), r.text


@pytest.fixture(autouse=True)
def _restore_default_quota(admin):
    yield
    _set_default_quota(admin, 1000)


@pytest.fixture
def user(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


def _set_quota(admin, user_id, value):
    return admin.patch(f"/users/{user_id}", json={"storage_quota_gb": value})


def _storage(client, user_id):
    r = client.get(f"/users/{user_id}/storage")
    assert r.status_code == 200, r.text
    return r.json()


# --- the three states -----------------------------------------------------------------------

def test_a_new_account_inherits_the_deployment_default(admin, user):
    _set_default_quota(admin, 12)
    body = _storage(admin, user["id"])
    assert body["storage_quota_bytes"] is None        # no override stored
    assert body["effective_quota_bytes"] == 12 * GIB
    assert body["default_quota_bytes"] == 12 * GIB
    assert body["quota_source"] == "default"
    assert body["allocated_bytes"] == 0
    assert body["available_bytes"] == 12 * GIB


def test_an_override_beats_the_default_and_survives_a_change_to_it(admin, user):
    _set_default_quota(admin, 12)
    assert _set_quota(admin, user["id"], 3).status_code == 200
    assert _storage(admin, user["id"])["effective_quota_bytes"] == 3 * GIB

    _set_default_quota(admin, 40)                     # the default moves; the override does not
    body = _storage(admin, user["id"])
    assert body["effective_quota_bytes"] == 3 * GIB
    assert body["quota_source"] == "account"


def test_inherit_clears_the_override(admin, user):
    _set_default_quota(admin, 12)
    _set_quota(admin, user["id"], 3)
    assert _set_quota(admin, user["id"], "inherit").status_code == 200
    body = _storage(admin, user["id"])
    assert body["storage_quota_bytes"] is None
    assert body["effective_quota_bytes"] == 12 * GIB
    assert body["quota_source"] == "default"


def test_null_is_read_as_inherit(admin, user):
    """A cleared field in the admin UI sends null, which must mean 'follow the default' — not
    'no storage at all'."""
    _set_default_quota(admin, 12)
    _set_quota(admin, user["id"], 5)
    assert _set_quota(admin, user["id"], None).status_code == 200
    assert _storage(admin, user["id"])["storage_quota_bytes"] is None


def test_unlimited_exempts_the_account_from_the_default(admin, user):
    _set_default_quota(admin, 1)
    assert _set_quota(admin, user["id"], "unlimited").status_code == 200
    body = _storage(admin, user["id"])
    assert body["storage_quota_bytes"] == -1
    assert body["effective_quota_bytes"] is None
    assert body["available_bytes"] is None
    # The source names where the setting came from, not what it says: this exemption was set on
    # the account, so it stays "account" and the null effective quota carries the "no limit".
    assert body["quota_source"] == "account"

    client = _client_for(user)
    big = client.post("/vaults", json={"name": unique("unl"), "size_limit_gb": 50})
    if big.status_code == 403:
        pytest.skip("this deployment's default role can't create vaults")
    assert big.status_code == 200, big.text
    client.delete_vault(big.json()["id"])


def test_a_zero_quota_allows_no_allocation_at_all(admin, user):
    """0 is distinct from 'unset': an account that may hold no storage. It is the one value where
    the per-account field and the deployment default deliberately disagree in meaning."""
    _set_default_quota(admin, 100)
    assert _set_quota(admin, user["id"], 0).status_code == 200
    body = _storage(admin, user["id"])
    assert body["effective_quota_bytes"] == 0
    assert body["available_bytes"] == 0

    client = _client_for(user)
    # No 403 guard: the request below is what this test asserts on. Creating a vault is granted
    # to a fresh account in code, not by configuration, so a refusal here is a finding.
    r = client.post("/vaults", json={"name": unique("zero"), "size_limit_gb": 1})
    assert r.status_code == 400, r.text


# --- the override actually binds --------------------------------------------------------------

def test_the_override_bounds_what_the_account_can_allocate(admin, user):
    _set_default_quota(admin, 100)                     # roomy default...
    assert _set_quota(admin, user["id"], 2).status_code == 200   # ...but 2 GB for this account
    client = _client_for(user)

    # As above: the refusal being checked is the quota's, so a different refusal is a finding.
    over = client.post("/vaults", json={"name": unique("cap"), "size_limit_gb": 3})
    assert over.status_code == 400, over.text

    ok = client.post("/vaults", json={"name": unique("cap-ok"), "size_limit_gb": 2})
    assert ok.status_code == 200, ok.text
    try:
        # the budget is now spent, so a second vault of any size is refused
        assert client.post("/vaults", json={"name": unique("cap-2"), "size_limit_gb": 1}).status_code == 400
        account = client.get("/account/storage").json()
        assert account["account_quota_bytes"] == 2 * GIB
        assert account["reserved_bytes"] == 2 * GIB
        assert account["available_bytes"] == 0
        assert account["quota_source"] == "account"
    finally:
        client.delete_vault(ok.json()["id"])


def test_raising_the_override_immediately_unblocks_allocation(admin, user):
    _set_default_quota(admin, 100)
    _set_quota(admin, user["id"], 1)
    client = _client_for(user)
    first = client.post("/vaults", json={"name": unique("raise"), "size_limit_gb": 1})
    if first.status_code == 403:
        pytest.skip("this deployment's default role can't create vaults")
    assert first.status_code == 200, first.text
    vid = first.json()["id"]
    try:
        assert client.put(f"/vaults/{vid}/storage", json={"granted_bytes": 4 * GIB}).status_code == 400
        assert _set_quota(admin, user["id"], 5).status_code == 200
        assert client.put(f"/vaults/{vid}/storage", json={"granted_bytes": 4 * GIB}).status_code == 200
    finally:
        client.delete_vault(vid)


def test_allocated_bytes_follow_the_account_across_vaults_it_does_not_own(admin, user):
    """Storage this person contributed to somebody else's vault still counts against THEIR
    quota — that is what makes it theirs to reclaim."""
    _set_default_quota(admin, 100)
    owner = admin.create_user(role="user")
    try:
        oc = _client_for(owner)
        created = oc.post("/vaults", json={"name": unique("shared"), "size_limit_gb": 1})
        if created.status_code == 403:
            pytest.skip("this deployment's default role can't create vaults")
        vid = created.json()["id"]
        try:
            assert oc.post(f"/vaults/{vid}/permissions",
                           json={"user_id": user["id"], "level": "manage"}).status_code == 200
            _client_for(user).put(f"/vaults/{vid}/storage", json={"granted_bytes": 3 * GIB})
            assert _storage(admin, user["id"])["allocated_bytes"] == 3 * GIB
            assert _storage(admin, owner["id"])["allocated_bytes"] == GIB
        finally:
            oc.delete_vault(vid)
    finally:
        admin.delete_user(owner["id"])


def test_admins_are_reported_as_exempt(admin):
    me = admin.get("/users/me").json()
    body = _storage(admin, me["id"])
    assert body["budget_exempt"] is True
    assert body["effective_quota_bytes"] is None
    assert body["quota_source"] == "exempt"


# --- who may set it ----------------------------------------------------------------------------

def test_a_user_cannot_raise_their_own_quota(admin, user):
    """The whole point of a default would be lost if the person it constrains could edit it."""
    _set_default_quota(admin, 1)
    client = _client_for(user)
    r = client.patch(f"/users/{user['id']}", json={"storage_quota_gb": 500})
    # Either the endpoint is closed to them, or the field is ignored — never applied.
    assert r.status_code in (200, 403), r.text
    assert _storage(admin, user["id"])["storage_quota_bytes"] is None


def test_the_user_directory_view_stays_administrator_only(admin, user):
    """/users/{id}/storage sits behind the same USER_VIEW gate as the rest of the user directory,
    which a plain account does not hold — even for its own row. A user's own picture comes from
    /account/storage instead, and that one must work."""
    other = admin.create_user(role="user")
    try:
        client = _client_for(user)
        assert client.get(f"/users/{user['id']}/storage").status_code == 403
        assert client.get(f"/users/{other['id']}/storage").status_code == 403

        mine = client.get("/account/storage")
        assert mine.status_code == 200, mine.text
        assert "account_quota_bytes" in mine.json()
    finally:
        admin.delete_user(other["id"])


def test_an_anonymous_caller_is_refused(anon, user):
    assert anon.get(f"/users/{user['id']}/storage").status_code in (401, 403)


def test_storage_for_an_unknown_account_is_a_404(admin):
    assert admin.get("/users/00000000-0000-4000-8000-000000000000/storage").status_code == 404


# --- malformed input ----------------------------------------------------------------------------

@pytest.mark.parametrize("bad", [-5, "abc", True, [], {}, 10 ** 12])
def test_malformed_quotas_are_refused(admin, user, bad):
    r = _set_quota(admin, user["id"], bad)
    assert r.status_code in (400, 422), r.text
    assert _storage(admin, user["id"])["storage_quota_bytes"] is None


def test_the_user_response_carries_the_override(admin, user):
    assert _set_quota(admin, user["id"], 7).status_code == 200
    assert admin.get(f"/users/{user['id']}").json()["storage_quota_bytes"] == 7 * GIB


def test_omitting_the_field_leaves_the_quota_alone(admin, user):
    """An unrelated edit (email, role, active) must not silently clear a quota an admin set."""
    assert _set_quota(admin, user["id"], 9).status_code == 200
    assert admin.patch(f"/users/{user['id']}", json={"is_active": True}).status_code == 200
    assert _storage(admin, user["id"])["storage_quota_bytes"] == 9 * GIB
