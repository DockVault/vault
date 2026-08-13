"""The vault storage-allocation ledger: who paid for a vault's size, and who may take it back.

A vault's size limit is the SUM of the allocations its owner and managers made out of their own
account quotas. These tests pin the properties that makes worth having:

* creating a vault opens the ledger with the creator holding the whole size;
* a manager can add storage to a SHARED vault out of their own budget;
* each contributor can reclaim exactly what they put in — never somebody else's share;
* a vault can never be shrunk below the bytes it already stores, or grown past the
  administrator's per-vault ceiling or the contributor's own quota.
"""
import pytest

from conftest import ApiClient, unique

GIB = 1024 ** 3


def _client_for(user) -> ApiClient:
    c = ApiClient()
    c.login(user["_username"], user["_password"])
    return c


def _grant_access(client, vid, user_id, level):
    return client.post(f"/vaults/{vid}/permissions", json={"user_id": user_id, "level": level})


def _upload(client, vault_id, name, content):
    return client.post(f"/vaults/{vault_id}/files",
                       files=[("files", (name, content, "text/plain"))])


def _set_quotas(admin, default_user_quota, max_vault_size):
    r = admin.put("/settings", json={"default_user_quota": default_user_quota,
                                     "max_vault_size": max_vault_size})
    assert r.status_code in (200, 204), r.text


@pytest.fixture(autouse=True)
def _generous_quotas(admin):
    """Leave the shared instance with roomy quotas after every test, so a failure mid-test can't
    strand a restriction that breaks the next file."""
    yield
    _set_quotas(admin, 1000, 1000)


@pytest.fixture
def owner(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def manager(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def reader(admin):
    u = admin.create_user(role="user")
    yield u
    admin.delete_user(u["id"])


@pytest.fixture
def owned_vault(admin, owner):
    """A 1 GB vault owned by a NON-admin, so the account budget actually applies (admins are
    exempt from it)."""
    client = _client_for(owner)
    r = client.post("/vaults", json={"name": unique("grant"), "size_limit_gb": 1})
    if r.status_code == 403:
        pytest.skip("this deployment's default role can't create vaults")
    assert r.status_code == 200, r.text
    vault = r.json()
    yield {"vault": vault, "client": client}
    client.delete_vault(vault["id"])


# --- the ledger opens with the creator holding everything ------------------------------------

def test_creating_a_vault_records_the_creator_as_the_sole_contributor(owned_vault, owner):
    vid = owned_vault["vault"]["id"]
    body = owned_vault["client"].get(f"/vaults/{vid}/storage").json()

    assert body["size_limit"] == GIB
    assert body["my_grant_bytes"] == GIB
    assert body["others_grant_bytes"] == 0
    assert body["can_contribute"] is True
    assert [c["user_id"] for c in body["contributors"]] == [owner["id"]]
    assert body["contributors"][0]["is_owner"] is True
    assert body["contributors"][0]["is_you"] is True


def test_the_account_counts_the_allocation_not_the_stored_bytes(owned_vault):
    """An empty vault still spends its owner's budget — that is what makes the storage
    reclaimable — even though it costs the DEPLOYMENT nothing."""
    account = owned_vault["client"].get("/account/storage").json()
    assert account["reserved_bytes"] == GIB


# --- the owner moving their own allocation ---------------------------------------------------

def test_owner_raises_and_lowers_their_own_allocation(owned_vault):
    vid, client = owned_vault["vault"]["id"], owned_vault["client"]

    up = client.put(f"/vaults/{vid}/storage", json={"granted_bytes": 4 * GIB})
    assert up.status_code == 200, up.text
    assert up.json()["size_limit"] == 4 * GIB
    assert client.get(f"/vaults/{vid}").json()["size_limit"] == 4 * GIB
    assert client.get("/account/storage").json()["reserved_bytes"] == 4 * GIB

    down = client.put(f"/vaults/{vid}/storage", json={"granted_bytes": 2 * GIB})
    assert down.status_code == 200, down.text
    assert down.json()["size_limit"] == 2 * GIB
    # the reclaimed 2 GB is available to this account again
    assert client.get("/account/storage").json()["reserved_bytes"] == 2 * GIB


def test_the_settings_patch_still_sets_the_total_and_keeps_the_ledger_in_step(owned_vault):
    """The older owner-facing spelling (PATCH .../settings {size_limit}) charges the difference
    to the owner's own allocation rather than inventing storage from nowhere."""
    vid, client = owned_vault["vault"]["id"], owned_vault["client"]
    r = client.patch(f"/vaults/{vid}/settings", json={"size_limit": 3 * GIB})
    assert r.status_code == 200, r.text
    body = client.get(f"/vaults/{vid}/storage").json()
    assert body["size_limit"] == 3 * GIB
    assert body["my_grant_bytes"] == 3 * GIB


def test_the_sole_contributor_cannot_withdraw_everything(owned_vault):
    vid, client = owned_vault["vault"]["id"], owned_vault["client"]
    r = client.put(f"/vaults/{vid}/storage", json={"granted_bytes": 0})
    assert r.status_code == 400, r.text
    assert "at least 1 byte" in r.text


def test_cannot_shrink_below_what_the_vault_already_stores(owned_vault):
    vid, client = owned_vault["vault"]["id"], owned_vault["client"]
    up = _upload(client, vid, unique("f") + ".txt", b"x" * 4096)
    assert up.status_code == 200, up.text

    r = client.put(f"/vaults/{vid}/storage", json={"granted_bytes": 1})
    assert r.status_code == 400, r.text
    assert "already stores" in r.text
    # ...while a limit at or above the stored bytes is fine
    assert client.put(f"/vaults/{vid}/storage", json={"granted_bytes": GIB}).status_code == 200


# --- a shared vault funded by more than one person -------------------------------------------

@pytest.fixture
def shared_vault(owned_vault, manager):
    """The owner's vault with a second person promoted to Manager — the multi-contributor case."""
    vid = owned_vault["vault"]["id"]
    r = _grant_access(owned_vault["client"], vid, manager["id"], "manage")
    assert r.status_code == 200, r.text
    return {"vault_id": vid, "owner_client": owned_vault["client"], "manager_client": _client_for(manager)}


def test_a_manager_contributes_storage_from_their_own_quota(shared_vault, manager, owner):
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]

    before = mc.get(f"/vaults/{vid}/storage").json()
    assert before["my_grant_bytes"] == 0
    assert before["others_grant_bytes"] == GIB
    assert before["can_contribute"] is True

    r = mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 5 * GIB})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["size_limit"] == 6 * GIB          # 1 GB owner + 5 GB manager
    assert body["my_grant_bytes"] == 5 * GIB
    assert body["others_grant_bytes"] == GIB

    # the manager's own account is what paid for it
    assert mc.get("/account/storage").json()["reserved_bytes"] == 5 * GIB
    assert shared_vault["owner_client"].get("/account/storage").json()["reserved_bytes"] == GIB

    contributors = {c["user_id"]: c["granted_bytes"]
                    for c in shared_vault["owner_client"].get(f"/vaults/{vid}/storage").json()["contributors"]}
    assert contributors == {owner["id"]: GIB, manager["id"]: 5 * GIB}


def test_a_manager_reclaims_exactly_what_they_gave(shared_vault):
    vid, mc = shared_vault["vault_id"], shared_vault["manager_client"]
    mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 5 * GIB})

    back = mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 0})
    assert back.status_code == 200, back.text
    assert back.json()["size_limit"] == GIB       # the owner's original allocation survives
    assert mc.get("/account/storage").json()["reserved_bytes"] == 0


def test_the_owner_cannot_shrink_a_shared_vault_by_cancelling_a_manager_contribution(shared_vault):
    vid = shared_vault["vault_id"]
    oc, mc = shared_vault["owner_client"], shared_vault["manager_client"]
    mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 5 * GIB})

    # The owner may reclaim their own 1 GB (total 6 -> 5) but not go under the manager's 5 GB.
    too_low = oc.patch(f"/vaults/{vid}/settings", json={"size_limit": 2 * GIB})
    assert too_low.status_code == 400, too_low.text
    assert "other contributors" in too_low.text.lower()

    ok = oc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 0})
    assert ok.status_code == 200, ok.text
    assert ok.json()["size_limit"] == 5 * GIB     # the manager's contribution stands alone


def test_simultaneous_contributions_all_survive(shared_vault):
    """Two people funding the same vault at the same instant is the case the ledger exists for.
    Each write is read-modify-write across two tables, so without serialization one writer's
    total can omit the other's row — and a later repair would then take the difference out of
    somebody's allocation. Every byte contributed must still be there afterwards."""
    import threading

    vid = shared_vault["vault_id"]
    oc, mc = shared_vault["owner_client"], shared_vault["manager_client"]
    results = {}

    def _put(name, client, amount):
        results[name] = client.put(f"/vaults/{vid}/storage", json={"granted_bytes": amount})

    threads = [threading.Thread(target=_put, args=("owner", oc, 2 * GIB)),
               threading.Thread(target=_put, args=("manager", mc, 5 * GIB))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=30)

    for name, r in results.items():
        assert r.status_code == 200, f"{name}: {r.text}"

    body = oc.get(f"/vaults/{vid}/storage").json()
    contributions = {c["username"]: c["granted_bytes"] for c in body["contributors"]}
    assert sorted(contributions.values()) == [2 * GIB, 5 * GIB]
    assert body["size_limit"] == 7 * GIB
    assert oc.get(f"/vaults/{vid}").json()["size_limit"] == 7 * GIB


def test_a_manager_cannot_move_somebody_elses_allocation(shared_vault):
    """PUT sets the CALLER's own share, so a manager raising theirs never touches the owner's."""
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]
    mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 2 * GIB})
    body = shared_vault["owner_client"].get(f"/vaults/{vid}/storage").json()
    assert body["my_grant_bytes"] == GIB          # untouched by the manager's write
    assert body["size_limit"] == 3 * GIB


# --- who may see and change what --------------------------------------------------------------

def test_a_plain_member_can_see_totals_but_not_who_paid_or_change_anything(owned_vault, reader):
    vid, oc = owned_vault["vault"]["id"], owned_vault["client"]
    assert _grant_access(oc, vid, reader["id"], "read").status_code == 200
    rc = _client_for(reader)

    body = rc.get(f"/vaults/{vid}/storage").json()
    assert body["size_limit"] == GIB
    assert body["my_grant_bytes"] == 0
    assert body["can_contribute"] is False
    assert "contributors" not in body            # who funded the vault is not a member's business

    r = rc.put(f"/vaults/{vid}/storage", json={"granted_bytes": GIB})
    assert r.status_code == 403, r.text


def test_a_stranger_cannot_read_or_change_vault_storage(owned_vault, reader):
    vid = owned_vault["vault"]["id"]
    rc = _client_for(reader)                      # granted nothing on this vault
    assert rc.get(f"/vaults/{vid}/storage").status_code in (403, 404)
    assert rc.put(f"/vaults/{vid}/storage", json={"granted_bytes": GIB}).status_code in (403, 404)


def test_an_anonymous_caller_is_refused(anon, owned_vault):
    vid = owned_vault["vault"]["id"]
    assert anon.get(f"/vaults/{vid}/storage").status_code in (401, 403)
    assert anon.put(f"/vaults/{vid}/storage", json={"granted_bytes": GIB}).status_code in (401, 403)


def test_a_temporary_credential_cannot_spend_the_account_budget(admin, owned_vault):
    """A temp credential outlives nothing: spending an account's storage budget would persist
    past the credential's time-box, so it needs an interactive session."""
    vid = owned_vault["vault"]["id"]
    # Minted from the ADMIN, whose own vault-storage writes would otherwise be allowed anywhere —
    # so a 403 here is the temp-session gate, not a missing permission. The default lifetime is
    # deliberate: a short-lived credential can expire midway through a later test that compares
    # before/after snapshots of the credential store, turning this into a flake somewhere else.
    r = admin.post("/auth/temp-credentials", json={})
    assert r.status_code == 200, r.text
    cred = r.json()
    tc = ApiClient()
    tc.login(cred["temp_username"], cred["credential"])

    resp = tc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 2 * GIB})
    assert resp.status_code == 403, resp.text
    # A temp session that CAN reach the vault is stopped by the interactive-session rule; one that
    # cannot is stopped earlier by scope. Either way it never spends an account's budget.
    assert owned_vault["client"].get(f"/vaults/{vid}").json()["size_limit"] == GIB


# --- the bounds an allocation has to respect --------------------------------------------------

def test_the_per_vault_ceiling_bounds_the_total_however_many_people_contribute(admin, shared_vault):
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]
    _set_quotas(admin, 1000, 3)                   # 3 GB per-vault ceiling, roomy accounts

    over = mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 3 * GIB})  # +1 GB owner = 4 GB
    assert over.status_code == 400, over.text
    assert "per vault" in over.text.lower()

    ok = mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 2 * GIB})    # exactly 3 GB total
    assert ok.status_code == 200, ok.text


def test_the_account_quota_bounds_what_one_contributor_can_give(admin, shared_vault):
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]
    _set_quotas(admin, 2, 1000)                   # 2 GB per account

    over = mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 3 * GIB})
    assert over.status_code == 400, over.text
    assert "quota" in over.text.lower()
    assert mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 2 * GIB}).status_code == 200


def test_a_ceiling_lowered_after_the_fact_still_lets_people_reclaim(admin, shared_vault):
    """An administrator tightening the per-vault maximum below an existing vault must not lock
    everyone's storage inside it — giving it back is the move that restores compliance."""
    vid = shared_vault["vault_id"]
    oc, mc = shared_vault["owner_client"], shared_vault["manager_client"]
    assert mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 5 * GIB}).status_code == 200

    _set_quotas(admin, 1000, 2)          # the vault is now 6 GB against a 2 GB ceiling

    back = mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 2 * GIB})
    assert back.status_code == 200, back.text
    assert back.json()["size_limit"] == 3 * GIB
    # ...but growing further past the ceiling is still refused.
    assert mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 6 * GIB}).status_code == 400
    assert oc.get(f"/vaults/{vid}/storage").json()["size_limit"] == 3 * GIB


def test_a_quota_cut_after_the_fact_still_lets_the_account_give_storage_back(admin, shared_vault):
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]
    assert mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 5 * GIB}).status_code == 200

    _set_quotas(admin, 1, 1000)          # the manager is now 4 GB over their own budget

    assert mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 1 * GIB}).status_code == 200
    assert mc.get("/account/storage").json()["reserved_bytes"] == GIB
    # and they cannot spend their way further over the budget
    assert mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 3 * GIB}).status_code == 400


def test_headroom_reported_for_a_contributor_accounts_for_the_others(admin, shared_vault):
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]
    _set_quotas(admin, 4, 1000)                   # 4 GB account budget, no per-vault ceiling

    body = mc.get(f"/vaults/{vid}/storage").json()
    assert body["my_max_grant_bytes"] == 4 * GIB          # the manager's whole budget
    assert body["max_total_bytes"] == 5 * GIB             # plus the owner's 1 GB already in
    assert body["account_quota_bytes"] == 4 * GIB


def test_the_vault_ceiling_caps_the_reported_headroom(admin, shared_vault):
    vid = shared_vault["vault_id"]
    mc = shared_vault["manager_client"]
    _set_quotas(admin, 1000, 2)                   # 2 GB per vault, of which the owner holds 1

    body = mc.get(f"/vaults/{vid}/storage").json()
    assert body["max_total_bytes"] == 2 * GIB
    assert body["my_max_grant_bytes"] == GIB


# --- malformed input ---------------------------------------------------------------------------

@pytest.mark.parametrize("payload", [
    {"granted_bytes": -1},
    {"granted_bytes": "lots"},
    {"granted_bytes": None},
    {"granted_bytes": 2 ** 63},      # past the BigInteger column
    {},                              # the field is required
    {"granted_gb": 5},               # no undeclared spellings
])
def test_malformed_allocations_are_refused(owned_vault, payload):
    vid, client = owned_vault["vault"]["id"], owned_vault["client"]
    r = client.put(f"/vaults/{vid}/storage", json=payload)
    assert r.status_code in (400, 422), r.text
    # whatever was rejected, the vault keeps the size it had
    assert client.get(f"/vaults/{vid}").json()["size_limit"] == GIB


def test_a_boolean_is_not_a_byte_count(owned_vault):
    vid, client = owned_vault["vault"]["id"], owned_vault["client"]
    r = client.put(f"/vaults/{vid}/storage", json={"granted_bytes": True})
    assert r.status_code in (400, 422), r.text


def test_storage_for_an_unknown_vault_is_a_404(owned_vault):
    client = owned_vault["client"]
    missing = "00000000-0000-4000-8000-000000000000"
    assert client.get(f"/vaults/{missing}/storage").status_code in (403, 404)


# --- deleting the vault returns the storage ----------------------------------------------------

def test_deleting_a_vault_returns_every_contributor_their_storage(shared_vault, admin, owner, manager):
    vid = shared_vault["vault_id"]
    oc, mc = shared_vault["owner_client"], shared_vault["manager_client"]
    mc.put(f"/vaults/{vid}/storage", json={"granted_bytes": 5 * GIB})
    assert mc.get("/account/storage").json()["reserved_bytes"] == 5 * GIB

    assert oc.delete_vault(vid).status_code in (200, 204)

    assert mc.get("/account/storage").json()["reserved_bytes"] == 0
    assert oc.get("/account/storage").json()["reserved_bytes"] == 0
