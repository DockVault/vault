"""Per-vault size + account-budget enforcement (the reservation model).

A vault carries a declared size_limit (default 10 GB, bounded by the per-vault ceiling). Two admin settings bound it: max_vault_size
(GB) is the hard per-vault ceiling; default_user_quota (GB) is a per-account budget that the SUM of
an owner's declared vault sizes must stay under. Admins are bounded by the per-vault ceiling but
exempt from the account budget.
"""
import pytest

GIB = 1024 ** 3


def _get_settings(admin):
    return admin.get("/settings").json()


def _set_quotas(admin, default_user_quota, max_vault_size):
    r = admin.put("/settings", json={"default_user_quota": default_user_quota,
                                     "max_vault_size": max_vault_size})
    assert r.status_code in (200, 204), r.text


def _reset_quotas(admin):
    # generous ceilings so no leftover restriction leaks into another test on the shared instance
    _set_quotas(admin, 1000, 1000)


def test_create_vault_default_size_is_10gb(admin):
    v = admin.create_vault(name="qsize-default")
    try:
        got = admin.get(f"/vaults/{v['id']}").json()
        assert got["size_limit"] == 10 * GIB
    finally:
        admin.delete_vault(v["id"])


def test_a_size_less_create_fits_under_a_ceiling_below_the_default(admin):
    """A caller who names no size gets the default, bounded by what they may have.

    The default rose from 1 GB (to 5 GB, then 10 GB). When it first rose, on a deployment whose
    per-vault ceiling was under it, every create that did not name a size — the API, the desktop
    app, anything not typing a number into the dialog — was refused with "5 GB exceeds 1 GB", for a
    size the caller never asked for. Only an EXPLICIT request above the ceiling is a mistake worth
    refusing.
    """
    _set_quotas(admin, 1000, 1)  # 1 GB ceiling, under the 10 GB default
    v = None
    try:
        r = admin.post("/vaults", json={"name": "qsize-fits", "description": "created by tests"})
        assert r.status_code in (200, 201), (
            f"a size-less create must fit under the ceiling, not be refused for the default: {r.text}")
        v = r.json()
        assert v["size_limit"] == GIB, f"the default should have been bounded to the ceiling: {v}"
        # An explicit request above the ceiling is still refused.
        over = admin.post("/vaults", json={"name": "qsize-over", "size_limit_gb": 3})
        assert over.status_code == 400, over.text
    finally:
        _reset_quotas(admin)
        if v:
            admin.delete_vault(v["id"])


def test_the_bounded_default_has_a_floor(admin, temp_user_client):
    """Bounded to what is left, down to a useful minimum; below that, refused rather than shrunk.

    A non-admin, because an admin is exempt from the account budget that makes the cap small.
    The floor is a fixed 1 GiB, whatever the default. Both edges: a budget of exactly the floor makes a
    vault of exactly the floor; a budget with a few megabytes left is refused, as it used to be,
    rather than quietly producing a vault too small to use.
    """
    _set_quotas(admin, 2, 1000)   # 2 GB account budget, no per-vault ceiling to speak of
    made = []
    try:
        # Half the budget spent explicitly: exactly the floor is left.
        first = temp_user_client.post("/vaults", json={"name": "qsize-half", "size_limit_gb": 1})
        assert first.status_code in (200, 201), first.text
        made.append(first.json())
        at_floor = temp_user_client.post("/vaults", json={"name": "qsize-floor"})
        assert at_floor.status_code in (200, 201), at_floor.text
        made.append(at_floor.json())
        assert made[1]["size_limit"] == GIB, f"1 GiB left should give a 1 GiB vault: {made[1]}"
        for v in made:
            temp_user_client.delete_vault(v["id"])
        made.clear()

        # Now leave LESS than the floor: 1.5 GB of a 2 GB budget spent, half a gigabyte left. The
        # default must not be bounded down to that; the request is refused the way an explicit
        # over-size one is, instead of quietly making a vault too small to be worth having.
        big = temp_user_client.post("/vaults", json={"name": "qsize-most", "size_limit_gb": 1.5})
        assert big.status_code in (200, 201), big.text
        made.append(big.json())
        crumbs = temp_user_client.post("/vaults", json={"name": "qsize-crumbs"})
        if crumbs.status_code in (200, 201):
            made.append(crumbs.json())
        assert crumbs.status_code == 400, (
            f"a size-less create with under a floor's worth of headroom should be refused, not "
            f"shrunk: {crumbs.status_code} {crumbs.text}")
    finally:
        _reset_quotas(admin)
        for v in made:
            temp_user_client.delete_vault(v["id"])


def test_create_vault_with_explicit_size(admin):
    r = admin.post("/vaults", json={"name": "qsize-2gb", "size_limit_gb": 2})
    assert r.status_code == 200, r.text
    v = r.json()
    try:
        assert v["size_limit"] == 2 * GIB
    finally:
        admin.delete_vault(v["id"])


def test_create_size_zero_truncation_and_overflow_rejected(admin):
    # a sub-nanogigabyte value passes gt=0 but truncates to 0 bytes, which every upload guard reads
    # as UNLIMITED — must be rejected; a huge value overflows the BigInteger column — also rejected
    tiny = admin.post("/vaults", json={"name": "qsize-tiny", "size_limit_gb": 5e-10})
    assert tiny.status_code == 400, tiny.text
    huge = admin.post("/vaults", json={"name": "qsize-huge", "size_limit_gb": 1e10})
    assert huge.status_code == 400, huge.text


def test_per_vault_ceiling_enforced_at_create(admin):
    _set_quotas(admin, 1000, 1)  # 1 GB per-vault ceiling
    try:
        over = admin.post("/vaults", json={"name": "qsize-over", "size_limit_gb": 3})
        assert over.status_code == 400, over.text
        assert "exceed" in over.text.lower()
        ok = admin.post("/vaults", json={"name": "qsize-ceil-ok", "size_limit_gb": 1})
        assert ok.status_code == 200, ok.text
        admin.delete_vault(ok.json()["id"])
    finally:
        _reset_quotas(admin)


def test_per_vault_ceiling_enforced_at_edit(admin):
    # Created AT 1 GB, explicitly. With the default now 5 GB, a vault made before the ceiling was
    # set would sit above it, and reducing it to 3 GB would be a shrink the edit rightly allows —
    # which made this test pass 200 where it expects the ceiling to refuse a growth.
    r = admin.post("/vaults", json={"name": "qsize-edit", "size_limit_gb": 1})
    assert r.status_code in (200, 201), r.text
    v = r.json()
    _set_quotas(admin, 1000, 1)  # 1 GB ceiling
    try:
        over = admin.patch(f"/vaults/{v['id']}/settings", json={"size_limit": 3 * GIB})
        assert over.status_code == 400, over.text
        ok = admin.patch(f"/vaults/{v['id']}/settings", json={"size_limit": 1 * GIB})
        assert ok.status_code == 200, ok.text
    finally:
        _reset_quotas(admin)
        admin.delete_vault(v["id"])


def test_edit_size_limit_null_and_nonpositive_rejected(admin):
    # null/0/negative must not clear the cap to "unlimited" and bypass the quota
    v = admin.create_vault(name="qsize-null")
    try:
        assert admin.patch(f"/vaults/{v['id']}/settings", json={"size_limit": None}).status_code == 400
        assert admin.patch(f"/vaults/{v['id']}/settings", json={"size_limit": 0}).status_code == 400
        assert admin.patch(f"/vaults/{v['id']}/settings", json={"size_limit": -100}).status_code == 400
        assert admin.patch(f"/vaults/{v['id']}/settings", json={"size_limit": 2 * GIB}).status_code == 200
    finally:
        admin.delete_vault(v["id"])


def test_settings_quota_validation(admin):
    try:
        assert admin.put("/settings", json={"default_user_quota": "abc"}).status_code == 400
        assert admin.put("/settings", json={"max_vault_size": -5}).status_code == 400
        assert admin.put("/settings", json={"default_user_quota": True}).status_code == 400
        assert admin.put("/settings", json={"default_user_quota": 10}).status_code in (200, 204)
    finally:
        _reset_quotas(admin)


def test_admin_exempt_from_account_budget(admin):
    _set_quotas(admin, 1, 1000)  # 1 GB account budget, but admin is exempt
    made = []
    try:
        for i in range(3):  # 3 GB of declared vaults, well over the 1 GB budget
            r = admin.post("/vaults", json={"name": f"admin-exempt-{i}", "size_limit_gb": 1})
            assert r.status_code == 200, r.text
            made.append(r.json()["id"])
    finally:
        for vid in made:
            admin.delete_vault(vid)
        _reset_quotas(admin)


def test_account_storage_endpoint(admin):
    r = admin.get("/account/storage")
    assert r.status_code == 200, r.text
    body = r.json()
    for k in ("reserved_bytes", "available_bytes", "per_vault_max_bytes", "account_quota_bytes", "budget_exempt"):
        assert k in body, body
    assert body["budget_exempt"] is True  # the admin is exempt from the account budget
    _set_quotas(admin, 1000, 5)  # 5 GB per-vault ceiling
    try:
        got = admin.get("/account/storage").json()
        assert got["per_vault_max_bytes"] == 5 * GIB
        assert got["available_bytes"] == 5 * GIB  # admin: only the ceiling binds
        assert got["account_quota_bytes"] is None  # admin is budget-exempt
    finally:
        _reset_quotas(admin)


def test_account_budget_enforced_for_non_admin(admin):
    _set_quotas(admin, 2, 1000)  # 2 GB per-account budget
    u = admin.create_user(role="user")
    client = admin.clone_anonymous()
    client.login(u["_username"], u["_password"])
    made = []
    try:
        first = client.post("/vaults", json={"name": "budget-1", "size_limit_gb": 2})
        if first.status_code == 403:
            pytest.skip("this deployment's default role can't create vaults")
        assert first.status_code == 200, first.text
        made.append(first.json()["id"])
        # the second vault's 1 GB would push the reservation sum past the 2 GB budget
        over = client.post("/vaults", json={"name": "budget-2", "size_limit_gb": 1})
        assert over.status_code == 400, over.text
        assert "account" in over.text.lower()
    finally:
        for vid in made:
            try:
                client.delete_vault(vid)
            except Exception:
                pass
        admin.delete_user(u["id"])
        _reset_quotas(admin)
