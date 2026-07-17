"""Per-vault size + account-budget enforcement (the reservation model).

A vault carries a declared size_limit (default 1 GB). Two admin settings bound it: max_vault_size
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


def test_create_vault_default_size_is_1gb(admin):
    v = admin.create_vault(name="qsize-default")
    try:
        got = admin.get(f"/vaults/{v['id']}").json()
        assert got["size_limit"] == GIB
    finally:
        admin.delete_vault(v["id"])


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
    v = admin.create_vault(name="qsize-edit")
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
