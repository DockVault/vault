"""The vault-access rate limiter must DENY at the threshold, not merely count.

app/services/vault_service.py gates password/passcode verification behind a per-(vault, owning
account) attempt counter: once `rate_limit:vault:{vault}:{account}` reaches the limit, the gate
raises RateLimitExceededError (HTTP 429) BEFORE checking the credential -- so even a CORRECT password
is refused. Existing tests only assert the counter INCREMENTS; none asserts this deny-at-threshold,
which is the actual security control. The bucket is keyed by the OWNING account and a temp session
runs AS that account, so a temp holder's wrong guesses fill the same bucket and can lock the owner out
(a real DoS-on-the-owner surface). Seeding the counter reaches the threshold without needing a low
CI limit.
"""
import os
import subprocess

import pytest

from conftest import skip_if_container_absent, unique

_REDIS = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
VAULT_PW = "Vault-Lockout-Pw-12!"


def _redis(*args):
    """Run a redis-cli command, returning the CompletedProcess. Skips (rather than errors) when
    docker/redis isn't reachable -- matching the seeding convention of the other db-backed suites."""
    try:
        return subprocess.run(["docker", "exec", _REDIS, "redis-cli", *args],
                              capture_output=True, text=True, timeout=15)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/redis unavailable: {exc}")


def _require_redis():
    """Skip cleanly when there is no redis container to seed -- BEFORE any vault is created, so a
    docker-less/remote run leaves nothing behind."""
    skip_if_container_absent(_redis("ping"), _REDIS)


def _owner_id(client):
    return client.get("/users/me").json()["id"]


def test_reaching_the_limit_refuses_even_a_correct_vault_password(admin):
    _require_redis()
    va = admin.create_vault(name=unique("lockout"), password=VAULT_PW)
    key = None
    try:
        key = f"rate_limit:vault:{va['id']}:{_owner_id(admin)}"
        # positive control: the correct password works while the bucket is empty
        assert admin.get(f"/vaults/{va['id']}/files",
                         headers={"X-Vault-Password": VAULT_PW}).status_code == 200
        # fill the bucket past any configured limit (admin=20 / user=5 / CI=2000 -- all < this)
        _redis("set", key, "999999")
        # the gate now refuses the CORRECT password (it fires before verification) -> 429
        r = admin.get(f"/vaults/{va['id']}/files", headers={"X-Vault-Password": VAULT_PW})
        assert r.status_code == 429, r.text
        # and clearing the counter restores access -- proving the 429 was the limiter, not a broken vault
        _redis("del", key)
        assert admin.get(f"/vaults/{va['id']}/files",
                         headers={"X-Vault-Password": VAULT_PW}).status_code == 200
    finally:
        if key:
            _redis("del", key)
        admin.delete_vault(va["id"], vault_password=VAULT_PW)


def test_the_bucket_is_keyed_by_the_owning_account(admin):
    """Regression on the shared-bucket key: a filled `rate_limit:vault:{vault}:{owner}` bucket locks
    the OWNER (so a temp session, which shares this key, could DoS the owner). A bucket under a
    DIFFERENT account id must NOT affect the owner (the key really includes the account)."""
    _require_redis()
    va = admin.create_vault(name=unique("lockkey"), password=VAULT_PW)
    foreign_key = None
    owner_key = None
    try:
        foreign_key = f"rate_limit:vault:{va['id']}:00000000-0000-0000-0000-000000000000"
        _redis("set", foreign_key, "999999")   # a different account's bucket
        # the owner is unaffected by another account's bucket
        assert admin.get(f"/vaults/{va['id']}/files",
                         headers={"X-Vault-Password": VAULT_PW}).status_code == 200
        # but the owner's OWN bucket locks the owner
        owner_key = f"rate_limit:vault:{va['id']}:{_owner_id(admin)}"
        _redis("set", owner_key, "999999")
        assert admin.get(f"/vaults/{va['id']}/files",
                         headers={"X-Vault-Password": VAULT_PW}).status_code == 429
        _redis("del", owner_key)
    finally:
        if foreign_key:
            _redis("del", foreign_key)
        if owner_key:
            _redis("del", owner_key)
        admin.delete_vault(va["id"], vault_password=VAULT_PW)
