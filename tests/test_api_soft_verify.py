"""GET /vaults/{id} soft-verify hardening.

An optional vault-password check on the metadata read now rides the X-Vault-Password HEADER and is
rate-limited via the same inline vault-password counter — it is no longer read from the URL query
string (which would leak the password into access logs) and is no longer un-throttled.
"""
import os
import subprocess
import uuid

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_PW = "Sup3r-Secret-PW-9!"


def _u(p):
    return f"{p}_{uuid.uuid4().hex[:8]}"


def _redis_get(key):
    return subprocess.run(["docker", "exec", _REDIS_CONTAINER, "redis-cli", "get", key],
                          capture_output=True, text=True, timeout=20).stdout.strip()


def test_soft_verify_uses_header_not_query_string(admin):
    v = admin.create_vault(name=_u("sv"), password=_PW)
    vid = v["id"]
    uid = admin.get("/users/me").json()["id"]
    try:
        # correct password in the HEADER -> soft-verify passes (200)
        assert admin.get(f"/vaults/{vid}", headers={"X-Vault-Password": _PW}).status_code == 200
        # a WRONG password in the QUERY STRING is IGNORED (no longer read) -> still 200 metadata
        assert admin.get(f"/vaults/{vid}", params={"vault_password": "wrong-in-query"}).status_code == 200
        # a WRONG password in the HEADER is rejected AND rate-limited (previously un-throttled)
        key = f"rate_limit:vault:{vid}:{uid}"
        before = int(_redis_get(key) or 0)
        r = admin.get(f"/vaults/{vid}", headers={"X-Vault-Password": "wrong-in-header"})
        assert r.status_code in (400, 401, 403), r.text
        assert int(_redis_get(key) or 0) == before + 1  # the failed soft-verify burned one attempt
    finally:
        admin.delete_vault(vid, vault_password=_PW)


def test_metadata_read_without_password_is_open(admin):
    """No password supplied -> the metadata read is unaffected (no verification, no rate-limit)."""
    v = admin.create_vault(name=_u("sv2"), password=_PW)
    vid = v["id"]
    try:
        r = admin.get(f"/vaults/{vid}")
        assert r.status_code == 200 and r.json()["has_password"] is True
    finally:
        admin.delete_vault(vid, vault_password=_PW)
