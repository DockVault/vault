"""Static request-order and transaction contracts for temporary ZK key access.

These checks stay offline so the most security-sensitive ordering cannot regress even
when the live API/browser suite is not running. Behavioral coverage lives in the
temporary-credential compatibility and UI suites.
"""

from pathlib import Path

import pytest


# Source-only assertions: no deployment, no database, no browser. The marker is what
# keeps that promise -- without it the shared autouse fixture classifies this module as
# integration and skips it whenever a container is not running, which is precisely when
# an ordering guard has to keep working.
pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _read(relative: str) -> str:
    return (ROOT / relative).read_text(encoding="utf-8")


def _slice(source: str, start: str, end: str) -> str:
    begin = source.index(start)
    finish = source.index(end, begin)
    return source[begin:finish]


def test_private_envelope_eligibility_precedes_keypair_lookup():
    source = _read("app/api/ecc_router.py")
    handler = _slice(
        source,
        "async def get_private_key(",
        "class PrivateKeyUpdateRequest",
    )

    assert "may_release_private_envelope" in handler
    assert handler.index("may_release_private_envelope") < handler.index(
        "db.query(UserKeyPair)"
    )
    assert "TEMP_ZK_KEY_ACCESS_DENIED" in handler


def test_vault_key_eligibility_precedes_reconciliation_and_secret_queries():
    source = _read("app/api/ecc_router.py")
    handler = _slice(
        source,
        "async def get_vault_keys(",
        '@router.get("/users/{user_id}/public-key")',
    )

    assert "may_release_vault_key" in handler
    gate = handler.index("may_release_vault_key")
    assert gate < handler.index("_reconcile_orphan_member_keys")
    assert gate < handler.index("db.query(VaultMemberKey)")
    assert "TEMP_ZK_KEY_ACCESS_DENIED" in handler


def test_selected_grants_are_validated_before_one_atomic_database_commit():
    source = _read("app/services/auth_service.py")
    # Bound the slice to create_temporary_credential alone: mint_device_sync_credential
    # (a separate credential-minting method with its own atomic commit) now follows it,
    # so ending at retrieve_temp_password would fold that method's commit into the count.
    method = _slice(
        source,
        "    def create_temporary_credential(",
        "    def mint_device_sync_credential(",
    )

    assert "selected_access_plans" in method
    assert "scope_ids must be null or an object" in method
    assert "self.db.flush()" in method
    assert method.count("self.db.commit()") == 1
    assert method.index("self.db.flush()") < method.index("self.db.commit()")
    assert method.index("self.db.commit()") < method.index("redis_client.setex(")


def test_central_policy_has_exact_capability_and_live_state_inputs():
    source = _read("app/core/zk_temp_access.py")

    for required in (
        '"vault.see_files"',
        '"vault.change_permissions"',
        "temp_zk_policy_allows",
        "zk_grant_has_key_authority",
        "has_selected_zk_object_conflict",
        "may_release_private_envelope",
        "may_release_vault_key",
        "VaultMemberKey.key_version",
        "vault_members.c.read_permission",
        "vault_members.c.manage_permission",
        "row.scope_ids",
    ):
        assert required in source

