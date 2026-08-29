"""GET /ecc/vaults/{id}/member-keys must not be a vault-existence oracle to a non-member.

The DEK keys GET and the index-key GET were already hardened to refuse a non-member consistently;
this endpoint had the same gap by a different mechanism: it answered 403 for an existing vault a
non-member cannot reach, but 404 for a vault id that does not exist — so 403-vs-404 let any
authenticated account confirm which vault ids are real. It does not use may_release_vault_key (so the
earlier oracle sweeps missed it); the fix defers the existence 404 until after the caller is
a proven member, so a stranger now gets 403 whether or not the vault exists, while a member (holding
an active key) still gets a normal 200.
"""
import contextlib
import uuid

from conftest import create_zk_vault


@contextlib.contextmanager
def _zk_enabled(admin):
    before = admin.get("/settings").json()
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={
            "zero_knowledge_enabled": before.get("zero_knowledge_enabled", False)})


def test_member_keys_no_existence_oracle_for_a_non_member(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = create_zk_vault(admin)
    vid = v["id"]
    try:
        # Existing vault, caller holds no active key -> 403 (unchanged).
        assert temp_user_client.get(f"/ecc/vaults/{vid}/member-keys").status_code == 403
        # A vault id that does not exist -> ALSO 403 now (was 404), so 403-vs-404 can't confirm
        # existence to a stranger.
        assert temp_user_client.get(f"/ecc/vaults/{uuid.uuid4()}/member-keys").status_code == 403
        # The owner holds an active key -> still reaches it normally.
        assert admin.get(f"/ecc/vaults/{vid}/member-keys").status_code == 200
    finally:
        admin.delete_vault(vid)
