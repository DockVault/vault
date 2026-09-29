"""The key-proof tables in the deployment's database: built at start, with their delete rules in PostgreSQL.

Both tables are new, so create_all builds them on a fresh database and on one an earlier release made,
and an image that predates them ignores them. The foreign keys carry their delete rules in the database
itself, which is what keeps a vault or account deletion clean even under such an image.
"""
import os
import subprocess
import uuid


from conftest import create_zk_vault, ensure_ecc_keypair, unique

_DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    result = subprocess.run(["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                            capture_output=True, text=True, timeout=30)
    assert result.returncode == 0, result.stderr
    return (result.stdout or "").strip()


def _delete_rule(table: str, column: str) -> str:
    """The ON DELETE rule of the foreign key on table.column ('c' cascade, 'n' set null), or ''."""
    return _psql(
        "SELECT c.confdeltype FROM pg_constraint c "
        "JOIN pg_attribute a ON a.attrelid = c.conrelid AND a.attnum = ANY (c.conkey) "
        f"WHERE c.contype = 'f' AND c.conrelid = '{table}'::regclass AND a.attname = '{column}'")


def test_both_tables_exist_with_their_delete_rules_and_uniqueness():
    assert _psql("SELECT to_regclass('public.vault_key_proofs') IS NOT NULL") == "t"
    assert _psql("SELECT to_regclass('public.zk_key_proof_challenges') IS NOT NULL") == "t"
    assert _delete_rule("vault_key_proofs", "vault_id") == "c"
    assert _delete_rule("vault_key_proofs", "created_by") == "n"
    assert _delete_rule("zk_key_proof_challenges", "user_id") == "c"
    assert _delete_rule("zk_key_proof_challenges", "vault_id") == "", "a create challenge names no vault yet"
    unique = _psql(
        "SELECT pg_get_constraintdef(oid) FROM pg_constraint "
        "WHERE conrelid = 'vault_key_proofs'::regclass AND contype = 'u'")
    assert "UNIQUE (vault_id, dek_epoch)" in unique


def test_deleting_the_account_and_the_vault_cleans_up_through_the_database(admin):
    """Rows planted directly, as a release that writes them would: the cascades are the database's."""
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    user = admin.create_user(username=unique("kpschema"))
    vid = None
    try:
        ensure_ecc_keypair(admin)
        vid = create_zk_vault(admin)["id"]   # its first epoch's row is the create's own
        uid = user["id"]
        _psql(
            "INSERT INTO vault_key_proofs (id, vault_id, dek_epoch, format, proof_public_key, "
            "sealed_private_key, dek_check, source, created_by, created_at) VALUES "
            f"('{uuid.uuid4()}', '{vid}', 2, 1, 'P', 'S', 'C', 'rotate', '{uid}', now())")
        _psql(
            "INSERT INTO zk_key_proof_challenges (id, user_id, vault_id, op, server_private_key_sealed, "
            "nonce, mode, dek_epoch, team_epoch, created_at) VALUES "
            f"('{uuid.uuid4()}', '{uid}', '{uuid.uuid4()}', 'create', 'sealed', 'n', 'direct', 1, 1, now())")
        assert _psql(f"SELECT count(*) FROM zk_key_proof_challenges WHERE user_id = '{uid}'") == "1"

        # A second row at the same epoch is refused by the database.
        dup = subprocess.run(
            ["docker", "exec", _DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
             "INSERT INTO vault_key_proofs (id, vault_id, dek_epoch, format, source, created_at) VALUES "
             f"('{uuid.uuid4()}', '{vid}', 2, 1, 'bootstrap', now())"],
            capture_output=True, text=True, timeout=30)
        assert dup.returncode != 0 and "uq_vault_key_proof_epoch" in dup.stderr, dup.stderr

        assert admin.delete_user(uid).status_code == 200
        assert _psql(f"SELECT count(*) FROM zk_key_proof_challenges WHERE user_id = '{uid}'") == "0"
        assert _psql(f"SELECT count(*) FROM vault_key_proofs WHERE vault_id = '{vid}' "
                     "AND created_by IS NULL") == "1", "the installer's id is cleared, the row kept"

        assert admin.delete_vault(vid).status_code == 200
        vid_deleted, vid = vid, None
        assert _psql(f"SELECT count(*) FROM vault_key_proofs WHERE vault_id = '{vid_deleted}'") == "0"
    finally:
        if vid:
            admin.delete_vault(vid)
        admin.put("/settings", json={"zero_knowledge_enabled": False})
        admin.delete_user(user["id"])
