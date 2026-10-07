"""How many zero-knowledge files and folders still carry a name that was never sealed.

A zero-knowledge vault's file and folder names are sealed in the browser ('zk1:' or 'zk2:' blobs in
``enc_name``). A row whose ``enc_name`` is absent, or is not such a blob, is left over from before the
write paths required sealing. The read guards already keep such a name from being served, so this is a
list of names to seal again, not a leak. A healthy deployment counts 0.

Counts only, never a name. Read by the administrators' ``GET /zk/unsealed`` and by the host command's
``zk-status`` action (app/core/host_operator.py).
"""
from sqlalchemy import and_, not_, or_


def _unsealed(column):
    # NULL (never sealed), or present but not a sealed blob. A sealed name is v1 (zk1:...) or v2
    # (zk2:..., bound to its row); neither is counted.
    return or_(column.is_(None), and_(not_(column.like("zk1:%")), not_(column.like("zk2:%"))))


def counts(db) -> dict:
    """``zk_vaults`` (every zero-knowledge vault), ``files_unsealed``, ``folders_unsealed`` and
    ``vaults_affected`` (the zero-knowledge vaults holding at least one of them)."""
    from app.core.models import File, Folder, Vault
    zk_ids = [r[0] for r in db.query(Vault.id).filter(Vault.type == "zero_knowledge").all()]
    if not zk_ids:
        return {"zk_vaults": 0, "files_unsealed": 0, "folders_unsealed": 0, "vaults_affected": 0}
    files_unsealed = db.query(File).filter(File.vault_id.in_(zk_ids), _unsealed(File.enc_name)).count()
    folders_unsealed = db.query(Folder).filter(Folder.vault_id.in_(zk_ids), _unsealed(Folder.enc_name)).count()
    affected = {r[0] for r in db.query(File.vault_id).filter(
        File.vault_id.in_(zk_ids), _unsealed(File.enc_name)).distinct()}
    affected |= {r[0] for r in db.query(Folder.vault_id).filter(
        Folder.vault_id.in_(zk_ids), _unsealed(Folder.enc_name)).distinct()}
    return {
        "zk_vaults": len(zk_ids),
        "files_unsealed": files_unsealed,
        "folders_unsealed": folders_unsealed,
        "vaults_affected": len(affected),
    }
