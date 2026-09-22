"""One-time boot migration: give every name-index-key row the label that names its bytes.

`VaultMemberIndexKey.wrapping_algorithm` was never set at the write site, so every row took the
column default -- 'ECDH-AES-256-GCM', the LEGACY direct-DEK label -- while the bytes were a v2
name-index wrap (the client's wrapNameIndexKeyV2 has never been gated). Nothing reads that column
today, so nothing has behaved differently; but the column carried two meanings, and an inventory
asking "which rows are legacy AES-KW wraps?" would have answered yes about rows that are v2. The
write site now stamps NAME_INDEX_ALGO; this relabels the rows already written.

Why a blanket relabel is SAFE here, when a blanket backfill is usually the dangerous shape: the
table and the v2 index wrap shipped in the same release, so there has never been a deployment in
which an index-key row was written with any other wrap. Every row in the table is a v2 name-index
wrap, whatever its label says; there are no rows that really are legacy for the update to mislabel.

Marker-guarded + idempotent + restart-safe (a `system_settings` marker records that it has run, so a
second boot scans nothing), following app/core/notelink_token_migration.py. The updates and the
marker commit together, so a crash mid-run leaves the marker unset and the migration is retried.
"""
from sqlalchemy import or_

_MARKER_KEY = "name_index_key_labels_v2"


def relabel_name_index_keys(db) -> int:
    """Stamp NAME_INDEX_ALGO on every name-index-key row that does not carry a name-index label
    (the legacy default, or NULL). Returns the number of rows relabelled."""
    from app.core.key_wrap_algorithms import NAME_INDEX_ALGO, NAME_INDEX_ALGOS
    from app.core.models import SystemSetting, VaultMemberIndexKey

    if db.query(SystemSetting).filter(SystemSetting.key == _MARKER_KEY).first():
        return 0  # already relabelled on an earlier boot -- no table scan

    col = VaultMemberIndexKey.wrapping_algorithm
    relabelled = db.query(VaultMemberIndexKey).filter(
        or_(col.is_(None), col.notin_(NAME_INDEX_ALGOS))
    ).update({col: NAME_INDEX_ALGO}, synchronize_session=False)

    # Mark done even when nothing needed relabelling, so the table is never scanned again. Same
    # transaction as the update: they persist together or not at all.
    db.add(SystemSetting(key=_MARKER_KEY, value={"rows": int(relabelled or 0)}))
    db.commit()
    return int(relabelled or 0)
