"""One-time boot migration: strip residual plaintext NAME keys from legacy audit-log rows.

The AuditLogger redacts file_name / folder_name / old_name / new_name / vault_name from an audit row's
`details` JSON before storing it (app/services/audit_logger.py) -- those names are encrypted in the
files/folders tables (and, for a zero-knowledge vault, the vault name is the residual plaintext label),
so persisting them in the clear one table over would defeat the at-rest sealing. Rows written BEFORE
that redaction still carry the names in the clear. This purges them from existing rows, once.

Idempotent + cheap on every later boot: a `system_settings` marker records that the purge has run, so
the table is scanned at most once ever. Safe on a fresh DB (nothing to purge; the marker is still set).
"""

_MARKER_KEY = "audit_name_redaction_purged"


def purge_audit_log_names(db) -> int:
    """Remove the redacted name keys from every legacy audit_logs.details row that still carries one.
    Returns the number of ROWS updated. Commits its own transaction (updates + marker together), so a
    crash mid-run leaves the marker unset and the purge is retried, never half-done."""
    from app.core.models import AuditLog, SystemSetting
    # The SAME list the AuditLogger strips on write, so this purge and the live redaction can never
    # drift: adding a key there covers legacy rows here too.
    from app.services.audit_logger import REDACTED_NAME_KEYS

    if db.query(SystemSetting).filter(SystemSetting.key == _MARKER_KEY).first():
        return 0  # already purged on an earlier boot -- no table scan

    rows_updated = 0
    # Stream (id, details) rather than whole entities; collect only the rows that actually carry a
    # name key before issuing the bulk UPDATEs. A JSON column deserializes to a dict here.
    pending = []
    for row in db.query(AuditLog.id, AuditLog.details).yield_per(1000):
        details = row[1]
        if isinstance(details, dict) and any(k in details for k in REDACTED_NAME_KEYS):
            pending.append((row[0], {k: v for k, v in details.items() if k not in REDACTED_NAME_KEYS}))
    for row_id, cleaned in pending:
        db.query(AuditLog).filter(AuditLog.id == row_id).update(
            {AuditLog.details: cleaned}, synchronize_session=False)
        rows_updated += 1

    # Mark done EVEN when nothing needed purging, so the table is never scanned again. In the same
    # transaction as the updates: they persist together or not at all.
    db.add(SystemSetting(key=_MARKER_KEY, value={"rows": rows_updated}))
    db.commit()
    return rows_updated
