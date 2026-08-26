"""Idempotent boot migration: seal any note/link content still stored in plaintext at rest.

Notes (title/body) and public note-link snapshots (title_snapshot/body_snapshot) predating the
at-rest sealing hold plaintext. Seal each in place under its per-row key. WITHOUT losing anything:
the read path decrypts on load and legacy plaintext is unaffected until this runs.

Reads the RAW column values with a COLUMN query (which does NOT fire the ORM load event, so an
already-sealed value is seen as its ciphertext, not the decrypted plaintext) and writes with a bulk
UPDATE (direct SQL, so it does NOT re-enter the before-flush seal event and double-seal). A value
that is already a valid seal is skipped, so this is a no-op after the first run and on a fresh DB.
"""


def backfill_note_content(db) -> int:
    """Seal any plaintext title/body (notes) and title_snapshot/body_snapshot (links). Returns the
    number of ROWS updated. Caller owns the transaction (this does not commit)."""
    from app.core.models import Note, NoteLink
    from app.core.security import encrypt_note_field, is_note_sealed, decrypt_note_field

    rows_updated = 0
    for model, fields in ((Note, ("title", "body")), (NoteLink, ("title_snapshot", "body_snapshot"))):
        columns = [model.id] + [getattr(model, f) for f in fields]
        # Column query -> raw tuples, no entity load, so sealed values stay ciphertext here. Stream it
        # (yield_per) rather than materialize the whole table, and collect only the rows that actually
        # need sealing before issuing the bulk UPDATEs -- so a run over an already-sealed table (the
        # common case after the first boot) holds nothing.
        pending = []
        for row in db.query(*columns).yield_per(1000):
            row_id = row[0]
            updates = {}
            for i, field in enumerate(fields):
                value = row[i + 1]
                if not value:
                    continue                         # empty '' stays '' (read-old returns '')
                if is_note_sealed(value):
                    try:
                        decrypt_note_field(row_id, value, field)
                        continue                     # a genuine seal -> leave it
                    except Exception:                # noqa: BLE001 — marker text a user typed: seal it
                        pass
                updates[getattr(model, field)] = encrypt_note_field(row_id, value, field)
            if updates:
                pending.append((row_id, updates))
        for row_id, updates in pending:
            # Bulk UPDATE: direct SQL, does not re-enter the before-flush seal event.
            db.query(model).filter(model.id == row_id).update(updates, synchronize_session=False)
            rows_updated += 1
    return rows_updated
