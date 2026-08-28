"""Idempotent boot migration: seal any note/link content still stored in plaintext at rest.

Notes (title/body) and public note-link snapshots (title_snapshot/body_snapshot) predating the
at-rest sealing hold plaintext. Seal each in place under its per-row key. WITHOUT losing anything:
the read path decrypts on load and legacy plaintext is unaffected until this runs.

Reads the RAW column values with a COLUMN query (which does NOT fire the ORM load event, so an
already-sealed value is seen as its ciphertext, not the decrypted plaintext) and writes with a bulk
UPDATE (direct SQL, so it does NOT re-enter the before-flush seal event and double-seal). A value
that already carries the seal marker is left untouched whether or not it decrypts -- never
re-sealed -- so a boot on a MISMATCHED ENCRYPTION_KEY cannot double-encrypt it into permanent loss;
only genuinely unmarked plaintext is sealed. This is a no-op after the first run and on a fresh DB.
"""


def backfill_note_content(db) -> int:
    """Seal any plaintext title/body (notes) and title_snapshot/body_snapshot (links). Returns the
    number of ROWS updated. Caller owns the transaction (this does not commit)."""
    from app.core.models import Note, NoteLink
    from app.core.security import encrypt_note_field, is_note_sealed, decrypt_note_field

    rows_updated = 0
    skipped_undecryptable = 0
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
                    # Already carries the seal marker: NEVER re-seal it, whether or not it decrypts.
                    # A genuine seal that will not open is exactly what a MISMATCHED ENCRYPTION_KEY
                    # looks like, and re-sealing it would double-encrypt the row under a key nobody
                    # keeps -- permanent, silent loss on a single wrong-key boot. It is also what a
                    # legacy plaintext value that happened to start with the marker looks like, and
                    # that case is already safe: the load listener leaves such a value as-is, and
                    # editing it re-seals it through the before-flush path. So leave it untouched --
                    # but COUNT the ones that will not decrypt, so the boot is loud about a probable
                    # key mismatch instead of silently lossy (matching the fail-safe read path).
                    try:
                        decrypt_note_field(row_id, value, field)
                    except Exception:                # noqa: BLE001 — marker present but won't open
                        skipped_undecryptable += 1
                    continue
                updates[getattr(model, field)] = encrypt_note_field(row_id, value, field)
            if updates:
                pending.append((row_id, updates))
        for row_id, updates in pending:
            # Bulk UPDATE: direct SQL, does not re-enter the before-flush seal event.
            db.query(model).filter(model.id == row_id).update(updates, synchronize_session=False)
            rows_updated += 1
    if skipped_undecryptable:
        # Loud on purpose: a marked-but-undecryptable value almost always means the configured
        # ENCRYPTION_KEY does not match the data that sealed these rows. Leaving them untouched is
        # lossless (the correct key still opens them); re-sealing them would not be.
        print(
            "⚠ SECURITY: %d note/link field(s) carry the seal marker but do NOT decrypt with the "
            "current ENCRYPTION_KEY. They were LEFT UNCHANGED (never re-sealed). If the key is wrong, "
            "the content is intact under the correct one -- restore it. If the key is confirmed "
            "correct, these are legacy values that literally began with the marker (harmless; they "
            "seal on the next edit)." % skipped_undecryptable
        )
    return rows_updated
