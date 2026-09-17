"""One-time boot migration: hash the plaintext NoteLink URL tokens at rest.

Note-link tokens were stored in the clear (note_public_links.token), so a database leak handed an
attacker working links. As of this release the token is stored HASHED (token_hash, sha256, like
PublicLink) and looked up by that hash. This migration derives the hash from the plaintext we still
hold for every existing row and NULLs the plaintext, so every already-minted link keeps redeeming
while the cleartext leaves the database. The plaintext column is dropped in a later release, once the
hash is populated and verified.

Marker-guarded + idempotent + restart-safe (a `system_settings` marker records that it has run, so a
second boot re-hashes nothing and scans nothing), following app/core/audit_migrations.py. The boot
DDL adds the token_hash column and its partial-unique index before this runs; on a fresh database
there is nothing to migrate and the marker is still set.
"""
import hashlib

_MARKER_KEY = "notelink_tokens_hashed"


def _token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def backfill_notelink_token_hashes(db) -> int:
    """Hash every existing NoteLink's plaintext token into token_hash and NULL the plaintext. Returns
    the number of rows migrated. Commits the updates and the marker together, so a crash mid-run
    leaves the marker unset and the migration is retried, never half-done."""
    from app.core.models import NoteLink, SystemSetting

    if db.query(SystemSetting).filter(SystemSetting.key == _MARKER_KEY).first():
        return 0  # already migrated on an earlier boot -- no table scan, re-hashes nothing

    pending = []
    for row in db.query(NoteLink.id, NoteLink.token).yield_per(1000):
        tok = row[1]
        if tok:  # a NULL token is already migrated (or a row created after the switch)
            pending.append((row[0], _token_hash(tok)))
    for row_id, h in pending:
        db.query(NoteLink).filter(NoteLink.id == row_id).update(
            {NoteLink.token_hash: h, NoteLink.token: None}, synchronize_session=False)

    # Mark done even when nothing needed migrating, so the table is never scanned again. Same
    # transaction as the updates: they persist together or not at all.
    db.add(SystemSetting(key=_MARKER_KEY, value={"rows": len(pending)}))
    db.commit()
    return len(pending)
