"""One-time boot migration: seal any file content checksum still stored in plaintext at rest.

`files.checksum_sha256` (a SHA-256 of the content -- a weak confirmation oracle for a DB/backup reader)
is sealed at rest into `enc_checksum` for new uploads; rows written before that carry the plaintext.
Seal each in place under its per-file key WITHOUT losing anything -- the read path decrypts on load.

Covers EVERY file (zero-knowledge + Standard): the checksum is server-computed, so unlike the name it
is never a browser blob. Batched (files can be many) and idempotent: after the first run every row has
`enc_checksum` set and `checksum_sha256` NULL, so the query finds nothing on later boots.
"""

_BATCH = 500


def backfill_file_checksums(db) -> int:
    """Seal any plaintext files.checksum_sha256 into enc_checksum and NULL the plaintext. Returns the
    number of ROWS updated. Commits per batch (so partial progress survives an interruption; the next
    boot resumes on the rows still carrying a plaintext checksum)."""
    from app.core.models import File
    from app.core.security import encrypt_object_field

    total = 0
    while True:
        # Loading File rows fires the decrypt load event, but a legacy row has enc_checksum NULL so it
        # is left as plaintext (nothing to decrypt); the name-decrypt uses set_committed_value (not
        # dirty), so the only columns this UPDATE writes are enc_checksum + checksum_sha256.
        rows = (db.query(File)
                .filter(File.enc_checksum.is_(None), File.checksum_sha256.isnot(None))
                .limit(_BATCH).all())
        if not rows:
            break
        for f in rows:
            f.enc_checksum = encrypt_object_field(f.vault_id, f.id, f.checksum_sha256, 'checksum')
            f.checksum_sha256 = None
            total += 1
        db.commit()
    return total
