"""Startup guard: refuse to boot if the configured ENCRYPTION_KEY cannot open data this deployment
sealed. A single boot under a MISMATCHED key can silently corrupt at-rest data (the note backfill and
every other in-place seal), so before any data-touching migration runs we prove the key is the one that
sealed the existing data.

Mechanism: a one-row canary in ``system_settings`` (key='encryption_key_canary') holds a Fernet token of
a fixed constant, sealed under the deployment key. On first sight (fresh DB, or the first boot of this
version on an existing DB) it is SEEDED under the current key -- so an upgrade boot never refuses. On
every later boot it is decrypted: a definitive wrong-key signal (InvalidToken, or a decrypted value that
does not match the constant) raises EncryptionKeyMismatch and stops boot. Anything ambiguous (missing
ciphertext, an unexpected setup error) is logged and NOT fatal -- the individual migrations are already
loss-safe, so this guard is defense-in-depth, never a new way to brick a healthy deployment.

Recovery: if the key is genuinely correct but the canary row was corrupted, delete the
'encryption_key_canary' row from system_settings and reboot -- it re-seeds under the current key. (An
attacker who can delete that row already has full DB write, so this escape hatch weakens nothing.)
"""
from __future__ import annotations

_CANARY_KEY = "encryption_key_canary"
_CANARY_PLAINTEXT = b"dockvault-encryption-key-canary-v1"


class EncryptionKeyMismatch(RuntimeError):
    """The configured ENCRYPTION_KEY does not match the key that sealed this deployment's data."""


def verify_or_seed_key_canary(db) -> str:
    """Prove the ENCRYPTION_KEY opens this deployment's sealed data, or raise EncryptionKeyMismatch.

    Returns a short status: 'seeded' (first sight) | 'ok' | 'skipped:<reason>'. Raises ONLY on a
    definitive wrong-key signal. The caller owns the transaction; a seed commits its own row."""
    from cryptography.fernet import InvalidToken
    from app.core.security import _fernet
    from app.core.models import SystemSetting

    row = db.query(SystemSetting).filter(SystemSetting.key == _CANARY_KEY).first()
    if row is None:
        # First sight: seed under the current key. On an existing DB this is the first boot of this
        # version, so the current key is trusted for this one boot (the migrations are loss-safe
        # regardless); on a fresh DB there is nothing to protect yet.
        token = _fernet().encrypt(_CANARY_PLAINTEXT).decode("ascii")
        db.add(SystemSetting(key=_CANARY_KEY, value={"ct": token, "v": 1}))
        db.commit()
        return "seeded"

    ct = row.value.get("ct") if isinstance(row.value, dict) else None
    if not ct:
        return "skipped:no-ct"          # malformed/empty canary row -- cannot verify, do not brick

    try:
        opened = _fernet().decrypt(ct.encode("ascii"))
    except InvalidToken:
        raise EncryptionKeyMismatch(
            "The configured ENCRYPTION_KEY does not decrypt this deployment's key canary. It almost "
            "certainly does not match the key that sealed the stored data, so a migration would corrupt "
            "at-rest content. Refusing to boot. Restore the correct ENCRYPTION_KEY (or the matching .env "
            "/ volume set). If you are certain the key is correct and the canary is corrupted, delete the "
            "'encryption_key_canary' row from system_settings to re-seed."
        )
    except Exception:                    # noqa: BLE001 -- non-ASCII ct or an infra/setup error. (A
        return "skipped:unreadable"      # base64-malformed ASCII ct raises InvalidToken above, and is
                                         # deliberately treated as a mismatch: if the stored canary is
                                         # unopenable, refuse rather than trust the key -- recovery is
                                         # deleting the row, as the InvalidToken message states.)

    if opened != _CANARY_PLAINTEXT:
        raise EncryptionKeyMismatch(
            "The deployment key canary decrypted to an unexpected value; the configured ENCRYPTION_KEY "
            "does not match the one that sealed this deployment's data. Refusing to boot."
        )
    return "ok"
