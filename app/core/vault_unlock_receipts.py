"""Unlocking a password-protected vault's names for a while, with the vault password once: a signed receipt.

An administrator looking at the Activity page (and, later, an auditor working a case, and a vault's owner reading
what a case opened in their vaults) can see a vault's file and folder names only where they could see them in the
vault itself, and a vault with a vault password asks for that password. Rather than send the password with every request, they give it once (POST .../unlock): it is checked
on the vault-password throttle every other check of that vault's password uses, and the answer is a receipt good
for 15 minutes, sent back with each request after.

Nothing is stored. The receipt is the expiry and an HMAC-SHA-256 under a key derived from ENCRYPTION_KEY for
this purpose alone, over, in order (each value tagged and length-prefixed, so no two lists give the same bytes):

    the purpose ("activity", "case" or "owner"), the session that asked, the case (none for the Activity page), the
    vault, the account, the expiry, and a digest of the vault's password hash as it is now.

So a receipt serves only the session, account, vault and purpose it was given for; it ends when the session
ends; and any change of the vault's password (set, changed or removed: each writes a new hash) voids every
receipt for that vault at once, because the digest is recomputed from the vault at each use and never sent.
A use must first establish that the vault exists: the digest of a vault with no password and of a vault that
does not exist are both "none".

The password is never recorded, never sent again, and a wrong one counts on the same throttle as any other
wrong password for that vault and account.
"""
from __future__ import annotations

import base64
import hashlib
import hmac
import struct
import uuid
from datetime import datetime, timedelta, timezone
from typing import Optional, Tuple

PURPOSE_ACTIVITY = "activity"
PURPOSE_CASE = "case"
# A vault's owner reading the names of their own files opened under a case, on Access to my vaults.
PURPOSE_OWNER = "owner"
PURPOSES = (PURPOSE_ACTIVITY, PURPOSE_CASE, PURPOSE_OWNER)
LIFETIME = timedelta(minutes=15)
PREFIX = "dvr1"
_LABEL = b"dvunlock-receipt-v1\x00"
_HKDF_SALT = b"dockvault-vault-unlock-receipt-v1"
_HKDF_INFO = b"vault-unlock-receipt"
_EPOCH = datetime(1970, 1, 1)


class UnlockRefused(Exception):
    """The unlock is refused: ``status`` and ``detail`` say why, as the route answers."""

    def __init__(self, status: int, detail: str):
        super().__init__(detail)
        self.status = status
        self.detail = detail


# --------------------------------------------------------------------------- the encoding

def _e_null() -> bytes:
    return b"\x00"


def _e_text(value: str) -> bytes:
    data = value.encode("utf-8")
    return b"\x01" + struct.pack(">I", len(data)) + data


def _e_bytes(value: bytes) -> bytes:
    return b"\x02" + struct.pack(">I", len(value)) + value


def _e_uuid(value) -> bytes:
    return b"\x04" + uuid.UUID(str(value)).bytes


def _e_timestamp(value: datetime) -> bytes:
    return b"\x05" + struct.pack(">q", _micros(value))


def _naive_utc(value: datetime) -> datetime:
    return value.astimezone(timezone.utc).replace(tzinfo=None) if value.tzinfo else value


def _micros(value: datetime) -> int:
    delta = _naive_utc(value) - _EPOCH
    return delta.days * 86_400_000_000 + delta.seconds * 1_000_000 + delta.microseconds


def credential_digest(password_hash: Optional[str]) -> Optional[bytes]:
    """SHA-256 of the vault's password hash as UTF-8, or None for a vault with no password."""
    return hashlib.sha256(password_hash.encode("utf-8")).digest() if password_hash else None


def _key() -> bytes:
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.hkdf import HKDF
    from app.core.security import _runtime_settings
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=_HKDF_SALT, info=_HKDF_INFO).derive(
        _runtime_settings().encryption_key.encode())


def _mac(*, purpose: str, session_hash: str, case_id, vault_id, user_id, expires: datetime,
         credential: Optional[bytes]) -> bytes:
    if purpose not in PURPOSES:
        raise ValueError(f"unknown purpose {purpose!r}")
    message = (_LABEL + _e_text(purpose) + _e_text(session_hash)
               + (_e_uuid(case_id) if case_id is not None else _e_null())
               + _e_uuid(vault_id) + _e_uuid(user_id) + _e_timestamp(expires)
               + (_e_bytes(credential) if credential is not None else _e_null()))
    return hmac.new(_key(), message, hashlib.sha256).digest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


# --------------------------------------------------------------------------- issuing and checking

def issue(*, purpose: str, session_hash: str, vault_id, user_id, credential: Optional[bytes], case_id=None,
          now: Optional[datetime] = None) -> Tuple[str, datetime]:
    """(receipt, expiry) for these bindings. ``session_hash`` is required: a receipt is always a session's."""
    if not session_hash:
        raise ValueError("a receipt is bound to a session, and there is none")
    expires = _naive_utc(now or datetime.now(timezone.utc)) + LIFETIME
    expires = expires.replace(microsecond=0)
    mac = _mac(purpose=purpose, session_hash=session_hash, case_id=case_id, vault_id=vault_id, user_id=user_id,
               expires=expires, credential=credential)
    return f"{PREFIX}.{_b64(struct.pack('>q', _micros(expires)))}.{_b64(mac)}", expires


def verify(receipt: str, *, purpose: str, session_hash: Optional[str], vault_id, user_id,
           credential: Optional[bytes], case_id=None, now: Optional[datetime] = None) -> bool:
    """Whether ``receipt`` was issued for exactly these bindings and has not expired. Never raises."""
    try:
        if not session_hash or not isinstance(receipt, str):
            return False
        prefix, stamp, mac = receipt.split(".")
        if prefix != PREFIX:
            return False
        (micros,) = struct.unpack(">q", _unb64(stamp))
        expires = _EPOCH + timedelta(microseconds=micros)
        if _naive_utc(now or datetime.now(timezone.utc)) >= expires or expires - LIFETIME > _naive_utc(
                now or datetime.now(timezone.utc)):
            return False
        wanted = _mac(purpose=purpose, session_hash=session_hash, case_id=case_id, vault_id=vault_id,
                      user_id=user_id, expires=expires, credential=credential)
        return hmac.compare_digest(_unb64(mac), wanted)
    except Exception:  # noqa: BLE001 -- anything malformed is simply not a receipt
        return False


# --------------------------------------------------------------------------- the password, once, throttled

def throttle_key(vault_id, user_id) -> str:
    """The vault-password throttle's bucket: the one every check of this vault's password by this account
    counts in (app/services/vault_service.py)."""
    return f"rate_limit:vault:{vault_id}:{user_id}"


def check_password(user, vault, password: str) -> None:
    """Check ``password`` against the vault's, on the shared throttle. Raises UnlockRefused (429 when the
    throttle is spent, 403 for a wrong password, which it counts)."""
    from app.core import rate_limit_settings, vault_attempt_throttle
    from app.core.models import RoleEnum
    from app.core.security import verify_password
    key = throttle_key(vault.id, user.id)
    limit = rate_limit_settings.effective(
        "rate_limit_vault_attempts_admin" if user.role == RoleEnum.ADMIN else "rate_limit_vault_attempts")
    window = rate_limit_settings.effective("rate_limit_vault_window_seconds")
    if vault_attempt_throttle.over_limit(key, limit, window):
        raise UnlockRefused(429, "Too many vault access attempts. Please try again later.")
    if not password or not verify_password(password, vault.password_hash):
        vault_attempt_throttle.burn(key, window)
        raise UnlockRefused(403, "The vault password is not right.")
