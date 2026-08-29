"""Second-factor (MFA / step-up) core: challenge -> verify -> receipt, keyed to (account, action).

Pure where possible; db/redis are passed in, like otp_service. Four verifiers (totp, recovery,
password, email), one receipt. No new key material: the TOTP seed is sealed with encrypt_secret,
recovery codes are argon2-hashed, and receipts + email codes are peppered HMACs via the OTP service.

The receipt IS an otp_service code (purpose ``stepup:{action}``, destination = the hash of the session
that earned it), so it inherits single-active-per-(action,user), single-winner consumption, a short
TTL, and session binding for free — a receipt earned in one session cannot be replayed from another.
"""
import base64
import hashlib
import hmac
import secrets
import struct
import time as _time
from datetime import datetime, timezone
from typing import List, Optional, Tuple

from app.core import otp_service
from app.core.models import SecondFactorEnrollment, SecondFactorRecoveryCode
from app.core.security import decrypt_secret, hash_password, verify_password

TOTP_STEP_SECONDS = 30
TOTP_DIGITS = 6
TOTP_DRIFT_STEPS = 1          # accept +/-1 step (RFC 6238 clock-skew tolerance)
RECOVERY_CODE_COUNT = 10
RECOVERY_PREFIX_LEN = 8       # non-secret hex lookup prefix (bits stay argon2-protected below)
RECEIPT_TTL_MINUTES = 5


class SecondFactorResult:
    """Outcome of verify_second_factor: on success, `receipt` is the plaintext step-up receipt."""
    __slots__ = ("ok", "receipt", "reason")

    def __init__(self, ok: bool, receipt: Optional[str] = None, reason: Optional[str] = None):
        self.ok = ok
        self.receipt = receipt
        self.reason = reason


# --- TOTP (RFC 6238, HMAC-SHA1, 6 digits, 30 s) --------------------------------------------------

def generate_totp_secret() -> str:
    """A fresh base32 TOTP seed (160 bits, the RFC 4226 recommendation), no padding."""
    return base64.b32encode(secrets.token_bytes(20)).decode("ascii").rstrip("=")


def _pad_b32(s: str) -> str:
    return s + "=" * ((8 - len(s) % 8) % 8)


def _totp_at_step(seed_b32: str, step: int) -> str:
    key = base64.b32decode(_pad_b32(seed_b32).upper().encode("ascii"), casefold=True)
    digest = hmac.new(key, struct.pack(">Q", int(step)), hashlib.sha1).digest()
    offset = digest[-1] & 0x0F
    code_int = (struct.unpack(">I", digest[offset:offset + 4])[0] & 0x7FFFFFFF) % (10 ** TOTP_DIGITS)
    return str(code_int).zfill(TOTP_DIGITS)


def current_totp_step(at_time: Optional[float] = None) -> int:
    return int((at_time if at_time is not None else _time.time()) // TOTP_STEP_SECONDS)


def matching_totp_step(seed_b32: str, code: str, at_time: Optional[float] = None) -> Optional[int]:
    """The time-step a presented code matches within the drift window, or None. Returns the STEP so a
    caller can CLAIM it: once step N (or later) is claimed, that 30 s code can't be replayed."""
    code = (code or "").strip()
    if not (code.isdigit() and len(code) == TOTP_DIGITS):
        return None
    now_step = current_totp_step(at_time)
    for step in range(now_step - TOTP_DRIFT_STEPS, now_step + TOTP_DRIFT_STEPS + 1):
        if hmac.compare_digest(_totp_at_step(seed_b32, step), code):
            return step
    return None


def otpauth_uri(seed_b32: str, *, account: str, issuer: str) -> str:
    """The standard otpauth:// provisioning URI an authenticator app imports (rendered as a QR later)."""
    from urllib.parse import quote
    label = quote(f"{issuer}:{account}")
    return (f"otpauth://totp/{label}?secret={seed_b32}&issuer={quote(issuer)}"
            f"&algorithm=SHA1&digits={TOTP_DIGITS}&period={TOTP_STEP_SECONDS}")


def otpauth_qr_svg(uri: str) -> Optional[str]:
    """An inline SVG QR of the otpauth URI, rendered server-side. Uses qrcode's SvgPathImage factory —
    a single <path>, stdlib xml only, no Pillow. Best-effort: returns None if rendering fails, so a
    QR hiccup never blocks enrollment (the secret is always shown for manual entry). qrcode is imported
    lazily so importing this module never depends on it."""
    try:
        import io
        import qrcode
        from qrcode.image.svg import SvgPathImage
        qr = qrcode.QRCode(error_correction=qrcode.constants.ERROR_CORRECT_M, box_size=10, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        buf = io.BytesIO()
        qr.make_image(image_factory=SvgPathImage).save(buf)
        return buf.getvalue().decode("utf-8")
    except Exception:      # noqa: BLE001
        return None


# --- Recovery codes ------------------------------------------------------------------------------

def _normalize_recovery(code: str) -> str:
    return (code or "").replace("-", "").replace(" ", "").strip().lower()


def generate_recovery_codes(n: int = RECOVERY_CODE_COUNT) -> List[Tuple[str, str, str]]:
    """Return a list of (plaintext, prefix, argon2_hash). The plaintext is shown to the user ONCE; only
    (prefix, hash) is stored. Each code is 80 bits; the 8-hex prefix is a NON-SECRET lookup key so verify
    selects at most one candidate row and runs a single argon2 per attempt, while the remaining 48 bits
    stay argon2-protected even if the DB leaks."""
    out: List[Tuple[str, str, str]] = []
    for _ in range(max(1, int(n))):
        code = secrets.token_hex(10)                      # 20 hex chars = 80 bits
        out.append((code, code[:RECOVERY_PREFIX_LEN], hash_password(code)))
    return out


def format_recovery_code(code: str) -> str:
    """Group into readable 4-char blocks for display (verification is case-insensitive + dash-agnostic)."""
    return "-".join(code[i:i + 4] for i in range(0, len(code), 4))


# --- Verify dispatch + receipt -------------------------------------------------------------------

def _active_enrollment(db, user) -> Optional[SecondFactorEnrollment]:
    return db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.user_id == user.id,
        SecondFactorEnrollment.status == "active",
    ).first()


def _verify_totp(db, user, code: str) -> bool:
    enr = _active_enrollment(db, user)
    if not enr or enr.method != "totp" or not enr.secret_enc:
        return False
    try:
        seed = decrypt_secret(enr.secret_enc)
    except Exception:      # noqa: BLE001 - a corrupt/undecryptable seed is a failed verify, never a 500
        return False
    step = matching_totp_step(seed, code)
    if step is None:
        return False
    # Claim the step in ONE conditional UPDATE: exactly one concurrent verify of the same code wins,
    # and the code cannot be replayed once its step (or a later one) is recorded. A read-then-write
    # would let two concurrent verifies of the same 30 s code both pass.
    claimed = db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.user_id == user.id,
        SecondFactorEnrollment.status == "active",
        SecondFactorEnrollment.last_used_step < step,
    ).update({"last_used_step": step, "last_used_at": datetime.now(timezone.utc)},
             synchronize_session=False)
    db.commit()
    return claimed == 1


def _verify_recovery(db, user, code: str) -> bool:
    norm = _normalize_recovery(code)
    if len(norm) < RECOVERY_PREFIX_LEN:
        return False
    prefix = norm[:RECOVERY_PREFIX_LEN]
    # One indexed lookup by the non-secret prefix -> at most one argon2 verify per attempt (no CPU-DoS).
    rows = db.query(SecondFactorRecoveryCode).filter(
        SecondFactorRecoveryCode.user_id == user.id,
        SecondFactorRecoveryCode.code_prefix == prefix,
        SecondFactorRecoveryCode.consumed_at.is_(None),
    ).all()
    for row in rows:
        if verify_password(norm, row.code_hash):
            consumed = db.query(SecondFactorRecoveryCode).filter(
                SecondFactorRecoveryCode.id == row.id,
                SecondFactorRecoveryCode.consumed_at.is_(None),
            ).update({"consumed_at": datetime.now(timezone.utc)}, synchronize_session=False)
            db.commit()
            return consumed == 1
    return False


def issue_step_up_receipt(db, *, user_id, action: str, session_hash: str, redis=None) -> str:
    """Mint the session-bound step-up receipt (an otp_service code). destination carries the session
    hash so consume_step_up_receipt can refuse a receipt earned in a different session."""
    return otp_service.issue(db, purpose=f"stepup:{action}", user_id=user_id,
                             destination=session_hash, ttl_minutes=RECEIPT_TTL_MINUTES, redis=redis)


def check_second_factor(db, *, user, action: str, method: str, code: str, redis=None) -> bool:
    """Verify a presented OTP second factor for (user, action) WITHOUT issuing a receipt — the LOGIN
    step (which creates the session directly) and anyone who just needs a yes/no. Consumes a TOTP step /
    a recovery code on success (single-winner).

    This checks ONLY genuine second factors — totp, recovery, email. It deliberately does NOT accept the
    account password: the password is the FIRST factor, so honouring it here would let a stolen password
    satisfy the second factor and defeat MFA entirely. The separate password RE-AUTH that a
    `require_password` action asks for is verified by the caller with verify_password(), never here."""
    method = (method or "").lower()
    if method == "totp":
        return _verify_totp(db, user, code)
    if method == "recovery":
        return _verify_recovery(db, user, code)
    if method == "email":
        return otp_service.verify(db, purpose=f"sf:{action}", user_id=user.id, code=code, redis=redis).ok
    return False


def verify_second_factor(db, *, user, action: str, method: str, code: str,
                         session_hash: str, redis=None) -> SecondFactorResult:
    """Verify one presented second factor for (user, action) and, on success, issue a session-bound
    step-up receipt (the step-up path — the login path uses check_second_factor and needs no receipt)."""
    if (method or "").lower() not in ("totp", "recovery", "email"):
        return SecondFactorResult(False, reason="unknown_method")
    if not check_second_factor(db, user=user, action=action, method=method, code=code, redis=redis):
        return SecondFactorResult(False, reason="invalid")
    receipt = issue_step_up_receipt(db, user_id=user.id, action=action,
                                    session_hash=session_hash, redis=redis)
    return SecondFactorResult(True, receipt=receipt)


def consume_step_up_receipt(db, *, user, action: str, receipt: str,
                            session_hash: str, redis=None) -> bool:
    """Verify + consume a step-up receipt for (user, action). Accepts ONLY when the receipt is valid AND
    was earned by THIS session (destination == session_hash). Single-use — covers exactly one call."""
    if not receipt:
        return False
    result = otp_service.verify(db, purpose=f"stepup:{action}", user_id=user.id, code=receipt, redis=redis)
    return bool(result.ok and result.destination == session_hash)
