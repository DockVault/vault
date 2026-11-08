"""The second factors an account holds, read once for every gate that asks.

Several gates used to ask the enrollment table directly whether an account "has a second factor": the
step-up requirement, the fixed step-ups, the method lists at sign-in and at a step-up, the effective
second-factor state. Each meant the authenticator-app enrollment. Passkeys are a second factor too, so
the question gets one answer here, and the gates read it: ``code_method`` is the authenticator enrollment
the account has (``totp``; ``email`` if that method ever lands), ``passkeys`` how many usable passkeys it
holds. The passkey store arrives with passkeys; until then the count is zero and every gate behaves as it
always did.
"""
from __future__ import annotations

from dataclasses import dataclass
from typing import Optional


@dataclass(frozen=True)
class ActiveFactors:
    code_method: Optional[str] = None
    passkeys: int = 0

    @property
    def code(self) -> bool:
        """An authenticator enrollment (a code the account can type)."""
        return self.code_method is not None

    @property
    def any(self) -> bool:
        """Some second factor of the vault's own: a code or a passkey."""
        return self.code or self.passkeys > 0


def active_factors(db, user_id) -> ActiveFactors:
    """What ``user_id`` can present as a second factor right now."""
    from app.core.models import SecondFactorEnrollment
    enrollment = db.query(SecondFactorEnrollment).filter(
        SecondFactorEnrollment.user_id == user_id, SecondFactorEnrollment.status == "active").first()
    return ActiveFactors(code_method=enrollment.method if enrollment is not None else None,
                         passkeys=_passkey_count(db, user_id))


def _passkey_count(db, user_id) -> int:
    """How many usable passkeys the account holds: registered and not retired by an administrator's reset. A
    provisional one (registered soon after an administrator changed the account's sign-in details) counts
    here, as a factor for signing in; the compliance step-ups ask about it separately."""
    from app.core.models import WebAuthnCredential
    from app.core.table_presence import has_table
    if not has_table(db, WebAuthnCredential.__tablename__):
        return 0
    return db.query(WebAuthnCredential.id).filter(
        WebAuthnCredential.user_id == user_id, WebAuthnCredential.retired_at.is_(None)).count()
