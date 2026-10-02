"""Unlocking a password-protected vault's names on the Activity page.

    POST /activity/vaults/{vault_id}/unlock    body {"password": ...}: a 15-minute receipt (app/core/
                                               vault_unlock_receipts.py), sent back after in X-Activity-Unlock.

The Activity page shows a vault's file and folder names only to an administrator who can read the vault, and
for a vault with a vault password only once that password is given. With a receipt the page shows that vault's
items as the recording levels recorded them: a name recorded in full, a fingerprint as a fingerprint, nothing
where nothing was recorded; never the item's name looked up now.

Refused: a vault the administrator cannot read themselves (the vault's own rule: being an administrator is not
enough), a zero-knowledge vault (the server never has its names), a vault with no password (its names are
shown already), and a wrong password, which counts on the vault-password throttle every check of that vault's
password by that account uses. Each unlock, and each refusal for a wrong password, writes an audit row; the
password is never recorded. Only an interactive administrator reaches it; it is a plain ``def`` with a
statement timeout.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel, Field
from sqlalchemy import text
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core import vault_unlock_receipts as receipts
from app.core.database import get_db
from app.core.models import User, Vault

router = APIRouter(tags=["Activity"])

STATEMENT_TIMEOUT_MS = 5000
ACTION = "activity_vault_unlocked"


class Unlock(BaseModel):
    password: str = Field(..., min_length=1, max_length=1024)


def limit_statements(db: Session) -> None:
    bind = db.get_bind()
    if bind is not None and bind.dialect.name == "postgresql":
        db.execute(text(f"SET LOCAL statement_timeout = {STATEMENT_TIMEOUT_MS}"))


def _audit(db, user, vault_id, status: str, details: dict) -> None:
    from app.services.audit_logger import AuditLogger
    db.add(AuditLogger(db).build_row(action="activity_vault_unlocked", status=status, user=user,
                                     resource_type="vault", resource_id=str(vault_id),
                                     details={"vault_id": str(vault_id), **details}))


@router.post("/activity/vaults/{vault_id}/unlock")
def unlock_vault_names(vault_id: uuid.UUID, body: Unlock, request: Request,
                       current_user: User = Depends(require_interactive_admin),
                       db: Session = Depends(get_db)):
    """A receipt that shows this vault's recorded names on the Activity page for 15 minutes."""
    limit_statements(db)
    from app.services.activity_names import readable_vault_ids
    vault = db.query(Vault).filter(Vault.id == vault_id).first()
    if vault is None or vault.id not in readable_vault_ids(db, current_user, {vault.id}):
        # Unknown and unreadable answer alike: a vault the administrator cannot read is not confirmed to exist.
        raise HTTPException(status_code=403, detail="You can see a vault's names only when you can read the "
                                                    "vault yourself.")
    if vault.type == "zero_knowledge":
        raise HTTPException(status_code=409, detail="The server never has a zero-knowledge vault's names.")
    if not vault.password_hash:
        raise HTTPException(status_code=400, detail="This vault has no vault password: its names are shown "
                                                    "already.")
    from app.api.api_server import _current_session_hash
    session_hash = _current_session_hash(request)
    if not session_hash:
        raise HTTPException(status_code=403, detail="A receipt is given only to a signed-in session.")
    try:
        receipts.check_password(current_user, vault, body.password)
    except receipts.UnlockRefused as refused:
        if refused.status == 403:
            try:
                limit_statements(db)
                _audit(db, current_user, vault.id, "failure", {"reason": "wrong password"})
                db.commit()
            except Exception:  # noqa: BLE001 -- the refusal stands without its row
                db.rollback()
        raise HTTPException(status_code=refused.status, detail=refused.detail)
    receipt, expires = receipts.issue(purpose=receipts.PURPOSE_ACTIVITY, session_hash=session_hash,
                                      vault_id=vault.id, user_id=current_user.id,
                                      credential=receipts.credential_digest(vault.password_hash))
    try:
        limit_statements(db)
        _audit(db, current_user, vault.id, "success", {"expires_at": expires.isoformat() + "Z"})
        db.commit()
    except Exception:  # noqa: BLE001 -- no receipt without its audit row
        db.rollback()
        raise HTTPException(status_code=503, detail="The names were not unlocked: the audit record could not be "
                                                    "written.")
    return {"vault_id": str(vault.id), "receipt": receipt, "expires_at": expires.isoformat() + "Z"}
