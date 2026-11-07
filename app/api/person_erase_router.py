"""Per-person erase (app/core/person_erase.py): the Settings page's form and list.

    GET  /settings/erase-requests                    every erase, newest first, as the audit chain holds it
    POST /settings/erase-requests/preview            what erasing a name would change now, store by store
    POST /settings/erase-requests                    ask for an erase of a name (the password every time)
    POST /settings/erase-requests/{id}/cancel        cancel an erase that has not begun, by any administrator

The name travels in the request body only (never in a URL, so it is in no access log), and no response but the
preview's repeats it. Asking writes its request seal in the audit chain, the request's row with the name sealed,
and its audit row (the placeholder, never the name) in one transaction; another writer of seals holding the chain's
lock gives 409 (busy, retry), and while sealing is stopped an erase cannot be asked for (it deletes sooner). A
cancel while sealing is stopped is saved, and its seal is written from the database once sealing runs again.
Every administrator is told of each request, cancel and completion.

Every route is a plain ``def`` (the thread pool) for an interactive administrator only (a temporary credential is
refused), and every statement it sends is bounded by a statement timeout.
"""
from __future__ import annotations

import uuid

from fastapi import APIRouter, Depends, HTTPException, Request
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.audit_integrity_router import require_chain_read
from app.api.managed_settings_router import STEP_UP_ACTION, limit_statements
from app.api.user_management_api import require_interactive_admin
from app.core import audit_chain_policy_seals as chain_seals
from app.core import audit_integrity
from app.core import fixed_step_up
from app.core import person_erase as pe
from app.core import settings_registry as registry
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Per-person erase"])

_step_up = fixed_step_up.guard(STEP_UP_ACTION)
# A preview counts over the audit table and the other stores.
PREVIEW_STATEMENT_TIMEOUT_MS = 30000


class EraseName(BaseModel):
    name: str


@router.get("/settings/erase-requests")
def list_erase_requests(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    limit_statements(db)
    audit_integrity.read_view(db.get_bind())     # until it has, a request reads as not known yet (pe.UNREAD)
    st = audit_integrity.state()
    return {"requests": pe.listing(db, st), "delay_days": pe.delay_days(st.view, st),
            "protected_minimum": pe.protected_minimum()}


@router.post("/settings/erase-requests/preview")
def preview_erase(body: EraseName, current_user: User = Depends(require_interactive_admin),
                  db: Session = Depends(get_db)):
    limit_statements(db, PREVIEW_STATEMENT_TIMEOUT_MS)
    require_chain_read(db, "What an erase would change (its archived days and its delay)")
    st = audit_integrity.state()
    try:
        return pe.preview(db, body.name, st.clock(), st)
    except pe.Refused as exc:
        raise HTTPException(status_code=400, detail=str(exc))


@router.post("/settings/erase-requests")
def request_erase(body: EraseName, request: Request, current_user: User = Depends(require_interactive_admin),
                  db: Session = Depends(get_db)):
    limit_statements(db)
    why = pe.name_problem(body.name)
    if why:
        raise HTTPException(status_code=400, detail=why)
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    limit_statements(db)
    try:
        with chain_seals.change_transaction(db.get_bind()) as w:
            limit_statements(w.db)
            actor = w.db.get(User, current_user.id) or current_user
            entry = pe.request(w, body.name, actor)
    except audit_integrity.ChainBusy:
        db.rollback()
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except audit_integrity.ChainStopped as stopped:
        db.rollback()
        raise HTTPException(status_code=409, detail=(
            "An erase deletes records, and the audit log's integrity chain is not sealing just now "
            f"({stopped.kind}), so it cannot be recorded. Nothing was asked for; try again later."))
    except pe.Refused as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no request without its audit row
        db.rollback()
        registry._say(f"Warning: an erase was not asked for ({type(exc).__name__})")
        raise HTTPException(status_code=503, detail="The erase was not asked for: its audit record could not be "
                                                    "written. Nothing was changed.")
    pe.tell_administrators("asked", entry, current_user.username)
    return {"status": "pending", "request": entry}


@router.post("/settings/erase-requests/{request_id}/cancel")
def cancel_erase(request_id: uuid.UUID, current_user: User = Depends(require_interactive_admin),
                 db: Session = Depends(get_db)):
    limit_statements(db)
    try:
        try:
            with chain_seals.change_transaction(db.get_bind()) as w:
                limit_statements(w.db)
                actor = w.db.get(User, current_user.id) or current_user
                entry = pe.cancel(w, request_id, actor)
        except audit_integrity.ChainStopped:
            # Saved now (the erase can then never run: its sealed name is gone), sealed from the database once
            # sealing runs again.
            entry = pe.cancel_while_stopped(db, request_id, current_user)
            db.commit()
    except audit_integrity.ChainBusy:
        db.rollback()
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="No such erase")
    except pe.Refused as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no cancel without its audit row
        db.rollback()
        registry._say(f"Warning: a cancel of an erase was not saved ({type(exc).__name__})")
        raise HTTPException(status_code=503, detail="The erase was not cancelled: its audit record could not be "
                                                    "written. It is still waiting.")
    pe.tell_administrators("cancelled", entry, current_user.username)
    return {"status": "cancelled", "request": entry}
