"""Removing values recorded under earlier recording levels (app/core/audit_value_removal.py), in Settings -> Activity
and records, beside the levels.

    GET  /settings/value-removals                 every removal, newest first, as the audit chain holds it
    POST /settings/value-removals/preview         what a removal asked for now would change
    POST /settings/value-removals                 ask for a removal (the password every time), with the levels
                                                  the preview showed
    POST /settings/value-removals/{id}/cancel     cancel a removal that has not begun, by any administrator

A removal brings the audit rows written before the end of the current hour down to the levels in force. Asking
writes its request seal in the audit chain, its row and its audit row in one transaction, with the fixed step-up
``admin.audit_privacy.write`` (the password every time, plus any second factor the account has enrolled), as saving
the levels does; another writer of seals holding the chain's lock gives 409 (busy, retry), and while sealing is
stopped a removal cannot be asked for (it deletes values). The request carries the levels its preview showed: when
the levels in force are others (another administrator changed one meanwhile) it is refused with 409 and nothing is
asked for. A cancel while sealing is stopped is saved, and its seal is written from the database once sealing runs
again. Every administrator is told of each request, cancel and
completion.

Every route is a plain ``def`` (the thread pool) for an interactive administrator only (a temporary credential is
refused), and every statement it sends is bounded by a statement timeout.
"""
from __future__ import annotations

import uuid
from typing import Dict

from fastapi import APIRouter, Depends, HTTPException, Request
from fastapi.responses import JSONResponse
from pydantic import BaseModel
from sqlalchemy.orm import Session

from app.api.audit_integrity_router import answer_from_view
from app.api.recording_levels_router import STEP_UP_ACTION, limit_statements
from app.api.user_management_api import require_interactive_admin
from app.core import audit_chain_policy_seals as chain_seals
from app.core import audit_integrity
from app.core import audit_privacy
from app.core import audit_value_removal as removal
from app.core import fixed_step_up
from app.core import settings_registry as registry
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Recording levels"])
# The reason a 409 gives when the levels in force are not the ones the preview showed (the page makes it again).
LEVELS_CHANGED = "levels-changed"

_step_up = fixed_step_up.guard(STEP_UP_ACTION)
# A preview reads the audit rows it would change (removal.PREVIEW_SECONDS, then it stops counting).
PREVIEW_STATEMENT_TIMEOUT_MS = 30000


@router.get("/settings/value-removals")
def list_removals(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    limit_statements(db)
    audit_integrity.read_view(db.get_bind())     # until it has, a request reads as not known yet (removal.UNREAD)
    st = audit_integrity.state()
    return {"requests": removal.listing(db, st), "delay_days": removal.listed_delay_days(st),
            "levels": removal.in_force(db)}


@router.post("/settings/value-removals/preview")
def preview_removal(current_user: User = Depends(require_interactive_admin), db: Session = Depends(get_db)):
    limit_statements(db, PREVIEW_STATEMENT_TIMEOUT_MS)
    st = audit_integrity.state()
    return answer_from_view(db, "What a removal would change (its archived days and its delay)",
                            lambda: removal.preview(db, st, st.clock()))


class RemovalAsk(BaseModel):
    levels: Dict[str, str]                   # the levels the preview showed, a level for each kind


@router.post("/settings/value-removals")
def request_removal(body: RemovalAsk, request: Request, current_user: User = Depends(require_interactive_admin),
                    db: Session = Depends(get_db)):
    limit_statements(db)
    if set(body.levels) != set(audit_privacy.POLICY_KEYS):
        raise HTTPException(status_code=400, detail="Name a level for each kind, as the preview gives them.")
    _step_up(db, current_user, request)       # may commit (a receipt is used once)
    limit_statements(db)
    try:
        with chain_seals.change_transaction(db.get_bind()) as w:
            limit_statements(w.db)
            actor = w.db.get(User, current_user.id) or current_user
            entry = removal.request(w, actor, expected=body.levels)
    except audit_integrity.ChainBusy:
        db.rollback()
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except audit_integrity.ChainStopped as stopped:
        db.rollback()
        raise HTTPException(status_code=409, detail=(
            "A removal changes recorded values, and the audit log's integrity chain is not sealing just now "
            f"({stopped.kind}), so it cannot be recorded. Nothing was asked for; try again later."))
    except removal.LevelsChanged as exc:
        db.rollback()
        return JSONResponse(status_code=409, content={"detail": str(exc), "reason": LEVELS_CHANGED})
    except removal.Refused as exc:
        db.rollback()
        raise HTTPException(status_code=400, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no request without its audit row
        db.rollback()
        registry._say(f"Warning: a removal of recorded values was not asked for ({type(exc).__name__})")
        raise HTTPException(status_code=503, detail="The removal was not asked for: its audit record could not be "
                                                    "written. Nothing was changed.")
    removal.tell_administrators("asked", entry, current_user.username)
    return {"status": "pending", "request": entry}


@router.post("/settings/value-removals/{request_id}/cancel")
def cancel_removal(request_id: uuid.UUID, current_user: User = Depends(require_interactive_admin),
                   db: Session = Depends(get_db)):
    limit_statements(db)
    try:
        try:
            with chain_seals.change_transaction(db.get_bind()) as w:
                limit_statements(w.db)
                actor = w.db.get(User, current_user.id) or current_user
                entry = removal.cancel(w, request_id, actor)
        except audit_integrity.ChainStopped:
            # Saved now (the removal then never runs: the job vetoes a request whose row does not wait), sealed from
            # the database once sealing runs again.
            entry = removal.cancel_while_stopped(db, request_id, current_user)
            db.commit()
    except audit_integrity.ChainBusy:
        db.rollback()
        raise HTTPException(status_code=409, detail="Busy, retry: the audit log is being sealed.")
    except LookupError:
        db.rollback()
        raise HTTPException(status_code=404, detail="No such removal")
    except removal.Refused as exc:
        db.rollback()
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception as exc:  # noqa: BLE001 -- no cancel without its audit row
        db.rollback()
        registry._say(f"Warning: a cancel of a removal was not saved ({type(exc).__name__})")
        raise HTTPException(status_code=503, detail="The removal was not cancelled: its audit record could not be "
                                                    "written. It is still waiting.")
    removal.tell_administrators("cancelled", entry, current_user.username)
    return {"status": "cancelled", "request": entry}
