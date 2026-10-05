"""The Activity page's searches with the filters in the request body.

    POST /activity/events/search    the Events list (as GET /activity/events)
    POST /activity/summary/search   the summary band (as GET /activity/summary)
    POST /activity/export           the export (as GET /activity/export)

A filter can hold what someone typed: a person's name, an address, free text. In a query string it would reach
every line that records the request (the server's output and the log-access copy); in the body it reaches none.
Each route takes the same filters, with the same bounds, as its GET form, and answers exactly as it does: the
same handler runs. A name typed into the person filter also matches the rows that recorded it as a fingerprint
(app/services/activity_events.py). Only an interactive administrator reaches them.
"""
from __future__ import annotations

from typing import List, Optional

from fastapi import APIRouter, Depends, Request
from pydantic import BaseModel, Field
from sqlalchemy.orm import Session

from app.api.user_management_api import require_interactive_admin
from app.core.database import get_db
from app.core.models import User

router = APIRouter(tags=["Activity search"])


class Filters(BaseModel):
    category: List[str] = Field(default_factory=list, max_length=200)
    channel: List[str] = Field(default_factory=list, max_length=20)
    status: List[str] = Field(default_factory=list, max_length=20)
    action: List[str] = Field(default_factory=list, max_length=500)
    user: Optional[str] = Field(None, max_length=128)
    user_match: str = Field("contains", pattern="^(contains|exact)$")
    no_account: bool = False
    ip: Optional[str] = Field(None, max_length=64)
    q: Optional[str] = Field(None, max_length=128)
    temp_credential_id: Optional[str] = Field(None, max_length=64)
    temp_credential: Optional[str] = Field(None, max_length=128)
    vault_id: Optional[str] = Field(None, max_length=64)
    from_date: Optional[str] = Field(None, max_length=64)
    to_date: Optional[str] = Field(None, max_length=64)


class EventsSearch(Filters):
    cursor: Optional[str] = Field(None, max_length=200)
    page: Optional[int] = Field(None, ge=1, le=1_000_000)
    after: Optional[str] = Field(None, max_length=200)
    overlap: int = Field(0, ge=0, le=300)
    ids: List[str] = Field(default_factory=list, max_length=8000)
    count_only: bool = False
    limit: int = 50


class SummarySearch(Filters):
    range: str = Field("24h", pattern="^(24h|7d|30d|custom|all)$")
    range_from: Optional[str] = Field(None, max_length=64)
    range_to: Optional[str] = Field(None, max_length=64)
    tz: Optional[str] = Field(None, max_length=64, pattern=r"^[A-Za-z0-9_+-]+(/[A-Za-z0-9_+-]+)*$")
    tz_offset: int = Field(0, ge=-840, le=840)


class ExportSearch(Filters):
    format: str = Field("csv", pattern="^(csv|ndjson)$")


@router.post("/activity/events/search")
def search_events(body: EventsSearch, request: Request, current_user: User = Depends(require_interactive_admin),
                  db: Session = Depends(get_db)):
    """The Events list for the filters in the body."""
    from app.api.api_server import activity_events
    return activity_events(**body.model_dump(), request=request, current_user=current_user, db=db)


@router.post("/activity/summary/search")
def search_summary(body: SummarySearch, current_user: User = Depends(require_interactive_admin),
                   db: Session = Depends(get_db)):
    """The summary band for the filters in the body."""
    from app.api.api_server import activity_summary
    fields = body.model_dump()
    fields["range_"] = fields.pop("range")
    return activity_summary(**fields, current_user=current_user, db=db)


@router.post("/activity/export")
def export_events(body: ExportSearch, request: Request, current_user: User = Depends(require_interactive_admin),
                  db: Session = Depends(get_db)):
    """The export for the filters in the body."""
    from app.api.api_server import activity_export
    return activity_export(**body.model_dump(), request=request, current_user=current_user, db=db)
