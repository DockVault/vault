"""The compliance case the code running now acts under, for the audit rows it writes.

A step of a case (placing or releasing its legal hold, approving it, opening a file in it) writes its audit
rows inside ``acting_for(case_id)``; AuditLogger.build_row's case hook (app/services/audit_row_hooks.py) puts
that case's id on each row it builds there (audit_logs.case_id). A row with a case id is kept while its case
is open or a hold stands, and for COMPLIANCE_RECORD_MIN_DAYS after the case closes
(app/core/compliance_retention.py). Outside such a block a row has no case.

A context variable, so it follows the request's own thread or task and never leaks into another request.
"""
from __future__ import annotations

import contextvars
import uuid
from contextlib import contextmanager
from typing import Optional

_CASE: contextvars.ContextVar = contextvars.ContextVar("dockvault_compliance_case", default=None)


def current() -> Optional[uuid.UUID]:
    """The case the running code acts under, or None."""
    return _CASE.get()


@contextmanager
def acting_for(case_id):
    """Audit rows built inside this block carry ``case_id``."""
    token = _CASE.set(uuid.UUID(str(case_id)) if case_id is not None else None)
    try:
        yield
    finally:
        _CASE.reset(token)
