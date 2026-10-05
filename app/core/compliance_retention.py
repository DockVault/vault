"""What the pruner keeps for compliance access: a case's audit rows and the compliance rows of the audit log.

Two row-keep rules on audit_logs (app/core/retention.py, register_keep), which every job over the table reads,
the maximum age and the size cap alike:

- A row written under a case (``case_id`` set) is kept while the case is open (not yet closed, whatever its
  state: pending, active, keeping a hold, suspended), while any legal hold of the case stands (placed and
  neither released nor lapsed), and until both COMPLIANCE_RECORD_MIN_DAYS have passed since the case closed
  and the case's own ``records_kept_until`` (the floor in force at its approval, the stricter one) has passed.
  A row whose case cannot be found is kept.
- A row of the compliance category (app/core/audit_catalog.py) is kept COMPLIANCE_RECORD_MIN_DAYS after it was
  written, case or not (an auditor grant, a reveal of a name, a refused request).

After that the rows follow the audit log's retention like any other. The floor is enforced here, by the
pruner's filters, rather than by a trigger on the busiest table: the pruner is the only thing that deletes
audit rows.
"""
from __future__ import annotations

from datetime import datetime, timedelta

from sqlalchemy import and_, exists, not_, or_

from app.core import retention


def floor_days() -> int:
    """COMPLIANCE_RECORD_MIN_DAYS, as in force now."""
    from app.core import compliance_settings as cs
    return int(cs.current(cs.RECORD_MIN_DAYS))


def case_rows_kept(model, now: datetime):
    """The rows of ``model`` (audit_logs) written under a case whose records must stay."""
    from app.core.models import ComplianceCase, LegalHoldVault
    floor = now - timedelta(days=floor_days())
    holding = exists().where(LegalHoldVault.case_id == model.case_id, LegalHoldVault.released_at.is_(None),
                             LegalHoldVault.lapsed_at.is_(None))
    # An open case has no closed_at, which is never before the floor.
    released = exists().where(ComplianceCase.id == model.case_id, ComplianceCase.closed_at < floor,
                              or_(ComplianceCase.records_kept_until.is_(None),
                                  ComplianceCase.records_kept_until < now))
    return and_(model.case_id.isnot(None), or_(not_(released), holding))


def compliance_rows_kept(model, now: datetime):
    """The rows of ``model`` (audit_logs) of the compliance category younger than the floor."""
    from app.core import audit_catalog
    return and_(model.action.in_(audit_catalog.stored_names(["compliance"])),
                model.timestamp >= now - timedelta(days=floor_days()))


retention.register_keep("audit_logs", case_rows_kept)
retention.register_keep("audit_logs", compliance_rows_kept)
