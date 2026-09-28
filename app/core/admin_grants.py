"""Who made each administrator one, and when: the record the two-administrator rule reads.

A held credential change must be approved by a DIFFERENT administrator (app/core/credential_changes.py).
That rule is empty if the one asking can make the approver: create an account, make it an administrator,
sign in as it and approve. So an administrator may not approve a request when

  * the one who asked made them an administrator, directly or through an administrator the one who
    asked made (the ``lineage`` below), or
  * they became an administrator after the request was made.

A row is written, in the caller's transaction, whenever an account becomes an administrator: created as
one, promoted to one, or by accepting an administrator's invitation (granted by whoever invited). An
administrator from before this record existed, and the first one the server set up, have no row: the
person who runs the server made them, and nothing restricts them. A demotion deletes the row, and a
later promotion writes a new one, by whoever made it.

Every administrator is told when an administrator is created or promoted (the routes do that, after
their commit), so a new administrator never appears unnoticed.

Nothing here commits.
"""
from datetime import datetime, timezone
from typing import Dict, Iterable, Optional

from app.core.models import AdminGrant

# The longest lineage kept. A chain of administrators made one from another longer than this is not
# something a deployment has; the bound only keeps a row from growing without limit.
MAX_LINEAGE = 64


def utcnow() -> datetime:
    """Now as these columns store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def record(db, user_id, *, granted_by_id, granted_by_name, now: Optional[datetime] = None) -> AdminGrant:
    """Record that ``user_id`` became an administrator, made so by ``granted_by_id`` (None: the host
    operator), in the caller's transaction. Replaces an earlier record for the account."""
    now = now or utcnow()
    lineage = []
    if granted_by_id is not None:
        parent = db.get(AdminGrant, granted_by_id)
        lineage = [str(granted_by_id)] + [x for x in ((parent.lineage or []) if parent else [])
                                          if x != str(user_id)]
    row = db.get(AdminGrant, user_id)
    if row is None:
        row = AdminGrant(user_id=user_id)
        db.add(row)
    row.granted_by_id = granted_by_id
    row.granted_by_name = (granted_by_name or "")[:255]
    row.granted_at = now
    row.lineage = lineage[:MAX_LINEAGE]
    db.flush()
    return row


def forget(db, user_id) -> None:
    """The account is no longer an administrator: its record goes, in the caller's transaction."""
    db.query(AdminGrant).filter(AdminGrant.user_id == user_id).delete(synchronize_session=False)


def of(db, user_ids: Iterable) -> Dict:
    """{account id: its record} for the given accounts that have one, in one query."""
    ids = list(user_ids)
    if not ids:
        return {}
    return {g.user_id: g for g in db.query(AdminGrant).filter(AdminGrant.user_id.in_(ids)).all()}


def made_by(grant: Optional[AdminGrant], admin_id) -> bool:
    """Whether ``admin_id`` made this administrator one, directly or through administrators it made."""
    return grant is not None and admin_id is not None and str(admin_id) in (grant.lineage or [])


def granted_after(grant: Optional[AdminGrant], moment: Optional[datetime]) -> bool:
    """Whether this administrator became one after ``moment`` (naive UTC)."""
    return grant is not None and moment is not None and grant.granted_at is not None and grant.granted_at > moment
