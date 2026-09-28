"""Who made each administrator one, and when: the record the two-administrator rule reads.

A held credential change must be approved by a DIFFERENT administrator (app/core/credential_changes.py).
That rule is empty if the one asking can make the approver: create an account, make it an administrator,
sign in as it and approve. So the rule reads, from the records here:

  * each administrator's ``lineage``: who made them one, who made that one, and so on. Neither the one
    who asked nor the approver may be in the other's lineage;
  * when each became an administrator. An approver must have been one for at least 14 days before the
    request was made, so an administrator made for the purpose cannot approve for a fortnight.

A row is written, in the caller's transaction, whenever an account becomes an administrator: created as
one, promoted to one, or by accepting an administrator's invitation (granted by whoever invited). An
administrator's invitation keeps its inviter's lineage from the moment it is made (lineage_through),
and the account that accepts it inherits that lineage, so demoting or deleting the inviter in between
cannot shorten it. An administrator from before this record existed, and the first one the server set
up, have no row: the person who runs the server made them, they count as administrators of long
standing, and nothing restricts them. A demotion deletes the row; a later promotion writes a new one,
by whoever made it, from that moment.

Every administrator is told when an administrator is created or promoted (the routes do that, after
their commit), so a new administrator never appears unnoticed.

Nothing here commits.
"""
from datetime import datetime, timezone
from typing import Dict, Iterable, List, Optional

from app.core.models import AdminGrant

# The longest lineage kept. A chain of administrators made one from another longer than this is not
# something a deployment has; the bound only keeps a row from growing without limit.
MAX_LINEAGE = 64


def utcnow() -> datetime:
    """Now as these columns store it: UTC with no time zone attached."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def lineage_through(db, admin_id) -> List[str]:
    """The lineage an administrator made by ``admin_id`` gets: ``admin_id``, then the administrators
    ``admin_id`` descends from, nearest first. Empty for the host operator (None).

    What an administrator's invitation keeps when it is made, so the account that accepts it descends
    from the same administrators even if the inviter has been demoted (which deletes their record) or
    deleted by then."""
    if admin_id is None:
        return []
    parent = db.get(AdminGrant, admin_id)
    return ([str(admin_id)] + [str(x) for x in ((parent.lineage or []) if parent else [])])[:MAX_LINEAGE]


def record(db, user_id, *, granted_by_id, granted_by_name, now: Optional[datetime] = None,
           inherited: Optional[Iterable] = None) -> AdminGrant:
    """Record that ``user_id`` became an administrator, made so by ``granted_by_id`` (None: the host
    operator, or an inviter since deleted), in the caller's transaction. Replaces an earlier record for
    the account. ``inherited`` is a lineage kept from earlier (an invitation's, see lineage_through): it
    is added after the one read now, so nothing the inviter's record lost since is lost here."""
    now = now or utcnow()
    lineage: List[str] = []
    for x in lineage_through(db, granted_by_id) + [str(i) for i in (inherited or [])]:
        if x != str(user_id) and x not in lineage:
            lineage.append(x)
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
    ids = [i for i in user_ids if i is not None]
    if not ids:
        return {}
    return {g.user_id: g for g in db.query(AdminGrant).filter(AdminGrant.user_id.in_(ids)).all()}


def made_by(grant: Optional[AdminGrant], admin_id) -> bool:
    """Whether ``admin_id`` made this administrator one, directly or through administrators it made."""
    return grant is not None and admin_id is not None and str(admin_id) in (grant.lineage or [])


def granted_after(grant: Optional[AdminGrant], moment: Optional[datetime]) -> bool:
    """Whether this administrator became one after ``moment`` (naive UTC). An administrator with no
    record (from before the record existed, or the first one) became one before any moment asked
    about."""
    return grant is not None and moment is not None and grant.granted_at is not None and grant.granted_at > moment
