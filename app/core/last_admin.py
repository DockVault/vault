"""A deployment always keeps one administrator who can act.

Only an administrator can make another administrator, unlock an account or reactivate one. So a
change that removes the last administrator who can still sign in -- demoting them, deactivating,
locking or deleting them -- leaves nobody able to undo it, and recovery needs direct access to the
database. Every route that can make such a change asks :func:`removes_last_admin` first and refuses
with :data:`LAST_ADMIN_DETAIL` when it answers True.

Administrators cannot do any of those things to themselves either (each route refuses a change to
your own account with its own message), so on its own this guard mostly catches two administrators
removing each other at the same moment. That is why it counts under a row lock.
"""
from app.core.models import RoleEnum, User

LAST_ADMIN_DETAIL = ("This would leave no active administrator. Make another account an "
                     "administrator first.")


def can_administer(user) -> bool:
    """An administrator who can act right now: active, and not locked.

    A timed lock on the account row (from before automatic locks moved to their own table) counts
    until its time runs out, exactly as sign-in reads it. An automatic lock in sign_in_lockouts does
    not: it only pauses new sign-ins, and the administrator's sessions carry on."""
    from app.services.auth_service import account_locked
    return (getattr(user, "role", None) == RoleEnum.ADMIN
            and getattr(user, "is_active", None) is not False
            and not account_locked(user))


def is_last_able_admin(admins, target_id) -> bool:
    """True if ``target_id`` is the only administrator in ``admins`` who can act."""
    able = [a.id for a in admins if can_administer(a)]
    return able == [target_id]


def removes_last_admin(db, target) -> bool:
    """True if taking ``target`` out of the administrators would leave none who can act.

    Every administrator row is locked first, in id order. Two such changes made at the same moment
    could otherwise both pass, each counting the other as the one who remains; with the lock the
    second waits for the first to commit and then counts what it left. populate_existing() makes the
    count read the rows as they stand under the lock, not as this session first loaded them.

    Call it BEFORE changing anything on ``target``: the refresh reloads every administrator this
    session holds, and would discard an edit not yet written."""
    admins = (db.query(User).filter(User.role == RoleEnum.ADMIN).order_by(User.id)
              .populate_existing().with_for_update().all())
    return is_last_able_admin(admins, getattr(target, "id", None))
