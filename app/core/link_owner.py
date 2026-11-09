"""Whether the owner of an anonymous link (a note, file or upload link) may still publish through it.

The account must exist and be active, and not be locked by an administrator. An administrator's lock has no
end (is_locked with locked_until empty); the automatic lock that wrong passwords arm has an end time and does
NOT take the links down: anyone who knows a username can arm it again and again, so letting it stop the links
would let a stranger make every link of that user answer 404 for as long as they kept guessing. That lock is
about signing in; the links stay as the owner left them.

Read by the link routes (app/api/api_server.py, _link_owner_if_live) and by the reminders before a link
expires (app/core/expiry_reminders.py): a link whose owner may not publish is dead, and is not reminded.
"""
from __future__ import annotations


def may_publish(user) -> bool:
    if user is None or not getattr(user, "is_active", True):
        return False
    if getattr(user, "is_locked", False) and getattr(user, "locked_until", None) is None:
        return False
    return True
