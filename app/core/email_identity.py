"""Normalization and uniqueness for the optional `users.email` column.

An account may have no email at all, and an email that IS present must be unambiguous — otherwise
`A@x.com` and `a@x.com` are two accounts, which becomes an impersonation vector the moment an
address can be used as a login identifier.

Two rules, and they are deliberately separate:

* **Normalize on write.** Every write path stores the trimmed, lowercased form, so the stored value
  is already canonical and nothing downstream has to remember to fold case.
* **Check case-insensitively.** A functional unique index on `lower(email)` is the only guard that
  survives two concurrent requests claiming the same address, but it cannot be relied on to exist:
  a deployment that already holds `Bob@x.com` and `bob@x.com` cannot build that index, and per owner
  design such a deployment boots anyway with a warning rather than failing. On those installs
  the application check below is the only guard there is, so it is not redundant with the index —
  it is the fallback for exactly the installs that need one most.

The empty string is normalized to `None` rather than stored. Otherwise "no email" would have two
distinct representations, `''` would collide with itself under the unique index, and every NULL
check downstream would need an `or not email` beside it.
"""
from typing import Optional

from sqlalchemy import func, text

from app.core.models import User

# Name of the functional unique index built at boot. Kept here so the migration that creates it and
# any diagnostic that looks for it cannot drift apart.
EMAIL_LOWER_UNIQUE_INDEX = "uq_users_email_lower"


def _fold_ascii(value: str) -> str:
    """Lowercase ASCII only, leaving everything else for the database to fold.

    Python's `str.lower()` and Postgres's `lower()` agree on ASCII and can DISAGREE outside it:
    `'İ'.lower()` is `i` followed by a combining dot above (U+0307), while Postgres returns a bare
    `i`. A value folded by one and compared against the other does not match, which is precisely
    how two accounts end up holding one address as printed — the impersonation case this module
    exists to prevent.

    So there is exactly ONE implementation of "the same address" in play: Postgres's. Non-ASCII is
    left untouched here and folded by the database on BOTH sides of every comparison and in the
    unique index. ASCII is folded here too, because that covers every real address and keeps the
    stored value readable.
    """
    return "".join(c.lower() if c.isascii() else c for c in value)


def normalize_email(value) -> Optional[str]:
    """Canonical stored form of an address: trimmed and ASCII-lowercased, or None.

    Accepts anything stringable (notably pydantic's `EmailStr`) so callers do not each have to
    remember the `str()`. Whitespace-only and empty input collapse to None — see the module note on
    why "no email" must have exactly one representation.

    Note this only canonicalizes; it does not validate. Validation belongs to the pydantic schema at
    the edge, which rejects a malformed address before it ever reaches here.
    """
    if value is None:
        return None
    normalized = _fold_ascii(str(value).strip())
    return normalized or None


def email_in_use(db, email, exclude_user_id=None) -> bool:
    """Is this address already claimed by some other account?

    Case-insensitive, matching the index. `exclude_user_id` lets an update ignore the row being
    updated, so re-saving a profile without touching the address is not a self-collision.

    An absent email NEVER collides. Postgres treats NULLs as distinct under UNIQUE, so any number of
    email-less accounts coexist at the database level, and this check has to agree — the previous
    code did not, and `User.email == None` compiles to `email IS NULL`, which matches every
    email-less row and made the *second* email-less account impossible to create.
    """
    normalized = normalize_email(email)
    if normalized is None:
        return False
    # BOTH sides are folded by the database, not one here and one there. A legacy row still holds
    # whatever bytes an older release stored, so folding the candidate in Python and the column in
    # SQL would compare two different notions of "lowercase" and miss a genuine duplicate.
    query = db.query(User.id).filter(func.lower(User.email) == func.lower(normalized))
    if exclude_user_id is not None:
        query = query.filter(User.id != exclude_user_id)
    return query.first() is not None


def find_user_by_email(db, email):
    """Resolve an address to the single account that owns it, case-insensitively, or None.

    Uses the database's `lower()` on BOTH sides — the exact expression the unique index and
    `email_in_use` use — so "the same address" has one definition everywhere (see `_fold_ascii`).

    Returns None for every ambiguous input, because this feeds login and an arbitrary pick is
    impersonation:

    * a blank/absent candidate (`normalize_email` -> None) — a NULL-email account is never
      reachable by email, and a `None` candidate must not compile to `email IS NULL` and match
      every email-less row;
    * no match; and
    * MORE THAN ONE match — a deployment that already held `Bob@x.com` and `bob@x.com` could not
      build the `lower(email)` unique index and boots anyway (see the module note), so one address
      can own two rows. Authenticating an arbitrary one is the impersonation case this module
      exists to prevent, so >1 rows is treated as no match: fail closed.
    """
    normalized = normalize_email(email)
    if normalized is None:
        return None
    rows = (
        db.query(User)
        .filter(func.lower(User.email) == func.lower(normalized))
        .limit(2)
        .all()
    )
    return rows[0] if len(rows) == 1 else None


def find_email_collisions(db):
    """Groups of existing accounts whose emails differ only in case.

    Used at boot to decide whether the functional unique index can be built at all. Returns a list
    of `(normalized_address, "user_a, user_b")`, empty when the data is clean.

    Takes anything with `.execute` — a Session during boot, a Connection in a test — so it does not
    care which layer the caller happens to hold.
    """
    rows = db.execute(text(
        """
        -- Groups on lower(email), the EXACT expression the unique index uses. Grouping on
        -- lower(trim(email)) instead would report a collision for two rows that differ only in
        -- surrounding whitespace, which the index would happily accept -- skipping the index
        -- forever on a database that could build it, and naming two accounts whose addresses
        -- print identically so the operator has nothing to act on.
        SELECT lower(email) AS normalized,
               string_agg(username, ', ' ORDER BY username) AS usernames
          FROM users
         WHERE email IS NOT NULL AND email <> ''
         GROUP BY lower(email)
        HAVING count(*) > 1
         ORDER BY normalized
        """
    )).fetchall()
    return [(row[0], row[1]) for row in rows]
