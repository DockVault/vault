"""One shared definition of when a temporary credential occupies a cap slot, plus the release that
frees it and the one-time upgrade backfill.

A temporary credential holds a slot in BOTH the per-user and the per-device credential caps from the
moment it is minted until it is RELEASED. Release is state-derived from the server's own
connection-close (the SFTP finally hook sets ``slot_released_at``), never a holder-claimable "I'm
done" call. The slot also frees on its own at the end of the credential's VALIDITY window
(``deactivate_at``) — past that a credential can no longer authenticate, so it must not keep
occupying a slot even if the close hook never fired (a SIGKILLed connection). That validity bound is
what stops the measured amplifier: before this, an unspent 1-minute credential kept its slot for the
full 65-minute hard lifetime.

``is_used`` is deliberately NOT part of the predicate. A single-use credential is spent at its first
auth but stays IN USE while its connection is open, so the slot frees on close, not on spend — and a
spent credential stays spent (release never touches ``is_used``). The three lifecycle states a caller
cares about are all derived from these columns: *active* (unreleased, unused, within validity),
*in use* (unreleased, used, connection open), *used / shown "expired"* (released, or past validity).
"""
from datetime import datetime


def outstanding_conditions(model, now: datetime):
    """SQLAlchemy filter conditions selecting the credentials that currently hold a cap slot.

    Callers AND their own scoping (``user_id ==`` for the per-user cap, ``device_id ==`` for the
    per-device cap) so both caps count the SAME set of slot-holders — the single shared predicate the
    mint and the pre-flight must agree on. ``model`` is the mapped class to build the clauses against
    (``TemporaryCredential`` in production; a throwaway mirror in the tests, so the behaviour is
    pinned against the real predicate rather than a copy). ``now`` is naive UTC (``deactivate_at`` is
    stored naive).
    """
    return (
        model.is_active == True,            # noqa: E712 — a revoked/deactivated credential holds nothing
        model.slot_released_at.is_(None),   # released by the connection-close hook -> slot freed
        model.deactivate_at > now,          # past its validity window -> cannot authenticate -> no slot
    )


def _aware_naive(value):
    """Drop tzinfo so a freshly-built (tz-aware) object compares like the DB's naive column."""
    if value is not None and value.tzinfo is not None:
        return value.replace(tzinfo=None)
    return value


def is_outstanding(cred, now: datetime = None) -> bool:
    """Row-level twin of ``outstanding_conditions`` for a single loaded credential (the gates use it
    to refuse a finished credential). Same three-part test, evaluated in Python."""
    now = now or datetime.utcnow()
    deactivate_at = _aware_naive(getattr(cred, "deactivate_at", None))
    return (
        bool(getattr(cred, "is_active", False))
        and getattr(cred, "slot_released_at", None) is None
        and deactivate_at is not None
        and deactivate_at > _aware_naive(now)
    )


def is_finished(cred, now: datetime = None) -> bool:
    """True when the credential no longer holds a slot: released on connection close, or past its
    validity window. The complement of :func:`is_outstanding` restricted to live (is_active) rows —
    a revoked credential is 'deleted', a distinct state the gates already refuse on is_active."""
    if not getattr(cred, "is_active", False):
        return False
    return not is_outstanding(cred, now)


def mark_released(cred, when: datetime = None) -> bool:
    """Release the credential's cap slot — the state-derived record that its connection FINISHED.

    Idempotent: the first release wins, so a re-close (or the reaper backstop running after the close
    hook) never moves the timestamp. Single-use-safe: it never touches ``is_used`` (a spent credential
    stays spent) and never flips ``is_active`` (the row is 'used/expired', not 'deleted'). Returns
    True only on the transition, so a caller can log/commit just the real release."""
    if getattr(cred, "slot_released_at", None) is None:
        cred.slot_released_at = when or datetime.utcnow()
        return True
    return False


_BACKFILL_MARKER_KEY = "temp_cred_slot_released_backfill_v1"


def backfill_released_slots(db) -> int:
    """One-time upgrade backfill: release the slots of credentials already FINISHED under the
    pre-lifecycle model (spent, ``is_used``), EXCEPT any whose connection is still OPEN at upgrade
    time — an active, unexpired session — which must stay IN USE. Idempotent via a SystemSetting
    marker (the ``audit_migrations`` precedent), so it scans once and never re-touches live rows on a
    later boot. Returns the number of rows released.

    Without it, every historically-spent credential would read as an unreleased slot-holder after the
    column is added and would wrongly occupy a cap slot until its validity window elapsed; with the
    naive `EXISTS(active session)` guard, a credential whose connection is open at upgrade time is
    left unreleased and stays in use.
    """
    from sqlalchemy import func
    from app.core.models import ActiveSession, SystemSetting, TemporaryCredential

    if db.query(SystemSetting).filter(SystemSetting.key == _BACKFILL_MARKER_KEY).first():
        return 0

    now = datetime.utcnow()
    updated = released_backfill_query(db, TemporaryCredential, ActiveSession, now).update(
        {TemporaryCredential.slot_released_at: func.coalesce(TemporaryCredential.used_at, now)},
        synchronize_session=False,
    )
    db.add(SystemSetting(key=_BACKFILL_MARKER_KEY, value={"rows": updated}))
    db.commit()
    return updated


def released_backfill_query(db, cred_model, session_model, now: datetime):
    """The rows the one-time backfill releases: credentials spent (``is_used``) under the old model
    whose slot is not yet released AND whose connection is NOT open right now (no active, unexpired
    session). Split out and parameterised by model so the in-flight guard is pinned behaviourally
    against the real query rather than a copy. Returns a Query; the caller applies the update."""
    from sqlalchemy import or_
    live_session = (
        db.query(session_model.id)
        .filter(
            session_model.temp_credential_id == cred_model.id,
            session_model.is_active == True,  # noqa: E712
            or_(session_model.expires_at.is_(None), session_model.expires_at > now),
        )
        .exists()
    )
    return db.query(cred_model).filter(
        cred_model.slot_released_at.is_(None),
        cred_model.is_used == True,  # noqa: E712 — spent under the old model = finished
        ~live_session,               # ...unless its connection is open right now (in flight)
    )


def release_for_session(db, cred_model, session_model, session_token, when: datetime = None) -> bool:
    """The connection-close hook's DB effect: end the session behind ``session_token`` and, if it is a
    temporary-credential session, RELEASE that credential's cap slot. State-derived from the server's
    own close — never a holder-claimable call. Idempotent (an already-released slot is not moved, and
    an already-ended session stays ended) and single-use-safe (never touches ``is_used``). Parameterised
    by model so it is pinned against a throwaway schema. The raw token is hashed here (never compared
    in plaintext), so callers pass the token the transport holds. Returns True only when it released."""
    from app.core.session_hash_utils import hash_session_token
    session = (
        db.query(session_model)
        .filter(session_model.session_token == hash_session_token(session_token))
        .first()
    )
    if session is None:
        return False
    released = False
    if session.temp_credential_id is not None:
        cred = (
            db.query(cred_model)
            .filter(cred_model.id == session.temp_credential_id)
            .first()
        )
        if cred is not None:
            released = mark_released(cred, when)
    session.is_active = False  # the connection is gone -> the session ends (the gates see it closed)
    return released


def release_ended_session_slots(db, cred_model, session_model, ended_cred_ids, when=None) -> int:
    """Release the cap slot of each temp credential in ``ended_cred_ids`` whose LAST active session
    has just ended -- web logout, admin terminate, or the session reaper. A hand-out credential spent
    at the WEB door otherwise holds its slot until its validity window; this frees it when the
    session that was using it goes away, the web twin of the SFTP connection-close release.

    The caller must have ALREADY marked the ended sessions ``is_active=False`` (and flushed), so the
    "any session still open?" guard sees the truth: a credential with another live session keeps its
    slot (a temp credential is single-session today, so this guards a future, not a common case).
    Idempotent and single-use-safe -- ``mark_released`` never touches ``is_used``/``is_active``.
    Returns the count released."""
    released = 0
    for cid in {c for c in ended_cred_ids if c is not None}:
        still_open = (
            db.query(session_model.id)
            .filter(session_model.temp_credential_id == cid,
                    session_model.is_active == True)  # noqa: E712
            .first()
        )
        if still_open is not None:
            continue
        cred = db.query(cred_model).filter(cred_model.id == cid).first()
        if cred is not None and mark_released(cred, when):
            released += 1
    return released


def release_expired_slots(db, cred_model, now: datetime) -> int:
    """Reaper BACKSTOP: release the slots of credentials whose VALIDITY window has ended but whose
    close hook never fired — a SIGKILLed connection. Keyed on ``deactivate_at``, NEVER on the
    never-updated ``last_activity`` column. The validity bound already drops these from the cap; this
    records the finished state and bounds a SIGKILL orphan. Idempotent (only unreleased rows), and it
    never touches ``is_used``. Returns rows released."""
    from sqlalchemy import func
    return (
        db.query(cred_model)
        .filter(
            cred_model.is_active == True,  # noqa: E712 — a revoked row is 'deleted', not a freed slot
            cred_model.slot_released_at.is_(None),
            cred_model.deactivate_at < now,
        )
        .update(
            {cred_model.slot_released_at: func.coalesce(cred_model.deactivate_at, now)},
            synchronize_session=False,
        )
    )


def display_lifecycle(cred, active_session_count=0, now: datetime = None) -> str:
    """The user-facing lifecycle label for a credential row: 'expired' when it no longer holds a slot
    (released on the connection close, revoked, or past its validity window), 'in-use' when it still
    holds a slot AND a live session is open, else 'active'. Derived from is_active + slot_released_at +
    deactivate_at (via :func:`is_outstanding`) and the live-session count -- the same signals the cap
    reads -- so the page state matches the connection state and a finished credential never shows
    active."""
    now = now or datetime.utcnow()
    if not is_outstanding(cred, now):
        return "expired"
    if active_session_count and active_session_count > 0:
        return "in-use"
    return "active"
