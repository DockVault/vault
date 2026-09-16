"""BV2 credential-lifecycle slot logic (app/core/temp_cred_slot.py): the ONE shared cap predicate
both caps use, the release that frees a slot on connection FINISH, and the upgrade backfill that must
not flip an in-flight row.

The predicate and the backfill selection are parameterised by model, so these run the REAL query
construction against a throwaway sqlite schema rather than a copy of it. The row-level twin and the
release are pinned as pure behaviour.
"""
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace

import pytest

from app.core import temp_cred_slot as slot

pytestmark = pytest.mark.unit

_NOW = datetime(2026, 1, 1, 12, 0, 0)
_PAST = _NOW - timedelta(minutes=5)
_FUTURE = _NOW + timedelta(minutes=5)


def _cred(**kw):
    base = dict(is_active=True, slot_released_at=None, deactivate_at=_FUTURE, is_used=False, used_at=None)
    base.update(kw)
    return SimpleNamespace(**base)


# ---- row-level predicate (is_outstanding / is_finished) ------------------------------------------
def test_active_unreleased_within_validity_holds_a_slot():
    assert slot.is_outstanding(_cred(), _NOW) is True
    assert slot.is_finished(_cred(), _NOW) is False


def test_a_used_but_unreleased_credential_still_holds_its_slot():
    # In use: spent at first auth but its connection is still open. The slot frees on CLOSE, not on
    # spend, so a used-but-unreleased credential must still count.
    assert slot.is_outstanding(_cred(is_used=True), _NOW) is True


def test_a_released_credential_holds_no_slot():
    c = _cred(is_used=True, slot_released_at=_PAST)
    assert slot.is_outstanding(c, _NOW) is False
    assert slot.is_finished(c, _NOW) is True


def test_past_validity_holds_no_slot_even_if_never_released():
    # The amplifier fix: a credential past its validity window frees its slot even if the close hook
    # never fired (a SIGKILLed connection), rather than lingering to the 65-minute hard expiry.
    c = _cred(deactivate_at=_PAST)
    assert slot.is_outstanding(c, _NOW) is False
    assert slot.is_finished(c, _NOW) is True


def test_a_revoked_credential_is_neither_outstanding_nor_finished():
    # is_active False = 'deleted', a distinct state the gates refuse on is_active, not a freed slot.
    c = _cred(is_active=False)
    assert slot.is_outstanding(c, _NOW) is False
    assert slot.is_finished(c, _NOW) is False


def test_is_outstanding_normalizes_a_tz_aware_validity():
    aware = _FUTURE.replace(tzinfo=timezone.utc)
    assert slot.is_outstanding(_cred(deactivate_at=aware), _NOW) is True


# ---- release (mark_released) ---------------------------------------------------------------------
def test_mark_released_sets_the_timestamp_once_and_never_changes_is_used_or_is_active():
    # Release NEVER touches is_used: it must not un-spend a spent credential, and (the mutation this
    # guards) it must not SPEND an unspent one either -- a connection can close on a credential that
    # never authenticated, and freeing its slot is not the same as marking it used.
    unspent = _cred(is_used=False)
    assert slot.mark_released(unspent, _NOW) is True
    assert unspent.slot_released_at == _NOW
    assert unspent.is_used is False and unspent.is_active is True   # not spent, not 'deleted'

    spent = _cred(is_used=True)
    assert slot.mark_released(spent, _NOW) is True
    assert spent.is_used is True and spent.is_active is True        # spent stays spent
    # Idempotent: a re-close (or the reaper running after the close hook) never moves it.
    assert slot.mark_released(spent, _NOW + timedelta(minutes=1)) is False
    assert spent.slot_released_at == _NOW


# ---- SQL predicate + backfill against a throwaway schema -----------------------------------------
def _sqlite_env():
    sa = pytest.importorskip("sqlalchemy")
    from sqlalchemy.orm import declarative_base, sessionmaker

    Base = declarative_base()

    class Cred(Base):
        __tablename__ = "cred_probe"
        id = sa.Column(sa.Integer, primary_key=True)
        device_id = sa.Column(sa.String)
        is_active = sa.Column(sa.Boolean)
        is_used = sa.Column(sa.Boolean)
        used_at = sa.Column(sa.DateTime)
        deactivate_at = sa.Column(sa.DateTime)
        slot_released_at = sa.Column(sa.DateTime)

    class Sess(Base):
        __tablename__ = "sess_probe"
        id = sa.Column(sa.Integer, primary_key=True)
        temp_credential_id = sa.Column(sa.Integer)
        is_active = sa.Column(sa.Boolean)
        expires_at = sa.Column(sa.DateTime)

    engine = sa.create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    return Cred, Sess, sessionmaker(bind=engine)()


def test_outstanding_conditions_counts_only_slot_holders_and_isolates_by_scope():
    Cred, _Sess, s = _sqlite_env()
    s.add_all([
        Cred(id=1, device_id="A", is_active=True, is_used=False, deactivate_at=_FUTURE, slot_released_at=None),   # active
        Cred(id=2, device_id="A", is_active=True, is_used=True, deactivate_at=_FUTURE, slot_released_at=None),    # in use
        Cred(id=3, device_id="A", is_active=True, is_used=True, deactivate_at=_FUTURE, slot_released_at=_PAST),   # released -> no
        Cred(id=4, device_id="A", is_active=True, is_used=False, deactivate_at=_PAST, slot_released_at=None),     # past validity -> no
        Cred(id=5, device_id="A", is_active=False, is_used=False, deactivate_at=_FUTURE, slot_released_at=None),  # revoked -> no
        Cred(id=6, device_id="B", is_active=True, is_used=False, deactivate_at=_FUTURE, slot_released_at=None),   # other scope
    ])
    s.commit()

    def count(dev):
        return s.query(Cred).filter(Cred.device_id == dev, *slot.outstanding_conditions(Cred, _NOW)).count()

    assert count("A") == 2   # only the active + the in-use row (released/expired/revoked drop out)
    assert count("B") == 1   # scope isolation: one scope never counts another's slots


def test_backfill_releases_spent_credentials_but_never_an_in_flight_one():
    Cred, Sess, s = _sqlite_env()
    s.add_all([
        Cred(id=1, is_active=True, is_used=True, deactivate_at=_PAST, slot_released_at=None, used_at=_PAST),    # spent, no session
        Cred(id=2, is_active=True, is_used=True, deactivate_at=_FUTURE, slot_released_at=None, used_at=_PAST),  # spent, LIVE session -> in flight
        Cred(id=3, is_active=True, is_used=False, deactivate_at=_FUTURE, slot_released_at=None, used_at=None),  # never used
        Cred(id=4, is_active=True, is_used=True, deactivate_at=_FUTURE, slot_released_at=_PAST, used_at=_PAST), # already released
        Cred(id=5, is_active=True, is_used=True, deactivate_at=_FUTURE, slot_released_at=None, used_at=_PAST),  # spent, EXPIRED session
    ])
    s.add_all([
        Sess(id=1, temp_credential_id=2, is_active=True, expires_at=_FUTURE),  # cred 2: connection open now
        Sess(id=2, temp_credential_id=5, is_active=True, expires_at=_PAST),    # cred 5: session already expired
    ])
    s.commit()

    targets = {c.id for c in slot.released_backfill_query(s, Cred, Sess, _NOW).all()}
    # Spent AND not-in-flight are released (1, 5); the in-flight row (2) is protected; never-used (3)
    # and already-released (4) are not backfill targets.
    assert targets == {1, 5}

    # Applying the release leaves the in-flight credential's slot unfreed.
    slot.released_backfill_query(s, Cred, Sess, _NOW).update(
        {Cred.slot_released_at: _NOW}, synchronize_session=False)
    s.commit()
    assert s.get(Cred, 2).slot_released_at is None   # in flight -> stays in use across upgrade
    assert s.get(Cred, 1).slot_released_at == _NOW
