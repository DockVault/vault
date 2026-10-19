"""The single-use download grant of a public file or folder link, against an in-memory store.

Redeeming a link spends one of its uses and mints a grant; the download that follows spends nothing
more. So the download does not ask whether the link has a use left (the redeem spent it), only
whether this grant may still deliver: it must belong to this link and to the address that redeemed
it, it must not have been used, and it must have been minted before the link expired. A grant that
lost the race for the link's last use is discarded at once, and so is one whose use the database could
not record (the real redeem handler, against a stand-in database).
"""
from datetime import datetime, timedelta, timezone

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S
from app.core import rate_limiter as R

pytestmark = pytest.mark.unit

LINK = "9f6c1d2e-0000-4000-8000-000000000001"
OTHER_LINK = "9f6c1d2e-0000-4000-8000-000000000002"
ADDRESS = "192.0.2.10"
MINTED = datetime(2026, 10, 16, 10, 0, 0, 123456)


class _Store:
    """The four calls the grant helpers make, on a dict, with SET's NX and EX options."""

    def __init__(self):
        self.data = {}
        self.expiry = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.data:
            return None
        self.data[key] = value.encode()
        self.expiry[key] = ex
        return True

    def get(self, key):
        return self.data.get(key)

    def delete(self, key):
        return 1 if self.data.pop(key, None) is not None else 0


@pytest.fixture
def store(monkeypatch):
    R._cb_record_success()                    # the breaker closed: the helpers use the store
    fake = _Store()
    monkeypatch.setattr(R.rate_limiter, "redis", fake, raising=False)
    return fake


def _issue(minted=MINTED, link=LINK, address=ADDRESS):
    return S._publiclink_issue_grant(link, address, minted)


def test_a_grant_records_its_link_address_and_mint_time_for_its_lifetime(store):
    grant = _issue()
    key = S._publiclink_grant_key(grant)
    assert grant not in key                               # stored under a hash of the secret
    assert store.data[key] == f"{LINK}|{ADDRESS}|2026-10-16T10:00:00.123456".encode()
    assert store.expiry[key] == S._PUBLINK_GRANT_TTL == 60


def test_a_grant_delivers_once_for_its_own_link_and_address(store):
    grant = _issue()
    assert S._publiclink_consume_grant(grant, OTHER_LINK, ADDRESS) is False
    assert S._publiclink_consume_grant(grant, LINK, "192.0.2.11") is False
    assert S._publiclink_consume_grant("not-the-grant", LINK, ADDRESS) is False
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS) is True
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS) is False   # used
    assert store.data == {}


def test_of_two_downloads_racing_with_one_grant_only_the_one_that_removes_it_delivers(store):
    grant = _issue()
    read = store.get

    def read_then_lose_the_race(key):
        # Another download read the same grant and removed it between this one's read and delete.
        value = read(key)
        store.data.pop(key, None)
        return value

    store.get = read_then_lose_the_race
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS) is False


def test_a_grant_minted_before_the_link_expired_still_delivers(store):
    # The redeem spent the use while the link was live; the link expiring before the download
    # reaches the server does not take that download back.
    assert S._publiclink_consume_grant(_issue(), LINK, ADDRESS,
                                       expires_at=MINTED + timedelta(microseconds=1)) is True
    assert S._publiclink_consume_grant(_issue(), LINK, ADDRESS, expires_at=None) is True


@pytest.mark.parametrize("expires_at", [MINTED, MINTED - timedelta(hours=1)])
def test_a_grant_minted_at_or_after_the_link_expired_is_refused(store, expires_at):
    grant = _issue()
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS, expires_at=expires_at) is False


def test_an_aware_expiry_is_compared_in_utc(store):
    aware = (MINTED + timedelta(seconds=1)).replace(tzinfo=timezone.utc).astimezone(
        timezone(timedelta(hours=3)))
    assert S._publiclink_consume_grant(_issue(), LINK, ADDRESS, expires_at=aware) is True
    aware_before = (MINTED - timedelta(seconds=1)).replace(tzinfo=timezone.utc)
    assert S._publiclink_consume_grant(_issue(), LINK, ADDRESS, expires_at=aware_before) is False


@pytest.mark.parametrize("value", [
    f"{LINK}|{ADDRESS}",                          # no mint time: never minted by this release
    f"{LINK}|{ADDRESS}|yesterday",                # a mint time that is not a time
    f"{LINK}|{ADDRESS}|2026-10-16T10:00:00|extra",
    f"{LINK}|{ADDRESS}|",
])
def test_a_grant_whose_record_is_not_link_address_and_time_is_refused(store, value):
    grant = "a-grant-written-by-hand"
    store.data[S._publiclink_grant_key(grant)] = value.encode()
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS) is False


def test_a_discarded_grant_cannot_deliver(store):
    grant = _issue()
    S._publiclink_discard_grant(grant)
    assert store.data == {}
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS) is False
    S._publiclink_discard_grant(grant)                    # discarding again is harmless


def test_the_mint_time_defaults_to_now_in_utc(store):
    before = datetime.utcnow()
    grant = S._publiclink_issue_grant(LINK, ADDRESS)
    after = datetime.utcnow()
    minted = datetime.fromisoformat(store.data[S._publiclink_grant_key(grant)].decode().split("|")[2])
    assert before <= minted <= after


@pytest.mark.parametrize("hours", [-5, 3])
def test_an_aware_expiry_on_either_side_of_utc_is_compared_in_utc(store, hours):
    # Behind UTC the wall clock reads EARLIER than the instant, ahead of it LATER. Compared by its wall
    # clock, an expiry at minus five hours would refuse a grant minted a second before it, and one at
    # plus three would let a grant minted a second after it through.
    offset = timezone(timedelta(hours=hours))
    after = (MINTED + timedelta(seconds=1)).replace(tzinfo=timezone.utc).astimezone(offset)
    before = (MINTED - timedelta(seconds=1)).replace(tzinfo=timezone.utc).astimezone(offset)
    assert after.utcoffset() == timedelta(hours=hours) and after.hour == (10 + hours) % 24
    assert S._publiclink_consume_grant(_issue(), LINK, ADDRESS, expires_at=after) is True
    assert S._publiclink_consume_grant(_issue(), LINK, ADDRESS, expires_at=before) is False


@pytest.mark.parametrize("expires_at", [None, MINTED + timedelta(hours=1)])
@pytest.mark.parametrize("stamp", ["2026-10-16T10:00:00+00:00", "2026-10-16T10:00:00-05:00"])
def test_a_grant_whose_mint_time_carries_an_offset_is_refused(store, stamp, expires_at):
    # This release writes the mint time as naive UTC (the time the redeem checked the link's expiry
    # against). A time with an offset was not written by it, and holding an aware time against the
    # naive expiry would raise in the middle of a download: refused, and left to expire.
    grant = "a-grant-with-an-aware-mint-time"
    store.data[S._publiclink_grant_key(grant)] = f"{LINK}|{ADDRESS}|{stamp}".encode()
    assert S._publiclink_consume_grant(grant, LINK, ADDRESS, expires_at=expires_at) is False
    assert S._publiclink_grant_key(grant) in store.data


# ---- the redeem that mints a grant and then cannot record its use ---------------------------------

class _UpdateFailed(Exception):
    pass


class _Rows:
    def __init__(self, row):
        self._row = row

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._row

    def all(self):
        return []


class _RedeemDB:
    """The redeem's reads answered from a {model: row} map; its one write (the guarded update that spends
    the use) raises, or matches no row. Audit rows are best-effort in the handler, so they are dropped."""

    def __init__(self, rows, update):
        self.rows, self.update, self.updates = rows, update, 0

    def query(self, model, *more):
        return _Rows(self.rows.get(model))

    def execute(self, statement, *args, **kwargs):
        self.updates += 1
        if self.update == "raises":
            raise _UpdateFailed("the database went away")
        return type("Result", (), {"rowcount": 0})()

    def add(self, obj):
        pass

    def commit(self):
        pass

    def rollback(self):
        pass


@pytest.fixture
def redeem(store, monkeypatch):
    import types
    import uuid

    from _async_run import run_coroutine

    monkeypatch.setattr(R.rate_limiter, "check_rate_limit", lambda *a, **k: (True, 0, 0))
    monkeypatch.setattr(S, "get_client_ip", lambda request: ADDRESS)
    monkeypatch.setattr(S.note_link_policy, "public_file_links_enabled", lambda blob: True)
    vault = types.SimpleNamespace(id=uuid.uuid4())
    monkeypatch.setattr(S, "_publiclink_resolve_live", lambda db, link: (vault, object()))

    def run(update):
        token = "tok-" + uuid.uuid4().hex
        file_row = types.SimpleNamespace(id=uuid.uuid4(), name="report.pdf", size_bytes=10, password_hash=None)
        link = types.SimpleNamespace(
            id=uuid.UUID(LINK), token_hash=S._publiclink_token_hash(token), owner_id=uuid.uuid4(),
            vault_id=vault.id, revoked=False, expires_at=None, max_uses=1, use_count=0, secret_kind="none",
            password_hash=None, target_type="file", target_file_id=file_row.id, target_folder_id=None)
        db = _RedeemDB({S.PublicLink: link, S.File: file_row}, update)
        return db, run_coroutine(S.redeem_public_link(token, S.PublicLinkRedeem(), None, db))

    return run


def test_a_redeem_whose_guarded_update_raises_discards_the_grant_it_minted(store, redeem):
    # The grant is minted before the use is spent, so a store outage costs no use. When the update that
    # spends it then raises, the use was never recorded, and the grant must not outlive the error.
    with pytest.raises(_UpdateFailed):
        redeem("raises")
    assert len(store.expiry) == 1, "the redeem did not mint a grant before its update"
    assert store.data == {}, "a grant whose use was never recorded is still held"


def test_a_redeem_whose_guarded_update_matches_nothing_discards_the_grant_it_minted(store, redeem):
    from fastapi import HTTPException

    with pytest.raises(HTTPException) as refused:
        redeem("no row")
    assert refused.value.status_code == 404
    assert len(store.expiry) == 1 and store.data == {}
