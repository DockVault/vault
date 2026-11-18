"""Offline unit tests for the generalized OTP service (app/core/otp_service.py).

Exercises BOTH stores with fakes: a dict-backed fake Redis and a list-backed fake DB (interpreting the
exact filter shapes the service uses). Pins the OWASP properties — single active code per (purpose,
user), (purpose, user, destination) binding, single-use, 3-strike lockout, expiry, hash-at-rest — and
the Redis-primary / DB-fallback orchestration (including a code issued during a Redis outage that
verifies once Redis returns).
"""
import time
from datetime import datetime, timedelta

import pytest

from app.core import otp_service as o
from app.core.models import OtpCode

pytestmark = pytest.mark.unit

PEP = "unit-test-pepper"


# ---- fakes ---------------------------------------------------------------------------------------
class FakeRedis:
    def __init__(self, *, down=False):
        self.h = {}
        self.down = down

    def _guard(self):
        if self.down:
            raise RuntimeError("redis down")

    def delete(self, k):
        self._guard(); return 1 if self.h.pop(k, None) is not None else 0

    def hset(self, k, mapping=None):
        self._guard(); self.h.setdefault(k, {}).update({kk: str(vv) for kk, vv in (mapping or {}).items()})

    def expire(self, k, ttl, nx=False):
        self._guard()

    def hgetall(self, k):
        self._guard(); return dict(self.h.get(k, {}))

    def hincrby(self, k, field, n):
        self._guard()
        d = self.h.setdefault(k, {}); d[field] = str(int(d.get(field, 0)) + n); return int(d[field])


def _pred(expr):
    """(column_name, kind, value) for the filter shapes the service uses: `Col == v` and `Col.is_(None)`."""
    col = expr.left.key
    if hasattr(expr.right, "value"):
        return (col, "eq", expr.right.value)
    return (col, "isnull", None)


class _FakeQ:
    def __init__(self, rows):
        self.rows = rows
        self.preds = []
        self._desc = False

    def filter(self, *exprs):
        self.preds += [_pred(e) for e in exprs]
        return self

    def order_by(self, *a):
        self._desc = True
        return self

    def _match(self):
        out = []
        for r in self.rows:
            ok = True
            for col, kind, val in self.preds:
                cur = getattr(r, col)
                if kind == "eq" and cur != val:
                    ok = False
                elif kind == "isnull" and cur is not None:
                    ok = False
            if ok:
                out.append(r)
        if self._desc:
            out.sort(key=lambda r: r.created_at or datetime.min, reverse=True)
        return out

    def first(self):
        m = self._match()
        return m[0] if m else None

    def delete(self, synchronize_session=False):
        keep = [r for r in self.rows if r not in self._match()]
        n = len(self.rows) - len(keep)
        self.rows[:] = keep
        return n

    def update(self, values, synchronize_session=False):
        m = self._match()
        for r in m:
            for k, v in values.items():
                setattr(r, k, v)
        return len(m)


class FakeDB:
    def __init__(self):
        self.rows = []
        self._seq = 0

    def query(self, _model):
        return _FakeQ(self.rows)

    def add(self, obj):
        import uuid
        self._seq += 1
        if getattr(obj, "id", None) is None:
            obj.id = uuid.uuid4()
        # deterministic ordering for order_by(created_at desc)
        obj.created_at = datetime.utcnow() + timedelta(microseconds=self._seq)
        if obj.attempts is None:
            obj.attempts = 0
        self.rows.append(obj)

    def commit(self):
        pass

    def rollback(self):
        pass


# ---- pure crypto ---------------------------------------------------------------------------------
def test_hash_is_peppered_and_matches_are_constant_time():
    h = o.hash_code("abc123", PEP)
    assert h == o.hash_code("abc123", PEP) and o.hash_code("abc123", "other") != h
    assert o._hash_matches(h, h) and not o._hash_matches(h, o.hash_code("nope", PEP))


def test_generate_code_is_hex_and_unique():
    a, b = o.generate_code(), o.generate_code()
    assert len(a) == 12 and int(a, 16) >= 0 and a != b


# ---- Redis path ----------------------------------------------------------------------------------
def test_redis_issue_verify_happy_and_single_use():
    r, db = FakeRedis(), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u1", destination="new@x.com",
                   ttl_minutes=5, pepper=PEP, redis=r)
    res = o.verify(db, purpose="email_change", user_id="u1", code=code, pepper=PEP, redis=r)
    assert res.ok and res.destination == "new@x.com"
    # consumed: a re-verify falls through to the (empty) DB and fails
    assert o.verify(db, purpose="email_change", user_id="u1", code=code, pepper=PEP, redis=r).reason == "not_found"


def test_redis_three_strikes_invalidates_even_the_real_code():
    r, db = FakeRedis(), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u2", destination="a@x", ttl_minutes=5, pepper=PEP, redis=r)
    assert o.verify(db, purpose="email_change", user_id="u2", code="bad1", pepper=PEP, redis=r).reason == "invalid"
    assert o.verify(db, purpose="email_change", user_id="u2", code="bad2", pepper=PEP, redis=r).reason == "invalid"
    assert o.verify(db, purpose="email_change", user_id="u2", code="bad3", pepper=PEP, redis=r).reason == "too_many"
    # the correct code no longer works after the lockout
    assert not o.verify(db, purpose="email_change", user_id="u2", code=code, pepper=PEP, redis=r).ok


def test_new_issue_invalidates_the_previous_code():
    r, db = FakeRedis(), FakeDB()
    old = o.issue(db, purpose="email_change", user_id="u3", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    new = o.issue(db, purpose="email_change", user_id="u3", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    assert not o.verify(db, purpose="email_change", user_id="u3", code=old, pepper=PEP, redis=r).ok
    assert o.verify(db, purpose="email_change", user_id="u3", code=new, pepper=PEP, redis=r).ok


def test_a_code_is_bound_to_its_purpose_and_user():
    r, db = FakeRedis(), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u4", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    assert not o.verify(db, purpose="password_reset", user_id="u4", code=code, pepper=PEP, redis=r).ok  # wrong purpose
    assert not o.verify(db, purpose="email_change", user_id="uX", code=code, pepper=PEP, redis=r).ok    # wrong user


def test_expired_redis_code_does_not_verify():
    r, db = FakeRedis(), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u5", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    # rewind the stored expiry into the past
    key = o.redis_key("email_change", "u5")
    r.h[key]["expires_at"] = str(int(datetime.utcnow().timestamp()) - 3600)
    assert o.verify(db, purpose="email_change", user_id="u5", code=code, pepper=PEP, redis=r).reason == "expired"


class _MixedUpRedis(FakeRedis):
    """A Redis whose next HGETALL answers with another command's reply, as a connection whose replies are out of
    step would: a map without a code's fields (what HELLO answers), or something that is no map at all."""

    def __init__(self, replies):
        super().__init__()
        self.replies = list(replies)

    def hgetall(self, k):
        if self.replies:
            self._guard()
            return self.replies.pop(0)
        return super().hgetall(k)


@pytest.mark.parametrize("reply", [
    {"server": "redis", "version": "7.4.1", "proto": "3", "id": "12", "mode": "standalone", "role": "master"},
    {"code_hash": "0" * 64},      # some of a code's fields, not all of them
    "OK",
    1,                            # an integer reply (EXISTS, DEL)
    ["subscribe", "monitor", 1],
])
def test_a_reply_that_is_not_a_codes_map_is_refused_and_the_code_kept(reply):
    """A map without every field a stored code has is not read as a code: read as one, its expiry was 0, so the
    real code was called expired and deleted. It is refused as unreadable, the code stays, and the next read
    verifies it."""
    r, db = _MixedUpRedis([reply]), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u6", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    first = o.verify(db, purpose="email_change", user_id="u6", code=code, pepper=PEP, redis=r)
    assert not first.ok and first.reason == "not_found", first.reason
    assert o.redis_key("email_change", "u6") in r.h, "the stored code was deleted"
    assert o.verify(db, purpose="email_change", user_id="u6", code=code, pepper=PEP, redis=r).ok


@pytest.mark.parametrize("missing", ["code_hash", "destination", "attempts", "max_attempts", "expires_at",
                                     "issued_at"])
def test_a_stored_codes_map_without_one_of_its_fields_is_refused_and_the_code_kept(missing):
    """Every field the store writes is required: the code's own map with any one of them gone is refused, the
    code stays, and the next read verifies it."""
    r, db = _MixedUpRedis([]), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u7", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    key = o.redis_key("email_change", "u7")
    stored = dict(r.h[key])
    assert set(stored) == {"code_hash", "destination", "attempts", "max_attempts", "expires_at", "issued_at"}
    del stored[missing]
    r.replies = [stored]
    first = o.verify(db, purpose="email_change", user_id="u7", code=code, pepper=PEP, redis=r)
    assert not first.ok and first.reason == "not_found", (missing, first.reason)
    assert key in r.h and r.h[key].get("attempts") == "0", "the stored code was deleted or struck"
    assert o.verify(db, purpose="email_change", user_id="u7", code=code, pepper=PEP, redis=r).ok


class _ExpiringRedis(FakeRedis):
    """The fake Redis, recording the expiry each key is given."""

    def __init__(self):
        super().__init__()
        self.ttl = {}

    def expire(self, k, ttl, nx=False):
        """As Redis: with nx, a key that already has an expiry keeps it."""
        self._guard()
        if not (nx and k in self.ttl):
            self.ttl[k] = ttl

    def delete(self, k):
        self.ttl.pop(k, None)
        return super().delete(k)


def test_a_strike_that_lands_after_the_code_is_gone_leaves_a_key_that_expires():
    """Two guesses read the code at once; the right one consumes it, then the wrong one strikes. The strike creates
    the key again holding only its count, which must lapse as the code would have, not stay for good."""
    r, db = _ExpiringRedis(), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="u8", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    key = o.redis_key("email_change", "u8")
    stale = o._redis_load(r, "email_change", "u8")          # the wrong guess's read, before the right one lands
    assert o.verify(db, purpose="email_change", user_id="u8", code=code, pepper=PEP, redis=r).ok
    assert key not in r.h and key not in r.ttl
    wrong = o._redis_consume_verify(r, "email_change", "u8", o.hash_code("bad", PEP), stale)
    assert wrong.reason == "invalid" and r.h[key] == {"attempts": "1"}
    # Exactly the code's own remaining life plus the grace, as the code's key had.
    expected = stale["expires_at"] - int(time.time()) + o._REDIS_GRACE_SECONDS
    assert abs(r.ttl.get(key, 0) - expected) <= 1, (r.ttl, expected)


def test_a_wrong_guess_on_a_live_code_leaves_its_expiry_and_never_shortens_a_code_issued_again():
    r, db = _ExpiringRedis(), FakeDB()
    key = o.redis_key("email_change", "u9")
    o.issue(db, purpose="email_change", user_id="u9", destination="d", ttl_minutes=1, pepper=PEP, redis=r)
    stale = o._redis_load(r, "email_change", "u9")           # a guess that read the first code
    o.issue(db, purpose="email_change", user_id="u9", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    issued_again = r.ttl[key]
    assert abs(issued_again - (5 * 60 + o._REDIS_GRACE_SECONDS)) <= 1, issued_again
    assert o._redis_consume_verify(r, "email_change", "u9", o.hash_code("bad", PEP), stale).reason == "invalid"
    assert r.ttl[key] == issued_again, "a strike read before the code was issued again shortened it"
    fresh = o._redis_load(r, "email_change", "u9")
    assert o._redis_consume_verify(r, "email_change", "u9", o.hash_code("bad2", PEP), fresh).reason == "invalid"
    assert r.ttl[key] == issued_again, "a wrong guess changed a live code's expiry"


# ---- DB fallback path (Redis down at issue) ------------------------------------------------------
def test_issue_falls_back_to_db_when_redis_is_down():
    down, db = FakeRedis(down=True), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="d1", destination="db@x", ttl_minutes=5, pepper=PEP, redis=down)
    assert len(db.rows) == 1 and db.rows[0].purpose == "email_change" and db.rows[0].consumed_at is None
    # verify while still down -> DB path
    res = o.verify(db, purpose="email_change", user_id="d1", code=code, pepper=PEP, redis=down)
    assert res.ok and res.destination == "db@x"
    assert db.rows[0].consumed_at is not None                    # single-use in the DB too


def test_db_code_verifies_once_redis_returns():
    # issued during an outage (DB), then Redis comes back UP but has no key -> verify must check the DB.
    db = FakeDB()
    code = o.issue(db, purpose="email_change", user_id="d2", destination="d", ttl_minutes=5, pepper=PEP,
                   redis=FakeRedis(down=True))
    up = FakeRedis()                                            # healthy, but empty
    assert o.verify(db, purpose="email_change", user_id="d2", code=code, pepper=PEP, redis=up).ok


def test_db_three_strikes_invalidates():
    down, db = FakeRedis(down=True), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="d3", destination="d", ttl_minutes=5, pepper=PEP, redis=down)
    for _ in range(3):
        o.verify(db, purpose="email_change", user_id="d3", code="wrong", pepper=PEP, redis=down)
    assert not o.verify(db, purpose="email_change", user_id="d3", code=code, pepper=PEP, redis=down).ok
    assert db.rows[0].consumed_at is not None


def test_reissue_on_redis_durably_clears_a_prior_db_code():
    # Regression: a DB code issued during an outage must be invalidated by a later re-issue on Redis,
    # or it could survive and be redeemed if Redis went down again.
    db = FakeDB()
    down, up = FakeRedis(down=True), FakeRedis()
    code1 = o.issue(db, purpose="email_change", user_id="x1", destination="a", ttl_minutes=5, pepper=PEP, redis=down)
    assert len(db.rows) == 1                          # code1 landed in the DB (Redis was down)
    o.issue(db, purpose="email_change", user_id="x1", destination="b", ttl_minutes=5, pepper=PEP, redis=up)
    assert db.rows == []                              # re-issue on Redis durably dropped the old DB code
    assert not o.verify(db, purpose="email_change", user_id="x1", code=code1, pepper=PEP, redis=down).ok


def test_a_newer_db_code_wins_over_a_stale_redis_key():
    # FIX-1: a re-issue during a Redis outage leaves a stale key in Redis and the current code in the DB.
    # Once Redis returns, the stale code must be DEAD and the current DB code must still verify.
    db = FakeDB()
    up = FakeRedis()
    codeA = o.issue(db, purpose="email_change", user_id="s1", destination="A", ttl_minutes=5, pepper=PEP, redis=up)
    down = FakeRedis(down=True); down.h = up.h          # Redis unreachable for the re-issue; key A survives
    codeB = o.issue(db, purpose="email_change", user_id="s1", destination="B", ttl_minutes=5, pepper=PEP, redis=down)
    up2 = FakeRedis(); up2.h = up.h                     # Redis recovers, still holding stale code_A
    assert not o.verify(db, purpose="email_change", user_id="s1", code=codeA, pepper=PEP, redis=up2).ok  # stale dead
    r = o.verify(db, purpose="email_change", user_id="s1", code=codeB, pepper=PEP, redis=up2)
    assert r.ok and r.destination == "B"               # the current code wins despite the stale Redis key


def test_partial_redis_write_does_not_leave_a_dual_store_code():
    # FIX-2: if the Redis write can't complete, issue falls back to the DB and must NOT also leave the
    # code in Redis (which would allow a second redemption via the DB after the Redis one is consumed).
    class HalfRedis(FakeRedis):
        def expire(self, k, ttl, nx=False):
            raise RuntimeError("dropped right after HSET")
    r, db = HalfRedis(), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="p1", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    assert not r.h.get(o.redis_key("email_change", "p1"))   # the partial Redis write was rolled back
    assert len(db.rows) == 1                                 # the code lives only in the DB
    up = FakeRedis(); up.h = r.h
    first = o.verify(db, purpose="email_change", user_id="p1", code=code, pepper=PEP, redis=up)
    assert first.ok
    assert not o.verify(db, purpose="email_change", user_id="p1", code=code, pepper=PEP, redis=up).ok  # no replay


def test_only_the_hash_is_stored_never_the_plaintext():
    down, db = FakeRedis(down=True), FakeDB()
    code = o.issue(db, purpose="email_change", user_id="d4", destination="d", ttl_minutes=5, pepper=PEP, redis=down)
    assert db.rows[0].code_hash != code and db.rows[0].code_hash == o.hash_code(code, PEP)
    r = FakeRedis()
    code2 = o.issue(db, purpose="pw", user_id="d5", destination="d", ttl_minutes=5, pepper=PEP, redis=r)
    stored = r.h[o.redis_key("pw", "d5")]
    # the PRIMARY (Redis) store keeps only the peppered hash — never the plaintext code, anywhere
    stored_vals = [str(v) for v in stored.values()]
    assert stored.get("code_hash") == o.hash_code(code2, PEP)
    assert code2 not in stored_vals and code2 not in stored             # plaintext absent from values AND keys
    assert not any(code2 in v for v in stored_vals)                     # not embedded in any stored field
