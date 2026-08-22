"""Unit coverage for `find_user_by_email` — the email->account resolver behind email/either login.

The database fold (`lower(email)` on both sides) is exercised by the live suite; what is pure logic,
and what a login oracle turns on, is the set of inputs that must resolve to NOTHING:

* a blank / whitespace / absent candidate must return None WITHOUT touching the database, so a
  `None` can never compile to `email IS NULL` and match every email-less account; and
* MORE THAN ONE matching row (a legacy install that could not build the `lower(email)` unique index)
  must return None — authenticating an arbitrary one of them is the impersonation case the resolver
  exists to prevent.

These are asserted here against a fake session, non-vacuously: the single-row case returns the exact
row, so "always None" could not pass.
"""
import pytest

from app.core.email_identity import find_user_by_email

pytestmark = pytest.mark.unit


class _FakeQuery:
    def __init__(self, rows):
        self._rows = rows

    def filter(self, *a, **k):
        return self

    def limit(self, n):
        return self

    def all(self):
        return list(self._rows)


class _FakeDB:
    """Records whether the query path was entered, so the 'return before the DB' guard is testable."""

    def __init__(self, rows=None):
        self._rows = rows or []
        self.query_calls = 0

    def query(self, *a, **k):
        self.query_calls += 1
        return _FakeQuery(self._rows)


@pytest.mark.parametrize("blank", ["", "   ", "\t\n", None])
def test_blank_candidate_returns_none_without_a_db_query(blank):
    db = _FakeDB(rows=["should-not-be-reached"])
    assert find_user_by_email(db, blank) is None
    assert db.query_calls == 0, "a blank/absent candidate must resolve to None before any DB read"


def test_single_match_is_returned():
    sentinel = object()
    db = _FakeDB(rows=[sentinel])
    assert find_user_by_email(db, "person@example.com") is sentinel
    assert db.query_calls == 1


def test_no_match_returns_none():
    db = _FakeDB(rows=[])
    assert find_user_by_email(db, "nobody@example.com") is None


def test_ambiguous_collision_fails_closed():
    # Two rows share one address on a deployment that could not build the unique index. Returning
    # either would be impersonation, so the resolver must treat >1 as no match.
    db = _FakeDB(rows=[object(), object()])
    assert find_user_by_email(db, "clash@example.com") is None
