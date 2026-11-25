"""The rule the lock-order recorder applies (tests/_lock_order_recorder.py), offline: which statements take which
of the locks of signing in and of a credential change, and which acquisitions are out of order. The recorder itself
listens to a test stack's engines; what it reports is only as good as this."""
import uuid

import pytest

import _lock_order_recorder as rec
from _lock_order_recorder import (ACCOUNT_ROW, ANY, CHANGE_ROW, PROVIDER_ROW, SESSIONS_TURN, SIGN_IN_TURN, Held,
                                  locks_of)

pytestmark = pytest.mark.unit

ALICE, BOB = str(uuid.uuid4()), str(uuid.uuid4())
A, B = ALICE.replace("-", ""), BOB.replace("-", "")
TURN = "SELECT pg_advisory_xact_lock(%(cls)s, hashtext(%(account)s))"


def test_the_statements_that_take_a_lock_are_read_as_what_they_take():
    assert locks_of(TURN, {"cls": 0x5354, "account": ALICE}) == [(SESSIONS_TURN, A)]
    assert locks_of("SELECT pg_advisory_xact_lock(%(cls)s, hashtext(%(key)s))",
                    {"cls": 0x5349, "key": ALICE}) == [(SIGN_IN_TURN, A)]
    assert locks_of(TURN, {"cls": 0x1234, "account": ALICE}) == []          # another lock altogether
    read = "SELECT users.id AS users_id \nFROM users \nWHERE users.id = %(id_1)s FOR NO KEY UPDATE"
    assert locks_of(read, {"id_1": uuid.UUID(ALICE)}) == [(ACCOUNT_ROW, A)]
    assert locks_of(read.replace("FOR NO KEY UPDATE", "FOR SHARE"), {"id_1": ALICE}) == [(ACCOUNT_ROW, A)]
    assert locks_of(read.replace(" FOR NO KEY UPDATE", ""), {"id_1": ALICE}) == []      # a plain read locks nothing
    assert locks_of("SELECT users.id FROM users WHERE users.role = %(role_1)s ORDER BY users.id FOR UPDATE",
                    {"role_1": "admin"}) == [(ACCOUNT_ROW, ANY)]
    assert locks_of("UPDATE users SET sessions_ended=%(sessions_ended)s WHERE users.id = %(id_1)s",
                    {"sessions_ended": 3, "id_1": ALICE}) == [(ACCOUNT_ROW, A)]
    assert locks_of("SELECT users.id FROM users WHERE users.id IN (%(id_1_1)s, %(id_1_2)s) FOR SHARE",
                    {"id_1_1": ALICE, "id_1_2": BOB}) == [(ACCOUNT_ROW, A), (ACCOUNT_ROW, B)]
    assert locks_of("SELECT sso_providers.id FROM sso_providers WHERE sso_providers.id = %(id_1)s FOR SHARE",
                    {"id_1": "p1"}) == [(PROVIDER_ROW, "p1")]
    assert locks_of("UPDATE sso_providers SET state=%(state)s WHERE sso_providers.id = %(id_1)s",
                    {"state": "disabled", "id_1": "p1"}) == [(PROVIDER_ROW, "p1")]
    assert locks_of("SELECT credential_changes.id FROM credential_changes WHERE credential_changes.id = %(id_1)s "
                    "FOR UPDATE", {"id_1": "c1"}) == [(CHANGE_ROW, "c1")]
    # A row that names an account is written without a lock on the account's row that anything here waits for.
    assert locks_of("INSERT INTO active_sessions (id, user_id) VALUES (%(id)s, %(user_id)s)",
                    {"id": "s", "user_id": ALICE}) == []
    assert locks_of("SELECT active_sessions.id FROM active_sessions JOIN users ON users.id = "
                    "active_sessions.user_id WHERE users.id = %(id_1)s", {"id_1": ALICE}) == []


def _taken(*acquisitions):
    """What is out of order as the acquisitions are made one after another: a list, one entry for each."""
    held = Held()
    return [held.take(kind, key) for kind, key in acquisitions]


def test_the_order_is_kept_by_the_shapes_the_application_uses():
    in_order = [
        [(SIGN_IN_TURN, A), (SESSIONS_TURN, A), (ACCOUNT_ROW, A)],                      # the password door
        [(SESSIONS_TURN, A), (ACCOUNT_ROW, A), (CHANGE_ROW, "c")],                      # a change made at once
        [(SESSIONS_TURN, A), (ACCOUNT_ROW, A), (CHANGE_ROW, "c"), (ACCOUNT_ROW, A)],    # an approval, then its write
        [(PROVIDER_ROW, "p"), (SESSIONS_TURN, A), (ACCOUNT_ROW, A)],                    # the provider door
        [(SESSIONS_TURN, A), (ACCOUNT_ROW, ANY)],                                       # the last-administrator guard
        [(SESSIONS_TURN, A), (ACCOUNT_ROW, A), (SESSIONS_TURN, A)],                     # a turn taken again
        [(SESSIONS_TURN, A), (ACCOUNT_ROW, A), (SESSIONS_TURN, B), (ACCOUNT_ROW, B)],   # two accounts, one by one
        [(ACCOUNT_ROW, A)],                                                             # a row alone
    ]
    for shape in in_order:
        assert _taken(*shape) == [[] for _ in shape], shape


@pytest.mark.parametrize("shape,last", [
    ([(ACCOUNT_ROW, A), (SESSIONS_TURN, A)], [(ACCOUNT_ROW, A)]),                 # the row, then the turn
    ([(ACCOUNT_ROW, ANY), (SESSIONS_TURN, A)], [(ACCOUNT_ROW, ANY)]),             # every administrator's row first
    ([(CHANGE_ROW, "c"), (SESSIONS_TURN, A)], [(CHANGE_ROW, "c")]),               # the request, then the turn
    ([(CHANGE_ROW, "c"), (ACCOUNT_ROW, A)], [(CHANGE_ROW, "c")]),                 # the request, then a row not held
    ([(SESSIONS_TURN, A), (PROVIDER_ROW, "p")], [(SESSIONS_TURN, A)]),            # a turn, then a provider's row
    ([(ACCOUNT_ROW, B), (PROVIDER_ROW, "p")], [(ACCOUNT_ROW, B)]),                # any row, then a provider's row
    ([(SESSIONS_TURN, A), (SIGN_IN_TURN, A)], [(SESSIONS_TURN, A)]),              # the turns the wrong way round
    ([(PROVIDER_ROW, "p"), (SIGN_IN_TURN, A)], [(PROVIDER_ROW, "p")]),
])
def test_an_acquisition_out_of_order_names_what_should_have_come_after(shape, last):
    assert _taken(*shape)[-1] == last
    assert all(found == [] for found in _taken(*shape)[:-1])


def test_a_turn_is_one_accounts_and_a_lock_already_held_is_free():
    # Bob's row held, Alice's turn taken: no ring can form over the two.
    assert _taken((ACCOUNT_ROW, B), (SESSIONS_TURN, A)) == [[], []]
    # Taken once out of order, the same lock again adds nothing.
    assert _taken((ACCOUNT_ROW, A), (SESSIONS_TURN, A), (SESSIONS_TURN, A))[-1] == []
    # A statement that names no row stands for every row of its table.
    held = Held()
    held.take(ACCOUNT_ROW, ANY)
    assert held.holds(ACCOUNT_ROW, A) and held.out_of_order(SESSIONS_TURN, B) == [(ACCOUNT_ROW, ANY)]


def test_the_report_adds_up_what_the_processes_wrote(tmp_path, capsys, monkeypatch):
    monkeypatch.setenv("LOCK_ORDER_OUT", str(tmp_path))
    monkeypatch.setattr(rec, "_frames", lambda: ["app/api/api_server.py:1 route"])

    class Connection:
        info = {}
    conn = Connection()
    for statement, parameters in ((TURN, {"cls": 0x5354, "account": ALICE}),
                                  ("UPDATE users SET x=%(x)s WHERE users.id = %(id_1)s", {"x": 1, "id_1": ALICE})):
        rec._on_statement(conn, None, statement, parameters, None, False)
    rec._on_end(conn)
    assert rec.report(str(tmp_path)) == 0
    assert "sessions turn > account row" in capsys.readouterr().out
    for statement, parameters in (("SELECT users.id FROM users WHERE users.id = %(id_1)s FOR UPDATE", {"id_1": ALICE}),
                                  (TURN, {"cls": 0x5354, "account": ALICE})):
        rec._on_statement(conn, None, statement, parameters, None, False)
    rec._on_end(conn)
    assert rec.report(str(tmp_path)) == 1
    said = capsys.readouterr().out
    assert "out of order: 1" in said and "took sessions turn while holding account row" in said
    assert "app/api/api_server.py:1 route" in said


def test_a_row_of_an_auditor_right_stands_where_a_row_of_a_change_does():
    """An account that loses its standing has its auditor right locked. That row is taken after the account's
    turn at its sessions, as a row of a change to its sign-in details is: the turn asked for after it is out of
    order, whichever account the turn is."""
    from _lock_order_recorder import CHANGE_ROW, SESSIONS_TURN, Held, locks_of
    read = ("SELECT auditor_grants.id FROM auditor_grants WHERE auditor_grants.user_id = %(user_id_1)s "
            "AND auditor_grants.status IN (%(status_1_1)s) FOR UPDATE")
    assert [kind for kind, _key in locks_of(read, {"user_id_1": "u1", "status_1_1": "active"})] == [CHANGE_ROW]
    assert [kind for kind, _key in locks_of("UPDATE auditor_grants SET status=%(status)s WHERE auditor_grants.id = "
                                            "%(auditor_grants_id)s", {"status": "suspended",
                                                                      "auditor_grants_id": "g1"})] == [CHANGE_ROW]
    assert locks_of("SELECT auditor_grants.id FROM auditor_grants WHERE auditor_grants.user_id = %(u)s", {"u": "u1"}) == []
    assert locks_of("INSERT INTO auditor_grants (id) VALUES (%(id)s)", {"id": "g1"}) == []
    held = Held()
    for kind, key in locks_of(read, {"user_id_1": "u1", "status_1_1": "active"}):
        assert held.take(kind, key) == []
    assert held.take(SESSIONS_TURN, "u1") != [], "the turn after the row of the auditor right is out of order"
    in_order = Held()
    assert in_order.take(SESSIONS_TURN, "u1") == []
    for kind, key in locks_of(read, {"user_id_1": "u1", "status_1_1": "active"}):
        assert in_order.take(kind, key) == []
