"""Live: an automatic lock and its release are audited, and failures sent together all count.

* The failure that arms a lock writes one ``account_auto_locked`` row: the account, the address the
  failure came from, the scope (that address, or account-wide), the count, and when the lock ends. A
  sign-in while the lock holds is refused before its password is checked, and counts nothing.
* A sign-in after the lock ran out clears it and writes ``account_auto_unlocked`` from that sign-in;
  the periodic timer does the same with no address. The timer is run here inside the web container,
  because it only fires every five minutes. A timed lock left on the account row from before automatic
  locks moved to their own table is released and recorded the same way.
* Failed sign-ins sent in parallel each add one to every count.
* The Activity page's Events feed lists both under sign-ins, with the request that made them (none for
  the timer).

test_account_auto_lock_audit.py and test_sign_in_lockout.py cover the same offline; the smart
lockout's behaviour across addresses and doors is in test_smart_lockout_live.py.
"""
import threading

import pytest

from conftest import ApiClient, BASE_URL
from _account_change_helpers import host_address, in_api_container, lock_rows, psql, reset_sign_in_throttle

pytestmark = pytest.mark.integration

LOCKED = "account_auto_locked"
UNLOCKED = "account_auto_unlocked"
# Far past any sane max_login_attempts, so a single further failure arms the lock whatever the
# deployment's threshold is.
PRIMED = 1_000_000


def _login(client, username, password):
    return client.session.post(f"{client.base_url}/auth/login",
                               json={"username": username, "password": password}, timeout=30)


def _rows(admin, action, uid):
    r = admin.get("/audit/log", params={"action": action, "user_id": uid})
    assert r.status_code == 200, r.text
    return [row for row in r.json() if row["action"] == action]


def _latest(admin, action, username):
    r = admin.get("/audit/log", params={"action": action, "limit": 2000})
    assert r.status_code == 200, r.text
    rows = [row for row in r.json() if row["action"] == action and row["username"] == username]
    assert rows, f"no {action} row for {username}"
    return rows[0]    # newest first


def _event(admin, action, username, **params):
    """The Events feed's view of the newest row of this action for this account."""
    r = admin.get("/activity/events", params={"user": username, "category": "sign_in", "limit": 200, **params})
    assert r.status_code == 200, r.text
    events = [e for e in r.json()["events"] if e["action"] == action and e["username"] == username]
    assert events, f"the Events feed has no {action} row for {username}"
    return events[0]


def _request(event):
    return (event["channel"], event["method"], event["endpoint"])


def test_the_failure_that_arms_the_lock_and_the_sign_in_that_clears_it_are_recorded(admin, temp_user):
    uid, name, password = temp_user["id"], temp_user["_username"], temp_user["_password"]
    reset_sign_in_throttle()
    client = ApiClient(BASE_URL)
    assert _login(client, name, "definitely-the-wrong-password").status_code == 401
    here = host_address(admin, name)
    psql(f"UPDATE sign_in_lockouts SET failed_attempts={PRIMED} WHERE user_id='{uid}' AND source='{here}'")

    r = _login(client, name, "definitely-the-wrong-password")
    assert r.status_code == 401, r.text
    assert "lock" not in r.text.lower(), "the failure that arms the lock still sees only the generic answer"
    assert lock_rows(uid)[here] == (PRIMED + 1, True)
    until = psql(f"SELECT coalesce(locked_until::text, '') FROM sign_in_lockouts "
                 f"WHERE user_id='{uid}' AND source='{here}'")
    assert psql(f"SELECT is_locked FROM users WHERE id='{uid}'") == "f", "the account row is never locked"

    rows = _rows(admin, LOCKED, uid)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["username"] == name and row["resource_id"] == uid and row["status"] == "success"
    assert row["details"]["scope"] == "address" and row["details"]["address"] == here
    assert row["details"]["failed_attempts"] == PRIMED + 1
    failure = _latest(admin, "login_failure", name)
    assert row["ip_address"] and row["ip_address"] == failure["ip_address"], (row, failure)
    event = _event(admin, LOCKED, name)
    # Named by its scope, in the Users page's words: this lock pauses one address, sessions carry on.
    assert (event["label"], event["status"]) == ("New sign-ins paused from one address", "success")
    assert _request(event) == ("web", "POST", "/auth/login")

    # While it holds, a sign-in from here is refused before its password is checked: a guess counts
    # nothing, and the right password is refused too.
    for attempt in ("another-guess", password):
        refused = _login(client, name, attempt)
        assert refused.status_code == 403, refused.text
        if until:
            assert int(refused.headers.get("Retry-After", "0")) > 0
    assert lock_rows(uid)[here] == (PRIMED + 1, True)
    assert len(_rows(admin, LOCKED, uid)) == 1

    if not until:
        pytest.skip("this deployment's automatic lock has no end (lockout_duration=0), so there is no "
                    "timed release to observe")
    assert row["details"]["locked_until"], row

    # The lock runs out; the next sign-in clears it and says so.
    psql(f"UPDATE sign_in_lockouts SET locked_until=(now() AT TIME ZONE 'utc') - interval '1 minute' "
         f"WHERE user_id='{uid}' AND source='{here}'")
    r = _login(client, name, password)
    assert r.status_code == 200, r.text
    assert here not in lock_rows(uid), "the released lock and its count are gone"

    released = _rows(admin, UNLOCKED, uid)
    assert len(released) == 1, released
    details = released[0]["details"]
    assert (details["cleared_by"], details["scope"], details["address"]) == ("sign_in", "address", here)
    assert details["failed_attempts"] == PRIMED + 1
    success = _latest(admin, "login_success", name)
    assert released[0]["ip_address"] == success["ip_address"], (released[0], success)
    event = _event(admin, UNLOCKED, name)
    assert event["label"] == "Sign-ins resumed"
    assert _request(event) == ("web", "POST", "/auth/login")


def test_the_timer_clears_an_expired_lock_and_records_it(admin, temp_user):
    uid = temp_user["id"]
    psql("INSERT INTO sign_in_lockouts (id, user_id, source, failed_attempts, window_start, locked_at, "
         f"locked_until) VALUES (gen_random_uuid(), '{uid}', '*', 7, now() AT TIME ZONE 'utc', "
         "now() AT TIME ZONE 'utc', (now() AT TIME ZONE 'utc') - interval '1 minute')")
    # The same call the periodic cleanup makes, on the real database. It clears every expired lock
    # in the deployment, which is what the timer would do within five minutes anyway.
    cleared = in_api_container(
        "from app.core.database import get_db_context\n"
        "from app.core import sign_in_lockout\n"
        "with get_db_context() as db:\n"
        "    n = sign_in_lockout.release_expired(db)\n"
        "    db.commit()\n"
        "    print(n)\n").stdout.strip().splitlines()[-1]
    assert int(cleared) >= 1
    # The lock is gone; the account-wide count stays, to lose its failures over the day
    # (app/core/sign_in_lockout.py).
    assert lock_rows(uid) == {"*": (7, False)}

    rows = _rows(admin, UNLOCKED, uid)
    assert len(rows) == 1, rows
    assert (rows[0]["details"]["cleared_by"], rows[0]["details"]["scope"]) == ("timer", "account")
    assert rows[0]["details"]["failed_attempts"] == 7
    assert rows[0]["ip_address"] is None
    assert _rows(admin, LOCKED, uid) == [], "nothing here armed a lock"
    event = _event(admin, UNLOCKED, temp_user["_username"], channel="unknown")
    assert _request(event) == (None, None, None), "the timer is not a request"


def test_a_timed_lock_left_on_the_account_row_is_still_released(admin, temp_user):
    uid = temp_user["id"]
    psql("UPDATE users SET is_locked=true, failed_login_attempts=7, "
         f"locked_until=(now() AT TIME ZONE 'utc') - interval '1 minute' WHERE id='{uid}'")
    cleared = in_api_container(
        "from app.core.database import get_db_context\n"
        "from app.services.auth_service import release_expired_locks\n"
        "with get_db_context() as db:\n"
        "    n = release_expired_locks(db)\n"
        "    db.commit()\n"
        "    print(n)\n").stdout.strip().splitlines()[-1]
    assert int(cleared) >= 1
    assert psql(f"SELECT is_locked, failed_login_attempts FROM users WHERE id='{uid}'") == "f|0"
    rows = _rows(admin, UNLOCKED, uid)
    assert len(rows) == 1 and rows[0]["details"]["cleared_by"] == "timer", rows


def test_failures_sent_in_parallel_each_count(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    reset_sign_in_throttle()
    senders, each = 4, 10
    statuses = []
    guard = threading.Lock()
    start = threading.Barrier(senders)

    def send():
        client = ApiClient(BASE_URL)
        start.wait()
        for _ in range(each):
            code = _login(client, name, "definitely-the-wrong-password").status_code
            with guard:
                statuses.append(code)

    threads = [threading.Thread(target=send) for _ in range(senders)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)

    # Only a failure that reached the password check is counted; a throttled (429) or refused (403)
    # one is not.
    reached = statuses.count(401)
    if reached < 8:
        pytest.skip(f"only {reached} of {len(statuses)} attempts got past this deployment's "
                    "sign-in throttle, too few to send in parallel")
    here = host_address(admin, name)
    rows = lock_rows(uid)
    assert rows[here][0] == reached, (statuses, rows)
    assert rows["*"][0] == reached, (statuses, rows)
    assert int(psql(f"SELECT failed_login_attempts FROM users WHERE id='{uid}'")) == reached
