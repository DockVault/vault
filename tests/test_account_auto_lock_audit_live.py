"""Live: an automatic lock and its release are audited, and failures sent together all count.

* The failure that arms the lock writes one ``account_auto_locked`` row: the account, the address
  the failure came from, the count, and when the lock ends. Failures against the running lock only
  move its end and write nothing more.
* A sign-in after the lock ran out clears it and writes ``account_auto_unlocked`` from that sign-in;
  the periodic timer does the same with no address. The timer is run here inside the web container,
  because it only fires every five minutes.
* Failed sign-ins sent in parallel each add one to the count. The count was read, increased and
  written back, so parallel failures overwrote each other and most were lost.

test_account_auto_lock_audit.py covers the same offline.
"""
import os
import subprocess
import threading

import pytest

from conftest import ApiClient, BASE_URL, skip_if_container_absent

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")
LOCKED = "account_auto_locked"
UNLOCKED = "account_auto_unlocked"
# Far past any sane max_login_attempts, so a single further failure arms the lock whatever the
# deployment's threshold is.
PRIMED = 1_000_000


def _psql(sql):
    try:
        r = subprocess.run(
            ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-Atc", sql],
            capture_output=True, text=True, timeout=30)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    skip_if_container_absent(r, _DB_CONTAINER)
    assert r.returncode == 0, r.stderr[:300]
    return r.stdout.strip()


def _in_web_container(source):
    script = ("from app.core.config import bootstrap_entrypoint\n"
              "bootstrap_entrypoint('lock-audit-test')\n" + source)
    try:
        r = subprocess.run(["docker", "exec", "-i", _API_CONTAINER, "python", "-c", script],
                           capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, _API_CONTAINER)
    assert r.returncode == 0, (r.stderr or r.stdout)[-600:]
    return r.stdout.strip().splitlines()[-1]


def _login(client, username, password):
    return client.session.post(f"{client.base_url}/auth/login",
                               json={"username": username, "password": password}, timeout=30)


def _state(uid):
    locked, count, until = _psql(
        f"SELECT is_locked, failed_login_attempts, coalesce(locked_until::text, '') FROM users "
        f"WHERE id='{uid}'").split("|")
    return locked == "t", int(count), until


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


def test_the_failure_that_arms_the_lock_and_the_sign_in_that_clears_it_are_recorded(admin, temp_user):
    uid, name, password = temp_user["id"], temp_user["_username"], temp_user["_password"]
    _psql(f"UPDATE users SET failed_login_attempts={PRIMED} WHERE id='{uid}'")
    client = ApiClient(BASE_URL)

    r = _login(client, name, "definitely-the-wrong-password")
    assert r.status_code == 401, r.text
    locked, count, until = _state(uid)
    assert (locked, count) == (True, PRIMED + 1)

    rows = _rows(admin, LOCKED, uid)
    assert len(rows) == 1, rows
    row = rows[0]
    assert row["username"] == name and row["resource_id"] == uid and row["status"] == "success"
    assert row["details"]["failed_attempts"] == PRIMED + 1
    failure = _latest(admin, "login_failure", name)
    assert row["ip_address"] and row["ip_address"] == failure["ip_address"], (row, failure)
    assert "lock" not in r.text.lower(), "the caller still sees only the generic failure"

    # A failure against the running lock moves its end but is not recorded again.
    assert _login(client, name, "definitely-the-wrong-password").status_code == 401
    assert _state(uid)[1] == PRIMED + 2
    assert len(_rows(admin, LOCKED, uid)) == 1

    if not until:
        pytest.skip("this deployment's failed-login lock is permanent (lockout_duration=0), "
                    "so there is no timed release to observe")
    assert row["details"]["locked_until"], row

    # The lock runs out; the next sign-in clears it and says so.
    _psql(f"UPDATE users SET locked_until=(now() AT TIME ZONE 'utc') - interval '1 minute' WHERE id='{uid}'")
    r = _login(client, name, password)
    assert r.status_code == 200, r.text
    assert _state(uid)[:2] == (False, 0)

    released = _rows(admin, UNLOCKED, uid)
    assert len(released) == 1, released
    assert released[0]["details"]["cleared_by"] == "sign_in"
    assert released[0]["details"]["failed_attempts"] == PRIMED + 2
    success = _latest(admin, "login_success", name)
    assert released[0]["ip_address"] == success["ip_address"], (released[0], success)


def test_the_timer_clears_an_expired_lock_and_records_it(admin, temp_user):
    uid = temp_user["id"]
    _psql("UPDATE users SET is_locked=true, failed_login_attempts=7, "
          f"locked_until=(now() AT TIME ZONE 'utc') - interval '1 minute' WHERE id='{uid}'")
    # The same call the periodic cleanup makes, on the real database. It clears every expired lock
    # in the deployment, which is what the timer would do within five minutes anyway.
    cleared = _in_web_container(
        "from app.core.database import get_db_context\n"
        "from app.services.auth_service import release_expired_locks\n"
        "with get_db_context() as db:\n"
        "    print(release_expired_locks(db))\n")
    assert int(cleared) >= 1
    assert _state(uid) == (False, 0, "")

    rows = _rows(admin, UNLOCKED, uid)
    assert len(rows) == 1, rows
    assert rows[0]["details"]["cleared_by"] == "timer"
    assert rows[0]["details"]["failed_attempts"] == 7
    assert rows[0]["ip_address"] is None
    assert _rows(admin, LOCKED, uid) == [], "nothing here armed a lock"


def test_failures_sent_in_parallel_each_count(temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    senders, each = 4, 10
    statuses = []
    guard = threading.Lock()
    start = threading.Barrier(senders)

    def send():
        client = ApiClient(BASE_URL)      # a source address of its own
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

    # Only a failure that reached the password check is counted; a throttled one (429) is not.
    reached = statuses.count(401)
    if reached < 8:
        pytest.skip(f"only {reached} of {len(statuses)} attempts got past this deployment's "
                    "sign-in throttle, too few to send in parallel")
    assert _state(uid)[1] == reached, statuses
