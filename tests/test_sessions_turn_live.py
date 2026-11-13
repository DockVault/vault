"""The account's turn at its sessions, on a real PostgreSQL (app/api/api_server.py _sessions_turn).

A renewal ("Stay signed in") puts a new session in the place of one; a sign-out everywhere ends all of an
account's sessions. Each takes the account's turn before it reads the sessions, so neither sees half of the
other. Here the turn is held from a database session of the test's own, as a renewal or a revocation in progress
would hold it: the renewal of that account waits and then goes through, another account's does not wait, a
sign-out everywhere waits too. Then the two are raced for real, many times: when both have answered, no token of
the account works, whichever came first.
"""
import os
import subprocess
import threading
import time
import uuid

import pytest
import requests

from conftest import ApiClient, BASE_URL

pytestmark = pytest.mark.integration

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
TURN_CLASS = 0x5354          # app/api/api_server.py _SESSIONS_TURN_CLASS (a unit test pins the value there)
HOLD = 2.5                   # seconds the turn is held: well under the connections' lock_timeout (5 s)
WAITED = HOLD - 1.0          # what a call that waited for the turn took at least
QUICK = HOLD - 1.5           # what a call that did not wait took at most


def _psql(sql):
    out = subprocess.run(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                         capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, out.stderr[:300]
    return out.stdout.strip()


def _hold_the_turn(user_id):
    """A transaction that takes the account's turn and keeps it for HOLD seconds. Returns once the lock is held."""
    account = str(uuid.UUID(str(user_id)))
    sql = (f"BEGIN; SELECT pg_advisory_xact_lock({TURN_CLASS}, hashtext('{account}')); "
           f"SELECT pg_sleep({HOLD}); COMMIT;")
    holder = subprocess.Popen(["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
                              stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        if _psql(f"SELECT count(*) FROM pg_locks WHERE locktype='advisory' AND classid={TURN_CLASS} AND granted") != "0":
            return holder
        time.sleep(0.05)
    holder.kill()
    pytest.fail("the turn was never taken")


def _me(token):
    return requests.get(f"{BASE_URL}/users/me", headers={"Authorization": f"Bearer {token}"}, timeout=15)


def _extend(token):
    return requests.post(f"{BASE_URL}/auth/session/extend", headers={"Authorization": f"Bearer {token}"}, timeout=30)


def _timed(call):
    began = time.monotonic()
    answer = call()
    return answer, time.monotonic() - began


def _signed_in(user):
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    return client.token


def test_a_renewal_waits_for_its_accounts_turn_and_another_accounts_does_not(admin):
    u, v = admin.create_user(role="user"), admin.create_user(role="user")
    try:
        mine, theirs = _signed_in(u), _signed_in(v)
        holder = _hold_the_turn(u["id"])
        waited = {}
        runner = threading.Thread(target=lambda: waited.update(zip(("answer", "took"), _timed(lambda: _extend(mine)))))
        runner.start()
        other, took = _timed(lambda: _extend(theirs))
        assert other.status_code == 200 and took < QUICK, (other.status_code, took)
        runner.join(timeout=30)
        holder.wait(timeout=30)
        assert waited["answer"].status_code == 200, waited["answer"].text
        assert waited["took"] >= WAITED, waited["took"]
        # It went through once the turn was free: the new token works and the old one is dead.
        assert _me(waited["answer"].json()["access_token"]).status_code == 200 and _me(mine).status_code == 401
    finally:
        admin.delete_user(u["id"])
        admin.delete_user(v["id"])


def test_a_sign_out_everywhere_waits_for_the_same_turn(admin):
    u = admin.create_user(role="user")
    try:
        token = _signed_in(u)
        holder = _hold_the_turn(u["id"])
        ended, took = _timed(lambda: admin.post(f"/users/{u['id']}/terminate-sessions"))
        holder.wait(timeout=30)
        assert ended.status_code == 200 and ended.json()["terminated_count"] >= 1, ended.text
        assert took >= WAITED, took
        assert _me(token).status_code == 401
    finally:
        admin.delete_user(u["id"])


def test_no_token_outlives_a_sign_out_everywhere_that_races_a_renewal(admin):
    u = admin.create_user(role="user")
    try:
        outcomes = set()
        for _round in range(15):
            token = _signed_in(u)
            answers = {}
            start = threading.Barrier(2)

            def renew():
                start.wait()
                answers["renewal"] = _extend(token)

            def sign_out_everywhere():
                start.wait()
                answers["revocation"] = admin.post(f"/users/{u['id']}/terminate-sessions")
            racers = [threading.Thread(target=renew), threading.Thread(target=sign_out_everywhere)]
            for racer in racers:
                racer.start()
            for racer in racers:
                racer.join(timeout=30)
            assert answers["revocation"].status_code == 200, answers["revocation"].text
            assert answers["renewal"].status_code in (200, 401), answers["renewal"].text
            outcomes.add(answers["renewal"].status_code)
            # Whichever came first, nothing of the account is signed in now.
            assert _me(token).status_code == 401
            if answers["renewal"].status_code == 200:
                assert _me(answers["renewal"].json()["access_token"]).status_code == 401
        assert outcomes        # 200: the renewal came first and its session was ended; 401: it came second
    finally:
        admin.delete_user(u["id"])
