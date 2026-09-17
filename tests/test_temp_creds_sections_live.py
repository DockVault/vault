"""End-to-end HTTP behaviour of the two-section temp-credentials listing, against a running
deployment: the section split, the device DISPLAY NAME (never an id/secret), the lifecycle state
(a finished credential shows expired), and scoping (a second user's credentials never appear).

Needs a running deployment (and the SFTP door for the finished case), so it lives in the live lane;
the field contract and the browser render are pinned offline / in the UI lane respectively.
"""
import threading
import time

import pytest

from conftest import BASE_URL, unique
from _device_boundary_helpers import grant, mint_sync_cred, register_device, sftp_authenticates

pytestmark = pytest.mark.integration


def _rows(client):
    return client.session.get(f"{BASE_URL}/temp-creds/list", timeout=90).json()


def test_the_listing_splits_shared_and_per_computer_and_names_the_device(admin, temp_vault):
    handout = admin.post("/auth/temp-credentials", json={"note": unique("handout")}).json()
    dev = register_device(admin, label="my-laptop")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()

    by_name = {r["temp_username"]: r for r in _rows(admin)}
    shared = by_name[handout["temp_username"]]
    assert shared["is_device_credential"] is False and shared["device_name"] is None

    per_computer = by_name[minted["temp_username"]]
    assert per_computer["is_device_credential"] is True
    assert per_computer["device_name"] == dev["label"]         # the display NAME, not an id
    assert per_computer["lifecycle"] in ("active", "in-use", "expired")

    # Non-enumeration: the row carries no device id (neither the key nor the value) and no secret.
    assert "device_id" not in per_computer
    assert dev["device_id"] not in str(per_computer), "the device UUID leaked into the row"
    assert all("secret" not in k.lower() for k in per_computer), per_computer.keys()


def test_a_finished_device_credential_shows_expired_never_active(admin, temp_vault):
    dev = register_device(admin, label="sync-box")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()
    assert sftp_authenticates(minted["temp_username"], minted["credential"])

    # The connection closed -> the credential is finished; its row settles to expired. A just-finished
    # credential can read 'active' for a brief transient -- measured at up to ~0.01 s, in a minority
    # of runs -- between the SFTP connection closing and the server-side close-release committing
    # slot_released_at. That transient is NOT the bug this guards (a credential that STAYS active), so
    # asserting 'not active' on the first poll turned it into a flaky failure. Poll until the lifecycle
    # SETTLES to 'expired' (typically within ~1 s) and fail only if it never does within a generous
    # close-release budget -- which still catches a credential stuck 'active'.
    last = None
    deadline = time.monotonic() + 10
    while time.monotonic() < deadline:
        row = next((r for r in _rows(admin) if r["temp_username"] == minted["temp_username"]), None)
        assert row is not None
        last = row["lifecycle"]
        if last == "expired":
            break
        time.sleep(0.2)
    assert last == "expired", f"a finished device credential never settled to expired (last={last!r})"


def test_a_second_user_never_sees_the_owners_device_credentials(admin, temp_vault, temp_user_client):
    dev = register_device(admin, label="owners-box")
    grant(admin, dev["device_id"], temp_vault["id"])
    minted = mint_sync_cred(dev["secret"], temp_vault["id"]).json()

    names = {r["temp_username"] for r in _rows(temp_user_client)}
    assert minted["temp_username"] not in names   # a non-admin sees only their own credentials


def _mint(client, note, timeout=15):
    try:
        r = client.session.post(f"{BASE_URL}/auth/temp-credentials", json={"note": note}, timeout=timeout)
        return r.status_code
    except Exception as exc:  # a client-side timeout on a wedged request must READ as a failure
        return "error:%s" % exc.__class__.__name__


def _clear_creds(client):
    for row in client.session.get(f"{BASE_URL}/temp-creds/list", timeout=30).json():
        client.session.post(f"{BASE_URL}/temp-creds/{row['temp_username']}/delete", timeout=30)


def _race_two_mints(client):
    """Fire two mints at once behind a barrier; join with a wall-clock bound so a lock WEDGE surfaces
    as a hung thread (assertion) rather than hanging the lane. Returns the two outcomes."""
    barrier = threading.Barrier(2)
    results = []

    def _one():
        barrier.wait()
        results.append(_mint(client, unique("race")))

    threads = [threading.Thread(target=_one) for _ in range(2)]
    started = time.monotonic()
    for t in threads:
        t.start()
    for t in threads:
        t.join(20)
    assert all(not t.is_alive() for t in threads), "a mint did not return within 20s -- a row-lock wedge"
    assert time.monotonic() - started < 20, "the two concurrent mints took too long -- a lock stall"
    return results


def test_two_concurrent_mints_at_the_per_user_cap_admit_exactly_one(admin, temp_user_client):
    # Carried pre-existing check-then-act, now under the per-user advisory lock. Repeat the boundary race so a
    # stall is caught, not tolerated: each trial fills the non-admin to one below the cap, fires two
    # mints at once, and asserts exactly one is admitted and one hits the cap -- within a wall-clock
    # bound, so reverting the advisory lock to a users-row FOR UPDATE (which deadlocks the audit insert) FAILS the
    # test on a hung thread instead of hanging the lane.
    cap = (admin.session.get(f"{BASE_URL}/temp-passcode-policy", timeout=30).json()
           .get("max_temp_creds_per_user") or 0)
    if cap <= 0 or cap > 30:
        pytest.skip(f"per-user cap ({cap}) is unlimited or too large to race cheaply")
    if _mint(temp_user_client, unique("probe")) not in (200, 201):
        pytest.skip("this non-admin cannot mint temp credentials here (step-up/permissions differ)")
    _clear_creds(temp_user_client)

    for trial in range(5):
        for _ in range(cap - 1):
            assert _mint(temp_user_client, unique("fill")) in (200, 201), f"fill failed on trial {trial}"
        results = _race_two_mints(temp_user_client)
        admitted = sum(1 for r in results if r in (200, 201))
        refused = sum(1 for r in results if r == 409)
        assert admitted == 1 and refused == 1, f"trial {trial}: {results}"
        _clear_creds(temp_user_client)


def test_two_different_users_mint_concurrently_without_contention(admin):
    # Cross-user control: the per-user advisory lock serializes ONE user, never two. Two different
    # non-admins each mint at once and both succeed -- they hash to different advisory keys, no wait.
    from conftest import ApiClient
    u1 = admin.create_user(role="user")
    u2 = admin.create_user(role="user")
    try:
        c1 = ApiClient(); c1.login(u1["_username"], u1["_password"])
        c2 = ApiClient(); c2.login(u2["_username"], u2["_password"])
        if _mint(c1, unique("probe")) not in (200, 201):
            pytest.skip("this non-admin cannot mint temp credentials here (step-up/permissions differ)")

        barrier = threading.Barrier(2)
        results = []

        def _one(client):
            barrier.wait()
            results.append(_mint(client, unique("cross")))

        threads = [threading.Thread(target=_one, args=(c,)) for c in (c1, c2)]
        started = time.monotonic()
        for t in threads:
            t.start()
        for t in threads:
            t.join(20)
        assert all(not t.is_alive() for t in threads), "a cross-user mint hung -- the lock is not per-user"
        assert time.monotonic() - started < 20
        assert all(r in (200, 201) for r in results), f"two different users could not both mint: {results}"
    finally:
        admin.delete_user(u1["id"])
        admin.delete_user(u2["id"])


import os as _os
import subprocess as _subprocess

_DB_CONTAINER = _os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql, timeout=30):
    return _subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=timeout)


def _idle_in_transaction_count():
    out = _psql("SELECT count(*) FROM pg_stat_activity WHERE datname='sftp_db' "
                "AND state='idle in transaction'")
    if out.returncode != 0:
        return None
    try:
        return int(out.stdout.strip())
    except ValueError:
        return None


def _require_db_or_skip():
    """The two anti-wedge tests below inspect Postgres directly via `docker exec <container> psql`.
    When the DB is unreachable that way -- almost always because VAULT_DB_CONTAINER does not name
    THIS stack's db container (it defaults to 'vault-db', with sftp_user/sftp_db hard-coded) -- the
    tests must NOT vanish into a silent skip on a stack that is meant to run the live lane, or the
    HIGH they guard goes unproven and the suite reads green. So: when an explicit live-lane marker is
    set (CI), a failed probe is a hard ERROR that names the knob to fix; on an ad-hoc local run (no
    marker) it degrades to a skip with the same message."""
    try:
        ok = _psql("SELECT 1").returncode == 0
        why = ""
    except Exception as exc:                       # docker missing, timeout, etc.
        ok, why = False, " (%s)" % exc.__class__.__name__
    if ok:
        return
    msg = ("cannot reach Postgres via `docker exec %s psql -U sftp_user -d sftp_db`%s; set "
           "VAULT_DB_CONTAINER to this stack's db container (currently %r)" % (_DB_CONTAINER, why, _DB_CONTAINER))
    if _os.environ.get("CI"):
        pytest.fail(msg)                           # live lane is meant to run -> do not hide the HIGH
    pytest.skip(msg)


def test_a_refused_mint_leaves_no_idle_in_transaction_backend_and_the_next_mint_is_immediate(
        admin, temp_user_client):
    # The anti-wedge proof: after a loser is refused at the cap, no API backend is left
    # idle-in-transaction (the refusal rolled back), and the same user's next mint returns at once
    # rather than waiting on a held lock.
    _require_db_or_skip()
    cap = (admin.session.get(f"{BASE_URL}/temp-passcode-policy", timeout=30).json()
           .get("max_temp_creds_per_user") or 0)
    if cap <= 0 or cap > 30:
        pytest.skip(f"per-user cap ({cap}) is unlimited or too large to race cheaply")
    if _mint(temp_user_client, unique("probe")) not in (200, 201):
        pytest.skip("this non-admin cannot mint temp credentials here (step-up/permissions differ)")
    _clear_creds(temp_user_client)

    for _ in range(cap - 1):
        assert _mint(temp_user_client, unique("fill")) in (200, 201)
    results = _race_two_mints(temp_user_client)          # one wins, one is refused at the cap
    assert sum(1 for r in results if r == 409) == 1, f"expected exactly one refusal: {results}"  # a loser exists

    # No API backend stuck idle-in-transaction after the refusal (poll briefly; other traffic may
    # transiently be mid-transaction, so allow it to settle to zero).
    settled = False
    for _ in range(10):
        n = _idle_in_transaction_count()
        if n == 0:
            settled = True
            break
        time.sleep(0.5)
    assert settled, "an API backend stayed idle-in-transaction after a refused mint (lock held past the raise)"

    # And the next mint by the SAME user returns immediately (a slot freed when a fill is deleted).
    _clear_creds(temp_user_client)
    started = time.monotonic()
    assert _mint(temp_user_client, unique("after")) in (200, 201)
    assert time.monotonic() - started < 10, "the next mint did not return promptly -- a lock stall"
    _clear_creds(temp_user_client)


def test_the_lock_timeout_backstop_turns_a_stuck_row_lock_into_a_clean_error():
    # A contended row lock, with lock_timeout at the app's value, raises within the timeout instead of
    # waiting forever. (The app applies lock_timeout via connect_args -- pinned by source; this proves
    # the VALUE is effective on this Postgres.)
    _require_db_or_skip()
    from app.core.database import _LOCK_TIMEOUT_MS
    lock_ms = _LOCK_TIMEOUT_MS

    holder = _subprocess.Popen(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc",
         "BEGIN; SELECT id FROM users ORDER BY id LIMIT 1 FOR UPDATE; SELECT pg_sleep(%d); ROLLBACK;"
         % (lock_ms // 1000 + 5)],
        stdout=_subprocess.PIPE, stderr=_subprocess.PIPE, text=True)
    try:
        time.sleep(1.5)   # let the holder take the row lock
        started = time.monotonic()
        waiter = _psql("SET lock_timeout='%dms'; BEGIN; "
                       "SELECT id FROM users ORDER BY id LIMIT 1 FOR UPDATE;" % lock_ms,
                       timeout=lock_ms // 1000 + 10)
        elapsed = time.monotonic() - started
        assert waiter.returncode != 0, "the contended lock did not error -- lock_timeout not effective"
        assert "lock timeout" in (waiter.stderr or "").lower(), waiter.stderr
        assert elapsed < (lock_ms / 1000) + 4, f"the lock wait ({elapsed:.1f}s) was not bounded by the timeout"
    finally:
        holder.terminate()
        try:
            holder.wait(timeout=10)
        except Exception:
            holder.kill()
