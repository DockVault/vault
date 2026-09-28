"""Live: the Activity summary counts the automatic sign-in locks, from one address and account-wide.

Wrong passwords arm a lock against the address they came from and, past a higher count across
addresses, one against every address. Each is recorded as account_auto_locked with its scope. The
summary band's sign-in outcomes count each lock armed as "Locked out", and every wrong or refused
sign-in, a refusal by a lock included, as "Failed"; the list filtered to the events the catalog gives
for "Locked out" shows the same locks. Everything is filtered to one fresh account, so other rows in
the log do not count.

The limits are set small for the test (3 per address, 3 x 2 = 6 account-wide). The second and third
source addresses are requests sent from inside the stack's own containers.
"""
import time

import pytest

from conftest import ApiClient, BASE_URL
from _account_change_helpers import (SFTP_CONTAINER, lock_rows, reset_sign_in_throttle,
                                     sign_in_from_inside)

pytestmark = pytest.mark.integration

THRESHOLD, MULTIPLE = 3, 2
WRONG = "definitely-not-the-password"


@pytest.fixture
def small_limits(admin):
    before = admin.get("/settings").json()
    snap = {k: before.get(k) or 0 for k in ("max_login_attempts", "lockout_backstop_multiplier")}
    r = admin.put("/settings", json={"max_login_attempts": THRESHOLD, "lockout_backstop_multiplier": MULTIPLE})
    assert r.status_code == 200, r.text
    reset_sign_in_throttle()
    yield
    admin.put("/settings", json=snap)
    reset_sign_in_throttle()


def _web(username, password):
    return ApiClient(BASE_URL).session.post(f"{BASE_URL}/auth/login", timeout=30,
                                            json={"username": username, "password": password})


def _events(admin, name, **params):
    r = admin.get("/activity/events", params={"user": name, "user_match": "exact", "page": 1, "limit": 100,
                                              **params})
    assert r.status_code == 200, r.text
    return r.json()


def _band(admin, name, want_locked):
    for _ in range(25):
        r = admin.get("/activity/summary", params={"range": "24h", "user": name, "user_match": "exact"})
        assert r.status_code == 200, r.text
        band = r.json()
        if band["sign_ins"]["locked"] >= want_locked:
            return band
        time.sleep(0.2)
    raise AssertionError(f"the band never counted {want_locked} locks: {band['sign_ins']}")


def test_the_band_counts_both_kinds_of_automatic_lock(admin, temp_user, small_limits):
    uid, name, pw = temp_user["id"], temp_user["_username"], temp_user["_password"]
    for _ in range(THRESHOLD):
        assert _web(name, WRONG).status_code == 401                 # this host: paused
    reset_sign_in_throttle()                     # the throttle fires at the same count; the lock stays
    assert _web(name, pw).status_code == 403                         # refused by that lock
    for _ in range(THRESHOLD - 1):
        assert sign_in_from_inside(name, WRONG, container=SFTP_CONTAINER,
                                   url="http://vault-api:8000")[0] == 401
    assert sign_in_from_inside(name, WRONG)[0] == 401               # the sixth failure: everywhere
    assert sign_in_from_inside(name, pw)[0] == 403                  # refused by the account-wide lock
    rows = lock_rows(uid)
    assert rows["*"] == (THRESHOLD * MULTIPLE, True)
    assert sum(1 for _count, locked in rows.values() if locked) == 2

    band = _band(admin, name, 2)
    assert band["sign_ins"]["locked"] == 2, band["sign_ins"]
    assert band["sign_ins"]["succeeded"] == 0, band["sign_ins"]
    # Six wrong passwords and two refusals by a lock, each a failed sign-in in the log.
    failures = _events(admin, name, action="login_failure")
    assert failures["total"] == 2 * THRESHOLD + 2
    assert band["sign_ins"]["failed"] == failures["total"], band["sign_ins"]

    # "Locked out" filters the list to the catalog's events for it: the two locks, one of each scope.
    outcomes = admin.get("/activity/catalog").json()["sign_in_outcomes"]
    assert outcomes["locked"] == ["account_auto_locked"]
    locks = _events(admin, name, action=outcomes["locked"])
    assert locks["total"] == 2
    assert sorted(e["details"]["scope"] for e in locks["events"]) == ["account", "address"]
    assert all(e["category"] == "sign_in" and e["username"] == name for e in locks["events"])


def test_the_host_operators_changes_are_among_names_with_no_account(admin, temp_user):
    """The server's operator acts from the host under a name no account may take (operator@host). The
    Activity page shows that name on the row and counts it with the names that have no account, as the
    page's help for that group says."""
    import json
    import subprocess
    from _account_change_helpers import API
    uid, name = temp_user["id"], temp_user["_username"]
    r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", "app.core.host_operator",
                        "reset-second-factor", "--username", name, "--confirm-username", name],
                       capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    assert r.returncode == 0 and json.loads(r.stdout.strip().splitlines()[-1])["ok"], r.stdout[-400:]
    rows = [e for e in _events(admin, "operator@host", no_account="true")["events"]
            if e["resource_id"] == uid]
    assert rows and all(e["username"] == "operator@host" and not e["automatic"] for e in rows)
