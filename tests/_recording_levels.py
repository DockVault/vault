"""Live-test helpers for the recording levels: read the version in force, and store a new one in the policies
table as the panel would, then give the web app and the SFTP server time to read it."""
import time

import pytest

from _account_change_helpers import psql

KEYS = ("names", "signin_names", "emails", "ip", "user_agent")
POLICY_ONE = {"names": "none", "signin_names": "full", "emails": "full", "ip": "full", "user_agent": "full"}
# The processes read the table again every few seconds (audit_privacy.REFRESH_SECONDS is 5).
SETTLE_SECONDS = 8


def latest():
    """(version, levels) of the newest version."""
    line = psql("SELECT version, " + ", ".join(KEYS) + " FROM audit_privacy_policies ORDER BY version DESC LIMIT 1")
    version, *levels = line.split("|")
    return int(version), dict(zip(KEYS, levels))


def store(levels, by="live test"):
    """Add the next version with ``levels`` and wait for the processes to read it. Returns its number."""
    version, _ = latest()
    psql("INSERT INTO audit_privacy_policies (version, " + ", ".join(KEYS) + ", reason, created_at, created_by_name) "
         f"VALUES ({version + 1}, " + ", ".join(f"'{levels[k]}'" for k in KEYS)
         + f", 'admin', now() AT TIME ZONE 'utc', '{by}')")
    time.sleep(SETTLE_SECONDS)
    return version + 1


@pytest.fixture
def levels_restored():
    """The levels in force when the test starts; stored again as a newer version when it ends. Every account is
    then marked as having read the notice, so the banner a change shows does not stay over other tests' pages."""
    _, before = latest()
    yield before
    version = store(before, by="live test, restoring")
    mark_all_read(version)
    # A version stored here, as the panel stores one, does not keep the rollback marker the way a save does.
    if all(before[k] == POLICY_ONE[k] or k == "names" for k in KEYS):
        psql("DO $$ BEGIN IF to_regclass('data_requirements') IS NOT NULL THEN "
             "DELETE FROM data_requirements WHERE key = 'recording-levels'; END IF; END $$")


ACTION = "admin.audit_privacy.write"


def save(admin, password, levels):
    """Save ``levels`` as the panel does: a password step-up for the action, then the PUT with its receipt.
    Returns the answer's JSON.

    A step-up is limited to ten an account in five minutes, and a run of tests that all confirm as the one
    administrator reaches that (the limit answers 429, with no receipt). Then the save is made by a short-lived
    second administrator confirming with its own password: the same rule, proven the same way
    (_sf_helpers.put_settings_with_password does the same for the settings)."""
    r = admin.post("/auth/second-factor/step-up", json={"action": ACTION, "method": "password", "code": password})
    if r.status_code == 429:
        return _save_as_a_second_administrator(admin, levels)
    assert r.status_code == 200, r.text
    saved = admin.put("/settings/recording", json={"levels": levels}, headers={"X-Second-Factor": r.json()["receipt"]})
    assert saved.status_code == 200, saved.text
    return saved.json()


def _save_as_a_second_administrator(admin, levels):
    from conftest import ApiClient

    other = admin.create_user(role="admin")
    done = False
    try:
        second = ApiClient()
        second.login(other["_username"], other["_password"])
        r = second.post("/auth/second-factor/step-up",
                        json={"action": ACTION, "method": "password", "code": other["_password"]})
        assert r.status_code == 200, r.text
        saved = second.put("/settings/recording", json={"levels": levels},
                           headers={"X-Second-Factor": r.json()["receipt"]})
        assert saved.status_code == 200, saved.text
        done = True
        return saved.json()
    finally:
        gone = admin.delete_user(other["id"])
        # Checked only when nothing else went wrong, so the first failure is the one reported.
        if done:
            assert gone.status_code in (200, 204), f"the second administrator was not removed: {gone.text}"


def mark_all_read(version=None):
    version = version if version is not None else latest()[0]
    psql(f"UPDATE users SET privacy_seen_version = {int(version)}")


def wait_for(check, timeout=20.0, step=0.5):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        value = check()
        if value:
            return value
        time.sleep(step)
    return check()
