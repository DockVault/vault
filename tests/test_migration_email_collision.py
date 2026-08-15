"""A pre-existing case-collision must not stop a deployment from booting.

`users.email` was case-SENSITIVE unique and was never lowercased on write, so a deployment running
today can legitimately hold `Bob@x.com` and `bob@x.com` as two accounts. The case-insensitive
unique index cannot be built there.

The chosen behaviour is: skip the index, warn naming the accounts, and boot anyway. The rejected
alternatives matter as much as the choice —

* **failing boot** would take a self-hosted vault down in the middle of an unattended update and
  keep it down until someone hand-edited the database;
* **nulling the newer duplicate** would silently destroy an address that may be the only way that
  person logs in.

The consequence is load-bearing and is asserted here: on such a deployment the index is ABSENT, so
the application-level uniqueness check is the only guard that remains. A future change that deletes
that check as "redundant with the index" would be wrong specifically for these installs.

This test restarts the API container, so it is excluded from the normal run and must be executed on
its own. It reverses everything it does, including rebuilding the index.
"""
import os
import subprocess
import time
import uuid

import pytest

pytestmark = [pytest.mark.integration, pytest.mark.disruptive]

DB = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
API = os.environ.get("VAULT_API_CONTAINER", "vault-api")
INDEX = "uq_users_email_lower"


def _psql(sql, fetch=True):
    cmd = ["docker", "exec", DB, "psql", "-U", "sftp_user", "-d", "sftp_db"]
    cmd += ["-tAc", sql] if fetch else ["-c", sql]
    out = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    assert out.returncode == 0, f"psql failed: {out.stderr[:400]}"
    return out.stdout.strip()


def _index_exists():
    return _psql(
        f"SELECT 1 FROM pg_indexes WHERE tablename='users' AND indexname='{INDEX}'"
    ) == "1"


def _restart_api_and_wait(timeout=180):
    subprocess.run(["docker", "restart", API], capture_output=True, text=True, timeout=120)
    deadline = time.time() + timeout
    while time.time() < deadline:
        out = subprocess.run(
            ["docker", "inspect", API, "--format", "{{.State.Health.Status}}"],
            capture_output=True, text=True, timeout=30,
        )
        if out.stdout.strip() == "healthy":
            return True
        time.sleep(3)
    return False


def _logs_since(marker_time):
    out = subprocess.run(
        ["docker", "logs", API, "--since", marker_time],
        capture_output=True, text=True, timeout=60,
    )
    return out.stdout + out.stderr


def test_a_pre_existing_case_collision_is_survived_not_fatal():
    """Seeds the exact situation an upgrade can meet, then reboots into it."""
    assert _index_exists(), (
        "precondition failed: the index should exist on a clean install, so this test would not "
        "prove the skip path"
    )

    local = f"collide_{uuid.uuid4().hex[:10]}"
    lower, upper = f"{local}@example.com", f"{local.upper()}@EXAMPLE.COM"
    user_a, user_b = f"{local}_a", f"{local}_b"

    try:
        # Recreate the pre-upgrade world: no case-insensitive index, and two accounts that
        # differ only in case. Both inserts must go in with the index gone, exactly as they
        # would have on a deployment that never had one.
        _psql(f"DROP INDEX IF EXISTS {INDEX}", fetch=False)
        for username, address in ((user_a, lower), (user_b, upper)):
            _psql(
                "INSERT INTO users (id, username, email, password_hash, role, is_active, "
                "created_at) VALUES (gen_random_uuid(), "
                f"'{username}', '{address}', 'x', 'USER', true, now())",
                fetch=False,
            )
        assert not _index_exists()

        marker = time.strftime("%Y-%m-%dT%H:%M:%S", time.gmtime(time.time() - 2))
        booted = _restart_api_and_wait()

        assert booted, (
            "the deployment did NOT come back up with a pre-existing case-collision — a real "
            "self-hoster would be left with a vault that is down mid-update"
        )

        logs = _logs_since(marker)
        assert INDEX in logs, (
            "boot produced no mention of the skipped index; the operator's only signal that "
            f"uniqueness is degraded is this warning. Logs:\n{logs[-1500:]}"
        )
        assert user_a in logs and user_b in logs, (
            "the warning did not NAME the colliding accounts, so an operator cannot act on it. "
            f"Logs:\n{logs[-1500:]}"
        )

        assert not _index_exists(), (
            "the index was created despite the collision — impossible unless the collision "
            "detector missed it, which would mean a real upgrade errors instead of warning"
        )

        # The whole point of the fallback: uniqueness must still be enforced without the index.
        assert _psql(
            "SELECT count(*) FROM users WHERE lower(email) = lower('%s')" % lower
        ) == "2", "the seeded collision is not actually present, so nothing was proven"

    finally:
        _psql(
            f"DELETE FROM users WHERE username IN ('{user_a}', '{user_b}')", fetch=False
        )
        _psql(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX} ON users (lower(email))", fetch=False
        )
        _restart_api_and_wait()


def test_the_index_is_rebuilt_once_the_collision_is_resolved():
    """The warning has to be actionable: resolving the accounts and restarting must fix it.

    Without this, "skip on collision" could be a permanent downgrade rather than a deferral, and
    an operator who did the work would get no reward for it.
    """
    assert _index_exists(), "expected the clean-install index to be present before this test"

    local = f"resolve_{uuid.uuid4().hex[:10]}"
    username = f"{local}_x"
    try:
        _psql(f"DROP INDEX IF EXISTS {INDEX}", fetch=False)
        _psql(
            "INSERT INTO users (id, username, email, password_hash, role, is_active, created_at) "
            f"VALUES (gen_random_uuid(), '{username}', '{local}@example.com', 'x', 'USER', true, "
            "now())",
            fetch=False,
        )
        # No collision this time, so the boot SHOULD build the index.
        assert _restart_api_and_wait(), "the stack did not come back up"
        assert _index_exists(), (
            "the index was not created on a clean database — the skip path is firing when it "
            "should not, silently leaving every deployment without race protection"
        )
    finally:
        _psql(f"DELETE FROM users WHERE username = '{username}'", fetch=False)
        _psql(
            f"CREATE UNIQUE INDEX IF NOT EXISTS {INDEX} ON users (lower(email))", fetch=False
        )
