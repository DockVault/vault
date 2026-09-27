"""Live: finished session and pending sign-in rows are deleted once they are 30 days old.

Rows are written straight into the database with the ages the purge looks at, then the purge the
periodic cleanup runs is called inside the web container, against the real database. The old
finished rows are gone, the recent ones are kept. The cleanup itself runs every five minutes, so it
may get to the old rows first; the test reads what is left rather than how many the call deleted.

test_session_retention.py covers the same offline.
"""
import os
import subprocess
import uuid

import pytest

from conftest import skip_if_container_absent

pytestmark = pytest.mark.integration

_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")
NOW = "(now() AT TIME ZONE 'utc')"


def _run(container, argv):
    try:
        r = subprocess.run(["docker", "exec", "-i", container, *argv],
                           capture_output=True, text=True, timeout=60)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, container)
    assert r.returncode == 0, (r.stderr or r.stdout)[-600:]
    return r.stdout.strip()


def _psql(sql):
    return _run(_DB_CONTAINER, ["psql", "-U", "sftp_user", "-d", "sftp_db",
                                "-v", "ON_ERROR_STOP=1", "-Atc", sql])


def _session(uid, *, age_days, active=False, revoked=False):
    sid = str(uuid.uuid4())
    when = f"{NOW} - interval '{age_days} days'"
    _psql("INSERT INTO active_sessions (id, session_token, user_id, ip_address, started_at, "
          "last_activity, is_active, revoked) VALUES "
          f"('{sid}', '{uuid.uuid4().hex}', '{uid}', '198.51.100.21', {when}, {when}, "
          f"{'true' if active else 'false'}, {'true' if revoked else 'false'})")
    return sid


def _pending(uid, *, age_days, consumed):
    pid = str(uuid.uuid4())
    when = f"{NOW} - interval '{age_days} days'"
    _psql("INSERT INTO pending_logins (id, user_id, client_ip, enrollment_required, attempts, "
          "expires_at, consumed_at, created_at) VALUES "
          f"('{pid}', '{uid}', '198.51.100.21', false, 0, {when} + interval '5 minutes', "
          f"{when if consumed else 'NULL'}, {when})")
    return pid


def _left(table, ids):
    listed = ", ".join(f"'{i}'" for i in ids)
    return set(_psql(f"SELECT id FROM {table} WHERE id IN ({listed})").split())


def test_finished_rows_older_than_thirty_days_are_deleted(temp_user):
    uid = temp_user["id"]
    old_sessions = {_session(uid, age_days=31), _session(uid, age_days=45, revoked=True)}
    kept_sessions = {_session(uid, age_days=29)}
    old_pending = {_pending(uid, age_days=31, consumed=True), _pending(uid, age_days=40, consumed=False)}
    kept_pending = {_pending(uid, age_days=29, consumed=True)}

    out = _run(_API_CONTAINER, ["python", "-c",
                                "from app.core.config import bootstrap_entrypoint\n"
                                "bootstrap_entrypoint('retention-test')\n"
                                "from app.core.database import get_db_context\n"
                                "from app.core.session_retention import purge_old_session_data\n"
                                "with get_db_context() as db:\n"
                                "    print(purge_old_session_data(db))\n"])
    assert out.splitlines()[-1].startswith("("), out

    assert _left("active_sessions", old_sessions | kept_sessions) == kept_sessions
    assert _left("pending_logins", old_pending | kept_pending) == kept_pending
