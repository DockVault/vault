"""Whether every SFTP process runs the web app's version, on a running stack (app/core/sftp_versions.py).

The stack's SFTP container records itself, with the version baked into its image, and keeps its row
fresh; the web container's sftp_same_version() then says yes. An older SFTP process recorded beside it
makes the answer no, naming its version; with none live the answer depends on whether the deployment
runs SFTP. test_sftp_versions.py covers the rest offline.
"""
from __future__ import annotations

import json
import os
import subprocess
import time
import uuid

import pytest

from _account_change_helpers import psql
from conftest import skip_if_container_absent

pytestmark = pytest.mark.integration

_CHECK = """
import json, sys
from datetime import datetime, timedelta
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint('sftp-version-check')
from app.core import sftp_versions as S
from app.core.database import SessionLocal
db = SessionLocal()
try:
    c = S.sftp_same_version(db, now=datetime.utcnow() + timedelta(seconds=int(sys.argv[2])),
                            environ=json.loads(sys.argv[1]))
finally:
    db.close()
print("CHECK=" + json.dumps({"ok": c.ok, "reason": c.reason, "versions": list(c.versions),
                             "explain": c.explain()}))
"""


def _api():
    return os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _sftp():
    return os.environ.get("VAULT_SFTP_CONTAINER", "vault-sftp")


def _check(environ, ahead_seconds=0):
    out = subprocess.run(["docker", "exec", _api(), "python", "-c", _CHECK, json.dumps(environ), str(ahead_seconds)],
                         capture_output=True, text=True, timeout=120)
    skip_if_container_absent(out, _api())
    assert out.returncode == 0, (out.stderr or "")[-800:]
    (line,) = [l for l in out.stdout.splitlines() if l.startswith("CHECK=")]
    return json.loads(line.split("=", 1)[1])


def _in(container, *cmd):
    out = subprocess.run(["docker", "exec", container, *cmd], capture_output=True, text=True, timeout=60)
    skip_if_container_absent(out, container)
    assert out.returncode == 0, out.stderr[-400:]
    return out.stdout.strip()


SPLIT = {"COMPOSE_PROFILES": "split"}
# What run_combined.py tells a web process it started with no SFTP server beside it.
NO_SFTP = {"COMPOSE_PROFILES": "combined", "RUN_SFTP": "", "VAULT_COMBINED_SFTP": "off"}
OWN = None      # the web container's own environment


def _sftp_rows():
    host = _in(_sftp(), "hostname")
    rows = psql(f"SELECT id, version, extract(epoch FROM seen_at) FROM sftp_processes WHERE host = '{host}' "
                "AND seen_at > now() AT TIME ZONE 'utc' - interval '2 minutes'")
    return [line.split("|") for line in rows.splitlines()]


def test_the_sftp_container_records_its_version_and_keeps_it_fresh():
    version = _in(_sftp(), "cat", "/app/VERSION")
    assert version == _in(_api(), "cat", "/app/VERSION")
    rows = []
    deadline = time.monotonic() + 60
    while not rows and time.monotonic() < deadline:
        rows = _sftp_rows()
        time.sleep(1)
    assert len(rows) == 1, rows
    pid, recorded, seen = rows[0]
    assert recorded == version
    deadline = time.monotonic() + 75
    while time.monotonic() < deadline:
        again = [r for r in _sftp_rows() if r[0] == pid]
        if again and float(again[0][2]) > float(seen):
            return
        time.sleep(2)
    raise AssertionError("the SFTP process did not refresh its row")


def test_the_web_app_sees_every_sftp_process_on_its_version():
    assert _sftp_rows(), "the SFTP container has not recorded itself"
    for environ in (SPLIT, NO_SFTP):
        check = _check(environ)
        assert (check["ok"], check["reason"]) == (True, "same"), check


def test_an_older_sftp_process_beside_it_makes_the_answer_no():
    pid = str(uuid.uuid4())
    psql("INSERT INTO sftp_processes (id, version, host, started_at, seen_at) VALUES "
         f"('{pid}', '0.33.9-probe', 'probe', now() AT TIME ZONE 'utc', now() AT TIME ZONE 'utc')")
    try:
        check = _check(SPLIT)
        assert (check["ok"], check["reason"], check["versions"]) == (False, "other_version", ["0.33.9-probe"])
        assert "0.33.9-probe" in check["explain"]
    finally:
        psql(f"DELETE FROM sftp_processes WHERE id = '{pid}'")
    assert _check(SPLIT)["ok"] is True


def test_with_none_live_the_answer_follows_whether_the_deployment_runs_sftp():
    # Asked an hour from now, every row is stale: nothing has recorded itself since.
    none_live = _check(SPLIT, ahead_seconds=3600)
    assert (none_live["ok"], none_live["reason"]) == (False, "none_live"), none_live
    off = _check(NO_SFTP, ahead_seconds=3600)
    assert (off["ok"], off["reason"]) == (True, "off"), off


def test_a_web_container_started_on_its_own_never_answers_that_sftp_is_off():
    # This stack's web container runs `python -m app.api.api_server` beside an SFTP container, as the trial
    # compose and the split profile do, whatever its .env says of RUN_SFTP and COMPOSE_PROFILES. An SFTP
    # server of an older release never records itself, so with none live the answer is no, never "off".
    assert "VAULT_COMBINED_SFTP" not in _in(_api(), "env")
    deadline = time.monotonic() + 60
    while not _sftp_rows() and time.monotonic() < deadline:
        time.sleep(1)
    now = _check(OWN)
    assert (now["ok"], now["reason"]) == (True, "same"), now
    none_live = _check(OWN, ahead_seconds=3600)
    assert (none_live["ok"], none_live["reason"]) == (False, "none_live"), none_live
