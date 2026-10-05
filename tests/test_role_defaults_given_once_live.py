"""Live: a role default an administrator revoked stays revoked when the web container restarts.

Before 0.33.1 every start granted each account every default of its role again, so a revoked default
(here the permission to create vaults) came back at the next restart. The start now gives an account only
the defaults added since the revision it holds. `dockvault.py accounts --action regranted-defaults` runs
python -m app.core.host_operator regranted-defaults in this container; it lists what an earlier restart
granted back, shown here with a row written as the old start wrote it.
test_role_defaults_given_once.py covers the rules offline.
"""
import json
import os
import subprocess
import time

import pytest
import requests

from conftest import ApiClient, BASE_URL, skip_if_container_absent
from _account_change_helpers import API, psql

pytestmark = [pytest.mark.integration, pytest.mark.disruptive]


def _groups(client, uid):
    r = client.get(f"/permissions/users/{uid}")
    assert r.status_code == 200, r.text
    return set(r.json()["granted_groups"])


def _restart_api():
    done = subprocess.run(["docker", "restart", API], capture_output=True, text=True, timeout=180)
    skip_if_container_absent(done, API)
    assert done.returncode == 0, (done.stderr or "")[:300]
    deadline = time.monotonic() + 180
    while time.monotonic() < deadline:
        try:
            if requests.get(f"{BASE_URL}/health", timeout=5).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(2)
    pytest.fail("the web container did not come back after a restart")


def _regranted():
    r = subprocess.run(["docker", "exec", "-i", API, "python", "-m", "app.core.host_operator",
                        "regranted-defaults"], capture_output=True, text=True, encoding="utf-8",
                       errors="replace", timeout=120)
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert lines and r.returncode == 0, (r.stderr or "")[-800:]
    answer = json.loads(lines[-1])
    assert answer["ok"], answer
    return {(p["username"], p["group"]) for p in answer["permissions"]}


def test_a_revoked_default_stays_revoked_across_a_restart(admin):
    account = admin.create_user()
    uid, name = account["id"], account["_username"]
    assert {"VAULT_CREATE", "FILE_DELETE"} <= _groups(admin, uid)
    assert psql(f"SELECT permission_defaults_revision FROM users WHERE id = '{uid}'") == "1"

    r = admin.delete(f"/permissions/users/{uid}/revoke/VAULT_CREATE")
    assert r.status_code == 200, r.text
    held = _groups(admin, uid)
    assert "VAULT_CREATE" not in held

    _restart_api()
    fresh = ApiClient(BASE_URL)
    fresh.login(os.environ.get("VAULT_ADMIN_USER", "admin"), os.environ["VAULT_ADMIN_PASS"])
    assert _groups(fresh, uid) == held, "the restart gave a revoked default back"
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'permission_default_granted' "
                f"AND resource_id = '{uid}'") == "0"
    assert (name, "VAULT_CREATE") not in _regranted()

    # What a restart before 0.33.1 did: the revoked group back, with no granter, after the revocation.
    psql("INSERT INTO user_endpoint_permissions (id, user_id, endpoint_group, granted_at, granted_by) "
         f"VALUES (gen_random_uuid(), '{uid}', 'VAULT_CREATE', (now() AT TIME ZONE 'utc') + interval '1 second', NULL)")
    assert (name, "VAULT_CREATE") in _regranted()
    fresh.delete(f"/permissions/users/{uid}/revoke/VAULT_CREATE")
    assert (name, "VAULT_CREATE") not in _regranted()
