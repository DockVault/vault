"""Live: an SFTP sign-in whose temporary-credential policy cannot be checked is refused.

Inside the SFTP container, against the real database, audit log and throttle, the second-factor
policy is made to raise before the password and key sign-ins run. Both are refused, the operational
log names the exception class and not its text, and the refused password sign-in is in the audit log
as "SFTP sign-in policy could not be checked". With the policy put back, the same two sign-ins
succeed, so the refusal came from the injected failure and nothing else. Before this change the
injected failure let both sign-ins through.

test_sftp_policy_fails_closed.py covers the same offline.
"""
import json
import os
import subprocess

import pytest

from conftest import skip_if_container_absent

paramiko = pytest.importorskip("paramiko")

pytestmark = pytest.mark.integration

_CONTAINER = (os.environ.get("VAULT_SFTP_CONTAINER") or os.environ.get("VAULT_API_CONTAINER")
              or "vault-sftp")
_CLIENT_IP = "198.51.100.77"

_SCRIPT = r"""
import base64, json, sys
from app.core.config import bootstrap_entrypoint
bootstrap_entrypoint("sftp-policy-test")
import paramiko
import app.core.second_factor_policy as pol
from app.sftp.sftp_server import SFTPServer

args = json.load(sys.stdin)
key = paramiko.RSAKey(data=base64.b64decode(args["key"]))
real = pol.effective_policy

def broken(blob):
    raise RuntimeError("injected-policy-failure")

def both():
    return {
        "password": SFTPServer(args["ip"]).check_auth_password(args["user"], args["password"]),
        "key": SFTPServer(args["ip"]).check_auth_publickey(args["user"], key),
    }

pol.effective_policy = broken
refused = both()
pol.effective_policy = real
allowed = both()
ok = paramiko.AUTH_SUCCESSFUL
print(json.dumps({"broken": {k: v == ok for k, v in refused.items()},
                  "readable": {k: v == ok for k, v in allowed.items()}}))
"""


def test_a_policy_that_cannot_be_checked_refuses_both_sign_ins(admin, temp_user):
    uid, name = temp_user["id"], temp_user["_username"]
    key = paramiko.RSAKey.generate(2048)
    r = admin.post(f"/users/{uid}/ssh-keys",
                   json={"name": "policy-probe", "public_key": f"{key.get_name()} {key.get_base64()}"})
    assert r.status_code in (200, 201), r.text

    args = {"user": name, "password": temp_user["_password"], "key": key.get_base64(), "ip": _CLIENT_IP}
    try:
        run = subprocess.run(["docker", "exec", "-i", _CONTAINER, "python", "-c", _SCRIPT],
                             input=json.dumps(args), capture_output=True, text=True, timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(run, _CONTAINER)
    assert run.returncode == 0, (run.stderr or run.stdout)[-800:]

    lines = run.stdout.strip().splitlines()
    result = json.loads(lines[-1])
    assert result["readable"] == {"password": True, "key": True}, (
        "with the policy readable both sign-ins must succeed, or the refusal below proves nothing")
    assert result["broken"] == {"password": False, "key": False}, result

    log = "\n".join(lines[:-1])
    assert log.count("event auth.policy-check.failed") == 2, log
    assert "err=RuntimeError" in log and "injected-policy-failure" not in log, log

    rows = admin.get("/audit/log", params={"action": "login_failure", "limit": 2000}).json()
    mine = [row for row in rows if row["username"] == name]
    assert mine and (mine[0]["details"] or {}).get("reason") == "SFTP sign-in policy could not be checked", mine[:3]
    assert mine[0]["ip_address"] == _CLIENT_IP
