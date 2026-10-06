"""Live: the host command's zk-status action, run inside the web container the way a managing operator's
tooling runs it (docker exec <web container> python -m app.core.host_operator zk-status).

  * it answers what an administrator reads from GET /zk-enabled and GET /zk/unsealed, a name that was
    never sealed included, and nothing name-like;
  * it needs no password: the answer is the same whatever ADMIN_USERNAME and ADMIN_PASSWORD hold in its
    environment, with none at all, and when no account is an administrator;
  * it changes nothing and writes no audit row.

test_host_operator_zk_status.py covers the answer's shape offline.
"""
import json
import secrets
import subprocess

import pytest

from conftest import create_zk_vault, skip_if_container_absent, unique, zk_chunked_upload
from _account_change_helpers import API, psql

pytestmark = pytest.mark.integration

ENABLED_KEYS = ("zero_knowledge_enabled", "must_use_zk", "plan_zero_knowledge", "max_zk_vaults", "zk_vault_count")
UNSEALED_KEYS = ("zk_vaults", "files_unsealed", "folders_unsealed", "vaults_affected")
NO_CREDENTIALS = (("ADMIN_USERNAME", ""), ("ADMIN_EMAIL", ""), ("ADMIN_PASSWORD", ""))


def zk_status(env=()):
    """The action's answer and everything it printed on standard output."""
    cmd = ["docker", "exec", "-i"]
    for name, value in env:
        cmd += ["-e", f"{name}={value}"]
    cmd += [API, "python", "-m", "app.core.host_operator", "zk-status"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert len(lines) == 1, (r.stdout[-800:], (r.stderr or "")[-800:])
    answer = json.loads(lines[0])
    assert r.returncode == 0 and answer["ok"] is True, (r.returncode, answer, (r.stderr or "")[-800:])
    return answer["zero_knowledge"], r.stdout


def _as_the_administrator_reads_it(admin):
    enabled = admin.get("/zk-enabled").json()
    unsealed = admin.get("/zk/unsealed").json()
    return {**{k: enabled[k] for k in ENABLED_KEYS}, **{k: unsealed[k] for k in UNSEALED_KEYS}}


@pytest.fixture
def zk_on(admin):
    before = admin.get("/settings").json().get("zero_knowledge_enabled")
    assert admin.put("/settings", json={"zero_knowledge_enabled": True}).status_code == 200
    yield
    if isinstance(before, bool):
        admin.put("/settings", json={"zero_knowledge_enabled": before})


def test_it_reads_what_an_administrator_reads_and_no_name(admin, zk_on):
    name = unique("zk-status-vault")
    vault = create_zk_vault(admin, name=name)
    try:
        file_name = unique("never-sealed-name") + ".txt"
        fid = zk_chunked_upload(admin, vault["id"], file_name, secrets.token_bytes(64), secrets.token_bytes(32))
        state, _ = zk_status()
        assert state == _as_the_administrator_reads_it(admin)
        assert state["zero_knowledge_enabled"] is True and state["zk_vault_count"] >= 1

        # A file whose name was never sealed, as one from before sealing was required: stored in the clear.
        psql(f"UPDATE files SET enc_name = NULL, name = '{file_name}' WHERE id = '{fid}'")
        after, printed = zk_status()
        assert after["files_unsealed"] == state["files_unsealed"] + 1
        assert after["vaults_affected"] >= 1
        assert after == _as_the_administrator_reads_it(admin)
        for secret in (name, file_name, vault["id"], fid):
            assert secret not in printed, secret
        assert all(isinstance(v, (bool, int)) for v in after.values())
    finally:
        admin.delete_vault(vault["id"])


def test_it_needs_no_password_and_no_administrator(admin):
    base, _ = zk_status()
    assert zk_status(env=(("ADMIN_PASSWORD", "Not-The-Admin-Password-" + secrets.token_hex(8)),))[0] == base
    assert zk_status(env=(("ADMIN_USERNAME", "no-such-administrator"),))[0] == base
    assert zk_status(env=NO_CREDENTIALS)[0] == base

    # No account is an administrator: the action reads the database, not an administrator's session.
    admins = psql("SELECT id FROM users WHERE role = 'ADMIN'").split()
    assert admins
    try:
        psql("UPDATE users SET role = 'USER' WHERE role = 'ADMIN'")
        assert psql("SELECT count(*) FROM users WHERE role = 'ADMIN'") == "0"
        assert zk_status(env=NO_CREDENTIALS)[0] == base
    finally:
        psql("UPDATE users SET role = 'ADMIN' WHERE id IN (%s)" % ", ".join(f"'{i}'" for i in admins))
    assert psql("SELECT count(*) FROM users WHERE role = 'ADMIN'") == str(len(admins))
    assert admin.get("/zk/unsealed").status_code == 200


def test_it_changes_nothing_and_writes_no_audit_row(admin):
    def snapshot():
        return (psql("SELECT count(*) FROM audit_logs WHERE username = 'operator@host'"),
                psql("SELECT count(*) FROM audit_logs WHERE action ILIKE '%zk%'"),
                psql("SELECT md5(string_agg(id::text || coalesce(enc_name, '') || type || is_active::text, ',' "
                     "ORDER BY id)) FROM vaults"),
                psql("SELECT md5(coalesce(string_agg(id::text || coalesce(enc_name, ''), ',' ORDER BY id), '')) "
                     "FROM files"))

    before = snapshot()
    zk_status()
    zk_status(env=NO_CREDENTIALS)
    assert snapshot() == before
