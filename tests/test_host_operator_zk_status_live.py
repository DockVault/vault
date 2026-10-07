"""Live: the host command's zk-status action, run inside the web container the way a managing operator's
tooling runs it (docker exec <web container> python -m app.core.host_operator zk-status).

  * it answers what an administrator reads from GET /zk-enabled and GET /zk/unsealed, a name that was
    never sealed included, and nothing name-like;
  * it needs no password: the answer is the same whatever ADMIN_USERNAME and ADMIN_PASSWORD hold in its
    environment, with none at all, and when no account is an administrator;
  * it changes nothing and writes no audit row;
  * an administrators' force kept after the plan dropped zero-knowledge forces nothing: the server's own
    create check makes a standard vault, and the action says no one must use zero-knowledge.

test_host_operator_zk_status.py covers the answer's shape offline, and test_zk_force_follows_the_plan.py the
force against the plan.
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


# The server's own create check, asked inside the web container for someone in no department: what it answers
# a request to make each kind of vault. It decides before anything is written, so nothing is made.
CREATE_CHECK = """
import contextlib, json, sys, types, uuid
with contextlib.redirect_stdout(sys.stderr):
    import app.api.api_server as api
    from fastapi import HTTPException
    from app.core.database import get_db_context
    made = {}
    with get_db_context() as db:
        for kind in ("standard", "zero_knowledge"):
            try:
                made[kind] = api._resolve_vault_type_for_create(types.SimpleNamespace(id=uuid.UUID(int=0)), kind, db)
            except HTTPException as exc:
                made[kind] = exc.detail
        db.rollback()
print(json.dumps(made))
"""
REQUIRED = "This organization requires zero-knowledge vaults. Choose the Zero-knowledge type."
NOT_ENABLED = "Zero-knowledge vaults are not enabled on this deployment."
FORCE_KEYS = ("zero_knowledge_enabled", "force_zero_knowledge", "standard_vault_allowed_groups")


def _create_check(env=()):
    cmd = ["docker", "exec", "-i"]
    for name, value in env:
        cmd += ["-e", f"{name}={value}"]
    cmd += [API, "python", "-c", CREATE_CHECK]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, API)
    assert r.returncode == 0, (r.stdout[-800:], (r.stderr or "")[-800:])
    return json.loads(r.stdout.strip().splitlines()[-1])


def _saved_force():
    raw = psql("SELECT value::text FROM system_settings WHERE key = 'global'")
    saved = json.loads(raw) if raw else {}
    return {key: saved[key] for key in FORCE_KEYS if key in saved}


def test_a_force_kept_after_the_plan_dropped_zero_knowledge_refuses_no_standard_vault(admin):
    before = _saved_force()
    try:
        saved = admin.put("/settings", json={"zero_knowledge_enabled": True, "force_zero_knowledge": True,
                                             "standard_vault_allowed_groups": []})
        assert saved.status_code == 200, saved.text
        # As deployed, the plan includes zero-knowledge: the administrators' force holds.
        state, _ = zk_status()
        assert (state["zero_knowledge_enabled"], state["must_use_zk"]) == (True, True)
        assert _create_check() == {"standard": REQUIRED, "zero_knowledge": "zero_knowledge"}
        # A plan without zero-knowledge, the force still saved: standard vaults can be made, and the
        # host command says no one must use zero-knowledge.
        no_zk = (("PLAN_ZERO_KNOWLEDGE", "false"),)
        state, _ = zk_status(env=no_zk)
        assert (state["plan_zero_knowledge"], state["zero_knowledge_enabled"], state["must_use_zk"]) == (
            False, False, False)
        assert _create_check(env=no_zk) == {"standard": "standard", "zero_knowledge": NOT_ENABLED}
    finally:
        # The three switches as they were saved, an absent one removed rather than saved as its default.
        drop = "".join(f" - '{key}'" for key in FORCE_KEYS)
        keep = json.dumps(before).replace("'", "''")
        psql(f"UPDATE system_settings SET value = ((value::jsonb{drop}) || '{keep}'::jsonb)::json "
             "WHERE key = 'global'")
    assert _saved_force() == before


@pytest.mark.parametrize("setting, said", [
    # The database refuses the connection.
    ("DATABASE_URL=postgresql://sftp_user:{made_up}@127.0.0.1:1/sftp_db", "127.0.0.1"),
    # The web app's start-up refuses the configuration and exits.
    ("ENCRYPTION_KEY={made_up}", "encryption-key-invalid"),
])
def test_when_something_stops_it_it_still_prints_one_answer(setting, said):
    # The action cannot answer, and says so in the one JSON line the tooling reads, with exit status 1. What
    # happened is on standard error; the made-up value given to it is in neither stream.
    made_up = "Not-A-Real-Value-" + secrets.token_hex(8)
    cmd = ["docker", "exec", "-i", "-e", setting.format(made_up=made_up),
           API, "python", "-m", "app.core.host_operator", "zk-status"]
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=120)
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker unavailable: {exc}")
    skip_if_container_absent(r, API)
    lines = [ln for ln in r.stdout.splitlines() if ln.strip()]
    assert [json.loads(ln) for ln in lines] == [
        {"ok": False, "error": "The account tool stopped before it could answer."}], (r.stdout, r.stderr[-800:])
    assert r.returncode == 1
    assert "Traceback" in r.stderr and said in r.stderr, r.stderr[-800:]
    assert made_up not in r.stdout and made_up not in r.stderr
