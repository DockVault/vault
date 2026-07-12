"""Zero-knowledge is auto-enabled for an entitled tenant (no undiscoverable admin toggle).

When the deployment's plan grants zero-knowledge, ZK creation is available by default; the local
'zero_knowledge_enabled' setting acts only as an explicit admin OFF override. GET /settings reports
the EFFECTIVE state so a settings save can't silently clobber the auto-enable, and /zk-enabled
distinguishes 'not on your plan' from 'turned off by the admin'.
"""
import os
import subprocess

import pytest

from conftest import create_zk_vault


def _db_mutate(sql: str):
    """Run a mutating SQL statement against the vault DB via docker exec. Skips when
    docker/psql is unavailable. Mirrors test_zk_dek_rotation._db_mutate."""
    container = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
    try:
        proc = subprocess.run(
            ["docker", "exec", container, "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


def test_zk_auto_enabled_when_plan_grants(admin):
    """With the plan granting ZK and NO explicit local override, ZK is auto-enabled: an
    entitled tenant creates a ZK vault without ever flipping the admin toggle."""
    original = admin.get("/settings").json().get("zero_knowledge_enabled")
    # Simulate a fresh entitled tenant: drop the explicit override so none is stored.
    _db_mutate(
        "UPDATE system_settings SET value = (value::jsonb - 'zero_knowledge_enabled')::json "
        "WHERE key='global';"
    )
    try:
        z = admin.get("/zk-enabled").json()
        assert z["plan_zero_knowledge"] is True         # the plan grants ZK
        assert z["zero_knowledge_enabled"] is True       # ... so it's auto-enabled, no toggle
        # GET /settings reports the effective value (so a save won't clobber it).
        assert admin.get("/settings").json().get("zero_knowledge_enabled") is True
        # And a ZK vault can actually be created without touching /settings.
        v = create_zk_vault(admin)
        admin.delete_vault(v["id"])
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": bool(original)})


def test_zk_off_states_are_distinguishable(admin):
    """An explicit admin OFF is honored and distinguishable (via /zk-enabled) from a plan that
    doesn't grant ZK at all — the two 'ZK unavailable' reasons the UI must tell apart."""
    original = admin.get("/settings").json().get("zero_knowledge_enabled")
    try:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
        z = admin.get("/zk-enabled").json()
        assert z["plan_zero_knowledge"] is True          # the plan DOES grant it...
        assert z["zero_knowledge_enabled"] is False       # ...but the admin turned it off
        # The effective value is reflected in /settings too.
        assert admin.get("/settings").json().get("zero_knowledge_enabled") is False
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": bool(original)})


def test_zk_enabled_reports_plan_force(admin):
    """/zk-enabled surfaces whether the PLAN itself mandates zero-knowledge (distinct from
    the local force_zero_knowledge toggle), so the Settings page can show a plan-imposed
    requirement instead of an unchecked, contradictory-looking box."""
    z = admin.get("/zk-enabled").json()
    assert "plan_force_zero_knowledge" in z
    assert isinstance(z["plan_force_zero_knowledge"], bool)
    # It's an AND of plan-force and plan-grants-ZK: a plan can't force what it doesn't grant.
    if z["plan_force_zero_knowledge"]:
        assert z["plan_zero_knowledge"] is True
