"""Setup-wizard tests.

The whole /setup surface is UNAUTHENTICATED (it must run before any admin exists), so it is
GATED to first-run: once an admin user exists — every production deploy seeds one via
setup-secure.sh / the SaaS portal — the wizard page and all /api/setup* endpoints return
404, so a live instance can't be reconfigured through it. These tests lock that gate at the
HTTP surface (the live container has a seeded admin) and cover the state machine
(``app/setup/state.py``, stdlib-only, loaded by path — no app imports leak into the test).

The free build also has NO license/product-key step (A6 removed it entirely); a pre-A6
state file carrying a "license" step must still load without raising.
"""
import importlib.util
import json
import os
import subprocess
from pathlib import Path

import pytest

APP_DIR = Path(__file__).resolve().parent.parent
DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")


def _psql(sql: str) -> str:
    """Run SQL in the vault DB container; skip the test cleanly if docker/psql is absent."""
    try:
        proc = subprocess.run(
            ["docker", "exec", DB_CONTAINER, "psql", "-U", "sftp_user", "-d", "sftp_db",
             "-v", "ON_ERROR_STOP=1", "-tAc", sql],
            capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=30,
        )
    except (FileNotFoundError, subprocess.TimeoutExpired) as exc:
        pytest.skip(f"docker/psql unavailable: {exc}")
    assert proc.returncode == 0, f"psql failed: {proc.stderr}"
    return proc.stdout.strip()


# ---------------------------------------------------------------------------
# Setup-surface first-run gate (live container — it has a seeded admin, i.e. "set up")
# ---------------------------------------------------------------------------
# The whole /setup surface is UNAUTHENTICATED, so once an admin exists it must be 404: a
# live production instance can't be reconfigured through the wizard. Every deploy seeds an
# admin (setup-secure.sh / the SaaS portal), so the wizard is unreachable in production. The
# live test container has an admin, so the entire surface must be 404 here.
def test_setup_surface_gated_when_admin_exists(anon):
    """SECURITY: on a set-up instance (an admin exists) the ENTIRE setup surface is 404 —
    the wizard page, the read endpoints, AND the config-writing endpoints (so the removed
    license endpoint and any wizard save are all unreachable)."""
    for path in ("/setup", "/api/setup/welcome/info", "/api/setup/state"):
        assert anon.get(path).status_code == 404, f"{path} reachable on a set-up instance"
    assert anon.post("/api/setup/license/validate",
                     json={"product_key": "x" * 12}).status_code == 404
    assert anon.post("/api/setup/branding/save", json={
        "app_name": "AnonWizardShouldNotApply", "company_name": "Anon Co",
        "primary_color": "#111111", "secondary_color": "#222222"}).status_code == 404
    # the public effective-branding read is NOT part of the setup surface and stays open
    assert anon.get("/branding").status_code == 200
    assert anon.get("/branding").json()["app_name"] != "AnonWizardShouldNotApply"


def test_setup_surface_gated_even_with_all_admins_deactivated(anon):
    """The gate keys on 'an admin has EVER existed' (role==ADMIN, IGNORING is_active), so
    deactivating every admin does NOT re-open the setup surface on a set-up instance (an
    is_active-only gate would collapse). Deactivate all admins, confirm the surface is still
    404, then reactivate them (the safe end state) no matter what."""
    _psql("SELECT 1;")  # probe first: skips cleanly if docker/psql is unavailable
    try:
        _psql("UPDATE users SET is_active=false WHERE role='ADMIN';")
        assert anon.get("/setup").status_code == 404
        assert anon.get("/api/setup/welcome/info").status_code == 404
        assert anon.post("/api/setup/branding/save", json={
            "app_name": "DeactivatedBypass", "company_name": "X",
            "primary_color": "#101010", "secondary_color": "#202020"}).status_code == 404
    finally:
        # reactivate ALL admins unconditionally — the normal, safe end state for the stack.
        try:
            _psql("UPDATE users SET is_active=true WHERE role='ADMIN';")
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass


# ---------------------------------------------------------------------------
# State machine (unit — app/setup/state.py is stdlib-only, loaded by path)
# ---------------------------------------------------------------------------
@pytest.fixture()
def state_module(tmp_path, monkeypatch):
    """Load app/setup/state.py by path with its module-import side effect (the global
    wizard_state instance creates its state file) pointed at a throwaway temp path."""
    monkeypatch.setenv("SETUP_STATE_FILE", str(tmp_path / "module_state.json"))
    spec = importlib.util.spec_from_file_location(
        "vault_setup_state_under_test", APP_DIR / "app" / "setup" / "state.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def test_wizard_flow_skips_straight_to_database(state_module, tmp_path):
    """No LICENSE member exists; completing WELCOME makes DATABASE the next required
    step — the wizard flow literally cannot ask for a key."""
    WizardStep = state_module.WizardStep
    assert not hasattr(WizardStep, "LICENSE")
    assert "license" not in {m.value for m in WizardStep}

    st = state_module.SetupWizardState(state_file=str(tmp_path / "fresh.json"))
    assert st.get_current_step() is WizardStep.WELCOME
    st.mark_step_completed(WizardStep.WELCOME)
    assert st.get_next_required_step() is WizardStep.DATABASE


def test_old_state_file_with_license_step_is_tolerated(state_module, tmp_path):
    """A state file written by a pre-A6 build (current_step 'license', 'license' in
    completed_steps) loads without raising: current step falls back to WELCOME and the
    unknown step name is skipped from the completed list."""
    WizardStep = state_module.WizardStep
    old_file = tmp_path / "old.json"
    old_file.write_text(json.dumps({
        "version": "1.0",
        "created_at": "2026-01-01T00:00:00+00:00",
        "updated_at": "2026-01-01T00:00:00+00:00",
        "current_step": "license",
        "completed_steps": ["welcome", "license"],
        "steps": {
            name: {"status": "not_started", "data": {}, "validation_errors": [],
                   "last_updated": None, "attempt_count": 0}
            for name in ["welcome", "license", "database", "redis", "security",
                         "admin", "storage", "branding", "review", "complete"]
        },
        "errors": [],
        "warnings": [],
        "metadata": {},
    }), encoding="utf-8")

    st = state_module.SetupWizardState(state_file=str(old_file))
    assert st.get_current_step() is WizardStep.WELCOME          # unknown step -> restart
    assert st.get_completed_steps() == [WizardStep.WELCOME]     # 'license' skipped
