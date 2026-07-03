"""Setup-wizard free-build tests (A6): onboarding completes with NO product key.

The former license/product-key step enforced nothing (offline JWT with a hardcoded
secret, imported only by the wizard) and confused self-hosters — A6 removed it
entirely: the ``/api/setup/license/validate`` endpoint, the ``LICENSE`` wizard step,
the wizard-page UI step, and the whole ``app/licensing`` package. These tests lock
the removal at the HTTP surface (live container) and at the state-machine level
(``app/setup/state.py`` loaded by path — it is stdlib-only, so no app imports leak
into the test process).

State files written by pre-A6 builds may still carry a "license" step; the state
readers must skip it instead of raising (a mid-setup self-hoster upgrading must not
get a 500 from /api/setup/state).
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
# HTTP surface (live container)
# ---------------------------------------------------------------------------
def test_license_validate_endpoint_removed(anon):
    """The product-key endpoint is gone — not rejecting, GONE (404)."""
    r = anon.post("/api/setup/license/validate",
                  json={"product_key": "DockVault-TRIAL-A1B2-C3D4-E5F6"})
    assert r.status_code == 404, f"license endpoint still routed: {r.status_code} {r.text[:200]}"


def test_wizard_state_has_no_license_step(anon):
    """A fresh instance's wizard state machine contains no license step at all."""
    r = anon.get("/api/setup/state")
    assert r.status_code == 200, r.text
    state = r.json()
    assert state["current_step"] != "license"
    assert "license" not in state["steps"], \
        f"license step still present in wizard state: {sorted(state['steps'])}"


def test_setup_page_is_keyless(anon):
    """The served /setup wizard page has no product-key/license step (the free build needs
    no key) and is brand-driven (shows the DockVault default via a data-brand-name hook)."""
    r = anon.get("/setup")
    assert r.status_code == 200, r.text
    html = r.text
    assert "product_key" not in html, "product-key input still present in the wizard page"
    assert "step-license" not in html, "license step markup still present in the wizard page"
    assert "validateLicense" not in html, "license-validation JS still present in the wizard page"
    assert "data-brand-name" in html, "wizard page is not brand-driven (missing data-brand-name)"


# ---------------------------------------------------------------------------
# A5 — wizard folds into the effective branding store
# ---------------------------------------------------------------------------
def test_wizard_welcome_uses_effective_branding(admin, anon):
    """The wizard welcome message reflects the EFFECTIVE branding (env + admin/DB
    override), not a hardcoded literal: an admin-set app_name shows in /welcome/info."""
    before = admin.get("/settings").json().get("app_name")
    try:
        assert admin.put("/settings", json={"app_name": "WizardBrandCo"}).status_code == 200
        info = anon.get("/api/setup/welcome/info").json()
        assert "WizardBrandCo" in info["welcome_message"], info["welcome_message"]
        assert "WizardBrandCo" in info["description"], info["description"]
    finally:
        admin.put("/settings", json={"app_name": before or ""})


def test_wizard_branding_save_gated_when_admin_exists(anon):
    """A5 security gate: the wizard's /branding/save is UNAUTHENTICATED, so once an admin
    exists it must NOT rebrand the live instance — effective /branding is unchanged after
    the call (the branding only lands in the inert state file). The first-run write path
    reuses the admin-editor-proven set_brand_overrides helper."""
    baseline = anon.get("/branding").json()["app_name"]
    r = anon.post("/api/setup/branding/save", json={
        "app_name": "AnonWizardShouldNotApply",
        "company_name": "Anon Co",
        "support_email": "a@example.com",
        "primary_color": "#111111",
        "secondary_color": "#222222",
    })
    assert r.status_code == 200, r.text
    after = anon.get("/branding").json()["app_name"]
    assert after == baseline, "an unauthenticated wizard call rebranded a live instance!"
    assert after != "AnonWizardShouldNotApply"


def test_wizard_branding_save_blocked_even_with_all_admins_deactivated(anon):
    """The gate keys on 'an admin has EVER existed' (role==ADMIN, IGNORING is_active), not
    the active-admin check — so deactivating every admin must NOT re-open the unauthenticated
    wizard live-write on a real post-setup instance (the review finding: is_setup_completed()
    is unreliable, so an is_active-only gate would collapse). Deactivate all admins, confirm
    /branding is unchanged, then reactivate them (the safe end state) no matter what."""
    baseline = anon.get("/branding").json()["app_name"]
    _psql("SELECT 1;")  # probe first: skips cleanly if docker/psql is unavailable
    try:
        _psql("UPDATE users SET is_active=false WHERE role='ADMIN';")
        r = anon.post("/api/setup/branding/save", json={
            "app_name": "DeactivatedAdminBypass",
            "company_name": "X Co",
            "support_email": "x@example.com",
            "primary_color": "#101010",
            "secondary_color": "#202020",
        })
        assert r.status_code == 200, r.text
        after = anon.get("/branding").json()["app_name"]
        assert after == baseline, "deactivated-admin bypass rebranded a live instance!"
        assert after != "DeactivatedAdminBypass"
    finally:
        # reactivate ALL admins unconditionally — the normal, safe end state for the stack —
        # and scrub any brand override a bypass write may have left, so a failing run (old
        # gate) can't pollute /branding for the rest of the suite.
        try:
            _psql("UPDATE users SET is_active=true WHERE role='ADMIN';")
        except Exception:  # noqa: BLE001 — teardown must never raise
            pass
        try:
            _psql("DELETE FROM system_settings WHERE key='brand';")
        except Exception:  # noqa: BLE001
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
