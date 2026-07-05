"""Operator-set, admin-irreversible allowed-vault-types policy (PLAN_ALLOWED_VAULT_TYPES).

The allowlist is a HARD outer gate at the vault-creation chokepoint: a type the
deployment's policy forbids is never creatable, whatever the local /settings toggles say,
and the customer's own admin has no lever to widen it. It is surfaced in /zk-enabled so
the UI can hide a forbidden option.

These tests run over HTTP against the live vault (conftest). The permissive-default and
surfacing checks run on any deployment; the forbid-path checks are conditional on the
deployment's own allowlist (green against a PLAN_ALLOWED_VAULT_TYPES-restricted instance,
skipped on an un-gated one), so the file is committable and non-vacuous either way.
"""
from pathlib import Path

from conftest import unique

RECOGNISED = {"standard", "zero_knowledge"}


def test_source_wires_the_allowlist_gate():
    """Default-CI safety net. The live forbid-path test above only fires on a
    PLAN_ALLOWED_VAULT_TYPES-restricted deployment, so on the everyday permissive :8200
    a *deletion* of the gate would otherwise slip through green. Lock the enforcement in
    source, tied to the creation chokepoint, so removing it fails on ANY deployment.
    (The vault suite runs on the host with the app source right beside it.)"""
    src = (Path(__file__).resolve().parent.parent / "api_server.py").read_text(encoding="utf-8")
    start = src.index("def _resolve_vault_type_for_create")
    body = src[start:src.index("\n@app.", start)]  # up to create_vault's decorator
    assert "_allowed_vault_types()" in body, "allowlist gate removed from the create chokepoint"
    assert "is not permitted on this deployment" in body, "forbid-path rejection removed"
    # /zk-enabled must keep surfacing the allowlist so the UI can hide a forbidden option.
    assert '"allowed_vault_types"' in src, "/zk-enabled no longer surfaces allowed_vault_types"


def _zk_enabled(admin) -> dict:
    r = admin.get("/zk-enabled")
    assert r.status_code == 200, r.text
    return r.json()


def test_allowed_vault_types_surfaced(admin):
    """/zk-enabled reports the allowlist as a sorted, non-empty subset of the
    recognised types (never empty — a mis-set env degrades to permissive)."""
    body = _zk_enabled(admin)
    allowed = body.get("allowed_vault_types")
    assert isinstance(allowed, list) and allowed, f"missing/empty allowed_vault_types: {body}"
    assert set(allowed) <= RECOGNISED, allowed
    assert allowed == sorted(allowed)
    # If ZK isn't in the allowlist, the effective creatable ZK state must be off too.
    if "zero_knowledge" not in allowed:
        assert body["zero_knowledge_enabled"] is False, body


def test_permitted_standard_create_works(admin):
    """Whatever the allowlist, if 'standard' is permitted a standard create succeeds
    (the default deployment permits it — a regression guard on the added gate)."""
    allowed = set(_zk_enabled(admin).get("allowed_vault_types") or [])
    if "standard" not in allowed:
        import pytest
        pytest.skip("this deployment forbids standard vaults (ZK-only)")
    r = admin.post("/vaults", json={"name": unique("v"), "type": "standard"})
    assert r.status_code == 200, r.text
    assert r.json()["type"] == "standard"
    admin.delete_vault(r.json()["id"])


def test_forbidden_type_rejected_with_policy_error(admin):
    """A type the deployment's allowlist forbids -> 400 with the policy message, and
    nothing is created. Exercises whichever direction THIS deployment restricts;
    skips on an un-gated (permissive) deployment."""
    import pytest
    allowed = set(_zk_enabled(admin).get("allowed_vault_types") or [])
    forbidden = RECOGNISED - allowed
    if not forbidden:
        pytest.skip("deployment permits all vault types; run against a "
                    "PLAN_ALLOWED_VAULT_TYPES-restricted instance to exercise the forbid path")
    ftype = sorted(forbidden)[0]
    before = {v["id"] for v in admin.get("/vaults").json()}
    r = admin.post("/vaults", json={"name": unique("v"), "type": ftype})
    assert r.status_code == 400, r.text
    assert "not permitted" in r.text.lower(), r.text
    # The policy gate fires ahead of any keypair/cap check -> truly nothing created.
    after = {v["id"] for v in admin.get("/vaults").json()}
    assert after == before, "a forbidden-type create must not persist a vault"
