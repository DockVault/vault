"""Offline contracts for the reusable preflight and setup lifecycle workflows."""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest


pytestmark = pytest.mark.unit

_ROOT = Path(__file__).parents[1]
_WORKFLOWS = _ROOT / ".github" / "workflows"
_SETUP = (_WORKFLOWS / "setup-matrix.yml").read_text(encoding="utf-8")
_TESTS = (_WORKFLOWS / "tests.yml").read_text(encoding="utf-8")
_PREFLIGHT = (_WORKFLOWS / "preflight.yml").read_text(encoding="utf-8")
_MASK_SCRIPT = _ROOT / ".github" / "scripts" / "mask_env_secrets.py"
_SPEC = importlib.util.spec_from_file_location("mask_env_secrets", _MASK_SCRIPT)
assert _SPEC and _SPEC.loader
_MASK = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MASK)


def _step(name: str, next_name: str) -> str:
    return _SETUP.split(f"- name: {name}", 1)[1].split(f"- name: {next_name}", 1)[0]


def test_every_pull_request_and_reusable_call_use_the_same_preflight():
    triggers = _SETUP.split("on:", 1)[1].split("permissions:", 1)[0]
    scenario_job = _SETUP.split("  scenarios:", 1)[1]

    assert "pull_request:" in triggers
    assert "paths:" not in triggers
    assert "workflow_call:" in triggers
    assert "uses: ./.github/workflows/preflight.yml" in _SETUP
    assert "needs: preflight" in scenario_job
    assert "uses: ./.github/workflows/preflight.yml" in _TESTS
    assert "workflow_call:" in _PREFLIGHT
    assert "--collect-only -q" in _PREFLIGHT
    assert '-m "unit and not docker" --maxfail=1' in _PREFLIGHT
    assert "docker compose" not in _PREFLIGHT


def test_original_scenarios_a_through_h_remain_present():
    for name in (
        "Scenario A — first install",
        "Scenario B — re-run over existing data keeps it",
        "Scenario C — the coupling stamp makes the next run instant",
        "Scenario D — backup, destroy, restore",
        "Scenario E — a mismatched .env must be refused, not started",
        "Scenario F — split deployment",
        "Scenario G — --no-start authors config without deploying",
        "Scenario H — a refused re-run must leave a RUNNING deployment running",
    ):
        assert _SETUP.count(name) == 1


def test_profile_transitions_preserve_state_volumes_sftp_and_inventory():
    to_split = _step(
        "Profile transition — combined to split preserves deployment",
        "Profile transition — split to combined preserves deployment",
    )
    to_combined = _step(
        "Profile transition — split to combined preserves deployment",
        "New volume set and paired-env repoint round trip",
    )

    assert "COMPOSE_PROFILES=split" in to_split
    assert "state-planted.json" in to_split
    assert "volumes-before-profile-transition" in to_split
    assert " down " not in to_split
    assert "vault-api vault-db vault-redis vault-sftp" in to_split
    assert "SSH-*" in to_split
    assert "COMPOSE_PROFILES=combined" in to_combined
    assert "state-planted.json" in to_combined
    assert "volumes-before-profile-transition" in to_combined
    assert " down " not in to_combined
    assert "vault vault-db vault-redis" in to_combined
    assert "SSH-*" in to_combined
    assert "down -v" not in to_split + to_combined


def test_new_volume_set_round_trip_keeps_both_sets_and_recovers_original():
    volume_round_trip = _step(
        "New volume set and paired-env repoint round trip",
        "Scenario F — split deployment",
    )

    assert "volumes --non-interactive --action new" in volume_round_trip
    assert "state['vault_ids']" in volume_round_trip
    assert "--action repoint" in volume_round_trip
    assert '--env-source ".env.${original_prefix}"' in volume_round_trip
    assert "state-planted.json" in volume_round_trip
    assert volume_round_trip.count("docker volume inspect") == 2
    assert "docker volume rm" not in volume_round_trip


def test_throwaway_secrets_are_generated_masked_and_checkout_is_read_only():
    assert "Dv-Matrix-" not in _SETUP
    assert 'ADMIN_PASS="$(openssl rand -base64 24)"' in _SETUP
    assert 'echo "::add-mask::${ADMIN_PASS}"' in _SETUP
    assert 'echo "::add-mask::${token}"' in _SETUP
    assert _SETUP.count("mask_env_secrets.py .env") >= 6
    assert "permissions:\n  contents: read" in _SETUP
    assert "persist-credentials: false" in _SETUP
    assert "actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1" in _SETUP


def test_failure_diagnostics_and_destructive_teardown_are_retained():
    assert "if: failure()" in _SETUP
    teardown = _SETUP.split("- name: Tear down", 1)[1]
    assert "if: always()" in teardown
    assert "dockvault.py reset --non-interactive --confirm" in teardown
    assert "down -v --remove-orphans" in teardown
    assert "label=com.dockvault.managed=true" in teardown


def test_mask_helper_emits_only_escaped_secret_workflow_commands(tmp_path):
    env_file = tmp_path / ".env"
    env_file.write_text(
        "PUBLIC=value\n"
        "ENCRYPTION_KEY='abc%def'\n"
        "VAULT_DB_PASSWORD=database-secret\n"
        "ADMIN_PASSWORD=''\n",
        encoding="utf-8",
    )

    assert _MASK.mask_commands(env_file) == [
        "::add-mask::abc%25def",
        "::add-mask::database-secret",
    ]
