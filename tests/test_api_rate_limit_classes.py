"""Live general-API rate-limit classes, Settings overrides, and authorization."""

import os
import subprocess
import time
import uuid
from concurrent.futures import ThreadPoolExecutor

import pytest
import requests

from conftest import ApiClient


pytestmark = pytest.mark.integration

RATE_KEYS = (
    "rate_limit_api_default",
    "rate_limit_api_default_window",
    "rate_limit_api_auth",
    "rate_limit_api_auth_window",
    "rate_limit_api_upload",
    "rate_limit_api_upload_window",
    "rate_limit_api_download",
    "rate_limit_api_download_window",
)


def _login(user):
    client = ApiClient()
    client.login(user["_username"], user["_password"])
    return client


def _assert_budget(client, method, path, expected_before_429):
    responses = [getattr(client, method)(path) for _ in range(expected_before_429 + 1)]
    for response in responses[:-1]:
        assert response.status_code != 429, (path, [r.status_code for r in responses])
        assert response.headers["X-RateLimit-Limit"] == str(expected_before_429)
        assert int(response.headers["X-RateLimit-Remaining"]) >= 0
        assert int(response.headers["X-RateLimit-Reset"]) > int(time.time())
    denied = responses[-1]
    assert denied.status_code == 429, (path, [r.status_code for r in responses])
    assert denied.headers["X-RateLimit-Limit"] == str(expected_before_429)
    assert denied.headers["X-RateLimit-Remaining"] == "0"
    # Fractional Redis scores round up so the client never retries before the
    # oldest request really leaves a 60-second window.
    assert 1 <= int(denied.headers["Retry-After"]) <= 61


def test_live_class_budgets_are_independent_and_update_without_restart(admin):
    before = admin.get("/settings").json()
    restore = {key: before.get(key, 0) for key in RATE_KEYS}
    editor_user = admin.create_user(role="admin")
    traffic_user = admin.create_user(role="user")
    editor = _login(editor_user)
    traffic = _login(traffic_user)
    fake_vault = str(uuid.uuid4())
    fake_file = str(uuid.uuid4())
    overrides = {key: (60 if key.endswith("_window") else 2) for key in RATE_KEYS}
    deployment_defaults = before["rate_limit_api_deployment_defaults"]
    try:
        updated = editor.put("/settings", json=overrides)
        assert updated.status_code == 200, updated.text

        # One authenticated principal, four independent class prefixes. Endpoint-level
        # 404/422 responses still consume a request because abuse is bounded before routing.
        _assert_budget(traffic, "get", "/users/me", 2)
        _assert_budget(traffic, "get", "/auth/session", 2)
        _assert_budget(traffic, "post", f"/vaults/{fake_vault}/uploads", 2)
        _assert_budget(
            traffic,
            "get",
            f"/vaults/{fake_vault}/files/{fake_file}/download",
            2,
        )

        # Zero is a live reset to the deployment contract, not a literal zero-request
        # budget. The editor's second low-budget request applies the reset immediately.
        reset = editor.put("/settings", json={key: 0 for key in RATE_KEYS})
        assert reset.status_code == 200, reset.text
        fallback = traffic.get("/users/me")
        assert fallback.status_code != 429, fallback.text
        assert (
            fallback.headers["X-RateLimit-Limit"]
            == str(deployment_defaults["rate_limit_api_default"])
        )
    finally:
        # The fresh editor has made exactly one default-class request under the low
        # policy, so this second request remains inside the limit and restores the suite.
        restored = editor.put("/settings", json=restore)
        assert restored.status_code == 200, restored.text
        admin.delete_user(traffic_user["id"])
        admin.delete_user(editor_user["id"])


def test_rate_limit_settings_validate_bounds_and_are_audited(admin):
    before = admin.get("/settings").json()
    restore = {key: before.get(key, 0) for key in RATE_KEYS}
    try:
        for key in RATE_KEYS:
            assert admin.put("/settings", json={key: -1}).status_code == 400
            assert admin.put("/settings", json={key: True}).status_code == 400
            assert admin.put("/settings", json={key: "5"}).status_code == 400
        assert admin.put(
            "/settings", json={"rate_limit_api_default": 1_000_001}
        ).status_code == 400
        assert admin.put(
            "/settings", json={"rate_limit_api_default_window": 86_401}
        ).status_code == 400
        assert admin.put(
            "/settings", json={"rate_limit_api_enabled": False}
        ).status_code == 400

        payload = {key: 0 for key in RATE_KEYS}
        assert admin.put("/settings", json=payload).status_code == 200
        settings = admin.get("/settings").json()
        assert all(settings[key] == 0 for key in RATE_KEYS)
        assert isinstance(settings["rate_limit_api_enabled"], bool)
        defaults = settings["rate_limit_api_deployment_defaults"]
        assert set(defaults) == set(RATE_KEYS)
        assert all(isinstance(defaults[key], int) and defaults[key] > 0 for key in RATE_KEYS)

        rows = admin.get(
            "/audit/log", params={"action": "settings_updated", "limit": 20}
        ).json()
        assert any(
            set(RATE_KEYS).issubset(set((row.get("details") or {}).get("keys") or []))
            for row in rows
        )
    finally:
        assert admin.put("/settings", json=restore).status_code == 200


def test_concurrent_requests_cannot_overshoot_the_budget(admin):
    before = admin.get("/settings").json()
    restore = {
        "rate_limit_api_default": before.get("rate_limit_api_default", 0),
        "rate_limit_api_default_window": before.get("rate_limit_api_default_window", 0),
    }
    editor_user = admin.create_user(role="admin")
    traffic_user = admin.create_user(role="user")
    editor = _login(editor_user)
    traffic = _login(traffic_user)
    workers = [ApiClient() for _ in range(20)]
    for worker in workers:
        worker.session.headers["Authorization"] = f"Bearer {traffic.token}"

    try:
        updated = editor.put(
            "/settings",
            json={"rate_limit_api_default": 2, "rate_limit_api_default_window": 60},
        )
        assert updated.status_code == 200, updated.text
        with ThreadPoolExecutor(max_workers=len(workers)) as pool:
            responses = list(pool.map(lambda client: client.get("/users/me"), workers))

        allowed = [response for response in responses if response.status_code != 429]
        denied = [response for response in responses if response.status_code == 429]
        assert len(allowed) == 2, [response.status_code for response in responses]
        assert len(denied) == 18
        assert all(response.headers["X-RateLimit-Limit"] == "2" for response in responses)
    finally:
        assert editor.put("/settings", json=restore).status_code == 200
        admin.delete_user(traffic_user["id"])
        admin.delete_user(editor_user["id"])


def test_rate_limit_settings_require_interactive_admin(admin, temp_user_client):
    assert temp_user_client.put(
        "/settings", json={"rate_limit_api_default": 3}
    ).status_code == 403

    minted = admin.post(
        "/auth/temp-credentials", json={"validity_minutes": 30}
    ).json()
    temporary_admin = ApiClient()
    temporary_admin.login(minted["temp_username"], minted["credential"])
    assert temporary_admin.put(
        "/settings", json={"rate_limit_api_default": 3}
    ).status_code == 403


@pytest.mark.skipif(
    os.environ.get("VAULT_REDIS_OUTAGE_TEST") not in ("1", "true", "yes"),
    reason="opt-in: pauses the disposable Redis container to prove general API fail-open",
)
def test_general_api_classes_fail_open_during_redis_outage(base_url, temp_user_client):
    container = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")

    def docker(*args):
        return subprocess.run(["docker", *args], capture_output=True, text=True)

    try:
        paused = docker("pause", container)
        assert paused.returncode == 0, paused.stderr
        time.sleep(2)
        first = temp_user_client.get("/users/me")
        second = temp_user_client.get("/users/me")
        assert first.status_code == 200, first.text
        assert second.status_code == 200, second.text
    finally:
        docker("unpause", container)
        for _ in range(30):
            try:
                health = requests.get(f"{base_url}/health", timeout=5).json()
                if health.get("redis") == "connected":
                    break
            except Exception:
                pass
            time.sleep(1)
