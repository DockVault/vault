"""Authorization and state-transition coverage for operation cancellation."""

import json
import os
import subprocess

import requests

from conftest import ApiClient, unique


_REDIS_CONTAINER = os.environ.get("VAULT_REDIS_CONTAINER", "vault-redis")
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")


def _redis(*args):
    result = subprocess.run(
        ["docker", "exec", _REDIS_CONTAINER, "redis-cli", *args],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _db(sql):
    result = subprocess.run(
        [
            "docker", "exec", _DB_CONTAINER,
            "psql", "-U", "sftp_user", "-d", "sftp_db", "-tAc", sql,
        ],
        capture_output=True,
        text=True,
        timeout=20,
    )
    assert result.returncode == 0, result.stderr
    return result.stdout.strip()


def _api_python(source):
    result = subprocess.run(
        ["docker", "exec", _API_CONTAINER, "python", "-c", source],
        capture_output=True,
        text=True,
        timeout=60,
    )
    assert result.returncode == 0, result.stderr or result.stdout
    return result.stdout.strip()

def _operation_id(label):
    return unique(label).replace("_", "-")


def _seed(
    operation_id,
    owner_id,
    *,
    status="in_progress",
    cancelled=False,
    temp_credential_id=None,
    vault_id=None,
):
    operation = {
        "operation_id": operation_id,
        "user_id": str(owner_id),
        "username": "test-owner",
        "temp_credential_id": temp_credential_id,
        "vault_id": vault_id,
        "type": "upload",
        "file_name": "opaque-test-file",
        "total_size": 1024,
        "transferred": 128,
        "progress_pct": 12.5,
        "cancelled": cancelled,
        "status": status,
    }
    _redis(
        "SETEX",
        f"operation:{operation_id}",
        "300",
        json.dumps(operation, separators=(",", ":")),
    )
    return operation


def _read(operation_id):
    raw = _redis("GET", f"operation:{operation_id}")
    return json.loads(raw) if raw else None


def _delete(operation_id):
    _redis("DEL", f"operation:{operation_id}")


def test_unauthenticated_caller_cannot_cancel_or_observe_active_operation(temp_user):
    operation_id = _operation_id("cancel-anon")
    _seed(operation_id, temp_user["id"])
    try:
        response = ApiClient().post(f"/api/operations/{operation_id}/cancel")
        assert response.status_code in (401, 403)
        assert _read(operation_id)["status"] == "in_progress"
    finally:
        _delete(operation_id)


def test_owner_cancellation_is_observable(temp_user, temp_user_client):
    operation_id = _operation_id("cancel-owner")
    _seed(operation_id, temp_user["id"])
    try:
        response = temp_user_client.post(f"/api/operations/{operation_id}/cancel")
        assert response.status_code == 200, response.text
        stored = _read(operation_id)
        assert stored["cancelled"] is True
        assert stored["status"] == "cancelled"
    finally:
        _delete(operation_id)


def test_other_user_gets_same_nonenumerating_denial_as_unknown(admin, temp_user):
    other = admin.create_user(role="user")
    other_client = ApiClient()
    operation_id = _operation_id("cancel-other")
    unknown_id = _operation_id("cancel-unknown")
    _seed(operation_id, temp_user["id"])
    try:
        other_client.login(other["_username"], other["_password"])
        denied = other_client.post(f"/api/operations/{operation_id}/cancel")
        unknown = other_client.post(f"/api/operations/{unknown_id}/cancel")
        assert denied.status_code == unknown.status_code == 404
        assert _read(operation_id)["status"] == "in_progress"
    finally:
        _delete(operation_id)
        admin.delete_user(other["id"])


def test_interactive_admin_can_cancel_another_users_operation(admin, temp_user):
    operation_id = _operation_id("cancel-admin")
    _seed(operation_id, temp_user["id"])
    try:
        response = admin.post(f"/api/operations/{operation_id}/cancel")
        assert response.status_code == 200, response.text
        assert _read(operation_id)["status"] == "cancelled"
    finally:
        _delete(operation_id)


def test_temp_admin_does_not_inherit_admin_override(admin, temp_user):
    created = admin.post(
        "/auth/temp-credentials",
        json={"note": unique("cancel-temp-admin")},
    )
    assert created.status_code == 200, created.text
    credential = created.json()
    temp_admin = ApiClient()
    operation_id = _operation_id("cancel-temp-admin")
    _seed(operation_id, temp_user["id"])
    try:
        temp_admin.login(credential["temp_username"], credential["credential"])
        response = temp_admin.post(f"/api/operations/{operation_id}/cancel")
        assert response.status_code == 404
        assert _read(operation_id)["status"] == "in_progress"
    finally:
        _delete(operation_id)
        admin.post(f"/temp-creds/{credential['temp_username']}/delete")


def test_completed_and_already_cancelled_operations_cannot_transition(temp_user, temp_user_client):
    completed_id = _operation_id("cancel-completed")
    cancelled_id = _operation_id("cancel-finished")
    _seed(completed_id, temp_user["id"], status="completed")
    _seed(cancelled_id, temp_user["id"], status="cancelled", cancelled=True)
    try:
        assert temp_user_client.post(
            f"/api/operations/{completed_id}/cancel"
        ).status_code == 404
        assert temp_user_client.post(
            f"/api/operations/{cancelled_id}/cancel"
        ).status_code == 404
        assert _read(completed_id)["status"] == "completed"
        assert _read(completed_id)["cancelled"] is False
        assert _read(cancelled_id)["status"] == "cancelled"
    finally:
        _delete(completed_id)
        _delete(cancelled_id)


def test_temp_operation_requires_exact_originating_credential(temp_user, temp_user_client):
    vault = temp_user_client.create_vault(name=unique("cancel-scope"))
    payload = {
        "note": unique("cancel-principal"),
        "scope": {
            "pages": ["vaults"],
            "caps": [],
            "temp": {},
        },
        "vault_access_mode": "selected",
        "selected_vaults": [{
            "vault_id": vault["id"],
            "caps": ["vault.see_info", "file.download"],
        }],
    }
    first = temp_user_client.post("/auth/temp-credentials", json=payload)
    second = temp_user_client.post("/auth/temp-credentials", json=payload)
    assert first.status_code == second.status_code == 200
    first_credential = first.json()
    second_credential = second.json()
    first_id = _db(
        "SELECT id FROM temporary_credentials WHERE temp_username="
        f"'{first_credential['temp_username']}'"
    )
    operation_id = _operation_id("cancel-principal")
    _seed(
        operation_id,
        temp_user["id"],
        temp_credential_id=first_id,
        vault_id=vault["id"],
    )
    matching_client = ApiClient()
    sibling_client = ApiClient()
    try:
        matching_client.login(
            first_credential["temp_username"], first_credential["credential"]
        )
        sibling_client.login(
            second_credential["temp_username"], second_credential["credential"]
        )

        # The base account and a sibling credential share user_id, but neither is
        # the exact scoped principal that created this operation.
        assert temp_user_client.post(
            f"/api/operations/{operation_id}/cancel"
        ).status_code == 404
        assert sibling_client.post(
            f"/api/operations/{operation_id}/cancel"
        ).status_code == 404
        assert _read(operation_id)["status"] == "in_progress"

        assert matching_client.post(
            f"/api/operations/{operation_id}/cancel"
        ).status_code == 200
        assert _read(operation_id)["status"] == "cancelled"
    finally:
        _delete(operation_id)
        temp_user_client.post(
            f"/temp-creds/{first_credential['temp_username']}/delete"
        )
        temp_user_client.post(
            f"/temp-creds/{second_credential['temp_username']}/delete"
        )
        temp_user_client.delete_vault(vault["id"])


def test_cancel_and_complete_have_one_atomic_terminal_winner():
    result = _api_python(
        r'''
import json
import threading
import uuid

from app.services.activity_monitor import ProgressTracker

tracker = ProgressTracker()
events = []
tracker.broadcaster.broadcast_sync = events.append
for _ in range(100):
    operation_id = "race_" + str(uuid.uuid4())
    tracker.start_operation(
        operation_id=operation_id,
        user_id="owner",
        username="owner",
        operation_type="upload",
        file_name="opaque",
        total_size=1,
    )
    events.clear()
    barrier = threading.Barrier(3)
    results = {}

    def cancel():
        barrier.wait()
        results["cancel"] = tracker.cancel_operation(
            operation_id, requester_id="owner"
        )

    def complete():
        barrier.wait()
        results["complete"] = tracker.complete_operation(operation_id) is not None

    first = threading.Thread(target=cancel)
    second = threading.Thread(target=complete)
    first.start()
    second.start()
    barrier.wait()
    first.join()
    second.join()

    assert int(results["cancel"]) + int(results["complete"]) == 1
    terminal = [
        event for event in events
        if event.get("type") in {"operation_cancelled", "operation_complete"}
    ]
    assert len(terminal) == 1
    raw = tracker.redis.get(tracker._get_operation_key(operation_id))
    if results["cancel"]:
        assert raw is not None
        assert json.loads(raw)["status"] == "cancelled"
    else:
        assert raw is None
print("ok")
'''
    )
    assert result.endswith("ok")


def test_live_download_worker_observes_cancellation(temp_user, temp_user_client):
    vault = temp_user_client.create_vault(name=unique("cancel-download"))
    content = b"x" * (24 * 1024 * 1024)
    upload = temp_user_client.post(
        f"/vaults/{vault['id']}/files",
        files=[("files", ("large.bin", content, "application/octet-stream"))],
    )
    assert upload.status_code == 200, upload.text
    file_id = upload.json()["files"][0]["id"]

    stream_client = ApiClient()
    stream_client.login(temp_user["_username"], temp_user["_password"])
    response = None
    operation_id = None
    received = 0
    try:
        response = stream_client.session.get(
            stream_client._url(f"/vaults/{vault['id']}/files/{file_id}/download"),
            stream=True,
            timeout=(10, 30),
        )
        assert response.status_code == 200, response.text
        operation_id = response.headers.get("X-Operation-ID")
        assert operation_id and operation_id.startswith("download_")

        cancelled = temp_user_client.post(
            f"/api/operations/{operation_id}/cancel"
        )
        assert cancelled.status_code == 200, cancelled.text

        try:
            for chunk in response.iter_content(65536):
                received += len(chunk)
        except (requests.exceptions.ChunkedEncodingError, requests.exceptions.ConnectionError):
            pass

        assert received < len(content), (
            "the response delivered the complete file after cancellation; "
            "the worker did not abort"
        )
        stored = _read(operation_id)
        assert stored and stored["status"] == "cancelled"
        assert stored["vault_id"] == vault["id"]
    finally:
        if response is not None:
            response.close()
        if operation_id:
            _delete(operation_id)
        temp_user_client.delete_vault(vault["id"])
