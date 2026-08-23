"""Live-monitor activity events carry vault + actor enrichment.

The upload/download broadcasts used to say only WHO acted, from which IP, on which file. An operator
watching the Live Monitor could not tell WHICH vault an event touched, nor whether it was a Standard
or a zero-knowledge vault, nor whether a temporary credential acted. `_vault_activity_fields` now adds
`vault_id` / `vault_name` / `vault_type` (and temp attribution) at every vault-scoped emit site.

This connects an admin monitor socket, performs a real upload, and asserts the broadcast frame carries
the vault's name and type — the end-to-end proof that the enrichment reaches the wire.
"""
import json
import time

import pytest

from conftest import unique

websocket = pytest.importorskip("websocket")  # websocket-client

_OCTET = {"Content-Type": "application/octet-stream"}


def _ws_url(base_url: str) -> str:
    return base_url.replace("http://", "ws://").replace("https://", "wss://") + "/ws/monitor"


def _upload(client, vault_id, name, content, chunk_size=None):
    """Store a file through the resumable path (what the browser uses)."""
    chunk_size = chunk_size or max(1, len(content))
    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content),
        "total_chunks": total_chunks, "chunk_size": chunk_size,
        "mime_type": "application/octet-stream",
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    for i in range(total_chunks):
        part = content[i * chunk_size:(i + 1) * chunk_size]
        r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=part, headers=_OCTET)
        assert r.status_code == 200, r.text
    done = client.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    return done.json()["id"]


def _drain(ws, rounds=5):
    ws.settimeout(1)
    for _ in range(rounds):
        try:
            ws.recv()
        except Exception:
            break


@pytest.mark.websocket
def test_upload_broadcast_carries_vault_name_and_type(base_url, admin, temp_vault):
    vid = str(temp_vault["id"])
    vname = temp_vault.get("name")

    ws = websocket.create_connection(_ws_url(base_url), timeout=10)
    try:
        ws.send(json.dumps({"type": "auth", "token": admin.token}))
        _drain(ws)  # discard the initial connected / metrics frames

        _upload(admin, vid, unique("mon") + ".bin", b"live-monitor-enrichment" * 200)

        ws.settimeout(1)
        deadline = time.time() + 10
        found = None
        while time.time() < deadline:
            try:
                msg = ws.recv()
            except Exception:
                continue
            if not msg:
                continue
            try:
                data = json.loads(msg)
            except Exception:
                continue
            ev = data.get("event") if isinstance(data, dict) else None
            if ev and ev.get("type") == "upload" and ev.get("vault_id") == vid:
                found = ev
                break

        assert found is not None, "no enriched upload event for our vault appeared on the WS feed"
        assert found.get("vault_type") == "standard", found
        if vname:
            assert found.get("vault_name") == vname, found
        # Uploaded as the (non-temp) admin account -> no temp attribution on the frame.
        assert found.get("is_temporary") in (None, False), found
    finally:
        try:
            ws.close()
        except Exception:
            pass
