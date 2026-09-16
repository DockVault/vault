"""A temporary-credential session must not manage or enumerate the account's devices.

A temporary credential is a scoped, expiring delegation. If its web session can enroll a device,
grant it vaults and mint sync credentials, it has turned itself into a longer-lived, write-capable
identity that outlives its own revocation — and even listing devices hands it every device label and
last-seen time. The whole /devices* family refuses a temp session, as a dependency that runs before
any device lookup, so the refusal is identical (403) whether or not the device id exists — a 404
ahead of the 403 would itself reveal which ids are real.
"""
import pytest

from conftest import unique
from _device_boundary_helpers import register_device, temp_login

pytestmark = pytest.mark.integration


def _denial_count(admin):
    rows = admin.get("/audit/log?action=device_access_denied").json()
    return len(rows) if isinstance(rows, list) else 0


def test_a_temporary_session_cannot_manage_or_enumerate_devices(admin):
    sess, _ = temp_login(admin)

    real = register_device(admin)
    real_id = real["device_id"]
    fake_id = "00000000-0000-4000-8000-000000000000"
    # Count BEFORE the probes: on a reused stack the log already carries this action from earlier
    # runs, so `len > 0` would pass by history even with the audit write reverted. The delta is what
    # this test's own probes add, so it goes red on revert on any stack.
    denials_before = _denial_count(admin)

    checks = [
        ("post", "/devices", {"label": "hijack"}),
        ("get", "/devices", None),
        ("post", f"/devices/{real_id}/grants", {"vault_id": fake_id}),
        ("post", f"/devices/{fake_id}/grants", {"vault_id": fake_id}),
        ("post", f"/devices/{real_id}/grants/{fake_id}/revoke", None),
        ("post", f"/devices/{fake_id}/grants/{fake_id}/revoke", None),
        ("post", f"/devices/{real_id}/restore", None),
        ("post", f"/devices/{fake_id}/restore", None),
        ("post", f"/devices/{real_id}/revoke", None),
        ("post", f"/devices/{fake_id}/revoke", None),
        ("delete", f"/devices/{real_id}", None),
        ("delete", f"/devices/{fake_id}", None),
    ]
    try:
        for verb, path, body in checks:
            r = getattr(sess, verb)(path, json=body) if body is not None else getattr(sess, verb)(path)
            assert r.status_code == 403, (
                f"a temporary session reached {verb.upper()} {path}: {r.status_code} {r.text[:200]}")

        # None of those attempts altered the account's devices.
        devices = admin.get("/devices").json()["devices"]
        still = next((d for d in devices if str(d.get("device_id")) == real_id), None)
        assert still is not None and still.get("is_active") is True, (
            "a temporary session's calls altered the account's devices")

        # And the probes left a trace: reaching for device management from a temporary session is
        # recorded, the same way an admin-plane denial is — an unrecorded 403 is a blind spot. The
        # count must GROW by this test's own probes, not merely be non-zero.
        assert _denial_count(admin) > denials_before, (
            "a temporary session's device-management probes were refused but left no audit rows")
    finally:
        admin.delete(f"/devices/{real_id}")


def test_an_interactive_owner_still_manages_devices(admin, temp_vault):
    """The regression guard the acceptance line does not state: a fix that refused EVERYONE would
    satisfy 'all 403' while breaking the product. An interactive owner still enrolls, lists, grants
    and revokes."""
    assert admin.get("/devices").status_code == 200

    reg = admin.post("/devices", json={"label": unique("mybox")})
    assert reg.status_code in (200, 201), reg.text
    dev = reg.json()
    assert dev.get("secret"), "registering a device must still return its secret to the owner"
    try:
        assert admin.post(f"/devices/{dev['device_id']}/grants",
                          json={"vault_id": temp_vault["id"]}).status_code in (200, 201)
        assert admin.post(f"/devices/{dev['device_id']}/revoke").status_code == 200
    finally:
        admin.delete(f"/devices/{dev['device_id']}")
