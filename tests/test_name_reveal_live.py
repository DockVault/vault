"""Revealing a recorded name outside a case on a running stack (app/core/name_reveal.py and its route).

With names recorded in full, an auditor who cannot read a vault reveals an upload event's file name with a reason:
the name recorded then comes back, the reason is sealed in the database, the reveal is recorded, and the vault's
owner is told once that day however many times the auditor reveals there. A vault with a password is refused. Only
a live auditor reveals. test_name_reveal.py covers the rules offline.
"""
import uuid

import pytest

from _account_change_helpers import psql
from _auditor_helpers import forget_grants, grant_right, new_auditor_account, two_admins
from _owner_notice_helpers import owner_with_vault
from _recording_levels import levels_restored, store, wait_for  # noqa: F401 -- a fixture

pytestmark = pytest.mark.integration

REASON = "Ticket SEC-2041: tracing who copied the payroll file."


@pytest.fixture
def world(admin):
    with two_admins(admin) as admins:
        uma, uma_c, codes = new_auditor_account(admin)
        grant_right(admins, uma["id"])
        olga, olga_c, vid = owner_with_vault(admin)
        try:
            yield {"admins": admins, "admin": admin, "uma": (uma, uma_c, codes), "olga": (olga, olga_c, vid)}
        finally:
            psql(f"DELETE FROM compliance_reveals WHERE auditor_id = '{uma['id']}'")
            psql(f"DELETE FROM compliance_notice_outbox WHERE case_id IS NULL AND user_id = '{olga['id']}'")
            forget_grants(uma["id"])


def _upload_row(client, vid, version, name, headers=None):
    up = client.post(f"/vaults/{vid}/files", files=[("files", (name, b"0123456789", "text/plain"))],
                     headers=headers or {})
    assert up.status_code in (200, 201), up.text[:200]
    return wait_for(lambda: psql(
        "SELECT id FROM audit_logs "
        f"WHERE details->>'vault_id' = '{vid}' AND privacy_version = {version} "
        "AND recorded->'names'->'values'->'file_name' ? 'sealed' ORDER BY timestamp DESC LIMIT 1"))


def test_an_auditor_reveals_a_recorded_name_and_the_owner_is_told_once(world, levels_restored):
    uma, uma_c, _codes = world["uma"]
    olga, olga_c, vid = world["olga"]
    version = store(dict(levels_restored, names="full"))
    first, second = f"reveal-{uuid.uuid4().hex}.txt", f"reveal-{uuid.uuid4().hex}.txt"
    row1 = _upload_row(olga_c, vid, version, first)
    row2 = _upload_row(olga_c, vid, version, second)
    shown = uma_c.get(f"/activity/events/{row1}").json()
    assert first not in str(shown), "the auditor does not read the vault: the event shows no name"
    body = {"reason_category": "security_incident", "reason_text": REASON}
    r = uma_c.post(f"/activity/events/{row1}/reveal", json=body)
    assert r.status_code == 200, r.text
    assert r.json()["names"]["file_name"] == first and "fp1:" not in r.text
    assert uma_c.post(f"/activity/events/{row2}/reveal", json=body).json()["names"]["file_name"] == second
    assert psql(f"SELECT count(*) FROM audit_logs WHERE action = 'audit_name_revealed' AND status = 'success' "
                f"AND user_id = '{uma['id']}'") == "2"
    assert psql(f"SELECT count(*) FROM compliance_reveals WHERE auditor_id = '{uma['id']}'") == "2"
    assert psql(f"SELECT count(*) FROM compliance_reveals WHERE reason_text_enc LIKE '%SEC-2041%'") == "0"
    assert psql("SELECT count(*) FROM audit_logs WHERE audit_logs::text LIKE '%SEC-2041%'") == "0"
    assert psql(f"SELECT count(*) FROM compliance_notice_outbox WHERE case_id IS NULL AND kind = 'reveal' "
                f"AND user_id = '{olga['id']}'") == "1", "once per auditor, vault and day"
    notes = psql(f"SELECT string_agg(body, ' ') FROM notifications WHERE user_id = '{olga['id']}' "
                 "AND type = 'compliance_access'")
    assert uma["username"] in notes and first not in notes and second not in notes


def test_a_vault_with_a_password_is_refused_and_only_an_auditor_reveals(world, levels_restored, admin):
    _uma, uma_c, _codes = world["uma"]
    _olga, olga_c, _vid = world["olga"]
    version = store(dict(levels_restored, names="full"))
    pv = olga_c.create_vault(name=f"locked-{uuid.uuid4().hex[:8]}", password="Vault-Pass-2026!")["id"]
    name = f"reveal-pw-{uuid.uuid4().hex}.txt"
    row = _upload_row(olga_c, pv, version, name, headers={"X-Vault-Password": "Vault-Pass-2026!"})
    body = {"reason_category": "security_incident", "reason_text": REASON}
    r = uma_c.post(f"/activity/events/{row}/reveal", json=body)
    assert r.status_code == 403 and r.json()["detail"]["reason"] == "password_vault" and name not in r.text
    assert admin.post(f"/activity/events/{row}/reveal", json=body).status_code == 403, "an administrator: no right"
    assert olga_c.post(f"/activity/events/{row}/reveal", json=body).status_code == 403
    olga_c.delete(f"/vaults/{pv}", headers={"X-Vault-Password": "Vault-Pass-2026!"})


def test_reveals_at_once_in_one_vault_tell_its_owner_once_and_all_succeed(world, levels_restored):
    """Reveals of one auditor run one at a time (their account row is locked for each): six at once in a vault, the
    first of the day there, each succeed, and the owner gets one notice."""
    from concurrent.futures import ThreadPoolExecutor

    import requests

    from conftest import BASE_URL
    uma, uma_c, _codes = world["uma"]
    olga, olga_c, vid = world["olga"]
    version = store(dict(levels_restored, names="full"))
    rows = [_upload_row(olga_c, vid, version, f"race-{uuid.uuid4().hex}.txt") for _ in range(6)]
    body = {"reason_category": "internal_investigation", "reason_text": REASON}

    def reveal(row):
        return requests.post(f"{BASE_URL}/activity/events/{row}/reveal", json=body, timeout=60,
                             headers={"Authorization": f"Bearer {uma_c.token}"}).status_code
    with ThreadPoolExecutor(max_workers=6) as pool:
        statuses = list(pool.map(reveal, rows))
    assert statuses == [200] * 6, statuses
    assert psql(f"SELECT count(*) FROM compliance_notice_outbox WHERE case_id IS NULL AND kind = 'reveal' "
                f"AND user_id = '{olga['id']}'") == "1"
    assert psql(f"SELECT count(*) FROM compliance_reveals WHERE auditor_id = '{uma['id']}'") == "6"
