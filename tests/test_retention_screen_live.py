"""The retention screen's Storage route on a running stack (GET /settings/managed/storage,
app/core/retention_storage.py): what an administrator reads of the audit log's rows and archive, the files' volume,
and the size cap (none on the stack); a user and a request with no session are refused."""
import pytest

pytestmark = pytest.mark.integration


def test_an_administrator_reads_what_the_audit_log_takes(admin):
    r = admin.get("/settings/managed/storage")
    assert r.status_code == 200, r.text
    body = r.json()
    assert set(body) == {"rows", "archive", "cap", "storage_volume", "database_volume", "existing_install"}
    assert body["rows"]["count"] >= 0 and body["rows"]["bytes"] > 0 and isinstance(body["rows"]["exact"], bool)
    assert body["archive"]["blocks"] >= 0 and body["archive"]["table_bytes"] > 0
    assert body["cap"] is None and body["database_volume"] is None
    vol = body["storage_volume"]
    assert vol["total"] >= vol["used"] > 0 and vol["free"] > 0
    assert body["existing_install"] is False                 # the stack's log began with this release


def test_a_user_and_no_session_are_refused(temp_user_client, anon):
    assert temp_user_client.get("/settings/managed/storage").status_code == 403
    assert anon.get("/settings/managed/storage").status_code in (401, 403)
