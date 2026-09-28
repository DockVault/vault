"""An Activity export is recorded before a row of it is sent, or it is not made.

An export holds up to 100,000 rows of personal data (usernames, addresses, browsers). Its audit row
used to be written best-effort, so when audit inserts failed (a full disk, say) while reads still
worked, the export went out and left no trace of who took it. It is now refused with 503 instead.
The route's own function runs here with the log's writer and the row count stood in for.
"""
from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from fastapi.responses import StreamingResponse

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.api import api_server as api  # noqa: E402
from app.services import activity_events as ev  # noqa: E402

pytestmark = pytest.mark.unit

ADMIN = SimpleNamespace(id="a-1", username="alice", role="admin")


class _Db:
    def __init__(self):
        self.rolled_back = 0

    def query(self, *_a):
        return None

    def rollback(self):
        self.rolled_back += 1


@pytest.fixture
def export(monkeypatch):
    """Run the export route; `fail` decides whether its audit row can be written."""
    written = []

    class _Logger:
        fail = False

        def __init__(self, _db):
            pass

        def log_action(self, **row):
            if _Logger.fail:
                raise RuntimeError("could not extend file: No space left on device")
            written.append(row)

    monkeypatch.setattr(api, "AuditLogger", _Logger)
    monkeypatch.setattr(ev, "build_events_query", lambda *_a, **_k: SimpleNamespace(
        order_by=lambda *_x: SimpleNamespace(count=lambda: 42)))

    def run(fail):
        _Logger.fail = fail
        db = _Db()
        return db, written, lambda: api.activity_export(
            format="csv", category=[], channel=[], status=[], action=[], user="bob", user_match="exact",
            no_account=False, ip=None, q=None, temp_credential_id=None, temp_credential=None, vault_id=None,
            from_date=None, to_date=None, current_user=ADMIN, db=db)
    return run


def test_an_export_is_recorded_before_it_is_sent(export):
    _db, written, call = export(fail=False)
    response = call()
    assert isinstance(response, StreamingResponse)
    (row,) = written
    assert (row["action"], row["status"], row["user"]) == ("audit_exported", "success", ADMIN)
    assert row["details"]["rows"] == 42 and row["details"]["filters"] == {"user": "bob", "user_match": "exact"}


def test_an_export_whose_record_cannot_be_written_is_refused(export):
    db, written, call = export(fail=True)
    with pytest.raises(HTTPException) as refused:
        call()
    assert refused.value.status_code == 503
    assert "not made" in refused.value.detail
    assert written == [] and db.rolled_back == 1
