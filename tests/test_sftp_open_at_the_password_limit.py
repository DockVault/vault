"""Opening a file over SFTP while its password is at its attempt limit is a plain denial.

SFTP never passes a file's password, so nothing can be guessed over it. But a user who reached a
file's limit from the web gets the limit's error when SFTP opens that file (the limit is checked
before "no password given"). That must answer as the missing password always did, PERMISSION_DENIED,
and not as a failure logged as a broken download.
"""
import contextlib
import uuid
from types import SimpleNamespace

import paramiko
import pytest

from app.sftp import sftp_server as ss
from app.services import vault_service as vs

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("raised, answer", [
    (vs.RateLimitExceededError("Too many file password attempts. Please try again later."),
     paramiko.SFTP_PERMISSION_DENIED),
    (vs.PasswordRequiredError("File password required"), paramiko.SFTP_PERMISSION_DENIED),
    (RuntimeError("the store broke"), paramiko.SFTP_FAILURE),
])
def test_a_file_at_its_password_limit_is_denied_not_failed(monkeypatch, raised, answer):
    events = []
    file_id, vault_id = uuid.uuid4(), uuid.uuid4()

    class _Service:
        def __init__(self, *_a, **_k):
            pass

        def open_random_reader(self, *_a, **_k):
            raise raised

    monkeypatch.setattr(ss, "get_db_context", contextlib.nullcontext)
    monkeypatch.setattr(ss, "VaultService", _Service)
    monkeypatch.setattr(ss, "PermissionService", lambda db: None)
    monkeypatch.setattr(ss, "safe_event", lambda event, *a, **k: events.append(event))
    server = ss.SFTPServerInterface.__new__(ss.SFTPServerInterface)   # bypass paramiko's __init__
    server._load_principal = lambda db: SimpleNamespace(id=uuid.uuid4())
    server._resolve_vault = lambda service, user, name: SimpleNamespace(id=vault_id)
    server._has_cap = lambda user, vid, cap: True
    server._resolve_folder = lambda db, vid, parts: None
    server._resolve_file = lambda db, vid, folder, name: SimpleNamespace(id=file_id)
    server._scope_ok_file = lambda db, user, vid, fid: True

    assert server._open_read(["vault", "report.pdf"]) == answer
    assert events == ([] if answer == paramiko.SFTP_PERMISSION_DENIED else ["download.failed"]), events
