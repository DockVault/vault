"""Drive the two chunk endpoints offline: a signed-in upload's chunk (upload_chunk) and an upload link's chunk
(receiver_upload_chunk).

The session's staging folder is a temporary directory and the body is sealed and staged for real; the database, the
door's checks and the checks asked again after the body are stand-ins. A test reads what the endpoint answered,
whether it read the body, and what it staged. The vault's password hash is what the stand-in reads as the vault's
credential; with ``change_password_at_door`` it changes while the door checks the request's password, as a change
committed then would.
"""
import uuid
from types import SimpleNamespace

from fastapi import HTTPException

import app.api.api_server as S
from _async_run import run_coroutine

TOKEN = "the-bearer-token"
SIZE = 4096
ENDPOINTS = ("signed in", "upload link")


class _Db:
    def __init__(self, world):
        self.world = world

    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def with_for_update(self, *a, **k):
        return self

    def first(self):
        return self.world.session

    def commit(self):
        pass

    def rollback(self):
        pass


class Body:
    """A request carrying one chunk of SIZE bytes, which records whether it was read."""

    def __init__(self):
        self.payload = b"c" * SIZE
        self.headers = {"authorization": f"Bearer {TOKEN}", "content-length": str(SIZE)}
        self.read = False

    def stream(self):
        async def pieces():
            self.read = True
            yield self.payload
        return pieces()


class ChunkWorld:
    def __init__(self, monkeypatch, staging, *, change_password_at_door=False):
        self.staging = staging
        self.vault_id = uuid.uuid4()
        self.user = SimpleNamespace(id=uuid.uuid4(), username="uploader", role=None)
        self.hash = "the vault's hash"
        self.doors = 0
        self.session = SimpleNamespace(
            id=uuid.uuid4(), vault_id=self.vault_id, user_id=self.user.id, folder_id=None, status="active",
            expires_at=None, total_chunks=1, total_size=SIZE, bytes_received=0, chunks_received=0,
            last_chunk_at=None, blob_id=None, filename=None)
        self.db = _Db(self)
        world = self

        class _VaultService:
            storage_path = staging

            def __init__(self, db, ps):
                pass

            def get_vault(self, vault_id, user, password, require_password=False, allow_share=False):
                world.doors += 1
                if change_password_at_door and world.doors == 1:
                    world.hash = "a new hash"           # committed while the door checks the old one
                return SimpleNamespace(id=vault_id, type="standard")

        async def current_user(credentials, db):
            assert credentials.credentials == TOKEN
            return world.user

        def resolved(db, token, session_id):
            assert token == TOKEN
            return (SimpleNamespace(id=uuid.uuid4()), world.session, SimpleNamespace(id=world.vault_id),
                    SimpleNamespace(id=world.user.id))

        monkeypatch.setattr(S, "PermissionService", lambda db: object())
        monkeypatch.setattr(S, "VaultService", _VaultService)
        monkeypatch.setattr(S, "_vault_credential_fingerprint", lambda db, vault_id: world.hash)
        monkeypatch.setattr(S, "require_folder_scope", lambda *a, **k: None)
        monkeypatch.setattr(S, "_session_principal", lambda user: True)
        monkeypatch.setattr(S, "get_current_user", current_user)
        monkeypatch.setattr(S, "_receiver_resolve_session", resolved)
        import app.core.endpoint_permissions as endpoint_permissions
        import app.core.temp_scope as temp_scope
        monkeypatch.setattr(endpoint_permissions, "check_endpoint_permission", lambda *a, **k: None)
        monkeypatch.setattr(temp_scope, "require_cap", lambda *a, **k: None)

    def staged(self):
        """The names in the session's staging folder: a published chunk, or a part left behind."""
        folder = self.staging / "_uploads" / str(self.session.id)
        return sorted(p.name for p in folder.iterdir()) if folder.exists() else []


def _raw(endpoint):
    while hasattr(endpoint, "__wrapped__"):
        endpoint = endpoint.__wrapped__
    return endpoint


def send_chunk(world, endpoint):
    """Send chunk 0 of the world's session through ``endpoint`` (one of ENDPOINTS). Returns what it answered (its
    dict, or the HTTPException it raised) and the request, which says whether its body was read."""
    body = Body()
    if endpoint == "signed in":
        call = _raw(S.upload_chunk)(world.vault_id, world.session.id, 0, body, current_user=world.user, db=world.db,
                                    x_vault_password="the vault's password")
    else:
        call = S.receiver_upload_chunk(TOKEN, world.session.id, 0, body, db=world.db)
    try:
        return run_coroutine(call), body
    except HTTPException as exc:
        return exc, body
