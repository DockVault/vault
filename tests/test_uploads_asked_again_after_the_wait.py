"""An upload that waited for its transfer slot asks again what let it in before it stores anything, offline.

A direct upload, the completion of a chunked upload and the completion of an upload through an upload link each
wait for a transfer slot (app/core/transfer_admission.py) for up to the queue's wait: 20 s by default, up to an hour.
They used the door's decision once they had it, so a session signed out, an account locked, a temporary credential
switched off or narrowed, a capability withdrawn or the vault's password changed meanwhile still let the upload
finish. Once they have the slot they now ask again, as a download does (tests/test_transfers_asked_again_after_
the_wait.py): the principal from its bearer token, the endpoint permission, the vault capability (a refusal recorded
as the door records it), the vault's access with its password compared with the hash read before the door checked it,
the destination folder's scope, and for a completion its upload session again; an upload link's completion
resolves its link and session again (the link revoked or expired, its owner locked, the links switched off).

These drive the endpoints with stand-ins for each check, which record what is asked after the wait, and the real
admission gate, its one slot held by another transfer while the upload arrives.
"""
import asyncio
import uuid
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core.transfer_admission import TransferAdmission  # noqa: E402
from _async_run import run_coroutine  # noqa: E402

pytestmark = pytest.mark.unit

TOKEN = "the-bearer-token"


class _Stop(Exception):
    """Raised where the upload starts storing: what came before is what these tests look at."""


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
        return self.world.upload_session()

    def commit(self):
        pass

    def rollback(self):
        pass


class _World:
    """The checks an upload passes. `refuse` names the one that refuses when it is asked after the wait;
    `change_at_door` makes the vault's password change while the door checks it."""

    def __init__(self, monkeypatch, gate, refuse=None, change_at_door=False):
        self.refuse, self.change_at_door = refuse, change_at_door
        self.waited = False
        self.asked = []
        self.recorded = []
        self.vault_id = uuid.uuid4()
        self.hash = "the vault's hash"
        self.door_user = SimpleNamespace(id=uuid.uuid4(), username="at-the-door", role=None)
        self.fresh_user = SimpleNamespace(id=self.door_user.id, username="asked-again", role=None)
        self.db = _Db(self)
        world = self

        def ask(name):
            if world.waited:
                world.asked.append(name)
            return world.refuse == name and world.waited

        class _VaultService:
            def __init__(self, db, ps):
                pass

            def get_vault(self, vault_id, user, password, require_password=False, allow_share=False):
                if world.change_at_door and not world.waited:
                    world.hash = "a new hash"
                if ask("vault"):
                    raise S.PermissionDeniedError("no longer a member")
                return SimpleNamespace(id=vault_id, type="standard", total_size_bytes=0, size_limit=0)

        def user_for_token(token, db):
            assert token == TOKEN
            if ask("session"):
                raise HTTPException(status_code=401, detail="Session has been terminated. Please login again.")
            return world.fresh_user

        def fingerprint(db, vault_id):
            return world.hash

        def endpoint_permission(db, user, group, kwargs):
            if ask(f"permission {group}"):
                raise HTTPException(status_code=403, detail="You do not have permission")

        def cap(user, vault_id, cap_name):
            if ask(f"capability {cap_name}"):
                raise HTTPException(status_code=403, detail="Temporary credential scope does not permit this")

        def folder_scope(db, user, vault_id, folder_id):
            if ask("folder scope"):
                raise S.PermissionDeniedError("out of scope")

        def started(*a, **k):
            world.asked.append("stored")
            raise _Stop()

        import app.core.endpoint_permissions as endpoint_permissions
        import app.core.temp_scope as temp_scope
        monkeypatch.setattr(S, "transfer_admission", gate)
        monkeypatch.setattr(S, "receiver_transfer_admission", gate)
        monkeypatch.setattr(S, "PermissionService", lambda db: object())
        monkeypatch.setattr(S, "VaultService", _VaultService)
        monkeypatch.setattr(S, "AuditLogger", lambda db: SimpleNamespace(log_action=lambda **k: None))
        monkeypatch.setattr(S, "_user_for_token", user_for_token)
        monkeypatch.setattr(S, "_vault_credential_fingerprint", fingerprint)
        monkeypatch.setattr(S, "require_folder_scope", folder_scope)
        monkeypatch.setattr(S, "_enforce_deployment_storage_quota", lambda db, size: None)
        monkeypatch.setattr(S, "_enforce_free_space", lambda size: None)
        monkeypatch.setattr(S, "_upload_policy", lambda db: (None, 10 ** 12))
        monkeypatch.setattr(S, "_enforce_file_type", lambda name, allowed: None)
        monkeypatch.setattr(S, "start_operation", started)
        monkeypatch.setattr(S, "_upload_session_dir", started)
        monkeypatch.setattr(S, "broadcast_event", lambda *a, **k: None)
        monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.1")
        monkeypatch.setattr(endpoint_permissions, "check_endpoint_permission", endpoint_permission)
        monkeypatch.setattr(temp_scope, "require_cap", cap)
        monkeypatch.setattr(temp_scope, "_audit_vault_cap_denial",
                            lambda db, user, vault_id, cap_name: world.recorded.append(
                                (getattr(user, "username", None), cap_name)))

        def resolve(db, token, session_id):
            if ask("link"):
                return None
            receiver = SimpleNamespace(id=uuid.uuid4())
            vault = SimpleNamespace(id=world.vault_id, type="standard")
            return receiver, world.upload_session(), vault, SimpleNamespace(id=uuid.uuid4(), username="owner")
        monkeypatch.setattr(S, "_receiver_resolve_session", resolve)

    def upload_session(self):
        if self.waited and self.refuse == "upload session":
            return None
        return SimpleNamespace(id=uuid.uuid4(), folder_id=None, status="active", file_id=None, total_chunks=1,
                               total_size=3, filename="a.txt", expires_at=datetime.utcnow() + timedelta(hours=1))


def _raw(endpoint):
    while hasattr(endpoint, "__wrapped__"):
        endpoint = endpoint.__wrapped__
    return endpoint


def _request():
    return SimpleNamespace(headers={"authorization": f"Bearer {TOKEN}", "content-length": "3"},
                           client=SimpleNamespace(host="192.0.2.1"))


def _call(kind, world):
    if kind == "direct upload":
        return _raw(S.upload_file)(world.vault_id, [SimpleNamespace(filename="a.txt", content_type="text/plain")],
                                   _request(), folder_id=None, current_user=world.door_user, db=world.db,
                                   x_vault_password="the vault's password")
    if kind == "chunked completion":
        return _raw(S.complete_chunked_upload)(world.vault_id, uuid.uuid4(), _request(),
                                               current_user=world.door_user, db=world.db,
                                               x_vault_password="the vault's password")
    return S.receiver_complete_upload("a-link-token", uuid.uuid4(), _request(), db=world.db)


def _run(monkeypatch, kind, refuse=None, change_at_door=False):
    """Send `kind` while another transfer holds the only slot; return the world and the answer (the status of a
    refusal, or "stored" when it reached the point where it stores)."""
    async def go():
        gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=30)
        world = _World(monkeypatch, gate, refuse, change_at_door)
        other = await gate.acquire()
        task = asyncio.ensure_future(_call(kind, world))
        for _ in range(200):
            if gate.stats()["waiting"]:
                break
            await asyncio.sleep(0.01)
        assert gate.stats()["waiting"] == 1, "it did not wait for a slot"
        world.waited = True
        gate.release(other)
        try:
            await task
            answer = 200
        except _Stop:
            answer = "stored"
        except HTTPException as exc:
            # The direct upload answers what stopped it inside its loop as a 500, with the cause kept.
            answer = "stored" if isinstance(exc.__cause__, _Stop) else exc.status_code
        except S.PermissionDeniedError:
            answer = 403
        except S.PasswordRequiredError:
            answer = 401
        assert gate.stats()["in_flight"] == 0, "its slot was not given back"
        return world, answer
    return run_coroutine(go())


SIGNED_IN = ["direct upload", "chunked completion"]


@pytest.mark.parametrize("kind", SIGNED_IN)
def test_a_signed_in_upload_asks_everything_again_once_it_has_its_slot(monkeypatch, kind):
    world, answer = _run(monkeypatch, kind)
    assert answer == "stored", answer
    asked = ["session", "permission FILE_UPLOAD", "capability file.upload", "vault", "folder scope"]
    assert world.asked[:len(asked)] == asked, world.asked
    assert world.asked[-1] == "stored"


@pytest.mark.parametrize("kind", SIGNED_IN)
@pytest.mark.parametrize("refused, status", [("session", 401), ("permission FILE_UPLOAD", 403),
                                             ("capability file.upload", 403), ("vault", 403),
                                             ("folder scope", 403)])
def test_what_changed_while_a_signed_in_upload_waited_refuses_it_before_it_stores(monkeypatch, kind, refused,
                                                                                    status):
    world, answer = _run(monkeypatch, kind, refuse=refused)
    assert answer == status, (refused, answer, world.asked)
    assert "stored" not in world.asked


@pytest.mark.parametrize("kind", SIGNED_IN)
def test_a_capability_withdrawn_while_it_waited_is_recorded_as_at_the_door(monkeypatch, kind):
    world, answer = _run(monkeypatch, kind, refuse="capability file.upload")
    assert answer == 403 and world.recorded == [("asked-again", "file.upload")], world.recorded


@pytest.mark.parametrize("kind", SIGNED_IN)
def test_a_password_changed_while_the_door_checked_it_refuses_the_upload_after_its_wait(monkeypatch, kind):
    world, answer = _run(monkeypatch, kind, change_at_door=True)
    assert answer == 401 and "stored" not in world.asked, (answer, world.asked)


def test_a_completion_whose_upload_session_went_while_it_waited_is_refused(monkeypatch):
    world, answer = _run(monkeypatch, "chunked completion", refuse="upload session")
    assert answer == 404 and "stored" not in world.asked, (answer, world.asked)


def test_an_upload_links_completion_resolves_its_link_and_session_again_once_it_has_its_slot(monkeypatch):
    world, answer = _run(monkeypatch, "link completion")
    assert answer == "stored" and world.asked == ["link", "stored"], world.asked
    world, answer = _run(monkeypatch, "link completion", refuse="link")
    assert answer == 404 and "stored" not in world.asked, (answer, world.asked)
