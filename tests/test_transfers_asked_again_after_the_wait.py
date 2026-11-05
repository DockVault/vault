"""A transfer waits for its slot holding no database connection, and what let it in is asked again once it has the
slot, offline.

A download, a rendered preview, a copy, a move and a folder copy each check their access at the door, then wait
for a transfer slot (app/core/transfer_admission.py): up to the queue's wait, 20 s by default and up to an hour.
Downloads and previews waited holding their read transaction, so a connection each: 16 downloads streaming and 32
waiting held the whole pool, and the server stopped answering anyone. Every request now ends its read transaction
before it waits. And the decisions made at the door are about a world that may move during the wait: the session
signed out or ended by an administrator, a temporary credential's scope narrowed, the vault's password changed,
the file deleted. Once a request has its slot it asks them again, in the order the door asks them: the principal
(the same decision as at the door, from its bearer token), the endpoint permission, the vault capability, the
vault's access check with its password compared (not verified again), the item's scope, and the file's row.

These drive the endpoints themselves with a stand-in session that counts the connection its transactions hold,
stand-ins for each check that record when they are asked, and the real admission gate.
tests/test_transfer_waits_live.py holds every slot of a running stack and checks the same there.
"""
import asyncio
import uuid
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
    """Raised where a request starts its transfer: what came before is what these tests look at."""


class _Session:
    """What the request's session does with its connection: the first query of a transaction checks one out,
    commit and rollback give it back."""

    def __init__(self, world):
        self.world = world
        self.held = 0

    def checked_out(self):
        if not self.held:
            self.held = 1
            self.world.log.append("checked out")

    def query(self, *a, **k):
        return self

    def filter(self, *a, **k):
        return self

    def first(self):
        self.checked_out()
        return self.world.file_row()

    def commit(self):
        self.held = 0
        self.world.log.append("commit")

    def rollback(self):
        self.held = 0
        self.world.log.append("rollback")


class _World:
    """The checks a transfer passes, each recording when it is asked and with which principal. `refuse` names the
    check that refuses when it is asked after the wait."""

    def __init__(self, monkeypatch, gate, refuse=None):
        self.gate = gate
        self.refuse = refuse
        self.log = []
        self.db = _Session(self)
        self.door_user = SimpleNamespace(id=uuid.uuid4(), username="at-the-door", role=None)
        self.fresh_user = SimpleNamespace(id=self.door_user.id, username="asked-again", role=None)
        self.waited = None
        world = self

        def ask(name, user=None):
            """Record the ask; True when it is asked after the wait and it is the check to refuse."""
            self.log.append((name, getattr(user, "username", None)))
            return self.refuse == name and bool(self.waited)

        class _VaultService:
            def __init__(self, db, ps):
                pass

            def get_vault(self, vault_id, user, password, require_password=False, allow_share=False):
                world.db.checked_out()
                if ask("vault", user):
                    raise S.PermissionDeniedError("no longer a member")
                world.log.append(("vault asked with", password, require_password, allow_share))
                world.db.commit()                               # as the real get_vault does
                return SimpleNamespace(id=vault_id, type="standard")

            def download_file(self, *a, **k):
                world.log.append("render")
                raise _Stop()

        def scope(name):
            def check(db, user, vault_id, item_id):
                world.db.checked_out()
                if ask(name, user):
                    raise S.PermissionDeniedError("out of scope")
            return check

        def user_for_token(token, db):
            assert token == TOKEN
            world.db.checked_out()
            if ask("session"):
                raise HTTPException(status_code=401, detail="Session has been terminated. Please login again.")
            return world.fresh_user

        def fingerprint(db, vault_id):
            world.db.checked_out()
            changed = ask("password")
            return "a new hash" if changed else "the hash"

        def endpoint_permission(db, user, group, kwargs):
            if ask("permission", user):
                raise HTTPException(status_code=403, detail="You do not have permission")

        def cap(user, vault_id, cap_name):
            if ask("capability", user):
                raise HTTPException(status_code=403, detail="Temporary credential scope does not permit this")

        def start_operation(operation_id):
            world.log.append("start")
            raise _Stop()

        monkeypatch.setattr(S, "transfer_admission", gate)
        monkeypatch.setattr(S, "PermissionService", lambda db: object())
        monkeypatch.setattr(S, "VaultService", _VaultService)
        monkeypatch.setattr(S, "AuditLogger", lambda db: SimpleNamespace(log_action=lambda **k: None))
        monkeypatch.setattr(S, "require_file_scope", scope("file scope"))
        monkeypatch.setattr(S, "require_download_scope", scope("download scope"))
        monkeypatch.setattr(S, "_user_for_token", user_for_token)
        monkeypatch.setattr(S, "_vault_credential_fingerprint", fingerprint)
        monkeypatch.setattr(S, "start_operation", start_operation)
        monkeypatch.setattr(S, "broadcast_event", lambda *a, **k: None)
        import app.core.endpoint_permissions as endpoint_permissions
        import app.core.temp_scope as temp_scope
        monkeypatch.setattr(endpoint_permissions, "check_endpoint_permission", endpoint_permission)
        monkeypatch.setattr(temp_scope, "require_cap", cap)

    def file_row(self):
        if self.refuse == "file row" and self.waited:
            self.log.append(("file row", None))
            return None
        self.log.append(("file row", None))
        return SimpleNamespace(id=uuid.uuid4(), size_bytes=10, folder_id=None, original_name="a.txt")


def _raw(endpoint):
    while hasattr(endpoint, "__wrapped__"):
        endpoint = endpoint.__wrapped__
    return endpoint


def _request():
    return SimpleNamespace(headers={"authorization": f"Bearer {TOKEN}"})


def _call(kind, world):
    vid, fid = uuid.uuid4(), uuid.uuid4()
    if kind == "download":
        return _raw(S.download_file)(vid, fid, _request(), file_password=None, current_user=world.door_user,
                                     db=world.db, x_vault_password="the vault's password")
    return _raw(S.preview_render_file)(vid, fid, _request(), kind=None, file_password=None,
                                       current_user=world.door_user, db=world.db,
                                       x_vault_password="the vault's password")


def _run(kind, refuse=None):
    """Send `kind` while another transfer holds the only slot; return the world, what was seen while it waited,
    its answer (an HTTPException) and the gate's statistics after."""
    def scenario(monkeypatch):
        async def go():
            gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=30)
            world = _World(monkeypatch, gate, refuse)
            other = await gate.acquire()
            task = asyncio.ensure_future(_call(kind, world))
            for _ in range(200):
                if gate.stats()["waiting"]:
                    break
                await asyncio.sleep(0.01)
            waiting = (gate.stats()["waiting"], world.db.held, len(world.log))
            world.waited = True
            gate.release(other)
            try:
                await task
            except HTTPException as exc:
                answer = exc
            else:
                answer = None
            return world, waiting, answer, gate.stats()
        return run_coroutine(go())
    return scenario


KINDS = ["download", "preview"]
# What the door asks, and what is asked again once the slot is held, in order.
DOOR = [("vault", "at-the-door"), ("file scope", "at-the-door"), ("download scope", "at-the-door"),
        ("file row", None), ("password", None)]
AGAIN = [("session", None), ("permission", "asked-again"), ("capability", "asked-again"), ("vault", "asked-again"),
         ("password", None), ("file scope", "asked-again"), ("download scope", "asked-again"), ("file row", None)]


def _asks(log):
    return [entry[:2] for entry in log if isinstance(entry, tuple) and entry[0] != "vault asked with"]


@pytest.mark.parametrize("kind", KINDS)
def test_it_waits_holding_no_connection_and_asks_everything_again_once_it_has_its_slot(monkeypatch, kind):
    world, waiting, answer, stats = _run(kind)(monkeypatch)
    count, held, logged = waiting
    assert count == 1, "it did not wait for the slot"
    assert held == 0, "it waited holding a connection"
    before, after = world.log[:logged], world.log[logged:]
    assert before[-1] == "rollback", f"its read transaction did not end before the wait: {before}"
    assert _asks(before) == DOOR, _asks(before)
    assert _asks(after) == AGAIN, _asks(after)
    assert after[-1] == ("start" if kind == "download" else "render"), after
    # The password is compared after the wait, never sent to be verified again.
    vault_asks = [e for e in world.log if isinstance(e, tuple) and e[0] == "vault asked with"]
    assert vault_asks[0][1:] == ("the vault's password", True, kind == "download")
    assert vault_asks[1][1:] == (None, False, kind == "download")
    assert answer is not None and answer.status_code == 500       # the stand-in stopped it where it starts
    assert stats["in_flight"] == 0 and stats["admitted"] == 2, "its slot was not given back"


# The check that refuses when asked again -> the answer
REFUSALS = {
    "session": 401,
    "permission": 403,
    "capability": 403,
    "vault": 403,
    "password": 401,
    "file scope": 403,
    "download scope": 403,
    "file row": 404,
}


@pytest.mark.parametrize("kind", KINDS)
@pytest.mark.parametrize("refused", list(REFUSALS))
def test_what_changed_while_it_waited_refuses_it_before_it_starts(monkeypatch, kind, refused):
    world, waiting, answer, stats = _run(kind, refuse=refused)(monkeypatch)
    assert waiting[0] == 1 and waiting[1] == 0
    assert answer is not None and answer.status_code == REFUSALS[refused], (refused, answer)
    if refused == "password":
        assert "password" in answer.detail, answer.detail       # the web app asks for it again, no sign-out
    assert "start" not in world.log and "render" not in world.log, world.log
    assert stats["in_flight"] == 0, "its slot was not given back"
