"""A transfer waits for its slot holding no database connection, and what let it in is asked again once it has the
slot, offline.

A download, a rendered preview, a copy, a move to another vault and a folder copy each check their access at the
door, then wait for a transfer slot (app/core/transfer_admission.py): up to the queue's wait, 20 s by default and
up to an hour. Downloads and previews waited holding their read transaction, so a connection each: 16 downloads
streaming and 32 waiting held the whole pool, and the server stopped answering anyone. Every request now ends its
read transaction before it waits. And the decisions made at the door are about a world that may move during the
wait: the session signed out or ended by an administrator, a temporary credential's scope narrowed, a vault's
password changed, the file deleted. Once a request has its slot it asks them again, in the order the door asks
them: the principal (the same decision as at the door, from its bearer token), the endpoint permission, the vault
capability, the vault's access check with its password compared (not verified again), the item's scope and its
row, and for a copy or a move the destination's access, password, capability and folder scope, and whether a
same-name file there may be replaced. A copy, a move and a folder copy ask them in the thread their work runs in.

These drive the endpoints themselves with a stand-in session that counts the connection its transactions hold,
stand-ins for each check that record when they are asked, with which principal and on which thread, and the real
admission gate. tests/test_transfer_waits_live.py holds every slot of a running stack and checks the same there.
"""
import asyncio
import threading
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
    """Raised where a download or a preview starts its transfer: what came before is what these tests look at."""


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
        return self.world.item_row()

    def commit(self):
        self.held = 0
        self.world.log.append("commit")

    def rollback(self):
        self.held = 0
        self.world.log.append("rollback")


class _World:
    """The checks a transfer passes, each recording when it is asked, with which principal and on which thread.
    `refuse` names the check that refuses when it is asked after the wait."""

    def __init__(self, monkeypatch, gate, source, dest, refuse=None):
        self.gate = gate
        self.refuse = refuse
        self.log = []
        self.threads = []
        self.db = _Session(self)
        self.which = {source: "source", dest: "dest"}
        self.door_user = SimpleNamespace(id=uuid.uuid4(), username="at-the-door", role=None)
        self.fresh_user = SimpleNamespace(id=self.door_user.id, username="asked-again", role=None)
        self.waited = None
        self.worked = []
        world = self

        def ask(name, user=None):
            """Record the ask; True when it is asked after the wait and it is the check to refuse."""
            self.log.append((name, getattr(user, "username", None)))
            self.threads.append((name, threading.current_thread().name))
            return self.refuse == name and bool(self.waited)

        class _VaultService:
            def __init__(self, db, ps):
                pass

            def get_vault(self, vault_id, user, password, require_password=False, allow_share=False):
                world.db.checked_out()
                which = world.which[vault_id]
                if ask(f"{which} vault", user):
                    raise S.PermissionDeniedError("no longer a member")
                world.log.append(("vault asked with", which, password, require_password, allow_share))
                world.db.commit()                               # as the real get_vault does
                return SimpleNamespace(id=vault_id, type="standard")

            def download_file(self, *a, **k):
                world.log.append("render")
                raise _Stop()

            def _work(self, name, user, **k):
                world.db.checked_out()
                world.log.append(("work", user.username))
                world.worked.append((name, threading.current_thread().name, k.get("replace_same_name")))
                return SimpleNamespace(id=uuid.uuid4())

            def copy_file(self, file_id, user, *a, **k):
                return self._work("copy", user, **k)

            def move_file(self, file_id, user, *a, **k):
                return self._work("move", user, **k)

            def copy_folder(self, folder_id, user, *a, **k):
                return self._work("folder copy", user, **k)

        def checked(name):
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
            changed = ask(f"{world.which[vault_id]} password")
            return "a new hash" if changed else "the hash"

        def endpoint_permission(db, user, group, kwargs):
            if ask(f"permission {group}", user):
                raise HTTPException(status_code=403, detail="You do not have permission")

        def cap(user, vault_id, cap_name):
            if ask(f"capability {cap_name}", user):
                raise HTTPException(status_code=403, detail="Temporary credential scope does not permit this")

        def may_replace(db, user, vault_id):
            ask("replace", user)
            return self.refuse != "replace" or not self.waited

        def start_operation(operation_id):
            world.log.append("start")
            raise _Stop()

        monkeypatch.setattr(S, "transfer_admission", gate)
        monkeypatch.setattr(S, "PermissionService", lambda db: object())
        monkeypatch.setattr(S, "VaultService", _VaultService)
        monkeypatch.setattr(S, "AuditLogger", lambda db: SimpleNamespace(
            log_action=lambda **k: world.log.append(("audited", getattr(k.get("user"), "username", None)))))
        monkeypatch.setattr(S, "require_file_scope", checked("file scope"))
        monkeypatch.setattr(S, "require_download_scope", checked("download scope"))
        monkeypatch.setattr(S, "require_item_scope", checked("item scope"))
        monkeypatch.setattr(S, "require_folder_scope", checked("folder scope"))
        monkeypatch.setattr(S, "_principal_can_replace_file", may_replace)
        monkeypatch.setattr(S, "_user_for_token", user_for_token)
        monkeypatch.setattr(S, "_vault_credential_fingerprint", fingerprint)
        monkeypatch.setattr(S, "start_operation", start_operation)
        monkeypatch.setattr(S, "broadcast_event", lambda *a, **k: None)
        monkeypatch.setattr(S, "get_client_ip", lambda request: "192.0.2.1")
        import app.core.endpoint_permissions as endpoint_permissions
        import app.core.temp_scope as temp_scope
        monkeypatch.setattr(endpoint_permissions, "check_endpoint_permission", endpoint_permission)
        monkeypatch.setattr(temp_scope, "require_cap", cap)

    def item_row(self):
        self.log.append(("item row", None))
        self.threads.append(("item row", threading.current_thread().name))
        if self.refuse == "item row" and self.waited:
            return None
        return SimpleNamespace(id=uuid.uuid4(), size_bytes=10, folder_id=None, original_name="a.txt")


def _raw(endpoint):
    while hasattr(endpoint, "__wrapped__"):
        endpoint = endpoint.__wrapped__
    return endpoint


def _request():
    return SimpleNamespace(headers={"authorization": f"Bearer {TOKEN}"})


def _call(kind, world, source, dest):
    item = uuid.uuid4()
    common = dict(current_user=world.door_user, db=world.db, x_vault_password="the vault's password")
    if kind == "download":
        return _raw(S.download_file)(source, item, _request(), file_password=None, **common)
    if kind == "preview":
        return _raw(S.preview_render_file)(source, item, _request(), kind=None, file_password=None, **common)
    if kind == "folder copy":
        return _raw(S.copy_folder_endpoint)(source, item, S.FolderMoveCopy(dest_vault_id=source), _request(),
                                            **common)
    endpoint = S.copy_file_endpoint if kind == "copy" else S.move_file_endpoint
    return _raw(endpoint)(source, item, S.ItemMoveCopy(dest_vault_id=dest, replace_same_name=True), _request(),
                          x_dest_vault_password="the destination's password", x_file_password=None, **common)


def _run(monkeypatch, kind, refuse=None):
    """Send `kind` while another transfer holds the only slot; return the world, what was seen while it waited,
    its answer (an HTTPException, or what it returned) and the gate's statistics after."""
    async def go():
        source, dest = uuid.uuid4(), uuid.uuid4()
        gate = TransferAdmission(limit=1, max_waiting=4, wait_seconds=30)
        world = _World(monkeypatch, gate, source, dest, refuse)
        other = await gate.acquire()
        task = asyncio.ensure_future(_call(kind, world, source, dest))
        for _ in range(200):
            if gate.stats()["waiting"]:
                break
            await asyncio.sleep(0.01)
        waiting = (gate.stats()["waiting"], world.db.held, len(world.log))
        world.waited = True
        gate.release(other)
        try:
            answer = await task
        except HTTPException as exc:
            answer = exc
        except (S.PermissionDeniedError, S.PasswordRequiredError) as exc:
            answer = exc                    # the application's handlers answer these 403 and 401
        return world, waiting, answer, gate.stats()
    return run_coroutine(go())


def _asks(log):
    return [entry[:2] for entry in log if isinstance(entry, tuple) and entry[0] not in ("vault asked with", "work",
                                                                                        "audited")]


AT_THE_DOOR = {
    "download": [("source vault", "at-the-door"), ("file scope", "at-the-door"), ("download scope", "at-the-door"),
                 ("item row", None), ("source password", None)],
    "copy": [("source vault", "at-the-door"), ("item row", None), ("item scope", "at-the-door"),
             ("dest vault", "at-the-door"), ("capability file.upload", "at-the-door"),
             ("folder scope", "at-the-door"), ("replace", "at-the-door"), ("source password", None),
             ("dest password", None)],
    "folder copy": [("source vault", "at-the-door"), ("item row", None), ("item scope", "at-the-door"),
                    ("folder scope", "at-the-door"), ("capability file.download", "at-the-door"),
                    ("capability file.upload", "at-the-door"), ("source password", None)],
}
AT_THE_DOOR["preview"] = AT_THE_DOOR["download"]
AT_THE_DOOR["move"] = AT_THE_DOOR["copy"]


def _again(group, cap, rest):
    return [("session", None), (f"permission {group}", "asked-again"), (f"capability {cap}", "asked-again"),
            ("source vault", "asked-again"), ("source password", None)] + rest


AFTER_THE_WAIT = {
    "download": _again("FILE_DOWNLOAD", "file.download", [
        ("file scope", "asked-again"), ("download scope", "asked-again"), ("item row", None)]),
    "copy": _again("FILE_DOWNLOAD", "file.download", [
        ("item row", None), ("item scope", "asked-again"), ("dest vault", "asked-again"), ("dest password", None),
        ("capability file.upload", "asked-again"), ("folder scope", "asked-again"), ("replace", "asked-again")]),
    "folder copy": _again("FOLDER_MANAGE", "folder.create", [
        ("item row", None), ("item scope", "asked-again"), ("folder scope", "asked-again"),
        ("capability file.download", "asked-again"), ("capability file.upload", "asked-again")]),
}
AFTER_THE_WAIT["preview"] = AFTER_THE_WAIT["download"]
AFTER_THE_WAIT["move"] = _again("FILE_DELETE", "file.delete", AFTER_THE_WAIT["copy"][5:])

KINDS = ["download", "preview", "copy", "move", "folder copy"]
COPIES = ["copy", "move", "folder copy"]


@pytest.mark.parametrize("kind", KINDS)
def test_it_waits_holding_no_connection_and_asks_everything_again_once_it_has_its_slot(monkeypatch, kind):
    world, waiting, answer, stats = _run(monkeypatch, kind)
    count, held, logged = waiting
    assert count == 1, "it did not wait for the slot"
    assert held == 0, "it waited holding a connection"
    before, after = world.log[:logged], world.log[logged:]
    assert before[-1] == "rollback", f"its read transaction did not end before the wait: {before}"
    assert _asks(before) == AT_THE_DOOR[kind], _asks(before)
    assert _asks(after) == AFTER_THE_WAIT[kind], _asks(after)
    # The vault's password is compared after the wait, never sent to be verified again.
    asked_with = [e[1:] for e in world.log if isinstance(e, tuple) and e[0] == "vault asked with"]
    share = kind == "download"
    assert asked_with[0] == ("source", "the vault's password", True, share), asked_with
    assert asked_with[-1 if kind in ("download", "preview", "folder copy") else -2] == (
        "source", None, False, share), asked_with
    if kind in ("copy", "move"):
        assert asked_with[1] == ("dest", "the destination's password", True, False)
        assert asked_with[-1] == ("dest", None, False, False)
    if kind in COPIES:
        # Asked in the thread the work runs in, with nothing between the answers and the work, and the work done
        # as the principal asked again.
        asked_after = world.threads[-len(AFTER_THE_WAIT[kind]):]
        assert {thread for _, thread in asked_after} == {world.worked[0][1]}, asked_after
        assert world.worked[0][1].startswith("stored-bytes"), world.worked
        assert after[-2:] == [("work", "asked-again"), ("audited", "asked-again")], after
        assert answer["id"]
        if kind != "folder copy":
            assert world.worked[0][2] is True, "the replace the door decided was not the one asked again"
    else:
        assert after[-1] == ("start" if kind == "download" else "render"), after
        assert isinstance(answer, HTTPException) and answer.status_code == 500  # the stand-in stopped it there
    assert stats["in_flight"] == 0 and stats["admitted"] == 2, "its slot was not given back"


# The check that refuses when asked after the wait -> the answer
REFUSALS = {
    "session": 401,
    "permission": 403,
    "capability": 403,
    "source vault": 403,
    "source password": 401,
    "item row": 404,
}
REFUSALS_OF = {
    "download": {**REFUSALS, "file scope": 403, "download scope": 403},
    "copy": {**REFUSALS, "item scope": 403, "dest vault": 403, "dest password": 401, "dest capability": 403,
             "folder scope": 403},
    "folder copy": {**REFUSALS, "item scope": 403, "folder scope": 403},
}
REFUSALS_OF["preview"] = REFUSALS_OF["download"]
REFUSALS_OF["move"] = REFUSALS_OF["copy"]
GROUP = {"download": "FILE_DOWNLOAD", "preview": "FILE_DOWNLOAD", "copy": "FILE_DOWNLOAD", "move": "FILE_DELETE",
         "folder copy": "FOLDER_MANAGE"}
CAP = {"download": "file.download", "preview": "file.download", "copy": "file.download", "move": "file.delete",
       "folder copy": "folder.create"}


def _check_name(kind, refused):
    if refused == "permission":
        return f"permission {GROUP[kind]}"
    if refused == "capability":
        return f"capability {CAP[kind]}"
    if refused == "dest capability":
        return "capability file.upload"
    return refused


def _status(answer):
    if isinstance(answer, HTTPException):
        return answer.status_code
    if isinstance(answer, S.PasswordRequiredError):
        return 401
    if isinstance(answer, S.PermissionDeniedError):
        return 403
    return 200


@pytest.mark.parametrize("kind, refused", [(k, r) for k in KINDS for r in REFUSALS_OF[k]])
def test_what_changed_while_it_waited_refuses_it_before_it_starts(monkeypatch, kind, refused):
    world, waiting, answer, stats = _run(monkeypatch, kind, refuse=_check_name(kind, refused))
    assert waiting[0] == 1 and waiting[1] == 0
    assert _status(answer) == REFUSALS_OF[kind][refused], (refused, answer)
    if refused.endswith("password"):
        # The web app asks for the password again on a 401 that says "password", rather than signing out.
        assert "password" in str(getattr(answer, "detail", answer)), answer
    assert world.worked == [] and "start" not in world.log and "render" not in world.log, world.log
    assert stats["in_flight"] == 0, "its slot was not given back"


@pytest.mark.parametrize("kind", ["copy", "move"])
def test_a_replace_withdrawn_while_it_waited_is_not_made(monkeypatch, kind):
    """Overwriting a same-name file deletes it, so it needs delete authority on the destination: decided again
    after the wait, and a copy or a move whose authority went meanwhile does not replace."""
    world, _waiting, answer, _stats = _run(monkeypatch, kind, refuse="replace")
    assert answer["id"]
    ((_name, _thread, replace),) = world.worked
    assert replace is False
