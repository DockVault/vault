"""A public file link gives back its use when the server fails before the first byte of the file.

Redeeming a link spends one of its uses and mints a single-use grant; the download spends the grant.
When the server then cannot start the file (no transfer slot, the stored file missing, unreadable or
changed while it was read, its checksum wrong, any other error) the person received nothing, so the
use is given back and they can try again: exactly one, atomically, never below zero, and recorded in
the audit log. Once a byte of the file is on its way, or when the client leaves, the use stays spent,
which is what keeps a link capped at N from delivering more than N.

The real download handler runs here against a stand-in database that applies the two updates it may
send (the refund, and the completed-download count) to an in-memory link, and a stand-in for the stored
file that fails where each case says. tests/test_api_public_links_refund.py does the same live.
"""
import asyncio
import types
import uuid

import pytest
from fastapi import HTTPException
from sqlalchemy.dialects import postgresql

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from app.core import rate_limiter as R  # noqa: E402
from app.core.security import EncryptionError, ObjectChangedDuringRead  # noqa: E402
from app.core.transfer_admission import TransferAdmission, TransferBusy  # noqa: E402
from app.services.download_stream import ChecksumMismatch  # noqa: E402

pytestmark = pytest.mark.unit

ADDRESS = "192.0.2.10"
PIECES = [b"a" * 1000, b"b" * 1000, b"c" * 500]

REFUND_SQL = ("UPDATE public_links SET use_count=(public_links.use_count - 1) "
              "WHERE public_links.id = '{id}' AND public_links.use_count > 0")


class _Store:
    def __init__(self):
        self.data = {}

    def set(self, key, value, ex=None, nx=False):
        if nx and key in self.data:
            return None
        self.data[key] = value.encode()
        return True

    def get(self, key):
        return self.data.get(key)

    def delete(self, key):
        return 1 if self.data.pop(key, None) is not None else 0


class _Rows:
    def __init__(self, row):
        self._row = row

    def filter(self, *args, **kwargs):
        return self

    def first(self):
        return self._row


class _DB:
    """Reads come from the link and file rows; each update is compiled to SQL and applied to the link,
    so a test sees what the statement would do in the database, not only that one was sent."""

    def __init__(self, link, file_row):
        self.link, self.file_row, self.statements = link, file_row, []
        self.events = []

    def query(self, model, *more):
        return _Rows({S.PublicLink: self.link, S.File: self.file_row}.get(model))

    def execute(self, statement, *args, **kwargs):
        sql = str(statement.compile(dialect=postgresql.dialect(), compile_kwargs={"literal_binds": True}))
        sql = " ".join(sql.split())
        self.statements.append(sql)
        if sql == REFUND_SQL.format(id=self.link.id):
            if self.link.use_count > 0:
                self.link.use_count -= 1
                return types.SimpleNamespace(rowcount=1)
            return types.SimpleNamespace(rowcount=0)
        if sql.startswith("UPDATE public_links SET download_count=(public_links.download_count + 1)"):
            self.link.download_count += 1
            return types.SimpleNamespace(rowcount=1)
        raise AssertionError(f"unexpected statement: {sql}")

    def add(self, obj):
        pass

    def commit(self):
        pass

    def rollback(self):
        self.events.append("rollback")


class _Stored:
    """The opened file: its pieces, failing with `exc` at piece `fail_at` when given."""

    def __init__(self, pieces, fail_at=None, exc=None):
        self._pieces, self._fail_at, self._exc = pieces, fail_at, exc
        self.name, self.mime_type = "report.bin", "application/octet-stream"
        self.total_length = sum(len(p) for p in pieces)
        self.closed = False

    def chunks(self):
        for i, piece in enumerate(self._pieces):
            if i == self._fail_at:
                raise self._exc
            yield piece
        if self._fail_at == len(self._pieces):
            raise self._exc

    def close(self):
        self.closed = True


class _Request:
    """gone_after: the body's disconnect checks answer yes after that many. left: the client closed its
    connection before the server answered, so the request's channel holds its empty body and then the
    disconnect; otherwise the channel holds the body and then nothing, as for a client still there."""

    def __init__(self, gone_after=None, left=False):
        self.checks, self.gone_after, self.left = 0, gone_after, left
        self._messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def is_disconnected(self):
        self.checks += 1
        return self.gone_after is not None and self.checks > self.gone_after

    async def receive(self):
        if self._messages:
            return self._messages.pop(0)
        if self.left:
            return {"type": "http.disconnect"}
        await asyncio.Event().wait()


@pytest.fixture
def harness(monkeypatch):
    R._cb_record_success()
    store = _Store()
    monkeypatch.setattr(R.rate_limiter, "redis", store, raising=False)
    monkeypatch.setattr(R.rate_limiter, "check_rate_limit", lambda *a, **k: (True, 0, 0))
    monkeypatch.setattr(S, "get_client_ip", lambda request: ADDRESS)
    monkeypatch.setattr(S.note_link_policy, "public_file_links_enabled", lambda blob: True)
    monkeypatch.setattr(S, "folder_ancestry", lambda db, vault_id, folder_id: [])
    vault = types.SimpleNamespace(id=uuid.uuid4(), type="standard", password_hash=None)
    monkeypatch.setattr(S, "_publiclink_resolve_live", lambda db, link: (vault, object()))
    monkeypatch.setattr(S, "PermissionService", lambda db: object())
    audit = []

    class _Audit:
        def __init__(self, db):
            pass

        def log_action(self, **row):
            audit.append(row)

    monkeypatch.setattr(S, "AuditLogger", _Audit)
    admission = TransferAdmission(limit=2, max_waiting=0, wait_seconds=0)
    monkeypatch.setattr(S, "transfer_admission", admission)
    opened = {}

    def run(stored=None, open_error=None, busy=False, request=None, use_count=1, during_wait=None):
        """during_wait(link, db): called while the download waits for its transfer slot."""
        file_id = uuid.uuid4()
        token = "tok-" + uuid.uuid4().hex
        link = types.SimpleNamespace(
            id=uuid.uuid4(), token_hash=S._publiclink_token_hash(token), revoked=False, expires_at=None,
            max_uses=1, use_count=use_count, download_count=0, bytes_served=0, target_type="file",
            target_file_id=file_id, target_folder_id=None)
        file_row = types.SimpleNamespace(id=file_id, folder_id=None, password_hash=None)
        db = _DB(link, file_row)

        class _Service:
            def __init__(self, db, permissions):
                pass

            def _open_stored_file(self, file, vault_, file_id_, whole=True):
                assert whole is False
                if open_error is not None:
                    raise open_error
                opened["file"] = stored
                return stored

        monkeypatch.setattr(S, "VaultService", _Service)
        if busy:
            async def refuse():
                raise TransferBusy(retry_after=5, waiting=0, limit=2)
            monkeypatch.setattr(admission, "acquire", refuse)
        elif during_wait is not None:
            take = TransferAdmission.acquire.__get__(admission)

            async def wait():
                db.events.append("waits")
                during_wait(link, db)
                return await take()
            monkeypatch.setattr(admission, "acquire", wait)
        grant = S._publiclink_issue_grant(link.id, ADDRESS)
        request = request or _Request()
        out = types.SimpleNamespace(link=link, db=db, store=store, audit=audit, admission=admission,
                                    status=None, body=b"", error=None, token=token, file_id=file_id,
                                    grant=grant)

        async def go():
            try:
                response = await S.download_public_link(token, file_id, request, db, x_download_grant=grant)
            except HTTPException as refused:
                out.status, out.error = refused.status_code, refused
                return
            out.status = response.status_code
            sent = []

            async def receive():
                return {"type": "http.request", "body": b"", "more_body": False}

            async def send(message):
                sent.append(message)

            await response({"type": "http", "asgi": {"spec_version": "2.4"}}, receive, send)
            out.body = b"".join(m.get("body", b"") for m in sent if m["type"] == "http.response.body")

        run_coroutine(go())
        out.refunds = [r for r in audit if r["action"] == "public_link_use_refunded"]
        out.completed = [r for r in audit if r["action"] == "public_link_download_completed"]
        return out

    return run


# name -> (how the server fails, the reason the refund records, the status the person gets)
BEFORE_THE_FIRST_BYTE = {
    "the stored file is missing": (dict(open_error=S.FileNotFoundError("gone")), "file_missing", 404),
    "it cannot be decrypted": (dict(open_error=S.FileServiceError("Failed to decrypt file")), "unreadable", 404),
    "its first record fails authentication": (
        dict(stored=_Stored(PIECES, 0, EncryptionError("tag"))), "unreadable", 404),
    "its one record does not match its checksum": (
        dict(stored=_Stored(PIECES[:1], 0, ChecksumMismatch("sum"))), "checksum_mismatch", 404),
    "an empty file does not match its checksum": (
        dict(stored=_Stored([], 0, ChecksumMismatch("sum"))), "checksum_mismatch", 404),
    "it was replaced while it was read": (
        dict(stored=_Stored(PIECES, 0, ObjectChangedDuringRead("moved"))), "changed_during_read", 404),
    "the disk refuses the read": (dict(open_error=PermissionError(13, "denied")), "read_error", 404),
    "an internal error": (dict(open_error=RuntimeError("a bug")), "internal_error", 404),
    "no transfer slot is free": (dict(busy=True), "busy", 503),
}


@pytest.mark.parametrize("case", list(BEFORE_THE_FIRST_BYTE))
def test_a_server_failure_before_the_first_byte_gives_back_exactly_one_use(harness, case):
    how, reason, status = BEFORE_THE_FIRST_BYTE[case]
    out = harness(**how)
    assert out.status == status, case
    assert out.body == b""
    assert out.link.use_count == 0, "the use was not given back"
    assert out.db.statements.count(REFUND_SQL.format(id=out.link.id)) == 1
    assert [r["status"] for r in out.refunds] == ["success"]
    assert out.refunds[0]["details"]["reason"] == reason
    assert out.refunds[0]["details"]["public_link_id"] == str(out.link.id)
    assert out.refunds[0]["ip_address"] == ADDRESS
    assert out.store.data == {}, "the grant must stay used: a retry redeems again"
    assert not out.admission._live, "the transfer slot was not given back"
    stored = how.get("stored")
    if stored is not None:
        assert stored.closed
    if status == 404:
        assert out.error.detail == "This file is not available."
    assert out.completed == []


@pytest.mark.parametrize("case", list(BEFORE_THE_FIRST_BYTE))
def test_a_client_that_left_before_a_server_failure_keeps_the_use_spent(harness, case):
    # The same failures, for a client that closed its connection before the server answered: one that
    # gave up while it waited for a transfer slot, above all. Its use is not given back; the download is
    # recorded as ended with its client gone, nothing sent, with the failure that ended it.
    how, reason, status = BEFORE_THE_FIRST_BYTE[case]
    out = harness(request=_Request(left=True), **how)
    assert out.status == status, case
    assert out.body == b""
    assert out.link.use_count == 1, "a use was given back to a client that had left"
    assert REFUND_SQL.format(id=out.link.id) not in out.db.statements and out.refunds == []
    assert [(r["status"], r["details"]["outcome"], r["details"]["bytes_sent"], r["details"]["reason"])
            for r in out.completed] == [("failed", "disconnected", 0, reason)]
    assert out.completed[0]["details"]["public_link_id"] == str(out.link.id)
    assert out.store.data == {}, "the grant must stay used"
    assert not out.admission._live, "the transfer slot was not given back"
    stored = how.get("stored")
    if stored is not None:
        assert stored.closed


def test_a_failure_whose_client_cannot_be_asked_still_gives_the_use_back(harness):
    # When the request's channel cannot be read, the server cannot say the client left, so a failure
    # of its own keeps its refund.
    class _Unreadable(_Request):
        async def receive(self):
            raise RuntimeError("no channel")

    out = harness(open_error=S.FileNotFoundError("gone"), request=_Unreadable())
    assert out.status == 404 and out.link.use_count == 0
    assert [(r["status"], r["details"]["reason"]) for r in out.refunds] == [("success", "file_missing")]
    assert out.completed == []


def _through_the_header_middleware(endpoint, left):
    """Run `endpoint(request)` behind the application's own security-header middleware (a
    BaseHTTPMiddleware), for a client that has left or one still there, and return what it found."""
    from fastapi import FastAPI, Request

    inner = FastAPI()
    found = {}

    @inner.get("/probe")
    async def probe(request: Request):
        found["answer"] = await endpoint(request)
        return {}

    messages = [{"type": "http.request", "body": b"", "more_body": False}]

    async def receive():
        if messages:
            return messages.pop(0)
        if left:
            return {"type": "http.disconnect"}
        await asyncio.Event().wait()

    async def send(message):
        pass

    scope = {"type": "http", "asgi": {"version": "3.0", "spec_version": "2.4"}, "http_version": "1.1",
             "method": "GET", "scheme": "http", "path": "/probe", "raw_path": b"/probe", "query_string": b"",
             "root_path": "", "headers": [(b"host", b"testserver")], "client": (ADDRESS, 50000),
             "server": ("testserver", 80)}
    run_coroutine(S.SecurityHeadersMiddleware(app=inner)(scope, receive, send), timeout=20)
    return found["answer"]


@pytest.mark.parametrize("left", [True, False])
def test_the_server_can_tell_a_client_that_left_behind_its_middleware(left):
    # What the download asks before it gives a use back, behind the middleware the application really
    # has: a client that closed its connection reads as gone, one still there as still there.
    assert _through_the_header_middleware(S._publiclink_client_left, left) is left


def test_the_disconnect_question_starlette_offers_cannot_tell_behind_that_middleware():
    # The control for the test above: it shows this set-up reproduces what made the download read the
    # request's channel itself. Behind the same middleware, the framework's own question says a client
    # that has left is still there. If this starts to fail, the framework can tell now, and the
    # download's question may be simplified to it.
    async def asked(request):
        return await request.is_disconnected()

    assert _through_the_header_middleware(asked, left=True) is False


def test_it_waits_for_its_slot_holding_no_read_transaction(harness):
    # A download waiting for a slot held its read transaction, so a connection: enough of them beside the
    # transfers streaming held the whole pool. Nothing is pending at that point (the gates only read).
    stored = _Stored(PIECES)
    out = harness(stored=stored, during_wait=lambda link, db: None)
    assert out.status == 200 and out.body == b"".join(PIECES)
    assert out.db.events == ["rollback", "waits"], out.db.events


def _revoke(link, db):
    link.revoked = True


def _delete_the_file(link, db):
    db.file_row = None


def _protect_the_file(link, db):
    db.file_row.password_hash = "a file password"


def _close_the_vault(monkeypatch):
    def closed(link, db):
        monkeypatch.setattr(S, "_publiclink_resolve_live", lambda db_, link_: None)
    return closed


# What changed while the download waited for its slot
CHANGED_WHILE_IT_WAITED = {
    "the link was revoked": lambda monkeypatch: _revoke,
    "the file was deleted": lambda monkeypatch: _delete_the_file,
    "the file was given a password": lambda monkeypatch: _protect_the_file,
    "the vault or its owner no longer lets it through": _close_the_vault,
}


@pytest.mark.parametrize("case", list(CHANGED_WHILE_IT_WAITED))
def test_a_gate_that_closed_while_it_waited_refuses_it_and_gives_the_use_back(harness, monkeypatch, case):
    # The gates are asked again once the download has its slot. Nothing was delivered, so the use goes back
    # (the grant stays used), and the slot is given back.
    stored = _Stored(PIECES)
    out = harness(stored=stored, during_wait=CHANGED_WHILE_IT_WAITED[case](monkeypatch))
    assert out.status == 404 and out.error.detail == "This file is not available.", case
    assert out.body == b""
    assert stored.closed is False, "the file was opened"
    assert out.link.use_count == 0, "the use was not given back"
    assert [(r["status"], r["details"]["reason"]) for r in out.refunds] == [("success", "no_longer_available")]
    assert out.store.data == {}, "the grant must stay used"
    assert not out.admission._live, "the transfer slot was not given back"
    assert out.completed == []


def test_a_completed_download_keeps_its_use_and_counts_the_download(harness):
    stored = _Stored(PIECES)
    out = harness(stored=stored)
    assert out.status == 200 and out.body == b"".join(PIECES)
    assert (out.link.use_count, out.link.download_count) == (1, 1)
    assert out.refunds == []
    assert [r["details"]["outcome"] for r in out.completed] == ["completed"]
    assert stored.closed and not out.admission._live


@pytest.mark.parametrize("fail_at", [1, 2, 3])
def test_a_failure_once_the_first_byte_is_on_its_way_keeps_the_use_spent(harness, fail_at):
    # Including the hold-back's checksum failure at the end of a file of several records: the person
    # has part of the file, so the use is not given back (that is what keeps a capped link capped).
    exc = ChecksumMismatch("sum") if fail_at == 3 else EncryptionError("tag")
    out = harness(stored=_Stored(PIECES, fail_at, exc))
    assert out.status == 200
    assert out.body == b"".join(PIECES[:fail_at])
    assert (out.link.use_count, out.link.download_count) == (1, 0)
    assert out.refunds == [] and REFUND_SQL.format(id=out.link.id) not in out.db.statements
    assert [r["details"]["outcome"] for r in out.completed] == [type(exc).__name__]


@pytest.mark.parametrize("gone_after", [0, 1, 2])
def test_a_client_that_leaves_keeps_the_use_spent(harness, gone_after):
    # gone_after=0: it left before the first byte went out; 1 and 2: after one or two pieces.
    out = harness(stored=_Stored(PIECES), request=_Request(gone_after=gone_after))
    assert out.status == 200
    assert out.body == b"".join(PIECES[:gone_after])
    assert (out.link.use_count, out.link.download_count) == (1, 0)
    assert out.refunds == []
    assert [r["details"]["outcome"] for r in out.completed] == ["disconnected"]
    assert not out.admission._live


def test_a_refund_never_takes_the_count_below_zero(harness):
    # A count already at zero (an earlier refund, an edit in the database): the guarded update matches
    # nothing, nothing is given back, and the audit row says the refund did not happen.
    out = harness(open_error=S.FileNotFoundError("gone"), use_count=0)
    assert out.status == 404
    assert out.link.use_count == 0
    assert [r["status"] for r in out.refunds] == ["failure"]


def test_a_used_grant_cannot_earn_a_second_refund(harness):
    # The same grant sent again is refused at the grant, before anything that could give a use back:
    # one grant, one use spent, at most one use returned.
    out = harness(open_error=S.FileNotFoundError("gone"), use_count=2)
    assert out.link.use_count == 1 and len(out.refunds) == 1

    async def retry():
        try:
            await S.download_public_link(out.token, out.file_id, _Request(), out.db,
                                         x_download_grant=out.grant)
        except HTTPException as refused:
            return refused.status_code

    assert run_coroutine(retry()) == 404
    assert len([r for r in out.audit if r["action"] == "public_link_use_refunded"]) == 1
    assert out.link.use_count == 1


def test_the_response_cleans_up_when_its_body_never_starts(harness, monkeypatch):
    # A client gone before the headers went out: the body's generator never runs, so its own finally
    # never does. The response's close still frees the slot, closes the file and records the outcome,
    # and gives nothing back.
    stored = _Stored(PIECES)
    seen = {}
    real = S._ClosingStreamingResponse.__call__

    async def headers_fail(self, scope, receive, send):
        async def broken(message):
            raise OSError("the client went away")
        seen["called"] = True
        try:
            await real(self, scope, receive, broken)
        except Exception:
            pass

    monkeypatch.setattr(S._ClosingStreamingResponse, "__call__", headers_fail)
    out = harness(stored=stored)
    assert seen["called"] and out.status == 200
    assert stored.closed and not out.admission._live
    assert (out.link.use_count, out.link.download_count) == (1, 0)
    assert out.refunds == []
    assert [r["details"]["outcome"] for r in out.completed] == ["incomplete"]
