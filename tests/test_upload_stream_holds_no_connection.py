"""A chunk write holds no database connection while the client sends the body.

Both chunk endpoints resolve and authorise on the request's one Session, whose first query checks
a pool connection out for the transaction that begins there; they then stream the body at the
client's pace -- unbounded by design -- and only afterwards lock, publish and commit. A slow client
was a pool slot held for its whole transfer, and enough of them starved every other request.

Now the read transaction ends before the first byte of body is read (``_release_db_before_streaming``),
and a short transaction after the body re-validates and publishes. The engine here is Postgres-only,
so these tests drive the endpoint functions themselves with a STAND-IN Session that models what the
real one does with its connection: the first query checks one out, rollback/commit/close return it,
and -- the part that bites -- touching an attribute of an instance the ended transaction expired
refreshes it, which is a checkout. The body is a slow async stream that samples the checkout count
at every piece. The stand-in was validated as an instrument by running it against the code as it
was before this change, where it reports the connection held throughout (see the record).
"""
from __future__ import annotations

import asyncio
import uuid
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env  # noqa: E402

set_bare_api_env()

import app.api.api_server as S  # noqa: E402
from fastapi import HTTPException  # noqa: E402
# Not asyncio.run(): after the browser tests a loop is left running in the main thread for the
# rest of the session, and this module sorts after them. See tests/_async_run.py.
from _async_run import call_with_a_running_loop_in_a_worker, run_coroutine  # noqa: E402

pytestmark = pytest.mark.unit


# ---- the instrument -----------------------------------------------------------------------------------

class _Pool:
    """How many connections the request's Session has out, and what the stream saw."""
    def __init__(self):
        self.checked_out = 0
        self.seen_during_stream = []
        self.transactions = 0

    def out(self):
        self.checked_out += 1
        self.transactions += 1

    def back(self):
        assert self.checked_out > 0, "returned a connection that was not out"
        self.checked_out -= 1


class _Row:
    """An ORM instance: reading an attribute after the transaction that loaded it has ended is a
    lazy refresh, which checks a connection out (that is what SQLAlchemy does with expire_on_commit
    and a rollback alike)."""
    def __init__(self, session, **fields):
        object.__setattr__(self, "_session", session)
        object.__setattr__(self, "_fields", dict(fields))
        object.__setattr__(self, "_expired", False)

    def __getattr__(self, name):
        fields = object.__getattribute__(self, "_fields")
        if name not in fields:
            raise AttributeError(name)
        if object.__getattribute__(self, "_expired"):
            object.__getattribute__(self, "_session")._begin()     # the refresh
            object.__setattr__(self, "_expired", False)
        return fields[name]

    def __setattr__(self, name, value):
        object.__getattribute__(self, "_fields")[name] = value


class _Query:
    def __init__(self, session, models):
        self.session, self.models = session, models

    def filter(self, *a, **k):
        return self

    def join(self, *a, **k):
        return self

    def with_for_update(self):
        self.session.locked = True
        return self

    def first(self):
        return self.session.rows_for(self.models[0])

    def all(self):
        r = self.first()
        return [r] if r is not None else []

    def count(self):
        return 0


class _StandInSession:
    def __init__(self, pool, provider):
        self.pool, self.provider = pool, provider
        self._in_tx = False
        self.loaded = []
        self.locked = False

    def _begin(self):
        if not self._in_tx:
            self._in_tx = True
            self.pool.out()

    def query(self, *models):
        self._begin()
        return _Query(self, models)

    def rows_for(self, model):
        row = self.provider(model, self)
        if row is not None:
            self.loaded.append(row)
        return row

    def _end(self):
        if self._in_tx:
            self._in_tx = False
            self.pool.back()
            for row in self.loaded:
                object.__setattr__(row, "_expired", True)

    def rollback(self):
        self._end()

    def commit(self):
        self._end()

    def close(self):
        self._end()

    def add(self, obj):
        self._begin()

    def refresh(self, obj):
        self._begin()


def _slow_body(pool, pieces=4):
    async def gen():
        for i in range(pieces):
            await asyncio.sleep(0)
            pool.seen_during_stream.append(pool.checked_out)
            yield b"x" * 16
    return gen()


class _Request:
    def __init__(self, body, headers=None):
        self._body, self.headers = body, headers or {}

    def stream(self):
        return self._body


async def _fake_seal(stream, dest_path, limit, session_id, chunk_index):
    n = 0
    async for piece in stream:
        n += len(piece)
    Path(dest_path).write_bytes(b"sealed" * 4)
    return n, "digest"


# ---- the receiver endpoint --------------------------------------------------------------------------------

def _receiver_world(monkeypatch, tmp_path, pool, *, revalidate_ok=True, locked_status="active"):
    sid = uuid.uuid4()
    vid = uuid.uuid4()
    state = {"resolutions": 0}

    def provider(model, session):
        if model is S.ChunkedUploadSession:
            return _Row(session, id=sid, status=locked_status, vault_id=vid, total_chunks=3, total_size=48,
                        bytes_received=0, filename="streamed.bin")
        return None

    db = _StandInSession(pool, provider)

    def resolve(db_, token, session_id):
        # The shipped resolver's six lookups on the request's Session, as one query on the stand-in.
        state["resolutions"] += 1
        row = db_.query(S.ChunkedUploadSession).first()
        if state["resolutions"] > 1 and not revalidate_ok:
            return None
        vault = _Row(db_, id=vid)
        return object(), row, vault, object()

    monkeypatch.setattr(S, "_receiver_resolve_session", resolve)
    monkeypatch.setattr(S, "PermissionService", lambda db_: object())
    monkeypatch.setattr(S, "VaultService", lambda db_, ps: object())
    monkeypatch.setattr(S, "_upload_session_dir", lambda vs, s: tmp_path / "sess")
    monkeypatch.setattr(S, "seal_stream_to_file", _fake_seal)
    monkeypatch.setattr(S, "sealed_plaintext_size", lambda p: 16)
    monkeypatch.setattr(S, "_chunk_hash_path", lambda d, i: d / f".hash_{i:06d}")
    return db, sid, state


def test_the_receiver_chunk_write_holds_no_connection_while_the_body_streams(monkeypatch, tmp_path):
    pool = _Pool()
    db, sid, state = _receiver_world(monkeypatch, tmp_path, pool)
    out = run_coroutine(S.receiver_upload_chunk("tok", sid, 1, _Request(_slow_body(pool)), db=db))
    # (mutation: the release before the stream removed -> the stream sees 1 throughout -> red.
    #  mutation: a scalar read from the expired row during the stream -> the refresh is a checkout
    #  the stream sees -> red.)
    assert pool.seen_during_stream == [0, 0, 0, 0], pool.seen_during_stream
    # Published: the chunk is in place, the counters recomputed, and the last transaction ended.
    assert out["received"] == 1 and out["total"] == 3 and (tmp_path / "sess" / "chunk_000001").exists()
    assert pool.checked_out == 0
    # Two transactions: the one before the body, and the short one after it.
    assert pool.transactions == 2 and state["resolutions"] == 2


def test_the_receiver_chunk_is_refused_and_not_published_when_the_binding_is_gone_after_the_stream(monkeypatch, tmp_path):
    # Revoked / kill switch / owner locked out / session closed while the body streamed: the
    # resolution runs again after the body and fails -> the uniform 404, the sealed bytes unlinked,
    # nothing published, the counters untouched.
    pool = _Pool()
    db, sid, state = _receiver_world(monkeypatch, tmp_path, pool, revalidate_ok=False)
    with pytest.raises(HTTPException) as e:
        run_coroutine(S.receiver_upload_chunk("tok", sid, 1, _Request(_slow_body(pool)), db=db))
    assert e.value.status_code == 404 and e.value.detail == "This upload is not available."
    sess = tmp_path / "sess"
    assert not (sess / "chunk_000001").exists(), "a refused chunk was published"
    assert not list(sess.glob(".chunk_*.part")), "the refused bytes were left on disk"
    assert pool.seen_during_stream == [0, 0, 0, 0] and state["resolutions"] == 2


def test_the_receiver_chunk_is_refused_when_the_locked_row_is_no_longer_active(monkeypatch, tmp_path):
    # The resolution passes but the row taken under the lock is not active any more (closed in the
    # instant between): refused the same way. (mutation: the status check under the lock removed
    # -> published -> red.)
    pool = _Pool()
    db, sid, _ = _receiver_world(monkeypatch, tmp_path, pool, locked_status="completed")
    with pytest.raises(HTTPException) as e:
        run_coroutine(S.receiver_upload_chunk("tok", sid, 1, _Request(_slow_body(pool)), db=db))
    assert e.value.status_code == 404
    assert not (tmp_path / "sess" / "chunk_000001").exists()


# ---- the authenticated endpoint ---------------------------------------------------------------------------

def _auth_world(monkeypatch, tmp_path, pool, *, principal_ok=True, locked_status="active", other_user=False,
                permission_ok=True, cap_ok=True, vault_ok=True, folder_ok=True, password_changed=False):
    sid, vid, uid = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
    calls = {"judged": 0, "loads": 0}

    def provider(model, session):
        if model is S.ChunkedUploadSession:
            calls["loads"] += 1
            # The row as first loaded is active and this user's -- the request is admitted; what
            # the LOCKED load after the body sees is the scenario's (closed, or another user's).
            first = calls["loads"] == 1
            return _Row(session, id=sid, status=("active" if first else locked_status), vault_id=vid,
                        user_id=(uid if first or not other_user else uuid.uuid4()), folder_id=None,
                        total_chunks=3, total_size=48, bytes_received=0, blob_id=None, expires_at=None,
                        filename="streamed.bin")
        return None

    db = _StandInSession(pool, provider)
    user = _Row(db, id=uid)

    async def judge(credentials, db_):
        calls["judged"] += 1
        db_.query(S.User).first()          # the shipped dependency's lookups, on the same Session
        if not principal_ok:
            raise HTTPException(status_code=401, detail="Invalid authentication credentials")
        return user

    class _VS:
        def __init__(self, db_, ps):
            pass

        def get_vault(self, *a, **k):
            db.query(S.Vault).first()
            calls["vault"] = calls.get("vault", 0) + 1
            # WITHDRAWN WHILE THE BODY STREAMED, so the FIRST call (which admits the request) must
            # succeed and the second must not -- a stub that refused both would refuse before the
            # body and prove nothing about the window this test exists for.
            if not vault_ok and calls["vault"] > 1:
                raise S.PermissionDeniedError("no longer a member")
            return _Row(db, id=vid)

    monkeypatch.setattr(S, "get_current_user", judge)
    # The re-authorisation asks the same guards the pre-body path asked; the two it imports from
    # their own modules are stubbed there, so a guard that stopped being asked shows up as a
    # missing call rather than as an import error.
    import app.core.endpoint_permissions as _ep
    import app.core.temp_scope as _ts

    def _perm(db_, user_, group, kwargs=None):
        calls["permission"] = calls.get("permission", 0) + 1
        if not permission_ok:
            raise HTTPException(status_code=403, detail="Required permission: %s" % group)

    def _cap(user_, vault_, cap):
        calls["cap"] = calls.get("cap", 0) + 1
        if not cap_ok:
            raise HTTPException(status_code=403, detail="Temporary credential scope does not permit this action")

    monkeypatch.setattr(_ep, "check_endpoint_permission", _perm)
    monkeypatch.setattr(_ts, "require_cap", _cap)
    monkeypatch.setattr(S, "PermissionService", lambda db_: object())
    monkeypatch.setattr(S, "VaultService", _VS)
    def _folder(db_, user_, vault_, folder_):
        calls["folder"] = calls.get("folder", 0) + 1
        if not folder_ok and calls["folder"] > 1:      # withdrawn mid-body, as above
            raise S.PermissionDeniedError("Scope does not permit this folder")

    monkeypatch.setattr(S, "require_folder_scope", _folder)
    # The vault's password credential: the same value before and after unless the test moves it.
    _fingerprints = iter(["hash-before", "hash-after" if password_changed else "hash-before"])
    monkeypatch.setattr(S, "_vault_credential_fingerprint", lambda db_, v: next(_fingerprints, "hash-before"))
    monkeypatch.setattr(S, "_session_principal", lambda u: True)
    monkeypatch.setattr(S, "_upload_session_dir", lambda vs, s: tmp_path / "sess")
    monkeypatch.setattr(S, "seal_stream_to_file", _fake_seal)
    monkeypatch.setattr(S, "sealed_plaintext_size", lambda p: 16)
    monkeypatch.setattr(S, "_chunk_hash_path", lambda d, i: d / f".hash_{i:06d}")
    return db, sid, vid, user, calls


def _raw(endpoint):
    fn = endpoint
    while hasattr(fn, "__wrapped__"):
        fn = fn.__wrapped__
    return fn


def test_the_authenticated_chunk_write_holds_no_connection_while_the_body_streams(monkeypatch, tmp_path):
    pool = _Pool()
    db, sid, vid, user, calls = _auth_world(monkeypatch, tmp_path, pool)
    # As the request would have arrived: the principal already judged on this Session (one checkout).
    run_coroutine(S.get_current_user(None, db))
    req = _Request(_slow_body(pool), headers={"authorization": "Bearer t"})
    out = run_coroutine(_raw(S.upload_chunk)(vid, sid, 1, req, current_user=user, db=db, x_vault_password=None))
    assert pool.seen_during_stream == [0, 0, 0, 0], pool.seen_during_stream
    assert out["received"] == 1 and (tmp_path / "sess" / "chunk_000001").exists()
    assert pool.checked_out == 0 and pool.transactions == 2
    # The principal was judged twice: once to admit the request, once after the body.
    assert calls["judged"] == 2


def test_the_authenticated_chunk_is_refused_when_the_principal_is_no_longer_valid_after_the_stream(monkeypatch, tmp_path):
    # Deactivated, locked, session revoked or the temporary credential withdrawn while the body
    # streamed: the same dependency that admitted the request refuses it now, with its 401; the
    # sealed bytes are unlinked and nothing is published.
    pool = _Pool()
    db, sid, vid, user, calls = _auth_world(monkeypatch, tmp_path, pool, principal_ok=False)
    req = _Request(_slow_body(pool), headers={"authorization": "Bearer t"})
    with pytest.raises(HTTPException) as e:
        run_coroutine(_raw(S.upload_chunk)(vid, sid, 1, req, current_user=user, db=db, x_vault_password=None))
    assert e.value.status_code == 401
    sess = tmp_path / "sess"
    assert not (sess / "chunk_000001").exists() and not list(sess.glob(".chunk_*.part"))
    assert calls["judged"] == 1 and pool.seen_during_stream == [0, 0, 0, 0]


@pytest.mark.parametrize("how", ["closed", "other-user"])
def test_the_authenticated_chunk_is_refused_when_the_locked_row_is_not_this_active_session(monkeypatch, tmp_path, how):
    pool = _Pool()
    db, sid, vid, user, _ = _auth_world(monkeypatch, tmp_path, pool,
                                        locked_status="completed" if how == "closed" else "active",
                                        other_user=(how == "other-user"))
    req = _Request(_slow_body(pool), headers={"authorization": "Bearer t"})
    with pytest.raises(HTTPException) as e:
        run_coroutine(_raw(S.upload_chunk)(vid, sid, 1, req, current_user=user, db=db, x_vault_password=None))
    assert e.value.status_code == (409 if how == "closed" else 404)
    assert not (tmp_path / "sess" / "chunk_000001").exists()


# ---- the shape, as a smoke alarm ----------------------------------------------------------------------------

def test_the_boundary_sits_between_the_last_read_and_the_first_byte_in_both_endpoints():
    import inspect
    for fn in (S.receiver_upload_chunk, _raw(S.upload_chunk)):
        src = "\n".join(ln for ln in inspect.getsource(fn).splitlines() if not ln.lstrip().startswith("#"))
        release = src.index("_release_db_before_streaming(db)")
        seal = src.index("await seal_stream_to_file(")
        assert release < seal, fn.__name__
        # Nothing between the boundary and the seal reads an ORM instance or the Session.
        between = src[release:seal]
        assert "session." not in between and "db." not in between and "current_user." not in between, between
        # ... and the seal is handed the copied id, not the instance's.
        assert "_sid, chunk_index)" in src[seal:seal + 200], fn.__name__


# ---- the way the coroutines are run --------------------------------------------------------------------------

def test_the_coroutines_run_even_when_a_loop_is_already_running_in_the_calling_thread():
    # After the browser tests, an event loop is left running in the main thread for the rest of the
    # session; this module sorts after them. `asyncio.run()` refuses in that state, and every local
    # lane hides it (they deselect the browser tests). The same state is made here on purpose --
    # IN A WORKER THREAD. The running-loop slot is thread-local, and the main thread's slot belongs
    # to Playwright's suspended dispatcher for the rest of the session: the first version of this
    # test set and then cleared the MAIN thread's slot, after which the dispatcher's next callback
    # raised "is not the running loop", the driver's reply never landed, and the session's
    # browser.close() at teardown blocked until the job cap -- twice. Nothing here may touch the
    # main thread's slot: the worker with the running loop is the helper's own (the one place a
    # test may set that slot, on a thread it owns), and the last assertion holds that.
    main_slot_before = asyncio.events._get_running_loop()

    async def two():
        await asyncio.sleep(0)
        return 2

    async def boom():
        raise HTTPException(status_code=418, detail="teapot")

    def in_worker():
        refused = two()
        with pytest.raises(RuntimeError, match="running event loop"):
            asyncio.run(refused)
        refused.close()                                 # never started; do not let it warn
        ran = run_coroutine(two())
        # ... and an exception inside the coroutine comes back as itself, not as a thread's silence.
        with pytest.raises(HTTPException) as raised:
            run_coroutine(boom())
        return ran, raised.value.status_code

    assert call_with_a_running_loop_in_a_worker(in_worker, timeout=30) == (2, 418)
    assert asyncio.events._get_running_loop() is main_slot_before, "the main thread's running-loop slot was touched"


# ---- the live pin's guard, armed ---------------------------------------------------------------------------

def test_the_live_controls_guard_gives_up_within_its_bound_when_the_container_is_not_there():
    # The live pin (tests/test_upload_stream_pool_live.py) opens a transaction inside the API
    # container as its positive control, and SKIPS with a reason when the container cannot run it.
    # A guard is only real once its trigger has been made to happen: point it at a container that
    # does not exist and it must come back -- with a reason, inside the bound -- rather than block.
    # (The first version blocked on an unbounded readline one line before its skip, and took a
    # 45-minute job with it.) Needs no stack: docker refuses at once, or is absent, and either is a
    # reason.
    import time
    from conftest import unique
    from test_upload_stream_pool_live import open_transaction_in_container
    started = time.monotonic()
    name = "no-such-container-" + unique("x")
    proc, reason = open_transaction_in_container(name, ready_timeout=8)
    took = time.monotonic() - started
    assert proc is None and reason, (proc, reason)
    assert took < 8 + 15, "the control did not give up inside its bound: %.1fs" % took
    assert name in reason or "docker" in reason.lower(), reason


@pytest.mark.parametrize("child", ["silent", "wrong-word"])
def test_the_live_controls_guard_gives_up_on_a_child_that_starts_and_never_says_open(child):
    # The hazard that actually took the job: the child STARTS (docker is there, the container is
    # there) and then never prints -- a stuck import, a stuck connect. And its cousin: it prints
    # the wrong thing, with the real reason on stderr. Both must come back inside the bound, with
    # the child killed and stderr in the reason.
    import sys
    import time
    from test_upload_stream_pool_live import open_transaction_in_container
    if child == "silent":
        script = "import time; time.sleep(60)"
    else:
        script = ("import sys, time; sys.stderr.write('ImportError: no such module' + chr(10)); "
                  "print('nope', flush=True); time.sleep(60)")
    started = time.monotonic()
    proc, reason = open_transaction_in_container("ignored", ready_timeout=3,
                                                 command=[sys.executable, "-c", script])
    took = time.monotonic() - started
    assert proc is None and reason, (proc, reason)
    assert took < 3 + 12, "the control did not give up inside its bound: %.1fs" % took
    if child == "silent":
        assert "never printed 'open' within 3s" in reason, reason
    else:
        assert "printed 'nope'" in reason and "ImportError: no such module" in reason, reason


# ---- what the world may have changed while the body streamed -------------------------------------
# The principal was already re-judged (above). These are the AUTHORISATION elements: each one exists
# to stop what this principal is doing, so each must also stop a transfer already in flight. Every
# leg asserts the same two things -- the request is refused, and nothing is left behind: no published
# chunk, and no staged `.part` (the cleanup's property, asserted here rather than separately because
# "refused" and "published nothing" are one claim).

@pytest.mark.parametrize("withdrawn", [
    "permission",     # the FILE_UPLOAD endpoint permission removed
    "cap",            # the temporary credential's file.upload capability narrowed away
    "vault",          # membership removed, or the vault taken out of a credential's scope
    "folder",         # the target folder taken out of the credential's id scope
    "password",       # the vault's password set, cleared or rotated
])
def test_an_authorisation_withdrawn_while_the_body_streamed_refuses_and_publishes_nothing(
        monkeypatch, tmp_path, withdrawn):
    pool = _Pool()
    kw = {
        "permission": {"permission_ok": False},
        "cap": {"cap_ok": False},
        "vault": {"vault_ok": False},
        "folder": {"folder_ok": False},
        "password": {"password_changed": True},
    }[withdrawn]
    db, sid, vid, user, calls = _auth_world(monkeypatch, tmp_path, pool, **kw)
    req = _Request(_slow_body(pool), headers={"authorization": "Bearer t"})
    # The vault and folder gates raise the domain error the app's handler turns into a 403 at the
    # HTTP layer; the others raise the HTTPException directly. Either way the request is refused.
    expected = S.PermissionDeniedError if withdrawn in ("vault", "folder") else HTTPException
    with pytest.raises(expected) as e:
        run_coroutine(_raw(S.upload_chunk)(vid, sid, 1, req, current_user=user, db=db, x_vault_password=None))
    if expected is HTTPException:
        assert e.value.status_code == (409 if withdrawn == "password" else 403), (withdrawn, e.value.detail)
    sess = tmp_path / "sess"
    assert not (sess / "chunk_000001").exists(), withdrawn
    assert not list(sess.glob(".chunk_*.part")), (withdrawn, "a staged .part survived the refusal")
    # The body still streamed without holding a connection: the re-check is after it, not before.
    assert pool.seen_during_stream == [0, 0, 0, 0], pool.seen_during_stream


def test_every_guard_the_request_passed_is_asked_again_after_the_body(monkeypatch, tmp_path):
    # Not "a refusal is possible" but "each one is actually consulted": the counts are the evidence
    # that no element was quietly dropped from the re-check. (mutation: delete any one call from
    # _reauthorize_after_body -> its count stays at 1 -> red.)
    pool = _Pool()
    db, sid, vid, user, calls = _auth_world(monkeypatch, tmp_path, pool)
    run_coroutine(S.get_current_user(None, db))
    req = _Request(_slow_body(pool), headers={"authorization": "Bearer t"})
    run_coroutine(_raw(S.upload_chunk)(vid, sid, 1, req, current_user=user, db=db, x_vault_password=None))
    assert calls["judged"] == 2, calls            # the principal: once to admit, once after the body
    assert calls["permission"] == 1, calls        # the endpoint permission (the decorator ran the first)
    assert calls["cap"] == 1, calls
    assert calls["vault"] == 2, calls             # vault access: pre-body, and again after
    assert calls["folder"] == 2, calls


def test_a_pool_or_lock_timeout_after_the_body_leaves_no_staged_bytes(monkeypatch, tmp_path):
    # The path an exception list could not cover. The FIRST statement after the connection
    # handback is a DB touch; a pool or lock timeout there raises OperationalError, which is not an
    # HTTPException, so the old `except HTTPException` let it past and the sealed `.part` survived.
    # It was invisible twice over: the accounting globs `chunk_*`, which does not match
    # `.chunk_NNNNNN.<hex>.part`, and the orphan sweep skips a session that is still active.
    from sqlalchemy.exc import OperationalError
    pool = _Pool()
    db, sid, vid, user, calls = _auth_world(monkeypatch, tmp_path, pool)

    async def _timeout(credentials, db_):
        raise OperationalError("SELECT 1", {}, Exception("QueuePool limit reached, timed out"))

    monkeypatch.setattr(S, "get_current_user", _timeout)
    req = _Request(_slow_body(pool), headers={"authorization": "Bearer t"})
    with pytest.raises(OperationalError):
        run_coroutine(_raw(S.upload_chunk)(vid, sid, 1, req, current_user=user, db=db, x_vault_password=None))
    sess = tmp_path / "sess"
    assert not list(sess.glob(".chunk_*.part")), "the staged .part survived a pool timeout"
    assert not (sess / "chunk_000001").exists()


def test_the_credential_comparison_rests_on_a_salt_that_makes_the_same_password_hash_differently():
    # THE HIDDEN PREMISE, made observable. The post-body check COMPARES the vault's stored password
    # hash with the one captured before the body instead of re-verifying the caller's password (see
    # _reauthorize_after_body for why: re-verifying would run an Argon2 KDF and a throttle round
    # trip per chunk, against the bucket the vault's owner shares). That comparison catches a
    # password re-set to the SAME value only because the hash is salted per set. The salt lives in
    # another module; if it ever became deterministic, this check would silently weaken and nothing
    # else would notice. So it is pinned here, beside the code that depends on it.
    from app.core.security import hash_password, verify_password
    first, second = hash_password("the same password"), hash_password("the same password")
    assert first != second, "hashing is deterministic: a password re-set to the same value would be invisible"
    assert verify_password("the same password", first) and verify_password("the same password", second)


def test_the_receiver_path_also_leaves_no_staged_bytes_on_a_pool_or_lock_timeout(monkeypatch, tmp_path):
    # The same defect, the same shape, on the other endpoint. Its first statement after the
    # connection handback is the re-resolution -- a DB touch -- so a pool or lock timeout there took
    # the same path past the same `except HTTPException`. Both endpoints now own the staged file in
    # a finally; without this leg the receiver's version of the fix is unpinned, and a mutation that
    # narrowed only that one would pass.
    from sqlalchemy.exc import OperationalError
    pool = _Pool()
    db, sid, state = _receiver_world(monkeypatch, tmp_path, pool)

    # The timeout must land on the re-resolution AFTER the body, not on the one that admits the
    # request: raising on the first would refuse before a byte was staged, and the test would pass
    # with no `.part` ever created -- green whatever the cleanup does.
    real_resolve = S._receiver_resolve_session
    seen = {"n": 0}

    def _timeout(db_, token, session_id):
        seen["n"] += 1
        if seen["n"] > 1:
            raise OperationalError("SELECT 1", {}, Exception("QueuePool limit reached, timed out"))
        return real_resolve(db_, token, session_id)

    monkeypatch.setattr(S, "_receiver_resolve_session", _timeout)
    with pytest.raises(OperationalError):
        run_coroutine(S.receiver_upload_chunk("tok", sid, 1, _Request(_slow_body(pool)), db=db))
    sess = tmp_path / "sess"
    assert seen["n"] == 2, "the timeout did not land on the re-resolution after the body"
    assert not list(sess.glob(".chunk_*.part")), "the staged .part survived a pool timeout"
    assert not (sess / "chunk_000001").exists()
