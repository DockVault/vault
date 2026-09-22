"""Live: a client-paced chunk upload holds no database transaction open while it streams.

The offline pins prove the ordering with a stand-in Session. This is the same claim measured from
the other side of the container wall, in the database's own words: a pool slot held open across a
client's slow body is a connection in state ``idle in transaction`` in ``pg_stat_activity`` -- the
production fault, by name. While an anonymous receiver upload sends its chunk at a crawl, that
state must not appear for the application's user.

The instrument is validated in the same run: a transaction is deliberately left open from inside
the API container (the app's own engine, the same route the API uses), and the poll must see it.
An instrument that cannot see the fault it is meant to catch proves nothing by seeing none.

Runs in CI's full-suite job against the live stack (no marker filter there); reaches the database
through ``docker exec``, the way every other live module here does.

QUARANTINED: OPT-IN ONLY, via VAULT_POOL_PIN_LIVE=1. By default this module SKIPS at collection,
before any fixture runs, so it is structurally incapable of holding the shared suite. The live
measurement behind this claim has NOT BEEN TAKEN IN CI. The claim ships on the offline evidence in
tests/test_upload_stream_holds_no_connection.py -- a stand-in Session whose instrument reported the
connection held ([1, 1, 1, 1]) on the code before the change and released ([0, 0, 0, 0]) after it,
plus eleven mutations -- and this test is a hand-run for a person against their own stack.

WHAT IS KNOWN, for whoever picks it up: every blocking call in this module carries a timeout
(the constants below; the child's stdout is pumped into a queue and waited on with a timeout; the
poll, the control's exit and the PUT are bounded; the sampler never dies in a poll), their sum is
about seven minutes worst case -- and the module still held a CI job for THIRTEEN minutes of total
silence, so whatever blocks is OUTSIDE the calls bounded here. Three candidates, none excluded yet:
(1) a conftest fixture this test pulls in that nobody bounded (`receivers_enabled`,
`_require_running_container`, `_verify_url` all appear in its collection listing); (2) the
docker exec / Popen interaction itself; (3) `requests`' `timeout=`, which bounds EACH SOCKET
OPERATION and not the whole request -- a generator body against a slow reader can run for as long
as the reader likes while every single operation stays inside the timeout. If (3) is it, every
future live upload test that reaches for `timeout=` on a streamed body will believe something it
does not mean; put a deadline on the body generator itself. The earlier history: the first version
blocked on an unbounded readline one line before its skip and took a 45-minute job cap; that one is
fixed and its guard is armed by three offline legs.
"""
import os
import queue
import subprocess
import threading
import time

import pytest

from conftest import unique  # noqa: E402
from test_api_receiver_upload import _mk_receiver, _open, receivers_enabled  # noqa: F401,E402

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("VAULT_POOL_PIN_LIVE") not in ("1", "true", "yes"),
        reason="quarantined live measurement, NOT run in CI: set VAULT_POOL_PIN_LIVE=1 to hand-run it "
               "against your own stack (it has held a shared job past its cap; see the module docstring)",
    ),
]

_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")
_DB_CONTAINER = os.environ.get("VAULT_DB_CONTAINER", "vault-db")
_DB_USER = "sftp_user"

_PSQL_TIMEOUT = 15            # one poll of pg_stat_activity
_CONTROL_READY_TIMEOUT = 30   # the container's python printing "open" (an import, a connect)
_CONTROL_HOLD_SECONDS = 4     # how long the control holds its transaction open
_CONTROL_EXIT_TIMEOUT = 20    # the control's process ending after that
_PUT_TIMEOUT = 60             # the slow upload itself (about four seconds of body)


def _psql(sql: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", _DB_CONTAINER, "psql", "-U", _DB_USER, "-d", "sftp_db", "-tAc", sql],
        capture_output=True, text=True, timeout=_PSQL_TIMEOUT)


def _idle_in_transaction() -> int:
    """Connections of the app's user idle in a transaction for MORE THAN A SECOND. Any request is
    idle in its transaction for the microseconds between two of its queries; a slot held across a
    client's body is idle in it for as long as the body takes. The threshold tells them apart."""
    out = _psql("SELECT count(*) FROM pg_stat_activity "
                f"WHERE usename = '{_DB_USER}' AND state = 'idle in transaction' "
                "AND now() - state_change > interval '1 second';")
    assert out.returncode == 0, out.stderr
    return int(out.stdout.strip() or "0")


def _sample_while(stop: threading.Event, samples: list, every: float = 0.25):
    while not stop.is_set():
        try:
            samples.append(_idle_in_transaction())
        except Exception:  # noqa: BLE001 -- a failed or timed-out poll is recorded, never a hung thread
            samples.append(-1)
        time.sleep(every)


_CONTROL_SCRIPT = (
    "import time\n"
    "from app.core.database import SessionLocal\n"
    "from sqlalchemy import text\n"
    "db = SessionLocal()\n"
    "db.execute(text('SELECT 1'))\n"       # begins a transaction: the connection is now idle in it
    "print('open', flush=True)\n"
    "time.sleep(%d)\n"
    "db.rollback(); db.close()\n"
) % _CONTROL_HOLD_SECONDS


def _pump(stream, into: "queue.Queue"):
    for line in stream:
        into.put(line)
    into.put("")                              # end of stream


def open_transaction_in_container(container: str, ready_timeout: float = _CONTROL_READY_TIMEOUT, command=None):
    """Start a python inside `container` that opens a transaction on the app's own engine and holds
    it. Returns (proc, None) once it has printed "open", or (None, reason) when it did not within the
    bound -- the container is missing, the image cannot import the app, the database is
    unreachable, docker is not installed. The reason carries what the child said on stderr. Never
    blocks past `ready_timeout` plus a few seconds: stdout is read on its own thread, so the wait
    is a bounded queue wait, not a readline. `command` replaces the docker invocation so the
    offline pins can hand this a child that stays silent, or says the wrong thing."""
    argv = command or ["docker", "exec", "-i", container, "python", "-c", _CONTROL_SCRIPT]
    try:
        proc = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except OSError as e:                      # no docker binary here
        return None, "could not run docker: %s" % e
    lines: "queue.Queue[str]" = queue.Queue()
    threading.Thread(target=_pump, args=(proc.stdout, lines), daemon=True).start()
    try:
        first = lines.get(timeout=ready_timeout)
    except queue.Empty:
        first = None
    if (first or "").strip() == "open":
        return proc, None
    proc.kill()
    try:
        _, err = proc.communicate(timeout=10)
    except subprocess.TimeoutExpired:
        err = "(the child did not exit after kill)"
    why = "never printed 'open' within %ss" % ready_timeout if first is None else "printed %r" % first.strip()
    return None, "could not open a transaction inside %s: %s; stderr: %s" % (
        container, why, (err or "").strip()[-400:])


@pytest.fixture
def instrument_sees_an_open_transaction():
    """The positive control: a transaction left open from inside the API container -- on the app's
    own engine, with the app's own user -- for a few seconds, must show up in the poll. Then it is
    waited out, and the count must be back to zero before the leg runs."""
    proc, reason = open_transaction_in_container(_API_CONTAINER)
    if proc is None:
        pytest.skip(reason)
    try:
        seen = 0
        for _ in range(10):                   # up to 2.5 s: past the one-second threshold
            time.sleep(0.25)
            seen = max(seen, _idle_in_transaction())
            if seen:
                break
        assert seen >= 1, "the instrument did not see a transaction that was deliberately left open"
    finally:
        try:
            proc.wait(timeout=_CONTROL_EXIT_TIMEOUT)   # the control's transaction closes before the leg runs
        except subprocess.TimeoutExpired:
            proc.kill()
            proc.wait(timeout=10)
    for _ in range(20):
        if _idle_in_transaction() == 0:
            break
        time.sleep(0.25)
    assert _idle_in_transaction() == 0, "the control's transaction is still open; the leg cannot be judged"
    yield


def _slow_body(total: int, pieces: int = 8, pause: float = 0.5):
    piece = total // pieces
    for i in range(pieces):
        time.sleep(pause)
        yield b"x" * (piece if i < pieces - 1 else total - piece * (pieces - 1))


def test_a_slow_anonymous_chunk_upload_leaves_no_transaction_idle_while_it_streams(
        admin, receivers_enabled, instrument_sees_an_open_transaction):
    rec = _mk_receiver(admin, max_total_bytes=1024 * 1024)
    anon = admin.clone_anonymous()
    size = 64 * 1024
    r = _open(anon, rec["token"], filename=unique("slow") + ".bin", total_size=size, total_chunks=1)
    assert r.status_code == 200, r.text
    sid = r.json()["session_id"]

    samples, stop = [], threading.Event()
    sampler = threading.Thread(target=_sample_while, args=(stop, samples), daemon=True)
    sampler.start()
    try:
        # The body is sent as it is generated: eight pieces, half a second apart -- four seconds of
        # a client dawdling, with the request open the whole time.
        put = anon.session.put(f"{anon.base_url}/receivers/{rec['token']}/upload-session/{sid}/chunks/0",
                               data=_slow_body(size), headers={"Content-Length": str(size)}, timeout=_PUT_TIMEOUT)
    finally:
        stop.set()
        sampler.join(timeout=_PSQL_TIMEOUT + 5)
    assert not sampler.is_alive(), "the sampler is still blocked in a poll"
    assert put.status_code == 200, put.text
    assert put.json()["received"] == 1
    # Sampled more than a dozen times across the four seconds, and never once was a connection of
    # the app's user sitting idle in a transaction. On the code before this change every sample
    # during the body reads 1 (the request's own transaction, open across the stream).
    assert len(samples) >= 10, samples
    assert -1 not in samples, "the poll itself failed: %r" % samples
    assert max(samples) == 0, "a transaction was left open while the client streamed: %r" % samples
