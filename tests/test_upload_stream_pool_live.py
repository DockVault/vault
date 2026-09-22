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
"""
import os
import subprocess
import threading
import time

import pytest

from conftest import unique  # noqa: E402
from test_api_receiver_upload import _mk_receiver, _open, _psql, receivers_enabled  # noqa: F401,E402

pytestmark = pytest.mark.integration

_API_CONTAINER = os.environ.get("VAULT_API_CONTAINER", "vault-api")
_DB_USER = "sftp_user"


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
        except AssertionError:
            samples.append(-1)
        time.sleep(every)


@pytest.fixture
def instrument_sees_an_open_transaction():
    """The positive control: a transaction left open from inside the API container -- on the app's
    own engine, with the app's own user -- for a few seconds, must show up in the poll."""
    script = (
        "import time\n"
        "from app.core.database import SessionLocal\n"
        "from sqlalchemy import text\n"
        "db = SessionLocal()\n"
        "db.execute(text('SELECT 1'))\n"       # begins a transaction: the connection is now idle in it
        "print('open', flush=True)\n"
        "time.sleep(4)\n"
        "db.rollback(); db.close()\n"
    )
    proc = subprocess.Popen(["docker", "exec", "-i", _API_CONTAINER, "python", "-c", script],
                            stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        line = proc.stdout.readline().strip()
        if line != "open":
            proc.kill()
            pytest.skip("could not open a transaction inside the API container: %r / %s"
                        % (line, proc.stderr.read()[:300]))
        seen = 0
        for _ in range(10):                       # up to 2.5 s: past the one-second threshold
            time.sleep(0.25)
            seen = max(seen, _idle_in_transaction())
            if seen:
                break
        assert seen >= 1, "the instrument did not see a transaction that was deliberately left open"
    finally:
        proc.wait(timeout=15)                     # the control's transaction is closed before the leg runs
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
                               data=_slow_body(size), headers={"Content-Length": str(size)}, timeout=60)
    finally:
        stop.set()
        sampler.join(timeout=5)
    assert put.status_code == 200, put.text
    assert put.json()["received"] == 1
    # Sampled more than a dozen times across the four seconds, and never once was a connection of
    # the app's user sitting idle in a transaction. On the code before this change every sample
    # during the body reads 1 (the request's own transaction, open across the stream).
    assert len(samples) >= 10, samples
    assert -1 not in samples, "the poll itself failed: %r" % samples
    assert max(samples) == 0, "a transaction was left open while the client streamed: %r" % samples
