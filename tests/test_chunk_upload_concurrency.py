"""Two requests at the same chunk index must not damage each other.

Re-sending a chunk is the documented retry -- the handler's own docstring calls it idempotent --
so two requests at one index are ordinary traffic, not an attack. They became dangerous when the
body started streaming to disk: the staged file went from being written in a single call at the
end of the request to being held open for the whole transfer, and it was named from the chunk
index alone. A shared name meant `open(..., 'wb')` truncated the other request's file, both wrote
at their own offsets into the same inode, and either one's cleanup deleted the other's work.

Two consequences, both reproduced before the fix and both guarded here:

- A zero-byte or oversized request at an index destroyed an in-flight upload at that index. The
  victim got a 500 and the session lost the chunk entirely.
- Two overlapping uploads produced a stored chunk holding one body while the reported digest
  described the other -- inverting the one thing the digests exist for, which is telling a
  resuming client whether its own copy still matches.

The fix names the staged file per request, so the rename stays the single atomic publish and a
cleanup can only reach its own file.
"""

import hashlib
import time
from concurrent.futures import ThreadPoolExecutor

import pytest

from conftest import unique


_OCTET = {"Content-Type": "application/octet-stream"}


def _open_session(admin, vault_id, total_size, total_chunks, chunk_size):
    r = admin.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": unique("concurrent") + ".bin", "total_size": total_size,
        "total_chunks": total_chunks, "chunk_size": chunk_size,
    })
    assert r.status_code == 200, r.text
    return r.json()["session_id"]


def _slow_body(payload, pieces=8, gap=0.05):
    """A body delivered over roughly `pieces * gap` seconds, so it is reliably still in flight."""
    step = len(payload) // pieces

    def _generate():
        for i in range(pieces):
            yield payload[i * step:(i + 1) * step] if i < pieces - 1 else payload[i * step:]
            time.sleep(gap)
    return _generate()


def _timed(fn, *args, **kwargs):
    """Call `fn`, returning `(response, started, finished)`.

    Every test here depends on two requests being in flight at once. Without the timings, a
    scheduling hiccup that serialises them turns the whole assertion into "one request then another
    request worked", which is not the property and would pass quietly forever.
    """
    started = time.monotonic()
    result = fn(*args, **kwargs)
    return result, started, time.monotonic()


def _assert_overlapped(first, second, what):
    """Both requests were open at the same moment, so the test measured what it claims to."""
    _, a_start, a_end = first
    _, b_start, b_end = second
    assert a_start < b_end and b_start < a_end, (
        f"{what} did not overlap (first {a_start:.3f}-{a_end:.3f}, "
        f"second {b_start:.3f}-{b_end:.3f}); this run proved nothing about concurrency")


def test_an_empty_request_does_not_destroy_an_upload_at_the_same_index(admin, temp_vault):
    """The refusal must land on the refused request's own file and nothing else.

    Before the fix this was a 500 for the victim and an empty session directory: one stray
    zero-byte request discarded a multi-megabyte upload that was most of the way done.
    """
    vid = temp_vault["id"]
    payload = b"S" * (2 * 1024 * 1024)
    sid = _open_session(admin, vid, len(payload), 1, len(payload))

    victim = admin.clone_anonymous()
    victim.session.headers.update({"Authorization": f"Bearer {admin.token}"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        slow = pool.submit(_timed, victim.put, f"/vaults/{vid}/uploads/{sid}/chunks/0",
                           data=_slow_body(payload), headers=_OCTET)
        time.sleep(0.15)   # mid-transfer, well before the generator is exhausted
        empty = pool.submit(_timed, admin.put, f"/vaults/{vid}/uploads/{sid}/chunks/0",
                            data=b"", headers=_OCTET)
        slow_timed, empty_timed = slow.result(), empty.result()

    _assert_overlapped(slow_timed, empty_timed, "the upload and the empty request")
    slow_result, empty_result = slow_timed[0], empty_timed[0]

    assert empty_result.status_code == 400, (
        f"an empty body should be refused, got {empty_result.status_code}")
    assert slow_result.status_code == 200, (
        f"the concurrent upload was collateral damage: {slow_result.status_code} "
        f"{slow_result.text[:200]}")

    detail = admin.get(f"/vaults/{vid}/uploads/{sid}").json()
    assert detail["received_chunks"] == [0], (
        f"the chunk did not survive: received_chunks={detail['received_chunks']}")

    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    got = admin.get(f"/vaults/{vid}/files/{done.json()['id']}/download")
    assert got.content == payload, "the stored file is not what was uploaded"


def test_an_oversized_request_does_not_destroy_an_upload_at_the_same_index(admin, temp_vault):
    """Same property on the other refusal path, which also writes and then cleans up."""
    vid = temp_vault["id"]
    payload = b"T" * (2 * 1024 * 1024)
    sid = _open_session(admin, vid, len(payload), 1, len(payload))

    victim = admin.clone_anonymous()
    victim.session.headers.update({"Authorization": f"Bearer {admin.token}"})

    with ThreadPoolExecutor(max_workers=2) as pool:
        slow = pool.submit(_timed, victim.put, f"/vaults/{vid}/uploads/{sid}/chunks/0",
                           data=_slow_body(payload), headers=_OCTET)
        time.sleep(0.15)
        # Four times the declared size, with no Content-Length, so it is refused by the receive
        # loop rather than by the header check -- which means it reaches disk first.
        over = pool.submit(_timed, admin.put, f"/vaults/{vid}/uploads/{sid}/chunks/0",
                           data=iter([b"X" * (1024 * 1024) for _ in range(8)]), headers=_OCTET)
        slow_timed, over_timed = slow.result(), over.result()

    _assert_overlapped(slow_timed, over_timed, "the upload and the oversized request")
    slow_result, over_result = slow_timed[0], over_timed[0]

    assert over_result.status_code == 413, (
        f"an oversized body should be refused, got {over_result.status_code}")
    assert slow_result.status_code == 200, (
        f"the concurrent upload was collateral damage: {slow_result.status_code} "
        f"{slow_result.text[:200]}")

    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    got = admin.get(f"/vaults/{vid}/files/{done.json()['id']}/download")
    assert got.content == payload, "the stored file is not what was uploaded"


@pytest.mark.parametrize("writers,stagger", [(2, 0.12), (5, 0.03), (6, 0.0)])
def test_overlapping_uploads_at_one_index_agree_with_their_own_digest(
        admin, temp_vault, writers, stagger):
    """Whichever body wins, the published digest has to describe the bytes that were kept.

    Before the fix the requests interleaved inside one file: the first finished and published its
    own digest, the second kept writing into the already-published chunk, and the session ended up
    advertising a digest for content it no longer held. A resuming client checks its own copy
    against exactly that value, so it would have been told a stale chunk was fine.

    Naming the staged file per request stops the interleaving, but publishing the chunk and
    publishing its digest are still two operations -- so the pair also has to happen under the
    session lock, or a slow request can rename its chunk first and write its digest last, landing
    one request's bytes under another's digest. That window is narrow, which is the reason for
    several writers and several timings rather than one tidy pair.
    """
    vid = temp_vault["id"]
    size = 2 * 1024 * 1024
    bodies = [bytes([65 + i]) * size for i in range(writers)]
    sid = _open_session(admin, vid, size, 1, size)

    clients = []
    for _ in range(writers):
        c = admin.clone_anonymous()
        c.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        clients.append(c)

    with ThreadPoolExecutor(max_workers=writers) as pool:
        futures = []
        for client, body in zip(clients, bodies):
            futures.append(pool.submit(_timed, client.put,
                                       f"/vaults/{vid}/uploads/{sid}/chunks/0",
                                       data=_slow_body(body), headers=_OCTET))
            if stagger:
                time.sleep(stagger)
        timed = [f.result() for f in futures]

    # Every writer has to have been open while the first one was, or the "overlapping" in the name
    # is decoration and a serialised run would report success for a property it never exercised.
    for later in timed[1:]:
        _assert_overlapped(timed[0], later, f"{writers} writers at stagger {stagger}")
    results = [t[0] for t in timed]

    assert all(r.status_code == 200 for r in results), (
        f"a re-send at the same index is documented as idempotent, got "
        f"{[r.status_code for r in results]}")

    published = admin.get(f"/vaults/{vid}/uploads/{sid}").json()["chunk_checksums"]["0"]
    done = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    stored = admin.get(f"/vaults/{vid}/files/{done.json()['id']}/download").content

    assert stored in bodies, (
        "the stored chunk is none of the bodies sent -- the requests interleaved into one file")
    assert hashlib.sha256(stored).hexdigest() == published, (
        "the session reported a digest that does not describe the bytes it stored")
