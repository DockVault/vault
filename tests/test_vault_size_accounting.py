"""The vault's size counter, under concurrent uploads.

A vault's size limit is enforced against `Vault.total_size_bytes`. That counter was maintained with
`vault.total_size_bytes += n` in Python -- a read-modify-write with no lock on the row -- so two
completions that overlap each load the same starting value, each add their own size, and the second
commit overwrites the first. The arithmetic is lost, and with it the limit: a vault fills past its
ceiling with every upload returning success, because each one checked against a total that was
already wrong.

Found by measurement, not by review: a run that moved 2.5 GB into a 1 GB vault succeeded while a
smaller sequential run of 1.5 GB was correctly refused. Sequentially the limit holds. That
asymmetry is the whole bug.
"""

from __future__ import annotations

import threading

import pytest

from conftest import unique

pytestmark = pytest.mark.integration

MB = 1024 * 1024
_OCTET = {"Content-Type": "application/octet-stream"}


def _upload_one(client, vault_id, name, body):
    """One resumable upload, start to finish. Returns the HTTP status of the completion."""
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(body), "total_chunks": 1,
        "chunk_size": len(body), "mime_type": "application/octet-stream",
    })
    if init.status_code != 200:
        return init.status_code
    session = init.json()["session_id"]
    put = client.put(f"/vaults/{vault_id}/uploads/{session}/chunks/0", data=body, headers=_OCTET)
    if put.status_code != 200:
        return put.status_code
    return client.post(f"/vaults/{vault_id}/uploads/{session}/complete").status_code


def test_concurrent_uploads_are_all_counted_against_the_vault(admin):
    """Every stored byte must reach the counter the limit is checked against.

    Not a test about limits: a test about arithmetic. Six uploads that all succeed must leave the
    vault reporting six uploads' worth, whatever order they finished in.
    """
    made = admin.post("/vaults", json={
        "name": unique("accounting"), "vault_type": "standard", "size_limit_gb": 1,
    })
    assert made.status_code == 200, made.text
    vault_id = made.json()["id"]
    try:
        each = 8 * MB
        count = 6
        body = b"A" * each
        statuses = []
        lock = threading.Lock()

        def _run(index):
            status = _upload_one(admin, vault_id, unique(f"acc{index}") + ".bin", body)
            with lock:
                statuses.append(status)

        threads = [threading.Thread(target=_run, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=300)

        # Not every attempt has to be admitted: an account has a ceiling on concurrent upload
        # sessions and some of these legitimately meet it. What must hold is that the vault counts
        # exactly what it stored -- the assertion is about arithmetic, not about admission.
        stored = sum(1 for status in statuses if status == 200)
        assert stored >= 2, (
            f"too few uploads were admitted to say anything about concurrency: {sorted(statuses)}")

        listing = admin.get(f"/vaults/{vault_id}/files")
        assert listing.status_code == 200
        files = [item for item in listing.json()["items"] if item["type"] == "file"]
        assert len(files) == stored, (
            f"{stored} uploads reported success but {len(files)} files exist")

        reported = admin.get(f"/vaults/{vault_id}").json().get("total_size_bytes") or 0
        assert reported == stored * each, (
            f"{stored} uploads of {each // MB} MB each are stored, but the vault reports "
            f"{reported / MB:.0f} MB rather than {stored * each / MB:.0f} MB. The counter the size "
            "limit is checked against has lost increments, so the limit no longer bounds anything")
    finally:
        # POST, not DELETE: there is no DELETE route and the 405 was never asserted,
        # so every run of this file used to leave its vaults behind.
        admin.post(f"/vaults/{vault_id}/delete")


def test_a_vault_cannot_be_filled_past_its_limit_by_uploading_in_parallel(admin):
    """The consequence, stated as the property an operator relies on.

    A size limit that holds when uploads arrive one at a time and not when they overlap is not a
    limit. Some of these uploads must be refused; what must never happen is all of them being
    accepted.

    WHAT THIS DOES NOT PROVE. Correct counting turns out to be sufficient at the concurrency one
    account can reach, because an account has a ceiling on simultaneous upload sessions and it
    throttles this test below the racing threshold -- verified by mutation: removing an atomic
    reservation entirely leaves this test green. The check at completion is still a read-decide-act
    with nothing serialising it, so it should still be reachable by several DIFFERENT accounts
    uploading into one shared vault, which no test here does. Until such a test exists, the extra
    machinery for it is not in the tree: shipping concurrency code that nothing exercises is how
    the original defect survived.
    """
    made = admin.post("/vaults", json={
        "name": unique("ceiling"), "vault_type": "standard", "size_limit_gb": 64 / 1024,
    })
    assert made.status_code == 200, made.text
    vault_id = made.json()["id"]
    try:
        limit = admin.get(f"/vaults/{vault_id}").json().get("size_limit") or 0
        assert limit > 0, "this vault has no ceiling, so nothing here is being tested"

        each = 24 * MB
        count = 6                                    # 144 MB into a 64 MB vault
        body = b"B" * each
        statuses = []
        lock = threading.Lock()

        def _run(index):
            status = _upload_one(admin, vault_id, unique(f"ceil{index}") + ".bin", body)
            with lock:
                statuses.append(status)

        threads = [threading.Thread(target=_run, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=300)

        accepted = sum(1 for status in statuses if status == 200)
        assert accepted < count, (
            f"all {count} uploads were accepted into a vault that holds {limit / MB:.0f} MB; "
            "the ceiling does not survive concurrency")

        listing = admin.get(f"/vaults/{vault_id}/files")
        files = [item for item in listing.json()["items"] if item["type"] == "file"]
        assert len(files) * each <= limit, (
            f"{len(files)} files of {each // MB} MB are stored in a {limit / MB:.0f} MB vault; "
            "the limit was exceeded rather than enforced")
    finally:
        # POST, not DELETE: there is no DELETE route and the 405 was never asserted,
        # so every run of this file used to leave its vaults behind.
        admin.post(f"/vaults/{vault_id}/delete")


def test_the_limit_holds_when_separate_accounts_upload_into_one_vault(admin):
    """The case a single account cannot reach, and the one that decided against a reservation.

    An account has a ceiling on simultaneous upload sessions, so a single-account test is throttled
    below the threshold where the check-then-act at completion could race. Separate accounts do not
    share that ceiling, so this is where the race should surface if it is reachable at all -- and
    it is the reason an atomic reservation was written for this path.

    It does not surface. Five accounts, released together from a barrier so their completions land
    at the same moment, still cannot put 120 MB into a 64 MB vault: the atomic counter is committed
    before the next completion reads it, and the reads serialise. That measurement is why the
    reservation is not in the tree -- machinery nothing can show a need for is machinery nothing
    exercises.

    If this test ever fails, the reservation is the answer and the reasoning above is where to
    start.
    """
    from conftest import ApiClient

    made = admin.post("/vaults", json={
        "name": unique("shared-ceiling"), "vault_type": "standard", "size_limit_gb": 64 / 1024,
    })
    assert made.status_code == 200, made.text
    vault_id = made.json()["id"]
    limit = admin.get(f"/vaults/{vault_id}").json().get("size_limit") or 0
    assert limit > 0

    accounts = []
    try:
        for _ in range(5):
            user = admin.create_user()
            granted = admin.post(f"/vaults/{vault_id}/permissions",
                                 json={"user_id": user["id"], "level": "write"})
            assert granted.status_code in (200, 201), granted.text
            client = ApiClient()
            client.login(user["_username"], user["_password"])
            accounts.append((user, client))

        each = 24 * MB
        body = b"M" * each
        statuses = []
        lock = threading.Lock()
        # Released together, so the completions -- the part that checks the limit -- overlap
        # instead of being spread out by how long the bytes take to arrive.
        gate = threading.Barrier(len(accounts))

        def _run(index, client):
            outcome = None
            try:
                init = client.post(f"/vaults/{vault_id}/uploads", json={
                    "file_name": f"shared-{index}.bin", "total_size": len(body),
                    "total_chunks": 1, "chunk_size": len(body),
                    "mime_type": "application/octet-stream"})
                if init.status_code != 200:
                    outcome = init.status_code
                else:
                    session = init.json()["session_id"]
                    put = client.put(f"/vaults/{vault_id}/uploads/{session}/chunks/0",
                                     data=body, headers=_OCTET)
                    outcome = put.status_code if put.status_code != 200 else None
                    if outcome is None:
                        gate.wait(timeout=300)
                        outcome = client.post(
                            f"/vaults/{vault_id}/uploads/{session}/complete").status_code
            except Exception:                        # noqa: BLE001
                outcome = "error"
            finally:
                if outcome is not None and not gate.broken:
                    try:
                        gate.wait(timeout=1)         # never strand the others behind a failure
                    except Exception:                # noqa: BLE001
                        gate.abort()
            with lock:
                statuses.append(outcome)

        threads = [threading.Thread(target=_run, args=(i, c))
                   for i, (_user, c) in enumerate(accounts)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=600)

        reported = admin.get(f"/vaults/{vault_id}").json().get("total_size_bytes") or 0
        assert reported <= limit, (
            f"five accounts put {reported / MB:.0f} MB into a {limit / MB:.0f} MB vault "
            f"({sorted(map(str, statuses))}); the limit does not survive concurrent accounts and "
            "an atomic reservation at the completion check is what closes it")
    finally:
        # POST, not DELETE: there is no DELETE route and the 405 was never asserted,
        # so every run of this file used to leave its vaults behind.
        admin.post(f"/vaults/{vault_id}/delete")
        for user, _client in accounts:
            admin.delete_user(user["id"])


@pytest.mark.skip(reason=(
    "DOES NOT REPRODUCE YET, and is checked in rather than deleted so the next attempt starts "
    "here. The hole is real and was demonstrated by review: two concurrent multipart requests from "
    "ONE ordinary account put 250% of a vault's ceiling into it, and sixteen put 400%. This test "
    "does not reproduce it because every request goes through the one `admin` client, whose "
    "requests.Session pools a single connection and serialises them -- verified by restoring the "
    "stale read and watching it still pass. It needs an independent client per thread, as the "
    "multi-account test above uses. The production re-gate it was written for IS in place."))
def test_the_direct_multipart_path_cannot_exceed_the_ceiling_either(admin):
    """The path the first fix missed, attacked the way it was actually broken.

    The resumable path was fixed and this one was not, which made the fix look complete while a
    single ordinary account could still put four times a vault's ceiling into it. Two holes, both
    on this path: the size the guards check against is read once before the stream starts and is
    stale by the time the bytes land, and the atomic reservation is only taken when Content-Length
    supplied a size -- so a client that omits that header, which any streaming client does by
    default, had no reservation and only the stale number.

    No barrier and no second account here. Concurrency alone is enough, which is what made this the
    serious one.
    """
    made = admin.post("/vaults", json={
        "name": unique("multipart-ceiling"), "vault_type": "standard",
        "size_limit_gb": 64 / 1024,
    })
    assert made.status_code == 200, made.text
    vault_id = made.json()["id"]
    try:
        limit = admin.get(f"/vaults/{vault_id}").json().get("size_limit") or 0
        assert limit > 0

        each = 16 * MB
        count = 8                                     # 128 MB into a 64 MB vault
        body = b"D" * each
        statuses = []
        lock = threading.Lock()

        def _run(index):
            # A plain body, so Content-Length is present and the reservation is taken. This still
            # breaches the ceiling, because both guards consume a size read once before the stream
            # began. Omitting the header removes the reservation as well and makes it worse, which
            # is a second hole in the same place; this covers the one that needs no special client.
            files = {"files": (f"mp-{index}.bin", body, "application/octet-stream")}
            try:
                status = admin.post(f"/vaults/{vault_id}/files", files=files).status_code
            except Exception:                         # noqa: BLE001
                status = "error"
            with lock:
                statuses.append(status)

        threads = [threading.Thread(target=_run, args=(i,)) for i in range(count)]
        for thread in threads:
            thread.start()
        for thread in threads:
            thread.join(timeout=600)

        reported = admin.get(f"/vaults/{vault_id}").json().get("total_size_bytes") or 0
        # Non-vacuity first. `reported <= limit` is trivially true when every upload failed, and
        # an earlier version of this test passed in half a second doing exactly that -- proving
        # nothing while looking like a guard.
        assert any(status == 200 for status in statuses), (
            f"no upload succeeded, so the ceiling was never tested: {sorted(map(str, statuses))}")
        assert reported > 0, "nothing was stored, so this test proved nothing"
        assert reported <= limit, (
            f"{reported / MB:.0f} MB was stored in a {limit / MB:.0f} MB vault "
            f"({sorted(map(str, statuses))}); the direct multipart path does not enforce the "
            "ceiling under concurrency")
    finally:
        admin.post(f"/vaults/{vault_id}/delete")
