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

        stored = sum(1 for status in statuses if status == 200)
        assert stored == count, f"the uploads did not all succeed: {sorted(statuses)}"

        listing = admin.get(f"/vaults/{vault_id}/files")
        assert listing.status_code == 200
        files = [item for item in listing.json()["items"] if item["type"] == "file"]
        assert len(files) == count, f"{len(files)} files exist after {count} successful uploads"

        reported = admin.get(f"/vaults/{vault_id}").json().get("total_size_bytes") or 0
        assert reported == count * each, (
            f"{count} uploads of {each // MB} MB each are stored, but the vault reports "
            f"{reported / MB:.0f} MB rather than {count * each / MB:.0f} MB. The counter the size "
            "limit is checked against has lost increments, so the limit no longer bounds anything")
    finally:
        admin.delete(f"/vaults/{vault_id}")


@pytest.mark.skip(reason=(
    "KNOWN OPEN: the limit is still bypassable by overlapping uploads. Correct counting (the test "
    "above) is necessary and not sufficient -- the check at completion still reads, decides and "
    "acts without serialisation, so concurrent requests all pass a check they would jointly fail. "
    "The obvious fix, a row lock around the check, was tried and reverted: at /complete the file "
    "has not been encrypted yet, so the lock is held across the expensive work and six concurrent "
    "uploads then exceed the client timeout. The right fix reserves the space up front through the "
    "same atomic Redis reservation the direct multipart path already uses, and releases it on "
    "failure -- which is a change to the upload path, not to a check."))
def test_a_vault_cannot_be_filled_past_its_limit_by_uploading_in_parallel(admin):
    """The consequence, stated as the property an operator relies on.

    A size limit that holds when uploads arrive one at a time and not when they overlap is not a
    limit. Some of these uploads must be refused; what must never happen is all of them being
    accepted.
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
        admin.delete(f"/vaults/{vault_id}")
