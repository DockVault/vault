"""The transfer ceiling, against a running deployment.

The unit tests cover the gate itself. These cover what an operator cares about: that a burst is
served rather than refused, and that when the deployment genuinely is full the answer is one a
client can act on.

That second point is the one worth being careful about. If a full deployment answered with a five
hundred, a client could not distinguish "come back in a moment" from "this file cannot be read",
and would either retry something hopeless or abandon something that would have worked. Proving it
needs a deployment that is actually full, which means one configured with a ceiling of one -- the
same shape as the throttle tests, which also need an instance configured against them.
"""

import os
import subprocess
import threading
import time

import pytest

from conftest import unique


MB = 1024 * 1024
_OCTET = {"Content-Type": "application/octet-stream"}


def _upload(client, vault_id, name, content, chunk_size=MB):
    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content),
        "total_chunks": total_chunks, "chunk_size": chunk_size,
        "mime_type": "application/octet-stream",
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    for i in range(total_chunks):
        r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}",
                       data=content[i * chunk_size:(i + 1) * chunk_size], headers=_OCTET)
        assert r.status_code == 200, r.text
    done = client.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    return done.json()["id"]


def _deployment_setting(name, default):
    """What the running deployment was configured with, read from the container's environment."""
    container = os.environ.get("VAULT_API_CONTAINER", "vault-api")
    out = subprocess.run(
        ["docker", "exec", container, "sh", "-c", f"echo ${{{name}:-{default}}}"],
        capture_output=True, text=True, timeout=60)
    if out.returncode != 0 or not out.stdout.strip():
        pytest.skip(f"cannot read {name} from the deployment")
    return out.stdout.strip()


def _limit():
    value = _deployment_setting("MAX_CONCURRENT_TRANSFERS", "16")
    if not value.isdigit():
        pytest.skip(f"MAX_CONCURRENT_TRANSFERS is not a number: {value!r}")
    return int(value)


def test_a_burst_of_downloads_is_served_rather_than_refused(admin, temp_vault):
    """More simultaneous transfers than the ceiling, all of which should still complete.

    A burst is normal traffic; refusing it would trade one failure mode for another. What the
    ceiling does is stop them running *at once*, not stop them happening.
    """
    vid = temp_vault["id"]
    body = b"burst" * 200_000                       # ~1 MB, big enough for the requests to overlap
    file_id = _upload(admin, vid, unique("burst") + ".bin", body)

    limit = _limit()
    attempts = limit + 6
    results = []
    lock = threading.Lock()

    def _download():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download")
        with lock:
            results.append((response.status_code, len(response.content)))

    threads = [threading.Thread(target=_download) for _ in range(attempts)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=180)

    assert len(results) == attempts, "some downloads never returned"
    codes = sorted({code for code, _ in results})
    assert codes == [200], (
        f"a burst of {attempts} against a ceiling of {limit} was not fully served: {codes}")
    assert all(length == len(body) for _, length in results), (
        "a queued download returned the wrong number of bytes")


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue; "
           "set VAULT_TRANSFER_LIMIT_IS_ONE=1 on such a round")
def test_a_full_deployment_answers_with_something_a_client_can_act_on(admin, temp_vault):
    """Against a deployment whose ceiling is one and whose queue is empty.

    The refusal must be a 503 carrying Retry-After -- not a 500, which is indistinguishable from an
    unreadable file, and not a silent drop.
    """
    assert _limit() == 1, (
        f"this test needs a ceiling of 1, but the deployment reports {_limit()}")

    vid = temp_vault["id"]
    body = b"S" * (24 * MB)                          # large enough to still be in flight
    file_id = _upload(admin, vid, unique("full") + ".bin", body)

    refusals = []
    holder_done = threading.Event()

    def _hold():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download", stream=True)
        next(response.iter_content(8192))
        time.sleep(4)                                # keep the single slot occupied
        response.close()
        holder_done.set()

    holder = threading.Thread(target=_hold)
    holder.start()
    time.sleep(1.5)

    second = admin.clone_anonymous()
    second.session.headers.update({"Authorization": f"Bearer {admin.token}"})
    response = second.get(f"/vaults/{vid}/files/{file_id}/download")
    refusals.append(response)

    holder.join(timeout=60)

    refused = refusals[0]
    assert refused.status_code == 503, (
        f"a full deployment answered {refused.status_code}; a client cannot tell that from an "
        "unreadable file")
    assert refused.headers.get("Retry-After"), "the refusal carries no interval to act on"
    assert int(refused.headers["Retry-After"]) >= 1
    assert "transfer" in refused.text.lower(), (
        f"the refusal does not say what happened: {refused.text[:160]}")


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_an_upload_is_admitted_on_the_same_ceiling_as_a_download(admin, temp_vault):
    """One ceiling covers both directions.

    A deployment's capacity is the transfers it is carrying, not the downloads and the uploads
    counted separately -- so a download in flight must be able to hold an upload off, and it is
    the same slot either way.
    """
    vid = temp_vault["id"]
    body = b"U" * (24 * MB)
    file_id = _upload(admin, vid, unique("both") + ".bin", body)

    def _hold():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download", stream=True)
        next(response.iter_content(8192))
        time.sleep(4)
        response.close()

    holder = threading.Thread(target=_hold)
    holder.start()
    time.sleep(1.5)

    uploader = admin.clone_anonymous()
    uploader.session.headers.update({"Authorization": f"Bearer {admin.token}"})
    refused = uploader.post(
        f"/vaults/{vid}/files",
        files=[("files", (unique("u") + ".bin", b"x" * 1024, "application/octet-stream"))])

    holder.join(timeout=60)

    assert refused.status_code == 503, (
        f"an upload was admitted while the single transfer slot was held by a download: "
        f"{refused.status_code}")
    assert refused.headers.get("Retry-After")
