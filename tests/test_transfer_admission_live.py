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


def _transfer_stats(client):
    """The gate's own counters, as the monitor reports them."""
    metrics = client.get("/api/monitoring/metrics")
    assert metrics.status_code == 200, metrics.text
    return metrics.json()


def _limit():
    value = _deployment_setting("MAX_CONCURRENT_TRANSFERS", "16")
    if not value.isdigit():
        pytest.skip(f"MAX_CONCURRENT_TRANSFERS is not a number: {value!r}")
    return int(value)


def test_a_burst_of_downloads_is_served_rather_than_refused(admin, temp_vault):
    """More simultaneous transfers than the ceiling, all of which should still complete.

    A burst is normal traffic; refusing it would trade one failure mode for another. What the
    ceiling does is stop them running *at once*, not stop them happening -- provided the
    deployment has a waiting room, which is what the queue settings are for. A round deliberately
    configured without one is being asked for the opposite behaviour, so skip there.
    """
    if int(_deployment_setting("MAX_QUEUED_TRANSFERS", "32") or 0) < 1:
        pytest.skip("this deployment is configured to refuse rather than queue")

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


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_the_resumable_path_is_admitted_too(admin, temp_vault):
    """The path the product's own client actually uses.

    The direct multipart endpoint was gated first; the resumable one was not, and it is the only
    one the browser takes. Assembling the staged chunks runs the same encryption pipeline for the
    same duration, so a deployment could answer 503 to everything it counted while a full upload
    ran through the door beside it.

    The chunk writes themselves are deliberately not admitted: each streams straight to disk and
    holds nothing, so gating them would refuse work that costs nothing to accept.
    """
    vid = temp_vault["id"]
    body = b"R" * (24 * MB)
    file_id = _upload(admin, vid, unique("hold") + ".bin", body)

    def _hold():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download", stream=True)
        next(response.iter_content(8192))
        time.sleep(5)
        response.close()

    holder = threading.Thread(target=_hold)
    holder.start()
    time.sleep(1.5)

    client = admin.clone_anonymous()
    client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
    payload = b"z" * (2 * MB)
    init = client.post(f"/vaults/{vid}/uploads", json={
        "file_name": unique("resumable") + ".bin", "total_size": len(payload),
        "total_chunks": 2, "chunk_size": MB, "mime_type": "application/octet-stream",
    })
    assert init.status_code == 200, "opening a session should not need a transfer slot"
    sid = init.json()["session_id"]
    for i in range(2):
        chunk = client.put(f"/vaults/{vid}/uploads/{sid}/chunks/{i}",
                           data=payload[i * MB:(i + 1) * MB], headers=_OCTET)
        assert chunk.status_code == 200, "a chunk write should not need a transfer slot"

    refused = client.post(f"/vaults/{vid}/uploads/{sid}/complete")
    holder.join(timeout=60)

    assert refused.status_code == 503, (
        f"assembly ran while the only transfer slot was held by a download: {refused.status_code}")
    assert refused.headers.get("Retry-After")


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_a_download_that_fails_after_admission_gives_its_slot_back(admin, temp_vault):
    """The limb between taking a slot and handing the response off.

    A download takes its slot early and releases it in the streaming generator, so anything that
    fails in between must return it through the endpoint's own teardown instead. A slot lost here
    does not fail loudly -- it shrinks the ceiling, permanently, until the deployment stops
    accepting transfers altogether.
    """
    vid = temp_vault["id"]
    missing = "00000000-0000-4000-8000-000000000000"

    for _ in range(3):
        gone = admin.get(f"/vaults/{vid}/files/{missing}/download")
        assert gone.status_code in (403, 404), gone.status_code

    # If any of those kept its slot, the single-slot deployment is now closed for business.
    body = b"after" * 1000
    file_id = _upload(admin, vid, unique("after") + ".bin", body)
    got = admin.get(f"/vaults/{vid}/files/{file_id}/download")
    assert got.status_code == 200, (
        f"a download after three failed ones was answered {got.status_code}; the failures kept "
        "their slots")
    assert got.content == body


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_a_completed_upload_gives_its_slot_back(admin, temp_vault):
    """The upload release limb, which nothing exercised.

    Every live test of the ceiling checked that an upload could be *refused*. None performed a
    successful one, so the branch that returns the slot afterwards was never run -- and on a
    deployment of one slot, failing to return it means the next transfer of any kind is refused
    for ever.
    """
    vid = temp_vault["id"]

    # One more upload than the deployment has slots. Below that, a leak is invisible: on a ceiling
    # of sixteen, three uploads that each kept their slot still leave thirteen free and every
    # assertion here passes.
    first = None
    for i in range(_limit() + 1):
        stored = admin.post(
            f"/vaults/{vid}/files",
            files=[("files", (unique(f"multi{i}") + ".bin", b"m" * 4096,
                              "application/octet-stream"))])
        assert stored.status_code == 200, (
            f"upload {i} of {_limit() + 1} was answered {stored.status_code}; an earlier upload "
            "kept its slot")
        first = first or stored.json()["files"][0]["id"]

    # End on something the ceiling actually governs. A listing is not admitted, so it answers 200
    # whether or not the slot came back, and would have proved nothing.
    got = admin.get(f"/vaults/{vid}/files/{first}/download")
    assert got.status_code == 200, (
        f"a download after {_limit() + 1} uploads was answered {got.status_code}; the uploads "
        "kept their slots and the deployment has no capacity left")


def test_a_multi_file_upload_takes_one_slot_for_the_whole_request(admin, temp_vault):
    """Several files in one request must be admitted once, not once each.

    A slot per file leaves a window in which a request stores its first file, finds the deployment
    full when it reaches the second, and answers 503 -- leaving the caller to work out which of the
    files they sent had landed. The window itself is microseconds wide and no test can reliably
    land inside it, so what is checked here is the cause rather than the symptom: the number of
    times the gate admitted something. One request, one admission, whatever it was carrying.
    """
    vid = temp_vault["id"]
    names = [unique(f"onerequest{i}") + ".bin" for i in range(3)]

    idle = _transfer_stats(admin)
    assert idle["transfersInFlight"] == 0, (
        "something else was transferring; this counts admissions and needs a quiet deployment")
    before = idle["transfersAdmitted"]
    stored = admin.post(f"/vaults/{vid}/files", files=[
        ("files", (name, b"a" * (256 * 1024), "application/octet-stream")) for name in names])
    assert stored.status_code == 200, stored.text
    after = _transfer_stats(admin)["transfersAdmitted"]

    assert after - before == 1, (
        f"a request carrying {len(names)} files was admitted {after - before} times; a slot per "
        "file lets a request be refused partway through work it has already begun")
    assert {f["name"] for f in stored.json()["files"]} == set(names)

    listing = admin.get(f"/vaults/{vid}/files")
    assert listing.status_code == 200
    present = {item["name"] for item in listing.json()["items"]}
    assert set(names) <= present, (
        "a multi-file upload stored only part of what it was given: "
        f"missing {sorted(set(names) - present)}")


def test_the_ceiling_is_visible_to_an_operator(admin):
    """The configured ceiling and what it has done, reported where an operator will look.

    A deployment is told to size MAX_CONCURRENT_TRANSFERS against its memory, which cannot be done
    without seeing how close to it the thing actually runs. Without this the only trace of a
    refusal is a 503 in an access log, which says nothing about how often it happens.
    """
    metrics = admin.get("/api/monitoring/metrics")
    assert metrics.status_code == 200, metrics.text
    body = metrics.json()

    for key in ("transferLimit", "transfersInFlight", "transfersWaiting",
                "transfersPeak", "transfersRefused"):
        assert key in body, f"the monitor does not report {key}"
        assert isinstance(body[key], (int, float)), f"{key} is not a number: {body[key]!r}"

    assert body["transferLimit"] == _limit(), (
        "the reported ceiling is not the one the deployment was configured with")
    assert body["transfersInFlight"] <= body["transferLimit"]
    assert body["transfersPeak"] >= body["transfersInFlight"]


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_a_refused_upload_leaves_nothing_behind(admin, temp_vault):
    """A 503 must cost the deployment nothing.

    The ceiling is here to bound what traffic can make the process hold. If being refused still
    registered an operation, a caller could grow a process-global set one cheap request at a time
    -- unbounded, by exactly the path that was supposed to bound it -- and the operation count an
    operator reads would climb and never come back down.
    """
    vid = temp_vault["id"]
    body = b"L" * (24 * MB)
    file_id = _upload(admin, vid, unique("leak") + ".bin", body)

    def _hold():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download", stream=True)
        next(response.iter_content(8192))
        time.sleep(8)
        response.close()

    holder = threading.Thread(target=_hold)
    holder.start()
    time.sleep(1.5)

    before = _transfer_stats(admin)
    refusals = 0
    for i in range(12):
        answer = admin.post(
            f"/vaults/{vid}/files",
            files=[("files", (unique(f"refused{i}") + ".bin", b"r" * 512,
                              "application/octet-stream"))])
        assert answer.status_code == 503, f"expected a refusal, got {answer.status_code}"
        refusals += 1
    after = _transfer_stats(admin)

    holder.join(timeout=60)

    assert after["transfersRefused"] - before["transfersRefused"] == refusals, (
        "the gate did not count every refusal it made")
    assert after["activeOperations"] <= before["activeOperations"], (
        f"{refusals} refused uploads left {after['activeOperations'] - before['activeOperations']} "
        "operations registered; a refusal must cost the deployment nothing")


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_a_caller_with_no_access_is_refused_access_not_a_slot(admin, temp_user_client,
                                                             temp_vault):
    """Authorization is answered before the ceiling is consulted.

    Admitting first means a caller who cannot touch the vault -- or who names one that does not
    exist -- is made to wait for a transfer slot and then told 503. On a deployment with a waiting
    room that is the cheapest denial of service available: no vault, no file, no bytes sent, and
    every parked request keeps a real transfer out.
    """
    vid = temp_vault["id"]
    outsider = temp_user_client
    body = b"A" * (24 * MB)
    file_id = _upload(admin, vid, unique("authz") + ".bin", body)
    baseline_refusals = _transfer_stats(admin)["transfersRefused"]

    def _hold():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download", stream=True)
        next(response.iter_content(8192))
        time.sleep(6)
        response.close()

    holder = threading.Thread(target=_hold)
    holder.start()
    time.sleep(1.5)

    # Without this the test proves nothing: if the holder never took the slot, every answer below
    # is the ordinary one and the test passes on the defective code too.
    assert _transfer_stats(admin)["transfersInFlight"] == 1, (
        "the holding download never took the slot, so nothing here is being tested")

    absent = "00000000-0000-4000-8000-000000000000"
    answers = {
        "complete": admin.post(f"/vaults/{absent}/uploads/{absent}/complete").status_code,
        "download": admin.get(f"/vaults/{vid}/files/{absent}/download").status_code,
        # A real caller who is really not allowed, not just a resource that is not there.
        "outsider-complete": outsider.post(
            f"/vaults/{vid}/uploads/{absent}/complete").status_code,
        "outsider-download": outsider.get(
            f"/vaults/{vid}/files/{file_id}/download").status_code,
    }
    refused_before_reaching_the_gate = _transfer_stats(admin)["transfersRefused"]

    holder.join(timeout=60)

    assert refused_before_reaching_the_gate == baseline_refusals, (
        "a caller who was never allowed in was counted as load the deployment shed")

    for path, code in answers.items():
        assert code != 503, (
            f"the {path} endpoint made a caller queue for a slot before telling them the thing "
            "they named does not exist")
        assert code in (403, 404, 409, 410), f"unexpected answer from {path}: {code}"


def test_a_stored_mime_type_cannot_take_the_deployment_down(admin, temp_vault):
    """A MIME type is whatever the client said it was, and it is stored verbatim.

    It ends up in the Content-Type header, which is encoded as Latin-1, so a value outside that
    range raises while the response is being built -- and it raises every time, for that file, for
    ever. Worse, it raises after the download has recorded that it handed its transfer slot to the
    streaming generator, so the slot is never returned: a handful of such files and the deployment
    refuses all transfers until it is restarted. One upload, no privileges, no large file.
    """
    vid = temp_vault["id"]
    hostile = [
        "text/plain; note=\u2603",              # outside Latin-1: raises in the header encode
        "text/plain\r\nX-Injected: yes",         # header injection, and ASCII, so an encode allows it
        "\u00e9" * 4,                            # Latin-1 but not a media type at all
    ]

    before = _transfer_stats(admin)
    for i, mime in enumerate(hostile):
        name = unique(f"mime{i}") + ".bin"
        body = b"hostile mime" * 64
        init = admin.post(f"/vaults/{vid}/uploads", json={
            "file_name": name, "total_size": len(body), "total_chunks": 1,
            "chunk_size": MB, "mime_type": mime,
        })
        assert init.status_code == 200, init.text
        sid = init.json()["session_id"]
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0",
                         data=body, headers=_OCTET).status_code == 200
        stored = admin.post(f"/vaults/{vid}/uploads/{sid}/complete")
        assert stored.status_code == 200, stored.text

        got = admin.get(f"/vaults/{vid}/files/{stored.json()['id']}/download")
        assert got.status_code == 200, (
            f"a file stored with mime_type {mime!r} cannot be downloaded at all: "
            f"{got.status_code}")
        assert got.content == body
        assert "\r" not in got.headers.get("Content-Type", ""), "the stored value reached a header"

    after = _transfer_stats(admin)
    assert after["transfersInFlight"] == before["transfersInFlight"], (
        f"{len(hostile)} downloads left "
        f"{after['transfersInFlight'] - before['transfersInFlight']} transfer slots held; the "
        "ceiling now shrinks every time one of these files is fetched")


@pytest.mark.skipif(
    os.environ.get("VAULT_TRANSFER_LIMIT_IS_ONE") != "1",
    reason="needs a deployment configured with MAX_CONCURRENT_TRANSFERS=1 and no queue")
def test_a_refused_upload_does_not_reserve_space_it_never_uses(admin):
    """Being refused must not make the vault look fuller than it is.

    An upload reserves the space it is about to need before it is admitted, and the reservation
    lives for five minutes. If a refusal leaves it behind, a trickle of refused uploads holds a
    size-limited vault at "not enough space" while storing nothing at all -- a denial of service
    against the vault, made out of requests the deployment already declined to do any work for.
    """
    made = admin.post("/vaults", json={
        "name": unique("reservation"), "vault_type": "standard",
        "size_limit_gb": 0.05,                        # ~51 MB: the reservation path only runs
    })                                                # on a vault that actually has a ceiling
    assert made.status_code == 200, made.text
    vid = made.json()["id"]
    ceiling = admin.get(f"/vaults/{vid}").json().get("size_limit") or 0
    assert ceiling > 0, (
        "this vault has no size limit, so nothing reserves space and the test proves nothing")

    filler = b"F" * (24 * MB)                          # half the ceiling, really stored
    file_id = _upload(admin, vid, unique("filler") + ".bin", filler, chunk_size=6 * MB)

    def _hold():
        client = admin.clone_anonymous()
        client.session.headers.update({"Authorization": f"Bearer {admin.token}"})
        response = client.get(f"/vaults/{vid}/files/{file_id}/download", stream=True)
        next(response.iter_content(8192))
        time.sleep(10)
        response.close()

    holder = threading.Thread(target=_hold)
    holder.start()
    time.sleep(1.5)

    refused = 0
    for i in range(4):
        answer = admin.post(
            f"/vaults/{vid}/files",
            files=[("files", (unique(f"phantom{i}") + ".bin", b"p" * (4 * MB),
                              "application/octet-stream"))])
        assert answer.status_code == 503, f"expected a refusal, got {answer.status_code}"
        refused += 1

    holder.join(timeout=60)
    assert refused == 4

    # The slot is free again. The only thing that could stop this is space the refusals reserved
    # and never gave back.
    stored = admin.post(
        f"/vaults/{vid}/files",
        files=[("files", (unique("real") + ".bin", b"r" * (16 * MB),
                          "application/octet-stream"))])
    assert stored.status_code == 200, (
        f"a real upload was answered {stored.status_code} after {refused} refused ones; they left "
        f"their space reservations behind: {stored.text[:200]}")

    admin.delete(f"/vaults/{vid}")


def test_the_request_teardown_never_masks_the_real_answer(admin, temp_user_client, temp_vault):
    """An upload that is refused before it reaches the vault must still say why.

    The teardown at the end of the upload request releases the transfer slot and the space
    reservation, and it runs on every path out -- including the ones that raise before either
    exists. If it reads something that was never bound, it raises on the way out and replaces the
    real answer with a server error: a caller who should have been told "you may not write here"
    is told "something broke", and the deployment looks unhealthy instead of correct.
    """
    vid = temp_vault["id"]

    denied = temp_user_client.post(
        f"/vaults/{vid}/files",
        files=[("files", (unique("denied") + ".bin", b"d" * 2048,
                          "application/octet-stream"))])
    assert denied.status_code in (401, 403, 404), (
        f"a caller with no write access was answered {denied.status_code}; the teardown replaced "
        f"the real answer: {denied.text[:200]}")

    # And the refusal cost nothing: the deployment still accepts a legitimate upload.
    stored = admin.post(
        f"/vaults/{vid}/files",
        files=[("files", (unique("after-denial") + ".bin", b"a" * 2048,
                          "application/octet-stream"))])
    assert stored.status_code == 200, (
        f"an upload after a denied one was answered {stored.status_code}; the denied request kept "
        "its slot or its space reservation")
