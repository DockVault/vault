"""Resuming an upload is something a client asks for, not something the server infers.

Resume matching keyed on vault, folder, filename, total size and chunk count. Nothing in that set
tells a genuine resume apart from a second upload of the same file — so an interrupted upload of a
file that was then edited *without changing its length* was continued rather than restarted, and
the stored object was the old attempt's chunks joined to the new file's. It committed with a 200
and no error anywhere.

A different length was always safe, because the length is part of the match. This closes the one
case where that discrimination is not doing the work.

Two mechanisms, because they answer different halves:

- **Explicit resume** stops the *accidental* case, where a second upload is silently continued.
- **Per-chunk digests** stop the *deliberate* one: a client that genuinely means to resume, whose
  file has changed since, re-reads the chunks the server holds and re-sends the ones that no longer
  match. An edit costs the chunks it touched rather than the whole file.
"""

import hashlib
import uuid

import pytest

from conftest import unique


pytestmark = pytest.mark.integration


@pytest.fixture
def vault(admin):
    r = admin.post("/vaults", json={"name": unique("resume")})
    r.raise_for_status()
    vid = r.json()["id"]
    yield vid
    admin.delete_vault(vid)


def _init(admin, vault_id, name, size=20, chunks=2, **extra):
    body = {"file_name": name, "total_size": size, "total_chunks": chunks, "chunk_size": 10}
    body.update(extra)
    return admin.post(f"/vaults/{vault_id}/uploads", json=body)


def test_a_second_upload_of_one_file_is_not_silently_continued(admin, vault):
    """The defect, at its source.

    Both uploads describe the same file in every way the matcher looked at. Only the caller knows
    whether the second is a continuation or a replacement, so only the caller can say.
    """
    first = _init(admin, vault, "report.bin")
    assert first.status_code in (200, 201), first.text
    sid = first.json()["session_id"]
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                     data=b"AAAAAAAAAA").status_code in (200, 201)

    second = _init(admin, vault, "report.bin")
    assert second.status_code in (200, 201), second.text
    assert second.json()["session_id"] != sid, (
        "a second upload of the same file was handed the first attempt's session and its chunks -- "
        "finishing it stores the earlier content, or a mixture of both")
    assert second.json()["received_chunks"] == [], (
        "the new session was told it already holds chunks it never received")


def test_a_resume_that_says_so_continues_the_same_session(admin, vault):
    """The other half. Refusing every continuation would also pass the test above."""
    first = _init(admin, vault, "resumable.bin")
    assert first.status_code in (200, 201), first.text
    sid = first.json()["session_id"]
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                     data=b"AAAAAAAAAA").status_code in (200, 201)

    again = _init(admin, vault, "resumable.bin", resume_session_id=sid)
    assert again.status_code in (200, 201), again.text
    assert again.json()["session_id"] == sid
    assert again.json()["received_chunks"] == [0], (
        "a declared resume did not get the progress it asked to continue")

    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/1",
                     data=b"BBBBBBBBBB").status_code in (200, 201)
    done = admin.post(f"/vaults/{vault}/uploads/{sid}/complete")
    assert done.status_code in (200, 201), done.text
    stored = admin.get(f"/vaults/{vault}/files/{done.json()['id']}/download").content
    assert stored == b"AAAAAAAAAABBBBBBBBBB", stored


def test_naming_a_session_that_cannot_be_continued_is_refused(admin, vault):
    """Silently opening a new upload the caller did not ask for is how progress goes missing.

    They asked to continue something specific. If it is gone, expired, describes a different file
    or belongs to somebody else, saying so is the only answer that lets them decide what to do.
    """
    gone = _init(admin, vault, "ghost.bin", resume_session_id=str(uuid.uuid4()))
    assert gone.status_code == 409, f"{gone.status_code} {gone.text}"
    assert "resume_target_gone" in gone.text, gone.text

    # A real session, but named from a request describing a different file.
    real = _init(admin, vault, "real.bin")
    assert real.status_code in (200, 201), real.text
    sid = real.json()["session_id"]
    wrong = _init(admin, vault, "real.bin", size=40, chunks=4, resume_session_id=sid)
    assert wrong.status_code == 409, (
        f"a session was continued by a request describing a different file: {wrong.text}")


def test_the_server_reports_a_digest_for_every_chunk_it_holds(admin, vault):
    """What a resuming client needs to tell whether its own copy still matches.

    Computed by the server from the bytes it actually stored, not supplied by the client -- a
    digest the uploader asserts proves nothing about what is on disk.
    """
    r = _init(admin, vault, "digest.bin")
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    for i, part in ((0, b"AAAAAAAAAA"), (1, b"BBBBBBBBBB")):
        assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/{i}",
                         data=part).status_code in (200, 201)

    detail = admin.get(f"/vaults/{vault}/uploads/{sid}")
    assert detail.status_code == 200, detail.text
    sums = detail.json().get("chunk_checksums")
    assert sums, "no digests were reported, so a resuming client cannot check anything"
    assert sums[str(0)] == hashlib.sha256(b"AAAAAAAAAA").hexdigest()
    assert sums[str(1)] == hashlib.sha256(b"BBBBBBBBBB").hexdigest()

    # And a re-sent chunk updates its digest, rather than leaving the old one behind.
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/1",
                     data=b"CCCCCCCCCC").status_code in (200, 201)
    sums = admin.get(f"/vaults/{vault}/uploads/{sid}").json()["chunk_checksums"]
    assert sums[str(1)] == hashlib.sha256(b"CCCCCCCCCC").hexdigest(), (
        "a re-sent chunk kept the digest of the bytes it replaced")


def test_an_edited_file_is_detectable_chunk_by_chunk(admin, vault):
    """The deliberate-resume case, from the server's side.

    A client that asks to continue, and whose file changed since, can find out exactly which of
    the chunks the server holds no longer match -- so it re-sends those and keeps the rest. This is
    what makes an edit cost the chunks it touched instead of the whole upload.
    """
    original = b"AAAAAAAAAA" + b"BBBBBBBBBB"
    edited = b"AAAAAAAAAA" + b"ZZZZZZZZZZ"      # same length, second half changed

    r = _init(admin, vault, "edited.bin")
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    for i in (0, 1):
        assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/{i}",
                         data=original[i * 10:(i + 1) * 10]).status_code in (200, 201)

    resumed = _init(admin, vault, "edited.bin", resume_session_id=sid)
    assert resumed.status_code in (200, 201), resumed.text
    sums = admin.get(f"/vaults/{vault}/uploads/{sid}").json()["chunk_checksums"]

    stale = [i for i in (0, 1)
             if sums[str(i)] != hashlib.sha256(edited[i * 10:(i + 1) * 10]).hexdigest()]
    assert stale == [1], (
        f"the changed chunk should be the only one that does not match; got {stale}")

    # Re-sending only that one produces the edited file, not a mixture of the two.
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/1",
                     data=edited[10:20]).status_code in (200, 201)
    done = admin.post(f"/vaults/{vault}/uploads/{sid}/complete")
    assert done.status_code in (200, 201), done.text
    stored = admin.get(f"/vaults/{vault}/files/{done.json()['id']}/download").content
    assert stored == edited, f"expected the edited file, stored {stored}"


def test_a_file_that_changed_length_was_always_safe(admin, vault):
    """Recorded because it is the reason this defect was only ever half a defect.

    The length is part of what a resume names, so a file edited to a different size never matched
    an existing session and always started a new upload. Pinned so a future change to the matcher
    cannot quietly widen the problem to the case that was fine.
    """
    first = _init(admin, vault, "grew.bin", size=20, chunks=2)
    assert first.status_code in (200, 201), first.text
    sid = first.json()["session_id"]
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                     data=b"AAAAAAAAAA").status_code in (200, 201)

    bigger = _init(admin, vault, "grew.bin", size=30, chunks=3, resume_session_id=sid)
    assert bigger.status_code == 409, (
        "a session was continued by an upload describing a different length")


def test_the_digest_is_of_what_was_stored_not_what_was_claimed(admin, vault):
    """A digest the uploader supplies proves nothing about what is on disk.

    The whole value of these is that a resuming client can trust them, and it can only trust them
    because the server computed them itself. Preferring a client-supplied header passed the entire
    suite before this test existed -- the property was asserted in prose and nowhere else.
    """
    r = _init(admin, vault, "asserted.bin", size=10, chunks=1)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]

    lie = hashlib.sha256(b"not what was sent").hexdigest()
    sent = admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/0", data=b"AAAAAAAAAA",
                     headers={"X-Chunk-Sha256": lie, "Digest": lie, "Content-MD5": lie})
    assert sent.status_code in (200, 201), sent.text

    sums = admin.get(f"/vaults/{vault}/uploads/{sid}").json()["chunk_checksums"]
    assert sums[str(0)] == hashlib.sha256(b"AAAAAAAAAA").hexdigest(), (
        f"the server reported a digest the client asserted rather than one it computed: {sums}")
    assert sums[str(0)] != lie
