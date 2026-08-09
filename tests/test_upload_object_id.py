"""An encrypted upload must finish under the id its material was bound to.

A zero-knowledge client seals a file's name against the object's id, and a coming content format
derives the content key from it too. The client declares that id when it finishes the upload — and
if the declaration is missing, malformed, not an object, or not an id, the server swallows all four
cases identically and assigns its own instead.

That fallback is reachable without anyone doing anything wrong: the client only sends the id when
it has one, and a queued upload stored before that field existed comes back without it. Today the
cost is a filename that will not open. Once content is keyed the same way it is the whole file —
unopenable forever, and reported to its owner as damaged rather than as a mistake.

**The check has to be at the start, not the end.** At the end the server cannot tell a client that
lost its id from an older client that never sent one, so it can refuse neither without breaking the
other. Declared at the start, those are two different sessions and only one of them is wrong.
"""

import uuid

import pytest

from conftest import unique, ensure_ecc_keypair


def _init(admin, vault_id, **extra):
    body = {
        "file_name": "note.txt",
        "total_size": 11,
        "total_chunks": 1,
        "chunk_size": 5 * 1024 * 1024,
    }
    body.update(extra)
    return admin.post(f"/vaults/{vault_id}/uploads", json=body)


_BI = uuid.uuid4().hex


@pytest.fixture(scope="module")
def zk_vault(admin):
    import base64

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        ensure_ecc_keypair(admin)
        r = admin.post("/vaults", json={
            "name": unique("objidzk"), "type": "zero_knowledge",
            "wrapped_dek": base64.b64encode(b"dek-" + uuid.uuid4().bytes).decode(),
            "ephemeral_public_key": base64.b64encode(b"eph-" + uuid.uuid4().bytes).decode(),
        })
        r.raise_for_status()
        vid = r.json()["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})
    yield vid
    admin.delete_vault(vid)


def _zk_init(admin, vault_id, file_id, name_bi):
    """An encrypted upload declares a blind index instead of a name; that is what pairs a resume."""
    import base64

    body = {
        "total_size": 11, "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
        "enc_name": "zk2:" + base64.b64encode(b"sealed-name").decode(),
        "enc_mime": "zk2:" + base64.b64encode(b"sealed-mime").decode(),
        "name_bi": name_bi,
        "zk_key_version": 1,
    }
    if file_id is not None:
        body["file_id"] = str(file_id)
    return admin.post(f"/vaults/{vault_id}/uploads", json=body)


@pytest.fixture
def std_vault(admin):
    r = admin.post("/vaults", json={"name": unique("objid")})
    r.raise_for_status()
    vid = r.json()["id"]
    yield vid
    admin.delete_vault(vid)


@pytest.mark.integration
def test_an_upload_that_declared_an_id_must_finish_with_it(admin, std_vault):
    """The load-bearing one. Anything else silently rebinds the file to an id nothing matches."""
    declared = uuid.uuid4()
    r = _init(admin, std_vault, file_id=str(declared))
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{std_vault}/uploads/{sid}/chunks/0",
                     data=b"hello world").status_code in (200, 201)

    wrong = admin.post(f"/vaults/{std_vault}/uploads/{sid}/complete",
                       json={"file_id": str(uuid.uuid4())})
    assert wrong.status_code == 400, (
        f"an upload finished under an id it never declared: {wrong.status_code} {wrong.text}"
    )
    assert "declared" in wrong.text

    ok = admin.post(f"/vaults/{std_vault}/uploads/{sid}/complete",
                    json={"file_id": str(declared)})
    assert ok.status_code in (200, 201), ok.text
    assert ok.json()["id"] == str(declared)


@pytest.mark.integration
def test_an_upload_that_declared_an_id_may_not_finish_without_one(admin, std_vault):
    """The reachable case: the client had an id at the start and lost it before the end.

    This is the shape a stored queue entry from an older build comes back in, and the one the
    server previously answered by quietly assigning its own id.
    """
    declared = uuid.uuid4()
    r = _init(admin, std_vault, file_id=str(declared))
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{std_vault}/uploads/{sid}/chunks/0",
                     data=b"hello world").status_code in (200, 201)

    # Bodyless: exactly what the client sends when it has no id to send.
    bare = admin.post(f"/vaults/{std_vault}/uploads/{sid}/complete")
    assert bare.status_code == 400, (
        f"a declared id was dropped and the server assigned its own: {bare.status_code} {bare.text}"
    )
    # This branch exists only to say something more useful than "does not match" when the id is
    # absent rather than wrong. Without pinning the wording, deleting the branch left the suite
    # green -- the fall-through refuses too, just less helpfully.
    assert "must supply the same one" in bare.text, bare.text


@pytest.mark.integration
def test_an_upload_that_declared_nothing_still_works(admin, std_vault):
    """A client that never declares an id keeps the old behaviour exactly.

    This is why the check lives at the start. Refusing a bodyless completion outright would break
    every client that has never sent an id, which is most of them.
    """
    r = _init(admin, std_vault)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{std_vault}/uploads/{sid}/chunks/0",
                     data=b"hello world").status_code in (200, 201)

    done = admin.post(f"/vaults/{std_vault}/uploads/{sid}/complete")
    assert done.status_code in (200, 201), done.text
    assert uuid.UUID(done.json()["id"])


@pytest.mark.integration
def test_a_malformed_declared_id_is_refused_at_the_start(admin, std_vault):
    """Rejected by the type at the door, where the message is about the actual fault."""
    for bad in ("not-a-uuid", "../../etc/passwd", "x" * 400):
        r = _init(admin, std_vault, file_id=bad)
        assert r.status_code == 422, f"{bad!r} was accepted: {r.status_code} {r.text}"


@pytest.mark.unit
def test_the_client_declares_the_id_when_the_upload_starts():
    """Declared at init, not only at completion — the whole point of the change.

    Pinned as source because nothing in this suite runs the upload queue, and a client that
    silently stopped declaring would leave the server with nothing to enforce.
    """
    from pathlib import Path
    app_js = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(
        encoding="utf-8")
    init_body = app_js.split("total_chunks: it.totalChunks", 1)[1].split("}),", 1)[0]
    # The VALUE, not just the field. Sending `file_id: null` with the real expression left in a
    # comment, and sending the blind index in place of the id, both passed the earlier form of
    # this test -- and neither declares anything the server can enforce.
    #
    # Comments are stripped, not just skipped: the first attempt at this test dropped lines that
    # START with `//` and was still fooled by `file_id: null,  // it.clientFileId ...`, where the
    # real expression sits in a TRAILING comment and satisfies a naive substring check.
    declared = []
    for ln in init_body.splitlines():
        code = ln.split("//", 1)[0]
        if "file_id:" in code:
            declared.append(code)
    assert len(declared) == 1, f"expected one declaration of the object id, found: {declared}"
    assert "it.clientFileId" in declared[0], (
        f"the upload declares something other than its object id: {declared[0].strip()}"
    )


@pytest.mark.unit
def test_an_encrypted_upload_without_an_object_id_is_not_completed():
    """A queued entry from before the field existed comes back without one.

    Completing it would bind the file to a server-assigned id its sealed name does not match.
    Stopping is the only safe answer, and it has to be loud — the material is already encrypted.
    """
    from pathlib import Path
    app_js = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(
        encoding="utf-8")
    guard_at = app_js.index("if (it.isZk && !it.clientFileId) {")
    complete_at = app_js.index("const zkComplete = it.isZk && it.clientFileId;")
    assert guard_at < complete_at, "the guard must come before the completion decision"
    # And it must stop. A warning here lets the upload finish under a server-assigned id, which is
    # the outcome the guard exists to prevent -- and that mutation survived the earlier version.
    assert "throw" in app_js[guard_at:complete_at], (
        "the guard warns instead of stopping, so the upload completes anyway"
    )


@pytest.mark.unit
def test_the_unencrypted_queue_path_refuses_a_zero_knowledge_vault():
    """It builds an entry with no encryption flag, so the request would carry a plaintext name.

    Nothing calls it today, which is exactly why it is worth closing: a future caller would look
    entirely reasonable and the leak would be silent.

    Asserting the guard's SHAPE, not its presence. Inverting the comparison -- refusing ordinary
    vaults and permitting encrypted ones, the exact opposite of the intent -- passed the earlier
    version of this test, as did turning the throw into a console warning.
    """
    from pathlib import Path
    app_js = (Path(__file__).resolve().parents[1] / "static" / "js" / "app.js").read_text(
        encoding="utf-8")
    body = app_js.split("    enqueueFiles(files) {", 1)[1].split("\n    },", 1)[0]

    guard = body[body.index("if (isZkVault"):]
    guard = guard[:guard.index("}") + 1]
    assert guard.startswith("if (isZkVault(state.currentVault))"), (
        f"the guard does not refuse encrypted vaults -- it may be inverted: {guard!r}"
    )
    assert "throw" in guard, "the guard warns instead of stopping, so the upload proceeds anyway"
    # The queue-entry FIELD, not the substring: the guard's own helper is called isZkVault, and
    # checking for a bare "isZk" started matching that instead of what it was written to catch.
    assert "isZk:" not in body, (
        "this path now sets an encryption flag on its queue entry -- if it genuinely encrypts, the "
        "guard above should go and this test with it; if it does not, the flag is a lie"
    )


@pytest.mark.integration
def test_an_encrypted_upload_is_protected_too(admin):
    """The vault type this change exists for, and the one nothing here covered.

    Every other test here uses an ordinary vault, so switching the protection off for exactly
    zero-knowledge uploads passed all of them -- and that is the one case that matters, because a
    zero-knowledge file's name is sealed against its id and its content soon will be.
    """
    import base64

    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        ensure_ecc_keypair(admin)
        v = admin.post("/vaults", json={
            "name": unique("objidzk"), "type": "zero_knowledge",
            "wrapped_dek": base64.b64encode(b"dek-" + uuid.uuid4().bytes).decode(),
            "ephemeral_public_key": base64.b64encode(b"eph-" + uuid.uuid4().bytes).decode(),
        })
        v.raise_for_status()
        vid = v.json()["id"]
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})

    try:
        declared = uuid.uuid4()
        r = admin.post(f"/vaults/{vid}/uploads", json={
            "total_size": 11, "total_chunks": 1, "chunk_size": 5 * 1024 * 1024,
            "enc_name": "zk2:" + base64.b64encode(b"sealed-name").decode(),
            "enc_mime": "zk2:" + base64.b64encode(b"sealed-mime").decode(),
            "name_bi": uuid.uuid4().hex,
            "zk_key_version": 1,
            "file_id": str(declared),
        })
        assert r.status_code in (200, 201), r.text
        sid = r.json()["session_id"]
        assert admin.put(f"/vaults/{vid}/uploads/{sid}/chunks/0",
                         data=b"ciphertext!").status_code in (200, 201)

        wrong = admin.post(f"/vaults/{vid}/uploads/{sid}/complete",
                           json={"file_id": str(uuid.uuid4())})
        assert wrong.status_code == 400, (
            f"an encrypted upload finished under an id its name is not sealed against: "
            f"{wrong.status_code} {wrong.text}"
        )
        ok = admin.post(f"/vaults/{vid}/uploads/{sid}/complete",
                        json={"file_id": str(declared)})
        assert ok.status_code in (200, 201), ok.text
        assert ok.json()["id"] == str(declared)
    finally:
        admin.delete_vault(vid)


@pytest.mark.integration
def test_resuming_with_a_different_object_id_is_refused_at_the_start(admin, std_vault):
    """Not silently ignored, and not discovered at the end.

    A resumed session keeps the id it was opened with, because the chunks already buffered belong
    to that encryption. Adopting a new one would assemble a file from two of them. But quietly
    keeping the old id was no kinder: the caller re-uploaded everything and only found out at the
    end, and each attempt pushed the session's expiry out another day.
    """
    first = uuid.uuid4()
    r = _init(admin, std_vault, file_id=str(first))
    assert r.status_code in (200, 201), r.text
    session_one = r.json()["session_id"]

    again = _init(admin, std_vault, file_id=str(uuid.uuid4()))
    assert again.status_code == 409, (
        f"a resume under a different object id was accepted: {again.status_code} {again.text}"
    )
    assert "object_id_mismatch" in again.text, again.text

    # The original id still resumes the same session, so this refuses a conflict and not a retry.
    same = _init(admin, std_vault, file_id=str(first))
    assert same.status_code in (200, 201), same.text
    assert same.json()["session_id"] == session_one

    # The caller has to be told WHICH upload to discard. Nothing else identifies it, and it is the
    # caller's own session -- the listing endpoint already returns more about it than this does.
    assert again.json()["detail"]["session_id"] == session_one


@pytest.mark.integration
def test_an_encrypted_resume_that_changes_the_object_id_is_refused(admin, zk_vault):
    """The resume rule, on the vault type it exists for.

    Every earlier test of it used an ordinary vault, so switching the rule off for exactly
    encrypted uploads passed all of them -- the same blind spot as the completion check had,
    reappearing in the code written to close it.
    """
    first = uuid.uuid4()
    r = _zk_init(admin, zk_vault, first, name_bi=_BI)
    assert r.status_code in (200, 201), r.text
    session_one = r.json()["session_id"]

    again = _zk_init(admin, zk_vault, uuid.uuid4(), name_bi=_BI)
    assert again.status_code == 409, (
        f"an encrypted resume adopted a different object id: {again.status_code} {again.text}"
    )
    assert again.json()["detail"]["code"] == "object_id_mismatch"

    same = _zk_init(admin, zk_vault, first, name_bi=_BI)
    assert same.status_code in (200, 201), same.text
    assert same.json()["session_id"] == session_one


@pytest.mark.integration
def test_a_declared_upload_may_not_adopt_a_session_that_declared_nothing(admin, zk_vault):
    """The hole the first version of the resume rule left open, and the one it is named after.

    That version only compared the two ids when BOTH sides had one, so a client that declares an id
    could resume a session opened by a client that did not. The server keeps the ORIGINAL session's
    sealed name and commits the row under the NEW id -- a stored name that will never open again.
    Reproduced end to end against a running vault: the stored name decrypts under the first id and
    fails under the second.

    Comparing the ids directly, present or absent, closes this and its mirror at once.
    """
    bi = uuid.uuid4().hex

    legacy = _zk_init(admin, zk_vault, None, name_bi=bi)
    assert legacy.status_code in (200, 201), legacy.text

    adopt = _zk_init(admin, zk_vault, uuid.uuid4(), name_bi=bi)
    assert adopt.status_code == 409, (
        f"a declared upload adopted an undeclared session's chunks and sealed name: "
        f"{adopt.status_code} {adopt.text}"
    )


@pytest.mark.integration
def test_an_undeclared_resume_of_a_declared_upload_is_refused_at_the_start(admin, zk_vault):
    """The mirror, refused at the start rather than after the whole re-upload.

    This direction was accepted and then failed at completion -- verbatim the cost the refusal was
    written to remove, still being paid in the other direction.
    """
    bi = uuid.uuid4().hex

    declared = _zk_init(admin, zk_vault, uuid.uuid4(), name_bi=bi)
    assert declared.status_code in (200, 201), declared.text

    undeclared = _zk_init(admin, zk_vault, None, name_bi=bi)
    assert undeclared.status_code == 409, (
        f"an undeclared resume was accepted and would have been refused only at the end: "
        f"{undeclared.status_code} {undeclared.text}"
    )
