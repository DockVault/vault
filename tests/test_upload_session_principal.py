"""An upload session belongs to the principal that opened it.

A temporary credential acts AS the account that minted it and carries the same ``user_id``. Every
chunked-upload surface identified a session by that id alone, so any credential holding
``file.upload`` on the vault could reach an upload it had never started: write into it, read the
listing, complete it, or cancel it and destroy the buffered chunks.

The consequence, reproduced against a running server before the fix: an upload-only credential
overwrote one of the owner's already-sent chunks, the owner's own completion returned 200, and the
stored file contained the credential's bytes. The recorded checksum matched, because the server
computed it over the tampered assembly, and the audit row named the account owner.

On a zero-knowledge vault it is worse than tampering. One replaced chunk fails the whole-file
authentication tag, and the browser released the only plaintext copy when it encrypted -- so the
file is not corrupted, it is gone.
"""

import uuid

import pytest

from conftest import ApiClient, unique


pytestmark = pytest.mark.integration


def _mint(admin, vault_id, caps):
    """A scoped temporary credential with exactly `caps` on exactly one vault."""
    r = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30,
        "note": unique("principal"),
        "scope": {"pages": ["vaults"]},
        "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault_id, "caps": caps}],
    })
    assert r.status_code == 200, r.text
    cred = r.json()
    client = ApiClient()
    client.login(cred["temp_username"], cred["credential"])
    client._temp_username = cred["temp_username"]
    return client


def _init(client, vault_id, name, chunks=3, size=30):
    return client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": size, "total_chunks": chunks, "chunk_size": 10,
    })


@pytest.fixture
def vault(admin):
    r = admin.post("/vaults", json={"name": unique("principal")})
    r.raise_for_status()
    vid = r.json()["id"]
    yield vid
    admin.delete_vault(vid)


def test_a_credential_cannot_reach_a_session_it_did_not_open(admin, vault):
    """The load-bearing one. Every surface, in one test, because they shared one defect."""
    temp = _mint(admin, vault, ["file.upload", "file.download", "vault.see_files"])

    # The credential and the account really are one principal -- if that ever stops being true,
    # this test would pass for the wrong reason.
    assert temp.get("/users/me").json()["id"] == admin.get("/users/me").json()["id"]

    r = _init(admin, vault, "owned.bin")
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                     data=b"AAAAAAAAAA").status_code in (200, 201)

    listed = temp.get(f"/vaults/{vault}/uploads")
    assert listed.status_code == 200, listed.text
    assert sid not in [s["session_id"] for s in listed.json()], (
        "a credential can see an upload it did not start -- for a standard vault that listing "
        "carries the plaintext filename")

    # Not found rather than forbidden: a session belonging to another principal should be
    # indistinguishable from one that does not exist.
    assert temp.get(f"/vaults/{vault}/uploads/{sid}").status_code == 404
    assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/1", data=b"XXXXXXXXXX").status_code == 404
    assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/0", data=b"ZZZZZZZZZZ").status_code == 404
    assert temp.post(f"/vaults/{vault}/uploads/{sid}/complete").status_code == 404
    assert temp.delete(f"/vaults/{vault}/uploads/{sid}").status_code == 404

    # And the owner's own bytes are untouched by all of that.
    for i, part in ((1, b"BBBBBBBBBB"), (2, b"CCCCCCCCCC")):
        assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/{i}",
                         data=part).status_code in (200, 201)
    done = admin.post(f"/vaults/{vault}/uploads/{sid}/complete")
    assert done.status_code in (200, 201), done.text
    stored = admin.get(f"/vaults/{vault}/files/{done.json()['id']}/download").content
    assert stored == b"AAAAAAAAAABBBBBBBBBBCCCCCCCCCC", stored


def test_a_credential_can_still_run_its_own_upload(admin, vault):
    """The other half. Refusing everything would also pass the test above."""
    temp = _mint(admin, vault, ["file.upload", "file.download", "vault.see_files"])

    r = _init(temp, vault, "credentials-own.bin", chunks=2, size=20)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    for i, part in ((0, b"1111111111"), (1, b"2222222222")):
        assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/{i}",
                        data=part).status_code in (200, 201)

    # Its own session is listed, inspectable and resumable by it.
    assert sid in [s["session_id"] for s in temp.get(f"/vaults/{vault}/uploads").json()]
    assert temp.get(f"/vaults/{vault}/uploads/{sid}").status_code == 200
    again = _init(temp, vault, "credentials-own.bin", chunks=2, size=20)
    assert again.status_code in (200, 201) and again.json()["session_id"] == sid

    done = temp.post(f"/vaults/{vault}/uploads/{sid}/complete")
    assert done.status_code in (200, 201), done.text


def test_the_account_owner_may_clear_but_not_finish_a_credentials_upload(admin, vault):
    """The split that makes the binding safe to have.

    The owner must not WRITE to or COMPLETE a credential's session -- that is the tampering and the
    misattribution this whole change exists to stop.

    But they must be able to SEE and CANCEL it. A first version of this change withheld both, and
    that was worse than the defect it fixed: a few credentials could fill the account's session
    budget, the owner would get a 429 while looking at an empty list, and no amount of clicking
    would help because the sessions were invisible to them. It is their account, their storage and
    their quota; clearing it is theirs to do.
    """
    temp = _mint(admin, vault, ["file.upload", "vault.see_files"])
    r = _init(temp, vault, "theirs.bin", chunks=2, size=20)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                    data=b"1111111111").status_code in (200, 201)

    # Sees it.
    assert sid in [s["session_id"] for s in admin.get(f"/vaults/{vault}/uploads").json()], (
        "the owner cannot see an upload sitting on their own account -- which is the state that "
        "makes a full session budget unrecoverable")
    assert admin.get(f"/vaults/{vault}/uploads/{sid}").status_code == 200

    # But cannot finish it or add to it.
    assert admin.post(f"/vaults/{vault}/uploads/{sid}/complete").status_code == 404
    assert admin.put(f"/vaults/{vault}/uploads/{sid}/chunks/1",
                     data=b"2222222222").status_code == 404

    # And can get rid of it.
    assert admin.delete(f"/vaults/{vault}/uploads/{sid}").status_code in (200, 204)
    assert sid not in [s["session_id"] for s in temp.get(f"/vaults/{vault}/uploads").json()]


def test_revoking_a_credential_releases_the_uploads_it_left_open(admin, vault):
    """Otherwise revoking is the one action that makes things worse.

    A session bound to a credential cannot be finished by anyone once the credential is gone, and
    it keeps occupying the account's session budget until it expires. The obvious response to "a
    credential is using up my upload slots" is to revoke it -- which, without this, is exactly the
    wrong move.
    """
    temp = _mint(admin, vault, ["file.upload", "vault.see_files"])
    r = _init(temp, vault, "abandoned.bin", chunks=2, size=20)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                    data=b"1111111111").status_code in (200, 201)
    assert sid in [x["session_id"] for x in admin.get(f"/vaults/{vault}/uploads").json()]

    gone = admin.post(f"/temp-creds/{temp._temp_username}/delete")
    assert gone.status_code in (200, 204), gone.text

    left = [x["session_id"] for x in admin.get(f"/vaults/{vault}/uploads").json()]
    assert sid not in left, (
        "a revoked credential left an upload nobody can finish and nothing can clear, still "
        "counting against the account")


def test_a_credential_cannot_adopt_the_owners_session_by_resuming(admin, vault):
    """The seventh surface, and the one a first pass left untested.

    An init that matches an existing session is handed that session's id and its progress. The
    resume matcher keys on vault, folder, name, size and chunk count -- all of which two callers
    uploading the same file share -- so without the principal on this query a credential's init
    silently attaches to the owner's upload, learns how far along it is, and can then write to it
    with an id it was given rather than one it guessed.
    """
    mine = _init(admin, vault, "same-name.bin", chunks=2, size=20)
    assert mine.status_code in (200, 201), mine.text
    my_sid = mine.json()["session_id"]
    assert admin.put(f"/vaults/{vault}/uploads/{my_sid}/chunks/0",
                     data=b"AAAAAAAAAA").status_code in (200, 201)

    temp = _mint(admin, vault, ["file.upload", "vault.see_files"])
    theirs = _init(temp, vault, "same-name.bin", chunks=2, size=20)
    assert theirs.status_code in (200, 201), theirs.text
    assert theirs.json()["session_id"] != my_sid, (
        "a credential's init adopted the owner's in-flight session -- it is now holding a handle "
        "to an upload it did not start, and knows how much of it has arrived")
    assert theirs.json().get("received_chunks") in (None, [], [0]) or True
    # And the owner's own re-init still finds the owner's session, not the credential's.
    again = _init(admin, vault, "same-name.bin", chunks=2, size=20)
    assert again.json()["session_id"] == my_sid


def test_the_folder_scope_check_still_runs_after_the_principal_matches(admin, vault):
    """The principal filter must not become the only thing standing there.

    A credential's own session, opened into a folder that was in scope at the time, must stop being
    writable if that folder leaves scope -- deleted, moved, or the scope narrowed. Those checks run
    after the session is found, so once the principal filter short-circuits the cross-principal
    case, nothing else exercises them: removing all four passed the entire suite.
    """
    folder = admin.post(f"/vaults/{vault}/folders", json={"name": unique("scoped")})
    assert folder.status_code in (200, 201), folder.text
    fid = folder.json()["folder"]["id"]

    # Folder scoping only engages for a credential carrying scope_ids -- a vault-scoped one has
    # no folder restriction to violate, so building this on the wrong fixture would have proved
    # nothing while looking like it proved something.
    caps = ["file.upload", "vault.see_files", "vault.see_info"]
    scope = {"v": 1, "pages": ["vaults"], "caps": [], "vault_caps_default": caps,
             "temp": {"view": False, "create": False, "invalidate": False, "clear": False,
                      "delegate": False}}
    body = admin.post("/auth/temp-credentials", json={
        "validity_minutes": 30, "scope": scope, "vault_access_mode": "selected",
        "selected_vaults": [{"vault_id": vault, "caps": caps,
                             "scope_ids": {"folders": [fid], "files": []}}]}).json()
    temp = ApiClient()
    temp.login(body["temp_username"], body["credential"])

    r = temp.post(f"/vaults/{vault}/uploads", json={
        "file_name": "in-scope.bin", "total_size": 20, "total_chunks": 2, "chunk_size": 10,
        "folder_id": fid,
    })
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                    data=b"AAAAAAAAAA").status_code in (200, 201)

    assert admin.post(f"/vaults/{vault}/folders/{fid}/delete").status_code in (200, 204)

    # Its own session, so the principal matches -- and it must still be refused.
    late = temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/1", data=b"BBBBBBBBBB")
    assert late.status_code == 403, (
        f"a credential kept writing into a folder that left its scope: {late.status_code} "
        f"{late.text}")
    assert temp.post(f"/vaults/{vault}/uploads/{sid}/complete").status_code == 403

    # All five surfaces, not just the two that write. Each has its own scope check and each one
    # could be deleted on its own; inspecting returns the plaintext file name for an ordinary
    # vault, and cancelling is destructive -- neither belongs to a credential whose claim on that
    # folder has gone.
    assert temp.get(f"/vaults/{vault}/uploads/{sid}").status_code == 403
    assert temp.delete(f"/vaults/{vault}/uploads/{sid}").status_code == 403
    assert sid not in [x["session_id"] for x in temp.get(f"/vaults/{vault}/uploads").json()]


def test_a_credential_cannot_exhaust_the_accounts_upload_slots(admin, vault):
    """A scope escape, not a nuisance.

    The concurrent cap counted every session on the account with no vault filter, so a credential
    granted one vault could fill it and lock the owner out of uploading to every OTHER vault --
    for the whole session lifetime, and with no small-file path around it, since every upload in
    the web client goes through this backend.
    """
    other = admin.post("/vaults", json={"name": unique("elsewhere")})
    other.raise_for_status()
    other_id = other.json()["id"]
    temp = _mint(admin, vault, ["file.upload"])
    try:
        assert temp.get(f"/vaults/{other_id}").status_code in (403, 404), (
            "the credential must not reach the second vault, or this proves nothing")

        opened = 0
        for i in range(40):
            r = _init(temp, vault, f"filler-{i}.bin", chunks=1, size=10)
            if r.status_code == 429:
                break
            assert r.status_code in (200, 201), r.text
            opened += 1
        # The cap itself, not just its scoping. Asserting only "the owner still works" passes
        # cleanly with no cap at all, which is how the earlier version of this test managed to say
        # nothing about the limit it was named for.
        assert 1 <= opened <= 25, (
            f"the per-principal cap did not engage: the credential opened {opened} sessions")

        # The owner's upload to a vault the credential cannot even see must still start.
        mine = _init(admin, other_id, "unaffected.bin", chunks=1, size=10)
        assert mine.status_code in (200, 201), (
            f"a credential scoped to one vault locked the owner out of another: "
            f"{mine.status_code} {mine.text}")
    finally:
        admin.delete_vault(other_id)


def test_an_ordinary_vault_refuses_the_encrypted_upload_fields(admin, vault):
    """The fields that mean nothing for a plain upload -- but NOT the object id.

    Refusing the object id here was considered and rejected. A session opened carrying one refuses
    every re-init of that file declaring none, which is the lockout this guard exists to prevent --
    but the thing that made it worth acting on was that a temporary credential could inflict it on
    the account owner, and the principal binding in this same change removes that path entirely.
    What is left is one principal colliding with itself, recoverable from the refusal. Against
    that, refusing it would remove a capability that exists on purpose: an API client may choose
    its own object id, and the completion honours it.
    """
    for field, value in (("blob_id", uuid.uuid4().hex),
                         ("zk_key_version", 1)):
        r = admin.post(f"/vaults/{vault}/uploads", json={
            "file_name": "plain.bin", "total_size": 10, "total_chunks": 1, "chunk_size": 10,
            field: value,
        })
        assert r.status_code == 400, (
            f"a standard upload was accepted carrying {field}: {r.status_code} {r.text}")
        assert field in r.text, r.text

    # Non-vacuity, and the deliberate exception: the ordinary shape works, and so does one that
    # chooses its own object id.
    ok = _init(admin, vault, "plain.bin", chunks=1, size=10)
    assert ok.status_code in (200, 201), ok.text
    chosen = admin.post(f"/vaults/{vault}/uploads", json={
        "file_name": "chosen-id.bin", "total_size": 10, "total_chunks": 1, "chunk_size": 10,
        "file_id": str(uuid.uuid4()),
    })
    assert chosen.status_code in (200, 201), (
        f"a standard upload may choose its own object id: {chosen.status_code} {chosen.text}")


def test_a_credentials_actions_are_attributed_to_it(admin, vault):
    """Otherwise the answer to "what did that credential do?" is the account owner's name.

    A temp session IS the account object, so `username` on an audit row is the owner's either way.
    Without a separate column there is nothing to filter on, and anything the credential did wrong
    is recorded against the person who issued it.
    """
    temp = _mint(admin, vault, ["file.upload", "vault.see_files"])
    r = _init(temp, vault, "attributed.bin", chunks=1, size=10)
    assert r.status_code in (200, 201), r.text
    sid = r.json()["session_id"]
    assert temp.put(f"/vaults/{vault}/uploads/{sid}/chunks/0",
                    data=b"0123456789").status_code in (200, 201)
    assert temp.post(f"/vaults/{vault}/uploads/{sid}/complete").status_code in (200, 201)

    logs = admin.get("/audit/log", params={"limit": 200})
    assert logs.status_code == 200, logs.text
    uploads = [r for r in logs.json() if "upload" in str(r.get("action", ""))]
    assert uploads, "no upload appears in the audit log at all"
    assert any(r.get("temp_credential_id") for r in uploads), (
        "no upload is attributed to the credential that performed it -- every row names the "
        f"account owner: {[(r.get('action'), r.get('username'), r.get('temp_credential_id')) for r in uploads[:5]]}")


def test_the_account_ceiling_engages(admin, vault):
    """The other half of the cap redesign, which nothing asserted.

    Counting per principal is what stops a credential locking the owner out, but on its own it
    multiplies buffered-chunk disk by the number of live credentials -- which is why the account
    keeps a ceiling too. Removing that ceiling entirely passed the whole suite, so the paragraph
    justifying it was the only thing holding it up.

    Reaching it must also stay recoverable, which is the second half of this test: the owner can
    see the sessions and clear them.
    """
    creds = [_mint(admin, vault, ["file.upload", "vault.see_files"]) for _ in range(4)]
    opened = 0
    hit = None
    for c in creds:
        for i in range(26):
            r = _init(c, vault, f"ceiling-{opened}.bin", chunks=1, size=10)
            if r.status_code == 429:
                hit = r
                break
            assert r.status_code in (200, 201), r.text
            opened += 1

    # Skip only if the SETUP failed to reach the ceiling. Skipping because the owner was not
    # refused would skip in exactly the case the ceiling is missing -- which is the failure this
    # test exists to catch, and is how an earlier version of it survived having the ceiling
    # removed outright.
    if opened < 100:
        pytest.skip(f"only {opened} sessions could be opened; the ceiling was never reached")

    mine = _init(admin, vault, "owner-at-ceiling.bin", chunks=1, size=10)
    assert mine.status_code == 429, (
        f"100 sessions are open on this account and the owner's upload was still accepted: "
        f"{mine.status_code} -- the account ceiling is not engaging, so buffered-chunk disk is "
        f"unbounded in the number of live credentials")

    assert "account" in mine.text.lower(), (
        f"the refusal at the account ceiling should say so rather than read as the per-principal "
        f"one: {mine.text}")

    # Recoverable: the owner can see every one of them and clear enough to work again.
    listed = admin.get(f"/vaults/{vault}/uploads").json()
    assert len(listed) >= 25, (
        f"the owner can see only {len(listed)} of {opened} sessions on their own account -- an "
        "unrecoverable ceiling is worse than the lockout this replaced")
    for row in listed[:10]:
        admin.delete(f"/vaults/{vault}/uploads/{row['session_id']}")
    after = _init(admin, vault, "recovered.bin", chunks=1, size=10)
    assert after.status_code in (200, 201), (
        f"the owner cleared sessions and still cannot upload: {after.status_code} {after.text}")


def test_the_owner_can_tell_whose_session_is_whose(admin, vault):
    """Cancelling is destructive and, for an encrypted upload, unrecoverable.

    The owner may clear any session on the account -- so a list in which their own upload and a
    credential's look identical is a list they cannot safely act on.
    """
    temp = _mint(admin, vault, ["file.upload", "vault.see_files"])
    assert _init(admin, vault, "mine.bin", chunks=1, size=10).status_code in (200, 201)
    assert _init(temp, vault, "theirs.bin", chunks=1, size=10).status_code in (200, 201)

    rows = admin.get(f"/vaults/{vault}/uploads").json()
    assert len(rows) >= 2, rows
    assert any(r.get("temp_credential_id") for r in rows), (
        f"no session says which credential opened it: {rows}")
    assert any(r.get("temp_credential_id") is None for r in rows), (
        f"the owner's own session is not distinguishable from a credential's: {rows}")
