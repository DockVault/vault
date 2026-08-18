"""Ranged downloads, over HTTP, against a live deployment.

The parser is proven separately in `test_byte_range_parsing.py`. What these establish is the part
that file cannot: that the endpoint offers ranges only where a range is cheap, refuses them where
honouring one would cost something a client should not be able to ask for, and returns bytes that
match the whole-file download exactly.

Three of these are refusals, and each is a refusal for a different reason:

* a **zero-knowledge** file, because the server holds no key and must not build a reader for a
  blob it cannot authenticate;
* a **share-authorized** download, because a capped share spends one download per request -- so
  resuming would either charge twice or make the cap bypassable with a header;
* an **unparseable header**, because RFC 7233 requires ignoring what cannot be understood.

Every one of them looks the same from the outside (a `200` carrying the whole file), which is why
each is asserted separately rather than by one representative case.
"""

import pytest

from conftest import skip_if_container_absent, unique


_OCTET = {"Content-Type": "application/octet-stream"}


def _upload(client, vault_id, name, content, chunk_size=None):
    """Store a file through the resumable path, which is what the browser uses."""
    chunk_size = chunk_size or max(1, len(content))
    total_chunks = max(1, (len(content) + chunk_size - 1) // chunk_size)
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(content),
        "total_chunks": total_chunks, "chunk_size": chunk_size,
        "mime_type": "application/octet-stream",
    })
    assert init.status_code == 200, init.text
    sid = init.json()["session_id"]
    for i in range(total_chunks):
        part = content[i * chunk_size:(i + 1) * chunk_size]
        r = client.put(f"/vaults/{vault_id}/uploads/{sid}/chunks/{i}", data=part, headers=_OCTET)
        assert r.status_code == 200, r.text
    done = client.post(f"/vaults/{vault_id}/uploads/{sid}/complete")
    assert done.status_code == 200, done.text
    return done.json()["id"]


# Deliberately not a round number and larger than one record, so a range can straddle a record
# boundary rather than always landing on one.
BODY = bytes((i * 31 + 7) & 0xFF for i in range(300_000))


@pytest.fixture
def stored_file(admin, temp_vault):
    skip_if_container_absent()
    vid = temp_vault["id"]
    fid = _upload(admin, vid, unique("ranged") + ".bin", BODY)
    return vid, fid


def test_a_rangeable_file_says_so(admin, stored_file):
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download")
    assert r.status_code == 200, r.text
    assert r.headers.get("Accept-Ranges") == "bytes", (
        "a standard-vault file in the at-rest format answers ranges cheaply, so it must advertise "
        "them -- a client has no other way to know resuming is possible")
    assert r.content == BODY


@pytest.mark.parametrize("header,start,last", [
    ("bytes=0-999", 0, 999),
    ("bytes=1000-1999", 1000, 1999),
    ("bytes=299000-", 299000, len(BODY) - 1),       # open-ended, to the end
    ("bytes=-1000", len(BODY) - 1000, len(BODY) - 1),   # suffix
    ("bytes=0-0", 0, 0),                            # exactly one byte
    ("bytes=131070-131074", 131070, 131074),        # straddles a record boundary
    ("bytes=0-99999999", 0, len(BODY) - 1),         # past the end, clamped not refused
])
def test_a_range_returns_exactly_those_bytes(admin, stored_file, header, start, last):
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download", headers={"Range": header})
    assert r.status_code == 206, r.text
    assert r.headers.get("Content-Range") == f"bytes {start}-{last}/{len(BODY)}"
    assert r.headers.get("Content-Length") == str(last - start + 1)
    assert r.content == BODY[start:last + 1], (
        f"{header} returned {len(r.content)} bytes that do not match the whole-file download")


def test_ranges_are_consistent_with_each_other(admin, stored_file):
    """Two halves fetched separately must reassemble into the whole.

    This is the property a resuming client depends on, and it is not implied by either half being
    correct on its own -- an off-by-one at the join would leave both requests looking right.
    """
    vid, fid = stored_file
    cut = 123_457                                  # deliberately not a record boundary
    head = admin.get(f"/vaults/{vid}/files/{fid}/download",
                     headers={"Range": f"bytes=0-{cut - 1}"})
    tail = admin.get(f"/vaults/{vid}/files/{fid}/download",
                     headers={"Range": f"bytes={cut}-"})
    assert head.status_code == 206 and tail.status_code == 206
    assert head.content + tail.content == BODY, "the two halves do not reassemble into the file"


def test_an_unsatisfiable_range_is_refused_and_says_the_real_length(admin, stored_file):
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download",
                  headers={"Range": f"bytes={len(BODY)}-"})
    assert r.status_code == 416, r.text
    assert r.headers.get("Content-Range") == f"bytes */{len(BODY)}", (
        "a 416 must tell the client the length it should have asked within")


@pytest.mark.parametrize("header", [
    "hamsters=0-100",          # a unit nobody registered
    "bytes=abc-def",
    "bytes=500-100",           # backwards
    "bytes=0-99,200-299",      # multiple ranges: multipart, deliberately unsupported
])
def test_a_header_we_cannot_honour_serves_the_whole_file(admin, stored_file, header):
    """Ignored, not rejected. Refusing would leave a client that sends a header this does not
    parse unable to download at all, which is worse than sending it more than it asked for."""
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download", headers={"Range": header})
    assert r.status_code == 200, r.text
    assert r.content == BODY
    assert "Content-Range" not in r.headers


def test_a_zero_knowledge_file_is_not_ranged(admin):
    """The server stores the client's ciphertext and holds no key for it.

    Serving a range would mean building a reader over a blob it cannot authenticate, which is the
    thing the service layer refuses outright. The endpoint must not offer what that would require.
    """
    skip_if_container_absent()
    made = admin.post("/vaults", json={
        "name": unique("zk-range"), "type": "zero_knowledge",
        "description": "ranged-download refusal",
    })
    if made.status_code in (400, 403):
        # A policy refusal is an environment gap: some deployments disable the type outright, and
        # this test has nothing to say about those. Anything else -- a 5xx above all -- is the
        # setup failing, and skipping on it would quietly retire the check.
        pytest.skip(f"this deployment forbids zero-knowledge vaults: {made.text[:200]}")
    assert made.status_code == 200, (
        f"creating the vault failed for a reason that is not policy, so the refusal this test "
        f"exists to check was never exercised: {made.status_code} {made.text[:300]}")
    vid = made.json()["id"]
    try:
        fid = _upload(admin, vid, unique("zk") + ".bin", BODY)
        plain = admin.get(f"/vaults/{vid}/files/{fid}/download")
        assert plain.status_code == 200, plain.text
        assert "Accept-Ranges" not in plain.headers, (
            "advertising ranges here would invite a request the server must refuse")

        ranged = admin.get(f"/vaults/{vid}/files/{fid}/download",
                           headers={"Range": "bytes=0-999"})
        assert ranged.status_code == 200, (
            f"expected the header to be ignored, got {ranged.status_code}")
        assert "Content-Range" not in ranged.headers
        assert len(ranged.content) == len(plain.content)
    finally:
        admin.delete(f"/vaults/{vid}")


# --- the share case ------------------------------------------------------------------------
#
# A capped share spends one download per request, burned before any bytes are served. Honouring a
# range would have to either burn again on the resumed request -- so one flaky transfer could
# exhaust a two-download share -- or skip the burn when a Range header is present, which makes the
# cap bypassable by anyone who sends one. Ranges are therefore withheld from share-authorized
# downloads, and both halves of that are asserted below: the header must not bypass the cap, and
# it must not charge twice for one file.

def _enable_sharing(admin, on=True):
    assert admin.put("/settings", json={"sharing_enabled": on}).status_code == 200


def _tag(admin):
    r = admin.post("/share-tags", json={
        "name": unique("rangetag"), "auto_enroll_new_users": True,
        "allowed_audiences": ["anyone_internal"],
        "max_recipients_cap": 10, "max_downloads_cap": 100,
    })
    assert r.status_code == 200, r.text
    return r.json()


def _share(admin, vault, tag, **over):
    body = {"vault_id": vault["id"], "tag_id": tag["id"], "target_type": "vault",
            "claim_audience": "anyone_internal"}
    body.update(over)
    r = admin.post("/shares", json=body)
    assert r.status_code == 200, r.text
    return r.json()


def test_a_shared_download_ignores_a_range_and_still_costs_exactly_one(admin, temp_user_client):
    skip_if_container_absent()
    _enable_sharing(admin, True)
    vault = admin.create_vault(name=unique("share-range"))
    try:
        fid = _upload(admin, vault["id"], unique("shared") + ".bin", BODY)
        share = _share(admin, vault, _tag(admin), max_downloads=2)
        assert temp_user_client.post(
            "/shares/claim", json={"token": share["link_token"]}).status_code == 200

        url = f"/vaults/{vault['id']}/files/{fid}/download"

        first = temp_user_client.get(url, headers={"Range": "bytes=0-99"})
        assert first.status_code == 200, (
            f"a range must be ignored here, not honoured: {first.status_code}")
        assert "Content-Range" not in first.headers
        assert "Accept-Ranges" not in first.headers, (
            "advertising ranges on a capped share invites a resume that cannot be paid for")
        assert first.content == BODY, "the whole file, since the range was ignored"

        # Exactly one download spent. Two, and a resumed transfer would drain the cap; zero, and
        # the header would be a way around it.
        second = temp_user_client.get(url, headers={"Range": "bytes=0-99"})
        assert second.status_code == 200, (
            "the first ranged request charged more than one download")
        third = temp_user_client.get(url)
        assert third.status_code == 403, (
            "the cap did not engage, so a Range header bought downloads that were not counted")
    finally:
        admin.delete(f"/vaults/{vault['id']}")
