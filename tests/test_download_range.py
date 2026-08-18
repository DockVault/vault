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

import os

import pytest

from conftest import create_zk_vault, unique, zk_chunked_upload


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


@pytest.fixture(scope="module")
def stored_file(admin):
    """One vault and one file for the whole module.

    Function scope re-uploaded 300 KB into a fresh vault for every parametrised case -- about
    twenty times -- which is twenty vaults and six megabytes of writes to answer questions that
    only ever read. Every test here is read-only, so one file serves them all, and the suite
    carries less state into whatever runs after it.
    """
    vault = admin.create_vault(name=unique("range-src"))
    try:
        fid = _upload(admin, vault["id"], unique("ranged") + ".bin", BODY)
        yield vault["id"], fid
    finally:
        admin.delete_vault(vault["id"])


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
])
def test_a_range_returns_exactly_those_bytes(admin, stored_file, header, start, last):
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download", headers={"Range": header})
    assert r.status_code == 206, r.text
    assert r.headers.get("Content-Range") == f"bytes {start}-{last}/{len(BODY)}"
    assert r.headers.get("Content-Length") == str(last - start + 1)
    assert r.content == BODY[start:last + 1], (
        f"{header} returned {len(r.content)} bytes that do not match the whole-file download")


def test_a_range_covering_everything_is_served_as_the_whole_file(admin, stored_file):
    """`bytes=0-` asks for the entire representation, and must not buy a weaker guarantee.

    The ranged path deliberately skips the stored-checksum hold-back, on the reasoning that a
    range is not the whole file. `bytes=0-` is the ordinary way to write "all of it", so without
    this the check was one header away from being skippable on every download — and it is not
    redundant with per-record AEAD for the two formats that have no terminal or no records at all.
    """
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download", headers={"Range": "bytes=0-"})
    assert r.status_code == 200, (
        f"a range spanning the whole object should be served as the whole object, not as a 206 "
        f"that skips the checksum: {r.status_code}")
    assert "Content-Range" not in r.headers
    assert r.content == BODY

    # An end past the end clamps to the same span, and must land the same way. This is the
    # likelier spelling in the wild -- a client that does not know the length asks for a big
    # number rather than for `bytes=0-`. It was previously asserted to be a 206, which is how
    # this rule was found to be one header away from skippable.
    clamped = admin.get(f"/vaults/{vid}/files/{fid}/download",
                        headers={"Range": "bytes=0-99999999"})
    assert clamped.status_code == 200, (
        f"a range clamped to the whole object must take the same path as one written that way, "
        f"not a 206 that skips the checksum: {clamped.status_code}")
    assert "Content-Range" not in clamped.headers
    assert clamped.content == BODY, "clamping past the end must not truncate or refuse"

    # A range that stops one byte short is still a real range, so it keeps the 206 path.
    partial = admin.get(f"/vaults/{vid}/files/{fid}/download",
                        headers={"Range": f"bytes=0-{len(BODY) - 2}"})
    assert partial.status_code == 206, partial.text
    assert partial.content == BODY[:-1]


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


def test_a_zero_knowledge_file_is_ranged_over_its_ciphertext(admin):
    """The flagship case, and the one most worth resuming: large client-encrypted files.

    The server holds no key here, so it answers with bytes out of the stored blob and interprets
    none of them. That is a different safety argument from the standard path, not a weaker one:
    `_open_random` refuses this type precisely because it would build an authenticated reader over
    a blob an attacker could have chosen, and nothing on this path constructs one.

    Offsets mean the same at both ends, because the response body IS the ciphertext. The client
    derives record boundaries from the stored length and decrypts what it asked for.
    """
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        vault = create_zk_vault(admin, name=unique("zk-range"))
    except Exception as exc:                      # noqa: BLE001 - narrow re-raise below
        admin.put("/settings", json={"zero_knowledge_enabled": False})
        if "not enabled on this deployment" in str(exc) or "not permitted" in str(exc):
            pytest.skip(f"this deployment forbids zero-knowledge vaults: {str(exc)[:200]}")
        raise
    admin.put("/settings", json={"zero_knowledge_enabled": False})
    vid = vault["id"]
    try:
        fid = zk_chunked_upload(admin, vid, unique("zk") + ".bin", BODY, os.urandom(32),
                                mime="application/octet-stream")
        whole = admin.get(f"/vaults/{vid}/files/{fid}/download")
        assert whole.status_code == 200, whole.text
        cipher = whole.content
        assert whole.headers.get("Accept-Ranges") == "bytes", (
            "a client-encrypted blob is the case resuming matters most for -- it must be offered")

        head = admin.get(f"/vaults/{vid}/files/{fid}/download",
                         headers={"Range": "bytes=0-4095"})
        assert head.status_code == 206, head.text
        assert head.content == cipher[:4096], "the range is not the same bytes the whole download "                                              "would have delivered"
        assert head.headers.get("Content-Range") == f"bytes 0-4095/{len(cipher)}"

        tail = admin.get(f"/vaults/{vid}/files/{fid}/download",
                         headers={"Range": "bytes=4096-"})
        assert tail.status_code == 206, tail.text
        assert head.content + tail.content == cipher, (
            "two halves of the ciphertext do not reassemble, so a resumed download would decrypt "
            "into damage")

        # The staleness guard applies here too, and matters more: a replaced blob spliced onto an
        # earlier half would fail to authenticate as damage rather than as a bug.
        assert whole.headers.get("ETag"), "without a tag a client cannot resume safely"
        stale = admin.get(f"/vaults/{vid}/files/{fid}/download",
                          headers={"Range": "bytes=4096-", "If-Range": '"not-the-stored-sum"'})
        assert stale.status_code == 200 and stale.content == cipher
    finally:
        gone = admin.delete_vault(vid)
        assert gone.status_code in (200, 204), (
            f"the zero-knowledge vault survived this test, and a later temp-credential mint will "
            f"meet a confirmation dialog because of it: {gone.status_code} {gone.text[:200]}")


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
        gone = admin.delete_vault(vault["id"])
        assert gone.status_code in (200, 204), (
            f"the shared vault survived this test: {gone.status_code} {gone.text[:200]}")


# --- resuming safely across two requests -----------------------------------------------------
#
# A range is only safe to splice onto an earlier one if both requests read the same bytes.
# Nothing else on this path establishes that: a same-name replacement between them would let a
# client assemble two different files and notice nothing, because each half authenticates
# perfectly well on its own. Per-record AEAD proves a record belongs to this file; it cannot prove
# two requests saw the same version of it. That is what the entity tag is for.

def test_a_rangeable_download_offers_a_tag_to_resume_against(admin, stored_file):
    vid, fid = stored_file
    whole = admin.get(f"/vaults/{vid}/files/{fid}/download")
    assert whole.status_code == 200
    tag = whole.headers.get("ETag")
    assert tag, "without a tag a client has nothing to quote back, so it cannot resume safely"

    ranged = admin.get(f"/vaults/{vid}/files/{fid}/download",
                       headers={"Range": "bytes=0-99"})
    assert ranged.status_code == 206
    assert ranged.headers.get("ETag") == tag, (
        "the tag must be the same on both, or a client cannot tell the two responses describe "
        "one file")


def test_a_resume_quoting_the_current_tag_is_honoured(admin, stored_file):
    vid, fid = stored_file
    tag = admin.get(f"/vaults/{vid}/files/{fid}/download").headers.get("ETag")
    r = admin.get(f"/vaults/{vid}/files/{fid}/download",
                  headers={"Range": "bytes=1000-1999", "If-Range": tag})
    assert r.status_code == 206, r.text
    assert r.content == BODY[1000:2000]


@pytest.mark.parametrize("if_range", [
    '"sha256-of-some-other-file"',
    '"',                              # a lone quote: malformed, not merely different
    'not-quoted-at-all',                # an unquoted tag is not the syntax either
    "Wed, 21 Oct 2015 07:28:00 GMT",     # the date form: accepted syntax we cannot answer
])
def test_a_resume_quoting_anything_else_restarts_instead_of_splicing(admin, stored_file, if_range):
    """The whole file, with a 200, rather than a range a client would append to stale bytes.

    Costing a restart is the point. The alternative is a silently corrupt file assembled from two
    versions, which no checksum the client holds would catch either, since it never had one for
    the file it ended up with.
    """
    vid, fid = stored_file
    r = admin.get(f"/vaults/{vid}/files/{fid}/download",
                  headers={"Range": "bytes=1000-1999", "If-Range": if_range})
    assert r.status_code == 200, (
        f"If-Range {if_range!r} did not match, so the range must not be honoured")
    assert "Content-Range" not in r.headers
    assert r.content == BODY


def test_replacing_the_file_invalidates_a_resume_in_flight(admin, temp_vault):
    """The scenario the tag exists for, driven end to end.

    Download part of a file, replace it, then resume with the tag from before. The server must
    refuse to serve the range against bytes the client has never seen.
    """
    vid = temp_vault["id"]
    name = unique("replaced") + ".bin"
    fid = _upload(admin, vid, name, BODY)
    url = f"/vaults/{vid}/files/{fid}/download"

    first = admin.get(url, headers={"Range": "bytes=0-999"})
    assert first.status_code == 206, first.text
    tag = first.headers.get("ETag")
    assert tag

    replacement = bytes((i * 5 + 11) & 0xFF for i in range(len(BODY)))
    # POST .../delete is the route; DELETE is not one. Unchecked, this test still passed -- but
    # for the wrong reason, because nothing was replaced and a second file was merely added
    # alongside the first. Asserted so the scenario is the one the name claims.
    removed = admin.post(f"/vaults/{vid}/files/{fid}/delete")
    assert removed.status_code in (200, 204), (
        f"the original was not removed, so this exercises two coexisting files rather than a "
        f"replacement: {removed.status_code} {removed.text[:200]}")
    new_fid = _upload(admin, vid, name, replacement)

    resumed = admin.get(f"/vaults/{vid}/files/{new_fid}/download",
                        headers={"Range": "bytes=1000-1999", "If-Range": tag})
    assert resumed.status_code == 200, (
        "the stored bytes changed, so the old tag must not buy a range that would be spliced "
        "onto the first thousand bytes of a file that no longer exists")
    assert resumed.content == replacement
