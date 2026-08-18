# Resuming an interrupted download

An interrupted multi-gigabyte download currently starts over. The endpoint does not handle HTTP
`Range` at all — there is no `Range` parsing, no `206`, and no `Accept-Ranges` anywhere in the API.

This note is written before the implementation because grounding it changed the shape of the work
twice: most of the machinery already exists, and the one obvious way to reuse it is wrong.

## Most of this is already built, for SFTP

`RandomAccessFile` (`app/services/download_stream.py:133`) already serves arbitrary ranges of a
stored file. It was built because SFTP's contract is "any offset, any order, any number of times",
and meeting it by holding the plaintext cost 120 MB for a 120 MB file from open to close. What
replaced that is the index the format walk already produces plus a two-record cache: a few bytes
per record, and at most two decrypted records resident.

`GcmChunkStreamReader.read_range` (`app/core/security.py:714`) is the reader underneath. It
decrypts only the records the requested span touches, and it clamps: a negative offset or a
non-positive length returns empty, an offset past the end returns empty, and a span straddling the
end returns what exists.

So the server-side half of resumable downloads is largely a wiring job, not new machinery.

## What `Range` collides with

The streaming download path has a deliberate integrity contract, and it is worth stating before
breaking it. `Content-Length` comes from the authenticated terminal — the writer's sealed statement
of the size, not the server's opinion — and the final piece is held back until the checksum
verifies. The property that buys: **stopping early delivers fewer bytes than promised, so a
conforming client reports a truncated response.** Completing the body and then deciding the file
was wrong would hand the client a clean success for a bad file.

A partial response looks exactly like that failure. A `206` is a short body on purpose, so the
signal that currently means "something went wrong" becomes ambiguous the moment ranges are served.

**The resolution is not to invent one.** Every record is independently AEAD-authenticated, and a
ranged read decrypts the records it touches — so a range is authenticated by the same mechanism as
a whole read, record by record. This is not a new trust model being proposed: it is the model SFTP
has been running on in production for as long as `RandomAccessFile` has existed. The whole-file
hold-back is an additional check on the *stored* checksum, and it is the part that cannot apply to
a range.

That distinction should be explicit in the implementation: a ranged response is authenticated but
not whole-file-checksummed, and a client that resumes must therefore read the terminal record — the
one that binds the totals — before it treats the assembled file as complete.

## The hazard: the obvious entry point is the wrong one

`VaultService.open_random_access` looks like the function to call. It is not.

It resolves the file through `_resolve_download(..., allow_share=False)`, and the comment says why:
a share claim confers nothing over SFTP. HTTP downloads **do** honour share claims. Wiring the
HTTP route to `open_random_access` would therefore compile, pass any test that uses an owner
account, and silently refuse every share-based download the moment a client sent a `Range` header —
a regression reachable only through a header most tests do not set.

The correct seam is `_open_random(file, vault, file_id)`, called after the HTTP path's own
resolution with its own `allow_share` policy. The permission, scope and per-file-password checks
then remain exactly the ones the non-ranged path runs, which is also what satisfies "a range cannot
be used to read outside the authorized object" — by reuse, rather than by a second implementation
that has to be kept in agreement with the first.

## Zero-knowledge and standard vaults differ here

For a zero-knowledge vault the stored blob is the client's ciphertext, kept verbatim; the server
holds no key and there are no records for it to index. `_open_random` says so directly, and notes
SFTP never reaches that branch.

That is not an obstacle — it is the easier case. The server serves a byte range of an opaque blob,
and the client resumes at a v2 content-record boundary and decrypts for itself. The framing is
derivable from the stored length, and every record authenticates independently, so the client can
restart at a record boundary without the preceding bytes. What the server must not do is pretend to
index records it cannot read.

For a standard vault the server decrypts, so the range is taken over plaintext offsets and
`read_range` already does the work.

## The client half

Resume from the last complete record, not from byte zero, and not from the last byte received —
a partial record is unauthenticated and must be discarded. With the length known, the record
boundary at or before the resume point is derivable, so the client can name an exact offset.

**One honest limit, and it is now the normal case rather than a caveat.** The measurements in the
download-sink note ruled out the staging sink, so the page has no sink it controls. A partial file
belongs to the browser, and the app cannot delete it. The UX must offer retry or discard and say
plainly that discarding removes the app's record of the transfer, not the file the browser wrote.
Promising a cleanup that cannot happen is worse than admitting the limit.

## Not established

- Whether `Accept-Ranges` should be advertised for zero-knowledge vaults, where the offsets are
  ciphertext offsets and mean something different to a generic client than they do to ours.
- How a range interacts with the transfer-admission slot. The slot is held for the whole response;
  a resumed download is a second response and would take a second slot, so a client retrying a
  large transfer repeatedly could hold more of the ceiling than one transfer's worth.
- Whether the audit completion record should distinguish a ranged read from a whole read. It
  currently records what the transfer did, and "served 4 MB" means something different when the
  request asked for 4 MB.
