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

`VaultService.open_random_reader` (`app/services/vault_service.py:1468`) looks like the function to call.
It is not.

It resolves the file through `_resolve_download(..., allow_share=False)`, and the comment says why:
a share claim confers nothing over SFTP. HTTP downloads **do** honour share claims. Wiring the
HTTP route to `open_random_reader` would therefore compile, pass any test that uses an owner
account, and silently refuse every share-based download the moment a client sent a `Range` header —
a regression reachable only through a header most tests do not set.

The correct seam is `_open_random(file, vault, file_id)`, called after the HTTP path's own
resolution with its own `allow_share` policy. The permission, scope and per-file-password checks
then remain exactly the ones the non-ranged path runs, which is also what satisfies "a range cannot
be used to read outside the authorized object" — by reuse, rather than by a second implementation
that has to be kept in agreement with the first.

## Zero-knowledge and standard vaults differ here

For a standard vault the server decrypts, the range is taken over plaintext offsets, and
`read_range` already does the work.

**Zero-knowledge is not the easy case, and an earlier draft of this note had it backwards.**
`_open_random` refuses outright:

    raise FileServiceError("Zero-knowledge files cannot be read by range")

and the reason it gives is worth keeping: failing there is better than routing an attacker-chosen
blob that happens to begin with the format magic into a reader that would try to authenticate it
under the deployment key. SFTP never reaches the branch, because it refuses non-standard vaults
entirely.

So serving zero-knowledge ranges is not a matter of reusing this path. It needs a branch that
returns raw bytes from the stored blob and never constructs the authenticated reader at all — which
is safe for a different reason than the standard path is safe: the server holds no key, makes no
integrity claim about the plaintext, and is a passthrough. The client's own AEAD is the integrity
statement, exactly as it is for a whole-file zero-knowledge download today.

That branch must be written so it cannot become the thing the existing refusal was guarding
against. The refusal protects a *reader*; a raw range must not acquire one.

**Built, and that is exactly how.** The sequential zero-knowledge opener now carries a
`read_range` that seeks the stored blob and copies bytes, interpreting none of them --
`_open_random` and its refusal are untouched, and no reader is constructed on this path. Seeking is
safe because the two paths are mutually exclusive within a request: a ranged response never
iterates the sequential generator, and a sequential one never calls the range function.

**Legacy Fernet cannot be ranged cheaply, and quietly is not the same as cannot.** `_open_random`
falls back to `RandomAccessFile.from_bytes`, which decrypts the entire file into memory — the exact
cost the class was built to avoid, retained deliberately because padding hides up to sixteen bytes
per token so no index is derivable without decrypting anyway. It is bounded in practice: no writer
produces the format, so the exposure shrinks and cannot grow. But a `Range` request against such a
file would load all of it, which is precisely the failure mode resumable downloads exist to avoid.
Advertising `Accept-Ranges` for these files would be a promise the implementation keeps by doing
the expensive thing silently.

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

- ~~Whether `Accept-Ranges` should be advertised for zero-knowledge vaults~~ -- **settled: yes.**
  The concern was that ciphertext offsets mean something different to a generic client. They do
  not: the response body IS the ciphertext, so a byte range names the same bytes at both ends. A
  generic client reassembling two ranges gets the same blob it would have downloaded whole, and
  our client additionally knows how to derive record boundaries from the stored length.
- How a range interacts with the transfer-admission slot. The slot is held for the whole response;
  a resumed download is a second response and would take a second slot, so a client retrying a
  large transfer repeatedly could hold more of the ceiling than one transfer's worth.
- Whether the audit completion record should distinguish a ranged read from a whole read. It
  currently records what the transfer did, and "served 4 MB" means something different when the
  request asked for 4 MB.
