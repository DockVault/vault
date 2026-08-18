# Where a decrypted download is written, and who decides

Follows the measurements in [`vault-browser-support-and-download-sink.md`](vault-browser-support-and-download-sink.md),
which ruled out the staging sink, and the resumable-download work that shipped alongside it.

## What we can and cannot control

Worth stating first, because the obvious design is built on something that is not true.

**A page cannot delete a file from the Downloads folder.** There is no web API for it;
`chrome.downloads` is extension-only. Nor does the page choose the `.part` / `.crdownload`
suffix — the browser already writes to a temporary name and renames on completion, and on failure
it is the browser or the user that cleans up. So "write to `.part`, delete it if the transfer
fails" is not a lever anyone here holds.

What *is* ours to decide is narrower and more useful: **whether bytes reach the disk before the
file has been authenticated at all.**

## The two modes

**Buffered — what ships today.** Records are decrypted as they arrive and accumulated in the page;
the browser is handed one finished file. Nothing appears in Downloads until the whole object has
authenticated. Costs about one copy of the file, measured, so a file larger than the tab can hold
fails.

**Streaming — the mode this adds.** A service worker holds a response open and the page writes
decrypted records into it as they arrive. Memory stays flat, so size stops being a limit. The cost
is that a failed transfer can leave a partial file in Downloads, marked failed by the browser, that
neither we nor the page can remove.

**Resume makes the second far less bad than it sounds.** The service worker's response stays open
across a dropped connection: the page re-requests the missing byte range and keeps writing into the
*same* download, so the browser sees one continuous file. A partial only survives if the tab is
closed, or retries are exhausted. Interrupted-but-recoverable transfers — the common case on a
poor link — leave nothing behind.

## Two constraints that decide how much this is worth

**A service worker needs a secure context.** HTTPS, or `localhost`. `API_USE_HTTPS` ships
**`false`**, so a self-hosted deployment reached over plain HTTP on a LAN address *cannot* register
one, and the streaming mode is simply unavailable there. This is not a small caveat: it means the
mode is off for a large share of self-hosters until they terminate TLS. The buffered path must stay
the fallback, chosen automatically and without an error.

**The worker's scope must cover the download URL.** A script served from `/static/js/` defaults to
a scope of `/static/js/` and cannot intercept `/vaults/{id}/files/{id}/download`. Either the script
is served from the root path, or its response carries `Service-Worker-Allowed: /`. The CSP needs no
change: `default-src 'self'` already permits a same-origin worker.

## Who decides

Three-valued organisation policy, one per-user preference, and a default that changes nothing:

| layer | values | default |
|---|---|---|
| organisation | `buffered` · `streaming` · `user_choice` | `user_choice` |
| user | `buffered` · `streaming` | `buffered` |

Effective mode is the organisation's, unless it is `user_choice`, in which case it is the user's.
**The shipped defaults therefore reproduce today's behaviour exactly** — nothing reaches disk early
for anyone until somebody opts in.

Why an organisation needs the lever at all: a tenant handling material that justified a
zero-knowledge vault may reasonably refuse to let unverified plaintext touch a workstation's disk,
even briefly, even marked failed. Why a user needs one: someone self-hosting for themselves, pulling
a large file over a poor link, is better served by a transfer that can continue than by one that
must restart.

A user preference can only choose within what the organisation allows. It can never widen it, and
that direction is the one the tests must prove.

## What the tests owe

- Each of the three policy values produces the mode it names, and `user_choice` defers.
- A user preference cannot override `buffered` or `streaming` when the organisation set one.
- Plain HTTP falls back to buffered **silently and correctly**, rather than failing or appearing to
  stream.
- The buffered path is unchanged when nothing is configured, which is the shipped default.

## Measured, before anything was wired to it

The sink was driven end to end against a local secure origin -- register the worker, open a slot,
write records, trigger the download -- at 8 MiB in 256 KiB records.

| | complete transfer | aborted transfer |
|---|---|---|
| Chromium | 8388608 bytes, content byte-exact, correct filename | download appears, `failure='canceled'` |
| Firefox | 8388608 bytes, content byte-exact | **no download event at all** |

Two things came out of that which change the implementation.

**The download must be triggered by a hidden same-origin iframe, not an anchor.** An anchor
navigates the DOCUMENT. When the stream then errors, the browser follows that navigation to an
error page and **the application is destroyed** -- confirmed on Firefox, where the probe's own page
was gone afterwards. Chromium tolerates it. An iframe confines the failure to the frame, and with
that change the page survives an abort on both engines. CSP already permits it: `frame-src 'self'`.

**The application must report a failed transfer itself.** Firefox surfaces no download event for an
aborted stream even with `Content-Length` declared, so the browser's own failure report -- the
entire remedy available once bytes are on disk -- cannot be relied on. On Chromium it is there and
accurate; on Firefox the user would otherwise see nothing at all. This settles the second open
question below.

A methodological note, since it nearly produced a wrong conclusion: the first run declared no
`Content-Length` on the aborted case, so there was nothing for a short body to be short OF. That is
not the case the app produces -- it always knows the plaintext length -- and the difference looked
like a browser behaviour until the probe was corrected.

## Measured after building it: the memory case is not made

The sink was built to remove a memory ceiling. Measured, it does not do that. It moves the cost
from one process to another, and the direction is the wrong one.

Chromium, 128 MiB delivered in 1 MiB records, resident memory split by process role, collection
forced, each arm in a fresh browser:

| arm | renderer (the tab) | browser process |
|---|---|---|
| buffered — what ships | **10.3%** | 110.6% |
| streamed — this sink | **116.5%** | 9.5% |

**Buffering never held the file in the tab.** Blob parts live in the browser process's blob store,
which is why the renderer stays at a tenth of the payload. The earlier note that the tab holds
"about one copy" was measured across all processes together and did not distinguish them; that
aggregate was right and the attribution was not.

**Streaming puts the file on the renderer side.** For a memory-constrained device that is worse
rather than better: the renderer is the process an operating system kills first, and it is the one
the iOS ceilings in this note are about.

### What is established, and what is not

Established: the two arms differ this way, reproducibly, and the earlier measurement that showed
them as identical could not tell them apart at all — it summed every process, so a cost that merely
moved looked like no change.

Not established: **why** the renderer holds it. The worker's stream queue does exceed its
high-water mark — `desiredSize` bottomed at −20, so about 21 MiB was queued beyond the mark, which
means the writer has no backpressure. But 21 MiB does not account for 116%, so missing backpressure
is a real defect and not a complete explanation. Slowing the producer by 8 ms per record changed
nothing, which rules out the simplest version of the theory.

### What follows

Nothing ships enabled: the policy defaults to `user_choice` with a per-user default of `buffered`,
so no deployment gets this path without asking for it. That was chosen for a different reason and
turns out to matter here.

The streaming mode should not be recommended, and the option-A trade-off should not be presented as
"flat memory in exchange for a partial file", until either the renderer cost is explained and
fixed — backpressure first — or the measurement is shown to be wrong. On the evidence today the
honest summary is that it buys a partial-file risk and no memory saving.

## Not established

- Whether the streaming mode should be offered at all below some file size, where buffering costs
  little and leaves nothing behind. A threshold is easy to add and easy to get wrong; no measurement
  yet says where it belongs.
- ~~Whether a failed streamed download should be reported in-app~~ -- **settled: required.**
  Firefox surfaces no download event for an aborted stream, so there is no browser report to rely
  on there.
