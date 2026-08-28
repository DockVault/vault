# Resource budgets

What a deployment costs while transferring files, measured rather than estimated, and what that
means for how much memory to give it.

Produced by `scripts/measure_transfer_budget.py`. Re-run it after any change to the transfer path.

---

## How this is measured

Memory is read from the container's own cgroup in a tight loop — roughly a thousand samples per
run — and **page cache is subtracted**, so the figures are anonymous memory: what the process
actually allocated. That matters here more than usual. On a stack that has moved a few gigabytes,
cache reaches 2.5 GB while allocated memory sits under 200 MB; a figure that included it would be
meaningless.

Each figure is the **rise from the same run's own resting reading**, not a difference against a
baseline taken earlier. Python does not return freed memory to the operating system promptly, so a
container that has already done work reads higher at rest than a later run's peak — comparing
across runs produced a negative cost, which is how this was noticed.

---

## The measurement

One transfer at a time, so the cost belongs to one half:

| Case | File | Peak rise | Against file size |
|---|---|---|---|
| Upload, 5 MB chunks | 128 MB | 22.7 MB | **0.18×** |
| Upload, one chunk for the whole file | 128 MB | 23.5 MB | **0.18×** |
| Download | 128 MB | 15.2 MB | **0.12×** |
| Download | 512 MB | 13.5 MB | **0.03×** |
| Download, zero-knowledge | 128 MB | 15.1 MB | **0.12×** |
| Download, zero-knowledge | 512 MB | 15.7 MB | **0.03×** |

## What it says

**Neither half of an HTTP transfer scales with the file any more.** The four download rows are the
load-bearing ones:
quadrupling the file did not raise the cost, which is what a fixed window looks like once
run-to-run spread is accounted for. The figure to carry forward is a constant of roughly 15 MB,
not a multiple of anything.

**Zero-knowledge vaults are measured separately, and they had to be.** They share the download
endpoint but not the reader: the blob is the client's ciphertext stored verbatim, so there is
nothing to decrypt and it is served in fixed windows rather than records. A figure taken against a
standard vault says nothing about that path, and a budget run that only covered standard vaults
would have passed while this one still cost twice the file. It does not — it costs the same
constant.

That is a change. The first version of this table put a 128 MB download at **267.9 MB — 2.09×**,
the largest number here by a wide margin. The reader decrypted record by record, correctly, then
accumulated every piece in a list and joined them, so at the join both the list and the joined copy
existed and one stayed resident for the whole response — including while a slow client read it.
Records are now decrypted one at a time and released as they are sent.

**Upload costs the same whatever the client does with it.** 22.7 MB in 5 MB pieces, 23.5 MB as a
single 128 MB chunk. That is the point of the two upload rows: they are the same workload described
differently by the client, and the server now charges the same for both.

It did not, until this was measured. The first run of this table put the single-chunk case at
**273.7 MB — 2.14×, the same as a download.** The handler bounded the request body by *how much of
the file was left* rather than by the chunk size the client declared, then accumulated it and copied
it. That declared size was echoed back at session start and never persisted or enforced, so a client
decided how much memory the server spent on it, and at the default 1 GB maximum file size a
single-chunk request cost roughly 2 GB. The body now goes to the staged chunk file as it arrives,
with its digest taken in passing; nothing larger than one piece of the stream is held.

That moves a cost rather than removing it, and the moved cost is worth stating: a request that is
going to be refused for being too large is now partly on disk before it can be measured, where
before it was in memory. The bound is the same either way — what remains of the session's declared
size, which is disk that session was already approved to buffer — and the partial file is removed
when the refusal is raised. What it is *not* is visible: staged files are skipped by the directory
accounting, so a refused body in flight appears in no total. That matters for how many transfers a
deployment admits at once, which is a separate piece of work.

The download reader now yields each record as it is decrypted, and the stored checksum is computed
as the bytes pass rather than over a reassembled copy — verifying it the old way would have put the
whole file straight back in memory and given back everything the streaming saved.

## SFTP

SFTP used to be the most expensive read in the system, and the only one whose cost was tied to how
long a client left a handle **open** rather than to the length of a transfer. Opening a 96 MB file
and reading 4 KB of it added **100.2 MB**, held until the handle closed — so a client that opened a
large file and walked away held all of it.

| SFTP, 96 MB file | Rise while the handle is open |
|---|---|
| Open, read 4 KB — **before** | 100.2 MB |
| Open, read 4 KB — **after** | **1.0 MB** |
| …then seek 50 MB in and read again | **2.2 MB** |

Closing returns to the resting figure exactly. The reader answers ranges out of the index the
format walk already builds and keeps the last two decrypted records, so what is resident is the
index plus **one or two record-sizes** — not the file, and not a function of how far a client
seeks.

**That figure depends on how the file was written, and the writers do not agree.** The resumable
and SFTP upload paths write 1 MiB records; the direct multipart upload writes 5 MiB ones. Measured
on the same 12 MB file: **1.0 MB per handle when it was written in 1 MiB records, 5.2 MB when it
was written in 5 MiB ones**, doubling to 10.2 MB for a read that straddles a boundary. Twenty such
handles cost 201 MB. The ceiling is two records, and a record may be up to 8 MiB, so size for
**2 × the largest record a writer produces, per concurrent handle** — not for the 1.0 MB headline.

A single read is answered in at most 1 MiB regardless of what the client asks for, so no one
request can re-materialise a file. Nothing caps how many handles may be open at once.

**One format is exempt.** Legacy Fernet blobs still read whole, because their plaintext record
lengths are not derivable from the framing — padding hides up to sixteen bytes per token, so an
index cannot be built without decrypting everything anyway. No writer produces that format, so the
exposure shrinks as those files are replaced and cannot grow.

**SFTP uploads buffer their plaintext before encrypting it, and that buffer is now RAM.** Each
upload is written to a staging directory and pushed through the encryption pipeline at close. The
compose files back that directory with a size-capped tmpfs (`SFTP_STAGING_TMPFS_MB`, default
512 MiB) so the plaintext never reaches the persistent disk — the trade is that the buffer is
resident memory while the upload is in flight, and a buffered upload cannot exceed the tmpfs (which
also caps the SFTP upload size until true streaming lands). The tmpfs is a single shared cap across
concurrent uploads, so it adds at most `SFTP_STAGING_TMPFS_MB` to the container's ceiling regardless
of how many run at once; size `mem_limit` above the resting figure plus that. An upload that fills
the tmpfs fails cleanly and is discarded rather than persisted truncated — but keep
`SFTP_STAGING_TMPFS_MB` **well** below `mem_limit`: sized at or above it, filling the tmpfs trips the
container's memory limit (an OOM process kill) instead of the clean ENOSPC the discard path relies on.

## Both halves at once

The table above is one transfer at a time, which isolates the cost of each half. This is the case
a deployment actually meets: a sustained upload and a sustained download together, on a four-core
host with 4 GB of memory.

| Payload each way | Wall | Simultaneous peak | CPU |
|---|---|---|---|
| 128 MB | 5.0 s | **234.0 MB** | 8.1 s |
| 512 MB | 22.5 s | **291.2 MB** | 40.3 s |

Read the **simultaneous peak**, not the sum of the per-service peaks. The sum is an upper bound
over figures that need not coincide -- 243.7 MB and 304.8 MB here -- while this is what the machine
has to hold at once.

Quadrupling both transfers moved the peak by 57 MB, which is the same fixed-window behaviour the
single-transfer rows show, and it leaves the whole stack inside the 500 MB target with room that is
not marginal.

The CPU splits the way the work does: of the 40.3 seconds at 512 MB, the API accounts for 19.4 and
the database, cache and SFTP service for about 7 each.

### These figures replace an earlier set, and the reason is worth keeping

An earlier run of exactly this workload reported 18.0 s and 74.4 s wall, and 257 s of CPU. Those
numbers were wrong, and not by a little.

The memory sampler was a shell loop with no sleep, injected into each container, and killing
`docker exec` does not kill what it started -- so a sampler survived every round and accumulated.
Nine were found on one host. The stack idled at roughly 100% CPU per container before the sleep
was added and about 31% after, so the measurements were taken on a machine the instrument had
loaded, and the CPU column was largely the instrument measuring itself. Four services with very
different jobs reporting CPU within 2% of each other is what gave it away.

**Memory was not affected** -- a sampler costs about a megabyte -- so the single-transfer table
above stands. Wall time and CPU were, and are re-measured here on a quiet host with the sampler
bounded and reaped.

The general lesson, recorded because it will apply to the next harness as well: an instrument that
can outlive its run will, and one that costs a core per container will change the thing it is
measuring. Both are cheap to prevent and invisible afterwards.

## What an upload costs the browser

Everything above measures containers. This measures the tab, because the claim made for the
zero-knowledge upload path is about the client: encrypting from a sliced file rather than a
whole-file buffer was supposed to stop the browser holding three copies.

Chromium, resident memory sampled continuously and split **by process role**, each arm in a fresh
browser, and each arm's payload built *before* the baseline is taken so what is reported is the
cost of the operation rather than the cost of having a file to operate on.

| payload | arm | renderer (the tab) | browser process |
|---|---|---|---|
| 64 MiB | whole-file path | 306.3% | — |
| 128 MiB | whole-file path | 303.8% | — |
| 64 MiB | **shipped path** | 57.1 MiB | 78.3 MiB |
| 128 MiB | **shipped path** | 66.6 MiB | 162.0 MiB |
| 256 MiB | **shipped path** | 61.0 MiB | 275.8 MiB |

**The whole-file path really did cost three copies**, and all of them in the renderer — 306% and
304% of payload at two sizes, which is as close to exactly 3x as this instrument resolves.

**The shipped path's renderer cost does not scale with the file.** 57, 67, 61 MiB across a
four-fold range of payload. A copy would have tracked the payload and reached ~230 MiB at the top
row; it stays near 60 MiB. What scales instead is the **browser process**, at roughly one copy
(1.22x, 1.27x, 1.08x) — the accumulated ciphertext living as Blob parts in the blob store, which is
exactly where `encryptBlobV2` says it hands them.

So the honest figure is: **about one copy of the file in the browser process, plus a bounded
working set of roughly 60 MiB in the renderer.** Two earlier statements of this were both wrong in
the same direction — "peak memory is a chunk rather than three times the file" (the original scope
line) and "peak JS heap is one chunk, total roughly one copy" (its first correction). The renderer
working set is not one chunk; it is ~60 MiB of live heap, decoder buffers and not-yet-collected
slices. It is simply **bounded**, which is the property that matters.

**Why bounded-in-the-renderer is the win, and not merely a smaller number.** The renderer is the
process an operating system kills first, and the one the mobile ceilings are about. The download
sink measured in `vault-download-sink-and-policy.md` moved a file *into* the renderer and was
withdrawn for it. The upload writer moves the file *out* of the renderer and into the blob store.
Same architecture, opposite direction, and only one of them is an improvement.

### Reading these numbers safely

The control arm holds one copy of the payload deliberately and must read ~100% in the renderer. It
read 110.6%, 105.3% and 101.2% at 64, 128 and 256 MiB — converging as the fixed overhead amortises.
An arm that does not calibrate is not evidence, and four memory probes in this project read
plausibly and wrongly before one did.

These are **resident set** figures, so they include garbage not yet collected. That is deliberate:
RSS is what an out-of-memory killer counts. A live-heap number would be smaller and less relevant.

Reproduce with `scripts/measure_browser_upload_memory.py --base-url <url> --payload-mb 128`.

## What a deployment needs

Measured across the whole stack during a 128 MB download, with page cache excluded.

| | At rest | Rise during a transfer |
|---|---|---|
| API | 126 MB | 23 MB |
| Database | 37 MB | 8 MB |
| SFTP | 85 MB | 4 MB |
| Redis | 11 MB | 4 MB |
| **Total** | **~260 MB** | **~40 MB** |

So, for **any** file size:

```
total ≈ 260 MB  +  40 MB per transfer in flight
```

There is no longer a term in `F`. That is the whole point of the change, and it is why the table
below asks a different question than it used to — "how many transfers", not "how large a file".

| Available RAM | Concurrent transfers it supports |
|---|---|
| 500 MB | ~6 |
| 1 GB | ~18 |
| 2 GB | ~44 |
| 4 GB | ~96 |

Set `MAX_CONCURRENT_TRANSFERS` at or below the figure for the memory available; the default of 16
suits 1 GB and above.

**A caution on those rows:** they extrapolate one measured point, and run-to-run spread on this
host reaches 11%.

**Concurrency is now enforced, not merely described.** `MAX_CONCURRENT_TRANSFERS` (16 by default)
caps how many transfers are carried at once, counting downloads and upload assembly together.
Arrivals beyond it wait — a burst is normal traffic — and are only turned away once the queue
(`MAX_QUEUED_TRANSFERS`, 32) is also full or the wait (`TRANSFER_QUEUE_WAIT_SECONDS`, 20) expires.
A refusal is a `503` with `Retry-After`, deliberately distinct from a failure, so a client can tell
"come back shortly" from "this file is broken".

At the default ceiling the transfer memory is about 16 × 40 MB = 640 MB on top of the ~260 MB
resting, which is why a deployment with less memory than that should lower it. **Open SFTP handles
are not counted by this ceiling** — they are not transfers, they are held state, they are bounded
separately by two record-sizes each, and SFTP runs as its own process, so an in-process ceiling
could not cover them in any case.

**What the ceiling does not cover.** A multipart upload's body is received and spooled by the web
framework before the endpoint runs, so those bytes arrive whether or not the deployment has a slot
free — the ceiling governs the encryption work that follows, not the receive. Each part is spooled
to disk above 1 MB, so this is bounded per request rather than per file, but it is not zero and it
is not counted here. The resumable path the browser uses does not have this property: its chunks
are written straight to disk by the application itself.

**What the ceiling costs, stated plainly.** A slot is held for as long as its transfer takes, and a
transfer has no deadline. A client that opens a download and then stops reading holds its slot
until it disconnects, so sixteen such clients will make the deployment answer `503` to everyone
else until they hang up — measured. Nor does cancelling the request necessarily help: a slot comes back
when the server next tries to write to a connection that has gone (up to about a minute, measured),
and never at all while the client keeps the connection open and simply declines to read. That is a
trade, not an oversight: the alternative was attempting every transfer at once, which ends in the
process being killed rather than in callers being asked to come back. Recovery is immediate once the
stalled clients disconnect, and a proxy with a response timeout in front of the deployment removes
the exposure entirely. Bounding how long
a slot may be held with no forward progress is the proper fix and is not in this change.

## On the 500 MB target

**Reached, and no longer dependent on file size — on either protocol.** A 500 MB deployment fits
the stack at rest with room for several concurrent transfers, whatever the files weigh, and an idle
SFTP handle costs one or two records rather than the file. Size the SFTP side by concurrent handles
times two record-sizes, as above, and remember that nothing enforces either count. The default `MAX_FILE_SIZE_MB` of 1024 no
longer implies a multi-gigabyte peak, so the API container's 4 GB `mem_limit` is now generous
rather than necessary.

Two numbers moved. Download: **267.9 MB for a 128 MB file, now 15.2 MB — and 13.5 MB for a file
four times larger.** An open SFTP handle: **100.2 MB for a 96 MB file, now 1.0 MB** — with the caveat above about the writer's record size.

**Nothing here was tuned to reach the target.** The instruction was to report the honest floor, and
the floor moved because the code did.

## Reproducing

```
python scripts/measure_transfer_budget.py \
    --base-url http://127.0.0.1:PORT \
    --admin-user admin --admin-pass ... \
    --containers <api> <db> <redis> <sftp> \
    --sizes 128 --mode download
```

`--mode upload|download|both` attributes the cost to one half; `--chunk-mb 0` makes the client
declare the whole file as one chunk, which is the impolite case above.

The harness refuses to report rather than reporting something misleading. It fails if a transfer
errors, if a download does not return what was uploaded, if it recorded fewer transfers than it
started, or if any container yielded too few samples to call anything a peak. Every one of those
is a state an earlier version printed a confident table for.
