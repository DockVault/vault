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

## What it says

**Neither half of an HTTP transfer scales with the file any more.** The two download rows are the
load-bearing ones:
quadrupling the file did not raise the cost, it lowered it slightly, which is what a fixed window
looks like once run-to-run spread is accounted for. The figure to carry forward is a constant of
roughly 15 MB, not a multiple of anything.

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

**Two cautions on those rows.** They extrapolate one measured point, and run-to-run spread on this
host reaches 11%. More importantly, nothing in the server currently *limits* concurrency — the
rows describe what the memory allows, not what the deployment enforces, and a hundred simultaneous
requests will all be attempted. Admission control is separate work.

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
