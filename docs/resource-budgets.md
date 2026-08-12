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

A 128 MB file, one transfer at a time, so the cost belongs to one half:

| Case | Peak rise | Against file size |
|---|---|---|
| Upload, 5 MB chunks | 22.7 MB | **0.18×** — effectively flat |
| Upload, one chunk for the whole file | 273.7 MB | **2.14×** |
| Download | 267.9 MB | **2.09×** |

## What it says

**Download always costs about twice the file size.** The reader decrypts chunk by chunk, correctly,
then accumulates every piece in a list and joins them — so at the moment of the join both the list
and the joined copy exist. One of those copies then stays resident for the whole response,
including while a slow client reads it.

**Upload costs nothing extra — but only because the client chose to be polite.** With 5 MB chunks
the rise is 22.7 MB for a 128 MB file. With the same file declared as a single chunk it is 273.7 MB,
the same as a download.

That difference is not a server property. The chunk-upload handler buffers a request body bounded
by *how much of the file is left*, not by the chunk size the client declared — and that declared
size is echoed back at session start and never persisted or enforced. **A client decides how much
server memory its upload consumes.** At the default 1 GB maximum file size, a single-chunk request
is accepted and costs roughly 2 GB.

So there are two distinct problems, and only one of them is about streaming:

1. **Download holds whole files.** Fixed by yielding chunks from the reader instead of collecting
   them — *and* by computing the stored checksum incrementally as they pass. Verifying it against a
   reassembled buffer puts the whole file straight back in memory and gains nothing.
2. **Upload trusts the client's chunk size.** Fixed by enforcing the declared size, or by streaming
   the request body to the staged chunk file rather than accumulating it. This is a limit, not a
   streaming change, and it belongs with the rest of the admission-control work.

## What a deployment needs

The non-API services are flat and do not care about file size: database ~45 MB, SFTP ~84 MB,
Redis ~11 MB, so about **140 MB** between them. The API rests at roughly 100 MB.

For a file of size `F`, with one transfer in flight:

```
total ≈ 240 MB  +  2.1F        (download, or an upload from an impolite client)
total ≈ 240 MB  +  0.2F        (upload from a client using small chunks)
```

| Available RAM | Largest file one download can handle |
|---|---|
| 500 MB | ~120 MB |
| 1 GB | ~380 MB |
| 2 GB | ~860 MB |
| 4 GB | ~1.8 GB |

Each additional simultaneous transfer adds its own `2.1F`; the 240 MB is paid once.

**These rows are derived from the formula above, which is fitted to a single file size.** Two
earlier points at 128 MB and 512 MB agreed on the slope to within 4%, but run-to-run spread on this
host reached 11%, which is wider than that agreement — so treat the slope as approximate and the
extrapolation to 1 GB as an estimate rather than a measurement.

## On the 500 MB target

**Not reachable at the configured maximum file size.** The default `MAX_FILE_SIZE_MB` is 1024,
which needs roughly 2 GB for a download alone — which is why the API container's `mem_limit` is
4 GB, and why that limit's comment tells you to keep the two in step.

500 MB is reachable today for deployments whose files stay under about 120 MB. That is a real
configuration rather than a consolation: set the file ceiling to match the memory instead of the
other way round.

Closing the gap means download not holding whole files, and the target is already measured and
sitting in the table above: **22.7 MB for a 128 MB upload is what bounded looks like on this
stack.** Once download matches it and the upload handler stops trusting the client's chunk size,
`2.1F` collapses to a fixed window and a 500 MB deployment stops depending on how large its files
are.

**Nothing here was tuned to reach the target.** The instruction was to report the honest floor.

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
