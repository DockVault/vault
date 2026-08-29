# Design: streaming SFTP uploads (record-by-record encryption, bounded reorder window)

Status: **proposed — design only, nothing in this document is implemented** · Scope:
`app/sftp/sftp_server.py` (`VaultSFTPHandle`, `SFTPServerInterface._open_write`,
`_make_upload_finalizer`, `session_ended`, `_sweep_sftp_tmp`), `app/services/streaming_upload.py`,
`app/services/vault_service.py` (`upload_file_streaming`, `finalize_streaming_upload`),
`app/core/security.py` (the at-rest format — read, not changed), `deploy/docker-compose*.yml`,
`.env.example`, `dockvault.py`, `docs/resource-budgets.md` · Audience: whoever builds it + self-hosters
sizing memory

An SFTP upload today buffers the **whole plaintext file** before encrypting a byte of it. The buffer is a
RAM tmpfs, so a client's memory cost is the file's size, the largest file SFTP accepts is the tmpfs, and
every concurrent upload shares one ceiling. The download side was already fixed: `open_random_reader`
answers ranges out of a `GcmChunkStreamReader` that keeps one or two records resident
(`docs/resource-budgets.md`, "SFTP"). This document does the same for the write side: encrypt
**record by record as bytes arrive**, with a **small bounded reorder window** for the offset-addressed
writes the SFTP protocol permits, backpressure from the SSH channel, and a **named** cancellation past
an idle timeout — while keeping two invariants that are easy to break and must be stated in full: the
web ↔ SFTP byte-identical guarantee, and the authenticated terminator (a truncated or tampered upload
fails closed and is never stored as if whole).

---

## 1. What exists

### 1.1 The write path, as shipped

`SFTPServerInterface._open_write` (`app/sftp/sftp_server.py`) authorizes the put — principal, vault
resolution, the `file.upload` capability, the admin file-type allowlist, the effective per-file
maximum, the destination folder's id-scope, and whether the principal may **overwrite** (needs both the
`file.delete` capability and vault DELETE) — and then (paraphrased; the real code computes `_eff_max`
first and closes the `mkstemp` descriptor before reopening the path):

```
fd, tmp_path = tempfile.mkstemp(prefix="up_", dir=str(_SFTP_TMP_DIR))   # storage/.sftp_tmp
handle.writefile = open(tmp_path, "wb")
handle.max_bytes = _staging_capped_max(_eff_max, settings.sftp_staging_tmpfs_mb)
handle.finalizer = self._make_upload_finalizer(vault_id, folder_id, filename, can_overwrite)
```

The DB session `_open_write` holds is a `with get_db_context() as db:` block scoped to the method; it is
closed on return. Nothing about the upload survives it except the handle.

`VaultSFTPHandle.write(offset, data)` refuses in-stream when `offset + len(data)` would exceed
`max_bytes` (a named status via `_MessageSFTPServer._send_status`), otherwise
**`seek(offset)` + `write(data)`** into the temp file — any offset, any order. `close()` flushes, and
if neither `overlimit` nor `write_failed` is set, calls the finalizer with the temp path, then unlinks
it.

`_finalize(tmp_path)` opens a **fresh** session and re-validates everything **at persist time** — the
principal and session (`_load_principal`, `_check_session_valid`), the vault through `get_vault`, the
folder id-scope, the per-vault password proof (`_vault_password_proven`), the vault `size_limit`
against the buffered size (an **unlocked** read — see §3.7), and the deployment storage ceiling
(`would_exceed_deployment_storage`) — and only then streams the buffer through the canonical pipeline:
`upload_file_streaming` → `StreamingUploadContext` with `GcmChunkStreamCodecV2`, fed in **1 MiB**
pieces (`tf.read(1024 * 1024)`), then `finalize_streaming_upload(..., replace_same_name=can_overwrite)`
which inserts the `File` row and performs the same-name replacement in the same transaction. An
exception after the stream is closed unlinks the encrypted blob so a failed put leaves no orphan.

Three consequences of this shape:

- **Memory is the file.** The compose files mount a size-capped tmpfs over `storage/.sftp_tmp`
  (`SFTP_STAGING_TMPFS_MB`, `.env.example` ships 512), so the plaintext never reaches persistent disk —
  at the cost of being resident RAM for the whole transfer, shared across every concurrent upload.
  (Documented in the module comment above `_SFTP_TMP_DIR`.)
- **The upload size is the tmpfs.** `_staging_capped_max` clamps the per-file maximum to the tmpfs, so
  the effective SFTP limit is `min(MAX_FILE_SIZE_MB, SFTP_STAGING_TMPFS_MB)` and `.env.example` has to
  tell operators to raise both together (`tests/test_sftp_staging_tmpfs.py` pins that agreement).
- **Close cannot report failure.** This repository's own comment in `_make_upload_finalizer` records
  that "an SFTP close can't report failure to the client"; the finalizer's outcome is
  `safe_event('upload.finalize.failed', …)` in the log. A put that is refused at close (quota, plan
  cap, a session revoked mid-transfer) looks successful to the client. This is a claim about
  `paramiko`'s `FXP_CLOSE` handling that the comment asserts and this document did **not** verify
  against the library — it is one of the three assumptions in §6. The design below moves as many
  refusals as it can to *write* time, where the protocol does carry a status.

One more consequence the source does not document, derived from reading `write`: because
`mkstemp` creates an empty file and `seek(offset)` past its end **sparse-fills with zeros**, a client
that writes its first bytes at offset *X* > 0 (a resumed put, or one lane of a parallel-chunk client)
produces a buffer whose first *X* bytes are zeros, and `_finalize` stores exactly that. This is not a
theoretical shape; §3.5 makes it a named refusal.

And one about disconnects: `SFTPServerInterface.session_ended` is a no-op (`pass`), and
`_sweep_sftp_tmp`'s docstring says why the sweep exists — "a crash, kill, or dropped connection
mid-transfer skips the finalizer's cleanup". Nothing closes an open handle when the transport drops;
the temp file simply waits for the next start-up. §3.8 changes that.

### 1.2 The at-rest format the writer must produce (`app/core/security.py`)

```
header   = 'DockVault' · 0x20 · 0x00 0x00 · write_id(16)                        (28 bytes)
record   = len(4, BE) · nonce(12) · ciphertext(len-28) · tag(16)                (AAD: vault, file, write_id, index)
terminal = 0xFFFFFFFF · nonce(12) · tag(16)                                      (AAD: vault, file, write_id, record_count, plaintext_length)
```

Properties the design leans on, each read from the code and its comments:

- **Records need not be uniform.** `GcmChunkStreamCodecV2`'s docstring says so and why: the resumable
  path already emits a short interior record when a staged chunk is not a multiple of 1 MiB. The header
  carries no chunk size. A streaming writer may therefore emit records of whatever size the arriving
  bytes make convenient, without a format change.
- **Bounds:** `MAX_CHUNK_SIZE` 8 MiB per record, `MAX_RECORDS` 2²¹, no empty record
  (`MIN_RECORD_BYTES` = 29). The writer enforces all three itself, so an object that uploads is an object
  that downloads.
- **The terminal authenticates count and length.** `GcmChunkStreamReader._walk` reads every length
  prefix, steps over the bodies, and decrypts the terminal with the walked count and summed length as
  AAD **before any data record is decrypted**. A missing terminal, trailing bytes, a truncated record,
  and any substitution that changes the record count or the summed plaintext length are refused at
  open. A same-length substitution, or a reordering of records, leaves the walked count and length
  unchanged and is caught instead by the per-record AAD (`write_id`, vault, file, index) when that
  record is decrypted — possibly after earlier records have already been emitted, which the reader's
  own docstring calls "the one failure that remains late". That is why I2 (§2) relies on the terminal
  and on **never writing one for a partial**, not on per-record checks. A terminal cannot be lifted from
  another write of the same object because `write_id` is minted per writer and never accepted from a
  caller.
- **The terminal is written only on a clean exit.** `StreamingUploadContext.__exit__` writes it iff
  `exc_type is None`, and `tests/test_streaming_upload_terminal.py` pins that a failed upload is *not*
  terminated and leaves nothing. This is the mechanism that makes "never store a partial as if whole"
  true, and the design must keep every failure path routed through it.

### 1.3 The byte-identity guarantee, as tested

`tests/test_sftp_roundtrip.py::test_web_upload_then_sftp_get_is_identical` and
`::test_sftp_put_then_web_get_is_identical_and_creates_row` pin that a file written on one surface reads
back byte-for-byte on the other; `tests/test_sftp_open_memory.py::test_the_handle_reports_the_size_the_format_carries`
pins that the SFTP `stat` size is the terminal-authenticated length, not the database row's. Both
surfaces write through `upload_file_streaming` and read through `GcmChunkStreamReader`, so identity is
a property of the pipeline, not of who buffered what. The design keeps the pipeline and changes only
how bytes reach it.

### 1.4 `paramiko`, as used here

`_MessageSFTPServer` documents the request model this design must fit: *"Paramiko processes one request
at a time per connection"* — the SFTP subsystem runs a serial request loop on the channel's thread, and
a handle method returns a status that `_send_status` sends before the next request is read. The
`paramiko.Transport(...)` call in `handle_sftp_client` passes only `disabled_algorithms`; **no channel
window or packet size is configured today.**

Three things this design relies on are **assumptions, not facts verified in this repository**, and §6
lists them again as risks: (1) the serial request loop above (asserted by this repository's own
comment); (2) an SSH channel's receive **window** bounds how much unacknowledged data a client may have
in flight, and `Transport(default_window_size=…, default_max_packet_size=…)` sets it (the library's
documented defaults are 2 MiB and 32 KiB); (3) `FXP_CLOSE` always answers `SFTP_OK` regardless of
what `handle.close()` does (asserted by the `_finalize` comment quoted in §1.1). Alongside those,
OpenSSH's `sftp` client pipelines up to 64 outstanding requests of 32 KiB by default (`-R`, `-B`) —
so a conformant client has at most ~2 MiB in flight, arriving **in offset order** on a single channel.

---

## 2. Goals and invariants

**Goals.** Per-client memory becomes O(window), not O(file); the SFTP upload limit becomes
`MAX_FILE_SIZE_MB` alone; plaintext is never written anywhere (not even tmpfs); refusals that can be
named at write time are.

**Invariants, stated so they can be tested:**

- **I1 — byte identity.** A file put over SFTP and fetched over HTTP (and vice versa) is byte-identical,
  and its `File.checksum_sha256` equals the web path's for the same bytes.
- **I2 — authenticated terminator.** An upload that ends early (client abort, disconnect, size cap,
  quota, hole, timeout, any exception) produces **no `File` row and no blob that any row references**:
  the terminal is never written, the partial is unlinked, an existing same-name file is untouched.
  Nothing that is not whole is ever stored as whole. (The one window in which a *whole* blob can exist
  with no row — a crash between the final rename and the row commit — is unreachable through any API
  and is swept; §3.7.)
- **I3 — bounded memory.** Resident per open upload handle ≤ the channel's unread buffer + the reorder
  window + one assembly record + one record's ciphertext; independent of file size.
- **I4 — no plaintext at rest.** The only bytes that touch disk are the encrypted partial, written in
  the vault's storage directory, unreadable without a terminal.
- **I5 — persist-time re-validation is kept, and tightened.** Every check `_finalize` makes today still
  runs at close, before the terminal and before the row — and the vault size check runs under a row
  lock, which it does not today.
- **I6 — named failures.** Every refusal the handle can make during the transfer carries a status
  description a human can act on, through the existing `_set_status_desc` path.

---

## 3. Design

### 3.1 Open: start the encrypted stream, not a temp file

`_open_write` keeps every authorization step. Instead of `mkstemp`, it calls
`vault_service.upload_file_streaming(vault_id, filename, user, folder_id, mime_type,
staging_suffix=".incoming")` inside the DB session it already holds, and keeps the returned
`(file_info, ctx)` on the handle. `upload_file_streaming` inserts no row — it allocates the file id,
the blob path and the codec and hands back a context — so nothing is committed at open. `file_info` is
a plain dict (the service already returns one) and `ctx` holds only file handles and the codec, so both
outlive the open-time session, which closes when `_open_write` returns; close builds a fresh session
and `VaultService` exactly as today's `_finalize` does. The handle enters the context immediately
(`ctx.__enter__` opens the blob and writes the 28-byte header).

`staging_suffix` is the **one service change** in this design (§3.10 lists it). Today
`upload_file_streaming` chooses the blob path itself and constructs `StreamingUploadContext` on it, and
`__exit__` unlinks `self.storage_path` on failure — so a partial must not be written to the final path
under a different name by mutating the context afterwards; the service must know both names. With the
suffix, `file_info['storage_path']` stays the **final** path (what the row will record) and the context
opens and, on failure, unlinks `<final>.incoming`.

Why a suffix in the vault's own directory: a partial must not be mistaken for a finished object by
anything that walks `storage/` (backups, the directory accounting), and the final step must be an
atomic `os.replace` on the same filesystem. `_sweep_sftp_tmp` is retargeted: at start-up it removes
every `*.incoming` under storage (a fresh process has no in-flight upload), exactly as it removes
`up_*` today. An `.incoming` file is ciphertext without a terminal: unreadable, and harmless if a sweep
is missed.

The handle also records the in-stream bounds it can enforce without a DB round-trip: `max_bytes`
(the effective per-file maximum — no longer clamped by any tmpfs) and a **vault headroom hint**
`size_limit − total_size_bytes` taken at open. The hint is advisory; the authoritative check is at
close, under a row lock the close path takes itself (§3.7). Its job is to turn a hopeless put into a
named write-time failure instead of a silent close-time discard.

### 3.2 The sequential fast path

State on the handle: `expected` (the next plaintext offset the stream needs), `assembly`
(a `bytearray`, < `RECORD_SIZE`), `pending` (§3.3), `written` (bytes handed to the codec).

A write at `offset == expected` appends to `assembly`; whenever `len(assembly) ≥ RECORD_SIZE` the
handle emits `ctx.write_chunk(assembly[:RECORD_SIZE])` and drops it. `RECORD_SIZE` is **1 MiB** — the
same record size the current SFTP finalizer and the resumable path produce, so the on-disk shape of an
SFTP-written file does not change, and the download-side figure in `docs/resource-budgets.md`
("1.0 MB per handle when it was written in 1 MiB records") keeps holding. After every emission the
handle drains `pending` (§3.3) in case a held chunk now sits at `expected`.

Memory on this path: `assembly` (< 1 MiB) plus the one record's ciphertext the codec returns, plus
whatever the channel has received but not yet handed to the subsystem. Nothing accumulates.

The size bound moves to the front: `offset + len(data) > max_bytes` refuses with the existing
description — today's text is *"upload rejected: file exceeds the %d MB SFTP limit (raise
SFTP_STAGING_TMPFS_MB, which uses that much RAM, or lower MAX_FILE_SIZE_MB to match)"* — with the
tmpfs advice dropped; `written + pending_bytes + len(data) > vault headroom` refuses with a new
*"upload rejected: the vault is full (N MB free)"*. Both mark the handle failed (§3.6).

### 3.3 The reorder window

A write at `offset > expected` is held in `pending`, a small ordered map `offset → bytes`, subject to:

- **Capacity.** `Σ len(pending) ≤ WINDOW_BYTES` (`SFTP_WRITE_WINDOW_MB`, default **4** — twice
  OpenSSH's default in-flight budget, so a conformant client never fills it; Q1). A write that would
  exceed it is **refused** with `SFTP_FAILURE` and the description *"upload rejected: writes arrived
  more than N MB out of order; use a sequential client or raise SFTP_WRITE_WINDOW_MB"*, and the handle
  is marked failed. It is not held, not silently dropped, and not queued past the bound.
- **Reach.** `offset − expected ≤ WINDOW_BYTES` — a write further ahead than the window could ever
  hold is the same refusal; without this a single far write would pin the window open waiting for a gap
  the client will never fill.
- **Coalescing.** A held chunk adjacent to another is merged, so `pending` holds at most a handful of
  runs and the drain is a dictionary lookup, not a scan.
- **Drain.** Whenever `expected` advances, the run starting at `expected` (if any) is moved into
  `assembly` and emitted as above, repeatedly.
- **Overlap.** A write whose range overlaps a held run or already-emitted bytes is refused (§3.5) —
  the encrypted stream is append-only and nothing can be "re-written".

**These two refusals — capacity and reach — are what bound the reorder window.** The SSH channel
window (§3.4) is a separate, additive bound on bytes the server has received but not yet processed; it
does not bound `pending`, because bytes in `pending` have already been consumed from the channel. The
window is a **tolerance for modest out-of-order pipelining**, not a resume mechanism and not a
random-access surface. On a single channel with an ordinary client it stays empty; it exists so that a
client that reorders a few requests, or retransmits one after a stall, does not fail a multi-gigabyte
put on a technicality.

### 3.4 Backpressure, the missing chunk, and the timeout

Three different things are in play here and they are worth separating.

**Flow control** is the SSH channel window, and it is the only lever a serial request loop actually has.
The transport thread reads packets into the channel's receive buffer **up to the window size** and no
further until the subsystem consumes them; a client that has exhausted the window stops sending. The
SFTP service sets `Transport(default_window_size=…)` to a value **≤ `WINDOW_BYTES`** so the unread
buffer is bounded by the same figure as the reorder window; the per-handle ceiling in §3.8 is then the
sum of the two, plus the fixed assembly and codec costs. (This is assumption (2) of §1.4; the test in
§5 that drives the channel full is what turns it into a fact.)

**Waiting for a missing chunk** cannot mean blocking inside `write()`. The request loop is serial: if
the handle blocks, no further request is read, and the missing chunk — if the client is going to send
it at all — is *behind* the blocked one and can never arrive. So the handle never waits. When the
window is full and the run at `expected` has not arrived, the write that does not fit is refused with the
named status above, immediately; the client sees the failure on that request, and every conformant
client aborts the transfer and reports it. **This is a deliberate departure from "wait for the window to
drain, then cancel on a timeout":** honouring that literally would mean deferring the status reply
without blocking the loop, which `paramiko`'s subsystem does not offer — it would need a non-blocking
request loop or a `_process` override of its own, on top of the one Q3 already weighs. Q9 puts the
choice to the owner with that cost stated.

**The timeout** is for the case where nothing arrives at all: a client that opened a handle, wrote some
bytes, and stalled (a suspended laptop, a NAT that dropped the connection without a FIN, a client
waiting on a request the server already refused). Its handle holds an open encrypted partial and up to a
window of memory. A per-handle **idle deadline** — `SFTP_UPLOAD_IDLE_SECONDS`, default 300 — is
refreshed on every write; a watchdog thread in the SFTP process walks open upload handles and, past the
deadline, marks the handle cancelled, releases its buffers, closes and unlinks the `.incoming` partial
(through `ctx.__exit__` with an exception, so no terminal), releases the upload slot (§3.8), and records
`safe_event('upload.cancelled.idle', …)`. The next request on that handle — a write or the close —
gets `SFTP_FAILURE` with *"upload cancelled: no data received for N seconds"*. Every handle carries one
lock: the watchdog takes it to cancel, `write` takes it to refresh the deadline and mutate the buffers,
and `close` takes it and **disarms the deadline before step 4 of §3.7**, so a close whose DB work is
slow cannot be cancelled mid-finalize.

### 3.5 Rewrites, holes, sparse writes, resume, truncation, parallel lanes — refused by name

The at-rest stream is append-only and authenticated per record; once bytes are encrypted they are not
re-writable. The following shapes are therefore **refused at the request that reveals them**, each with
a status description, and each marks the handle failed:

| Shape | Detection | Description sent |
|---|---|---|
| Rewrite of already-emitted bytes | `offset < written` | *"upload rejected: rewriting already-received bytes is not supported over SFTP"* |
| Rewrite inside the assembly buffer | `written ≤ offset < expected` | honoured **only** if the range lies entirely within `assembly` (the bytes are not yet encrypted): overwrite in place. Otherwise as above. |
| Overlap with a held run | range intersects `pending` | same refusal |
| Resume / append (first write at `offset > 0` with nothing before it) | when the first write's offset alone exceeds the window; else on close: `written == 0 and pending` | *"upload rejected: resuming or appending to an SFTP upload is not supported; re-upload the whole file"* |
| `O_APPEND` open | the open flags | same refusal, at `open` |
| Truncate via `fsetstat` / `setstat` with a size on an open write handle | the request | *"upload rejected: changing the size of an in-progress upload is not supported"* (some clients touch the handle with `fsetstat` before writing — a size-less `fsetstat` is honoured as today) |
| Sparse write (a gap the client never fills) | on close: `pending` non-empty | discard; *"upload discarded: the file had a gap"* logged; close cannot carry it (§3.7) |
| Parallel lanes (several handles on one path) | each lane is a resume from that lane's offset → refused as above; the lane starting at 0 succeeds alone if it covers the whole file | as for resume |

Today every one of these is stored **wrong** rather than refused — a sparse zero-filled prefix, or the
last lane's partial winning the same-name replacement. Turning silent corruption into a named refusal
is a behaviour change worth stating in the release notes, and Q2 asks whether any of these clients
matter enough to support instead.

### 3.6 Marking a handle failed

A failed handle drops `assembly` and `pending`, exits the context with an exception (`ctx.__exit__`
unlinks the `.incoming` blob and writes no terminal), releases its upload slot, records the reason, and
answers every later `write` with the same failure status and description; `close` on a failed handle is
a no-op that returns. The existing `overlimit` / `write_failed` flags collapse into one `failed_reason`.

### 3.7 Close

In order, under the handle lock, with the idle deadline disarmed first:

1. Refuse if the handle is failed (already cleaned up).
2. **Hole check:** `pending` must be empty. If not, fail (§3.5) — no terminal.
3. Flush `assembly` as the final (short) record — allowed to be < 1 MiB, never empty (the codec refuses
   an empty record). A zero-byte put (`written == 0`) would yield a header plus a terminal binding
   count 0 and length 0, which `GcmChunkStreamReader._walk` accepts (it requires a terminal, not a
   record); whether to store that or refuse it — the resumable web path refuses an empty body
   (`EmptyBody`) — is Q8.
4. **Persist-time re-validation**, in a fresh session and `VaultService`, in the same order as
   `_finalize` today: principal + session valid, `get_vault` (membership + temp scope + password
   proof), folder id-scope, then **`SELECT … FOR UPDATE` on the `Vault` row** and the `size_limit`
   check against `written` under that lock, then the deployment storage ceiling. The lock is new
   behaviour, not inherited: `finalize_streaming_upload`'s own comment says "the row lock taken by the
   caller before the limit check is what stops two uploads both passing a check they would jointly
   fail", the HTTP `/complete` path takes it (`with_for_update()` on the vault), and today's SFTP
   `_finalize` does not — two concurrent puts into a nearly-full vault can both pass. Any failure →
   exit the context with an exception → no terminal, partial unlinked, log + audit.
5. `ctx.__exit__(None, …)` writes the terminal; `os.replace(<final>.incoming → <final>)`;
   `finalize_streaming_upload(..., total_size=written, checksum=ctx.get_checksum(),
   replace_same_name=can_overwrite)` in the **same** session and transaction as the lock in step 4; the
   same-name replacement happens inside that transaction as today; commit; audit `file_upload` with
   `via: sftp`.
6. On any exception after the rename, unlink the blob (the existing orphan guard) and re-raise into the
   log.

**The window between the rename in step 5 and the commit.** A process crash there leaves a fully
terminated, readable blob at the final path with no `File` row. It is unreachable — every read path
resolves a blob through a row's `storage_path`, so a blob without a row cannot be listed or downloaded —
but it is disk, and the `*.incoming` sweep does not see it. The order is kept as-is on purpose: the
codebase's own rule (recorded in `cleanup_expired_files`) is that an orphan blob is recoverable and a
dangling row is not, and committing the row before the rename would produce the latter. A bounded
start-up sweep — terminated blobs under `storage/` with no row whose `storage_path` names them, removed,
with a count in the log — closes it. That sweep is a new facility and is listed in §3.10 and §6.

The SHA-256 the context accumulates is over plaintext in offset order — the same bytes in the same
order the web path hashes — so `File.checksum_sha256` is identical for identical input (I1).

What close still cannot do is **tell the client**. Per this repository's comment (and §1.4's
assumption (3)), `paramiko` answers `FXP_CLOSE` with `SFTP_OK` after calling `handle.close()`; a
persist-time refusal at step 4 is invisible to the client exactly as it is today. The design narrows
that window by moving every bound it can to write time (§3.2, §3.3, §3.5); what remains at close is the
set of conditions that genuinely cannot be known earlier (a session revoked in the last millisecond, a
concurrent upload that took the last of the vault's space). Q3 asks whether a `_process` override that
returns a failure status from `FXP_CLOSE` when the finalizer failed is worth the `paramiko`-version
coupling.

### 3.8 Memory, concurrency, and disconnects

| Component | Bound | Set by |
|---|---|---|
| Channel receive buffer (unread) | `default_window_size` | the SFTP service, ≤ `WINDOW_BYTES` |
| Reorder window (`pending`, consumed but not yet in order) | `WINDOW_BYTES` | `SFTP_WRITE_WINDOW_MB` (default 4) |
| Assembly buffer | < `RECORD_SIZE` (1 MiB) | fixed |
| Codec working set | one record's ciphertext (≤ 1 MiB + 28) | fixed |
| **Total** | **≈ channel window + reorder window + 2 MiB ≈ 10 MiB at the defaults** | — |

The first two rows are additive — the channel bounds what has not been read, the reorder refusals
bound what has — which is why the flow-control test in §5 must drive writes **out of order** to
exercise the second row at all. The figure to carry is **~10 MiB per open upload handle**; the §5
assertion allows 2 MiB of allocator slack on top. Versus **the file** today.

Because open handles are not counted by the HTTP `transfer_admission` ceiling (a separate process —
`docs/resource-budgets.md` says so), the SFTP process gets its own: `SFTP_MAX_CONCURRENT_UPLOADS`
(default 16) enforced at `_open_write` with a named refusal (*"upload refused: the server is handling
its maximum of N concurrent uploads; try again shortly"*), counted **globally and per session**. A
pre-authentication limit on connections (the SSH-server "MaxStartups" idea) would be the complementary
bound one layer down; none exists in this tree and none is designed here.

**Disconnects release everything immediately.** `session_ended` stops being a no-op: it cancels every
open upload handle of that session through the same path the watchdog uses — drop buffers, exit the
context with an exception (no terminal, `.incoming` unlinked), release the slot, log
`upload.cancelled.disconnect`. Without this, a dropped connection would pin a slot, a window of memory,
a descriptor and an `.incoming` file until the idle deadline; sixteen open-write-then-drop cycles from
one authenticated account would then block every SFTP upload on the deployment for five minutes at a
time. The per-session count bounds the same shape from one live session.

Sizing guidance for `docs/resource-budgets.md`: `SFTP_MAX_CONCURRENT_UPLOADS × ~10 MiB` on top of the
resting figure, instead of `SFTP_STAGING_TMPFS_MB`.

### 3.9 What goes away, and the files that change together

`SFTP_STAGING_TMPFS_MB`, the `.sftp_tmp` tmpfs mounts in both compose files, `_staging_capped_max`,
the `min(MAX_FILE_SIZE_MB, SFTP_STAGING_TMPFS_MB)` rule and its `.env.example` prose are all made
redundant. Per the config-sync rule, `config.py`, `.env.example`, `dockvault.py` and the compose files
change in the **same** commit; the env key is kept for one release as accepted-and-ignored with a
deprecation note (an operator's `.env` must not fail to parse on upgrade), then removed, and
`docs/upgrade-matrix.json` carries the note.

`tests/test_sftp_staging_tmpfs.py` splits: the clamp, tmpfs-mount, environment-export and
`.env.example`-agreement tests are retired with the mechanism they pin; the status-description tests
(the over-limit and staging-full descriptions, the no-server guard, and
`test_message_server_substitutes_and_clears_pending_desc`) stay, move to a file named for what they
test, and are extended with the descriptions in §3.5.

### 3.10 Things that deliberately do not change — and the two that do

Unchanged: the at-rest format (no version bump: 0x20 already permits variable records); the record size
(1 MiB); `finalize_streaming_upload`; the download path; the web multipart and resumable paths; the
authorization sequence at open; the `_set_status_desc` / `_MessageSFTPServer` mechanism (reused for
every new description); zero-knowledge vaults stay excluded from SFTP
(`test_sftp_excludes_zero_knowledge_vault`).

Changed, and only these: `upload_file_streaming` gains an optional `staging_suffix` (§3.1), and a
bounded start-up orphan-blob sweep is added beside the `.incoming` sweep (§3.7).

---

## 4. Failure matrix

| Event | When detected | Client sees | On disk after | Row |
|---|---|---|---|---|
| Over `MAX_FILE_SIZE_MB` | the write that crosses it | `SFTP_FAILURE` + named | partial unlinked | none |
| Vault headroom exceeded | the write that crosses the hint; re-checked under lock at close | named at write; silent at close | partial unlinked | none |
| Out-of-order beyond window | the write that does not fit | `SFTP_FAILURE` + named | partial unlinked | none |
| Rewrite / overlap / truncate / append | that request | `SFTP_FAILURE` + named | partial unlinked | none |
| Hole at close | close | `SFTP_OK` (protocol) | partial unlinked | none |
| Client disconnect | `session_ended` (immediate) | — | partial unlinked | none |
| Idle past deadline | watchdog | `SFTP_FAILURE` + named on next request | partial unlinked | none |
| Session revoked / scope narrowed / password rotated mid-put | close (step 4) | `SFTP_OK` (protocol) | partial unlinked | none |
| Process crash before the rename | next start | — | `.incoming` swept | none |
| Process crash between rename and commit | next start | — | terminated orphan, unreachable, swept | none |
| Clean put | close | `SFTP_OK` | terminated blob at `storage_path` | inserted |

Every row but the last ends with "no row" and nothing a row references — that is I2 in tabular form.

---

## 5. Testing (the load-bearing cases)

- **I1**: the two existing round-trip tests, unchanged, plus: an out-of-order put *within* the window
  (a harness that sends offsets 1 MiB..2 MiB before 0..1 MiB on one channel) reads back identical over
  HTTP with the same `checksum_sha256` as the web upload of the same bytes.
- **I2**: for each row of §4 that ends in "none": no `File` row, no blob at `storage_path`, no
  `.incoming` after close (or after a sweep for the crash cases), an existing same-name file
  byte-identical before and after, and — the direct test — an `.incoming` partial captured mid-put fails
  `GcmChunkStreamReader` construction with *"ended without a terminal record"*. A failed put unlinks the
  `.incoming` file and leaves nothing at the final path (the `staging_suffix` contract).
- **I3**: `tests/test_sftp_open_memory.py`'s shape applied to writes — put a 512 MB file **with a
  deliberately out-of-order harness** (1–2 MiB before 0–1 MiB, then runs up to 4 MiB ahead) and assert
  the SFTP service's rise stays under `channel window + reorder window + 4 MiB` (the ~10 MiB bound plus
  2 MiB of slack); then 8 concurrent puts, rise under 8× that.
- **I5**: two concurrent puts into a vault with headroom for exactly one: one lands, one is refused at
  close, the vault's `total_size_bytes` never exceeds `size_limit`.
- **Named refusals**: each description in §3.5 arrives in the status message (the
  `_MessageSFTPServer` substitution test extended); a resumed put (`reput`), an `O_APPEND` open and an
  `fsetstat` size are refused by name.
- **Flow control**: with the channel window set to the reorder window, a client configured with 128
  outstanding 32 KiB requests (4 MiB in flight) still completes when sequential — the channel, not the
  reorder refusal, throttles it — and is refused by name when the same 4 MiB arrives 4 MiB ahead of
  `expected`. This is the pair that turns assumption (2) of §1.4 into a fact.
- **Timeout**: a client that writes 1 MiB and stalls is cancelled after the deadline; its next write
  gets the named status; the partial is gone; memory returns to resting. A close that starts before the
  deadline and finishes after it is not cancelled (the disarm).
- **Disconnect**: drop the transport mid-put; within a second the slot is free, the `.incoming` file is
  gone and a new put on a fresh connection is admitted.
- **Sweeps**: an `.incoming` file present at start-up is removed; a terminated blob with no row is
  removed; a finished blob with a row is not.
- **Config sync**: `.env.example` documents `SFTP_WRITE_WINDOW_MB`, `SFTP_UPLOAD_IDLE_SECONDS`,
  `SFTP_MAX_CONCURRENT_UPLOADS`; `dockvault.py` setup prompts for them; the compose files no longer
  mount `.sftp_tmp`; `SFTP_STAGING_TMPFS_MB` is accepted and ignored.

---

## 6. Risks

- **`paramiko` internals are load-bearing and were not read for this document.** The three assumptions
  of §1.4 — the serial request loop, the channel window as a hard bound on unread bytes, and
  `FXP_CLOSE` always answering `SFTP_OK` — must be confirmed against `paramiko==5.0.0` in
  `requirements.txt` by the flow-control and close tests in §5 before the memory bound is claimed in
  `docs/resource-budgets.md`.
- **Client compatibility.** The refusals in §3.5 change the outcome for resumed puts, parallel-lane
  clients, append opens and truncating `fsetstat`s from *silently corrupt* to *refused*. The set to
  exercise before release: OpenSSH `sftp` (default and `-R 128`), WinSCP (including its resume
  behaviour), FileZilla, Cyberduck, `lftp` (`put` and `pget`-style parallel put), `rclone`, and
  `paramiko`'s own `putfo` with `set_pipelined(True)`.
- **An encrypted partial now touches persistent disk.** It is ciphertext with no terminal — unreadable
  by construction — but it is a new kind of file under `storage/` that backups will see. The `.incoming`
  suffix and the start-up sweep bound its lifetime; the backup tooling should skip the suffix (Q4).
- **The rename-to-commit window** (§3.7) can leave a whole, unreachable blob after a crash; the
  orphan-blob sweep is the mitigation, and it is new code that walks `storage/` — it must be bounded
  and must never delete a blob any row references, which the sweep test in §5 pins.
- **The vault headroom hint can be stale** under concurrent uploads into one vault; the locked check at
  close is authoritative, so the failure mode is a silent close-time discard for a put the hint let
  through — the same visibility as today, and narrower.
- **Two records' worth of memory per handle is the download-side figure; the write side is ~10 MiB.**
  The resource-budgets document must be updated in the same change so the sizing table does not
  describe the wrong ceiling.
- **Watchdog, `session_ended` and handle lifecycle** share one lock per handle; the tests in §5
  exercise the races (stall then late write; close racing the deadline; disconnect mid-write).

---

## 7. Non-goals

- **Resume / append / random-access rewrite over SFTP.** Refused by name (§3.5). The at-rest stream is
  append-only and authenticated; supporting resume means a different object model (a persistent
  in-progress upload with its own id, as the HTTP resumable path has), which is a separate design.
- **Sparse files.** SFTP's zero-fill semantics are not honoured; a gap is a failure.
- **A format change.** 0x20 is kept; variable records are already legal.
- **Aligning records to transport packets.** 1 MiB records regardless of the client's packet size.
- **Zero-knowledge vaults over SFTP.** Still excluded — there is no browser-held key on the server.
- **Counting SFTP uploads in the HTTP `transfer_admission` ceiling.** Separate processes; the SFTP
  ceiling in §3.8 is its own.
- **Making `close` carry a status.** Kept as today unless Q3 says otherwise.
- **Deferring a write's status reply to wait for a missing chunk.** Not possible on the serial loop
  without a request-loop rewrite; Q9.

---

## 8. Open questions (decisions to make before building)

1. **Window size** (§3.3): 4 MiB default, exposed as `SFTP_WRITE_WINDOW_MB`? Or fixed and not
   configurable, on the argument that a client needing more is misbehaving?
2. **Which non-sequential clients matter** (§3.5): is a named refusal of resume / parallel-lane /
   append / truncate puts acceptable, or does some deployment depend on `reput`-style resume badly
   enough to justify the separate resumable-object design?
3. **Close status** (§3.7): accept that persist-time refusals stay invisible to the client (today's
   contract), or override `paramiko`'s `FXP_CLOSE` handling to return a failure — a ~100-line
   `_process` override coupled to the library version?
4. **Partial on disk** (§3.1): `.incoming` beside the finished blobs (proposed, same filesystem so the
   rename is atomic) or a dedicated `storage/.incoming/` directory the backup tooling can exclude
   wholesale?
5. **Idle deadline** (§3.4): 300 s default? Some SFTP clients (and some networks) pause longer than that
   legitimately.
6. **Concurrent-upload ceiling** (§3.8): 16 to match `MAX_CONCURRENT_TRANSFERS`, or derived from
   available memory the way the resource-budgets table suggests? And the per-session share of it?
7. **Deprecation of `SFTP_STAGING_TMPFS_MB`** (§3.9): one release as ignored-with-warning (proposed), or
   removed outright with a release note?
8. **Zero-byte puts** (§3.7): store an empty file (header + terminal), or refuse as the resumable web
   path refuses an empty body? Today's SFTP path stores whatever the buffer holds, including nothing;
   the behaviour was not checked against the multipart web path for this document.
9. **Window-full behaviour** (§3.4): refuse the non-fitting write immediately (proposed — the serial
   request loop makes waiting impossible without a loop rewrite), or invest in a non-blocking request
   loop / `_process` override so the server can defer the status and cancel on a timeout as originally
   asked?
10. **Orphan-blob sweep** (§3.7): a bounded start-up sweep of terminated blobs with no row (proposed),
    or reorder close so the row commits before the rename and accept a dangling-row window instead?
