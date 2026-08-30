# Streaming SFTP upload (memory-bounded)

Status: proposed. Ships behind a default-OFF flag (`SFTP_STREAMING_UPLOAD`); flip on after review +
a real large-file measurement.

## Problem

An SFTP upload buffers the **whole plaintext** to a per-upload staging file in `.sftp_tmp` before it
is encrypted at handle close. That directory is a **size-capped tmpfs (RAM)** by design, so the
plaintext never touches persistent disk (`app/sftp/sftp_server.py`, `_SFTP_TMP_DIR`). The consequence
is that a 1 GB upload occupies ~1 GB of RAM for the life of the transfer, even though the Python
process's own heap stays small. (The **read/download** path is already memory-bounded — it answers
ranges and decrypts only the records a request touches, ~1 MB per open handle. The **encryption
pipeline** is already streaming too: `VaultService.upload_file_streaming` +
`StreamingUploadContext.write_chunk` write fixed 1 MiB records at close.)

So the cost is a deliberate **RAM-vs-plaintext-on-disk** trade, and neither horn is necessary: we can
encrypt-and-persist *as records arrive* so the full plaintext is never held in either place.

## What must not change (invariants the current close-time path guarantees)

1. **Close-time re-authorization (TOCTOU).** Between `open()` and `close()` a principal may be locked,
   deactivated, session-revoked, have its temp-credential scope narrowed, or have a vault password
   added/rotated. `_finalize` re-checks *all* of these at persist time; a failure must land no file.
2. **No orphan blob, no data loss.** A rejected / oversize / failed upload must leave no encrypted
   blob **and** must not destroy the existing same-name file. The `File` row insert (inside
   `finalize_streaming_upload`, which deletes the old same-name row in the *same* transaction) is the
   commit point.
3. **No plaintext on persistent disk** (the reason the staging tmpfs exists).
4. **In-stream size bound** (`max_bytes`), the vault `size_limit`, and the deployment plan ceiling.
5. **At-rest format is byte-identical to the web path.** Records are 1 MiB and each is AES-GCM-sealed
   bound to its **monotonic 0-based index** in the AAD (`GcmChunkStreamCodec`), so the reader detects
   a reordered/oversized record. The streaming writer must therefore feed records **in order** and at
   the **same 1 MiB size**.

## Design

Keep the existing staging path as the default. Behind `SFTP_STREAMING_UPLOAD=on`, the write handle
streams:

- `open()` (unchanged authz up front): resolve vault/folder, run the no-clobber + write-permission
  checks, then instead of opening a staging file, attach streaming state to the handle: a 1 MiB
  **re-chunk buffer**, `next_offset = 0`, a bounded **reorder map**, and a deferred encryptor (created
  on first write so an opened-but-never-written handle costs nothing).
- First `write()`: call `upload_file_streaming(...)` to obtain `(file_info, stream_ctx)` and
  `stream_ctx.__enter__()` (opens the blob, writes the codec header). This does **not** commit a `File`
  row and holds **no DB transaction** — `StreamingUploadContext` is just a file handle + hasher.
- `write(offset, data)`:
  - `offset == next_offset`: append to the re-chunk buffer; while it holds ≥ 1 MiB, `write_chunk` a
    1 MiB slice. `next_offset += len(data)`. Then drain any now-contiguous entries from the reorder map.
  - `offset > next_offset` (gap): stash in the reorder map, capped at a **reorder window**
    (`SFTP_STREAMING_REORDER_MB`, default 16). Exceeding the window → mark the handle for a descriptive
    failure (true random-access writer; `sftp put`/`scp` never do this).
  - `offset < next_offset` (rewrite of an already-sealed region): cannot seek back through the AEAD →
    fail. (The plaintext is gone; honest failure beats silent corruption.)
  - Enforce `max_bytes` against `next_offset + buffered`.
- `close()`:
  - If the handle was flagged (over-limit / random-access / write error): exit the ctx **with an
    exception** so `__exit__` unlinks the blob and writes **no terminal**; persist nothing.
  - Else flush the re-chunk buffer's tail as a final short `write_chunk`, then run the **full
    `_finalize` re-authz block** (principal, session, folder scope, vault password proof, vault quota,
    plan ceiling). On any failure → exit the ctx with an exception (unlink blob), persist nothing.
  - On success → exit the ctx cleanly (writes the terminal, marking the blob complete) →
    `finalize_streaming_upload(file_info, total_size, checksum, replace_same_name=can_overwrite)` — the
    atomic overwrite, exactly as today.

Memory bound = one 1 MiB record + the reorder window (≤ ~16 MiB), independent of file size, with no
plaintext on tmpfs or disk.

### Why the invariants still hold

- (1) TOCTOU: the re-authz still runs at close *before* the terminal + `File` row. The encrypted blob
  written during `write()` is uncommitted; on a close-time auth failure it is unlinked, so nothing
  lands — same contract as today, just with the blob already partly written (and removed).
- (2) No orphan/loss: `__exit__(exc)` unlinks on any failure; the atomic overwrite is unchanged, so a
  failed replace never destroys the existing file.
- (3) No plaintext at rest: nothing is staged; only sealed records reach disk.
- (5) Format: identical codec, 1 MiB records, monotonic index — a streamed file and a web/staged file
  are byte-identical and mutually decryptable.

## Config (kept in sync: `config.py` ⇄ `.env.example` ⇄ `dockvault.py`)

- `SFTP_STREAMING_UPLOAD` (bool, default `false`): use the streaming writer. When off, the tmpfs
  staging path is unchanged.
- `SFTP_STREAMING_REORDER_MB` (int, default `16`): reorder-window ceiling; a write beyond it fails the
  upload.

## Tests

- Sequential large put: RSS stays flat (`scripts/measure_transfer_budget.py`); file downloads back
  byte-identical; byte-identical to the same file uploaded via the web path.
- Out-of-order within the window: reordered records assemble correctly.
- Random-access beyond the window: clean, descriptive failure; no blob, existing file intact.
- TOCTOU: revoke the session mid-transfer → no `File` row, no orphan blob.
- Atomic overwrite: a failed streaming replace leaves the existing file intact.
- Flag off: behaviour is the current staging path (regression).

## Implementation notes (for the handle wiring)

- `VaultService.upload_file_streaming` returns `(file_info, stream_ctx)`. `file_info` is a plain dict
  **except** it carries `'vault': <ORM Vault>` bound to the session that created it, and
  `stream_ctx` (`StreamingUploadContext`) is just a file handle + hasher (no DB). Two viable session
  shapes: (a) hold ONE `get_db_context()` open for the whole upload (simplest; the session is idle
  between the initial vault lookup and the close-time `File` insert, but a long-lived transaction is a
  cost worth measuring), or (b) at first write take a brief session to get `file_info` + the open
  `stream_ctx`, then at close take a FRESH session for the re-authz + `finalize_streaming_upload`,
  re-fetching the vault by `file_info['vault_id']` so no detached ORM object is used. Prefer (b) if
  `finalize_streaming_upload` can be given a session-fresh vault; confirm by reading it before wiring.
  CONFIRMED: `finalize_streaming_upload` reads `file_info['vault']` (an ORM object) for the same-name
  replacement + the ZK check, so shape (b) must, at close, re-fetch the vault into the fresh session
  and set `file_info['vault'] = <fresh vault>` before calling finalize (the streaming phase only needs
  file_info's scalar fields, so the detached vault from the first-write session is never touched).
- Drive the context manually: `stream_ctx.__enter__()` at first record, `stream_ctx.__exit__(...)` at
  close — pass an exception on any failure path so it unlinks the blob and writes no terminal.
- Re-chunk with `UploadAssembler(on_record=stream_ctx.write_chunk, record_size=1 MiB,
  reorder_window=SFTP_STREAMING_REORDER_MB)`; map `AssemblerError` to the handle's descriptive-failure
  path (like over-limit today). Enforce `max_bytes` on `assembler.total_bytes` in `write()`.
- Integration tests (need the stack): sequential large put with flat RSS; reorder within window;
  random-access beyond window (clean fail, no blob); TOCTOU (revoke mid-transfer → no row, no blob);
  atomic overwrite survives a failed replace; byte-identical to a web-path upload of the same file.

## Rollout

Land behind the default-OFF flag. Flip on for a deployment only after the security review and a
real large-file SFTP measurement confirm flat RSS and byte-identical round-trips. Rollback = flip the
flag off (no data-format change: streamed and staged files share one at-rest format).
