"""Re-assemble SFTP ``write(offset, data)`` calls into ordered, fixed-size records for a streaming
encryptor.

An SFTP client writes a file as a sequence of ``(offset, data)`` calls. ``sftp put`` / ``scp`` write
strictly sequentially, but the protocol permits a client to write records slightly out of order or
(rarely) at arbitrary offsets. A streaming encryptor cannot accept that directly: it seals each record
bound to a **monotonic index** (the record's position is part of the AEAD AAD), so records must be fed
**in order** and at a **fixed size** (except a possibly-short final one).

This assembler bridges the two. It accepts writes in any order, holds at most one record's worth of
contiguous bytes plus a **bounded reorder window** of out-of-order bytes, and emits complete in-order
records through ``on_record``. It is pure (no I/O, no crypto, no DB) so it can be unit-tested on its
own; the SFTP handle wires ``on_record`` to the encryptor's ``write_chunk`` and calls ``finish`` at
close.

Two conditions raise :class:`AssemblerError`, and the caller maps them to a descriptive SFTP failure:

* a **rewrite** of an already-emitted/received region (``offset`` below the contiguous frontier) --
  the bytes are gone through the AEAD, so there is no honest way to serve it; and
* out-of-order data that would exceed the reorder window -- a genuinely random-access writer, which
  the buffered (non-streaming) path still serves.
"""

DEFAULT_RECORD_SIZE = 1024 * 1024  # 1 MiB -- matches the buffered/web write path's chunk size.


class AssemblerError(Exception):
    """A write could not be assembled into the sequential record stream."""


class UploadAssembler:
    """Turn arbitrary-order ``feed(offset, data)`` writes into ordered fixed-size records.

    Args:
        on_record: called with each complete record (``record_size`` bytes, except the final one
            emitted by :meth:`finish`, which may be shorter). Called strictly in order.
        record_size: the emitted record size in bytes.
        reorder_window: the maximum number of bytes of not-yet-contiguous (out-of-order) data held
            at once. A write that would push the held out-of-order bytes past this raises. ``0``
            disables reordering entirely (any gap fails immediately).

    Memory held is at most ``record_size`` (the pending contiguous tail) plus ``reorder_window``
    bytes, across at most ``max_gaps`` distinct out-of-order regions (so a 1-byte fragmentation
    pattern cannot amplify entry overhead or the overlap scan).
    """

    def __init__(self, on_record, record_size: int = DEFAULT_RECORD_SIZE,
                 reorder_window: int = 16 * 1024 * 1024, max_gaps: int = 4096):
        if record_size <= 0:
            raise ValueError("record_size must be positive")
        if reorder_window < 0:
            raise ValueError("reorder_window must be >= 0")
        if max_gaps < 1:
            raise ValueError("max_gaps must be >= 1")
        self._on_record = on_record
        self._record_size = record_size
        self._reorder_window = reorder_window
        # Cap on the NUMBER of distinct out-of-order regions held at once (not just their bytes). A
        # near-sequential client holds a handful; a hostile 1-byte fragmentation pattern would stay
        # within the byte window yet create millions of dict entries with an O(N) scan each -> O(N^2)
        # CPU + huge memory. This bounds both, failing a pathological pattern fast.
        self._max_gaps = max_gaps
        # The contiguous frontier: every byte in [0, _frontier) has been received.
        self._frontier = 0
        # Contiguous bytes received but not yet emitted as a record (always < record_size after a flush).
        self._pending = bytearray()
        # Out-of-order writes not yet contiguous with the frontier: {start_offset: bytes}. Kept
        # non-overlapping; total bytes are bounded by _reorder_window.
        self._gaps = {}
        self._gap_bytes = 0
        self._finished = False
        # Total plaintext bytes accepted (== _frontier once finished / no gaps). Exposed for the caller
        # to enforce a size bound in-stream.
        self.total_bytes = 0

    # -- public API ---------------------------------------------------------
    def feed(self, offset: int, data: bytes) -> None:
        """Accept one SFTP write. Emits any records that become complete."""
        if self._finished:
            raise AssemblerError("write after finish")
        if not data:
            return
        end = offset + len(data)
        if offset < self._frontier:
            # Overlaps bytes already accepted into the contiguous stream (and possibly already sealed).
            # Even a purely-overlapping rewrite cannot be honoured once records are sealed; reject the
            # whole write rather than silently dropping or double-counting.
            raise AssemblerError(
                f"non-monotonic write at offset {offset} below the {self._frontier}-byte frontier")
        if offset == self._frontier:
            self._append_contiguous(data)
            self._drain_gaps()
        else:
            self._add_gap(offset, end, data)

    def finish(self) -> None:
        """Signal end of input: emit the final (possibly short) record.

        Raises if any out-of-order data never became contiguous (a hole in the file).
        """
        if self._finished:
            return
        if self._gaps:
            missing = min(self._gaps)
            raise AssemblerError(
                f"upload ended with a gap: {self._gap_bytes} byte(s) from offset {missing} never "
                f"became contiguous")
        self._finished = True
        if self._pending:
            self._on_record(bytes(self._pending))
            self._pending = bytearray()

    # -- internals ----------------------------------------------------------
    def _append_contiguous(self, data: bytes) -> None:
        self._pending.extend(data)
        self._frontier += len(data)
        self.total_bytes += len(data)
        self._flush_full_records()

    def _flush_full_records(self) -> None:
        rs = self._record_size
        while len(self._pending) >= rs:
            self._on_record(bytes(self._pending[:rs]))
            del self._pending[:rs]

    def _add_gap(self, offset: int, end: int, data: bytes) -> None:
        # A write strictly ahead of the frontier. Bound the NUMBER of gap regions BEFORE the O(N)
        # overlap scan below, so a hostile 1-byte fragmentation pattern (which stays within the byte
        # window) can't grow the dict/scan without limit -- fail fast instead of amplifying memory + CPU.
        if len(self._gaps) >= self._max_gaps:
            raise AssemblerError(
                f"too many out-of-order regions ({self._max_gaps}); the streaming path needs "
                f"near-sequential writes")
        # Reject any overlap with an existing gap span (a client re-sending an already-buffered future
        # record) rather than guessing which copy wins.
        for g_off, g_data in self._gaps.items():
            if offset < g_off + len(g_data) and end > g_off:
                raise AssemblerError(f"overlapping out-of-order write at offset {offset}")
        if self._gap_bytes + len(data) > self._reorder_window:
            raise AssemblerError(
                f"out-of-order write exceeds the {self._reorder_window}-byte reorder window "
                f"(random-access uploads are not supported over the streaming path)")
        self._gaps[offset] = data
        self._gap_bytes += len(data)

    def _drain_gaps(self) -> None:
        # Pull any gap that now starts exactly at the frontier into the contiguous stream, repeating
        # as each one advances the frontier to the next.
        while self._frontier in self._gaps:
            data = self._gaps.pop(self._frontier)
            self._gap_bytes -= len(data)
            self._append_contiguous(data)
