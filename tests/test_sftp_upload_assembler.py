"""Unit tests for the SFTP streaming-upload assembler (pure logic, no stack).

The assembler turns arbitrary-order SFTP write(offset, data) calls into ordered, fixed-size records
for the streaming encryptor. These pin: correct records for sequential input, reassembly of
out-of-order writes within the reorder window, the two failure modes (rewrite of a sealed region;
out-of-order beyond the window), gap-at-finish detection, and a full round-trip.
"""
import importlib.util
from pathlib import Path

import pytest

# Pure logic -- no running stack. Marked unit so the suite's default-integration classification (and
# its stack-health skip) does not apply; this runs in the offline lane.
pytestmark = pytest.mark.unit

# Import the module by path so the test needs no package install / sys.path juggling.
_MOD = Path(__file__).resolve().parents[1] / "app" / "sftp" / "upload_assembler.py"
_spec = importlib.util.spec_from_file_location("upload_assembler", _MOD)
upload_assembler = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(upload_assembler)
UploadAssembler = upload_assembler.UploadAssembler
AssemblerError = upload_assembler.AssemblerError


def _collect(record_size=4, reorder_window=1024):
    records = []
    a = UploadAssembler(records.append, record_size=record_size, reorder_window=reorder_window)
    return a, records


def test_sequential_exact_records():
    a, recs = _collect(record_size=4)
    a.feed(0, b"AAAA")
    a.feed(4, b"BBBB")
    a.finish()
    assert recs == [b"AAAA", b"BBBB"]
    assert a.total_bytes == 8


def test_sequential_with_short_tail():
    a, recs = _collect(record_size=4)
    a.feed(0, b"AAAA")
    a.feed(4, b"BC")            # partial final record
    a.finish()
    assert recs == [b"AAAA", b"BC"]
    assert a.total_bytes == 6


def test_small_writes_accumulate_into_records():
    a, recs = _collect(record_size=4)
    for i, ch in enumerate(b"ABCDEFG"):
        a.feed(i, bytes([ch]))
    # 7 bytes -> one full 4-byte record so far, 3 buffered.
    assert recs == [b"ABCD"]
    a.finish()
    assert recs == [b"ABCD", b"EFG"]


def test_large_write_splits_into_multiple_records():
    a, recs = _collect(record_size=4)
    a.feed(0, b"ABCDEFGHIJ")   # 10 bytes -> 2 full records + 2 buffered
    assert recs == [b"ABCD", b"EFGH"]
    a.finish()
    assert recs == [b"ABCD", b"EFGH", b"IJ"]


def test_out_of_order_within_window_reassembles():
    a, recs = _collect(record_size=4, reorder_window=64)
    a.feed(4, b"BBBB")         # gap: arrives before its predecessor
    a.feed(8, b"CCCC")         # another future block
    assert recs == []          # nothing contiguous yet
    a.feed(0, b"AAAA")         # fills the hole -> drains 0,4,8 in order
    a.finish()
    assert recs == [b"AAAA", b"BBBB", b"CCCC"]
    assert a.total_bytes == 12


def test_out_of_order_interleaved_partial_drain():
    a, recs = _collect(record_size=4, reorder_window=64)
    a.feed(0, b"AA")           # frontier=2, buffered "AA"
    a.feed(4, b"CCCC")         # gap at 4
    a.feed(2, b"BB")           # frontier=4 -> record "AABB", then drains gap at 4
    a.finish()
    assert recs == [b"AABB", b"CCCC"]


def test_rewrite_below_frontier_raises():
    a, recs = _collect(record_size=4)
    a.feed(0, b"AAAA")
    with pytest.raises(AssemblerError):
        a.feed(2, b"XX")       # overlaps already-sealed bytes


def test_overlapping_out_of_order_write_raises():
    a, recs = _collect(record_size=4, reorder_window=64)
    a.feed(4, b"BBBB")
    with pytest.raises(AssemblerError):
        a.feed(6, b"XX")       # overlaps the pending gap [4,8)


def test_out_of_order_beyond_window_raises():
    a, recs = _collect(record_size=4, reorder_window=4)
    a.feed(8, b"CCCC")         # 4 bytes held, exactly the window
    with pytest.raises(AssemblerError):
        a.feed(16, b"DDDD")    # would push held out-of-order bytes past the window


def test_gap_count_is_bounded_against_fragmentation():
    # A hostile 1-byte fragmentation pattern (strided, byte 0 withheld so nothing ever drains) stays
    # well within a huge byte window, but must NOT create unbounded gap entries: the assembler caps the
    # gap COUNT and fails fast. This is the memory-amplification / O(N^2) DoS guard.
    recs = []
    a = UploadAssembler(recs.append, record_size=1024, reorder_window=64 * 1024 * 1024, max_gaps=8)
    for k in range(1, 9):
        a.feed(2 * k, b"x")    # offsets 2,4,...,16 -> 8 non-adjacent 1-byte gaps, exactly at the cap
    with pytest.raises(AssemblerError):
        a.feed(100, b"x")      # the 9th distinct region exceeds max_gaps despite a near-empty byte budget
    assert recs == []


def test_reorder_window_zero_rejects_any_gap():
    a, recs = _collect(record_size=4, reorder_window=0)
    with pytest.raises(AssemblerError):
        a.feed(4, b"BBBB")     # any gap fails when reordering is disabled


def test_finish_with_unfilled_gap_raises():
    a, recs = _collect(record_size=4, reorder_window=64)
    a.feed(0, b"AAAA")
    a.feed(8, b"CCCC")         # gap at [4,8) never filled
    with pytest.raises(AssemblerError):
        a.finish()


def test_empty_write_is_noop():
    a, recs = _collect(record_size=4)
    a.feed(0, b"")
    a.feed(0, b"AAAA")
    a.finish()
    assert recs == [b"AAAA"]


def test_feed_after_finish_raises():
    a, recs = _collect(record_size=4)
    a.feed(0, b"AAAA")
    a.finish()
    with pytest.raises(AssemblerError):
        a.feed(4, b"BBBB")


def test_full_roundtrip_realistic_sizes():
    # A ~2.5 MiB payload written in irregular, mildly-out-of-order chunks reassembles byte-identical.
    import os
    payload = os.urandom(2_500_000)
    a, recs = _collect(record_size=1024 * 1024, reorder_window=8 * 1024 * 1024)
    # Deterministic pseudo-shuffle of contiguous spans: feed in blocks, occasionally deferring one.
    spans, i = [], 0
    while i < len(payload):
        n = 40_000 if (i // 40_000) % 5 != 3 else 37_000
        spans.append((i, payload[i:i + n]))
        i += n
    # Swap some adjacent spans to exercise the reorder path (kept within the window).
    order = list(range(len(spans)))
    for k in range(1, len(order) - 1, 7):
        order[k], order[k + 1] = order[k + 1], order[k]
    for idx in order:
        off, data = spans[idx]
        a.feed(off, data)
    a.finish()
    assert b"".join(recs) == payload
    assert a.total_bytes == len(payload)
    # Every record except possibly the last is exactly the record size.
    assert all(len(r) == 1024 * 1024 for r in recs[:-1])
    assert 0 < len(recs[-1]) <= 1024 * 1024


# ---- the buffered-bytes bound (the memory ceiling holds under back-pressure) ----------------------
def test_buffered_bytes_never_exceeds_one_record_on_a_sequential_fast_client():
    # A fast sequential client whose sink drains slowly: on_record is where the record goes to
    # storage, and it runs SYNCHRONOUSLY inside feed(), so feed() cannot return (and the client
    # cannot send the next write) until the record is drained -- the back-pressure. Sampling the
    # buffered bytes at the moment each record is emitted proves the writer never holds more than one
    # record's worth on the contiguous path, regardless of how much the client sends.
    peak = {"n": 0}
    a = None

    def _slow_sink(_record):
        # Observe the writer's own buffering at the instant a record is handed to storage.
        peak["n"] = max(peak["n"], a.buffered_bytes())

    a = UploadAssembler(_slow_sink, record_size=4, reorder_window=1024)
    for i in range(0, 4000, 4):
        a.feed(i, b"ABCD")
    a.finish()
    # Never more than ONE record in flight: at emit the pending holds exactly record_size (deleted
    # right after), and between flushes it is strictly less -- so the contiguous buffer is bounded by
    # one record no matter how much the client streams.
    assert peak["n"] <= 4, f"buffered bytes exceeded one record: {peak['n']}"
    assert a.buffered_bytes() == 0


def test_out_of_order_buffer_is_capped_at_the_reorder_window_and_refuses_past_it():
    # The reorder window (clamped to the memory ceiling by the caller) is a HARD bound: out-of-order
    # bytes are held only up to it, and a write that would push past is REFUSED, never buffered. So a
    # fast client cannot grow the writer's buffer past the ceiling by writing out of order.
    a, _ = _collect(record_size=4, reorder_window=8)
    a.feed(4, b"BBBB")               # a gap ahead of the frontier: 4 buffered
    a.feed(8, b"CCCC")               # 8 buffered -- exactly the window
    assert a.buffered_bytes() == 8
    with pytest.raises(AssemblerError):
        a.feed(12, b"DDDD")          # would be 12 > 8 -> refused, not buffered
    assert a.buffered_bytes() == 8   # unchanged: the refused write added nothing
