"""Source pins for the bounded-memory web download path (the browser half).

The live RSS proof (a multi-GB file-UI download with a flat renderer) is the live/acceptance lane;
these pin the wiring the acceptance rests on: a standard-vault download streams straight into the
service-worker sink instead of buffering a whole blob, and when streaming is unavailable the file UI
REFUSES a file too large to hold in memory rather than silently reading it whole.
"""
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

APPJS = Path(__file__).resolve().parents[1] / "static" / "js" / "app.js"


def _js():
    return APPJS.read_text(encoding="utf-8")


def _download_fn():
    js = _js()
    start = js.index("async function _downloadFile(")
    return js[start:js.index("\nasync function ", start + 10)]


def test_a_standard_vault_download_streams_into_the_sink_not_a_whole_blob():
    js = _js()
    helper = js[js.index("async function dvTryStandardStreamedDownload("):
                js.index("async function zkTryStreamedDownload(")]
    # It reads the response body incrementally and writes each chunk to the SW sink, releasing it.
    assert "response.body.getReader()" in helper
    assert "dvOpenDownloadSink(" in helper
    assert "sink.write(value)" in helper and "sink.done()" in helper
    # No whole-file materialisation in the streaming helper.
    assert "arrayBuffer()" not in helper and "response.blob()" not in helper


def test_downloadFile_prefers_the_standard_streaming_path_when_policy_streams():
    body = _download_fn()
    assert "!isZkVault(state.currentVault) && state.downloadSink === 'streaming'" in body
    assert "dvTryStandardStreamedDownload(" in body
    # The three outcomes are handled: under way (return), failed part-way (return, no fallback),
    # false -> re-fetch for the buffered path.
    seg = body[body.index("dvTryStandardStreamedDownload("):]
    assert "=== true" in seg[:400] and "'failed'" in seg[:600]


def test_the_buffered_path_refuses_a_file_too_large_to_hold_in_memory():
    js = _js()
    assert "const MAX_BUFFERED_DOWNLOAD_BYTES = 256 * 1024 * 1024;" in js
    body = _download_fn()
    # The threshold check sits BEFORE the buffered blob read, and returns (refuses) rather than
    # buffering. (mutation: drop the `_fsize > MAX_BUFFERED_DOWNLOAD_BYTES` guard -> a multi-GB file
    # falls into the whole-blob read -> the browser blows up.)
    assert "_fsize > MAX_BUFFERED_DOWNLOAD_BYTES" in body
    guard = body.index("_fsize > MAX_BUFFERED_DOWNLOAD_BYTES")
    blob_read = body.index("let blob;", guard)
    assert guard < blob_read, "the size refusal must precede the buffered blob read"
    # The refusal names why (too large + streaming unavailable), it does not silently proceed.
    refuse = body[guard:blob_read]
    assert "too large to download here" in refuse and "return;" in refuse
