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


def test_an_over_threshold_file_is_refused_before_any_content_get_when_not_streaming():
    js = _js()
    assert "const MAX_BUFFERED_DOWNLOAD_BYTES = 256 * 1024 * 1024;" in js
    body = _download_fn()
    # When streaming is NOT going to be attempted (buffered policy / no service worker / plain HTTP),
    # the size refusal fires BEFORE the first content GET, so the browser never buffers a file it is
    # about to refuse. (mutation: move the guard back below the first fetch -> a fetch whose body is
    # never read keeps downloading gigabytes while the tab shows the refusal.)
    assert "state.downloadSink !== 'streaming' && _fsize > MAX_BUFFERED_DOWNLOAD_BYTES" in body
    pre_guard = body.index("state.downloadSink !== 'streaming' && _fsize > MAX_BUFFERED_DOWNLOAD_BYTES")
    first_fetch = body.index("await fetch(")
    assert pre_guard < first_fetch, "the size refusal must precede the first content GET"


def test_a_streaming_attempt_that_fails_cancels_the_body_instead_of_buffering_a_huge_file():
    body = _download_fn()
    # When a streaming attempt returns false (sink unavailable at runtime) for an over-threshold file,
    # the spent response body is CANCELLED and the download refused -- never re-fetched into a buffered
    # whole-file read. Both the standard and the ZK false-branches do this.
    assert body.count("await response.body.cancel();") >= 2
    # Each cancel sits with a threshold guard + a refusal, not a re-fetch.
    assert body.count("_refuseTooLarge()") >= 3   # pre-fetch + both false-branches (+ final backstop)
    # The refusal names the administrator action (LOW: not just "open over https").
    assert "ask an administrator to serve the site over https" in body
