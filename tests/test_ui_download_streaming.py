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


def test_every_refusal_aborts_the_connection_by_construction():
    body = _download_fn()
    # _refuseTooLarge aborts the fetch controller BEFORE showing the message, so every refusal path
    # (pre-fetch, both streamed===false branches, the final backstop) tears the connection down --
    # the guarantee that works even on the ZK branch where _peekStream has locked response.body and
    # response.body.cancel() would throw. (mutation: delete the _dlAbort.abort() inside
    # _refuseTooLarge -> a locked-body refusal leaves the download running -> red.)
    refuse_def = body[body.index("const _refuseTooLarge = () => {"):]
    refuse_def = refuse_def[:refuse_def.index("showError(")]
    assert "_dlAbort.abort();" in refuse_def, "the refusal must abort the fetch before showing the message"
    # The refusal is used on every path: pre-fetch guard + both false-branches (+ the final backstop).
    assert body.count("_refuseTooLarge()") >= 3
    # The refusal names the administrator action (LOW: not just "open over https").
    assert "ask an administrator to serve the site over https" in body


def test_the_service_worker_activation_wait_is_bounded():
    # navigator.serviceWorker.ready never rejects and never resolves when a worker cannot activate
    # (blocked / throws on install), so a blind await hangs the download with no refusal. dvSinkWorker
    # must bound the wait so a blocked worker resolves to "no sink" -> the caller refuses (with abort)
    # an over-threshold file. (mutation: drop the Promise.race timer -> the wait is unbounded -> red.)
    js = _js()
    fn = js[js.index("async function dvSinkWorker("):js.index("async function dvOpenDownloadSink(")]
    assert "Promise.race([" in fn
    assert "navigator.serviceWorker.ready" in fn
    assert "setTimeout(" in fn and "reject(" in fn      # the bounding timer that rejects on expiry
    # A blocked/failed activation returns null (no sink), which routes the caller to refuse+abort.
    assert "return null;" in fn
