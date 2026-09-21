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
    # The refusal is CALLED from four places: the pre-fetch guard, both streamed-false branches, the
    # final backstop. That it is called says nothing about whether any of those calls can be
    # REACHED -- `false &&` in front of all three identical conditions leaves this count exactly as
    # it is. Whether each site refuses is shown by running it: test_download_refusal_sites.py.
    assert body.count("_refuseTooLarge();") == 4
    # The refusal names the administrator action (LOW: not just "open over https").
    assert "ask an administrator to serve the site over https" in body


def _sinkworker_src():
    js = _js()
    return js[js.index("async function dvSinkWorker("):js.index("async function dvOpenDownloadSink(")]


def test_the_service_worker_activation_wait_is_bounded():
    # navigator.serviceWorker.ready never rejects and never resolves when a worker cannot activate,
    # so a blind await hangs the download with no refusal. The wait is bounded by a backstop timer
    # raced against ready + the installing worker's statechange. (mutation: drop the timer -> the
    # blocked-activation case is unbounded and hangs again -> red.)
    fn = _sinkworker_src()
    assert "navigator.serviceWorker.ready" in fn
    assert "setTimeout(" in fn                          # the backstop timer for no-event states
    assert "new Promise((resolve)" in fn                # the three-signal race


def test_a_redundant_worker_resolves_no_sink_immediately():
    # A worker that throws on install goes 'redundant' -- definitively will not activate -- so the
    # statechange listener resolves no-sink AT ONCE, not after the timer. (mutation: drop the
    # statechange listener -> a dead worker waits the full timer -> red.)
    fn = _sinkworker_src()
    assert "addEventListener('statechange'" in fn
    assert "'redundant'" in fn
    assert "installing.state === 'redundant'" in fn


def test_the_worker_is_not_cached_on_a_failure():
    # _sinkWorker is assigned ONLY on a real sink (ready/activated), never on redundant/timeout/
    # blocked -- so a later download succeeds once a worker activates. (mutation: cache on failure ->
    # a transient block would permanently disable streaming for the tab.)
    fn = _sinkworker_src()
    # Every `_sinkWorker = ` assignment sits with a success return, never on the reason path.
    assert "_sinkUnavailableReason = outcome.reason;" in fn
    reason_path = fn[fn.index("_sinkUnavailableReason = outcome.reason;"):]
    assert "_sinkWorker =" not in reason_path           # no cache after the reason is set


def test_the_refusal_wording_is_reason_driven():
    # A first-visit worker still installing at the backstop -> "try again in a moment" (a retry
    # works), NOT "this browser can't stream". Every other reason keeps the can't-stream/admin text.
    # (mutation: collapse the branch -> the installing case shows the wrong message -> red.)
    body = _download_fn()
    assert "_sinkUnavailableReason === 'timeout-installing'" in body
    branch = body[body.index("_sinkUnavailableReason === 'timeout-installing'"):]
    assert "try again in a moment" in branch[:700]
    # the reason is reset per download so a pre-fetch refusal never reads a stale value
    assert "_sinkUnavailableReason = null;" in body


def test_the_whole_opener_is_bounded_timer_before_register():
    # register() itself fetches the worker script with no timeout, so a black-holed /download-sw.js
    # leaves it pending forever. The single backstop timer is started BEFORE register(), covering the
    # register fetch AND the activation wait, so a never-settling registration resolves no-sink at the
    # bound. (mutation: move the setTimeout after the register() call -> the register fetch is
    # unbounded again -> red.)
    fn = _sinkworker_src()
    timer_at = fn.index("setTimeout(")
    register_at = fn.index("navigator.serviceWorker.register(")
    assert timer_at < register_at, "the backstop timer must start before register()"
    # A never-settling registration falls to the timer with reason blocked/timeout-installing.
    assert "reason: (installing && installing.state === 'installing') ? 'timeout-installing' : 'blocked'" in fn


def test_a_falsy_registration_is_register_failed_without_throwing():
    # Some blocked-SW harnesses resolve register() to undefined; reading .active on it would throw a
    # TypeError out of dvSinkWorker, breaking the never-throw contract (it would surface as a 'failed'
    # stream and skip the refusal). A falsy registration is treated as register-failed. (mutation:
    # drop the `if (!registration)` guard -> a TypeError escapes -> red.)
    fn = _sinkworker_src()
    assert "if (!registration) { done({ reason: 'register-failed' }); return; }" in fn
    # The whole opener is inside the settle-once Promise with a catch, so no throw escapes dvSinkWorker.
    assert ".catch(() => done({ reason: 'register-failed' }));" in fn


def test_the_outcome_is_settled_once():
    # A late-resolving registration or a worker that activates after the timer must not flip the
    # result for this download: done() is guarded by a settled flag and clears the timer.
    fn = _sinkworker_src()
    assert "if (settled) return;" in fn and "settled = true;" in fn
    assert "clearTimeout(timer)" in fn
