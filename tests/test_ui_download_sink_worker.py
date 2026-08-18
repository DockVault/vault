"""The streaming sink's worker: served where it can work, and registrable.

A service worker's scope is the directory it was served from, so this file being reachable at the
ORIGIN ROOT is not a detail — served from `/static/js/` the same bytes could only ever intercept
`/static/js/...` and would never see a download. That is invisible until someone tries to stream a
file, which is why it is asserted here rather than assumed.

**Deliberately no aborted-transfer case.** A browser will not close while a streamed download is
still pending, and an aborted stream leaves one open: a probe written that way hung for 65 minutes
before it was noticed, and the same test in CI would consume the job's entire time budget rather
than failing. The abort path is covered by the design note's measurements, taken outside CI where
a hang costs one process rather than a build.
"""
from __future__ import annotations

import pytest

pytestmark = pytest.mark.ui


def test_the_worker_is_served_from_the_origin_root(anon):
    """Not from /static/js/, and with a content type a browser will execute."""
    r = anon.get("/download-sw.js")
    assert r.status_code == 200, r.text
    assert "javascript" in r.headers.get("Content-Type", ""), (
        "a worker served without a JavaScript content type is refused by the browser")
    assert r.headers.get("Service-Worker-Allowed") == "/", (
        "without this the scope is the serving directory, and the sink URL is outside it")
    assert "dv-sink-open" in r.text, "this is not the sink worker"


def test_a_page_can_register_it_and_it_takes_control(page, base_url):
    """Registration, on the deployment as configured.

    CI reaches the vault on a loopback address, which browsers treat as a secure context, so this
    exercises the real thing. A deployment reached over plain HTTP on a LAN address cannot register
    a worker at all — that is why the policy resolves to buffered there, and why this test asserts
    the capability rather than assuming it.
    """
    page.goto("/")
    result = page.evaluate(
        """async () => {
            if (!window.isSecureContext) return {secure: false};
            if (!('serviceWorker' in navigator)) return {secure: true, supported: false};
            try {
                const reg = await navigator.serviceWorker.register(
                    '/download-sw.js', {scope: '/'});
                await navigator.serviceWorker.ready;
                const active = !!(reg.active || navigator.serviceWorker.controller);
                const scope = reg.scope;
                await reg.unregister();
                return {secure: true, supported: true, active, scope};
            } catch (e) {
                return {secure: true, supported: true, error: String(e).slice(0, 200)};
            }
        }"""
    )

    if not result.get("secure"):
        pytest.skip(f"{base_url} is not a secure context, so no worker can be registered here")

    assert result.get("supported"), "this browser has no service workers at all"
    assert not result.get("error"), f"registration failed: {result.get('error')}"
    assert result.get("active"), "the worker registered but never became active"
    assert result.get("scope", "").endswith("/"), (
        f"scope {result.get('scope')!r} does not cover the whole origin, so the worker would "
        f"never see a download URL")
