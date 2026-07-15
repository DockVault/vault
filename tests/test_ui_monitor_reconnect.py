"""The monitor WebSocket auto-reconnect coalesces to a single pending timer (no stacking).

The live event feed connects a single app-wide WebSocket and auto-reconnects on close/error. It has
several entry points (initial login, opening the Monitor page, the "Reconnect" button, the onclose
handler, and a WebSocket-constructor throw). Without coalescing, each of those could schedule its own
5s retry, so repeated failures fan out into a burst of connection attempts. This asserts that no matter
how many times a (re)connect is triggered, at most ONE reconnect timer is ever pending.
"""
import pytest
from playwright.sync_api import Page, expect

pytestmark = pytest.mark.ui


def _login(page: Page, username: str, password: str):
    page.goto("/")
    expect(page.locator("#login-screen")).to_be_visible()
    page.fill("#username", username)
    page.fill("#password", password)
    page.click("#login-form button[type=submit]")
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)


def test_reconnect_timer_does_not_stack(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    pending = page.evaluate(
        """() => {
            // Force the WebSocket constructor to throw so every connect attempt deterministically
            // takes the catch -> reconnect path (no real socket, no async onclose to race).
            const RealWS = window.WebSocket;
            window.WebSocket = function () { throw new Error('blocked by test'); };
            // Instrument timers to count *outstanding* 5s reconnect timers.
            const realSet = window.setTimeout, realClear = window.clearTimeout;
            const active = new Set();
            window.setTimeout = function (fn, ms, ...a) {
                const id = realSet(function () { active.delete(id); return fn.apply(this, a); }, ms, ...a);
                if (ms === 5000) active.add(id);
                return id;
            };
            window.clearTimeout = function (id) { active.delete(id); return realClear(id); };
            try {
                // Hammer the entry point the way several sources (login + init + button) would.
                for (let i = 0; i < 6; i++) connectMonitorWebSocket();
                return active.size;   // coalesced fix: 1. stacking bug: 6.
            } finally {
                window.setTimeout = realSet;
                window.clearTimeout = realClear;
                window.WebSocket = RealWS;
            }
        }"""
    )
    assert pending == 1, f"expected a single coalesced reconnect timer, got {pending}"


def test_stale_socket_close_does_not_rearm_reconnect(page: Page, admin_creds):
    """When a (re)connect supersedes a still-open socket, a LATE close event from the old socket must
    not re-arm the reconnect timer (which would tear down the healthy replacement 5s later), while the
    CURRENT socket's close DOES arm exactly one reconnect. Exercises the real onclose path (the ctor-
    throw test above only covers the catch path)."""
    _login(page, admin_creds["username"], admin_creds["password"])
    res = page.evaluate(
        """() => {
            const realSet = window.setTimeout, realClear = window.clearTimeout, RealWS = window.WebSocket;
            const active = new Set();
            window.setTimeout = function (fn, ms, ...a) {
                const id = realSet(function () { active.delete(id); return fn.apply(this, a); }, ms, ...a);
                if (ms === 5000) active.add(id);
                return id;
            };
            window.clearTimeout = function (id) { active.delete(id); return realClear(id); };
            // Fake socket whose lifecycle events we fire by hand: the constructor never throws and
            // close() does not auto-fire onclose, so the test drives onopen/onclose explicitly.
            const created = [];
            function FakeWS(url) { this.url = url; created.push(this); }
            FakeWS.prototype.send = function () {};
            FakeWS.prototype.close = function () {};
            window.WebSocket = FakeWS;
            const out = {};
            try {
                connectMonitorWebSocket();                  // socket A becomes current
                const a = created[created.length - 1];
                connectMonitorWebSocket();                  // supersedes A; socket B becomes current
                const b = created[created.length - 1];
                if (b.onopen) b.onopen();                   // B connects -> clears any pending reconnect
                if (a.onclose) a.onclose();                 // STALE close from the superseded A
                out.pendingAfterStaleClose = active.size;   // guarded: must be 0
                if (b.onclose) b.onclose();                 // CURRENT close from B
                out.pendingAfterCurrentClose = active.size; // onclose arms exactly one: must be 1
                return out;
            } finally {
                window.setTimeout = realSet;
                window.clearTimeout = realClear;
                window.WebSocket = RealWS;
            }
        }"""
    )
    assert res["pendingAfterStaleClose"] == 0, f"a stale socket's close re-armed the reconnect: {res}"
    assert res["pendingAfterCurrentClose"] == 1, f"current close should arm exactly one reconnect: {res}"
