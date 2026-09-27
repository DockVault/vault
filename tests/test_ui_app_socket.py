"""The app-wide socket in the page: it reconnects without stacking timers, hands the Activity signal to
the page, and the pages it used to feed are gone.

The socket is opened at sign-in and auto-reconnects on close or error. It has several entry points
(sign-in, a navigation that finds it closed, the onclose handler, and a WebSocket-constructor throw).
Without coalescing, each could schedule its own 5 s retry, so repeated failures fan out into a burst of
connection attempts; at most ONE reconnect timer may ever be pending.

Until 0.33.0 the socket also fed the Live Monitor page, and the Settings -> Audit Log tab read the log
for itself; the Activity page replaced both.
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
                // Hammer the entry point the way several sources (sign-in + navigation) would.
                for (let i = 0; i < 6; i++) connectAppSocket();
                return active.size;   // coalesced: 1. stacking: 6.
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
    CURRENT socket's close DOES arm exactly one reconnect."""
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
                connectAppSocket();                         // socket A becomes current
                const a = created[created.length - 1];
                connectAppSocket();                         // supersedes A; socket B becomes current
                const b = created[created.length - 1];
                if (b.onopen) b.onopen();                   // B connects -> clears any pending reconnect
                if (a.onclose) a.onclose();                 // STALE close from the superseded A
                out.pendingAfterStaleClose = active.size;   // guarded: must be 0
                if (b.onclose) b.onclose();                 // CURRENT close from B
                out.pendingAfterCurrentClose = active.size; // onclose arms exactly one: must be 1
                closeAppSocket();                           // sign-out: nothing left pending
                out.pendingAfterSignOut = active.size;
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
    assert res["pendingAfterSignOut"] == 0, f"signing out left a reconnect pending: {res}"


def test_the_activity_signal_reaches_the_page_as_an_event(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    got = page.evaluate(
        """() => {
            const seen = [];
            const listen = (e) => seen.push(e.detail);
            window.addEventListener('dockvault:activity', listen);
            try {
                handleSocketFrame({ type: 'activity',
                                    events: [{ id: '8c6f0d2e-1111-4a4a-9a9a-000000000001', category: 'sign_in' }] });
                handleSocketFrame({ type: 'connected', message: 'Connected as admin' });
                handleSocketFrame({ event: { type: 'upload', user: 'someone' } });
                return seen;
            } finally {
                window.removeEventListener('dockvault:activity', listen);
            }
        }"""
    )
    assert got == [{"events": [{"id": "8c6f0d2e-1111-4a4a-9a9a-000000000001", "category": "sign_in"}]}]


def test_the_page_hears_how_the_socket_is_doing(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    # Signed in: the socket is open, and a page opened later can read that.
    page.wait_for_function("() => window.dockvaultSocketState === 'open'", timeout=10000)
    states = page.evaluate(
        """() => {
            const seen = [];
            const listen = (e) => seen.push(e.detail.state);
            window.addEventListener('dockvault:socket', listen);
            const RealWS = window.WebSocket;
            try {
                window.WebSocket = function () { throw new Error('blocked by test'); };
                connectAppSocket();                  // connecting, then error
                closeAppSocket();                    // closed, as at sign-out
                return seen;
            } finally {
                window.WebSocket = RealWS;
                window.removeEventListener('dockvault:socket', listen);
            }
        }"""
    )
    assert states == ["connecting", "error", "closed"], states


def test_the_live_monitor_and_the_settings_audit_log_are_gone(page: Page, admin_creds):
    _login(page, admin_creds["username"], admin_creds["password"])
    expect(page.locator('.sidebar-item[data-section="activity"]')).to_be_visible()
    assert page.locator('.sidebar-item[data-section="monitor"]').count() == 0
    assert page.locator("#monitor-section").count() == 0
    page.click('.sidebar-item[data-section="settings"]')
    expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
    assert page.locator('.tab-btn[data-tab="audit"]').count() == 0
    assert page.locator("#settings-tab-audit").count() == 0


def test_a_page_remembered_from_an_older_release_opens_the_dashboard(page: Page, admin_creds):
    # A browser whose last view was the Live Monitor, before the upgrade.
    _login(page, admin_creds["username"], admin_creds["password"])
    page.evaluate("sessionStorage.setItem('dv_nav', JSON.stringify({ section: 'monitor' }))")
    page.reload()
    expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
    expect(page.locator("#dashboard-section")).to_be_visible(timeout=10000)
    # And the dashboard is loaded, not left as the empty shell a missing page used to leave behind.
    expect(page.locator("#dashboard-vaults-count")).not_to_have_text("-", timeout=10000)
