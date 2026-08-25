/**
 * DockVault auth boot — runs synchronously in <head>, before first paint.
 *
 * Decides the FIRST-PAINT screen from whether a session token is cached, so the
 * app never flashes the wrong screen on load:
 *   - token present -> mark <html data-auth="pending">; CSS (theme.css) shows the
 *     neutral #boot-screen splash instead of the default-active login screen.
 *     app.js then verifies the token with the server (GET /users/me) and either
 *     reveals the dashboard or routes to login on 401 — so an EXPIRED token never
 *     flashes the app shell before bouncing to login.
 *   - no token      -> do nothing; the default #login-screen paints immediately.
 *
 * The token lives in localStorage OR sessionStorage (the app.js storage helper
 * falls back to sessionStorage in private mode), so check both. Mirrors the
 * pre-paint pattern of ui-boot.js; app.js clears data-auth once it routes.
 */
(function () {
    'use strict';
    try {
        // An invitation-acceptance link takes precedence over any cached session: an anonymous
        // visitor opening /?invite=... must land on the accept screen, never the app shell or a
        // stale login. Set data-invite pre-paint (CSS hides login/boot, shows #invite-screen).
        if (/[?&]invite=/.test(location.search)) {
            document.documentElement.setAttribute('data-invite', '1');
            return;
        }
        // A password-reset link (/?reset=...) likewise takes precedence over any cached session: the
        // visitor must land on the set-new-password screen, not the app shell or a stale login.
        if (/[?&]reset=/.test(location.search)) {
            document.documentElement.setAttribute('data-reset', '1');
            return;
        }
        var t = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
        if (t) document.documentElement.setAttribute('data-auth', 'pending');
    } catch (e) { /* storage blocked -> treat as logged out (login screen shows) */ }
})();
