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
        var t = localStorage.getItem('authToken') || sessionStorage.getItem('authToken');
        if (t) document.documentElement.setAttribute('data-auth', 'pending');
    } catch (e) { /* storage blocked -> treat as logged out (login screen shows) */ }
})();
