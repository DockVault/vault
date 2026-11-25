/*
 * The public pages' theme (upload link, public link, shared note, privacy): light or dark before the first
 * paint. The visitor's saved choice in this browser ('theme', the key the app itself keeps) wins; with none,
 * the system's preference. Loaded in <head> without defer, as a file of its own, so it runs under the
 * content security policy with nothing inline.
 */
(function () {
    'use strict';

    var root = document.documentElement;

    function saved() {
        try {
            var t = localStorage.getItem('theme');
            return t === 'light' || t === 'dark' ? t : null;
        } catch (_) { return null; }
    }

    function system() {
        try {
            return window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)').matches ? 'dark' : 'light';
        } catch (_) { return 'light'; }
    }

    root.setAttribute('data-theme', saved() || system());

    // With no saved choice, follow the system when it changes while the page is open.
    try {
        var query = window.matchMedia && window.matchMedia('(prefers-color-scheme: dark)');
        if (query && query.addEventListener) {
            query.addEventListener('change', function () {
                if (!saved()) root.setAttribute('data-theme', system());
            });
        }
    } catch (_) { /* an older browser keeps the theme it started with */ }
})();
