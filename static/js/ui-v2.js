/**
 * DockVault Console (v2) skin — presentational enhancements.
 *
 * Runs ONLY when ui-boot.js has activated the v2 skin (`data-ui="v2"` on
 * <html>). Everything here is additive and cosmetic: no functional element is
 * moved, renamed or re-wired, so app.js selectors and behaviour are untouched.
 * Delete this file together with the v1 skin retirement (see ui-boot.js).
 */
(function () {
    'use strict';
    if (document.documentElement.getAttribute('data-ui') !== 'v2') return;

    // Sidebar group labels — purely visual rail sections. Each group leads
    // with an always-visible item, so labels never sit over an empty group
    // (Users/Groups/Settings are admin-only and revealed later by app.js).
    var GROUPS = [
        { before: 'dashboard', label: 'Overview' },
        { before: 'vaults', label: 'Storage' },
        { before: 'temp-creds', label: 'Access' },
        { before: 'monitor', label: 'System' }
    ];

    function injectGroupLabels() {
        var nav = document.querySelector('.sidebar-nav');
        if (!nav || nav.querySelector('.nav-group-label')) return;
        GROUPS.forEach(function (group) {
            var item = nav.querySelector('.sidebar-item[data-section="' + group.before + '"]');
            if (!item) return;
            var label = document.createElement('div');
            label.className = 'nav-group-label';
            label.setAttribute('aria-hidden', 'true');
            label.textContent = group.label;
            nav.insertBefore(label, item);
        });
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', injectGroupLabels);
    } else {
        injectGroupLabels();
    }
})();
