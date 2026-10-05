/*
 * A banner across the top of the app after sign-in, for a notice the signed-in user has to read: shown until they
 * say they have read it. NoticeBanner.show({ id, text, linkText, href, onRead }) puts one up (one per id);
 * NoticeBanner.hide(id) takes it down. Built with createElement and textContent only.
 *
 * The recording notice uses it: when the recording levels changed since the user last read the notice
 * (GET /privacy/recording/status), at sign-in and live when the server announces a change, the banner links to
 * /recording, and "I've read it" posts POST /privacy/recording/seen (which records reading it, not consent).
 * Uses app.js's apiRequest when it is there.
 */
(function () {
    'use strict';

    const shown = new Map();

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function host() {
        const screen = document.getElementById('dashboard-screen');
        if (!screen) return null;
        let box = document.getElementById('notice-banners');
        if (!box) {
            box = el('div', 'notice-banners');
            box.id = 'notice-banners';
            box.setAttribute('role', 'region');
            box.setAttribute('aria-label', 'Notices');
            screen.insertBefore(box, screen.firstChild);
        }
        return box;
    }

    function show(opts) {
        const box = host();
        if (!box) return null;
        hide(opts.id);
        const banner = el('div', 'notice-banner');
        banner.dataset.notice = opts.id;
        banner.setAttribute('role', 'status');
        banner.appendChild(el('span', 'notice-banner-text', opts.text));
        if (opts.href) {
            const link = el('a', 'notice-banner-link', opts.linkText || 'Read it');
            link.href = opts.href;
            link.target = '_blank';
            link.rel = 'noopener';
            banner.appendChild(link);
        }
        const read = el('button', 'btn btn-sm btn-primary notice-banner-read', "I've read it");
        read.type = 'button';
        read.addEventListener('click', async () => {
            read.disabled = true;
            try {
                if (opts.onRead) await opts.onRead();
                hide(opts.id);
            } catch (e) {
                read.disabled = false;
            }
        });
        banner.appendChild(read);
        box.appendChild(banner);
        shown.set(opts.id, banner);
        return banner;
    }

    function hide(id) {
        const banner = shown.get(id);
        if (banner) { banner.remove(); shown.delete(id); }
    }

    window.NoticeBanner = { show, hide };

    // ---- the recording notice ------------------------------------------------------------------------
    const RECORDING = 'recording-levels';

    function request(path, options) {
        if (typeof apiRequest === 'function') return apiRequest(path, Object.assign({ silent: true }, options || {}));
        return Promise.reject(new Error('not signed in'));
    }

    async function checkRecording() {
        let status;
        try { status = await request('/privacy/recording/status'); } catch (_) { return; }
        if (!status || !status.show) { hide(RECORDING); return; }
        show({
            id: RECORDING, text: status.text, linkText: 'What this vault records', href: '/recording',
            onRead: () => request('/privacy/recording/seen', { method: 'POST', body: JSON.stringify({ version: status.version }) }),
        });
    }

    // At sign-in: when the app shows its dashboard.
    function watchSignIn() {
        const screen = document.getElementById('dashboard-screen');
        if (!screen) return;
        let active = screen.classList.contains('active');
        if (active) checkRecording();
        new MutationObserver(() => {
            const now = screen.classList.contains('active');
            if (now && !active) checkRecording();
            if (!now) hide(RECORDING);
            active = now;
        }).observe(screen, { attributes: true, attributeFilter: ['class'] });
    }

    // Live: the server announced a new version (app.js passes the socket's notification on).
    window.addEventListener('dockvault:recording-levels', checkRecording);

    // The notification's link opens the notice.
    function linkNotification() {
        try {
            if (typeof _NOTIF_TARGET_OPEN === 'object' && _NOTIF_TARGET_OPEN) {
                _NOTIF_TARGET_OPEN['#recording'] = () => window.open('/recording', '_blank', 'noopener');
            }
        } catch (_) { /* the bell then only marks it read */ }
    }

    if (document.readyState === 'loading') {
        document.addEventListener('DOMContentLoaded', () => { watchSignIn(); linkNotification(); });
    } else {
        watchSignIn();
        linkNotification();
    }
})();
