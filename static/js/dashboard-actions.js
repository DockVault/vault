// The dashboard as a place work starts (static/js/dashboard-actions.js).
//
// Three things, drawn after app.js has loaded the dashboard's numbers and lanes (loadDashboardStats calls
// DashboardActions.render):
//   * quick actions, by role and permission: upload a file, a new vault, a new upload link, share a vault,
//     invite a user, a new temporary credential. Each opens the page and the dialog the action lives in;
//     nothing here changes data on its own.
//   * a "Needs attention" lane: the account's own shares, public links, note links and upload links that
//     expire within seven days; uploads received on its upload links; for an administrator, invitations
//     still pending and credential changes waiting for approval.
//   * for an administrator, a "Get started" checklist (email set up and a test send passed, a public
//     address, the second-factor policy decided, a backup recorded) that goes away once done or dismissed.
//
// Everything is built with createElement and textContent: a name or a label is never HTML. Every request is
// silent and tolerated: a page that cannot be read leaves its rows out, nothing else breaks.
(function () {
    'use strict';

    const SOON_DAYS = 7;
    const LANE_LIMIT = 6;

    function el(tag, cls, text) {
        const e = document.createElement(tag);
        if (cls) e.className = cls;
        if (text != null) e.textContent = text;
        return e;
    }

    function icon(name) {
        if (typeof _svgIcon === 'function') return _svgIcon(name, 'icon-sm');
        const span = el('span');
        span.textContent = '';
        return span;
    }

    async function quiet(path) {
        try { return await apiRequest(path, { silent: true }); } catch (_) { return null; }
    }

    function isAdmin() {
        const temporary = (typeof isScopedTemp !== 'undefined' && isScopedTemp)
            || !!(typeof sessionAccess !== 'undefined' && sessionAccess && sessionAccess.is_temp_session);
        return !!(typeof currentUser !== 'undefined' && currentUser && currentUser.role === 'admin') && !temporary;
    }

    function may(group) {
        return typeof hasPermission === 'function' && hasPermission(group);
    }

    function visible(id) {
        const b = document.getElementById(id);
        return !!(b && b.offsetParent !== null && getComputedStyle(b).display !== 'none');
    }

    // Go to a page and press one of its buttons once it is there (the button is drawn by the page itself).
    function goAndPress(section, buttonId, tries) {
        navigateToSection(section);
        let left = tries || 20;
        const tick = () => {
            if (visible(buttonId)) { document.getElementById(buttonId).click(); return; }
            if (--left > 0) setTimeout(tick, 100);
        };
        setTimeout(tick, 50);
    }

    // The vault opened most recently (the dashboard's own lists know it), else the first one.
    function recentVault(vaults) {
        const list = (vaults || []).slice().sort((a, b) => {
            const ta = parseServerTime(a.last_viewed_at), tb = parseServerTime(b.last_viewed_at);
            return (tb ? tb.getTime() : 0) - (ta ? ta.getTime() : 0);
        });
        return list[0] || null;
    }

    async function openVaultAndPress(vault, buttonId) {
        if (!vault) return;
        await openVault(vault.id);
        let left = 30;
        const tick = () => {
            if (visible(buttonId)) { document.getElementById(buttonId).click(); return; }
            if (--left > 0) setTimeout(tick, 100);
        };
        setTimeout(tick, 100);
    }

    // ---- quick actions --------------------------------------------------------------------------------------
    async function renderQuickActions(ctx) {
        const host = document.getElementById('dashboard-quick-actions');
        if (!host) return;
        const vaults = ctx.vaults || [];
        const scoped = typeof isScopedTemp !== 'undefined' && isScopedTemp;
        const caps = (typeof sessionAccess !== 'undefined' && sessionAccess && sessionAccess.scope_caps) || [];
        const tempPerms = (typeof sessionAccess !== 'undefined' && sessionAccess && sessionAccess.temp_perms) || {};
        const actions = [];
        if (vaults.length) {
            actions.push({ id: 'qa-upload', icon: 'upload', label: 'Upload a file',
                           run: () => openVaultAndPress(recentVault(vaults), 'upload-file-btn') });
        }
        if (scoped ? caps.includes('vault.create') : may('VAULT_CREATE')) {
            actions.push({ id: 'qa-new-vault', icon: 'plus', label: 'New vault', run: () => goAndPress('vaults', 'create-vault-btn') });
        }
        if (!scoped) {
            if (typeof state !== 'undefined' && state._receiversEnabled === undefined
                && typeof refreshReceiverAvailability === 'function') {
                try { await refreshReceiverAvailability(); } catch (_) {}
            }
            if (typeof state !== 'undefined' && state._receiversEnabled) {
                actions.push({ id: 'qa-upload-link', icon: 'upload', label: 'New upload link',
                               run: () => goAndPress('uploadlinks', 'receiver-new-btn') });
            }
        }
        if (vaults.length && typeof vaultShareable === 'function') {
            actions.push({ id: 'qa-share', icon: 'link', label: 'Share a vault',
                           run: () => openVaultAndPress(recentVault(vaults), 'share-vault-btn') });
        }
        if (isAdmin() && may('USER_MANAGE') && typeof currentSettings !== 'undefined' && currentSettings.invite_enabled === undefined) {
            // The settings ride the admin-only GET /settings; the Users page loads them, the dashboard may come first.
            const settings = await quiet('/settings');
            if (settings) currentSettings = settings;
        }
        if (isAdmin() && may('USER_MANAGE') && typeof currentSettings !== 'undefined' && currentSettings.invite_enabled === true) {
            actions.push({ id: 'qa-invite', icon: 'users', label: 'Invite a user', run: () => goAndPress('users', 'invite-user-btn') });
        }
        if (scoped ? !!tempPerms.create : may('TEMP_CREDS_MANAGE')) {
            actions.push({ id: 'qa-temp-cred', icon: 'key', label: 'New temporary credential',
                           run: () => goAndPress('temp-creds', 'generate-temp-creds-btn') });
        }
        host.replaceChildren();
        host.hidden = actions.length === 0;
        actions.forEach((a) => {
            const b = el('button', 'btn btn-secondary btn-sm quick-action');
            b.type = 'button';
            b.id = a.id;
            b.appendChild(icon(a.icon));
            b.appendChild(document.createTextNode(' ' + a.label));
            b.addEventListener('click', () => { a.run(); });
            host.appendChild(b);
        });
    }

    // ---- needs attention ------------------------------------------------------------------------------------
    function soon(iso) {
        const t = parseServerTime(iso);
        if (!t) return null;
        const days = (t.getTime() - Date.now()) / 86400000;
        return days >= 0 && days <= SOON_DAYS ? days : null;
    }

    function inDays(days) {
        if (days < 1) return 'within a day';
        const d = Math.ceil(days);
        return `in ${d} day${d === 1 ? '' : 's'}`;
    }

    function row(iconName, title, sub, onClick) {
        const r = el('button', 'dashboard-lane-item attention-item');
        r.type = 'button';
        const ic = el('span', 'dashboard-lane-icon');
        ic.appendChild(icon(iconName));
        r.appendChild(ic);
        const main = el('div', 'dashboard-lane-main');
        main.appendChild(el('div', 'dashboard-lane-title', title));
        if (sub) main.appendChild(el('div', 'dashboard-lane-sub text-secondary', sub));
        r.appendChild(main);
        r.addEventListener('click', onClick);
        return r;
    }

    function list(x, key) {
        if (Array.isArray(x)) return x;
        if (x && Array.isArray(x[key])) return x[key];
        return [];
    }

    async function renderAttention(ctx) {
        const box = document.getElementById('lane-attention');
        if (!box) return;
        const rows = [];
        const scoped = typeof isScopedTemp !== 'undefined' && isScopedTemp;
        if (!scoped) {
            const [shares, publicLinks, noteLinks, receivers] = await Promise.all([
                quiet('/shares'), quiet('/public-links'), quiet('/note-links'), quiet('/receivers')]);
            list(shares, 'shares').filter(s => s.status === 'active' && soon(s.expires_at) != null)
                .forEach(s => rows.push(row('link', `Share of ${s.target_name || s.vault_name || 'an item'} expires ${inDays(soon(s.expires_at))}`,
                                             s.vault_name || '', () => navigateToSection('shared'))));
            list(publicLinks, 'links').filter(l => !l.revoked && l.status !== 'expired' && soon(l.expires_at) != null)
                .forEach(l => rows.push(row('globe', `Public link expires ${inDays(soon(l.expires_at))}`,
                                             l.tag_name || '', () => openVault(l.vault_id))));
            list(noteLinks, 'links').filter(l => !l.revoked && soon(l.expires_at) != null)
                .forEach(l => rows.push(row('file-text', `Note link "${l.title || 'note'}" expires ${inDays(soon(l.expires_at))}`,
                                             '', () => navigateToSection('notes'))));
            const recv = list(receivers, 'receivers');
            recv.filter(r => (r.upload_count || 0) > 0)
                .forEach(r => rows.push(row('upload', `${r.upload_count} upload${r.upload_count === 1 ? '' : 's'} received on ${r.label || 'an upload link'}`,
                                             'Open the drop vault', () => openVault(r.vault_id, { from: 'uploadlinks' }))));
            recv.filter(r => soon(r.expires_at) != null)
                .forEach(r => rows.push(row('upload', `Upload link ${r.label || ''} expires ${inDays(soon(r.expires_at))}`.replace(/\s+/g, ' '),
                                             '', () => navigateToSection('uploadlinks'))));
        }
        if (isAdmin()) {
            const [invites, requests] = await Promise.all([
                may('USER_VIEW') ? quiet('/invites') : null, may('USER_MANAGE') ? quiet('/admin/credential-requests') : null]);
            const pending = list(invites, 'invites').filter(i => i.status === 'pending').length;
            if (pending) rows.unshift(row('users', `${pending} invitation${pending === 1 ? '' : 's'} pending`,
                                          'Not accepted yet', () => navigateToSection('users')));
            const held = list(requests, 'requests').length;
            if (held) rows.unshift(row('shield', `${held} credential change${held === 1 ? '' : 's'} await${held === 1 ? 's' : ''} approval`,
                                       'Approve or deny on the Users page', () => navigateToSection('users')));
        }
        box.replaceChildren();
        if (!rows.length) { box.appendChild(el('p', 'dashboard-lane-empty text-secondary', 'Nothing needs your attention.')); return; }
        rows.slice(0, LANE_LIMIT).forEach(r => box.appendChild(r));
    }

    // ---- get started (administrators) -----------------------------------------------------------------------
    const CHECKS = [
        { key: 'email', label: 'Email set up, and a test message sent',
          hint: 'Settings > Email: a sending profile, then "Send a test email".', go: () => navigateToSection('settings') },
        { key: 'public_address', label: 'A public address for emailed links',
          hint: 'ALLOWED_HOSTS in the deployment’s .env names the address people use; emailed links are pinned to it.' },
        { key: 'second_factor', label: 'The second-factor policy decided',
          hint: 'Settings > Security: require a second factor, or keep it optional on purpose.',
          go: () => navigateToSection('settings'), ack: { second_factor_decided: true }, ackLabel: 'Keep it optional' },
        { key: 'backup', label: 'A backup recorded',
          hint: 'Back up the data and record it here, so the first restore is not the first try.',
          ack: { backup_recorded: true }, ackLabel: 'I recorded a backup' },
    ];

    async function post(body) {
        try {
            return await apiRequest('/admin/get-started', { method: 'POST', body: JSON.stringify(body), silent: true });
        } catch (_) { return null; }
    }

    async function renderGetStarted() {
        const card = document.getElementById('dashboard-get-started');
        if (!card) return;
        if (!isAdmin()) { card.hidden = true; return; }
        const view = await quiet('/admin/get-started');
        if (!view || view.dismissed || view.done) { card.hidden = true; return; }
        drawGetStarted(card, view);
        card.hidden = false;
    }

    function drawGetStarted(card, view) {
        const listEl = card.querySelector('.get-started-list');
        listEl.replaceChildren();
        CHECKS.forEach((c) => {
            const done = !!(view.items && view.items[c.key]);
            const li = el('li', 'get-started-item' + (done ? ' is-done' : ''));
            li.setAttribute('data-check', c.key);
            const mark = el('span', 'get-started-mark', done ? '✓' : '');
            mark.setAttribute('aria-label', done ? 'Done' : 'To do');
            li.appendChild(mark);
            const main = el('div', 'get-started-main');
            main.appendChild(el('div', 'get-started-label', c.label));
            if (!done) {
                main.appendChild(el('div', 'get-started-hint text-secondary', c.hint));
                const acts = el('div', 'get-started-actions');
                if (c.go) {
                    const go = el('button', 'btn btn-sm btn-secondary', 'Open settings');
                    go.type = 'button';
                    go.addEventListener('click', c.go);
                    acts.appendChild(go);
                }
                if (c.ack) {
                    const ack = el('button', 'btn btn-sm btn-ghost get-started-ack', c.ackLabel);
                    ack.type = 'button';
                    ack.addEventListener('click', async () => {
                        const next = await post(c.ack);
                        if (next) { if (next.done) card.hidden = true; else drawGetStarted(card, next); }
                    });
                    acts.appendChild(ack);
                }
                if (acts.childNodes.length) main.appendChild(acts);
            }
            li.appendChild(main);
            listEl.appendChild(li);
        });
        const dismiss = card.querySelector('.get-started-dismiss');
        if (dismiss && !dismiss.dataset.wired) {
            dismiss.dataset.wired = '1';
            dismiss.addEventListener('click', async () => { await post({ dismissed: true }); card.hidden = true; });
        }
    }

    // ---- stat cards as links --------------------------------------------------------------------------------
    function wireStatCards() {
        document.querySelectorAll('.stat-card[data-go]').forEach((card) => {
            if (card.dataset.wired) return;
            card.dataset.wired = '1';
            card.setAttribute('role', 'link');
            card.setAttribute('tabindex', '0');
            const go = () => navigateToSection(card.getAttribute('data-go'));
            card.addEventListener('click', go);
            card.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
        });
    }

    async function render(ctx) {
        wireStatCards();
        await Promise.all([renderQuickActions(ctx || {}), renderAttention(ctx || {}), renderGetStarted()]);
    }

    window.DashboardActions = { render, soon, inDays };
})();
