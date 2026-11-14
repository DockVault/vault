// The dashboard as a place work starts (static/js/dashboard-actions.js).
//
// Three things, drawn after app.js has loaded the dashboard's numbers and lanes (loadDashboardStats calls
// DashboardActions.render):
//   * quick actions, by role and permission: upload a file, a new vault, a new upload link, share a vault,
//     invite a user, a new temporary credential. Each opens the page and the dialog the action lives in;
//     nothing here changes data on its own.
//   * a "Needs attention" lane: the account's own shares, public links, note links and upload links that
//     expire within seven days; files still waiting in the drop vaults of its upload links; for an
//     administrator, invitations still pending and credential changes waiting for approval. A thing listed
//     here is left out of "What's waiting for you" (the notice about it is the same thing, said twice).
//     Each row's full title is its tooltip, for a title the lane cuts short.
//   * for an administrator, a "Get started" checklist (email set up and a test send passed, a public
//     address, the second-factor policy decided, backups set up, on the administrator's word) that goes
//     away once done or dismissed.
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

    // The session a draw begins for, and whether it has ended since (a sign-out, or another person signed in): an
    // answer that comes back after that is the last person's, and none of it is drawn.
    function session() { return typeof authToken !== 'undefined' ? authToken : null; }
    function gone(who) { return !who || session() !== who; }

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

    // The upload-link policy as this page knows it, asked of the server when it does not know yet (one question
    // for the sign-in, the quick actions and the attention lane together: refreshReceiverAvailability in app.js).
    async function receiverPolicyKnown() {
        if (typeof state === 'undefined') return false;
        if (state._receiversEnabled === undefined && typeof refreshReceiverAvailability === 'function') {
            try { await refreshReceiverAvailability(); } catch (_) {}
        }
        return true;
    }

    // Whether this person may make an upload link: the feature on, and a tag they may make one with.
    async function receiversOn() {
        return (await receiverPolicyKnown()) && !!state._receiversEnabled;
    }

    // Whether upload links are switched on at all. The links a person already has (their files waiting, their
    // expiry) are theirs to see whatever the tags allow them to make now; a switched-off feature asks nothing.
    async function receiversSwitchedOn() {
        return (await receiverPolicyKnown()) && !!(state._receiverPolicy && state._receiverPolicy.enabled);
    }

    // ---- quick actions --------------------------------------------------------------------------------------
    async function renderQuickActions(ctx) {
        const host = document.getElementById('dashboard-quick-actions');
        if (!host) return;
        const who = session();
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
            const on = await receiversOn();
            if (gone(who)) return;
            if (on) {
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
            if (gone(who)) return;
            if (settings) currentSettings = settings;
        }
        if (isAdmin() && may('USER_MANAGE') && typeof currentSettings !== 'undefined' && currentSettings.invite_enabled === true) {
            actions.push({ id: 'qa-invite', icon: 'users', label: 'Invite a user', run: () => goAndPress('users', 'invite-user-btn') });
        }
        if (scoped ? !!tempPerms.create : may('TEMP_CREDS_MANAGE')) {
            actions.push({ id: 'qa-temp-cred', icon: 'key', label: 'New temporary credential',
                           run: () => goAndPress('temp-creds', 'generate-temp-creds-btn') });
        }
        if (gone(who)) return;
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

    function row(iconName, title, sub, onClick, kind) {
        const r = el('button', 'dashboard-lane-item attention-item');
        r.type = 'button';
        if (kind) r.setAttribute('data-kind', kind);
        const ic = el('span', 'dashboard-lane-icon');
        ic.appendChild(icon(iconName));
        r.appendChild(ic);
        const main = el('div', 'dashboard-lane-main');
        const t = el('div', 'dashboard-lane-title', title);
        t.title = title;                    // the lane cuts a long title short; the whole of it on hover
        main.appendChild(t);
        if (sub) {
            const s = el('div', 'dashboard-lane-sub text-secondary', sub);
            s.title = sub;
            main.appendChild(s);
        }
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
        const who = session();
        const rows = [];
        const scoped = typeof isScopedTemp !== 'undefined' && isScopedTemp;
        if (!scoped) {
            // Upload links switched off: their page is not asked for, here as anywhere else.
            const [shares, publicLinks, noteLinks, receivers] = await Promise.all([
                quiet('/shares'), quiet('/public-links'), quiet('/note-links'),
                receiversSwitchedOn().then(on => (on ? quiet('/receivers') : null))]);
            if (gone(who)) return;
            // Each expiry row opens the place its Extend button is: the "Shared by me" tab and the card, the
            // Notes "Shared" tab, the Drop vaults tab, or the vault's "My public links" dialog (openAppTarget in
            // app.js understands the same targets the reminder notices carry).
            list(shares, 'shares').filter(s => s.status === 'active' && soon(s.expires_at) != null)
                .forEach(s => rows.push(row('link', `Share of ${s.target_name || s.vault_name || 'an item'} expires ${inDays(soon(s.expires_at))}`,
                                             s.vault_name || '', () => openAppTarget('#shared/by-me/' + s.id), 'share')));
            list(publicLinks, 'links').filter(l => !l.revoked && l.status !== 'expired' && soon(l.expires_at) != null)
                .forEach(l => rows.push(row('globe', `Public link expires ${inDays(soon(l.expires_at))}`,
                                             l.tag_name || '', () => openAppTarget('#vault/' + l.vault_id + '/public-links/' + l.id), 'public_link')));
            list(noteLinks, 'links').filter(l => !l.revoked && soon(l.expires_at) != null)
                .forEach(l => rows.push(row('file-text', `Note link "${l.title || 'note'}" expires ${inDays(soon(l.expires_at))}`,
                                             '', () => openAppTarget('#notes/shared/' + l.id), 'note_link')));
            const recv = list(receivers, 'receivers');
            // The files still in the drop vault, not every upload ever received: once the owner has moved them
            // out, nothing waits and the row goes. (An older server without the count: the uploads received.)
            const waiting = r => (r.files_in_vault != null ? r.files_in_vault : (r.upload_count || 0));
            recv.filter(r => waiting(r) > 0)
                .forEach(r => rows.push(row('upload', `${waiting(r)} file${waiting(r) === 1 ? '' : 's'} waiting in ${r.label || 'an upload link'}`,
                                             'Open the drop vault', () => openVault(r.vault_id, { from: 'uploadlinks' }), 'receiver_upload')));
            recv.filter(r => soon(r.expires_at) != null)
                .forEach(r => rows.push(row('upload', `Upload link ${r.label || ''} expires ${inDays(soon(r.expires_at))}`.replace(/\s+/g, ' '),
                                             '', () => openAppTarget('#uploadlinks/drops/' + r.id), 'receiver')));
        }
        if (isAdmin()) {
            const [invites, requests] = await Promise.all([
                may('USER_VIEW') ? quiet('/invites') : null, may('USER_MANAGE') ? quiet('/admin/credential-requests') : null]);
            if (gone(who)) return;
            const pending = list(invites, 'invites').filter(i => i.status === 'pending').length;
            if (pending) rows.unshift(row('users', `${pending} invitation${pending === 1 ? '' : 's'} pending`,
                                          'Not accepted yet', () => navigateToSection('users')));
            const held = list(requests, 'requests').length;
            if (held) rows.unshift(row('shield', `${held} credential change${held === 1 ? '' : 's'} await${held === 1 ? 's' : ''} approval`,
                                       'Approve or deny on the Users page', () => navigateToSection('users')));
        }
        box.replaceChildren();
        const listed = rows.slice(0, LANE_LIMIT);
        shown = new Set(listed.map(r => r.getAttribute('data-kind')).filter(Boolean));
        if (!rows.length) box.appendChild(el('p', 'dashboard-lane-empty text-secondary', 'Nothing needs your attention.'));
        else listed.forEach(r => box.appendChild(r));
        // "What's waiting for you" was drawn first; drawn again, it leaves out what this lane now lists.
        if (typeof renderWaitingLane === 'function' && typeof state !== 'undefined') {
            try { renderWaitingLane(state.dashboardShared || []); } catch (_) {}
        }
    }

    // The kinds of thing the lane lists right now, and whether a notice is about one of them: an expiry
    // reminder names its kind by the page it opens, an upload notice by its type.
    let shown = new Set();
    const REMINDER_KIND = { '#shared': 'share', '#vaults': 'public_link', '#vault': 'public_link', '#notes': 'note_link', '#uploadlinks': 'receiver' };
    function listsNotice(n) {
        if (!n) return false;
        if (n.type === 'receiver_upload') return shown.has('receiver_upload');
        if (n.type === 'expiry_reminder') return shown.has(REMINDER_KIND[String(n.target || '').split('/')[0]] || '');
        return false;
    }

    // ---- get started (administrators) -----------------------------------------------------------------------
    // Settings opened on the page an item is about, not on General: the page's button is pressed once the
    // Settings page has wired it.
    function openSettingsPage(tab) {
        navigateToSection('settings');
        let left = 40;
        const tick = () => {
            const b = document.querySelector('#settings-section .tab-btn[data-tab="' + tab + '"]');
            if (b && b.dataset.wired) { if (!b.classList.contains('active')) b.click(); return; }
            if (--left > 0) setTimeout(tick, 100);
        };
        setTimeout(tick, 50);
    }

    const CHECKS = [
        { key: 'email', label: 'Email set up, and a test message sent',
          hint: 'Settings > Email: a sending profile, then "Send a test email".', go: () => openSettingsPage('email') },
        { key: 'public_address', label: 'A public address for emailed links',
          hint: 'ALLOWED_HOSTS in the deployment’s .env names the address people use; emailed links are pinned to it.' },
        { key: 'second_factor', label: 'The second-factor policy decided',
          hint: 'Settings > Security: require a second factor, or keep it optional on purpose.',
          go: () => openSettingsPage('security'), ack: { second_factor_decided: true }, ackLabel: 'Keep it optional' },
        // DockVault keeps no record of backup runs: this is ticked on the administrator's word alone.
        { key: 'backup', label: 'Backups set up',
          hint: 'Back up on the host (dockvault.py backup) and try a restore once. DockVault cannot see backups '
              + 'taken on the host, so this is ticked on your word.',
          ack: { backup_recorded: true }, ackLabel: 'I have set up backups' },
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
        const who = session();
        const view = await quiet('/admin/get-started');
        if (gone(who)) return;
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
            mark.setAttribute('role', 'img');
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

    // What this module drew for the person signed in goes at a sign-out (logout in app.js), so the next person on
    // the tab sees none of it before their own dashboard is drawn.
    function reset() {
        shown = new Set();
        const actions = document.getElementById('dashboard-quick-actions');
        if (actions) { actions.replaceChildren(); actions.hidden = true; }
        const attention = document.getElementById('lane-attention');
        if (attention) attention.replaceChildren();
        const card = document.getElementById('dashboard-get-started');
        if (card) {
            card.hidden = true;
            const list = card.querySelector('.get-started-list');
            if (list) list.replaceChildren();
        }
    }

    window.DashboardActions = { render, reset, soon, inDays, listsNotice };
})();
