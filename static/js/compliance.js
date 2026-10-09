/*
 * Compliance access in the web app.
 *
 * A vault's owner: the banner after sign-in while a notice about access to their vaults is unread (the shared
 * notice banner), and "Access to my vaults" (GET /me/compliance-access), opened from it, from the notification
 * and from the account menu. A vault's members: the neutral banner of a vault under an authorised review.
 *
 * The step-ups no switch of the step-up matrix changes (GET /second-factor/actions, "fixed"): listed read-only
 * below the matrix in Settings -> Security, each with what it always asks for. The compliance steps (proposing
 * or approving an auditor grant, requesting, approving or exporting from a case, placing or releasing a legal
 * hold) always ask for the password and an authenticator or recovery code.
 *
 * Builds the page with createElement and textContent only.
 */
(function () {
    'use strict';

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function renderFixedStepUps(fixed) {
        const table = document.getElementById('mfa-actions-table');
        if (!table) return;
        let box = document.getElementById('mfa-fixed-table');
        if (!box) {
            box = el('div');
            box.id = 'mfa-fixed-table';
            table.insertAdjacentElement('afterend', box);
        }
        box.replaceChildren();
        if (!Array.isArray(fixed) || !fixed.length) return;
        box.appendChild(el('p', 'text-tertiary text-sm mt-md mb-xs',
            'Always required: these steps ask for the same thing every time, whatever the switches above say.'));
        fixed.forEach((a) => {
            const row = el('div', 'flex gap-sm items-center mfa-fixed-row');
            row.dataset.fixedKey = a.key || '';
            row.style.padding = '6px 0';
            row.style.borderTop = '1px solid var(--border, #e5e7eb)';
            row.style.flexWrap = 'wrap';
            const name = el('div', 'text-sm', a.name || a.key || '');
            name.style.flex = '1 1 200px';
            const requires = el('div', 'text-sm text-secondary mfa-fixed-requires', a.requires || '');
            requires.style.flex = '1 1 260px';
            row.appendChild(name);
            row.appendChild(requires);
            box.appendChild(row);
        });
    }

    window.renderFixedStepUps = renderFixedStepUps;

    function sizeText(bytes) {
        if (typeof window.formatBytes === 'function') return window.formatBytes(bytes || 0);
        return String(bytes || 0) + ' B';
    }

    // Settings -> Storage: what legal holds keep after their deletion (GET /storage/stats, kept_for_cases). Those
    // bytes are on the disk but in no vault's size, so the line says so beside the totals.
    function renderKeptForCases(stats) {
        const anchor = document.getElementById('storage-stat-allocated');
        if (!anchor) return;
        let line = document.getElementById('storage-stat-kept');
        const kept = (stats && stats.kept_for_cases) || null;
        if (!kept || !(kept.files || kept.folders)) {
            if (line) line.remove();
            return;
        }
        if (!line) {
            line = el('small', 'text-secondary');
            line.id = 'storage-stat-kept';
            line.style.display = 'block';
            anchor.insertAdjacentElement('afterend', line);
        }
        line.textContent = 'Kept for cases: ' + kept.files + (kept.files === 1 ? ' file, ' : ' files, ')
            + sizeText(kept.bytes) + ' (deleted under a legal hold; on this disk, in no vault\'s size)';
    }

    window.renderKeptForCases = renderKeptForCases;

    // ---- a vault's owner: the banner after sign-in and "Access to my vaults" ---------------------------------
    // GET /me/compliance-access lists the cases that told the signed-in user about one of their vaults, and the
    // notices not read yet. While one is unread, the shared notice banner (static/js/notice-banner.js) says so and
    // opens the page; "I've read it" posts /me/compliance-access/seen. The page names the owner's own vaults from
    // the list the app already holds, and a file's name only as the owner could read it in the vault: a
    // password-protected vault's after its password is given here (a 15-minute receipt, kept in memory only).

    const ACCESS_BANNER = 'compliance-access';
    const receipts = new Map();          // vault id -> receipt, for this page's session only

    const PURPOSES = {
        internal_investigation: 'Internal investigation', litigation_hold: 'Litigation or legal hold',
        regulator_request: 'Regulator or authority request', data_subject_request: 'Data-subject request',
        security_incident: 'Security incident', other: 'Other',
    };
    const BASES = { legal_obligation: 'Legal obligation', public_task: 'Public task',
        legitimate_interests: 'Legitimate interests' };
    const STATUSES = { active: 'Active', suspended: 'Suspended', hold_only: 'Legal hold only', closed: 'Closed',
        pending: 'Waiting for approval', rejected: 'Turned down', withdrawn: 'Withdrawn',
        expired_unapproved: 'Expired before approval' };

    function call(path, options) {
        if (typeof apiRequest === 'function') return apiRequest(path, Object.assign({ silent: true }, options || {}));
        return Promise.reject(new Error('not signed in'));
    }

    function when(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        return isNaN(d.getTime()) ? iso : d.toLocaleString(undefined, { dateStyle: 'medium', timeStyle: 'short' });
    }

    function unlockHeader() {
        const parts = [];
        receipts.forEach((receipt, vid) => parts.push(vid + '=' + receipt));
        return parts.length ? { 'X-Owner-Unlock': parts.join(',') } : {};
    }

    function vaultName(id) {
        try {
            const all = (typeof state !== 'undefined' && state && state.allVaults) || [];
            const v = all.find((x) => String(x.id) === String(id));
            if (v && typeof vaultDisplayName === 'function') return vaultDisplayName(v);
        } catch (_) { /* the id is shown instead */ }
        return 'Vault ' + String(id).slice(0, 8);
    }

    async function checkAccessBanner() {
        const nb = window.NoticeBanner;
        if (!nb) return;
        let page;
        try { page = await call('/me/compliance-access'); } catch (_) { return; }
        const unseen = (page && page.unseen) || [];
        if (!unseen.length) { nb.hide(ACCESS_BANNER); return; }
        const newest = unseen[0].at;
        nb.show({
            id: ACCESS_BANNER,
            text: unseen.length === 1
                ? 'There is news about access to your vaults (an investigation, a legal hold, or a recorded name revealed).'
                : 'There are ' + unseen.length + ' notices about access to your vaults (investigations, legal holds, or recorded names revealed).',
            linkText: 'Access to my vaults', onOpen: () => openMyAccess(),
            onRead: () => call('/me/compliance-access/seen', { method: 'POST', body: JSON.stringify({ through: newest }) }),
        });
    }

    // Laid out to wrap: a label above its value on a phone, beside it on a wider screen.
    function row(label, value) {
        const line = el('div', 'my-access-row');
        line.style.display = 'flex';
        line.style.flexWrap = 'wrap';
        line.style.gap = '0 12px';
        line.style.padding = '2px 0';
        const name = el('span', 'my-access-label text-tertiary', label);
        name.style.flex = '0 0 140px';
        const text = el('span', 'my-access-value', value);
        text.style.flex = '1 1 200px';
        text.style.overflowWrap = 'anywhere';
        line.appendChild(name);
        line.appendChild(text);
        return line;
    }

    async function unlock(vaultId) {
        if (typeof showPrompt !== 'function') return;
        const password = await showPrompt('Give this vault\'s password to see the names of the files opened in it.',
            'Unlock ' + vaultName(vaultId), { password: true, placeholder: 'Vault password' });
        if (!password) return;
        try {
            const out = await call('/me/compliance-access/vaults/' + encodeURIComponent(vaultId) + '/unlock',
                { method: 'POST', body: JSON.stringify({ password: password }) });
            if (out && out.receipt) receipts.set(String(vaultId), out.receipt);
        } catch (e) {
            if (typeof showError === 'function') showError((e && e.message) || 'The vault was not unlocked.');
        }
        await renderMyAccess();
    }

    function caseCard(c) {
        const card = el('div', 'card my-access-case');
        card.dataset.caseId = c.id;
        card.style.padding = '12px';
        card.style.margin = '12px 0';
        const head = el('div', 'my-access-head');
        head.appendChild(el('strong', null, 'Case ' + (c.number || '')));
        head.appendChild(el('span', 'badge my-access-status', STATUSES[c.status] || c.status));
        card.appendChild(head);
        card.appendChild(row('Purpose', PURPOSES[c.purpose] || c.purpose || ''));
        card.appendChild(row('Legal basis', BASES[c.legal_basis] || c.legal_basis || ''));
        if (c.hold_only) {
            card.appendChild(row('Placed by', c.placed_by || ''));
        } else {
            card.appendChild(row('Auditor', c.auditor || ''));
            card.appendChild(row('Approved by', (c.approved_by || '') + (c.approved_at ? ', ' + when(c.approved_at) : '')));
            if (c.access_ends_at) card.appendChild(row('Access until', when(c.access_ends_at)));
            card.appendChild(row('Exports', String(c.exports || 0) + (c.can_export ? '' : ' (not allowed)')));
        }
        if (c.closed_at) card.appendChild(row('Closed', when(c.closed_at)));
        if (c.note) {
            const note = el('blockquote', 'my-access-note');
            note.appendChild(el('div', 'text-tertiary text-sm', 'Note to you'));
            note.appendChild(el('div', null, c.note));
            card.appendChild(note);
        }
        const vaults = el('div', 'my-access-vaults');
        vaults.appendChild(el('div', 'text-tertiary text-sm', 'Your vaults in it'));
        (c.vaults || []).forEach((v) => {
            const line = el('div', 'my-access-vault');
            line.dataset.vaultId = v.vault_id;
            const covers = v.covers === 'whole' ? 'the whole vault' : (v.covers === 'folders' ? 'some folders'
                : 'no longer covered');
            line.appendChild(el('span', null, vaultName(v.vault_id) + ': ' + covers
                + (v.type === 'zero_knowledge' ? ' (zero-knowledge: its contents and names cannot be opened)' : '')
                + (v.hold ? '; a legal hold keeps what is deleted' : '')
                + (v.kept_files ? '; ' + v.kept_files + (v.kept_files === 1 ? ' file kept' : ' files kept') : '')));
            vaults.appendChild(line);
        });
        card.appendChild(vaults);
        const opened = el('div', 'my-access-opened');
        opened.appendChild(el('div', 'text-tertiary text-sm', 'Files opened'));
        if (!(c.opened || []).length) {
            opened.appendChild(el('div', 'text-sm', c.hold_only ? 'A legal hold opens nothing.' : 'None so far.'));
        }
        const askedUnlock = new Set();
        (c.opened || []).forEach((f) => {
            const line = el('div', 'my-access-file text-sm');
            let name = f.name;
            if (!name) {
                name = f.name_hidden === 'zero_knowledge' ? '(zero-knowledge: the name cannot be shown)'
                    : f.name_hidden === 'password' ? '(name hidden until the vault is unlocked)'
                    : f.name_hidden === 'not_owner' ? '(the vault is no longer yours)' : '(no longer there)';
            }
            line.appendChild(el('span', 'my-access-when', when(f.at)));
            line.appendChild(el('span', null, ' ' + vaultName(f.vault_id) + ': ' + name));
            opened.appendChild(line);
            if (f.name_hidden === 'password' && !askedUnlock.has(f.vault_id)) {
                askedUnlock.add(f.vault_id);
                const btn = el('button', 'btn btn-secondary btn-sm my-access-unlock', 'Unlock ' + vaultName(f.vault_id));
                btn.type = 'button';
                btn.addEventListener('click', () => unlock(f.vault_id));
                opened.appendChild(btn);
            }
        });
        card.appendChild(opened);
        return card;
    }

    function dialog() {
        let modal = document.getElementById('my-access-modal');
        if (modal) return modal;
        modal = el('div', 'modal');
        modal.id = 'my-access-modal';
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', 'my-access-title');
        const content = el('div', 'modal-content modal-lg my-access');
        const header = el('div', 'modal-header');
        const title = el('h3', null, 'Access to my vaults');
        title.id = 'my-access-title';
        header.appendChild(title);
        const close = el('button', 'modal-close', '×');
        close.type = 'button';
        close.setAttribute('aria-label', 'Close');
        close.addEventListener('click', () => modal.classList.remove('active'));
        header.appendChild(close);
        content.appendChild(header);
        const body = el('div', 'modal-body');
        body.id = 'my-access-body';
        content.appendChild(body);
        modal.appendChild(content);
        modal.addEventListener('click', (e) => { if (e.target === modal) modal.classList.remove('active'); });
        document.body.appendChild(modal);
        return modal;
    }

    async function renderMyAccess() {
        const body = document.getElementById('my-access-body');
        if (!body) return;
        let page;
        try {
            page = await call('/me/compliance-access', { headers: unlockHeader() });
        } catch (e) {
            body.replaceChildren(el('p', 'text-secondary', 'This page could not be loaded.'));
            return;
        }
        const out = [el('p', 'text-secondary text-sm',
            'Investigations and legal holds that concern vaults you own. Every file opened under a case is listed here '
            + 'as it happens.')];
        const list = (page && page.cases) || [];
        if (!list.length) out.push(el('p', 'my-access-empty', 'No investigation or legal hold concerns your vaults.'));
        list.forEach((c) => out.push(caseCard(c)));
        body.replaceChildren(...out);
    }

    async function openMyAccess() {
        dialog().classList.add('active');
        await renderMyAccess();
    }

    window.openMyAccess = openMyAccess;

    // ---- a vault's members: the neutral banner while an authorised review covers it -------------------------
    function renderVaultReview(vault) {
        const title = document.getElementById('vault-view-title');
        let banner = document.getElementById('vault-review-banner');
        const review = vault && vault.compliance_review;
        if (!review || !title) {
            if (banner) banner.remove();
            return;
        }
        if (!banner) {
            banner = el('div', 'notice-banner vault-review-banner');
            banner.id = 'vault-review-banner';
            banner.setAttribute('role', 'status');
            const header = title.parentElement;
            header.insertAdjacentElement('afterend', banner);
        }
        let text = 'This vault is part of an authorised review until ' + when(review.until) + '.';
        if (review.hold) text += ' Files deleted here are kept until it ends.';
        banner.replaceChildren(el('span', 'notice-banner-text', text));
    }

    window.renderVaultReview = renderVaultReview;

    function watchSignIn() {
        const screen = document.getElementById('dashboard-screen');
        if (!screen) return;
        let active = screen.classList.contains('active');
        if (active) checkAccessBanner();
        new MutationObserver(() => {
            const now = screen.classList.contains('active');
            if (now && !active) checkAccessBanner();
            if (!now && window.NoticeBanner) window.NoticeBanner.hide(ACCESS_BANNER);
            active = now;
        }).observe(screen, { attributes: true, attributeFilter: ['class'] });
    }

    function wire() {
        watchSignIn();
        window.addEventListener('dockvault:compliance-access', checkAccessBanner);
        const btn = document.getElementById('my-access-btn');
        if (btn) btn.addEventListener('click', () => openMyAccess());
        try {
            if (typeof _NOTIF_TARGET_OPEN === 'object' && _NOTIF_TARGET_OPEN) {
                _NOTIF_TARGET_OPEN['#my-access'] = () => openMyAccess();
            }
        } catch (_) { /* the bell then only marks it read */ }
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
    else wire();
})();
