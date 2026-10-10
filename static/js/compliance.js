/*
 * Compliance access in the web app.
 *
 * The Compliance page (the sidebar's "Compliance", for administrators and holders of the auditor right): cases in one
 * dense table with chips as filters; a case's page (what it asks in plain words, where the auditor's account came
 * from, the justification, its vaults and holds, and the steps the viewer may take: approve, turn down, extend,
 * narrow, close, withdraw); the new-case sheet with a live preview of the owners' notice; legal holds; the auditor
 * right (propose, review with the account's provenance, approve, turn down, revoke; the holder's own page, with
 * reconfirming). A case's workspace for its auditor: the scope tree, the file table, the open file with a watermark,
 * up and down (or j and k) through the files, a password prompt on a password vault, search, export through the
 * app's download sink, the case log; on a phone one screen at a time. The auditor's badge beside the account menu,
 * and a count of what waits for an administrator's approval on the sidebar. The Activity page uses this module for
 * the auditor's Case chip, Reveal and "Add to a new case" (static/js/activity.js).
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
        out.push(revealsCard((page && page.reveals) || [], Boolean(page && page.reveals_more)));
        body.replaceChildren(...out);
    }

    // Names an auditor revealed from the activity log's events on the owner's vaults, outside any case: when, by
    // whom, why (the category); never the reason's text or the names themselves.
    function revealsCard(reveals, more) {
        const card = el('div', 'card my-access-reveals');
        card.style.padding = '12px';
        card.style.margin = '12px 0';
        card.appendChild(el('strong', null, 'Recorded names revealed'));
        card.appendChild(el('p', 'text-tertiary text-sm',
            'An auditor can reveal a name the activity log recorded in full about one of your vaults, outside a case, '
            + 'giving a reason. Each time is listed here, newest first.'));
        if (!reveals.length) {
            card.appendChild(el('div', 'text-sm my-access-reveals-empty', 'None so far.'));
            return card;
        }
        reveals.forEach((r) => {
            const line = el('div', 'my-access-reveal text-sm');
            line.dataset.vaultId = r.vault_id;
            line.appendChild(el('span', 'my-access-when', when(r.at)));
            line.appendChild(el('span', null, ' ' + vaultName(r.vault_id) + ': by ' + (r.auditor || '')
                + ', reason: ' + (REVEAL_REASONS[r.reason_category] || r.reason_category || '')));
            card.appendChild(line);
        });
        if (more) card.appendChild(el('div', 'text-tertiary text-sm', 'Older ones are kept in the record, not listed here.'));
        return card;
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

    // ---- a vault's owner: a notice that someone else gave a person access to one of their vaults ------------
    // Its target is the vault ("#vault/<id>") when it is about one vault: the bell opens it, where the owner sees
    // who has access. A notice about several vaults has no target (it says how many).
    function openNotifTarget(target) {
        const m = /^#vault\/([0-9a-fA-F-]{36})$/.exec(String(target || ''));
        if (m && typeof openVault === 'function') openVault(m[1]);
    }

    window.openNotifTarget = openNotifTarget;

    // =========================================================================================================
    // The Compliance page: cases, legal holds, the auditor right, and a case's workspace. For administrators and
    // auditors (the sidebar's "Compliance"). Every step that changes something asks the server, which decides; the
    // step-up the compliance steps always ask for (the password and an authenticator or recovery code) is the app's
    // own dialog, opened when the server asks for it (requestStepUpReceipt in app.js).
    // =========================================================================================================

    const GRANT_STATUSES = {
        proposed: 'Waiting for approval', active: 'In force', suspended: 'Suspended', expired: 'Expired',
        revoked: 'Revoked', rejected: 'Turned down', lapsed: 'Lapsed', ended: 'Ended',
    };
    const ART9 = {
        employment: '(b) employment and social security', vital_interests: '(c) vital interests',
        not_for_profit: '(d) a not-for-profit body', made_public: '(e) made public by the person',
        legal_claims: '(f) legal claims', substantial_public_interest: '(g) substantial public interest',
        health_care: '(h) health or social care', public_health: '(i) public health',
        archiving_research: '(j) archiving, research or statistics',
    };
    const FILE_STATUS = { live: 'Live', expired: 'Expired', deleted_kept: 'Deleted, kept', expired_kept: 'Expired, kept' };
    const REVEAL_REASONS = {
        security_incident: 'Security incident', internal_investigation: 'Internal investigation',
        regulator_request: 'Regulator or authority request', data_subject_request: 'Data-subject request',
        litigation_hold: 'Litigation', other: 'Other',
    };
    const BADGE = {
        active: 'badge-success', pending: 'badge-warning', suspended: 'badge-warning', hold_only: 'badge-info',
        closed: 'badge-secondary', rejected: 'badge-secondary', withdrawn: 'badge-secondary',
        expired_unapproved: 'badge-secondary', proposed: 'badge-warning', expired: 'badge-secondary',
        revoked: 'badge-secondary', lapsed: 'badge-secondary', ended: 'badge-secondary',
    };

    const CP = {
        admin: false, me: null, live: false, shownActivity: false,
        tab: 'cases', filter: 'all', screen: 'list',
        cases: null, accessEnabled: true, holds: null, grants: null, grantInfo: null,
        caseId: null, seq: 0,
    };
    // Receipts of password vaults unlocked in a case: case id -> vault id -> {receipt, expires}. In memory only, for
    // this page; sent back in X-Case-Unlock by the workspace and by the Activity page with that case selected.
    const CASE_RECEIPTS = new Map();

    // ---- talking to the server ---------------------------------------------------------------------------------

    function problemText(detail, status) {
        if (typeof detail === 'string' && detail) return detail;
        if (Array.isArray(detail)) return detail.map((d) => (d && d.msg) || '').filter(Boolean).join('; ') || 'Not accepted.';
        if (detail && typeof detail === 'object') {
            if (Array.isArray(detail.reasons) && detail.reasons.length) {
                return detail.reasons.map((r) => r.text || r.reason).filter(Boolean).join(' ');
            }
            if (detail.text) return String(detail.text);
            if (detail.reason) return String(detail.reason).replace(/_/g, ' ');
        }
        return 'The server answered ' + status + '.';
    }

    function problem(status, reason, text) {
        const err = new Error(text);
        err.status = status;
        err.reason = reason;
        return err;
    }

    // A call to the server: JSON in and out (``json``), or the Response itself (``raw``). A step the server guards
    // with the step-up comes back as its 403 (second_factor_required): the app's dialog asks for the password and the
    // code, and the call is made once more with the receipt. Every other refusal is thrown with its status, reason and
    // the server's own words.
    async function cmp(path, opts) {
        opts = opts || {};
        const headers = Object.assign({}, opts.headers || {});
        if (opts.json !== undefined) headers['Content-Type'] = 'application/json';
        if (typeof authToken !== 'undefined' && authToken) headers.Authorization = 'Bearer ' + authToken;
        const init = { method: opts.method || (opts.json !== undefined ? 'POST' : 'GET'), headers };
        if (opts.json !== undefined) init.body = JSON.stringify(opts.json);
        if (opts.signal) init.signal = opts.signal;
        const resp = await fetch(API_BASE + path, init);
        if (resp.ok && opts.raw) return resp;
        let data = null;
        try { data = await resp.json(); } catch (_) { data = null; }
        if (resp.ok) return data;
        const detail = data ? data.detail : null;
        if (resp.status === 401) {
            try { if (typeof apiRequest === 'function') await apiRequest('/auth/session', { silent: true }); } catch (_) { /* signs out */ }
            throw problem(401, 'signed_out', 'Your session has ended.');
        }
        if (resp.status === 403 && detail && typeof detail === 'object' && detail.second_factor_required) {
            if (detail.reason === 'enroll_required') {
                throw problem(403, 'enroll_required', 'This step needs an authenticator app on your account: set one up in Your account first.');
            }
            if (!opts._retried && typeof requestStepUpReceipt === 'function') {
                const receipt = await requestStepUpReceipt(detail.action, detail.methods || []);
                if (receipt) {
                    return cmp(path, Object.assign({}, opts, {
                        _retried: true, headers: Object.assign({}, opts.headers || {}, { 'X-Second-Factor': receipt }),
                    }));
                }
            }
            throw problem(403, 'step_up', 'Not done: this step needs your password and a code.');
        }
        throw problem(resp.status, detail && typeof detail === 'object' ? (detail.reason || null) : null,
            problemText(detail, resp.status));
    }

    function caseUnlockHeader(caseId) {
        const map = CASE_RECEIPTS.get(String(caseId));
        if (!map) return {};
        const now = Date.now();
        const parts = [];
        map.forEach((r, vid) => { if (r.expires > now) parts.push(vid + '=' + r.receipt); else map.delete(vid); });
        return parts.length ? { 'X-Case-Unlock': parts.join(',') } : {};
    }

    async function unlockCaseVault(caseId, vaultId, password) {
        const out = await cmp('/compliance/cases/' + encodeURIComponent(caseId) + '/vaults/' + encodeURIComponent(vaultId) + '/unlock',
            { json: { password } });
        if (!CASE_RECEIPTS.has(String(caseId))) CASE_RECEIPTS.set(String(caseId), new Map());
        CASE_RECEIPTS.get(String(caseId)).set(String(vaultId), {
            receipt: out.receipt, expires: Date.parse(out.expires_at) || (Date.now() + 15 * 60000),
        });
        return out;
    }

    window.complianceCaseUnlockHeader = caseUnlockHeader;
    window.complianceUnlockCaseVault = unlockCaseVault;

    // ---- small words -------------------------------------------------------------------------------------------

    function icon(name) {
        const ns = 'http://www.w3.org/2000/svg';
        const svg = document.createElementNS(ns, 'svg');
        svg.setAttribute('class', 'icon icon-sm');
        svg.setAttribute('aria-hidden', 'true');
        const use = document.createElementNS(ns, 'use');
        use.setAttribute('href', '#i-' + name);
        svg.appendChild(use);
        return svg;
    }

    function plural(n, one, many) { return n + ' ' + (n === 1 ? one : (many || one + 's')); }

    function day(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        return isNaN(d.getTime()) ? iso : d.toLocaleDateString(undefined, { dateStyle: 'medium' });
    }

    function untilText(iso) {
        if (!iso) return '';
        const ms = new Date(iso).getTime() - Date.now();
        if (isNaN(ms)) return '';
        if (ms <= 0) return 'ended';
        const minutes = Math.floor(ms / 60000);
        const d = Math.floor(minutes / 1440), h = Math.floor((minutes % 1440) / 60), m = minutes % 60;
        if (d) return 'ends in ' + d + ' d ' + h + ' h';
        if (h) return 'ends in ' + h + ' h ' + m + ' min';
        return 'ends in ' + m + ' min';
    }

    function badge(status, text) {
        const b = el('span', 'badge ' + (BADGE[status] || 'badge-secondary') + ' cmp-status', text || STATUSES[status] || GRANT_STATUSES[status] || status || '');
        b.dataset.status = status || '';
        return b;
    }

    function button(text, cls, onClick, attrs) {
        const b = el('button', 'btn ' + (cls || 'btn-secondary') + ' btn-sm', text);
        b.type = 'button';
        Object.entries(attrs || {}).forEach(([k, v]) => b.setAttribute(k, v));
        if (onClick) b.addEventListener('click', onClick);
        return b;
    }

    function fail(err, where) {
        const text = (err && err.message) || 'That did not work.';
        if (where) {
            where.replaceChildren(el('div', 'alert alert-error', text));
            where.hidden = false;
        } else if (typeof showError === 'function') {
            showError(text);
        }
    }

    function ok(text) { if (typeof showSuccess === 'function') showSuccess(text); }

    function table(heads, cls) {
        const t = el('table', 'data-table cmp-table' + (cls ? ' ' + cls : ''));
        const head = el('thead');
        const tr = el('tr');
        heads.forEach((h) => { const th = el('th', null, h); th.scope = 'col'; tr.appendChild(th); });
        head.appendChild(tr);
        t.appendChild(head);
        const body = el('tbody');
        t.appendChild(body);
        return { table: t, body };
    }

    function cell(row, label, value) {
        const td = el('td');
        td.dataset.label = label;
        if (value instanceof Node) td.appendChild(value);
        else td.textContent = value == null ? '' : String(value);
        row.appendChild(td);
        return td;
    }

    function lines(pairs, cls) {
        const dl = el('dl', 'cmp-facts' + (cls ? ' ' + cls : ''));
        pairs.forEach(([k, v]) => {
            if (v == null || v === '') return;
            dl.appendChild(el('dt', null, k));
            const dd = el('dd');
            if (v instanceof Node) dd.appendChild(v); else dd.textContent = String(v);
            dl.appendChild(dd);
        });
        return dl;
    }

    // A dialog of its own (full screen on a phone): {modal, body, foot, close}.
    function sheet(id, title, opts) {
        let modal = document.getElementById(id);
        if (modal) modal.remove();
        modal = el('div', 'modal cmp-sheet' + ((opts && opts.wide) ? ' cmp-sheet-wide' : ''));
        modal.id = id;
        modal.setAttribute('role', 'dialog');
        modal.setAttribute('aria-modal', 'true');
        modal.setAttribute('aria-labelledby', id + '-title');
        const content = el('div', 'modal-content cmp-sheet-content');
        const header = el('div', 'modal-header');
        const h = el('h3', null, title);
        h.id = id + '-title';
        const x = el('button', 'modal-close', '×');
        x.type = 'button';
        x.setAttribute('aria-label', 'Close');
        header.append(h, x);
        const body = el('div', 'modal-body cmp-sheet-body');
        const foot = el('div', 'modal-footer cmp-sheet-foot');
        content.append(header, body, foot);
        modal.appendChild(content);
        const close = () => { modal.classList.remove('active'); setTimeout(() => modal.remove(), 0); };
        x.addEventListener('click', close);
        modal.addEventListener('click', (e) => { if (e.target === modal) close(); });
        document.body.appendChild(modal);
        modal.classList.add('active');
        return { modal, body, foot, close };
    }

    function field(labelText, control, hint) {
        const g = el('div', 'form-group cmp-field');
        const id = control.id || ('cmp-f-' + Math.random().toString(36).slice(2, 9));
        control.id = id;
        const lab = el('label', 'form-label', labelText);
        lab.htmlFor = id;
        g.append(lab, control);
        if (hint) g.appendChild(el('small', 'text-tertiary cmp-hint', hint));
        return g;
    }

    function input(type, attrs) {
        const i = el(type === 'textarea' ? 'textarea' : 'input', 'form-control');
        if (type !== 'textarea') i.type = type;
        Object.entries(attrs || {}).forEach(([k, v]) => { if (v != null) i.setAttribute(k, v); });
        return i;
    }

    function select(options, value) {
        const s = el('select', 'form-control');
        Object.entries(options).forEach(([k, v]) => {
            const o = el('option', null, v);
            o.value = k;
            if (k === value) o.selected = true;
            s.appendChild(o);
        });
        return s;
    }

    function check(labelText, checked) {
        const lab = el('label', 'checkbox-label cmp-check');
        const box = el('input');
        box.type = 'checkbox';
        box.checked = !!checked;
        lab.append(box, el('span', null, ' ' + labelText));
        return { label: lab, box };
    }

    // ---- who is signed in: the nav item, the auditor's badge, the count for administrators -------------------------

    function signedInUser() {
        const user = typeof currentUser !== 'undefined' ? currentUser : null;
        const temp = (typeof isScopedTemp !== 'undefined' && isScopedTemp)
            || (typeof sessionAccess !== 'undefined' && sessionAccess && sessionAccess.is_temp_session);
        return user && !temp ? user : null;
    }

    async function refreshStanding() {
        const user = signedInUser();
        CP.admin = !!(user && user.role === 'admin');
        let me = null;
        if (user) {
            try { me = await cmp('/compliance/me'); } catch (_) { me = null; }
        }
        CP.me = me && me.grant ? me.grant : null;
        CP.live = !!(CP.me && CP.me.live);
        // The Activity page lets an auditor whose right is in force read the log (app/api/activity_viewer.py).
        window.complianceAuditorLive = CP.live && !CP.admin;
        const nav = document.getElementById('nav-compliance');
        const holds = CP.me && ['active', 'suspended'].includes(CP.me.status);
        if (nav) nav.style.display = (user && (CP.admin || holds)) ? 'flex' : 'none';
        const activityNav = document.querySelector('.sidebar-item[data-section="activity"]');
        if (activityNav && window.complianceAuditorLive) { activityNav.style.display = 'flex'; CP.shownActivity = true; }
        renderAuditorBadge();
        if (typeof reconcileNavGroupLabels === 'function') { try { reconcileNavGroupLabels(); } catch (_) { /* nav groups are cosmetic */ } }
        if (CP.admin) refreshCount();
        else setCount(0);
    }

    function forgetStanding() {
        CP.admin = false; CP.me = null; CP.live = false;
        CP.cases = CP.holds = CP.grants = null; CP.screen = 'list'; CP.caseId = null;
        window.complianceAuditorLive = false;
        CASE_RECEIPTS.clear();
        const nav = document.getElementById('nav-compliance');
        if (nav) nav.style.display = 'none';
        if (CP.shownActivity) {
            const activityNav = document.querySelector('.sidebar-item[data-section="activity"]');
            if (activityNav) activityNav.style.display = 'none';
            CP.shownActivity = false;
        }
        renderAuditorBadge();
        setCount(0);
        stopWorkspace();
    }

    // The auditor's badge: beside the account menu, and, where the top bar is too narrow for it (a phone), in the
    // account menu's header under the role.
    function renderAuditorBadge() {
        let b = document.getElementById('auditor-badge');
        let inMenu = document.getElementById('auditor-badge-menu');
        if (!CP.me || !['active', 'suspended'].includes(CP.me.status)) {
            if (b) b.remove();
            if (inMenu) inMenu.remove();
            return;
        }
        const role = document.getElementById('profile-role');
        if (!inMenu && role && role.parentElement) {
            inMenu = el('div', 'auditor-badge-menu');
            inMenu.id = 'auditor-badge-menu';
            role.insertAdjacentElement('afterend', inMenu);
        }
        if (inMenu) inMenu.textContent = CP.live ? 'Auditor' : 'Auditor (suspended)';
        if (!b) {
            const menu = document.querySelector('.profile-menu');
            if (!menu || !menu.parentElement) return;
            b = el('button', 'badge auditor-badge');
            b.id = 'auditor-badge';
            b.type = 'button';
            b.addEventListener('click', () => { if (typeof navigateToSection === 'function') navigateToSection('compliance'); });
            menu.parentElement.insertBefore(b, menu);
        }
        b.className = 'badge auditor-badge ' + (CP.live ? 'badge-info' : 'badge-warning');
        b.textContent = CP.live ? 'Auditor' : 'Auditor · suspended';
        b.title = CP.live ? ('You hold the auditor right until ' + day(CP.me.expires_at) + '.')
            : ('Your auditor right is suspended: ' + (CP.me.reason_text || CP.me.suspend_reason || '') + '.');
    }

    function setCount(n) {
        const c = document.getElementById('nav-compliance-count');
        if (!c) return;
        c.textContent = n ? String(n) : '';
        c.hidden = !n;
        c.title = n ? plural(n, 'step waits', 'steps wait') + ' for your approval' : '';
    }

    async function refreshCount() {
        let n = 0;
        try {
            const [cases, grants] = await Promise.all([cmp('/compliance/cases'), cmp('/compliance/auditors')]);
            n += ((cases && cases.cases) || []).filter((c) => c.you_may_approve).length;
            n += ((grants && grants.grants) || []).filter((g) => g.status === 'proposed' && g.you_may_approve).length;
        } catch (_) { /* the count is a hint */ }
        setCount(n);
    }

    // ---- the page ------------------------------------------------------------------------------------------------

    function root() { return document.getElementById('cmp-root'); }

    async function initCompliance() {
        const r = root();
        if (!r) return;
        if (!signedInUser()) { r.replaceChildren(el('p', 'text-secondary', 'Sign in with your own account to see this page.')); return; }
        // Read again each time the page opens: a right approved, suspended or ended since shows at once. The page
        // opens on its list, whatever was open before.
        await refreshStanding();
        CP.caseId = null;
        renderShell();
    }

    window.initCompliance = initCompliance;

    function tabsFor() {
        const tabs = [['cases', 'Cases'], ['holds', 'Legal holds']];
        if (CP.admin) tabs.push(['auditors', 'Auditors']);
        if (CP.me) tabs.push(['me', 'My auditor right']);
        return tabs;
    }

    function renderShell() {
        stopWorkspace();
        CP.screen = 'list';
        const r = root();
        const head = el('div', 'cmp-head');
        head.appendChild(el('h2', 'cmp-title', 'Compliance'));
        head.appendChild(el('p', 'text-secondary text-sm cmp-sub',
            'Investigations of other people\'s vaults, legal holds and the auditor right. Every step is recorded, and owners are told.'));
        const tabs = el('div', 'tabs cmp-tabs');
        tabs.setAttribute('role', 'tablist');
        if (!tabsFor().some(([k]) => k === CP.tab)) CP.tab = 'cases';
        tabsFor().forEach(([key, text]) => {
            const b = el('button', 'tab-btn' + (CP.tab === key ? ' active' : ''), text);
            b.type = 'button';
            b.dataset.cmpTab = key;
            b.setAttribute('role', 'tab');
            b.setAttribute('aria-selected', CP.tab === key ? 'true' : 'false');
            b.addEventListener('click', () => { CP.tab = key; renderShell(); });
            tabs.appendChild(b);
        });
        const body = el('div', 'cmp-body');
        body.id = 'cmp-body';
        r.replaceChildren(head, tabs, body);
        if (CP.tab === 'cases') renderCasesTab(body);
        else if (CP.tab === 'holds') renderHoldsTab(body);
        else if (CP.tab === 'auditors') renderAuditorsTab(body);
        else renderMyRight(body);
    }

    function offNotice(enabled) {
        return enabled === false ? el('div', 'alert alert-warning cmp-off',
            'Compliance access is turned off on this server: no case gives access, and no new one can be asked for or approved.') : null;
    }

    // ---- cases ---------------------------------------------------------------------------------------------------

    const FILTERS = [['all', 'All'], ['mine', 'Waiting for my approval'], ['active', 'Active'], ['hold_only', 'Hold only'], ['closed', 'Closed']];
    const CLOSED = new Set(['closed', 'rejected', 'withdrawn', 'expired_unapproved']);

    function matches(c, f) {
        const s = c.effective_status || c.status;
        if (f === 'mine') return !!c.you_may_approve;
        if (f === 'active') return s === 'active' || s === 'suspended';
        if (f === 'hold_only') return s === 'hold_only';
        if (f === 'closed') return CLOSED.has(s);
        return true;
    }

    async function renderCasesTab(body) {
        const seq = ++CP.seq;
        body.replaceChildren(el('p', 'text-secondary', 'Loading cases…'));
        let data;
        try { data = await cmp('/compliance/cases'); } catch (e) { if (seq === CP.seq) fail(e, body); return; }
        if (seq !== CP.seq) return;
        CP.cases = data.cases || [];
        CP.accessEnabled = data.access_enabled;
        drawCases(body);
    }

    function drawCases(body) {
        const out = [];
        const off = offNotice(CP.accessEnabled);
        if (off) out.push(off);
        const bar = el('div', 'cmp-toolbar');
        const chips = el('div', 'seg-filter cmp-chips');
        chips.setAttribute('role', 'radiogroup');
        chips.setAttribute('aria-label', 'Show');
        FILTERS.filter(([k]) => k !== 'mine' || CP.admin).forEach(([key, text]) => {
            const n = CP.cases.filter((c) => matches(c, key)).length;
            const b = el('button', 'seg-btn cmp-chip' + (CP.filter === key ? ' active' : ''), text + (key === 'all' ? '' : ' (' + n + ')'));
            b.type = 'button';
            b.dataset.filter = key;
            b.setAttribute('role', 'radio');
            b.setAttribute('aria-checked', CP.filter === key ? 'true' : 'false');
            b.addEventListener('click', () => { CP.filter = key; drawCases(body); });
            chips.appendChild(b);
        });
        bar.appendChild(chips);
        if (CP.live) {
            bar.appendChild(button('New case', 'btn-primary cmp-new-case', () => openNewCase({})));
        }
        out.push(bar);
        const shown = CP.cases.filter((c) => matches(c, CP.filter));
        if (!shown.length) {
            out.push(el('p', 'text-secondary cmp-empty', CP.cases.length ? 'No case matches.' : (CP.live
                ? 'No cases yet. A case is asked for here and approved by an independent administrator.'
                : 'No cases.')));
        } else {
            const t = table(['Case', 'Status', 'Auditor', 'Owners', 'Vaults', 'Access until', 'Hold', 'Files opened', 'Exports']);
            shown.forEach((c) => {
                const tr = el('tr', 'cmp-case-row');
                tr.dataset.caseId = c.id;
                tr.tabIndex = 0;
                const owners = Array.from(new Set((c.vaults || []).map((v) => v.owner).filter(Boolean)));
                cell(tr, 'Case', c.number || ('Asked ' + day(c.requested_at)));
                const st = cell(tr, 'Status', badge(c.effective_status || c.status));
                if (c.you_may_approve) st.appendChild(el('span', 'badge badge-warning cmp-yours', 'Your approval'));
                cell(tr, 'Auditor', c.auditor || '');
                cell(tr, 'Owners', owners.join(', '));
                cell(tr, 'Vaults', String((c.vaults || []).length));
                cell(tr, 'Access until', c.access_ends_at ? when(c.access_ends_at) : (c.status === 'pending' ? (c.access_days + ' days once approved') : ''));
                cell(tr, 'Hold', c.holds_standing ? 'Standing' : (c.hold ? 'Asked' : ''));
                cell(tr, 'Files opened', String(c.files_opened || 0));
                cell(tr, 'Exports', String(c.exports || 0));
                const open = () => openCase(c.id);
                tr.addEventListener('click', open);
                tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); open(); } });
                t.body.appendChild(tr);
            });
            out.push(el('div', 'cmp-table-wrap'));
            out[out.length - 1].appendChild(t.table);
        }
        body.replaceChildren(...out);
    }

    // ---- one case ------------------------------------------------------------------------------------------------

    function summaryLine(c) {
        const owners = Array.from(new Set((c.vaults || []).map((v) => v.owner).filter(Boolean)));
        let text = (c.auditor || 'The auditor') + ' asks to view files' + (c.can_export ? ' and export copies' : '')
            + ' in ' + plural((c.vaults || []).length, 'vault') + (owners.length ? ' of ' + owners.join(', ') : '')
            + ' for ' + plural(c.access_days || 0, 'day');
        if (c.files_from || c.files_to) text += ', files from ' + (day(c.files_from) || 'the start') + ' to ' + (day(c.files_to) || 'now');
        text += '. Purpose: ' + (PURPOSES[c.purpose] || c.purpose) + '. Legal basis: ' + (BASES[c.legal_basis] || c.legal_basis)
            + (c.lia_reference ? ' (assessment ' + c.lia_reference + ')' : '') + '.';
        if (c.special_category) text += ' Special-category data, Art. 9(2)' + (ART9[c.art9_condition] ? ' ' + ART9[c.art9_condition] : '') + '.';
        if (c.criminal_offence) text += ' Criminal-offence data (Art. 10).';
        if (c.hold) text += ' A legal hold starts with it.';
        if (c.password_override) text += ' Vaults with a password are opened without it.';
        return text;
    }

    function provenanceLines(p) {
        if (!p || !p.username) return null;
        const out = [];
        out.push(['Account', p.username + ' · ' + (p.role || '') + (p.active === false ? ' · inactive' : '')]);
        out.push(['Created', (day(p.created_at) || 'not recorded') + (p.created_by ? ' by ' + p.created_by : ' (who created it is not recorded)')]);
        out.push(['Password', p.password_set_by_other ? ('set by ' + (p.password_set_by || 'someone else') + (p.password_set_at ? ' on ' + day(p.password_set_at) : '') + ', not by them') : 'their own']);
        out.push(['Authenticator', p.authenticator ? ('since ' + day(p.authenticator.since)) : 'none']);
        if (p.administrator_since) out.push(['Administrator', 'since ' + day(p.administrator_since) + (p.made_administrator_by ? ' (made by ' + p.made_administrator_by + ')' : '')]);
        if (p.last_change_by_someone_else) {
            const l = p.last_change_by_someone_else;
            out.push(['Last change by someone else', String(l.kind || '').replace(/_/g, ' ') + ' on ' + day(l.at) + (l.by ? ' by ' + l.by : '')]);
        }
        return out;
    }

    function back(text, onClick) {
        const b = el('button', 'btn btn-secondary btn-sm cmp-back', '← ' + text);
        b.type = 'button';
        b.addEventListener('click', onClick);
        return b;
    }

    async function openCase(caseId) {
        stopWorkspace();
        CP.screen = 'case';
        CP.caseId = caseId;
        const r = root();
        if (!r) return;
        const seq = ++CP.seq;
        r.replaceChildren(back('Compliance', () => { CP.caseId = null; renderShell(); }), el('p', 'text-secondary', 'Loading the case…'));
        let c, holds = null;
        try {
            c = await cmp('/compliance/cases/' + encodeURIComponent(caseId));
            if (c.holds_standing || c.hold) {
                try { holds = ((await cmp('/compliance/holds')).cases || []).find((h) => h.id === c.id) || null; } catch (_) { holds = null; }
            }
        } catch (e) {
            if (seq === CP.seq) { r.replaceChildren(back('Compliance', () => { CP.caseId = null; renderShell(); })); fail(e, r.appendChild(el('div'))); }
            return;
        }
        if (seq !== CP.seq) return;
        drawCase(c, holds);
    }

    function drawCase(c, holds) {
        const r = root();
        const page = el('div', 'cmp-case');
        page.dataset.caseId = c.id;
        const top = el('div', 'cmp-case-head');
        top.appendChild(back('Compliance', () => { CP.caseId = null; renderShell(); }));
        const title = el('h2', 'cmp-title', c.number ? 'Case ' + c.number : 'Case asked for ' + day(c.requested_at));
        top.appendChild(title);
        top.appendChild(badge(c.effective_status || c.status));
        if (c.access_ends_at && (c.effective_status || c.status) === 'active') top.appendChild(el('span', 'cmp-ends', untilText(c.access_ends_at)));
        if (c.owners_told && c.owners_told.at) {
            top.appendChild(el('span', 'cmp-told text-secondary', 'Owners told ' + when(c.owners_told.at) + ' · app ✓ · email '
                + ({ sent: '✓', queued: 'queued', retrying: 'retrying', failed: 'failed', no_email_address: 'no address' }[c.owners_told.email] || '–')));
        }
        page.appendChild(top);
        const msg = el('div', 'cmp-msg');
        msg.hidden = true;
        page.appendChild(msg);

        const sum = el('section', 'card cmp-card cmp-summary');
        sum.appendChild(el('h3', 'cmp-h', 'What it asks'));
        sum.appendChild(el('p', 'cmp-summary-line', summaryLine(c)));
        if (c.status === 'pending' && c.pending_until) sum.appendChild(el('p', 'text-secondary text-sm', 'It expires unapproved on ' + when(c.pending_until) + '.'));
        page.appendChild(sum);

        const prov = provenanceLines(c.auditor_provenance);
        if (prov) {
            const card = el('section', 'card cmp-card cmp-provenance');
            card.appendChild(el('h3', 'cmp-h', 'Where the auditor\'s account came from'));
            card.appendChild(lines(prov));
            if (c.grant) card.appendChild(el('p', 'text-sm text-secondary', 'Auditor right proposed by ' + (c.grant.proposed_by || '–')
                + ', approved by ' + (c.grant.approved_by || 'the server\'s operator') + ' on ' + day(c.grant.approved_at) + '.'));
            if (c.auditor_open_cases != null) card.appendChild(el('p', 'text-sm text-secondary', 'Open cases of this auditor: ' + c.auditor_open_cases + '.'));
            page.appendChild(card);
        }
        if (c.justification) {
            const card = el('section', 'card cmp-card cmp-justification');
            card.appendChild(el('h3', 'cmp-h', 'Justification'));
            card.appendChild(el('p', 'cmp-text', c.justification));
            page.appendChild(card);
        }
        if (Array.isArray(c.people) && c.people.length) {
            const card = el('section', 'card cmp-card cmp-people');
            card.appendChild(el('h3', 'cmp-h', 'People it concerns'));
            card.appendChild(lines(c.people.map((p) => [p.username || 'an account since deleted', p.why === 'named' ? 'named in the request' : (p.why === 'owner' ? 'owns a vault in it' : String(p.why || '').replace(/_/g, ' '))])));
            page.appendChild(card);
        }
        const vcard = el('section', 'card cmp-card cmp-vaults');
        vcard.appendChild(el('h3', 'cmp-h', 'Vaults'));
        const vt = table(['Owner', 'Type', 'Covers', 'Files', 'Notes']);
        (c.vaults || []).forEach((v) => {
            const tr = el('tr', 'cmp-vault-row');
            tr.dataset.vaultId = v.vault_id;
            cell(tr, 'Owner', v.owner || '–');
            cell(tr, 'Type', v.type === 'zero_knowledge' ? 'Zero-knowledge' : 'Standard');
            cell(tr, 'Covers', v.covers === 'whole' ? 'the whole vault' : (v.covers === 'folders' ? plural(v.folders, 'folder') : 'nothing now'));
            cell(tr, 'Files', v.file_count != null ? (v.file_count + ' · ' + sizeText(v.bytes)) : '');
            const notes = [];
            if (!v.exists) notes.push('deleted since');
            if (v.has_password) notes.push('has a password');
            if (v.type === 'zero_knowledge') notes.push('cannot be opened');
            if (v.you_are_member) notes.push('you can open it yourself');
            if (v.owner_told_at) notes.push('owner told ' + day(v.owner_told_at));
            cell(tr, 'Notes', notes.join('; '));
            vt.body.appendChild(tr);
        });
        const wrap = el('div', 'cmp-table-wrap');
        wrap.appendChild(vt.table);
        vcard.appendChild(wrap);
        page.appendChild(vcard);
        if (c.owner_note) {
            const card = el('section', 'card cmp-card');
            card.appendChild(el('h3', 'cmp-h', 'The auditor\'s note to the owners'));
            card.appendChild(el('p', 'cmp-text', c.owner_note));
            page.appendChild(card);
        }
        const extra = [];
        if (c.reject_reason) extra.push(['Turned down because', c.reject_reason]);
        if (c.close_reason) extra.push(['Closed because', c.close_reason]);
        if (c.closed_at) extra.push(['Closed', when(c.closed_at) + (c.closed_by ? ' by ' + c.closed_by : '')]);
        if (Array.isArray(c.objections) && c.objections.length) {
            c.objections.forEach((o, i) => extra.push(['Objection ' + (i + 1), (o.text || '') + (o.by ? ' (' + o.by + ', ' + day(o.at) + ')' : '')]));
        }
        if (c.status === 'pending' && Array.isArray(c.independent_approvers)) {
            extra.push(['Who may approve', c.independent_approvers.length ? c.independent_approvers.join(', ') : 'only the server\'s operator (no independent administrator)']);
        }
        if (extra.length) {
            const card = el('section', 'card cmp-card');
            card.appendChild(lines(extra));
            page.appendChild(card);
        }
        if (holds) page.appendChild(holdCard(holds, () => openCase(c.id)));
        page.appendChild(caseActions(c, msg));
        r.replaceChildren(page);
    }

    function caseActions(c, msg) {
        const bar = el('div', 'cmp-actions');
        const may = c.you_may || {};
        const run = async (fn, done) => {
            msg.hidden = true;
            bar.querySelectorAll('button').forEach((b) => { b.disabled = true; });
            try { const out = await fn(); if (done) done(out); else openCase(c.id); } catch (e) {
                if (e.status === 412) { fail(problem(412, null, 'The case changed since you read it: read it again before you decide.'), msg); }
                else fail(e, msg);
                bar.querySelectorAll('button').forEach((b) => { b.disabled = false; });
            }
        };
        const version = { 'If-Match': '"' + c.version + '"' };
        const live = (c.effective_status || c.status) === 'active';
        if (live && c.auditor && signedInUser() && signedInUser().username === c.auditor) {
            bar.appendChild(button('Open workspace', 'btn-primary cmp-open-ws', () => openWorkspace(c.id)));
        }
        if (may.approve && may.approve.may) {
            bar.appendChild(button('Approve', 'btn-primary cmp-approve', () => run(async () => {
                const sure = typeof showConfirm === 'function' ? await showConfirm(
                    'Approve case access as described? The owners are told at once, and the auditor can open the files.',
                    'Approve the case', null, 'Approve') : true;
                if (!sure) throw problem(0, null, 'Not approved.');
                await cmp('/compliance/cases/' + c.id + '/approve', { method: 'POST', headers: version });
                ok('Approved. The owners have been told.');
            })));
        }
        if (may.reject && may.reject.may) {
            bar.appendChild(button('Turn down', 'btn-danger cmp-reject', () => run(async () => {
                const reason = await askReason('Why do you turn this case down? The auditor reads it.', 'Turn the case down');
                await cmp('/compliance/cases/' + c.id + '/reject', { json: { reason } });
                ok('Turned down.');
            })));
        }
        if (may.withdraw && may.withdraw.may) {
            bar.appendChild(button('Withdraw', 'btn-secondary cmp-withdraw', () => run(async () => {
                await cmp('/compliance/cases/' + c.id + '/withdraw', { method: 'POST' });
                ok('Withdrawn.');
            })));
        }
        if (may.extend && may.extend.may) {
            bar.appendChild(button('Extend', 'btn-secondary cmp-extend', () => run(async () => {
                const days = await askText('How many more days?', 'Extend access', '7', 'number');
                await cmp('/compliance/cases/' + c.id + '/extend', { json: { days: parseInt(days, 10) }, headers: version });
                ok('Extended. The owners have been told.');
            })));
        }
        if (may.narrow && may.narrow.may) {
            bar.appendChild(button('Narrow', 'btn-secondary cmp-narrow', () => openNarrow(c)));
        }
        if (may.objection && may.objection.may && CP.admin) {
            bar.appendChild(button('Record an objection', 'btn-secondary cmp-objection', () => run(async () => {
                const text = await askReason('The owner\'s objection, as they gave it:', 'Record an objection');
                await cmp('/compliance/cases/' + c.id + '/objection', { json: { text } });
                ok('Recorded.');
            })));
        }
        if (may.close && may.close.may) {
            bar.appendChild(button('Close the case', 'btn-danger cmp-close', () => run(async () => {
                const reason = await askReason('Why is the case closed? Its legal holds are released with it.', 'Close the case');
                await cmp('/compliance/cases/' + c.id + '/close', { json: { reason } });
                ok('Closed. The owners have been told.');
            })));
        }
        const why = ['approve', 'close'].map((k) => may[k] && !may[k].may && may[k].why_not ? may[k].why_not.text : null)
            .filter((t) => t && !/not allowed/i.test(t));
        if (!bar.children.length && why.length) bar.appendChild(el('p', 'text-secondary text-sm cmp-why', why[0]));
        return bar;
    }

    async function askText(message, title, value, type) {
        if (typeof showPrompt !== 'function') throw problem(0, null, 'Not done.');
        const out = await showPrompt(message, title, { defaultValue: value || '' });
        if (out == null || String(out).trim() === '') throw problem(0, null, 'Not done.');
        if (type === 'number' && !/^[0-9]+$/.test(String(out).trim())) throw problem(0, null, 'Give a whole number of days.');
        return String(out).trim();
    }

    function askReason(message, title) { return askText(message, title, ''); }

    // ---- narrowing a case: fewer vaults, or a shorter time range ------------------------------------------------

    function openNarrow(c) {
        const s = sheet('cmp-narrow-sheet', 'Narrow the case');
        s.body.appendChild(el('p', 'text-secondary text-sm', 'A case can only be narrowed here: anything wider needs a new case.'));
        const boxes = [];
        (c.vaults || []).filter((v) => v.covers !== 'nothing').forEach((v) => {
            const ch = check((v.owner || 'Vault') + ' · ' + (v.type === 'zero_knowledge' ? 'zero-knowledge' : 'standard') + ' · ' + v.vault_id.slice(0, 8), true);
            ch.box.dataset.vaultId = v.vault_id;
            boxes.push(ch.box);
            s.body.appendChild(ch.label);
        });
        const from = input('date', { value: c.files_from ? c.files_from.slice(0, 10) : '' });
        const to = input('date', { value: c.files_to ? c.files_to.slice(0, 10) : '' });
        s.body.append(field('Files from', from), field('Files to', to));
        const msg = el('div');
        s.body.appendChild(msg);
        const go = button('Narrow', 'btn-primary', async () => {
            const kept = boxes.filter((b) => b.checked).map((b) => ({ kind: 'vault', target_id: b.dataset.vaultId }));
            if (!kept.length) { fail(problem(0, null, 'Keep at least one vault, or close the case.'), msg); return; }
            const body = { scope: kept };
            if (from.value) body.files_from = from.value + 'T00:00:00Z';
            if (to.value) body.files_to = to.value + 'T23:59:59Z';
            go.disabled = true;
            try {
                await cmp('/compliance/cases/' + c.id + '/scope', { method: 'PATCH', json: body });
                s.close();
                ok('Narrowed.');
                openCase(c.id);
            } catch (e) { fail(e, msg); go.disabled = false; }
        });
        s.foot.append(button('Cancel', 'btn-secondary', s.close), go);
    }

    // ---- asking for a case -----------------------------------------------------------------------------------------

    // The note to the owners, as their notice will say it (app/core/owner_notices.py, the activation): number,
    // purpose and basis, who and until when, the note.
    function ownerPreview(f) {
        const days = parseInt(f.days, 10) || 14;
        const until = new Date(Date.now() + days * 86400000);
        const who = (signedInUser() && signedInUser().username) || 'the auditor';
        return 'Case (number given at approval) · Purpose: ' + (PURPOSES[f.purpose] || '-').toLowerCase() + ' · Legal basis: '
            + (BASES[f.legal_basis] || '-').toLowerCase() + '. ' + who + ' (auditor) can view files' + (f.export ? ' and export copies' : '')
            + ' until about ' + until.toLocaleDateString(undefined, { dateStyle: 'medium' }) + '. '
            + (f.hold ? 'A legal hold keeps files deleted from your vaults until the case ends. ' : '')
            + 'Every file opened is listed on Access to my vaults, as it happens.'
            + (f.note ? ' The auditor\'s note: “' + f.note + '”' : '');
    }

    function openNewCase(prefill) {
        if (typeof navigateToSection === 'function') {
            const sec = document.getElementById('compliance-section');
            if (!sec || !sec.classList.contains('active')) navigateToSection('compliance');
        }
        const s = sheet('cmp-new-case', 'New case', { wide: true });
        s.modal.classList.add('cmp-new-case-sheet');
        const purpose = select(Object.assign({ '': 'Choose…' }, PURPOSES), '');
        const basis = select(Object.assign({ '': 'Choose…' }, BASES), '');
        const lia = input('text', { maxlength: '255', placeholder: 'Your legitimate-interests assessment, by its reference' });
        const liaField = field('Assessment reference', lia, 'Needed with legitimate interests.');
        liaField.hidden = true;
        const art9 = check('It concerns special-category data (GDPR Art. 9)', false);
        const art9cond = select(Object.assign({ '': 'Choose the condition of Art. 9(2)…' }, ART9), '');
        const art9Field = field('Art. 9(2) condition', art9cond);
        art9Field.hidden = true;
        const art10 = check('It concerns criminal-offence data (GDPR Art. 10)', false);
        const just = input('textarea', { rows: '4', maxlength: '4000', placeholder: 'Why this access is needed, and what you look for (at least 30 characters). The approver reads it; the owners do not.' });
        const named = input('text', { placeholder: 'Usernames, separated by commas', autocomplete: 'off' });
        const note = input('textarea', { rows: '3', maxlength: '4000', placeholder: 'What the owners read with their notice.' });
        const preview = el('div', 'cmp-preview');
        const pickOwner = input('text', { placeholder: 'An owner\'s username', autocomplete: 'off' });
        const pickBtn = button('Find vaults', 'btn-secondary cmp-pick');
        const picked = el('div', 'cmp-picked');
        const from = input('date');
        const to = input('date');
        const days = input('number', { min: '1', max: '90', value: '14' });
        const exp = check('Allow exports (copies of files, in an archive)', false);
        const override = check('Open vaults with a password without it (only if this server allows it)', false);
        const hold = check('Place a legal hold with it', false);
        let holdTouched = false;
        hold.box.addEventListener('change', () => { holdTouched = true; });
        const scope = new Map();     // vault id -> {owner, label, custodian}
        (prefill.vaults || []).forEach((v) => scope.set(String(v.id), { owner: v.owner || null, label: v.label || ('Vault ' + String(v.id).slice(0, 8)) }));

        const sumLine = el('p', 'cmp-summary-line cmp-new-summary');
        const msg = el('div');
        function state() {
            return { purpose: purpose.value, legal_basis: basis.value, days: days.value, export: exp.box.checked,
                hold: hold.box.checked, note: note.value.trim() };
        }
        function redraw() {
            liaField.hidden = basis.value !== 'legitimate_interests';
            art9Field.hidden = !art9.box.checked;
            if (!holdTouched) hold.box.checked = ['internal_investigation', 'litigation_hold', 'regulator_request', 'security_incident'].includes(purpose.value);
            preview.replaceChildren(el('div', 'text-tertiary text-sm', 'What the owners will read'), el('div', 'cmp-preview-text', ownerPreview(state())));
            picked.replaceChildren();
            scope.forEach((v, id) => {
                const row = el('div', 'cmp-picked-row');
                row.dataset.vaultId = id;
                row.appendChild(el('span', null, v.label + (v.owner ? ' · ' + v.owner : '')));
                const x = button('Remove', 'btn-secondary', () => { scope.delete(id); redraw(); });
                row.appendChild(x);
                picked.appendChild(row);
            });
            if (!scope.size) picked.appendChild(el('p', 'text-secondary text-sm', 'No vault chosen yet.'));
            sumLine.textContent = 'The approver will read: ' + ((signedInUser() && signedInUser().username) || 'you') + ' asks to view files'
                + (exp.box.checked ? ' and export copies' : '') + ' in ' + plural(scope.size, 'vault') + ' for '
                + plural(parseInt(days.value, 10) || 14, 'day') + '. Purpose: ' + (PURPOSES[purpose.value] || '–') + '. Legal basis: '
                + (BASES[basis.value] || '–') + '.' + (hold.box.checked ? ' A legal hold starts with it.' : '');
        }
        [purpose, basis, days, note].forEach((c) => c.addEventListener('input', redraw));
        [purpose, basis].forEach((c) => c.addEventListener('change', redraw));
        [exp.box, hold.box, art9.box].forEach((c) => c.addEventListener('change', redraw));

        async function find() {
            const owner = pickOwner.value.trim();
            if (!owner) return;
            pickBtn.disabled = true;
            const list = el('div', 'cmp-vault-picker');
            try {
                const out = await cmp('/compliance/vault-picker?owner=' + encodeURIComponent(owner));
                if (!out.vaults.length) list.appendChild(el('p', 'text-secondary text-sm', out.owner.username + ' owns no vault.'));
                out.vaults.forEach((v) => {
                    const label = (v.name || ('Vault ' + v.id.slice(0, 8))) + ' · ' + (v.type === 'zero_knowledge' ? 'zero-knowledge' : 'standard')
                        + (v.has_password ? ' · password' : '') + ' · ' + plural(v.file_count, 'file') + ' · created ' + day(v.created_at);
                    const ch = check(label, scope.has(v.id));
                    ch.box.dataset.vaultId = v.id;
                    ch.box.addEventListener('change', () => {
                        if (ch.box.checked) scope.set(v.id, { owner: out.owner.username, label: v.name || ('Vault ' + v.id.slice(0, 8)) });
                        else scope.delete(v.id);
                        redraw();
                    });
                    list.appendChild(ch.label);
                });
            } catch (e) { list.appendChild(el('div', 'alert alert-error', e.message)); }
            pickBtn.disabled = false;
            const old = s.body.querySelector('.cmp-vault-picker');
            if (old) old.replaceWith(list); else pickerBox.appendChild(list);
        }
        pickBtn.addEventListener('click', find);
        pickOwner.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); find(); } });
        const pickRow = el('div', 'cmp-pick-row');
        pickRow.append(pickOwner, pickBtn);
        const pickerBox = el('div', 'cmp-picker-box');
        pickerBox.append(field('Vaults: find them by their owner', pickRow, 'Each search is recorded. A name shows only where you can read the vault already.'));

        const grid = el('div', 'cmp-form-grid');
        grid.append(field('Purpose', purpose), field('Legal basis', basis), liaField);
        s.body.append(grid, art9.label, art9Field, art10.label, field('Justification', just),
            field('People it concerns', named, 'Named here, they cannot approve it, and the case is kept from them.'),
            field('Note to the owners', note), preview, pickerBox, picked);
        const grid2 = el('div', 'cmp-form-grid');
        grid2.append(field('Files from', from), field('Files to', to), field('Days of access', days));
        s.body.append(grid2, exp.label, override.label, hold.label, sumLine, msg);
        const send = button('Ask for approval', 'btn-primary cmp-send', async () => {
            const body = {
                purpose: purpose.value, legal_basis: basis.value, lia_reference: lia.value.trim() || null,
                special_category: art9.box.checked, art9_condition: art9.box.checked ? (art9cond.value || null) : null,
                criminal_offence: art10.box.checked, justification: just.value.trim(), owner_note: note.value.trim(),
                named_usernames: named.value.split(',').map((x) => x.trim()).filter(Boolean),
                scope: Array.from(scope.keys()).map((id) => ({ kind: 'vault', target_id: id })),
                access_days: parseInt(days.value, 10) || null, can_export: exp.box.checked,
                password_override: override.box.checked, hold: hold.box.checked,
            };
            if (from.value) body.files_from = from.value + 'T00:00:00Z';
            if (to.value) body.files_to = to.value + 'T23:59:59Z';
            if (!body.purpose || !body.legal_basis) { fail(problem(0, null, 'Choose the purpose and the legal basis.'), msg); return; }
            if (!body.scope.length) { fail(problem(0, null, 'Choose at least one vault.'), msg); return; }
            send.disabled = true;
            try {
                const out = await cmp('/compliance/cases', { json: body });
                s.close();
                ok('Asked for. An independent administrator approves it; until then nothing is readable and the owners are not told.');
                CP.tab = 'cases';
                openCase(out.id);
            } catch (e) { fail(e, msg); send.disabled = false; }
        });
        s.foot.append(button('Cancel', 'btn-secondary', s.close), send);
        redraw();
        purpose.focus();
    }

    window.openNewCase = openNewCase;

    // ---- legal holds -----------------------------------------------------------------------------------------------

    function holdCard(h, after) {
        const card = el('section', 'card cmp-card cmp-hold');
        card.dataset.caseId = h.id;
        const head = el('div', 'cmp-hold-head');
        head.appendChild(el('h3', 'cmp-h', 'Legal hold' + (h.number ? ' · case ' + h.number : '')));
        head.appendChild(badge(h.status));
        card.appendChild(head);
        const standing = (h.holds || []).filter((x) => x.standing);
        card.appendChild(lines([
            ['Started by', (h.started_by || '–') + ' on ' + day(h.started_at)],
            ['Vaults', plural((h.holds || []).length, 'vault') + (standing.length !== (h.holds || []).length ? ' (' + standing.length + ' standing)' : '')],
            ['Kept so far', plural(h.kept.files, 'file') + ', ' + sizeText(h.kept.bytes) + (h.kept.folders ? ', ' + plural(h.kept.folders, 'folder') : '')],
            ['Confirm by', standing.filter((x) => x.confirm_by).map((x) => when(x.confirm_by))[0] || null],
            ['Confirmed', standing.filter((x) => x.confirmed_at).map((x) => when(x.confirmed_at) + ' by ' + (x.confirmed_by || '–'))[0] || null],
            ['Released', (h.holds || []).filter((x) => x.released_at).map((x) => when(x.released_at) + (x.purge_after ? ' · kept files deleted after ' + day(x.purge_after) : ''))[0] || null],
        ]));
        const msg = el('div');
        card.appendChild(msg);
        const bar = el('div', 'cmp-actions');
        const may = h.you_may || {};
        const run = async (fn, text) => {
            bar.querySelectorAll('button').forEach((b) => { b.disabled = true; });
            try { await fn(); ok(text); after(); } catch (e) { fail(e, msg); bar.querySelectorAll('button').forEach((b) => { b.disabled = false; }); }
        };
        const base = '/compliance/cases/' + encodeURIComponent(h.id) + '/hold/';
        if (may.confirm && may.confirm.may) bar.appendChild(button('Confirm the hold', 'btn-primary cmp-hold-confirm', () => run(() => cmp(base + 'confirm', { method: 'POST' }), 'Confirmed.')));
        if (may.review && may.review.may) bar.appendChild(button('Still needed', 'btn-secondary cmp-hold-review', () => run(() => cmp(base + 'review', { method: 'POST' }), 'Recorded.')));
        if (may.release && may.release.may) bar.appendChild(button('Release', 'btn-danger cmp-hold-release', () => run(async () => {
            const reason = await askReason('Why is the hold released? What it kept is deleted after a delay, unless the release is undone.', 'Release the hold');
            await cmp(base + 'release', { json: { reason } });
        }, 'Released.')));
        if (may.undo_release && may.undo_release.may) bar.appendChild(button('Undo the release', 'btn-secondary cmp-hold-undo', () => run(() => cmp(base + 'undo-release', { method: 'POST' }), 'The hold stands again.')));
        if (bar.children.length) card.appendChild(bar);
        return card;
    }

    async function renderHoldsTab(body) {
        const seq = ++CP.seq;
        body.replaceChildren(el('p', 'text-secondary', 'Loading legal holds…'));
        let data;
        try { data = await cmp('/compliance/holds'); } catch (e) { if (seq === CP.seq) fail(e, body); return; }
        if (seq !== CP.seq) return;
        CP.holds = data;
        const out = [];
        const off = offNotice(data.access_enabled);
        if (off) out.push(off);
        const bar = el('div', 'cmp-toolbar');
        bar.appendChild(el('p', 'text-secondary text-sm', 'A legal hold keeps what is deleted from a vault until it is released. A second administrator confirms it, or it lapses.'));
        bar.appendChild(button('Place a hold', 'btn-primary cmp-place-hold', () => openPlaceHold(data)));
        out.push(bar);
        if (!(data.cases || []).length) out.push(el('p', 'text-secondary cmp-empty', 'No legal holds.'));
        (data.cases || []).forEach((h) => out.push(holdCard(h, () => renderHoldsTab(body))));
        body.replaceChildren(...out);
    }

    function openPlaceHold(data) {
        const s = sheet('cmp-hold-sheet', 'Place a legal hold', { wide: true });
        const purpose = select(Object.assign({ '': 'Choose…' }, PURPOSES), 'litigation_hold');
        const basis = select(Object.assign({ '': 'Choose…' }, BASES), 'legal_obligation');
        const lia = input('text', { maxlength: '255' });
        const just = input('textarea', { rows: '3', maxlength: '4000', placeholder: 'Why the vaults must be preserved (at least 30 characters).' });
        const note = input('textarea', { rows: '2', maxlength: '4000', placeholder: 'What the owners read with their notice.' });
        const owner = input('text', { placeholder: 'An owner\'s username', autocomplete: 'off' });
        const chosen = new Map();
        const list = el('div', 'cmp-vault-picker');
        const msg = el('div');
        const find = button('Find vaults', 'btn-secondary', async () => {
            list.replaceChildren();
            try {
                const out = await cmp('/compliance/vault-picker?owner=' + encodeURIComponent(owner.value.trim()));
                out.vaults.forEach((v) => {
                    const ch = check((v.name || ('Vault ' + v.id.slice(0, 8))) + ' · ' + out.owner.username + ' · ' + plural(v.file_count, 'file'), chosen.has(v.id));
                    ch.box.dataset.vaultId = v.id;
                    ch.box.addEventListener('change', () => { if (ch.box.checked) chosen.set(v.id, true); else chosen.delete(v.id); });
                    list.appendChild(ch.label);
                });
                if (!out.vaults.length) list.appendChild(el('p', 'text-secondary text-sm', out.owner.username + ' owns no vault.'));
            } catch (e) { list.appendChild(el('div', 'alert alert-error', e.message)); }
        });
        const row = el('div', 'cmp-pick-row');
        row.append(owner, find);
        const grid = el('div', 'cmp-form-grid');
        grid.append(field('Purpose', purpose), field('Legal basis', basis), field('Assessment reference', lia, 'Needed with legitimate interests.'));
        s.body.append(grid, field('Justification', just), field('Note to the owners', note), field('Vaults: find them by their owner', row), list, msg);
        const go = button('Place the hold', 'btn-primary cmp-hold-go', async () => {
            if (!chosen.size) { fail(problem(0, null, 'Choose at least one vault.'), msg); return; }
            go.disabled = true;
            try {
                await cmp('/compliance/holds', { json: { vault_ids: Array.from(chosen.keys()), purpose: purpose.value, legal_basis: basis.value,
                    lia_reference: lia.value.trim() || null, justification: just.value.trim(), owner_note: note.value.trim() } });
                s.close();
                ok('Placed. Another administrator confirms it, or it lapses.');
                CP.tab = 'holds';
                renderShell();
            } catch (e) { fail(e, msg); go.disabled = false; }
        });
        s.foot.append(button('Cancel', 'btn-secondary', s.close), go);
    }

    // ---- the auditor right -------------------------------------------------------------------------------------------

    async function renderAuditorsTab(body) {
        const seq = ++CP.seq;
        body.replaceChildren(el('p', 'text-secondary', 'Loading auditors…'));
        let data, cases = [];
        try {
            [data, cases] = await Promise.all([cmp('/compliance/auditors'),
                cmp('/compliance/cases').then((out) => out.cases || []).catch(() => [])]);
        } catch (e) { if (seq === CP.seq) fail(e, body); return; }
        if (seq !== CP.seq) return;
        CP.grants = data.grants || [];
        // The open cases of each auditor (by username), from the cases this administrator may see.
        const open = {};
        cases.filter((c) => ['pending', 'active', 'suspended'].includes(c.effective_status || c.status))
            .forEach((c) => { open[c.auditor] = (open[c.auditor] || 0) + 1; });
        const out = [];
        const off = offNotice(data.access_enabled);
        if (off) out.push(off);
        const bar = el('div', 'cmp-toolbar');
        bar.appendChild(el('p', 'text-secondary text-sm', 'The auditor right lets an account read the activity log and ask for cases. One administrator proposes it, '
            + 'a second, independent one approves it; it lasts ' + data.grant_days + ' days.' + (data.admin_may_hold ? '' : ' Administrators cannot hold it on this server.')));
        bar.appendChild(button('Propose an auditor', 'btn-primary cmp-propose', () => openPropose()));
        out.push(bar);
        if (!CP.grants.length) out.push(el('p', 'text-secondary cmp-empty', 'Nobody holds the auditor right.'));
        else {
            const t = table(['Account', 'Status', 'Proposed', 'Approved', 'Until', 'Open cases', 'Actions']);
            CP.grants.forEach((g) => {
                const tr = el('tr', 'cmp-grant-row');
                tr.dataset.grantId = g.id;
                tr.dataset.username = g.username || '';
                cell(tr, 'Account', (g.username || g.username_at_grant || '–') + (g.role ? ' · ' + g.role : ''));
                const st = cell(tr, 'Status', badge(g.status));
                if (g.suspend_reason && g.status === 'suspended') st.appendChild(el('div', 'text-tertiary text-sm', String(g.suspend_reason).replace(/_/g, ' ')));
                cell(tr, 'Proposed', (g.proposed_by || '–') + ' · ' + day(g.proposed_at));
                cell(tr, 'Approved', g.approved_at ? ((g.approved_by_operator ? 'the server\'s operator' : (g.approved_by || '–')) + ' · ' + day(g.approved_at)) : (g.lapses_at ? 'lapses ' + day(g.lapses_at) : ''));
                cell(tr, 'Until', g.expires_at ? day(g.expires_at) + (g.age_days != null ? ' (held ' + plural(g.age_days, 'day') + ')' : '') : '');
                cell(tr, 'Open cases', g.status === 'proposed' ? '' : String(open[g.username] || 0));
                const acts = el('div', 'cmp-row-actions');
                if (g.status === 'proposed') {
                    acts.appendChild(button('Review', g.you_may_approve ? 'btn-primary cmp-grant-review' : 'btn-secondary cmp-grant-review', () => openGrant(g.id)));
                }
                if (['proposed', 'active', 'suspended'].includes(g.status) && g.user_id) {
                    acts.appendChild(button(g.status === 'proposed' ? 'Withdraw' : 'Revoke', 'btn-danger cmp-grant-revoke', async () => {
                        try {
                            const reason = typeof showPrompt === 'function' ? await showPrompt('Why? (optional; the account and the administrators read it)', g.status === 'proposed' ? 'Withdraw the proposal' : 'Revoke the auditor right', {}) : null;
                            if (reason === null) return;
                            await cmp('/users/' + g.user_id + '/auditor', { method: 'DELETE', json: { reason: reason || null } });
                            ok('Done.');
                            renderAuditorsTab(body);
                        } catch (e) { fail(e); }
                    }));
                }
                cell(tr, 'Actions', acts);
                t.body.appendChild(tr);
            });
            const wrap = el('div', 'cmp-table-wrap');
            wrap.appendChild(t.table);
            out.push(wrap);
        }
        body.replaceChildren(...out);
    }

    function openPropose() {
        const s = sheet('cmp-propose-sheet', 'Propose an auditor');
        s.body.appendChild(el('p', 'text-secondary text-sm', 'The account needs an authenticator app, a password it set itself, and no change by an administrator to its sign-in details in the last 14 days. A second administrator, independent of you and of the account, approves it.'));
        const who = input('text', { placeholder: 'Username', autocomplete: 'off' });
        const note = input('textarea', { rows: '2', maxlength: '2000', placeholder: 'Why this account (optional; the approver reads it).' });
        const msg = el('div');
        s.body.append(field('Account', who), field('Note', note), msg);
        const go = button('Propose', 'btn-primary cmp-propose-go', async () => {
            go.disabled = true;
            try {
                const id = await accountId(who.value.trim());
                await cmp('/compliance/auditor-grants', { json: { user_id: id, note: note.value.trim() || null } });
                s.close();
                ok('Proposed. A second administrator approves it.');
                CP.tab = 'auditors';
                renderShell();
            } catch (e) { fail(e, msg); go.disabled = false; }
        });
        s.foot.append(button('Cancel', 'btn-secondary', s.close), go);
        who.focus();
    }

    // An account's id from its username, through the administrators' user list.
    async function accountId(username) {
        if (!username) throw problem(0, null, 'Give the account\'s username.');
        const users = await cmp('/users');
        const list = Array.isArray(users) ? users : (users && (users.users || users.items)) || [];
        const found = list.find((u) => String(u.username).toLowerCase() === username.toLowerCase());
        if (!found) throw problem(404, null, 'No account is called ' + username + '.');
        return found.id;
    }

    async function openGrant(grantId) {
        const s = sheet('cmp-grant-sheet', 'Proposal of the auditor right', { wide: true });
        const msg = el('div');
        let g;
        try { g = await cmp('/compliance/auditor-grants/' + encodeURIComponent(grantId)); } catch (e) { fail(e, s.body); return; }
        s.modal.dataset.grantId = g.id;
        s.body.appendChild(el('p', 'cmp-summary-line', (g.proposed_by || 'An administrator') + ' proposes the auditor right for ' + (g.username || '–')
            + ' on ' + day(g.proposed_at) + '. If approved, it lasts until about ' + day(new Date(Date.now() + 365 * 86400000).toISOString()) + '.'));
        const prov = provenanceLines(g.provenance);
        if (prov) {
            s.body.appendChild(el('h4', 'cmp-h', 'Where the account came from'));
            s.body.appendChild(lines(prov, 'cmp-provenance'));
        }
        if (g.note) s.body.append(el('h4', 'cmp-h', 'Note'), el('p', 'cmp-text', g.note));
        if (Array.isArray(g.problems) && g.problems.length) {
            s.body.appendChild(el('div', 'alert alert-warning', 'It cannot be approved now: ' + g.problems.map((p) => p.text).join(' ')));
        }
        if (g.why_not && !g.you_may_approve) s.body.appendChild(el('p', 'text-secondary text-sm cmp-why', 'You cannot approve it: ' + g.why_not.text));
        if (g.host_approval) s.body.appendChild(el('p', 'text-secondary text-sm', 'No independent administrator can approve it: only the server\'s operator can, on the host.'));
        s.body.appendChild(msg);
        const after = () => { s.close(); if (CP.tab === 'auditors' && CP.screen === 'list') renderShell(); };
        if (g.you_may_reject) {
            s.foot.appendChild(button('Turn down', 'btn-danger cmp-grant-reject', async () => {
                try {
                    const reason = await askReason('Why do you turn it down? The account and the administrators read it.', 'Turn the proposal down');
                    await cmp('/compliance/auditor-grants/' + g.id + '/reject', { json: { reason } });
                    ok('Turned down.');
                    after();
                } catch (e) { fail(e, msg); }
            }));
        }
        if (g.you_may_approve) {
            s.foot.appendChild(button('Approve', 'btn-primary cmp-grant-approve', async () => {
                try {
                    await cmp('/compliance/auditor-grants/' + g.id + '/approve', { method: 'POST' });
                    ok('Approved: ' + (g.username || 'the account') + ' holds the auditor right.');
                    after();
                } catch (e) { fail(e, msg); }
            }));
        }
        s.foot.appendChild(button('Close', 'btn-secondary', s.close));
    }

    async function renderMyRight(body) {
        let me;
        try { me = await cmp('/compliance/me'); } catch (e) { fail(e, body); return; }
        const g = me && me.grant;
        CP.me = g || null;
        if (!g) { body.replaceChildren(el('p', 'text-secondary', 'You do not hold the auditor right.')); return; }
        const out = [lines([
            ['Status', badge(g.status)],
            ['Proposed by', g.proposed_by],
            ['Approved by', g.approved_by ? g.approved_by + ' on ' + day(g.approved_at) : null],
            ['Until', g.expires_at ? day(g.expires_at) : null],
            ['Now', g.live ? 'In force: you can read the activity log and ask for cases.' : (g.reason_text || 'Not in force.')],
        ], 'cmp-my-right')];
        if (g.may_reconfirm) {
            const msg = el('div');
            out.push(button('Confirm my auditor right again', 'btn-primary cmp-reconfirm', async () => {
                try {
                    await cmp('/compliance/auditor-grants/' + g.id + '/reconfirm', { method: 'POST' });
                    ok('Confirmed: your auditor right is in force again.');
                    await refreshStanding();
                    renderShell();
                } catch (e) { fail(e, msg); }
            }), msg);
        } else if (g.reconfirm_problem) {
            out.push(el('p', 'text-secondary text-sm', g.reconfirm_problem.text));
        }
        body.replaceChildren(...out);
    }

    // ---- a case's workspace ------------------------------------------------------------------------------------------

    let WS = null;

    function stopWorkspace() {
        if (!WS) return;
        if (WS.url) { try { URL.revokeObjectURL(WS.url); } catch (_) { /* gone */ } }
        if (WS.abort) { try { WS.abort.abort(); } catch (_) { /* done */ } }
        document.removeEventListener('keydown', WS.keys);
        window.removeEventListener('resize', WS.resize);
        WS = null;
    }

    async function openWorkspace(caseId) {
        stopWorkspace();
        CP.screen = 'workspace';
        CP.caseId = caseId;
        const r = root();
        if (!r) return;
        r.replaceChildren(el('p', 'text-secondary', 'Opening the case…'));
        let c, vaults;
        try {
            c = await cmp('/compliance/cases/' + encodeURIComponent(caseId));
            vaults = (await cmp('/compliance/cases/' + encodeURIComponent(caseId) + '/tree', { headers: caseUnlockHeader(caseId) })).vaults || [];
        } catch (e) {
            r.replaceChildren(back('The case', () => openCase(caseId)));
            fail(e, r.appendChild(el('div')));
            return;
        }
        WS = { c, vaults, items: [], index: -1, vault: null, folder: null, path: [], tab: 'files', screen: 'list',
            url: null, abort: null, keys: null, resize: null, seq: 0 };
        drawWorkspace();
        WS.keys = (e) => onKeys(e);
        WS.resize = () => layoutWorkspace();
        document.addEventListener('keydown', WS.keys);
        window.addEventListener('resize', WS.resize);
        const first = vaults.find((v) => v.exists && !v.refused) || vaults[0];
        if (first) openFolder(first.vault_id, null);
    }

    window.openCaseWorkspace = openWorkspace;

    function layoutWorkspace() {
        const ws = document.querySelector('.cmp-ws');
        if (!ws || !WS) return;
        const narrow = ws.clientWidth < 760;
        ws.classList.toggle('cmp-ws-phone', narrow);
        ws.dataset.screen = narrow ? WS.screen : 'all';
    }

    function setScreen(screen) {
        if (!WS) return;
        WS.screen = screen;
        layoutWorkspace();
    }

    function drawWorkspace() {
        const r = root();
        const c = WS.c;
        const ws = el('div', 'cmp-ws');
        ws.dataset.caseId = c.id;
        const head = el('div', 'cmp-ws-head');
        head.appendChild(back('The case', () => openCase(c.id)));
        head.appendChild(el('strong', 'cmp-ws-number', 'Case ' + (c.number || '')));
        head.appendChild(badge(c.effective_status || c.status));
        head.appendChild(el('span', 'cmp-ends', untilText(c.access_ends_at)));
        if (c.owners_told && c.owners_told.at) {
            head.appendChild(el('span', 'cmp-told text-secondary', 'Owner notified ' + when(c.owners_told.at) + ' · app ✓ · email '
                + ({ sent: '✓', queued: 'queued', retrying: 'retrying', failed: 'failed', no_email_address: 'no address' }[c.owners_told.email] || '–')));
        }
        const tools = el('div', 'cmp-ws-tools');
        const tabFiles = button('Files', 'btn-secondary cmp-ws-tab', () => switchTab('files'), { 'data-tab': 'files' });
        const tabLog = button('Case log', 'btn-secondary cmp-ws-tab', () => switchTab('log'), { 'data-tab': 'log' });
        tools.append(tabFiles, tabLog);
        if (c.can_export) tools.appendChild(button('Export…', 'btn-secondary cmp-ws-export', () => openExport()));
        if (c.you_may && c.you_may.close && c.you_may.close.may) {
            tools.appendChild(button('Close the case', 'btn-danger cmp-ws-close', async () => {
                try {
                    const reason = await askReason('Why is the case closed? Its legal holds are released with it.', 'Close the case');
                    await cmp('/compliance/cases/' + c.id + '/close', { json: { reason } });
                    ok('Closed. The owners have been told.');
                    openCase(c.id);
                } catch (e) { fail(e); }
            }));
        }
        head.appendChild(tools);
        ws.appendChild(head);

        const main = el('div', 'cmp-ws-main');
        const tree = el('nav', 'cmp-ws-tree');
        tree.setAttribute('aria-label', 'The case\'s vaults');
        const files = el('section', 'cmp-ws-files');
        files.setAttribute('aria-label', 'Files');
        const viewer = el('section', 'cmp-ws-viewer');
        viewer.setAttribute('aria-label', 'File');
        const log = el('section', 'cmp-ws-log');
        log.hidden = true;
        main.append(tree, files, viewer, log);
        ws.appendChild(main);
        r.replaceChildren(ws);
        drawTree();
        drawFiles();
        drawViewer(null);
        layoutWorkspace();
    }

    function switchTab(tab) {
        if (!WS) return;
        WS.tab = tab;
        const ws = document.querySelector('.cmp-ws');
        ws.querySelectorAll('.cmp-ws-tab').forEach((b) => b.classList.toggle('active', b.dataset.tab === tab));
        ws.querySelector('.cmp-ws-log').hidden = tab !== 'log';
        ['.cmp-ws-tree', '.cmp-ws-files', '.cmp-ws-viewer'].forEach((s) => { ws.querySelector(s).hidden = tab === 'log'; });
        if (tab === 'log') loadLog();
    }

    function drawTree() {
        const tree = document.querySelector('.cmp-ws-tree');
        if (!tree || !WS) return;
        const out = [];
        WS.vaults.forEach((v) => {
            const node = el('div', 'cmp-tree-vault' + (WS.vault === v.vault_id ? ' active' : ''));
            node.dataset.vaultId = v.vault_id;
            const name = v.name || (v.zero_knowledge ? 'Zero-knowledge vault' : 'Vault ' + v.vault_id.slice(0, 8));
            const b = button(name, 'btn-link cmp-tree-btn', () => openFolder(v.vault_id, null));
            node.appendChild(b);
            const facts = [];
            if (!v.exists) facts.push('deleted');
            if (v.zero_knowledge) facts.push('zero-knowledge: contents and names cannot be opened');
            if (v.locked) facts.push('password needed');
            if (v.password_override) facts.push('opened without its password');
            if (v.file_count != null) facts.push(plural(v.file_count, 'file'));
            node.appendChild(el('div', 'text-tertiary text-sm', facts.join(' · ')));
            if (v.locked && !v.zero_knowledge) node.appendChild(unlockInline(v));
            out.push(node);
        });
        tree.replaceChildren(...out);
    }

    function unlockInline(v) {
        const form = el('form', 'cmp-unlock');
        const pw = input('password', { placeholder: 'Vault password', autocomplete: 'off', 'aria-label': 'Vault password' });
        const go = el('button', 'btn btn-sm btn-primary', 'Unlock');
        go.type = 'submit';
        const msg = el('small', 'text-tertiary', 'For 15 minutes, in this case.');
        form.append(pw, go, msg);
        form.addEventListener('submit', async (e) => {
            e.preventDefault();
            go.disabled = true;
            try {
                await unlockCaseVault(WS.c.id, v.vault_id, pw.value);
                pw.value = '';
                const out = await cmp('/compliance/cases/' + WS.c.id + '/tree', { headers: caseUnlockHeader(WS.c.id) });
                WS.vaults = out.vaults || WS.vaults;
                drawTree();
                openFolder(v.vault_id, null);
            } catch (err) { msg.textContent = err.message; go.disabled = false; }
        });
        return form;
    }

    async function openFolder(vaultId, folderId) {
        if (!WS) return;
        const seq = ++WS.seq;
        WS.vault = vaultId;
        WS.folder = folderId;
        drawTree();
        const files = document.querySelector('.cmp-ws-files');
        if (files) files.replaceChildren(el('p', 'text-secondary', 'Loading…'));
        let out;
        try {
            out = await cmp('/compliance/cases/' + WS.c.id + '/tree?vault_id=' + encodeURIComponent(vaultId)
                + (folderId ? '&folder_id=' + encodeURIComponent(folderId) : ''), { headers: caseUnlockHeader(WS.c.id) });
        } catch (e) {
            if (WS && seq === WS.seq && files) fail(e, files);
            return;
        }
        if (!WS || seq !== WS.seq) return;
        WS.listing = out;
        WS.items = (out.entries || []).filter((x) => x.kind === 'file');
        WS.folders = (out.entries || []).filter((x) => x.kind === 'folder');
        WS.path = out.path || [];
        WS.index = -1;
        drawFiles();
    }

    function fileLabel(f) {
        if (f.name) return f.name;
        return WS && WS.listing && WS.listing.vault && WS.listing.vault.zero_knowledge ? 'Name sealed (zero-knowledge)' : 'Name hidden until the vault is unlocked';
    }

    function drawFiles() {
        const box = document.querySelector('.cmp-ws-files');
        if (!box || !WS) return;
        const out = [];
        const search = el('form', 'cmp-ws-search');
        const q = input('search', { placeholder: 'Search file names in the case', maxlength: '255', 'aria-label': 'Search file names' });
        search.append(q);
        search.addEventListener('submit', async (e) => {
            e.preventDefault();
            if (!q.value.trim()) return;
            try {
                const res = await cmp('/compliance/cases/' + WS.c.id + '/search', { json: { q: q.value.trim() }, headers: caseUnlockHeader(WS.c.id) });
                WS.items = res.results || [];
                WS.folders = [];
                WS.index = -1;
                WS.searched = { q: q.value.trim(), truncated: res.truncated, notSearched: (res.vaults_not_searched || []).length };
                drawFiles();
            } catch (err) { fail(err); }
        });
        out.push(search);
        if (WS.searched) {
            out.push(el('p', 'text-secondary text-sm cmp-ws-searched', plural(WS.items.length, 'file') + ' named “' + WS.searched.q + '…”'
                + (WS.searched.truncated ? ' (only the newest names were read)' : '') + (WS.searched.notSearched ? '; ' + plural(WS.searched.notSearched, 'vault') + ' not searched (names sealed or locked)' : '') + '.'));
            out.push(button('Back to the folders', 'btn-secondary', () => { WS.searched = null; openFolder(WS.vault, WS.folder); }));
        } else {
            const crumbs = el('div', 'cmp-ws-crumbs');
            crumbs.appendChild(button('Root', 'btn-link', () => openFolder(WS.vault, null)));
            (WS.path || []).forEach((p) => {
                crumbs.appendChild(el('span', 'text-tertiary', ' / '));
                crumbs.appendChild(button(p.name || 'Folder', 'btn-link', () => openFolder(WS.vault, p.id)));
            });
            out.push(crumbs);
            (WS.folders || []).forEach((f) => {
                const row = el('div', 'cmp-folder-row');
                row.dataset.folderId = f.id;
                const open = button((f.name || 'Folder') + (f.status === 'deleted_kept' ? ' (deleted, kept)' : ''), 'btn-link', () => openFolder(WS.vault, f.id));
                open.prepend(icon('folder'));
                row.appendChild(open);
                out.push(row);
            });
        }
        const t = table(['Name', 'Size', 'Uploaded', 'By', 'Status'], 'cmp-files-table');
        WS.items.forEach((f, i) => {
            const tr = el('tr', 'cmp-file-row' + (i === WS.index ? ' selected' : ''));
            tr.dataset.fileId = f.id;
            tr.tabIndex = -1;
            cell(tr, 'Name', fileLabel(f));
            cell(tr, 'Size', sizeText(f.size));
            cell(tr, 'Uploaded', day(f.uploaded_at));
            cell(tr, 'By', f.uploaded_by || '–');
            cell(tr, 'Status', FILE_STATUS[f.status] || f.status || '');
            tr.addEventListener('click', () => pickFile(i));
            t.body.appendChild(tr);
        });
        if (!WS.items.length) out.push(el('p', 'text-secondary text-sm cmp-empty', WS.searched ? 'No file matches.' : 'No files here.'));
        else {
            const wrap = el('div', 'cmp-table-wrap');
            wrap.appendChild(t.table);
            out.push(wrap);
            out.push(el('p', 'text-tertiary text-sm cmp-keys', 'Up and down, or j and k, move through the files.'));
        }
        box.replaceChildren(...out);
    }

    function pickFile(i) {
        if (!WS || i < 0 || i >= WS.items.length) return;
        WS.index = i;
        document.querySelectorAll('.cmp-file-row').forEach((tr, n) => tr.classList.toggle('selected', n === i));
        const row = document.querySelectorAll('.cmp-file-row')[i];
        if (row) { row.focus({ preventScroll: true }); row.scrollIntoView({ block: 'nearest' }); }
        setScreen('file');
        drawViewer(WS.items[i]);
    }

    function onKeys(e) {
        if (!WS || WS.tab !== 'files' || CP.screen !== 'workspace') return;
        const t = e.target;
        if (t && (t.tagName === 'INPUT' || t.tagName === 'TEXTAREA' || t.tagName === 'SELECT' || t.isContentEditable)) return;
        if (document.querySelector('.modal.active')) return;
        const sec = document.getElementById('compliance-section');
        if (!sec || !sec.classList.contains('active')) return;
        if (e.key === 'ArrowDown' || e.key === 'j') { e.preventDefault(); pickFile(Math.min(WS.items.length - 1, WS.index + 1)); }
        else if (e.key === 'ArrowUp' || e.key === 'k') { e.preventDefault(); pickFile(Math.max(0, WS.index - 1)); }
        else if (e.key === 'Escape' && WS.screen === 'file') { setScreen('list'); }
    }

    function watermark(box) {
        const who = (signedInUser() && signedInUser().username) || '';
        const mark = el('div', 'cmp-watermark');
        mark.setAttribute('aria-hidden', 'true');
        const text = 'Case ' + (WS.c.number || '') + ' · ' + who + ' · ' + new Date().toLocaleString(undefined, { dateStyle: 'short', timeStyle: 'short' });
        for (let i = 0; i < 12; i++) mark.appendChild(el('span', null, text));
        box.appendChild(mark);
    }

    const PREVIEW_MAX = 256 * 1024 * 1024;

    async function drawViewer(f) {
        const box = document.querySelector('.cmp-ws-viewer');
        if (!box || !WS) return;
        if (WS.url) { try { URL.revokeObjectURL(WS.url); } catch (_) { /* gone */ } WS.url = null; }
        if (WS.abort) { try { WS.abort.abort(); } catch (_) { /* done */ } WS.abort = null; }
        const nav = el('div', 'cmp-viewer-nav');
        nav.append(button('← List', 'btn-secondary cmp-viewer-back', () => setScreen('list')),
            button('Previous', 'btn-secondary cmp-viewer-prev', () => pickFile(Math.max(0, WS.index - 1))),
            button('Next', 'btn-secondary cmp-viewer-next', () => pickFile(Math.min(WS.items.length - 1, WS.index + 1))));
        if (!f) { box.replaceChildren(el('p', 'text-secondary cmp-viewer-empty', 'Choose a file. Opening one is recorded, and its owner sees it on their page.')); return; }
        const meta = lines([
            ['Name', fileLabel(f)], ['Size', sizeText(f.size)], ['Uploaded', when(f.uploaded_at) + (f.uploaded_by ? ' by ' + f.uploaded_by : '')],
            ['Changed', f.changed_at && f.changed_at !== f.uploaded_at ? when(f.changed_at) + (f.changed_by ? ' by ' + f.changed_by : '') : null],
            ['Status', FILE_STATUS[f.status] || f.status], ['Kept since', f.kept_at ? when(f.kept_at) : null],
        ], 'cmp-viewer-meta');
        const stage = el('div', 'cmp-viewer-stage');
        box.replaceChildren(nav, meta, stage);
        box.dataset.fileId = f.id;
        const vault = WS.vaults.find((v) => v.vault_id === f.vault_id) || (WS.listing && WS.listing.vault) || {};
        if (vault.zero_knowledge) { stage.appendChild(el('p', 'cmp-viewer-why', 'This vault is zero-knowledge: the server cannot open its files, so no case can.')); return; }
        if (f.has_password && !(WS.c.password_override)) { stage.appendChild(el('p', 'cmp-viewer-why', 'This file has a password of its own: it cannot be opened in this case.')); return; }
        if ((f.size || 0) > PREVIEW_MAX) { stage.appendChild(el('p', 'cmp-viewer-why', 'Too large to show here. Export it to keep a copy.')); return; }
        const seq = ++WS.seq;
        const ctl = new AbortController();
        WS.abort = ctl;
        stage.appendChild(el('p', 'text-secondary', 'Opening…'));
        let resp;
        try {
            resp = await cmp('/compliance/cases/' + WS.c.id + '/files/' + f.id + '/content', { raw: true, headers: caseUnlockHeader(WS.c.id), signal: ctl.signal });
        } catch (e) {
            if (!WS || seq !== WS.seq || e.name === 'AbortError') return;
            stage.replaceChildren(el('div', 'alert alert-error cmp-viewer-error', e.message));
            return;
        }
        const type = (resp.headers.get('Content-Type') || '').split(';')[0].trim().toLowerCase();
        const ext = String(f.name || '').split('.').pop().toLowerCase();
        let blob;
        try { blob = await resp.blob(); } catch (e) { if (WS && seq === WS.seq && e.name !== 'AbortError') stage.replaceChildren(el('div', 'alert alert-error', 'The file could not be read.')); return; }
        if (!WS || seq !== WS.seq) return;
        stage.replaceChildren();
        const isPdf = type === 'application/pdf' || ext === 'pdf';
        if (type.startsWith('image/') && type !== 'image/svg+xml') {
            WS.url = URL.createObjectURL(blob);
            const img = el('img', 'cmp-viewer-img');
            img.alt = fileLabel(f);
            img.src = WS.url;
            stage.appendChild(img);
        } else if (isPdf) {
            WS.url = URL.createObjectURL(new Blob([blob], { type: 'application/pdf' }));
            const frame = el('iframe', 'cmp-viewer-frame');
            frame.title = fileLabel(f);
            frame.setAttribute('sandbox', 'allow-same-origin allow-scripts');
            frame.src = WS.url;
            stage.appendChild(frame);
        } else if (type.startsWith('video/') || type.startsWith('audio/')) {
            WS.url = URL.createObjectURL(blob);
            const media = el(type.startsWith('video/') ? 'video' : 'audio', 'cmp-viewer-media');
            media.controls = true;
            media.src = WS.url;
            stage.appendChild(media);
        } else if (type.startsWith('text/') || blob.size < 2 * 1024 * 1024 && /^(txt|md|json|csv|log|xml|ya?ml|ini|cfg|conf|py|js|ts|css|html?|sh|sql)$/.test(ext)) {
            const text = await blob.slice(0, 2 * 1024 * 1024).text();
            const pre = el('pre', 'cmp-viewer-text', text);
            stage.appendChild(pre);
            if (blob.size > 2 * 1024 * 1024) stage.appendChild(el('p', 'text-secondary text-sm', 'Showing the first 2 MB.'));
        } else {
            stage.appendChild(el('p', 'cmp-viewer-why', 'No preview for this kind of file. Export it to keep a copy.'));
        }
        watermark(stage);
    }

    // ---- export ----------------------------------------------------------------------------------------------------

    function openExport() {
        if (!WS) return;
        const s = sheet('cmp-export-sheet', 'Export from case ' + (WS.c.number || ''));
        const all = check('Every file of the case (what it can open)', !WS.items.length);
        const shown = check('The files listed now (' + WS.items.length + ')', !!WS.items.length);
        all.box.name = shown.box.name = 'cmp-export-what';
        all.box.type = shown.box.type = 'radio';
        s.body.append(el('p', 'text-secondary text-sm', 'An archive with the files, a manifest, their checksums and the case\'s facts. Exporting asks for your password and a code; each owner is told. It can be fetched once, now.'),
            all.label, shown.label);
        const msg = el('div');
        s.body.appendChild(msg);
        const go = button('Export', 'btn-primary cmp-export-go', async () => {
            go.disabled = true;
            const body = all.box.checked ? { all: true } : { file_ids: WS.items.map((f) => f.id) };
            try {
                const prepared = await cmp('/compliance/cases/' + WS.c.id + '/exports', { json: body, headers: caseUnlockHeader(WS.c.id) });
                s.close();
                await fetchExport(prepared);
            } catch (e) { fail(e, msg); go.disabled = false; }
        });
        s.foot.append(button('Cancel', 'btn-secondary', s.close), go);
    }

    // The archive, once: through the app's download sink when it has one (the bytes go to the browser's download as
    // they arrive), otherwise read whole and handed over.
    async function fetchExport(prepared) {
        const name = 'case-' + (WS.c.number || 'export') + '-' + String(prepared.export_id).slice(0, 8) + '.zip';
        const ctl = new AbortController();
        const resp = await cmp('/compliance/cases/' + WS.c.id + '/exports/' + prepared.export_id, { raw: true, headers: caseUnlockHeader(WS.c.id), signal: ctl.signal });
        if (typeof dvTryStandardStreamedDownload === 'function') {
            const streamed = await dvTryStandardStreamedDownload(resp, name, 0, 'application/zip', ctl);
            if (streamed === true) { ok('Exporting ' + plural(prepared.files, 'file') + ' into ' + name + '.'); return; }
            if (streamed === 'failed') throw problem(0, null, 'The export stopped before it was complete; it was recorded as stopped.');
        }
        if (prepared.bytes > 256 * 1024 * 1024) { ctl.abort(); throw problem(0, null, 'This export is too large to save without the download service of this browser.'); }
        const blob = await resp.blob();
        const url = URL.createObjectURL(blob);
        const a = el('a');
        a.href = url;
        a.download = name;
        document.body.appendChild(a);
        a.click();
        a.remove();
        setTimeout(() => URL.revokeObjectURL(url), 60000);
        ok('Exported ' + plural(prepared.files, 'file') + ' into ' + name + '.');
    }

    // ---- the case log -------------------------------------------------------------------------------------------------

    async function loadLog() {
        const box = document.querySelector('.cmp-ws-log');
        if (!box || !WS) return;
        box.replaceChildren(el('p', 'text-secondary', 'Loading the case log…'));
        let out;
        try { out = await cmp('/activity/events?case=' + encodeURIComponent(WS.c.id) + '&limit=100', { headers: caseUnlockHeader(WS.c.id) }); }
        catch (e) { fail(e, box); return; }
        const events = out.events || out.items || [];
        const t = table(['When', 'Who', 'What', 'Status'], 'cmp-log-table');
        events.forEach((ev) => {
            const tr = el('tr', 'cmp-log-row');
            tr.dataset.eventId = ev.id;
            cell(tr, 'When', when(ev.timestamp));
            cell(tr, 'Who', ev.username || '–');
            cell(tr, 'What', ev.label || ev.action);
            cell(tr, 'Status', ev.status || '');
            t.body.appendChild(tr);
        });
        const wrap = el('div', 'cmp-table-wrap');
        wrap.appendChild(t.table);
        const go = button('Open in Activity', 'btn-secondary cmp-log-activity', () => {
            window.complianceActivityCase = WS.c.id;
            if (typeof navigateToSection === 'function') navigateToSection('activity');
        });
        box.replaceChildren(el('p', 'text-secondary text-sm', 'Everything recorded under this case, newest first.'), go,
            events.length ? wrap : el('p', 'text-secondary', 'Nothing recorded yet.'));
    }

    // ---- the Activity page: the auditor's case chip, Reveal, and Add to a new case -------------------------------------------

    // The auditor's cases that give access now (the Activity page's Case chip).
    async function activeCases() {
        try {
            const out = await cmp('/compliance/cases');
            const me = signedInUser();
            return (out.cases || []).filter((c) => (c.effective_status || c.status) === 'active' && me && c.auditor === me.username)
                .map((c) => ({ id: c.id, number: c.number }));
        } catch (_) { return []; }
    }

    window.complianceActiveCases = activeCases;

    function openRevealDialog(ev, onDone) {
        const s = sheet('cmp-reveal-sheet', 'Reveal the recorded names');
        s.body.appendChild(el('p', 'text-secondary text-sm', 'You see the names this event recorded in full, never names read from the vault now. '
            + 'The reveal is recorded with your reason, and the vault\'s owner is told (once a day per vault). Never for a vault with a password or a zero-knowledge one.'));
        const cat = select(Object.assign({ '': 'Choose…' }, REVEAL_REASONS), '');
        const text = input('textarea', { rows: '3', maxlength: '2000', placeholder: 'Why you need these names.' });
        const msg = el('div');
        const result = el('div', 'cmp-reveal-result');
        s.body.append(field('Reason', cat), field('Why', text), msg, result);
        const go = button('Reveal', 'btn-primary cmp-reveal-go', async () => {
            if (!cat.value || !text.value.trim()) { fail(problem(0, null, 'Choose the reason and say why.'), msg); return; }
            go.disabled = true;
            msg.hidden = true;
            try {
                const out = await cmp('/activity/events/' + encodeURIComponent(ev.id) + '/reveal', { json: { reason_category: cat.value, reason_text: text.value.trim() } });
                const names = out.names || {};
                const keys = Object.keys(names);
                result.replaceChildren(keys.length ? lines(keys.map((k) => [k.replace(/_/g, ' '), names[k]]), 'cmp-revealed')
                    : el('p', 'text-secondary', 'This event recorded no name in full.'));
                if ((out.not_in_full || []).length) result.appendChild(el('p', 'text-tertiary text-sm', 'Recorded only as a fingerprint: ' + out.not_in_full.join(', ').replace(/_/g, ' ') + '.'));
                go.remove();
                if (onDone) onDone(out);
            } catch (e) { fail(e, msg); go.disabled = false; }
        });
        s.foot.append(button('Close', 'btn-secondary', s.close), go);
    }

    window.openRevealDialog = openRevealDialog;

    window.openNewCaseFor = function openNewCaseFor(vaultId, label) {
        openNewCase({ vaults: vaultId ? [{ id: vaultId, label: label || null }] : [] });
    };

    function watchSignIn() {
        const screen = document.getElementById('dashboard-screen');
        if (!screen) return;
        let active = screen.classList.contains('active');
        if (active) { checkAccessBanner(); refreshStanding(); }
        new MutationObserver(() => {
            const now = screen.classList.contains('active');
            if (now && !active) { checkAccessBanner(); refreshStanding(); }
            if (!now) {
                if (window.NoticeBanner) window.NoticeBanner.hide(ACCESS_BANNER);
                forgetStanding();
            }
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
            // The notices of cases, holds and the auditor right open the Compliance page.
            if (typeof _NOTIF_TARGET_SECTION === 'object' && _NOTIF_TARGET_SECTION) {
                _NOTIF_TARGET_SECTION['#compliance'] = 'compliance';
            }
        } catch (_) { /* the bell then only marks it read */ }
        // A notice about the auditor right may change what this account may do: read its standing again.
        window.addEventListener('dockvault:auditor-right', () => refreshStanding());
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', wire);
    else wire();
})();
