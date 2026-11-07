/*
 * Settings -> Activity and records: erase a person's records (GET /settings/erase-requests,
 * POST /settings/erase-requests/preview, POST /settings/erase-requests, POST /settings/erase-requests/{id}/cancel,
 * app/api/person_erase_router.py).
 *
 * The name is typed exactly as the records hold it (a deleted account's username, or a name typed at a failed
 * sign-in), previewed first (what it would change in each place, the near misses, what it does not reach), and only
 * then asked for: asking needs the password (apiRequest runs the step-up) and typing "erase". The name travels in
 * request bodies only, is never kept in the browser, and the field is cleared once it is asked for, and with its
 * preview at a sign-out (reset), so the next person on the tab finds neither. The list shows
 * each erase by its placeholder, never by the name: waiting (with the date it runs and why it may wait longer),
 * running, completed (with what it changed) or cancelled; a waiting one can be cancelled by any administrator.
 *
 * Uses app.js's helpers (apiRequest, showToast, showConfirm). Builds the page with createElement and textContent.
 */
(function () {
    'use strict';

    const S = { preview: null, previewed: null, busy: false, data: null };
    // A sign-out begins the next person's time on this tab (reset, called by the app's logout): what the page held
    // for the person who signed out is cleared, and the answer to a request they made is dropped when it comes.
    let resets = 0;
    const STATUS = { pending: 'Waiting', running: 'Running', completed: 'Completed', cancelled: 'Cancelled',
        'not recorded': 'Not in the audit log', unread: 'Not known yet' };

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function byId(id) { return document.getElementById(id); }

    function when(text) {
        if (!text) return '';
        const d = new Date(text);
        return isNaN(d.getTime()) ? text : d.toLocaleString();
    }

    function plural(n, one, many) { return `${n} ${n === 1 ? one : many}`; }

    function nameInput() { return byId('erase-name'); }

    // A preview stands for the name it was made for only.
    function current() {
        const input = nameInput();
        return input ? input.value : '';
    }

    function renderPreview() {
        const box = byId('erase-preview');
        const ask = byId('erase-ask');
        if (!box) return;
        box.replaceChildren();
        const p = S.preview;
        const fresh = p && S.previewed === current();
        if (ask) ask.disabled = S.busy || !fresh || Boolean(p && p.refused);
        if (!p) return;
        if (!fresh) {
            box.appendChild(el('p', 'text-secondary', 'The name changed: preview it again.'));
            return;
        }
        if (p.refused) {
            box.appendChild(el('p', 'alert alert-warning', `This name cannot be erased now: ${p.refused}.`));
        }
        const list = el('ul', 'erase-preview-list');
        let rows = p.audit_rows == null ? 'Audit rows: too many to count just now (the erase counts them as it runs)'
            : `${plural(p.audit_rows, 'audit row', 'audit rows')}`;
        if (p.oldest && p.newest) rows += ` (${when(p.oldest)} to ${when(p.newest)})`;
        list.appendChild(el('li', null, rows));
        if (p.archived_days) {
            list.appendChild(el('li', null, `${plural(p.archived_days, 'archived day', 'archived days')}: read when ` +
                'the erase runs, and its rows there are changed too'));
        }
        (p.stores || []).filter((s) => s.count).forEach((s) => {
            list.appendChild(el('li', null, `${s.label}: ${s.count}`));
        });
        box.appendChild(el('p', null, 'If it ran now, it would give a placeholder in place of the name in:'));
        box.appendChild(list);
        if ((p.near_misses || []).length) {
            box.appendChild(el('p', 'text-secondary text-sm', 'The records also hold these names, which this erase ' +
                'leaves: ' + p.near_misses.join(', ') + '. Each is erased only by an erase of its own.'));
        }
        if (p.mentioned_by_others) {
            box.appendChild(el('p', 'text-secondary text-sm', `${plural(p.mentioned_by_others, 'row', 'rows')} of ` +
                'other people mention the name in their details; they are not changed.'));
        }
        const not = el('ul', 'text-secondary text-sm erase-not-reached');
        (p.not_reached || []).forEach((t) => not.appendChild(el('li', null, t)));
        box.appendChild(el('p', 'text-secondary text-sm', 'What an erase does not reach:'));
        box.appendChild(not);
        box.appendChild(el('p', 'text-secondary text-sm', `It waits ${plural(p.delay_days, 'day', 'days')} before it ` +
            'runs, and any administrator can cancel it until then. Every administrator is told.'));
    }

    function renderList() {
        const box = byId('erase-list');
        if (!box || !S.data) return;
        box.replaceChildren();
        const items = S.data.requests || [];
        if (!items.length) {
            box.appendChild(el('p', 'text-secondary', 'No erase has been asked for.'));
            return;
        }
        items.forEach((e) => {
            const item = el('div', 'erase-request');
            item.dataset.request = e.id || '';
            item.dataset.status = e.status;
            const head = el('p', null);
            head.appendChild(el('strong', null, e.placeholder || 'An erase'));
            head.appendChild(el('span', 'badge erase-status', STATUS[e.status] || e.status));
            item.appendChild(head);
            let text = `Asked for by ${e.requested_by || 'an administrator'} on ${when(e.requested_at)}`;
            if (e.status === 'pending') text += `; runs on ${when(e.effective_at)} unless it is cancelled.`;
            else if (e.status === 'running') text += `; running since ${when(e.started_at)}.`;
            else if (e.status === 'completed') text += `; completed on ${when(e.completed_at)}.`;
            else if (e.status === 'cancelled') {
                text += `; cancelled${e.decided_by ? ' by ' + e.decided_by : ''}${e.decided_at ? ' on ' + when(e.decided_at) : ''}.`;
            } else if (e.status === 'unread') {
                text += ". Its state is not known yet: this server has not read the audit log's integrity chain " +
                    'through (it does so as it starts).';
            } else text += '. The audit log holds no request of it, so it does not run.';
            item.appendChild(el('p', 'text-secondary text-sm', text));
            if (e.waiting) item.appendChild(el('p', 'text-secondary text-sm erase-waiting', e.waiting));
            if (e.status === 'completed' && e.counts) {
                const stores = e.counts.stores || {};
                const others = Object.values(stores).reduce((a, b) => a + (Number(b) || 0), 0);
                item.appendChild(el('p', 'text-secondary text-sm', `It changed ${plural(e.counts.audit_rows || 0,
                    'audit row', 'audit rows')} and ${plural(others, 'other record', 'other records')}.`));
            }
            if (e.cancellable) {
                const cancel = el('button', 'btn btn-outline btn-sm erase-cancel', 'Cancel this erase');
                cancel.type = 'button';
                cancel.disabled = S.busy;
                cancel.addEventListener('click', () => cancelErase(e));
                item.appendChild(cancel);
            }
            box.appendChild(item);
        });
    }

    async function preview() {
        const name = current();
        if (!name) {
            showToast('Type the name to erase', 'error');
            return;
        }
        const asked = resets;
        S.busy = true;
        renderPreview();
        let answer = null;
        let failure = null;
        try {
            answer = await apiRequest('/settings/erase-requests/preview', {
                method: 'POST', body: JSON.stringify({ name }), silent: true,
            });
        } catch (e) {
            failure = e;
        }
        if (asked !== resets) return;
        S.busy = false;
        if (failure) {
            S.preview = null;
            showToast(failure.message || 'The preview could not be made', 'error');
        } else {
            S.preview = answer;
            S.previewed = name;
        }
        renderPreview();
    }

    async function ask() {
        const name = current();
        if (S.busy || !S.preview || S.previewed !== name || S.preview.refused) return;
        const p = S.preview;
        const where = p.audit_rows == null ? 'the audit log' : plural(p.audit_rows, 'audit row', 'audit rows');
        const message = `Erase this name from ${where} and the other ` +
            `records? It runs in ${plural(p.delay_days, 'day', 'days')} unless an administrator cancels it, and ` +
            'cannot be undone once it has run.';
        const asked = resets;
        const ok = await showConfirm(message, "Erase a person's records?", 'erase', 'Ask for this erase');
        if (!ok || asked !== resets) return;
        S.busy = true;
        renderPreview();
        let out = null;
        let failure = null;
        try {
            out = await apiRequest('/settings/erase-requests', {
                method: 'POST', body: JSON.stringify({ name }), silent: true,
            });
        } catch (e) {
            failure = e;
        }
        if (asked !== resets) return;
        if (failure) {
            showToast(failure.message || 'The erase was not asked for', 'error');
        } else {
            const input = nameInput();
            if (input) input.value = '';
            S.preview = null;
            S.previewed = null;
            showToast(`The erase ${out.request.placeholder} runs on ${when(out.request.effective_at)} unless it is ` +
                'cancelled', 'success');
        }
        S.busy = false;
        renderPreview();
        await load();
    }

    async function cancelErase(e) {
        if (S.busy) return;
        const asked = resets;
        S.busy = true;
        renderList();
        let failure = null;
        try {
            await apiRequest(`/settings/erase-requests/${encodeURIComponent(e.id)}/cancel`, { method: 'POST', silent: true });
        } catch (err) {
            failure = err;
        }
        if (asked !== resets) return;
        if (failure) showToast(failure.message || 'The erase was not cancelled', 'error');
        else showToast(`The erase ${e.placeholder} is cancelled`, 'success');
        S.busy = false;
        await load();
    }

    async function load() {
        if (!byId('erase-list')) return;
        const asked = resets;
        let data;
        try {
            data = await apiRequest('/settings/erase-requests', { silent: true });
        } catch (e) {
            if (asked !== resets) return;
            S.data = null;
            const box = byId('erase-list');
            if (box) box.replaceChildren(el('p', 'text-secondary', `The erases could not be read: ${e.message}`));
            return;
        }
        if (asked !== resets) return;
        S.data = data;
        const note = byId('erase-protected');
        if (note) note.hidden = !S.data.protected_minimum;
        renderList();
    }

    function wire() {
        const button = byId('erase-preview-btn');
        if (button && !button.dataset.wired) {
            button.dataset.wired = '1';
            button.addEventListener('click', preview);
        }
        const askBtn = byId('erase-ask');
        if (askBtn && !askBtn.dataset.wired) {
            askBtn.dataset.wired = '1';
            askBtn.addEventListener('click', ask);
        }
        const input = nameInput();
        if (input && !input.dataset.wired) {
            input.dataset.wired = '1';
            input.addEventListener('input', renderPreview);
            input.addEventListener('keydown', (ev) => {
                if (ev.key === 'Enter') {
                    ev.preventDefault();
                    preview();
                }
            });
        }
    }

    document.addEventListener('click', (e) => {
        const tab = e.target.closest && e.target.closest('.tab-btn[data-tab="records"]');
        if (tab) {
            wire();
            load();
        }
    });
    document.addEventListener('DOMContentLoaded', wire);

    // At a sign-out: the name typed, its preview (with the near-miss names the records hold) and the Ask button it
    // turned on, and the list of erases, so the next person on the tab finds none of them; an answer still on its
    // way is dropped.
    function reset() {
        resets += 1;
        S.preview = null;
        S.previewed = null;
        S.busy = false;
        S.data = null;
        const input = nameInput();
        if (input) input.value = '';
        const box = byId('erase-preview');
        if (box) box.replaceChildren();
        const askBtn = byId('erase-ask');
        if (askBtn) askBtn.disabled = true;
        const list = byId('erase-list');
        if (list) list.replaceChildren();
    }

    window.EraseSettings = { load, preview, ask, reset };
})();
