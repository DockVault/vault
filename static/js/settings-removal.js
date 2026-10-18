/*
 * Settings -> Activity and records: remove the values recorded under earlier recording levels
 * (GET /settings/value-removals, POST /settings/value-removals/preview, POST /settings/value-removals,
 * POST /settings/value-removals/{id}/cancel, app/api/value_removal_router.py).
 *
 * Once a level has been lowered, the audit rows written before still hold what they recorded. A removal brings every
 * row written before the end of the current hour, archived or not, down to the levels in force. It is previewed
 * first (for each kind below full, how many rows hold a value above its level), then asked for: asking needs the
 * password (apiRequest runs the step-up) and typing "remove", and sends the levels the preview showed (when another
 * administrator changed one meanwhile, nothing is asked for and the preview is made again). It waits the reduction
 * delay, any administrator can
 * cancel it until it begins, and every administrator is told. The list shows each removal: waiting (with the date it
 * runs and why it may wait longer), running, completed (with how many rows it changed) or cancelled.
 *
 * Uses app.js's helpers (apiRequest, showToast, showConfirm), and the erase card's styles (static/css/activity.css).
 * Builds the page with createElement and textContent.
 */
(function () {
    'use strict';

    const S = { preview: null, busy: false, data: null };
    const STATUS = { pending: 'Waiting', running: 'Running', completed: 'Completed', cancelled: 'Cancelled',
        'not recorded': 'Not in the audit log' };
    const LEVEL_WORDS = { none: 'not recorded', fingerprint: 'fingerprint', shortened: 'shortened', full: 'full' };
    const KIND_WORDS = { names: 'names', signin_names: 'names typed at sign-in', emails: 'email addresses',
        ip: 'IP addresses', user_agent: 'browser descriptions' };

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

    function levelsText(levels) {
        const parts = Object.keys(KIND_WORDS).filter((k) => levels && levels[k] && levels[k] !== 'full')
            .map((k) => `${KIND_WORDS[k]}: ${LEVEL_WORDS[levels[k]] || levels[k]}`);
        return parts.length ? parts.join('; ') : 'every kind in full';
    }

    function renderPreview() {
        const box = byId('removal-preview');
        const ask = byId('removal-ask');
        if (!box) return;
        box.replaceChildren();
        const p = S.preview;
        const lowered = p ? (p.kinds || []) : [];
        if (ask) ask.disabled = S.busy || !p || !lowered.length || Boolean(p.waiting);
        if (!p) return;
        if (!lowered.length) {
            box.appendChild(el('p', 'text-secondary', 'Every kind of personal data is recorded in full, so there is ' +
                'nothing to remove. Choose a lower level above first.'));
            return;
        }
        if (p.waiting) {
            box.appendChild(el('p', 'alert alert-warning', 'A removal is already waiting or running: cancel it below, ' +
                'or let it complete, before asking for another.'));
        }
        box.appendChild(el('p', null, `If it ran now, the audit rows written before ${when(p.before)} would keep only ` +
            'what the levels in force record:'));
        const list = el('ul', 'erase-preview-list removal-preview-list');
        lowered.forEach((k) => {
            const rows = k.rows == null ? 'too many to count just now' : plural(k.rows, 'row', 'rows');
            const item = el('li', null, `${k.label}, ${LEVEL_WORDS[k.level] || k.level}: ${rows}`);
            item.dataset.kind = k.key;
            list.appendChild(item);
        });
        box.appendChild(list);
        let total;
        if (p.rows == null) total = 'The rows could not be counted just now; the removal counts them as it runs.';
        else if (!p.counted) total = `At least ${plural(p.rows, 'row', 'rows')} in all (there are too many to count ` +
            'just now; the removal counts them as it runs).';
        else total = `${plural(p.rows, 'row', 'rows')} in all.`;
        box.appendChild(el('p', 'removal-total', total));
        if (p.archived_days) {
            box.appendChild(el('p', 'text-secondary text-sm', `${plural(p.archived_days, 'archived day', 'archived days')}` +
                ': read when the removal runs, and their rows are changed too (not counted here).'));
        }
        const not = el('ul', 'text-secondary text-sm erase-not-reached removal-not-reached');
        (p.not_reached || []).forEach((t) => not.appendChild(el('li', null, t)));
        box.appendChild(el('p', 'text-secondary text-sm', 'What a removal does not reach:'));
        box.appendChild(not);
        box.appendChild(el('p', 'text-secondary text-sm', `It waits ${plural(p.delay_days, 'day', 'days')} before it ` +
            'runs, and any administrator can cancel it until then. Every administrator is told.'));
    }

    function renderList() {
        const box = byId('removal-list');
        if (!box || !S.data) return;
        box.replaceChildren();
        const items = S.data.requests || [];
        if (!items.length) {
            box.appendChild(el('p', 'text-secondary', 'No removal has been asked for.'));
            return;
        }
        items.forEach((r) => {
            const item = el('div', 'erase-request removal-request');
            item.dataset.request = r.id || '';
            item.dataset.status = r.status;
            const head = el('p', null);
            head.appendChild(el('strong', null, `Rows written before ${when(r.before)}`));
            head.appendChild(el('span', 'badge erase-status removal-status', STATUS[r.status] || r.status));
            item.appendChild(head);
            item.appendChild(el('p', 'text-secondary text-sm', `Brought down to: ${levelsText(r.levels)}.`));
            let text = `Asked for by ${r.requested_by || 'an administrator'} on ${when(r.requested_at)}`;
            if (r.status === 'pending') text += `; runs on ${when(r.effective_at)} unless it is cancelled.`;
            else if (r.status === 'running') text += `; running since ${when(r.started_at)}.`;
            else if (r.status === 'completed') text += `; completed on ${when(r.completed_at)}.`;
            else if (r.status === 'cancelled') {
                text += `; cancelled${r.decided_by ? ' by ' + r.decided_by : ''}${r.decided_at ? ' on ' + when(r.decided_at) : ''}.`;
            } else text += '. The audit log holds no request of it, so it does not run.';
            item.appendChild(el('p', 'text-secondary text-sm', text));
            if (r.waiting) item.appendChild(el('p', 'text-secondary text-sm removal-waiting', r.waiting));
            if (r.status === 'completed' && r.counts) {
                const n = (Number(r.counts.rows) || 0) + (Number(r.counts.archived_rows) || 0);
                item.appendChild(el('p', 'text-secondary text-sm removal-counts',
                    `It changed ${plural(n, 'row', 'rows')}, ${Number(r.counts.archived_rows) || 0} of them archived.`));
            }
            if (r.cancellable) {
                const cancel = el('button', 'btn btn-outline btn-sm removal-cancel', 'Cancel this removal');
                cancel.type = 'button';
                cancel.disabled = S.busy;
                cancel.addEventListener('click', () => cancelRemoval(r));
                item.appendChild(cancel);
            }
            box.appendChild(item);
        });
    }

    async function preview() {
        S.busy = true;
        renderPreview();
        try {
            S.preview = await apiRequest('/settings/value-removals/preview', { method: 'POST', silent: true });
        } catch (e) {
            S.preview = null;
            showToast(e.message || 'The preview could not be made', 'error');
        } finally {
            S.busy = false;
            renderPreview();
        }
    }

    async function ask() {
        const p = S.preview;
        if (S.busy || !p || !(p.kinds || []).length || p.waiting) return;
        const what = p.rows == null ? 'the audit rows' : (p.counted ? plural(p.rows, 'audit row', 'audit rows')
            : `at least ${plural(p.rows, 'audit row', 'audit rows')}`);
        const message = `Remove from ${what} written before ${when(p.before)} the values above the levels in force ` +
            `(${levelsText(p.levels)})? It runs in ${plural(p.delay_days, 'day', 'days')} unless an administrator ` +
            'cancels it, and cannot be undone once it has run.';
        const ok = await showConfirm(message, 'Remove earlier recorded values?', 'remove', 'Ask for this removal');
        if (!ok) return;
        S.busy = true;
        renderPreview();
        let stale = false;
        try {
            const out = await apiRequest('/settings/value-removals', {
                method: 'POST', body: JSON.stringify({ levels: p.levels }), silent: true,
            });
            S.preview = null;
            showToast(`The removal runs on ${when(out.request.effective_at)} unless it is cancelled`, 'success');
        } catch (e) {
            stale = e.status === 409 && e.reason === 'levels-changed';
            showToast(e.message || 'The removal was not asked for', 'error');
        } finally {
            S.busy = false;
            renderPreview();
            await load();
        }
        // The levels changed since the preview: make it again, so what is asked for next is what it shows.
        if (stale) await preview();
    }

    async function cancelRemoval(r) {
        if (S.busy) return;
        S.busy = true;
        renderList();
        try {
            await apiRequest(`/settings/value-removals/${encodeURIComponent(r.id)}/cancel`, { method: 'POST', silent: true });
            showToast('The removal is cancelled', 'success');
        } catch (err) {
            showToast(err.message || 'The removal was not cancelled', 'error');
        } finally {
            S.busy = false;
            await load();
        }
    }

    async function load() {
        if (!byId('removal-list')) return;
        try {
            S.data = await apiRequest('/settings/value-removals', { silent: true });
        } catch (e) {
            S.data = null;
            const box = byId('removal-list');
            if (box) box.replaceChildren(el('p', 'text-secondary', `The removals could not be read: ${e.message}`));
            return;
        }
        renderList();
    }

    function wire() {
        const button = byId('removal-preview-btn');
        if (button && !button.dataset.wired) {
            button.dataset.wired = '1';
            button.addEventListener('click', preview);
        }
        const askBtn = byId('removal-ask');
        if (askBtn && !askBtn.dataset.wired) {
            askBtn.dataset.wired = '1';
            askBtn.addEventListener('click', ask);
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

    // Called once the levels are saved (static/js/settings-records.js): a preview made before then is stale.
    function levelsChanged() {
        S.preview = null;
        renderPreview();
        load();
    }

    window.ValueRemoval = { load, preview, ask, levelsChanged };
})();
