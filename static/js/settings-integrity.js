/*
 * Settings -> Activity and records: the audit log's integrity warnings an administrator acknowledges once seen
 * (GET /settings/audit-integrity/warnings, POST /settings/audit-integrity/acknowledge,
 * app/api/audit_integrity_router.py), and when the archive starts and what it holds.
 *
 * Each late seal is shown with the rows it added (time, action, account, resource), so an administrator
 * acknowledges what they have seen, not a count; each seal written from the database's values says what it
 * kept. Acknowledging asks for the password (apiRequest runs the step-up). Uses app.js's apiRequest and
 * showToast; builds the list with createElement and textContent only.
 */
(function () {
    'use strict';

    const S = { warnings: [], read: true, chosen: new Set(), busy: false };

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

    function renderRows(rows) {
        const wrap = el('div', 'table-wrap mt-sm');
        const table = el('table', 'data-table');
        table.setAttribute('aria-label', 'Rows the late seal added');
        const head = el('thead');
        const hr = el('tr');
        ['Time', 'Action', 'Account', 'Resource'].forEach((t) => {
            const th = el('th', null, t);
            th.scope = 'col';
            hr.appendChild(th);
        });
        head.appendChild(hr);
        table.appendChild(head);
        const body = el('tbody');
        rows.forEach((r) => {
            const tr = el('tr');
            [when(r.timestamp), r.action || '', r.account || '', r.resource || ''].forEach((v) => tr.appendChild(el('td', null, v)));
            body.appendChild(tr);
        });
        table.appendChild(body);
        wrap.appendChild(table);
        return wrap;
    }

    function render() {
        const box = byId('integrity-warnings-list');
        const button = byId('integrity-warnings-ack');
        if (!box || !button) return;
        box.replaceChildren();
        if (!S.read) {
            // The server lists them from its view of the chain only once it has read it through.
            box.appendChild(el('p', 'text-secondary integrity-warnings-unread', 'Which seals wait to be acknowledged '
                + "is not known yet: this server has not read the audit log's integrity chain through. The integrity "
                + 'status on the Activity page says why.'));
        } else if (!S.warnings.length) {
            box.appendChild(el('p', 'text-secondary', 'Nothing waits to be acknowledged.'));
        }
        S.warnings.forEach((w) => {
            const item = el('div', 'integrity-warning mb-md');
            const label = el('label', 'checkbox-label');
            const box2 = el('input');
            box2.type = 'checkbox';
            box2.checked = S.chosen.has(w.seq);
            box2.addEventListener('change', () => {
                if (box2.checked) S.chosen.add(w.seq); else S.chosen.delete(w.seq);
                button.disabled = S.busy || S.chosen.size === 0;
            });
            label.appendChild(box2);
            const title = w.kind === 'late'
                ? 'Seal ' + w.seq + ': ' + w.added + ' rows arrived in ' + when(w.hour) + ' after it was sealed (sealed late ' + when(w.sealed_at) + ')'
                : 'Seal ' + w.seq + ': ' + (w.what || 'held from the database') + ' (' + when(w.sealed_at) + ')';
            label.appendChild(el('span', null, ' ' + title));
            item.appendChild(label);
            if (w.kind === 'late' && w.rows && w.rows.length) item.appendChild(renderRows(w.rows));
            if (w.kind === 'late' && w.added > (w.rows || []).length) {
                item.appendChild(el('p', 'text-secondary text-sm', 'The first ' + w.rows.length + ' of ' + w.added + ' rows are shown.'));
            }
            box.appendChild(item);
        });
        button.disabled = S.busy || S.chosen.size === 0;
    }

    // The archive (app/core/audit_archive.py summary): when archiving starts, the row window, and the days held.
    function renderArchive(a) {
        const box = byId('integrity-archive');
        if (!box) return;
        box.replaceChildren();
        if (!a || !a.hot_days) { box.hidden = true; return; }
        let text = 'Audit days older than ' + a.hot_days + ' days are moved into compressed daily blocks, each ' +
            'checked against the seals first; nothing is deleted by it. ';
        if (a.starts_on) text += 'Archiving ' + (new Date(a.starts_on) > new Date() ? 'starts' : 'started') + ' on ' +
            when(a.starts_on) + '. ';
        else if (a.read !== false) {
            text += 'Archiving starts ' + a.start_after_days + ' days after the log is first sealed. ';
        }
        if (a.read === false) {
            text += "Which audit days are archived is not known yet: this server has not read the audit log's " +
                'integrity chain through (it does so as it starts).';
        } else text += a.days ? (a.days + ' days are archived, ' + a.oldest_day + ' to ' + a.newest_day + '.')
            : 'No day is archived yet.';
        box.appendChild(el('span', null, text));
        box.hidden = false;
    }

    async function load() {
        if (!byId('integrity-warnings-list')) return;
        try {
            const out = await apiRequest('/settings/audit-integrity/warnings', { silent: true });
            S.warnings = out.warnings || [];
            S.read = out.read !== false;
            S.chosen = new Set([...S.chosen].filter((s) => S.warnings.some((w) => w.seq === s)));
            render();
            renderArchive(out.archive);
        } catch (e) {
            showToast(`The audit log's warnings could not be read: ${e.message}`, 'error');
        }
    }

    async function acknowledge() {
        if (!S.chosen.size || S.busy) return;
        S.busy = true;
        render();
        try {
            const out = await apiRequest('/settings/audit-integrity/acknowledge', {
                method: 'POST', body: JSON.stringify({ seqs: [...S.chosen] }), silent: true,
            });
            showToast('Acknowledged seals ' + (out.acknowledged || []).join(', '), 'success');
            S.chosen.clear();
        } catch (e) {
            showToast(e.message || 'Nothing was acknowledged', 'error');
        } finally {
            S.busy = false;
            await load();
        }
    }

    document.addEventListener('click', (e) => {
        const tab = e.target.closest && e.target.closest('.tab-btn[data-tab="records"]');
        if (tab) load();
        if (e.target.closest && e.target.closest('#integrity-warnings-ack')) acknowledge();
    });

    window.IntegrityWarnings = { load, acknowledge };
})();
