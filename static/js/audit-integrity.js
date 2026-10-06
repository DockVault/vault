/*
 * The audit log's integrity status on the Activity page (GET /activity/integrity,
 * app/api/audit_integrity_router.py): the chain's head, the line to keep somewhere else, how far the hours
 * are sealed, the last check, and every failure and warning not yet acknowledged.
 *
 * Shown under the Activity page's header each time the page opens. Uses app.js's apiRequest; builds the
 * strip with createElement and textContent only.
 */
(function () {
    'use strict';

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function when(text) {
        if (!text) return '';
        const d = new Date(text);
        return isNaN(d.getTime()) ? text : d.toLocaleString();
    }

    function render(box, s) {
        box.replaceChildren();
        const failed = (s.failures || []).length > 0;
        const warned = (s.warnings || []).length > 0;
        const stopped = s.stopped || null;
        box.dataset.state = (failed || stopped) ? 'failed' : (warned ? 'warning' : (s.head ? 'clean' : 'waiting'));
        const line = el('div', 'act-integrity-line');
        let words;
        if (stopped) words = 'Sealing of the audit log is stopped until the host operator looks at it.';
        else if (!s.head) words = 'The audit log has not been sealed yet. The first seal is written a few minutes after the server starts.';
        else if (failed) words = 'The audit log’s integrity check found a problem.';
        else if (warned) words = 'The audit log is sealed; some events need a look.';
        else words = 'The audit log is sealed' + (s.sealed_through ? ' through ' + when(s.sealed_through) : '') + '.';
        line.appendChild(el('strong', null, words));
        if (s.checked_at) line.appendChild(el('span', 'text-secondary', ' Last checked ' + when(s.checked_at) + '.'));
        box.appendChild(line);
        if (s.head) {
            const head = el('div', 'act-integrity-head');
            head.appendChild(el('span', 'text-secondary', 'Head: '));
            const code = el('code', 'act-integrity-code', s.head);
            code.title = 'Keep this line somewhere else (a ticket, a printout): a later change to the history before it then shows.';
            head.appendChild(code);
            const copy = el('button', 'btn btn-outline btn-sm', 'Copy');
            copy.type = 'button';
            copy.addEventListener('click', () => {
                if (navigator.clipboard) navigator.clipboard.writeText(s.head).catch(() => {});
            });
            head.appendChild(copy);
            box.appendChild(head);
        }
        if (stopped) box.appendChild(el('div', 'act-integrity-failure', 'stopped: ' + (stopped.kind || '') + ': ' +
            (stopped.message || '')));
        [['failures', 'act-integrity-failure'], ['warnings', 'act-integrity-warning']].forEach(([key, cls]) => {
            (s[key] || []).forEach((f) => {
                box.appendChild(el('div', cls, f.kind + ': ' + (f.message || '') +
                    (f.first_seen ? ' (since ' + when(f.first_seen) + ')' : '')));
            });
        });
        if (s.key_shared) {
            box.appendChild(el('div', 'text-secondary text-sm',
                'The chain’s key is derived from ENCRYPTION_KEY; set AUDIT_CHAIN_KEY to give it a key of its own.'));
        }
        if (s.claim) box.appendChild(el('div', 'text-secondary text-sm', s.claim));
        box.hidden = false;
    }

    async function load() {
        const box = document.getElementById('act-integrity');
        if (!box || typeof apiRequest !== 'function') return;
        try {
            render(box, await apiRequest('/activity/integrity', { silent: true }));
        } catch (err) {
            box.hidden = true;
        }
    }

    const init = window.initActivity;
    if (typeof init === 'function') {
        window.initActivity = async function () {
            const out = await init.apply(this, arguments);
            const section = document.getElementById('activity-section');
            if (section && section.classList.contains('active')) load();
            return out;
        };
    }
    const reset = window.resetActivity;
    if (typeof reset === 'function') {
        window.resetActivity = function () {
            const box = document.getElementById('act-integrity');
            if (box) { box.replaceChildren(); box.hidden = true; }
            return reset.apply(this, arguments);
        };
    }
}());
