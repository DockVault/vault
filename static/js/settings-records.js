/*
 * Settings -> Activity and records: what the audit log records of the personal data attached to events
 * (GET/PUT /settings/recording, app/api/recording_levels_router.py).
 *
 * One row per kind of data: a choice of level, the .env limit, and what a sample row records at the chosen
 * level. A level above the limit is shown disabled with the .env line that would allow it. The presets fill
 * the rows within the limits. Saving is its own action (never "Save All Changes"): the server asks for the
 * password every time, which apiRequest (app.js) prompts for and retries with. The versions saved are listed
 * below, newest first.
 *
 * Uses app.js's helpers (apiRequest, showToast). Builds the page with createElement and textContent only.
 */
(function () {
    'use strict';

    const LEVEL_WORDS = { none: 'Not recorded', fingerprint: 'Fingerprint', shortened: 'Shortened', full: 'Full' };
    const REASONS = {
        initial: 'First version (what earlier releases recorded)',
        admin: 'Saved by an administrator',
        limit: 'Brought within a lowered .env limit',
        locked: 'Set to the .env limits (locked by the deployment)',
    };
    const S = { data: null, chosen: {}, loading: false };

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function byId(id) { return document.getElementById(id); }

    function changed() {
        if (!S.data) return false;
        return S.data.kinds.some((k) => S.chosen[k.key] !== k.level);
    }

    function sampleFor(kind, level) {
        const choice = kind.choices.find((c) => c.level === level);
        return choice && choice.sample != null ? choice.sample : 'Not recorded';
    }

    function renderPresets() {
        const box = byId('recording-levels-presets');
        if (!box) return;
        box.replaceChildren();
        box.appendChild(el('span', 'text-secondary text-sm', 'Presets:'));
        (S.data.presets || []).forEach((preset) => {
            const b = el('button', 'btn btn-outline btn-sm', preset.label);
            b.type = 'button';
            b.disabled = !!S.data.locked;
            b.title = Object.keys(preset.levels).map((k) => `${k}: ${LEVEL_WORDS[preset.levels[k]]}`).join(', ');
            b.addEventListener('click', () => {
                S.chosen = Object.assign({}, preset.levels);
                renderTable();
            });
            box.appendChild(b);
        });
    }

    function renderTable() {
        const body = document.querySelector('#recording-levels-table tbody');
        if (!body || !S.data) return;
        body.replaceChildren();
        S.data.kinds.forEach((kind) => {
            const tr = el('tr');
            tr.dataset.kind = kind.key;
            tr.appendChild(el('th', null, kind.label)).setAttribute('scope', 'row');
            const levels = el('td');
            const group = el('div', 'recording-choices');
            group.setAttribute('role', 'radiogroup');
            group.setAttribute('aria-label', kind.label);
            kind.choices.forEach((choice) => {
                const label = el('label', 'recording-choice' + (choice.allowed ? '' : ' is-disabled'));
                const input = el('input');
                input.type = 'radio';
                input.name = `recording-level-${kind.key}`;
                input.value = choice.level;
                input.checked = S.chosen[kind.key] === choice.level;
                input.disabled = !choice.allowed;
                input.addEventListener('change', () => { S.chosen[kind.key] = choice.level; renderTable(); });
                label.appendChild(input);
                label.appendChild(el('span', null, ' ' + choice.label));
                if (choice.env_line) {
                    const hint = `Add ${choice.env_line} to .env, then run docker compose up -d`;
                    label.title = hint;
                    label.appendChild(el('span', 'recording-env-line text-secondary text-sm', ` (${hint})`));
                }
                group.appendChild(label);
            });
            levels.appendChild(group);
            tr.appendChild(levels);
            const limit = el('td');
            limit.appendChild(el('span', null, LEVEL_WORDS[kind.limit] || kind.limit));
            limit.appendChild(el('span', 'text-secondary text-sm',
                kind.limit_source === 'env' ? ` (${kind.env} in .env)` : ' (default)'));
            tr.appendChild(limit);
            tr.appendChild(el('td', 'act-mono', sampleFor(kind, S.chosen[kind.key])));
            body.appendChild(tr);
        });
        const save = byId('recording-levels-save');
        if (save) save.disabled = !!S.data.locked || !changed() || S.loading;
        renderNote();
    }

    function renderNote() {
        const note = byId('recording-levels-note');
        if (!note) return;
        const parts = [];
        if (S.data.locked) {
            parts.push(`The deployment sets these levels (${S.data.lock_line}): each is its .env limit.`);
        }
        if (S.data.ip_full_days > 0) {
            parts.push(`An address recorded in full is shortened to its network once its row is ${S.data.ip_full_days} ` +
                `day${S.data.ip_full_days === 1 ? '' : 's'} old, and in a day the archive holds once the whole ` +
                'day is (up to a day later; "Keep full addresses in audit rows for", under Retention).');
        }
        if (S.data.sftp && !S.data.sftp.same_version) {
            parts.push(`Levels that record less than earlier releases cannot be saved yet: ${S.data.sftp.explain}`);
        }
        parts.push('A fingerprint hides a name from someone who reads the database without the .env file; ' +
            'anyone who holds that file (it is in the backups) can test guesses of a short or common name. ' +
            'Any administrator can also test a guess of a name typed at a failed sign-in, by searching for it.');
        note.textContent = parts.join(' ');
        note.hidden = false;
    }

    function renderHistory() {
        const list = byId('recording-levels-history');
        if (!list) return;
        list.replaceChildren();
        (S.data.history || []).forEach((v) => {
            const li = el('li', 'recording-history-item');
            const when = v.at ? new Date(v.at).toLocaleString() : '';
            li.appendChild(el('strong', null, `Version ${v.version}`));
            li.appendChild(el('span', 'text-secondary', ` · ${when} · ${v.by || 'unknown'} · ${REASONS[v.reason] || v.reason}`));
            li.appendChild(el('div', 'text-sm', Object.keys(v.levels).map((k) => {
                const kind = S.data.kinds.find((x) => x.key === k);
                return `${kind ? kind.label : k}: ${LEVEL_WORDS[v.levels[k]] || v.levels[k]}`;
            }).join(' · ')));
            list.appendChild(li);
        });
    }

    function show(data) {
        S.data = data;
        S.chosen = {};
        data.kinds.forEach((k) => { S.chosen[k.key] = k.level; });
        renderPresets();
        renderTable();
        renderHistory();
    }

    async function load() {
        if (!byId('recording-levels-table')) return;
        try {
            show(await apiRequest('/settings/recording', { silent: true }));
        } catch (e) {
            showToast(`The recording levels could not be read: ${e.message}`, 'error');
        }
        loadNotice();
    }

    // The legal basis and the contact the public notice states (general settings, saved on their own).
    async function loadNotice() {
        try {
            const all = await apiRequest('/settings', { silent: true });
            byId('recording-notice-basis').value = all.recording_notice_legal_basis || '';
            byId('recording-notice-contact').value = all.recording_notice_contact || '';
        } catch (_) { /* left empty */ }
    }

    async function saveNotice() {
        const body = {
            recording_notice_legal_basis: byId('recording-notice-basis').value.trim(),
            recording_notice_contact: byId('recording-notice-contact').value.trim(),
        };
        try {
            await apiRequest('/settings', { method: 'PUT', body: JSON.stringify(body), silent: true });
            showToast('The notice is saved', 'success');
        } catch (e) {
            showToast(e.message || 'The notice was not saved', 'error');
        }
    }

    async function save() {
        if (!S.data || !changed()) return;
        S.loading = true;
        renderTable();
        try {
            const out = await apiRequest('/settings/recording', {
                method: 'PUT', body: JSON.stringify({ levels: S.chosen }), silent: true,
            });
            show(out);
            showToast(out.status === 'saved' ? `Recording levels saved as version ${out.version}`
                : 'The recording levels were already these', 'success');
            if (out.status === 'saved' && window.ValueRemoval) window.ValueRemoval.levelsChanged();
        } catch (e) {
            showToast(e.message || 'The recording levels were not saved', 'error');
        } finally {
            S.loading = false;
            if (S.data) renderTable();
        }
    }

    document.addEventListener('click', (e) => {
        const tab = e.target.closest && e.target.closest('.tab-btn[data-tab="records"]');
        if (tab) load();
        if (e.target.closest && e.target.closest('#recording-levels-save')) save();
        if (e.target.closest && e.target.closest('#recording-notice-save')) saveNotice();
    });

    window.RecordingLevels = { load, save };
})();
