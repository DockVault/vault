/*
 * Settings -> Activity and records: how long records are kept (GET /settings/managed, PUT /settings/managed/{key},
 * POST /settings/managed/changes/{id}/cancel, GET /settings/managed/audit/preview, GET /settings/managed/storage,
 * app/api/managed_settings_router.py), beside the recording levels (static/js/settings-records.js).
 *
 * Each setting shows the value in force and where it comes from (the default, .env, set here, or locked by the
 * deployment); a locked one shows the .env line to change instead of a field, and so does one only .env sets.
 * Each change is saved on its own: the server asks for the password every time (apiRequest prompts for it). A
 * change that deletes records sooner first shows what it would delete (the audit numbers: the preview, as the
 * audit job counts) and asks to confirm; it then waits the deployment's delay, during which any administrator can
 * cancel it from the list of waiting changes. That list is the audit log's integrity chain's (what the pruner
 * applies), never the database's rows: beside a change the database no longer shows waiting it says so, and a
 * change another writer added says it waits for the host operator. The Storage card shows what the audit log and
 * its archive take, what the size cap counts and what the log takes now (a warning from 80 % of the cap on the
 * bytes now, saying when the cap would start deleting and what), the files' volume's free space, the archive's
 * progress and the integrity status. An install that ran before this release is told what it changed, once per browser.
 *
 * Uses app.js's helpers (apiRequest, showToast, showConfirm). Builds the page with createElement and textContent.
 */
(function () {
    'use strict';

    const GROUPS = [
        ['audit_retention', 'Audit log'],
        ['retention', 'Other records'],
        ['audit_integrity', 'Sealing'],
        ['working_records', 'Fixed periods'],
    ];
    const SOURCES = { default: 'Default', env: 'From .env', admin: 'Set here', locked: 'Locked' };
    // The audit numbers the preview counts for.
    const PREVIEW = { audit_max_days: 'max_days', audit_min_days: 'min_days', audit_admin_min_days: 'admin_min_days',
        audit_max_mb: 'max_mb' };
    const BANNER_KEY = 'dockvault.retention.banner.dismissed';
    const S = { data: null, storage: null, integrity: null, capPreview: null, busy: false };

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

    function bytes(n) {
        if (n == null) return 'unknown';
        const units = ['bytes', 'KB', 'MB', 'GB', 'TB'];
        let v = n;
        let i = 0;
        while (v >= 1024 && i < units.length - 1) { v /= 1024; i += 1; }
        return (i ? v.toFixed(1) : String(v)) + ' ' + units[i];
    }

    // A value as the page says it.
    function shown(row, v) {
        if (v == null) return 'not set';
        if (row.kind === 'bool') return v ? 'On' : 'Off';
        if (row.unlimited != null && v === row.unlimited) return row.unit === 'MB' ? 'No cap' : 'No limit';
        if (!row.unit) return String(v);
        return `${v} ${v === 1 && row.unit.endsWith('s') ? row.unit.slice(0, -1) : row.unit}`;   // 1 hour, 1 day
    }

    function rank(row, v) {
        if (row.kind === 'bool') return v ? 1 : 0;
        if (row.unlimited != null && v === row.unlimited) return Infinity;
        return Number(v);
    }

    // Whether changing `from` to `to` deletes records sooner, as the server tells it (settings_registry.is_reduction).
    function isReduction(row, from, to) {
        if (!row.reduction || from == null || to == null) return false;
        return row.reduction === 'lower' ? rank(row, to) < rank(row, from) : rank(row, to) > rank(row, from);
    }

    function envLine(row) {
        if (!row.env) return 'its .env line';
        const v = row.kind === 'bool' ? String(!!row.deployment) : String(row.deployment);
        return `${row.env}=${v}`;
    }

    // ---- the banner ----------------------------------------------------------------------------------------

    function dismissed() {
        try { return window.localStorage.getItem(BANNER_KEY) === '1'; } catch (_) { return false; }
    }

    function renderBanner() {
        const box = byId('retention-banner');
        if (!box) return;
        box.replaceChildren();
        if (!S.storage || !S.storage.existing_install || !S.data || dismissed()) { box.hidden = true; return; }
        const a = S.data.archive || {};
        const admin = (S.data.settings || []).find((r) => r.key === 'audit_admin_min_days');
        let text = 'This release keeps the audit log for good unless you choose otherwise: events stay as rows for ' +
            `${a.hot_days} days, then move into compressed daily blocks`;
        text += a.starts_on ? ` (from ${when(a.starts_on)})` : '';
        text += ', which the Activity page still searches. Nothing is deleted by that.';
        if (admin) text += ` Administration and security events are kept at least ${shown(admin, admin.value)}.`;
        if ((S.data.pending || []).length) {
            text += ' A change that deletes records sooner waits below, and any administrator can cancel it.';
        }
        box.appendChild(el('p', null, text));
        const close = el('button', 'btn btn-outline btn-sm', 'Got it');
        close.type = 'button';
        close.id = 'retention-banner-dismiss';
        close.addEventListener('click', () => {
            try { window.localStorage.setItem(BANNER_KEY, '1'); } catch (_) { /* shown again next time */ }
            box.hidden = true;
        });
        box.appendChild(close);
        box.hidden = false;
    }

    // ---- the settings --------------------------------------------------------------------------------------

    function input(row) {
        const id = `retention-input-${row.key}`;
        if (row.kind === 'bool') {
            const box = el('input');
            box.type = 'checkbox';
            box.id = id;
            box.checked = !!row.value;
            return box;
        }
        const field = el('input', 'form-control retention-number');
        field.type = 'number';
        field.id = id;
        field.step = '1';
        field.min = String(row.unlimited != null && row.unlimited < (row.min ?? 0) ? row.unlimited : (row.min ?? 0));
        if (row.max != null) field.max = String(row.max);
        field.value = String(row.value);
        return field;
    }

    function readInput(row, field) {
        if (row.kind === 'bool') return field.checked;
        const text = field.value.trim();
        if (!/^\d+$/.test(text)) return undefined;
        return parseInt(text, 10);
    }

    function renderRow(row) {
        const item = el('div', 'retention-row');
        item.dataset.key = row.key;
        item.dataset.setting = row.key;   // its level, "New" and the provider's lock (settings-levels.js)
        const head = el('div', 'retention-head');
        const label = el('label', 'retention-label', row.label);
        label.htmlFor = `retention-input-${row.key}`;
        head.appendChild(label);
        const badge = el('span', 'badge retention-source', SOURCES[row.source] || row.source);
        badge.dataset.source = row.source;
        head.appendChild(badge);
        item.appendChild(head);
        if (row.help) item.appendChild(el('p', 'text-secondary text-sm', row.help));
        const canEdit = row.editable === 'admin' && !row.locked;
        if (canEdit) {
            const line = el('div', 'retention-edit');
            const field = input(row);
            line.appendChild(field);
            if (row.kind !== 'bool' && row.unit) line.appendChild(el('span', 'text-secondary', row.unit));
            const save = el('button', 'btn btn-primary btn-sm retention-save', 'Save');
            save.type = 'button';
            save.disabled = true;
            const changedNow = () => {
                const v = readInput(row, field);
                save.disabled = S.busy || v === undefined || v === row.value;
            };
            field.addEventListener('input', changedNow);
            field.addEventListener('change', changedNow);
            save.addEventListener('click', () => change(row, readInput(row, field)));
            line.appendChild(save);
            if (row.source === 'admin') {
                const back = el('button', 'btn btn-outline btn-sm retention-reset',
                    `Use the deployment's value (${shown(row, row.deployment)})`);
                back.type = 'button';
                back.addEventListener('click', () => change(row, null));
                line.appendChild(back);
            }
            item.appendChild(line);
            const notes = [];
            if (row.unlimited != null && row.kind === 'int') {
                notes.push(`${row.unlimited} means ${shown(row, row.unlimited).toLowerCase()}.`);
            }
            if (row.floor != null) {
                notes.push(`The deployment keeps it at least ${shown(row, row.floor)}` +
                    (row.floor_env ? ` (${row.floor_env} in .env).` : '.'));
            }
            if (row.ceiling != null) {
                notes.push(`The deployment allows at most ${shown(row, row.ceiling)}` +
                    (row.ceiling_env ? ` (${row.ceiling_env} in .env).` : '.'));
            }
            if (row.clamped) notes.push('The value set here is outside those bounds, so the bound is in force.');
            if (notes.length) item.appendChild(el('p', 'text-secondary text-sm', notes.join(' ')));
        } else {
            const value = el('p', 'retention-value');
            value.appendChild(el('strong', null, shown(row, row.value)));
            item.appendChild(value);
            let why;
            if (row.locked) {
                why = `Set by your provider and locked (SETTINGS_LOCKED_KEYS). Whoever runs the vault changes it: ` +
                    `${envLine(row)} in .env, then docker compose up -d.`;
            } else if (row.editable === 'env_only') {
                why = `Set in .env: ${envLine(row)}. Change it there, then run docker compose up -d.`;
            } else {
                why = 'Fixed: the same on every install.';
            }
            const p = el('p', 'text-secondary text-sm retention-env', why);
            item.appendChild(p);
        }
        return item;
    }

    function renderSettings() {
        const box = byId('retention-groups');
        if (!box || !S.data) return;
        box.replaceChildren();
        const rows = S.data.settings || [];
        GROUPS.forEach(([group, title]) => {
            const mine = rows.filter((r) => r.group === group);
            if (!mine.length) return;
            const section = el('section', 'retention-group');
            section.dataset.group = group;
            section.dataset.settingGroup = '';   // hidden while every setting in it is (settings-levels.js)
            section.appendChild(el('h4', null, title));
            mine.forEach((r) => section.appendChild(renderRow(r)));
            box.appendChild(section);
        });
    }

    function rowOf(key) {
        return (S.data && S.data.settings || []).find((r) => r.key === key) || { key, label: key, kind: 'int' };
    }

    function renderPending() {
        const box = byId('retention-pending');
        if (!box || !S.data) return;
        box.replaceChildren();
        const pending = S.data.pending || [];
        const chain = S.data.pending_chain || {};
        if (chain.read === false) {
            box.appendChild(el('p', 'text-secondary retention-pending-chain',
                'The changes waiting are read from the audit log\'s integrity chain, which this server has not ' +
                'read yet; no change applies until it has.'));
        } else if (chain.stopped) {
            box.appendChild(el('p', 'text-secondary retention-pending-chain',
                `Sealing is stopped just now (${chain.stopped}): no change applies until it runs again.`));
        }
        if (!pending.length) {
            if (chain.read !== false) box.appendChild(el('p', 'text-secondary', 'No change is waiting.'));
            return;
        }
        // The list is the audit log's integrity chain's (what the pruner acts on), never the database's rows.
        pending.forEach((c) => {
            const row = rowOf(c.key);
            const item = el('div', 'retention-change');
            item.dataset.change = c.id;
            item.dataset.request = String(c.request_seq);
            const to = c.setting == null ? `the deployment's value (${shown(row, c.new)})` : shown(row, c.new);
            item.appendChild(el('p', null, `${c.label}: ${shown(row, c.old)} to ${to}.`));
            const asked = `Asked by ${c.requested_by || 'an administrator'} on ${when(c.requested_at)}`;
            let text;
            if (c.applied_by != null) {
                const counts = c.counts_from ? `from ${when(c.counts_from)}`
                    : `once acknowledged, and no earlier than ${when(c.effective_at)}`;
                text = `${asked}. Applied by seal ${c.applied_by}, which another writer added to the audit log and ` +
                    `which waits for the host operator (dockvault.py audit acknowledge); its value counts ${counts}. ` +
                    'It can no longer be cancelled: to keep the current value, change the setting back.';
            } else if (c.waits_for_host) {
                text = `${asked}. Another writer added this request to the audit log: it waits for the host ` +
                    'operator (dockvault.py audit acknowledge), and applies no earlier than ' +
                    `${when(c.effective_at)} unless an administrator cancels it.`;
            } else {
                text = `${asked}; applies on ${when(c.effective_at)} unless an administrator cancels it.`;
            }
            item.appendChild(el('p', 'text-secondary text-sm', text));
            if (c.database) {
                const said = c.database === 'missing' ? 'holds no row of this change' : `marks this change ${c.database}`;
                // While sealing is stopped the server offers no cancel for it (it already does not apply).
                const then = c.cancellable ? 'Cancel it here to record the cancel in the audit log now.'
                    : 'The audit log records its end once sealing runs again.';
                item.appendChild(el('p', 'text-secondary text-sm retention-change-database',
                    `The database ${said}: it does not apply while the database says so. ${then}`));
            }
            if (c.cancellable) {
                const cancel = el('button', 'btn btn-outline btn-sm retention-cancel', 'Cancel this change');
                cancel.type = 'button';
                cancel.disabled = S.busy;
                cancel.addEventListener('click', () => cancelChange(c));
                item.appendChild(cancel);
            }
            box.appendChild(item);
        });
    }

    // What deleting sooner would delete, as the audit job counts it (the preview route), in one sentence.
    async function previewText(row, value) {
        const param = PREVIEW[row.key];
        if (!param) return '';
        let p;
        try {
            p = await apiRequest(`/settings/managed/audit/preview?${param}=${encodeURIComponent(value)}`,
                { silent: true });
        } catch (e) {
            return ` What it would delete could not be counted just now (${e.message || 'no answer'}).`;
        }
        const archived = p.archived || { by_age: { rows: 0 }, by_size: { rows: 0 } };
        const rows = p.by_age.rows + p.by_size.rows + archived.by_age.rows + archived.by_size.rows;
        const size = p.by_age.bytes + p.by_size.bytes + archived.by_age.bytes + archived.by_size.bytes;
        let text = ` If it applied now, it would delete ${rows} events (${bytes(size)}): ` +
            `${p.by_age.rows + archived.by_age.rows} for their age and ${p.by_size.rows + archived.by_size.rows} ` +
            'for the size cap.';
        if (archived.by_age.rows + archived.by_size.rows) {
            text += ` ${archived.by_age.rows + archived.by_size.rows} of them are archived (an estimate in whole hours).`;
        }
        if (p.cap_met === false) {
            text += ' The size cap cannot be met without administration and security events, which it never ' +
                'deletes: administrators are warned instead.';
        }
        return text;
    }

    async function change(row, value) {
        if (S.busy) return;
        if (value === undefined) {
            showToast(`${row.label}: enter a whole number`, 'error');
            return;
        }
        const target = value == null ? row.deployment : value;
        S.busy = true;
        try {
            if (isReduction(row, row.value, target)) {
                const delay = S.data.reduction_delay_days;
                let message = `${row.label}: ${shown(row, row.value)} to ${shown(row, target)}. This deletes records ` +
                    `sooner, so it waits ${delay} days before it applies, and any administrator can cancel it ` +
                    'meanwhile. Every administrator is told.';
                message += await previewText(row, target);
                const ok = await showConfirm(message, 'Delete records sooner?', null, 'Ask for this change');
                if (!ok) return;
            }
            const out = await apiRequest(`/settings/managed/${encodeURIComponent(row.key)}`, {
                method: 'PUT', body: JSON.stringify({ value }), silent: true,
            });
            if (out.status === 'pending' && out.change) {
                showToast(`${row.label} changes on ${when(out.change.effective_at)} unless it is cancelled`, 'success');
            } else {
                showToast(`${row.label} is saved`, 'success');
            }
        } catch (e) {
            showToast(e.message || `${row.label} was not changed`, 'error');
        } finally {
            S.busy = false;
            await load();
        }
    }

    async function cancelChange(c) {
        if (S.busy) return;
        S.busy = true;
        renderPending();
        try {
            await apiRequest(`/settings/managed/changes/${encodeURIComponent(c.id)}/cancel`, { method: 'POST', silent: true });
            showToast(`The change of ${c.label} is cancelled`, 'success');
        } catch (e) {
            showToast(e.message || 'The change was not cancelled', 'error');
        } finally {
            S.busy = false;
            await load();
        }
    }

    // ---- storage, the archive and integrity ---------------------------------------------------------------

    // The warning from 80 % of the size cap, on the bytes now: when the cap would start deleting, and what.
    function capWarning(cap, pct) {
        let text = `The audit log is at ${pct} % of its size cap.`;
        if (!cap.over_from) {
            if (cap.now_bytes >= cap.cap_bytes) {
                // At or over the cap with no date: what the cap counts has not passed it on what is sealed now.
                return `${text} The cap does not count all of it yet (rows count once they are sealed, and growth ` +
                    'only after the wait before a change that deletes sooner), so nothing is deleted for now; once ' +
                    'its count passes the cap, the oldest events are deleted, except administration and security ' +
                    'events, unless the cap is raised or the hold is turned on.';
            }
            return `${text} Once it is reached, the oldest events are deleted, except administration and security ` +
                'events.';
        }
        text += ` From ${when(cap.over_from)} at the earliest, the size cap deletes the oldest events, except ` +
            'administration and security events, unless the cap is raised or the hold is turned on.';
        const p = S.capPreview;
        if (p && p.by_size) {
            const archived = (p.archived && p.archived.by_size) || { rows: 0, bytes: 0 };
            text += ` As things stand it would delete ${p.by_size.rows + archived.rows} events ` +
                `(${bytes(p.by_size.bytes + archived.bytes)}).`;
        }
        return text;
    }

    function renderStorage() {
        const box = byId('retention-storage');
        if (!box) return;
        box.replaceChildren();
        const s = S.storage;
        if (!s) return;
        const list = el('ul', 'retention-storage-list');
        const add = (text, cls) => list.appendChild(el('li', cls || null, text));
        add(`Audit rows: ${s.rows.exact ? '' : 'about '}${s.rows.count}` +
            (s.rows.bytes != null ? `, taking ${bytes(s.rows.bytes)} with their indexes.` : '.'));
        add(`Archive: ${s.archive.blocks} blocks holding ${s.archive.rows} events, ${bytes(s.archive.bytes)} ` +
            'compressed' + (s.archive.table_bytes != null ? ` (${bytes(s.archive.table_bytes)} on disk).` : '.'));
        if (s.cap) {
            if (s.cap.counted_bytes == null) {
                add(`Size cap: ${bytes(s.cap.cap_bytes)}; what it counts is known once the log is sealed.`);
            } else {
                const pct = Math.round(s.cap.fraction * 100);
                add(`Size cap: ${bytes(s.cap.cap_bytes)}. The audit log takes ${bytes(s.cap.now_bytes)} of it now ` +
                    `(${pct} %); the cap counts ${bytes(s.cap.counted_bytes)} so far, since growth counts only after ` +
                    'the wait before a change that deletes sooner.');
                if (s.cap.warn) add(capWarning(s.cap, pct), 'text-warning retention-cap-warning');
            }
        }
        if (s.storage_volume) {
            add(`The files' volume: ${bytes(s.storage_volume.free)} free of ${bytes(s.storage_volume.total)}.`);
        }
        add("The database's volume is in another container, so its free space is not known here; " +
            'dockvault.py audit unarchive checks it before it restores archived days.', 'text-secondary');
        box.appendChild(list);
        const a = S.data && S.data.archive;
        if (a && a.hot_days) {
            let text = `Days older than ${a.hot_days} days move into compressed daily blocks. `;
            if (a.starts_on) {
                text += `Archiving ${new Date(a.starts_on) > new Date() ? 'starts' : 'started'} on ${when(a.starts_on)}. `;
            }
            text += a.days ? `${a.days} days are archived, ${a.oldest_day} to ${a.newest_day}.` : 'No day is archived yet.';
            if (s.rows.oldest) text += ` The oldest day still kept as rows is ${s.rows.oldest.slice(0, 10)}.`;
            box.appendChild(el('p', 'text-sm retention-archive', text));
        }
        const i = S.integrity;
        if (i) {
            const failures = (i.failures || []).length;
            let text = `Integrity: ${failures ? `${failures} failures for the server's operator` : (i.outcome || 'not started')}`;
            if (i.sealed_through) text += `; sealed through ${when(i.sealed_through)}`;
            if (i.checked_at) text += `; last checked ${when(i.checked_at)}`;
            box.appendChild(el('p', 'text-sm retention-integrity' + (failures ? ' text-warning' : ''), text + '.'));
        }
    }

    function render() {
        renderBanner();
        renderSettings();
        renderPending();
        renderStorage();
    }

    async function load() {
        if (!byId('retention-groups')) return;
        try {
            S.data = await apiRequest('/settings/managed', { silent: true });
        } catch (e) {
            showToast(`The retention settings could not be read: ${e.message}`, 'error');
            return;
        }
        try { S.storage = await apiRequest('/settings/managed/storage', { silent: true }); } catch (_) { S.storage = null; }
        // Over the cap now: what the cap would delete once that counts (the preview with the bytes now).
        S.capPreview = null;
        if (S.storage && S.storage.cap && S.storage.cap.over_from) {
            try {
                S.capPreview = await apiRequest('/settings/managed/audit/preview?bytes_now=true', { silent: true });
            } catch (_) { S.capPreview = null; }
        }
        try { S.integrity = await apiRequest('/activity/integrity', { silent: true }); } catch (_) { S.integrity = null; }
        render();
    }

    document.addEventListener('click', (e) => {
        const tab = e.target.closest && e.target.closest('.tab-btn[data-tab="records"]');
        if (tab) load();
    });

    window.RetentionSettings = { load, isReduction, shown };
})();
