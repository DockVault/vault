/* Activity page (administrators): an Overview of the last 24 hours, and Events, the audit log filtered
 * by every kind of event, channel, status, user, address, text and time, a page at a time.
 *
 * Uses app.js's helpers (apiRequest, _el, formatServerTime, auditStatusBadge, openModal). Every value
 * from the server is written with textContent; nothing here builds markup from data. */
(function () {
    'use strict';

    const CHANNEL_LABELS = {
        web: 'Web', sftp: 'SFTP', public_link: 'Public link', upload_link: 'Upload link',
        device_sync: 'Device sync', unknown: 'Not recorded',
    };
    const STATUS_LABELS = {
        success: 'Succeeded', authorized: 'Allowed', failure: 'Failed', failed: 'Failed',
        error: 'Failed', refused: 'Refused', active: 'Active', revoked: 'Revoked', unconfirmed: 'Unconfirmed',
    };

    const state = { catalog: null, events: [], cursor: null, total: null, loading: false, wired: false, seq: 0, params: new URLSearchParams() };

    const $ = (id) => document.getElementById(id);

    function channelLabel(c) { return CHANNEL_LABELS[c || 'unknown'] || c; }
    function statusLabel(s) { return STATUS_LABELS[s] || s || '—'; }

    // ---- filters --------------------------------------------------------------------------------

    function checkedValues(listId) {
        return Array.from(document.querySelectorAll(`#${listId} input[type=checkbox]:checked`)).map(i => i.value);
    }

    function summarisePick(listId, valueId, labels) {
        const picked = checkedValues(listId);
        const el = $(valueId);
        if (!el) return;
        if (!picked.length) { el.textContent = 'All'; return; }
        el.textContent = picked.length === 1 ? (labels[picked[0]] || picked[0]) : `${picked.length} chosen`;
    }

    function buildPickList(listId, items, onChange) {
        const host = $(listId);
        if (!host) return;
        host.replaceChildren();
        items.forEach(({ value, label }) => {
            const row = _el('label', 'activity-pick-item');
            const box = document.createElement('input');
            box.type = 'checkbox';
            box.value = value;
            box.addEventListener('change', onChange);
            row.append(box, _el('span', '', label));
            host.appendChild(row);
        });
    }

    function toIso(localValue) {
        // datetime-local is the viewer's local time; the server wants an instant.
        if (!localValue) return null;
        const d = new Date(localValue);
        return isNaN(d) ? null : d.toISOString();
    }

    function filterParams() {
        const p = new URLSearchParams();
        checkedValues('activity-category-list').forEach(v => p.append('category', v));
        checkedValues('activity-channel-list').forEach(v => p.append('channel', v));
        const status = $('activity-status').value;
        if (status) p.append('status', status);
        [['user', 'activity-user'], ['ip', 'activity-ip'], ['q', 'activity-q']].forEach(([k, id]) => {
            const v = ($(id).value || '').trim();
            if (v) p.append(k, v);
        });
        const from = toIso($('activity-from').value), to = toIso($('activity-to').value);
        if (from) p.append('from_date', from);
        if (to) p.append('to_date', to);
        return p;
    }

    // ---- events ---------------------------------------------------------------------------------

    function whenCell(ts) {
        const d = ts ? new Date(ts) : null;
        const cell = _el('span', 'activity-when', formatServerTime(ts));
        if (d && !isNaN(d)) cell.title = d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, ' UTC');
        return cell;
    }

    function eventCell(ev) {
        const wrap = _el('div', 'activity-event');
        wrap.appendChild(_el('span', 'activity-event-label', ev.label));
        const cat = state.catalog && state.catalog.categories.find(c => c.key === ev.category);
        wrap.appendChild(_el('span', 'activity-event-cat text-tertiary text-xs', cat ? cat.label : ev.category));
        return wrap;
    }

    function whoText(ev) {
        // An anonymous link visitor has no account; say what they had instead of "unknown".
        const anonymous = ev.channel === 'public_link' || ev.channel === 'upload_link';
        const who = ev.username || (anonymous ? 'Someone with the link' : 'Unknown');
        return ev.temp_credential_id ? `${who} (temporary credential)` : who;
    }

    function statusBadge(ev) {
        return _el('span', 'badge badge-' + auditStatusBadge(ev.status), statusLabel(ev.status));
    }

    function renderRows(append) {
        const body = $('activity-rows'), cards = $('activity-cards');
        if (!append) { body.replaceChildren(); cards.replaceChildren(); }
        const start = append ? body.children.length : 0;
        state.events.slice(start).forEach((ev, i) => {
            const index = start + i;
            const tr = document.createElement('tr');
            tr.className = 'activity-row' + (auditStatusBadge(ev.status) === 'danger' ? ' is-bad' : '');
            tr.tabIndex = 0;
            const cells = [whenCell(ev.timestamp), eventCell(ev), _el('span', '', whoText(ev)),
                _el('span', '', channelLabel(ev.channel)), statusBadge(ev), _el('span', 'activity-ip', ev.ip_address || '—')];
            cells.forEach(c => { const td = document.createElement('td'); td.appendChild(c); tr.appendChild(td); });
            tr.addEventListener('click', () => openEvent(index));
            tr.addEventListener('keydown', (e) => { if (e.key === 'Enter') openEvent(index); });
            body.appendChild(tr);

            const card = _el('button', 'activity-card' + (auditStatusBadge(ev.status) === 'danger' ? ' is-bad' : ''));
            card.type = 'button';
            const head = _el('div', 'activity-card-head');
            head.append(_el('span', 'activity-event-label', ev.label), statusBadge(ev));
            const meta = _el('div', 'activity-card-meta text-secondary text-sm');
            meta.textContent = [whoText(ev), channelLabel(ev.channel), ev.ip_address].filter(Boolean).join(' · ');
            card.append(head, meta, whenCell(ev.timestamp));
            card.addEventListener('click', () => openEvent(index));
            cards.appendChild(card);
        });
        const empty = !state.events.length;
        if (empty) {
            const tr = document.createElement('tr');
            const td = document.createElement('td');
            td.colSpan = 6;
            td.className = 'text-secondary text-center py-xl';
            td.textContent = 'No events match these filters.';
            tr.appendChild(td);
            body.appendChild(tr);
            cards.appendChild(_el('p', 'text-secondary text-center py-xl', 'No events match these filters.'));
        }
        const active = Array.from(state.params.keys()).length;
        $('activity-filters-toggle').textContent = active ? `Filters (${active})` : 'Filters';
        const shown = state.events.length;
        const summary = state.total == null ? `${shown} shown`
            : `Showing ${shown.toLocaleString()} of ${state.total.toLocaleString()} ${state.total === 1 ? 'event' : 'events'}`;
        $('activity-summary').textContent = empty ? '' : summary;
        $('activity-more').hidden = !state.cursor;
    }

    // A new search replaces any still in flight; its reply is the one shown. "Load more" continues the
    // results on screen with the filters they were searched with, not whatever the fields now hold.
    async function search(append) {
        if (append && (state.loading || !state.cursor)) return;
        const seq = ++state.seq;
        state.loading = true;
        const btn = $('activity-more');
        btn.disabled = true;
        try {
            if (!append) state.params = filterParams();
            const p = new URLSearchParams(state.params);
            p.set('limit', '50');
            if (append) p.set('cursor', state.cursor);
            const data = await apiRequest('/activity/events?' + p.toString());
            if (seq !== state.seq) return;          // a newer search has replaced this one
            if (append) {
                state.events = state.events.concat(data.events || []);
            } else {
                state.events = data.events || [];
                state.total = data.total;
            }
            state.cursor = data.next_cursor || null;
            renderRows(append);
        } catch (e) {
            if (seq !== state.seq) return;
            $('activity-summary').textContent = 'The events could not be loaded: ' + ((e && e.message) || 'unknown error');
        } finally {
            if (seq === state.seq) {
                state.loading = false;
                btn.disabled = false;
            }
        }
    }

    function openEvent(index) {
        const ev = state.events[index];
        if (!ev) return;
        $('activity-event-title').textContent = ev.label;
        const dl = $('activity-event-fields');
        dl.replaceChildren();
        const d = ev.timestamp ? new Date(ev.timestamp) : null;
        const rows = [
            ['When', formatServerTime(ev.timestamp)],
            ['When (UTC)', d && !isNaN(d) ? d.toISOString().replace('T', ' ').replace(/\.\d+Z$/, '') : null],
            ['Who', whoText(ev)],
            ['Status', statusLabel(ev.status)],
            ['Channel', channelLabel(ev.channel)],
            ['IP address', ev.ip_address],
            ['Request', ev.method && ev.endpoint ? `${ev.method} ${ev.endpoint}` : ev.endpoint],
            ['Browser or client', ev.user_agent],
            ['Affected', ev.resource_type ? `${ev.resource_type} ${ev.resource_id || ''}`.trim() : null],
            ['Error', ev.error_message],
            ['Stored as', ev.action],
        ];
        rows.forEach(([k, v]) => {
            if (v == null || v === '') return;
            dl.append(_el('dt', '', k), _el('dd', '', String(v)));
        });
        const pre = $('activity-event-details');
        const hasDetails = ev.details && typeof ev.details === 'object' && Object.keys(ev.details).length;
        pre.hidden = !hasDetails;
        pre.textContent = hasDetails ? JSON.stringify(ev.details, null, 2) : '';
        openModal('activity-event-modal');
    }

    // ---- overview -------------------------------------------------------------------------------

    async function countOf(params) {
        params.set('limit', '1');
        const data = await apiRequest('/activity/events?' + params.toString());
        return { total: data.total || 0, first: (data.events || [])[0] || null };
    }

    async function loadOverview() {
        const since = new Date(Date.now() - 24 * 3600 * 1000).toISOString();
        const tiles = [
            ['Events', new URLSearchParams({ from_date: since })],
            ['Failed sign-ins', new URLSearchParams({ from_date: since, category: 'sign_in', status: 'failed' })],
            ['Refusals and denials', new URLSearchParams({ from_date: since, category: 'security' })],
            ['Failed or refused', new URLSearchParams({ from_date: since, status: 'failed' })],
        ];
        const host = $('activity-stats');
        host.replaceChildren();
        await Promise.all(tiles.map(async ([label, params], i) => {
            const tile = _el('button', 'activity-stat');
            tile.type = 'button';
            tile.style.order = String(i);
            const num = _el('span', 'activity-stat-num', '…');
            tile.append(num, _el('span', 'activity-stat-label', label));
            tile.addEventListener('click', () => showEventsWith(params));
            host.appendChild(tile);
            try { num.textContent = (await countOf(new URLSearchParams(params))).total.toLocaleString(); }
            catch (e) { num.textContent = '—'; }
        }));

        const recent = $('activity-overview-recent');
        recent.replaceChildren();
        try {
            const p = new URLSearchParams({ from_date: since, status: 'failed', limit: '8' });
            const data = await apiRequest('/activity/events?' + p.toString());
            const list = data.events || [];
            if (!list.length) { recent.appendChild(_el('p', 'text-secondary', 'Nothing failed or was refused in the last 24 hours.')); return; }
            list.forEach(ev => {
                const row = _el('div', 'activity-recent-row');
                row.append(_el('span', 'activity-event-label', ev.label),
                    _el('span', 'text-secondary text-sm', [whoText(ev), ev.ip_address].filter(Boolean).join(' · ')),
                    whenCell(ev.timestamp));
                recent.appendChild(row);
            });
        } catch (e) {
            recent.appendChild(_el('p', 'text-secondary', 'Recent failures could not be loaded.'));
        }
    }

    // Jump from an Overview tile to Events with that tile's filters applied.
    function showEventsWith(params) {
        resetFilters(false);
        const cats = params.getAll('category'), status = params.get('status'), from = params.get('from_date');
        document.querySelectorAll('#activity-category-list input').forEach(b => { b.checked = cats.includes(b.value); });
        if (status) $('activity-status').value = status;
        if (from) {
            const d = new Date(from);
            const pad = (n) => String(n).padStart(2, '0');
            $('activity-from').value = `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
        }
        refreshPickSummaries();
        selectTab('events');
        search(false);
    }

    // ---- page -----------------------------------------------------------------------------------

    function refreshPickSummaries() {
        const catLabels = {};
        (state.catalog ? state.catalog.categories : []).forEach(c => { catLabels[c.key] = c.label; });
        summarisePick('activity-category-list', 'activity-pick-category-value', catLabels);
        summarisePick('activity-channel-list', 'activity-pick-channel-value', CHANNEL_LABELS);
    }

    function resetFilters(andSearch) {
        document.querySelectorAll('#activity-filters input[type=checkbox]').forEach(b => { b.checked = false; });
        ['activity-user', 'activity-ip', 'activity-q', 'activity-from', 'activity-to'].forEach(id => { $(id).value = ''; });
        $('activity-status').value = '';
        refreshPickSummaries();
        if (andSearch) search(false);
    }

    function selectTab(name) {
        document.querySelectorAll('[data-activity-tab]').forEach(b => {
            const on = b.getAttribute('data-activity-tab') === name;
            b.classList.toggle('active', on);
            b.setAttribute('aria-selected', on ? 'true' : 'false');
        });
        document.querySelectorAll('.activity-tab').forEach(p => { p.hidden = p.id !== `activity-tab-${name}`; });
    }

    function wire() {
        if (state.wired) return;
        state.wired = true;
        document.querySelectorAll('[data-activity-tab]').forEach(b => b.addEventListener('click', () => {
            const name = b.getAttribute('data-activity-tab');
            selectTab(name);
            if (name === 'events' && !state.events.length) search(false);
            if (name === 'overview') loadOverview();
        }));
        $('activity-filters').addEventListener('submit', (e) => {
            e.preventDefault();
            document.querySelectorAll('#activity-filters details[open]').forEach(d => d.removeAttribute('open'));
            $('activity-filters').classList.remove('is-open');
            $('activity-filters-toggle').setAttribute('aria-expanded', 'false');
            search(false);
        });
        $('activity-reset').addEventListener('click', () => resetFilters(true));
        $('activity-filters-toggle').addEventListener('click', () => {
            const form = $('activity-filters');
            const open = !form.classList.contains('is-open');
            form.classList.toggle('is-open', open);
            $('activity-filters-toggle').setAttribute('aria-expanded', open ? 'true' : 'false');
        });
        // One checklist open at a time, and a tap anywhere else closes it: an open list covers the
        // fields and buttons below it.
        const picks = Array.from(document.querySelectorAll('#activity-filters details.activity-pick'));
        picks.forEach(d => d.addEventListener('toggle', () => {
            if (d.open) picks.forEach(o => { if (o !== d) o.open = false; });
        }));
        document.addEventListener('click', (e) => {
            picks.forEach(d => { if (d.open && !d.contains(e.target)) d.open = false; });
        });
        document.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') picks.forEach(d => { if (d.open) { d.open = false; d.querySelector('summary').focus(); } });
        });
        $('activity-more').addEventListener('click', () => search(true));
    }

    async function loadCatalog() {
        if (state.catalog) return;
        state.catalog = await apiRequest('/activity/catalog');
        buildPickList('activity-category-list',
            state.catalog.categories.map(c => ({ value: c.key, label: c.label })), refreshPickSummaries);
        buildPickList('activity-channel-list',
            state.catalog.channels.map(c => ({ value: c, label: CHANNEL_LABELS[c] || c })), refreshPickSummaries);
    }

    window.initActivity = async function initActivity() {
        wire();
        try { await loadCatalog(); } catch (e) { /* the filters stay empty; searching still works */ }
        selectTab(document.querySelector('[data-activity-tab].active')?.getAttribute('data-activity-tab') || 'overview');
        loadOverview();
    };
})();
