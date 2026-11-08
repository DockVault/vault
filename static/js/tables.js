// Business tables: sortable headers, a search box, and a density the person chooses, remembered per account.
//
//   Tables.enhance(table, {key, search: inputEl | true, skip: [colIndex...]})
//       Makes every titled header of `table` sortable (click or Enter/Space; aria-sort says which way), sorting
//       the body's rows by that column: a <time datetime> cell by its moment, a number by its value, else by
//       text. An expandable table (rows .exp-row followed by their .exp-detail) keeps each pair together. The
//       sort is remembered under `key` for this account (saveUserPreference "tables"), and applied again when
//       the table is drawn again. `search: true` adds a search box above the table that hides rows whose text
//       does not hold every typed word; an existing input can be given instead.
//   Tables.setDensity('comfortable' | 'compact'), Tables.density()
//       The tables' row height, as data-density on <html>, remembered for the account.
//
// Everything is built with createElement and textContent; nothing is read from the rows but their text.
(function () {
    'use strict';

    const KEY = 'dv_tables';
    const DENSITY_KEY = 'dv_density';
    let remembered = null;

    function load() {
        if (remembered) return remembered;
        try { remembered = JSON.parse(localStorage.getItem(KEY) || '{}') || {}; } catch (_) { remembered = {}; }
        return remembered;
    }

    function save() {
        const text = JSON.stringify(load());
        try { localStorage.setItem(KEY, text); } catch (_) {}
        if (typeof saveUserPreference === 'function' && text.length <= 2000) saveUserPreference({ tables: text });
    }

    // What the account saved on the server, applied once the app has it (the app calls this with the
    // preferences it fetched at sign-in).
    function applyPreferences(prefs) {
        if (!prefs) return;
        if (typeof prefs.tables === 'string') {
            try {
                const parsed = JSON.parse(prefs.tables);
                if (parsed && typeof parsed === 'object') {
                    remembered = parsed;
                    try { localStorage.setItem(KEY, prefs.tables); } catch (_) {}
                }
            } catch (_) { /* a saved value this build cannot read: ignored */ }
        }
        if (prefs.density === 'compact' || prefs.density === 'comfortable') setDensity(prefs.density, { quiet: true });
    }

    function cellKey(cell) {
        if (!cell) return { text: '', time: null, num: null };
        const t = cell.querySelector('time[datetime]');
        if (t) {
            const ms = Date.parse(t.getAttribute('datetime'));
            return { text: cell.textContent.trim(), time: isNaN(ms) ? null : ms, num: null };
        }
        const text = cell.textContent.trim();
        const n = text.replace(/[,\s]/g, '');
        const num = /^-?\d+(\.\d+)?$/.test(n) ? parseFloat(n) : null;
        return { text, time: null, num };
    }

    function compare(a, b, dir) {
        let out;
        if (a.time != null || b.time != null) out = (a.time == null) - (b.time == null) || (a.time || 0) - (b.time || 0);
        else if (a.num != null && b.num != null) out = a.num - b.num;
        else out = a.text.localeCompare(b.text, undefined, { numeric: true, sensitivity: 'base' });
        return dir === 'desc' ? -out : out;
    }

    // The body's rows as units: a row and the detail row that belongs to it.
    function units(tbody) {
        const out = [];
        Array.from(tbody.children).forEach((row) => {
            if (row.classList.contains('exp-detail') && out.length) out[out.length - 1].push(row);
            else out.push([row]);
        });
        return out;
    }

    function sortTable(table, col, dir) {
        const tbody = table.tBodies[0];
        if (!tbody) return;
        const list = units(tbody).map((u, i) => ({ u, i, key: cellKey(u[0].cells[col]) }));
        list.sort((x, y) => compare(x.key, y.key, dir) || x.i - y.i);
        list.forEach((item) => item.u.forEach((row) => tbody.appendChild(row)));
        table.querySelectorAll('thead th[data-sort-col]').forEach((th) => {
            const mine = Number(th.getAttribute('data-sort-col')) === col;
            th.setAttribute('aria-sort', mine ? (dir === 'desc' ? 'descending' : 'ascending') : 'none');
        });
    }

    function filterTable(table, query) {
        const words = query.toLowerCase().split(/\s+/).filter(Boolean);
        const tbody = table.tBodies[0];
        if (!tbody) return;
        units(tbody).forEach((u) => {
            const text = u[0].textContent.toLowerCase();
            const show = words.every((w) => text.indexOf(w) >= 0);
            u.forEach((row, idx) => {
                if (idx === 0) row.hidden = !show;
                else if (!show) row.hidden = true;
                else row.hidden = !u[0].classList.contains('open') && row.hidden;
            });
        });
        let empty = table.nextElementSibling && table.nextElementSibling.classList.contains('table-search-empty')
            ? table.nextElementSibling : null;
        const none = Array.from(tbody.children).every((r) => r.hidden);
        if (none && words.length) {
            if (!empty) {
                empty = document.createElement('p');
                empty.className = 'text-secondary text-sm table-search-empty';
                empty.textContent = 'Nothing matches.';
                table.insertAdjacentElement('afterend', empty);
            }
            empty.hidden = false;
        } else if (empty) {
            empty.hidden = true;
        }
    }

    function searchBox(table, key) {
        const existing = table.parentNode && table.parentNode.querySelector(':scope > .table-search');
        if (existing) return existing;
        const input = document.createElement('input');
        input.type = 'search';
        input.className = 'form-control form-control-sm table-search';
        input.placeholder = 'Search this table';
        input.setAttribute('aria-label', 'Search this table');
        input.autocomplete = 'off';
        if (key) input.id = 'table-search-' + key;
        table.insertAdjacentElement('beforebegin', input);
        return input;
    }

    function enhance(table, options) {
        if (!table || !table.tHead) return table;
        const o = options || {};
        const key = o.key || table.id || '';
        const skip = new Set(o.skip || []);
        const headers = Array.from(table.tHead.rows[0] ? table.tHead.rows[0].cells : []);
        headers.forEach((th, col) => {
            if (skip.has(col) || !th.textContent.trim() || th.dataset.sortCol !== undefined) return;
            th.setAttribute('data-sort-col', String(col));
            th.setAttribute('aria-sort', 'none');
            th.setAttribute('tabindex', '0');
            th.setAttribute('role', 'columnheader');
            th.classList.add('sortable');
            th.title = 'Sort by ' + th.textContent.trim();
            const go = () => {
                const dir = th.getAttribute('aria-sort') === 'ascending' ? 'desc' : 'asc';
                sortTable(table, col, dir);
                if (key) { load()[key] = { col, dir }; save(); }
            };
            th.addEventListener('click', go);
            th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
        });
        if (key && load()[key] && headers[load()[key].col]) sortTable(table, load()[key].col, load()[key].dir === 'desc' ? 'desc' : 'asc');
        let input = null;
        if (o.search === true) input = searchBox(table, key);
        else if (o.search && o.search.addEventListener) input = o.search;
        if (input && !input.dataset.tableWired) {
            input.dataset.tableWired = '1';
            input.addEventListener('input', () => filterTable(table, input.value));
        }
        if (input && input.value) filterTable(table, input.value);
        return table;
    }

    function density() {
        return document.documentElement.getAttribute('data-density') === 'compact' ? 'compact' : 'comfortable';
    }

    function setDensity(value, options) {
        const v = value === 'compact' ? 'compact' : 'comfortable';
        if (v === 'compact') document.documentElement.setAttribute('data-density', 'compact');
        else document.documentElement.removeAttribute('data-density');
        try { localStorage.setItem(DENSITY_KEY, v); } catch (_) {}
        document.querySelectorAll('.density-choice').forEach((b) => {
            const on = b.getAttribute('data-density') === v;
            b.classList.toggle('selected', on);
            b.setAttribute('aria-pressed', on ? 'true' : 'false');
        });
        if (!(options && options.quiet) && typeof saveUserPreference === 'function') saveUserPreference({ density: v });
    }

    function start() {
        let stored = null;
        try { stored = localStorage.getItem(DENSITY_KEY); } catch (_) {}
        setDensity(stored === 'compact' ? 'compact' : 'comfortable', { quiet: true });
        document.addEventListener('click', (e) => {
            const b = e.target && e.target.closest && e.target.closest('.density-choice[data-density]');
            if (b) setDensity(b.getAttribute('data-density'));
        });
    }
    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    window.Tables = { enhance, sortTable, filterTable, setDensity, density, applyPreferences };
})();
