// Tables: sortable headers, a search box, and a density the person chooses, remembered per account.
//
//   Tables.enhance(table, {key, search: inputEl | true, skip: [colIndex...]})
//       Makes every titled header of `table` sortable (click or Enter/Space; aria-sort says which way), sorting
//       the body's rows by that column: a <time datetime> cell by its moment, a number by its value, else by
//       text; a cell with nothing in it ("—", "Never", empty) goes last either way. An expandable table (rows
//       .exp-row followed by their .exp-detail) keeps each pair together. Each header is known by its column id
//       (`data-col`, set by the caller; else a slug of its text), so the sort is remembered under `key` for this
//       account (saveUserPreference "tables") as {col: id, dir}, and applied again when the table is drawn again,
//       even after a column is added. `search: true` adds a search box above the table that hides rows whose
//       text does not hold every typed word; an existing input can be given instead. `facets: [{col, label}]`
//       adds one small select per named column, listing the values its cells hold, that keeps only the rows
//       with the chosen value; the search and the facets narrow the table together.
//   Tables.reset()
//       Forgets every remembered sort (sign-out: the next account on this tab starts from its own).
//   Tables.setDensity('comfortable' | 'compact'), Tables.density()
//       The tables' row height, as data-density on <html>, remembered for the account.
//
// Everything is built with createElement and textContent; nothing is read from the rows but their text. People
// placeholders (static/js/people.js) in the rows are turned into their chips and times before anything is read.
(function () {
    'use strict';

    const KEY = 'dv_tables';
    const DENSITY_KEY = 'dv_density';
    const COL_ID = /^[a-z][a-z0-9-]{0,31}$/;
    let remembered = null;
    const facetsOf = new WeakMap();   // table -> its facet selects
    const searchOf = new WeakMap();   // table -> its search box
    const tableOf = new WeakMap();    // a search box or facet select -> the table it narrows now (a redrawn table is a new element)

    // A saved map with only the entries this build reads: a column id and a direction.
    function clean(map) {
        const out = {};
        if (!map || typeof map !== 'object') return out;
        Object.keys(map).forEach((k) => {
            const e = map[k];
            if (e && typeof e.col === 'string' && COL_ID.test(e.col) && (e.dir === 'asc' || e.dir === 'desc')) out[k] = { col: e.col, dir: e.dir };
        });
        return out;
    }

    function load() {
        if (remembered) return remembered;
        let raw = null;
        try { raw = localStorage.getItem(KEY); remembered = clean(JSON.parse(raw || '{}')); } catch (_) { remembered = {}; }
        const text = JSON.stringify(remembered);
        if (raw !== null && raw !== text) { try { localStorage.setItem(KEY, text); } catch (_) {} }
        return remembered;
    }

    function save() {
        const text = JSON.stringify(load());
        try { localStorage.setItem(KEY, text); } catch (_) {}
        if (typeof saveUserPreference === 'function' && text.length <= 2000) saveUserPreference({ tables: text });
    }

    // Nothing remembered: the next account on this tab starts from what its own preferences say.
    function reset() {
        remembered = {};
        try { localStorage.removeItem(KEY); } catch (_) {}
    }

    // What the account saved on the server, applied once the app has it (the app calls this with the
    // preferences it fetched at sign-in). An account that saved no sort starts with none.
    function applyPreferences(prefs) {
        if (!prefs) return;
        if (typeof prefs.tables === 'string') {
            try {
                const parsed = JSON.parse(prefs.tables);
                if (parsed && typeof parsed === 'object') {
                    remembered = clean(parsed);
                    try { localStorage.setItem(KEY, JSON.stringify(remembered)); } catch (_) {}
                }
            } catch (_) { /* a saved value this build cannot read: ignored */ }
        } else {
            reset();
        }
        if (prefs.density === 'compact' || prefs.density === 'comfortable') setDensity(prefs.density, { quiet: true });
    }

    function slug(text) {
        return String(text || '').toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/^-+|-+$/g, '').slice(0, 32);
    }

    // The column's id: what the caller named it, else a slug of its title.
    function colId(th) {
        return th.getAttribute('data-col') || slug(th.textContent);
    }

    function headerCells(table) {
        return table.tHead && table.tHead.rows[0] ? Array.from(table.tHead.rows[0].cells) : [];
    }

    // The index of a column named by id (or given as an index); -1 when the table has no such column.
    function columnIndex(table, col) {
        const headers = headerCells(table);
        if (typeof col === 'number') return col >= 0 && col < headers.length ? col : -1;
        return headers.findIndex((th) => colId(th) === col);
    }

    const MISSING = /^(—|–|-|never|none)?$/i;

    // What a cell shows: the chosen option of a select, else its text.
    function cellText(cell) {
        if (!cell) return '';
        const sel = cell.querySelector('select');
        if (sel && sel.selectedIndex >= 0 && sel.options && sel.options[sel.selectedIndex]) return sel.options[sel.selectedIndex].textContent.trim();
        return cell.textContent.trim();
    }

    function cellKey(cell) {
        if (!cell) return { text: '', time: null, num: null, missing: true };
        const explicit = cell.getAttribute('data-sort-value');
        if (explicit != null) {
            const n = explicit.trim();
            const num = /^-?\d+(\.\d+)?$/.test(n) ? parseFloat(n) : null;
            return { text: n, time: null, num, missing: n === '' };
        }
        const t = cell.querySelector('time[datetime]');
        if (t) {
            const ms = Date.parse(t.getAttribute('datetime'));
            return { text: cell.textContent.trim(), time: isNaN(ms) ? null : ms, num: null, missing: isNaN(ms) };
        }
        const text = cellText(cell);
        const n = text.replace(/[,\s]/g, '');
        const num = /^-?\d+(\.\d+)?$/.test(n) ? parseFloat(n) : null;
        return { text, time: null, num, missing: MISSING.test(text) };
    }

    // A cell with nothing in it sorts last whichever way the column goes.
    function compare(a, b, dir) {
        if (a.missing !== b.missing) return a.missing ? 1 : -1;
        if (a.missing && b.missing) return 0;
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
        const index = columnIndex(table, col);
        if (!tbody || index < 0) return;
        const list = units(tbody).map((u, i) => ({ u, i, key: cellKey(u[0].cells[index]) }));
        list.sort((x, y) => compare(x.key, y.key, dir) || x.i - y.i);
        list.forEach((item) => item.u.forEach((row) => tbody.appendChild(row)));
        const id = colId(headerCells(table)[index]);
        table.querySelectorAll('thead th[data-sort-col]').forEach((th) => {
            th.setAttribute('aria-sort', colId(th) === id ? (dir === 'desc' ? 'descending' : 'ascending') : 'none');
        });
    }

    // The facets with a value chosen, as the column index and the value each row must show there.
    function activeFacets(table) {
        return (facetsOf.get(table) || []).filter((s) => s.value)
            .map((s) => ({ index: columnIndex(table, s.getAttribute('data-facet-col')), value: s.value }))
            .filter((f) => f.index >= 0);
    }

    // Rows that hold every word of `query` (the search box's text when not given) and match every chosen facet.
    function filterTable(table, query) {
        const q = query == null ? ((searchOf.get(table) || {}).value || '') : query;
        const words = String(q).toLowerCase().split(/\s+/).filter(Boolean);
        const facets = activeFacets(table);
        const tbody = table.tBodies[0];
        if (!tbody) return;
        units(tbody).forEach((u) => {
            const text = u[0].textContent.toLowerCase();
            const show = words.every((w) => text.indexOf(w) >= 0) && facets.every((f) => cellText(u[0].cells[f.index]) === f.value);
            u.forEach((row, idx) => {
                if (idx === 0) row.hidden = !show;
                else if (!show) row.hidden = true;
                else row.hidden = !u[0].classList.contains('open') && row.hidden;
            });
        });
        let empty = table.nextElementSibling && table.nextElementSibling.classList.contains('table-search-empty')
            ? table.nextElementSibling : null;
        const none = Array.from(tbody.children).every((r) => r.hidden);
        if (none && (words.length || facets.length)) {
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

    // One facet's select, kept across redraws of the table; its options are the values the column holds now,
    // and a chosen value stays chosen while the column still holds it.
    function facetSelect(table, key, facet) {
        const label = facet.label || facet.col;
        let el = table.parentNode && table.parentNode.querySelector(':scope > select.table-facet[data-facet-col="' + facet.col + '"]');
        if (!el) {
            el = document.createElement('select');
            el.className = 'form-control form-control-sm table-facet';
            el.setAttribute('data-facet-col', facet.col);
            el.setAttribute('aria-label', 'Filter by ' + label);
            if (key) el.id = 'table-facet-' + key + '-' + facet.col;
            table.insertAdjacentElement('beforebegin', el);
        }
        const index = columnIndex(table, facet.col);
        const values = [];
        if (index >= 0 && table.tBodies[0]) {
            units(table.tBodies[0]).forEach((u) => {
                const v = cellText(u[0].cells[index]);
                if (v && !MISSING.test(v) && values.indexOf(v) < 0) values.push(v);
            });
        }
        values.sort((a, b) => a.localeCompare(b, undefined, { numeric: true, sensitivity: 'base' }));
        const current = el.value;
        el.replaceChildren();
        const all = document.createElement('option');
        all.value = '';
        all.textContent = label + ': all';
        el.appendChild(all);
        values.forEach((v) => {
            const option = document.createElement('option');
            option.value = v;
            option.textContent = v;
            el.appendChild(option);
        });
        el.value = values.indexOf(current) >= 0 ? current : '';
        return el;
    }

    function enhance(table, options) {
        if (!table || !table.tHead) return table;
        // A list drawn from a template holds People placeholders until the page's watcher turns them into
        // chips and times, which happens after this call: turn them now, so a remembered sort on a time
        // column and a search for a name see the real cells.
        if (window.People && typeof People.hydrate === 'function') People.hydrate(table);
        const o = options || {};
        const key = o.key || table.id || '';
        const skip = new Set(o.skip || []);
        const headers = headerCells(table);
        headers.forEach((th, col) => {
            if (skip.has(col) || !th.textContent.trim()) return;
            const id = colId(th);
            if (!th.getAttribute('data-col')) th.setAttribute('data-col', id);
            if (th.dataset.sortCol !== undefined) return;
            th.setAttribute('data-sort-col', id);
            th.setAttribute('aria-sort', 'none');
            th.setAttribute('tabindex', '0');
            th.setAttribute('role', 'columnheader');
            th.classList.add('sortable');
            th.title = 'Sort by ' + th.textContent.trim();
            const go = () => {
                const dir = th.getAttribute('aria-sort') === 'ascending' ? 'desc' : 'asc';
                sortTable(table, id, dir);
                if (key) { load()[key] = { col: id, dir }; save(); }
            };
            th.addEventListener('click', go);
            th.addEventListener('keydown', (e) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); go(); } });
        });
        const kept = key ? load()[key] : null;
        if (kept && columnIndex(table, kept.col) >= 0) sortTable(table, kept.col, kept.dir === 'desc' ? 'desc' : 'asc');
        let input = null;
        if (o.search === true) input = searchBox(table, key);
        else if (o.search && o.search.addEventListener) input = o.search;
        if (input) {
            searchOf.set(table, input);
            tableOf.set(input, table);
            if (!input.dataset.tableWired) {
                input.dataset.tableWired = '1';
                input.addEventListener('input', () => filterTable(tableOf.get(input), input.value));
            }
        }
        const facets = (Array.isArray(o.facets) ? o.facets : []).filter((f) => f && f.col).map((f) => facetSelect(table, key, f));
        facetsOf.set(table, facets);
        facets.forEach((s) => {
            tableOf.set(s, table);
            if (!s.dataset.tableWired) {
                s.dataset.tableWired = '1';
                s.addEventListener('change', () => filterTable(tableOf.get(s)));
            }
        });
        if ((input && input.value) || facets.some((s) => s.value)) filterTable(table);
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

    window.Tables = { enhance, sortTable, filterTable, setDensity, density, applyPreferences, reset };
})();
