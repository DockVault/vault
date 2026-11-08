/*
 * Settings: levels, "New", the provider's settings and the search (GET /settings/catalogue,
 * POST /settings/catalogue/seen, app/api/settings_catalogue_router.py).
 *
 * Every setting on a Settings page is marked data-setting="<key>" (static/index.html, and the rows the page's
 * scripts draw: the rate limits in app.js, how long records are kept in settings-retention.js), and the
 * catalogue gives each key its page, its level, whether it is new to this administrator and whether the
 * deployment has locked it. On each page:
 *   - the essential settings show; "Show advanced settings (N)" reveals the advanced ones, each marked
 *     Advanced; a container marked data-setting-group hides when every setting in it is hidden;
 *   - a setting that arrived recently, or after the release this administrator last opened Settings at, is
 *     marked New;
 *   - the marks are for the eye (aria-hidden, so a label's accessible name stays as it was); what they say
 *     reaches assistive technology as a visually hidden note right after the setting's title, which each of
 *     the setting's own fields names as its description;
 *   - the settings the provider has locked leave their place for one collapsed list at the foot of the page,
 *     "Set by your provider (N)", read-only, each with its value and the reason.
 * A search box above the tabs finds a setting by its label and help text on every page, and goes to it (its
 * page, its advanced settings shown, or its line in the provider's list).
 *
 * Nothing here changes a value or what a save sends: a hidden setting is still on the page, filled and
 * saved as before. Without the catalogue (it could not be read) every setting shows, and the search still
 * finds the settings on the pages. The pages are watched for rows the other scripts draw later, and each pass
 * changes the page only where it differs, so a pass never starts another one.
 *
 * Uses app.js's apiRequest. Builds everything with createElement and textContent.
 */
(function () {
    'use strict';

    const S = { data: null, byKey: {}, show: {}, loaded: false, loading: null, frame: 0, query: '' };
    const LIMIT = 12;

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function section() { return document.getElementById('settings-section'); }

    // A value inside a selector: the server's keys are plain names, but a selector never trusts that.
    function q(value) { return window.CSS && CSS.escape ? CSS.escape(String(value)) : String(value); }

    function pageEls() {
        const root = section();
        return root ? Array.from(root.querySelectorAll('.settings-tab-content[id^="settings-tab-"]')) : [];
    }

    function pageOf(node) {
        const page = node.closest && node.closest('.settings-tab-content[id^="settings-tab-"]');
        return page ? page.id.slice('settings-tab-'.length) : null;
    }

    function pageName(page) {
        const tab = document.querySelector(`#settings-section .tab-btn[data-tab="${q(page)}"]`);
        return tab ? tab.textContent.trim() : page;
    }

    // Hidden by the app itself (not by this file, which uses classes): left out of every count.
    function present(node) {
        return !node.hidden && node.style.display !== 'none';
    }

    function entryOf(key) { return S.byKey[key] || null; }

    function isAdvanced(entry) { return !!(entry && entry.level === 'advanced'); }

    function isFolded(entry) { return !!(entry && entry.locked); }

    // ------------------------------------------------------------------ marks

    function titleOf(node) {
        if (node.classList.contains('card')) return node.querySelector('.card-header h3, .card-header h4, h3');
        if (node.classList.contains('retention-row')) return node.querySelector('.retention-label');
        if (node.classList.contains('rl-row')) return node.querySelector('strong');
        return node.querySelector('label, legend, h4, h3, strong');
    }

    function titleText(node) {
        const title = titleOf(node);
        if (!title) return '';
        let text = '';
        title.childNodes.forEach((child) => {
            if (child.nodeType === 1 && child.classList.contains('setting-chips')) return;
            text += child.textContent;
        });
        return text.replace(/\s+/g, ' ').trim();
    }

    function helpText(node) {
        return Array.from(node.querySelectorAll('p, small'))
            .filter((p) => !p.closest('.modal, table, ul, ol, .setting-chips') && p.closest('[data-setting]') === node)
            .map((p) => p.textContent.replace(/\s+/g, ' ').trim())
            .filter(Boolean)
            .join(' ');
    }

    function setChips(node, entry) {
        const title = titleOf(node);
        if (!title) return;
        const want = [];
        if (entry && entry.new) want.push('new');
        if (isAdvanced(entry)) want.push('advanced');
        let chips = title.querySelector(':scope > .setting-chips');
        const state = want.join(' ');
        if (!chips) {
            if (!want.length) return;
            chips = el('span', 'setting-chips');
            chips.setAttribute('aria-hidden', 'true');
            title.appendChild(chips);
        }
        if (chips.dataset.state === state) return;
        chips.dataset.state = state;
        chips.replaceChildren(...want.map((kind) => {
            const chip = el('span', `setting-chip setting-chip-${kind}`, kind === 'new' ? 'New' : 'Advanced');
            chip.title = kind === 'new' ? `New in ${entry.since}` : 'An advanced setting';
            return chip;
        }));
    }

    // What the marks say, for assistive technology: a visually hidden note right after the title, named by each
    // of the setting's own fields as its description (beside any description the field had).
    let notes = 0;

    function noteText(entry) {
        const parts = [];
        if (entry && entry.new) parts.push(`New in ${entry.since}.`);
        if (isAdvanced(entry)) parts.push('An advanced setting.');
        return parts.join(' ');
    }

    function ownFields(node) {
        return Array.from(node.querySelectorAll('input:not([type="hidden"]), select, textarea'))
            .filter((field) => field.closest('[data-setting]') === node);
    }

    function describedBy(field, id, on) {
        const ids = (field.getAttribute('aria-describedby') || '').split(/\s+/).filter(Boolean);
        if ((ids.indexOf(id) >= 0) === on) return;
        const next = on ? ids.concat(id) : ids.filter((one) => one !== id);
        if (next.length) field.setAttribute('aria-describedby', next.join(' '));
        else field.removeAttribute('aria-describedby');
    }

    function setNote(node, entry) {
        const title = titleOf(node);
        const text = title ? noteText(entry) : '';
        let note = Array.from(node.querySelectorAll('.setting-marks-note'))
            .find((one) => one.closest('[data-setting]') === node) || null;
        if (!text) {
            if (note) {
                ownFields(node).forEach((field) => describedBy(field, note.id, false));
                note.remove();
            }
            return;
        }
        if (!note) {
            notes += 1;
            note = el('span', 'setting-marks-note');
            note.id = `setting-marks-note-${notes}`;
        }
        if (note.previousElementSibling !== title || note.parentNode !== title.parentNode) title.after(note);
        setText(note, text);
        ownFields(node).forEach((field) => describedBy(field, note.id, true));
    }

    function toggleClass(node, cls, on) {
        if (node.classList.contains(cls) !== on) node.classList.toggle(cls, on);
    }

    // ------------------------------------------------------------------ one page

    function bar(page, pageEl) {
        let box = pageEl.querySelector(':scope > .settings-level-bar');
        if (!box) {
            box = el('div', 'settings-level-bar');
            const note = el('p', 'text-secondary text-sm settings-level-note', 'Every setting on this page is advanced.');
            note.hidden = true;
            const button = el('button', 'btn btn-outline btn-sm settings-advanced-toggle');
            button.type = 'button';
            button.setAttribute('aria-pressed', 'false');
            button.addEventListener('click', () => {
                S.show[page] = !S.show[page];
                applyNow();
            });
            box.append(note, button);
            box.hidden = true;
            pageEl.insertBefore(box, pageEl.firstChild);
        }
        return box;
    }

    function setText(node, text) {
        if (node.textContent !== text) node.textContent = text;
    }

    function setHidden(node, hidden) {
        if (node.hidden !== hidden) node.hidden = hidden;
    }

    function fold(pageEl) {
        let box = pageEl.querySelector(':scope > .settings-provider-fold');
        if (!box) {
            box = el('details', 'card mt-lg settings-provider-fold');
            box.appendChild(el('summary', 'settings-provider-summary'));
            const body = el('div', 'p-lg');
            body.appendChild(el('ul', 'settings-provider-list'));
            box.appendChild(body);
            box.hidden = true;
            pageEl.appendChild(box);
        }
        return box;
    }

    function renderFold(page, pageEl) {
        const rows = S.data ? S.data.entries.filter((e) => e.page === page && e.locked) : [];
        const box = fold(pageEl);
        setHidden(box, !rows.length);
        setText(box.querySelector('summary'), `Set by your provider (${rows.length})`);
        const sign = JSON.stringify(rows.map((r) => [r.key, r.value, r.reason, r.label]));
        const list = box.querySelector('.settings-provider-list');
        if (list.dataset.sign === sign) return;
        list.dataset.sign = sign;
        list.replaceChildren(...rows.map((row) => {
            const item = el('li', 'settings-provider-item');
            item.dataset.foldKey = row.key;
            const head = el('div', 'settings-provider-head');
            const nodes = Array.from(pageEl.querySelectorAll(`[data-setting="${q(row.key)}"]`));
            head.appendChild(el('strong', null, row.label || (nodes.length ? titleText(nodes[0]) : '') || row.key));
            if (row.value) head.appendChild(el('span', 'settings-provider-value', row.value));
            item.appendChild(head);
            if (row.help) item.appendChild(el('p', 'text-secondary text-sm', row.help));
            item.appendChild(el('p', 'text-secondary text-sm settings-provider-reason', row.reason || ''));
            return item;
        }));
    }

    function applyPage(pageEl) {
        const page = pageEl.id.slice('settings-tab-'.length);
        const show = !!S.show[page];
        const advanced = new Set();
        const essential = new Set();
        pageEl.querySelectorAll('[data-setting]').forEach((node) => {
            const key = node.dataset.setting;
            const entry = entryOf(key);
            const folded = isFolded(entry);
            toggleClass(node, 'setting-folded', folded);
            toggleClass(node, 'setting-advanced', isAdvanced(entry));
            toggleClass(node, 'setting-level-hidden', !folded && isAdvanced(entry) && !show);
            setChips(node, entry);
            setNote(node, entry);
            if (folded || !present(node)) return;
            (isAdvanced(entry) ? advanced : essential).add(key);
        });
        pageEl.querySelectorAll('[data-setting-group]').forEach((group) => {
            const inside = Array.from(group.querySelectorAll('[data-setting]'));
            const empty = inside.length > 0 && inside.every((node) =>
                node.classList.contains('setting-folded') || node.classList.contains('setting-level-hidden'));
            toggleClass(group, 'setting-group-hidden', empty);
        });
        const box = bar(page, pageEl);
        setHidden(box, advanced.size === 0);
        const button = box.querySelector('.settings-advanced-toggle');
        setText(button, show ? 'Hide advanced settings' : `Show advanced settings (${advanced.size})`);
        if (button.getAttribute('aria-pressed') !== String(show)) button.setAttribute('aria-pressed', String(show));
        setHidden(box.querySelector('.settings-level-note'), show || essential.size > 0 || advanced.size === 0);
        renderFold(page, pageEl);
    }

    function applyNow() {
        S.frame = 0;
        pageEls().forEach(applyPage);
    }

    function schedule() {
        if (S.frame) return;
        S.frame = window.requestAnimationFrame(applyNow);
    }

    // ------------------------------------------------------------------ the catalogue

    // The catalogue is the administrators': its read is refused, and recorded, for anyone else.
    function administrator() {
        const user = typeof currentUser !== 'undefined' ? currentUser : null;
        return !!(user && user.role === 'admin');
    }

    async function load() {
        if (!administrator()) return;
        if (S.loading) return S.loading;
        S.loading = (async () => {
            try {
                const data = await apiRequest('/settings/catalogue', { silent: true });
                if (data && Array.isArray(data.entries)) {
                    S.data = data;
                    S.byKey = {};
                    data.entries.forEach((e) => { S.byKey[e.key] = e; });
                    applyNow();
                    // Seen now: the next visit counts "New" from this release.
                    apiRequest('/settings/catalogue/seen', { method: 'POST', silent: true }).catch(() => {});
                }
            } catch (_) {
                // Without the catalogue every setting shows; the search still finds what is on the pages.
            } finally {
                S.loading = null;
            }
        })();
        return S.loading;
    }

    // ------------------------------------------------------------------ the search

    // What the search can find: every marked setting on the pages, and every entry of the catalogue (a row a
    // page draws only when it opens is found by its catalogue label). A setting the app itself hides (the
    // update checks while they are off) is left out.
    function candidates() {
        const found = {};
        pageEls().forEach((pageEl) => {
            pageEl.querySelectorAll('[data-setting]').forEach((node) => {
                const key = node.dataset.setting;
                const item = found[key] || (found[key] = {
                    key, page: pageOf(node), label: titleText(node), help: helpText(node), drawn: true, shown: false,
                });
                if (present(node)) item.shown = true;
            });
        });
        if (S.data) {
            S.data.entries.forEach((e) => {
                const item = found[e.key] || (found[e.key] = {
                    key: e.key, page: e.page, label: '', help: '', drawn: false, shown: false,
                });
                if (e.label) item.label = e.label;
                if (e.help && item.help.indexOf(e.help) < 0) item.help = `${e.help} ${item.help}`.trim();
                item.page = e.page;
            });
        }
        return Object.values(found).filter((item) => (item.label || item.help)
            && (!item.drawn || item.shown));
    }

    function search(query) {
        const words = query.toLowerCase().split(/\s+/).filter(Boolean);
        if (!words.length) return [];
        const order = pageEls().map((p) => p.id.slice('settings-tab-'.length));
        return candidates()
            .map((item) => {
                const label = item.label.toLowerCase();
                const all = `${label} ${item.help.toLowerCase()}`;
                if (!words.every((w) => all.indexOf(w) >= 0)) return null;
                return { item, rank: words.every((w) => label.indexOf(w) >= 0) ? 0 : 1 };
            })
            .filter(Boolean)
            .sort((a, b) => a.rank - b.rank || order.indexOf(a.item.page) - order.indexOf(b.item.page))
            .map((hit) => hit.item);
    }

    function results() { return document.getElementById('settings-search-results'); }

    function closeResults() {
        const box = results();
        if (box) { box.hidden = true; box.replaceChildren(); }
    }

    function showResults(query) {
        const box = results();
        if (!box) return;
        const hits = search(query);
        box.replaceChildren();
        if (!query.trim()) { box.hidden = true; return; }
        if (!hits.length) {
            box.appendChild(el('p', 'text-secondary text-sm settings-search-none', 'No setting matches.'));
        }
        hits.slice(0, LIMIT).forEach((item) => {
            const entry = entryOf(item.key);
            const button = el('button', 'settings-search-hit');
            button.type = 'button';
            button.dataset.key = item.key;
            button.appendChild(el('span', 'settings-search-label', item.label || item.key));
            const where = [pageName(item.page)];
            if (isFolded(entry)) where.push('Set by your provider');
            else if (isAdvanced(entry)) where.push('Advanced');
            if (entry && entry.new) where.push('New');
            button.appendChild(el('span', 'settings-search-where text-secondary text-sm', where.join(' · ')));
            button.addEventListener('click', () => go(item.key));
            box.appendChild(button);
        });
        if (hits.length > LIMIT) {
            box.appendChild(el('p', 'text-secondary text-sm settings-search-more',
                `${hits.length - LIMIT} more: type more of the name to narrow them.`));
        }
        box.hidden = false;
    }

    function wait(test, ms) {
        return new Promise((resolve) => {
            const until = Date.now() + ms;
            (function poll() {
                const found = test();
                if (found || Date.now() > until) resolve(found || null);
                else window.setTimeout(poll, 50);
            })();
        });
    }

    function firstPresent(page, key) {
        const pageEl = document.getElementById(`settings-tab-${page}`);
        if (!pageEl) return null;
        return Array.from(pageEl.querySelectorAll(`[data-setting="${q(key)}"]`)).find(present) || null;
    }

    async function go(key) {
        const entry = entryOf(key);
        const node = document.querySelector(`#settings-section [data-setting="${q(key)}"]`);
        const page = entry ? entry.page : node && pageOf(node);
        if (!page) return;
        closeResults();
        const input = document.getElementById('settings-search');
        if (input) input.value = '';
        const tab = document.querySelector(`#settings-section .tab-btn[data-tab="${q(page)}"]`);
        if (tab && !tab.classList.contains('active')) tab.click();
        let target;
        if (isFolded(entry)) {
            applyNow();
            const box = document.querySelector(`#settings-tab-${q(page)} > .settings-provider-fold`);
            if (box) box.open = true;
            target = box && box.querySelector(`[data-fold-key="${q(key)}"]`);
        } else {
            if (isAdvanced(entry)) S.show[page] = true;
            applyNow();
            target = await wait(() => firstPresent(page, key), 5000);
        }
        if (!target) return;
        target.scrollIntoView({ block: 'center' });
        target.classList.add('setting-found');
        window.setTimeout(() => target.classList.remove('setting-found'), 2000);
        const focusable = target.querySelector(
            'input:not([type="hidden"]):not([disabled]), select:not([disabled]), textarea:not([disabled]), button:not([disabled])');
        if (focusable) focusable.focus({ preventScroll: true });
    }

    function buildSearch() {
        const root = section();
        if (!root || document.getElementById('settings-search')) return;
        const tabs = root.querySelector('.tabs');
        if (!tabs) return;
        const box = el('div', 'settings-search');
        box.setAttribute('role', 'search');
        const input = el('input', 'form-control settings-search-input');
        input.type = 'search';
        input.id = 'settings-search';
        input.placeholder = 'Search settings';
        input.setAttribute('aria-label', 'Search settings');
        input.setAttribute('aria-controls', 'settings-search-results');
        input.autocomplete = 'off';
        const list = el('div', 'settings-search-results');
        list.id = 'settings-search-results';
        list.setAttribute('aria-label', 'Settings found');
        list.hidden = true;
        let timer = 0;
        input.addEventListener('input', () => {
            window.clearTimeout(timer);
            timer = window.setTimeout(() => showResults(input.value), 120);
        });
        input.addEventListener('keydown', (e) => {
            if (e.key === 'Escape') { input.value = ''; closeResults(); }
            else if (e.key === 'ArrowDown') {
                const first = list.querySelector('.settings-search-hit');
                if (first) { e.preventDefault(); first.focus(); }
            } else if (e.key === 'Enter') {
                window.clearTimeout(timer);
                showResults(input.value);
                const first = list.querySelector('.settings-search-hit');
                if (first) { e.preventDefault(); go(first.dataset.key); }
            }
        });
        list.addEventListener('keydown', (e) => {
            const hits = Array.from(list.querySelectorAll('.settings-search-hit'));
            const at = hits.indexOf(document.activeElement);
            if (e.key === 'ArrowDown' && at >= 0 && at < hits.length - 1) { e.preventDefault(); hits[at + 1].focus(); }
            else if (e.key === 'ArrowUp') { e.preventDefault(); (at > 0 ? hits[at - 1] : input).focus(); }
            else if (e.key === 'Escape') { input.value = ''; closeResults(); input.focus(); }
        });
        document.addEventListener('click', (e) => {
            if (!box.contains(e.target)) closeResults();
        });
        box.append(input, list);
        root.insertBefore(box, tabs);
    }

    // ------------------------------------------------------------------ start

    function start() {
        const root = section();
        if (!root) return;
        buildSearch();
        // Rows other scripts draw later, and what the app hides or shows, get their marks in the next frame.
        new MutationObserver(schedule).observe(root, {
            childList: true, subtree: true, attributes: true, attributeFilter: ['style', 'hidden'],
        });
        // Opening Settings reads the catalogue again (and says it has been seen).
        new MutationObserver(() => { if (root.classList.contains('active')) load(); })
            .observe(root, { attributes: true, attributeFilter: ['class'] });
        if (root.classList.contains('active')) load();
        applyNow();
    }

    if (document.readyState === 'loading') document.addEventListener('DOMContentLoaded', start);
    else start();

    window.SettingsLevels = { load, apply: applyNow, search, go };
})();
