/*
 * The page /recording: what this vault records, read from GET /privacy/recording (public). For a signed-in
 * visitor (a session token in this browser), the earlier versions too, from GET /privacy/recording/history.
 * Built with createElement and textContent only; nothing on the page is inline, so it runs under the app's
 * content security policy unchanged.
 */
(function () {
    'use strict';

    function el(tag, cls, text) {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text != null) node.textContent = text;
        return node;
    }

    function byId(id) { return document.getElementById(id); }

    function token() {
        try { return localStorage.getItem('authToken') || sessionStorage.getItem('authToken'); } catch (_) { return null; }
    }

    function show(id) { const n = byId(id); if (n) n.hidden = false; }

    function render(data) {
        byId('always').textContent = data.always;
        const levels = byId('levels');
        levels.replaceChildren();
        data.levels.forEach((item) => {
            levels.appendChild(el('dt', null, item.label));
            levels.appendChild(el('dd', 'level-' + item.level, item.words));
        });
        if (data.fingerprints) { byId('fingerprints').textContent = data.fingerprints; show('fingerprints'); }
        show('levels-section');

        const stores = byId('stores');
        stores.replaceChildren();
        data.stores.forEach((store) => {
            const li = el('li');
            li.appendChild(el('span', 'what', store.what));
            li.appendChild(el('span', 'kept', ' ' + store.kept));
            if (store.follows_levels) li.appendChild(el('span', 'muted', ' The levels above apply here.'));
            stores.appendChild(li);
        });
        show('kept-section');

        const who = byId('who');
        who.replaceChildren();
        data.who_can_see.forEach((line) => who.appendChild(el('li', null, line)));
        show('who-section');

        byId('basis').textContent = data.legal_basis
            ? `Legal basis, as the operator states it: ${data.legal_basis}`
            : 'The operator of this vault has not stated a legal basis here.';
        byId('contact').textContent = data.contact
            ? `Questions about this: ${data.contact}` : 'Ask the operator of this vault.';
        show('basis-section');
        byId('changes').textContent = data.changes;
    }

    function renderHistory(data) {
        const list = byId('history');
        list.replaceChildren();
        (data.versions || []).forEach((v) => {
            const li = el('li');
            const when = v.since ? new Date(v.since).toLocaleDateString() : '';
            li.appendChild(el('strong', null, `Version ${v.version}`));
            li.appendChild(el('span', 'muted', ` since ${when}: ${v.why}`));
            const ul = el('ul');
            v.levels.forEach((l) => ul.appendChild(el('li', null, `${l.label}: ${l.words}`)));
            li.appendChild(ul);
            list.appendChild(li);
        });
        if ((data.versions || []).length) show('history-section');
    }

    async function load() {
        try {
            const r = await fetch('/privacy/recording', { headers: { Accept: 'application/json' } });
            if (!r.ok) throw new Error(String(r.status));
            render(await r.json());
            byId('loading').hidden = true;
        } catch (_) {
            byId('loading').hidden = true;
            show('failed');
            return;
        }
        try {
            const b = await fetch('/branding');
            if (b.ok) { const j = await b.json(); if (j && j.app_name) byId('brand-name').textContent = j.app_name; }
        } catch (_) { /* the default name stays */ }
        const t = token();
        if (!t) return;
        try {
            const r = await fetch('/privacy/recording/history', { headers: { Authorization: `Bearer ${t}` } });
            if (r.ok) renderHistory(await r.json());
        } catch (_) { /* the history is for signed-in visitors only */ }
    }

    load();
})();
