/*
 * Settings -> Sign-in: how people sign in. The passkey settings (GET /settings/sign-in, PUT
 * /settings/sign-in/{setting}, app/api/sign_in_settings_router.py), each saved on its own: a change asks for the
 * administrator's password (and their second factor when they have one), never rides "Save All Changes", and is
 * refused by the server, with its reason shown here, when a guard says no.
 *
 * The line above the settings says whether a passkey can be made at the vault's address, in the server's own
 * words, with what to change when it cannot: the address is the first ALLOWED_HOSTS entry, set in .env, never
 * something this page can change.
 *
 * Every row is marked data-setting="<key>", so the levels (essential, advanced, set by the provider) and the
 * search treat it as they treat every other setting (static/js/settings-levels.js).
 *
 * Uses app.js's apiRequest and showToast. Builds everything with createElement and textContent.
 */
(function () {
    'use strict';

    const byId = (id) => document.getElementById(id);
    const el = (tag, cls, text) => {
        const node = document.createElement(tag);
        if (cls) node.className = cls;
        if (text !== undefined && text !== null) node.textContent = text;
        return node;
    };
    // What a choice is called on the page; a choice with no name here shows as the server wrote it.
    const NAMES = {
        off: 'Off', optional: 'Optional', required_for_roles: 'Required for roles',
        none: 'None', direct: 'Direct',
        admin: 'Administrators', user: 'Users', external: 'External people',
    };
    const named = (choice) => (Object.prototype.hasOwnProperty.call(NAMES, choice) ? NAMES[choice] : String(choice));
    let loads = 0;      // only the latest read draws the page

    // The control of one setting: its element, and how to read the value it holds.
    function control(row, id) {
        if (row.kind === 'bool') {
            const box = el('input');
            box.type = 'checkbox'; box.id = id; box.checked = !!row.value;
            return { node: box, read: () => box.checked, inline: true };
        }
        if (row.kind === 'enum') {
            const select = el('select', 'form-control');
            select.id = id;
            (row.choices || []).forEach((choice) => {
                const option = el('option', null, named(choice));
                option.value = choice;
                select.appendChild(option);
            });
            select.value = row.value;
            return { node: select, read: () => select.value };
        }
        if (row.kind === 'int') {
            const number = el('input', 'form-control');
            number.type = 'number'; number.id = id; number.value = row.value;
            if (row.min !== null && row.min !== undefined) number.min = row.min;
            if (row.max !== null && row.max !== undefined) number.max = row.max;
            return { node: number, read: () => (number.value === '' ? null : Number(number.value)) };
        }
        const chosen = Array.isArray(row.value) ? row.value : [];
        if ((row.choices || []).length) {
            const group = el('div', 'signin-choices');
            group.setAttribute('role', 'group');
            const boxes = row.choices.map((choice, i) => {
                const label = el('label', 'checkbox-label');
                const box = el('input');
                box.type = 'checkbox'; box.id = `${id}-${i}`; box.value = choice; box.checked = chosen.includes(choice);
                label.appendChild(box);
                label.appendChild(document.createTextNode(' ' + named(choice)));
                group.appendChild(label);
                return box;
            });
            return { node: group, read: () => boxes.filter((b) => b.checked).map((b) => b.value), group: true };
        }
        const lines = el('textarea', 'form-control');
        lines.id = id; lines.rows = 3; lines.value = chosen.join('\n');
        lines.placeholder = 'One on each line';
        return { node: lines, read: () => lines.value.split(/[\s,]+/).filter(Boolean) };
    }

    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

    function drawRow(row) {
        const id = `signin-setting-${row.key}`;
        const item = el('div', 'form-group signin-setting');
        item.dataset.setting = row.key;
        const field = control(row, id);
        const title = field.group ? el('strong', 'signin-setting-title', row.label) : el('label', null, row.label);
        if (!field.group) title.htmlFor = id;
        if (field.inline) {
            title.textContent = '';
            title.className = 'checkbox-label';
            title.appendChild(field.node);
            title.appendChild(document.createTextNode(' ' + row.label));
            item.appendChild(title);
        } else {
            item.appendChild(title);
            if (field.group) field.node.setAttribute('aria-label', row.label);
            item.appendChild(field.node);
        }
        if (row.unit && row.kind === 'int') item.appendChild(el('span', 'text-secondary text-sm', ` ${row.unit}`));
        if (row.help) item.appendChild(el('p', 'text-secondary text-sm mt-xs', row.help));

        const actions = el('div', 'signin-setting-actions mt-xs');
        const save = el('button', 'btn btn-primary btn-sm', 'Save');
        save.type = 'button'; save.disabled = true;
        const said = el('span', 'text-sm signin-setting-said');
        said.setAttribute('role', 'status');
        actions.appendChild(save);
        let back = null;
        if (row.stored !== null && row.stored !== undefined) {
            back = el('button', 'btn btn-link btn-sm', 'Use the default');
            back.type = 'button';
            actions.appendChild(back);
        }
        actions.appendChild(said);
        item.appendChild(actions);

        if (row.locked) {
            // Set in the deployment: shown, never changed here (the levels list it under "Set by your provider").
            item.querySelectorAll('input, select, textarea, button').forEach((n) => { n.disabled = true; });
            said.textContent = 'Set by your provider.';
            return item;
        }
        const changed = () => { save.disabled = same(field.read(), row.value); said.textContent = ''; };
        item.addEventListener('input', changed);
        item.addEventListener('change', changed);
        const send = async (value) => {
            save.disabled = true;
            if (back) back.disabled = true;
            said.className = 'text-sm signin-setting-said';
            said.textContent = 'Saving...';
            try {
                const out = await apiRequest(`/settings/sign-in/${encodeURIComponent(row.key)}`, {
                    method: 'PUT', body: JSON.stringify({ value }), silent: true,
                });
                if (out && out.status === 'applied') {
                    showToast(`${row.label}: saved.`, 'success');
                    item.replaceWith(drawRow(out.setting));
                    return;
                }
                // Held for another administrator, or waiting out its delay: nothing changed yet.
                said.textContent = 'The change was recorded and is not in force yet.';
            } catch (e) {
                said.className = 'text-sm signin-setting-said text-error';
                said.setAttribute('role', 'alert');
                said.textContent = e.message || 'The change was not saved.';
                save.disabled = same(field.read(), row.value);
            }
            if (back) back.disabled = false;
        };
        save.addEventListener('click', () => send(field.read()));
        if (back) back.addEventListener('click', () => send(null));
        return item;
    }

    function drawReadiness(data) {
        const line = byId('signin-passkey-readiness');
        if (!line) return;
        const ready = data.readiness || {};
        line.hidden = false;
        if (ready.usable) {
            line.className = 'alert alert-info mb-md';
            line.textContent = `Passkeys can be made at ${ready.origin}. A passkey works only at the address it was `
                + 'made at, so changing the vault\'s address later leaves every passkey unusable.';
        } else {
            line.className = 'alert alert-warning mb-md';
            line.textContent = 'No passkey can be made at this vault yet, whatever is chosen below. '
                + (data.why_not || '')
                + (data.requirement_paused ? ' The passkey requirement below is paused until then: nobody is held at '
                    + 'the sign-in for a passkey that cannot be made, and the time to set one up starts over.' : '');
        }
    }

    async function load() {
        const box = byId('signin-passkey-settings');
        if (!box) return;
        // These settings are the administrators': their reads are refused, and recorded, for anyone else.
        const user = typeof currentUser !== 'undefined' ? currentUser : null;
        if (!user || user.role !== 'admin') return;
        const mine = ++loads;
        let data;
        try {
            data = await apiRequest('/settings/sign-in', { silent: true });
        } catch (e) {
            if (mine === loads) showToast(`The sign-in settings could not be read: ${e.message}`, 'error');
            return;
        }
        if (mine !== loads) return;
        drawReadiness(data);
        box.replaceChildren(...(data.settings || []).map(drawRow));
    }

    // Nothing of one administrator's page is left for the next person on the tab.
    function reset() {
        loads += 1;
        const box = byId('signin-passkey-settings');
        if (box) box.replaceChildren();
        const line = byId('signin-passkey-readiness');
        if (line) { line.textContent = ''; line.hidden = true; }
    }

    document.addEventListener('click', (e) => {
        const tab = e.target.closest && e.target.closest('.tab-btn[data-tab="signin"]');
        if (tab) load();
    });

    window.SignInSettings = { load, reset };
})();
