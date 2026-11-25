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
 * Under two rows the page says what the counts the server reads mean for them: the passkeys in use that never
 * checked a PIN, fingerprint or face (under the rule that asks for one), and the accounts whose only second factor
 * is a passkey (under the Passkeys switch). A save that applies redraws its own row and reads the page again for
 * everything said around the rows; the other rows are left as they are, with whatever is typed in them.
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
    // The value in force of one setting, as a read of the page gives it.
    const valueOf = (data, key) => {
        const row = ((data && data.settings) || []).find((one) => one.key === key);
        return row ? row.value : undefined;
    };
    // The row of one setting as the page shows it now.
    const rowOf = (key) => {
        const box = byId('signin-passkey-settings');
        return box ? box.querySelector(`[data-setting="${key}"]`) : null;
    };

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
            // Locked by the deployment: shown, never changed here (the levels list it under "Set by your provider").
            // A setting no .env line sets keeps its default under the lock.
            item.querySelectorAll('input, select, textarea, button').forEach((n) => { n.disabled = true; });
            said.textContent = row.env ? 'Set by your provider.'
                : 'Kept at its default by your provider (locked): it cannot be changed here.';
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
                    reread();
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

    // Direct attestation with no trust anchors: every passkey anyone tries to add is refused (nothing can check the
    // authenticator's statement), while the ones already added keep signing in. With passkeys off nothing is added or
    // used, and there is nothing to say of it.
    const noAnchors = (data) => valueOf(data, 'webauthn_attestation') === 'direct' && Number(data.trust_anchors) === 0
        && valueOf(data, 'webauthn_mode') !== 'off';

    // Opened at another address than the vault's: the vault's may be the wrong one. Where this page's own address
    // could carry passkeys (a host name, not an IP address, over https or on this computer by name), the line says
    // how to make it the vault's: the first ALLOWED_HOSTS entry is the vault's address.
    function orFixTheAddress() {
        const host = String(location.hostname || '');
        const couldServe = host !== '' && !/^\d+(\.\d+){3}$/.test(host) && !host.startsWith('[')
            && (location.protocol === 'https:' || host === 'localhost');
        return couldServe ? ` If people open the vault at ${location.origin}, put that address first in ALLOWED_HOSTS `
            + 'in .env and run python dockvault.py restart.' : '';
    }

    function drawReadiness(data) {
        const line = byId('signin-passkey-readiness');
        if (!line) return;
        const ready = data.readiness || {};
        const blocked = noAnchors(data);
        line.hidden = false;
        if (ready.usable && ready.origin && ready.origin !== location.origin) {
            line.className = 'alert alert-warning mb-md';
            line.textContent = (blocked
                ? `Passkeys work at ${ready.origin}, which is not the address this page was opened at `
                    + `(${location.origin}). Open the vault there to use one: here the browser refuses. None can be `
                    + 'added now (see below).'
                : `Passkeys can be made at ${ready.origin}, which is not the address this page was opened at `
                    + `(${location.origin}). Open the vault there to add or use one: here the browser refuses.`)
                + orFixTheAddress();
        } else if (ready.usable && blocked) {
            line.className = 'alert alert-warning mb-md';
            line.textContent = `Passkeys work at ${ready.origin}: those already added sign in there. None can be added `
                + 'now (see below).';
        } else if (ready.usable) {
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

    // Under the line above the settings while direct attestation has no trust anchors: that no passkey can be added,
    // why (the server's words, which never name the file's path), and the two ways out. Attestation set to None is
    // a save the guards always let through: it asks for less than what is in force.
    function drawAnchors(data) {
        let line = byId('signin-passkey-anchors');
        if (!noAnchors(data)) {
            if (line) { line.textContent = ''; line.hidden = true; }
            return;
        }
        if (!line) {
            const ready = byId('signin-passkey-readiness');
            if (!ready || !ready.parentNode) return;
            line = el('div', 'alert alert-warning mb-md');
            line.id = 'signin-passkey-anchors';
            line.setAttribute('role', 'alert');
            ready.parentNode.insertBefore(line, ready.nextElementSibling);
        }
        const problem = String(data.trust_anchors_problem || '');
        const roles = valueOf(data, 'webauthn_required_roles');
        const running = valueOf(data, 'webauthn_mode') === 'required_for_roles' && Array.isArray(roles)
            && roles.length > 0 && !data.requirement_paused;
        line.hidden = false;
        line.textContent = 'Direct attestation is on, but the server finds no trust anchors: every passkey anyone '
            + 'tries to add is refused, and the passkeys already added keep signing in. '
            + (problem ? `${problem.charAt(0).toUpperCase()}${problem.slice(1)}. ` : '')
            + 'Point WEBAUTHN_ATTESTATION_ROOTS in .env at a readable PEM bundle of root certificates and restart the '
            + 'vault (python dockvault.py restart; a plain docker restart keeps the old .env), or set Attestation (an '
            + 'advanced setting) to None to let passkeys be added again.'
            + (running ? ' The passkey requirement keeps running meanwhile: people in the roles it names who hold no '
                + 'passkey are asked for one they cannot add.' : '');
    }

    // Under direct attestation: the passkeys added before it, which keep signing in and prove no compliance step-up.
    function drawOlder(data) {
        const line = byId('signin-passkey-older');
        if (!line) return;
        const count = Number(data.unattested_passkeys);
        if (!(count > 0)) { line.textContent = ''; line.hidden = true; return; }
        line.hidden = false;
        line.textContent = (count === 1 ? '1 passkey in use was' : `${count} passkeys in use were`)
            + ' added before this vault checked authenticator makes. '
            + (count === 1 ? 'It keeps' : 'They keep') + ' signing in and serving as a second factor, and '
            + (count === 1 ? 'does' : 'do') + ' not prove a compliance step-up until '
            + (count === 1 ? 'its owner adds it' : 'their owners add them') + ' again.';
    }

    // What the counts mean for two rows: the passkeys that never checked a PIN, fingerprint or face, under the rule
    // that asks for one (app/core/webauthn_settings.never_verified), and the accounts whose only second factor is a
    // passkey, under the Passkeys switch (only_a_passkey). Nothing is said where a count is 0.
    function drawCounts(data) {
        document.querySelectorAll('#signin-passkey-settings .signin-setting-note').forEach((note) => note.remove());
        const say = (key, text) => {
            const row = rowOf(key);
            if (row) row.appendChild(el('p', 'text-secondary text-sm mt-xs signin-setting-note', text));
        };
        const never = Number(data.passkeys_without_verification) || 0;
        const noOther = Number(data.accounts_with_only_such_passkeys) || 0;
        if (never > 0) {
            const one = never === 1;
            const keys = (one ? '1 passkey in use' : `${never} passkeys in use`)
                + ' never checked a PIN, fingerprint or face';
            const holders = noOther === 1 ? '1 account holds' : `${noOther} accounts hold`;
            if (valueOf(data, 'webauthn_require_uv')) {
                say('webauthn_require_uv', `${keys}: while this is on, ${one ? 'it counts' : 'they count'} as no `
                    + `second factor and ${one ? 'is' : 'are'} refused at any use that does not check one.`
                    + (noOther > 0 ? ` ${holders} no passkey that did: `
                        + (noOther === 1 ? 'without an authenticator app, it sets a second factor up again at its'
                            : 'those without an authenticator app set a second factor up again at their')
                        + ' next sign-in.' : ''));
            } else {
                say('webauthn_require_uv', `${keys}: turned on, this makes ${one ? 'it' : 'them'} count as no `
                    + `second factor and refuses ${one ? 'it' : 'them'} at any use that does not check one`
                    + (noOther > 0 ? `; ${holders} no passkey that did.` : '.'));
            }
        }
        const alone = Number(data.accounts_with_only_a_passkey) || 0;
        const admins = Number(data.administrators_with_only_a_passkey) || 0;
        if (alone > 0) {
            const one = alone === 1;
            let who = one ? '1 account' : `${alone} accounts`;
            if (admins > 0) {
                who += one ? ' (an administrator)'
                    : ` (${admins} of them ${admins === 1 ? 'an administrator' : 'administrators'})`;
            }
            if (valueOf(data, 'webauthn_mode') === 'off') {
                say('webauthn_mode', `${who} had a passkey as ${one ? 'its' : 'their'} only second factor: `
                    + `${one ? 'it sets' : 'they set'} an authenticator app up at ${one ? 'its' : 'their'} next `
                    + 'sign-in, and the passkeys count again when passkeys are turned back on.');
            } else {
                say('webauthn_mode', `${who} ${one ? 'has' : 'have'} a passkey as ${one ? 'its' : 'their'} only `
                    + `second factor. With Passkeys set to Off, ${one ? 'it sets' : 'they set'} an authenticator app `
                    + `up at ${one ? 'its' : 'their'} next sign-in.`);
            }
        }
    }

    // 'Required for roles' with no role chosen requires nobody (the requirement asks only the roles listed): said on
    // the Passkeys row, in a note of its own that the counts leave in place.
    function drawRolesNote(data) {
        document.querySelectorAll('#signin-passkey-settings .signin-roles-note').forEach((note) => note.remove());
        const roles = valueOf(data, 'webauthn_required_roles');
        if (valueOf(data, 'webauthn_mode') !== 'required_for_roles' || (Array.isArray(roles) && roles.length)) return;
        const row = rowOf('webauthn_mode');
        if (!row) return;
        const listed = ((data && data.settings) || []).find((one) => one.key === 'webauthn_required_roles');
        const label = (listed && listed.label) || 'Roles that must have a passkey';
        row.appendChild(el('p', 'alert alert-warning mt-xs signin-roles-note',
            `No role is chosen under “${label}”: nobody is required to hold a passkey.`));
    }

    // The accounts the server's operator lifted a role's passkey requirement for (python dockvault.py accounts,
    // clear-passkey-requirement), under the settings: the server sends the first 500 by name. A lifting ends when the
    // account adds a passkey or its role changes, or when the operator puts the requirement back.
    const LIFTED_SHOWN = 500;

    function drawLifted(data) {
        let box = byId('signin-passkey-lifted');
        const lifted = Array.isArray(data.requirement_lifted_for) ? data.requirement_lifted_for : [];
        if (!lifted.length) {
            if (box) { box.replaceChildren(); box.hidden = true; }
            return;
        }
        if (!box) {
            const settings = byId('signin-passkey-settings');
            if (!settings || !settings.parentNode) return;
            box = el('div', 'mt-md');
            box.id = 'signin-passkey-lifted';
            box.style.overflowWrap = 'anywhere';        // a long user name wraps on a phone
            settings.parentNode.insertBefore(box, settings.nextElementSibling);
        }
        const one = lifted.length === 1;
        const capped = lifted.length >= LIFTED_SHOWN;
        const who = capped ? `${lifted.length} accounts or more` : (one ? '1 account' : `${lifted.length} accounts`);
        const said = el('p', 'text-secondary text-sm',
            `The server's operator lifted the passkey requirement for ${who}: `
            + (one ? 'it is not' : 'none of them is') + ' asked for the passkey a role requires. It stays lifted for '
            + 'an account until the account adds a passkey or its role changes, or until the operator puts it back '
            + '(python dockvault.py accounts, restore-passkey-requirement).'
            + (capped ? ` The first ${LIFTED_SHOWN} by name are listed.` : ''));
        const list = el('ul', 'text-sm');
        lifted.forEach((entry) => {
            const since = entry.lifted_at ? new Date(entry.lifted_at) : null;
            const day = since && !Number.isNaN(since.getTime()) ? `, since ${since.toLocaleDateString()}` : '';
            list.appendChild(el('li', null, `${entry.username} (${named(entry.role)})${day}`));
        });
        box.replaceChildren(said, list);
        box.hidden = false;
    }

    // Everything said around the rows, from one read of the page.
    function drawAround(data) {
        drawReadiness(data);
        drawAnchors(data);
        drawOlder(data);
        drawCounts(data);
        drawRolesNote(data);
        drawLifted(data);
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
        box.replaceChildren(...(data.settings || []).map(drawRow));
        drawAround(data);
    }

    // After a save that applied: the page read again for what is said around the rows (the counts, and what the
    // setting just saved changed in them), without drawing the rows again. A read that fails leaves the page as it is.
    async function reread() {
        const mine = ++loads;
        let data;
        try {
            data = await apiRequest('/settings/sign-in', { silent: true });
        } catch (e) {
            return;
        }
        if (mine !== loads) return;
        drawAround(data);
    }

    // Nothing of one administrator's page is left for the next person on the tab.
    function reset() {
        loads += 1;
        const box = byId('signin-passkey-settings');
        if (box) box.replaceChildren();
        const line = byId('signin-passkey-readiness');
        if (line) { line.textContent = ''; line.hidden = true; }
        const older = byId('signin-passkey-older');
        if (older) { older.textContent = ''; older.hidden = true; }
        const anchors = byId('signin-passkey-anchors');
        if (anchors) { anchors.textContent = ''; anchors.hidden = true; }
        const lifted = byId('signin-passkey-lifted');
        if (lifted) { lifted.replaceChildren(); lifted.hidden = true; }
    }

    document.addEventListener('click', (e) => {
        const tab = e.target.closest && e.target.closest('.tab-btn[data-tab="signin"]');
        if (tab) load();
    });

    window.SignInSettings = { load, reset };
})();
