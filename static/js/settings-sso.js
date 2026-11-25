/*
 * Settings -> Sign-in: the single sign-on providers (GET/POST /admin/sso/providers, PATCH, POST .../state, DELETE,
 * app/api/sso_providers_router.py; a test sign-in starts in static/js/sso.js).
 *
 * The card lists the providers in the sign-in page's order, each with what it is now (on, off and tested, off and
 * not tested), and says whether the vault has an address a provider can send a browser back to (the first
 * ALLOWED_HOSTS entry, set in .env: nothing here can change it). "Add a provider" asks for a name and a kind and
 * makes a draft, so the two addresses the provider's own console asks for exist before anything else is typed. A
 * provider opens in a dialog with its pages: Connection (with the addresses to copy and the test sign-in), Access,
 * Second factor, Sessions. Each page is saved on its own and sends only what changed; a change asks for the
 * administrator's password (and their second factor when they have one), and what the server refuses is shown in
 * its own words. The client secret is typed, sent, and never shown again. A fifth page, Identities, lists the
 * accounts linked to the provider (GET /admin/sso/providers/{id}/identities) and where each stands, lifts a
 * refusal or a hold (POST /admin/sso/identities/{id}/clear-refusal) and unlinks an account (DELETE
 * /admin/sso/identities/{id}), each under the same step-up as a change. A save, a turn-on or a turn-off says what
 * it did to the sessions and the accounts linked to the provider, as the server answers it; sessions a turn-off
 * could not end are said on the dialog until "Turn off again" (a provider that is off) has ended them.
 *
 * When the deployment locks single sign-on (SETTINGS_LOCKED_KEYS naming sso or *), the server refuses every change
 * to a provider, and the card and the dialog say so in the server's words (`locked_message`) and offer none: no "Add
 * a provider", Turn on or off, Turn off again, Remove or Save, and a provider's fields are read-only. Open, the test
 * sign-in, the addresses to copy and the Identities page's Lift and Unlink stay, as their routes do.
 *
 * Uses app.js's apiRequest, openModal, closeModal, showConfirm, showToast and _el, and sso.js's Sso.startTest.
 * Builds everything with createElement and textContent.
 */
(function () {
    'use strict';

    const byId = (id) => document.getElementById(id);
    let data = null;            // the last list read
    let loads = 0;              // only the latest read draws the card
    let open = null;            // the provider the dialog shows, as last read
    let page = 'connection';    // the dialog's page
    let drafts = {};            // typed and not saved, by page: {field id: value}, kept while another page is shown
    let fresh = {};             // the values the page on screen was built with
    let identitiesFrom = 0;     // where the Identities page starts in the provider's list of accounts
    let identityReads = 0;      // only the latest read of that list draws it
    let identitiesNote = null;  // a refused removal's sentence, said once at the top of the Identities page
    let standing = {};          // by provider: sessions a turn-off could not end (a number; null: not counted)

    const ICON_NAMES = { generic: 'Plain', microsoft: 'Microsoft', google: 'Google', okta: 'Okta', keycloak: 'Keycloak', authentik: 'Authentik' };
    const PAGES = [['connection', 'Connection'], ['access', 'Access'], ['factor', 'Second factor'], ['sessions', 'Sessions'],
        ['identities', 'Identities']];

    function status(provider) {
        if (provider.state === 'enabled') return ['On', 'badge-success'];
        if (!provider.configured) return ['Draft', 'badge-secondary'];
        return provider.tested ? ['Off · tested', 'badge-info'] : ['Off · not tested', 'badge-warning'];
    }

    const lines = (value) => String(value || '').split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    // Required groups are one on each line: a group's name may hold a comma (a distinguished name has several), and
    // a group is matched letter for letter (sso_policy.restriction), so it is never cut at one.
    const groupLines = (value) => String(value || '').split(/\n+/).map((s) => s.trim()).filter(Boolean);
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);
    // The deployment's lock, as the last read of the list says.
    const lockedNow = () => !!(data && data.locked);
    const LOCKED_FALLBACK = 'Single sign-on is locked in this deployment: nothing can be changed here.';

    // ---------------------------------------------------------------- the card

    function drawAddress() {
        const line = byId('signin-sso-address');
        if (!line) return;
        const address = (data && data.address) || {};
        line.hidden = false;
        if (address.usable && address.base && address.base !== location.origin) {
            line.className = 'alert alert-warning mb-md';
            line.textContent = `Providers send people back to ${address.base}, which is not the address this page was `
                + `opened at (${location.origin}). A sign-in, a link or a test started here does not come back here: `
                + 'open the vault there.';
        } else if (address.usable) {
            line.className = 'alert alert-info mb-md';
            line.textContent = `Providers send people back to ${address.base}. Changing the vault's address later means `
                + 'giving every provider its new redirect address.';
        } else {
            line.className = 'alert alert-warning mb-md';
            line.textContent = 'No provider can be tested or turned on yet. ' + (address.why_not || '');
        }
    }

    // Under the lock: a line above the list says so, in the server's words; without it the line is hidden.
    function drawLocked() {
        let line = byId('signin-sso-locked');
        if (!lockedNow()) {
            if (line) { line.textContent = ''; line.hidden = true; }
            return;
        }
        if (!line) {
            const anchor = byId('signin-sso-address') || byId('signin-sso-providers');
            if (!anchor || !anchor.parentNode) return;
            line = _el('div', 'alert alert-info mb-md');
            line.id = 'signin-sso-locked';
            line.setAttribute('role', 'status');
            anchor.parentNode.insertBefore(line, anchor);
        }
        line.hidden = false;
        line.textContent = data.locked_message || LOCKED_FALLBACK;
    }

    function drawRow(provider) {
        const row = _el('div', 'sso-provider-row flex items-center gap-sm mb-sm');
        row.dataset.provider = provider.id;
        const text = _el('div', 'flex-1');
        const title = _el('div', 'text-sm font-bold', provider.label || provider.name);
        const [word, badge] = status(provider);
        const mark = _el('span', 'badge ' + badge + ' ml-sm sso-provider-status', word);
        title.appendChild(mark);
        text.appendChild(title);
        const bits = [provider.name];
        if (provider.issuer) bits.push(provider.issuer);
        bits.push(provider.identities === 1 ? '1 linked account' : `${provider.identities} linked accounts`);
        if (provider.state === 'enabled' && !provider.tested) bits.push('changed since its last test');
        text.appendChild(_el('div', 'text-secondary text-xs', bits.join(' · ')));
        row.appendChild(text);
        const edit = _el('button', 'btn btn-secondary btn-sm', 'Open');
        edit.type = 'button';
        // Which provider it opens: its button text, and its name where they differ (a name is never shared).
        edit.setAttribute('aria-label', 'Open ' + (provider.label || provider.name)
            + (provider.label && provider.label !== provider.name ? ` (${provider.name})` : ''));
        edit.addEventListener('click', () => show(provider.id, 'connection'));
        row.appendChild(edit);
        return row;
    }

    function draw() {
        const box = byId('signin-sso-providers');
        if (!box || !data) return;
        drawLocked();
        drawAddress();
        const providers = data.providers || [];
        box.replaceChildren(...providers.map(drawRow));
        if (!providers.length) {
            box.appendChild(_el('p', 'text-secondary text-sm mb-sm', 'No provider yet. People sign in with their password'
                + ' (and a passkey, when they have one).'));
        }
        const add = byId('signin-sso-add');
        if (add) add.disabled = lockedNow() || providers.length >= (data.limit || 20);
    }

    async function load() {
        const box = byId('signin-sso-providers');
        if (!box) return null;
        const user = typeof currentUser !== 'undefined' ? currentUser : null;
        if (!user || user.role !== 'admin') return null;
        const mine = ++loads;
        let read;
        try { read = await apiRequest('/admin/sso/providers', { silent: true }); }
        catch (e) {
            if (mine === loads) showToast(`The single sign-on providers could not be read: ${e.message}`, 'error');
            return null;
        }
        if (mine !== loads) return null;
        data = read;
        draw();
        return data;
    }

    // ---------------------------------------------------------------- form pieces

    function field(labelText, control, help) {
        const group = _el('div', 'form-group');
        const label = _el('label', null, labelText);
        if (control.id) label.htmlFor = control.id;
        group.appendChild(label);
        group.appendChild(control);
        if (help) group.appendChild(_el('p', 'text-secondary text-sm mt-xs', help));
        return group;
    }

    function input(id, value, type) {
        const node = _el('input', 'form-control');
        node.id = id; node.type = type || 'text'; node.value = value === null || value === undefined ? '' : value;
        return node;
    }

    function area(id, list) {
        const node = _el('textarea', 'form-control');
        node.id = id; node.rows = 3; node.value = (list || []).join('\n'); node.placeholder = 'One on each line';
        return node;
    }

    function choice(id, options, value) {
        const node = _el('select', 'form-control');
        node.id = id;
        options.forEach(([key, text]) => { const o = _el('option', null, text); o.value = key; node.appendChild(o); });
        node.value = value;
        return node;
    }

    function tick(id, text, checked, help) {
        const group = _el('div', 'form-group');
        const label = _el('label', 'checkbox-label');
        const box = _el('input');
        box.type = 'checkbox'; box.id = id; box.checked = !!checked;
        label.appendChild(box);
        label.appendChild(document.createTextNode(' ' + text));
        group.appendChild(label);
        if (help) group.appendChild(_el('p', 'text-secondary text-sm mt-xs', help));
        return { group, box };
    }

    // An address to give the provider: read-only, named by its label for a screen reader, with a Copy button that
    // says what it copies, and a line of help when the address is only sometimes needed.
    function copyLine(labelText, value, id, help) {
        const group = _el('div', 'form-group');
        const label = _el('label', null, labelText);
        label.htmlFor = id;
        group.appendChild(label);
        const row = _el('div', 'flex items-center gap-sm');
        const shown = _el('input', 'form-control');
        shown.id = id; shown.readOnly = true; shown.value = value;
        const copy = _el('button', 'btn btn-secondary btn-sm', 'Copy');
        copy.type = 'button';
        copy.setAttribute('aria-label', 'Copy ' + labelText.charAt(0).toLowerCase() + labelText.slice(1));
        copy.addEventListener('click', async () => {
            try { await navigator.clipboard.writeText(value); showToast('Copied.', 'success'); }
            catch (_) { shown.select(); showToast('Select the address and copy it.', 'info'); }
        });
        row.appendChild(shown);
        row.appendChild(copy);
        group.appendChild(row);
        if (help) group.appendChild(_el('p', 'text-secondary text-sm mt-xs', help));
        return group;
    }

    // A page's Save: `collect()` gives what the page holds now; only what differs from the provider as read is sent.
    function saveBar(collect, said) {
        const bar = _el('div', 'sso-save mt-md');
        const save = _el('button', 'btn btn-primary btn-sm', 'Save');
        save.type = 'button';
        save.id = 'sso-save';
        save.disabled = lockedNow();
        bar.appendChild(save);
        bar.appendChild(said);
        save.addEventListener('click', async () => {
            if (lockedNow()) return;
            const body = collect();
            said.className = 'text-sm ml-sm sso-said';
            said.setAttribute('role', 'status');
            if (!Object.keys(body).length) { said.textContent = 'Nothing was changed.'; return; }
            save.disabled = true;
            said.textContent = 'Saving...';
            const saved = open.id;
            try {
                const out = await apiRequest(`/admin/sso/providers/${encodeURIComponent(saved)}`, {
                    method: 'PATCH', body: JSON.stringify(body), silent: true,
                });
                // Sessions a turn-off by this save could not end are said on the dialog until they are ended.
                if (out.turned_off) noteStanding(saved, 'disabled', out);
                // An answer that comes after the dialog was closed, or opened on another provider, draws nothing
                // into it: the list is read again and says what was saved.
                if (!open || open.id !== saved) { load(); return; }
                open = out.provider;
                let told = 'Saved.';
                if (out.connection_changed && open.state !== 'enabled') told = 'Saved. Run a test sign-in before turning it on.';
                if (out.turned_off) {
                    told = 'Saved. The connection changed, so the provider was turned off: run a test sign-in, then '
                        + 'turn it on again.';
                    if (out.sessions_ended) {
                        told += ` ${out.sessions_ended} session(s) that came through it were ended.`;
                    }
                    if (out.held) {
                        told += ` ${out.held} account(s) whose days there had run out stay held: lift each on the `
                            + 'Identities page when it should have its keys back.';
                    }
                    const left = standingSaid(out.sessions_not_ended, 'it');
                    if (left) told += ' ' + left;
                }
                if (out.secret_cleared) told += ' Enter the client secret again: it is kept only for the address it was entered for.';
                if ((out.made_sso_only || []).length) told += ` ${out.made_sso_only.length} linked account(s) now sign in only through it.`;
                if ((out.restored || []).length) {
                    // "Forgot your password?" sends a link only where the vault offers it (off by default; the server
                    // says so in self_service_reset), and only to an account with an email address.
                    told += ` ${out.restored.length} linked account(s) may hold a password again and have none yet: `
                        + (out.self_service_reset
                            ? 'each that has an email address can set one with "Forgot your password?" on the sign-in '
                              + 'page, and you can make a reset link for any of them on the Users page.'
                            : 'make each a reset link on the Users page.');
                }
                if (out.owners_told) {
                    told += ` The ${out.owners_told} account(s) linked to it were told it was pointed somewhere else.`;
                }
                // Whom the provider's days hold now that they changed (the other administrators are told the same).
                if (out.newly_held) {
                    told += ` ${out.newly_held} more linked account(s) have not signed in through it within its days `
                        + 'as they are now: their password and passkeys do not sign them in until they have. They were '
                        + `told. ${out.held_by_its_days} account(s) are held so in all.`;
                } else if (out.held_by_its_days) {
                    told += ` ${out.held_by_its_days} linked account(s) are held to a sign-in through it by its days.`;
                }
                showToast(told, out.turned_off && standsIn(out) ? 'warning' : 'success');
                delete drafts[page];                       // this page was saved; the others keep what was typed
                drawDialog({ keep: false, focus: 'sso-save' });
                load();
            } catch (e) {
                said.className = 'text-sm ml-sm sso-said text-error';
                said.setAttribute('role', 'alert');
                said.textContent = e.message || 'The change was not saved.';
                save.disabled = false;
            }
        });
        return bar;
    }

    // What a page of the dialog holds, as the fields to send: only those that differ from the provider as read.
    function changed(now, before) {
        const out = {};
        Object.keys(now).forEach((key) => { if (!same(now[key], before[key])) out[key] = now[key]; });
        return out;
    }

    // ---------------------------------------------------------------- the dialog's pages

    function testSummary(provider) {
        const box = _el('div', 'sso-test mt-md');
        box.id = 'sso-test-summary';
        const last = provider.last_test;
        if (!last) {
            box.appendChild(_el('p', 'text-secondary text-sm', 'No test sign-in yet.'));
            return box;
        }
        const head = last.outcome === 'ok' ? 'The last test sign-in passed' : 'The last test sign-in did not pass';
        box.appendChild(_el('p', 'text-sm font-bold', head + (last.tester ? ` (${last.tester})` : '') + '.'
            + (provider.tested ? '' : ' The connection changed since: test again.')));
        if (last.outcome !== 'ok') {
            // A test that did not pass says why, in words for the one who can change the settings; nothing the
            // provider sent is shown, because nothing it sent was accepted.
            box.appendChild(_el('p', 'text-sm text-error', last.message || 'The test sign-in did not pass.'));
            return box;
        }
        const list = _el('ul', 'text-sm');
        const add = (text) => list.appendChild(_el('li', null, text));
        if (last.would) add('What the vault would do with this person: ' + last.would + '.');
        add('Email address: ' + (last.email_present ? (last.email_verified ? 'sent, verified by the provider' : 'sent, not verified') : 'not sent') + '.');
        add('Time of the sign-in (auth_time): ' + (last.auth_time_present ? 'sent' : 'not sent: the provider cannot confirm a person afresh for a step-up') + '.');
        add('Second factor at the provider: ' + ((last.amr || []).length ? 'amr ' + last.amr.join(', ') : 'no amr')
            + (last.acr ? ', acr ' + last.acr : '') + (last.mfa_trusted ? ' (counts as the second factor here)' : ' (does not count here)') + '.');
        add('Groups: ' + ((last.groups || []).length ? last.groups.join(', ') : 'none sent') + '.');
        add('Claims received: ' + ((last.claim_names || []).join(', ') || 'none') + '.');
        box.appendChild(list);
        return box;
    }

    function connectionPage(provider) {
        const box = _el('div');
        const preset = ((data && data.presets) || []).find((p) => p.icon === provider.icon && p.id !== 'oidc')
            || ((data && data.presets) || []).find((p) => p.id === 'oidc') || {};
        if (provider.addresses) {
            box.appendChild(_el('p', 'text-secondary text-sm mb-sm', 'Give these to the provider. ' + (preset.console || '')));
            box.appendChild(copyLine('Redirect address', provider.addresses.redirect_uri, 'sso-redirect-uri'));
            box.appendChild(copyLine('Back-channel logout address', provider.addresses.backchannel_logout_uri, 'sso-logout-uri'));
            box.appendChild(copyLine('Sign-out return address', provider.addresses.post_logout_redirect_uri, 'sso-post-logout-uri',
                'Only when signing out here also signs the person out at the provider (Sessions): the provider sends '
                + 'the browser back here after its own logout, and refuses an address it was not given.'));
            box.appendChild(copyLine('Sign-in link to hand out', provider.addresses.sign_in_link, 'sso-sign-in-link'));
        }
        const name = input('sso-name', provider.name);
        const label = input('sso-label', provider.label);
        const icon = choice('sso-icon', ((data && data.icons) || []).map((i) => [i, ICON_NAMES[i] || i]), provider.icon || 'generic');
        const order = input('sso-order', provider.sort_order, 'number');
        order.min = 0; order.max = 999;
        const shown = tick('sso-show', 'Show a button on the sign-in page', provider.show_on_sign_in,
            'Without the button, people use the sign-in link above.');
        const issuer = input('sso-issuer', provider.issuer);
        issuer.placeholder = preset.issuer_example || 'https://';
        const clientId = input('sso-client-id', provider.client_id);
        const secret = input('sso-client-secret', '', 'password');
        secret.autocomplete = 'new-password';
        secret.placeholder = provider.has_client_secret ? 'Stored. Type a new one to replace it.' : '';
        const scopes = input('sso-scopes', provider.scopes);
        const auth = choice('sso-token-auth', [['client_secret_basic', 'In the request header (basic)'], ['client_secret_post', 'In the request body (post)']], provider.token_auth);
        const discovery = input('sso-discovery', provider.discovery_url);
        const inside = tick('sso-private', 'The provider is inside the network', provider.private_network,
            'Lets the vault call a provider on a private address or name. Leave it off for a provider on the internet.');
        box.appendChild(field('Name', name, 'For administrators: in this list, in notices and in the records.'));
        box.appendChild(field('Button text', label, 'What the sign-in page\'s button says. Empty: the name.'));
        box.appendChild(field('Provider type', icon, 'Which provider this is: it chooses the instructions shown above for its console.'));
        box.appendChild(field('Order', order, 'Lower comes first on the sign-in page.'));
        box.appendChild(shown.group);
        box.appendChild(field('Issuer', issuer, preset.issuer_help || ''));
        box.appendChild(field('Client ID', clientId));
        box.appendChild(field('Client secret', secret, 'Kept encrypted and never shown again.'));
        box.appendChild(field('Scopes', scopes, 'Separated by spaces; openid is always among them.'));
        box.appendChild(field('How the secret is sent', auth));
        box.appendChild(field('Discovery address', discovery, 'Only when it is not <issuer>/.well-known/openid-configuration.'));
        box.appendChild(inside.group);
        const claimKeys = [['username', 'Username'], ['email', 'Email address'], ['email_verified', 'Email verified'],
            ['name', 'Display name'], ['groups', 'Groups'], ['tenant', 'Tenant'], ['domain', 'Hosted domain']];
        const claimInputs = {};
        const claimBox = _el('div', 'sso-claims');
        claimBox.appendChild(_el('p', 'text-secondary text-sm', 'Claim names, when the provider calls them something else. Empty: the usual name.'));
        claimKeys.forEach(([key, text]) => {
            claimInputs[key] = input('sso-claim-' + key, (provider.claims || {})[key]);
            claimBox.appendChild(field(text, claimInputs[key]));
        });
        box.appendChild(claimBox);
        const said = _el('span', 'text-sm ml-sm sso-said');
        box.appendChild(saveBar(() => {
            const claims = {};
            claimKeys.forEach(([key]) => { const v = claimInputs[key].value.trim(); if (v) claims[key] = v; });
            const now = {
                name: name.value.trim(), label: label.value.trim() || null, icon: icon.value,
                sort_order: Number(order.value), show_on_sign_in: shown.box.checked, issuer: issuer.value.trim(),
                client_id: clientId.value.trim(), scopes: scopes.value.trim(), token_auth: auth.value,
                discovery_url: discovery.value.trim() || null, private_network: inside.box.checked, claims,
            };
            const before = Object.assign({}, provider, { claims: provider.claims || {}, issuer: provider.issuer || '', client_id: provider.client_id || '' });
            const out = changed(now, before);
            if (secret.value) out.client_secret = secret.value;
            return out;
        }, said));

        // The test sign-in: the page leaves for the provider and comes back with what it sent.
        const test = _el('button', 'btn btn-secondary btn-sm mt-md', 'Test sign-in');
        test.type = 'button';
        test.id = 'sso-test';
        test.disabled = !provider.configured || !(data && data.address && data.address.usable);
        test.addEventListener('click', async () => {
            test.disabled = true;
            try { await Sso.startTest(provider.id); }
            catch (e) { test.disabled = false; showToast(e.message || 'The test could not be started.', 'error'); }
        });
        box.appendChild(test);
        box.appendChild(_el('p', 'text-secondary text-sm mt-xs', 'You sign in at the provider in this tab and come back here. '
            + 'Nobody is signed in or linked by a test. Save your changes first.'));
        box.appendChild(testSummary(provider));
        return box;
    }

    function accessPage(provider) {
        const box = _el('div');
        const policy = provider.policy || {};
        const tenants = area('sso-tenants', policy.sso_allowed_tenants);
        const domains = area('sso-domains', policy.sso_allowed_domains);
        const groups = area('sso-groups', policy.sso_required_groups);
        // The account policy's sign-up domain list (sso_policy.restriction): held to in every mode but Off; only an
        // allow-list with domains on it says who may sign in (sso_policy.is_restricted).
        const signup = tick('sso-signup-domains', 'Also hold people to the sign-up domain list', policy.sso_use_signup_domains,
            'The Email domain gate on the Accounts & Access page, when it is on. An allow-list admits only its domains '
            + 'and, when it holds any, counts as saying who may sign in, which making accounts at a first sign-in and '
            + 'linking by email need; a deny-list keeps its domains out and does not count. Either way, a person '
            + 'whose domain the provider does not vouch for (no verified address, or at a provider with an '
            + 'organisation-domain claim, no such claim) is kept out. Set to Off there, this does nothing.');
        const creation = choice('sso-creation', [['invite_only', 'Only invited or linked people sign in'],
            ['jit', 'Make an account at a person\'s first sign-in']], policy.sso_account_creation);
        const role = choice('sso-role', [['user', 'User'], ['external', 'External']], policy.sso_default_role);
        const byEmail = tick('sso-link-email', 'Link an existing account by its email address', policy.sso_link_by_email,
            'The provider must have verified the address, and the vault must have confirmed it for the account: an '
            + 'administrator or an invitation set it, or its owner confirmed it with an emailed code. An address a person '
            + 'wrote on their own account links nothing; a test sign-in says what would happen. Only for a provider that '
            + 'says who may sign in, and never for an administrator, an auditor, or an account that set up its own '
            + 'second factor: its owner links the provider under Your account.');
        const password = choice('sso-password', [['allowed', 'Linked accounts keep their password'],
            ['disabled', 'Linked accounts sign in only through this provider']], policy.sso_password_login);
        const madeHere = tick('sso-jit-password', 'An account made at a first sign-in may set a password', policy.sso_jit_password,
            'Off: an account this provider makes signs in only through it, whatever is chosen above, so a person the '
            + 'provider no longer signs in cannot give themselves a password and stay. Making such an account an '
            + 'administrator ends that for it: it is sent a link to choose a password.');
        box.appendChild(_el('p', 'text-secondary text-sm mb-sm', 'Who may sign in through this provider. With none of the '
            + 'three lists, and the sign-up domain list not held to below, anyone the provider signs in may try; '
            + 'accounts are then made only by invitation.'));
        box.appendChild(field('Tenants', tenants, 'Microsoft Entra ID: the tenant ids whose accounts may sign in.'));
        box.appendChild(field('Domains', domains, 'Google Workspace: the hosted domains, else the verified email\'s domain.'));
        box.appendChild(field('Required groups', groups, 'A person must be in at least one of these groups. One on each '
            + 'line, written as the provider sends it: a comma is part of the name.'));
        box.appendChild(signup.group);
        box.appendChild(field('Accounts', creation));
        box.appendChild(field('Role of the accounts made', role));
        box.appendChild(byEmail.group);
        box.appendChild(field('Password sign-in', password,
            `${provider.sso_only_accounts} of ${provider.identities} linked account(s) sign in only through a provider now. `
            + 'An administrator or an auditor always keeps a password.'));
        box.appendChild(madeHere.group);
        const said = _el('span', 'text-sm ml-sm sso-said');
        box.appendChild(saveBar(() => {
            const now = {
                sso_allowed_tenants: lines(tenants.value), sso_allowed_domains: lines(domains.value),
                sso_required_groups: groupLines(groups.value), sso_use_signup_domains: signup.box.checked,
                sso_account_creation: creation.value, sso_default_role: role.value,
                sso_link_by_email: byEmail.box.checked, sso_password_login: password.value,
                sso_jit_password: madeHere.box.checked,
            };
            const part = changed(now, policy);
            return Object.keys(part).length ? { policy: part } : {};
        }, said));
        return box;
    }

    function factorPage(provider) {
        const box = _el('div');
        const policy = provider.policy || {};
        const last = provider.last_test || {};
        const trust = tick('sso-trust-mfa', 'A second factor at the provider counts as the second factor here', policy.sso_trust_idp_mfa,
            'Only when the token carries one of the values below. An administrator still types the password.');
        const amr = area('sso-amr', policy.sso_accepted_amr);
        const acr = area('sso-acr', policy.sso_accepted_acr);
        const asked = input('sso-requested-acr', policy.sso_requested_acr);
        box.appendChild(trust.group);
        box.appendChild(field('Accepted methods (amr)', amr, 'A method listed here counts when the provider names another '
            + 'method beside it (otp with pwd, say), or says mfa itself; one method alone is one factor. The last test '
            + 'sign-in carried: ' + ((last.amr || []).join(', ') || 'none') + '.'));
        box.appendChild(field('Accepted levels (acr)', acr, 'The last test sign-in carried: ' + (last.acr || 'none') + '.'));
        box.appendChild(field('Level to ask the provider for (acr_values)', asked, 'Empty: none is asked for.'));
        const said = _el('span', 'text-sm ml-sm sso-said');
        box.appendChild(saveBar(() => {
            const part = changed({ sso_trust_idp_mfa: trust.box.checked, sso_accepted_amr: lines(amr.value),
                sso_accepted_acr: lines(acr.value), sso_requested_acr: asked.value.trim() }, policy);
            return Object.keys(part).length ? { policy: part } : {};
        }, said));
        return box;
    }

    function sessionsPage(provider) {
        const box = _el('div');
        const policy = provider.policy || {};
        const back = tick('sso-backchannel', 'The provider may end a person\'s sessions here (back-channel logout)', policy.sso_backchannel_logout,
            'Give the provider the back-channel logout address on the Connection page.');
        const out = tick('sso-idp-logout', 'Signing out here also signs the person out at the provider', policy.sso_idp_logout,
            'When a person signs out here, the browser goes to the provider to end its session too, then comes back to '
            + 'the sign-in page. A session that runs out on its own ends here only. The address the browser goes to '
            + 'carries the person\'s sign-in token, as the provider\'s standard asks: it signs nobody in, but it names '
            + 'the person and their email address, and it stays in that browser\'s history. On a computer several '
            + 'people share, clear that browser\'s history as well. Give the provider the sign-out return address on the '
            + 'Connection page first.');
        const fresh = input('sso-freshness', policy.sso_freshness_days, 'number');
        fresh.min = 0; fresh.max = 365;
        const ends = tick('sso-refusal', 'When the provider refuses a known person, their access here ends', policy.sso_refusal_ends_access,
            'Their sessions end and their SSH keys, temporary credentials and devices pause, until the provider admits them again.');
        box.appendChild(back.group);
        box.appendChild(out.group);
        box.appendChild(field('Days a person may go without signing in through the provider', fresh,
            'After that their SSH keys, temporary credentials and devices pause until they sign in again. The days go '
            + 'on counting while the provider is turned off. 0: no limit.'));
        box.appendChild(ends.group);
        const lapse = tick('sso-lapse', 'After those days, or a refusal, the account signs in only through a provider', policy.sso_lapse_ends_sign_in,
            'Its password, a passkey by itself and SFTP with a password are refused, and the person is told to sign in '
            + 'through the provider; that sign-in restores everything. An administrator or an auditor keeps their '
            + 'password as the way in while the provider cannot be reached. While this provider is turned off '
            + 'here, the days stop no password (nobody could sign in through it); an account already held when it '
            + 'was turned off stays held. Off: the password goes on signing the person in after the provider has '
            + 'stopped vouching for them.');
        box.appendChild(lapse.group);
        const said = _el('span', 'text-sm ml-sm sso-said');
        box.appendChild(saveBar(() => {
            // An empty box is sent as empty, for the server to refuse: as a number it would be 0, and 0 days
            // turns the rule off.
            const days = fresh.value.trim() === '' ? null : Number(fresh.value);
            const part = changed({ sso_backchannel_logout: back.box.checked, sso_idp_logout: out.box.checked,
                sso_freshness_days: days, sso_refusal_ends_access: ends.box.checked,
                sso_lapse_ends_sign_in: lapse.box.checked }, policy);
            return Object.keys(part).length ? { policy: part } : {};
        }, said));
        return box;
    }

    // ---------------------------------------------------------------- the provider's identities

    const IDENTITIES_PAGE = 50;
    const STATE_WORDS = { refused: ['Refused or held', 'badge-error'], lapsed: ['Days run out', 'badge-warning'],
        linked: ['Linked', 'badge-success'] };
    const LINKED_BY = { self: 'Linked by its owner', email: 'Linked by its verified email address',
        invitation: 'Linked when its invitation was accepted', jit: 'Made at its first sign-in through this provider',
        admin: 'Linked by an administrator' };

    function day(iso) {
        const d = iso ? new Date(iso) : null;
        return d && !isNaN(d.getTime()) ? d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' }) : '';
    }

    // The accounts linked to the provider, read when the page is shown: each with where it stands, and a way to lift
    // a refusal or a hold. What a refusal and a hold are, and how each ends, is said on the page.
    function identitiesPage(provider) {
        const box = _el('div');
        if (identitiesNote) {
            // A removal refused for the accounts listed here: its sentence first, once.
            const note = _el('p', 'alert alert-warning mb-sm', identitiesNote);
            note.id = 'sso-identities-note';
            note.setAttribute('role', 'alert');
            box.appendChild(note);
            identitiesNote = null;
        }
        const about = _el('p', 'text-secondary text-sm mb-sm', 'The accounts linked to this provider. Refused or held: '
            + 'the provider refused the person when they last signed in there, or their days without a sign-in here had '
            + 'run out when the provider was turned off or was to be removed. The vault keeps the date of either, not '
            + 'which of the two it was; the account\'s SSH keys, temporary credentials and devices are paused, and a '
            + 'sign-in the provider admits lifts it, or you lift it here. Days run out: only a sign-in through the '
            + 'provider ends that, or you unlink the account here. An account whose password and passkeys no longer '
            + 'sign it in is marked so below.');
        about.id = 'sso-identities-about';
        box.appendChild(about);
        const list = _el('div', 'sso-identities');
        list.id = 'sso-identities';
        list.appendChild(_el('p', 'text-secondary text-sm', 'Reading the linked accounts…'));
        box.appendChild(list);
        readIdentities(provider.id, list);
        return box;
    }

    async function readIdentities(providerId, list) {
        const mine = ++identityReads;
        let read;
        try {
            read = await apiRequest(`/admin/sso/providers/${encodeURIComponent(providerId)}/identities`
                + `?skip=${identitiesFrom}&limit=${IDENTITIES_PAGE}`, { silent: true });
        } catch (e) {
            if (mine === identityReads) {
                list.replaceChildren(_el('p', 'text-error text-sm', e.message || 'The linked accounts could not be read.'));
            }
            return;
        }
        // A later read draws the list (another page of it, the list read again after a lift, the page shown again):
        // this answer draws nothing. A list the dialog no longer shows is not in the page any more.
        if (mine !== identityReads) return;
        const rows = Array.isArray(read.identities) ? read.identities : [];
        const total = Number(read.total) || 0;
        const from = Number(read.skip) || 0;
        if (!rows.length && from > 0) { identitiesFrom = 0; readIdentities(providerId, list); return; }
        list.replaceChildren();
        const counts = read.counts || {};
        const summary = _el('p', 'text-sm mb-sm', total === 1 ? '1 linked account' : `${total} linked accounts`);
        summary.id = 'sso-identities-counts';
        if (total) summary.textContent += `: ${counts.refused || 0} refused or held, ${counts.lapsed || 0} with their days run out.`;
        list.appendChild(summary);
        if (!total) {
            list.appendChild(_el('p', 'text-secondary text-sm', 'No account is linked to this provider.'));
            return;
        }
        rows.forEach((identity) => list.appendChild(identityRow(providerId, identity, list)));
        if (total > rows.length) {
            const pager = _el('div', 'sso-identities-pager flex items-center gap-sm mt-sm');
            const prev = _el('button', 'btn btn-secondary btn-sm', 'Previous');
            prev.type = 'button';
            prev.disabled = from <= 0;
            prev.addEventListener('click', () => { identitiesFrom = Math.max(0, from - IDENTITIES_PAGE); readIdentities(providerId, list); });
            const next = _el('button', 'btn btn-secondary btn-sm', 'Next');
            next.type = 'button';
            next.disabled = from + rows.length >= total;
            next.addEventListener('click', () => { identitiesFrom = from + rows.length; readIdentities(providerId, list); });
            pager.append(prev, _el('span', 'text-secondary text-sm', `${from + 1} to ${from + rows.length} of ${total}`), next);
            list.appendChild(pager);
        }
    }

    // What lifting the refusal or hold on an account gives, from where the server says the lift leaves it
    // (`after_lift`). A hold the vault wrote after the person's days had run out leaves them run out: the keys stay
    // paused until the person signs in through the provider, and while the provider is on they sign in only there.
    function liftSays(name, identity) {
        const after = identity.after_lift || { state: 'linked', holds_sign_in: false };
        const signInBack = identity.holds_sign_in && !after.holds_sign_in
            ? ' Their password and passkeys sign them in again.' : '';
        const told = ' They and the other administrators are told.';
        if (after.state === 'lapsed') {
            return `Lift the refusal or hold on ${name}? Their days without a sign-in through this provider have run `
                + 'out all the same, so their SSH keys, temporary credentials and devices stay paused until they sign '
                + 'in through it' + (after.holds_sign_in
                    ? ', and their password and passkeys still do not sign them in: until then, lifting it changes '
                      + 'nothing they can do.'
                    : '.') + signInBack + told;
        }
        return `Lift the refusal or hold on ${name}? Their SSH keys, temporary credentials and devices work again, `
            + 'unless another rule pauses them.' + signInBack + told
            + ' Lift it when the refusal was a mistake the provider cannot answer.';
    }

    // What unlinking an account does, said before it is done: what ends with the link, what the vault refuses, who
    // is told (DELETE /admin/sso/identities/{id}, app/api/sso_admin_router.py).
    function unlinkSays(name, label, identity) {
        const ends = identity.state === 'refused' ? ` The refusal or hold ${label} had on it ends with the link.`
            : identity.state === 'lapsed' ? ` Its days without a sign-in through ${label} end with the link.` : '';
        return `Unlink ${name} from ${label}? The account can no longer sign in through ${label}, and its sessions `
            + `that came through ${label} end.` + ends + ` If ${label} is what keeps the account from holding a `
            + 'password, it may hold one again, and has none anybody can type until it sets one. The vault refuses '
            + 'an unlink that would leave the account no way to sign in, and says what to do first. '
            + `${name} and the other administrators are told.`;
    }

    // What the unlink did, from the server's answer. The sign-in page's own password reset is off by default, so the
    // account is not sent there: an administrator makes it a reset link.
    function unlinkDid(name, label, out) {
        const done = out || {};
        return `${name} was unlinked from ${label}.`
            + (done.sessions_ended ? ` ${done.sessions_ended} session(s) that came through it ended.` : '')
            + (done.held ? ` ${label} held that account to its own sign-in: the hold ended with the link.` : '')
            + (done.keys_paused ? ` The pause ${label} had on its SSH keys, temporary credentials and devices ended `
                + 'with the link.' : '')
            + (done.may_set_password ? ' The account may hold a password again: it has none anybody can type until '
                + 'it sets one. You can make it a reset link on the Users page.' : '');
    }

    function unlinkButton(providerId, identity, name, list) {
        const label = (open && open.id === providerId && (open.label || open.name)) || 'the provider';
        const unlink = _el('button', 'btn btn-danger btn-sm sso-identity-unlink', 'Unlink');
        unlink.type = 'button';
        unlink.setAttribute('aria-label', `Unlink ${name} from ${label}`);
        unlink.addEventListener('click', async () => {
            const ok = await showConfirm(unlinkSays(name, label, identity), 'Unlink', null, 'Unlink');
            if (!ok) return;
            unlink.disabled = true;
            try {
                const out = await apiRequest(`/admin/sso/identities/${encodeURIComponent(identity.id)}`,
                    { method: 'DELETE', silent: true });
                showToast(unlinkDid(name, label, out), 'success');
            } catch (e) { showToast(e.message || 'The account was not unlinked.', 'error'); }
            // Read again whatever the answer: the list says how the accounts stand now.
            readIdentities(providerId, list);
            load();
        });
        return unlink;
    }

    // An administrator's own identity is neither lifted nor unlinked by them here (the server refuses both): where
    // each is done instead. Their own unlink, under Your account, is refused while a refusal, a hold or days run out
    // stand (owners_unlink_refusal in app/api/sso_router.py).
    const OWN_SAYS = { refused: 'Your own: another administrator lifts or unlinks it.',
        lapsed: 'Your own: sign in through it again before you unlink it under Your account, or another '
            + 'administrator unlinks it.',
        linked: 'Your own: unlink it under Your account.' };

    function identityRow(providerId, identity, list) {
        const row = _el('div', 'sso-identity-row flex flex-wrap items-center gap-sm mb-sm');
        row.dataset.identity = identity.id;
        const name = identity.username || 'An account';
        const text = _el('div', 'flex-1');
        const title = _el('div', 'text-sm font-bold', name);
        const [word, badge] = STATE_WORDS[identity.state] || STATE_WORDS.linked;
        title.appendChild(_el('span', 'badge ' + badge + ' ml-sm sso-identity-state', word));
        text.appendChild(title);
        const bits = ['Account ' + identity.user_id,
            (LINKED_BY[identity.linked_by] || 'Linked') + (day(identity.linked_at) ? ' on ' + day(identity.linked_at) : ''),
            identity.last_sign_in_at ? 'last signed in through it on ' + day(identity.last_sign_in_at)
                : 'never signed in through it'];
        if (identity.state === 'refused' && identity.refused_at) bits.push('refused or held since ' + day(identity.refused_at));
        if (identity.due_at) {
            const ranOut = new Date(identity.due_at).getTime() <= Date.now();
            bits.push((ranOut ? 'its days ran out on ' : 'its days run out on ') + day(identity.due_at));
        }
        if (identity.holds_sign_in) bits.push('its password and passkeys do not sign it in now');
        text.appendChild(_el('div', 'text-secondary text-xs', bits.join(' · ')));
        row.appendChild(text);
        if (identity.own) {
            row.appendChild(_el('span', 'text-secondary text-xs', OWN_SAYS[identity.state] || OWN_SAYS.linked));
            return row;
        }
        if (identity.state === 'refused') {
            const lift = _el('button', 'btn btn-secondary btn-sm', 'Lift refusal');
            lift.type = 'button';
            lift.setAttribute('aria-label', 'Lift the refusal of ' + name);
            lift.addEventListener('click', async () => {
                const ok = await showConfirm(liftSays(name, identity), 'Lift refusal', null, 'Lift refusal');
                if (!ok) return;
                lift.disabled = true;
                try {
                    await apiRequest(`/admin/sso/identities/${encodeURIComponent(identity.id)}/clear-refusal`,
                        { method: 'POST', silent: true });
                    showToast(`The refusal on ${name} was lifted.`, 'success');
                } catch (e) { showToast(e.message || 'The refusal was not lifted.', 'error'); }
                // Read again whatever the answer: the list says how the account stands now.
                readIdentities(providerId, list);
                load();
            });
            row.appendChild(lift);
        }
        row.appendChild(unlinkButton(providerId, identity, name, list));
        return row;
    }

    // ---------------------------------------------------------------- the dialog

    // Sessions that came through a provider and could not be ended when it was turned off stand until they run out.
    // The server's sentence for them (_said_of_sessions_standing in app/api/sso_providers_router.py), with what this
    // page offers to end them; `through` is 'it' after the provider was named, 'this provider' on its own. Empty
    // when none stands: `n` is how many stand, or null when they could not be counted.
    function standingSaid(n, through) {
        if (n !== null && !(n > 0)) return '';
        const many = n === null ? 'Sessions' : `${n} session(s)`;
        return `${many} that came through ${through} could not be ended and stand until they run out: use "Turn off `
            + 'again" to end them, or end its linked accounts\' sessions with "Terminate Sessions" on the Users page.';
    }

    const standsIn = (out) => !!out && (out.sessions_not_ended === null || out.sessions_not_ended > 0);
    const stands = (id) => Object.prototype.hasOwnProperty.call(standing, id)
        && standsIn({ sessions_not_ended: standing[id] });

    // What a turn-on or a turn-off did, as POST .../state answers it.
    function stateSaid(state, out) {
        const ended = out.sessions_ended ? ` ${out.sessions_ended} session(s) that came through it were ended.` : '';
        const left = standingSaid(out.sessions_not_ended, 'it');
        const still = left ? ' ' + left : '';
        if (!out.changed) {
            // Somebody else had turned it so meanwhile. An off provider whose sessions still stood ended them.
            return `It was already ${state === 'enabled' ? 'on' : 'off'}.` + ended + still;
        }
        if (state === 'enabled') {
            return 'The provider is on.' + (out.due ? ` ${out.due} linked account(s) have not signed in through it `
                + 'within its days: their password and passkeys do not sign them in until they have.' : '');
        }
        return 'The provider is off.' + ended + (out.held ? ` ${out.held} account(s) whose days there had run out stay `
            + 'held: lift each on the Identities page when it should have its keys back.' : '') + still;
    }

    // What the server said of a provider's sessions, kept for its dialog: a turn-on leaves nothing to say.
    function noteStanding(id, state, out) {
        if (state === 'enabled' && out.changed) delete standing[id];
        else if (Object.prototype.hasOwnProperty.call(out, 'sessions_not_ended')) standing[id] = out.sessions_not_ended;
    }

    async function setState(state) {
        if (state === 'disabled' && open.only_way_in_accounts) {
            const ok = await showConfirm(`${open.only_way_in_accounts} account(s) linked to this provider have no other way `
                + 'to sign in (no password of their own, and no other provider that is on): nothing signs them in while '
                + 'it is off.', 'Turn the provider off', null, 'Turn off');
            if (!ok) return;
        }
        const asked = open.id;
        try {
            const out = await apiRequest(`/admin/sso/providers/${encodeURIComponent(asked)}/state`, {
                method: 'POST', body: JSON.stringify({ state }), silent: true,
            });
            noteStanding(asked, state, out);
            if (!open || open.id !== asked) { load(); return; }       // as after a save
            open = out.provider;
            showToast(stateSaid(state, out), standsIn(out) ? 'warning' : 'success');
            drawDialog({ focus: 'sso-toggle' });
            load();
        } catch (e) { showToast(e.message || 'The provider was not changed.', 'error'); }
    }

    // "Turn off again": a provider that is off is asked again to end the sessions that came through it and still
    // stand. The server answers changed:false, with what it ended, or with nothing when none stood (and then asked
    // for no step-up). Turned on by somebody meanwhile, the provider is turned off, and that is said.
    async function endSessions() {
        if (lockedNow() || !open) return;
        const asked = open.id;
        const button = byId('sso-end-sessions');
        if (button) button.disabled = true;
        try {
            const out = await apiRequest(`/admin/sso/providers/${encodeURIComponent(asked)}/state`, {
                method: 'POST', body: JSON.stringify({ state: 'disabled' }), silent: true,
            });
            let said;
            if (out.changed) {
                noteStanding(asked, 'disabled', out);
                said = stateSaid('disabled', out);
            } else if (!Object.prototype.hasOwnProperty.call(out, 'sessions_ended')
                    && !Object.prototype.hasOwnProperty.call(out, 'sessions_not_ended')) {
                standing[asked] = 0;
                said = 'No session that came through it still stands.';
            } else {
                noteStanding(asked, 'disabled', out);
                said = ((out.sessions_ended ? `${out.sessions_ended} session(s) that came through it were ended. ` : '')
                    + standingSaid(out.sessions_not_ended, 'it')).trim()
                    || 'No session that came through it still stands.';
            }
            if (!open || open.id !== asked) { load(); return; }       // as after a save
            open = out.provider;
            showToast(said, standsIn(out) ? 'warning' : 'success');
            drawDialog({ focus: 'sso-end-sessions' });
            load();
        } catch (e) {
            showToast(e.message || 'The sessions were not ended.', 'error');
            if (button) button.disabled = false;
        }
    }

    // The refusals whose sentence sends the administrator to the provider's Identities page: accounts held by it
    // (some of them held by this very removal, after its step-up), or past its days.
    const TO_IDENTITIES = ['refusals_in_force', 'days_ran_out'];

    async function remove() {
        const ok = await showConfirm(`Remove ${open.name}? Its ${open.identities} link(s) to accounts are removed with it`
            + (open.group_mappings ? `, and its ${open.group_mappings} group mapping(s)` : '') + '; the accounts stay.',
            'Remove the provider', null, 'Remove');
        if (!ok) return;
        const asked = open.id;
        try {
            await apiRequest(`/admin/sso/providers/${encodeURIComponent(asked)}`, { method: 'DELETE', silent: true });
            showToast('The provider was removed.', 'success');
            open = null;
            forgetDrafts();
            closeModal();
            load();
        } catch (e) {
            // Whatever the refusal, the list is read again: one that came after the step-up may have held accounts.
            load();
            if (!TO_IDENTITIES.includes(e.reason)) {
                showToast(e.message || 'The provider was not removed.', 'error');
                return;
            }
            // The sentence names the Identities page: the provider is read again and shown on it, the sentence first.
            identitiesNote = e.message || null;
            await show(asked, 'identities');
            if (identitiesNote) {                   // the page was not drawn: the sentence is said all the same
                identitiesNote = null;
                showToast(e.message || 'The provider was not removed.', 'error');
            }
        }
    }

    // The values of a page's fields, by field id (an address shown to be copied is no field).
    function valuesOf(box) {
        const out = {};
        box.querySelectorAll('input, select, textarea').forEach((el) => {
            if (el.id && !el.readOnly) out[el.id] = el.type === 'checkbox' ? el.checked : el.value;
        });
        return out;
    }

    // Before the page on screen is taken down: keep what was typed on it and not saved.
    function keepDraft(body) {
        const shown = body.querySelector('[data-sso-shown]');
        if (!shown) return;
        const now = valuesOf(shown);
        const kept = {};
        Object.keys(now).forEach((id) => { if (id in fresh && now[id] !== fresh[id]) kept[id] = now[id]; });
        if (Object.keys(kept).length) drafts[shown.dataset.ssoShown] = kept;
        else delete drafts[shown.dataset.ssoShown];
    }

    function restoreDraft(shown) {
        const kept = drafts[shown.dataset.ssoShown] || {};
        shown.querySelectorAll('input, select, textarea').forEach((el) => {
            if (!el.id || !(el.id in kept)) return;
            if (el.type === 'checkbox') el.checked = kept[el.id]; else el.value = kept[el.id];
        });
    }

    // The dialog says whether a page that is not on screen holds something typed: a click beside the dialog then
    // does not close it (static/js/dialogs.js), and the page's tab says so.
    function markUnsaved() {
        const modal = byId('sso-provider-modal');
        const waiting = Object.keys(drafts).filter((key) => key !== page);
        if (modal) {
            if (waiting.length) modal.dataset.unsaved = 'true'; else delete modal.dataset.unsaved;
        }
        waiting.forEach((key) => {
            const tab = byId('sso-tab-' + key);
            if (tab && !tab.querySelector('.sso-unsaved')) tab.appendChild(_el('span', 'sso-unsaved', ' (not saved)'));
        });
    }

    function forgetDrafts() {
        drafts = {};
        fresh = {};
        const modal = byId('sso-provider-modal');
        if (modal) delete modal.dataset.unsaved;
    }

    // What was typed and not saved (a client secret among it) is kept no longer than the dialog is open: closed by
    // its button, by a click beside it or by Escape, it forgets.
    let watchingClose = false;
    function forgetWhenClosed() {
        const modal = byId('sso-provider-modal');
        if (watchingClose || !modal || typeof MutationObserver !== 'function') return;
        watchingClose = true;
        new MutationObserver(() => { if (!modal.classList.contains('active')) forgetDrafts(); })
            .observe(modal, { attributes: true, attributeFilter: ['class'] });
    }

    // `how.keep === false`: what the page on screen holds is not kept (it was just saved, or another provider is
    // opened). `how.focus`: where the keyboard goes afterwards, 'tab' for the page's tab or the id of a button (the
    // one that was used: a confirmation dialog may have held the keyboard in between).
    function drawDialog(how) {
        const body = byId('sso-provider-body');
        const title = byId('sso-provider-title');
        if (!body || !open) return;
        const opts = how || {};
        forgetWhenClosed();
        // Every node of the body is replaced: where the keyboard was is found again afterwards, so a person using
        // a keyboard or a screen reader stays inside the dialog and in their place.
        const active = document.activeElement;
        const held = opts.focus === 'tab' ? 'sso-tab-' + page
            : (opts.focus || (active && body.contains(active) ? (active.id || 'sso-tab-' + page) : null));
        if (opts.keep !== false) keepDraft(body);
        if (title) title.textContent = open.label || open.name;
        body.replaceChildren();
        const locked = lockedNow();
        if (locked) {
            const said = _el('div', 'alert alert-info mb-md', data.locked_message || LOCKED_FALLBACK);
            said.id = 'sso-locked-line';
            body.appendChild(said);
        }
        const head = _el('div', 'flex flex-wrap items-center gap-sm mb-md');
        const [word, badge] = status(open);
        const mark = _el('span', 'badge ' + badge, word);
        mark.id = 'sso-provider-state';
        head.appendChild(mark);
        const toggle = _el('button', 'btn btn-secondary btn-sm', open.state === 'enabled' ? 'Turn off' : 'Turn on');
        toggle.type = 'button';
        toggle.id = 'sso-toggle';
        toggle.disabled = locked;
        toggle.addEventListener('click', () => setState(open.state === 'enabled' ? 'disabled' : 'enabled'));
        head.appendChild(toggle);
        if (open.state !== 'enabled') {
            const gone = _el('button', 'btn btn-danger btn-sm', 'Remove');
            gone.type = 'button';
            gone.id = 'sso-remove';
            gone.disabled = locked;
            gone.addEventListener('click', remove);
            head.appendChild(gone);
        }
        // A provider that is off may still have sessions that came through it (a turn-off could not end them):
        // turning it off again ends them. Not offered for a draft that was never on.
        if (open.state === 'disabled' && (open.configured || open.identities > 0 || stands(open.id))) {
            const again = _el('button', 'btn btn-secondary btn-sm', 'Turn off again');
            again.type = 'button';
            again.id = 'sso-end-sessions';
            again.disabled = locked;
            again.setAttribute('aria-label',
                `Turn ${open.label || open.name} off again to end the sessions that still stand`);
            again.addEventListener('click', endSessions);
            head.appendChild(again);
        }
        body.appendChild(head);
        if (open.state === 'disabled' && stands(open.id)) {
            const left = _el('div', 'alert alert-warning mb-md', standingSaid(standing[open.id], 'this provider'));
            left.id = 'sso-sessions-standing';
            body.appendChild(left);
        }
        const tabs = _el('div', 'sso-tabs flex gap-sm mb-md');
        tabs.setAttribute('role', 'tablist');
        PAGES.forEach(([key, text]) => {
            const tab = _el('button', 'btn btn-sm ' + (key === page ? 'btn-primary' : 'btn-secondary'), text);
            tab.type = 'button';
            tab.id = 'sso-tab-' + key;
            tab.dataset.ssoPage = key;
            tab.setAttribute('role', 'tab');
            tab.setAttribute('aria-selected', key === page ? 'true' : 'false');
            tab.setAttribute('aria-controls', 'sso-page-' + key);
            tab.tabIndex = key === page ? 0 : -1;        // one stop for Tab; the arrow keys move between the pages
            tab.addEventListener('click', () => { page = key; drawDialog({ focus: 'tab' }); });
            tab.addEventListener('keydown', (e) => {
                const at = PAGES.findIndex(([k]) => k === key);
                const to = { ArrowRight: at + 1, ArrowLeft: at - 1, Home: 0, End: PAGES.length - 1 }[e.key];
                if (to === undefined) return;
                e.preventDefault();
                page = PAGES[(to + PAGES.length) % PAGES.length][0];
                drawDialog({ focus: 'tab' });
            });
            tabs.appendChild(tab);
        });
        body.appendChild(tabs);
        const draws = { connection: connectionPage, access: accessPage, factor: factorPage, sessions: sessionsPage,
            identities: identitiesPage };
        const shown = draws[page](open);
        shown.id = 'sso-page-' + page;
        shown.dataset.ssoShown = page;
        shown.setAttribute('role', 'tabpanel');
        shown.setAttribute('aria-labelledby', 'sso-tab-' + page);
        // Locked, nothing on the page can be saved: its fields are read-only too (an address to copy already is).
        if (locked) {
            shown.querySelectorAll('input, select, textarea').forEach((node) => { if (!node.readOnly) node.disabled = true; });
        }
        body.appendChild(shown);
        fresh = valuesOf(shown);
        // The page as built is what the dialog holds; what was typed on it before, put back now, is an edit.
        const modal = byId('sso-provider-modal');
        if (modal && window.Dialogs && typeof Dialogs.retake === 'function') Dialogs.retake(modal);
        restoreDraft(shown);
        markUnsaved();
        if (held) {
            const back = byId(held);
            const to = back && !back.disabled ? back : byId('sso-tab-' + page);
            try { if (to) to.focus(); } catch (_) {}
        }
    }

    async function show(providerId, which) {
        let read;
        try { read = await apiRequest(`/admin/sso/providers/${encodeURIComponent(providerId)}`, { silent: true }); }
        catch (e) { showToast(e.message || 'The provider could not be read.', 'error'); return; }
        open = read.provider;
        page = which || 'connection';
        identitiesFrom = 0;
        forgetDrafts();
        drawDialog({ keep: false });
        openModal('sso-provider-modal');
    }

    // ---------------------------------------------------------------- add a provider

    function drawWizard() {
        const body = byId('sso-provider-body');
        const title = byId('sso-provider-title');
        if (!body) return;
        open = null;
        forgetDrafts();
        if (title) title.textContent = 'Add a provider';
        body.replaceChildren();
        const presets = (data && data.presets) || [];
        const kind = choice('sso-new-preset', presets.map((p) => [p.id, p.name]), presets.length ? presets[0].id : 'oidc');
        const name = input('sso-new-name', '');
        const hint = _el('p', 'text-secondary text-sm mt-xs');
        const tell = () => {
            const preset = presets.find((p) => p.id === kind.value) || {};
            hint.textContent = (preset.restriction_help || '') + ' ' + (preset.console || '');
            if (!name.dataset.typed) name.value = preset.id === 'oidc' ? '' : (preset.name || '');
        };
        name.addEventListener('input', () => { name.dataset.typed = '1'; });
        kind.addEventListener('change', tell);
        tell();
        body.appendChild(field('Provider', kind));
        body.appendChild(hint);
        body.appendChild(field('Name', name, 'For administrators; the sign-in page\'s button can say something else.'));
        const said = _el('span', 'text-sm ml-sm sso-said');
        const make = _el('button', 'btn btn-primary btn-sm mt-md', 'Add');
        make.type = 'button';
        make.id = 'sso-new-add';
        make.disabled = lockedNow();
        make.addEventListener('click', async () => {
            if (lockedNow()) return;
            make.disabled = true;
            said.className = 'text-sm ml-sm sso-said';
            said.textContent = '';
            try {
                const out = await apiRequest('/admin/sso/providers', {
                    method: 'POST', body: JSON.stringify({ name: name.value.trim(), preset: kind.value }), silent: true,
                });
                open = out.provider;
                page = 'connection';
                forgetDrafts();
                drawDialog({ keep: false });
                load();
            } catch (e) {
                said.className = 'text-sm ml-sm sso-said text-error';
                said.setAttribute('role', 'alert');
                said.textContent = e.message || 'The provider was not added.';
                make.disabled = false;
            }
        });
        body.appendChild(make);
        body.appendChild(said);
        openModal('sso-provider-modal');
    }

    // The page came back from a test sign-in: the Sign-in settings open on the provider, with what it sent.
    async function showTest(providerId, summary) {
        const section = document.querySelector('.sidebar-item[data-section="settings"]');
        if (section) section.click();
        const tab = document.querySelector('#settings-section .tab-btn[data-tab="signin"]');
        if (tab) tab.click();
        await load();
        await show(providerId, 'connection');
        showToast(summary && summary.outcome === 'ok' ? 'The test sign-in passed.' : 'The test sign-in came back.', 'success');
        const box = byId('sso-test-summary');
        if (box && typeof box.scrollIntoView === 'function') box.scrollIntoView({ block: 'nearest' });
    }

    // Nothing of one administrator's page is left for the next person on the tab.
    function reset() {
        loads += 1;
        identityReads += 1;
        identitiesFrom = 0;
        identitiesNote = null;
        standing = {};
        data = null;
        open = null;
        forgetDrafts();
        const box = byId('signin-sso-providers');
        if (box) box.replaceChildren();
        const line = byId('signin-sso-address');
        if (line) { line.textContent = ''; line.hidden = true; }
        const lock = byId('signin-sso-locked');
        if (lock) { lock.textContent = ''; lock.hidden = true; }
        const body = byId('sso-provider-body');
        if (body) body.replaceChildren();
    }

    document.addEventListener('click', (e) => {
        const target = e.target;
        if (!target || !target.closest) return;
        if (target.closest('.tab-btn[data-tab="signin"]')) load();
        if (target.closest('#signin-sso-add')) drawWizard();
    });

    window.SsoSettings = { load, reset, showTest };
})();
