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
 * its own words. The client secret is typed, sent, and never shown again.
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

    const ICON_NAMES = { generic: 'Plain', microsoft: 'Microsoft', google: 'Google', okta: 'Okta', keycloak: 'Keycloak', authentik: 'Authentik' };
    const PAGES = [['connection', 'Connection'], ['access', 'Access'], ['factor', 'Second factor'], ['sessions', 'Sessions']];

    function status(provider) {
        if (provider.state === 'enabled') return ['On', 'badge-success'];
        if (!provider.configured) return ['Draft', 'badge-secondary'];
        return provider.tested ? ['Off · tested', 'badge-info'] : ['Off · not tested', 'badge-warning'];
    }

    const lines = (value) => String(value || '').split(/[\n,]+/).map((s) => s.trim()).filter(Boolean);
    const same = (a, b) => JSON.stringify(a) === JSON.stringify(b);

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
        edit.addEventListener('click', () => show(provider.id, 'connection'));
        row.appendChild(edit);
        return row;
    }

    function draw() {
        const box = byId('signin-sso-providers');
        if (!box || !data) return;
        drawAddress();
        const providers = data.providers || [];
        box.replaceChildren(...providers.map(drawRow));
        if (!providers.length) {
            box.appendChild(_el('p', 'text-secondary text-sm mb-sm', 'No provider yet. People sign in with their password'
                + ' (and a passkey, when they have one).'));
        }
        const add = byId('signin-sso-add');
        if (add) add.disabled = providers.length >= (data.limit || 20);
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
        bar.appendChild(save);
        bar.appendChild(said);
        save.addEventListener('click', async () => {
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
                // An answer that comes after the dialog was closed, or opened on another provider, draws nothing
                // into it: the list is read again and says what was saved.
                if (!open || open.id !== saved) { load(); return; }
                open = out.provider;
                let told = 'Saved.';
                if (out.connection_changed && open.state !== 'enabled') told = 'Saved. Run a test sign-in before turning it on.';
                if (out.turned_off) told = 'Saved. The connection changed, so the provider was turned off: run a test sign-in, then turn it on again.';
                if (out.secret_cleared) told += ' Enter the client secret again: it is kept only for the address it was entered for.';
                if ((out.made_sso_only || []).length) told += ` ${out.made_sso_only.length} linked account(s) now sign in only through it.`;
                if ((out.restored || []).length) {
                    told += ` ${out.restored.length} linked account(s) may hold a password again: each asks for a reset `
                        + 'link on the sign-in page, or you make one for them on the Users page.';
                }
                showToast(told, 'success');
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
        const signup = tick('sso-signup-domains', 'Also hold people to the sign-up domain list', policy.sso_use_signup_domains,
            'The list on the Accounts page, when it is an allow-list.');
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
        box.appendChild(_el('p', 'text-secondary text-sm mb-sm', 'Who may sign in through this provider. With none of the '
            + 'three lists, anyone the provider signs in may try; accounts are then made only by invitation.'));
        box.appendChild(field('Tenants', tenants, 'Microsoft Entra ID: the tenant ids whose accounts may sign in.'));
        box.appendChild(field('Domains', domains, 'Google Workspace: the hosted domains, else the verified email\'s domain.'));
        box.appendChild(field('Required groups', groups, 'A person must be in at least one of these groups.'));
        box.appendChild(signup.group);
        box.appendChild(field('Accounts', creation));
        box.appendChild(field('Role of the accounts made', role));
        box.appendChild(byEmail.group);
        box.appendChild(field('Password sign-in', password,
            `${provider.sso_only_accounts} of ${provider.identities} linked account(s) sign in only through a provider now. `
            + 'An administrator or an auditor always keeps a password.'));
        const said = _el('span', 'text-sm ml-sm sso-said');
        box.appendChild(saveBar(() => {
            const now = {
                sso_allowed_tenants: lines(tenants.value), sso_allowed_domains: lines(domains.value),
                sso_required_groups: lines(groups.value), sso_use_signup_domains: signup.box.checked,
                sso_account_creation: creation.value, sso_default_role: role.value,
                sso_link_by_email: byEmail.box.checked, sso_password_login: password.value,
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
        box.appendChild(field('Accepted methods (amr)', amr, 'The last test sign-in carried: ' + ((last.amr || []).join(', ') || 'none') + '.'));
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
            + 'people share, the history is cleared as well. Give the provider the sign-out return address on the '
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
        const said = _el('span', 'text-sm ml-sm sso-said');
        box.appendChild(saveBar(() => {
            const part = changed({ sso_backchannel_logout: back.box.checked, sso_idp_logout: out.box.checked,
                sso_freshness_days: Number(fresh.value), sso_refusal_ends_access: ends.box.checked }, policy);
            return Object.keys(part).length ? { policy: part } : {};
        }, said));
        return box;
    }

    // ---------------------------------------------------------------- the dialog

    async function setState(state) {
        if (state === 'disabled' && open.sso_only_accounts) {
            const ok = await showConfirm(`${open.sso_only_accounts} account(s) sign in only through a provider and are linked `
                + 'to this one: they cannot sign in while it is off.', 'Turn the provider off', null, 'Turn off');
            if (!ok) return;
        }
        const asked = open.id;
        try {
            const out = await apiRequest(`/admin/sso/providers/${encodeURIComponent(asked)}/state`, {
                method: 'POST', body: JSON.stringify({ state }), silent: true,
            });
            if (!open || open.id !== asked) { load(); return; }       // as after a save
            open = out.provider;
            showToast(state === 'enabled' ? 'The provider is on.' : 'The provider is off.', 'success');
            drawDialog({ focus: 'sso-toggle' });
            load();
        } catch (e) { showToast(e.message || 'The provider was not changed.', 'error'); }
    }

    async function remove() {
        const ok = await showConfirm(`Remove ${open.name}? Its ${open.identities} link(s) to accounts are removed with it; the `
            + 'accounts stay.', 'Remove the provider', null, 'Remove');
        if (!ok) return;
        try {
            await apiRequest(`/admin/sso/providers/${encodeURIComponent(open.id)}`, { method: 'DELETE', silent: true });
            showToast('The provider was removed.', 'success');
            open = null;
            forgetDrafts();
            closeModal();
            load();
        } catch (e) { showToast(e.message || 'The provider was not removed.', 'error'); }
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
        const head = _el('div', 'flex items-center gap-sm mb-md');
        const [word, badge] = status(open);
        const mark = _el('span', 'badge ' + badge, word);
        mark.id = 'sso-provider-state';
        head.appendChild(mark);
        const toggle = _el('button', 'btn btn-secondary btn-sm', open.state === 'enabled' ? 'Turn off' : 'Turn on');
        toggle.type = 'button';
        toggle.id = 'sso-toggle';
        toggle.addEventListener('click', () => setState(open.state === 'enabled' ? 'disabled' : 'enabled'));
        head.appendChild(toggle);
        if (open.state !== 'enabled') {
            const gone = _el('button', 'btn btn-danger btn-sm', 'Remove');
            gone.type = 'button';
            gone.id = 'sso-remove';
            gone.addEventListener('click', remove);
            head.appendChild(gone);
        }
        body.appendChild(head);
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
        const draws = { connection: connectionPage, access: accessPage, factor: factorPage, sessions: sessionsPage };
        const shown = draws[page](open);
        shown.id = 'sso-page-' + page;
        shown.dataset.ssoShown = page;
        shown.setAttribute('role', 'tabpanel');
        shown.setAttribute('aria-labelledby', 'sso-tab-' + page);
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
        make.addEventListener('click', async () => {
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
        data = null;
        open = null;
        forgetDrafts();
        const box = byId('signin-sso-providers');
        if (box) box.replaceChildren();
        const line = byId('signin-sso-address');
        if (line) { line.textContent = ''; line.hidden = true; }
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
