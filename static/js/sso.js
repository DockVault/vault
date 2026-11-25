/*
 * Single sign-on in the browser: the provider buttons of the sign-in screen, the proof a tab keeps for a flow that
 * leaves the page, what the page does when the provider sends the browser back, and the person's own linked
 * providers in Your account.
 *
 * A flow leaves the page for the provider and comes back as a new page load with a short fragment:
 *   #sso=<code>         a sign-in: the code is turned into the session by POST /auth/finish
 *   #sso-linked=<code>  a link the signed-in person started: claimed by POST /users/me/identities/finish
 *   #sso-test=<code>    an administrator's test sign-in: claimed by POST /admin/sso/providers/{id}/test/finish
 *   #sso-stepup=<code>  a fresh sign-in that confirms the person: staged by POST /users/me/identities/reauth/finish
 *   #sso-error=<code>   a refusal, as a reason code; its sentence comes from GET /auth/sso/reasons
 * Nothing in a fragment is a session, and a code is worth nothing without this tab's verifier: made here before the
 * page is left (32 random bytes), kept in sessionStorage for this tab only, sent to the server as its SHA-256 at the
 * start and as itself at the finish, and forgotten the moment the page comes back, whatever came back.
 *
 * The fragment is taken out of the address before anything else reads it (takeReturn, called by app.js as the page
 * loads). An address the server answers is followed only when it is https (or http on this computer).
 *
 * Uses app.js's API_BASE, apiRequest, logout, showConfirm, showError, showSuccess and _el. Builds everything with
 * createElement and textContent.
 */
(function () {
    'use strict';

    const FLOW_KEY = 'dv_sso_flow';
    const FLOW_MAX_AGE_MS = 15 * 60 * 1000;      // a state lives ten minutes at the server; a flow older is not this one
    const FRAGMENT = /^#(sso|sso-error|sso-linked|sso-test|sso-stepup)=([A-Za-z0-9._~-]{1,200})(?:&return_to=([A-Za-z0-9_-]{1,40}))?$/;
    const GENERIC = 'Single sign-on did not finish. Try again.';
    let reasonTexts = null;

    function base64url(bytes) {
        let text = '';
        bytes.forEach((b) => { text += String.fromCharCode(b); });
        return btoa(text).replace(/\+/g, '-').replace(/\//g, '_').replace(/=+$/, '');
    }

    async function sha256Hex(text) {
        const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(text));
        return Array.from(new Uint8Array(digest)).map((b) => b.toString(16).padStart(2, '0')).join('');
    }

    function available() {
        return !!(window.crypto && crypto.subtle && typeof crypto.getRandomValues === 'function');
    }

    // Begin a flow that leaves the page: this tab's verifier is made and kept with what the flow is for, and its
    // hash is returned for the start request. One flow at a time: a new one forgets the last.
    async function begin(purpose, more) {
        if (!available()) throw new Error('Single sign-on needs a secure page (https).');
        const bytes = new Uint8Array(32);
        crypto.getRandomValues(bytes);
        const verifier = base64url(bytes);
        const flow = Object.assign({ purpose, verifier, at: Date.now() }, more || {});
        sessionStorage.setItem(FLOW_KEY, JSON.stringify(flow));
        return sha256Hex(verifier);
    }

    function forget() {
        try { sessionStorage.removeItem(FLOW_KEY); } catch (_) {}
    }

    // The flow this tab began, read once and forgotten; null when there is none, or it is not one of ours.
    function recall() {
        let raw = null;
        try { raw = sessionStorage.getItem(FLOW_KEY); } catch (_) {}
        forget();
        if (!raw) return null;
        try {
            const flow = JSON.parse(raw);
            if (!flow || typeof flow !== 'object' || typeof flow.verifier !== 'string' || typeof flow.purpose !== 'string') return null;
            if (typeof flow.at !== 'number' || Date.now() - flow.at > FLOW_MAX_AGE_MS) return null;
            return flow;
        } catch (_) { return null; }
    }

    // What the provider's redirect brought back, taken out of the address at once: {kind, value, returnTo, flow},
    // or null when the address holds nothing of single sign-on. The tab's flow is forgotten whenever a fragment of
    // ours arrived.
    function takeReturn() {
        const found = (location.hash || '').match(FRAGMENT);
        if (!found) return null;
        try { history.replaceState(null, '', location.pathname + location.search); } catch (_) {}
        return { kind: found[1], value: found[2], returnTo: found[3] || '', flow: recall() };
    }

    // An address the server answered, when it is one this page will open: only https, or http on this computer, and
    // never anything else. null otherwise.
    function followable(address) {
        let url = null;
        try { url = new URL(String(address)); } catch (_) { url = null; }
        const local = url && (url.hostname === 'localhost' || url.hostname === '127.0.0.1' || url.hostname === '[::1]');
        return (url && (url.protocol === 'https:' || (url.protocol === 'http:' && local))) ? url : null;
    }

    function leaveFor(address) {
        const url = followable(address);
        if (!url) {
            forget();
            throw new Error('The provider\'s address is not one this page will open.');
        }
        window.location.assign(url.href);
    }

    // After a sign-out here: the provider's own logout, when the session came through a provider that asks for it.
    // The page is replaced, so Back does not return to the page that showed the app; the provider sends the browser
    // back to the sign-in page. False when the address is not one this page will open: the caller stays.
    function leaveToSignOut(address) {
        const url = followable(address);
        if (!url) return false;
        window.location.replace(url.href);
        return true;
    }

    function refusalText(data, fallback) {
        const detail = data && data.detail;
        if (detail && typeof detail === 'object' && typeof detail.message === 'string') return detail.message;
        if (typeof detail === 'string') return detail;
        return fallback;
    }

    // The sentence for a reason code, from the server's own list (kept once it was read; a list that could not be
    // read is asked for again the next time); a code the list does not hold gets the general sentence, never the code.
    async function reasonText(code) {
        if (reasonTexts === null) {
            try {
                const res = await fetch(`${API_BASE}/auth/sso/reasons`, { headers: { Accept: 'application/json' } });
                const data = res.ok ? await res.json() : null;
                if (!data || typeof data.reasons !== 'object' || !data.reasons) return GENERIC;
                reasonTexts = data.reasons;
            } catch (_) { return GENERIC; }
        }
        const text = Object.prototype.hasOwnProperty.call(reasonTexts, code) ? reasonTexts[code] : null;
        return typeof text === 'string' && text ? text : GENERIC;
    }

    // ---------------------------------------------------------------- the sign-in screen

    // Start a sign-in at a provider from the sign-in screen. `invitation` is the token of an invitation being
    // accepted through the provider: the flow notes that there is one (never the token), so that a page the provider
    // sends back signed in as someone else can say the invitation was not accepted.
    async function startSignIn(providerId, options) {
        const opts = options || {};
        const hash = await begin('sign_in', Object.assign({ provider: providerId },
            opts.invitation ? { invitation: true } : {}));
        const body = { verifier_hash: hash };
        if (opts.invitation) body.invitation = opts.invitation;
        if (opts.returnTo) body.return_to = opts.returnTo;
        const res = await fetch(`${API_BASE}/auth/sso/${encodeURIComponent(providerId)}/start`, {
            method: 'POST', headers: { 'Content-Type': 'application/json', Accept: 'application/json' },
            body: JSON.stringify(body),
        });
        let data = null;
        try { data = await res.json(); } catch (_) { data = null; }
        if (!res.ok || !data || typeof data.authorization_url !== 'string') {
            forget();
            throw new Error(refusalText(data, 'This sign-in could not be started. Try again in a moment.'));
        }
        leaveFor(data.authorization_url);
    }

    // The provider buttons, from /auth/policy's methods.providers: [{id, label, kind, icon, order}], in the order
    // given, under a heading that says what they do (a button carries the provider's name alone) and names the
    // group for a screen reader (the box's aria-labelledby). `onError(message)` shows what a start that failed said.
    // `options.returnTo()`, asked at the click, names the app's view the provider's answer brings the page back to.
    function renderButtons(providers, onError, options) {
        const box = document.getElementById('sso-sign-in');
        if (!box) return;
        const list = Array.isArray(providers) ? providers.filter((p) => p && typeof p.id === 'string' && p.id) : [];
        box.replaceChildren();
        box.style.display = list.length ? '' : 'none';
        if (list.length) {
            const heading = _el('p', 'sso-sign-in-heading text-secondary text-sm mt-md', 'Sign in with your organisation');
            heading.id = 'sso-sign-in-heading';
            box.appendChild(heading);
        }
        list.forEach((provider) => {
            const button = _el('button', 'btn btn-secondary btn-block mt-sm sso-sign-in-btn',
                typeof provider.label === 'string' && provider.label ? provider.label : 'Single sign-on');
            button.type = 'button';
            button.dataset.provider = provider.id;
            if (typeof provider.icon === 'string' && /^[a-z]{1,20}$/.test(provider.icon)) button.dataset.icon = provider.icon;
            button.addEventListener('click', async () => {
                box.querySelectorAll('button').forEach((b) => { b.disabled = true; });
                try {
                    const returnTo = (options && typeof options.returnTo === 'function') ? options.returnTo() : '';
                    await startSignIn(provider.id, { returnTo });
                }
                catch (e) {
                    box.querySelectorAll('button').forEach((b) => { b.disabled = false; });
                    if (typeof onError === 'function') onError((e && e.message) || GENERIC);
                }
            });
            box.appendChild(button);
        });
    }

    // ---------------------------------------------------------------- flows of a signed-in person

    async function startAuthed(path, purpose, more, body) {
        const hash = await begin(purpose, more);
        let data;
        try {
            data = await apiRequest(path, { method: 'POST', silent: true, body: JSON.stringify(Object.assign({ verifier_hash: hash }, body || {})) });
        } catch (e) { forget(); throw e; }
        if (!data || typeof data.authorization_url !== 'string') {
            forget();
            throw new Error('This could not be started. Try again in a moment.');
        }
        leaveFor(data.authorization_url);
    }

    const startLink = (providerId) => startAuthed(`/users/me/identities/${encodeURIComponent(providerId)}/start`,
        'link', { provider: providerId });
    const startTest = (providerId) => startAuthed(`/admin/sso/providers/${encodeURIComponent(providerId)}/test/start`,
        'test', { provider: providerId });
    // A fresh sign-in at the provider that confirms the person for `action`; `then` names what the page does once
    // it is back ('add-passkey', 'step-up'), and `label` is the provider's name for the page to say on its return.
    const startConfirm = (providerId, action, then, label) => startAuthed(
        `/users/me/identities/${encodeURIComponent(providerId)}/reauth`, 'step_up',
        { provider: providerId, action, then: then || '', label: typeof label === 'string' ? label : '' }, { action });

    // The providers that can confirm the signed-in person afresh, from their own identities: [{id, label}], in the
    // sign-in page's order; empty when none can, or when the list cannot be read.
    async function confirmers() {
        let data = null;
        try { data = await apiRequest('/users/me/identities', { silent: true }); } catch (_) { return []; }
        const providers = (data && Array.isArray(data.providers)) ? data.providers : [];
        return providers.filter((p) => p && p.reauth === true && typeof p.id === 'string' && p.id)
            .map((p) => ({ id: p.id, label: typeof p.label === 'string' ? p.label : '' }));
    }

    // What a signed-in page does with what came back, once the app is shown. Returns what happened, for the caller
    // to act on: {kind: 'linked', passwordStopped} | {kind: 'tested', provider, summary} |
    // {kind: 'confirmed', action, then, label, expiresIn} | {kind: 'error', message} | null. A confirmation lasts
    // `expiresIn` seconds at the server, for this session and this action only.
    async function resume(back) {
        if (!back) return null;
        if (back.kind === 'sso-error') return { kind: 'error', message: await reasonText(back.value) };
        if (back.kind === 'sso') return null;        // a sign-in's code is not for a page that is already signed in
        const flow = back.flow;
        const expected = { 'sso-linked': 'link', 'sso-test': 'test', 'sso-stepup': 'step_up' }[back.kind];
        if (!flow || flow.purpose !== expected) {
            return { kind: 'error', message: 'That did not come back to the tab that started it. Start again.' };
        }
        const claim = { method: 'POST', silent: true, body: JSON.stringify({ code: back.value, verifier: flow.verifier }) };
        try {
            if (back.kind === 'sso-linked') {
                const linked = await apiRequest('/users/me/identities/finish', claim);
                return { kind: 'linked', passwordStopped: !!(linked && linked.password_stopped) };
            }
            if (back.kind === 'sso-test') {
                const out = await apiRequest(`/admin/sso/providers/${encodeURIComponent(flow.provider)}/test/finish`, claim);
                return { kind: 'tested', provider: flow.provider, summary: (out && out.summary) || {} };
            }
            const out = await apiRequest('/users/me/identities/reauth/finish', claim);
            const lasts = out && Number.isFinite(out.expires_in) && out.expires_in > 0 ? out.expires_in : 120;
            return { kind: 'confirmed', action: (out && out.action) || flow.action || '', then: flow.then || '',
                     label: typeof flow.label === 'string' ? flow.label : '', expiresIn: lasts };
        } catch (e) {
            return { kind: 'error', message: (e && e.message) || GENERIC };
        }
    }

    // The name a fresh sign-in is staged under to confirm an unlink (app/services/sso_sign_in.py).
    const UNLINK_CONFIRMATION = 'sso.identity.unlink';

    // How an account that may hold a password again, and has none, gets one. "Forgot your password?" sends a reset
    // link only where the vault offers it, sends email and has its public address, and the account has an address:
    // the server says whether it does (self_service_reset). An administrator's reset link works everywhere.
    function howToSetAPassword(selfServiceReset) {
        return selfServiceReset === true
            ? 'set one with "Forgot your password?" on the sign-in page, or ask an administrator for a reset link.'
            : 'ask an administrator for a reset link.';
    }

    // What the page does once an unlink went through. An unlink ends every session made through the identity, so
    // when this session came through it (the answer's ended_this_session) the page signs out with a sentence: the
    // list read again would meet a session that has ended. Another way in is left, or the unlink was refused.
    function afterUnlink(answer, name) {
        if (answer && answer.ended_this_session === true) {
            logout(undefined, 'You unlinked ' + name + ', which this session came through, so you were signed out. '
                + 'Sign in again another way.');
            return;
        }
        // The provider that held the account to no password is gone: the account may hold one again, and has none.
        showSuccess(answer && answer.may_set_password === true
            ? 'Unlinked. Your account may hold a password again and has none yet: '
                + howToSetAPassword(answer.self_service_reset)
            : 'Unlinked.');
        renderAccount();
    }

    // The unlink of an identity, once the person is back from confirming it at the provider. `label` is the
    // provider's name, kept with the confirmation's flow.
    async function unlinkConfirmed(identityId, label) {
        const name = typeof label === 'string' && label ? label : 'the provider';
        let answer;
        try {
            answer = await apiRequest('/users/me/identities/' + encodeURIComponent(identityId), { method: 'DELETE' });
        } catch (e) {
            if (e && e.status === 503 && e.reason === 'busy') {
                // The account was being changed: nothing was done, and the answer came before the provider's
                // confirmation was taken, so it stays staged for this session for its two minutes. Trying again
                // sends the unlink again from here, not the person to the provider once more.
                const again = await showConfirm(e.message, 'Unlink single sign-on', null, 'Try again');
                if (again) return unlinkConfirmed(identityId, label);
                renderAccount();
                return;
            }
            showError((e && e.message) || 'It was not unlinked.');
            renderAccount();
            return;
        }
        afterUnlink(answer, name);
    }

    // ---------------------------------------------------------------- Your account

    function when(iso) {
        if (!iso) return '';
        const d = new Date(iso);
        return isNaN(d.getTime()) ? '' : d.toLocaleDateString(undefined, { year: 'numeric', month: 'short', day: 'numeric' });
    }

    // The person's linked providers, and the providers they could link, in Your account. Hidden when the vault has
    // no provider for them.
    async function renderAccount() {
        const section = document.getElementById('us-identities-section');
        const body = document.getElementById('us-identities-body');
        if (!section || !body) return;
        body.replaceChildren(_el('div', 'spinner'));
        let data;
        try { data = await apiRequest('/users/me/identities', { silent: true }); }
        catch (_) { section.style.display = 'none'; return; }
        const identities = (data && Array.isArray(data.identities)) ? data.identities : [];
        const providers = (data && Array.isArray(data.providers)) ? data.providers : [];
        const linkable = providers.filter((p) => p && !p.linked);
        const email = (data && data.email && data.email.address) ? data.email : null;
        if (!identities.length && !linkable.length && !email) { section.style.display = 'none'; return; }
        section.style.display = '';
        body.replaceChildren();
        if (!identities.length) {
            body.appendChild(_el('p', 'text-secondary text-sm mb-sm',
                'Not linked. Linking lets you sign in through your organisation\'s own sign-in as well.'));
        }
        identities.forEach((identity) => {
            const row = _el('div', 'identity-row flex items-center gap-sm mb-sm');
            row.dataset.identityId = identity.id;
            const text = _el('div', 'flex-1 identity-text');
            text.appendChild(_el('div', 'text-sm font-bold', identity.provider || 'A provider'));
            const bits = ['Linked ' + (when(identity.linked_at) || 'earlier'),
                identity.last_sign_in_at ? 'last signed in ' + when(identity.last_sign_in_at) : 'never signed in through it'];
            // Who the identity is at the provider, as the provider said when it was linked: a wrong one shows.
            const who = [identity.display_name, identity.email].filter((v) => typeof v === 'string' && v);
            if (who.length) bits.unshift('as ' + who.join(', '));
            // The day a sign-in through it is due (the notices that it is near or has passed open this page).
            const due = typeof identity.due_at === 'string' ? Date.parse(identity.due_at) : NaN;
            if (!isNaN(due)) {
                bits.push(due > Date.now() ? 'sign in through it by ' + when(identity.due_at)
                    : 'its time ran out on ' + when(identity.due_at) + ': sign out and sign in through it');
            }
            text.appendChild(_el('div', 'text-secondary text-xs', bits.join(' · ')));
            row.appendChild(text);
            const refusal = identity.unlink_refusal;
            if (refusal && typeof refusal.message === 'string' && refusal.message) {
                // The unlink would be refused whatever the provider says: its reason, in the server's words, in place
                // of the button, so that nobody is sent to the provider for an unlink refused on their return.
                const said = _el('div', 'text-secondary text-xs identity-unlink-refused', refusal.message);
                if (typeof refusal.reason === 'string') said.dataset.reason = refusal.reason;
                text.appendChild(said);
                body.appendChild(row);
                return;
            }
            const unlink = _el('button', 'btn btn-danger btn-sm', 'Unlink');
            unlink.type = 'button';
            unlink.setAttribute('aria-label', 'Unlink ' + (identity.provider || 'this provider'));
            unlink.addEventListener('click', async () => {
                const name = identity.provider || 'this provider';
                // What else the unlink does, said before it: the provider held the account to no password (it may
                // hold one again, and has none yet), and it ends every session made through the identity, this one
                // too when it came through it.
                const alsoSaid = (identity.restores_password === true ? ' Your account may then hold a password '
                    + 'again, but has none yet: ' + howToSetAPassword(data && data.self_service_reset) : '')
                    + (identity.this_session === true ? ' You signed in this time through ' + name
                        + ', so unlinking it also signs you out here and wherever you signed in through it.' : '');
                if (identity.unlink_asks_provider) {
                    // The provider confirms the unlink with a fresh sign-in there: the page goes to the provider
                    // and unlinks once it is back (app.js, resume).
                    if (!identity.provider_can_confirm) {
                        showError(name + ' cannot confirm you right now, so it is not unlinked here. Ask an administrator.');
                        return;
                    }
                    const go = await showConfirm('Unlink ' + name + '? You will no longer sign in through it. To '
                        + 'confirm it is you, ' + name + ' asks you to sign in there once more first.' + alsoSaid,
                        'Unlink single sign-on', null, 'Continue');
                    if (!go) return;
                    unlink.disabled = true;
                    try { await startConfirm(identity.provider_id, UNLINK_CONFIRMATION, 'unlink:' + identity.id, name); }
                    catch (e) { unlink.disabled = false; showError((e && e.message) || 'It could not be started.'); }
                    return;
                }
                const ok = await showConfirm('Unlink ' + name + '? You will no longer '
                    + 'sign in through it.' + alsoSaid, 'Unlink single sign-on', null, 'Unlink');
                if (!ok) return;
                let answer;
                try {
                    answer = await apiRequest('/users/me/identities/' + encodeURIComponent(identity.id), { method: 'DELETE' });
                } catch (e) {
                    showError((e && e.message) || 'It was not unlinked.');
                    renderAccount();
                    return;
                }
                afterUnlink(answer, name);
            });
            row.appendChild(unlink);
            body.appendChild(row);
        });
        linkable.forEach((provider) => {
            const refusal = provider.link_refusal;
            if (refusal && typeof refusal.message === 'string' && refusal.message) {
                // The server would refuse the start whatever the provider says: its reason is said in place of the
                // button, so nobody is sent through a step-up and to the provider for nothing.
                const said = _el('p', 'text-secondary text-sm identity-link-refused',
                    (provider.label || 'A provider') + ': ' + refusal.message);
                said.dataset.provider = provider.id;
                if (typeof refusal.reason === 'string') said.dataset.reason = refusal.reason;
                body.appendChild(said);
                return;
            }
            const link = _el('button', 'btn btn-secondary btn-sm mr-sm mb-sm identity-link', 'Link ' + (provider.label || 'a provider'));
            link.type = 'button';
            link.dataset.provider = provider.id;
            link.addEventListener('click', async () => {
                if (provider.ends_password) {
                    // The provider's people hold no vault password: said before the link, since linking ends it.
                    const ok = await showConfirm((provider.label || 'This provider') + ' signs its people in without a '
                        + 'vault password. If you link it, your password and your SFTP password sign-in stop working, and '
                        + 'you sign in only through it.', 'Link and stop using your password?', null, 'Link');
                    if (!ok) return;
                }
                link.disabled = true;
                try { await startLink(provider.id); }
                catch (e) { link.disabled = false; showError((e && e.message) || 'The link could not be started.'); }
            });
            body.appendChild(link);
        });
        // A provider can be linked from here only where the server would start the link (link_refusal).
        const canLink = providers.some((p) => p && !p.linked && !p.link_refusal);
        if (email) body.appendChild(emailConfirmation(email, canLink));
    }

    // The address an account holds is its owner's own claim until the vault confirmed it, and the organisation's
    // sign-in finds an account by a confirmed address only. The owner confirms it here with a code the vault
    // sends to that address; where the vault sends no email, an administrator confirms it.
    // canLink: a provider can be linked from this page, which needs no confirmed address and costs nothing.
    function emailConfirmation(email, canLink) {
        const box = _el('div', 'identity-email-confirm mt-sm');
        box.id = 'us-email-confirm';
        box.appendChild(_el('p', 'text-secondary text-sm mb-sm', 'Your email address (' + email.address + ') is not '
            + 'confirmed yet. Your organisation\'s sign-in finds your account by a confirmed address only.'));
        if (!email.can_send_code) {
            box.appendChild(_el('p', 'text-secondary text-sm', 'This vault sends no email, so it cannot send you a '
                + 'code.' + (canLink ? ' Link your organisation\'s sign-in above instead: it then finds your account '
                    + 'without your address. Linking asks for your second factor: set one up '
                    + (email.factor_here === false ? '' : 'here ') + 'first if you have none.' : '')));
            const cost = _el('p', 'text-secondary text-sm', 'An administrator can confirm your address. That counts as '
                + 'a change to your sign-in details: your zero-knowledge vaults are then held for up to 14 days, and on '
                + 'this vault only the person who runs the server can lift that.');
            cost.id = 'us-email-confirm-by-admin';
            box.appendChild(cost);
            return box;
        }
        const send = _el('button', 'btn btn-secondary btn-sm', 'Send me a code');
        send.type = 'button';
        send.id = 'us-email-confirm-send';
        const row = _el('div', 'flex items-center gap-sm mt-sm');
        row.id = 'us-email-confirm-row';
        row.style.display = 'none';
        const code = document.createElement('input');
        code.type = 'text';
        code.id = 'us-email-confirm-code';
        code.className = 'form-input';
        code.autocomplete = 'one-time-code';
        code.inputMode = 'text';                  // letters and digits
        code.autocapitalize = 'off';
        code.spellcheck = false;
        code.maxLength = 32;
        code.placeholder = 'Code';
        code.setAttribute('aria-label', 'The code sent to your email address');
        const confirm = _el('button', 'btn btn-primary btn-sm', 'Confirm');
        confirm.type = 'button';
        confirm.id = 'us-email-confirm-submit';
        row.append(code, confirm);
        send.addEventListener('click', async () => {
            send.disabled = true;
            try {
                await apiRequest('/users/me/email/confirmation/request', { method: 'POST' });
                row.style.display = '';
                send.textContent = 'Send another code';
                showSuccess('A code was sent to ' + email.address + '.');
                code.focus();
            } catch (e) { showError((e && e.message) || 'The code could not be sent.'); }
            send.disabled = false;
        });
        const submit = async () => {
            const typed = code.value.trim();
            if (!typed) { showError('Enter the code from the email.'); return; }
            confirm.disabled = true;
            try {
                await apiRequest('/users/me/email/confirmation', { method: 'POST', body: JSON.stringify({ code: typed }) });
                showSuccess('Your email address is confirmed.');
                renderAccount();
                return;
            } catch (e) { showError((e && e.message) || 'That code was not accepted.'); }
            confirm.disabled = false;
        };
        confirm.addEventListener('click', submit);
        code.addEventListener('keydown', (e) => { if (e.key === 'Enter') { e.preventDefault(); submit(); } });
        box.append(send, row);
        return box;
    }

    function reset() {
        forget();
        const body = document.getElementById('us-identities-body');
        if (body) body.replaceChildren();
        const section = document.getElementById('us-identities-section');
        if (section) section.style.display = 'none';
    }

    window.Sso = {
        available, takeReturn, reasonText, renderButtons, startSignIn, startLink, startTest, startConfirm, confirmers, resume,
        unlinkConfirmed, renderAccount, reset, leaveToSignOut,
    };
})();
