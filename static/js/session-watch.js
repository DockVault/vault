// A minute before the signed-in session ends, the page asks whether to stay (static/js/session-watch.js).
//
// The session's end is measured on this device's own clock: the token's lifetime (exp - iat) counted
// from the moment the token arrived here, which is kept in storage so a reload measures the same way.
// A token with no stored arrival (one that just arrived, or one held from before the arrival was kept)
// is armed at once as if it had just arrived, then corrected from the server: the time it has left is
// read on the server's clock (the token's exp against the Date of a /users/me answer), carried onto
// this device's clock, and the arrival that implies is stored. The server's clock and this device's may
// differ, so the device never ends a session on its own: when the count reaches zero the page asks the
// server, and signs out only when the server refuses the token. Sixty seconds before the end, a dialog
// with a count-down ring opens above everything else. It does not focus a button, so a key pressed by accident (Enter, Space) chooses nothing. Closing it with
// Escape, the x or a click beside it counts as "stay": a person who dismisses the warning is present.
// "Stay signed in" asks the server for a new token (POST /auth/session/extend); the server ends the old
// session at once, so the request cannot be replayed, and the page stores the new token and arms itself
// again. A refusal (the sign-in's renewal limit reached, a second factor now required, a temporary
// credential) signs out with the server's sentence. A temporary credential's session is never renewed:
// its warning is timed to whichever ends first, the token or the credential, and offers only "Sign out".
// Another request of the session refused for it (a poll's answer may come before the warning's own check)
// signs out the same way, once, and the sign-in screen says why (refusedSession, called by apiRequest).
// All text is written with textContent.
(function () {
    'use strict';

    const WARN_SECONDS = 60;
    const RING = 2 * Math.PI * 52;   // the ring's circumference (r=52 in a 120-unit box)
    const ARRIVAL_KEY = 'authTokenAt';   // "<ms the token arrived>:<the token's tail>", beside the token; a
                                         // leading "~" marks a guess the server has not confirmed yet

    let deadline = null;             // ms on this device's clock at which the session ends
    let timer = null;                // opens the dialog WARN_SECONDS before the deadline
    let ticker = null;               // redraws the count while the dialog is armed
    let busy = false;
    let checking = false;
    let temporary = false;           // a temporary credential's session: no renewal offered
    let closingOurselves = false;    // the dialog is being hidden by this module, not by the person
    let armedFor = null;             // the token whose own arming is in force (its tail); null once anything
                                     // else armed: a correction from the server applies only while it is
    const askedFor = new Set();      // tokens (tails) whose arrival this load has asked the server about

    function claimsOf(token) {
        try {
            return JSON.parse(atob(String(token).split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        } catch (_) { return null; }
    }

    function el(id) { return document.getElementById(id); }

    function tailOf(token) { return String(token).slice(-24); }

    // When this token arrived on this device, as stored for the same token: { ms, guessed } (guessed: the
    // server has not confirmed it yet); null when none is stored.
    function storedArrival(token) {
        let stored = null;
        try { stored = storage.getItem(ARRIVAL_KEY); } catch (_) {}
        if (stored) {
            const guessed = stored.charAt(0) === '~';
            const text = guessed ? stored.slice(1) : stored;
            const at = text.indexOf(':');
            const ms = Number(text.slice(0, at));
            if (at > 0 && Number.isFinite(ms) && text.slice(at + 1) === tailOf(token)) return { ms, guessed };
        }
        return null;
    }

    function rememberArrival(token, ms, guessed) {
        try { storage.setItem(ARRIVAL_KEY, (guessed ? '~' : '') + Math.round(ms) + ':' + tailOf(token)); } catch (_) {}
    }

    // Ask the server for the account, for the Date of its answer only. The answer's body is read to its end
    // and dropped: a body nobody reads keeps its request open in the browser for as long as the page lives.
    // An answer that has not come within CHECK_TIMEOUT_MS is given up (the caller asks again later), so a hung
    // request never leaves the count standing at zero. Returns the answer and, for a refusal, its sentence.
    const CHECK_TIMEOUT_MS = 15000;
    async function askTheServer(token) {
        const stop = typeof AbortController === 'function' ? new AbortController() : null;
        const timer = stop ? setTimeout(() => stop.abort(), CHECK_TIMEOUT_MS) : null;
        try {
            const res = await fetch(`${API_BASE}/users/me`, {
                headers: { 'Authorization': `Bearer ${token}` }, ...(stop ? { signal: stop.signal } : {}),
            });
            let detail = '';
            try {
                const text = await res.text();
                if (!res.ok) {
                    const body = JSON.parse(text);
                    if (body && typeof body.detail === 'string') detail = body.detail;
                }
            } catch (_) { /* no body, or not one with a sentence */ }
            return { res, detail };
        } finally {
            if (timer) clearTimeout(timer);
        }
    }

    // A token with no stored arrival: the time it has left as the server counts it, carried onto this
    // device's clock, as expire() does. Its arrival is stored from that, so a reload agrees. When the server
    // does not answer, the local arming stands.
    async function correctFromServer(token, claims) {
        const tail = tailOf(token);
        try {
            const { res } = await askTheServer(token);
            const serverNow = Date.parse(res.headers.get('Date') || '');
            if (!res.ok || !Number.isFinite(serverNow)) return;
            if (armedFor !== tail || authToken !== token) return;   // armed since from something else
            // The Date header counts whole seconds and was written before the answer travelled here: the
            // server's clock now is at least a second past it. Taking that later moment ends the count a
            // little early, never after the token itself has run out.
            const serverNowLatest = serverNow + 1000;
            const issuedMs = (claims.iat || claims.exp) * 1000;
            rememberArrival(token, Date.now() - (serverNowLatest - issuedMs));
            armAt(Date.now() + (claims.exp * 1000 - serverNowLatest));
            armedFor = tail;
        } catch (_) { /* the local arming stands */ }
    }

    function forgetArrival() {
        try { storage.removeItem(ARRIVAL_KEY); } catch (_) {}
    }

    // Arm from a token: its lifetime, counted from its arrival on this device. False when the token says
    // nothing about its end.
    function armFromToken(token) {
        const claims = token ? claimsOf(token) : null;
        if (!claims || !claims.exp) { disarm(); return false; }
        temporary = !!claims.is_temporary;
        const lifetimeMs = (claims.exp - (claims.iat || claims.exp)) * 1000;
        const stored = storedArrival(token);
        let arrival;
        if (stored) arrival = stored.ms;
        else {
            // Armed at once as if it had just arrived, stored as a guess, then corrected from the server. Until
            // the server has confirmed it, a later load asks again; this load asks once.
            arrival = Date.now();
            rememberArrival(token, arrival, true);
        }
        const armed = armAt(lifetimeMs > 0 ? arrival + lifetimeMs : Date.now());
        const tail = tailOf(token);
        armedFor = tail;
        if ((!stored || stored.guessed) && lifetimeMs > 0 && !askedFor.has(tail)) {
            askedFor.add(tail);
            correctFromServer(token, claims);
        }
        return armed;
    }

    // A temporary credential's session: timed to whichever ends first, the token or the credential
    // (``endsAt``: the server's ISO time of the credential's end), and never renewed.
    function armTemporary(endsAt) {
        temporary = true;
        const credentialEnd = endsAt ? Date.parse(endsAt) : NaN;
        if (Number.isFinite(credentialEnd) && (!deadline || credentialEnd < deadline)) {
            // Read on the server's clock; the shorter reading wins, and the server has the last word at zero.
            armAt(credentialEnd);
        } else if (deadline) {
            draw();
        }
        return true;
    }

    // Arm for a deadline on this device's clock. The kind of session (a temporary credential's, which is
    // never renewed) is kept: only a sign-out, or a token of another kind, changes it.
    function armAt(ms) {
        disarm({ keepKind: true });
        deadline = Number(ms);
        if (!Number.isFinite(deadline)) { deadline = null; return false; }
        schedule();
        return true;
    }

    // A browser's timer takes at most 2^31-1 ms (24.8 days): a longer wait is taken in steps, re-armed from the
    // deadline each time (a session may last up to 30 days).
    const LONGEST_TIMER_MS = 2147483647;
    function schedule() {
        const wait = Math.max(0, deadline - Date.now() - WARN_SECONDS * 1000);
        if (wait > LONGEST_TIMER_MS) { timer = setTimeout(schedule, LONGEST_TIMER_MS); return; }
        timer = setTimeout(show, wait);
    }

    function disarm(opts) {
        if (timer) clearTimeout(timer);
        if (ticker) clearInterval(ticker);
        timer = ticker = null;
        deadline = null;
        armedFor = null;
        if (!(opts && opts.keepKind)) temporary = false;
        hide();
    }

    function remaining() {
        if (!deadline) return 0;
        return Math.max(0, Math.round((deadline - Date.now()) / 1000));
    }

    function show() {
        if (!deadline) return;
        const modal = el('session-expiry-modal');
        if (!modal) return;
        wire();
        draw();
        modal.classList.add('active');
        if (!ticker) ticker = setInterval(tick, 250);
    }

    function hide() {
        const modal = el('session-expiry-modal');
        if (!modal || !modal.classList.contains('active')) return;
        closingOurselves = true;
        modal.classList.remove('active');
        // The class change is observed after this call returns: the flag outlives it by a tick.
        setTimeout(() => { closingOurselves = false; }, 0);
    }

    function draw() {
        const s = remaining();
        const number = el('session-expiry-seconds');
        if (number) number.textContent = String(s);
        const fill = el('session-ring-fill');
        if (fill) {
            fill.style.strokeDasharray = String(RING);
            fill.style.strokeDashoffset = String(RING * (1 - Math.min(1, s / WARN_SECONDS)));
        }
        const stayBtn = el('session-stay');
        if (stayBtn) stayBtn.hidden = temporary;
        const text = el('session-expiry-text');
        if (!text) return;
        const seconds = `${s} second${s === 1 ? '' : 's'}`;
        if (temporary) {
            text.textContent = s > 0
                ? `Your temporary access ends in ${seconds}. This credential cannot be used again; ask for a new one if you need more time.`
                : 'Your temporary access has ended.';
        } else {
            text.textContent = s > 0
                ? `Your session ends in ${seconds}. Stay signed in, or sign out now. Closing this counts as staying; if you do nothing, you are signed out when the count reaches zero.`
                : 'Your session has ended.';
        }
    }

    function tick() {
        if (!deadline) return;
        draw();
        if (remaining() <= 0) expire();
    }

    // What the sign-in screen says when a session is over: it ran out (a temporary credential's, or one nobody
    // chose to keep), or it ended otherwise.
    const RAN_OUT = 'Your session ended because nobody chose to stay signed in. Sign in again.';
    const TEMPORARY_RAN_OUT = 'Your temporary access ended. Ask for a new credential if you need more time.';
    const ENDED = 'Your session has ended. Sign in again.';

    // The server's sentences for a session it ended itself (signed out, ended by an administrator, by a password
    // change, revoked; a temporary credential deactivated or released; the account deleted): such a 401 never
    // reads as one that ran out.
    const ENDED_ON_THE_SERVER = /terminated|deactivated|has ended|user not found/i;

    // Why a 401 of `token` ended its session: that it ran out only when its end has passed or is two seconds away
    // (the count may end a second after the token does, since the server's clock is read in whole seconds) and the
    // server did not say that it ended the session itself; else that it has ended.
    function sentenceFor401(token, detail) {
        if (typeof detail === 'string' && ENDED_ON_THE_SERVER.test(detail)) return ENDED;
        if (!endsWithin(token, 2000)) return ENDED;
        return temporary ? TEMPORARY_RAN_OUT : RAN_OUT;
    }

    // The count reached zero on this device's clock: the server decides. Refused: signed out, with the
    // reason on the sign-in screen. Still accepted (this device's clock runs ahead of the server's): armed
    // again from the server's own reading of the time left, and the dialog waits for the real end.
    async function expire() {
        if (checking) return;
        checking = true;
        if (ticker) clearInterval(ticker);
        ticker = null;
        const token = authToken;
        try {
            const { res, detail } = await askTheServer(token);
            if (res.status === 401) {
                // Another tab of this browser may have renewed the sign-in in its last second: its token is taken.
                // Else signed out, unless a refusal of another request of this session has done it first.
                if (!takeRenewedToken(token)) signOutWithNote(sentenceFor401(token, detail), token);
                return;
            }
            if (res.status === 403 && detail) {
                // Refused for the account (locked, made inactive): signed out with the server's sentence, rather
                // than asked again every thirty seconds for ever.
                refusedSession(token, 403, detail);
                return;
            }
            const claims = claimsOf(authToken);
            const serverNow = Date.parse(res.headers.get('Date') || '');
            if (res.ok && claims && claims.exp && Number.isFinite(serverNow)) {
                // The token's end as the server counts it, carried onto this device's clock.
                const left = claims.exp * 1000 - serverNow;
                if (left > 0) { armAt(Date.now() + left); return; }
            }
            // No answer to go by: asked again shortly; the server, not this clock, ends the session.
            armAt(Date.now() + 30000);
        } catch (_) {
            armAt(Date.now() + 30000);
        } finally {
            checking = false;
        }
    }

    // Sign out the session of `token` and say why on the sign-in screen. Once per session: when the tab no longer
    // holds that token (signed out already, by this or by another refusal, or signed in again) nothing is done,
    // so a second refusal of the same session neither signs out twice nor writes over the first reason. True when
    // this call signed the tab out.
    function signOutWithNote(sentence, token) {
        if (!token || authToken !== token) return false;
        disarm();
        forgetArrival();
        // The sign-in screen says why: this page's, and the page's that replaces it after the sign-out.
        if (typeof logout === 'function') logout(undefined, sentence);
        return true;
    }

    // When the sign-in a token belongs to happened: its auth_time once renewed, its iat before that; 0 when unknown.
    const signedInAt = (claims) => Number(claims.auth_time || claims.iat) || 0;

    // Whether the token `theirs` renews the sign-in of `mine` (both as claims), so that a tab holding `mine` may
    // take it: the same person's full sign-in, not the token of another account signed in since in another tab,
    // never a temporary credential's (it carries its owner's id as sub), still running, and the same sign-in,
    // not a new sign-in of the same person since: a tab signed out and never told signs out rather than open a
    // session it was not part of. The same sign-in is told by the id the server gives every sign-in and keeps
    // through its renewals (sign_in_id); a token from before that id, by the time of the sign-in.
    function renewsSignIn(mine, theirs) {
        if (!mine || !theirs) return false;
        if (theirs.sub !== mine.sub || theirs.username !== mine.username) return false;
        if (theirs.is_temporary || mine.is_temporary) return false;
        if (!theirs.exp || theirs.exp * 1000 <= Date.now()) return false;
        if (mine.sign_in_id || theirs.sign_in_id) return !!mine.sign_in_id && theirs.sign_in_id === mine.sign_in_id;
        return !!signedInAt(mine) && signedInAt(theirs) === signedInAt(mine);
    }

    // Another tab of this browser renewed this sign-in first, so the token sent is spent (the server answered it
    // with a 401): the renewed one, which that tab stored for the browser, is taken instead, when it renews this
    // tab's sign-in (renewsSignIn). True when the tab now holds such a token.
    function takeRenewedToken(sent) {
        if (authToken && authToken !== sent) {                                          // taken already
            if (!renewsSignIn(claimsOf(sent), claimsOf(authToken))) return false;
            armFromToken(authToken);
            return true;
        }
        if (authToken !== sent) return false;                                          // signed out since
        let stored = null;
        try { stored = storage.getItem('authToken'); } catch (_) {}
        if (!stored || stored === sent || !renewsSignIn(claimsOf(sent), claimsOf(stored))) return false;
        return adopt(stored);
    }

    // Another tab told this one that it renewed the session this tab holds, and stored `stored`, the token its
    // message names (static/js/app.js, the sign-out channel). Taken only when it renews this tab's sign-in
    // (renewsSignIn): a tab the browser froze gets its messages when it wakes, by which time the token stored may
    // be the next sign-in's. Otherwise nothing is taken, and the tab's next request, refused, signs it out.
    function takeToldRenewal(stored) {
        if (!authToken || !stored || stored === authToken) return false;
        if (!renewsSignIn(claimsOf(authToken), claimsOf(stored))) return false;
        return adopt(stored);
    }

    // A session renewed for a tab that has signed out, or signed in again, while the answer was on its way: it is
    // nobody's now, and it is ended on the server rather than left open.
    function endUnwantedSession(token) {
        try {
            fetch(`${API_BASE}/auth/sign-out`, { method: 'POST', headers: { 'Authorization': `Bearer ${token}` } })
                .then((r) => r.text()).catch(() => {});
        } catch (_) {}
    }

    // A renewal on its way: the token it was asked for, and what settles once its answer has been dealt with
    // (refusedSession waits for it).
    let renewing = null;

    async function stay() {
        if (busy || temporary) return;
        busy = true;
        const btn = el('session-stay');
        if (btn) btn.disabled = true;
        const sent = authToken;
        let settled;
        // `renewed`: the token this renewal produced, once taken (refusedSession carries on only with it).
        renewing = { token: sent, renewed: null, done: new Promise((resolve) => { settled = resolve; }) };
        try {
            // Asked directly rather than through apiRequest: a refusal here is this dialog's to explain. Through
            // apiRequest a 401, or a 403 that names the account, signs the tab out before the answer is read,
            // a 401 even when another tab of this browser has just renewed the sign-in.
            const res = await fetch(`${API_BASE}/auth/session/extend`, {
                method: 'POST', headers: { 'Authorization': `Bearer ${sent}` },
            });
            let body = null;
            try { body = await res.json(); } catch (_) {}
            if (res.status === 401 || res.status === 403) {
                // A 401: the token sent is spent, perhaps by another tab's renewal of this sign-in, whose token is
                // then taken. A 403: the server refused this renewal (its limit, a second factor now required, the
                // account locked or made inactive) and the token is not spent: nothing is taken. Otherwise the
                // session is over, and the sign-in screen says why.
                if (res.status === 401 && takeRenewedToken(sent)) return;
                const detail = body && typeof body.detail === 'string' ? body.detail : '';
                signOutWithNote(res.status === 403
                    ? (detail || 'This session could not be renewed. Sign in again.')
                    : ENDED, sent);
                return;
            }
            if (!res.ok) {
                // Any other refusal (the vault busy with this account, a limit) is said in the server's words, and
                // the warning stays for the person to try again: a renewal mints a new token, so it is never sent
                // again behind their back.
                const said = body && typeof body.detail === 'string' ? body.detail : '';
                if (typeof showError === 'function') {
                    showError(said || 'Could not extend the session right now. Try again, or sign in again when it ends.');
                }
                show();
                return;
            }
            if (!body || !body.access_token) throw new Error('no token');
            if (authToken !== sent) { endUnwantedSession(body.access_token); return; }
            authToken = body.access_token;
            if (renewing) renewing.renewed = authToken;
            try { storage.setItem('authToken', authToken); } catch (_) {}
            armFromToken(authToken);   // hides the dialog and arms for the new expiry
            // The other tabs of this browser hold the old token, which is dead now: told which token replaced it,
            // they take that one from the shared storage and carry on (static/js/app.js, the sign-out channel).
            if (typeof _tellOtherTabsRenewed === 'function') _tellOtherTabsRenewed(sent, authToken);
            if (typeof showSuccess === 'function') showSuccess('You stay signed in.');
        } catch (e) {
            if (typeof showError === 'function') showError('Could not extend the session right now. Try again, or sign in again when it ends.');
            show();
        } finally {
            busy = false;
            if (btn) btn.disabled = false;
            renewing = null;
            settled();
        }
    }

    function signOut() {
        disarm();
        forgetArrival();
        // 'asked': the person chose to sign out (app.js, SIGN_OUT_ASKED).
        if (typeof logout === 'function') logout('asked');
    }

    // Whether the session of `token` ends within `ms` (or has ended): by this device's count when it is armed for
    // that token, which is measured on this device's clock from the token's arrival; else by the token's own exp.
    function endsWithin(token, ms) {
        if (deadline && authToken === token) return deadline - Date.now() <= ms;
        const claims = claimsOf(token);
        return !!(claims && claims.exp && claims.exp * 1000 - Date.now() <= ms);
    }

    // A request of this tab's own session was refused for the session (apiRequest: a 401, or a 403 that names
    // the account), perhaps before this warning's own check at the end of the count. A 403 signs out with the
    // server's own sentence. A 401 first takes the token of another tab's renewal of this sign-in, when there is
    // one (the session renewed in its last second); else it signs out, saying that the session ran out or that it
    // has ended (sentenceFor401, by the answer's own sentence). Once per session (signOutWithNote). A renewal of
    // this token on its way (Stay pressed in this tab) ends the old session at once, so a request sent meanwhile is
    // refused: the refusal waits for the renewal's answer and is weighed again with what the tab holds then. Resolves
    // true when the tab carries on with a renewed token or was signed out by this call; after a renewal of its own,
    // only when the tab holds the token that renewal produced (not that of a sign-in made on the page since).
    async function refusedSession(token, status, detail) {
        if (status === 403) return signOutWithNote((typeof detail === 'string' && detail) || ENDED, token);
        if (renewing && renewing.token === token) {
            const own = renewing;
            await own.done;
            if (own.renewed && authToken === own.renewed) return true;
        }
        if (takeRenewedToken(token)) return true;
        return signOutWithNote(sentenceFor401(token, detail), token);
    }

    // The dialog closed by the person (Escape, the x, a click beside it) while the count still ran: they
    // are present, so that is "stay". A temporary credential's dialog closes and its count goes on.
    function closedByPerson() {
        if (closingOurselves || !deadline || temporary) return;
        stay();
    }

    let wired = false;
    function wire() {
        if (wired) return;
        wired = true;
        const modal = el('session-expiry-modal');
        const stayBtn = el('session-stay');
        const outBtn = el('session-signout');
        if (stayBtn) stayBtn.addEventListener('click', stay);
        if (outBtn) outBtn.addEventListener('click', signOut);
        // The x closes this dialog alone, whatever else is open under it: it gets its own listener in
        // place of the page-wide one that closes every dialog.
        const x = modal ? modal.querySelector('.close-modal-btn') : null;
        if (x) {
            const own = x.cloneNode(true);
            x.replaceWith(own);
            own.addEventListener('click', (e) => { e.preventDefault(); e.stopImmediatePropagation(); hide(); closedByPerson(); });
        }
        if (modal && typeof MutationObserver === 'function') {
            new MutationObserver(() => {
                if (!modal.classList.contains('active')) closedByPerson();
            }).observe(modal, { attributes: true, attributeFilter: ['class'] });
        }
        // A tab that slept past the warning draws the truth when it wakes.
        document.addEventListener('visibilitychange', () => { if (!document.hidden && deadline) tick(); });
    }

    // Another tab renewed the session this tab shares: take the new token from storage and arm for it.
    function adopt(token) {
        if (!token) return false;
        authToken = token;
        armFromToken(token);
        return true;
    }

    window.SessionWatch = { armFromToken, armTemporary, armAt, disarm, show, remaining, adopt, forgetArrival,
                            refusedSession, takeToldRenewal, isTemporary: () => temporary, WARN_SECONDS,
                            // Whether the token `held` renews the sign-in of the token `sent` (renewsSignIn).
                            renews: (sent, held) => renewsSignIn(claimsOf(sent), claimsOf(held)),
                            REASONS: { ran_out: RAN_OUT, temporary_ran_out: TEMPORARY_RAN_OUT } };
})();
