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

    // A token with no stored arrival: the time it has left as the server counts it, carried onto this
    // device's clock, as expire() does. Its arrival is stored from that, so a reload agrees. When the server
    // does not answer, the local arming stands.
    async function correctFromServer(token, claims) {
        const tail = tailOf(token);
        try {
            const res = await fetch(`${API_BASE}/users/me`, { headers: { 'Authorization': `Bearer ${token}` } });
            const serverNow = Date.parse(res.headers.get('Date') || '');
            if (!res.ok || !Number.isFinite(serverNow)) return;
            if (armedFor !== tail || authToken !== token) return;   // armed since from something else
            const issuedMs = (claims.iat || claims.exp) * 1000;
            rememberArrival(token, Date.now() - (serverNow - issuedMs));
            armAt(Date.now() + (claims.exp * 1000 - serverNow));
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

    // The count reached zero on this device's clock: the server decides. Refused: signed out, with the
    // reason on the sign-in screen. Still accepted (this device's clock runs ahead of the server's): armed
    // again from the server's own reading of the time left, and the dialog waits for the real end.
    async function expire() {
        if (checking) return;
        checking = true;
        if (ticker) clearInterval(ticker);
        ticker = null;
        try {
            const res = await fetch(`${API_BASE}/users/me`, { headers: { 'Authorization': `Bearer ${authToken}` } });
            if (res.status === 401) {
                signOutWithNote(temporary
                    ? 'Your temporary access ended. Ask for a new credential if you need more time.'
                    : 'Your session ended because nobody chose to stay signed in. Sign in again.');
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

    function signOutWithNote(sentence) {
        disarm();
        forgetArrival();
        if (typeof logout === 'function') logout();
        // The sign-in screen says why, once the sign-out has drawn it.
        setTimeout(() => {
            const note = el('login-error');
            if (note) {
                note.className = 'alert alert-warning mt-md';
                note.setAttribute('role', 'alert');
                note.textContent = sentence;
                note.style.display = 'block';
            }
        }, 400);
    }

    async function stay() {
        if (busy || temporary) return;
        busy = true;
        const btn = el('session-stay');
        if (btn) btn.disabled = true;
        try {
            const res = await apiRequest('/auth/session/extend', { method: 'POST', silent: true });
            if (!res || !res.access_token) throw new Error('no token');
            const previous = authToken;
            authToken = res.access_token;
            try { storage.setItem('authToken', authToken); } catch (_) {}
            armFromToken(authToken);   // hides the dialog and arms for the new expiry
            // The other tabs of this browser hold the old token, which is dead now: told, they take the new
            // one from the shared storage and carry on (static/js/app.js, the sign-out channel).
            if (typeof _tellOtherTabsRenewed === 'function') _tellOtherTabsRenewed(previous);
            if (typeof showSuccess === 'function') showSuccess('You stay signed in.');
        } catch (e) {
            if (e && e.status === 403) {
                // The server will not renew this sign-in (its limit, a second factor now required): it ends
                // when the token does, and the person signs in again; said on the sign-in screen.
                signOutWithNote(e.message || 'This session could not be renewed. Sign in again.');
            } else {
                if (typeof showError === 'function') showError('Could not extend the session right now. Try again, or sign in again when it ends.');
                show();
            }
        } finally {
            busy = false;
            if (btn) btn.disabled = false;
        }
    }

    function signOut() {
        disarm();
        forgetArrival();
        if (typeof logout === 'function') logout();
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
                            isTemporary: () => temporary, WARN_SECONDS };
})();
