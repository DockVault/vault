// A minute before the signed-in session ends, the page asks whether to stay (static/js/session-watch.js).
//
// The session's end is the token's own expiry (the exp claim), read when the token is stored and again
// after it is renewed. Sixty seconds before it, a dialog with a count-down ring opens. It does not focus a
// button, so a key pressed by accident (Enter, Space) chooses nothing, and it can be closed with Escape or a
// click beside it without choosing: the count goes on and, at zero, the person is signed out. "Stay signed
// in" asks the server for a new token (POST /auth/session/extend); the server ends the old session at once,
// so the request cannot be replayed, and the page stores the new token and arms itself again. Clicking
// "Sign out" signs out now. All text is written with textContent.
(function () {
    'use strict';

    const WARN_SECONDS = 60;
    const RING = 2 * Math.PI * 52;   // the ring's circumference (r=52 in a 120-unit box)

    let deadline = null;             // ms since the epoch at which the session ends
    let timer = null;                // opens the dialog WARN_SECONDS before the deadline
    let ticker = null;               // redraws the count while the dialog is armed
    let busy = false;

    function claimsOf(token) {
        try {
            return JSON.parse(atob(String(token).split('.')[1].replace(/-/g, '+').replace(/_/g, '/')));
        } catch (_) { return null; }
    }

    function el(id) { return document.getElementById(id); }

    // Arm from a token's expiry; false when the token says nothing about it.
    function armFromToken(token) {
        const claims = token ? claimsOf(token) : null;
        if (!claims || !claims.exp) { disarm(); return false; }
        return armAt(claims.exp * 1000);
    }

    function armAt(ms) {
        disarm();
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

    function disarm() {
        if (timer) clearTimeout(timer);
        if (ticker) clearInterval(ticker);
        timer = ticker = null;
        deadline = null;
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
        if (modal) modal.classList.remove('active');
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
        const text = el('session-expiry-text');
        if (text) text.textContent = s > 0
            ? `Your session ends in ${s} second${s === 1 ? '' : 's'}. Stay signed in, or sign out now. If you do nothing, you are signed out when the count reaches zero.`
            : 'Your session has ended.';
    }

    function tick() {
        if (!deadline) return;
        draw();
        if (remaining() <= 0) expire();
    }

    function expire() {
        disarm();
        if (typeof logout === 'function') logout();
        // The sign-in screen says why, once the sign-out has drawn it.
        setTimeout(() => {
            const note = el('login-error');
            if (note) {
                note.className = 'alert alert-warning mt-md';
                note.textContent = 'Your session ended because you were away. Sign in again.';
                note.style.display = 'block';
            }
        }, 400);
    }

    async function stay() {
        if (busy) return;
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
            if (typeof showError === 'function') showError('Could not extend the session. Sign in again when it ends.');
        } finally {
            busy = false;
            if (btn) btn.disabled = false;
        }
    }

    function signOut() {
        disarm();
        if (typeof logout === 'function') logout();
    }

    let wired = false;
    function wire() {
        if (wired) return;
        wired = true;
        const stayBtn = el('session-stay');
        const outBtn = el('session-signout');
        if (stayBtn) stayBtn.addEventListener('click', stay);
        if (outBtn) outBtn.addEventListener('click', signOut);
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

    window.SessionWatch = { armFromToken, armAt, disarm, show, remaining, adopt, WARN_SECONDS };
})();
