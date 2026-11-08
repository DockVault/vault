// The one password rule for every form that sets a password: read from the server's effective policy,
// never a number written into a form.
//
// The rule is the administrators' (Settings > Security: the minimum length, floored by the server, and the
// complexity switches). The server enforces it on every password it is given; a form only shows the rule
// and refuses what would be refused anyway, so the hint and the server never disagree. GET /auth/policy is
// public (the sign-in page reads it), so a signed-in form reads the same source as the sign-up form.
//
//   PasswordPolicy.load()                    -> the policy {min_length, require_uppercase, ...}; the floor on failure
//   PasswordPolicy.describe(policy)          -> one sentence for a hint
//   PasswordPolicy.failures(password, policy)-> the requirements the password misses (as the server words them)
//   PasswordPolicy.applyTo(inputIds, hintId) -> loads the policy, sets each input's minlength and the hint's text
//
// Every text here is set with textContent.
(function () {
    'use strict';

    const FLOOR = 8;   // the server's floor; a stored minimum can only raise it

    function base() {
        return (typeof API_BASE === 'string' && API_BASE) ? API_BASE : '';
    }

    function normalise(pol) {
        const p = (pol && typeof pol === 'object') ? pol : {};
        const n = parseInt(p.min_length, 10);
        return {
            min_length: Math.max(FLOOR, isNaN(n) ? FLOOR : n),
            require_uppercase: p.require_uppercase === true,
            require_lowercase: p.require_lowercase === true,
            require_numbers: p.require_numbers === true,
            require_special: p.require_special === true,
        };
    }

    async function load() {
        try {
            const res = await fetch(`${base()}/auth/policy`, { headers: { Accept: 'application/json' } });
            if (!res.ok) return normalise(null);
            const body = await res.json();
            return normalise(body && body.password_policy);
        } catch (_) {
            return normalise(null);
        }
    }

    // "At least 12 characters, with an uppercase letter and a number."
    function describe(policy) {
        const p = normalise(policy);
        const extras = [];
        if (p.require_uppercase) extras.push('an uppercase letter');
        if (p.require_lowercase) extras.push('a lowercase letter');
        if (p.require_numbers) extras.push('a number');
        if (p.require_special) extras.push('a special character');
        let text = `At least ${p.min_length} characters`;
        if (extras.length) {
            const last = extras.pop();
            text += ', with ' + (extras.length ? extras.join(', ') + ' and ' + last : last);
        }
        return text + '.';
    }

    // The requirements `password` misses, worded as the server words them. The classes are Unicode, as
    // the server's are (an uppercase letter is any letter in uppercase, a number any decimal digit, a
    // special character anything that is neither a letter, a digit nor a space), so the form and the
    // server agree outside ASCII too.
    function failures(password, policy) {
        const p = normalise(policy);
        const pw = password || '';
        const out = [];
        if (pw.length < p.min_length) out.push(`be at least ${p.min_length} characters long`);
        if (p.require_uppercase && !/\p{Lu}/u.test(pw)) out.push('include an uppercase letter');
        if (p.require_lowercase && !/\p{Ll}/u.test(pw)) out.push('include a lowercase letter');
        if (p.require_numbers && !/\p{Nd}/u.test(pw)) out.push('include a number');
        if (p.require_special && !/[^\p{L}\p{N}\s]/u.test(pw)) out.push('include a special character');
        return out;
    }

    // Set the rule on a form: each input's minlength, and the hint's text. Returns the policy, so the form's
    // submit can check with the same one.
    async function applyTo(inputIds, hintId) {
        const policy = await load();
        (inputIds || []).forEach((id) => {
            const el = document.getElementById(id);
            if (el) el.setAttribute('minlength', String(policy.min_length));
        });
        const hint = hintId ? document.getElementById(hintId) : null;
        if (hint) hint.textContent = describe(policy);
        return policy;
    }

    window.PasswordPolicy = { load, describe, failures, applyTo, FLOOR };
})();
