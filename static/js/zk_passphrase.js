/**
 * What a new zero-knowledge passphrase must be.
 *
 * The passphrase is the one low-entropy secret in the zero-knowledge design. Its envelope (the account's
 * private key, sealed under it with PBKDF2-SHA256 at 600,000 iterations) is released to the account's own
 * sessions, so whoever can act as an account -- an administrator who reset its password, a stolen session --
 * can download it and guess offline, at thousands of guesses a second per GPU. A guessed passphrase makes
 * the guesser that member, and every zero-knowledge guarantee then holds for them. Length and not being a
 * common choice are the two things that raise the cost for everyone, with no change to any format.
 *
 * So a new or changed passphrase (and a recovery kit's) must be at least 12 characters, and must not be one
 * of the common choices below: a listed passphrase, a common word with only digits or symbols around it,
 * one character or a short run repeated, a run of the alphabet, the digits or a keyboard row, only digits
 * and symbols, or mostly the account's own name. A passphrase that was set before this rule still unlocks;
 * the app suggests changing it (see `weakForUnlock`).
 *
 * Pure and dependency-free, so the rule is tested off the browser (tests/js/zk_passphrase.js).
 */
'use strict';

const ZkPassphrase = (() => {
    const MIN_LENGTH = 12;

    // Common passphrases of 12 characters or more, compared lower-cased with everything but letters and
    // digits removed. Shorter ones fail the length rule anyway.
    const BLOCKED = new Set([
        'password1234', 'password12345', 'password123456', 'passw0rd1234', 'p4ssw0rd1234', 'passwordpassword',
        'mypassword123', 'password2023', 'password2024', 'password2025', 'password2026', 'secretpassword',
        'supersecret123', 'topsecret1234', 'passphrase123', 'mypassphrase1', 'passphrase1234',
        'qwertyuiop12', 'qwertyuiop123', 'qwerty123456', 'qwertyqwerty', 'qwerty12345678', 'asdfghjkl123',
        'zxcvbnm12345', '1q2w3e4r5t6y', '1qaz2wsx3edc', 'zaq12wsxcde3', 'qazwsxedcrfv', 'q1w2e3r4t5y6',
        '1234qwerasdf', 'qwer1234asdf', 'asdf1234qwer', '1234567890ab', 'abc123abc123', 'iloveyou1234',
        'iloveyouiloveyou', 'iloveyou2024', 'princess1234', 'football1234', 'baseball1234', 'basketball12',
        'soccer123456', 'hockey123456', 'sunshine1234', 'dragon123456', 'monkey123456', 'master123456',
        'superman1234', 'batman123456', 'starwars1234', 'whatever1234', 'trustno11234', 'trustno1trustno1',
        'welcome12345', 'welcome1234', 'letmein12345', 'letmeinplease', 'opensesame123', 'changeme1234',
        'changeme12345', 'default12345', 'administrator', 'administrator1', 'adminadmin123', 'rootroot1234',
        'testtest1234', 'test12345678', 'hello1234567', 'helloworld123', 'helloworld1234', 'lovelove1234',
        'michael12345', 'jennifer1234', 'charlie12345', 'computer1234', 'internet1234', 'chocolate123',
        'butterfly123', 'liverpool123', 'chelsea12345', 'arsenal12345', 'manchester12', 'newyork12345',
        'london123456', 'berlin123456', 'correcthorsebatterystaple', 'thequickbrownfox',
        'thequickbrownfoxjumpsoverthelazydog', 'encryptionkey', 'encryptionpassphrase', 'dockvault1234',
        'dockvault12345', 'dockvaultpassword', 'vaultpassword', 'myvaultpassword', 'zeroknowledge',
        'zeroknowledge1',
    ]);
    // Common words that, with nothing but digits or symbols around them, make a passphrase a common one.
    const COMMON_WORDS = new Set([
        'password', 'passwd', 'passphrase', 'secret', 'qwerty', 'qwertyuiop', 'asdfgh', 'iloveyou', 'letmein',
        'welcome', 'admin', 'administrator', 'changeme', 'default', 'dragon', 'monkey', 'master', 'football',
        'baseball', 'princess', 'sunshine', 'shadow', 'superman', 'batman', 'trustno', 'hello', 'helloworld',
        'dockvault', 'vault', 'encryption', 'test', 'login', 'user', 'root',
    ]);
    // Runs a keyboard, the alphabet and the digits make, both ways.
    const RUNS = [
        'abcdefghijklmnopqrstuvwxyz', '01234567890123456789', 'qwertyuiopasdfghjklzxcvbnm',
        '1qaz2wsx3edc4rfv5tgb6yhn7ujm8ik9ol0p', 'qazwsxedcrfvtgbyhnujmikolp', '1234567890qwertyuiop',
    ];

    function _normal(text) {
        return String(text || '').toLowerCase().replace(/[^a-z0-9]/g, '');
    }

    function _repeats(norm) {
        for (let unit = 1; unit <= 4; unit++) {
            if (norm.length >= unit * 3 && norm.length % unit === 0
                && norm.slice(0, unit).repeat(norm.length / unit) === norm) {
                return true;
            }
        }
        return false;
    }

    function _run(norm) {
        if (norm.length < 6) return false;
        return RUNS.some(r => r.includes(norm) || r.split('').reverse().join('').includes(norm));
    }

    /**
     * Why a NEW passphrase is not acceptable, as one sentence, or null when it is.
     * @param {string} pass
     * @param {{username?: string, email?: string}} [account]
     * @returns {string|null}
     */
    function problem(pass, account) {
        const text = String(pass || '');
        if (text.length < MIN_LENGTH) return `The passphrase must be at least ${MIN_LENGTH} characters.`;
        const norm = _normal(text);
        const letters = norm.replace(/[^a-z]/g, '');
        if (!letters) return 'Use words in the passphrase, not only digits and symbols.';
        // Read as written, and with the usual stand-ins read as the letters they stand for (p@ssw0rd).
        const common = candidate => {
            const core = candidate.replace(/[^a-z]/g, '');
            // A common word with only digits or symbols around it: its letters are that word, in one piece.
            return BLOCKED.has(candidate) || (COMMON_WORDS.has(core) && candidate.includes(core));
        };
        const standIns = _normal(text.toLowerCase().replace(/@/g, 'a').replace(/\$/g, 's').replace(/0/g, 'o'));
        if (common(norm) || common(standIns)) {
            return 'That passphrase is a common one, and would be among the first guessed. Choose another.';
        }
        if (_repeats(norm)) return 'The passphrase repeats itself. Choose one that does not.';
        if (_run(norm)) return 'The passphrase is a run of the keyboard, the alphabet or the digits. Choose another.';
        const acct = account || {};
        for (const name of [acct.username, String(acct.email || '').split('@')[0]]) {
            const n = _normal(name);
            if (n.length >= 3 && norm.includes(n) && norm.length - n.length < 8) {
                return 'The passphrase is mostly your account name. Choose another.';
            }
        }
        return null;
    }

    /**
     * Would this passphrase, which just unlocked the account's key, be refused as a new one? The app then
     * suggests changing it; it never stops the unlock.
     */
    function weakForUnlock(pass, account) {
        return problem(pass, account) !== null;
    }

    return { MIN_LENGTH, problem, weakForUnlock };
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ZkPassphrase;
}
