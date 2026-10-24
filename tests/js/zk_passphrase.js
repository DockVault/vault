#!/usr/bin/env node
'use strict';

// The rule for a new zero-knowledge passphrase (static/js/zk_passphrase.js). Each line printed is one case;
// the Python side reads them.

const path = require('path');
const P = require(path.resolve(__dirname, '../../static/js/zk_passphrase.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.log('FAIL ' + msg); }
};
const refused = (pass, account) => P.problem(pass, account) !== null;

note(P.MIN_LENGTH === 12, 'the minimum is 12 characters');
note(refused('a-1-b-2-c-3'), 'eleven characters are refused');
note(!refused('amber-kettle-9'), 'twelve or more characters of words are accepted');
note(P.problem('short') === 'The passphrase must be at least 12 characters.', 'the length sentence');
for (const p of ['password1234', 'Password1234!', 'P@ssw0rd1234', 'qwertyuiop12', 'correct horse battery staple',
                 'iloveyou1234', 'Administrator', 'changeme1234']) {
    note(refused(p), `a listed passphrase is refused: ${p}`);
}
for (const p of ['password-2027-!!', '2027password!!', '!!!dockvault!!!', 'SECRET-00000000']) {
    note(refused(p), `a common word with only digits or symbols around it is refused: ${p}`);
}
note(refused('123456789012345'), 'only digits are refused');
note(refused('!@#$%^&*()_+-='), 'only symbols are refused');
note(refused('aaaaaaaaaaaaaa'), 'one character repeated is refused');
note(refused('abcabcabcabc'), 'a short run repeated is refused');
note(refused('abcdefghijklm'), 'a run of the alphabet is refused');
note(refused('zyxwvutsrqpon'), 'a run of the alphabet backwards is refused');
note(refused('qwertyuiopas'), 'a run of a keyboard row is refused');
note(refused('1qaz2wsx3edc4rfv'), 'a run down the keyboard is refused');
note(refused('maria.garcia-1', { username: 'maria.garcia' }), 'mostly the account name is refused');
note(refused('mgarcia-2027', { email: 'mgarcia@example.com' }), 'mostly the email name is refused');
note(!refused('maria.garcia climbs every tuesday', { username: 'maria.garcia' }),
     'the account name inside a longer passphrase is accepted');
for (const p of ['passphrase-A-123', 'zk-cancel-pass-1', 'correct-zk-pass-123', 'tangerine kettle orbit',
                 'Blue-Heron-Paddles-42', 'rotate-pass-A-123']) {
    note(!refused(p), `an ordinary passphrase is accepted: ${p}`);
}
note(P.weakForUnlock('hunter22') === true, 'an old short passphrase is suggested for a change at unlock');
note(P.weakForUnlock('amber-kettle-9') === false, 'a good one is not');

console.log(failures ? `${failures} FAILED` : 'ALL OK');
process.exit(failures ? 1 : 0);
