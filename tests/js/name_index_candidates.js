#!/usr/bin/env node
'use strict';

// The candidate set a zero-knowledge upload matches its name against.
//
// The index is keyed per (DEK, epoch). After a forward-only rekey an existing file's stored index
// sits at an old epoch, and an upload that computes only the current epoch's index misses it -- the
// clash the server's replace/reject guard needs to see. `nameBlindIndexCandidates` produces the
// union across every epoch the caller can still unwrap a DEK for, so the server finds the old row.
//
// What this pins:
//  - each candidate equals the single-value nameBlindIndex at its epoch (so the server, which
//    stores one value per row, matches against a set the row's own value is guaranteed to be in);
//  - different epochs give different candidates (there is something to fix), and the set covers
//    all of them, not just adjacent ones;
//  - identical (dek, epoch) inputs collapse, so a duplicated epoch does not pad the list;
//  - the common never-rotated vault yields exactly one candidate;
//  - a name that differs produces a disjoint set (it is keyed by the name, not just the epoch).
//
// Own console + exit code for pass/fail: a sibling harness stubs console to silence the library,
// and a sentinel test that inherited that stub would pass vacuously.

const path = require('path');
const nodeCrypto = require('crypto');

// nameBlindIndex reads window.crypto.subtle; provide it before requiring the library.
global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
};

const subtle = nodeCrypto.webcrypto.subtle;
const mkDek = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);

const VID = 'aaaaaaaa-1111-4222-8333-444444444444';

async function main() {
    const lib = new ECCCryptoLibrary();
    const dek1 = await mkDek();
    const dek2 = await mkDek();
    const dek3 = await mkDek();
    const name = 'quarterly-report.xlsx';

    // Each candidate equals the single-value index at its epoch -- the property the server relies on.
    {
        const cands = await lib.nameBlindIndexCandidates(name, VID, [
            { epoch: 1, dek: dek1 }, { epoch: 2, dek: dek2 },
        ]);
        const bi1 = await lib.nameBlindIndex(name, dek1, VID, 1);
        const bi2 = await lib.nameBlindIndex(name, dek2, VID, 2);
        note(cands.length === 2, `two epochs -> two candidates (got ${cands.length})`);
        note(cands.includes(bi1) && cands.includes(bi2),
             'candidates are exactly the per-epoch single-value indices');
        note(bi1 !== bi2, 'the two epochs really do differ (there is something to fix)');
    }

    // A vault rotated twice: an upload at epoch 3 must still cover a file sealed at epoch 1, not
    // just the adjacent epoch 2.
    {
        const cands = await lib.nameBlindIndexCandidates(name, VID, [
            { epoch: 1, dek: dek1 }, { epoch: 2, dek: dek2 }, { epoch: 3, dek: dek3 },
        ]);
        const bi1 = await lib.nameBlindIndex(name, dek1, VID, 1);
        note(cands.length === 3 && cands.includes(bi1),
             'a three-epoch vault covers the oldest epoch, not only the adjacent one');
    }

    // The common case: never rotated -> exactly one candidate, so this costs one HMAC there.
    {
        const cands = await lib.nameBlindIndexCandidates(name, VID, [{ epoch: 1, dek: dek1 }]);
        const bi1 = await lib.nameBlindIndex(name, dek1, VID, 1);
        note(cands.length === 1 && cands[0] === bi1, 'a never-rotated vault yields one candidate');
    }

    // A repeated (dek, epoch) must not pad the list: same input, same index, de-duplicated.
    {
        const cands = await lib.nameBlindIndexCandidates(name, VID, [
            { epoch: 1, dek: dek1 }, { epoch: 1, dek: dek1 },
        ]);
        note(cands.length === 1, `a duplicated epoch collapses (got ${cands.length})`);
    }

    // Keyed by the NAME, not just the epoch: a different name shares no candidate.
    {
        const a = await lib.nameBlindIndexCandidates('a.txt', VID, [{ epoch: 1, dek: dek1 }]);
        const b = await lib.nameBlindIndexCandidates('b.txt', VID, [{ epoch: 1, dek: dek1 }]);
        note(a[0] !== b[0], 'different names give disjoint candidates');
    }

    // Empty or malformed input is refused rather than silently producing an empty match set --
    // an empty candidate list would make every same-name check pass "no clash" and reopen the bug.
    for (const bad of [null, undefined, []]) {
        let threw = false;
        try { await lib.nameBlindIndexCandidates(name, VID, bad); } catch (_) { threw = true; }
        note(threw, `empty/absent epochDeks is refused (${JSON.stringify(bad)})`);
    }
    {
        let threw = false;
        try {
            await lib.nameBlindIndexCandidates(name, VID, [{ epoch: 1, dek: null }]);
        } catch (_) { threw = true; }
        note(threw, 'a null dek in an entry is refused, not skipped');
    }

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('candidate derivation is per-epoch, deduped, name-keyed, and fails closed on empty');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
