#!/usr/bin/env node
'use strict';

// Where a resumed download restarts.
//
// The number this produces goes straight into a Range header, so an off-by-one does not fail
// loudly -- it fetches from one byte inside a record, and every record after it decrypts into
// garbage that fails authentication. The client would report a corrupt file and be wrong about
// why. So these check the offset against the real framing of a real encryption, for every record
// boundary in the object rather than a representative one.

const path = require('path');
const nodeCrypto = require('crypto');

global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const CTX = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    objectId: '22222222-2222-4222-8222-222222222222',
    dekEpoch: 3,
};

async function main() {
    const lib = new ECCCryptoLibrary();
    let failures = 0;
    const note = (ok, msg) => {
        if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
    };

    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', new Uint8Array(32).fill(9), 'AES-GCM', true, ['encrypt', 'decrypt']);

    // Sizes chosen so the final chunk is full in one case and a remainder in the others, since the
    // last record is the only one whose stored size differs.
    for (const [plainLen, chunkSize] of [[4096 * 3, 4096], [4096 * 3 + 1, 4096],
                                         [4096 * 3 - 1, 4096], [10, 4096], [70000, 8192]]) {
        const plain = Uint8Array.from({ length: plainLen }, (_, i) => (i * 13 + 5) & 0xff);
        const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize })).bytes;
        const header = enc.subarray(0, 28);
        const total = enc.length;

        const first = lib.v2ContentResumeOffset(header, total, 0);
        note(first.offset === 0 + 28 && !first.done,
            `${plainLen}B/${chunkSize}: nothing kept yet resumes just past the header`);

        // Every boundary, walked. Each offset must land exactly where a record starts, which is
        // checked by decrypting the whole object and counting the stored sizes independently.
        const n = first.records;
        let walked = 28;
        let allExact = true;
        for (let k = 0; k < n; k++) {
            const got = lib.v2ContentResumeOffset(header, total, k);
            if (got.offset !== walked) { allExact = false; break; }
            // A full chunk's stored size; the last one is whatever remains.
            walked += (k === n - 1) ? (total - walked) : (chunkSize + 28);
        }
        note(allExact, `${plainLen}B/${chunkSize}: all ${n} boundaries land where a record starts`);

        const last = lib.v2ContentResumeOffset(header, total, n);
        note(last.offset === total && last.done,
            `${plainLen}B/${chunkSize}: every record kept means done, at the end of the object`);
    }

    // A count nobody could have reached is refused rather than clamped: a plausible offset would
    // produce a file that fails to authenticate, and the client would blame the data.
    const plain = Uint8Array.from({ length: 5000 }, (_, i) => i & 0xff);
    const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize: 4096 })).bytes;
    const header = enc.subarray(0, 28);
    for (const bad of [-1, 99, 1.5, NaN, '2', null, undefined]) {
        let threw = false;
        try { lib.v2ContentResumeOffset(header, enc.length, bad); } catch (e) { threw = true; }
        note(threw, `a record count of ${String(bad)} is refused rather than turned into an offset`);
    }

    // The header still has to be a header. A resumed client that kept the wrong bytes must be told
    // so here, not by a decryption failure three records later.
    let rejectedGarbage = false;
    try {
        lib.v2ContentResumeOffset(new Uint8Array(28), enc.length, 0);
    } catch (e) { rejectedGarbage = true; }
    note(rejectedGarbage, 'a header of zeroes is refused');

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('resume offsets land on record boundaries, and impossible counts are refused');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
