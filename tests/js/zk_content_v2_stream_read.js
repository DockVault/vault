#!/usr/bin/env node
'use strict';

// Reading a version-2 file without holding it, and refusing to finish when it is damaged.
//
// Two properties, and the second is the one worth the trouble. The streaming reader must produce
// exactly what the buffered reader produces -- otherwise the cheap path is a different reader
// wearing the same name. And it must NOT resolve when the file is damaged, because the buffered
// reader's contract is that nothing is handed over until the final record authenticates. A
// streaming reader keeps that only if its caller can still throw away what it wrote, so what is
// pinned here is that failure reaches the caller AS a failure, with the damage located.
//
// The chunks it wrote before failing are deliberately NOT asserted to be empty: it streams, so of
// course it wrote some. The point is that it never claims success.

const path = require('path');
const nodeCrypto = require('crypto');

global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const CHUNK = 4096;
const CTX = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    objectId: '22222222-2222-4222-8222-222222222222',
    dekEpoch: 3,
};

function hexToBytes(hex) { return new Uint8Array(Buffer.from(hex, 'hex')); }
function codeOf(e) { return (e && e.code) || (e && e.name) || String(e); }

async function main() {
    const lib = new ECCCryptoLibrary();
    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', hexToBytes('07'.repeat(32)), 'AES-GCM', true, ['encrypt', 'decrypt']);

    const cases = [
        ['empty', 0],
        ['short of one chunk', CHUNK - 1],
        ['exactly one chunk', CHUNK],
        ['exactly two chunks', CHUNK * 2],
        ['partial tail', CHUNK * 2 + 17],
    ];

    let failures = 0;
    let biggestChunkSeen = 0;

    for (const [name, size] of cases) {
        const plain = Uint8Array.from({ length: size }, (_, i) => (i * 31 + 7) & 0xff);
        const enc = await lib.encryptFileV2(plain, dek, CTX, { chunkSize: CHUNK });
        const stored = new Blob([enc.bytes]);

        // What the buffered reader says, for comparison.
        const wanted = new Uint8Array(await lib.decryptFileV2(enc.bytes, dek, CTX));

        const pieces = [];
        const res = await lib.decryptBlobV2(stored, dek, CTX, p => {
            biggestChunkSeen = Math.max(biggestChunkSeen, p.length);
            pieces.push(p);
        });

        const got = new Uint8Array(pieces.reduce((a, p) => a + p.length, 0));
        let at = 0;
        for (const p of pieces) { got.set(p, at); at += p.length; }

        const problems = [];
        if (res.totalPlaintext !== size) {
            problems.push(`reported ${res.totalPlaintext} bytes, file holds ${size}`);
        }
        if (got.length !== wanted.length) {
            problems.push(`streamed ${got.length} bytes, buffered reader gave ${wanted.length}`);
        } else {
            const d = got.findIndex((v, i) => v !== wanted[i]);
            if (d !== -1) { problems.push(`differs from the buffered reader at offset ${d}`); }
        }
        if (problems.length) {
            failures += 1;
            console.error(`FAIL ${name}: ${problems.join('; ')}`);
        } else {
            console.log(`ok   ${name} (${size} bytes) in ${pieces.length} chunk(s), ` +
                `matches the buffered reader`);
        }
    }

    // Nothing larger than one chunk should ever reach the sink.
    if (biggestChunkSeen > CHUNK) {
        failures += 1;
        console.error(`FAIL a chunk of ${biggestChunkSeen} bytes reached the sink, ` +
            `above the ${CHUNK}-byte frame`);
    } else {
        console.log(`ok   no chunk above ${CHUNK} bytes reached the sink (largest ${biggestChunkSeen})`);
    }

    // Damage. Each of these must reach the caller as a failure rather than as a short file.
    const body = Uint8Array.from({ length: CHUNK * 2 + 17 }, (_, i) => (i * 13) & 0xff);
    const good = (await lib.encryptFileV2(body, dek, CTX, { chunkSize: CHUNK })).bytes;

    const damaged = [
        ['a truncated file', good.slice(0, good.length - 40)],
        ['a flipped bit in the final record', (() => {
            const c = good.slice(); c[c.length - 5] ^= 0x01; return c;
        })()],
        ['a flipped bit in the first record', (() => {
            const c = good.slice(); c[40] ^= 0x01; return c;
        })()],
        ['a relabelled header', (() => {
            const c = good.slice(); c[5] = 0x09; return c;   // a different purpose byte
        })()],
    ];

    for (const [name, bytes] of damaged) {
        let wrote = 0;
        let resolved = false;
        let code = null;
        try {
            await lib.decryptBlobV2(new Blob([bytes]), dek, CTX, p => { wrote += p.length; });
            resolved = true;
        } catch (e) {
            code = codeOf(e);
        }
        if (resolved) {
            failures += 1;
            console.error(`FAIL ${name}: reported success after writing ${wrote} bytes`);
        } else {
            console.log(`ok   ${name}: refused with ${code} after writing ${wrote} byte(s)`);
        }
    }

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('streamed output matches the buffered reader, and damage never resolves');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
