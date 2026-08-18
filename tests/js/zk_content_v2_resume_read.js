#!/usr/bin/env node
'use strict';

// Resuming a download, at every place it could have been interrupted.
//
// A resumed read is only sound because each record authenticates on its own and its AAD is bound
// to the record INDEX -- so record k verifies without records 0..k-1 ever being seen. If that ever
// stopped being true, resuming would still appear to work for k = 0 and fail for every other k,
// which is why this walks all of them instead of picking one.
//
// The check that matters most is the last one: a resumed reader must still refuse a file whose
// final record does not match the totals, because that record is where the size is bound.

const path = require('path');
const nodeCrypto = require('crypto');

global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const CTX = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    objectId: '22222222-2222-4222-8222-222222222222',
    dekEpoch: 3,
};

function streamOf(bytes, piece) {
    let at = 0;
    return new ReadableStream({
        pull(c) {
            if (at >= bytes.length) { c.close(); return; }
            const end = Math.min(at + piece, bytes.length);
            c.enqueue(bytes.slice(at, end));
            at = end;
        },
    });
}

// Refusals are checked by CODE, not by "something threw". An incidental TypeError also throws,
// and a test that accepts it cannot tell a deliberate refusal from a crash -- which is exactly
// what happened here: deleting the "resume needs the kept header" guard left the header undefined,
// the framing threw, and a looser version of this file called that a pass.
async function refuses(label, code, fn) {
    let err = null;
    try { await fn(); } catch (e) { err = e; }
    if (!err) { return { ok: false, why: 'it was accepted' }; }
    if (err.code !== code) { return { ok: false, why: `code was ${err.code}, wanted ${code}` }; }
    return { ok: true, why: '' };
}

function joined(parts) {
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return out;
}

async function main() {
    const lib = new ECCCryptoLibrary();
    let failures = 0;
    const note = (ok, msg) => {
        if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
    };

    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', new Uint8Array(32).fill(4), 'AES-GCM', true, ['encrypt', 'decrypt']);

    const CHUNK = 4096;
    const H = 28;
    const S = CHUNK + 28;                       // a full record's stored size

    for (const plainLen of [CHUNK * 4, CHUNK * 4 + 17, CHUNK - 1]) {
        const plain = Uint8Array.from({ length: plainLen }, (_, i) => (i * 29 + 3) & 0xff);
        const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize: CHUNK })).bytes;
        const header = enc.slice(0, H);
        const n = Math.max(1, Math.ceil((enc.length - H) / S));

        let everyBoundaryWhole = true;
        for (let k = 0; k <= n; k++) {
            // k = 0 is not a resume: a client with nothing kept re-requests the whole object,
            // header included, and takes the ordinary path. Sending it down the resume path would
            // hand the reader a stream whose first bytes are a record and ask it to read a header.
            const offset = k === 0 ? 0 : (k >= n ? enc.length : H + k * S);
            const opts = k === 0 ? undefined : { startRecord: k, header };
            const parts = [];
            await lib.decryptStreamV2(
                streamOf(enc.slice(offset), 777), enc.length, dek, CTX,
                p => parts.push(p), opts);
            const got = joined(parts);
            // What a resumed reader produces is the tail; the client already holds the head.
            const expected = plain.slice(Math.min(k * CHUNK, plain.length));
            if (got.length !== expected.length || !got.every((v, i) => v === expected[i])) {
                everyBoundaryWhole = false;
                console.error(`     boundary ${k}: got ${got.length}, expected ${expected.length}`);
                break;
            }
        }
        note(everyBoundaryWhole,
            `${plainLen}B: resuming at each of ${n + 1} boundaries yields exactly the remaining bytes`);

        // Head plus resumed tail is the original, which is what the caller actually assembles.
        const cut = Math.min(1, n - 1) >= 0 ? 1 : 0;
        if (n > 1) {
            const head = [];
            await lib.decryptStreamV2(streamOf(enc, 999), enc.length, dek, CTX, p => head.push(p));
            const tail = [];
            await lib.decryptStreamV2(
                streamOf(enc.slice(H + cut * S), 512), enc.length, dek, CTX,
                p => tail.push(p), { startRecord: cut, header });
            const rebuilt = joined([joined(head).slice(0, cut * CHUNK), joined(tail)]);
            note(rebuilt.length === plain.length && rebuilt.every((v, i) => v === plain[i]),
                `${plainLen}B: the kept head and the resumed tail reassemble into the original`);
        }
    }

    // Starting beyond the end is refused rather than treated as "already finished".
    const plain = Uint8Array.from({ length: 5000 }, (_, i) => i & 0xff);
    const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize: CHUNK })).bytes;
    const header = enc.slice(0, H);
    let r = await refuses('too far', 'INVALID_INPUT', () =>
        lib.decryptStreamV2(streamOf(new Uint8Array(0), 8), enc.length, dek, CTX,
                            () => {}, { startRecord: 99, header }));
    note(r.ok, 'a start beyond the last record is refused ' + r.why);

    // Resuming without the header it cannot read from the stream.
    r = await refuses('no header', 'INVALID_INPUT', () =>
        lib.decryptStreamV2(streamOf(enc.slice(H + S), 512), enc.length, dek, CTX,
                            () => {}, { startRecord: 1 }));
    note(r.ok, 'resuming without the kept header is refused rather than guessed ' + r.why);

    // A header from a DIFFERENT object must not open this one, even at a valid boundary.
    const other = (await lib.encryptFileV2(plain, dek,
        { ...CTX, objectId: '33333333-3333-4333-8333-333333333333' },
        { chunkSize: CHUNK })).bytes;
    r = await refuses('foreign header', 'CONTENT_AUTH_FAILED', () =>
        lib.decryptStreamV2(streamOf(enc.slice(H + S), 512), enc.length, dek, CTX,
                            () => {}, { startRecord: 1, header: other.slice(0, H) }));
    note(r.ok, "another object's header does not open this one " + r.why);

    // The totals live in the final record, so a resumed read is still checked against them.
    const truncated = enc.slice(0, enc.length - 1);
    r = await refuses('truncated', 'CONTENT_INVALID', () =>
        lib.decryptStreamV2(streamOf(truncated.slice(H + S), 512), enc.length, dek, CTX,
                            () => {}, { startRecord: 1, header }));
    note(r.ok, 'a resumed read still refuses a body short of the declared length ' + r.why);

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('resuming reads the remaining records and refuses what a whole read would refuse');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
