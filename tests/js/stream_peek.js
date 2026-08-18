#!/usr/bin/env node
'use strict';

// Peeking at a stream without spending it.
//
// The failure this guards against is silent and total: a replay that drops the bytes it looked at
// hands the reader a file starting mid-header, and one that emits them twice hands it a file with
// a duplicated prefix. Both authenticate as damage rather than as a bug in the plumbing, so the
// test compares the replayed bytes against the original in full rather than checking a length.
//
// The last case is the one that matters — a peeked stream fed to the real reader, end to end.

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

async function drain(stream) {
    const reader = stream.getReader();
    const parts = [];
    for (;;) {
        const r = await reader.read();
        if (r.done) { break; }
        parts.push(r.value);
    }
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

    const body = Uint8Array.from({ length: 5000 }, (_, i) => (i * 7 + 3) & 0xff);

    // Delivery sizes that put the peek boundary in different places: mid-piece, exactly on a
    // boundary, one byte either side, and a single piece holding everything.
    for (const piece of [1, 3, 7, 8, 9, 1000, 5000]) {
        const { head, stream } = await lib._peekStream(streamOf(body, piece), 8);
        const replayed = await drain(stream);
        const headOk = head.length === 8 && head.every((v, i) => v === body[i]);
        const wholeOk = replayed.length === body.length
            && replayed.every((v, i) => v === body[i]);
        note(headOk && wholeOk,
            `pieces of ${piece}: head is the first 8 bytes, and the replay is the whole body ` +
            `(${replayed.length} of ${body.length})`);
    }

    // A body shorter than the peek. The head is short rather than padded, which is the answer for
    // anything too small to carry a header.
    const tiny = Uint8Array.from([1, 2, 3]);
    const { head: shortHead, stream: shortStream } = await lib._peekStream(streamOf(tiny, 2), 8);
    const shortReplay = await drain(shortStream);
    note(shortHead.length === 3 && shortReplay.length === 3,
        `a 3-byte body peeked for 8 gives a 3-byte head and replays 3 bytes`);

    // An empty body.
    const { head: emptyHead, stream: emptyStream } = await lib._peekStream(streamOf(new Uint8Array(0), 4), 8);
    note(emptyHead.length === 0 && (await drain(emptyStream)).length === 0,
        'an empty body peeks to nothing and replays nothing');

    // The point of the exercise: peek, choose, then hand the same stream to the reader.
    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', new Uint8Array(32).fill(7), 'AES-GCM', true, ['encrypt', 'decrypt']);
    const plain = Uint8Array.from({ length: 4096 * 2 + 5 }, (_, i) => (i * 11) & 0xff);
    const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize: 4096 })).bytes;

    const { head: encHead, stream: encStream } = await lib._peekStream(streamOf(enc, 333), 8);
    const recognised = lib._inspectV2Header(encHead);
    const parts = [];
    await lib.decryptStreamV2(encStream, enc.length, dek, CTX, p => parts.push(p));
    const back = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let at = 0;
    for (const p of parts) { back.set(p, at); at += p.length; }
    note(recognised === 'UNSUPPORTED' && back.length === plain.length
         && back.every((v, i) => v === plain[i]),
        `a peeked stream is recognised as ${recognised} and still decrypts to the original`);

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('peeking costs nothing: the head is read and the stream is still whole');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
