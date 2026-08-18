#!/usr/bin/env node
'use strict';

// A dropped connection and a bad file must not look alike.
//
// This exists because they did. The reader funnels every failure through one catch that gives it a
// crypto code, so a connection reset arrived as CONTENT_AUTH_FAILED -- indistinguishable from
// "these bytes do not authenticate". A caller deciding whether to resume needs the opposite of
// that: retry a dropped body, never retry a failed authentication, because re-requesting the same
// range returns the same bytes and fails identically.
//
// The consequence of getting it wrong was not a wrong error message. It made an entire resume
// loop unreachable: the condition that gated it could never be true, so a transient drop aborted
// a download that had already written bytes, leaving the user a partial file.

const path = require('path');
const nodeCrypto = require('crypto');

global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const CTX = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    objectId: '22222222-2222-4222-8222-222222222222',
    dekEpoch: 3,
};

/** A body that delivers `upTo` bytes and then fails the way a reset connection does. */
function failingStream(bytes, upTo) {
    let at = 0;
    return new ReadableStream({
        pull(c) {
            if (at >= upTo) {
                c.error(new TypeError('network error'));
                return;
            }
            const end = Math.min(at + 4096, upTo);
            c.enqueue(bytes.slice(at, end));
            at = end;
        },
    });
}

/** A body that simply stops early, cleanly. */
function shortStream(bytes, upTo) {
    let at = 0;
    return new ReadableStream({
        pull(c) {
            if (at >= upTo) { c.close(); return; }
            const end = Math.min(at + 4096, upTo);
            c.enqueue(bytes.slice(at, end));
            at = end;
        },
    });
}

/** What a caller sees: is this coded (content) or uncoded (transport)? */
function classify(err) {
    if (err && err.isCryptoError === true && err.code) return { kind: 'content', code: err.code };
    if (err && err.isTransportError === true) return { kind: 'transport' };
    return { kind: 'unknown', name: err && err.name };
}

async function main() {
    const lib = new ECCCryptoLibrary();
    let failures = 0;
    const note = (ok, msg) => {
        if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
    };

    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', new Uint8Array(32).fill(6), 'AES-GCM', true, ['encrypt', 'decrypt']);
    const plain = Uint8Array.from({ length: 40000 }, (_, i) => (i * 7) & 0xff);
    const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize: 4096 })).bytes;

    // 1. The body fails mid-read. This is the case the resume loop exists for.
    let caught = null;
    try {
        await lib.decryptStreamV2(failingStream(enc, 12000), enc.length, dek, CTX, () => {});
    } catch (e) { caught = e; }
    const dropped = classify(caught);
    note(dropped.kind === 'transport',
        `a body that fails mid-read reports as transport (got ${JSON.stringify(dropped)})`);

    // 2. The bytes are wrong. This must NOT look resumable: the same range would fail again.
    const tampered = enc.slice();
    tampered[tampered.length - 20] ^= 0xff;
    caught = null;
    try {
        await lib.decryptStreamV2(shortStream(tampered, tampered.length), tampered.length,
                                  dek, CTX, () => {});
    } catch (e) { caught = e; }
    const corrupt = classify(caught);
    note(corrupt.kind === 'content' && corrupt.code === 'CONTENT_AUTH_FAILED',
        `damaged content reports as content/CONTENT_AUTH_FAILED (got ${JSON.stringify(corrupt)})`);

    // 3. The two must be distinguishable BY THE TEST A CALLER ACTUALLY MAKES. Asserting each in
    //    isolation would not catch a change that made both the same.
    note(dropped.kind !== corrupt.kind,
        'a dropped body and damaged content are told apart, which is what makes resume reachable');

    // 4. A wrong key is content, not transport -- retrying it forever would be the spin the rule
    //    exists to prevent.
    const otherDek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', new Uint8Array(32).fill(9), 'AES-GCM', true, ['encrypt', 'decrypt']);
    caught = null;
    try {
        await lib.decryptStreamV2(shortStream(enc, enc.length), enc.length, otherDek, CTX,
                                  () => {});
    } catch (e) { caught = e; }
    note(classify(caught).kind === 'content',
        `the wrong key reports as content (got ${JSON.stringify(classify(caught))})`);

    // 5. A body that stops early and cleanly stays content: a short object is damage, not a drop,
    //    and resuming it would ask the server for bytes it has already said do not exist.
    caught = null;
    try {
        await lib.decryptStreamV2(shortStream(enc, 12000), enc.length, dek, CTX, () => {});
    } catch (e) { caught = e; }
    note(classify(caught).kind === 'content',
        `a cleanly truncated body stays content (got ${JSON.stringify(classify(caught))})`);

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('a dropped connection and a bad file are distinguishable');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
