#!/usr/bin/env node
'use strict';

// Reading version-2 content straight from a byte stream.
//
// The interesting case is not that it works. It is the length: a stream does not carry its own
// size, so the framing has to come from what the transfer declares — in practice a
// Content-Length, which the server asserts. That looks like trusting the server and is not, and
// this file is where that claim gets tested rather than argued: the chunk count and plaintext
// total are derived from the length and authenticated, so a wrong length cannot yield a short
// file. It stops the read.
//
// WHERE it stops is not where it first seems. Those totals are bound into the FINAL record only --
// deliberately, since binding them into every record would force a writer to know the length
// before writing anything and foreclose a streaming producer. So a wrong length is caught at the
// end, after earlier records have already been handed out. The file is never accepted; the caller
// is left holding bytes it must discard.
//
// The stream is deliberately fed in pieces that do not line up with record boundaries, because a
// reader that only works when the producer chunks conveniently is a reader that works in tests.

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

// A body delivered in `piece` byte slices, so record boundaries and delivery boundaries disagree.
function streamOf(bytes, piece) {
    let at = 0;
    return new ReadableStream({
        pull(controller) {
            if (at >= bytes.length) { controller.close(); return; }
            const end = Math.min(at + piece, bytes.length);
            controller.enqueue(bytes.slice(at, end));
            at = end;
        },
    });
}

async function collect(lib, bytes, length, piece, dek) {
    const parts = [];
    const res = await lib.decryptStreamV2(
        streamOf(bytes, piece), length, dek, CTX, p => parts.push(p));
    const out = new Uint8Array(parts.reduce((a, p) => a + p.length, 0));
    let at = 0;
    for (const p of parts) { out.set(p, at); at += p.length; }
    return { out, res, chunks: parts.length };
}

async function main() {
    const lib = new ECCCryptoLibrary();
    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', hexToBytes('07'.repeat(32)), 'AES-GCM', true, ['encrypt', 'decrypt']);

    let failures = 0;
    const note = (ok, msg) => { if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); } };

    // Delivery sizes chosen to be awkward: smaller than a record, larger than a record, and a
    // prime that never aligns with one.
    for (const [name, size] of [['empty', 0], ['one chunk', CHUNK],
                                ['partial tail', CHUNK * 2 + 17]]) {
        const plain = Uint8Array.from({ length: size }, (_, i) => (i * 31 + 7) & 0xff);
        const enc = (await lib.encryptFileV2(plain, dek, CTX, { chunkSize: CHUNK })).bytes;
        const wanted = new Uint8Array(await lib.decryptFileV2(enc, dek, CTX));

        for (const piece of [7, 1000, CHUNK + 28, 65536]) {
            const { out, res } = await collect(lib, enc, enc.length, piece, dek);
            const same = out.length === wanted.length && out.every((v, i) => v === wanted[i]);
            note(same && res.totalPlaintext === size,
                `${name} delivered in ${piece}-byte pieces matches the buffered reader`);
        }
    }

    // The length claim. Each of these must stop the read rather than produce a short file.
    const body = Uint8Array.from({ length: CHUNK * 3 + 11 }, (_, i) => (i * 13) & 0xff);
    const good = (await lib.encryptFileV2(body, dek, CTX, { chunkSize: CHUNK })).bytes;

    for (const [name, claimed] of [
        ['a length one byte short', good.length - 1],
        ['a length one byte long', good.length + 1],
        ['a length a whole record short', good.length - (CHUNK + 28)],
        ['a length that halves the file', Math.floor(good.length / 2)],
    ]) {
        let wrote = 0;
        let resolved = false;
        let code = null;
        try {
            await lib.decryptStreamV2(streamOf(good, 1000), claimed, dek, CTX,
                p => { wrote += p.length; });
            resolved = true;
        } catch (e) { code = codeOf(e); }
        note(!resolved,
            resolved
                ? `${name} was accepted, producing ${wrote} bytes`
                : `${name} stopped the read with ${code} after ${wrote} byte(s)`);
    }

    // And a body that ends early against an honest length.
    let truncCode = null;
    try {
        await lib.decryptStreamV2(streamOf(good.slice(0, good.length - 50), 1000),
            good.length, dek, CTX, () => {});
    } catch (e) { truncCode = codeOf(e); }
    note(truncCode !== null, `a body that ends early is refused with ${truncCode}`);

    // A body with bytes beyond the declared length is equally not vouchable.
    const longer = new Uint8Array(good.length + 32);
    longer.set(good, 0);
    let trailCode = null;
    try {
        await lib.decryptStreamV2(streamOf(longer, 1000), good.length, dek, CTX, () => {});
    } catch (e) { trailCode = codeOf(e); }
    note(trailCode !== null, `a body longer than its declared length is refused with ${trailCode}`);

    // The same over-long body, delivered so that the extra bytes arrive in a SEPARATE piece.
    // With 1000-byte pieces above, the read that completes the last record over-reads past the
    // declared end and the surplus is caught in hand; here nothing is over-read, so the surplus
    // can only be found by draining the stream afterwards. Two different branches, and a test
    // that exercised one of them would have left the other unproven.
    let splitCode = null;
    const twoPieces = new ReadableStream({
        start(c) {
            c.enqueue(longer.slice(0, good.length));
            c.enqueue(longer.slice(good.length));
            c.close();
        },
    });
    try {
        await lib.decryptStreamV2(twoPieces, good.length, dek, CTX, () => {});
    } catch (e) { splitCode = codeOf(e); }
    note(splitCode !== null,
        `trailing bytes arriving after the declared end are refused with ${splitCode}`);

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('stream reads match the buffered reader, and a wrong length stops the read');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
