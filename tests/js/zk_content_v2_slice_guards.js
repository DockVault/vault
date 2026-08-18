#!/usr/bin/env node
'use strict';

// What the sliced writer must REFUSE, and what it must report when it does.
//
// The parity harness beside this one compares the two writers. That is a differential test, and a
// differential test cannot see a defect in code they share: hoist the nonce out of the shared loop
// and both writers reuse it identically, so parity stays green. The shared loop is covered by the
// pinned vectors through the buffered writer; THIS file covers the part the sliced writer does not
// share -- its own guard, and its registration with the error boundary.
//
// Both were wrong when first written, which is why they are pinned here rather than trusted.

const path = require('path');
const nodeCrypto = require('crypto');

global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const CTX = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    objectId: '22222222-2222-4222-8222-222222222222',
    dekEpoch: 3,
};

async function dek() {
    return nodeCrypto.webcrypto.subtle.importKey(
        'raw', new Uint8Array(32).fill(7), 'AES-GCM', true, ['encrypt', 'decrypt']);
}

function codeOf(e) { return (e && e.code) || (e && e.name) || String(e); }

async function refuses(lib, key, input, label, results) {
    try {
        await lib.encryptBlobV2(input, key, CTX);
        results.push(`FAIL ${label}: accepted, and should not have`);
    } catch (e) {
        results.push(`ok   ${label}: refused with ${codeOf(e)}`);
    }
}

async function main() {
    const key = await dek();
    const results = [];
    let failures = 0;

    const lib = new ECCCryptoLibrary();

    // Things that are not a Blob at all. A string is the interesting one: "abc".slice IS a
    // function, so only the size check rejects it.
    for (const [label, value] of [
        ['a Uint8Array', new Uint8Array(4)],
        ['an ArrayBuffer', new ArrayBuffer(4)],
        ['a DataView', new DataView(new ArrayBuffer(4))],
        ['a string', 'abc'],
        ['null', null],
    ]) {
        await refuses(lib, key, value, label, results);
    }

    // A real Blob that lies about its size. NaN is the only value that makes the chunk count NaN,
    // so the loop never runs and the length check inside it never fires -- the writer would return
    // a valid id for a header-only file nobody can ever open.
    class LyingBlob extends Blob { get size() { return NaN; } }
    await refuses(lib, key, new LyingBlob([new Uint8Array(10)]), 'a Blob whose size is NaN',
        results);
    class FractionalBlob extends Blob { get size() { return 100.5; } }
    await refuses(lib, key, new FractionalBlob([new Uint8Array(10)]), 'a Blob with a fractional size',
        results);
    class NegativeBlob extends Blob { get size() { return -5; } }
    await refuses(lib, key, new NegativeBlob([new Uint8Array(10)]), 'a Blob with a negative size',
        results);

    // Registered with the error boundary. Without the table entry the codes are still right, but
    // the module's single diagnostic hook never fires -- a failed upload that the other writer
    // reported now reports nothing. The repo already had this exact omission once.
    let diagCalls = 0;
    const spied = new ECCCryptoLibrary();
    spied._diag = () => { diagCalls += 1; };
    try {
        await spied.encryptBlobV2(new Blob([new Uint8Array(4)]), key, {});
    } catch (e) { /* the refusal is the point; the diagnostic is what is being counted */ }
    if (diagCalls === 0) {
        results.push('FAIL the writer is not registered with the error boundary: _diag never fired');
    } else {
        results.push(`ok   registered with the error boundary: _diag fired ${diagCalls} time(s)`);
    }

    // The shipped call passes no options at all, so the default chunk size is the only one
    // production ever uses -- and nothing else exercises it.
    const big = new Uint8Array(3 * 1024 * 1024).fill(9);
    const out = await spied.encryptBlobV2(new Blob([big]), key, CTX);
    const bytes = new Uint8Array(await out.blob.arrayBuffer());
    // The reader hands back an ArrayBuffer, not a view, so compare through one.
    const back = new Uint8Array(await spied.decryptFileV2(bytes, key, CTX));
    const same = back.length === big.length && back.every((v, i) => v === big[i]);
    if (!same) {
        results.push('FAIL at the default chunk size the file did not round-trip');
    } else {
        results.push(`ok   default chunk size round-trips (${big.length} bytes in, ` +
            `${bytes.length} stored)`);
    }

    for (const line of results) {
        if (line.startsWith('FAIL')) { failures += 1; console.error(line); } else { console.log(line); }
    }
    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('every refusal reported, boundary registered, default chunk size exercised');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
