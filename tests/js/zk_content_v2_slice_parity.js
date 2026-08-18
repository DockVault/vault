#!/usr/bin/env node
'use strict';

// The sliced writer must emit exactly what the buffered one emits.
//
// Both produce version-2 content. One is handed the whole plaintext; the other reads it a slice at
// a time so the heap never holds the file. If those two ever disagree by a byte, the cheaper path
// writes files only it can open, and nothing at runtime says so until somebody downloads one.
//
// Entropy is stubbed per instance, the same way the sibling writer harness does it, so both
// writers see identical values for the same input -- which is what makes comparing their output a
// statement about framing rather than about two random streams. Draining is checked too: a writer
// that asks for one nonce too few has produced a file with a chunk missing.
//
// Sizes cover the framing edges the grammar cares about: empty, short of a chunk, exactly one,
// exactly two, and a partial tail.

const path = require('path');
const nodeCrypto = require('crypto');

global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const CHUNK = 4096;                    // the smallest the grammar allows, so the cases stay quick
const DEK_HEX = '07'.repeat(32);
const BLOB_ID_HEX = '0102030405060708090a0b0c0d0e0f10';
const CTX = {
    vaultId: '11111111-1111-4111-8111-111111111111',
    objectId: '22222222-2222-4222-8222-222222222222',
    dekEpoch: 3,
};

function hexToBytes(hex) {
    return new Uint8Array(Buffer.from(hex, 'hex'));
}

function nonceFor(i) {
    return Uint8Array.from({ length: 12 }, (_, k) => ((i + 1) * 16 + k) & 0xff);
}

function freshLib() {
    const lib = new ECCCryptoLibrary();
    let nonceAt = 0;
    lib._randomBytes = (n) => {
        if (n === 16) { return hexToBytes(BLOB_ID_HEX); }
        if (n === 12) { return nonceFor(nonceAt++); }
        throw new Error('unexpected entropy request of ' + n + ' bytes');
    };
    return { lib, used: () => nonceAt };
}

async function main() {
    const cases = [
        ['empty', 0],
        ['short of one chunk', CHUNK - 1],
        ['exactly one chunk', CHUNK],
        ['exactly two chunks', CHUNK * 2],
        ['partial tail', CHUNK * 2 + 17],
    ];

    // An AES-GCM CryptoKey, not raw bytes: the derivation refuses anything else, and it checks
    // the algorithm before the length because an HMAC key exports 32 bytes just as happily.
    const dek = await nodeCrypto.webcrypto.subtle.importKey(
        'raw', hexToBytes(DEK_HEX), 'AES-GCM', true, ['encrypt', 'decrypt']);
    let failures = 0;

    for (const [name, size] of cases) {
        const plain = Uint8Array.from({ length: size }, (_, i) => (i * 31 + 7) & 0xff);

        const a = freshLib();
        const buffered = await a.lib.encryptFileV2(plain, dek, CTX, { chunkSize: CHUNK });

        const b = freshLib();
        const sliced = await b.lib.encryptBlobV2(new Blob([plain]), dek, CTX, { chunkSize: CHUNK });
        const slicedBytes = new Uint8Array(await sliced.blob.arrayBuffer());

        const problems = [];
        if (buffered.blobId !== sliced.blobId) { problems.push('blob ids differ'); }
        if (a.used() !== b.used()) {
            problems.push(`nonce counts differ: buffered ${a.used()}, sliced ${b.used()}`);
        }
        if (buffered.bytes.length !== slicedBytes.length) {
            problems.push(`lengths differ: ${buffered.bytes.length} vs ${slicedBytes.length}`);
        } else {
            const at = buffered.bytes.findIndex((v, i) => v !== slicedBytes[i]);
            if (at !== -1) { problems.push(`bytes differ at offset ${at}`); }
        }

        // Parity alone would be satisfied by two writers being identically wrong, so the sliced
        // output also has to read back. Caught rather than thrown: a refusal here is this case
        // failing, and it should say which case and why instead of ending the run with a stack.
        try {
            const round = await b.lib.decryptFileV2(slicedBytes, dek, CTX);
            const back = round instanceof Uint8Array ? round : new Uint8Array(round);
            if (back.length !== plain.length || back.some((v, i) => v !== plain[i])) {
                problems.push('the sliced output did not decrypt back to the input');
            }
        } catch (e) {
            problems.push(`the sliced output would not decrypt: ${(e && e.code) || e}`);
        }

        if (problems.length) {
            failures += 1;
            console.error(`FAIL ${name} (${size} bytes): ${problems.join('; ')}`);
        } else {
            console.log(`ok   ${name} (${size} bytes) -> ${slicedBytes.length} bytes identical, ` +
                `${b.used()} nonce(s), decrypts back`);
        }
    }

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('every case byte-identical to the buffered writer');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
