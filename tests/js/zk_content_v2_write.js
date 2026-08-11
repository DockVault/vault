#!/usr/bin/env node
'use strict';

// Drive the REAL shipped browser WRITER over the content-v2 vectors, under Node's WebCrypto.
//
// Its companion harness proves the module can read bytes an independent Python implementation
// wrote. This one proves the reverse and it is the stricter direction: given the same attempt
// token and the same nonces, the module must reproduce those vectors BYTE FOR BYTE. A reader can
// be lenient and still look correct; a writer that emits a field in the wrong order produces
// files only itself can open, and nothing at runtime says so until the day the other
// implementation has to read one.
//
// Entropy is stubbed by SIZE, not by call order -- 16 bytes is the attempt token, 12 is the next
// nonce. Pinning the order instead would pin an implementation detail: a writer that mints its
// nonce before its token is not wrong, and a test that fails for that reason teaches nothing.
//
// All constants are public, deterministic test material.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const realSubtle = nodeCrypto.webcrypto.subtle;
// The module reaches for `window.crypto` for BOTH subtle and entropy. Supplying the whole object
// rather than overriding two private accessors keeps the writer on the same availability gate it
// runs on in a browser -- and the writer is the half that needs real entropy.
global.window = { crypto: nodeCrypto.webcrypto };
global.console = { ...console, log() {}, error() {}, warn() {} };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const FIXTURE_DIR = process.argv[2];

function hexToBytes(hex) {
    return new Uint8Array(Buffer.from(hex, 'hex'));
}

async function importDek(dekHex) {
    return realSubtle.importKey('raw', hexToBytes(dekHex), 'AES-GCM', true,
        ['encrypt', 'decrypt']);
}

function codeOf(err) {
    return (err && err.code) || (err && err.name) || String(err);
}

/**
 * Hand back exactly the fixture's entropy, and report what was left over.
 *
 * Draining matters as much as matching: a writer that asks for one nonce too few has produced a
 * file with a chunk missing, and the byte comparison alone would report only that the lengths
 * differ.
 */
function stubEntropy(lib, blobIdHex, noncesHex) {
    const nonces = noncesHex.map(hexToBytes);
    let nonceAt = 0;
    let tokens = 0;
    lib._randomBytes = (n) => {
        if (n === 16) { tokens += 1; return hexToBytes(blobIdHex); }
        if (n === 12) {
            if (nonceAt >= nonces.length) throw new Error('writer asked for too many nonces');
            return nonces[nonceAt++];
        }
        throw new Error('unexpected entropy request of ' + n + ' bytes');
    };
    return () => ({ noncesUsed: nonceAt, noncesAvailable: nonces.length, tokensMinted: tokens });
}

async function main() {
    const out = { runtime: { webcrypto: !!realSubtle }, vectors: {}, negatives: {}, checks: {} };

    const manifest = JSON.parse(
        fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8'));

    for (const entry of manifest.vectors) {
        const v = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, entry.path), 'utf8'));
        const i = v.inputs;
        const lib = new ECCCryptoLibrary();
        const drained = stubEntropy(lib, i.blob_id_hex, i.nonces_hex);

        const dek = await importDek(i.dek_hex);
        const plaintext = new Uint8Array(Buffer.from(i.plaintext_b64, 'base64'));
        const record = { id: v.fixture_id };
        try {
            const written = await lib.encryptFileV2(
                plaintext, dek,
                { vaultId: i.vault_id, objectId: i.object_id, dekEpoch: i.dek_epoch },
                { chunkSize: i.chunk_size });
            record.ok = true;
            record.encoded_b64 = Buffer.from(written.bytes).toString('base64');
            record.blob_id = written.blobId;
            Object.assign(record, drained());
        } catch (e) {
            record.ok = false;
            record.code = codeOf(e);
        }
        out.vectors[v.fixture_id] = record;
    }

    // Everything below runs on real entropy, which is the configuration that ships.
    const lib = new ECCCryptoLibrary();
    const base = JSON.parse(fs.readFileSync(
        path.join(FIXTURE_DIR, 'zk-content-v2-multi-chunk-partial-tail.json'), 'utf8'));
    const bi = base.inputs;
    const dek = await importDek(bi.dek_hex);
    const ctx = { vaultId: bi.vault_id, objectId: bi.object_id, dekEpoch: bi.dek_epoch };
    const body = new Uint8Array(Buffer.from(bi.plaintext_b64, 'base64'));

    // The writer's own output must come back through the PUBLIC reader entry point -- the one a
    // download actually calls, header routing and all.
    //
    // Guarded, so a writer that cannot read its own output reports THAT rather than aborting the
    // harness: an uncaught throw here fails every test in the file at once, including the byte
    // comparisons that would have said precisely which field moved.
    const first = await lib.encryptFileV2(body, dek, ctx, { chunkSize: bi.chunk_size });
    try {
        const back = await lib.decryptFile(first.bytes, dek, ctx);
        out.checks.round_trip_b64 = Buffer.from(new Uint8Array(back)).toString('base64');
    } catch (e) {
        out.checks.round_trip_b64 = null;
        out.checks.round_trip_code = codeOf(e);
    }

    // Two encryptions of one file, every input identical. Sharing a token would share a key and
    // share every non-final chunk's associated data, which makes the two files' chunks
    // interchangeable; the reference-codec test alongside this one demonstrates the splice.
    const second = await lib.encryptFileV2(body, dek, ctx, { chunkSize: bi.chunk_size });
    out.checks.distinct_tokens = first.blobId !== second.blobId;
    out.checks.distinct_bytes =
        Buffer.from(first.bytes).toString('base64') !== Buffer.from(second.bytes).toString('base64');
    out.checks.token_is_32_hex = /^[0-9a-f]{32}$/.test(first.blobId);
    // The token the caller declares to the server has to be the one sealed into the file, or the
    // server's attempt matching and the file's own binding disagree about what an attempt is.
    out.checks.token_matches_header =
        Buffer.from(first.bytes.slice(12, 28)).toString('hex') === first.blobId;

    // No caller said what size to use, so the build's default did -- and the reader takes the size
    // from the header, so this is recorded rather than assumed.
    const defaulted = await lib.encryptFileV2(new Uint8Array(3), dek, ctx);
    out.checks.default_chunk_size = new DataView(
        defaulted.bytes.buffer, defaulted.bytes.byteOffset, defaulted.bytes.byteLength)
        .getUint32(8, false);
    out.checks.declared_default = lib.V2_CONTENT_CHUNK_DEFAULT;
    out.checks.write_gate_default = lib.ZK_CONTENT_WRITE_V2;

    // Input types. Every offline vector above passes a Uint8Array; the SHIPPED caller passes an
    // ArrayBuffer, so until this block existed the branch that actually runs was the one branch
    // nothing executed. A mutation that made it return empty passed the whole suite.
    const sample = new Uint8Array(300);
    for (let i = 0; i < sample.length; i++) sample[i] = (i * 7) & 0xff;
    const asUint8 = await lib.encryptFileV2(sample, dek, ctx, { chunkSize: 4096 });
    out.checks.input_lengths = {};
    for (const [name, value] of [
        ['arraybuffer', sample.buffer.slice(0)],
        ['dataview', new DataView(sample.buffer.slice(0))],
        // A view with a non-zero offset: taking `.buffer` without honouring byteOffset/byteLength
        // silently encrypts the WHOLE backing buffer, which is the neighbouring mistake.
        ['offset_view', new Uint8Array(sample.buffer.slice(0), 8, 100)],
        // Element width larger than a byte: the bytes it spans, not one byte per element.
        ['uint16_view', new Uint16Array(sample.buffer.slice(0))],
    ]) {
        try {
            const w = await lib.encryptFileV2(value, dek, ctx, { chunkSize: 4096 });
            out.checks.input_lengths[name] = w.bytes.length;
        } catch (e) {
            out.checks.input_lengths[name] = codeOf(e);
        }
    }
    out.checks.input_lengths.uint8 = asUint8.bytes.length;

    async function expectFail(name, run) {
        try {
            await run();
            out.negatives[name] = { rejected: false };
        } catch (e) {
            out.negatives[name] = { rejected: true, code: codeOf(e) };
        }
    }

    // A transcript field the writer cannot bind is a file nothing can open. Each must fail before
    // any byte is produced, as bad input rather than as a mystery later.
    await expectFail('no_context', () => lib.encryptFileV2(body, dek, undefined));
    await expectFail('no_vault', () =>
        lib.encryptFileV2(body, dek, { ...ctx, vaultId: undefined }));
    await expectFail('no_object', () =>
        lib.encryptFileV2(body, dek, { ...ctx, objectId: undefined }));
    await expectFail('no_epoch', () =>
        lib.encryptFileV2(body, dek, { ...ctx, dekEpoch: undefined }));
    await expectFail('epoch_zero', () => lib.encryptFileV2(body, dek, { ...ctx, dekEpoch: 0 }));
    await expectFail('object_not_a_uuid', () =>
        lib.encryptFileV2(body, dek, { ...ctx, objectId: 'not-a-uuid' }));

    // Out-of-range chunk sizes. The grammar's bounds are not advice: below the floor the
    // per-chunk overhead dominates and the nonce budget shrinks, above the ceiling no reader
    // will accept the header it writes.
    await expectFail('chunk_below_floor', () =>
        lib.encryptFileV2(body, dek, ctx, { chunkSize: lib.V2_CONTENT_CHUNK_MIN - 1 }));
    await expectFail('chunk_above_ceiling', () =>
        lib.encryptFileV2(body, dek, ctx, { chunkSize: lib.V2_CONTENT_CHUNK_MAX + 1 }));
    await expectFail('chunk_not_an_integer', () =>
        lib.encryptFileV2(body, dek, ctx, { chunkSize: 8192.5 }));

    // A chunk size whose value changes between reads. Validating one read and framing by another
    // produced a header that disagreed with its own body -- a file the writer could not open.
    let reads = 0;
    const shifting = { valueOf() { return ++reads === 1 ? 4096 : 64; } };
    try {
        const w = await lib.encryptFileV2(body, dek, ctx, { chunkSize: shifting });
        const back = await lib.decryptFile(w.bytes, dek, ctx);
        out.checks.shifting_chunk_size_readable =
            Buffer.from(new Uint8Array(back)).toString('base64') === bi.plaintext_b64;
    } catch (e) {
        out.checks.shifting_chunk_size_readable = codeOf(e);
    }

    // Anything that is not a BufferSource. `new Uint8Array(x)` answers zero length for these
    // rather than throwing, so each of them used to encrypt as an empty file and succeed.
    for (const [name, value] of [
        ['plaintext_null', null], ['plaintext_undefined', undefined],
        ['plaintext_string', 'hello world'], ['plaintext_number', 300],
        ['plaintext_object', { length: 4 }],
    ]) {
        await expectFail(name, () => lib.encryptFileV2(value, dek, ctx, { chunkSize: 4096 }));
    }

    // HKDF takes keying material of any length, so a short or wrong-algorithm key derives a
    // valid-looking content key and the file round-trips with nothing to show for it.
    const dek16 = await realSubtle.importKey('raw', new Uint8Array(16), 'AES-GCM', true,
        ['encrypt', 'decrypt']);
    const dekHmac = await realSubtle.importKey('raw', new Uint8Array(32),
        { name: 'HMAC', hash: 'SHA-256' }, true, ['sign', 'verify']);
    await expectFail('dek_too_short', () => lib.encryptFileV2(body, dek16, ctx));
    await expectFail('dek_wrong_algorithm', () => lib.encryptFileV2(body, dekHmac, ctx));

    process.stdout.write(JSON.stringify(out));
}

main().catch((e) => {
    process.stdout.write(JSON.stringify({ fatal: String((e && e.stack) || e) }));
    process.exit(1);
});
