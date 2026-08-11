#!/usr/bin/env node
'use strict';

// Drive the REAL shipped browser reader over the content-v2 vectors, under Node's WebCrypto.
//
// The point is that these bytes were produced by an independent Python implementation built from
// the specification, not by this module. A single-byte disagreement between the two -- a field in
// the wrong order, a width off by four, a separator missing -- is indistinguishable at runtime
// from a working system, because each side is self-consistent. Reading one's output with the
// other is the only thing that catches it.
//
// All constants are public, deterministic test material.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const realSubtle = nodeCrypto.webcrypto.subtle;
// The module logs to console on failure paths; keep stdout clean so it stays parseable JSON.
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

// Anything thrown by the library carries a stable code; report it rather than a message, because
// the code is the contract and the message is not.
function codeOf(err) {
    return (err && err.code) || (err && err.name) || String(err);
}

async function main() {
    const lib = new ECCCryptoLibrary();
    lib._subtle = () => realSubtle;

    const out = { runtime: { webcrypto: !!realSubtle }, vectors: {}, negatives: {} };

    const manifest = JSON.parse(
        fs.readFileSync(path.join(FIXTURE_DIR, 'manifest.json'), 'utf8'));

    for (const entry of manifest.vectors) {
        const v = JSON.parse(fs.readFileSync(path.join(FIXTURE_DIR, entry.path), 'utf8'));
        const i = v.inputs;
        const encoded = new Uint8Array(Buffer.from(v.encoded_b64, 'base64'));
        const dek = await importDek(i.dek_hex);
        const ctx = { vaultId: i.vault_id, objectId: i.object_id, dekEpoch: i.dek_epoch };

        const record = { id: v.fixture_id };
        try {
            // Through the PUBLIC entry point, not the private reader: the seam that routes a v2
            // content header to the new reader is part of what is under test.
            const plain = await lib.decryptFile(encoded, dek, ctx);
            record.plaintext_b64 = Buffer.from(new Uint8Array(plain)).toString('base64');
            record.ok = true;
        } catch (e) {
            record.ok = false;
            record.code = codeOf(e);
        }
        out.vectors[v.fixture_id] = record;
    }

    // Negatives, all derived from the multi-chunk vector so the framing is non-trivial.
    const base = JSON.parse(fs.readFileSync(
        path.join(FIXTURE_DIR, 'zk-content-v2-multi-chunk-partial-tail.json'), 'utf8'));
    const bi = base.inputs;
    const good = new Uint8Array(Buffer.from(base.encoded_b64, 'base64'));
    const dek = await importDek(bi.dek_hex);
    const ctx = { vaultId: bi.vault_id, objectId: bi.object_id, dekEpoch: bi.dek_epoch };

    async function expectFail(name, bytes, context) {
        try {
            await lib.decryptFile(bytes, dek, context || ctx);
            out.negatives[name] = { rejected: false };
        } catch (e) {
            out.negatives[name] = { rejected: true, code: codeOf(e) };
        }
    }

    const other = '33333333-3333-4333-8333-333333333333';

    // Context: every field the key and AAD bind. Changing any one must break it.
    await expectFail('wrong_vault', good, { ...ctx, vaultId: other });
    await expectFail('wrong_object', good, { ...ctx, objectId: other });
    await expectFail('wrong_epoch', good, { ...ctx, dekEpoch: bi.dek_epoch + 1 });

    // Tamper in the header, the first chunk's nonce, and the last chunk's tag.
    for (const [name, idx] of [['tamper_header', 9], ['tamper_nonce', 30],
                               ['tamper_last_tag', good.length - 1]]) {
        const t = good.slice();
        t[idx] ^= 0xFF;
        await expectFail(name, t);
    }

    // A relabelled purpose byte must not decrypt. The header is authenticated as it appears on the
    // wire, so this is caught even though every other byte is genuine.
    const relabelled = good.slice();
    relabelled[5] = 0x01;
    await expectFail('relabelled_purpose', relabelled);

    // Truncation. Every chunk that survives authenticates on its own; only the absent terminator
    // reveals the cut, which is exactly why nothing may be released before it.
    const span = bi.chunk_size + 28;
    await expectFail('truncated_to_one_chunk', good.slice(0, 28 + span));
    await expectFail('truncated_mid_chunk', good.slice(0, good.length - 5));

    // A length in the gap between two valid chunk counts describes no possible file.
    await expectFail('gap_length', good.slice(0, 28 + span + 14));

    // Below the floor, and a chunk_size outside its bounds.
    await expectFail('below_minimum', good.slice(0, 55));
    // Just the eight-byte header. The recogniser accepts it as a v2 content header and routes it
    // here, and there are not enough bytes to read the chunk size that everything downstream needs
    // -- so this is the only length at which the minimum-length check is the thing standing there.
    // At 55 the framing arithmetic reaches the same verdict, which is why removing the check
    // changed no test until this case existed.
    await expectFail('header_only', good.slice(0, 8));
    const badSize = good.slice();
    new DataView(badSize.buffer).setUint32(8, 1024, false);      // under the 4096 floor
    await expectFail('chunk_size_too_small', badSize);
    const hugeSize = good.slice();
    new DataView(hugeSize.buffer).setUint32(8, 0x7FFFFFFF, false);
    await expectFail('chunk_size_too_large', hugeSize);

    // Extension: trailing bytes are not a valid further chunk.
    const extended = new Uint8Array(good.length + 40);
    extended.set(good, 0);
    await expectFail('appended_bytes', extended);

    // A relabelled VERSION byte. Every other byte is genuine, and the file must still not open --
    // the version sits inside the authenticated header, and the seam only routes version 2.
    const reversioned = good.slice();
    reversioned[4] = 0x03;
    await expectFail('relabelled_version', reversioned);

    // A zero-length final chunk on a non-empty file. Forbidden so that a plaintext which is an
    // exact multiple of chunk_size has exactly ONE valid encoding -- and it binds the READER, not
    // just the writer: accepting it here would leave two encodings acceptable on the read side,
    // which is the ambiguity the rule exists to remove. Rejected on framing, before any
    // decryption is attempted.
    const exact = JSON.parse(fs.readFileSync(
        path.join(FIXTURE_DIR, 'zk-content-v2-exact-multiple.json'), 'utf8'));
    const exactBytes = new Uint8Array(Buffer.from(exact.encoded_b64, 'base64'));
    const withEmptyTail = new Uint8Array(exactBytes.length + 28);
    withEmptyTail.set(exactBytes, 0);
    const exactDek = await importDek(exact.inputs.dek_hex);
    try {
        await lib.decryptFile(withEmptyTail, exactDek, {
            vaultId: exact.inputs.vault_id, objectId: exact.inputs.object_id,
            dekEpoch: exact.inputs.dek_epoch,
        });
        out.negatives['zero_length_final_chunk'] = { rejected: false };
    } catch (e) {
        out.negatives['zero_length_final_chunk'] = { rejected: true, code: codeOf(e) };
    }

    // The public entry point checks the four discriminator bytes before routing, so everything
    // the reader's own header comparison could catch is already gone by the time it runs -- which
    // makes that loop look redundant and testable only from outside. It is neither: this method is
    // public, and a streaming reader is exactly the caller this grammar exists to enable. Called
    // directly with the comparison removed, a file relabelled to any version or purpose decrypts.
    // The caller's own context, malformed. This is the only thing that exercises the failure
    // code the encoders were given a parameter for: reported as a WRAP failure it tells the user
    // to ask an owner to re-share the vault, which is the right advice about a broken key wrap and
    // the wrong advice about a file.
    for (const [name, bad] of [
        ['vault', { ...ctx, vaultId: 'not-a-uuid' }],
        ['object', { ...ctx, objectId: '' }],
        ['epoch', { ...ctx, dekEpoch: 0 }],
    ]) {
        try {
            await lib.decryptFile(good, dek, bad);
            out.negatives['malformed_context_' + name] = { rejected: false };
        } catch (e) {
            out.negatives['malformed_context_' + name] = { rejected: true, code: codeOf(e) };
        }
    }

    out.direct = {};
    for (const [name, mutate] of [
        ['magic', b => { b[0] ^= 0xFF; }],
        ['version', b => { b[4] = 0x03; }],
        ['purpose', b => { b[5] = 0x01; }],
        ['reserved', b => { b[6] = 0x01; }],
    ]) {
        const t = good.slice();
        mutate(t);
        try {
            await lib.decryptFileV2(t, dek, ctx);
            out.direct[name] = { rejected: false };
        } catch (e) {
            out.direct[name] = { rejected: true, code: codeOf(e) };
        }
    }
    // And unmodified bytes must still read through the direct entry point, so the four above are
    // rejections of the tampering rather than of the calling convention.
    try {
        const plain = await lib.decryptFileV2(good, dek, ctx);
        out.direct.clean = { ok: true, bytes: new Uint8Array(plain).length };
    } catch (e) {
        out.direct.clean = { ok: false, code: codeOf(e) };
    }

    process.stdout.write(JSON.stringify(out));
}

main().catch(e => {
    process.stdout.write(JSON.stringify({ fatal: String((e && e.stack) || e) }));
    process.exit(1);
});
