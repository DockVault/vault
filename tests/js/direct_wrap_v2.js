#!/usr/bin/env node
'use strict';

// Cross-runtime harness for the version-2 direct recipient DEK wrap (purpose 0x01).
//
// The browser's writer and reader share one transcript builder, so they agree with each other no
// matter what the grammar says: reorder the context, drop the separators, encode the uuids as raw
// bytes instead of the 36-character text, widen the epoch -- every one of those round-trips
// perfectly and is invisible to a test that only asks the module to read its own output. This
// harness exists so a second implementation can disagree.
//
// Determinism needs BOTH queues. The nonce comes from _randomBytes, which most harnesses stub, but
// the ephemeral keypair comes from subtle.generateKey, which they do not -- stubbing only the
// entropy leaves the wrap different on every run and the vector unreproducible.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const realSubtle = nodeCrypto.webcrypto.subtle;
global.console = { ...console, log() {}, error() {}, warn() {} };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

const b64 = bytes => Buffer.from(bytes).toString('base64');
const fromB64 = value => Buffer.from(value, 'base64');
const b64url = bytes => Buffer.from(bytes).toString('base64url');

function scalarBytes(scalarHex) {
    const raw = Buffer.from(scalarHex.length % 2 ? `0${scalarHex}` : scalarHex, 'hex');
    if (raw.length > 48) throw new Error('P-384 scalar exceeds 48 bytes');
    return Buffer.concat([Buffer.alloc(48 - raw.length), raw]);
}

async function fixedP384KeyPair(scalarHex) {
    const ecdh = nodeCrypto.createECDH('secp384r1');
    ecdh.setPrivateKey(scalarBytes(scalarHex));
    const raw = ecdh.getPublicKey(undefined, 'uncompressed');
    const d = b64url(scalarBytes(scalarHex));
    const privateJwk = {
        kty: 'EC', crv: 'P-384', x: b64url(raw.subarray(1, 49)),
        y: b64url(raw.subarray(49, 97)), d, ext: true,
    };
    const publicJwk = { kty: 'EC', crv: 'P-384', x: privateJwk.x, y: privateJwk.y, ext: true };
    return {
        privateKey: await realSubtle.importKey(
            'jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-384' }, true,
            ['deriveBits', 'deriveKey']),
        publicKey: await realSubtle.importKey(
            'jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-384' }, true, []),
    };
}

// Queues BOTH sources of freshness. An exhausted queue throws rather than falling back to real
// randomness: a vector that quietly regenerated its own inputs would pass against anything.
function installDeterministicCrypto({ randomHex = [], generatedPairs = [] } = {}) {
    const randomQueue = randomHex.map(value => Buffer.from(value, 'hex'));
    const pairQueue = [...generatedPairs];
    const subtle = new Proxy(realSubtle, {
        get(target, property) {
            if (property === 'generateKey') {
                return async (...args) => {
                    const algorithm = args[0];
                    if (algorithm && algorithm.name === 'ECDH') {
                        if (!pairQueue.length) throw new Error('deterministic keypair queue exhausted');
                        return pairQueue.shift();
                    }
                    return target.generateKey(...args);
                };
            }
            const value = target[property];
            return typeof value === 'function' ? value.bind(target) : value;
        },
    });
    global.window = {
        crypto: {
            subtle,
            getRandomValues(target) {
                if (!randomQueue.length) throw new Error('deterministic random queue exhausted');
                const value = randomQueue.shift();
                if (value.length !== target.byteLength) {
                    throw new Error(`deterministic random ${value.length} != ${target.byteLength}`);
                }
                new Uint8Array(target.buffer, target.byteOffset, target.byteLength).set(value);
                return target;
            },
        },
    };
}

async function rejected(operation) {
    try {
        await operation();
        return null;
    } catch (err) {
        return err && err.code ? err.code : String((err && err.message) || err);
    }
}

async function writerOutput(vector) {
    const i = vector.inputs;
    const recipient = await fixedP384KeyPair(i.recipient_private_scalar_hex);
    const ephemeral = await fixedP384KeyPair(i.ephemeral_private_scalar_hex);
    installDeterministicCrypto({ randomHex: [i.nonce_hex], generatedPairs: [ephemeral] });

    const lib = new ECCCryptoLibrary();
    const dek = await realSubtle.importKey(
        'raw', Buffer.from(i.dek_hex, 'hex'), { name: 'AES-GCM', length: 256 }, true,
        ['encrypt', 'decrypt']);

    const written = await lib.wrapVaultDEKV2(dek, recipient.publicKey, {
        vaultId: i.vault_id,
        recipientUserId: i.recipient_user_id,
        dekEpoch: i.dek_epoch,
    });
    return {
        wrapped_dek_b64: written.wrappedDEK,
        ephemeral_public_key_b64: written.ephemeralPublicKey,
    };
}

async function readerResult(vector) {
    const i = vector.inputs;
    const e = vector.expected;
    const recipient = await fixedP384KeyPair(i.recipient_private_scalar_hex);
    installDeterministicCrypto();

    const lib = new ECCCryptoLibrary();
    const context = {
        vaultId: i.vault_id,
        recipientUserId: i.recipient_user_id,
        dekEpoch: i.dek_epoch,
    };
    const dek = await lib.unwrapVaultDEK(
        e.wrapped_dek_b64, e.ephemeral_public_key_b64, recipient.privateKey, context);
    const raw = await realSubtle.exportKey('raw', dek);
    return Buffer.from(raw).toString('hex');
}

// Every one of these needs a hostile writer to produce, which is precisely why the browser's own
// round-trip tests cannot reach them: the module will not emit a wrap the module refuses.
async function adversarial(vector) {
    const i = vector.inputs;
    const e = vector.expected;
    const recipient = await fixedP384KeyPair(i.recipient_private_scalar_hex);
    const other = await fixedP384KeyPair(i.other_recipient_private_scalar_hex);
    const context = {
        vaultId: i.vault_id,
        recipientUserId: i.recipient_user_id,
        dekEpoch: i.dek_epoch,
    };

    // `ctx` is passed through EXACTLY as given, including undefined: an earlier version of this
    // helper substituted the real context for a falsy one, so the missing-context case silently
    // tested the happy path and reported that the reader accepted it.
    const OMITTED = Symbol('omitted');
    const read = async (wrappedB64, pointB64, ctx = OMITTED, key) => {
        installDeterministicCrypto();
        const lib = new ECCCryptoLibrary();
        return lib.unwrapVaultDEK(
            wrappedB64, pointB64, key || recipient.privateKey,
            ctx === OMITTED ? context : ctx);
    };
    const mutate = (index, value) => {
        const bytes = fromB64(e.wrapped_dek_b64);
        bytes[index] = value;
        return b64(bytes);
    };

    const point = fromB64(e.ephemeral_public_key_b64);
    const offCurve = Buffer.from(point);
    offCurve[offCurve.length - 1] ^= 0x01;          // still 97 bytes and still 0x04-prefixed
    const shortPoint = point.subarray(0, 96);

    return {
        magic_tampered: await rejected(() => read(mutate(0, 0x44 ^ 0x20), e.ephemeral_public_key_b64)),
        version_below: await rejected(() => read(mutate(4, 0x01), e.ephemeral_public_key_b64)),
        version_future: await rejected(() => read(mutate(4, 0x03), e.ephemeral_public_key_b64)),
        purpose_team: await rejected(() => read(mutate(5, 0x02), e.ephemeral_public_key_b64)),
        reserved_set: await rejected(() => read(mutate(6, 0xAA), e.ephemeral_public_key_b64)),
        nonce_tampered: await rejected(() => read(mutate(9, fromB64(e.wrapped_dek_b64)[9] ^ 0xFF),
                                                  e.ephemeral_public_key_b64)),
        tag_tampered: await rejected(() => {
            const bytes = fromB64(e.wrapped_dek_b64);
            bytes[bytes.length - 1] ^= 0x01;
            return read(b64(bytes), e.ephemeral_public_key_b64);
        }),
        truncated: await rejected(() => read(b64(fromB64(e.wrapped_dek_b64).subarray(0, 67)),
                                             e.ephemeral_public_key_b64)),
        point_short: await rejected(() => read(e.wrapped_dek_b64, b64(shortPoint))),
        point_off_curve: await rejected(() => read(e.wrapped_dek_b64, b64(offCurve))),
        wrong_vault: await rejected(() => read(e.wrapped_dek_b64, e.ephemeral_public_key_b64,
            { ...context, vaultId: i.other_vault_id })),
        wrong_recipient_id: await rejected(() => read(e.wrapped_dek_b64, e.ephemeral_public_key_b64,
            { ...context, recipientUserId: i.other_recipient_user_id })),
        // A neighbouring epoch that is still INSIDE the grammar. At the maximum, +1 leaves the
        // valid range and the reader answers "malformed" instead of "authentication failed" --
        // correct of it, but it would be testing range validation rather than binding.
        wrong_epoch: await rejected(() => read(e.wrapped_dek_b64, e.ephemeral_public_key_b64,
            { ...context, dekEpoch: i.dek_epoch === 0x7FFFFFFF ? i.dek_epoch - 1 : i.dek_epoch + 1 })),
        wrong_key: await rejected(() => read(e.wrapped_dek_b64, e.ephemeral_public_key_b64,
            context, other.privateKey)),
        // Called with three arguments, not four. Passing `undefined` as the fourth would trigger
        // the default parameter and quietly restore the real context -- which it did, and the
        // case reported that the reader accepts an unbound wrap.
        no_context: await rejected(() => {
            installDeterministicCrypto();
            const lib = new ECCCryptoLibrary();
            return lib.unwrapVaultDEK(
                e.wrapped_dek_b64, e.ephemeral_public_key_b64, recipient.privateKey);
        }),
        empty_context: await rejected(
            () => read(e.wrapped_dek_b64, e.ephemeral_public_key_b64, {})),
        // A wrap of a 16-byte key rather than a 32-byte DEK. It is refused for a reason worth
        // being precise about: the payload is 52 bytes, so the LENGTH dispatch turns it away
        // before the reader's own plaintext-length check is reached. That check is unreachable
        // for this construction -- 68 bytes fixes the plaintext at exactly 32 -- so it is
        // defence in depth against a future variable-length variant, not a live guard here.
        short_plaintext: e.short_plaintext_wrapped_b64
            ? await rejected(() => read(e.short_plaintext_wrapped_b64, e.short_plaintext_point_b64))
            : 'ABSENT',
        short_plaintext_byte_length: e.short_plaintext_wrapped_b64
            ? fromB64(e.short_plaintext_wrapped_b64).length : 0,
    };
}

async function main() {
    const dir = process.argv[2];
    if (!dir) throw new Error('usage: direct_wrap_v2.js <fixture-dir>');
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    const out = {};
    for (const entry of manifest.vectors) {
        const vector = JSON.parse(fs.readFileSync(path.join(dir, entry.path), 'utf8'));
        // Each part is captured independently. A grammar change makes the READER throw on bytes
        // it can no longer decode; letting that escape would error every test in the file with a
        // stack trace, when what the reader of the failure needs to know is which half diverged.
        const capture = async (fn) => {
            try {
                return { ok: true, value: await fn() };
            } catch (err) {
                return { ok: false, error: String((err && err.code) || (err && err.message) || err) };
            }
        };
        out[entry.path] = {
            writer: await capture(() => writerOutput(vector)),
            reader: await capture(() => readerResult(vector)),
            adversarial: await adversarial(vector),
        };
    }
    process.stdout.write(JSON.stringify(out));
}

main().catch(err => {
    process.stderr.write(String((err && err.stack) || err));
    process.exit(1);
});
