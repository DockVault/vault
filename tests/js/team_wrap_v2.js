#!/usr/bin/env node
'use strict';

// Cross-runtime harness for the two version-2 TEAM wraps: the team DEK (purpose 0x02) and the team
// private key (purpose 0x03).
//
// Same reason as the direct wrap's harness. Each construction's writer and reader share one
// transcript builder, so they agree with each other whatever the grammar says, and the two team
// constructions additionally share a sealing routine -- which means a mistake in that routine is
// consistent across both and invisible to any test that only asks them to read their own output.
//
// What differs from the direct wrap, and what the vectors exist to pin:
//   * the team DEK binds vault and epoch and NO recipient (one wrap serves every member) and is
//     wrapped to the vault's TEAM public key rather than to a person;
//   * the team private key binds vault and recipient and NO epoch, is wrapped to a member's own
//     key, and is variable length -- so length cannot identify it and the header does all the work.

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

async function fixedP384KeyPair(scalarHex, usages) {
    const ecdh = nodeCrypto.createECDH('secp384r1');
    ecdh.setPrivateKey(scalarBytes(scalarHex));
    const raw = ecdh.getPublicKey(undefined, 'uncompressed');
    const privateJwk = {
        kty: 'EC', crv: 'P-384', x: b64url(raw.subarray(1, 49)),
        y: b64url(raw.subarray(49, 97)), d: b64url(scalarBytes(scalarHex)), ext: true,
    };
    const publicJwk = { kty: 'EC', crv: 'P-384', x: privateJwk.x, y: privateJwk.y, ext: true };
    return {
        privateKey: await realSubtle.importKey(
            'jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-384' }, true,
            usages || ['deriveBits', 'deriveKey']),
        publicKey: await realSubtle.importKey(
            'jwk', publicJwk, { name: 'ECDH', namedCurve: 'P-384' }, true, []),
    };
}

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
        if (err && err.code) {
            return err.operation ? `${err.code} @ ${err.operation}` : err.code;
        }
        return String((err && err.message) || err);
    }
}

async function capture(fn) {
    try {
        return { ok: true, value: await fn() };
    } catch (err) {
        return { ok: false, error: String((err && err.code) || (err && err.message) || err) };
    }
}

// ---- purpose 0x02: the team DEK -----------------------------------------------------------
async function teamDekResults(vector) {
    const i = vector.inputs;
    const e = vector.expected;
    const team = await fixedP384KeyPair(i.team_private_scalar_hex);
    const ephemeral = await fixedP384KeyPair(i.ephemeral_private_scalar_hex);

    installDeterministicCrypto({ randomHex: [i.nonce_hex], generatedPairs: [ephemeral] });
    let lib = new ECCCryptoLibrary();
    const dek = await realSubtle.importKey(
        'raw', Buffer.from(i.dek_hex, 'hex'), { name: 'AES-GCM', length: 256 }, true,
        ['encrypt', 'decrypt']);
    const written = await capture(() => lib.wrapTeamDEKV2(dek, team.publicKey, {
        vaultId: i.vault_id, dekEpoch: i.dek_epoch,
    }));

    installDeterministicCrypto();
    lib = new ECCCryptoLibrary();
    const context = { vaultId: i.vault_id, dekEpoch: i.dek_epoch, teamMode: true };
    const read = await capture(async () => {
        const key = await lib.unwrapVaultDEK(
            e.wrapped_dek_b64, e.ephemeral_public_key_b64, team.privateKey, context);
        return Buffer.from(await realSubtle.exportKey('raw', key)).toString('hex');
    });

    const readWith = (wrapped, point, ctx, priv) => {
        installDeterministicCrypto();
        return new ECCCryptoLibrary().unwrapVaultDEK(
            wrapped, point, priv || team.privateKey, ctx || context);
    };
    const mutate = (index, value) => {
        const bytes = fromB64(e.wrapped_dek_b64);
        bytes[index] = value;
        return b64(bytes);
    };
    const member = await fixedP384KeyPair(i.recipient_private_scalar_hex);

    // Does the BROWSER bind a recipient? Ask it to write the same wrap with a different one and
    // require identical bytes. Asserting this on the reference encoder alone proves nothing: that
    // encoder does not read the field, so changing it is a no-op by construction and the test
    // passes whatever the browser does.
    installDeterministicCrypto({ randomHex: [i.nonce_hex], generatedPairs: [
        await fixedP384KeyPair(i.ephemeral_private_scalar_hex)] });
    const withRecipient = await capture(async () => {
        const l = new ECCCryptoLibrary();
        const k = await realSubtle.importKey(
            'raw', Buffer.from(i.dek_hex, 'hex'), { name: 'AES-GCM', length: 256 }, true,
            ['encrypt', 'decrypt']);
        const out = await l.wrapTeamDEKV2(k, team.publicKey, {
            vaultId: i.vault_id, dekEpoch: i.dek_epoch,
            recipientUserId: i.other_recipient_user_id,
        });
        return out.wrappedDEK;
    });

    return {
        writer: written.ok
            ? { wrapped_dek_b64: written.value.wrappedDEK,
                ephemeral_public_key_b64: written.value.ephemeralPublicKey, ok: true }
            : written,
        reader: read,
        unbound_field_ignored: withRecipient,
        adversarial: {
            // The direct purpose in a team read: the caller states the purpose, the payload never
            // selects it, so a direct wrap must not be openable here.
            purpose_direct: await rejected(() => readWith(mutate(5, 0x01), e.ephemeral_public_key_b64)),
            wrong_vault: await rejected(() => readWith(e.wrapped_dek_b64,
                e.ephemeral_public_key_b64, { ...context, vaultId: i.other_vault_id })),
            wrong_epoch: await rejected(() => readWith(e.wrapped_dek_b64,
                e.ephemeral_public_key_b64, { ...context, dekEpoch: i.dek_epoch + 1 })),
            // A member's own key must not open the team DEK: it is sealed to the TEAM key, and
            // the member reaches it only by first unwrapping the team private key.
            member_key: await rejected(() => readWith(e.wrapped_dek_b64,
                e.ephemeral_public_key_b64, context, member.privateKey)),
            // Read as a DIRECT wrap. Same length, same header shape; only the caller's teamMode
            // and the purpose byte separate them.
            read_as_direct: await rejected(() => readWith(e.wrapped_dek_b64,
                e.ephemeral_public_key_b64,
                { vaultId: i.vault_id, recipientUserId: i.recipient_user_id,
                  dekEpoch: i.dek_epoch })),
            tag_tampered: await rejected(() => {
                const bytes = fromB64(e.wrapped_dek_b64);
                bytes[bytes.length - 1] ^= 0x01;
                return readWith(b64(bytes), e.ephemeral_public_key_b64);
            }),
            reserved_set: await rejected(() => readWith(mutate(6, 0x01),
                e.ephemeral_public_key_b64)),
        },
    };
}

// ---- purpose 0x03: the team private key ---------------------------------------------------
async function teamPrivResults(vector) {
    const i = vector.inputs;
    const e = vector.expected;
    const member = await fixedP384KeyPair(i.recipient_private_scalar_hex);
    const ephemeral = await fixedP384KeyPair(i.ephemeral_private_scalar_hex);
    const team = await fixedP384KeyPair(i.team_private_scalar_hex, ['deriveBits', 'deriveKey']);

    installDeterministicCrypto({ randomHex: [i.nonce_hex], generatedPairs: [ephemeral] });
    let lib = new ECCCryptoLibrary();
    const written = await capture(() => lib.wrapTeamPrivateKeyV2(
        team.privateKey, member.publicKey,
        { vaultId: i.vault_id, recipientUserId: i.recipient_user_id }));

    installDeterministicCrypto();
    lib = new ECCCryptoLibrary();
    const context = { vaultId: i.vault_id, recipientUserId: i.recipient_user_id };
    const read = await capture(async () => {
        const key = await lib.unwrapPrivateKeyFromWrapped(
            e.wrapped_key_b64, e.ephemeral_public_key_b64, member.privateKey, true, context);
        return Buffer.from(await realSubtle.exportKey('pkcs8', key)).toString('base64');
    });

    const readWith = (wrapped, point, ctx, priv) => {
        installDeterministicCrypto();
        return new ECCCryptoLibrary().unwrapPrivateKeyFromWrapped(
            wrapped, point, priv || member.privateKey, true, ctx || context);
    };
    const mutate = (index, value) => {
        const bytes = fromB64(e.wrapped_key_b64);
        bytes[index] = value;
        return b64(bytes);
    };

    // The mirror-image question for the private wrap: does an epoch reach its transcript?
    installDeterministicCrypto({ randomHex: [i.nonce_hex], generatedPairs: [
        await fixedP384KeyPair(i.ephemeral_private_scalar_hex)] });
    const withEpoch = await capture(async () => {
        const l = new ECCCryptoLibrary();
        const out = await l.wrapTeamPrivateKeyV2(team.privateKey, member.publicKey, {
            vaultId: i.vault_id, recipientUserId: i.recipient_user_id, dekEpoch: 99,
        });
        return out.wrappedKey;
    });

    return {
        writer: written.ok
            ? { wrapped_key_b64: written.value.wrappedKey,
                ephemeral_public_key_b64: written.value.ephemeralPublicKey, ok: true }
            : written,
        reader: read,
        unbound_field_ignored: withEpoch,
        adversarial: {
            purpose_team_dek: await rejected(() => readWith(mutate(5, 0x02),
                e.ephemeral_public_key_b64)),
            wrong_vault: await rejected(() => readWith(e.wrapped_key_b64,
                e.ephemeral_public_key_b64, { ...context, vaultId: i.other_vault_id })),
            wrong_recipient: await rejected(() => readWith(e.wrapped_key_b64,
                e.ephemeral_public_key_b64,
                { ...context, recipientUserId: i.other_recipient_user_id })),
            tag_tampered: await rejected(() => {
                const bytes = fromB64(e.wrapped_key_b64);
                bytes[bytes.length - 1] ^= 0x01;
                return readWith(b64(bytes), e.ephemeral_public_key_b64);
            }),
            reserved_set: await rejected(() => readWith(mutate(6, 0x01),
                e.ephemeral_public_key_b64)),
            // Variable length is what makes this construction different, so the ceiling is the
            // guard that replaces "the length identifies it".
            oversized: await rejected(() => readWith(
                b64(Buffer.alloc(9000, 0x41)), e.ephemeral_public_key_b64)),
        },
    };
}

async function main() {
    const dir = process.argv[2];
    if (!dir) throw new Error('usage: team_wrap_v2.js <fixture-dir>');
    const manifest = JSON.parse(fs.readFileSync(path.join(dir, 'manifest.json'), 'utf8'));
    const out = {};
    for (const entry of manifest.vectors) {
        const vector = JSON.parse(fs.readFileSync(path.join(dir, entry.path), 'utf8'));
        out[entry.path] = vector.purpose === 3
            ? await teamPrivResults(vector)
            : await teamDekResults(vector);
    }
    process.stdout.write(JSON.stringify(out));
}

main().catch(err => {
    process.stderr.write(String((err && err.stack) || err));
    process.exit(1);
});
