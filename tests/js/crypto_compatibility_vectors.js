#!/usr/bin/env node
'use strict';

// Deterministic compatibility harness for the real shipped browser crypto.
// All constants come from conspicuously public crypto compatibility test vectors.

const fs = require('fs');
const path = require('path');
const nodeCrypto = require('crypto');

const realSubtle = nodeCrypto.webcrypto.subtle;
const quietConsole = { ...console, log() {}, error() {}, warn() {} };
global.console = quietConsole;
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

function load(dir, name) {
    return JSON.parse(fs.readFileSync(path.join(dir, name), 'utf8'));
}

function b64(bytes) {
    return Buffer.from(bytes).toString('base64');
}

function fromB64(value) {
    return Buffer.from(value, 'base64');
}

function hex(bytes) {
    return Buffer.from(bytes).toString('hex');
}

function b64url(bytes) {
    return Buffer.from(bytes).toString('base64url');
}

function scalarBytes(scalarHex) {
    const raw = Buffer.from(scalarHex.length % 2 ? `0${scalarHex}` : scalarHex, 'hex');
    if (raw.length > 48) throw new Error('P-384 scalar exceeds 48 bytes');
    return Buffer.concat([Buffer.alloc(48 - raw.length), raw]);
}

async function privatePemFromScalar(scalarHex, lib) {
    const pair = await fixedP384KeyPair(scalarHex);
    installDeterministicCrypto();
    return lib.exportPrivateKeyPEM(pair.privateKey);
}

async function fixedP384KeyPair(scalarHex) {
    const ecdh = nodeCrypto.createECDH('secp384r1');
    const d = scalarBytes(scalarHex);
    ecdh.setPrivateKey(d);
    const raw = ecdh.getPublicKey(undefined, 'uncompressed');
    const privateJwk = {
        kty: 'EC', crv: 'P-384', x: b64url(raw.subarray(1, 49)),
        y: b64url(raw.subarray(49, 97)), d: b64url(d), ext: true,
    };
    const publicJwk = {
        kty: 'EC', crv: 'P-384', x: privateJwk.x, y: privateJwk.y, ext: true,
    };
    return {
        privateKey: await realSubtle.importKey(
            'jwk', privateJwk, { name: 'ECDH', namedCurve: 'P-384' }, true,
            ['deriveBits', 'deriveKey']),
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
                    if (algorithm && algorithm.name === 'ECDH' && pairQueue.length) {
                        return pairQueue.shift();
                    }
                    return target.generateKey(...args);
                };
            }
            const value = target[property];
            return typeof value === 'function' ? value.bind(target) : value;
        },
    });
    const deterministic = {
        subtle,
        getRandomValues(target) {
            if (!randomQueue.length) throw new Error('deterministic random queue exhausted');
            const value = randomQueue.shift();
            if (value.length !== target.byteLength) {
                throw new Error(`deterministic random length ${value.length} != ${target.byteLength}`);
            }
            new Uint8Array(target.buffer, target.byteOffset, target.byteLength).set(value);
            return target;
        },
    };
    global.window = { crypto: deterministic };
    return deterministic;
}

async function aesGcmKey(hexValue, extractable = true) {
    return realSubtle.importKey(
        'raw', Buffer.from(hexValue, 'hex'), { name: 'AES-GCM', length: 256 },
        extractable, ['encrypt', 'decrypt']);
}

async function rejected(operation) {
    try {
        await operation();
        return false;
    } catch (_) {
        return true;
    }
}

function flipLast(encoded) {
    const value = fromB64(encoded);
    value[value.length - 1] ^= 1;
    return b64(value);
}

async function contentResults(vector) {
    const lib = new ECCCryptoLibrary();
    const inputs = vector.inputs;
    const expected = fromB64(vector.encoded_b64);
    const dek = await aesGcmKey(inputs.dek_hex);
    installDeterministicCrypto({ randomHex: [inputs.iv_hex] });
    const written = Buffer.from(await lib.encryptFile(fromB64(inputs.plaintext_b64), dek));
    installDeterministicCrypto();
    const read = Buffer.from(await lib.decryptFile(expected, dek));
    const wrong = await aesGcmKey('ff'.repeat(32));
    const tampered = Buffer.from(expected); tampered[tampered.length - 1] ^= 1;
    return {
        writer_matches: written.equals(expected),
        reader_matches: b64(read) === inputs.plaintext_b64,
        wrong_key_rejected: await rejected(() => lib.decryptFile(expected, wrong)),
        tamper_rejected: await rejected(() => lib.decryptFile(tampered, dek)),
        truncation_rejected: await rejected(() => lib.decryptFile(expected.subarray(0, -1), dek)),
        append_rejected: await rejected(() => lib.decryptFile(Buffer.concat([expected, Buffer.from([0])]), dek)),
    };
}

async function privateEnvelopeResults(vector) {
    const lib = new ECCCryptoLibrary();
    const i = vector.inputs;
    const envelope = vector.expected.envelope;
    const privateKeyPem = await privatePemFromScalar(i.identity_private_scalar_hex, lib);
    installDeterministicCrypto({ randomHex: [i.salt_hex, i.iv_hex] });
    const written = await lib.encryptPrivateKey(privateKeyPem, i.password);
    installDeterministicCrypto();
    const read = await lib.decryptPrivateKey(
        envelope.encrypted, i.password, envelope.salt, envelope.iterations);
    const differentPrivateKeyPem = await privatePemFromScalar('12', lib);
    installDeterministicCrypto({
        randomHex: [
            'b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecf',
            'd0d1d2d3d4d5d6d7d8d9dadb',
        ],
    });
    const differentEnvelope = await lib.encryptPrivateKey(differentPrivateKeyPem, i.password);
    installDeterministicCrypto();
    const differentUnlocked = await lib.decryptPrivateKey(
        differentEnvelope.encrypted, i.password, differentEnvelope.salt,
        differentEnvelope.iterations);
    return {
        writer_matches: JSON.stringify(written) === JSON.stringify(envelope),
        reader_matches: read === privateKeyPem,
        valid_different_p384_key_unlock_characterized:
            differentUnlocked === differentPrivateKeyPem && differentUnlocked !== privateKeyPem,
        wrong_password_rejected: await rejected(() => lib.decryptPrivateKey(
            envelope.encrypted, `${i.password}-WRONG`, envelope.salt, envelope.iterations)),
        tamper_rejected: await rejected(() => lib.decryptPrivateKey(
            flipLast(envelope.encrypted), i.password, envelope.salt, envelope.iterations)),
        truncation_rejected: await rejected(() => lib.decryptPrivateKey(
            b64(fromB64(envelope.encrypted).subarray(0, -1)), i.password,
            envelope.salt, envelope.iterations)),
        append_rejected: await rejected(() => lib.decryptPrivateKey(
            b64(Buffer.concat([fromB64(envelope.encrypted), Buffer.from([0])])),
            i.password, envelope.salt, envelope.iterations)),
        malformed_encrypted_base64_rejected: await rejected(() => lib.decryptPrivateKey(
            'not-valid%%%base64', i.password, envelope.salt, envelope.iterations)),
        malformed_salt_base64_rejected: await rejected(() => lib.decryptPrivateKey(
            envelope.encrypted, i.password, 'not-valid%%%base64', envelope.iterations)),
    };
}

async function directWrapResults(vector, teamVector) {
    const lib = new ECCCryptoLibrary();
    const i = vector.inputs;
    const recipient = await fixedP384KeyPair(i.recipient_private_scalar_hex);
    const ephemeral = await fixedP384KeyPair(i.ephemeral_private_scalar_hex);
    const dek = await aesGcmKey(i.dek_hex);
    installDeterministicCrypto({ generatedPairs: [ephemeral] });
    const written = await lib.wrapVaultDEK(dek, recipient.publicKey);
    installDeterministicCrypto();
    const unwrapped = await lib.unwrapVaultDEK(
        vector.expected.wrapped_dek_b64,
        vector.expected.ephemeral_public_key_b64,
        recipient.privateKey);
    const raw = await realSubtle.exportKey('raw', unwrapped);
    const wrongRecipient = await fixedP384KeyPair('23');
    const malformedPoint = b64(Buffer.alloc(97));
    return {
        writer_matches: written.wrappedDEK === vector.expected.wrapped_dek_b64
            && written.ephemeralPublicKey === vector.expected.ephemeral_public_key_b64,
        reader_matches: hex(raw) === i.dek_hex,
        wrong_private_key_rejected: await rejected(() => lib.unwrapVaultDEK(
            vector.expected.wrapped_dek_b64,
            vector.expected.ephemeral_public_key_b64,
            wrongRecipient.privateKey)),
        tamper_rejected: await rejected(() => lib.unwrapVaultDEK(
            flipLast(vector.expected.wrapped_dek_b64),
            vector.expected.ephemeral_public_key_b64,
            recipient.privateKey)),
        truncation_rejected: await rejected(() => lib.unwrapVaultDEK(
            b64(fromB64(vector.expected.wrapped_dek_b64).subarray(0, -1)),
            vector.expected.ephemeral_public_key_b64,
            recipient.privateKey)),
        malformed_point_rejected: await rejected(() => lib.unwrapVaultDEK(
            vector.expected.wrapped_dek_b64, malformedPoint, recipient.privateKey)),
        malformed_wrapped_base64_rejected: await rejected(() => lib.unwrapVaultDEK(
            'not-valid%%%base64', vector.expected.ephemeral_public_key_b64,
            recipient.privateKey)),
        malformed_point_base64_rejected: await rejected(() => lib.unwrapVaultDEK(
            vector.expected.wrapped_dek_b64, 'not-valid%%%base64', recipient.privateKey)),
        team_blob_cross_use_rejected: await rejected(() => lib.unwrapVaultDEK(
            teamVector.expected.wrapped_key_b64,
            teamVector.expected.ephemeral_public_key_b64,
            recipient.privateKey)),
    };
}

async function teamWrapResults(vector, directVector) {
    const lib = new ECCCryptoLibrary();
    const i = vector.inputs;
    const member = await fixedP384KeyPair(i.member_private_scalar_hex);
    const ephemeral = await fixedP384KeyPair(i.ephemeral_private_scalar_hex);
    const team = await fixedP384KeyPair(i.team_private_scalar_hex);
    const expectedPkcs8 = await realSubtle.exportKey('pkcs8', team.privateKey);
    installDeterministicCrypto({ randomHex: [i.iv_hex], generatedPairs: [ephemeral] });
    const written = await lib.wrapPrivateKeyToPublic(team.privateKey, member.publicKey);
    installDeterministicCrypto();
    const unwrapped = await lib.unwrapPrivateKeyFromWrapped(
        vector.expected.wrapped_key_b64,
        vector.expected.ephemeral_public_key_b64,
        member.privateKey,
        true);
    const pkcs8 = await realSubtle.exportKey('pkcs8', unwrapped);
    const wrongMember = await fixedP384KeyPair('56');
    const malformedPoint = b64(Buffer.alloc(97));
    const defaultNonExtractable = await lib.unwrapPrivateKeyFromWrapped(
        vector.expected.wrapped_key_b64,
        vector.expected.ephemeral_public_key_b64,
        member.privateKey);
    return {
        writer_matches: written.wrappedKey === vector.expected.wrapped_key_b64
            && written.ephemeralPublicKey === vector.expected.ephemeral_public_key_b64,
        reader_matches: Buffer.from(pkcs8).equals(Buffer.from(expectedPkcs8)),
        default_non_extractable: defaultNonExtractable.extractable === false,
        wrong_private_key_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            vector.expected.wrapped_key_b64,
            vector.expected.ephemeral_public_key_b64,
            wrongMember.privateKey)),
        tamper_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            flipLast(vector.expected.wrapped_key_b64),
            vector.expected.ephemeral_public_key_b64,
            member.privateKey)),
        truncation_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            b64(fromB64(vector.expected.wrapped_key_b64).subarray(0, -1)),
            vector.expected.ephemeral_public_key_b64,
            member.privateKey)),
        malformed_point_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            vector.expected.wrapped_key_b64, malformedPoint, member.privateKey)),
        malformed_wrapped_base64_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            'not-valid%%%base64', vector.expected.ephemeral_public_key_b64,
            member.privateKey)),
        malformed_point_base64_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            vector.expected.wrapped_key_b64, 'not-valid%%%base64', member.privateKey)),
        direct_blob_cross_use_rejected: await rejected(() => lib.unwrapPrivateKeyFromWrapped(
            directVector.expected.wrapped_dek_b64,
            directVector.expected.ephemeral_public_key_b64,
            member.privateKey)),
    };
}

async function nameResults(v1, v2) {
    const lib = new ECCCryptoLibrary();
    const i1 = v1.inputs;
    const i2 = v2.inputs;
    const dek = await aesGcmKey(i1.dek_hex);
    installDeterministicCrypto({ randomHex: [i2.iv_hex] });
    const written = await lib.encryptName(
        i2.plaintext, dek, i2.vault_id, i2.field, i2.epoch, i2.object_id);
    installDeterministicCrypto();
    const read1 = await lib.decryptName(
        v1.expected.token, dek, i1.vault_id, i1.field, i1.epoch, 'ignored-object');
    const prefixless = await lib.decryptName(
        v1.encoded_b64, dek, i1.vault_id, i1.field, i1.epoch, 'also-ignored');
    const read2 = await lib.decryptName(
        v2.expected.token, dek, i2.vault_id, i2.field, i2.epoch, i2.object_id);
    const blind = await lib.nameBlindIndex(i2.plaintext, dek, i2.vault_id, i2.epoch);
    const otherNameBlind = await lib.nameBlindIndex(`${i2.plaintext}-other`, dek, i2.vault_id, i2.epoch);
    const otherEpochBlind = await lib.nameBlindIndex(i2.plaintext, dek, i2.vault_id, i2.epoch + 1);
    const otherVaultBlind = await lib.nameBlindIndex(
        i2.plaintext, dek, '33333333-3333-4333-8333-333333333333', i2.epoch);
    return {
        zk1_reader_matches: read1 === i1.plaintext,
        zk1_prefixless_reader_matches: prefixless === i1.plaintext,
        zk1_object_transposition_characterized: read1 === prefixless,
        zk2_reader_matches: read2 === i2.plaintext,
        zk2_writer_matches: written === v2.expected.token,
        blind_index_matches: blind === v2.expected.blind_index
            && blind === v1.expected.blind_index,
        blind_index_context_separated: blind !== otherNameBlind
            && blind !== otherEpochBlind && blind !== otherVaultBlind,
        missing_object_writer_rejected: await rejected(() => lib.encryptName(
            i2.plaintext, dek, i2.vault_id, i2.field, i2.epoch, '')),
        wrong_object_rejected: await rejected(() => lib.decryptName(
            v2.expected.token, dek, i2.vault_id, i2.field, i2.epoch,
            '33333333-3333-4333-8333-333333333333')),
        wrong_vault_rejected: await rejected(() => lib.decryptName(
            v2.expected.token, dek, '33333333-3333-4333-8333-333333333333',
            i2.field, i2.epoch, i2.object_id)),
        wrong_field_rejected: await rejected(() => lib.decryptName(
            v2.expected.token, dek, i2.vault_id, 'mime', i2.epoch, i2.object_id)),
        wrong_epoch_rejected: await rejected(() => lib.decryptName(
            v2.expected.token, dek, i2.vault_id, i2.field, i2.epoch + 1, i2.object_id)),
        tamper_rejected: await rejected(() => lib.decryptName(
            `zk2:${flipLast(v2.encoded_b64)}`, dek, i2.vault_id, i2.field,
            i2.epoch, i2.object_id)),
        truncation_rejected: await rejected(() => lib.decryptName(
            `zk2:${b64(fromB64(v2.encoded_b64).subarray(0, -1))}`,
            dek, i2.vault_id, i2.field, i2.epoch, i2.object_id)),
        append_rejected: await rejected(() => lib.decryptName(
            `zk2:${b64(Buffer.concat([fromB64(v2.encoded_b64), Buffer.from([0])]))}`,
            dek, i2.vault_id, i2.field, i2.epoch, i2.object_id)),
        unknown_prefix_rejected: await rejected(() => lib.decryptName(
            `zk3:${v2.encoded_b64}`, dek, i2.vault_id, i2.field,
            i2.epoch, i2.object_id)),
        malformed_base64_rejected: await rejected(() => lib.decryptName(
            'zk2:not-valid%%%base64', dek, i2.vault_id, i2.field,
            i2.epoch, i2.object_id)),
    };
}

async function main() {
    const dir = process.argv[2];
    if (!dir) throw new Error('usage: crypto_compatibility_vectors.js FIXTURE_DIRECTORY');
    const content = load(dir, 'zk-content-unversioned.json');
    const privateEnvelope = load(dir, 'zk-private-envelope-legacy.json');
    const direct = load(dir, 'zk-direct-dek-wrap-legacy.json');
    const team = load(dir, 'zk-team-private-wrap-v1.json');
    const nameV1 = load(dir, 'zk-name-zk1.json');
    const nameV2 = load(dir, 'zk-name-zk2.json');
    const results = {
        runtime: { node: process.version, webcrypto: Boolean(realSubtle) },
        content: await contentResults(content),
        private_envelope: await privateEnvelopeResults(privateEnvelope),
        direct_wrap: await directWrapResults(direct, team),
        team_private_wrap: await teamWrapResults(team, direct),
        names: await nameResults(nameV1, nameV2),
    };
    process.stdout.write(`${JSON.stringify(results)}\n`);
}

main().catch(error => {
    process.stdout.write(`${JSON.stringify({ fatal: error.stack || String(error) })}\n`);
    process.exitCode = 1;
});
