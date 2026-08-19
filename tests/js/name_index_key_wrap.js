#!/usr/bin/env node
'use strict';

// The per-vault name-index key wrap (purpose 0x05).
//
// It is the direct-DEK wrap with a different purpose byte and no epoch. The properties worth
// pinning are the ones that make the separation real, not just the happy round-trip:
//
//  - it round-trips: what the owner wraps, the owner unwraps, to the same 32-byte key;
//  - a DEK wrap (0x01) handed to the index-key unwrap is REJECTED, and an index-key wrap handed to
//    the DEK unwrap is REJECTED -- the transposition between the two key types the purpose byte
//    exists to stop. A test that only round-trips would pass with the purpose byte deleted;
//  - the wrong recipient's private key fails, and the wrong vault id fails -- the transcript binds
//    both;
//  - the reserved header bytes and the length are enforced before any key work.

const path = require('path');
const nodeCrypto = require('crypto');
global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
};

const subtle = nodeCrypto.webcrypto.subtle;
const genIndexKey = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
const genIdentity = () => subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);

const VID = 'aaaaaaaa-1111-4222-8333-444444444444';
const OTHER_VID = 'bbbbbbbb-2222-4333-8444-555555555555';
const UID = 'cccccccc-3333-4444-8555-666666666666';

async function rawKey(k) { return new Uint8Array(await subtle.exportKey('raw', k)); }
const eq = (a, b) => a.length === b.length && a.every((x, i) => x === b[i]);

async function main() {
    const lib = new ECCCryptoLibrary();
    const owner = await genIdentity();
    const stranger = await genIdentity();
    const K = await genIndexKey();
    const ownerPubPem = await lib.exportPublicKeyPEM(owner.publicKey);
    const ownerPub = await lib.importPublicKeyPEM(ownerPubPem);

    // Round-trip.
    const wrap = await lib.wrapNameIndexKeyV2(K, ownerPub, { vaultId: VID, recipientUserId: UID });
    const back = await lib.unwrapNameIndexKeyV2(
        wrap.wrappedKey, wrap.ephemeralPublicKey, owner.privateKey, { vaultId: VID, recipientUserId: UID });
    note(eq(await rawKey(K), await rawKey(back)), 'round-trips to the same 32-byte key');

    // A DEK wrap must NOT unwrap as an index key. Build a real direct-DEK wrap of the SAME key to
    // the SAME recipient, then try to unwrap it with the index-key reader.
    const dekWrap = await lib.wrapVaultDEKV2(K, ownerPub, { vaultId: VID, recipientUserId: UID, dekEpoch: 1 });
    let rejectedDek = false;
    try {
        await lib.unwrapNameIndexKeyV2(dekWrap.wrappedDEK, dekWrap.ephemeralPublicKey,
            owner.privateKey, { vaultId: VID, recipientUserId: UID });
    } catch (_) { rejectedDek = true; }
    note(rejectedDek, 'a DEK wrap (0x01) is rejected by the index-key unwrap');

    // ...and the reverse: an index-key wrap must NOT unwrap as a DEK.
    let rejectedIdx = false;
    try {
        await lib.unwrapVaultDEK(wrap.wrappedKey, wrap.ephemeralPublicKey,
            owner.privateKey, { vaultId: VID, recipientUserId: UID, dekEpoch: 1 });
    } catch (_) { rejectedIdx = true; }
    note(rejectedIdx, 'an index-key wrap (0x05) is rejected by the DEK unwrap');

    // Wrong recipient private key.
    let wrongKey = false;
    try {
        await lib.unwrapNameIndexKeyV2(wrap.wrappedKey, wrap.ephemeralPublicKey,
            stranger.privateKey, { vaultId: VID, recipientUserId: UID });
    } catch (_) { wrongKey = true; }
    note(wrongKey, "a stranger's private key cannot unwrap");

    // Wrong vault id in the transcript (the AAD binds it).
    let wrongVault = false;
    try {
        await lib.unwrapNameIndexKeyV2(wrap.wrappedKey, wrap.ephemeralPublicKey,
            owner.privateKey, { vaultId: OTHER_VID, recipientUserId: UID });
    } catch (_) { wrongVault = true; }
    note(wrongVault, 'the wrong vault id fails (the transcript binds it)');

    // Structural checks before any key work: a corrupted length and a flipped reserved byte.
    const good = new Uint8Array(Buffer.from(wrap.wrappedKey, 'base64'));
    const short = Buffer.from(good.slice(0, good.length - 1)).toString('base64');
    let badLen = false;
    try {
        await lib.unwrapNameIndexKeyV2(short, wrap.ephemeralPublicKey, owner.privateKey,
            { vaultId: VID, recipientUserId: UID });
    } catch (_) { badLen = true; }
    note(badLen, 'a wrong length is rejected');

    const reserved = good.slice(); reserved[6] = 1;
    let badReserved = false;
    try {
        await lib.unwrapNameIndexKeyV2(Buffer.from(reserved).toString('base64'),
            wrap.ephemeralPublicKey, owner.privateKey, { vaultId: VID, recipientUserId: UID });
    } catch (_) { badReserved = true; }
    note(badReserved, 'a non-zero reserved byte is rejected');

    // The wrap is the same fixed 68 bytes as the direct DEK wrap.
    note(good.length === lib.V2_DIRECT_WRAP_BYTES, `wrap is ${lib.V2_DIRECT_WRAP_BYTES} bytes (got ${good.length})`);

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('index-key wrap round-trips, is bound to (vault, recipient), and cannot be swapped with a DEK wrap');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
