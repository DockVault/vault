#!/usr/bin/env node
'use strict';

// The owner-encrypted link-token re-copy (purpose 0x06), run in Node against the shipped
// ecc_crypto.js. The properties worth pinning:
//   - it round-trips: what the owner wraps to its OWN public key, the owner unwraps to the same token;
//   - the container the server stores is a V2 LINK-TOKEN blob (magic DVZ2, version 2, purpose 0x06,
//     reserved 0) shaped header(8)||epk(97)||nonce(12)||ct+tag -- the exact shape the server shape
//     check enforces -- and it is NOT the fixed 68-byte key-wrap length (the token is variable-length);
//   - a blob wrapped for one (link, owner) fails to unwrap under another link id or owner id (the AAD
//     binds both), so a copy cannot be replayed onto another link;
//   - a ROTATED key cannot unwrap (a different private key derives a different secret) -- the honest
//     "create a new link" branch the UI renders.

const path = require('path');
const nodeCrypto = require('crypto');
global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
};

const subtle = nodeCrypto.webcrypto.subtle;
const genIdentity = () => subtle.generateKey({ name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);

const LINK = 'aaaaaaaa-1111-4222-8333-444444444444';
const OTHER_LINK = 'bbbbbbbb-2222-4333-8444-555555555555';
const OWNER = 'cccccccc-3333-4444-8555-666666666666';
const OTHER_OWNER = 'dddddddd-4444-4555-8666-777777777777';
const TOKEN = 'Xy7Qm2Zb9Kd4Rf1Ns';   // a base62-ish URL token, variable length

async function failsToUnwrap(lib, blob, priv, ctx, msg) {
    try {
        await lib.unwrapLinkTokenV2(blob, priv, ctx);
        note(false, msg + ' (unexpectedly succeeded)');
    } catch (_e) {
        note(true, msg);
    }
}

async function main() {
    const lib = new ECCCryptoLibrary();
    const owner = await genIdentity();
    const stranger = await genIdentity();     // a rotated / different key

    const blob = await lib.wrapLinkTokenV2(TOKEN, owner.publicKey, { linkId: LINK, ownerId: OWNER });

    // Round-trip to the same token with the owner's own private key.
    const back = await lib.unwrapLinkTokenV2(blob, owner.privateKey, { linkId: LINK, ownerId: OWNER });
    note(back === TOKEN, 'round-trips to the same token');

    // Container shape = the server shape check: base64 of DVZ2||02||06||00 00 || epk(97) || nonce(12) || ct.
    const raw = new Uint8Array(Buffer.from(blob, 'base64'));
    note(raw[0] === 0x44 && raw[1] === 0x56 && raw[2] === 0x5A && raw[3] === 0x32, 'magic is DVZ2');
    note(raw[4] === 0x02, 'version is 2');
    note(raw[5] === 0x06, 'purpose is link-token (0x06)');
    note(raw[6] === 0 && raw[7] === 0, 'reserved bytes are zero');
    note(raw[8] === 0x04 && raw.length >= 8 + 97 + 12 + 16 + 1, 'carries a P-384 point + nonce + tag');
    note(raw.length !== 68, 'is NOT the fixed 68-byte key-wrap length (variable token)');

    // AAD binds (link, owner): a blob for this link/owner does not unwrap under another.
    await failsToUnwrap(lib, blob, owner.privateKey, { linkId: OTHER_LINK, ownerId: OWNER },
        'a blob for another link id fails to unwrap');
    await failsToUnwrap(lib, blob, owner.privateKey, { linkId: LINK, ownerId: OTHER_OWNER },
        'a blob for another owner id fails to unwrap');

    // A rotated / different key cannot unwrap (the retired key derives a different secret).
    await failsToUnwrap(lib, blob, stranger.privateKey, { linkId: LINK, ownerId: OWNER },
        'a rotated (different) private key cannot unwrap');

    if (failures) { console.error(failures + ' failure(s)'); process.exit(1); }
}

main().catch((e) => { console.error(e && e.stack || e); process.exit(1); });
