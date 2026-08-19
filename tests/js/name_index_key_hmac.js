#!/usr/bin/env node
'use strict';

// The rotation-independent name index: HMAC of the name under the per-vault name-index key.
//
// It is nameBlindIndex keyed on K_index instead of (DEK, epoch). The properties worth pinning:
//
//  - deterministic: same (K_index, vault, name) -> same hex, so the server matches on equality;
//  - keyed by the NAME and the VAULT: a different name or a different vault gives a different index;
//  - keyed by K_INDEX: a different key gives a different index (that is what makes it a secret index
//    a removed member without the key cannot compute);
//  - a DISTINCT domain from the DEK-derived index. During migration both are matched against at
//    once, so if the K_index index of a name could equal that name's (DEK, epoch) index, matching
//    would get a false same-name hit. The distinct salt must make them provably different -- tested
//    directly by computing both for the same name and requiring inequality.

const path = require('path');
const nodeCrypto = require('crypto');
global.window = { crypto: nodeCrypto.webcrypto };
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { console.log('ok   ' + msg); } else { failures += 1; console.error('FAIL ' + msg); }
};

const subtle = nodeCrypto.webcrypto.subtle;
const mkKey = () => subtle.generateKey({ name: 'AES-GCM', length: 256 }, true, ['encrypt', 'decrypt']);
const VID = 'aaaaaaaa-1111-4222-8333-444444444444';
const OTHER_VID = 'bbbbbbbb-2222-4333-8444-555555555555';

async function main() {
    const lib = new ECCCryptoLibrary();
    const K = await mkKey();
    const K2 = await mkKey();
    const dek = await mkKey();
    const name = 'quarterly-report.xlsx';

    const a = await lib.nameIndexKeyBlindIndex(name, K, VID);
    const again = await lib.nameIndexKeyBlindIndex(name, K, VID);
    note(a === again, 'deterministic: same key, vault and name give the same index');
    note(/^[0-9a-f]{64}$/.test(a), 'a 64-hex-char (256-bit) digest');

    note(await lib.nameIndexKeyBlindIndex('other.txt', K, VID) !== a, 'a different name differs');
    note(await lib.nameIndexKeyBlindIndex(name, K, OTHER_VID) !== a, 'a different vault differs');
    note(await lib.nameIndexKeyBlindIndex(name, K2, VID) !== a, 'a different index key differs');

    // The load-bearing separation: the K_index index and the DEK-epoch index of the SAME name
    // must not collide, or migration matching would false-hit.
    const dekIdx1 = await lib.nameBlindIndex(name, dek, VID, 1);
    const dekIdx2 = await lib.nameBlindIndex(name, dek, VID, 2);
    note(a !== dekIdx1 && a !== dekIdx2,
         "the K_index index is a distinct domain from the DEK-derived index (no cross-domain collision)");

    // Even if a vault's DEK and its index key were somehow the SAME bytes, the distinct salt keeps
    // the two indices apart -- the strongest form of the separation.
    const sameBytesDek = K;   // reuse K as both the "DEK" and the index key
    const idxUnderK = await lib.nameIndexKeyBlindIndex(name, K, VID);
    const dekUnderK = await lib.nameBlindIndex(name, sameBytesDek, VID, 1);
    note(idxUnderK !== dekUnderK, 'distinct even when the key bytes coincide (the salt separates them)');

    if (failures) { console.error(`${failures} failure(s)`); process.exit(1); }
    console.log('the index-key index is deterministic, name/vault/key-bound, and a distinct domain from the DEK index');
}

main().catch(e => { console.error((e && e.stack) || String(e)); process.exit(1); });
