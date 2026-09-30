#!/usr/bin/env node
'use strict';

// The member-side checks of a zero-knowledge key (static/js/zk_key_checks.js), run with the shipped
// crypto module on real keys.
//
// The key check on the write path is the one client check that stops anything: a member whose key does
// not reproduce the epoch's check cannot upload. So the cases that must NOT stop anyone are tested as
// carefully as the one that must: an epoch made while the server was rolled back (no stored check), an
// answer from an older server, a team vault after its team key changed, an owner's reset. And a key that
// really is another one must stop the write. Each line printed is one case; the Python side reads them.

const path = require('path');
const { webcrypto } = require('crypto');

global.window = { crypto: webcrypto };
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
const realLog = console.log;
console.error = () => {};
console.warn = () => {};
const ECCCryptoLibrary = require(path.resolve(__dirname, '../../static/js/ecc_crypto.js'));
const Checks = require(path.resolve(__dirname, '../../static/js/zk_key_checks.js'));

let failures = 0;
const note = (ok, msg) => {
    if (ok) { realLog('ok   ' + msg); } else { failures += 1; realLog('FAIL ' + msg); }
};

const VAULT = '11111111-2222-4333-8444-555555555555';
const MEMBER = '66666666-7777-4888-9999-aaaaaaaaaaaa';

async function main() {
    const lib = new ECCCryptoLibrary();

    // ------------------------------------------------------------------ direct: the write path
    const dek = await lib.generateVaultDEK();
    const other = await lib.generateVaultDEK();
    const set = { state: 'set', source: 'rotate', dek_check: await lib.dekCheck(dek, VAULT, 3) };
    const verdict = (view, key, epoch = 3) => Checks.writeVerdict(lib, {
        mode: 'direct', vaultId: VAULT, epoch, view, dek: key, isCurrent: true });

    note((await verdict(set, dek)).verdict === Checks.WRITE_OK, 'direct: the key that made the check writes');
    const wrong = await verdict(set, other);
    note(wrong.verdict === Checks.WRITE_MISMATCH && wrong.finding === 'dek_check',
         'direct: a planted wrong key is refused, as a dek_check finding');
    note((await verdict(set, dek, 4)).verdict === Checks.WRITE_MISMATCH,
         'direct: the right key checked at another epoch does not pass');
    note((await verdict({ state: 'missing' }, other)).verdict === Checks.WRITE_UNCHECKED,
         'direct: an epoch rotated while rolled back (no row) never blocks');
    note((await verdict(null, other)).verdict === Checks.WRITE_UNCHECKED,
         'direct: an older server (no key_proof) never blocks');
    note((await verdict({ state: 'set', source: 'rotate' }, other)).verdict === Checks.WRITE_UNCHECKED,
         'direct: a row without a key check never blocks');
    // An owner's reset: a new epoch with fresh material made with the new key, which every remaining
    // member is given.
    const reset = await lib.generateVaultDEK();
    const resetRow = { state: 'set', source: 'owner_reset', lineage_tag: null,
                       dek_check: (await lib.sealKeyProofKey(reset, VAULT, 5)).dekCheck };
    note((await verdict(resetRow, reset, 5)).verdict === Checks.WRITE_OK,
         "direct: after an owner's reset the new key writes");

    // ------------------------------------------------------------------ team vaults: the team key
    const member = await lib.generateKeypair();
    const teamA = await lib.generateKeypair();
    const teamB = await lib.generateKeypair();
    const pemA = await lib.exportPublicKeyPEM(teamA.publicKey);
    const pemB = await lib.exportPublicKeyPEM(teamB.publicKey);
    const ctx = { vaultId: VAULT, recipientUserId: MEMBER };
    for (const [label, wrap] of [
        ['v2', await lib.wrapTeamPrivateKeyV2(teamB.privateKey, member.publicKey, ctx)],
        ['legacy', await lib.wrapPrivateKeyToPublic(teamB.privateKey, member.publicKey)],
    ]) {
        const right = await lib.unwrapTeamPrivateKeyWithCheck(
            wrap.wrappedKey, wrap.ephemeralPublicKey, member.privateKey, ctx, pemB);
        note(right.matchesPublic === true, `${label}: the team key unwrapped is the vault's team key`);
        note(right.privateKey.extractable === false
             && JSON.stringify(right.privateKey.usages) === '["deriveBits"]',
             `${label}: the checked key is derive-only and non-extractable`);
        const swapped = await lib.unwrapTeamPrivateKeyWithCheck(
            wrap.wrappedKey, wrap.ephemeralPublicKey, member.privateKey, ctx, pemA);
        note(swapped.matchesPublic === false, `${label}: a team key that is not the vault's is told apart`);
        const plain = await lib.unwrapPrivateKeyFromWrapped(
            wrap.wrappedKey, wrap.ephemeralPublicKey, member.privateKey, false, ctx);
        note(plain && plain.type === 'private' && !('matchesPublic' in plain),
             `${label}: the unchecked unwrap still returns the key itself`);
    }
    let refused = 'NONE';
    try {
        const wrap = await lib.wrapTeamPrivateKeyV2(teamB.privateKey, member.publicKey, ctx);
        await lib.unwrapTeamPrivateKeyWithCheck(wrap.wrappedKey, wrap.ephemeralPublicKey, member.privateKey, ctx, '');
    } catch (e) { refused = e.code; }
    note(refused === 'INVALID_INPUT', 'a checked unwrap without the public key to check is refused');

    const team = (matches, isCurrent = true) => Checks.writeVerdict(lib, {
        mode: 'hierarchical', vaultId: VAULT, epoch: 7, view: { state: 'team' }, isCurrent,
        teamKeyMatches: matches });
    // After a team rotation the member unwraps the NEW team key and compares it with the NEW public key.
    note((await team(true)).verdict === Checks.WRITE_OK, 'team: after a team rotation the new key writes');
    const teamWrong = await team(false);
    note(teamWrong.verdict === Checks.WRITE_MISMATCH && teamWrong.finding === 'team_key',
         "team: a current team key that is not the vault's is refused, as a team_key finding");
    note((await team(false, false)).verdict === Checks.WRITE_UNCHECKED,
         'team: an older team epoch is never checked against the current public key');
    note((await team(null)).verdict === Checks.WRITE_UNCHECKED, 'team: an uncompared key never blocks');

    // ------------------------------------------------------------------ lineage
    const prev = await lib.generateVaultDEK();
    const next = await lib.sealKeyProofKey(dek, VAULT, 3);
    const directFields = { vaultId: VAULT, prevEpoch: 2, mode: 'direct', nextTeamEpoch: 1,
                           nextVerifierPem: next.publicKeyPem, nextDekCheck: next.dekCheck };
    const tag = await lib.keyLineageTag(prev, directFields);
    const row = (over) => ({ state: 'set', source: 'rotate', public_key: next.publicKeyPem,
                             dek_check: next.dekCheck, lineage_tag: tag, ...over });
    const lineage = (view, prevDek = prev, epoch = 3) => Checks.lineageState(lib, {
        mode: 'direct', vaultId: VAULT, epoch, view, prevDek });
    note(await lineage(row()) === Checks.LINEAGE_VERIFIED, 'lineage: a rotation by a holder of the previous key');
    note(await lineage(row(), other) === Checks.LINEAGE_FAILED, 'lineage: a tag made with another key fails');
    note(await lineage(row({ dek_check: await lib.dekCheck(other, VAULT, 3) })) === Checks.LINEAGE_FAILED,
         'lineage: a tag over other material fails');
    note(await lineage(row({ lineage_tag: null })) === Checks.LINEAGE_FAILED,
         'lineage: a rotation that should carry a tag and does not fails');
    note(await lineage(row({ source: 'owner_reset', lineage_tag: null })) === Checks.LINEAGE_RESET,
         "lineage: an owner's reset without the previous key is told as a reset");
    note(await lineage(row({ source: 'owner_reset' })) === Checks.LINEAGE_VERIFIED,
         "lineage: an owner's reset with the previous key verifies");
    note(await lineage(row({ source: 'bootstrap', lineage_tag: null })) === Checks.LINEAGE_UNVERIFIABLE,
         'lineage: an epoch set up afterwards has nothing to verify');
    note(await lineage({ state: 'missing' }) === Checks.LINEAGE_UNVERIFIABLE,
         'lineage: an epoch rotated while rolled back is not verifiable');
    note(await lineage(null) === Checks.LINEAGE_UNVERIFIABLE, 'lineage: an older server is not verifiable');
    note(await lineage(row(), null) === Checks.LINEAGE_UNVERIFIABLE,
         'lineage: a member who never held the previous key cannot verify');
    note(await lineage(row({ source: 'create', lineage_tag: null })) === Checks.LINEAGE_FAILED,
         'lineage: a later epoch claiming to be the first fails');
    note(await lineage(row(), prev, 1) === Checks.LINEAGE_FIRST, "lineage: the first epoch has no previous key");

    // A team vault: the tag binds the team DEK wrap and the team public key of the new epoch.
    const teamWrap = await lib.wrapTeamDEKV2(dek, teamB.publicKey, { vaultId: VAULT, dekEpoch: 3 });
    const teamFields = { vaultId: VAULT, prevEpoch: 2, mode: 'hierarchical', nextTeamEpoch: 2,
                         nextVerifierPem: pemB, nextTeamWrap: teamWrap.wrappedDEK };
    const teamTag = await lib.keyLineageTag(prev, teamFields);
    const teamLineage = (over, wrapB64 = teamWrap.wrappedDEK, teamPem = pemB) => Checks.lineageState(lib, {
        mode: 'hierarchical', vaultId: VAULT, epoch: 3, prevDek: prev, teamEpoch: 2, teamPublicKeyPem: teamPem,
        teamWrap: wrapB64, view: { state: 'team', source: 'rotate', lineage_tag: teamTag, ...over } });
    note(await teamLineage({}) === Checks.LINEAGE_VERIFIED, 'team lineage: a team rotation by a holder verifies');
    const otherWrap = await lib.wrapTeamDEKV2(other, teamB.publicKey, { vaultId: VAULT, dekEpoch: 3 });
    note(await teamLineage({}, otherWrap.wrappedDEK) === Checks.LINEAGE_FAILED,
         'team lineage: a substituted team DEK wrap fails');
    note(await teamLineage({}, teamWrap.wrappedDEK, pemA) === Checks.LINEAGE_FAILED,
         'team lineage: a substituted team key fails');
    note(await teamLineage({ source: null, lineage_tag: null }) === Checks.LINEAGE_UNVERIFIABLE,
         'team lineage: an epoch with no row is not verifiable');

    realLog(failures ? `${failures} FAILED` : 'ALL OK');
    process.exit(failures ? 1 : 0);
}

main().catch(e => { realLog('HARNESS ' + (e && e.stack)); process.exit(2); });
