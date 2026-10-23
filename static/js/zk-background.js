/*
 * Work the web app does for zero-knowledge vaults on its own, without asking anyone anything.
 *
 * Setting up a direct vault's key check. A key change (a rotation, a share, minting the name index key) proves the
 * vault's current key against a key check its epoch keeps (app/services/zk_key_proof.py). An epoch made before key
 * proofs, or while they were not required, has none, and the first key change sets one up on the way. When a
 * manager who holds the key opens such a vault, the key check is set up then, so that a later removal does not wait
 * for it (any manager who holds the key may). It never asks for the passphrase: it runs only while the key is
 * unlocked, and when the key is locked it waits for the unlock the vault's opening (or anything else) asks for, as
 * long as that vault is still open. It is tried once per vault and epoch for the page, whatever came of it: a failure
 * is left to the setup the next key change does on demand.
 *
 * Sharing with several people. A bulk share runs at most BULK_SHARE_AT_ONCE shares at a time: a share of a
 * zero-knowledge vault is several requests in a row, and the server keeps a bounded number of live key-proof
 * challenges per account.
 *
 * Uses app.js's functions at call time (state, zkKeyUnlocked, zkBootstrapKeyProof); loaded before it.
 */
'use strict';

const BULK_SHARE_AT_ONCE = 4;

// fn(item) for every item, at most `limit` running at once, started in the items' order. Resolves to the outcomes
// in the items' order, as Promise.allSettled gives them: one failure stops nothing else.
async function runAtMost(items, limit, fn) {
    const list = Array.from(items);
    const out = new Array(list.length);
    let next = 0;
    async function worker() {
        while (next < list.length) {
            const i = next++;
            try {
                out[i] = { status: 'fulfilled', value: await fn(list[i], i) };
            } catch (reason) {
                out[i] = { status: 'rejected', reason };
            }
        }
    }
    const width = Math.max(1, Math.min(Number(limit) || 1, list.length));
    await Promise.all(Array.from({ length: list.length ? width : 0 }, worker));
    return out;
}

// "vaultId:epoch" of every key check this page has set up, or tried to.
const _zkBackgroundTried = new Set();
// The one waiting for an unlock: {vaultId, epoch}.
let _zkBackgroundPending = null;

// Whether the /ecc/vaults/{id}/keys answer `keys` is a direct vault's current epoch with no key check.
function zkKeyCheckMissing(keys) {
    if (!keys || !keys.has_access || keys.mode === 'hierarchical' || keys.wrapped_team_privkey) return false;
    const proof = keys.key_proof;
    if (!proof || proof.state !== 'missing') return false;
    return keys.key_version != null && keys.key_version === keys.current_dek_version;
}

// Called when a manager who holds the key has the vault open (refreshZkRekeyNotice), with its /keys answer.
function zkBootstrapInBackground(vault, keys) {
    if (!vault || !zkKeyCheckMissing(keys)) return;
    const epoch = keys.key_version;
    if (_zkBackgroundTried.has(`${vault.id}:${epoch}`)) return;
    if (!zkKeyUnlocked()) {
        _zkBackgroundPending = { vaultId: vault.id, epoch };
        return;
    }
    _zkBackgroundRun(vault.id, epoch);
}

// Called by app.js once the key is unlocked: the setup waiting for it runs if its vault is still the one open.
function zkAfterUnlock() {
    const pending = _zkBackgroundPending;
    _zkBackgroundPending = null;
    if (!pending || !state.currentVault || String(state.currentVault.id) !== String(pending.vaultId)) return;
    if (_zkBackgroundTried.has(`${pending.vaultId}:${pending.epoch}`)) return;
    _zkBackgroundRun(pending.vaultId, pending.epoch);
}

async function _zkBackgroundRun(vaultId, epoch) {
    _zkBackgroundTried.add(`${vaultId}:${epoch}`);
    if (_zkBackgroundPending && String(_zkBackgroundPending.vaultId) === String(vaultId)) _zkBackgroundPending = null;
    if (!zkKeyUnlocked()) return;           // locked meanwhile: never a prompt from here
    try {
        await zkBootstrapKeyProof(vaultId, epoch);
    } catch (_) {
        // Left to the on-demand setup of the next key change.
    }
}
