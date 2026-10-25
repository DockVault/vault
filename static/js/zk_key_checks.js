/**
 * The checks a member's browser makes on the zero-knowledge key it holds.
 *
 * The server never sees a vault's key, so it cannot tell a member whether the key they were given is the
 * vault's. Two values it stores for each key epoch let the member's browser tell for itself:
 *
 *  - the KEY CHECK of a direct epoch: a MAC keyed by the epoch's key over the vault and the epoch. A member
 *    whose key does not reproduce it holds another key -- a bad share, a wrap swapped by someone who holds
 *    the key, or a database edit -- and their browser refuses to encrypt anything under it. For a team
 *    vault the team public key plays that part: the team private key a member unwrapped must be its pair.
 *  - the LINEAGE TAG of an epoch made by a rotation: a MAC keyed by the previous epoch's key over what the
 *    rotation installed, which only someone who held the previous key could have made.
 *
 * This module decides what those checks say; the web app (app.js) fetches what they need and acts on the
 * answer. It is here, apart and free of the page, because the one check that blocks anything -- the key
 * check on the write path -- must never block an honest member, and the cases that must not block are
 * exactly the ones worth running off the browser: an epoch made while the server was rolled back, a team
 * vault after its team key changed, an owner's reset. See docs/design/vault-zk-key-proof-v1.md.
 *
 * `lib` is the ECCCryptoLibrary instance (static/js/ecc_crypto.js).
 */
'use strict';

const ZkKeyChecks = (() => {
    // What the web app may do with the key it holds for an epoch.
    const WRITE_OK = 'ok';                   // the key reproduces the epoch's check: write with it
    const WRITE_MISMATCH = 'mismatch';       // it does not: refuse to write, say why, tell the owner
    const WRITE_UNCHECKED = 'not-verifiable'; // nothing to check it against: write as before

    // The four states of an epoch's lineage, plus the first epoch, which has no previous key.
    const LINEAGE_VERIFIED = 'verified';
    const LINEAGE_UNVERIFIABLE = 'not-verifiable';
    const LINEAGE_RESET = 'reset-by-owner';
    const LINEAGE_FAILED = 'failed';
    const LINEAGE_FIRST = 'first';

    // A key the server names cannot be compared without the answer of this epoch: `view` is the
    // `key_proof` object of GET /ecc/vaults/{id}/keys for the epoch (absent from an older server).
    function _b64Equal(a, b) {
        if (typeof a !== 'string' || typeof b !== 'string' || !a || a.length !== b.length) return false;
        let diff = 0;
        for (let i = 0; i < a.length; i++) diff |= a.charCodeAt(i) ^ b.charCodeAt(i);
        return diff === 0;
    }

    /**
     * What the comparison of an unwrapped team private key with the vault's team public key answered, as the
     * write path keeps it: true (it is the pair), false (it is not: a mismatch, which stops a write), or null
     * (the comparison could not run: a stored team public key the browser cannot read, which writes as before).
     * Anything but true or false is null: only a positive mismatch may stop an honest member.
     *
     * @returns {boolean|null}
     */
    function teamKeyAnswer(matchesPublic) {
        if (matchesPublic === true) return true;
        if (matchesPublic === false) return false;
        return null;
    }

    /**
     * May a member write under the key they hold for this epoch?
     *
     * opts: {mode ('direct' | 'hierarchical'), vaultId, epoch, view (the epoch's key_proof, or null),
     *        dek (direct: the epoch's DEK, a CryptoKey), isCurrent (the epoch is the vault's current one),
     *        teamKeyMatches (hierarchical: whether the team private key the member unwrapped is the pair of
     *        the vault's team public key; true, false, or null when that was not compared)}
     *
     * Blocks ONLY on a positive mismatch: a direct epoch whose stored check the member's key does not
     * reproduce, or a current team key that is not the vault's. Everything the member cannot check -- an
     * epoch with no stored check (made before the checks existed, or while the server was rolled back), an
     * older team epoch, an answer from an older server -- is written as it always was.
     *
     * @returns {Promise<{verdict: string, finding?: string}>}
     */
    async function writeVerdict(lib, opts) {
        const o = opts || {};
        if (o.mode === 'hierarchical') {
            if (!o.isCurrent || o.teamKeyMatches === null || o.teamKeyMatches === undefined) {
                return { verdict: WRITE_UNCHECKED };
            }
            return o.teamKeyMatches === true ? { verdict: WRITE_OK }
                                             : { verdict: WRITE_MISMATCH, finding: 'team_key' };
        }
        const view = o.view;
        if (!view || view.state !== 'set' || typeof view.dek_check !== 'string' || !view.dek_check) {
            return { verdict: WRITE_UNCHECKED };
        }
        const mine = await lib.dekCheck(o.dek, o.vaultId, o.epoch);
        return _b64Equal(mine, view.dek_check) ? { verdict: WRITE_OK }
                                                : { verdict: WRITE_MISMATCH, finding: 'dek_check' };
    }

    /**
     * The lineage of the vault's current epoch: was it made by someone who held the previous key?
     *
     * opts: {mode, vaultId, epoch (the current DEK epoch),
     *        view (the current epoch's key_proof), prevDek (the previous epoch's DEK, or null when this
     *        member does not hold it), direct: nothing more; hierarchical: {teamEpoch (the team epoch the
     *        current DEK is wrapped under), teamPublicKeyPem (the vault's team public key), teamWrap (the
     *        base64 team DEK wrap of the current epoch)}}
     *
     * @returns {Promise<string>} one of verified, not-verifiable, reset-by-owner, failed, first
     */
    async function lineageState(lib, opts) {
        const o = opts || {};
        const epoch = Number(o.epoch) || 1;
        if (epoch <= 1) return LINEAGE_FIRST;
        const view = o.view;
        // No row: the epoch was made before the checks existed, while the server was rolled back, or by a
        // request accepted without a proof. Set up afterwards (a bootstrap) it has no tag by design.
        const hasRow = !!view && (o.mode === 'hierarchical' ? !!view.source : view.state === 'set');
        if (!hasRow || view.source === 'bootstrap') return LINEAGE_UNVERIFIABLE;
        const tag = view.lineage_tag;
        if (!tag) {
            // An owner's reset without a tag: the owner could not open the previous key. Anything else
            // made by a rotation should carry one, and a missing one is not a pass.
            return view.source === 'owner_reset' ? LINEAGE_RESET : LINEAGE_FAILED;
        }
        if (view.source !== 'rotate' && view.source !== 'owner_reset') return LINEAGE_FAILED;
        if (!o.prevDek) return LINEAGE_UNVERIFIABLE;     // joined later: never held the previous key
        const fields = o.mode === 'hierarchical'
            ? { vaultId: o.vaultId, prevEpoch: epoch - 1, mode: 'hierarchical', nextTeamEpoch: o.teamEpoch,
                nextVerifierPem: o.teamPublicKeyPem, nextTeamWrap: o.teamWrap }
            : { vaultId: o.vaultId, prevEpoch: epoch - 1, mode: 'direct', nextTeamEpoch: 1,
                nextVerifierPem: view.public_key, nextDekCheck: view.dek_check };
        const ok = await lib.verifyKeyLineageTag(o.prevDek, fields, tag);
        return ok ? LINEAGE_VERIFIED : LINEAGE_FAILED;
    }

    // What the key details say for each lineage state, and the report finding each failure files.
    const LINEAGE_TEXT = {
        [LINEAGE_VERIFIED]: 'This key was made by someone who held the previous key.',
        [LINEAGE_UNVERIFIABLE]: 'Who made this key cannot be checked here: you did not hold the previous '
            + 'key, or the key was made before this check existed.',
        [LINEAGE_RESET]: "The owner reset this vault's key without the previous one.",
        [LINEAGE_FAILED]: 'This key could not be traced to someone who held the previous key. It may have '
            + 'been changed by someone who should not have been able to. The owner has been told.',
        [LINEAGE_FIRST]: "This is the vault's first key.",
    };

    return {
        WRITE_OK, WRITE_MISMATCH, WRITE_UNCHECKED,
        LINEAGE_VERIFIED, LINEAGE_UNVERIFIABLE, LINEAGE_RESET, LINEAGE_FAILED, LINEAGE_FIRST,
        LINEAGE_TEXT,
        teamKeyAnswer, writeVerdict, lineageState,
    };
})();

if (typeof module !== 'undefined' && module.exports) {
    module.exports = ZkKeyChecks;
}
