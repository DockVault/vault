"""Hierarchical zero-knowledge key wrapping (VaultTeamKey, Increment 2).

HTTP-level contracts for the hierarchical /ecc surface. As in test_zk_dek_rotation.py the
wraps are OPAQUE STUBS (the server stores them verbatim and never unwraps) — the real ECDH/
pkcs8 crypto round-trip is the browser's job. These tests lock down the SERVER behavior that
the v2 design review flagged as security-critical:

  * create hierarchical -> team columns set + owner TEAMPRIV row @ team epoch 1;
  * GET /keys returns the TWO-AXIS descriptor (DEK wrap @ dek epoch + team-priv wrap @ team epoch);
  * grant is O(1): one TEAMPRIV row, the DEK map is untouched, the team epoch is unchanged;
  * ROUTINE rotation bumps dek_version ONLY, writes no TEAMPRIV rows, and members still read the
    new epoch (the v1 lockout bug this design fixes);
  * TEAM-member revoke ROTATES the team keypair (new team_public_key, exactly-remaining TEAMPRIV
    set @ team epoch+1, revoked member cut off at every epoch); the cheap DEK-only path is
    REJECTED (400) for a team-member revoke;
  * owner guards (no-revoke-owner, owner-in-set); 409 on stale from_version;
  * retire-version is two-axis (drops stale DEK epochs + stale TEAMPRIV rows by their OWN floors);
  * direct vaults are entirely unaffected (back-compat).
"""
import contextlib
import os
import subprocess
import uuid

import pytest

from conftest import unique, ensure_ecc_keypair, ApiClient


@contextlib.contextmanager
def _zk_enabled(admin):
    admin.put("/settings", json={"zero_knowledge_enabled": True})
    try:
        yield
    finally:
        admin.put("/settings", json={"zero_knowledge_enabled": False})


def _stub(prefix="w"):
    import base64
    return base64.b64encode(f"{prefix}-{uuid.uuid4().hex}".encode()).decode()


def _create_hier_vault(admin):
    """Create a hierarchical ZK vault with opaque stub wraps (server stores them verbatim)."""
    ensure_ecc_keypair(admin)
    r = admin.post("/vaults", json={
        "name": unique("hteam"),
        "type": "zero_knowledge",
        "key_wrapping_mode": "hierarchical",
        "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
        "team_wrapped_dek": _stub("tdek"),
        "team_dek_ephemeral_public_key": _stub("teph"),
        "wrapped_team_privkey": _stub("tpriv"),
        "team_privkey_ephemeral_public_key": _stub("tpeph"),
    })
    r.raise_for_status()
    return r.json()


def _grant_team(admin, vid, target_id, target_client):
    """Hierarchical share: wrap the team privkey to the target (TEAMPRIV) + grant authz."""
    ensure_ecc_keypair(target_client)
    r = admin.post(f"/ecc/vaults/{vid}/members", json={
        "user_id": str(target_id),
        "wrapped_team_privkey": _stub("tpriv"),
        "team_ephemeral_public_key": _stub("tpeph"),
    })
    r.raise_for_status()
    r = admin.post(f"/vaults/{vid}/permissions", json={"user_id": str(target_id), "level": "read"})
    r.raise_for_status()


def _routine_rotate(admin, vid, frm):
    """Routine O(1) DEK rotation: new DEK wrapped to the SAME team pubkey, no member_keys."""
    return admin.post(f"/ecc/vaults/{vid}/rekey", json={
        "from_version": frm, "to_version": frm + 1, "revoke_user_id": None,
        "member_keys": [],
        "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
    })


def _team_rotate(admin, vid, frm, revoke_user_id, member_ids):
    """Team-keypair rotation (forward-secret revoke): NEW team pubkey + TEAMPRIV for each remaining."""
    return admin.post(f"/ecc/vaults/{vid}/rekey", json={
        "from_version": frm, "to_version": frm + 1, "revoke_user_id": revoke_user_id,
        "member_keys": [{"user_id": str(u), "wrapped_dek": _stub("tpriv"),
                         "ephemeral_public_key": _stub("tpeph")} for u in member_ids],
        "team_public_key": "TEAMPUB-" + uuid.uuid4().hex,
        "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
    })


# --- create + read (two-axis descriptor) -------------------------------------

def test_create_hierarchical_sets_team_columns_and_owner_teampriv(admin):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        keys = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["mode"] == "hierarchical"
        assert keys["has_access"] is True
        assert keys["current_dek_version"] == 1
        assert keys["key_version"] == 1               # DEK epoch
        assert keys["team_key_version"] == 1          # team-keypair epoch
        assert keys["team_public_key"]                # the team pubkey is served
        assert keys["wrapped_dek"]                    # DEK wrapped to the team pubkey
        assert keys["wrapped_team_privkey"]           # owner's wrap of the team privkey
        assert keys["team_ephemeral_public_key"]
    finally:
        admin.delete_vault(vid)


# --- grant is O(1) -----------------------------------------------------------

def test_grant_is_o1_one_teampriv_row_dek_untouched(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        # The new member reads via the team path at team epoch 1, DEK epoch 1.
        keys = temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["has_access"] is True and keys["mode"] == "hierarchical"
        assert keys["team_key_version"] == 1 and keys["current_dek_version"] == 1
        # Grant did NOT rotate the DEK or the team key.
        owner_keys = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert owner_keys["current_dek_version"] == 1 and owner_keys["team_key_version"] == 1
    finally:
        admin.delete_vault(vid)


# --- routine rotation: bumps dek_version only, members still read (v1 killer) -

def test_routine_rotation_keeps_members_readable(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        r = _routine_rotate(admin, vid, 1)
        assert r.status_code == 200, r.text
        body = r.json()
        assert body["dek_version"] == 2 and body["team_key_version"] == 1  # team epoch UNCHANGED

        # Both members can still read the NEW DEK epoch (their team-priv @ epoch 1 still unwraps
        # the new DEK, which was wrapped to the unchanged team pubkey). This is the lockout bug
        # the two-axis model fixes.
        for c in (admin, temp_user_client):
            cur = c.get(f"/ecc/vaults/{vid}/keys").json()
            assert cur["has_access"] is True and cur["current_dek_version"] == 2
            assert cur["key_version"] == 2 and cur["team_key_version"] == 1
        # And the OLD DEK epoch is still readable too.
        old = admin.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()
        assert old["has_access"] is True and old["key_version"] == 1
    finally:
        admin.delete_vault(vid)


# --- team-member revoke rotates the team keypair -----------------------------

def test_team_revoke_rotates_team_keypair_and_cuts_off_member(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True

        r = _team_rotate(admin, vid, 1, str(temp_user["id"]), [admin.user["id"]])
        assert r.status_code == 200, r.text
        assert r.json()["dek_version"] == 2 and r.json()["team_key_version"] == 2

        # Revoked member: no access at any epoch (TEAMPRIV deactivated everywhere).
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys?key_version=1").json()["has_access"] is False
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys?key_version=2").json()["has_access"] is False
        # Owner keeps access at the new team epoch.
        owner = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert owner["has_access"] is True and owner["team_key_version"] == 2
    finally:
        admin.delete_vault(vid)


def test_cheap_dek_only_rotation_rejected_for_team_member_revoke(admin, temp_user, temp_user_client):
    """The central forward-secrecy gate: revoking a TEAM member via a DEK-only (no new
    team_public_key) rotation must be rejected — the revoked member's old team-priv would still
    unwrap the new DEK."""
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        r = admin.post(f"/ecc/vaults/{vid}/rekey", json={
            "from_version": 1, "to_version": 2, "revoke_user_id": str(temp_user["id"]),
            "member_keys": [],  # cheap path: no team rotation
            "team_dek_wrapped": _stub("tdek"), "team_dek_ephemeral_public_key": _stub("teph"),
        })
        assert r.status_code == 400, r.text
        # No mutation.
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["current_dek_version"] == 1
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is True
    finally:
        admin.delete_vault(vid)


def test_bare_revoke_forces_team_rotation_before_next_rekey(admin, temp_user, temp_user_client):
    """Forward-secrecy gap fix: a bare revoke (DELETE /permissions) deactivates a team member's
    TEAMPRIV without rotating the team keypair. The server must then REFUSE a cheap DEK-only
    rotation (which would re-grant them via the unchanged team pubkey) until a real team-keypair
    rotation — even though the revoke didn't go through /rekey."""
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        # Bare revoke (NOT via /rekey): removes authz + deactivates the member's TEAMPRIV.
        assert admin.delete(f"/vaults/{vid}/permissions/{temp_user['id']}").status_code == 200
        # The removed member already has no server access.
        assert temp_user_client.get(f"/ecc/vaults/{vid}/keys").json()["has_access"] is False
        # A cheap routine rotation is now REFUSED (a team rotation is owed).
        r = _routine_rotate(admin, vid, 1)
        assert r.status_code == 400, r.text
        # A proper team-keypair rotation is accepted and clears the owed state.
        r2 = _team_rotate(admin, vid, 1, None, [admin.user["id"]])
        assert r2.status_code == 200, r2.text
        assert r2.json()["team_key_version"] == 2
        # Routine rotation works again now the owed state is cleared.
        assert _routine_rotate(admin, vid, 2).status_code == 200
    finally:
        admin.delete_vault(vid)


# --- owner guards + optimistic lock ------------------------------------------

def test_cannot_revoke_owner(admin):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        r = _team_rotate(admin, vid, 1, admin.user["id"], [admin.user["id"]])
        assert r.status_code == 400, r.text
    finally:
        admin.delete_vault(vid)


def test_team_rotation_requires_owner_in_set(admin, temp_user, temp_user_client):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        _grant_team(admin, vid, temp_user["id"], temp_user_client)
        # Revoke nobody but supply ONLY temp_user (owner omitted) -> must be rejected (owner
        # would be locked out, and the remaining set wouldn't match either).
        r = _team_rotate(admin, vid, 1, None, [temp_user["id"]])
        assert r.status_code == 400, r.text
        assert admin.get(f"/ecc/vaults/{vid}/keys").json()["team_key_version"] == 1
    finally:
        admin.delete_vault(vid)


def test_rekey_rejects_stale_from_version(admin):
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        r = _routine_rotate(admin, vid, 5)  # current is 1
        assert r.status_code == 409, r.text
    finally:
        admin.delete_vault(vid)


# --- retire-version is two-axis ----------------------------------------------

def test_retire_version_two_axis(admin):
    """After two routine rotations and no files, retire drops the stale DEK map epochs but keeps
    the single (unchanged) team epoch's TEAMPRIV rows — nobody is locked out."""
    with _zk_enabled(admin):
        v = _create_hier_vault(admin)
    vid = v["id"]
    try:
        assert _routine_rotate(admin, vid, 1).status_code == 200
        assert _routine_rotate(admin, vid, 2).status_code == 200  # dek_version now 3, team epoch 1
        r = admin.post(f"/ecc/vaults/{vid}/retire-version")
        assert r.status_code == 200, r.text
        body = r.json()
        assert "retired_team_below" in body and "retired_dek_below" in body
        # The owner can STILL read the current epoch (their team-priv @ epoch 1 survived retire).
        cur = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert cur["has_access"] is True and cur["current_dek_version"] == 3 and cur["team_key_version"] == 1
    finally:
        admin.delete_vault(vid)


# --- back-compat: direct vaults are unaffected -------------------------------

def test_direct_vault_unaffected(admin):
    """A plain (direct) ZK vault still reports mode='direct' and carries no team fields."""
    ensure_ecc_keypair(admin)
    with _zk_enabled(admin):
        r = admin.post("/vaults", json={
            "name": unique("hdirect"), "type": "zero_knowledge",
            "wrapped_dek": _stub("dek"), "ephemeral_public_key": _stub("eph"),
        })
        r.raise_for_status()
    vid = r.json()["id"]
    try:
        keys = admin.get(f"/ecc/vaults/{vid}/keys").json()
        assert keys["mode"] == "direct" and keys["has_access"] is True
        assert keys.get("team_public_key") is None and keys.get("wrapped_team_privkey") is None
    finally:
        admin.delete_vault(vid)


# --- browser crypto round-trip (real ecc_crypto.js under Node) ----------------
# The HTTP tests above use opaque stub wraps. This proves the NEW primitives actually work
# end-to-end: wrap the DEK to the team pubkey, wrap the team privkey to a member, then a member
# recovers team-priv -> DEK and decrypts a blob — AND the two blob types are NOT interchangeable
# (domain separation: a team-priv blob can't be unwrapped as a DEK, or vice-versa).
_NODE_HIER = r'''
const { webcrypto } = require('crypto');
global.window = { crypto: webcrypto };
console.log = () => {};  // the lib logs progress to stdout; keep stdout to our JSON result only
const ECC = require(process.env.ECC_JS);
(async () => {
  const lib = new ECC();
  const member = await lib.generateKeypair();
  const team = await lib.generateKeypair();
  const dek = await lib.generateVaultDEK();
  const dekWrap = await lib.wrapVaultDEK(dek, team.publicKey);                       // DEK -> team pubkey
  const privWrap = await lib.wrapPrivateKeyToPublic(team.privateKey, member.publicKey); // team priv -> member
  const recoveredTeamPriv = await lib.unwrapPrivateKeyFromWrapped(
      privWrap.wrappedKey, privWrap.ephemeralPublicKey, member.privateKey, false);
  const recoveredDek = await lib.unwrapVaultDEK(
      dekWrap.wrappedDEK, dekWrap.ephemeralPublicKey, recoveredTeamPriv);
  const msg = new TextEncoder().encode('hierarchical round-trip ok');
  const ct = await lib.encryptFile(msg, dek);
  const pt = await lib.decryptFile(ct, recoveredDek);
  const roundtrip = Buffer.from(new Uint8Array(pt)).toString() === 'hierarchical round-trip ok';
  // Domain separation — each must REJECT the other's blob (different HKDF info / AES-KW vs GCM).
  let sepA = false, sepB = false;
  try { await lib.unwrapVaultDEK(privWrap.wrappedKey, privWrap.ephemeralPublicKey, member.privateKey); }
  catch (e) { sepA = true; }
  try { await lib.unwrapPrivateKeyFromWrapped(dekWrap.wrappedDEK, dekWrap.ephemeralPublicKey, team.privateKey, false); }
  catch (e) { sepB = true; }
  process.stdout.write(JSON.stringify({ roundtrip, sepA, sepB }));
})().catch(e => { console.error(e); process.exit(1); });
'''


def test_hierarchical_browser_crypto_roundtrip():
    """Real ecc_crypto.js (under Node): team-priv wrap/unwrap + the two-level DEK unwrap round-trip,
    and the two blob types are not interchangeable. Skips if node is unavailable."""
    import shutil as _shutil
    from pathlib import Path as _Path
    node = _shutil.which("node")
    if not node:
        pytest.skip("node unavailable for hierarchical crypto round-trip")
    ecc_js = str((_Path(__file__).resolve().parent.parent / "static" / "js" / "ecc_crypto.js")).replace("\\", "/")
    proc = subprocess.run([node, "-"], input=_NODE_HIER, capture_output=True, text=True,
                          encoding="utf-8", env={**os.environ, "ECC_JS": ecc_js}, timeout=30)
    assert proc.returncode == 0, f"node hierarchical script failed: {proc.stderr}"
    import json as _json
    out = _json.loads(proc.stdout)
    assert out["roundtrip"] is True, "team-priv -> DEK two-level unwrap did not round-trip"
    assert out["sepA"] is True, "a team-priv blob was wrongly accepted by the DEK unwrap path"
    assert out["sepB"] is True, "a DEK blob was wrongly accepted by the team-priv unwrap path"
