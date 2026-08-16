"""The two team constructions: a DEK wrapped to a vault's team key, and that team key wrapped to a
member.

Both bind less than the direct wrap does, and the grammar says why: of the two fields worth adding,
one cannot be recovered when reading and the other cannot be known when writing. What they do bind
is the vault — and, for the team DEK, the data-key epoch, which is a different column from the team
epoch and is the one a client proposes and the server verifies.

Two things here are easy to get wrong and invisible when you do.

**The recipient, on the share path.** Reading the team key opens a wrap made for the person doing
the sharing; writing it makes one for the person being shared with. Those are two different accounts
named three lines apart, and swapping them fails as an authentication error indistinguishable from
tampering.

**Which purpose a reader will accept.** Both DEK wraps are the same size, so length cannot tell them
apart — only the caller's expectation can. A reader that took the purpose off the wire to choose its
transcript would satisfy every other rule here and lose the property the whole family exists for.

Everything runs the real shipped module under Node, so what is tested is the file the browser gets.
"""

import json
import subprocess
from pathlib import Path

import pytest

from app_source import bound_value, call_text, positional_arg

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"


def _node(script: str) -> dict:
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
console.error = () => {{}};
const codeOf = async fn => {{
  try {{ await fn(); return null; }} catch (e) {{ return e && e.code ? e.code : 'UNCODED'; }}
}};
(async () => {{
  const lib = new ECCCryptoLibrary();
  const VAULT = '11111111-2222-4333-8444-555555555555';
  const OTHERV = '99999999-8888-4777-8666-555555555555';
  const MEMBER = '66666666-7777-4888-8999-aaaaaaaaaaaa';
  const OTHERU = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
  const teamKp = await webcrypto.subtle.generateKey(
      {{ name: 'ECDH', namedCurve: 'P-384' }}, true, ['deriveBits']);
  const memberKp = await webcrypto.subtle.generateKey(
      {{ name: 'ECDH', namedCurve: 'P-384' }}, true, ['deriveBits']);
  const dek = await webcrypto.subtle.generateKey(
      {{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  const dekCtx = {{ vaultId: VAULT, dekEpoch: 3, teamMode: true }};
  const privCtx = {{ vaultId: VAULT, recipientUserId: MEMBER }};
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + e.stack); process.exit(1); }});
"""
    proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True,
                          timeout=300, cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


# =================================================================================================
# Round trips
# =================================================================================================

def test_a_team_dek_wrap_round_trips_at_the_specified_size():
    out = _node("""
  const w = await lib.wrapTeamDEKV2(dek, teamKp.publicKey, dekCtx);
  const b = Buffer.from(w.wrappedDEK, 'base64');
  const back = await lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, teamKp.privateKey, dekCtx);
  const got = Buffer.from(await webcrypto.subtle.exportKey('raw', back));
  const want = Buffer.from(await webcrypto.subtle.exportKey('raw', dek));
  console.log(JSON.stringify({
    length: b.length, magic: b.slice(0, 4).toString('ascii'),
    version: b[4], purpose: b[5], reserved: b[6] * 256 + b[7],
    roundTripped: got.equals(want),
  }));
""")
    assert out["length"] == 68
    assert out["magic"] == "DVZ2" and out["version"] == 0x02
    assert out["purpose"] == 0x02, "a team DEK wrap must not claim the direct purpose"
    assert out["reserved"] == 0
    assert out["roundTripped"] is True


def test_a_team_private_wrap_round_trips_and_is_not_fixed_length():
    out = _node("""
  const w = await lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, privCtx);
  const b = Buffer.from(w.wrappedKey, 'base64');
  const back = await lib.unwrapPrivateKeyFromWrapped(
      w.wrappedKey, w.ephemeralPublicKey, memberKp.privateKey, false, privCtx);
  // Prove it is the same key by agreeing with it and with the original.
  const eph = await webcrypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
  const viaBack = Buffer.from(await webcrypto.subtle.deriveBits(
      { name: 'ECDH', public: eph.publicKey }, back, 384));
  const viaOrig = Buffer.from(await webcrypto.subtle.deriveBits(
      { name: 'ECDH', public: eph.publicKey }, teamKp.privateKey, 384));
  // The share path legitimately needs an exportable copy to re-wrap for a new member, so the
  // flag is the caller's. Read it both ways, so this pins that the flag is HONOURED rather than
  // merely that the default happens to be false.
  const exportable = await lib.unwrapPrivateKeyFromWrapped(
      w.wrappedKey, w.ephemeralPublicKey, memberKp.privateKey, true, privCtx);
  console.log(JSON.stringify({
    length: b.length, purpose: b[5], sameKey: viaBack.equals(viaOrig),
    extractable: back.extractable, usages: back.usages,
    exportableWhenAsked: exportable.extractable, exportableUsages: exportable.usages,
  }));
""")
    assert out["purpose"] == 0x03
    assert out["length"] != 68, "this payload must not be fixed-length; length cannot discriminate it"
    assert out["sameKey"] is True
    # Non-extractable unless a caller asks otherwise, and key agreement either way. The usages are
    # the part that is never negotiable: this key must never be able to sign or wrap anything.
    assert out["extractable"] is False
    assert out["exportableWhenAsked"] is True
    assert out["usages"] == ["deriveBits"]
    assert out["exportableUsages"] == ["deriveBits"]


# =================================================================================================
# Every bound field must actually bind
# =================================================================================================

@pytest.mark.parametrize("field,label", [
    ("vaultId: OTHERV", "wrong vault"),
    ("dekEpoch: 4", "wrong epoch"),
])
def test_the_team_dek_transcript_binds_what_it_claims(field, label):
    out = _node("""
  const w = await lib.wrapTeamDEKV2(dek, teamKp.publicKey, dekCtx);
  const bad = Object.assign({}, dekCtx, { %s });
  console.log(JSON.stringify({ code: await codeOf(() =>
    lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, teamKp.privateKey, bad)) }));
""" % field)
    assert out["code"] == "WRAP_FAILED", f"{label} did not break the unwrap"


@pytest.mark.parametrize("field,label", [
    ("vaultId: OTHERV", "wrong vault"),
    ("recipientUserId: OTHERU", "wrong recipient"),
])
def test_the_team_private_transcript_binds_what_it_claims(field, label):
    out = _node("""
  const w = await lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, privCtx);
  const bad = Object.assign({}, privCtx, { %s });
  console.log(JSON.stringify({ code: await codeOf(() =>
    lib.unwrapPrivateKeyFromWrapped(w.wrappedKey, w.ephemeralPublicKey,
                                    memberKp.privateKey, false, bad)) }));
""" % field)
    assert out["code"] == "WRAP_FAILED", f"{label} did not break the unwrap"


# =================================================================================================
# The three constructions must be mutually unreadable
# =================================================================================================

def test_no_construction_can_be_read_as_another():
    """The confusion this whole family exists to prevent.

    A direct wrap fed to the team reader, a team wrap fed to the direct reader, and a DEK wrap fed
    to the private-key reader must all fail. The purpose byte and the distinct labels are what make
    that true; either alone would leave a gap.
    """
    out = _node("""
  const direct = await lib.wrapVaultDEKV2(dek, memberKp.publicKey,
      { vaultId: VAULT, recipientUserId: MEMBER, dekEpoch: 3 });
  const teamDek = await lib.wrapTeamDEKV2(dek, teamKp.publicKey, dekCtx);
  const teamPriv = await lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, privCtx);
  console.log(JSON.stringify({
    directAsTeam: await codeOf(() =>
      lib.unwrapVaultDEK(direct.wrappedDEK, direct.ephemeralPublicKey, memberKp.privateKey, dekCtx)),
    teamAsDirect: await codeOf(() =>
      lib.unwrapVaultDEK(teamDek.wrappedDEK, teamDek.ephemeralPublicKey, teamKp.privateKey,
                         { vaultId: VAULT, recipientUserId: MEMBER, dekEpoch: 3 })),
    dekAsPrivate: await codeOf(() =>
      lib.unwrapPrivateKeyFromWrapped(teamDek.wrappedDEK, teamDek.ephemeralPublicKey,
                                      memberKp.privateKey, false, privCtx)),
    privateAsDek: await codeOf(() =>
      lib.unwrapVaultDEK(teamPriv.wrappedKey, teamPriv.ephemeralPublicKey,
                         memberKp.privateKey, dekCtx)),
  }));
""")
    for key, code in out.items():
        assert code in ("WRAP_UNSUPPORTED", "WRAP_INVALID", "WRAP_FAILED"), f"{key} was {code}"
        assert code != "UNCODED", f"{key} escaped the error boundary"


def test_the_reader_never_takes_the_purpose_off_the_wire():
    """Relabelling a team wrap as direct must not make a direct reader accept it.

    If a reader chose its transcript from the byte it found, this would steer a payload into the
    wrong reader — which is the attack the header's authentication is meant to deny, and the reason
    the expected purpose is the caller's statement rather than the payload's.
    """
    out = _node("""
  const teamDek = await lib.wrapTeamDEKV2(dek, teamKp.publicKey, dekCtx);
  const relabelled = Buffer.from(teamDek.wrappedDEK, 'base64');
  relabelled[5] = 0x01;  // claim to be a direct wrap
  console.log(JSON.stringify({
    // Read with a TEAM context: everything else about the payload is right, so the only thing
    // that can reject it is the purpose comparison itself. Reading it with a direct context
    // would fail too -- but on the tag, which proves the transcript works and says nothing at
    // all about whether the purpose is compared. Demonstrated: deleting the purpose check left
    // that version of this test green.
    code: await codeOf(() => lib.unwrapVaultDEK(relabelled.toString('base64'),
      teamDek.ephemeralPublicKey, teamKp.privateKey, dekCtx)),
  }));
""")
    assert out["code"] == "WRAP_UNSUPPORTED", (
        "a payload relabelled to a purpose this caller did not ask for was not refused on that "
        "ground -- the purpose is being taken off the wire, or not compared at all"
    )


def test_a_future_version_is_refused_on_both_team_readers():
    out = _node("""
  const teamDek = await lib.wrapTeamDEKV2(dek, teamKp.publicKey, dekCtx);
  const teamPriv = await lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, privCtx);
  const bumpDek = Buffer.from(teamDek.wrappedDEK, 'base64'); bumpDek[4] = 0x03;
  const bumpPriv = Buffer.from(teamPriv.wrappedKey, 'base64'); bumpPriv[4] = 0x03;
  console.log(JSON.stringify({
    dekV3: await codeOf(() => lib.unwrapVaultDEK(bumpDek.toString('base64'),
      teamDek.ephemeralPublicKey, teamKp.privateKey, dekCtx)),
    privV3: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(bumpPriv.toString('base64'),
      teamPriv.ephemeralPublicKey, memberKp.privateKey, false, privCtx)),
  }));
""")
    assert out["dekV3"] == "WRAP_UNSUPPORTED"
    assert out["privV3"] == "WRAP_UNSUPPORTED"


def test_structural_faults_are_not_reported_as_tampering():
    out = _node("""
  const w = await lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, privCtx);
  const b = Buffer.from(w.wrappedKey, 'base64');
  const reserved = Buffer.from(b); reserved[6] = 0xAA;
  const tooShort = Buffer.from(b.slice(0, 35));
  const tooLong = Buffer.concat([b, Buffer.alloc(9000)]);
  console.log(JSON.stringify({
    reservedSet: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(reserved.toString('base64'),
      w.ephemeralPublicKey, memberKp.privateKey, false, privCtx)),
    belowFloor: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(tooShort.toString('base64'),
      w.ephemeralPublicKey, memberKp.privateKey, false, privCtx)),
    aboveCeiling: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(tooLong.toString('base64'),
      w.ephemeralPublicKey, memberKp.privateKey, false, privCtx)),
    noContext: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(w.wrappedKey,
      w.ephemeralPublicKey, memberKp.privateKey, false, null)),
    badEpoch: await codeOf(() => lib.wrapTeamDEKV2(dek, teamKp.publicKey,
      Object.assign({}, dekCtx, { dekEpoch: 0 }))),
  }));
""")
    for key, code in out.items():
        assert code == "WRAP_INVALID", f"{key} was reported as {code}, not a structural fault"


# =================================================================================================
# Legacy must keep working, byte for byte
# =================================================================================================

def test_the_legacy_team_pair_is_untouched():
    """These two write the shipped format and their bytes must not move.

    Both are reached from the choke points whenever the newer writer is off, and every existing
    stored wrap depends on the reader half continuing to behave exactly as it does.
    """
    source = CRYPTO_JS.read_text(encoding="utf-8")
    for name in ("wrapPrivateKeyToPublic", "unwrapPrivateKeyFromWrapped", "wrapVaultDEK"):
        assert f"async {name}(" in source, f"{name} disappeared"
    after = source.split("    async wrapPrivateKeyToPublic(", 1)[1]
    body = after.split("\n    }", 1)[0]
    assert 0 < len(body) < 2000, "the slice did not land on a single method body"
    assert "V2_" not in body, "the legacy team writer grew a version-2 branch"


def test_a_legacy_team_private_wrap_still_opens():
    out = _node("""
  const w = await lib.wrapPrivateKeyToPublic(teamKp.privateKey, memberKp.publicKey);
  const back = await lib.unwrapPrivateKeyFromWrapped(
      w.wrappedKey, w.ephemeralPublicKey, memberKp.privateKey, false, privCtx);
  console.log(JSON.stringify({ ok: !!back, usages: back.usages }));
""")
    assert out["ok"] is True
    assert out["usages"] == ["deriveBits"]


# =================================================================================================
# The call sites
# =================================================================================================

def test_one_place_decides_each_format():
    """Three constructions, three choke points, each consulting the gate exactly once.

    A fourth write site added later inherits the decision instead of having to remember it — and
    forgetting is not a visible bug, it just quietly keeps writing the old format.
    """
    source = APP_JS.read_text(encoding="utf-8")
    assert source.count("lib.ZK_WRAP_WRITE_V2") == 3
    for fn in ("zkWrapDekForRecipient", "zkWrapTeamDek", "zkWrapTeamPrivateKey"):
        assert f"async function {fn}(" in source


def test_the_share_path_uses_the_right_account_at_each_end():
    """The read names the sharer; the write names the recipient. Adjacent, and easy to swap."""
    source = APP_JS.read_text(encoding="utf-8")
    share = source.split("async function zkShareVaultToUser(", 1)[1].split("\n}", 1)[0]
    read_at = share.index("unwrapPrivateKeyFromWrapped(")
    write_at = share.index("zkWrapTeamPrivateKey(")
    assert read_at < write_at

    # Slice each call, not the rest of the function. An earlier version of this test asserted the
    # write's id appeared "somewhere after" the write -- which the direct branch further down
    # satisfies, so the swap it exists to catch could be made with every test still passing. That
    # was demonstrated by mutation, not guessed.
    read_call = share[read_at:share.index(";", read_at)]
    write_call = share[write_at:share.index(";", write_at)]

    assert bound_value(read_call, "recipientUserId") == "keys.recipient_user_id", (
        f"the read must name the account the server says the wrap was made for: {read_call}"
    )
    assert "recipientUserId: userId" in write_call, (
        f"the write must name the person being shared with: {write_call}"
    )
    # And they must not be the same expression, which is the whole hazard.
    assert "keys.recipient_user_id" not in write_call, (
        "the write is naming the sharer instead of the recipient"
    )


def test_every_team_write_site_binds_the_right_values():
    """The gated team sites -- the VALUES, exactly, not a substring of them.

    This test was written after four wrong values passed the whole suite. It caught those four and
    then let their near neighbours through, because it asked whether the call CONTAINED the right
    text: `"dekEpoch: 1"` is also true of `dekEpoch: 10`, `recipientUserId: uid` of
    `recipientUserId: uidBeingRemoved`, `vaultId: payload.id` of `vaultId: payload.idOther`. The
    same flaw was found in the direct wrap's equivalent by review and fixed there; this is the
    sibling, fixed the same way and sharing the same reader so the two cannot drift.

    What makes these worth checking at all: none of these lines runs while the writer is gated off,
    so a wrong value ships quietly and produces a vault that opens for nobody.
    """
    source = APP_JS.read_text(encoding="utf-8")

    # Creation. The team DEK wrap binds the vault and the epoch -- epoch 1, because the vault is
    # new -- and binds no recipient at all: one wrap serves every member, which is the point of the
    # hierarchical mode.
    create_dek, i = call_text(source, "zkWrapTeamDek(")
    assert bound_value(create_dek, "vaultId") == "payload.id", bound_value(create_dek, "vaultId")
    assert bound_value(create_dek, "dekEpoch") == "1", bound_value(create_dek, "dekEpoch")
    # The TEAM public key, because that is what a team DEK is sealed to. Sealing it to the
    # creator's own key instead makes a vault only its creator can open, which is the opposite of
    # what the hierarchical mode is for -- and the transcript would be identical either way.
    assert positional_arg(create_dek, 1) == "teamKp.publicKey", positional_arg(create_dek, 1)

    # The team PRIVATE key wrap binds the vault and the recipient, and no epoch: the only epoch
    # that would mean anything here is the team keypair's, which the server assigns.
    create_priv, p = call_text(source, "zkWrapTeamPrivateKey(")
    assert bound_value(create_priv, "vaultId") == "payload.id", bound_value(create_priv, "vaultId")
    assert bound_value(create_priv, "recipientUserId") == "myUserId", (
        bound_value(create_priv, "recipientUserId"))
    assert positional_arg(create_priv, 0) == "teamKp.privateKey", positional_arg(create_priv, 0)
    assert positional_arg(create_priv, 1) == "myPub", positional_arg(create_priv, 1)

    # Rotation. The server stores the wrap under to_version, which is fromVersion + 1; stamping the
    # epoch being replaced labels every re-wrap as the key it supersedes.
    rot_dek, j = call_text(source, "zkWrapTeamDek(", i + 1)
    assert bound_value(rot_dek, "dekEpoch") == "fromVersion + 1", bound_value(rot_dek, "dekEpoch")
    # Asserted here because every other site asserts it and this one did not: a rotation stamped
    # with another vault's id re-wraps the key to a transcript no member of THIS vault will build.
    assert bound_value(rot_dek, "vaultId") == "vaultId", bound_value(rot_dek, "vaultId")
    assert positional_arg(rot_dek, 1) == "teamKp.publicKey", positional_arg(rot_dek, 1)

    # SHARE. Never asserted before: the earlier version of this test walked two team-private sites
    # and there are three, so the one in the middle -- the share path, which unwraps the team
    # private key with the sharer's identity and re-wraps it to the recipient -- was checked by
    # nothing. Wrapping to the sharer here hands the recipient a key they cannot open.
    share_priv, k = call_text(source, "zkWrapTeamPrivateKey(", p + 1)
    assert bound_value(share_priv, "vaultId") == "vaultId", bound_value(share_priv, "vaultId")
    # Sealed to the RECIPIENT's key. Sealed to the team's own, or to the sharer's, it is a
    # well-formed wrap nobody who needs it can open -- and no transcript check would notice.
    assert positional_arg(share_priv, 0) == "teamPriv", positional_arg(share_priv, 0)
    assert positional_arg(share_priv, 1) == "recipientPub", positional_arg(share_priv, 1)
    assert bound_value(share_priv, "recipientUserId") == "userId", (
        f"the team share wraps the private key to "
        f"{bound_value(share_priv, 'recipientUserId')!r}, not the recipient")

    # And on rotation each member is named by the loop variable. Naming the member being removed
    # would hand the new team private key to exactly the person the rotation exists to exclude.
    rot_priv, _ = call_text(source, "zkWrapTeamPrivateKey(", k + 1)
    assert bound_value(rot_priv, "vaultId") == "vaultId", bound_value(rot_priv, "vaultId")
    assert positional_arg(rot_priv, 0) == "teamKp.privateKey", positional_arg(rot_priv, 0)
    assert positional_arg(rot_priv, 1) == "recipientPub", (
        f"the rotation seals the team private key to {positional_arg(rot_priv, 1)!r}; every "
        "surviving member would hold a wrap no key of theirs can open")
    assert bound_value(rot_priv, "recipientUserId") == "uid", (
        f"the rotation wraps the team private key to "
        f"{bound_value(rot_priv, 'recipientUserId')!r}")


def test_the_number_of_team_write_sites_has_not_changed():
    """The assertions above address these sites by order of appearance."""
    source = APP_JS.read_text(encoding="utf-8")
    assert source.count("await zkWrapTeamDek(") == 2, "the team DEK write sites changed"
    assert source.count("await zkWrapTeamPrivateKey(") == 3, (
        "the team private write sites changed; there are three -- create, share and rotate -- and "
        "an earlier version of these assertions walked only two, leaving the share path unchecked")


def test_a_missing_recipient_is_refused_rather_than_encoded():
    """An absent id would be encoded as nothing and authenticate against nothing.

    The specification names this failure explicitly, and it is what lands if the server ever stops
    echoing the account id -- so it has to be a structural refusal at both ends, not a silent
    empty field.
    """
    out = _node("""
  const w = await lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, privCtx);
  console.log(JSON.stringify({
    readMissing: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(w.wrappedKey,
      w.ephemeralPublicKey, memberKp.privateKey, false, { vaultId: VAULT })),
    readEmpty: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(w.wrappedKey,
      w.ephemeralPublicKey, memberKp.privateKey, false,
      { vaultId: VAULT, recipientUserId: '' })),
    writeMissing: await codeOf(() =>
      lib.wrapTeamPrivateKeyV2(teamKp.privateKey, memberKp.publicKey, { vaultId: VAULT })),
  }));
""")
    for key, code in out.items():
        assert code == "WRAP_INVALID", f"{key} was {code}, not a structural refusal"


def test_the_team_dek_reader_validates_its_header_and_point_too():
    """Covered for the private wrap already; the DEK wrap needs the same, and had none."""
    out = _node("""
  const w = await lib.wrapTeamDEKV2(dek, teamKp.publicKey, dekCtx);
  const reserved = Buffer.from(w.wrappedDEK, 'base64'); reserved[6] = 0xAA;
  const shortPoint = Buffer.from(
      Buffer.from(w.ephemeralPublicKey, 'base64').slice(0, 96));
  console.log(JSON.stringify({
    reservedSet: await codeOf(() => lib.unwrapVaultDEK(reserved.toString('base64'),
      w.ephemeralPublicKey, teamKp.privateKey, dekCtx)),
    shortPoint: await codeOf(() => lib.unwrapVaultDEK(w.wrappedDEK,
      shortPoint.toString('base64'), teamKp.privateKey, dekCtx)),
    wrongLength: await codeOf(() => lib.unwrapVaultDEK(
      Buffer.from(w.wrappedDEK, 'base64').slice(0, 60).toString('base64'),
      w.ephemeralPublicKey, teamKp.privateKey, dekCtx)),
  }));
""")
    for key, code in out.items():
        assert code == "WRAP_INVALID", f"{key} was {code}, not a structural fault"
