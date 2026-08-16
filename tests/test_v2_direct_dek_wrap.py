"""The version-2 direct DEK wrap: reader shipped, writer gated off.

A DEK wrap is minted by one member's browser and read by every other member. That asymmetry is why
the writer is off by default: one person on a build that writes v2, performing one rekey, re-wraps
the key for everybody -- and any member still on an older cached bundle could no longer open the
vault, with nothing on the server able to re-wrap for them. So the reader ships first and alone,
and enabling the writer is a deliberate, reviewable source change.

The round-trips below therefore call the v2 writer DIRECTLY, bypassing the gate rather than
flipping it. Be precise about what that does and does not leave uncovered, because an earlier
version of this note got it wrong in both directions.

The create path IS executed: a browser test drives the real page and creates zero-knowledge
vaults through it, so a name that does not resolve there fails loudly. What no test reaches is
the transcript itself -- with the gate off it is built and then discarded, so a wrong value
inside it is invisible everywhere. A wrong VARIABLE now fails; a wrong VALUE does not.

That distinction matters because the failure it leaves open is the quiet one: a lock stamped
with the wrong thing is not detectably wrong until someone tries to open it, by which time the
key it was made from is gone. Driving the browser lane once with the gate on is what closes
it, and it is worth doing before the gate is ever flipped.

Everything here runs the REAL shipped `ecc_crypto.js` under Node's Web Crypto, so what is under
test is the file the browser is served rather than a reimplementation of it.
"""

import json
import subprocess
from pathlib import Path

import pytest

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
  const USER  = '66666666-7777-4888-8999-aaaaaaaaaaaa';
  const OTHER = 'bbbbbbbb-cccc-4ddd-8eee-ffffffffffff';
  const kp = await webcrypto.subtle.generateKey(
      {{ name: 'ECDH', namedCurve: 'P-384' }}, true, ['deriveBits']);
  const dek = await webcrypto.subtle.generateKey(
      {{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  const ctx = {{ vaultId: VAULT, recipientUserId: USER, dekEpoch: 3 }};
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + e.stack); process.exit(1); }});
"""
    proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True,
                          timeout=300, cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


# =================================================================================================
# The gate
# =================================================================================================

def test_the_v2_writer_is_off_in_source():
    """Pinned as literal source text, matching how the private-key envelope's gate is pinned.

    A runtime read would pass equally against a build that had flipped it, and a flipped gate does
    not show up as a failing test -- it shows up as members locked out after somebody rekeys.
    """
    assert "this.ZK_WRAP_WRITE_V2 = false;" in CRYPTO_JS.read_text(encoding="utf-8")


def test_the_writer_is_a_new_method_not_a_change_to_the_shared_one():
    """The legacy helper also writes the hierarchical team-DEK wraps every existing vault holds.

    Editing it would move bytes on a path this change must leave byte-identical, so the writer
    has to be separate. Pinned because the separation is invisible once the diff is old.
    """
    source = CRYPTO_JS.read_text(encoding="utf-8")
    assert "async wrapVaultDEKV2(" in source
    # Slice the legacy method's OWN body. Splitting forward to `wrapVaultDEKV2` would find
    # nothing, because the v2 method is defined earlier in the file -- the slice would run to
    # the end and the assertion below would be satisfied by unrelated helpers.
    after = source.split("    async wrapVaultDEK(", 1)[1]
    legacy = after.split("\n    }", 1)[0]
    assert 0 < len(legacy) < 2000, "the slice did not land on a single method body"
    assert "AES-KW" in legacy and "_deriveWrappingKey(" in legacy
    assert "V2_" not in legacy, "the legacy writer must not have grown a v2 branch"


def test_the_new_writer_is_registered_with_the_error_boundary():
    """An unregistered public method escapes the boundary and throws with no code at all.

    The table's loop throws at load for a *listed* method that is missing; the reverse -- a real
    method nobody listed -- fails silently, surfacing as an uncoded error that no user-facing
    message can classify.
    """
    source = CRYPTO_JS.read_text(encoding="utf-8")
    table = source.split("const _OPERATION_DEFAULT_CODE", 1)[1].split("});", 1)[0]
    assert "wrapVaultDEKV2:" in table


# =================================================================================================
# Real round-trips, against the shipped module
# =================================================================================================

def test_a_v2_wrap_round_trips_and_is_exactly_the_specified_size():
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const bytes = Buffer.from(w.wrappedDEK, 'base64');
  const back = await lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, kp.privateKey, ctx);
  const raw = Buffer.from(await webcrypto.subtle.exportKey('raw', back));
  const want = Buffer.from(await webcrypto.subtle.exportKey('raw', dek));
  console.log(JSON.stringify({
    length: bytes.length,
    magic: bytes.slice(0, 4).toString('ascii'),
    version: bytes[4], purpose: bytes[5], reserved: bytes[6] * 256 + bytes[7],
    roundTripped: raw.equals(want),
  }));
""")
    assert out["length"] == 68, "8 header + 12 nonce + 32 key + 16 tag"
    assert out["magic"] == "DVZ2"
    assert out["version"] == 0x02 and out["purpose"] == 0x01 and out["reserved"] == 0
    assert out["roundTripped"] is True


@pytest.mark.parametrize("field,label", [
    ("vaultId: OTHER", "wrong vault"),
    ("recipientUserId: OTHER", "wrong recipient"),
    ("dekEpoch: 4", "wrong epoch"),
])
def test_every_bound_field_actually_binds(field, label):
    """Each transcript field must make the unwrap fail when it differs. Otherwise it is decoration.

    This is the test that would have caught a transcript builder that dropped a field, or one whose
    separators made two different contexts encode identically.
    """
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const bad = Object.assign({}, ctx, { %s });
  console.log(JSON.stringify({
    code: await codeOf(() =>
      lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, kp.privateKey, bad)),
  }));
""" % field)
    assert out["code"] == "WRAP_FAILED", f"{label} did not break the unwrap"


def test_a_wrong_key_and_a_tampered_tag_both_fail_closed():
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const other = await webcrypto.subtle.generateKey(
      { name: 'ECDH', namedCurve: 'P-384' }, true, ['deriveBits']);
  const flipped = Buffer.from(w.wrappedDEK, 'base64');
  flipped[flipped.length - 1] ^= 0x01;
  console.log(JSON.stringify({
    wrongKey: await codeOf(() =>
      lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, other.privateKey, ctx)),
    tampered: await codeOf(() =>
      lib.unwrapVaultDEK(flipped.toString('base64'), w.ephemeralPublicKey, kp.privateKey, ctx)),
  }));
""")
    assert out["wrongKey"] == "WRAP_FAILED"
    assert out["tampered"] == "WRAP_FAILED"


def test_structural_faults_are_reported_as_invalid_not_as_tampering():
    """The distinction is the point of the whole error contract.

    A damaged length, a non-zero reserved field or a malformed point are not authentication
    failures, and reporting them as such tells an operator their data was attacked when in fact
    their input was the wrong shape.
    """
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const b = Buffer.from(w.wrappedDEK, 'base64');
  const short = Buffer.concat([b.slice(0, 67)]);
  const reserved = Buffer.from(b); reserved[6] = 0xAA;
  const badPoint = Buffer.from(Buffer.from(w.ephemeralPublicKey, 'base64').slice(0, 96));
  console.log(JSON.stringify({
    wrongLength: await codeOf(() =>
      lib.unwrapVaultDEK(short.toString('base64'), w.ephemeralPublicKey, kp.privateKey, ctx)),
    reservedSet: await codeOf(() =>
      lib.unwrapVaultDEK(reserved.toString('base64'), w.ephemeralPublicKey, kp.privateKey, ctx)),
    shortPoint: await codeOf(() =>
      lib.unwrapVaultDEK(w.wrappedDEK, badPoint.toString('base64'), kp.privateKey, ctx)),
    noContext: await codeOf(() =>
      lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, kp.privateKey, null)),
    badEpoch: await codeOf(() =>
      lib.wrapVaultDEKV2(dek, kp.publicKey, Object.assign({}, ctx, { dekEpoch: 0 }))),
    negativeEpoch: await codeOf(() =>
      lib.wrapVaultDEKV2(dek, kp.publicKey, Object.assign({}, ctx, { dekEpoch: -1 }))),
    badUuid: await codeOf(() =>
      lib.wrapVaultDEKV2(dek, kp.publicKey, Object.assign({}, ctx, { vaultId: 'not-a-uuid' }))),
  }));
""")
    for key in ("wrongLength", "reservedSet", "shortPoint", "noContext",
                "badEpoch", "negativeEpoch", "badUuid"):
        assert out[key] == "WRAP_INVALID", f"{key} was reported as {out[key]}, not a structural fault"


def test_a_future_version_is_not_read_under_this_grammar():
    """The version byte is the one header field the transcript cannot pin, so it needs a check.

    The AAD is built from a header this code reconstructs, not from the header on the wire -- which
    is fine for magic, purpose and reserved, because each of those is validated separately, but it
    left the version outside both the authenticated transcript AND every structural check. A wrap
    relabelled to any other version decrypted perfectly under the v2 grammar.

    That is worse than it sounds. It is a regression against the behaviour shipped specifically so
    an older build meets a newer format and says "update this deployment" rather than "damaged", and
    it would have let a genuine v3 payload be read under v2 rules the moment v3 existed. Neither
    review's other findings would have surfaced it; only this case does.
    """
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const res = {};
  for (const v of [0x03, 0x7f, 0xff]) {
    const b = Buffer.from(w.wrappedDEK, 'base64'); b[4] = v;
    res['v' + v] = await codeOf(() =>
      lib.unwrapVaultDEK(b.toString('base64'), w.ephemeralPublicKey, kp.privateKey, ctx));
  }
  console.log(JSON.stringify(res));
""")
    for key, code in out.items():
        assert code == "WRAP_UNSUPPORTED", (
            f"a wrap relabelled {key} was answered {code}; a version this build does not implement "
            "must send someone to the update notes, never be read and never be called damaged"
        )


def test_a_payload_of_neither_length_is_malformed_rather_than_damaged():
    """Dispatch is on length first, because both formats are fixed size.

    Anything else is structurally wrong, and letting it reach the legacy cipher would report a
    malformed input as an authentication failure -- telling an operator their grant was tampered
    with when it was simply the wrong shape.
    """
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const b = Buffer.from(w.wrappedDEK, 'base64');
  console.log(JSON.stringify({
    tooShort: await codeOf(() =>
      lib.unwrapVaultDEK(b.slice(0, 50).toString('base64'), w.ephemeralPublicKey, kp.privateKey, ctx)),
    tooLong: await codeOf(() =>
      lib.unwrapVaultDEK(Buffer.concat([b, Buffer.alloc(4)]).toString('base64'),
                         w.ephemeralPublicKey, kp.privateKey, ctx)),
  }));
""")
    assert out["tooShort"] == "WRAP_INVALID"
    assert out["tooLong"] == "WRAP_INVALID"


def test_the_other_v2_purposes_stay_unreadable():
    """This reader opens one purpose. The others have their own readers, and it must refuse them.

    An older build meeting a format it cannot read should send someone to the update notes, not to
    a backup -- and a build that can read ONE purpose must not start implying it can read four.
    """
    out = _node("""
  const w = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const res = {};
  for (const p of [0x02, 0x03, 0x04]) {
    const b = Buffer.from(w.wrappedDEK, 'base64'); b[5] = p;
    res['p' + p] = await codeOf(() =>
      lib.unwrapVaultDEK(b.toString('base64'), w.ephemeralPublicKey, kp.privateKey, ctx));
  }
  console.log(JSON.stringify(res));
""")
    assert out["p2"] == "WRAP_UNSUPPORTED"
    assert out["p3"] == "WRAP_UNSUPPORTED"
    assert out["p4"] == "WRAP_UNSUPPORTED"


def test_the_legacy_wrap_still_round_trips_untouched():
    """The reader dispatches; it does not replace. A legacy wrap must be unaffected by all of this.

    Passing v2 context alongside a legacy payload must also be harmless, because the read path
    supplies it unconditionally and cannot know which format it is about to meet.
    """
    out = _node("""
  const w = await lib.wrapVaultDEK(dek, kp.publicKey);
  const bytes = Buffer.from(w.wrappedDEK, 'base64');
  const back = await lib.unwrapVaultDEK(w.wrappedDEK, w.ephemeralPublicKey, kp.privateKey, ctx);
  const raw = Buffer.from(await webcrypto.subtle.exportKey('raw', back));
  const want = Buffer.from(await webcrypto.subtle.exportKey('raw', dek));
  console.log(JSON.stringify({ length: bytes.length, roundTripped: raw.equals(want) }));
""")
    assert out["length"] == 40, "a legacy wrap is RFC 3394 over a 32-byte key"
    assert out["roundTripped"] is True


def test_two_wraps_of_the_same_key_differ():
    """A fresh ephemeral keypair and nonce per wrap, so the format is not deterministic."""
    out = _node("""
  const a = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  const b = await lib.wrapVaultDEKV2(dek, kp.publicKey, ctx);
  console.log(JSON.stringify({
    sameWrap: a.wrappedDEK === b.wrappedDEK,
    sameEphemeral: a.ephemeralPublicKey === b.ephemeralPublicKey,
  }));
""")
    assert out["sameWrap"] is False and out["sameEphemeral"] is False


# =================================================================================================
# The call sites
# =================================================================================================

def test_the_create_path_chooses_the_id_before_it_locks_the_key():
    """Creating a vault used to be the one path that could not stamp its lock.

    The key is locked and sent in the same request that creates the vault, and the server used to
    invent the id when that request landed -- so at the moment of locking there was nothing to
    stamp. The browser now picks the id first and sends it, which is the only ordering that lets
    the stamp exist at all.

    Order is the whole property, so it is what this pins: a rearrangement that locked the key
    before choosing the id would still look correct and would bind `undefined`.
    """
    source = APP_JS.read_text(encoding="utf-8")
    create = source.split("payload.type = 'zero_knowledge'", 1)[1].split("zkPendingDek = dek", 1)[0]
    assert "payload.id = zkNewObjId();" in create, "the browser no longer chooses the vault id"
    # Through the choke point, not around it. A direct call to the v2 writer here would still
    # work and would still pass every other test, while quietly reintroducing a second place
    # that decides the wrap format.
    assert "zkWrapDekForRecipient(" in create
    assert "wrapVaultDEKV2(" not in create
    assert "vaultId: payload.id" in create, "the lock is not stamped with the chosen id"
    assert create.index("payload.id = zkNewObjId();") < create.index("vaultId: payload.id"), (
        "the id must be chosen BEFORE the key is locked; the other order binds nothing"
    )


def test_both_gated_write_sites_pass_a_complete_transcript():
    """Every field, at every site -- an omitted one mints a wrap that will never open.

    The gate means these lines do not execute in a normal test run, so a missing or misnamed
    identifier here would ship silently and only fire for whoever enabled v2 first.
    """
    source = APP_JS.read_text(encoding="utf-8")
    calls = [ln.strip() for ln in source.splitlines()
             if "recipientUserId:" in ln and "dekEpoch:" in ln]
    assert len(calls) == 4, (
        "expected four transcript sites -- the direct read, and the create, share and rekey "
        f"writes -- but found {len(calls)}:\n  " + "\n  ".join(calls))
    for call in calls:
        assert "vaultId" in call, f"transcript site missing the vault: {call}"
    # One choke point per construction -- direct, team DEK, team private -- so a new write
    # site inherits the decision rather than having to remember it. `test_v2_team_wraps`
    # names them individually; this only pins that the count has not grown by accident.
    assert source.count("lib.ZK_WRAP_WRITE_V2") == 3


def _wrap_call(source: str, fn: str, after: int = 0) -> tuple[str, int]:
    """The text of one `await <fn>(...)` CALL, and where it started.

    Anchored on the call rather than the bare name: matching the name finds the choke point's own
    declaration first, and asserting against a function signature proves nothing.
    """
    i = source.index("await " + fn, after)
    return source[i:source.index(";", i)], i


def _bound(call: str, field: str) -> str:
    """The exact value bound to `field` in a transcript literal, whitespace-normalised.

    Substring matching is what this replaces, and it was wrong in both directions. `"dekEpoch: 1"`
    is a prefix of `"dekEpoch: 10"`, so a rotation labelling every survivor ten epochs ahead passed;
    the same held for every other field, since each real value is a prefix of a plausible wrong one
    (`userId` of `userIdOfSharer`, `uid` of `uidBeingRemoved`, `payload.id` of `payload.idOther`).
    In the other direction the match broke on harmless edits -- a removed space, a parenthesised
    expression, a renamed local -- so it failed on refactors and passed on defects.

    Reading to the delimiter fixes both: the value is whatever sits between the colon and the next
    comma or closing brace, with whitespace collapsed.
    """
    marker = field + ":"
    if marker not in call:
        # Shorthand: `{ vaultId, ... }` binds the local of the same name, which is a real binding
        # and has to be read as one rather than reported as a missing field.
        import re as _re
        if _re.search(r"[{,]\s*" + _re.escape(field) + r"\s*[,}]", call):
            return field
        raise AssertionError(f"{field} is not bound at this call site at all: {' '.join(call.split())}")
    i = call.index(marker) + len(marker)
    end = min(
        (pos for pos in (call.find(",", i), call.find("}", i)) if pos != -1),
        default=len(call),
    )
    value = " ".join(call[i:end].split())
    # A redundant outer parenthesis is the same value written differently, and failing on it makes
    # this a test of formatting rather than of what is bound.
    while value.startswith("(") and value.endswith(")"):
        value = value[1:-1].strip()
    return value


def test_every_direct_write_site_binds_the_right_values():
    """The gated direct sites -- the VALUES, exactly, not a substring of them.

    The site test this replaces collected source lines carrying both `recipientUserId:` and
    `dekEpoch:`, counted four, and asserted each mentioned `vaultId`. It never separated a read
    from a write and never looked at a value, so three wrong values passed the whole suite. Its
    first replacement caught those three and still let seven near neighbours through, because it
    compared prefixes -- it had been calibrated to the mutations its author thought of, which is a
    test shaped by the bugs someone imagined rather than by the values that are correct.

    Each of these produces a wrap that is perfectly well formed and opens for nobody, and none of
    these lines runs while the writer is gated off, so a wrong value ships quietly and surfaces for
    whoever enables version 2 first.
    """
    source = APP_JS.read_text(encoding="utf-8")

    # Creation: the vault's own id, the creator as recipient, epoch 1 because it is the first.
    create, i = _wrap_call(source, "zkWrapDekForRecipient(")
    assert _bound(create, "vaultId") == "payload.id", _bound(create, "vaultId")
    assert _bound(create, "recipientUserId") == "myUserId", _bound(create, "recipientUserId")
    assert _bound(create, "dekEpoch") == "1", (
        f"a new vault's first DEK is epoch 1, not {_bound(create, 'dekEpoch')!r}")

    # Share: the recipient is the person being granted access, not the person granting it, and the
    # epoch is the one the wrapped DEK actually belongs to.
    share, j = _wrap_call(source, "zkWrapDekForRecipient(", i + 1)
    assert _bound(share, "vaultId") == "vaultId", _bound(share, "vaultId")
    assert _bound(share, "recipientUserId") == "userId", (
        f"the share path wraps to {_bound(share, 'recipientUserId')!r}; if that is the sharer, the "
        "recipient holds a well-formed wrap they cannot open")
    assert _bound(share, "dekEpoch") == "shareEpoch", _bound(share, "dekEpoch")

    # Rotation: the NEW epoch, and each survivor named by the loop variable. Naming the removed
    # member would re-grant exactly the access the rotation exists to withdraw.
    rekey, _ = _wrap_call(source, "zkWrapDekForRecipient(", j + 1)
    assert _bound(rekey, "vaultId") == "vaultId", _bound(rekey, "vaultId")
    assert _bound(rekey, "recipientUserId") == "uid", (
        f"the rotation wraps to {_bound(rekey, 'recipientUserId')!r}")
    assert _bound(rekey, "dekEpoch") == "fromVersion + 1", (
        f"the rotation stamps {_bound(rekey, 'dekEpoch')!r}; every survivor's key would be "
        "labelled with an epoch the server never assigns")


def test_there_are_exactly_three_direct_write_sites():
    """A fourth would be unreviewed, and these assertions are positional."""
    source = APP_JS.read_text(encoding="utf-8")
    assert source.count("await zkWrapDekForRecipient(") == 3, (
        "the number of direct wrap sites changed; the value assertions above address them by "
        "order of appearance and no longer describe what they claim to")


def test_the_share_epoch_is_computed_once_and_used_for_both_statements():
    """The wrap and the declaration that accompanies it must not disagree.

    The wrap binds an epoch cryptographically; the request body tells the server which epoch the
    blob is for. Computed separately with different fallbacks -- which an earlier version did, one
    to 1 and one to absent -- they are two answers to the same question on adjacent lines, and the
    recipient ends up holding a key labelled as something it is not.
    """
    source = APP_JS.read_text(encoding="utf-8")
    assert "const shareEpoch = " in source, "the single-value share epoch is gone"
    i = source.index("const shareEpoch = ")
    window = source[i:i + 1600]
    assert window.count("shareEpoch") >= 3, (
        "shareEpoch is computed but not used by both the wrap and the declaration beside it")
    assert "dekEpoch: shareEpoch" in window
    assert "dek_version: shareEpoch" in window, (
        "the request body no longer derives its epoch from the same value the wrap binds")
