"""Cross-runtime vectors for the two version-2 TEAM wraps (purposes 0x02 and 0x03).

The direct wrap got this treatment first; these are its siblings, and they need it more, not less.
Each construction's writer and reader share one transcript builder, so they agree with each other
whatever the grammar says -- and the two team constructions additionally share a sealing routine,
which means a mistake there is consistent across both and invisible to any test that only asks them
to read back what they wrote.

What is specific to these two, and what the vectors pin that no round trip can:

  * The team DEK binds the vault and the epoch and NO recipient. One wrap serves every member --
    that is the whole point of the hierarchical mode -- and "no recipient is bound" is a claim
    about absence, which a round trip cannot make. It is asserted here by encoding the same inputs
    with different recipients and requiring identical bytes.
  * The team private key binds the vault and the recipient and NO epoch. Same shape of claim, same
    method.
  * All three constructions share a header, a salt and a cipher suite, and two of them share a
    length. Only the purpose byte and the caller's own expectation separate them, so each must be
    unreadable as either of the others.

These vectors are public test values. They protect nothing.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path

import pytest

import crypto_reference_vectors as reference

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto" / "team-wrap-v2"
NODE_HARNESS = Path(__file__).parent / "js" / "team_wrap_v2.js"

TEAM_DEK = 2
TEAM_PRIV = 3

# The kind of refusal, and the guard that produces it. The guard matters as much as the code: a
# team DEK and a direct DEK are the same length with the same header shape, so "it was refused" is
# not enough -- it has to be refused by the check that distinguishes them.
EXPECTED_DEK_REFUSALS = {
    "purpose_direct": "WRAP_UNSUPPORTED @ unwrapVaultDEK.v2.purpose",
    "read_as_direct": "WRAP_UNSUPPORTED @ unwrapVaultDEK.v2.purpose",
    "wrong_vault": "WRAP_FAILED @ unwrapTeamDEK.v2",
    "member_key": "WRAP_FAILED @ unwrapTeamDEK.v2",
    "tag_tampered": "WRAP_FAILED @ unwrapTeamDEK.v2",
    "reserved_set": "WRAP_INVALID @ unwrapVaultDEK.v2",
}
EXPECTED_PRIV_REFUSALS = {
    "purpose_team_dek": "WRAP_UNSUPPORTED @ unwrapPrivateKeyFromWrapped.v2.purpose",
    "wrong_vault": "WRAP_FAILED @ unwrapTeamPriv.v2",
    "wrong_recipient": "WRAP_FAILED @ unwrapTeamPriv.v2",
    "tag_tampered": "WRAP_FAILED @ unwrapTeamPriv.v2",
    "reserved_set": "WRAP_INVALID @ unwrapPrivateKeyFromWrapped.v2",
    # Variable length is what makes this construction different from the other two, so a ceiling
    # applied BEFORE the payload is materialised is the guard that replaces "the length identifies
    # it". Judged from the encoded length, because a ceiling applied after the decode has already
    # let a hostile server hand the browser as much memory as it liked.
    "oversized": "WRAP_INVALID @ unwrapPrivateKeyFromWrapped.size",
}


def _names() -> list[str]:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    return [entry["path"] for entry in manifest["vectors"]]


def _vector(name: str) -> dict:
    return reference.load_unreleased_vector(FIXTURE_DIR / name)


def _payload_key(vector: dict) -> str:
    return "wrapped_dek_b64" if vector["purpose"] == TEAM_DEK else "wrapped_key_b64"


@pytest.fixture(scope="module")
def browser_results() -> dict:
    node = shutil.which("node")
    assert node, "Node is required: a cross-runtime vector cannot be skipped into passing"
    completed = subprocess.run(
        [node, str(NODE_HARNESS), str(FIXTURE_DIR)],
        capture_output=True, text=True, timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout)


def test_the_fixture_set_is_pinned():
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["test_only"] is True
    assert "NOT A SECRET" in manifest["notice"]
    for entry in manifest["vectors"]:
        path = FIXTURE_DIR / entry["path"]
        assert path.exists(), f"{entry['path']} is listed and missing"
        assert reference.sha256_file(path) == entry["sha256"], (
            f"{entry['path']} has changed since it was pinned")
    on_disk = {p.name for p in FIXTURE_DIR.glob("*.json")} - {"manifest.json"}
    assert on_disk == set(_names())


@pytest.mark.parametrize("name", _names())
def test_the_browser_writes_exactly_the_stored_bytes(name, browser_results):
    vector = _vector(name)
    written = browser_results[name]["writer"]
    assert written.get("ok"), f"the browser writer raised: {written.get('error')}"
    key = _payload_key(vector)
    assert written[key] == vector["expected"][key], (
        "the browser's team wrap no longer matches the reference encoder; the derivation grammar "
        "has changed on one side")
    assert written["ephemeral_public_key_b64"] == vector["expected"]["ephemeral_public_key_b64"]


@pytest.mark.parametrize("name", _names())
def test_the_browser_reads_bytes_it_did_not_write(name, browser_results):
    vector = _vector(name)
    outcome = browser_results[name]["reader"]
    assert outcome["ok"], f"the browser could not read the stored vector: {outcome.get('error')}"
    if vector["purpose"] == TEAM_DEK:
        assert outcome["value"] == vector["inputs"]["dek_hex"]
    else:
        assert outcome["value"] == vector["inputs"]["team_private_pkcs8_b64"]


@pytest.mark.parametrize("name", _names())
def test_the_reference_encoder_reproduces_the_stored_bytes(name):
    """Run the encoder rather than trusting bytes it produced once."""
    vector = _vector(name)
    encode = (reference.encode_team_dek_wrap_v2 if vector["purpose"] == TEAM_DEK
              else reference.encode_team_priv_wrap_v2)
    produced = encode(vector)
    key = _payload_key(vector)
    assert produced[key] == vector["expected"][key]


@pytest.mark.parametrize("name", _names())
def test_the_reference_decoder_reads_the_stored_bytes(name):
    vector = _vector(name)
    i = vector["inputs"]
    if vector["purpose"] == TEAM_DEK:
        recovered = reference.decode_team_dek_wrap_v2(
            vector["expected"]["wrapped_dek_b64"],
            ephemeral_public_key_b64=vector["expected"]["ephemeral_public_key_b64"],
            team_private_scalar_hex=i["team_private_scalar_hex"],
            vault_id=i["vault_id"], dek_epoch=i["dek_epoch"])
        assert recovered.hex() == i["dek_hex"]
    else:
        recovered = reference.decode_team_priv_wrap_v2(
            vector["expected"]["wrapped_key_b64"],
            ephemeral_public_key_b64=vector["expected"]["ephemeral_public_key_b64"],
            recipient_private_scalar_hex=i["recipient_private_scalar_hex"],
            vault_id=i["vault_id"], recipient_user_id=i["recipient_user_id"])
        assert reference.b64e(recovered) == i["team_private_pkcs8_b64"]


@pytest.mark.parametrize("name", _names())
def test_every_hostile_payload_is_refused_with_the_right_kind_of_no(name, browser_results):
    vector = _vector(name)
    expected = (EXPECTED_DEK_REFUSALS if vector["purpose"] == TEAM_DEK
                else EXPECTED_PRIV_REFUSALS)
    cases = browser_results[name]["adversarial"]
    for case, want in expected.items():
        got = cases[case]
        assert got is not None, f"the reader ACCEPTED the {case} payload"
        assert got == want, f"{case}: expected {want}, got {got}"


def test_the_wrong_epoch_is_refused_however_it_is_wrong(browser_results):
    """Separated out because the reason differs at the top of the range.

    A neighbouring epoch fails authentication; an epoch outside the grammar is structural. Both are
    refusals, and conflating them would hide the day one became the other.
    """
    for name in _names():
        vector = _vector(name)
        if vector["purpose"] != TEAM_DEK:
            continue
        got = browser_results[name]["adversarial"]["wrong_epoch"]
        at_ceiling = vector["inputs"]["dek_epoch"] == 0x7FFFFFFF
        want = ("WRAP_INVALID @ v2TeamDek.epoch" if at_ceiling
                else "WRAP_FAILED @ unwrapTeamDEK.v2")
        assert got == want, f"{name}: expected {want}, got {got}"


def test_the_team_dek_binds_no_recipient():
    """A claim about ABSENCE, which no round trip can make.

    One team DEK wrap serves every member. If a recipient were bound, each member would need their
    own -- and the way that failure would present is not an error but a vault that silently only
    opens for whoever it was minted against.
    """
    vector = _vector("team-dek-v2-epoch-1.json")
    baseline = reference.encode_team_dek_wrap_v2(vector)

    moved = json.loads(json.dumps(vector))
    moved["inputs"]["recipient_user_id"] = moved["inputs"]["other_recipient_user_id"]
    assert reference.encode_team_dek_wrap_v2(moved)["wrapped_dek_b64"] == \
        baseline["wrapped_dek_b64"], (
        "changing the recipient changed the team DEK wrap, so a recipient IS bound into it and one "
        "wrap no longer serves every member")

    # The two things it does bind must both move the bytes, or the assertion above is vacuous.
    for field, value in (("vault_id", vector["inputs"]["other_vault_id"]), ("dek_epoch", 2)):
        changed = json.loads(json.dumps(vector))
        changed["inputs"][field] = value
        assert reference.encode_team_dek_wrap_v2(changed)["wrapped_dek_b64"] != \
            baseline["wrapped_dek_b64"], f"{field} is not bound into the team DEK wrap"


def test_the_team_private_key_wrap_binds_no_epoch():
    """The mirror-image claim, for the same reason.

    The only epoch that would mean anything here is the team keypair's, and the server assigns it.
    Binding the DEK epoch instead would tie a member's team key to a rotation it has nothing to do
    with, and every DEK rotation would lock members out of a key that had not changed.
    """
    vector = _vector("team-priv-v2-baseline.json")
    baseline = reference.encode_team_priv_wrap_v2(vector)

    with_epoch = json.loads(json.dumps(vector))
    with_epoch["inputs"]["dek_epoch"] = 99
    assert reference.encode_team_priv_wrap_v2(with_epoch)["wrapped_key_b64"] == \
        baseline["wrapped_key_b64"], "an epoch reached the team private key transcript"

    for field, value in (("vault_id", vector["inputs"]["other_vault_id"]),
                         ("recipient_user_id", vector["inputs"]["other_recipient_user_id"])):
        changed = json.loads(json.dumps(vector))
        changed["inputs"][field] = value
        assert reference.encode_team_priv_wrap_v2(changed)["wrapped_key_b64"] != \
            baseline["wrapped_key_b64"], f"{field} is not bound into the team private key wrap"


def test_the_three_constructions_cannot_be_confused_for_one_another():
    """Same header, same salt, same suite; two of them the same length.

    Only the purpose byte and the caller's own expectation separate them, so the transcripts must
    differ even when everything a caller controls is identical. If two agreed, a wrap minted for
    one role could be served in the other's place -- the first threat the envelope design names.
    """
    dek = _vector("team-dek-v2-epoch-1.json")
    priv = _vector("team-priv-v2-baseline.json")

    dek_context = reference._v2_team_dek_context(dek["inputs"]["vault_id"],
                                                 dek["inputs"]["dek_epoch"])
    priv_context = reference._v2_team_priv_context(priv["inputs"]["vault_id"],
                                                   priv["inputs"]["recipient_user_id"])
    direct_context = reference._v2_direct_context(dek["inputs"]["vault_id"],
                                                  priv["inputs"]["recipient_user_id"],
                                                  dek["inputs"]["dek_epoch"])
    assert len({dek_context, priv_context, direct_context}) == 3, (
        "two constructions build the same context from the same inputs")

    labels = {reference.V2_INFO_DEK_DIRECT, reference.V2_INFO_DEK_TEAM,
              reference.V2_INFO_TEAMPRIV}
    assert len(labels) == 3, "two constructions derive their key with the same info label"

    purposes = {reference.V2_PURPOSE_DIRECT_DEK, reference.V2_PURPOSE_TEAM_DEK,
                reference.V2_PURPOSE_TEAM_PRIV}
    assert purposes == {0x01, 0x02, 0x03}


def test_the_grammar_constants_are_what_the_specification_says():
    assert reference.V2_PURPOSE_TEAM_DEK == 0x02
    assert reference.V2_PURPOSE_TEAM_PRIV == 0x03
    assert reference.V2_INFO_DEK_TEAM == b"dockvault-zk-dek-team-v2"
    assert reference.V2_INFO_TEAMPRIV == b"dockvault-zk-teampriv-v2"

    source = (Path(__file__).resolve().parents[1] / "static" / "js" / "ecc_crypto.js").read_text(
        encoding="utf-8")
    for literal in ("dockvault-zk-dek-team-v2", "dockvault-zk-teampriv-v2"):
        assert literal in source, (
            f"{literal} is no longer in the shipped module; these vectors describe a format the "
            "product does not implement")
