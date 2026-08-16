"""Cross-runtime vectors for the version-2 direct recipient DEK wrap (purpose 0x01).

Until these existed, every assertion about the v2 direct wrap was one JavaScript module writing a
value and then reading it back. That proves the two halves agree with each other, which they always
will: writer and reader share `_v2DirectTranscript`, so a change to the grammar changes both at
once. Reordering the context, dropping the zero separators, encoding the uuids as raw 16 bytes
instead of the 36-character text the specification requires, widening the epoch, renaming the info
label -- each of those round-trips perfectly, and each is a different wire format that a second
implementation, or a future release, would fail to read.

So the vectors here are checked in BOTH directions against an independent Python encoder that was
written from the specification: the browser must produce exactly the stored bytes, and it must read
bytes the browser never produced. The adversarial half matters for the same reason -- a hostile
payload (a wrap carrying a plaintext that is not a 32-byte key, a point that is not on the curve)
cannot be produced by the module under test, so only a foreign writer can ask the reader about it.

These vectors are public test values. They protect nothing.
"""

from __future__ import annotations

import json
import shutil
import uuid
import subprocess
from pathlib import Path

import pytest

import crypto_reference_vectors as reference

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

FIXTURE_DIR = Path(__file__).parent / "fixtures" / "crypto" / "direct-wrap-v2"
NODE_HARNESS = Path(__file__).parent / "js" / "direct_wrap_v2.js"

# What the reader must answer for each hostile payload. The split is the point: INVALID means the
# bytes are malformed, UNSUPPORTED means they are well formed and this build will not read them,
# and FAILED means authentication failed -- i.e. tampering, or the wrong context. Collapsing any
# two of those loses the distinction between "someone is attacking this" and "update the app".
EXPECTED_REFUSALS = {
    "magic_tampered": "WRAP_INVALID",
    "version_below": "WRAP_INVALID",
    "version_future": "WRAP_UNSUPPORTED",
    "purpose_team": "WRAP_UNSUPPORTED",
    "reserved_set": "WRAP_INVALID",
    "nonce_tampered": "WRAP_FAILED",
    "tag_tampered": "WRAP_FAILED",
    "truncated": "WRAP_INVALID",
    "point_short": "WRAP_INVALID",
    "point_off_curve": "WRAP_INVALID",
    "wrong_vault": "WRAP_FAILED",
    "wrong_recipient_id": "WRAP_FAILED",
    "wrong_epoch": "WRAP_FAILED",
    "wrong_key": "WRAP_FAILED",
    "no_context": "WRAP_INVALID",
    "empty_context": "WRAP_INVALID",
    "short_plaintext": "WRAP_INVALID",
}


def _vector_names() -> list[str]:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    return [entry["path"] for entry in manifest["vectors"]]


def _vector(name: str) -> dict:
    return json.loads((FIXTURE_DIR / name).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def browser_results() -> dict:
    """Run the real shipped crypto module over every vector, once."""
    node = shutil.which("node")
    assert node, "Node is required: a cross-runtime vector cannot be skipped into passing"
    completed = subprocess.run(
        [node, str(NODE_HARNESS), str(FIXTURE_DIR)],
        capture_output=True, text=True, timeout=300,
    )
    assert completed.returncode == 0, completed.stderr[-2000:]
    return json.loads(completed.stdout)


def test_the_fixture_set_is_pinned():
    """A vector nobody can change silently is the only kind worth having."""
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    assert manifest["test_only"] is True
    assert "NOT A SECRET" in manifest["notice"]
    assert manifest["vectors"], "the manifest lists no vectors"
    for entry in manifest["vectors"]:
        path = FIXTURE_DIR / entry["path"]
        assert path.exists(), f"{entry['path']} is listed and missing"
        assert reference.sha256_file(path) == entry["sha256"], (
            f"{entry['path']} has changed since it was pinned")

    on_disk = {p.name for p in FIXTURE_DIR.glob("*.json")} - {"manifest.json"}
    assert on_disk == set(_vector_names()), (
        "a vector file exists that the manifest does not pin, or the other way round")


@pytest.mark.parametrize("name", _vector_names())
def test_the_browser_writes_exactly_the_stored_bytes(name, browser_results):
    """The shipped writer, driven with the vector's own inputs, must land on the stored bytes.

    Both sources of freshness are pinned in the harness -- the GCM nonce AND the ephemeral keypair,
    which comes from subtle.generateKey rather than from the entropy hook most harnesses stub. If
    only the nonce were fixed, this would compare a fresh wrap against a stored one and fail.
    """
    vector = _vector(name)
    outcome = browser_results[name]["writer"]
    assert outcome["ok"], f"the browser writer raised: {outcome.get('error')}"
    written = outcome["value"]
    assert written["wrapped_dek_b64"] == vector["expected"]["wrapped_dek_b64"], (
        "the browser's v2 direct wrap no longer matches the reference encoder; the derivation "
        "grammar has changed on one side")
    assert written["ephemeral_public_key_b64"] == vector["expected"]["ephemeral_public_key_b64"]


@pytest.mark.parametrize("name", _vector_names())
def test_the_browser_reads_bytes_it_did_not_write(name, browser_results):
    vector = _vector(name)
    outcome = browser_results[name]["reader"]
    assert outcome["ok"], (
        f"the browser could not read the stored vector at all: {outcome.get('error')}. Either the "
        "grammar changed on one side, or the stored bytes are no longer a v2 direct wrap")
    assert outcome["value"] == vector["inputs"]["dek_hex"]


@pytest.mark.parametrize("name", _vector_names())
def test_the_reference_decoder_reads_the_stored_bytes(name):
    """The other direction, without Node in the picture at all."""
    vector = _vector(name)
    recovered = reference.decode_direct_dek_wrap_v2(
        vector["expected"]["wrapped_dek_b64"],
        ephemeral_public_key_b64=vector["expected"]["ephemeral_public_key_b64"],
        recipient_private_scalar_hex=vector["inputs"]["recipient_private_scalar_hex"],
        vault_id=vector["inputs"]["vault_id"],
        recipient_user_id=vector["inputs"]["recipient_user_id"],
        dek_epoch=vector["inputs"]["dek_epoch"],
    )
    assert recovered.hex() == vector["inputs"]["dek_hex"]


@pytest.mark.parametrize("name", _vector_names())
@pytest.mark.parametrize("case", sorted(EXPECTED_REFUSALS))
def test_every_hostile_payload_is_refused_with_the_right_kind_of_no(name, case, browser_results):
    got = browser_results[name]["adversarial"][case]
    assert got is not None, (
        f"the reader ACCEPTED the {case} payload; a wrap that should not decode did")
    assert got == EXPECTED_REFUSALS[case], (
        f"{case}: expected {EXPECTED_REFUSALS[case]}, got {got}. The three answers are not "
        "interchangeable -- malformed, unsupported and authentication-failed tell a caller "
        "different things about what to do next")


def test_swapping_the_two_bound_ids_produces_different_bytes():
    """The field ORDER is load-bearing and nothing else pins it.

    A context assembled as recipient-then-vault instead of vault-then-recipient round-trips
    perfectly inside one implementation. The only way to see it is to encode both orders and
    observe that they differ -- which is why the swapped-ids vector is stored rather than derived.
    """
    baseline = _vector("direct-wrap-v2-baseline.json")
    swapped = _vector("direct-wrap-v2-swapped-ids.json")
    assert baseline["inputs"]["vault_id"] == swapped["inputs"]["recipient_user_id"]
    assert baseline["inputs"]["recipient_user_id"] == swapped["inputs"]["vault_id"]
    assert baseline["inputs"]["dek_hex"] == swapped["inputs"]["dek_hex"]
    assert baseline["inputs"]["nonce_hex"] == swapped["inputs"]["nonce_hex"]
    assert (baseline["expected"]["wrapped_dek_b64"]
            != swapped["expected"]["wrapped_dek_b64"]), (
        "exchanging the vault id and the recipient id left the wrap unchanged, so the two are "
        "concatenated in a way that does not distinguish them")


def test_the_grammar_constants_are_what_the_specification_says():
    """Named here so a rename is a failing test rather than a silent format change.

    The encoder and the browser would agree with each other after any of these were renamed -- in
    lockstep, which is exactly the failure this file exists to catch. Pinning the literals is what
    makes the agreement mean something.
    """
    assert reference.V2_MAGIC == b"DVZ2"
    assert reference.V2_VERSION == 0x02
    assert reference.V2_PURPOSE_DIRECT_DEK == 0x01
    assert reference.V2_SALT == b"dockvault-zk-envelope-v2-salt-01"
    assert reference.V2_INFO_DEK_DIRECT == b"dockvault-zk-dek-direct-v2"
    assert reference.V2_DIRECT_WRAP_BYTES == 68

    source = (Path(__file__).resolve().parents[1] / "static" / "js" / "ecc_crypto.js").read_text(
        encoding="utf-8")
    for literal in ("dockvault-zk-envelope-v2-salt-01", "dockvault-zk-dek-direct-v2"):
        assert literal in source, (
            f"{literal} is no longer in the shipped module; the vectors describe a format the "
            "product does not implement")


def test_the_uuid_form_is_the_text_one_not_the_raw_one():
    """The product binds uuids two different ways and they are one typo apart.

    The v2 wrap grammar binds the 36-character lowercase hyphenated TEXT. The Standard-vault chunk
    grammar in the same codebase binds the raw 16 bytes. Either choice works if both sides make it,
    so this pins which one this format made.
    """
    context = reference._v2_direct_context(
        "3f2504e0-4f89-41d3-9a0c-0305e82c3301",
        "9b1deb4d-3b7d-4bad-9bdd-2b0d7b3dcb6d",
        1,
    )
    assert len(context) == 36 + 1 + 36 + 1 + 4
    assert context.startswith(b"3f2504e0-4f89-41d3-9a0c-0305e82c3301\x00")
    assert context.endswith(b"\x00\x00\x00\x01"), "the epoch is four bytes, big-endian"

    # Case is normalised, exactly as the browser does (it lowercases, then matches).
    assert (reference._v2_uuid_text("3F2504E0-4F89-41D3-9A0C-0305E82C3301")
            == b"3f2504e0-4f89-41d3-9a0c-0305e82c3301")

    # Everything else is refused rather than normalised. uuid.UUID() accepts all three of these
    # and canonicalises them, so an encoder built on it could emit a vector carrying a value the
    # browser refuses outright -- the two runtimes would disagree about what is even encodable.
    for hostile in ("{3f2504e0-4f89-41d3-9a0c-0305e82c3301}",
                    "urn:uuid:3f2504e0-4f89-41d3-9a0c-0305e82c3301",
                    "3f2504e04f8941d39a0c0305e82c3301"):
        with pytest.raises(ValueError):
            reference._v2_uuid_text(hostile)
        # The permissive parser really would have taken it -- this is the trap, not a hypothetical.
        assert uuid.UUID(hostile)


def test_a_wrap_of_the_wrong_sized_key_cannot_even_be_the_right_length(browser_results):
    """Worth stating precisely, because it is easy to claim more than is true here.

    The reader carries a check that an unwrapped plaintext is exactly 32 bytes. For THIS
    construction that check is unreachable: the payload is a fixed 68 bytes, which fixes the
    ciphertext at 48 and the plaintext at exactly 32, and anything else is turned away by the
    length dispatch first. Deleting the check leaves this whole file green -- measured, not
    assumed. It is defence in depth against a future variable-length variant, and the property
    that actually holds today is the one asserted here.
    """
    for name in _vector_names():
        cases = browser_results[name]["adversarial"]
        assert cases["short_plaintext_byte_length"] == 52, (
            "a wrap of a 16-byte key should be 52 bytes; if it is 68 the plaintext-length check "
            "is reachable after all and deserves a test of its own")
        assert cases["short_plaintext"] == "WRAP_INVALID"


def test_an_epoch_outside_the_grammar_is_refused():
    for bad in (0, -1, 0x80000000):
        with pytest.raises(ValueError):
            reference._v2_epoch(bad)
    assert reference._v2_epoch(1) == b"\x00\x00\x00\x01"
    assert reference._v2_epoch(0x7FFFFFFF) == b"\x7f\xff\xff\xff"
