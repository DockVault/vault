"""Chunk-framed zero-knowledge content, purpose 0x04: the reader.

Offline by design — pure Python plus the real shipped browser module under Node, so the format
contract holds with no deployment running.

The point of this file is that the bytes are built **twice, independently**. The vectors are
produced by `crypto_reference_vectors.py`, which imports no application code and is written from
the specification; they are read back by `static/js/ecc_crypto.js`, the module the browser actually
runs. A single-byte disagreement between the two — a field in the wrong order, a width off by four,
a separator missing — is indistinguishable at runtime from a working system, because each side is
self-consistent with itself. Reading one's output with the other is the only thing that catches it.

Specified by ``docs/design/vault-zk-envelope-v2.md`` §7.4. Where a test here and that document
disagree, the document is the contract.

The writer is not built yet. This is deliberate and is the document's own rule: readers ship before
writers, so that a file written by a newer build is never met by an older one that cannot read it.
"""

import base64
import json
from pathlib import Path
import shutil
import subprocess

import pytest

import crypto_reference_vectors as reference


pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "crypto" / "zk-content-v2"
HARNESS = ROOT / "tests" / "js" / "zk_content_v2.js"
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
DESIGN_DOC = ROOT / "docs" / "design" / "vault-zk-envelope-v2.md"


def _manifest() -> dict:
    return json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))


def _vectors():
    for entry in _manifest()["vectors"]:
        yield json.loads((FIXTURE_DIR / entry["path"]).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def browser_results() -> dict:
    """Run the real browser module over the vectors under Node's WebCrypto."""
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    done = subprocess.run(
        [node, str(HARNESS), str(FIXTURE_DIR)],
        cwd=ROOT, capture_output=True, text=True, timeout=120,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    out = json.loads(done.stdout)
    assert "fatal" not in out, out.get("fatal")
    assert out["runtime"]["webcrypto"] is True
    return out


def test_the_fixture_set_is_pinned():
    """A vector that changes silently is a contract that changed silently."""
    import hashlib

    manifest = _manifest()
    assert manifest["test_only"] is True
    assert "NOT A SECRET" in manifest["notice"]
    for entry in manifest["vectors"]:
        path = FIXTURE_DIR / entry["path"]
        digest = hashlib.sha256(path.read_bytes()).hexdigest()
        assert digest == entry["sha256"], f"{entry['path']} does not match its pinned digest"


@pytest.mark.parametrize("vector", list(_vectors()), ids=lambda v: v["fixture_id"])
def test_the_reference_writer_reproduces_the_pinned_bytes(vector):
    """The vectors are deterministic given their inputs, nonces included."""
    assert reference.encode_zk_content_v2(vector) == base64.b64decode(vector["encoded_b64"])


@pytest.mark.parametrize("vector", list(_vectors()), ids=lambda v: v["fixture_id"])
def test_the_reference_reader_recovers_the_plaintext(vector):
    i = vector["inputs"]
    got = reference.decode_zk_content_v2(
        base64.b64decode(vector["encoded_b64"]), dek_hex=i["dek_hex"],
        vault_id=i["vault_id"], object_id=i["object_id"], dek_epoch=i["dek_epoch"])
    assert got == base64.b64decode(vector["expected"]["plaintext_b64"])


def test_the_browser_reads_what_the_reference_wrote(browser_results):
    """The load-bearing test in this file.

    Every other test here checks one implementation against itself. This one checks them against
    each other, which is the only way a disagreement in the byte layout can surface: both sides are
    internally consistent, so nothing else would notice.
    """
    for vector in _vectors():
        got = browser_results["vectors"].get(vector["fixture_id"])
        assert got, f"the browser harness produced no result for {vector['fixture_id']}"
        assert got["ok"], (
            f"the browser could not read {vector['fixture_id']} written by the independent "
            f"implementation: {got.get('code')}")
        assert got["plaintext_b64"] == vector["expected"]["plaintext_b64"], (
            f"{vector['fixture_id']} decrypted to different bytes in the browser")


def test_the_four_shapes_are_all_covered(browser_results):
    """Each is a case a straightforward implementation gets wrong in its own way.

    The exact multiple is the one to keep: a `while (remaining)` loop emits a trailing empty chunk
    there, and a zero-length final chunk is forbidden for every file except the empty one, so that
    extra chunk produces a blob every conforming reader rejects.
    """
    ids = set(browser_results["vectors"])
    for shape in ("empty", "one-partial-chunk", "exact-multiple", "multi-chunk-partial-tail"):
        assert f"zk-content-v2-{shape}" in ids, f"no vector covers the {shape} case"

    empty = next(v for v in _vectors() if v["fixture_id"].endswith("-empty"))
    assert empty["expected"]["stored_bytes"] == 56, (
        "the empty file must be exactly the 28-byte header plus one empty chunk's nonce and tag; "
        "the specification's stated minimum depends on it")
    assert empty["expected"]["total_chunks"] == 1, "an empty file is one chunk, not zero"


def test_the_browser_rejects_every_tampered_and_malformed_input(browser_results):
    """Each of these is a rule the reader can break while still decrypting ordinary files."""
    negatives = browser_results["negatives"]
    expected = {
        # Context: every field bound into the key and the AAD.
        "wrong_vault", "wrong_object", "wrong_epoch",
        # Tamper, at three positions.
        "tamper_header", "tamper_nonce", "tamper_last_tag",
        # Relabelling. The header is authenticated as it appears on the wire, so changing either
        # discriminator byte is caught even though every other byte is genuine.
        "relabelled_purpose", "relabelled_version",
        # Truncation and extension. Every surviving chunk authenticates on its own -- only the
        # absent terminator reveals a cut, which is why nothing may be released before it.
        "truncated_to_one_chunk", "truncated_mid_chunk", "appended_bytes",
        # Framing: a length in the gap between two valid chunk counts describes no possible file.
        "gap_length", "below_minimum", "header_only", "chunk_size_too_small",
        "chunk_size_too_large",
        # The encoding-determinism rule, which binds the reader and not only the writer.
        "zero_length_final_chunk",
    }
    assert expected <= set(negatives), f"missing negatives: {expected - set(negatives)}"
    accepted = [name for name, r in negatives.items() if not r["rejected"]]
    assert not accepted, f"the reader accepted input it must refuse: {accepted}"

    # WHY it refused, not just that it did. A structural fault reported as an authentication
    # failure tells the user their intact file is damaged, and it let five separate checks be
    # deleted without a single test noticing -- each one merely changing which honest-looking
    # refusal came back.
    structural = {
        "gap_length", "below_minimum", "chunk_size_too_small", "chunk_size_too_large",
        "zero_length_final_chunk", "tamper_header", "header_only",
    }
    unreadable = {"relabelled_purpose", "relabelled_version"}
    tampered = {
        "wrong_vault", "wrong_object", "wrong_epoch", "tamper_nonce", "tamper_last_tag",
        "truncated_to_one_chunk", "truncated_mid_chunk", "appended_bytes",
    }
    for name in structural:
        assert negatives[name]["code"] == "CONTENT_INVALID", (
            f"{name} is a malformed input and must be reported as such, not as damage: "
            f"{negatives[name]['code']}")
    for name in unreadable:
        assert negatives[name]["code"] == "CONTENT_UNSUPPORTED", (
            f"{name} is a format this build cannot read; saying 'damaged' about an intact file is "
            f"the failure the whole recognition path exists to prevent: {negatives[name]['code']}")
    for name in tampered:
        assert negatives[name]["code"] == "CONTENT_AUTH_FAILED", (
            f"{name} really is a failed authentication and must say so: {negatives[name]['code']}")

    # A malformed value in the CALLER's context is bad input. Reported as a wrap failure it would
    # tell the user to ask an owner to re-share the vault -- right about a broken key wrap, wrong
    # about a file, and the reason the encoders take a failure code at all.
    for name in ("malformed_context_vault", "malformed_context_object", "malformed_context_epoch"):
        assert negatives[name]["rejected"], f"{name} was accepted"
        assert negatives[name]["code"] == "INVALID_INPUT", (
            f"{name} is bad input from the caller, not a key-wrap problem the user can act on by "
            f"asking for access again: {negatives[name]['code']}")


def test_the_reader_authenticates_the_header_it_was_actually_given(browser_results):
    """Called directly, not through the seam -- which is the only way this is reachable.

    The public entry point checks the magic, version, purpose and reserved bytes before routing, so
    by the time the reader runs they are already known good and its own comparison looks redundant.
    It is not. `decryptFileV2` is public, a streaming reader is the caller this grammar exists to
    enable, and the AAD it authenticates is REBUILT from a constant purpose plus parsed fields --
    so nothing else in the construction says anything about how those four bytes actually arrived.
    With the comparison removed, a direct call decrypts a file relabelled to any version or
    purpose.
    """
    direct = browser_results["direct"]
    assert direct["clean"]["ok"], (
        f"unmodified bytes do not read through the direct entry point, so the rejections below "
        f"prove nothing: {direct['clean'].get('code')}")
    for field in ("magic", "version", "purpose", "reserved"):
        assert direct[field]["rejected"], (
            f"a file with a tampered {field} byte decrypted when the reader was called directly")
        assert direct[field]["code"] == "CONTENT_INVALID", (
            f"a tampered {field} byte is a malformed header, not damage: {direct[field]['code']}")


def test_the_reader_is_reachable_only_through_the_documented_seam():
    """The purpose byte selects a reader here, and only here.

    Inside the reader the transcript is built from what the CALLER expects, never from what the
    wire says. A reader that chose its own transcript off the wire would satisfy every other rule
    in this family and lose the property the whole family exists for.
    """
    src = CRYPTO_JS.read_text(encoding="utf-8")
    seam = src[src.index("async decryptFile(encryptedContent"):]
    seam = seam[:seam.index("\n    async ", 10)]
    assert "this.V2_PURPOSE_CONTENT" in seam and "decryptFileV2" in seam, (
        "the seam no longer routes a version-2 content header to its reader")
    assert "b[4] === this.V2_VERSION" in seam, (
        "the seam does not check the version byte, so a future format would be fed to this reader")

    # The transcript takes its context from the caller's argument, not from the parsed bytes.
    body = src[src.index("async decryptFileV2("):]
    body = body[:body.index("\n    async ", 10)]
    assert "ctx.vaultId" in body and "ctx.objectId" in body and "ctx.dekEpoch" in body
    assert "_v2ContentTranscript(\n            ctx.vaultId" in body or "ctx.vaultId, ctx.objectId" in body


def test_the_writer_has_not_shipped():
    """Readers before writers, and this is the document's own rule.

    A file written by a newer build and met by an older one that cannot read it is unrecoverable
    without the server's help, and the server holds nothing it could re-derive. The reader must be
    in every bundle first. Enabling a writer is a separate, operator-gated change.
    """
    src = CRYPTO_JS.read_text(encoding="utf-8")
    assert "encryptFileV2" not in src, (
        "a version-2 content writer has appeared -- it must not ship in the same change as the "
        "reader, and never with its gate on")
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    assert "ZK_CONTENT_WRITE_V2" not in app and "ZK_CONTENT_WRITE_V2" not in src

    # And the existing wrap gate is untouched: its own tests count the choke points.
    assert "this.ZK_WRAP_WRITE_V2 = false;" in src


def test_the_specification_still_says_what_this_implements():
    """A format whose document and code drift apart has neither."""
    doc = DESIGN_DOC.read_text(encoding="utf-8")
    for claim in (
        "dockvault-zk-content-v2",
        "56 bytes",                       # the corrected minimum
        "total_chunks     = ceil((L - 28) / (28 + chunk_size))",
        "4096",                            # the chunk-size floor
        "8388608",                         # and its ceiling
    ):
        assert claim in doc, f"the design document no longer states: {claim}"
