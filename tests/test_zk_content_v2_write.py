"""Chunk-framed zero-knowledge content, purpose 0x04: the writer.

Its companion file proves the shipped browser module can READ bytes an independent Python
implementation wrote. This one proves the reverse, which is the stricter direction. A reader can be
lenient about a field it does not understand and still look correct forever; a writer that emits a
field in the wrong order produces files only itself can open, and nothing at runtime says so until
the day the other implementation has to read one.

So the writer is driven over the same four vectors with the same attempt token and the same nonces,
and its output must equal them **byte for byte**. Both sides were built from
``docs/design/vault-zk-envelope-v2.md`` §7.4 and neither imports the other. Where a test here and
that document disagree, the document is the contract.

The writer stays behind a default-off gate. Readers ship first so that a file written by a newer
build is never met by an older one that cannot read it; this is the second half of that rule, not
an exception to it.
"""

import base64
import json
from pathlib import Path
import re
import shutil
import subprocess

import pytest

import crypto_reference_vectors as reference


pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "crypto" / "zk-content-v2"
HARNESS = ROOT / "tests" / "js" / "zk_content_v2_write.js"
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"

VAULT = "11111111-1111-4111-8111-111111111111"
OBJECT = "22222222-2222-4222-8222-222222222222"
DEK_HEX = "00" * 32
CHUNK = 4096
OVERHEAD = 28
HEADER = 28


def _vectors():
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    for entry in manifest["vectors"]:
        yield json.loads((FIXTURE_DIR / entry["path"]).read_text(encoding="utf-8"))


@pytest.fixture(scope="module")
def written() -> dict:
    """Run the real browser WRITER over the vectors under Node's WebCrypto."""
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


def test_the_writer_reproduces_every_vector_byte_for_byte(written):
    """The whole point of the file.

    Four shapes, and each is a different way to get the framing wrong: the empty file is the one a
    naive ``ceil`` writes as zero chunks, the exact multiple is the one that grows a trailing empty
    chunk, the single partial chunk is the only case where a final chunk may also be the first, and
    the multi-chunk tail is the ordinary case that hides all three.
    """
    for vector in _vectors():
        got = written["vectors"][vector["fixture_id"]]
        assert got["ok"], f"{vector['fixture_id']}: {got.get('code')}"
        assert got["encoded_b64"] == vector["encoded_b64"], (
            f"{vector['fixture_id']}: the browser writer and the reference implementation "
            "disagree about these bytes")


def test_the_writer_consumes_exactly_the_entropy_the_framing_needs(written):
    """One token per file, one nonce per chunk, none left over.

    Byte equality alone would not catch a writer that asked for a nonce it never used: the file
    would still match, and the next one would silently be encrypted under a nonce meant for this
    one. Reusing a nonce under a fixed key is the single worst thing this format can do.
    """
    for vector in _vectors():
        got = written["vectors"][vector["fixture_id"]]
        assert got["tokensMinted"] == 1, vector["fixture_id"]
        assert got["noncesUsed"] == got["noncesAvailable"] == len(vector["inputs"]["nonces_hex"]), (
            f"{vector['fixture_id']}: used {got['noncesUsed']} of {got['noncesAvailable']} nonces")


def test_what_the_writer_writes_the_reader_reads(written):
    """Through the public entry point, on real entropy -- the configuration that ships."""
    base = json.loads(
        (FIXTURE_DIR / "zk-content-v2-multi-chunk-partial-tail.json").read_text(encoding="utf-8"))
    assert written["checks"]["round_trip_b64"] is not None, (
        "the writer produced a file its own reader rejects: "
        f"{written['checks'].get('round_trip_code')}")
    assert written["checks"]["round_trip_b64"] == base["inputs"]["plaintext_b64"]


def test_every_encryption_gets_its_own_attempt_token(written):
    """The property the whole construction leans on, asserted where it is produced.

    Two encryptions sharing a token share a derived key and share every non-final chunk's
    associated data. The test below this one shows what that buys an attacker. Here: the writer
    mints the token itself, so no caller can arrange it -- and two calls with every input
    identical still differ.
    """
    checks = written["checks"]
    assert checks["distinct_tokens"], "two encryptions were given the same attempt token"
    assert checks["distinct_bytes"]
    assert checks["token_is_32_hex"]
    assert checks["token_matches_header"], (
        "the token handed to the caller is not the one sealed into the file, so what the server "
        "matches attempts on and what the file binds are two different things")


def test_a_reused_attempt_token_makes_two_files_interchangeable_chunk_by_chunk():
    """Why the writer mints its own token, demonstrated rather than asserted.

    Everything a non-final chunk binds -- the header, the vault, the object, the epoch, the index --
    is identical between two encryptions that share an attempt token, and the key derived from that
    token is the same key. So chunk *i* of one file is a valid chunk *i* of the other, and a shorter
    second attempt supplies the final chunk that turns a substitution into a truncation.

    The spliced file below is authentic in every way a reader can check: every chunk authenticates,
    the terminator is present, the totals agree with the length. It is a file neither encryption
    ever produced.

    This is worth a test rather than a comment because the change that reintroduces it is a
    reasonable-sounding one: deriving the token from a hash of the content, so that identical files
    deduplicate. That is exactly the reuse this forbids.
    """
    shared_token = "ab" * 16

    def build(plaintext: bytes, nonce_seed: int, token: str) -> bytes:
        chunks = max(1, -(-len(plaintext) // CHUNK))
        return reference.encode_zk_content_v2({"inputs": {
            "dek_hex": DEK_HEX, "blob_id_hex": token, "chunk_size": CHUNK,
            "vault_id": VAULT, "object_id": OBJECT, "dek_epoch": 1,
            "plaintext_b64": base64.b64encode(plaintext).decode(),
            "nonces_hex": [f"{nonce_seed + i:024x}" for i in range(chunks)],
        }})

    long_body = b"L" * (CHUNK * 2 + 50)
    short_body = b"S" * (CHUNK + 30)
    long_blob = build(long_body, 0x100, shared_token)
    short_blob = build(short_body, 0x200, shared_token)

    # The long file's first chunk, in front of the short file's terminator.
    spliced = (short_blob[:HEADER]
               + long_blob[HEADER:HEADER + CHUNK + OVERHEAD]
               + short_blob[HEADER + CHUNK + OVERHEAD:])

    out = reference.decode_zk_content_v2(
        spliced, dek_hex=DEK_HEX, vault_id=VAULT, object_id=OBJECT, dek_epoch=1)
    assert out == long_body[:CHUNK] + short_body[CHUNK:], (
        "the splice was expected to succeed -- that is the hazard being recorded")
    assert out not in (long_body, short_body)

    # And with a token per encryption, which is what the writer does, the same splice is dead: the
    # derived keys differ, so the borrowed chunk does not authenticate.
    fresh = build(short_body, 0x200, "cd" * 16)
    spliced_fresh = (fresh[:HEADER]
                     + long_blob[HEADER:HEADER + CHUNK + OVERHEAD]
                     + fresh[HEADER + CHUNK + OVERHEAD:])
    with pytest.raises(Exception):
        reference.decode_zk_content_v2(
            spliced_fresh, dek_hex=DEK_HEX, vault_id=VAULT, object_id=OBJECT, dek_epoch=1)


def test_the_writer_refuses_a_transcript_it_cannot_bind(written):
    """Bad input, reported as bad input, before any byte is encrypted.

    A missing vault or object id is not a smaller file or a weaker file -- it is a file nothing can
    ever open, and the failure has to arrive at the call that caused it rather than at a download
    months later.
    """
    for name in ("no_context", "no_vault", "no_object", "no_epoch", "epoch_zero",
                 "object_not_a_uuid"):
        assert written["negatives"][name]["rejected"], name
        assert written["negatives"][name]["code"] == "INVALID_INPUT", name


def test_the_writer_will_not_leave_the_grammars_chunk_bounds(written):
    """The bounds are load-bearing on both sides.

    Below the floor the per-chunk overhead dominates and the nonce budget for one file shrinks
    toward the birthday bound; above the ceiling no conforming reader will accept the header the
    writer just wrote, including this one.
    """
    for name in ("chunk_below_floor", "chunk_above_ceiling", "chunk_not_an_integer"):
        assert written["negatives"][name]["rejected"], name
        assert written["negatives"][name]["code"] == "INVALID_INPUT", name


def test_the_default_chunk_size_is_recorded_in_the_file(written):
    """A caller that says nothing gets the build's default -- and it is written down, not implied.

    The reader takes the size from the header, so changing this default is a writer-only decision
    and files written under the old one keep opening. Pinned so that stays true by intent rather
    than by luck.
    """
    checks = written["checks"]
    assert checks["declared_default"] == 1048576
    assert checks["default_chunk_size"] == checks["declared_default"], (
        "the header does not record the size the writer actually used")
    # And the document says which size this build picked, because a reader of the grammar has no
    # way to derive it -- the bounds permit any of them.
    doc = (ROOT / "docs" / "design" / "vault-zk-envelope-v2.md").read_text(encoding="utf-8")
    assert "writer picks **1 MiB**" in doc, (
        "the design document no longer records the size this build's writer uses")


def test_every_buffer_source_is_encrypted_as_the_bytes_it_spans(written):
    """The input branch the shipped caller actually takes, which nothing executed.

    Every vector above hands the writer a ``Uint8Array``; the browser hands it an ``ArrayBuffer``.
    A review mutation that made that branch return empty passed all twenty-five tests. What made
    the gap serious rather than untidy is what the code did with an input it did not recognise:
    ``new Uint8Array(x)`` answers *zero length* instead of throwing, so a ``DataView`` -- the
    natural type for a caller working in byte offsets, and for the streaming writer this grammar
    exists for -- was encrypted as an empty file, silently, with a correct totals binding for the
    empty file it had become. No reader could tell it from a file that really was empty.
    """
    got = written["checks"]["input_lengths"]
    assert got["uint8"] == 28 + 28 + 300, got
    for name in ("arraybuffer", "dataview"):
        assert got[name] == got["uint8"], (
            f"{name} produced {got[name]} bytes where the same 300 bytes as a Uint8Array "
            f"produced {got['uint8']}")
    assert got["offset_view"] == 28 + 28 + 100, (
        f"a view at a non-zero offset encrypted {got['offset_view'] - 56} bytes, not its own 100 "
        "-- the backing buffer was taken whole")
    assert got["uint16_view"] == 28 + 28 + 300, (
        "a 16-bit view should contribute the bytes it spans, not one byte per element")


def test_the_writer_refuses_anything_that_is_not_a_buffer(written):
    """Because the alternative is not an error, it is an empty file that authenticates."""
    for name in ("plaintext_null", "plaintext_undefined", "plaintext_string",
                 "plaintext_number", "plaintext_object"):
        assert written["negatives"][name]["rejected"], name
        assert written["negatives"][name]["code"] == "INVALID_INPUT", name


def test_the_content_key_refuses_a_dek_that_is_not_thirty_two_bytes(written):
    """HKDF will take anything, which is exactly the problem.

    A 16-byte key, or an HMAC key, seeds a perfectly valid AES-256 content key and the file round
    trips -- the cipher is fine and the entropy silently is not. The legacy writer got this check
    for free by handing the key to AES-GCM, which refuses the wrong algorithm outright; deriving
    instead means making the check. Both v2 unwrap paths already make it on the other side of the
    same key.
    """
    for name in ("dek_too_short", "dek_wrong_algorithm"):
        assert written["negatives"][name]["rejected"], name
        assert written["negatives"][name]["code"] == "INVALID_INPUT", name


def test_a_chunk_size_that_changes_between_reads_cannot_split_the_file(written):
    """One value, read once.

    The size was validated as a coerced copy and the framing loop then re-read the caller's
    original. Anything whose ``valueOf`` answers differently on the second read -- a hostile
    caller, or an accessor with a side effect -- got a header declaring one chunk size and a body
    framed at another. That file is not forgeable, it is unopenable, including by the writer that
    produced it.
    """
    assert written["checks"]["shifting_chunk_size_readable"] is True, (
        "the writer produced a file it cannot read back: "
        f"{written['checks']['shifting_chunk_size_readable']}")


def test_the_writer_is_registered_with_the_error_boundary():
    """An unregistered public method escapes the boundary and reports nothing.

    The table's loop throws at load for a *listed* method that does not exist; the reverse -- a
    real method nobody listed -- fails silently and never reaches the diagnostic. The same test
    exists for the previous construction, which is how this one was noticed missing.
    """
    source = CRYPTO_JS.read_text(encoding="utf-8")
    table = source.split("const _OPERATION_DEFAULT_CODE", 1)[1].split("});", 1)[0]
    listed = set(re.findall(r"^\s{4}(\w+):", table, re.M))
    assert "encryptFileV2:" in table

    # Every public method, not just this one. Naming them individually is how the omission this
    # test describes happened again: a new writer was added beside the one above, the assertion
    # kept passing because it only ever looked for the old name, and the new method's failures
    # reached no diagnostic. Comparing the whole surface cannot miss the next one.
    ignore = {"constructor", "get", "if", "for", "while", "catch", "switch", "return"}
    getters = set(re.findall(r"^    get (\w+)\(", source, re.M))
    methods = {
        m.group(1)
        for m in re.finditer(r"^    (?:async )?(\w+)\s*\(", source, re.M)
        if not m.group(1).startswith("_") and m.group(1) not in ignore
    } - getters

    assert not (methods - listed), (
        "public method(s) missing from the error boundary, so their failures reach no "
        f"diagnostic: {sorted(methods - listed)}")
    # The other direction throws at load, but a name here with no method behind it is still a
    # table that has stopped describing the class, so say which one.
    assert not (listed - methods), (
        f"the boundary lists name(s) that are not methods: {sorted(listed - methods)}")


def test_the_writer_ships_on_by_default(written):
    """Readers shipped before this writer; the writer is now the default. The gate is the
    mechanism, so it gets a test.

    Both the runtime value the constructed library reports and the source text are checked: a build
    could flip the field after construction and the runtime check alone would not notice, and the
    source could carry a value the constructor overrides.
    """
    assert written["checks"]["write_gate_default"] is True
    source = CRYPTO_JS.read_text(encoding="utf-8")
    assert "this.ZK_CONTENT_WRITE_V2 = true;" in source
    # Exactly one assignment, and it is the enabled one: no leftover default-off line survives.
    assert source.count("ZK_CONTENT_WRITE_V2 = true") == 1
    assert "ZK_CONTENT_WRITE_V2 = false" not in source


def test_the_legacy_whole_file_writer_covers_the_flag_off_branch():
    """The writer ships on and the e2e path now exercises the v2 branch by default, so the legacy
    whole-file encryptor -- the branch the flag selects when it is OFF -- keeps a behavioural pin.

    Forcing the flag off in a constructed library, the legacy encryptor produces a NON-framed blob
    (a 12-byte IV, then ciphertext and a GCM tag -- not the DVZ2 content header) that round-trips
    through the legacy reader. (mutation: make the legacy encryptor emit a framed header -> the
    header check reds; or point the OFF upload branch at the v2 writer -> the `encryptFile` slice
    below is not found and this reds.)
    """
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
console.error = () => {{}};
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
(async () => {{
  const lib = new ECCCryptoLibrary();
  lib.ZK_CONTENT_WRITE_V2 = false;                       // force the legacy branch
  const dek = await webcrypto.subtle.generateKey(
      {{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  const plain = new Uint8Array(4096);
  for (let i = 0; i < plain.length; i++) plain[i] = (i * 13) & 0xff;
  const enc = await lib.encryptFile(plain, dek);
  const bytes = new Uint8Array(enc);
  const back = new Uint8Array(await lib.decryptFile(enc, dek));
  let ok = back.length === plain.length;
  for (let i = 0; ok && i < plain.length; i++) if (back[i] !== plain[i]) ok = false;
  process.stdout.write(JSON.stringify({{
    flag_after_force: lib.ZK_CONTENT_WRITE_V2,
    header4: Array.from(bytes.slice(0, 4)),
    total_len: bytes.length,
    roundtrips: ok,
  }}));
}})().catch(e => {{ process.stderr.write('HARNESS ' + (e && e.stack || e)); process.exit(1); }});
"""
    done = subprocess.run([node, "-e", harness], cwd=str(ROOT),
                          capture_output=True, text=True, timeout=120)
    assert done.returncode == 0, done.stdout + done.stderr
    out = json.loads(done.stdout)
    assert out["flag_after_force"] is False
    # DVZ2 is 0x44 0x56 0x5a 0x32; the legacy blob must not carry the v2 content header.
    assert out["header4"] != [0x44, 0x56, 0x5a, 0x32], "the legacy writer emitted a v2 content header"
    # A 12-byte AES-GCM IV + the 4096-byte plaintext + the 16-byte tag; no per-chunk framing.
    assert out["total_len"] == 12 + 4096 + 16
    assert out["roundtrips"] is True

    # The flag-OFF upload branch keeps the whole-file read behind the in-memory refusal. The
    # behavioural 256 MiB refusal runs in the ui/live lane; it is source-pinned here so the legacy
    # branch is not left uncovered now that the default upload path is v2.
    app = (ROOT / "static" / "js" / "app.js").read_text(encoding="utf-8")
    off = app[app.index("The legacy writer takes the whole plaintext"):]
    off = off[:off.index("encryptFile(await entry.file.arrayBuffer()") + 60]
    assert "entry.file.size > MAX_BUFFERED_DOWNLOAD_BYTES" in off
    assert "too large to encrypt in this browser" in off
