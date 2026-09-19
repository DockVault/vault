"""The on-demand version-2 content writer: an encryption that is STARTED, then sealed frame by frame.

The whole-file writers hand back the entire ciphertext. An uploader that wants to send each frame as
it is produced needs the same writer opened up: the attempt token and the exact ciphertext length up
front, then one frame at a time. These tests hold that session to the two things that matter:

  * its bytes are the SAME FILE the other writers produce -- header, then frames -- so every reader
    opens them, and with the same entropy they are byte-for-byte what ``encryptBlobV2`` emits;
  * the attempt token is minted inside the writer and never supplied by a caller, and a resumed
    session is only ever the writer's own record of an attempt, refused for a different-size file.

The per-frame MAC a browser keeps for resuming is keyed from the vault key: it must be stable for the
same plaintext, differ per frame index, and differ under another attempt -- and it is never a bare
digest of the plaintext.
"""

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"

CHUNK = 4096
HEADER = 28
OVERHEAD = 28


def _node(script: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this format must not be skipped"
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
console.error = () => {{}};
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
const codeOf = async fn => {{
  try {{ await fn(); return null; }} catch (e) {{ return e && e.code ? e.code : 'UNCODED'; }}
}};
(async () => {{
  const lib = new ECCCryptoLibrary();
  const CTX = {{ vaultId: '11111111-1111-4111-8111-111111111111',
                objectId: '22222222-2222-4222-8222-222222222222', dekEpoch: 3 }};
  const dek = await webcrypto.subtle.generateKey(
      {{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  const plain = new Uint8Array({CHUNK} * 2 + 300);
  for (let i = 0; i < plain.length; i++) plain[i] = (i * 31 + 7) & 0xff;
  const hex = b => Buffer.from(b).toString('hex');
  const assemble = async s => {{
    const parts = [s.header()];
    const macs = [];
    for (let i = 0; i < s.totalChunks; i++) {{
      const f = await s.sealFrame(i); parts.push(f.frame); macs.push(f.mac);
    }}
    return {{ bytes: Buffer.concat(parts.map(p => Buffer.from(p))), macs }};
  }};
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + (e && e.stack || e)); process.exit(1); }});
"""
    done = subprocess.run([node, "-e", harness], capture_output=True, text=True,
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads([ln for ln in done.stdout.splitlines() if ln.startswith("{")][-1])


def test_a_session_emits_a_file_every_reader_opens_at_the_length_it_declared():
    out = _node(f"""
  const s = await lib.startContentV2Encryption(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  const a = await assemble(s);
  const back = new Uint8Array(await lib.decryptFileV2(new Uint8Array(a.bytes), dek, CTX));
  let lens = 0; for (let i = 0; i < s.totalChunks; i++) lens += s.frameLength(i);
  console.log(JSON.stringify({{
    roundtrip: hex(back) === hex(plain), declared: s.ciphertextLength, actual: a.bytes.length,
    frames: s.totalChunks, frameLens: lens, headerLen: s.header().length,
    tokenInHeader: hex(s.header().slice(12, 28)), blobId: s.blobId }}));
""")
    assert out["roundtrip"] is True
    # Exact, and known before a byte is read: header + plaintext + one nonce-and-tag per frame.
    assert out["frames"] == 3
    assert out["declared"] == out["actual"] == HEADER + (CHUNK * 2 + 300) + OVERHEAD * 3
    assert out["headerLen"] == HEADER and out["frameLens"] == out["actual"] - HEADER
    # One mint feeds both: the token a caller declares IS header bytes 12..28.
    assert re.fullmatch(r"[0-9a-f]{32}", out["blobId"])
    assert out["tokenInHeader"] == out["blobId"]


def test_with_the_same_entropy_a_session_is_byte_identical_to_the_whole_file_writer():
    # Entropy stubbed by SIZE (16 = the token, 12 = a nonce), replayed identically for both writers.
    out = _node(f"""
  const stub = l => {{ let k = 0; l._randomBytes = n => {{
      const b = new Uint8Array(n); for (let i = 0; i < n; i++) b[i] = (k * 17 + i * 3 + n) & 0xff;
      k += 1; return b; }}; }};
  const one = new ECCCryptoLibrary(); stub(one);
  const whole = await one.encryptBlobV2(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  const wholeBytes = Buffer.from(await whole.blob.arrayBuffer());
  const two = new ECCCryptoLibrary(); stub(two);
  const s = await two.startContentV2Encryption(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  const a = await assemble(s);
  console.log(JSON.stringify({{ same: hex(a.bytes) === hex(wholeBytes),
                                sameToken: s.blobId === whole.blobId }}));
""")
    assert out == {"same": True, "sameToken": True}


def test_a_resumed_session_reseals_a_missing_frame_into_a_file_that_still_opens():
    # Frames sealed by the FIRST session, except one; that one sealed by a session RESUMED from the
    # writer's own state. Fresh nonce, same token: each frame authenticates alone under its index.
    out = _node(f"""
  const s1 = await lib.startContentV2Encryption(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  const state = JSON.parse(JSON.stringify(s1.resumeState()));
  const f0 = await s1.sealFrame(0), f2 = await s1.sealFrame(2);
  const s2 = await lib.resumeContentV2Encryption(new Blob([plain]), dek, CTX, state);
  const f1 = await s2.sealFrame(1);
  const bytes = Buffer.concat([s1.header(), f0.frame, f1.frame, f2.frame].map(p => Buffer.from(p)));
  const back = new Uint8Array(await lib.decryptFileV2(new Uint8Array(bytes), dek, CTX));
  const other = new Uint8Array(plain.length - 1);
  console.log(JSON.stringify({{
    opens: hex(back) === hex(plain), sameToken: s2.blobId === s1.blobId,
    sameHeader: hex(s2.header()) === hex(s1.header()),
    macStable: (await s2.frameMac(1)) === f1.mac && (await s1.frameMac(0)) === f0.mac,
    wrongSize: await codeOf(() => lib.resumeContentV2Encryption(new Blob([other]), dek, CTX, state)),
    badState: await codeOf(() => lib.resumeContentV2Encryption(new Blob([plain]), dek, CTX,
                                                               {{ v: 1, blobId: 'zz', totalPlaintext: plain.length }})),
    noState: await codeOf(() => lib.resumeContentV2Encryption(new Blob([plain]), dek, CTX, null)),
    badIndex: await codeOf(() => s1.sealFrame(3)),
  }}));
""")
    assert out["opens"] is True and out["sameToken"] is True and out["sameHeader"] is True
    assert out["macStable"] is True
    # A different-size file is never sealed under the old token; a malformed state is refused.
    assert out["wrongSize"] == "INVALID_INPUT"
    assert out["badState"] == "INVALID_INPUT" and out["noState"] == "INVALID_INPUT"
    assert out["badIndex"] == "INVALID_INPUT"


def test_the_frame_mac_is_keyed_per_frame_and_per_attempt_never_a_bare_digest():
    out = _node(f"""
  const blob = new Blob([plain]);
  const s1 = await lib.startContentV2Encryption(blob, dek, CTX, {{ chunkSize: {CHUNK} }});
  const s2 = await lib.startContentV2Encryption(blob, dek, CTX, {{ chunkSize: {CHUNK} }});
  const dek2 = await webcrypto.subtle.generateKey(
      {{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  const s3 = await lib.resumeContentV2Encryption(blob, dek2, CTX, s1.resumeState());
  const same = new Uint8Array({CHUNK} * 2);           // two identical all-zero frames
  const sz = await lib.startContentV2Encryption(new Blob([same]), dek, CTX, {{ chunkSize: {CHUNK} }});
  console.log(JSON.stringify({{
    m0: await s1.frameMac(0), otherAttempt: await s2.frameMac(0), otherKey: await s3.frameMac(0),
    z0: await sz.frameMac(0), z1: await sz.frameMac(1),
    frame0: hex(plain.slice(0, {CHUNK})) }}));
""")
    assert re.fullmatch(r"[0-9a-f]{64}", out["m0"])
    # Bound to the attempt and to the vault key: unlinkable across attempts, useless without the key.
    assert out["otherAttempt"] != out["m0"] and out["otherKey"] != out["m0"]
    # Bound to the index: identical plaintext frames do not share a MAC.
    assert out["z0"] != out["z1"]
    # And not an unkeyed digest of the plaintext, which would be an offline confirmation oracle.
    frame0 = bytes.fromhex(out["frame0"])
    assert out["m0"] != hashlib.sha256(frame0).hexdigest()
    assert out["m0"] != hashlib.sha256((0).to_bytes(8, "big") + frame0).hexdigest()


def _method_src(name: str) -> str:
    src = CRYPTO_JS.read_text(encoding="utf-8")
    start = src.index(f"    async {name}(")
    body = src[start:src.index("\n    }\n", start)]
    return "\n".join(ln for ln in body.splitlines() if not ln.lstrip().startswith(("//", "*", "/*")))


def test_the_attempt_token_is_minted_inside_the_writer_and_never_taken_from_a_caller():
    # The public start has no token parameter and reads none from its options: one mint, in here.
    # (mutation: accept `opts.blobId` / a token argument -> red.)
    start = _method_src("startContentV2Encryption")
    assert start.splitlines()[0].strip() == "async startContentV2Encryption(blob, vaultDEK, context, options) {"
    assert start.count("this._randomBytes(16)") == 1
    assert "blobId" not in start and "token" not in start.lower()
    # A resume takes the writer's own state, and refuses a file of another size before anything
    # is sealed under the old token. (mutation: drop the size check -> red, here and in the run.)
    resume = _method_src("resumeContentV2Encryption")
    assert "blob.size !== s.totalPlaintext" in resume
    assert "_randomBytes" not in resume
    # The shared session mints nothing: the token only ever arrives from one of the two above.
    assert "_randomBytes(16)" not in _method_src("_v2ContentSession")
