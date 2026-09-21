"""The upload chunks a sealed-as-it-uploads transfer sends, produced by the SHIPPED uploader code.

The source pins say the uploader has the right shape. This runs the part of it that touches bytes:
``_sealUploadChunk`` and the two pure planning helpers are lifted out of ``app.js`` verbatim and driven
under Node against the real writer session, so what is checked is what the browser would put on the
wire -- that the chunks are whole frames of the planned length, that together they are exactly the
file the session declared, that a reader opens it, and that a continued upload which re-seals a whole
missing chunk under the same token still yields a file that opens.

What this cannot show is the transfer itself (the requests, the tray, IndexedDB) -- that is the live
lane.
"""

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"

CHUNK = 4096
FRAME = CHUNK + 28


def _shipped() -> str:
    """The shipped planning helpers and the chunk sealer, as runnable JavaScript."""
    js = APP_JS.read_text(encoding="utf-8")
    out = []
    for name in ("zkUploadPlan", "zkUploadChunkFrames"):
        m = re.search(r"function " + name + r"\([^)]*\) \{.*?\n\}", js, re.S)
        assert m, name
        out.append(m.group(0))
    m = re.search(r"const ZK_FRAMES_PER_UPLOAD_CHUNK = \d+;", js)
    assert m
    out.append(m.group(0))
    start = js.index("    async _sealUploadChunk(it, index) {")
    method = js[start:js.index("\n    },\n", start) + 6]
    out.append("const uploader = {\n" + method + "\n};")
    return "\n".join(out)


def _node(script: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this path must not be skipped"
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
console.error = () => {{}};
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
{_shipped()}
const codeOf = async fn => {{
  try {{ await fn(); return null; }} catch (e) {{ return e && e.code ? e.code : 'UNCODED'; }}
}};
(async () => {{
  const lib = new ECCCryptoLibrary();
  const CTX = {{ vaultId: '11111111-1111-4111-8111-111111111111',
                objectId: '22222222-2222-4222-8222-222222222222', dekEpoch: 2 }};
  const dek = await webcrypto.subtle.generateKey(
      {{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  const plain = new Uint8Array({CHUNK} * 9 + 17);              // 10 frames -> 3 upload chunks
  for (let i = 0; i < plain.length; i++) plain[i] = (i * 13 + 5) & 0xff;
  const hex = b => Buffer.from(b).toString('hex');
  const open = async bytes => new Uint8Array(await lib.decryptFileV2(new Uint8Array(bytes), dek, CTX));
  const item = s => ({{ zkStream: s, frameMacs: new Array(s.totalChunks).fill(null) }});
  // What the seal hands to fetch. Its KIND is recorded, because that decides which process holds
  // the copy -- and the choice between the two was made by measurement, not by taste.
  const kinds = [];
  const chunkBytes = async (it, i) => {{
    const body = await uploader._sealUploadChunk(it, i);
    kinds.push(body && body.constructor ? body.constructor.name : typeof body);
    return body instanceof Uint8Array ? Buffer.from(body) : Buffer.from(await body.arrayBuffer());
  }};
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + (e && e.stack || e)); process.exit(1); }});
"""
    done = subprocess.run([node, "-e", harness], capture_output=True, text=True,
                          timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads([ln for ln in done.stdout.splitlines() if ln.startswith("{")][-1])


def test_the_chunks_the_uploader_sends_are_whole_frames_and_open_as_the_declared_file():
    out = _node(f"""
  const s = await lib.startContentV2Encryption(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  // The same session, with every part it hands out written down as it goes.
  const handedOut = [];
  const recording = {{ totalChunks: s.totalChunks,
    header: () => {{ const h = s.header(); handedOut.push(Buffer.from(h)); return h; }},
    sealFrame: async f => {{ const r = await s.sealFrame(f); handedOut.push(Buffer.from(r.frame)); return r; }} }};
  const it = item(recording);
  const plan = zkUploadPlan(s.chunkSize + lib.V2_CONTENT_CHUNK_OVERHEAD, s.totalChunks,
                            s.ciphertextLength, ZK_FRAMES_PER_UPLOAD_CHUNK);
  const chunks = [];
  for (let i = 0; i < plan.totalChunks; i++) chunks.push(await chunkBytes(it, i));
  const whole = Buffer.concat(chunks);
  console.log(JSON.stringify({{
    plan, lens: chunks.map(c => c.length), total: whole.length, declared: s.ciphertextLength,
    opens: hex(await open(whole)) === hex(plain),
    headerToken: hex(chunks[0].subarray(12, 28)), blobId: s.blobId,
    onlyChunk0HasHeader: chunks.slice(1).every(c => c.subarray(0, 4).toString('latin1') !== 'DVZ2'),
    macs: it.frameMacs.filter(m => typeof m === 'string' && m.length === 64).length,
    frames: s.totalChunks,
    kinds, parts: handedOut.length, sameBytesAsTheParts: Buffer.concat(handedOut).equals(whole),
  }}));
""")
    assert out["frames"] == 10 and out["plan"]["totalChunks"] == 3
    assert out["plan"]["chunkSize"] == 4 * FRAME                       # a whole number of frames
    # chunk 0 = header + 4 frames; chunk 1 = 4 frames; the last = 2 frames, the second short.
    assert out["lens"] == [28 + 4 * FRAME, 4 * FRAME, FRAME + (17 + 28)]
    assert out["total"] == out["declared"] == out["plan"]["totalSize"]
    assert out["opens"] is True
    # The token the uploader declares IS bytes 12..28 of the first chunk it sends.
    assert out["headerToken"] == out["blobId"] and out["onlyChunk0HasHeader"] is True
    # A MAC is recorded for every frame sealed.
    assert out["macs"] == out["frames"] == 10
    # Each chunk is handed over as a BLOB of the parts. One Uint8Array was tried and MEASURED: it
    # freed the browser process's copy of the file, and the page then retained about two files'
    # worth that a forced collection did not release -- a higher total. Until what holds them is
    # found the Blob is the shipped shape, and changing it again is a decision to take with
    # numbers, not in passing. (mutation: hand over one Uint8Array again -> red.)
    assert out["kinds"] == ["Blob"] * 3, out["kinds"]
    # And it is a Blob of EXACTLY the parts, in order: the header and the ten frames, nothing added
    # or dropped. (mutation: `new Blob(parts.slice(1))` -> red here, and it no longer opens.)
    assert out["parts"] == 11 and out["sameBytesAsTheParts"] is True


def test_a_continued_upload_reseals_a_whole_missing_chunk_under_the_same_token():
    out = _node(f"""
  const s1 = await lib.startContentV2Encryption(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  const it1 = item(s1);
  const c0 = await chunkBytes(it1, 0), c1 = await chunkBytes(it1, 1), c2 = await chunkBytes(it1, 2);
  // The server holds chunks 0 and 2; chunk 1 never arrived. The record has every MAC, because a
  // frame's MAC is stored before its bytes are sent.
  const state = JSON.parse(JSON.stringify({{ ...s1.resumeState(), frameMacs: it1.frameMacs }}));
  const s2 = await lib.resumeContentV2Encryption(new Blob([plain]), dek, CTX, state);
  const it2 = {{ zkStream: s2, frameMacs: state.frameMacs.slice() }};
  const again1 = await chunkBytes(it2, 1);                    // the WHOLE index, fresh nonces
  const whole = Buffer.concat([c0, again1, c2]);
  // The same file, edited at the same size inside chunk 1: the old token must not seal it.
  const edited = new Uint8Array(plain); edited[{CHUNK} * 5 + 3] ^= 0x01;
  const s3 = await lib.resumeContentV2Encryption(new Blob([edited]), dek, CTX, state);
  const it3 = {{ zkStream: s3, frameMacs: state.frameMacs.slice() }};
  console.log(JSON.stringify({{
    opens: hex(await open(whole)) === hex(plain),
    resealedDiffers: hex(again1) !== hex(c1), sameLength: again1.length === c1.length,
    macsUnchanged: JSON.stringify(it2.frameMacs) === JSON.stringify(state.frameMacs),
    editedRefused: await codeOf(() => uploader._sealUploadChunk(it3, 1)),
    noSession: await codeOf(() => uploader._sealUploadChunk({{ zkStream: null, frameMacs: [] }}, 0)),
  }}));
""")
    assert out["opens"] is True
    # Fresh nonces, so the bytes differ -- which is why a digest of them is never compared -- yet the
    # MACs of the PLAINTEXT are what they were, which is what lets a resume recognise the same file.
    assert out["resealedDiffers"] is True and out["sameLength"] is True
    assert out["macsUnchanged"] is True
    assert out["editedRefused"] == "CONTENT_INVALID"
    # An item with no writer session sends nothing, rather than anything.
    assert out["noSession"] == "UNCODED"
