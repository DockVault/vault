"""A buffered zero-knowledge download: what it returns, and what it never returns.

When a chunk-framed file cannot be streamed to disk it is decrypted a record at a time and the
pieces are held until the end, each wrapped in a Blob of its own as it arrives. Keeping the pieces as
plain bytes and building one Blob at the end was tried and MEASURED (250 MiB, three downloads each
way, bytes identical throughout): the browser process ends with one copy of the file either way --
the Blob that is saved has to exist whole -- and the page paid for a second copy until the end,
about 295 MiB against about 70. So the Blob per piece is the shipped shape, and changing it again
is a decision to take with numbers.

What the tests below hold does not depend on that shape, and was not covered before: the two
buffered reads are RUN against the real decryptor. What comes back is the file, made of exactly the
pieces in order; a damaged record stops the read and nothing of the file is returned; and the
reader hands out every piece as a buffer of its own, only after that record's tag has verified.
"""
import json
import shutil
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

from _js_source import strip_comments  # noqa: E402

ROOT = Path(__file__).resolve().parents[1]
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"

CHUNK = 4096
SITES = ("async function zkMaybeDecryptBlob(", "async function zkMaybeDecryptResponse(")


def _fn(js: str, head: str) -> str:
    start = js.index(head)
    return js[start:js.index("\n}\n", start) + 3]


def _code(src: str) -> str:
    return strip_comments(src)


def _run(script: str) -> dict:
    node = shutil.which("node")
    assert node, "Node is required: the browser side of this path must not be skipped"
    js = APP_JS.read_text(encoding="utf-8")
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
console.error = () => {{}};
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
const lib = new ECCCryptoLibrary();
const eccLib = () => lib;
const isZkVault = () => true;
let resolved;
const zkResolveKey = async () => resolved;
{_fn(js, SITES[0])}
{_fn(js, SITES[1])}
(async () => {{
  const CTX = {{ vaultId: '11111111-1111-4111-8111-111111111111',
                objectId: '22222222-2222-4222-8222-222222222222', dekEpoch: 2 }};
  const dek = await webcrypto.subtle.generateKey({{ name: 'AES-GCM', length: 256 }}, true, ['encrypt', 'decrypt']);
  resolved = {{ dek, context: CTX }};
  const plain = new Uint8Array({CHUNK} * 2 + 17);                       // three records, the last short
  for (let i = 0; i < plain.length; i++) plain[i] = (i * 13 + 5) & 0xff;
  const s = await lib.startContentV2Encryption(new Blob([plain]), dek, CTX, {{ chunkSize: {CHUNK} }});
  const sealedParts = [s.header()];
  for (let f = 0; f < s.totalChunks; f++) sealedParts.push((await s.sealFrame(f)).frame);
  const cipher = Buffer.concat(sealedParts.map(p => Buffer.from(p)));
  const hex = b => Buffer.from(b).toString('hex');
  const bytesOf = async blob => Buffer.from(await blob.arrayBuffer());
  // Watch what the accumulation is handed, and what kind of thing it keeps.
  const watch = (name) => {{ const real = lib[name].bind(lib); const seen = [];
    lib[name] = (...args) => {{ const write = args[args.length - 1];        // the shipped callers pass it last
      args[args.length - 1] = async p => {{ seen.push(Buffer.from(p)); return write(p); }};
      return real(...args); }};
    return {{ seen, restore: () => {{ lib[name] = real; }} }}; }};
  const response = (bytes) => new Response(new Blob([bytes]).stream(), {{ headers: {{
      'Content-Length': String(bytes.length), 'Content-Type': 'application/x-test' }} }});
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + (e && e.stack || e)); process.exit(1); }});
"""
    done = subprocess.run([node, "-e", harness], capture_output=True, text=True, timeout=120, cwd=str(ROOT))
    assert done.returncode == 0, done.stdout + done.stderr
    return json.loads([ln for ln in done.stdout.splitlines() if ln.startswith("{")][-1])


def test_both_buffered_reads_return_the_file_made_of_exactly_the_pieces_in_order():
    out = _run("""
  const w1 = watch('decryptBlobV2');
  const viaBlob = await zkMaybeDecryptBlob(new Blob([cipher], { type: 'application/x-test' }), { id: 'V' }, 2, 'F');
  w1.restore();
  const w2 = watch('decryptStreamV2');
  const viaStream = await zkMaybeDecryptResponse(response(cipher), { id: 'V' }, 2, 'F');
  w2.restore();
  console.log(JSON.stringify({
    blob:   { pieces: w1.seen.length, type: viaBlob.type, size: viaBlob.size,
              isTheSource: hex(await bytesOf(viaBlob)) === hex(plain),
              isThePieces: hex(await bytesOf(viaBlob)) === hex(Buffer.concat(w1.seen)) },
    stream: { pieces: w2.seen.length, type: viaStream.type, size: viaStream.size,
              isTheSource: hex(await bytesOf(viaStream)) === hex(plain),
              isThePieces: hex(await bytesOf(viaStream)) === hex(Buffer.concat(w2.seen)) },
  }));
""")
    for site in ("blob", "stream"):
        r = out[site]
        assert r["pieces"] == 3, r
        # Byte-identical to what was encrypted, and exactly the pieces handed over, in order.
        # (mutation: drop or reorder a piece -> red.)
        assert r["isTheSource"] is True and r["isThePieces"] is True, (site, r)
        assert r["size"] == CHUNK * 2 + 17 and r["type"] == "application/x-test", (site, r)


def test_a_piece_is_kept_only_after_its_record_has_verified_and_nothing_of_a_bad_file_is_returned():
    # One bit flipped in the LAST record: the first two verify and are handed over, the third must
    # not be, and the read as a whole must fail -- no Blob of the two good pieces comes back.
    out = _run("""
  const bad = Buffer.from(cipher); bad[bad.length - 3] ^= 1;
  const tries = {};
  for (const [name, call] of [
      ['blob',   () => zkMaybeDecryptBlob(new Blob([bad]), { id: 'V' }, 2, 'F')],
      ['stream', () => zkMaybeDecryptResponse(response(bad), { id: 'V' }, 2, 'F')]]) {
    const w = watch(name === 'blob' ? 'decryptBlobV2' : 'decryptStreamV2');
    let returned = null, code = null;
    try { returned = await call(); } catch (e) { code = e && e.code ? e.code : 'UNCODED'; }
    w.restore();
    tries[name] = { handedOver: w.seen.length, returned: returned === null ? null : 'a blob', code,
                    onlyGenuine: hex(Buffer.concat(w.seen)) === hex(plain.subarray(0, w.seen.length * """ + str(CHUNK) + """)) };
  }
  console.log(JSON.stringify(tries));
""")
    for site in ("blob", "stream"):
        r = out[site]
        assert r["returned"] is None and r["code"] == "CONTENT_AUTH_FAILED", (site, r)
        # (mutation in the READER: hand a record over before checking its tag -> three -> red.)
        assert r["handedOver"] == 2 and r["onlyGenuine"] is True, (site, r)


def test_every_piece_the_reader_hands_out_is_a_buffer_of_its_own():
    # A property of the READER that anything keeping a piece past the callback depends on -- the
    # streamed path transfers each piece to the download as it comes. Wrapping a piece in a Blob
    # copies it at once, so the buffered reads would not notice a reader that reused one buffer
    # for every record; this does.
    out = _run("""
  const kept = [];
  await lib.decryptBlobV2(new Blob([cipher]), dek, CTX, p => { kept.push(p); });
  const keptStream = [];
  await lib.decryptStreamV2(new Blob([cipher]).stream(), cipher.length, dek, CTX, p => { keptStream.push(p); });
  const own = (list) => new Set(list.map(p => p.buffer)).size === list.length
      && list.every(p => p.byteOffset === 0 && p.byteLength === p.buffer.byteLength);
  console.log(JSON.stringify({ blob: own(kept), stream: own(keptStream),
    stillRight: hex(Buffer.concat(kept.map(p => Buffer.from(p)))) === hex(plain)
             && hex(Buffer.concat(keptStream.map(p => Buffer.from(p)))) === hex(plain) }));
""")
    assert out == {"blob": True, "stream": True, "stillRight": True}, out


def test_each_buffered_site_wraps_a_piece_in_a_blob_as_it_arrives():
    # The source half, comment-stripped: the measured shape. A piece is wrapped as it arrives, so it
    # leaves the page then, and the pieces are joined once at the end.
    # (mutation: push the raw piece at either site -> red. It is byte-for-byte the same download;
    # what differs is a copy of the whole file held by the page until the end -- which only a
    # measurement shows, and did.)
    js = APP_JS.read_text(encoding="utf-8")
    for head in SITES:
        code = _code(_fn(js, head))
        assert code.count("p => { parts.push(new Blob([p])); }") == 1, head
        assert "parts.push(p)" not in code, head
        assert code.count("new Blob(parts, { type })") == 1, head
