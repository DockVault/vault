"""Version 1 of the account private-key envelope.

Offline by design: every assertion here is either pure Python or the real shipped browser module
loaded under Node, so the contract holds even when no deployment is running. The behavioural
counterparts that need a live stack live in the crypto compatibility and UI suites.

Specified by ``docs/design/vault-private-key-envelope-v1.md``. Where a test here and that document
disagree, the document is the contract: fix the code, or change the document first and say why.
"""

import json
from pathlib import Path
import subprocess

import pytest

import crypto_reference_vectors as reference


pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "crypto" / "private-envelope-v1"
LEGACY_FIXTURE = (
    ROOT / "tests" / "fixtures" / "crypto" / "v0.10.0" / "zk-private-envelope-legacy.json"
)
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"
DESIGN_DOC = ROOT / "docs" / "design" / "vault-private-key-envelope-v1.md"


def _vector() -> dict:
    # Loaded through the reference module so the public-test-material guards actually run. A bare
    # json.loads would silently skip them, and these fixtures must never carry real key material.
    return reference.load_unreleased_vector(FIXTURE_DIR / "zk-private-envelope-v1.json")


def _legacy_vector() -> dict:
    return json.loads(LEGACY_FIXTURE.read_text(encoding="utf-8"))


def _node(script: str) -> dict:
    """Run the REAL shipped ecc_crypto.js under Node's Web Crypto and return its JSON result.

    The module is ``require``d, exactly as the existing vector harness loads it, so what is under
    test is the file the browser is served rather than a copy of it.
    """
    harness = f"""
const path = require('path');
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
const quiet = {{ ...console, log: console.log, error() {{}}, warn() {{}} }};
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
const realLog = console.log;
console.error = () => {{}};
const rejected = async fn => {{ try {{ await fn(); return false; }} catch (e) {{ return true; }} }};
(async () => {{
  const lib = new ECCCryptoLibrary();
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + e.stack); process.exit(1); }});
"""
    proc = subprocess.run(
        ["node", "-e", harness], capture_output=True, text=True, timeout=300, cwd=str(ROOT)
    )
    assert proc.returncode == 0, proc.stderr
    line = [ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1]
    return json.loads(line)


# --------------------------------------------------------------------------------------------
# The pinned vector
# --------------------------------------------------------------------------------------------


def test_manifest_pins_the_exact_reviewed_fixture_set() -> None:
    """A vector cannot be added, nor an existing one edited, without review."""
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    listed = [entry["path"] for entry in manifest["vectors"]]
    assert {p.name for p in FIXTURE_DIR.glob("*.json")} == {"manifest.json", *listed}
    for entry in manifest["vectors"]:
        assert reference.sha256_file(FIXTURE_DIR / entry["path"]) == entry["sha256"]


def test_reference_writer_reproduces_the_pinned_bytes_exactly() -> None:
    vector = _vector()
    assert reference.encode_private_envelope_v1(vector) == vector["expected"]["envelope"]


def test_reference_reader_round_trips_the_pinned_envelope() -> None:
    vector = _vector()
    pem = reference.decode_private_envelope_v1(
        vector["expected"]["envelope"], password=vector["inputs"]["password"]
    )
    assert pem.startswith("-----BEGIN PRIVATE KEY-----")
    assert pem.endswith("-----END PRIVATE KEY-----")
    assert not pem.endswith("\n")


def test_pinned_aad_is_the_documented_transcript() -> None:
    """The AAD is a byte-exactness surface: drift makes affected envelopes unreadable forever."""
    vector = _vector()
    envelope = vector["expected"]["envelope"]
    expected = (
        f"dockvault-private-key-envelope-v1|PBKDF2-SHA256|{envelope['iter']}|"
        f"AES-256-GCM|{envelope['salt']}"
    )
    assert vector["expected"]["aad_utf8"] == expected
    assert reference.private_envelope_v1_aad(
        envelope["iter"], envelope["salt"]
    ) == expected.encode("utf-8")


def test_transcript_cannot_be_confused_by_a_delimiter_in_a_field() -> None:
    """Base64 has no '|', so no field value can shift a boundary in the transcript."""
    envelope = _vector()["expected"]["envelope"]
    assert "|" not in envelope["salt"] and "|" not in envelope["iv"]


# --------------------------------------------------------------------------------------------
# The shipped browser implementation
# --------------------------------------------------------------------------------------------


def test_browser_and_reference_agree_byte_for_byte() -> None:
    """Two independent implementations of the same frozen bytes. This is what catches drift."""
    vector = _vector()
    inputs = vector["inputs"]
    out = _node(f"""
  const queue = [Buffer.from({json.dumps(inputs['salt_hex'])}, 'hex'),
                 Buffer.from({json.dumps(inputs['iv_hex'])}, 'hex')];
  const legacy = {json.dumps(_legacy_vector()['expected']['envelope'])};
  const pem = await lib.decryptPrivateKey(
      legacy.encrypted, {json.dumps(inputs['password'])}, legacy.salt, legacy.iterations);
  const real = webcrypto.getRandomValues.bind(webcrypto);
  global.window.crypto = new Proxy(webcrypto, {{ get(t, p) {{
      if (p === 'getRandomValues') return a => {{ const n = queue.shift();
          if (!n) return real(a); a.set(n); return a; }};
      const v = t[p]; return typeof v === 'function' ? v.bind(t) : v; }} }});
  const written = await lib.encryptPrivateKeyV1(pem, {json.dumps(inputs['password'])});
  realLog(JSON.stringify({{ written }}));
""")
    assert out["written"] == vector["expected"]["envelope"]


def test_browser_reads_v1_and_the_pinned_legacy_envelope() -> None:
    """The point of the version: both shapes read through one reader, same key out."""
    vector, legacy = _vector(), _legacy_vector()
    out = _node(f"""
  const v1 = {json.dumps(vector['expected']['envelope'])};
  const l = {json.dumps(legacy['expected']['envelope'])};
  const pw = {json.dumps(vector['inputs']['password'])};
  const a = await lib.decryptPrivateEnvelope(v1, pw);
  const b = await lib.decryptPrivateEnvelope(l, pw);
  realLog(JSON.stringify({{
      v1_reads: a.startsWith('-----BEGIN PRIVATE KEY-----'),
      legacy_reads: b.startsWith('-----BEGIN PRIVATE KEY-----'),
      same_key: a === b,
      legacy_via_original_reader:
          (await lib.decryptPrivateKey(l.encrypted, pw, l.salt, l.iterations)) === b,
  }}));
""")
    assert out == {
        "v1_reads": True,
        "legacy_reads": True,
        "same_key": True,
        "legacy_via_original_reader": True,
    }


def test_browser_rejects_every_malformed_and_tampered_v1_envelope() -> None:
    vector = _vector()
    out = _node(f"""
  const e = {json.dumps(vector['expected']['envelope'])};
  const pw = {json.dumps(vector['inputs']['password'])};
  const c = o => Object.assign({{}}, e, o);
  const flip = s => s.slice(0, -2) + (s.slice(-2) === 'AA' ? 'AB' : 'AA');
  realLog(JSON.stringify({{
    wrong_passphrase:  await rejected(() => lib.decryptPrivateEnvelope(e, pw + 'x')),
    tampered_ct:       await rejected(() => lib.decryptPrivateEnvelope(c({{ ct: flip(e.ct) }}), pw)),
    tampered_iter:     await rejected(() => lib.decryptPrivateEnvelope(c({{ iter: e.iter + 1 }}), pw)),
    unknown_version:   await rejected(() => lib.parsePrivateEnvelope(c({{ v: 2 }}))),
    unknown_kdf:       await rejected(() => lib.parsePrivateEnvelope(c({{ kdf: 'scrypt' }}))),
    unknown_cipher:    await rejected(() => lib.parsePrivateEnvelope(c({{ cipher: 'AES-128-GCM' }}))),
    extra_member:      await rejected(() => lib.parsePrivateEnvelope(c({{ extra: 1 }}))),
    iter_over_ceiling: await rejected(() => lib.parsePrivateEnvelope(c({{ iter: 10000001 }}))),
    iter_zero:         await rejected(() => lib.parsePrivateEnvelope(c({{ iter: 0 }}))),
    iter_float:        await rejected(() => lib.parsePrivateEnvelope(c({{ iter: 1.5 }}))),
    iter_string:       await rejected(() => lib.parsePrivateEnvelope(c({{ iter: '600000' }}))),
    // A salt whose base64 genuinely contains '+' and '/', so the URL-safe substitution below
    // actually changes the string. The pinned fixture's salt happens to contain neither, which
    // would make this assertion vacuous.
    urlsafe_alphabet_is_distinct: (() => {{
        const s = lib._arrayBufferToBase64(new Uint8Array(32).fill(0xfb));
        return s !== s.replace(/\\+/g, '-').replace(/\\//g, '_');
    }})(),
    urlsafe_salt:      await rejected(() => {{
                           const s = lib._arrayBufferToBase64(new Uint8Array(32).fill(0xfb));
                           return lib.parsePrivateEnvelope(
                               c({{ salt: s.replace(/\\+/g, '-').replace(/\\//g, '_') }}));
                       }}),
    noncanonical_b64:  await rejected(() => lib.parsePrivateEnvelope(
                           c({{ salt: e.salt.slice(0, -2) + '/=' }}))),
    short_iv:          await rejected(() => lib.parsePrivateEnvelope(
                           c({{ iv: lib._arrayBufferToBase64(new Uint8Array(11)) }}))),
    short_salt:        await rejected(() => lib.parsePrivateEnvelope(
                           c({{ salt: lib._arrayBufferToBase64(new Uint8Array(31)) }}))),
    tiny_ct:           await rejected(() => lib.parsePrivateEnvelope(
                           c({{ ct: lib._arrayBufferToBase64(new Uint8Array(16)) }}))),
    array:             await rejected(() => lib.parsePrivateEnvelope([])),
    null_envelope:     await rejected(() => lib.parsePrivateEnvelope(null)),
    oversized:         await rejected(() => lib.parsePrivateEnvelope(
                           JSON.stringify(e) + ' '.repeat(20000))),
  }}));
""")
    assert all(out.values()), {k: v for k, v in out.items() if not v}


def test_a_v1_ciphertext_cannot_be_repackaged_into_the_legacy_shape() -> None:
    """This is the AAD's real security value. Everything else it does, key derivation already did."""
    vector = _vector()
    out = _node(f"""
  const e = {json.dumps(vector['expected']['envelope'])};
  const cat = new Uint8Array([...Buffer.from(e.iv, 'base64'), ...Buffer.from(e.ct, 'base64')]);
  const repackaged = {{ encrypted: lib._arrayBufferToBase64(cat), salt: e.salt, iterations: e.iter }};
  realLog(JSON.stringify({{
    repackaged_rejected: await rejected(() => lib.decryptPrivateEnvelope(
        repackaged, {json.dumps(vector['inputs']['password'])})),
  }}));
""")
    assert out["repackaged_rejected"] is True


# --------------------------------------------------------------------------------------------
# Lockout safety: legacy must never get stricter
# --------------------------------------------------------------------------------------------


def test_legacy_keeps_its_lenient_handling_and_gains_only_dos_bounds() -> None:
    """Rejecting a genuine legacy envelope is unrecoverable, so legacy may only gain DoS bounds.

    Registration refuses a second keypair once one exists, and removing it would orphan every
    vault wrap, so a reader that turns away a user's own envelope ends their access permanently.
    """
    legacy = _legacy_vector()
    out = _node(f"""
  const l = {json.dumps(legacy['expected']['envelope'])};
  const pw = {json.dumps(legacy['inputs']['password'])};
  const ok = async o => {{ try {{ return (await lib.decryptPrivateEnvelope(o, pw))
      .startsWith('-----BEGIN PRIVATE KEY-----'); }} catch (e) {{ return false; }} }};
  realLog(JSON.stringify({{
    as_pinned:           await ok(l),
    iterations_absent:   await ok({{ encrypted: l.encrypted, salt: l.salt }}),
    iterations_null:     await ok({{ encrypted: l.encrypted, salt: l.salt, iterations: null }}),
    iterations_string:   await ok({{ encrypted: l.encrypted, salt: l.salt, iterations: '600000' }}),
    iterations_nonsense: await ok({{ encrypted: l.encrypted, salt: l.salt, iterations: 'lots' }}),
    extra_member_ok:     await ok(Object.assign({{}}, l, {{ future_field: 'ignored' }})),
    ceiling_applies:     await rejected(() => lib.parsePrivateEnvelope(
                             Object.assign({{}}, l, {{ iterations: 10000001 }}))),
  }}));
""")
    assert out["as_pinned"] is True
    assert out["iterations_absent"] is True
    assert out["iterations_null"] is True
    assert out["iterations_string"] is True
    assert out["iterations_nonsense"] is True, (
        "a nonsense iteration count must fall back, not reject: rejecting deployed data is "
        "unrecoverable, and the ceiling already bounds the expensive direction"
    )
    assert out["extra_member_ok"] is True
    assert out["ceiling_applies"] is True


def test_the_legacy_writer_is_untouched() -> None:
    """The legacy pair is deliberately unmodified so its pinned writer vector keeps proving the
    deployed format has not drifted. v1 is a SEPARATE writer."""
    source = CRYPTO_JS.read_text(encoding="utf-8")
    legacy_writer = source[
        source.index("async encryptPrivateKey(") : source.index("async decryptPrivateKey(")
    ]
    assert "additionalData" not in legacy_writer
    assert "PRIV_ENVELOPE" not in legacy_writer
    assert "async encryptPrivateKeyV1(" in source


# --------------------------------------------------------------------------------------------
# Writer gate and key consistency
# --------------------------------------------------------------------------------------------


def test_the_v1_writer_ships_disabled_and_every_write_goes_through_the_gate() -> None:
    """Enabling v1 is forward-only for a deployment, so merging code must not enable it."""
    source = CRYPTO_JS.read_text(encoding="utf-8")
    app = APP_JS.read_text(encoding="utf-8")
    assert "this.PRIV_ENVELOPE_WRITE_V1 = false;" in source
    assert app.count("async function zkWrapPrivateKey(") == 1
    body = app[app.index("async function zkWrapPrivateKey(") :][:700]
    assert "PRIV_ENVELOPE_WRITE_V1" in body
    assert "encryptPrivateKeyV1" in body
    # No write path may bypass the gate by calling a writer directly.
    outside = app.replace(body, "")
    assert "encryptPrivateKey(" not in outside
    assert "encryptPrivateKeyV1(" not in outside


def test_writer_draws_a_fresh_salt_and_iv_every_time() -> None:
    """Reusing an IV under a derived key, over this structured PEM plaintext, would leak it."""
    out = _node("""
  const kp = await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-384'}, true, ['deriveBits']);
  const b = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', kp.privateKey)).toString('base64');
  const pem = '-----BEGIN PRIVATE KEY-----\\n' + b.match(/.{1,64}/g).join('\\n') + '\\n-----END PRIVATE KEY-----';
  const a = await lib.encryptPrivateKeyV1(pem, 'same-passphrase');
  const c = await lib.encryptPrivateKeyV1(pem, 'same-passphrase');
  realLog(JSON.stringify({
      salt_differs: a.salt !== c.salt,
      iv_differs: a.iv !== c.iv,
      ct_differs: a.ct !== c.ct,
  }));
""")
    assert out == {"salt_differs": True, "iv_differs": True, "ct_differs": True}


def test_key_consistency_accepts_the_real_pair_and_fails_closed_otherwise() -> None:
    """Decrypting proves the passphrase; it does not prove this is the ACCOUNT's key."""
    out = _node("""
  const mk = async () => {
    const kp = await webcrypto.subtle.generateKey({name:'ECDH',namedCurve:'P-384'}, true, ['deriveBits']);
    const pk = Buffer.from(await webcrypto.subtle.exportKey('pkcs8', kp.privateKey)).toString('base64');
    const sp = Buffer.from(await webcrypto.subtle.exportKey('spki', kp.publicKey)).toString('base64');
    return {
      priv: '-----BEGIN PRIVATE KEY-----\\n' + pk.match(/.{1,64}/g).join('\\n') + '\\n-----END PRIVATE KEY-----',
      pub:  '-----BEGIN PUBLIC KEY-----\\n' + sp.match(/.{1,64}/g).join('\\n') + '\\n-----END PUBLIC KEY-----',
    };
  };
  const A = await mk(), B = await mk();
  const M = (p, q) => lib.privateKeyMatchesRegisteredPublicKey(p, q);
  realLog(JSON.stringify({
    matching_pair:      await M(A.priv, A.pub),
    different_key:      await M(A.priv, B.pub),
    public_key_absent:  await M(A.priv, null),
    public_key_empty:   await M(A.priv, '   '),
    public_key_garbage: await M(A.priv, 'not a pem'),
    whitespace_noise:   await M(A.priv, '\\n  ' + A.pub + '  \\n'),
    crlf_line_endings:  await M(A.priv, A.pub.replace(/\\n/g, '\\r\\n')),
  }));
""")
    assert out["matching_pair"] is True
    # PEM cosmetics are not key material; a raw-point comparison must see through them.
    assert out["whitespace_noise"] is True
    assert out["crlf_line_endings"] is True
    # Everything else fails CLOSED. "Cannot check" must never mean "check passed".
    assert out["different_key"] is False
    assert out["public_key_absent"] is False
    assert out["public_key_empty"] is False
    assert out["public_key_garbage"] is False


# --------------------------------------------------------------------------------------------
# The recovery kit wrapper
# --------------------------------------------------------------------------------------------


def test_recovery_kit_wrapper_is_bounded_before_anything_expensive() -> None:
    """The kit is a file the user selects, so its wrapper is as attacker-supplied as its envelope."""
    legacy = _legacy_vector()
    out = _node(f"""
  const env = {json.dumps(legacy['expected']['envelope'])};
  const base = {{ type: 'dockvault-zk-recovery-key', version: 1,
                 user_id: 'u', fingerprint: 'f', public_key: 'p', recovery: env }};
  const k = o => JSON.stringify(Object.assign({{}}, base, o));
  const ok = t => {{ try {{ lib.parseRecoveryKitFile(t); return true; }} catch (e) {{ return false; }} }};
  realLog(JSON.stringify({{
    genuine_kit:        ok(k({{}})),
    unknown_field_ok:   ok(k({{ future_field: 'ignored' }})),
    wrong_type:         !ok(k({{ type: 'something-else' }})),
    unknown_version:    !ok(k({{ version: 2 }})),
    missing_envelope:   !ok(k({{ recovery: undefined }})),
    oversized_file:     !ok(k({{}}) + ' '.repeat(70000)),
    overlong_field:     !ok(k({{ public_key: 'x'.repeat(5000) }})),
    not_json:           !ok('this is not json'),
    array_file:         !ok('[]'),
    bad_inner_envelope: !ok(k({{ recovery: {{ nonsense: true }} }})),
  }}));
""")
    assert all(out.values()), {k: v for k, v in out.items() if not v}


# --------------------------------------------------------------------------------------------
# The document is the contract
# --------------------------------------------------------------------------------------------


def test_design_document_and_code_agree_on_every_bound() -> None:
    """A number that drifts between the specification and the code is how lockouts happen."""
    doc = DESIGN_DOC.read_text(encoding="utf-8")
    source = CRYPTO_JS.read_text(encoding="utf-8")
    for label, doc_text, code_text in [
        ("iteration ceiling", "10,000,000", "this.PRIV_ENVELOPE_MAX_ITER = 10000000;"),
        ("serialized cap", "16,384", "this.PRIV_ENVELOPE_MAX_SERIALIZED = 16384;"),
        ("ciphertext cap", "8,192", "this.PRIV_ENVELOPE_MAX_CT = 8192;"),
        ("kit file cap", "65,536", "this.RECOVERY_KIT_MAX_FILE = 65536;"),
        ("kit field cap", "4,096", "this.RECOVERY_KIT_MAX_FIELD = 4096;"),
    ]:
        assert doc_text in doc, f"{label}: {doc_text} absent from the design document"
        assert code_text in source, f"{label}: {code_text} absent from the implementation"
    # The document must keep saying there is no policy floor: a floor can only lock users out.
    assert "no policy floor" in doc


# --------------------------------------------------------------------------------------------
# Call-site wiring
#
# The tests above prove the comparator and the parsers work. They say nothing about whether the
# unlock paths actually USE them -- the check could be deleted from every call site and they would
# all still pass. Section 6's operative claim ("no private key, no derived key and no vault key is
# cached" unless the check passes) is a property of the CALL SITES, so it is pinned here.
# --------------------------------------------------------------------------------------------


def _fn_body(source: str, signature: str) -> str:
    """The source of one top-level async function, up to the next one."""
    start = source.index(signature)
    nxt = source.find("\nasync function ", start + 1)
    end = source.find("\nfunction ", start + 1)
    stop = min(x for x in (nxt, end, len(source)) if x != -1)
    return source[start:stop]


def test_every_stored_envelope_read_goes_through_the_versioned_reader() -> None:
    """No path may keep using the legacy-only reader, or it would reject v1 once enabled.

    This is not hypothetical: an early draft of this change left a leftover shape check that
    required `.encrypted` and `.salt`, which would have broken recovery export the moment the
    writer was switched on.
    """
    app = APP_JS.read_text(encoding="utf-8")
    for signature in (
        "async function zkEnsureUnlocked(",
        "async function zkChangePassphrase(",
        "async function zkExportRecoveryKey(",
        "async function zkRestoreFromRecoveryKey(",
    ):
        body = _fn_body(app, signature)
        assert "decryptPrivateEnvelope(" in body, f"{signature} does not use the v1-aware reader"
        assert "decryptPrivateKey(" not in body, f"{signature} still uses the legacy-only reader"
        # A leftover legacy shape assertion would reject a v1 envelope.
        assert ".encrypted || " not in body and "!bundle.encrypted" not in body, signature


def test_every_unlock_path_checks_key_consistency_before_caching_anything() -> None:
    """Section 6's fail-closed claim is a property of the call sites, not of the comparator."""
    app = APP_JS.read_text(encoding="utf-8")

    unlock = _fn_body(app, "async function zkEnsureUnlocked(")
    assert "privateKeyMatchesRegisteredPublicKey(" in unlock
    # Nothing may be cached before the check passes.
    assert unlock.index("privateKeyMatchesRegisteredPublicKey(") < unlock.index(
        "zkState.privateKey ="
    ), "the private key is cached before the consistency check"

    change = _fn_body(app, "async function zkChangePassphrase(")
    assert "privateKeyMatchesRegisteredPublicKey(" in change
    # The re-wrap replaces the account's only copy, so the check must precede the write.
    assert change.index("privateKeyMatchesRegisteredPublicKey(") < change.index(
        "zkWrapPrivateKey("
    ), "the envelope is re-wrapped before the consistency check"

    restore = _fn_body(app, "async function zkRestoreFromRecoveryKey(")
    assert "privateKeyMatchesRegisteredPublicKey(" in restore, (
        "recovery restore must use the canonical raw-point comparison, not a PEM string compare: "
        "it is reached only after the main passphrase is lost, so a false mismatch is terminal"
    )
    # The load-bearing comparison must not be a PEM string compare. The separate advisory check
    # on the kit's ASSERTED public_key is untrusted metadata and is deliberately left alone, so
    # this targets the derived-key comparison rather than every .trim() in the function.
    assert "derivedPub" not in restore
    assert restore.index("privateKeyMatchesRegisteredPublicKey(") < restore.index(
        "zkWrapPrivateKey("
    ), "the recovered key is re-wrapped before the consistency check"


def test_recovery_restore_bounds_the_kit_file_before_parsing_it() -> None:
    """Section 1.1's wrapper bounds are worthless if the call site parses the file itself."""
    restore = _fn_body(APP_JS.read_text(encoding="utf-8"), "async function zkRestoreFromRecoveryKey(")
    assert "parseRecoveryKitFile(" in restore
    assert "JSON.parse(" not in restore, (
        "the kit file must go through parseRecoveryKitFile, which bounds its size before parsing "
        "and validates the wrapper; a bare JSON.parse skips every one of those bounds"
    )


def test_validation_precedes_the_passphrase_prompt_on_every_path() -> None:
    """A corrupt or hostile envelope should fail before the user is asked to type anything."""
    app = APP_JS.read_text(encoding="utf-8")
    for signature, validator in (
        ("async function zkEnsureUnlocked(", "parsePrivateEnvelope("),
        ("async function zkChangePassphrase(", "parsePrivateEnvelope("),
        ("async function zkExportRecoveryKey(", "parsePrivateEnvelope("),
        ("async function zkRestoreFromRecoveryKey(", "parseRecoveryKitFile("),
    ):
        body = _fn_body(app, signature)
        assert validator in body, f"{signature} does not validate before use"
        assert body.index(validator) < body.index("showPrompt("), (
            f"{signature} prompts for a passphrase before validating the envelope"
        )
