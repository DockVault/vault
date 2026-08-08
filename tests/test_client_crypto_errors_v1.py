"""The client crypto failure contract: stable codes, and diagnostics that keep their mouth shut.

Frozen by ``docs/design/vault-client-crypto-errors-v1.md``. These run offline against the REAL
shipped module under Node's Web Crypto, so what is proven is the file the browser is served.

The property that matters most here is not that a failure is reported -- it always was -- but that
it is reported as the RIGHT KIND of failure. Before this contract, an envelope written by a newer
build and a genuinely damaged one produced the same sentence, and that sentence told the user to
re-register their key: an action the server refuses while a keypair exists, and which would orphan
every wrapped vault key if it did not.
"""

import json
from pathlib import Path
import re
import subprocess

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parent.parent
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"


def _node(script: str, *, window: str = "{ crypto: webcrypto }", extra: str = "") -> dict:
    """Run the shipped module under Node and return its JSON result.

    ``window`` is a JS expression, so a test can hand the module a realistic browser global or a
    deliberately broken one -- which is the only way to reach the unavailable-crypto code.
    """
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {window};
{extra}
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
const out = console.log.bind(console);
// Capture rather than silence. Both existing harnesses replace console with a stub, and a
// diagnostics test that reused one would pass without ever looking at what was written.
const CONSOLE = [];
const CONSOLE_ARGS = [];
console.error = (...a) => {{
  CONSOLE_ARGS.push(a.length);
  CONSOLE.push(a.map(x => (x instanceof Error ? x.stack : String(x))).join(' '));
}};
console.warn = console.error;
const codeOf = async fn => {{
  try {{ await fn(); return null; }} catch (e) {{ return e && e.code ? e.code : 'UNCODED'; }}
}};
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


_V1 = {
    "v": 1, "kdf": "PBKDF2-SHA256", "cipher": "AES-256-GCM", "iter": 600000,
    "salt": "A" * 43 + "=", "iv": "AAAAAAAAAAAAAAAA", "ct": "A" * 44,
}


def _v1(**over):
    return json.dumps({**_V1, **over})


# ---------------------------------------------------------------------------------------------
# Every code is reachable, and each means what the contract says
# ---------------------------------------------------------------------------------------------


def test_each_code_is_reachable_and_distinct() -> None:
    """The whole point is telling failures apart, so every code must be separately provokable."""
    out = _node("""
  const kit = o => JSON.stringify(o);
  out(JSON.stringify({
    envelope_not_json:   await codeOf(() => lib.parsePrivateEnvelope('{{{')),
    envelope_not_object: await codeOf(() => lib.parsePrivateEnvelope('[]')),
    unknown_version:     await codeOf(() => lib.parsePrivateEnvelope(%s)),
    unknown_kdf:         await codeOf(() => lib.parsePrivateEnvelope(%s)),
    unknown_cipher:      await codeOf(() => lib.parsePrivateEnvelope(%s)),
    iter_ceiling:        await codeOf(() => lib.parsePrivateEnvelope(%s)),
    iter_not_integer:    await codeOf(() => lib.parsePrivateEnvelope(%s)),
    key_unusable:        await codeOf(() => lib.importPrivateKeyPEM(
                            '-----BEGIN PRIVATE KEY-----\\nZm9v\\n-----END PRIVATE KEY-----')),
    kit_wrong_marker:    await codeOf(() => lib.parseRecoveryKitFile(kit({type:'nope', version:1}))),
    kit_newer_version:   await codeOf(() => lib.parseRecoveryKitFile(
                            kit({type:'dockvault-zk-recovery-key', version:99}))),
    invalid_input:       await codeOf(() => lib.encryptName('n', null, 'v', 'name', 1, null)),
  }));
""" % (_v1(v=99), _v1(kdf="scrypt"), _v1(cipher="AES-128-GCM"),
        _v1(iter=10_000_001), _v1(iter=1.5)))

    assert out == {
        "envelope_not_json": "ENVELOPE_INVALID",
        "envelope_not_object": "ENVELOPE_INVALID",
        # Well formed, simply not implemented here. Reporting these as damage is what produced
        # the "re-register your key" advice the server refuses to honour.
        "unknown_version": "ENVELOPE_UNSUPPORTED",
        "unknown_kdf": "ENVELOPE_UNSUPPORTED",
        "unknown_cipher": "ENVELOPE_UNSUPPORTED",
        # A ceiling breach is a policy refusal; a non-integer is a malformed envelope. One `if`
        # used to cover both, and only one of them is about work.
        "iter_ceiling": "WORK_FACTOR_REJECTED",
        "iter_not_integer": "ENVELOPE_INVALID",
        "key_unusable": "KEY_UNUSABLE",
        "kit_wrong_marker": "RECOVERY_KIT_INVALID",
        "kit_newer_version": "RECOVERY_KIT_UNSUPPORTED",
        "invalid_input": "INVALID_INPUT",
    }


def test_a_wrong_passphrase_and_a_tampered_ciphertext_are_one_outcome() -> None:
    """AES-GCM cannot tell them apart, so the contract must not pretend to."""
    out = _node("""
  const pem = (await lib.generateKeypair()).privateKey;
  const env = await lib.encryptPrivateKey(await lib.exportPrivateKeyPEM(pem), 'right-passphrase');
  const blob = JSON.stringify(env);
  const tampered = JSON.parse(blob);
  const b = Buffer.from(tampered.encrypted, 'base64');
  b[0] ^= 0xff;
  tampered.encrypted = b.toString('base64');
  out(JSON.stringify({
    wrong_passphrase: await codeOf(() => lib.decryptPrivateEnvelope(blob, 'WRONG')),
    tampered:         await codeOf(() => lib.decryptPrivateEnvelope(JSON.stringify(tampered), 'right-passphrase')),
  }));
""")
    assert out["wrong_passphrase"] == "AUTH_FAILED"
    assert out["tampered"] == "AUTH_FAILED"


def test_content_decryption_never_reports_as_a_passphrase_failure() -> None:
    """By the time content is decrypted the passphrase has already succeeded and the user typed
    nothing, so a damaged file must not be reported as though a secret were wrong."""
    out = _node("""
  const dek = await lib.generateVaultDEK();
  const enc = await lib.encryptFile(new TextEncoder().encode('hello'), dek);
  const bytes = new Uint8Array(enc instanceof ArrayBuffer ? enc : (enc.buffer || enc));
  bytes[bytes.length - 1] ^= 0xff;
  out(JSON.stringify({ content: await codeOf(() => lib.decryptFile(bytes, dek)) }));
""")
    assert out["content"] == "CONTENT_AUTH_FAILED"
    assert out["content"] != "AUTH_FAILED", "content damage must not read as a passphrase problem"


def test_absent_webcrypto_is_its_own_code_on_every_entry_point() -> None:
    """Without one probe this is unreachable: it surfaces as a TypeError from whichever line
    touched `subtle` first, and on the decrypt paths that would be reported as a bad passphrase."""
    out = _node("""
  out(JSON.stringify({
    generate: await codeOf(() => lib.generateKeypair()),
    decrypt:  await codeOf(() => lib.decryptPrivateEnvelope(%s, 'pw')),
    dek:      await codeOf(() => lib.generateVaultDEK()),
  }));
""" % json.dumps(_v1()), window="{}")
    assert out == {
        "generate": "CRYPTO_UNAVAILABLE",
        "decrypt": "CRYPTO_UNAVAILABLE",
        "dek": "CRYPTO_UNAVAILABLE",
    }


# ---------------------------------------------------------------------------------------------
# The shapes the rest of the system depends on
# ---------------------------------------------------------------------------------------------


def test_the_two_parse_methods_stay_synchronous() -> None:
    """Both are called for their throw, inside a plain try/catch, with the result used on the next
    line. Wrapping them in an async boundary would return a pending promise instead: the catch
    would never fire, so the corrupt-envelope guard would pass everything through, and the caller
    reading a field off the result would get undefined."""
    out = _node("""
  const legacy = JSON.stringify({ encrypted: 'AAAA', salt: 'AAAA', iterations: 600000 });
  const parsed = lib.parsePrivateEnvelope(legacy);
  let threw = false, code = null;
  try { lib.parsePrivateEnvelope('{{{'); } catch (e) { threw = true; code = e.code; }
  const kitText = JSON.stringify({
    type: 'dockvault-zk-recovery-key', version: 1,
    recovery: { encrypted: 'AAAA', salt: 'AAAA', iterations: 600000 },
  });
  const kit = lib.parseRecoveryKitFile(kitText);
  out(JSON.stringify({
    envelope_is_a_value: !(parsed instanceof Promise),
    guard_still_throws: threw,
    guard_code: code,
    kit_is_a_value: !(kit instanceof Promise),
    kit_field_readable: !!(kit && kit.kit),
  }));
""")
    assert out == {
        "envelope_is_a_value": True,
        "guard_still_throws": True,
        "guard_code": "ENVELOPE_INVALID",
        "kit_is_a_value": True,
        "kit_field_readable": True,
    }


def test_the_error_carries_a_branchable_code_and_an_unusable_message() -> None:
    """Callers branch on `.code`. `message` is deliberately not a sentence, so that if one ever
    reaches a user it reads as a bug rather than as advice."""
    out = _node("""
  let e = null;
  try { lib.parsePrivateEnvelope('{{{'); } catch (err) { e = err; }
  out(JSON.stringify({
    code: e.code,
    is_flagged: e.isCryptoError === true,
    message: e.message,
    // instanceof is NOT the mechanism: the module is a classic script in the browser and a
    // require here, and a prototype identity does not survive both.
    has_own_flag: Object.prototype.hasOwnProperty.call(e, 'isCryptoError'),
    keeps_cause: e.cause !== undefined,
  }));
""")
    assert out["code"] == "ENVELOPE_INVALID"
    assert out["is_flagged"] is True
    assert out["has_own_flag"] is True
    assert re.fullmatch(r"CryptoError\([A-Z_]+@[A-Za-z0-9_.]+\)", out["message"]), out["message"]
    assert out["keeps_cause"] is True, "the platform exception must survive for debug mode"


def test_the_default_export_shape_is_unchanged() -> None:
    """Seven Node harnesses construct the default export directly. The code set and error type
    hang off the class so `require` and the classic-script global see one shape."""
    out = _node("""
  out(JSON.stringify({
    default_is_the_class: typeof ECCCryptoLibrary === 'function',
    codes_attached: Object.keys(ECCCryptoLibrary.CODES || {}).length,
    error_attached: typeof ECCCryptoLibrary.CryptoError === 'function',
    codes_frozen: Object.isFrozen(ECCCryptoLibrary.CODES),
  }));
""")
    assert out["default_is_the_class"] is True
    assert out["error_attached"] is True
    assert out["codes_frozen"] is True
    assert out["codes_attached"] >= 13


# ---------------------------------------------------------------------------------------------
# Diagnostics
# ---------------------------------------------------------------------------------------------


def test_production_console_output_is_operation_and_code_only() -> None:
    """The raw platform exception is the thing a bug reporter copies into a ticket."""
    out = _node("""
  await codeOf(() => lib.importPrivateKeyPEM(
      '-----BEGIN PRIVATE KEY-----\\nZm9v\\n-----END PRIVATE KEY-----'));
  await codeOf(() => lib.decryptPrivateEnvelope(%s, 'pw'));
  out(JSON.stringify({ lines: CONSOLE }));
""" % json.dumps(_v1()))
    lines = out["lines"]
    assert lines, "the failures should still be diagnosable"
    for line in lines:
        assert re.fullmatch(r"crypto [A-Za-z0-9_.]+ [A-Z_]+", line), line
        for leak in ("DOMException", "OperationError", "Error:", "at ", "atob"):
            assert leak not in line, f"platform detail leaked into production console: {line}"


def test_debug_mode_is_the_only_way_to_see_the_cause_and_ships_off() -> None:
    """An unpinned default is one careless edit away from shipping verbose."""
    assert "this.DEBUG = false;" in CRYPTO_JS.read_text(encoding="utf-8")
    bad_pem = "-----BEGIN PRIVATE KEY-----\\nZm9v\\n-----END PRIVATE KEY-----"
    out = _node("""
  const seen = {};
  lib.DEBUG = false;
  await codeOf(() => lib.importPrivateKeyPEM('%s'));
  seen.quiet_args = CONSOLE_ARGS.slice();
  seen.quiet_text = CONSOLE.slice();
  CONSOLE.length = 0; CONSOLE_ARGS.length = 0;
  lib.DEBUG = true;
  await codeOf(() => lib.importPrivateKeyPEM('%s'));
  seen.debug_args = CONSOLE_ARGS.slice();
  out(JSON.stringify(seen));
""" % (bad_pem, bad_pem))
    # Whether the cause is HANDED to the console is the property; a length threshold would have
    # passed on a one-character margin, and the stack the capture records excludes `cause`.
    assert out["quiet_args"] == [1], "production passed more than the code"
    assert out["debug_args"] == [2], "debug should hand over the cause as well"
    assert "KEY_UNUSABLE" in " ".join(out["quiet_text"])


def test_no_success_traces_survive() -> None:
    """They ran on every operation and each was a place a later edit could append something."""
    assert "console.log" not in CRYPTO_JS.read_text(encoding="utf-8")


# ---------------------------------------------------------------------------------------------
# The interface side
# ---------------------------------------------------------------------------------------------


def test_the_interface_uses_codes_the_library_actually_defines() -> None:
    """The seam compares literals, so a typo would silently take the default branch forever.

    This is the check that makes literals safe: the design permits them precisely because it also
    requires this enumeration.
    """
    app = APP_JS.read_text(encoding="utf-8")
    seam = app[app.index("function safeMessageForCode("):]
    seam = seam[: seam.index("\nfunction ")]
    used = set(re.findall(r"case '([A-Z_]+)':", seam))
    assert used, "the seam should branch on codes"

    source = CRYPTO_JS.read_text(encoding="utf-8")
    block = source[source.index("const CRYPTO_ERROR_CODES = Object.freeze({"):]
    block = block[: block.index("});")]
    defined = set(re.findall(r"^\s+([A-Z_]+):", block, re.M))

    assert used <= defined, f"interface branches on codes the library never raises: {used - defined}"


def test_no_generic_handler_renders_a_crypto_error_message() -> None:
    """`message` is not a sentence. Every one of these sites used to render it, and after this
    change would have shown the literal `CryptoError(AUTH_FAILED@...)` to a user."""
    app = APP_JS.read_text(encoding="utf-8")
    for banned in (
        "showError('Failed to decrypt file: ' + e.message)",
        "showError('Zero-knowledge encryption failed: ' + e.message)",
        "showError('Encryption key setup failed: ' + err.message)",
        "Failed to preview: ${escapeHtml(e.message)}",
    ):
        assert banned not in app, f"still renders a crypto error message: {banned}"
    # And the seam is what replaced them.
    assert app.count("safeMessageForCode(") >= 10


def test_the_unsupported_envelope_no_longer_advises_a_refused_reregistration() -> None:
    """The server returns 409 while a keypair exists, and re-registering would orphan every
    wrapped vault key. Advising it was the single most harmful thing the old wording did."""
    app = APP_JS.read_text(encoding="utf-8")
    assert "incomplete or corrupt — re-register your key" not in app
    seam = app[app.index("function safeMessageForCode("):]
    seam = seam[: seam.index("\nfunction ")]
    label = "case 'ENVELOPE_UNSUPPORTED':"
    unsupported = seam[seam.index(label) + len(label):]
    unsupported = unsupported[: unsupported.index("case '")]
    assert unsupported.strip(), "sliced an empty branch; the anchor moved"
    assert "Do not re-register" in unsupported
    assert "newer version" in unsupported


def test_transport_failures_never_take_a_crypto_code() -> None:
    """Point decompression calls an authenticated, rate-limited endpoint. Dressing its 429 as a
    crypto code would let a server response answer through the code channel, which is exactly the
    oracle this contract is required to avoid."""
    source = CRYPTO_JS.read_text(encoding="utf-8")
    fn = source[source.index("async _decompressP384Point("):]
    fn = fn[: fn.index("\n    _arrayBufferToBase64(")]
    assert "isTransportError = true" in fn
    assert "CRYPTO_ERROR_CODES" not in fn, "a transport failure must not carry a crypto code"
    # And the boundary lets it through rather than coercing it.
    boundary = source[source.index("for (const [_name, _code] of Object.entries("):]
    assert "isTransportError" in boundary


def test_no_code_is_raised_from_a_server_response_field() -> None:
    """Whether some OTHER account has registered a key is guarded server-side against enumeration.
    Turning that answer into a stable code would rebuild the oracle on the client."""
    app = APP_JS.read_text(encoding="utf-8")
    fn = app[app.index("async function zkShareVaultToUser("):]
    fn = fn[: fn.index("\nasync function ")]
    assert "has_keypair" in fn, "guard anchored on the wrong function"
    assert "safeMessageForCode" not in fn
    assert "CryptoError" not in fn


# ---------------------------------------------------------------------------------------------
# The oracle exclusions, exercised rather than grepped
# ---------------------------------------------------------------------------------------------


def test_a_server_status_never_becomes_a_crypto_code() -> None:
    """A rate-limited or refused decompression must not answer through the code channel.

    This is the phase's stop condition, and it is reachable in ordinary use: the ephemeral point
    is server-supplied, a compressed one triggers the round trip, and that endpoint is
    authenticated and rate limited. The earlier source-text check could not see this, because the
    conversion happened one frame ABOVE the function it inspected -- in a method with its own
    catch, which coerced the transport failure before the boundary could exempt it.
    """
    out = _node("""
  const compressed = new Uint8Array(Buffer.concat([Buffer.from([0x02]), Buffer.alloc(48, 1)]));
  const b64 = Buffer.from(compressed).toString('base64');
  const kp = await lib.generateKeypair();
  const seen = {};
  try { await lib.unwrapVaultDEK(Buffer.alloc(40).toString('base64'), b64, kp.privateKey); }
  catch (e) { seen.unwrap_code = e.code === undefined ? null : e.code;
              seen.unwrap_transport = !!e.isTransportError;
              seen.unwrap_status = e.status === undefined ? null : e.status; }
  try { await lib.unwrapPrivateKeyFromWrapped(Buffer.alloc(40).toString('base64'), b64, kp.privateKey); }
  catch (e) { seen.priv_code = e.code === undefined ? null : e.code;
              seen.priv_transport = !!e.isTransportError; }
  out(JSON.stringify(seen));
""", window="{ crypto: webcrypto }", extra="""
global.localStorage = { getItem: () => 'test-token' };
global.fetch = async () => ({ ok: false, status: 429, statusText: 'Too Many Requests' });
""")
    assert out["unwrap_code"] is None, f"a 429 surfaced as the crypto code {out['unwrap_code']}"
    assert out["unwrap_transport"] is True
    assert out["unwrap_status"] == 429, "the status should survive for diagnosis"
    assert out["priv_code"] is None
    assert out["priv_transport"] is True


def test_the_authentication_path_does_not_absorb_other_failures() -> None:
    """The one path whose wording blames the user's passphrase must report only authentication.

    An unusable algorithm reported here as AUTH_FAILED is exactly the mislabel this phase exists
    to remove -- the passphrase would be correct and the user would be told it was not.
    """
    out = _node("""
  const kp = await lib.generateKeypair();
  const blob = JSON.stringify(
      await lib.encryptPrivateKey(await lib.exportPrivateKeyPEM(kp.privateKey), 'pw'));
  const broken = new (require(%s))();
  broken._subtle = () => new Proxy(webcrypto.subtle, {
      get: (t, k) => k === 'decrypt'
          ? async () => { const err = new Error('no'); err.name = 'NotSupportedError'; throw err; }
          : (typeof t[k] === 'function' ? t[k].bind(t) : t[k]),
  });
  out(JSON.stringify({
    genuine_wrong_passphrase: await codeOf(() => lib.decryptPrivateEnvelope(blob, 'WRONG')),
    algorithm_unusable:       await codeOf(() => broken.decryptPrivateEnvelope(blob, 'pw')),
  }));
""" % json.dumps(str(CRYPTO_JS)))
    # Still one outcome for the case that genuinely is one outcome...
    assert out["genuine_wrong_passphrase"] == "AUTH_FAILED"
    # ...and emphatically not for the case that is not.
    assert out["algorithm_unusable"] != "AUTH_FAILED"
    assert out["algorithm_unusable"] == "CRYPTO_OPERATION_FAILED"


# ---------------------------------------------------------------------------------------------
# Interface wiring the source-text checks could not see
# ---------------------------------------------------------------------------------------------


def test_the_restore_flow_keeps_the_kit_code() -> None:
    """A kit written by a NEWER build is good, and calling it invalid invites the user to discard
    the only copy of their key. The restore path used to swallow every code from the parser, which
    made two branches of the message table unreachable."""
    app = APP_JS.read_text(encoding="utf-8")
    fn = app[app.index("async function zkRestoreFromRecoveryKey("):]
    fn = fn[: fn.index("\nasync function ")]
    parse = fn[fn.index("parseRecoveryKitFile"):]
    parse = parse[: parse.index("\n    const ")]
    assert "catch (_)" not in parse, "the kit code is being discarded again"
    assert "safeMessageForCode" in parse


def test_every_seam_branch_is_reachable_from_some_call_site() -> None:
    """A handled code that nothing can raise is dead reassurance: the table looks complete while
    the user still gets the wrong sentence. Checking `used <= defined` alone cannot catch it."""
    app = APP_JS.read_text(encoding="utf-8")
    seam = app[app.index("function safeMessageForCode("):]
    seam = seam[: seam.index("\nfunction ")]
    handled = set(re.findall(r"case '([A-Z_]+)':", seam))

    source = CRYPTO_JS.read_text(encoding="utf-8")
    raised = set(re.findall(r"CRYPTO_ERROR_CODES\.([A-Z_]+)", source))
    raised |= set(re.findall(r"safeMessageForCode\('([A-Z_]+)'", app))

    unreachable = handled - raised
    assert not unreachable, f"the interface handles codes nothing can produce: {unreachable}"


def test_no_console_call_on_a_crypto_path_logs_the_error_object() -> None:
    """The error now RETAINS the platform exception as its cause, and developer tools expand that.
    Logging the object is therefore a leak route that did not exist before this contract."""
    app = APP_JS.read_text(encoding="utf-8")

    # A "crypto path" is a function that actually touches the library. Elsewhere in the app an
    # error is a plain Error with no cause, and logging it is both harmless and useful.
    blocks = re.split(r"\n(?=(?:async )?function )", app)
    offenders = []
    for block in blocks:
        if "eccLib()" not in block:
            continue
        name = re.match(r"(?:async )?function (\w+)", block)
        for line in block.splitlines():
            if re.search(r"console\.error\([^)]*,\s*(e|err|error)\s*\)", line):
                offenders.append(f"{name.group(1) if name else '?'}: {line.strip()}")
    assert not offenders, f"logs an error object on a crypto path: {offenders}"


def test_the_listing_swallow_all_still_reports_an_unusable_platform() -> None:
    """Swallowing one damaged name is right; swallowing every row because the platform has no
    WebCrypto leaves a directory of padlocks and no explanation."""
    app = APP_JS.read_text(encoding="utf-8")
    fn = app[app.index("async function zkDecryptListingNames("):]
    fn = fn[: fn.index("\n// ")]
    assert "CRYPTO_UNAVAILABLE" in fn
    assert "🔒 Encrypted name" in fn, "anchored on the wrong function"
