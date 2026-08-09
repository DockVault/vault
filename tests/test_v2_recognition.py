"""Today's readers must recognise a version-2 payload rather than call it damaged.

This ships before any writer, and the ordering is the whole point. A reader that meets a v2
payload without this check reports "damaged" — which sends someone hunting for a backup of a file
that is perfectly intact, at exactly the moment they are least inclined to doubt the software.

Recognition is all this does. Nothing here can read v2.
"""

import base64
import importlib.util
import json
import re
import subprocess
from pathlib import Path

import pytest

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parent.parent
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"


def _node(script: str) -> dict:
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
const out = console.log.bind(console);
console.error = () => {{}};
const codeOf = async fn => {{
  try {{ await fn(); return null; }} catch (e) {{ return e && e.code ? e.code : 'UNCODED'; }}
}};
(async () => {{
  const lib = new ECCCryptoLibrary();
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + e.stack); process.exit(1); }});
"""
    proc = subprocess.run(["node", "-e", harness], capture_output=True, text=True,
                          timeout=300, cwd=str(ROOT))
    assert proc.returncode == 0, proc.stderr
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


def _v2(purpose: int = 0x04, version: int = 0x02, reserved: bytes = b"\x00\x00",
        body: bytes = b"\x00" * 40) -> str:
    return base64.b64encode(b"DVZ2" + bytes([version, purpose]) + reserved + body).decode()


def test_a_v2_payload_is_reported_as_unsupported_not_damaged() -> None:
    """The headline. 'Damaged' about an intact file is worse than no message at all.

    The direct-DEK purpose (0x01) has since become readable, so it is no longer part of this
    claim -- a build that can read a format should not be reporting it as unsupported, and
    `test_v2_direct_dek_wrap.py` covers what it does instead. Everything still unreadable is
    checked here, and the purposes are checked individually rather than as a group so that the
    next one to become readable fails this test rather than quietly narrowing it.
    """
    out = _node("""
  const b64 = %s;
  const bytes = Buffer.from(b64, 'base64');
  const dek = await lib.generateVaultDEK();
  out(JSON.stringify({
    content:  await codeOf(() => lib.decryptFile(bytes, dek)),
    teamDek:  await codeOf(() => lib.unwrapVaultDEK(%s, 'AAAA', null)),
    teamPriv: await codeOf(() => lib.unwrapPrivateKeyFromWrapped(%s, 'AAAA', null)),
  }));
""" % (json.dumps(_v2(0x04)), json.dumps(_v2(0x02, body=bytes(60))), json.dumps(_v2(0x03))))

    # The DEK-wrap reader dispatches on length before it looks at anything else, so the team-DEK
    # payload has to be a full 68 bytes to reach the purpose check at all -- a short one is
    # correctly rejected as malformed, which would be a different property than the one under test.
    assert out["content"] == "CONTENT_UNSUPPORTED", out
    assert out["teamDek"] == "WRAP_UNSUPPORTED", out
    assert out["teamPriv"] == "WRAP_UNSUPPORTED", out
    # The point of the whole change: none of these is the damaged code.
    assert "CONTENT_AUTH_FAILED" not in out.values()


def test_the_readable_purpose_no_longer_claims_to_be_unsupported() -> None:
    """The other half of the same property, and the reason the test above was narrowed.

    Saying "update this deployment" about a format this build reads perfectly well is the same
    class of wrong answer as saying "damaged" about an intact one. A structural reject is the
    honest response to a header with nothing behind it.
    """
    out = _node("""
  out(JSON.stringify({
    direct: await codeOf(() => lib.unwrapVaultDEK(%s, 'AAAA', null,
      { vaultId: '11111111-2222-4333-8444-555555555555',
        recipientUserId: '66666666-7777-4888-8999-aaaaaaaaaaaa', dekEpoch: 1 })),
  }));
""" % json.dumps(_v2(0x01)))
    assert out["direct"] == "WRAP_INVALID", out


def test_a_malformed_v2_header_is_structural_not_from_the_future() -> None:
    """A payload claiming to be v2 but malformed is not a format this build is behind on.

    The two outcomes send a person to different places -- the update notes, or a backup -- so
    conflating them would reintroduce the same failure in a subtler form.
    """
    out = _node("""
  const dek = await lib.generateVaultDEK();
  const b = s => Buffer.from(s, 'base64');
  out(JSON.stringify({
    reserved_set:    await codeOf(() => lib.decryptFile(b(%s), dek)),
    unknown_purpose: await codeOf(() => lib.decryptFile(b(%s), dek)),
    version_too_low: await codeOf(() => lib.decryptFile(b(%s), dek)),
  }));
""" % (json.dumps(_v2(reserved=b"\x00\x01")),
        json.dumps(_v2(purpose=0x09)),
        json.dumps(_v2(version=0x01))))

    assert out["reserved_set"] == "CONTENT_INVALID", out
    assert out["unknown_purpose"] == "CONTENT_INVALID", out
    assert out["version_too_low"] == "CONTENT_INVALID", out


def test_a_future_version_still_reads_as_unsupported() -> None:
    """Version 3 does not exist yet. When it does, this build must still say 'update me' rather
    than 'malformed' -- the recognition has to be forward-looking or it only works once."""
    out = _node("""
  const dek = await lib.generateVaultDEK();
  out(JSON.stringify({
    v3: await codeOf(() => lib.decryptFile(Buffer.from(%s, 'base64'), dek)),
  }));
""" % json.dumps(_v2(version=0x03)))
    assert out["v3"] == "CONTENT_UNSUPPORTED", out


def test_legacy_payloads_are_untouched_by_the_check() -> None:
    """The recognition must not shadow a single legacy byte.

    A legacy payload is a random IV followed by ciphertext, so the check has to be precise enough
    that ordinary bytes never trip it -- and a genuinely tampered file must still authenticate-fail
    rather than be mistaken for a format problem.
    """
    out = _node("""
  const dek = await lib.generateVaultDEK();
  const enc = await lib.encryptFile(new TextEncoder().encode('legacy content'), dek);
  const round = await lib.decryptFile(enc, dek);

  const tampered = new Uint8Array(enc.slice(0));
  tampered[tampered.length - 1] ^= 0xff;

  out(JSON.stringify({
    roundtrip_ok: new TextDecoder().decode(round) === 'legacy content',
    tampered:     await codeOf(() => lib.decryptFile(tampered, dek)),
    short_input:  await codeOf(() => lib.decryptFile(new Uint8Array([1, 2, 3]), dek)),
  }));
""")
    assert out["roundtrip_ok"] is True, "the check broke ordinary legacy decryption"
    # Tampering is still an authentication failure, not a format complaint.
    assert out["tampered"] == "CONTENT_AUTH_FAILED", out
    assert out["short_input"] == "CONTENT_AUTH_FAILED", out


def test_the_new_codes_are_handled_and_say_update_not_damaged() -> None:
    """Wording is the deliverable here, not just the code. A code that maps to a sentence about
    damage would leave the defect in place with an extra layer of indirection."""
    app = APP_JS.read_text(encoding="utf-8")
    seam = app[app.index("function safeMessageForCode("):]
    seam = seam[: seam.index("\nfunction ")]

    for code in ("CONTENT_UNSUPPORTED", "CONTENT_INVALID", "WRAP_UNSUPPORTED", "WRAP_INVALID"):
        assert f"case '{code}':" in seam, f"{code} is raised but not handled"

    branch = seam[seam.index("case 'CONTENT_UNSUPPORTED':"):]
    branch = branch[: branch.index("case 'CONTENT_INVALID':")]
    # Only the returned SENTENCE, not the comments explaining it -- an earlier version of this
    # test matched the word "damaged" in a comment about avoiding the word "damaged".
    sentence = " ".join(re.findall(r"'([^']*)'", branch)[1:]).lower()
    assert sentence, branch

    assert "newer version" in sentence and "update" in sentence, sentence
    assert "damaged" not in sentence, "the unsupported message still calls the item damaged"
    assert "fine" in sentence, "the message does not reassure that the item is intact"


def test_the_frozen_contract_records_the_additions() -> None:
    """That document says its code set is closed and that adding one is a change to it first.

    So the amendment is the deliverable and the code is downstream, not the other way round.
    """
    doc = (ROOT / "docs" / "design" / "vault-client-crypto-errors-v1.md").read_text(encoding="utf-8")
    for code in ("CONTENT_UNSUPPORTED", "CONTENT_INVALID", "WRAP_UNSUPPORTED", "WRAP_INVALID"):
        assert code in doc, f"{code} was added to the code but not to the contract"

    source = CRYPTO_JS.read_text(encoding="utf-8")
    block = source[source.index("const CRYPTO_ERROR_CODES = Object.freeze({"):]
    block = block[: block.index("});")]
    defined = set(re.findall(r"^\s+([A-Z_]+):", block, re.M))
    documented = set(re.findall(r"`([A-Z_]{4,})`", doc))
    assert defined <= documented, f"codes exist that the contract never mentions: {defined - documented}"
