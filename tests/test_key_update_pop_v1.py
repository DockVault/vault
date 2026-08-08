"""Proof of possession for replacing the stored private-key envelope.

Offline by design: pure Python plus the real shipped browser module loaded under Node, so the
protocol contract holds even with no deployment running. The behavioural half -- that the endpoint
actually refuses an unproven replacement -- needs a live stack and lives in the API suite.

Specified by ``docs/design/vault-private-key-update-pop-v1.md``. Where a test here and that
document disagree, the document is the contract.
"""

import base64
import hashlib
import json
from pathlib import Path
import re
import subprocess

import pytest

import crypto_reference_vectors as reference

from app.services import ecc_update_pop as pop
from app.services import ecc_pop as registration_pop


pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "crypto" / "key-update-pop-v1"
CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"
APP_JS = ROOT / "static" / "js" / "app.js"
ROUTER = ROOT / "app" / "api" / "ecc_router.py"
DESIGN_DOC = ROOT / "docs" / "design" / "vault-private-key-update-pop-v1.md"


def _route_body(src: str, anchor: str) -> str:
    """One top-level function's source, ending at the next top-level def/decorator."""
    start = src.index(anchor)
    m = re.search(r"\n(?:@|def |async def |class )", src[start + len(anchor):])
    return src[start:start + len(anchor) + m.start()] if m else src[start:]


def _vector() -> dict:
    return reference.load_unreleased_vector(FIXTURE_DIR / "zk-key-update-pop-v1.json")


def _node(script: str) -> dict:
    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
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
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


# --------------------------------------------------------------------------------------------
# The pinned vector, and cross-implementation agreement
# --------------------------------------------------------------------------------------------


def test_manifest_pins_the_exact_reviewed_fixture_set() -> None:
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    listed = [e["path"] for e in manifest["vectors"]]
    assert {p.name for p in FIXTURE_DIR.glob("*.json")} == {"manifest.json", *listed}
    for entry in manifest["vectors"]:
        assert reference.sha256_file(FIXTURE_DIR / entry["path"]) == entry["sha256"]


def test_verifier_reproduces_the_pinned_transcript_and_mac() -> None:
    v = _vector()
    i, e = v["inputs"], v["expected"]
    assert pop.transcript(
        i["challenge_id"], i["nonce_b64"], i["user_id"],
        i["account_public_key_pem"], i["replacement_envelope_utf8"],
    ).hex() == e["transcript_sha256_hex"]
    assert base64.b64encode(pop.expected_mac(
        i["server_ephemeral_private_scalar_hex"] and _server_priv_pem(v),
        i["account_public_key_pem"], i["challenge_id"], i["nonce_b64"],
        i["user_id"], i["replacement_envelope_utf8"],
    )).decode() == e["mac_b64"]


def _server_priv_pem(v: dict) -> str:
    """Rebuild the server ephemeral private key from its pinned scalar."""
    from cryptography.hazmat.primitives import serialization
    from cryptography.hazmat.primitives.asymmetric import ec

    k = ec.derive_private_key(
        int(v["inputs"]["server_ephemeral_private_scalar_hex"], 16), ec.SECP384R1()
    )
    return k.private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    ).decode()


def test_browser_and_verifier_produce_the_same_mac() -> None:
    """The whole protocol rests on this. A Python-only mirror would agree by construction and
    leave a browser-side divergence green, so the shipped module is what is executed here."""
    v = _vector()
    i = v["inputs"]
    out = _node(f"""
  const priv = await lib.importPrivateKeyPEM({json.dumps(i['account_private_key_pem'])}, false);
  const mac = await lib.computeKeyUpdatePoP(
      {json.dumps(i['server_ephemeral_public_key_pem'])},
      {json.dumps(i['nonce_b64'])},
      {json.dumps(i['challenge_id'])},
      {json.dumps(i['user_id'])},
      {json.dumps(i['account_public_key_pem'])},
      {json.dumps(i['replacement_envelope_utf8'])},
      priv);
  realLog(JSON.stringify({{ mac }}));
""")
    assert out["mac"] == v["expected"]["mac_b64"]


def test_encoding_choices_are_the_pinned_ones() -> None:
    """The four things two implementers would otherwise resolve differently."""
    v = _vector()
    i, e = v["inputs"], v["expected"]
    point = pop.public_point(i["account_public_key_pem"])
    assert len(point) == 97 and point[0] == 0x04, "canonical uncompressed P-384 point"
    # Digests contribute 32 RAW bytes, the nonce is base64-DECODED, ids are lowercase.
    rebuilt = hashlib.sha256(b"\x00".join([
        e["protocol_label"].encode(),
        i["challenge_id"].lower().encode(),
        base64.b64decode(i["nonce_b64"]),
        i["user_id"].lower().encode(),
        hashlib.sha256(point).digest(),
        hashlib.sha256(i["replacement_envelope_utf8"].encode("utf-8")).digest(),
    ])).digest()
    assert rebuilt.hex() == e["transcript_sha256_hex"]


# --------------------------------------------------------------------------------------------
# The transcript binds what it claims to bind
# --------------------------------------------------------------------------------------------


@pytest.mark.parametrize(
    "field",
    ["challenge_id", "nonce_b64", "user_id", "replacement_envelope_utf8", "account_public_key_pem"],
)
def test_changing_any_bound_element_changes_the_transcript(field: str) -> None:
    """Each element earns its place, or the proof is not bound to what the design says it is."""
    v = _vector()
    i = dict(v["inputs"])
    base = pop.transcript(
        i["challenge_id"], i["nonce_b64"], i["user_id"],
        i["account_public_key_pem"], i["replacement_envelope_utf8"],
    )
    if field == "challenge_id":
        i[field] = "00000000-0000-4000-8000-000000000000"
    elif field == "nonce_b64":
        i[field] = base64.b64encode(bytes(range(1, 33))).decode()
    elif field == "user_id":
        i[field] = "11111111-2222-4333-8444-555555555555"
    elif field == "replacement_envelope_utf8":
        i[field] = i[field] + " "
    else:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric import ec

        other = ec.derive_private_key(0x33, ec.SECP384R1())
        i[field] = other.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
    changed = pop.transcript(
        i["challenge_id"], i["nonce_b64"], i["user_id"],
        i["account_public_key_pem"], i["replacement_envelope_utf8"],
    )
    assert changed != base, f"{field} is not bound into the transcript"


def test_a_proof_cannot_authorise_a_different_replacement() -> None:
    """The property that makes this proof *bound* rather than merely present."""
    v = _vector()
    i = v["inputs"]
    srv = _server_priv_pem(v)
    good = base64.b64encode(pop.expected_mac(
        srv, i["account_public_key_pem"], i["challenge_id"], i["nonce_b64"],
        i["user_id"], i["replacement_envelope_utf8"],
    )).decode()
    other_envelope = json.dumps({"encrypted": "SOMETHING-ELSE", "salt": "AA==", "iterations": 600000})
    assert pop.verify_pop(
        srv, i["account_public_key_pem"], i["challenge_id"], i["nonce_b64"],
        i["user_id"], i["replacement_envelope_utf8"], good,
    ) is True
    assert pop.verify_pop(
        srv, i["account_public_key_pem"], i["challenge_id"], i["nonce_b64"],
        i["user_id"], other_envelope, good,
    ) is False, "a captured proof authorised a replacement it did not cover"


def test_the_public_point_is_hashed_not_the_pem() -> None:
    """Cosmetic re-encoding of the stored key must not invalidate a genuine proof."""
    v = _vector()
    i = v["inputs"]
    pem = i["account_public_key_pem"]
    variants = [pem, pem.replace("\n", "\r\n"), "\n  " + pem.strip() + "  \n"]
    digests = {
        pop.transcript(i["challenge_id"], i["nonce_b64"], i["user_id"], p,
                       i["replacement_envelope_utf8"]).hex()
        for p in variants
    }
    assert len(digests) == 1, "a re-encoded PEM produced a different transcript"


def test_verification_rejects_a_wrong_key_wrong_user_and_malformed_input() -> None:
    v = _vector()
    i = v["inputs"]
    srv = _server_priv_pem(v)
    good = base64.b64encode(pop.expected_mac(
        srv, i["account_public_key_pem"], i["challenge_id"], i["nonce_b64"],
        i["user_id"], i["replacement_envelope_utf8"],
    )).decode()

    def verify(**over):
        args = dict(
            server_priv_pem=srv, public_key_pem=i["account_public_key_pem"],
            challenge_id=i["challenge_id"], nonce_b64=i["nonce_b64"],
            user_id=i["user_id"], envelope=i["replacement_envelope_utf8"], mac_b64=good,
        )
        args.update(over)
        return pop.verify_pop(**args)

    assert verify() is True
    assert verify(user_id="11111111-2222-4333-8444-555555555555") is False
    assert verify(challenge_id="00000000-0000-4000-8000-000000000000") is False
    assert verify(nonce_b64=base64.b64encode(b"\x01" * 32).decode()) is False
    assert verify(mac_b64="not base64!!") is False
    assert verify(mac_b64=base64.b64encode(b"\x00" * 32).decode()) is False
    assert verify(public_key_pem="not a pem") is False


# --------------------------------------------------------------------------------------------
# Domain separation from registration
# --------------------------------------------------------------------------------------------


def test_the_two_protocols_share_no_domain() -> None:
    """A challenge issued for one purpose must not be answerable for the other."""
    update_src = (ROOT / "app" / "services" / "ecc_update_pop.py").read_text(encoding="utf-8")
    reg_src = (ROOT / "app" / "services" / "ecc_pop.py").read_text(encoding="utf-8")
    assert b"dv-ecc-update-pop-v1" == pop._HKDF_SALT
    assert b"private-key-update-pop" == pop._HKDF_INFO
    assert registration_pop._HKDF_SALT != pop._HKDF_SALT
    assert registration_pop._HKDF_INFO != pop._HKDF_INFO
    # Separate tables, not one table with a purpose column: cross-use should be unreachable,
    # not merely filtered out.
    assert "ecc_key_update_challenges" in (ROOT / "app" / "core" / "models.py").read_text(encoding="utf-8")
    assert "ECCRegistrationChallenge" not in update_src
    assert "ecc_update_pop" not in reg_src


def test_a_registration_mac_does_not_verify_as_an_update_proof() -> None:
    """Domain separation, demonstrated rather than asserted."""
    v = _vector()
    i = v["inputs"]
    srv = _server_priv_pem(v)
    reg_mac = base64.b64encode(
        registration_pop._mac(srv, i["account_public_key_pem"], i["nonce_b64"])
    ).decode()
    assert pop.verify_pop(
        srv, i["account_public_key_pem"], i["challenge_id"], i["nonce_b64"],
        i["user_id"], i["replacement_envelope_utf8"], reg_mac,
    ) is False


def test_the_browser_helpers_use_different_key_derivation_domains() -> None:
    src = CRYPTO_JS.read_text(encoding="utf-8")
    update = src[src.index("async computeKeyUpdatePoP("):]
    update = update[: update.index("\n    // =====")]
    assert "dv-ecc-update-pop-v1" in update and "private-key-update-pop" in update
    assert "registration-pop" not in update


# --------------------------------------------------------------------------------------------
# Endpoint wiring
# --------------------------------------------------------------------------------------------


def test_the_update_route_validates_before_consuming_and_consumes_before_verifying() -> None:
    """The ordering IS the security property, so it is pinned rather than assumed.

    Malformed never consumes, or anyone able to send garbage burns an honest client's in-flight
    challenge. Well-formed always consumes, pass or fail, or a wrong proof can be retried against
    one issuance.
    """
    src = ROUTER.read_text(encoding="utf-8")
    body = _route_body(src, "async def update_private_key(")

    i_size = body.index("_MAX_ENVELOPE_BYTES")
    i_lookup = body.index("ECCKeyUpdateChallenge.id == cid")
    i_delete = body.index("db.delete(ch)")
    i_verify = body.index("ecc_update_pop.verify_pop")
    i_write = body.index("keypair.encrypted_private_key = request.encrypted_private_key")
    assert i_size < i_lookup, "the size bound must precede any challenge lookup"
    assert i_lookup < i_delete < i_verify, "the challenge must be consumed before verification"
    assert i_verify < i_write, "the envelope must not be written before the proof verifies"


def test_the_server_never_parses_the_envelope() -> None:
    """Keeping the server format-blind is what lets the versioned writer be enabled client-side
    alone -- and a format-aware server would reject every replacement today's client makes."""
    src = ROUTER.read_text(encoding="utf-8")
    body = _route_body(src, "async def update_private_key(")
    for forbidden in ("json.loads", "parsePrivateEnvelope", '"v"', "'iter'", "iterations"):
        assert forbidden not in body, f"the update route inspects the envelope: {forbidden}"


def test_both_routes_are_interactive_only_and_rate_limited() -> None:
    src = ROUTER.read_text(encoding="utf-8")
    for anchor in ("async def key_update_challenge(", "async def update_private_key("):
        body = _route_body(src, anchor)
        assert "_is_temp_session" in body, f"{anchor} does not refuse temporary credentials"
        assert "_ecc_rate_limit" in body, f"{anchor} is not rate limited"
    # Separate buckets, so exhausting one cannot lock out the other.
    assert '"key_update_challenge": (' in src
    assert '"key_update": (' in src


def test_issuance_serialises_on_the_owning_user_row() -> None:
    """Without the lock, two issuances can interleave and leave two live challenges."""
    src = ROUTER.read_text(encoding="utf-8")
    body = _route_body(src, "async def key_update_challenge(")
    assert "with_for_update()" in body
    assert body.index("with_for_update()") < body.index("ECCKeyUpdateChallenge(")


def _envelope_put_sites(app: str) -> list[int]:
    """Offsets of every request that PUTs the private-key envelope.

    Counting bare `method: 'PUT'` occurrences cannot do this job: the file is full of unrelated
    PUTs, so an added envelope write would move the total from N to N+1 and any relative
    assertion still holds. This matches the TARGET and then looks for the verb near it.
    """
    sites, at = [], 0
    needle = "apiRequest('/ecc/keys/private'"
    while True:
        i = app.find(needle, at)
        if i == -1:
            return sites
        if "method: 'PUT'" in app[i:i + 300]:
            sites.append(i)
        at = i + 1


def test_every_client_replacement_carries_a_proof() -> None:
    """Exactly one write path, and it always proves. A second, unproven PUT would silently
    reopen the hole this phase closes, so the test must be able to SEE one."""
    app = APP_JS.read_text(encoding="utf-8")
    assert app.count("async function zkPutPrivateEnvelope(") == 1
    start = app.index("async function zkPutPrivateEnvelope(")
    end = start + app[start:].index("\nasync function ", 1)
    helper = app[start:end]
    assert "computeKeyUpdatePoP(" in helper
    assert "keys/private/challenge" in helper
    # The read-back the design mandates: the server cannot verify the envelope, so the client must.
    assert "decryptPrivateEnvelope(" in helper
    assert helper.index("decryptPrivateEnvelope(") < helper.index("keys/private/challenge"), (
        "the read-back must precede the challenge, so a client bug cannot burn one"
    )

    sites = _envelope_put_sites(app)
    assert len(sites) == 1, f"expected exactly one envelope PUT, found {len(sites)}"
    assert start <= sites[0] < end, "the envelope is PUT from outside the proving helper"

    for caller in ("async function zkChangePassphrase(", "async function zkRestoreFromRecoveryKey("):
        body = app[app.index(caller):]
        body = body[: body.index("\nasync function ", 1)]
        assert "zkPutPrivateEnvelope(" in body, f"{caller} does not prove possession"


def test_the_unproven_put_detector_actually_detects_one() -> None:
    """Guards the guard. The previous version of the check above counted every PUT in the file,
    so a second envelope write still satisfied it -- it could not fail. This proves the
    replacement can."""
    app = APP_JS.read_text(encoding="utf-8")
    assert len(_envelope_put_sites(app)) == 1
    injected = app + (
        "\nasync function sneaky() {\n"
        "    await apiRequest('/ecc/keys/private', { method: 'PUT', body: 'x' });\n"
        "}\n"
    )
    assert len(_envelope_put_sites(injected)) == 2, (
        "the detector cannot see an added unproven envelope PUT"
    )


def test_failed_proofs_are_audited_without_recording_the_attempt() -> None:
    """Both routes are authenticated and rate-limited, and the limiter fails OPEN on a backing
    store outage -- so this record is what keeps an attempt burst visible exactly then."""
    src = ROUTER.read_text(encoding="utf-8")
    body = _route_body(src, "async def update_private_key(")
    assert body.count("zk_key_update_pop_failed") >= 2
    assert '"reason"' in body
    for secret in ("pop.mac", "nonce}", "encrypted_private_key}"):
        assert f"details={{{secret}" not in body


def test_design_document_and_code_agree() -> None:
    doc = DESIGN_DOC.read_text(encoding="utf-8")
    src = ROUTER.read_text(encoding="utf-8")
    assert "dv-ecc-update-pop-v1" in doc
    assert "private-key-update-pop" in doc
    assert "16,384" in doc and "_MAX_ENVELOPE_BYTES = 16384" in src
    assert "10 per 15 minutes" in doc and '"key_update": (10, 900)' in src
    assert pop.CHALLENGE_TTL_SECONDS == 300 and "five-minute" in doc.lower()


def test_a_refused_principal_does_not_spend_the_owner_budget() -> None:
    """A temporary session is the OWNER's user row tagged temporary, and the limiter keys on the
    user id -- so charging a refused request would let a leaked temporary credential hold the
    owner out of both routes indefinitely. That is an availability attack on exactly what this
    phase protects, so the refusal must come first.

    Pinned as source order because the surrounding house pattern still rate-limits first, and
    this would quietly drift back.
    """
    src = ROUTER.read_text(encoding="utf-8")
    for anchor, bucket in (
        ("async def key_update_challenge(", '"key_update_challenge"'),
        ("async def update_private_key(", '"key_update"'),
    ):
        body = _route_body(src, anchor)
        assert body.index("_is_temp_session") < body.index(f"_ecc_rate_limit(current_user, {bucket}"), (
            f"{anchor} charges the owner's rate budget before refusing a temporary credential"
        )


def test_failed_proofs_are_recorded_as_failures_not_successes() -> None:
    """An audit row that renders green in the admin feed is worse than no row: it hides the very
    signal this control exists to surface."""
    src = ROUTER.read_text(encoding="utf-8")
    body = _route_body(src, "async def update_private_key(")
    for block in body.split("zk_key_update_pop_failed")[1:]:
        window = block[: block.index(")") + 1] if ")" in block else block
        assert 'status="failure"' in window, "a failed proof is audited as a success"
    # And the helper must actually honour a status argument rather than hardcoding one.
    helper = _route_body(src, "def _audit_zk(")
    assert "status: str = \"success\"" in helper
    assert "status=status," in helper


def test_the_envelope_size_check_cannot_500_on_unencodable_input() -> None:
    """JSON admits a lone surrogate; encoding one raises. That is a malformed request, not a
    server fault -- and the bound must stay on UTF-8 bytes, never narrowed to ASCII, or it would
    refuse legitimate callers and drift from the client-side check."""
    body = _route_body(ROUTER.read_text(encoding="utf-8"), "async def update_private_key(")
    assert "UnicodeEncodeError" in body
    assert body.index("UnicodeEncodeError") < body.index("_MAX_ENVELOPE_BYTES:")
    assert "isascii" not in body and "ascii" not in body.lower().split("unicodeencodeerror")[0][-200:]
