"""The key proof that changes to a zero-knowledge vault's keys carry: its wire format and stored material.

Offline. Three implementations must agree byte for byte: the server module
(``app/services/zk_key_proof.py``), the browser module (``static/js/ecc_crypto.js``) and the independent
reference (``tests/zk_key_proof_reference.py``), which produced the frozen vectors in
``tests/fixtures/crypto/zk-key-proof-v1/``. A Python-only check would agree by construction, which is why
the vectors are frozen files rather than values recomputed at test time.
"""
import base64
import json
import os
import subprocess
import tempfile
from pathlib import Path

import pytest
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

import crypto_reference_vectors as vectors
import zk_key_proof_reference as ref

from app.core import security
from app.services import ecc_pop, ecc_update_pop
from app.services import zk_key_proof as kp

pytestmark = [pytest.mark.unit, pytest.mark.crypto_compatibility]

ROOT = Path(__file__).resolve().parents[1]
FIXTURE_DIR = ROOT / "tests" / "fixtures" / "crypto" / "zk-key-proof-v1"


def _vector() -> dict:
    return vectors.load_unreleased_vector(FIXTURE_DIR / "zk-key-proof-v1.json")


def _server_pem(v) -> str:
    return ref.private_pem(ref.private_from_scalar(v["inputs"]["server_scalar_hex"]))


def _case_transcript(v, case, **overrides) -> bytes:
    i = v["inputs"]
    args = dict(
        op=case["op"], challenge_id=i["challenge_id"], nonce_b64=i["nonce_b64"], user_id=i["user_id"],
        vault_id=i["vault_id"], mode=case["mode"], dek_epoch=case["dek_epoch"],
        team_epoch=case["team_epoch"], identity_public_key=i["identity_public_key_pem"],
        current_public_key=i["current_public_key_pem"] if case["has_current_key"] else None,
        new_public_key=i["new_public_key_pem"] if case["has_new_key"] else None,
        body=i["body_utf8"].encode("utf-8"),
    )
    args.update(overrides)
    return kp.transcript(**args)


# ------------------------------------------------------------------------------ the fixture set

def test_manifest_pins_the_exact_reviewed_fixture_set():
    manifest = json.loads((FIXTURE_DIR / "manifest.json").read_text(encoding="utf-8"))
    listed = [e["path"] for e in manifest["vectors"]]
    assert {p.name for p in FIXTURE_DIR.glob("*.json")} == {"manifest.json", *listed}
    for entry in manifest["vectors"]:
        assert vectors.sha256_file(FIXTURE_DIR / entry["path"]) == entry["sha256"]


def test_the_reference_still_produces_the_frozen_vector():
    """A frozen vector is a format. If the reference drifts, it no longer describes what the other two
    implementations are checked against."""
    assert ref.build_vectors() == _vector()


def test_the_vector_covers_every_operation_and_mode():
    cases = _vector()["transcripts"]
    assert {c["op"] for c in cases} == set(kp.OPS)
    assert {c["mode"] for c in cases} == set(kp.MODES)
    for c in cases:
        assert c["has_current_key"] == (c["op"] not in kp.OPS_WITHOUT_CURRENT_KEY)


# ----------------------------------------------------------------------------- the transcript

def test_the_server_reproduces_every_frozen_transcript():
    v = _vector()
    for case in v["transcripts"]:
        assert _case_transcript(v, case).hex() == case["transcript_sha256_hex"], case["name"]


def test_the_constants_are_the_specified_ones():
    assert kp.PROOF_LABEL == ref.PROOF_LABEL == b"dockvault-zk-key-proof-v1"
    assert kp.PROOF_SALT == ref.PROOF_SALT == b"dv-zk-key-proof-v1"
    assert kp.ROLES == ref.ROLES == ("identity", "current-key", "new-key")
    assert kp.OPS == ref.OPS
    assert kp.MODES == ref.MODES
    assert kp.OPS_WITHOUT_CURRENT_KEY == frozenset(ref.OPS_WITHOUT_CURRENT_KEY)
    assert kp.SEALED_KEY_HEADER == ref.KEY_PROOF_KEY_HEADER == b"DVZ2\x02\x07\x00\x00"
    assert kp.CHALLENGE_TTL_SECONDS == 300
    assert kp.HEADER_NAME == "X-ZK-Key-Proof"


_OTHER = {
    "op": "share",
    "challenge_id": "00000000-0000-4000-8000-000000000000",
    "nonce_b64": base64.b64encode(bytes(range(1, 33))).decode(),
    "user_id": "11111111-2222-4333-8444-555555555555",
    "vault_id": "66666666-7777-4888-9999-aaaaaaaaaaaa",
    "mode": "hierarchical",
    "dek_epoch": 4,
    "team_epoch": 9,
}


@pytest.mark.parametrize("field", sorted(_OTHER) + [
    "identity_public_key", "current_public_key", "new_public_key", "body"])
def test_changing_any_bound_field_changes_the_transcript(field):
    v = _vector()
    case = next(c for c in v["transcripts"] if c["name"] == "rekey-direct")
    base = _case_transcript(v, case)
    if field in _OTHER:
        changed = _case_transcript(v, case, **{field: _OTHER[field]})
    elif field == "body":
        body = bytearray(v["inputs"]["body_utf8"].encode("utf-8"))
        body[-2] ^= 0x01
        changed = _case_transcript(v, case, body=bytes(body))
    else:
        changed = _case_transcript(v, case, **{field: ref.public_pem(ref.private_from_scalar("99"))})
    assert changed != base, f"{field} is not bound into the transcript"


@pytest.mark.parametrize("field", ["current_public_key", "new_public_key"])
def test_an_absent_key_is_not_the_same_as_a_present_one(field):
    v = _vector()
    case = next(c for c in v["transcripts"] if c["name"] == "rekey-direct")
    assert _case_transcript(v, case, **{field: None}) != _case_transcript(v, case)


def test_the_public_point_is_hashed_not_the_pem():
    v = _vector()
    case = v["transcripts"][0]
    pem = v["inputs"]["identity_public_key_pem"]
    for variant in (pem.replace("\n", "\r\n"), "\n  " + pem.strip() + "  \n"):
        assert _case_transcript(v, case, identity_public_key=variant) == _case_transcript(v, case)


def test_ids_are_lowercased_before_they_are_bound():
    v = _vector()
    case = v["transcripts"][0]
    i = v["inputs"]
    assert _case_transcript(v, case, challenge_id=i["challenge_id"].upper(),
                            vault_id=i["vault_id"].upper()) == _case_transcript(v, case)


@pytest.mark.parametrize("override", [
    {"op": "rotate"}, {"mode": "flat"}, {"nonce_b64": base64.b64encode(b"\x00" * 31).decode()},
    {"nonce_b64": "not base64!"}, {"user_id": "not-a-uuid"}, {"vault_id": "0a1b2c3d4e5f40618273849"},
    {"dek_epoch": -1}, {"team_epoch": 2 ** 32}, {"dek_epoch": True},
    {"identity_public_key": "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----\n"},
])
def test_a_malformed_transcript_input_is_refused_as_malformed(override):
    v = _vector()
    with pytest.raises(kp.MalformedProof):
        _case_transcript(v, v["transcripts"][0], **override)


# ------------------------------------------------------------------------------------- the MACs

def test_the_server_verifies_every_frozen_mac_in_its_role():
    v = _vector()
    i = v["inputs"]
    server = _server_pem(v)
    keys = {"identity": i["identity_public_key_pem"], "current-key": i["current_public_key_pem"],
            "new-key": i["new_public_key_pem"]}
    for case in v["transcripts"]:
        t = _case_transcript(v, case)
        for role, mac in case["macs_b64url"].items():
            raw = ref.b64url_decode(mac)
            assert kp.expected_mac(role, server, keys[role], t) == raw, (case["name"], role)
            assert kp.verify_role(role, server, keys[role], t, raw) is True


def test_swapping_two_roles_macs_fails():
    v = _vector()
    i = v["inputs"]
    server = _server_pem(v)
    case = next(c for c in v["transcripts"] if c["name"] == "rekey-direct")
    t = _case_transcript(v, case)
    macs = {r: ref.b64url_decode(m) for r, m in case["macs_b64url"].items()}
    keys = {"identity": i["identity_public_key_pem"], "current-key": i["current_public_key_pem"],
            "new-key": i["new_public_key_pem"]}
    for a in keys:
        for b in keys:
            if a != b:
                assert kp.verify_role(a, server, keys[a], t, macs[b]) is False, (a, b)
    # The same key in another role derives another MAC key: the roles cannot be moved between keys.
    assert kp.expected_mac("identity", server, keys["identity"], t) != kp.expected_mac(
        "current-key", server, keys["identity"], t)


def test_a_mac_does_not_verify_for_another_transcript():
    v = _vector()
    i = v["inputs"]
    server = _server_pem(v)
    a, b = v["transcripts"][0], v["transcripts"][3]
    mac = ref.b64url_decode(a["macs_b64url"]["identity"])
    assert kp.verify_role("identity", server, i["identity_public_key_pem"], _case_transcript(v, b), mac) is False


def test_verification_never_raises():
    v = _vector()
    server = _server_pem(v)
    t = bytes(32)
    for pem, mac in [("garbage", b"\x00" * 32), (v["inputs"]["identity_public_key_pem"], None),
                     (None, b"\x00" * 32), (v["inputs"]["identity_public_key_pem"], b"")]:
        assert kp.verify_role("identity", server, pem, t, mac) is False
    assert kp.verify_role("no-such-role", server, v["inputs"]["identity_public_key_pem"], t, b"\x00" * 32) is False
    assert kp.verify_role("identity", "not a key", v["inputs"]["identity_public_key_pem"], t, b"\x00" * 32) is False


def test_the_reference_client_mac_is_what_the_server_expects():
    """The two sides of each ECDH: the client's (role private key, server public key) and the server's
    (server private key, role public key) derive the same MAC key."""
    v = _vector()
    i = v["inputs"]
    t = bytes(range(32))
    for role, scalar, pem in (("identity", i["identity_scalar_hex"], i["identity_public_key_pem"]),
                              ("new-key", i["new_scalar_hex"], i["new_public_key_pem"])):
        client = ref.role_mac(role, ref.private_from_scalar(scalar), i["server_public_key_pem"], t)
        assert kp.verify_role(role, _server_pem(v), pem, t, client) is True


# ----------------------------------------------------------------------------------- the header

def test_every_frozen_header_parses_to_its_macs():
    v = _vector()
    for case in v["transcripts"]:
        h = kp.parse_header(case["header"])
        assert h.challenge_id == v["inputs"]["challenge_id"]
        macs = {r: ref.b64url_decode(m) for r, m in case["macs_b64url"].items()}
        assert h.identity_mac == macs["identity"]
        assert h.current_key_mac == macs.get("current-key")
        assert h.new_key_mac == macs.get("new-key")


def _mac43():
    return ref.b64url(bytes(range(32)))


@pytest.mark.parametrize("value", [
    None, "", 7, "v2.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}.-.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}.-.-.-",
    "v1.not-a-challenge-id.{m}.-.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.-.-.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}=.-.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}.+{m}.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}.{short}.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{noncanon}.-.-",
    "v1.3f2504e0-4f89-11d3-9a0c-0305e82c3301.{m}.-.-" + "x" * 300,
])
def test_a_malformed_header_is_refused_as_malformed(value):
    if isinstance(value, str):
        m = _mac43()
        noncanon = m[:-1] + ("B" if m[-1] == "A" else chr(ord(m[-1]) + 1))
        value = value.format(m=m, short=m[:40], noncanon=noncanon)
    with pytest.raises(kp.MalformedProof):
        kp.parse_header(value)


def test_the_header_challenge_id_is_normalised():
    h = kp.parse_header(f"v1.3F2504E0-4F89-11D3-9A0C-0305E82C3301.{_mac43()}.-.-")
    assert h.challenge_id == "3f2504e0-4f89-11d3-9a0c-0305e82c3301"
    assert h.current_key_mac is None and h.new_key_mac is None


# ------------------------------------------------------------------------ the material's shape

def test_the_sealed_key_shape_is_checked_without_opening_it():
    sealed = _vector()["seal"]["sealed_b64"]
    raw = kp.validate_sealed_key(sealed)
    assert raw == base64.b64decode(sealed)
    bad = [
        None, "", "not base64!",
        base64.b64encode(b"DVZ2\x02\x07\x00\x00" + b"\x00" * 27).decode(),        # 35 bytes: too short
        base64.b64encode(b"DVZ2\x02\x07\x00\x00" + b"\x00" * 8185).decode(),      # 8193 bytes: too long
        base64.b64encode(b"DVZ1\x02\x07\x00\x00" + b"\x00" * 40).decode(),        # magic
        base64.b64encode(b"DVZ2\x01\x07\x00\x00" + b"\x00" * 40).decode(),        # version
        base64.b64encode(b"DVZ2\x02\x03\x00\x00" + b"\x00" * 40).decode(),        # purpose (team key)
        base64.b64encode(b"DVZ2\x02\x07\x00\x01" + b"\x00" * 40).decode(),        # reserved
        "A" * 20000,
    ]
    for value in bad:
        with pytest.raises(kp.MalformedProof):
            kp.validate_sealed_key(value)
    kp.validate_sealed_key(base64.b64encode(b"DVZ2\x02\x07\x00\x00" + b"\x00" * 28).decode())   # 36
    kp.validate_sealed_key(base64.b64encode(b"DVZ2\x02\x07\x00\x00" + b"\x00" * 8184).decode())  # 8192


def test_a_key_check_and_a_lineage_tag_are_exactly_32_bytes():
    v = _vector()
    kp.validate_mac32(v["dek_check"][0]["dek_check_b64"], "dek_check")
    kp.validate_mac32(v["lineage"][0]["lineage_tag_b64"], "lineage_tag")
    for value in (None, "", base64.b64encode(b"\x00" * 31).decode(), base64.b64encode(b"\x00" * 33).decode(),
                  "!" * 44, "A" * 100):
        with pytest.raises(kp.MalformedProof):
            kp.validate_mac32(value, "dek_check")


def test_only_a_p384_public_key_is_accepted():
    v = _vector()
    assert len(kp.public_point(v["inputs"]["new_public_key_pem"])) == 97
    p256 = ec.generate_private_key(ec.SECP256R1()).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo).decode()
    for value in (None, "", "TEAMPUB-1234", p256, "-----BEGIN PUBLIC KEY-----\nAAAA\n-----END PUBLIC KEY-----",
                  "x" * 5000, v["inputs"]["identity_private_key_pem"]):
        with pytest.raises(kp.MalformedProof):
            kp.public_point(value)


def test_a_challenge_is_a_fresh_p384_key_and_a_32_byte_nonce():
    a, b = kp.generate_challenge(), kp.generate_challenge()
    assert a[0] != b[0] and a[2] != b[2]
    assert len(kp.public_point(a[1])) == 97
    assert len(base64.b64decode(a[2])) == 32
    assert "PRIVATE KEY" in a[0]


# --------------------------------------------------------------------------- domain separation

def test_no_mac_crosses_between_this_proof_and_the_other_two():
    """Registration and envelope replacement answer a challenge of the same shape. A MAC made for either,
    over the same server key, must never verify here, and the reverse."""
    v = _vector()
    i = v["inputs"]
    server = _server_pem(v)
    pem = i["identity_public_key_pem"]
    case = v["transcripts"][0]
    t = _case_transcript(v, case)
    registration = ecc_pop._mac(server, pem, i["nonce_b64"])
    update = ecc_update_pop.expected_mac(server, pem, i["challenge_id"], i["nonce_b64"], i["user_id"], "x")
    for role in kp.ROLES:
        assert kp.verify_role(role, server, pem, t, registration) is False
        assert kp.verify_role(role, server, pem, t, update) is False
    ours = ref.b64url_decode(case["macs_b64url"]["identity"])
    assert ecc_pop.verify_pop(server, pem, i["nonce_b64"], base64.b64encode(ours).decode()) is False
    assert ecc_update_pop.verify_pop(server, pem, i["challenge_id"], i["nonce_b64"], i["user_id"], "x",
                                     base64.b64encode(ours).decode()) is False
    assert len({kp.PROOF_SALT, ecc_pop._HKDF_SALT, ecc_update_pop._HKDF_SALT}) == 3
    assert kp.PROOF_LABEL != ecc_update_pop._PROTOCOL_LABEL


def test_the_derivation_labels_are_pairwise_distinct_and_none_prefixes_another():
    """Every DEK-derived key in the zero-knowledge format family is derived under its own label, and a
    label is followed by 0x00 before its context, so one derivation's input can never be another's."""
    src = (ROOT / "static" / "js" / "ecc_crypto.js").read_text(encoding="utf-8")
    labels = {
        "seal": ref.INFO_KEY_PROOF_KEY,
        "check": ref.INFO_DEK_CHECK,
        "lineage": ref.INFO_KEY_LINEAGE,
        "content": b"dockvault-zk-content-v2",
        "resume": b"dockvault-zk-resume-frame-mac-v1",
        "name-index-key": b"dockvault-zk-name-index-key-v2",
        "direct": b"dockvault-zk-dek-direct-v2",
        "team-dek": b"dockvault-zk-dek-team-v2",
        "team-private": b"dockvault-zk-teampriv-v2",
        "link-token": b"dockvault-zk-link-token-v2",
    }
    for name in ("content", "resume", "name-index-key", "direct", "team-dek", "team-private", "link-token"):
        assert f"'{labels[name].decode()}'" in src, f"{name}: the browser module's label moved"
    terminated = {n: l + b"\x00" for n, l in labels.items()}
    for a, la in terminated.items():
        for b, lb in terminated.items():
            if a != b:
                assert not lb.startswith(la), f"{a} prefixes {b}"
    # The name blind index keys an HMAC by salt, not by one of these infos.
    assert b"dv-zk-name-bi-v1" not in labels.values()


# ----------------------------------------------------------------------- the reference material

def test_the_reference_seal_opens_only_with_its_own_dek_vault_epoch_and_key():
    s = _vector()["seal"]
    sealed = base64.b64decode(s["sealed_b64"])
    dek = bytes.fromhex(s["dek_hex"])
    opened = ref.open_key_proof_key(sealed, dek, s["vault_id"], s["dek_epoch"], s["proof_public_key_pem"])
    assert ref.point(ref.public_pem(opened)) == ref.point(s["proof_public_key_pem"])
    other_key = ref.public_pem(ref.private_from_scalar("45"))
    for args in [(bytes(32), s["vault_id"], s["dek_epoch"], s["proof_public_key_pem"]),
                 (dek, "66666666-7777-4888-9999-aaaaaaaaaaaa", s["dek_epoch"], s["proof_public_key_pem"]),
                 (dek, s["vault_id"], s["dek_epoch"] + 1, s["proof_public_key_pem"]),
                 (dek, s["vault_id"], s["dek_epoch"], other_key)]:
        with pytest.raises(Exception):
            ref.open_key_proof_key(sealed, *args)


def test_the_key_check_and_lineage_tag_bind_what_they_claim():
    v = _vector()
    d = v["dek_check"][0]
    dek = bytes.fromhex(d["dek_hex"])
    check = ref.dek_check(dek, d["vault_id"], d["dek_epoch"])
    assert base64.b64encode(check).decode() == d["dek_check_b64"]
    assert ref.dek_check(dek, d["vault_id"], d["dek_epoch"] + 1) != check
    assert ref.dek_check(bytes(32), d["vault_id"], d["dek_epoch"]) != check
    assert ref.dek_check(dek, "66666666-7777-4888-9999-aaaaaaaaaaaa", d["dek_epoch"]) != check

    ln = v["lineage"][0]
    base = dict(vault_id=ln["vault_id"], prev_epoch=ln["prev_epoch"], mode="direct",
                next_team_epoch=ln["next_team_epoch"], next_verifier_pem=ln["next_verifier_pem"],
                next_dek_check=base64.b64decode(ln["next_dek_check_b64"]), next_team_wrap_b64=None)
    prev = bytes.fromhex(ln["prev_dek_hex"])
    tag = ref.lineage_tag(prev, **base)
    assert base64.b64encode(tag).decode() == ln["lineage_tag_b64"]
    for change in [{"prev_epoch": 4}, {"next_team_epoch": 2},
                   {"next_verifier_pem": ref.public_pem(ref.private_from_scalar("56"))},
                   {"next_dek_check": bytes(32)}, {"vault_id": "66666666-7777-4888-9999-aaaaaaaaaaaa"}]:
        assert ref.lineage_tag(prev, **{**base, **change}) != tag, change
    assert ref.lineage_tag(bytes(32), **base) != tag


# ---------------------------------------------------------------------------- the strict decrypt

@pytest.fixture
def fernet_key(monkeypatch):
    key = Fernet.generate_key().decode()
    monkeypatch.setattr(security, "_runtime_settings", lambda: type("S", (), {"encryption_key": key})())
    return key


def test_the_strict_decrypt_opens_only_what_this_deployment_sealed(fernet_key):
    pem = "-----BEGIN PRIVATE KEY-----\nMIG2...\n-----END PRIVATE KEY-----\n"
    sealed = security.encrypt_secret(pem)
    assert "BEGIN" not in sealed
    assert security.decrypt_secret_strict(sealed) == pem
    for planted in (pem, "", None, "not-a-token", "gAAAAAB" + "A" * 80):
        with pytest.raises(ValueError):
            security.decrypt_secret_strict(planted)
    other = Fernet(Fernet.generate_key()).encrypt(pem.encode()).decode()
    with pytest.raises(ValueError):
        security.decrypt_secret_strict(other)
    # The lenient decrypt keeps its back-compat behaviour for stored credentials.
    assert security.decrypt_secret(pem) == pem


# ----------------------------------------------------------------------------- the browser module

CRYPTO_JS = ROOT / "static" / "js" / "ecc_crypto.js"


def _node(script: str) -> dict:
    """Run `script` against the shipped browser module under Node; it prints one JSON line."""

    harness = f"""
const {{ webcrypto }} = require('crypto');
global.window = {{ crypto: webcrypto }};
global.btoa = s => Buffer.from(s, 'binary').toString('base64');
global.atob = s => Buffer.from(s, 'base64').toString('binary');
const ECCCryptoLibrary = require({json.dumps(str(CRYPTO_JS))});
const realLog = console.log;
console.error = () => {{}};
const V = {json.dumps(_vector())};
const aes = hex => webcrypto.subtle.importKey('raw', Buffer.from(hex, 'hex'), {{ name: 'AES-GCM', length: 256 }},
                                              true, ['encrypt', 'decrypt']);
const code = async fn => {{ try {{ await fn(); return 'NONE'; }} catch (e) {{ return e.code || ('UNCODED:' + e); }} }};
(async () => {{
  const lib = new ECCCryptoLibrary();
{script}
}})().catch(e => {{ process.stderr.write('HARNESS ' + (e && e.stack)); process.exit(1); }});
"""
    # A file rather than `node -e`: the script carries the whole vector, which is longer than a Windows
    # command line may be.
    fd, path = tempfile.mkstemp(suffix=".js")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(harness)
        proc = subprocess.run(["node", path], capture_output=True, text=True, timeout=300, cwd=str(ROOT))
    finally:
        os.unlink(path)
    assert proc.returncode == 0, proc.stderr
    return json.loads([ln for ln in proc.stdout.splitlines() if ln.startswith("{")][-1])


_KEYS_JS = """
  const i = V.inputs;
  const keys = {
    identityKey: await lib.importPrivateKeyPEM(i.identity_private_key_pem, false),
    currentKey: await lib.importPrivateKeyPEM(i.current_private_key_pem, false),
    newKey: await lib.importPrivateKeyPEM(i.new_private_key_pem, false),
  };
  const challenge = { challenge_id: i.challenge_id, nonce: i.nonce_b64,
                      server_ephemeral_public_key: i.server_public_key_pem };
"""


def test_the_browser_reproduces_every_frozen_transcript_and_header():
    """The whole protocol rests on this. A Python-only check would agree by construction and leave a
    browser-side divergence green, so the shipped module is what is executed."""
    out = _node(_KEYS_JS + """
  const res = {};
  for (const c of V.transcripts) {
    const p = { op: c.op, userId: i.user_id, vaultId: i.vault_id, mode: c.mode, dekEpoch: c.dek_epoch,
      teamEpoch: c.team_epoch, identityPem: i.identity_public_key_pem,
      currentPem: c.has_current_key ? i.current_public_key_pem : null,
      newPem: c.has_new_key ? i.new_public_key_pem : null, bodyString: i.body_utf8 };
    const t = await lib.keyProofTranscript({ ...p, challengeId: i.challenge_id, nonce: i.nonce_b64 });
    const h = await lib.computeKeyProof({ ...p, challenge }, keys);
    res[c.name] = { t: Buffer.from(t).toString('hex'), h };
  }
  realLog(JSON.stringify(res));
""")
    for case in _vector()["transcripts"]:
        assert out[case["name"]]["t"] == case["transcript_sha256_hex"], case["name"]
        assert out[case["name"]]["h"] == case["header"], case["name"]


def test_an_operation_without_a_current_key_never_binds_or_proves_one():
    """The operations that install the first verifier or replace damaged material prove no current key.
    Handed one anyway, the browser must neither hash it into the transcript nor send its MAC."""
    out = _node(_KEYS_JS + """
  const c = V.transcripts.find(x => x.name === 'bootstrap-direct');
  const p = { op: c.op, userId: i.user_id, vaultId: i.vault_id, mode: c.mode, dekEpoch: c.dek_epoch,
    teamEpoch: c.team_epoch, identityPem: i.identity_public_key_pem, currentPem: i.current_public_key_pem,
    newPem: i.new_public_key_pem, bodyString: i.body_utf8 };
  realLog(JSON.stringify({ h: await lib.computeKeyProof({ ...p, challenge }, keys) }));
""")
    assert out["h"] == next(c for c in _vector()["transcripts"] if c["name"] == "bootstrap-direct")["header"]


def test_the_browser_opens_the_frozen_sealed_key_as_a_derive_only_key():
    out = _node("""
  const s = V.seal;
  const key = await lib.openKeyProofKey(s.sealed_b64, s.proof_public_key_pem, await aes(s.dek_hex),
                                        s.vault_id, s.dek_epoch);
  realLog(JSON.stringify({ extractable: key.extractable, usages: key.usages, type: key.type }));
""")
    assert out == {"extractable": False, "usages": ["deriveBits"], "type": "private"}


def test_a_sealed_key_fails_closed_with_the_code_for_each_fault():
    s = _vector()["seal"]
    sealed = base64.b64decode(s["sealed_b64"])
    pem, dek, vid, ep = s["proof_public_key_pem"], s["dek_hex"], s["vault_id"], s["dek_epoch"]

    def b64(raw):
        return base64.b64encode(raw).decode()

    # Sealed for the right public key but holding another private key: it authenticates, and only the
    # point comparison can catch it.
    other_pkcs8 = ref.private_from_scalar("45").private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    mismatched = ref.seal_key_proof_key(bytes.fromhex(dek), vid, ep, pem, other_pkcs8, bytes(12))
    cases = {
        "wrong_dek": (s["sealed_b64"], pem, "00" * 32, vid, ep),
        "other_vault": (s["sealed_b64"], pem, dek, "66666666-7777-4888-9999-aaaaaaaaaaaa", ep),
        "other_epoch": (s["sealed_b64"], pem, dek, vid, ep + 1),
        "other_public_key": (s["sealed_b64"], ref.public_pem(ref.private_from_scalar("46")), dek, vid, ep),
        "flipped_tag": (b64(sealed[:-1] + bytes([sealed[-1] ^ 1])), pem, dek, vid, ep),
        "magic": (b64(b"DVZ1" + sealed[4:]), pem, dek, vid, ep),
        "version": (b64(sealed[:4] + b"\x03" + sealed[5:]), pem, dek, vid, ep),
        "purpose": (b64(sealed[:5] + b"\x03" + sealed[6:]), pem, dek, vid, ep),
        "reserved": (b64(sealed[:7] + b"\x01" + sealed[8:]), pem, dek, vid, ep),
        "too_short": (b64(sealed[:35]), pem, dek, vid, ep),
        "too_long": (b64(sealed + bytes(8193 - len(sealed))), pem, dek, vid, ep),
        "not_base64": ("%%%", pem, dek, vid, ep),
        "bad_public_key": (s["sealed_b64"], "not a key", dek, vid, ep),
        "mismatched_private_half": (b64(mismatched), pem, dek, vid, ep),
    }
    out = _node(f"""
  const cases = {json.dumps(cases)};
  const res = {{}};
  for (const [name, [b64, pem, dek, vid, ep]] of Object.entries(cases)) {{
    res[name] = await code(async () => lib.openKeyProofKey(b64, pem, await aes(dek), vid, ep));
  }}
  const s = V.seal;
  const short = await webcrypto.subtle.importKey('raw', Buffer.alloc(16, 1), {{ name: 'AES-GCM', length: 128 }},
                                                 true, ['encrypt']);
  const hmacKey = await webcrypto.subtle.importKey('raw', Buffer.alloc(32, 1), {{ name: 'HMAC', hash: 'SHA-256' }},
                                                   true, ['sign']);
  res.aes128_dek = await code(() => lib.openKeyProofKey(s.sealed_b64, s.proof_public_key_pem, short, s.vault_id, s.dek_epoch));
  res.hmac_dek = await code(() => lib.openKeyProofKey(s.sealed_b64, s.proof_public_key_pem, hmacKey, s.vault_id, s.dek_epoch));
  res.seal_aes128 = await code(() => lib.sealKeyProofKey(short, s.vault_id, 1));
  res.seal_hmac = await code(() => lib.sealKeyProofKey(hmacKey, s.vault_id, 1));
  res.check_hmac = await code(() => lib.dekCheck(hmacKey, s.vault_id, 1));
  realLog(JSON.stringify(res));
""")
    assert out == {
        "wrong_dek": "WRAP_FAILED", "other_vault": "WRAP_FAILED", "other_epoch": "WRAP_FAILED",
        "other_public_key": "WRAP_FAILED", "flipped_tag": "WRAP_FAILED",
        "magic": "WRAP_INVALID", "version": "WRAP_INVALID", "purpose": "WRAP_INVALID", "reserved": "WRAP_INVALID",
        "too_short": "WRAP_INVALID", "too_long": "WRAP_INVALID", "not_base64": "WRAP_INVALID",
        "bad_public_key": "WRAP_INVALID", "mismatched_private_half": "KEY_MISMATCH",
        "aes128_dek": "INVALID_INPUT", "hmac_dek": "INVALID_INPUT", "seal_aes128": "INVALID_INPUT",
        "seal_hmac": "INVALID_INPUT", "check_hmac": "INVALID_INPUT",
    }


def test_a_browser_sealed_key_opens_in_the_reference_and_its_check_matches():
    """The other direction: what the browser writes, an independent implementation reads."""
    s = _vector()["seal"]
    out = _node("""
  const s = V.seal;
  const dek = await aes(s.dek_hex);
  const m = await lib.sealKeyProofKey(dek, s.vault_id, 5);
  const again = await lib.openKeyProofKey(m.sealedKey, m.publicKeyPem, dek, s.vault_id, 5);
  realLog(JSON.stringify({ pem: m.publicKeyPem, sealed: m.sealedKey, check: m.dekCheck,
    priv: { extractable: m.privateKey.extractable, usages: m.privateKey.usages },
    reopened: again.extractable === false }));
""")
    dek = bytes.fromhex(s["dek_hex"])
    opened = ref.open_key_proof_key(base64.b64decode(out["sealed"]), dek, s["vault_id"], 5, out["pem"])
    assert ref.point(ref.public_pem(opened)) == ref.point(out["pem"])
    assert base64.b64decode(out["check"]) == ref.dek_check(dek, s["vault_id"], 5)
    assert out["priv"] == {"extractable": False, "usages": ["deriveBits"]}
    assert out["reopened"] is True
    assert kp.validate_sealed_key(out["sealed"])[:8] == kp.SEALED_KEY_HEADER


def test_the_browser_key_check_and_lineage_tag_reproduce_the_vectors():
    out = _node("""
  const res = { checks: [], lineage: {} };
  for (const d of V.dek_check) res.checks.push(await lib.dekCheck(await aes(d.dek_hex), d.vault_id, d.dek_epoch));
  for (const l of V.lineage) {
    const prev = await aes(l.prev_dek_hex);
    const f = { vaultId: l.vault_id, prevEpoch: l.prev_epoch, mode: l.mode, nextTeamEpoch: l.next_team_epoch,
      nextVerifierPem: l.next_verifier_pem, nextDekCheck: l.next_dek_check_b64, nextTeamWrap: l.next_team_wrap_b64 };
    res.lineage[l.mode] = {
      tag: await lib.keyLineageTag(prev, f),
      verifies: await lib.verifyKeyLineageTag(prev, f, l.lineage_tag_b64),
      other_field: await lib.verifyKeyLineageTag(prev, { ...f, nextTeamEpoch: f.nextTeamEpoch + 1 }, l.lineage_tag_b64),
      other_dek: await lib.verifyKeyLineageTag(await aes('00'.repeat(32)), f, l.lineage_tag_b64),
      garbage: await lib.verifyKeyLineageTag(prev, { ...f, mode: 'flat' }, l.lineage_tag_b64),
    };
  }
  realLog(JSON.stringify(res));
""")
    v = _vector()
    assert out["checks"] == [d["dek_check_b64"] for d in v["dek_check"]]
    for ln in v["lineage"]:
        assert out["lineage"][ln["mode"]] == {"tag": ln["lineage_tag_b64"], "verifies": True, "other_field": False,
                                              "other_dek": False, "garbage": False}, ln["mode"]


def test_the_team_key_match_compares_points():
    i = _vector()["inputs"]
    new_der = ref.private_from_scalar(i["new_scalar_hex"]).private_bytes(
        serialization.Encoding.DER, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    crlf_pem = i["new_public_key_pem"].replace("\n", "\r\n")
    out = _node(f"""
  const der = Buffer.from({json.dumps(new_der.hex())}, 'hex');
  realLog(JSON.stringify({{
    same: await lib.teamPrivateKeyMatchesPublic(der, V.inputs.new_public_key_pem),
    reencoded: await lib.teamPrivateKeyMatchesPublic(der, {json.dumps(crlf_pem)}),
    other: await lib.teamPrivateKeyMatchesPublic(der, V.inputs.current_public_key_pem),
    garbage: await lib.teamPrivateKeyMatchesPublic(Buffer.from('nope'), V.inputs.new_public_key_pem),
  }}));
""")
    assert out == {"same": True, "reencoded": True, "other": False, "garbage": False}


def test_the_browser_refuses_malformed_transcript_input():
    out = _node(_KEYS_JS + """
  const base = { op: 'share', challengeId: i.challenge_id, nonce: i.nonce_b64, userId: i.user_id,
    vaultId: i.vault_id, mode: 'direct', dekEpoch: 1, teamEpoch: 1, identityPem: i.identity_public_key_pem,
    currentPem: null, newPem: null, bodyString: '{}' };
  const res = {};
  for (const [name, over] of Object.entries({
    op: { op: 'rotate' }, mode: { mode: 'flat' }, nonce: { nonce: Buffer.alloc(31).toString('base64') },
    user: { userId: 'nope' }, vault: { vaultId: '0a1b2c3d4e5f' }, epoch: { dekEpoch: 0 },
    body: { bodyString: { a: 1 } },
  })) res[name] = await code(() => lib.keyProofTranscript({ ...base, ...over }));
  res.no_identity = await code(() => lib.computeKeyProof({ ...base, challenge }, {}));
  realLog(JSON.stringify(res));
""")
    assert set(out.values()) == {"INVALID_INPUT"}, out


def test_the_browser_constants_and_registration():
    """Every public key-proof method is behind the coded-error boundary (which refuses to load if a named
    method is missing), the labels are the reference's, and the stored-material format is pinned."""
    src = CRYPTO_JS.read_text(encoding="utf-8")
    table = src[src.index("const _OPERATION_DEFAULT_CODE"):]
    table = table[: table.index("});")]
    for name in ("sealKeyProofKey", "openKeyProofKey", "dekCheck", "keyLineageTag", "verifyKeyLineageTag",
                 "teamPrivateKeyMatchesPublic", "keyProofTranscript", "computeKeyProof"):
        assert f"    {name}: CRYPTO_ERROR_CODES." in table, name
    out = _node("""
  realLog(JSON.stringify({
    purpose: lib.V2_PURPOSE_KEY_PROOF_KEY, info: lib.V2_INFO_KEY_PROOF_KEY, check: lib.V2_INFO_DEK_CHECK,
    lineage: lib.V2_INFO_KEY_LINEAGE, label: lib.KEY_PROOF_LABEL, salt: lib.KEY_PROOF_SALT,
    version: lib.KEY_PROOF_HEADER_VERSION, ops: lib.KEY_PROOF_OPS, modes: lib.KEY_PROOF_MODES,
    without: lib.KEY_PROOF_OPS_WITHOUT_CURRENT_KEY, format: lib.ZK_KEY_PROOF_WRITE_FORMAT, debug: lib.DEBUG,
    min: lib.V2_KEY_PROOF_KEY_MIN_BYTES, max: lib.V2_KEY_PROOF_KEY_MAX_BYTES,
    inspect: lib._inspectV2Header(Buffer.from([0x44, 0x56, 0x5a, 0x32, 2, 7, 0, 0])),
  }));
""")
    assert out == {
        "purpose": ref.V2_PURPOSE_KEY_PROOF_KEY, "info": ref.INFO_KEY_PROOF_KEY.decode(),
        "check": ref.INFO_DEK_CHECK.decode(), "lineage": ref.INFO_KEY_LINEAGE.decode(),
        "label": ref.PROOF_LABEL.decode(), "salt": ref.PROOF_SALT.decode(), "version": ref.HEADER_VERSION,
        "ops": ref.OPS, "modes": ref.MODES, "without": list(ref.OPS_WITHOUT_CURRENT_KEY), "format": 1,
        "debug": False, "min": ref.SEALED_MIN_BYTES, "max": ref.SEALED_MAX_BYTES, "inspect": "UNSUPPORTED",
    }
