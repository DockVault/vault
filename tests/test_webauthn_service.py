"""The passkey service (app/services/webauthn_service.py) against a software authenticator: the four ceremonies'
happy paths for every allowed algorithm, and every refusal the vault makes itself or takes from the library,
each by its reason. Offline."""
import os
import uuid

import pytest

from _bare_api_env import set_bare_api_env
from _webauthn_softauth import EDDSA, ES256, FLAG, RS256, SoftAuthenticator

pytestmark = pytest.mark.unit

ORIGIN = "http://localhost:8200"
RP_ID = "localhost"
USER_ID = uuid.uuid4()


def _svc():
    set_bare_api_env()
    from app.services import webauthn_service as ws
    return ws


def _rp():
    ws = _svc()
    return ws.RelyingParty(rp_id=RP_ID, origin=ORIGIN, name="Test Vault")


def _register(ws, auth, policy=None, *, rp=None, origin=ORIGIN, existing=(), **mk):
    rp = rp or _rp()
    policy = policy or ws.PasskeyPolicy()
    challenge = os.urandom(32)
    options = ws.registration_options(rp, policy, challenge=challenge, user_id=USER_ID.bytes, username="alice",
                                      display_name="Alice", existing=existing)
    credential = auth.make_credential(options, origin, **mk)
    return ws.verify_registration(rp, policy, challenge=challenge, credential=credential,
                                  existing_ids=[cid for cid, _ in existing]), options, credential


def _key(ws, registered, *, sign_count=None, backup_eligible=None, user_id=USER_ID.bytes):
    return ws.KnownKey(credential_id=registered.credential_id, public_key_cose=registered.public_key_cose,
                       cose_alg=registered.cose_alg,
                       sign_count=registered.sign_count if sign_count is None else sign_count,
                       backup_eligible=registered.backup_eligible if backup_eligible is None else backup_eligible,
                       user_id=user_id, transports=registered.transports)


def _assert(ws, auth, key, policy=None, *, rp=None, origin=ORIGIN, allow=None, **ga):
    rp = rp or _rp()
    policy = policy or ws.PasskeyPolicy()
    challenge = os.urandom(32)
    allow = [(key.credential_id, key.transports)] if allow is None else allow
    options = ws.authentication_options(rp, policy, challenge=challenge, allow=allow)
    credential = auth.get_assertion(options, origin, **ga)
    return ws.verify_authentication(rp, policy, challenge=challenge, credential=credential, key=key,
                                    allow_ids=[cid for cid, _ in allow])


@pytest.mark.parametrize("alg", [ES256, RS256, EDDSA])
def test_a_key_is_registered_and_asserted_for_every_allowed_algorithm(alg):
    ws = _svc()
    auth = SoftAuthenticator(alg)
    registered, options, credential = _register(ws, auth, transports=["internal"])
    pk = options["publicKey"]
    assert pk["rp"] == {"id": RP_ID, "name": "Test Vault"} and pk["user"]["name"] == "alice"
    assert [p["alg"] for p in pk["pubKeyCredParams"]] == [ES256, RS256, EDDSA]
    assert pk["authenticatorSelection"]["userVerification"] == "required"
    assert pk["authenticatorSelection"]["residentKey"] == "preferred" and pk["attestation"] == "none"
    assert pk["extensions"] == {"credProps": True} and pk["timeout"] == 120000
    assert registered.credential_id == auth.credential_id and registered.cose_alg == alg
    assert registered.transports == ("internal",) and registered.uv_initialized and registered.sign_count == 0
    assert registered.backup_eligible is False and registered.aaguid is None and registered.attestation_format == "none"
    key = _key(ws, registered)
    result = _assert(ws, auth, key, sign_count=1)
    assert result.credential_id == auth.credential_id and result.user_handle == USER_ID.bytes
    assert result.sign_count == 1 and result.up and result.uv and not result.be


def test_the_flags_and_the_authenticators_identifier_are_recorded_as_received():
    ws = _svc()
    aaguid = uuid.uuid4()
    auth = SoftAuthenticator(ES256, aaguid=aaguid.bytes)
    registered, _, _ = _register(ws, auth, flags=FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS, sign_count=7,
                                 extensions={"credProps": {"rk": True}})
    assert registered.backup_eligible and registered.backup_state and registered.discoverable is True
    assert registered.aaguid == aaguid and registered.sign_count == 7
    # A synced passkey may not count: equal and lower counts are accepted for it.
    key = _key(ws, registered)
    assert _assert(ws, auth, key, flags=FLAG.UP | FLAG.UV | FLAG.BE | FLAG.BS, sign_count=0).be
    assert _assert(ws, auth, key, flags=FLAG.UP | FLAG.UV | FLAG.BE, sign_count=3).bs is False


def test_the_origin_and_the_relying_party_id_must_match_exactly():
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    key = _key(ws, registered)
    for bad_origin in ("http://localhost:1", "http://localhost", "https://localhost:8200", "http://evil.localhost",
                       "https://evil.example"):
        with pytest.raises(ws.Refused) as e:
            _assert(ws, auth, key, origin=bad_origin)
        assert e.value.code == "origin_mismatch", bad_origin
        with pytest.raises(ws.Refused) as e:
            _register(ws, SoftAuthenticator(ES256), origin=bad_origin)
        assert e.value.code == "origin_mismatch", bad_origin
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, rp_id_override="evil.localhost")
    assert e.value.code == "rp_id_mismatch"
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, challenge_override="AAAA")
    assert e.value.code == "challenge_mismatch"


def test_the_person_must_be_present_and_verified_when_the_policy_says_so():
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    key = _key(ws, registered)
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, flags=FLAG.UV)
    assert e.value.code == "user_not_present"
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, flags=FLAG.UP)
    assert e.value.code == "user_not_verified"
    # Without the requirement the assertion is accepted and the flag recorded for the pipeline to judge.
    lax = ws.PasskeyPolicy(require_uv=False)
    result = _assert(ws, auth, key, lax, flags=FLAG.UP)
    assert result.up and not result.uv
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256), flags=FLAG.UP)
    assert e.value.code == "user_not_verified"
    assert _register(ws, SoftAuthenticator(ES256), lax, flags=FLAG.UP)[0].uv_initialized is False


def test_the_vault_checks_user_verification_itself_and_does_not_lean_on_the_library(monkeypatch):
    """The library refuses a ceremony without user verification when it was told that the ceremony required it. The
    vault's own check stands beside that one, not behind it: with the library told that verification was only
    preferred (as a later version, or a changed call, might read it), a registration and an assertion without
    user verification are refused all the same, and one with it is accepted."""
    from fido2.server import Fido2Server
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    key = _key(ws, registered)
    register, authenticate = Fido2Server.register_complete, Fido2Server.authenticate_complete

    def lax(state):
        assert state["user_verification"] == "required"          # what the vault told the library
        return {**state, "user_verification": "preferred"}
    monkeypatch.setattr(Fido2Server, "register_complete", lambda self, state, response: register(self, lax(state), response))
    monkeypatch.setattr(Fido2Server, "authenticate_complete",
                        lambda self, state, credentials, response: authenticate(self, lax(state), credentials, response))
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, flags=FLAG.UP)
    assert e.value.code == "user_not_verified"
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256), flags=FLAG.UP)
    assert e.value.code == "user_not_verified"
    assert _assert(ws, auth, key, flags=FLAG.UP | FLAG.UV).uv is True
    assert _register(ws, SoftAuthenticator(ES256))[0].uv_initialized is True


def test_the_algorithm_is_the_policys_at_registration_and_the_keys_at_assertion():
    ws = _svc()
    only_es256 = ws.PasskeyPolicy(allowed_algs=(ES256,))
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(RS256), only_es256)
    assert e.value.code == "algorithm_not_allowed"
    # A key that lies about its algorithm in the COSE key is refused the same way.
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256, cose_alg_override=-65535), ws.PasskeyPolicy())
    assert e.value.code == "algorithm_not_allowed"
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth, only_es256)
    key = _key(ws, registered)
    assert _assert(ws, auth, key, only_es256).sign_count == 1
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, ws.KnownKey(**{**key.__dict__, "cose_alg": RS256}), only_es256)
    assert e.value.code == "algorithm_mismatch"


def test_the_sign_count_moves_forward_on_a_device_bound_key():
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth, sign_count=5)
    key = _key(ws, registered)
    assert _assert(ws, auth, key, sign_count=6).sign_count == 6
    for same_or_lower in (5, 4, 0):
        with pytest.raises(ws.Refused) as e:
            _assert(ws, auth, key, sign_count=same_or_lower)
        assert e.value.code == "sign_count_regressed", same_or_lower
    # An authenticator that never counts (0 then 0) is accepted.
    never = _key(ws, registered, sign_count=0)
    assert _assert(ws, auth, never, sign_count=0).sign_count == 0


def test_the_backup_flag_is_pinned_at_registration():
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    key = _key(ws, registered)
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, flags=FLAG.UP | FLAG.UV | FLAG.BE)
    assert e.value.code == "backup_flag_changed"


def test_the_credential_must_be_one_the_ceremony_offered_or_the_handle_must_name_its_owner():
    ws = _svc()
    auth, other = SoftAuthenticator(ES256), SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    key = _key(ws, registered)
    _register(ws, other)
    # Offered the first key, asserted with the second.
    with pytest.raises(ws.Refused) as e:
        _assert(ws, other, key)
    assert e.value.code == "credential_not_offered"
    # A discoverable sign-in (nothing offered): the user handle must be the owner.
    assert _assert(ws, auth, key, allow=[]).user_handle == USER_ID.bytes
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, allow=[], include_user_handle=False)
    assert e.value.code == "user_handle_mismatch"
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, allow=[], user_handle_override=uuid.uuid4().bytes)
    assert e.value.code == "user_handle_mismatch"
    # The right id offered, but a key record of another credential.
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, _key(ws, registered), allow=[(auth.credential_id, ())], credential_id_override=other.credential_id)
    assert e.value.code == "credential_not_offered"


def test_a_bad_signature_a_wrong_type_and_garbage_are_refused():
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    key = _key(ws, registered)
    with pytest.raises(ws.Refused) as e:
        _assert(ws, auth, key, bad_signature=True)
    assert e.value.code == "bad_signature"
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256), credential_type="foo")
    assert e.value.code == "malformed"
    rp, policy = _rp(), ws.PasskeyPolicy()
    for garbage in (None, [], {}, {"type": "public-key"}, {"type": "public-key", "rawId": "!!", "response": {}},
                    {"type": "public-key", "rawId": "YWJj", "response": "x"}):
        with pytest.raises(ws.Refused) as e:
            ws.verify_registration(rp, policy, challenge=os.urandom(32), credential=garbage)
        assert e.value.code == "malformed", garbage
        with pytest.raises(ws.Refused) as e:
            ws.verify_authentication(rp, policy, challenge=os.urandom(32), credential=garbage, key=key,
                                     allow_ids=[key.credential_id])
        assert e.value.code == "malformed", garbage


def test_a_key_already_registered_is_refused_and_the_person_s_keys_are_excluded_from_the_options():
    ws = _svc()
    auth = SoftAuthenticator(ES256)
    registered, _, _ = _register(ws, auth)
    existing = [(registered.credential_id, registered.transports)]
    with pytest.raises(ws.Refused) as e:
        _register(ws, auth, existing=existing)
    assert e.value.code == "already_registered"
    options = ws.registration_options(_rp(), ws.PasskeyPolicy(), challenge=os.urandom(32), user_id=USER_ID.bytes,
                                      username="alice", display_name=None, existing=existing)
    assert [c["id"] for c in options["publicKey"]["excludeCredentials"]] == [ws.b64url(registered.credential_id)]
    assert options["publicKey"]["user"]["displayName"] == "alice"


def test_direct_attestation_needs_trust_anchors_and_refuses_a_self_attestation_under_them():
    ws = _svc()
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256), ws.PasskeyPolicy(attestation="direct"))
    assert e.value.code == "attestation_unverifiable"
    # With an anchor the library verifies the statement; a self attestation has no chain to anchor.
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes, serialization
    from cryptography.hazmat.primitives.asymmetric import ec
    from cryptography.x509.oid import NameOID
    import datetime as dt
    ca_key = ec.generate_private_key(ec.SECP256R1())
    name = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "Test Root")])
    now = dt.datetime.now(dt.timezone.utc)
    ca = (x509.CertificateBuilder().subject_name(name).issuer_name(name).public_key(ca_key.public_key())
          .serial_number(1).not_valid_before(now - dt.timedelta(days=1)).not_valid_after(now + dt.timedelta(days=365))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_key, hashes.SHA256()))
    anchored = ws.PasskeyPolicy(attestation="direct", trust_anchors=(ca.public_bytes(serialization.Encoding.DER),))
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256), anchored, fmt="packed")
    assert e.value.code == "attestation_refused"
    with pytest.raises(ws.Refused) as e:
        _register(ws, SoftAuthenticator(ES256), anchored, fmt="none")
    assert e.value.code == "attestation_refused"
    # The authentication options carry the relying-party id, the challenge and an empty allow list by default.
    options = ws.authentication_options(_rp(), ws.PasskeyPolicy(), challenge=b"\x01" * 32)
    pk = options["publicKey"]
    assert pk["rpId"] == RP_ID and pk["allowCredentials"] == [] and pk["userVerification"] == "required"
    assert pk["challenge"] == ws.b64url(b"\x01" * 32)


def test_the_relying_party_comes_from_the_public_address(monkeypatch):
    ws = _svc()
    import app.core.config as config
    monkeypatch.setattr(config.settings, "allowed_hosts", "https://vault.example.com:8443, other.example.com",
                        raising=False)
    rp = ws.relying_party("Acme Vault")
    assert rp == ws.RelyingParty(rp_id="vault.example.com", origin="https://vault.example.com:8443", name="Acme Vault")
    # No passkey at an address reached by IP, at one sign-in cannot be built on, or with none configured.
    for no_address in ("https://10.0.0.5", "http://vault.lan:8200", "*.example.com", ""):
        monkeypatch.setattr(config.settings, "allowed_hosts", no_address, raising=False)
        assert ws.relying_party("Acme Vault") is None, no_address
