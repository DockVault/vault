"""The passkey service: WebAuthn Level 3 ceremonies behind one interface, python-fido2 behind it.

Nothing in the vault parses CBOR, COSE or an attestation statement by hand: the library does that, and it
checks the relying-party id hash, the user-presence flag, user verification when the options asked for it,
the challenge, the client data type and the signature. Its origin check is loose (any port, any subdomain),
so the vault gives it the exact origin of its public address (app/core/public_url.py). Everything the
library leaves to the relying party is checked here, in a fixed order, each refusal with its own reason for
the audit detail (the HTTP answer is one generic sentence):

* the credential id is one the ceremony offered, or (a discoverable sign-in) the user handle names its owner;
* the library's verification, against the exact origin and the relying-party id;
* user presence; user verification when the policy requires it (recorded either way);
* the algorithm is one the policy allows (registration) or the stored key's (assertion);
* the sign count moves forward, except for a synced passkey, which may not count;
* the backup-eligible flag is the one pinned at registration;
* the attestation: ``none`` stores the authenticator's identifier as a hint and trusts nothing; ``direct``
  verifies the statement against trust anchors, and refuses without them.

The routes decide what an accepted assertion is worth (app/services/sign_in.py) and store the keys; this
module knows nothing of the database.
"""
from __future__ import annotations

import base64
import uuid
from dataclasses import dataclass, field
from typing import Iterable, List, Optional, Sequence, Tuple

from fido2.attestation import AttestationVerifier, InvalidData, InvalidSignature, UnsupportedType, UntrustedAttestation
from fido2.attestation.base import InvalidAttestation
from fido2.server import Fido2Server, to_descriptor
from fido2.utils import websafe_decode, websafe_encode
from fido2.webauthn import (AttestationConveyancePreference, AttestedCredentialData, AttestationObject,
                            AuthenticatorData, PublicKeyCredentialDescriptor, PublicKeyCredentialParameters,
                            PublicKeyCredentialRpEntity, PublicKeyCredentialType, PublicKeyCredentialUserEntity,
                            ResidentKeyRequirement, UserVerificationRequirement)

ES256, RS256, EDDSA = -7, -257, -8
DEFAULT_ALGS = (ES256, RS256, EDDSA)
ALG_NAMES = {ES256: "ES256", RS256: "RS256", EDDSA: "EdDSA"}
ATTESTATION_NONE = "none"
ATTESTATION_DIRECT = "direct"
TIMEOUT_MS = 120_000
MAX_PASSKEYS_PER_ACCOUNT = 20


class Refused(Exception):
    """A ceremony the vault does not accept. ``code`` is the reason for the audit detail; the person is told
    only that the passkey was not accepted."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code


@dataclass(frozen=True)
class PasskeyPolicy:
    """What the administrator's settings say about passkeys, as the service needs it."""
    require_uv: bool = True
    allowed_algs: Tuple[int, ...] = DEFAULT_ALGS
    attestation: str = ATTESTATION_NONE
    allowed_aaguids: Tuple[str, ...] = ()        # UUID strings; only with ``direct``
    trust_anchors: Tuple[bytes, ...] = ()        # DER certificates; ``direct`` is refused without any


@dataclass(frozen=True)
class KnownKey:
    """What the service needs to know of a stored passkey to verify an assertion against it."""
    credential_id: bytes
    public_key_cose: bytes
    cose_alg: int
    sign_count: int
    backup_eligible: bool
    user_id: bytes                               # the account's id as the user handle (uuid bytes)
    transports: Tuple[str, ...] = ()


@dataclass(frozen=True)
class RegisteredKey:
    credential_id: bytes
    public_key_cose: bytes
    cose_alg: int
    sign_count: int
    transports: Tuple[str, ...]
    aaguid: Optional[uuid.UUID]
    backup_eligible: bool
    backup_state: bool
    uv_initialized: bool
    discoverable: Optional[bool]
    attestation_format: str


@dataclass(frozen=True)
class AssertionResult:
    credential_id: bytes
    user_handle: Optional[bytes]
    sign_count: int
    up: bool
    uv: bool
    be: bool
    bs: bool


@dataclass
class RelyingParty:
    """The vault as a relying party: its id and origin come from the public address, its name from the brand."""
    rp_id: str
    origin: str
    name: str


def relying_party(name: str) -> Optional[RelyingParty]:
    """The relying party for the configured public address, or None when passkeys cannot work there (no
    public host, or one reached by an IP address)."""
    from app.core.public_url import expected_origin, readiness
    ready = readiness()
    if not ready["usable"]:
        return None
    return RelyingParty(rp_id=ready["rp_id"], origin=expected_origin(), name=name or ready["rp_id"])


# --------------------------------------------------------------------------- the library, configured

class _AnchoredVerifier(AttestationVerifier):
    """Verifies an attestation statement against the operator's trust anchors. A self attestation or none
    has no chain to anchor, so it is untrusted under ``direct`` (the library would otherwise accept a
    returned anchor for an empty chain)."""

    def __init__(self, anchors: Sequence[bytes]):
        super().__init__()
        self._anchors = list(anchors)

    def ca_lookup(self, result, auth_data):
        return anchor_of(result.trust_path, self._anchors)


def anchor_of(trust_path: Sequence[bytes], anchors: Sequence[bytes], *, now=None) -> Optional[bytes]:
    """The trust anchor the statement's certificates lead to as a valid path, or None.

    ``trust_path`` is the statement's own list: the attestation certificate first, then whatever stands above
    it. The path is judged as a path, and not only by a name that matches an anchor's:

    * every certificate, the anchor too, is within its validity period;
    * every certificate above the attestation certificate is a certificate authority (basic constraints with
      ``cA`` set; where it states a key usage, signing certificates is among it), and so many authorities may
      stand below it as its path length allows;
    * each certificate is signed by the one above it, the topmost by the anchor;
    * every anchor whose name matches is tried, not only the first.

    Matched by name alone, and with only the signatures checked, any certificate under an anchor could vouch for
    an attestation certificate its holder made up: an ordinary end-entity certificate from a general-purpose
    authority in the bundle was enough to register any software key as any make of authenticator, attested and
    device-bound.

    An anchor is trusted because the operator put it in the bundle: one that carries no basic constraints (an
    old root) is taken as it is, one that carries them must say it is an authority. Which makes of authenticator
    an anchor may vouch for is not bound here: the bundle is to hold authenticator vendors' attestation roots
    and nothing else."""
    from datetime import datetime, timezone
    from cryptography import x509
    now = now or datetime.now(timezone.utc)
    try:
        path = [x509.load_der_x509_certificate(der) for der in trust_path or ()]
    except Exception:  # noqa: BLE001 -- not a certificate: no path
        return None
    if not path:
        return None

    def in_time(cert) -> bool:
        return cert.not_valid_before_utc <= now <= cert.not_valid_after_utc

    def an_authority(cert, below: int, *, required: bool) -> bool:
        """``below``: how many authorities stand between it and the attestation certificate."""
        try:
            basic = cert.extensions.get_extension_for_class(x509.BasicConstraints).value
        except x509.ExtensionNotFound:
            return not required
        except Exception:  # noqa: BLE001 -- extensions that cannot be read
            return False
        if not basic.ca or (basic.path_length is not None and basic.path_length < below):
            return False
        try:
            return bool(cert.extensions.get_extension_for_class(x509.KeyUsage).value.key_cert_sign)
        except x509.ExtensionNotFound:
            return True

    def signed_by(cert, issuer) -> bool:
        try:
            cert.verify_directly_issued_by(issuer)
        except Exception:  # noqa: BLE001 -- another name, another key, a signature that does not verify
            return False
        return True

    if not all(in_time(cert) for cert in path):
        return None
    for i in range(1, len(path)):
        if not an_authority(path[i], i - 1, required=True) or not signed_by(path[i - 1], path[i]):
            return None
    for anchor_der in anchors:
        try:
            anchor = x509.load_der_x509_certificate(anchor_der)
        except Exception:  # noqa: BLE001
            continue
        if in_time(anchor) and an_authority(anchor, len(path) - 1, required=False) and signed_by(path[-1], anchor):
            return anchor_der
    return None


def _server(rp: RelyingParty, policy: PasskeyPolicy) -> Fido2Server:
    direct = policy.attestation == ATTESTATION_DIRECT
    attestation = AttestationConveyancePreference.DIRECT if direct else AttestationConveyancePreference.NONE
    verifier = _AnchoredVerifier(policy.trust_anchors) if (direct and policy.trust_anchors) else None
    server = Fido2Server(PublicKeyCredentialRpEntity(id=rp.rp_id, name=rp.name), attestation=attestation,
                         verify_origin=lambda origin: origin == rp.origin, verify_attestation=verifier)
    server.allowed_algorithms = [PublicKeyCredentialParameters(type=PublicKeyCredentialType.PUBLIC_KEY, alg=alg)
                                 for alg in policy.allowed_algs]
    server.timeout = TIMEOUT_MS
    return server


def _uv_requirement(policy: PasskeyPolicy) -> UserVerificationRequirement:
    return UserVerificationRequirement.REQUIRED if policy.require_uv else UserVerificationRequirement.PREFERRED


def _descriptors(keys: Iterable[Tuple[bytes, Sequence[str]]]) -> List[PublicKeyCredentialDescriptor]:
    return [PublicKeyCredentialDescriptor(type=PublicKeyCredentialType.PUBLIC_KEY, id=cred_id,
                                          transports=list(transports) or None)
            for cred_id, transports in keys]


def _state(challenge: bytes, policy: PasskeyPolicy) -> dict:
    return {"challenge": websafe_encode(challenge), "user_verification": _uv_requirement(policy).value}


def _check_policy(policy: PasskeyPolicy, *, registration: bool = True) -> None:
    """A policy the service can act on. Direct attestation without anchors refuses a registration (nothing could
    verify the authenticator's statement); an assertion reads no attestation, so it is judged without that rule."""
    if policy.attestation not in (ATTESTATION_NONE, ATTESTATION_DIRECT):
        raise ValueError(f"not an attestation setting: {policy.attestation!r}")
    if registration and policy.attestation == ATTESTATION_DIRECT and not policy.trust_anchors:
        raise Refused("attestation_unverifiable", "direct attestation needs trust anchors")
    if not policy.allowed_algs:
        raise ValueError("at least one algorithm must be allowed")


# --------------------------------------------------------------------------- the ceremonies

def registration_options(rp: RelyingParty, policy: PasskeyPolicy, *, challenge: bytes, user_id: bytes,
                         username: str, display_name: Optional[str],
                         existing: Iterable[Tuple[bytes, Sequence[str]]] = ()) -> dict:
    """The options a browser gives ``PublicKeyCredential.parseCreationOptionsFromJSON``, under ``publicKey``:
    the relying party, the person, the allowed algorithms in the policy's order, a discoverable key preferred,
    user verification per policy, the attestation setting, the person's existing keys excluded, and the
    ``credProps`` extension asked for."""
    _check_policy(policy)
    server = _server(rp, policy)
    user = PublicKeyCredentialUserEntity(id=user_id, name=username, display_name=display_name or username)
    options, _ = server.register_begin(
        user, credentials=_descriptors(existing), resident_key_requirement=ResidentKeyRequirement.PREFERRED,
        user_verification=_uv_requirement(policy), challenge=challenge, extensions={"credProps": True})
    return _json(dict(options))


def verify_registration(rp: RelyingParty, policy: PasskeyPolicy, *, challenge: bytes, credential: dict,
                        existing_ids: Iterable[bytes] = ()) -> RegisteredKey:
    """Accept a browser's registration response or raise :class:`Refused` with the reason."""
    _check_policy(policy)
    if not isinstance(credential, dict) or credential.get("type") != "public-key":
        raise Refused("malformed", "not a public-key credential")
    server = _server(rp, policy)
    try:
        auth_data = server.register_complete(_state(challenge, policy), credential)
    except (UntrustedAttestation, UnsupportedType, InvalidData, InvalidSignature, InvalidAttestation) as exc:
        raise Refused("attestation_refused", type(exc).__name__) from exc
    except ValueError as exc:
        raise Refused(_reason_of(exc), str(exc)) from exc
    except (KeyError, TypeError, IndexError, AttributeError, AssertionError) as exc:
        # The library asserts the shape it expects (an attestation without the credential flag, for one).
        raise Refused("malformed", type(exc).__name__) from exc
    except Exception as exc:  # noqa: BLE001 -- see _refused_for
        raise _refused_for(exc) from exc
    _refuse_a_ceremony_in_a_frame(rp, credential)
    cred = auth_data.credential_data
    if cred is None:
        raise Refused("malformed", "no credential in the authenticator data")
    if not (16 <= len(cred.credential_id) <= 1023):
        raise Refused("malformed", "credential id outside the standard's bounds")
    flags = AuthenticatorData.FLAG(auth_data.flags)
    if not (flags & AuthenticatorData.FLAG.UP):
        raise Refused("user_not_present")
    uv = bool(flags & AuthenticatorData.FLAG.UV)
    if policy.require_uv and not uv:
        raise Refused("user_not_verified")
    _refuse_backed_up_but_not_eligible(flags)
    alg = cred.public_key.ALGORITHM
    if alg not in policy.allowed_algs:
        raise Refused("algorithm_not_allowed", ALG_NAMES.get(alg, str(alg)))
    _refuse_a_short_rsa_key(cred.public_key)
    if any(cred.credential_id == known for known in existing_ids):
        raise Refused("already_registered")
    aaguid = _aaguid(cred.aaguid)
    if policy.attestation == ATTESTATION_DIRECT and policy.allowed_aaguids:
        if aaguid is None or str(aaguid) not in {a.lower() for a in policy.allowed_aaguids}:
            raise Refused("authenticator_not_allowed")
    response = credential.get("response") or {}
    reported = response.get("transports") if isinstance(response, dict) else None
    transports = tuple(t[:16] for t in reported if isinstance(t, str) and t)[:8] if isinstance(reported, list) else ()
    extensions = credential.get("clientExtensionResults")
    props = extensions.get("credProps") if isinstance(extensions, dict) else None
    rk = props.get("rk") if isinstance(props, dict) else None
    try:
        fmt = AttestationObject(websafe_decode(response["attestationObject"])).fmt
    except Exception:  # noqa: BLE001 -- the library already parsed it; the name is for the record only
        fmt = "unknown"
    from fido2 import cbor
    return RegisteredKey(
        credential_id=cred.credential_id, public_key_cose=cbor.encode(dict(cred.public_key)), cose_alg=alg,
        sign_count=int(auth_data.counter), transports=transports, aaguid=aaguid,
        backup_eligible=bool(flags & AuthenticatorData.FLAG.BE), backup_state=bool(flags & AuthenticatorData.FLAG.BS),
        uv_initialized=uv, discoverable=rk if isinstance(rk, bool) else None, attestation_format=fmt)


def authentication_options(rp: RelyingParty, policy: PasskeyPolicy, *, challenge: bytes,
                           allow: Iterable[Tuple[bytes, Sequence[str]]] = ()) -> dict:
    """The options a browser gives ``PublicKeyCredential.parseRequestOptionsFromJSON``: the relying-party id,
    the challenge, user verification per policy, and the offered credentials (an empty list lets the browser
    offer the person's discoverable keys)."""
    _check_policy(policy, registration=False)
    server = _server(rp, policy)
    options, _ = server.authenticate_begin(credentials=_descriptors(allow), user_verification=_uv_requirement(policy),
                                           challenge=challenge)
    body = _json(dict(options))
    body["publicKey"].setdefault("allowCredentials", [])
    return body


def verify_authentication(rp: RelyingParty, policy: PasskeyPolicy, *, challenge: bytes, credential: dict,
                          key: KnownKey, allow_ids: Iterable[bytes] = ()) -> AssertionResult:
    """Accept a browser's assertion against the stored ``key`` or raise :class:`Refused` with the reason.

    ``allow_ids`` are the ids the ceremony offered; when the list is empty (a discoverable sign-in) the user
    handle must name the key's owner.
    """
    _check_policy(policy, registration=False)
    if not isinstance(credential, dict) or credential.get("type") != "public-key":
        raise Refused("malformed", "not a public-key credential")
    try:
        asserted_id = websafe_decode(credential["rawId"])
        response = credential["response"]
        raw_auth_data = websafe_decode(response["authenticatorData"])
        handle = response.get("userHandle")
        user_handle = websafe_decode(handle) if isinstance(handle, str) and handle else None
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise Refused("malformed", type(exc).__name__) from exc
    offered = list(allow_ids)
    if offered:
        if not any(asserted_id == cid for cid in offered):
            raise Refused("credential_not_offered")
    elif user_handle is None or user_handle != key.user_id:
        raise Refused("user_handle_mismatch")
    if asserted_id != key.credential_id:
        raise Refused("credential_mismatch")
    try:
        stored_key = _cose(key.public_key_cose)
        stored = AttestedCredentialData.create(b"\x00" * 16, key.credential_id, stored_key)
    except Exception as exc:  # noqa: BLE001 -- a stored key the library cannot read is a refusal, not a 500
        raise Refused("stored_key_unreadable", type(exc).__name__) from exc
    _refuse_a_short_rsa_key(stored_key)
    server = _server(rp, policy)
    try:
        server.authenticate_complete(_state(challenge, policy), [stored], credential)
    except ValueError as exc:
        raise Refused(_reason_of(exc), str(exc)) from exc
    except NotImplementedError as exc:
        raise Refused("algorithm_not_allowed", str(exc)) from exc
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise Refused("malformed", type(exc).__name__) from exc
    except Exception as exc:  # noqa: BLE001 -- see _refused_for
        raise _refused_for(exc) from exc
    _refuse_a_ceremony_in_a_frame(rp, credential)
    try:
        auth_data = AuthenticatorData(raw_auth_data)
    except Exception as exc:  # noqa: BLE001 -- the library read these bytes a moment ago; refused all the same
        raise _refused_for(exc) from exc
    flags = AuthenticatorData.FLAG(auth_data.flags)
    up, uv = bool(flags & AuthenticatorData.FLAG.UP), bool(flags & AuthenticatorData.FLAG.UV)
    be, bs = bool(flags & AuthenticatorData.FLAG.BE), bool(flags & AuthenticatorData.FLAG.BS)
    if not up:
        raise Refused("user_not_present")
    if policy.require_uv and not uv:
        raise Refused("user_not_verified")
    _refuse_backed_up_but_not_eligible(flags)
    if stored.public_key.ALGORITHM != key.cose_alg:
        raise Refused("algorithm_mismatch")
    new_count = int(auth_data.counter)
    if (key.sign_count > 0 or new_count > 0) and new_count <= key.sign_count and not key.backup_eligible:
        raise Refused("sign_count_regressed", f"{new_count} after {key.sign_count}")
    if be != key.backup_eligible:
        raise Refused("backup_flag_changed")
    return AssertionResult(credential_id=asserted_id, user_handle=user_handle, sign_count=new_count,
                           up=up, uv=uv, be=be, bs=bs)


# --------------------------------------------------------------------------- helpers

def _refuse_a_ceremony_in_a_frame(rp: RelyingParty, credential: dict) -> None:
    """The standard's step for a ceremony made inside a frame, after the library has checked the origin: the
    browser says in the client data whether the page that asked was framed by another site (``crossOrigin``), and
    which page was on top (``topOrigin``). The vault is never shown inside another site's page, so a ceremony
    that says it was, or that names a top page which is not the vault's own address, is refused.

    The library reads neither. What kept a framed prompt from ever happening was the headers every answer of the
    server carries (no framing at all); the ceremony itself took an answer made in an attacker's frame. A route
    served without those headers one day, or a proxy that drops them, would have been the only thing missing."""
    import json
    response = credential.get("response")
    try:
        data = json.loads(websafe_decode(response["clientDataJSON"]))
    except Exception as exc:  # noqa: BLE001 -- the library read it a moment ago; refused all the same
        raise _refused_for(exc) from exc
    if not isinstance(data, dict):
        raise Refused("malformed", "client data that is no object")
    # Left out by a browser that does not say, it is taken as "no". Said, only the value false is "no": 0, 0.0 and
    # null are not a browser's "no" (and compared with ==, 0 and 0.0 passed as false).
    if data.get("crossOrigin", False) is not False:
        raise Refused("cross_origin", "made in a frame of another site")
    top = data.get("topOrigin")
    if top is not None and top != rp.origin:
        raise Refused("cross_origin", "another site's page on top")


RSA_KEY_MIN_BITS = 2048             # an RSA passkey under this is refused, as a provider's signing key is


def rsa_key_bits(cose_key) -> Optional[int]:
    """The size in bits of the RSA public key ``cose_key`` holds (its modulus: member -1 of a key of type 3), or
    None for a key that is no RSA key. A key of that type whose modulus cannot be read has no bits."""
    try:
        if cose_key.get(1) != 3:
            return None
        return int.from_bytes(bytes(cose_key.get(-1)), "big").bit_length()
    except Exception:  # noqa: BLE001
        return 0


def _refuse_a_short_rsa_key(cose_key) -> None:
    """An RS256 passkey whose RSA key is shorter than :data:`RSA_KEY_MIN_BITS` is refused, when it is registered
    and at every use of one that is stored. The checks asked only whether the algorithm is allowed, and the
    library's RS256 has no floor: a badly built authenticator's 512-bit key registered and signed in, while a
    provider's key of that size verifies nothing. For a role that signs in with a passkey alone that key is the
    whole sign-in, and whoever reads a copy of the table can factor it."""
    bits = rsa_key_bits(cose_key)
    if bits is not None and bits < RSA_KEY_MIN_BITS:
        raise Refused("key_too_short", f"an RSA key of {bits} bits")


def _refuse_backed_up_but_not_eligible(flags) -> None:
    """The standard's step for the two backup flags, at a registration and at every use: a key that says it is
    backed up (BS) while it says it cannot be (BE not set) contradicts itself, and is refused as malformed.
    Whether a key may be copied to other devices is what a role held to device-bound keys is judged by, and that
    reads BE alone; a key that sets BS without it was stored as one that is backed up and is not eligible."""
    backed_up = bool(flags & AuthenticatorData.FLAG.BS)
    if backed_up and not (flags & AuthenticatorData.FLAG.BE):
        raise Refused("malformed", "backed up but not backup eligible")


def _refused_for(exc: Exception) -> Refused:
    """The refusal for whatever else a browser's answer made the parser or the verifier raise. The answer is the
    caller's bytes, so nothing in it is a failure of the server: arrays nested until the decoder's stack runs
    out (RecursionError), a length cut off (struct.error), an attestation of a kind the library does not verify
    (NotImplementedError) or a certificate it cannot read (cryptography's UnsupportedAlgorithm). Left to pass,
    each was answered as a server error: the attempt was not recorded as a refused one and not counted against
    the account or the address. An attestation that was not verified is refused as that; the rest is malformed.
    The detail is the error's class, never its text."""
    try:
        from cryptography.exceptions import UnsupportedAlgorithm
    except Exception:  # noqa: BLE001 -- without the library there is no such error to tell apart
        UnsupportedAlgorithm = ()
    not_verified = isinstance(exc, NotImplementedError) or (
        bool(UnsupportedAlgorithm) and isinstance(exc, UnsupportedAlgorithm))
    return Refused("attestation_refused" if not_verified else "malformed", type(exc).__name__)


def _reason_of(exc: ValueError) -> str:
    text = str(exc).lower()
    if "origin" in text:
        return "origin_mismatch"
    if "rp id" in text:
        return "rp_id_mismatch"
    if "challenge" in text:
        return "challenge_mismatch"
    if "user present" in text:
        return "user_not_present"
    if "user verif" in text:
        return "user_not_verified"
    if "signature" in text:
        return "bad_signature"
    if "credential id" in text or "rawid" in text:
        return "credential_mismatch"
    return "refused"


def _aaguid(raw) -> Optional[uuid.UUID]:
    try:
        value = uuid.UUID(bytes=bytes(raw))
    except (TypeError, ValueError):
        return None
    return None if value.int == 0 else value


def _cose(blob: bytes):
    """The stored COSE key (CBOR bytes) as the library's key object."""
    from fido2 import cbor
    from fido2.cose import CoseKey
    return CoseKey.parse(cbor.decode(blob))


def _json(options: dict) -> dict:
    """The library's options as plain JSON (its dataclasses serialize to the Level 3 JSON shapes)."""
    import json
    return json.loads(json.dumps(options))


def user_handle_for(user_id: uuid.UUID) -> bytes:
    return user_id.bytes


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode("ascii")
