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
        if not result.trust_path:
            return None
        from cryptography import x509
        leaf = x509.load_der_x509_certificate(result.trust_path[-1])
        for anchor_der in self._anchors:
            anchor = x509.load_der_x509_certificate(anchor_der)
            if leaf.issuer == anchor.subject:
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


def _check_policy(policy: PasskeyPolicy) -> None:
    if policy.attestation not in (ATTESTATION_NONE, ATTESTATION_DIRECT):
        raise ValueError(f"not an attestation setting: {policy.attestation!r}")
    if policy.attestation == ATTESTATION_DIRECT and not policy.trust_anchors:
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
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise Refused("malformed", type(exc).__name__) from exc
    cred = auth_data.credential_data
    if cred is None:
        raise Refused("malformed", "no credential in the authenticator data")
    flags = AuthenticatorData.FLAG(auth_data.flags)
    if not (flags & AuthenticatorData.FLAG.UP):
        raise Refused("user_not_present")
    uv = bool(flags & AuthenticatorData.FLAG.UV)
    if policy.require_uv and not uv:
        raise Refused("user_not_verified")
    alg = cred.public_key.ALGORITHM
    if alg not in policy.allowed_algs:
        raise Refused("algorithm_not_allowed", ALG_NAMES.get(alg, str(alg)))
    if any(cred.credential_id == known for known in existing_ids):
        raise Refused("already_registered")
    aaguid = _aaguid(cred.aaguid)
    if policy.attestation == ATTESTATION_DIRECT and policy.allowed_aaguids:
        if aaguid is None or str(aaguid) not in {a.lower() for a in policy.allowed_aaguids}:
            raise Refused("authenticator_not_allowed")
    response = credential.get("response") or {}
    transports = tuple(t for t in (response.get("transports") or []) if isinstance(t, str))[:8]
    extensions = credential.get("clientExtensionResults") or {}
    rk = (extensions.get("credProps") or {}).get("rk") if isinstance(extensions, dict) else None
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
    _check_policy(policy)
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
    _check_policy(policy)
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
        stored = AttestedCredentialData.create(b"\x00" * 16, key.credential_id, _cose(key.public_key_cose))
    except Exception as exc:  # noqa: BLE001 -- a stored key the library cannot read is a refusal, not a 500
        raise Refused("stored_key_unreadable", type(exc).__name__) from exc
    server = _server(rp, policy)
    try:
        server.authenticate_complete(_state(challenge, policy), [stored], credential)
    except ValueError as exc:
        raise Refused(_reason_of(exc), str(exc)) from exc
    except NotImplementedError as exc:
        raise Refused("algorithm_not_allowed", str(exc)) from exc
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise Refused("malformed", type(exc).__name__) from exc
    auth_data = AuthenticatorData(raw_auth_data)
    flags = AuthenticatorData.FLAG(auth_data.flags)
    up, uv = bool(flags & AuthenticatorData.FLAG.UP), bool(flags & AuthenticatorData.FLAG.UV)
    be, bs = bool(flags & AuthenticatorData.FLAG.BE), bool(flags & AuthenticatorData.FLAG.BS)
    if not up:
        raise Refused("user_not_present")
    if policy.require_uv and not uv:
        raise Refused("user_not_verified")
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
