"""A temporary credential is throttled in a bucket chosen by what the lookup finds — never, for a
KNOWN credential, the shared per-IP login bucket.

The rule under test lives in AuthService.authenticate_temporary_credential, right where it resolves
the credential row and picks a throttle:

  * a credential carrying a device_id (live or revoked) -> the device's own bucket;
  * a KNOWN credential with no device_id (a hand-out credential, or one whose device was deleted and
    its link set NULL) -> its OWN per-username login bucket, and NEVER login:<ip>;
  * an UNKNOWN username (no row) -> the IP + username login throttle, so junk stays bounded.

This is a pure unit test of that decision: it stubs the three throttle methods so calling
authenticate_temporary_credential reveals WHICH one the routing picked, with no Redis, no DB, and no
verification. The defect it guards: routing a known-but-device-less credential to the IP bucket lets a
looping client of a deleted/hand-out credential spend the owner's per-IP login budget and lock them
out. Reverting the middle branch to the IP throttle turns the middle case red.
"""
import pytest

from app.services.auth_service import AuthService

pytestmark = pytest.mark.unit


class _Routed(Exception):
    """Raised by a stubbed throttle to report which bucket the routing chose."""

    def __init__(self, which):
        self.which = which


class _Cred:
    def __init__(self, device_id):
        self.device_id = device_id


class _FakeQuery:
    def __init__(self, result):
        self._result = result

    def filter(self, *a, **k):
        return self

    def first(self):
        return self._result


class _FakeDB:
    def __init__(self, cred):
        self._cred = cred

    def query(self, *a, **k):
        return _FakeQuery(self._cred)


def _service_that_finds(cred):
    svc = AuthService.__new__(AuthService)  # bypass __init__: we only exercise the routing
    svc.db = _FakeDB(cred)

    def _throttle(name):
        def _stub(*a, **k):
            raise _Routed(name)
        return _stub

    svc._check_device_rate_limit = _throttle("device")
    svc._check_username_rate_limit = _throttle("username")
    svc._check_rate_limit = _throttle("ip")
    return svc


def _route_for(cred, *, allow_device_credential=True):
    svc = _service_that_finds(cred)
    with pytest.raises(_Routed) as exc:
        svc.authenticate_temporary_credential(
            "temp_probe", "whatever", "203.0.113.9",
            allow_device_credential=allow_device_credential)
    return exc.value.which


def test_a_device_credential_routes_to_the_device_bucket_at_the_sftp_door():
    # allow_device_credential=True is the SFTP door, where a device credential legitimately spends its
    # device bucket.
    assert _route_for(_Cred(device_id="dev-123"), allow_device_credential=True) == "device"


def test_a_device_credential_routes_to_its_username_bucket_at_the_web_door():
    # allow_device_credential=False is the WEB door, where a device credential is refused after the
    # throttle. It must NOT charge the device bucket there: otherwise its higher trip count classifies
    # a device-sync name, and wrong-password web attempts drain the device's SFTP budget. It throttles
    # in its own per-username bucket like any other known name. Reverting to the device bucket here
    # makes this read "device" and go red.
    assert _route_for(_Cred(device_id="dev-123"), allow_device_credential=False) == "username"


def test_a_known_credential_without_a_device_routes_to_its_own_username_bucket():
    # A hand-out credential, or one whose device was deleted (device_id NULL), is KNOWN and must
    # throttle in its own per-username bucket — never login:<ip>. Reverting this to the IP throttle
    # (the old behaviour) makes this assertion read "ip" and go red.
    assert _route_for(_Cred(device_id=None)) == "username"


def test_an_unknown_username_routes_to_the_ip_and_username_throttle():
    assert _route_for(None) == "ip"
