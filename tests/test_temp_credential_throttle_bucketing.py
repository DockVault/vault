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

import app.services.auth_service as A
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


@pytest.mark.parametrize("cred", [
    _Cred(device_id="dev-123"),  # device-linked
    _Cred(device_id=None),       # known, no device (hand-out / deleted device)
    None,                        # unknown name
])
def test_the_web_door_routes_every_kind_through_the_full_login_throttle(cred):
    # allow_device_credential=False is the WEB door: EVERY temp_ name goes through the full
    # login throttle (login:<temp_username> + login:<ip>). A per-kind bucket here is a status-code
    # oracle — a known name's own-bucket path never touches login:<ip> while an unknown name's IP leg
    # does, so priming login:<ip> then separates a live row (401) from a dead one (429). Routing any
    # web-door kind to a per-kind bucket makes this read "device"/"username" and go red.
    assert _route_for(cred, allow_device_credential=False) == "ip"


def test_the_sftp_door_device_credential_routes_to_the_device_bucket():
    assert _route_for(_Cred(device_id="dev-123"), allow_device_credential=True) == "device"


def test_the_sftp_door_known_credential_without_a_device_routes_to_its_username_bucket():
    # A hand-out credential, or one whose device was deleted (device_id NULL), is KNOWN and must
    # throttle in its own per-username bucket at the SFTP door — never login:<ip>. Reverting this to
    # the IP throttle lets a looping client spend the owner's IP budget — red.
    assert _route_for(_Cred(device_id=None), allow_device_credential=True) == "username"


def test_the_sftp_door_unknown_name_routes_to_the_ip_and_username_throttle():
    # An SFTP-door unknown name still hits the IP + username login throttle. A throttled refusal here
    # stays CHEAP (no verify): burning a dummy hash would invert the gap once a known name's own
    # bucket trips and would turn the limiter into an argon2 amplifier. The known-value timing oracle
    # under a primed IP is an accepted residual (see the contract comment).
    assert _route_for(None, allow_device_credential=True) == "ip"
