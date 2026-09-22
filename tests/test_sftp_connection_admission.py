"""Unit tests for the SFTP pre-auth connection admission (the SSH MaxStartups equivalent).

The SFTP accept loop spawns a worker thread + a paramiko Transport per accepted TCP connection, and
the auth throttles only fire once a credential is offered -- so before this gate a flood of
connections that never authenticate could exhaust threads/Transports. These tests pin the admission
logic: the total ceiling, the per-IP ceiling, that a rejected per-IP admit gives back the total slot
it briefly took, and that admit/release stay balanced (a BoundedSemaphore raises on over-release).
The second half pins the SECOND per-address cap, on authenticated sessions, and the handler wiring
that moves a connection between the two buckets.
"""
import threading

import pytest

from app.sftp.sftp_server import _ConnectionAdmission

pytestmark = pytest.mark.unit


def test_total_ceiling_admits_then_refuses_then_frees_on_release():
    adm = _ConnectionAdmission(max_total=2, max_per_ip=0)
    assert adm.admit("1.1.1.1") is True
    assert adm.admit("2.2.2.2") is True
    # Third connection (any IP) is over the total ceiling.
    assert adm.admit("3.3.3.3") is False
    # Releasing one frees exactly one slot.
    adm.release("1.1.1.1")
    assert adm.admit("3.3.3.3") is True
    assert adm.admit("4.4.4.4") is False


def test_per_ip_ceiling_is_isolated_per_source():
    adm = _ConnectionAdmission(max_total=0, max_per_ip=2)
    assert adm.admit("10.0.0.1") is True
    assert adm.admit("10.0.0.1") is True
    # A third from the SAME ip is refused...
    assert adm.admit("10.0.0.1") is False
    # ...but a different ip is unaffected.
    assert adm.admit("10.0.0.2") is True
    # Releasing one for the capped ip lets it back in.
    adm.release("10.0.0.1")
    assert adm.admit("10.0.0.1") is True


def test_per_ip_reject_returns_the_total_slot():
    # A per-IP rejection must not consume a total slot -- otherwise a single abuser hammering one IP
    # would drain the global semaphore and lock everyone out.
    adm = _ConnectionAdmission(max_total=5, max_per_ip=1)
    assert adm.admit("9.9.9.9") is True          # ip at its cap; one total slot taken
    for _ in range(10):
        assert adm.admit("9.9.9.9") is False     # each rejected, and each must give the total back
    # All four remaining total slots are still available to other IPs.
    assert [adm.admit(f"8.8.8.{i}") for i in range(4)] == [True, True, True, True]
    assert adm.admit("8.8.8.99") is False        # now the total (5) is exhausted


def test_zero_limits_disable_admission():
    adm = _ConnectionAdmission(max_total=0, max_per_ip=0)
    assert all(adm.admit("1.2.3.4") for _ in range(1000))


def test_release_never_over_releases_across_cycles():
    # A BoundedSemaphore raises ValueError if released more than acquired; drive many admit/release
    # cycles and a couple of interleavings to prove the counting stays balanced.
    adm = _ConnectionAdmission(max_total=3, max_per_ip=2)
    for _ in range(200):
        assert adm.admit("7.7.7.7") is True
        adm.release("7.7.7.7")
    a = adm.admit("7.7.7.7"); b = adm.admit("7.7.7.7")
    assert a and b
    adm.release("7.7.7.7"); adm.release("7.7.7.7")
    # Back to empty: full capacity available again, and the per-IP map cleaned up.
    assert adm.admit("7.7.7.7") and adm.admit("7.7.7.7")


def test_concurrent_admits_respect_the_total_ceiling():
    adm = _ConnectionAdmission(max_total=8, max_per_ip=0)
    granted = []
    lock = threading.Lock()

    def worker(i):
        ok = adm.admit(f"5.5.5.{i}")
        with lock:
            granted.append(ok)

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(50)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    # Exactly the ceiling is granted, no more, no fewer -- the semaphore is the source of truth.
    assert sum(1 for g in granted if g) == 8


# --- the second per-address cap: authenticated sessions -------------------------------------------
#
# The pre-auth cap above is sized against a flood (small). A fleet of devices behind one NAT all
# authenticate from ONE address, so a single per-address cap sized for the flood turned the tenth
# device away. Authenticating moves a connection out of the pre-auth count and into a separate
# authenticated count with its own, larger cap; release() returns the slot to whichever bucket the
# connection was in.


def test_authenticating_frees_the_pre_auth_slot_for_the_next_handshake_from_that_address():
    adm = _ConnectionAdmission(max_total=0, max_per_ip=1, max_authenticated_per_ip=0)
    assert adm.admit("10.0.0.1") is True
    assert adm.admit("10.0.0.1") is False           # the one pre-auth slot is held by the handshake
    assert adm.authenticated("10.0.0.1") is True    # ...until it authenticates
    assert adm.admit("10.0.0.1") is True            # the next device's handshake gets in
    assert adm.authenticated("10.0.0.1") is True
    # The fleet: many authenticated sessions from one address, through a pre-auth cap of ONE.
    for _ in range(60):
        assert adm.admit("10.0.0.1") is True
        assert adm.authenticated("10.0.0.1") is True


def test_the_authenticated_cap_is_its_own_number_and_refuses_at_its_own_ceiling():
    adm = _ConnectionAdmission(max_total=0, max_per_ip=1, max_authenticated_per_ip=2)
    for _ in range(2):
        assert adm.admit("10.0.0.1") is True
        assert adm.authenticated("10.0.0.1") is True
    assert adm.admit("10.0.0.1") is True            # a third handshake is admitted (pre-auth cap is 1, and free)
    assert adm.authenticated("10.0.0.1") is False   # ...but the address holds its share of sessions
    # A refused transition leaves the connection where it was: in the pre-auth bucket, which is
    # therefore still full for this address until the caller closes it and releases.
    assert adm.admit("10.0.0.1") is False
    adm.release("10.0.0.1", authenticated=False)
    assert adm.admit("10.0.0.1") is True
    # Another address is unaffected by the first one's sessions.
    assert adm.admit("10.0.0.2") is True
    assert adm.authenticated("10.0.0.2") is True


def test_release_returns_the_slot_to_the_bucket_the_connection_was_in():
    ip = "10.0.0.1"
    adm = _ConnectionAdmission(max_total=0, max_per_ip=1, max_authenticated_per_ip=1)
    assert adm.admit(ip) and adm.authenticated(ip)      # A: a session; pre-auth empty
    assert adm.admit(ip) is True                         # B: a handshake in flight
    assert adm.authenticated(ip) is False                # B is over the session cap (A holds it)
    # Releasing the SESSION frees the session cap and not the pre-auth slot...
    adm.release(ip, authenticated=True)                  # A ends
    assert adm.admit(ip) is False                        # ...B's handshake still holds that
    assert adm.authenticated(ip) is True                 # ...and B now gets its session
    # Releasing a PRE-AUTH connection frees the pre-auth slot and not a session.
    assert adm.admit(ip) is True                         # C: a handshake
    adm.release(ip, authenticated=False)                 # C dropped before authenticating
    assert adm.admit(ip) is True                         # D gets the pre-auth slot C gave back...
    assert adm.authenticated(ip) is False                # ...but no session: B's is still counted
    adm.release(ip, authenticated=True)                  # B ends
    assert adm.authenticated(ip) is True                 # D gets it


def test_a_session_still_holds_its_total_slot_until_it_ends():
    # The two per-address buckets share the ONE total ceiling: authenticating does not give the
    # total slot back (the thread and transport are still live), only release() does.
    adm = _ConnectionAdmission(max_total=2, max_per_ip=0, max_authenticated_per_ip=0)
    assert adm.admit("1.1.1.1") and adm.authenticated("1.1.1.1")
    assert adm.admit("2.2.2.2") and adm.authenticated("2.2.2.2")
    assert adm.admit("3.3.3.3") is False
    adm.release("1.1.1.1", authenticated=True)
    assert adm.admit("3.3.3.3") is True


def test_a_zero_authenticated_cap_disables_only_that_limit():
    adm = _ConnectionAdmission(max_total=0, max_per_ip=1, max_authenticated_per_ip=0)
    for _ in range(1000):
        assert adm.admit("1.2.3.4") and adm.authenticated("1.2.3.4")
    assert adm.admit("1.2.3.4") is True
    assert adm.admit("1.2.3.4") is False            # the pre-auth cap is still in force


def test_the_defaults_are_the_documented_ones_and_the_session_cap_sits_within_the_total():
    # The settings the live instance is built from: pre-auth 10 (a flood), authenticated 50 (a fleet
    # behind one NAT), total 100 -- a per-address session cap above the total would be a dead letter.
    from app.core.config import Settings
    fields = Settings.model_fields
    assert fields["sftp_max_connections_per_ip"].default == 10
    assert fields["sftp_max_authenticated_per_ip"].default == 50
    assert fields["sftp_max_connections"].default == 100
    assert fields["sftp_max_authenticated_per_ip"].default <= fields["sftp_max_connections"].default
    # And the number is sized against the device caps it is documented against, not a bare literal:
    # one account may hold max_devices_per_user x max_device_sync_creds_per_device credentials.
    fleet = fields["max_devices_per_user"].default * fields["max_device_sync_creds_per_device"].default
    assert fleet == 100
    assert fields["sftp_max_authenticated_per_ip"].default == fleet // 2


def test_the_handler_moves_an_authenticated_connection_over_and_releases_the_right_bucket():
    # Wiring, in the handler source: the transition happens once the channel is open (auth done),
    # a refusal closes the connection, and the finally releases whichever bucket the connection
    # ended up in -- a handler that released the pre-auth bucket for every connection would let
    # the session count grow forever (and the pre-auth count go negative).
    from pathlib import Path
    src = Path(__file__).resolve().parents[1].joinpath("app", "sftp", "sftp_server.py").read_text(encoding="utf-8")
    body = src[src.index("def handle_sftp_client("):src.index("\nif __name__ == '__main__':")]
    assert "_slot_authenticated = False" in body
    chan = body.index("channel = transport.accept(20)")
    move = body.index("if not _connection_admission.authenticated(client_address[0]):")
    assert chan < move, "the transition must wait for authentication"
    assert body[move:move + 200].count("return") == 1, "a refused transition closes the connection"
    assert "_slot_authenticated = True" in body[move:move + 300]
    fin = body[body.index("    finally:"):]
    assert "_connection_admission.release(client_address[0], authenticated=_slot_authenticated)" in fin
    assert "_connection_admission.release(client_address[0])\n" not in body
    # The live instance is built with all three caps.
    assert ("_ConnectionAdmission(\n    settings.sftp_max_connections, settings.sftp_max_connections_per_ip,\n"
            "    settings.sftp_max_authenticated_per_ip)") in src


def test_the_tool_and_the_env_example_carry_the_new_setting():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    tool = root.joinpath("dockvault.py").read_text(encoding="utf-8")
    assert '("sftp_max_authenticated_per_ip", "SFTP_MAX_AUTHENTICATED_PER_IP", 50)' in tool
    assert '"sftp_max_authenticated_per_ip": (current_env.get("SFTP_MAX_AUTHENTICATED_PER_IP")' in tool
    env = root.joinpath(".env.example").read_text(encoding="utf-8")
    assert "\nSFTP_MAX_AUTHENTICATED_PER_IP=50\n" in env
