"""Unit tests for the SFTP pre-auth connection admission (the SSH MaxStartups equivalent).

The SFTP accept loop spawns a worker thread + a paramiko Transport per accepted TCP connection, and
the auth throttles only fire once a credential is offered -- so before this gate a flood of
connections that never authenticate could exhaust threads/Transports. These tests pin the admission
logic: the total ceiling, the per-IP ceiling, that a rejected per-IP admit gives back the total slot
it briefly took, and that admit/release stay balanced (a BoundedSemaphore raises on over-release).
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
