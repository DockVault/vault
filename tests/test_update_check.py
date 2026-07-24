"""Unit tests for the opt-in update-check service (app/services/update_check.py).

Loaded by file path (the module is pure stdlib — no app imports), so these run without a live
instance and never touch the real network (the fetch is monkeypatched)."""
import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location(
    "update_check_mod", ROOT / "app" / "services" / "update_check.py")
uc = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(uc)


@pytest.fixture(autouse=True)
def _reset_cache():
    uc._cache.update({"checked_at": 0.0, "latest": None, "url": None, "notes": None})
    yield


def test_is_newer_semver():
    assert uc.is_newer("v0.7.0", "0.6.0")
    assert uc.is_newer("0.6.10", "0.6.9")            # multi-digit patch, not lexical
    assert uc.is_newer("v0.7.0-rc1", "0.6.0")        # pre-release core still compares
    assert not uc.is_newer("0.6.0", "0.6.0")         # equal -> not newer
    assert not uc.is_newer("0.5.0", "0.6.0")         # older
    assert not uc.is_newer("garbage", "0.6.0")       # unparseable -> False (no false 'update')
    assert not uc.is_newer(None, "0.6.0")
    assert not uc.is_newer("0.7.0", None)


def test_default_off_makes_no_network_call(monkeypatch):
    called = {"n": 0}
    def _boom():
        called["n"] += 1
        return (None, None, None)
    monkeypatch.setattr(uc, "_fetch_latest", _boom)
    s = uc.get_update_status("0.6.0", enabled=False, managed=False)
    assert s["enabled"] is False and s["update_available"] is False
    assert called["n"] == 0, "disabled must never hit the network"


def test_managed_deployment_suppresses(monkeypatch):
    monkeypatch.setattr(uc, "_fetch_latest",
                        lambda: (_ for _ in ()).throw(AssertionError("managed must not fetch")))
    s = uc.get_update_status("0.6.0", enabled=True, managed=True)
    assert s["managed"] is True and s["update_available"] is False


def test_enabled_newer_then_current(monkeypatch):
    monkeypatch.setattr(uc, "_fetch_latest",
                        lambda: ("v0.9.0", "https://github.com/DockVault/vault/releases/tag/v0.9.0", "notes"))
    s = uc.get_update_status("0.6.0", enabled=True, managed=False, force=True)
    assert s["update_available"] is True and s["latest"] == "v0.9.0"
    uc._cache["checked_at"] = 0.0                       # simulate the force-throttle window elapsing
    monkeypatch.setattr(uc, "_fetch_latest", lambda: ("v0.6.0", "u", ""))
    s2 = uc.get_update_status("0.6.0", enabled=True, managed=False, force=True)
    assert s2["update_available"] is False


def test_configurable_interval_respected(monkeypatch):
    n = {"c": 0}
    def _fetch():
        n["c"] += 1
        return ("v0.9.0", "u", "")
    monkeypatch.setattr(uc, "_fetch_latest", _fetch)
    uc.get_update_status("0.6.0", enabled=True, managed=False, interval_seconds=900)   # empty cache -> fetch
    uc.get_update_status("0.6.0", enabled=True, managed=False, interval_seconds=900)   # within interval -> cached
    assert n["c"] == 1, "must not re-fetch within the interval"
    uc._cache["checked_at"] = 0.0                                                        # interval elapsed
    uc.get_update_status("0.6.0", enabled=True, managed=False, interval_seconds=900)   # -> re-fetch
    assert n["c"] == 2


def test_force_is_throttled(monkeypatch):
    n = {"c": 0}
    def _fetch():
        n["c"] += 1
        return ("v0.9.0", "u", "")
    monkeypatch.setattr(uc, "_fetch_latest", _fetch)
    uc.get_update_status("0.6.0", enabled=True, managed=False, force=True)   # fetch
    uc.get_update_status("0.6.0", enabled=True, managed=False, force=True)   # throttled (within FORCE_MIN_SECONDS)
    assert n["c"] == 1, "a forced check within the min window must not re-hit the network"
    uc._cache["checked_at"] = 0.0                                             # window elapsed
    uc.get_update_status("0.6.0", enabled=True, managed=False, force=True)   # -> re-fetch
    assert n["c"] == 2


def test_clamp_interval_minutes():
    assert uc.clamp_interval_minutes(5) == uc.MIN_INTERVAL_MINUTES           # below floor -> floor
    assert uc.clamp_interval_minutes(10 ** 9) == uc.MAX_INTERVAL_MINUTES     # above ceiling -> ceiling
    assert uc.clamp_interval_minutes(60) == 60                               # in range -> unchanged
    assert uc.clamp_interval_minutes("nope") == uc.DEFAULT_INTERVAL_MINUTES  # non-int -> default
    assert uc.clamp_interval_minutes(None) == uc.DEFAULT_INTERVAL_MINUTES


def test_fail_closed_silent(monkeypatch):
    # A fetch that finds nothing (offline / firewalled / rate-limited) never raises + no banner.
    monkeypatch.setattr(uc, "_fetch_latest", lambda: (None, None, None))
    s = uc.get_update_status("0.6.0", enabled=True, managed=False, force=True)
    assert s["update_available"] is False and s["latest"] is None


def test_read_capped_rejects_oversized():
    class _R:
        def __init__(self, n):
            self._d = b"x" * n
        def read(self, k):
            return self._d[:k]
    assert uc._read_capped(_R(10)) == b"x" * 10          # under the cap -> returned
    with pytest.raises(Exception):                        # over the cap -> fail-closed
        uc._read_capped(_R(uc.MAX_BODY_BYTES + 100))


def test_cache_ttl_limits_fetches(monkeypatch):
    n = {"c": 0}
    def _fetch():
        n["c"] += 1
        return ("v0.9.0", "u", "")
    monkeypatch.setattr(uc, "_fetch_latest", _fetch)
    uc.get_update_status("0.6.0", enabled=True, managed=False)   # cache empty -> fetch
    uc.get_update_status("0.6.0", enabled=True, managed=False)   # within TTL -> cached
    assert n["c"] == 1, "must not re-fetch within CACHE_TTL"
