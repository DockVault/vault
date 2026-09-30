"""Unit tests for the opt-in update-check service (app/services/update_check.py).

Loaded by file path (the module is pure stdlib — no app imports), so these run without a live
instance and never touch the real network (the fetch is monkeypatched)."""
import importlib.util
import json
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


# --- release lines ---------------------------------------------------------------------------------
# The synthetic matrix of a fix released on two lines (0.33.2 and 0.34.1), with dated `lines`; the
# host tool's tests read the same file.

_TWO_LINES = ROOT / "tests" / "fixtures" / "upgrade-matrix-two-lines.json"


def _two_lines():
    return json.loads(_TWO_LINES.read_text(encoding="utf-8"))


def _tag_matrix(version):
    """What a release's own published matrix proves here: that it declares the release."""
    return {"versions": {version: {"released": "2027-01-11", "notes": version}}}


def test_an_install_on_an_older_line_is_offered_the_newest_release_of_its_line():
    update = uc.line_update("0.33.1", "v0.34.1", _two_lines(), _two_lines(),
                            {"0.33.2": _tag_matrix("0.33.2")}, today="2027-02-01")
    assert update == {"version": "0.33.2", "line": "0.33", "fixes_vulnerability": True,
                      "security_fixes_until": "2027-06-10"}


def test_there_is_no_line_update_on_the_newest_line():
    assert uc.line_update("0.34.0", "v0.34.1", _two_lines(), _two_lines(),
                          {"0.34.1": _tag_matrix("0.34.1")}) is None


def test_a_line_release_is_offered_only_once_its_own_matrix_was_fetched():
    m = _two_lines()
    assert uc.line_update("0.33.1", "v0.34.1", m, m, None) is None
    assert uc.line_update("0.33.1", "v0.34.1", m, m, {"0.33.2": None}) is None       # fetch failed
    assert uc.line_update("0.33.1", "v0.34.1", m, m, {"0.33.2": _tag_matrix("0.33.1")}) is None
    assert uc.line_update("0.33.2", "v0.34.1", m, m, {"0.33.2": _tag_matrix("0.33.2")}) is None


def test_a_line_update_that_fixes_nothing_the_install_has_says_so():
    main = _two_lines()
    main["versions"]["0.33.3"] = {"released": "2027-02-10", "notes": "0.33.3",
                                  "support": {"eol": False, "secure": True}}
    update = uc.line_update("0.33.2", "v0.34.1", _two_lines(), main, {"0.33.3": _tag_matrix("0.33.3")})
    assert update["version"] == "0.33.3" and update["fixes_vulnerability"] is False


def test_the_line_status_says_when_the_lines_security_fixes_end():
    bundled = _two_lines()
    bundled["lines"] = {"0.33": {"security_fixes_until": None}}      # as 0.33.1 shipped it
    main = _two_lines()
    assert uc.line_status("0.33.1", bundled, main, today="2027-06-10") == {
        "line": "0.33", "security_fixes_until": "2027-06-10", "ended": False}
    assert uc.line_status("0.33.1", bundled, main, today="2027-06-11")["ended"] is True
    assert uc.line_status("0.33.1", bundled, None, today="2027-06-11") == {
        "line": "0.33", "security_fixes_until": None, "ended": False}
    assert uc.line_status("0.32.6", bundled, main) is None             # no support period stated
    main["lines"]["0.33"]["security_fixes_until"] = "\x1b[2J soon"     # not a day: ignored
    assert uc.line_status("0.33.1", bundled, main)["security_fixes_until"] is None
    bundled["lines"]["0.33"]["security_fixes_until"] = "2027-06-10"
    main["lines"]["0.33"]["security_fixes_until"] = "2027-12-01"
    assert uc.line_status("0.33.1", bundled, main)["security_fixes_until"] == "2027-06-10"  # earlier


def _stub_round(monkeypatch, *, latest, calls):
    monkeypatch.setattr(uc, "_fetch_latest", lambda: (
        latest, "https://github.com/DockVault/vault/releases/tag/" + latest, ""))
    monkeypatch.setattr(uc, "fetch_main_matrix", _two_lines)
    monkeypatch.setattr(uc, "_read_bundled_matrix", _two_lines)

    def fetch_matrix(tag):
        calls.append(str(tag))
        return _tag_matrix(str(tag).lstrip("v"))
    monkeypatch.setattr(uc, "_fetch_matrix", fetch_matrix)


def test_the_line_releases_matrix_is_fetched_in_the_same_round_as_the_check(monkeypatch):
    calls = []
    _stub_round(monkeypatch, latest="v0.34.1", calls=calls)
    for _ in range(3):
        status = uc.get_update_status("0.33.1", enabled=True, managed=False)
    assert calls == ["v0.34.1", "0.33.2"], "one round of requests per interval"
    assert status["line_update"]["version"] == "0.33.2"
    assert status["line"]["line"] == "0.33"


def test_the_requests_do_not_depend_on_the_running_version(monkeypatch):
    # A request that only an install on the 0.33 line made would tell GitHub which line it runs.
    rounds = {}
    for running in ("0.33.1", "0.34.0"):
        calls = []
        _stub_round(monkeypatch, latest="v0.34.1", calls=calls)
        uc._cache.update({"checked_at": 0.0, "latest": None})
        status = uc.get_update_status(running, enabled=True, managed=False)
        rounds[running] = calls
    assert rounds["0.33.1"] == rounds["0.34.0"] == ["v0.34.1", "0.33.2"]
    assert "line_update" not in status                                  # 0.34.0 is on the newest line


def test_older_lines_are_the_ones_mains_lines_map_lists_newest_first_and_bounded():
    main = _two_lines()
    assert uc._older_line_releases(main, "v0.34.1") == ["0.33.2"]
    del main["lines"]
    assert uc._older_line_releases(main, "v0.34.1") == []                # no support periods stated
    main = _two_lines()
    for minor in range(20, 33):
        main["versions"]["0.%d.0" % minor] = {"released": "2026-01-01", "notes": "n"}
        main["lines"]["0.%d" % minor] = {"security_fixes_until": "2026-12-01"}
    assert uc._older_line_releases(main, "v0.34.1") == [
        "0.33.2", "0.32.6", "0.31.0", "0.30.0", "0.29.0"]


def test_a_malformed_lines_map_never_breaks_the_status(monkeypatch):
    calls = []
    _stub_round(monkeypatch, latest="v0.34.1", calls=calls)
    bad = _two_lines()
    bad["lines"] = ["not", "a", "map"]
    bad["versions"]["0.33.2"] = "not an entry"
    monkeypatch.setattr(uc, "fetch_main_matrix", lambda: bad)
    status = uc.get_update_status("0.33.1", enabled=True, managed=False)
    assert status["update_available"] is True and "security" in status


def test_a_short_reference_is_told_the_fix_on_its_own_line():
    m = _two_lines()
    m["versions"]["0.34.0"]["vulnerabilities"] = [{"advisory": "two-lines"}]
    assert uc._version_vulnerabilities(m, "0.34.0") == [
        {"title": "Shared link opens after its owner is locked", "fixed_in": "0.34.1"}]


def test_the_merge_counts_one_advisory_once_whatever_its_wording():
    local = [{"title": "A", "fixed_in": "0.33.2", "advisory": "x"}]
    remote = [{"title": "A, reworded", "fixed_in": "0.33.2", "advisory": "x"},
              {"title": "A", "fixed_in": "0.33.2", "advisory": "y"},
              {"title": "A", "fixed_in": "0.33.2", "advisory": None}]
    assert [v["advisory"] for v in uc._merge_vulnerabilities(local, remote)] == ["x", "y"]
