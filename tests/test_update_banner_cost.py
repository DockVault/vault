"""The update banner says what the update would cost, not just that one exists.

An operator who reads "0.11.0 available" and presses update has no way to tell a drop-in from a
one-way schema change, and afterwards is the wrong time to find out. The check now resolves the
target's upgrade matrix and reports what the hop involves.

Everything this module already guaranteed still holds and is asserted here rather than assumed: it
never raises, a managed deployment is still suppressed, the outbound work stays inside the existing
cache and lock so a polling admin page costs one round of requests, and a matrix that cannot be
fetched degrades to the banner that existed before this.
"""

from __future__ import annotations

import importlib.util
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parents[1]


def _fresh_module():
    """A module with its own cache, so one test's fetch cannot satisfy another's."""
    spec = importlib.util.spec_from_file_location(
        "update_check_under_test", ROOT / "app" / "services" / "update_check.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def _matrix(*, backup=False, reversible=True, blocked=False, conditions=None):
    edge = {"from": "0.1.0", "to": "0.2.0", "kind": "blocked" if blocked else "direct",
            "reversible": reversible, "requires_backup": backup}
    if blocked:
        edge["reason"] = "do not"
    if conditions:
        edge["conditions"] = conditions
    return {"schema_version": 1, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
            "versions": {"0.1.0": {"released": "2026-01-01", "notes": "a"},
                         "0.2.0": {"released": "2026-01-02", "notes": "b"}},
            "edges": [edge]}


# --- what the banner learns ---------------------------------------------------------------------

def test_a_drop_in_update_is_reported_as_one():
    uc = _fresh_module()
    hop = uc.describe_hop(_matrix(), "0.1.0", "0.2.0")
    assert hop == {"known": True, "requires_backup": False, "irreversible": False,
                   "blocked": False, "conditions": [], "steps": 1, "stages": 1}


def test_an_update_that_needs_a_backup_says_so():
    uc = _fresh_module()
    hop = uc.describe_hop(_matrix(backup=True, reversible=False), "0.1.0", "0.2.0")
    assert hop["known"] and hop["requires_backup"] and hop["irreversible"]


def test_the_conditions_reach_the_banner():
    uc = _fresh_module()
    hop = uc.describe_hop(_matrix(conditions=[{"id": "x", "summary": "an index may be skipped"}]),
                          "0.1.0", "0.2.0")
    assert hop["conditions"] == ["an index may be skipped"]


@pytest.mark.parametrize("matrix, current, target", [
    (None, "0.1.0", "0.2.0"),
    ("not a matrix", "0.1.0", "0.2.0"),
    ({"versions": "wrong type"}, "0.1.0", "0.2.0"),
    (_matrix(), "0.1.0", "9.9.9"),
    (_matrix(), "9.9.9", "0.2.0"),
    ({"versions": {"0.1.0": {}, "0.2.0": {}}, "edges": []}, "0.1.0", "0.2.0"),
])
def test_anything_it_cannot_describe_is_not_called_a_drop_in(matrix, current, target):
    """Unknown means "assume the worst", never "fine".

    The banner is read by someone deciding whether to press a button; a default of safe would make
    every gap in the matrix an invitation.
    """
    uc = _fresh_module()
    hop = uc.describe_hop(matrix, current, target)
    assert not hop["known"]
    assert hop["requires_backup"] and hop["irreversible"]


def test_it_never_raises_on_junk():
    """The module's whole contract is fail-closed-silent; a new code path must not break that."""
    uc = _fresh_module()
    for junk in ([], 0, {"versions": {"x": {}}}, {"versions": {"0.1.0": {}}, "edges": "no"},
                 {"versions": {"0.1.0": {}, "bad": {}}, "edges": []}):
        assert uc.describe_hop(junk, "0.1.0", "0.2.0")["known"] is False


# --- how it behaves inside the existing check -----------------------------------------------------

def _stub_fetches(uc, monkeypatch, *, latest="0.2.0", matrix=None, calls=None):
    def fake_latest():
        if calls is not None:
            calls.append("latest")
        return latest, "https://example.invalid/r", "notes"

    def fake_matrix(tag):
        if calls is not None:
            calls.append("matrix")
        return matrix

    monkeypatch.setattr(uc, "_fetch_latest", fake_latest)
    monkeypatch.setattr(uc, "_fetch_matrix", fake_matrix)


def test_the_status_carries_what_the_update_involves(monkeypatch):
    uc = _fresh_module()
    _stub_fetches(uc, monkeypatch, matrix=_matrix(backup=True))
    status = uc.get_update_status("0.1.0", enabled=True, managed=False)
    assert status["update_available"] is True
    assert status["upgrade"]["requires_backup"] is True


def test_a_deployment_already_current_is_told_nothing_about_upgrades(monkeypatch):
    """No verdict when there is nothing on offer.

    Otherwise a current deployment would carry an "unknown, assume the worst" note about an upgrade
    nobody is being offered, which reads as a warning about the running version.
    """
    uc = _fresh_module()
    _stub_fetches(uc, monkeypatch, latest="0.1.0")
    status = uc.get_update_status("0.1.0", enabled=True, managed=False)
    assert status["update_available"] is False
    assert "upgrade" not in status


def test_an_unfetchable_matrix_degrades_to_the_old_banner(monkeypatch):
    """The failure that must not block: no matrix still means the update is announced."""
    uc = _fresh_module()
    _stub_fetches(uc, monkeypatch, matrix=None)
    status = uc.get_update_status("0.1.0", enabled=True, managed=False)
    assert status["update_available"] is True and status["latest"] == "0.2.0"
    assert status["upgrade"]["known"] is False


def test_a_matrix_fetch_that_throws_does_not_reach_the_caller(monkeypatch):
    uc = _fresh_module()

    def explode(url):
        raise RuntimeError("network on fire")

    monkeypatch.setattr(uc, "_http_json", explode)
    monkeypatch.setattr(uc, "_fetch_latest", lambda: ("0.2.0", "u", "n"))
    status = uc.get_update_status("0.1.0", enabled=True, managed=False)
    assert status["update_available"] is True
    assert status["upgrade"]["known"] is False


def test_the_matrix_rides_the_existing_cache_rather_than_adding_a_request(monkeypatch):
    """One outbound round per interval, however often the page polls.

    The cache and lock here exist to protect a rate limit. A second fetch added outside them would
    double the traffic and could exhaust it on a busy admin page.
    """
    uc = _fresh_module()
    calls = []
    _stub_fetches(uc, monkeypatch, matrix=_matrix(), calls=calls)
    for _ in range(5):
        uc.get_update_status("0.1.0", enabled=True, managed=False)
    assert calls == ["latest", "matrix"], f"expected one round of fetches, got {calls}"


def test_a_managed_deployment_is_still_suppressed(monkeypatch):
    """A centrally managed deployment upgrades by operator promote; it must not be told to press
    anything, and must not spend an outbound request finding out."""
    uc = _fresh_module()
    calls = []
    _stub_fetches(uc, monkeypatch, matrix=_matrix(), calls=calls)
    status = uc.get_update_status("0.1.0", enabled=True, managed=True)
    assert status == {"enabled": False, "managed": True, "current": "0.1.0",
                      "update_available": False}
    assert calls == [], "a managed deployment made an outbound request"


def test_disabled_stays_disabled(monkeypatch):
    uc = _fresh_module()
    calls = []
    _stub_fetches(uc, monkeypatch, matrix=_matrix(), calls=calls)
    status = uc.get_update_status("0.1.0", enabled=False, managed=False)
    assert status["update_available"] is False and calls == []


# --- the two implementations of one rule ----------------------------------------------------------

def test_the_app_and_the_host_tool_agree_about_every_hop():
    """`dockvault.py` carries its own copy of this walk, and must not drift from it.

    It cannot import this module: it is stdlib-only and runs on the host, outside the image,
    exactly so it keeps working when the app does not. Two implementations of one rule is a real
    drift risk, so rather than pretend otherwise, they are pinned equivalent here.
    """
    uc = _fresh_module()
    spec = importlib.util.spec_from_file_location("dockvault_for_parity", ROOT / "dockvault.py")
    tool = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(tool)

    backport = {
        "schema_version": 1, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
        "versions": {"0.9.0": {"released": "2026-01-01", "notes": "a"},
                     "0.9.1": {"released": "2026-03-01", "notes": "backport"},
                     "0.10.0": {"released": "2026-02-01", "notes": "b"}},
        "edges": [{"from": "0.9.0", "to": "0.10.0", "kind": "direct",
                   "reversible": True, "requires_backup": False},
                  {"from": "0.9.0", "to": "0.9.1", "kind": "direct",
                   "reversible": True, "requires_backup": False}],
    }
    staged = {
        "schema_version": 1, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
        "versions": {"0.1.0": {"released": "2026-01-01", "notes": "a"},
                     "0.2.0": {"released": "2026-01-02", "notes": "b", "must_land_here": True},
                     "0.3.0": {"released": "2026-01-03", "notes": "c"}},
        "edges": [{"from": "0.1.0", "to": "0.2.0", "kind": "direct",
                   "reversible": True, "requires_backup": True},
                  {"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                   "reversible": True, "requires_backup": False}],
    }
    three = _matrix(backup=True)
    three["versions"]["0.3.0"] = {"released": "2026-01-03", "notes": "c"}
    three["edges"].append({"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                           "reversible": False, "requires_backup": False})

    cases = [
        (_matrix(), "0.1.0", "0.2.0"),
        (_matrix(backup=True), "0.1.0", "0.2.0"),
        (_matrix(reversible=False), "0.1.0", "0.2.0"),
        (_matrix(blocked=True), "0.1.0", "0.2.0"),
        (three, "0.1.0", "0.3.0"),
        (_matrix(), "0.1.0", "9.9.9"),
        (_matrix(), "9.9.9", "0.2.0"),
        (_matrix(), "0.2.0", "0.1.0"),
        (None, "0.1.0", "0.2.0"),
        ({"versions": {"0.1.0": {}, "0.2.0": {}}, "edges": []}, "0.1.0", "0.2.0"),
        # A backport sorts between two shipped releases, so the hop it sits between has no
        # neighbour edge and only a declared one. Both implementations must find it, and must
        # agree that the backport itself leads nowhere.
        (backport, "0.9.0", "0.10.0"),
        (backport, "0.9.1", "0.10.0"),
        (backport, "0.9.0", "0.9.1"),
        # A release the upgrade has to land on: both implementations must agree how many stages
        # that makes, or the banner and the tool describe the same upgrade differently.
        (staged, "0.1.0", "0.3.0"),
        (staged, "0.1.0", "0.2.0"),
        (staged, "0.2.0", "0.3.0"),
    ]
    for matrix, current, target in cases:
        here = uc.describe_hop(matrix, current, target)
        there = tool.plan_upgrade_path(matrix, current, target)
        assert here["known"] == there["known"], (matrix, current, target)
        assert here["requires_backup"] == there["requires_backup"], (matrix, current, target)
        assert here["irreversible"] == there["irreversible"], (matrix, current, target)
        assert here["blocked"] == (there["blocked"] is not None), (matrix, current, target)
        assert here["steps"] == len(there["steps"]), (matrix, current, target)
        assert here["stages"] == len(there["legs"]), (matrix, current, target)


def test_the_banner_learns_how_many_stages_an_upgrade_runs_in():
    """So it can say the upgrade takes longer without implying more work for the operator."""
    uc = _fresh_module()
    staged = {
        "schema_version": 1, "about": "t", "kinds": {"direct": "a", "blocked": "b"},
        "versions": {"0.1.0": {"released": "2026-01-01", "notes": "a"},
                     "0.2.0": {"released": "2026-01-02", "notes": "b", "must_land_here": True},
                     "0.3.0": {"released": "2026-01-03", "notes": "c"}},
        "edges": [{"from": "0.1.0", "to": "0.2.0", "kind": "direct",
                   "reversible": True, "requires_backup": False},
                  {"from": "0.2.0", "to": "0.3.0", "kind": "direct",
                   "reversible": True, "requires_backup": False}],
    }
    assert uc.describe_hop(staged, "0.1.0", "0.3.0")["stages"] == 2
    assert uc.describe_hop(staged, "0.1.0", "0.2.0")["stages"] == 1


def test_an_ordinary_upgrade_reports_one_stage():
    """Non-vacuity: the field must not be 2 for everything."""
    uc = _fresh_module()
    assert uc.describe_hop(_matrix(), "0.1.0", "0.2.0")["stages"] == 1
