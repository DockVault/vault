"""The rules for which vault types can be made (app/core/zero_knowledge_rules.py), one by one, offline.

test_zk_force_follows_the_plan.py holds every mix of them against the server's create check, and
test_zero_knowledge_settings_save.py what a settings save may change; this file names each rule on its own.
"""
from types import SimpleNamespace

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import zero_knowledge_rules as R  # noqa: E402
from app.core.config import settings  # noqa: E402

pytestmark = pytest.mark.unit

BOTH = {"standard", "zero_knowledge"}
ZK_ONLY = {"zero_knowledge"}
STANDARD_ONLY = {"standard"}


@pytest.fixture(autouse=True)
def plan(monkeypatch):
    def set_plan(zk=True, force=False, cap=-1):
        monkeypatch.setattr(settings, "plan_zero_knowledge", zk)
        monkeypatch.setattr(settings, "plan_force_zero_knowledge", force)
        monkeypatch.setattr(settings, "plan_max_zk_vaults", cap)
    set_plan()
    return set_plan


@pytest.mark.parametrize("zk, cap, offers", [(True, -1, True), (True, 2, True), (True, None, True),
                                             (True, 0, False), (False, -1, False), (False, 2, False)])
def test_the_plan_offers_zero_knowledge_with_a_cap_that_is_not_zero(plan, zk, cap, offers):
    plan(zk=zk, cap=cap)
    assert R.plan_offers() is offers
    plan(zk=zk, cap=cap, force=True)
    assert R.plan_forces() is offers


@pytest.mark.parametrize("raw, offers, expected", [
    ("", True, BOTH), ("bogus", True, BOTH), ("standard", True, STANDARD_ONLY), (" Zero_Knowledge ", True, ZK_ONLY),
    ("standard,zero_knowledge", True, BOTH), ("zero_knowledge", False, BOTH), ("standard", False, STANDARD_ONLY),
])
def test_the_allowed_types_never_leave_nothing(plan, raw, offers, expected):
    plan(zk=offers)
    assert R.allowed_types(raw, BOTH) == expected


@pytest.mark.parametrize("stored, on", [({}, True), ({"zero_knowledge_enabled": None}, True),
                                        ({"zero_knowledge_enabled": True}, True),
                                        ({"zero_knowledge_enabled": False}, False)])
def test_the_zero_knowledge_switch_never_saved_counts_as_on(stored, on):
    assert R.switch_on(stored) is on
    assert R.force_on(stored) is False and R.force_on({"force_zero_knowledge": True}) is True


@pytest.mark.parametrize("plan_args, stored, allowed, expected", [
    ({}, {}, BOTH, True),
    ({}, {"zero_knowledge_enabled": False}, BOTH, False),
    ({}, {"zero_knowledge_enabled": False}, ZK_ONLY, True),            # the off switch would leave nothing
    ({"force": True}, {"zero_knowledge_enabled": False}, BOTH, True),   # the plan's force
    ({"cap": 0}, {"zero_knowledge_enabled": True}, BOTH, False),       # a cap of 0 is no zero-knowledge
    ({"zk": False}, {"zero_knowledge_enabled": True}, BOTH, False),
])
def test_when_zero_knowledge_vaults_may_be_made(plan, plan_args, stored, allowed, expected):
    plan(**plan_args)
    assert R.enabled(stored, allowed) is expected


@pytest.mark.parametrize("plan_args, stored, holds", [
    ({}, {"force_zero_knowledge": True}, True),                                # the switch never saved: on
    ({}, {"force_zero_knowledge": True, "zero_knowledge_enabled": True}, True),
    ({}, {"force_zero_knowledge": True, "zero_knowledge_enabled": False}, False),
    ({}, {"zero_knowledge_enabled": True}, False),
    ({"cap": 0}, {"force_zero_knowledge": True, "zero_knowledge_enabled": True}, False),
    ({"zk": False}, {"force_zero_knowledge": True, "zero_knowledge_enabled": True}, False),
])
def test_when_the_administrators_force_holds(plan, plan_args, stored, holds):
    plan(**plan_args)
    assert R.admin_force_holds(stored) is holds


@pytest.mark.parametrize("plan_args, stored, allowed, expected", [
    ({}, {}, BOTH, False),
    ({}, {"force_zero_knowledge": True}, BOTH, True),
    ({}, {"force_zero_knowledge": True}, STANDARD_ONLY, False),
    ({}, {}, ZK_ONLY, True),
    ({"force": True}, {}, BOTH, True),
    ({"force": True, "cap": 0}, {"force_zero_knowledge": True}, BOTH, False),
])
def test_what_the_force_is_in_effect_for_someone_in_no_department(plan, plan_args, stored, allowed, expected):
    plan(**plan_args)
    assert R.force_in_effect(stored, allowed) is expected


@pytest.mark.parametrize("plan_args, allowed, reason", [
    ({}, BOTH, None),
    ({"cap": 2}, BOTH, None),                                                  # a cap with room is no lock
    ({"zk": False}, BOTH, "This deployment's plan does not include zero-knowledge vaults."),
    ({"cap": 0}, BOTH, "This deployment's plan allows no zero-knowledge vaults."),
    ({"force": True}, BOTH, "This deployment's plan requires zero-knowledge vaults."),
    ({}, ZK_ONLY, "This deployment allows only zero-knowledge vaults, so they cannot be turned off."),
    ({}, STANDARD_ONLY, "This deployment does not allow zero-knowledge vaults."),
])
def test_why_the_switches_are_locked(plan, plan_args, allowed, reason):
    plan(**plan_args)
    assert R.switch_lock(allowed) == reason


def test_a_save_of_a_locked_switch_keeps_it_as_saved(plan):
    plan(zk=False)
    stored = {"zero_knowledge_enabled": True}
    payload = {"zero_knowledge_enabled": True, "force_zero_knowledge": False, "other": 1}
    assert R.settle_switches(payload, stored, BOTH) == {"other": 1}     # equal: taken out, nothing changes
    assert payload == {"zero_knowledge_enabled": True, "force_zero_knowledge": False, "other": 1}
    for change in ({"zero_knowledge_enabled": False}, {"force_zero_knowledge": True}):
        with pytest.raises(ValueError, match="cannot be changed now: This deployment's plan does not include"):
            R.settle_switches(change, stored, BOTH)
    plan(zk=True)
    assert R.settle_switches({"zero_knowledge_enabled": False}, stored, BOTH) == {"zero_knowledge_enabled": False}


def test_the_server_reads_zero_knowledge_off_where_the_plan_offers_none_even_when_the_store_fails(plan):
    """Where the settings cannot be read, zero-knowledge follows the plan: on where it is offered (the
    confidentiality-safe direction), off where the plan lacks it or its cap is 0."""
    from app.api import api_server as api

    class _Broken:
        def query(self, *_a):
            raise RuntimeError("the store is out of reach")

    assert api._zk_enabled(_Broken()) is True
    plan(force=True)
    assert api._zk_enabled(_Broken()) is True
    for args in ({"zk": False}, {"cap": 0}, {"zk": False, "force": True}, {"cap": 0, "force": True}):
        plan(**args)
        assert api._zk_enabled(_Broken()) is False, args
        assert api._user_must_use_zk(_Broken(), SimpleNamespace(id=None)) is False, args
