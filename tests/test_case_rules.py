"""The rules of a compliance case (app/core/case_rules.py), offline: every status and step, the clocks to the
second, the limits, what a scope covers and whom it concerns, narrowing, the password rule and the suspension
that COMPLIANCE_ACCESS=disabled means."""
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import case_rules as r  # noqa: E402
from app.core import compliance_settings as cs  # noqa: E402

pytestmark = pytest.mark.unit

T0 = datetime(2026, 11, 2, 10, 0, 0)
SECOND = timedelta(seconds=1)


# --------------------------------------------------------------------------- statuses and steps

# Every (status, step) a case may take, and where it leads; every other pair is refused.
ALLOWED = {
    (r.PENDING, r.APPROVE): r.ACTIVE,
    (r.PENDING, r.REJECT): r.REJECTED,
    (r.PENDING, r.WITHDRAW): r.WITHDRAWN,
    (r.PENDING, r.EXPIRE_UNAPPROVED): r.EXPIRED_UNAPPROVED,
    (r.PENDING, r.NARROW): r.PENDING,
    (r.ACTIVE, r.EXTEND): r.ACTIVE,
    (r.ACTIVE, r.END_ACCESS): r.CLOSED,
    (r.ACTIVE, r.CLOSE): r.CLOSED,
    (r.ACTIVE, r.NARROW): r.ACTIVE,
    (r.ACTIVE, r.OBJECTION): r.ACTIVE,
    (r.ACTIVE, r.SUSPEND): r.SUSPENDED,
    (r.SUSPENDED, r.RESUME): r.ACTIVE,
    (r.SUSPENDED, r.END_ACCESS): r.CLOSED,
    (r.SUSPENDED, r.CLOSE): r.CLOSED,
    (r.SUSPENDED, r.NARROW): r.SUSPENDED,
    (r.SUSPENDED, r.OBJECTION): r.SUSPENDED,
    (r.HOLD_ONLY, r.CLOSE): r.CLOSED,
    (r.HOLD_ONLY, r.OBJECTION): r.HOLD_ONLY,
    (r.CLOSED, r.OBJECTION): r.CLOSED,
}


@pytest.mark.parametrize("status", r.STATUSES)
@pytest.mark.parametrize("step", r.STEPS)
def test_every_status_and_step(status, step):
    expected = ALLOWED.get((status, step))
    assert r.next_status(status, step) == expected
    assert r.step_refusal(status, step) == (None if expected is not None else r.NOT_NOW)


def test_the_table_is_exactly_the_allowed_steps():
    assert r.TRANSITIONS == ALLOWED


@pytest.mark.parametrize("status", [r.ACTIVE, r.SUSPENDED])
def test_access_that_ends_while_a_hold_stands_keeps_the_hold(status):
    assert r.next_status(status, r.END_ACCESS, hold_stands=True) == r.HOLD_ONLY
    assert r.next_status(status, r.END_ACCESS, hold_stands=False) == r.CLOSED


def test_a_standing_hold_changes_no_other_step():
    for (status, step), after in ALLOWED.items():
        if step != r.END_ACCESS:
            assert r.next_status(status, step, hold_stands=True) == after


@pytest.mark.parametrize("status", r.FINAL)
def test_nothing_follows_a_final_status_but_an_objection_on_a_closed_case(status):
    for step in r.STEPS:
        after = r.next_status(status, step)
        assert after is None or (status, step) == (r.CLOSED, r.OBJECTION)


def test_the_open_and_final_statuses():
    assert set(r.OPEN) == {r.PENDING, r.ACTIVE, r.SUSPENDED}
    assert set(r.FINAL) == {r.CLOSED, r.REJECTED, r.WITHDRAWN, r.EXPIRED_UNAPPROVED}
    assert not set(r.OPEN) & set(r.FINAL)
    assert r.HOLD_ONLY not in r.OPEN and r.HOLD_ONLY not in r.FINAL


# --------------------------------------------------------------------------- clocks

def test_a_pending_case_expires_seven_days_after_its_request_to_the_second():
    assert r.PENDING_DAYS == 7
    assert r.pending_until(T0) == T0 + timedelta(days=7)
    assert not r.pending_expired(T0, T0 + timedelta(days=7) - SECOND)
    assert r.pending_expired(T0, T0 + timedelta(days=7))
    assert r.pending_expired(T0, T0 + timedelta(days=8))


def test_access_starts_at_the_approval_and_lasts_the_days_asked():
    assert r.DEFAULT_ACCESS_DAYS == 14
    assert r.access_window(T0, 14) == (T0, T0 + timedelta(days=14))
    assert r.access_window(T0, 30) == (T0, T0 + timedelta(days=30))


def test_access_is_open_from_its_start_to_the_second_before_its_end():
    start, end = r.access_window(T0, 14)
    assert not r.access_open(start, end, T0 - SECOND)
    assert r.access_open(start, end, T0)
    assert r.access_open(start, end, end - SECOND)
    assert not r.access_open(start, end, end)
    assert not r.access_open(None, end, T0)
    assert not r.access_open(start, None, T0)


@pytest.mark.parametrize("days,maximum,why", [
    (1, 30, None), (14, 30, None), (30, 30, None), (31, 30, r.TOO_LONG), (0, 30, r.BAD_DAYS),
    (-1, 30, r.BAD_DAYS), (True, 30, r.BAD_DAYS), ("14", 30, r.BAD_DAYS), (None, 30, r.BAD_DAYS),
    (8, 7, r.TOO_LONG), (7, 7, None)])
def test_the_access_period_asked_for(days, maximum, why):
    assert r.access_days_refusal(days, maximum) == why


def test_an_extension_adds_a_period_to_the_current_end():
    start, end = r.access_window(T0, 14)
    new_end, total = r.extension(start, end, 14, now=T0 + timedelta(days=13), max_access_days=30,
                                 max_total_days=90)
    assert new_end == T0 + timedelta(days=28) and total == 28


def test_an_extension_reaches_the_total_exactly_and_never_past_it():
    start, end = r.access_window(T0, 30)
    end, total = r.extension(start, end, 30, now=T0 + timedelta(days=29), max_access_days=30, max_total_days=90)
    assert total == 60
    end, total = r.extension(start, end, 30, now=T0 + timedelta(days=59), max_access_days=30, max_total_days=90)
    assert total == 90 and end == T0 + timedelta(days=90)
    with pytest.raises(r.CaseRuleRefused) as refused:
        r.extension(start, end, 1, now=T0 + timedelta(days=89), max_access_days=30, max_total_days=90)
    assert refused.value.reason == r.TOO_LONG


def test_an_extension_one_day_over_the_total_is_refused():
    start, end = r.access_window(T0, 14)
    with pytest.raises(r.CaseRuleRefused) as refused:
        r.extension(start, end, 7, now=T0, max_access_days=30, max_total_days=20)
    assert refused.value.reason == r.TOO_LONG
    assert r.extension(start, end, 6, now=T0, max_access_days=30, max_total_days=20)[1] == 20


def test_an_extension_longer_than_one_period_is_refused():
    start, end = r.access_window(T0, 14)
    with pytest.raises(r.CaseRuleRefused) as refused:
        r.extension(start, end, 31, now=T0, max_access_days=30, max_total_days=90)
    assert refused.value.reason == r.TOO_LONG


def test_no_extension_once_access_has_ended():
    start, end = r.access_window(T0, 14)
    assert r.extension(start, end, 1, now=end - SECOND, max_access_days=30, max_total_days=90)[0] \
        == end + timedelta(days=1)
    with pytest.raises(r.CaseRuleRefused) as refused:
        r.extension(start, end, 1, now=end, max_access_days=30, max_total_days=90)
    assert refused.value.reason == r.ACCESS_ENDED


def test_total_days_counts_a_part_of_a_day_as_a_day():
    assert r.total_days(T0, T0 + timedelta(days=14)) == 14
    assert r.total_days(T0, T0 + timedelta(days=14, seconds=1)) == 15
    assert r.total_days(T0, T0) == 0


# --------------------------------------------------------------------------- limits

def test_five_open_cases_per_auditor():
    assert r.MAX_OPEN_CASES == 5
    assert r.open_cases_refusal(4) is None
    assert r.open_cases_refusal(5) == r.TOO_MANY_CASES
    assert r.open_cases_refusal(6) == r.TOO_MANY_CASES


def test_vaults_per_case():
    assert r.vault_count_refusal(0, 25) == r.NO_VAULTS
    assert r.vault_count_refusal(1, 25) is None
    assert r.vault_count_refusal(25, 25) is None
    assert r.vault_count_refusal(26, 25) == r.TOO_MANY_VAULTS


# --------------------------------------------------------------------------- the request's text

GOOD = dict(purpose="internal_investigation", legal_basis="legal_obligation", lia_reference=None,
            justification="Suspected exfiltration of client records, ticket SEC-2041.",
            owner_note="Your vaults are part of an internal review.")


def test_good_text_has_no_problem():
    assert r.text_problems(**GOOD) == []


@pytest.mark.parametrize("change,problems", [
    (dict(purpose="curiosity"), [r.BAD_PURPOSE]),
    (dict(legal_basis="consent"), [r.BAD_BASIS]),
    (dict(legal_basis="legitimate_interests"), [r.NO_LIA_REFERENCE]),
    (dict(legal_basis="legitimate_interests", lia_reference="  "), [r.NO_LIA_REFERENCE]),
    (dict(legal_basis="legitimate_interests", lia_reference="LIA-7"), []),
    (dict(justification="x" * 29), [r.SHORT_JUSTIFICATION]),
    (dict(justification="  " + "x" * 29 + "  "), [r.SHORT_JUSTIFICATION]),
    (dict(justification="x" * 30), []),
    (dict(owner_note="   "), [r.NO_OWNER_NOTE]),
    (dict(special_category=True), [r.NO_ART9_CONDITION]),
    (dict(special_category=True, art9_condition="consent"), [r.BAD_ART9_CONDITION]),
    (dict(special_category=True, art9_condition="legal_claims"), []),
    (dict(art9_condition="consent"), [r.BAD_ART9_CONDITION]),
    (dict(purpose="x", legal_basis="y", justification="", owner_note=""),
     [r.BAD_PURPOSE, r.BAD_BASIS, r.SHORT_JUSTIFICATION, r.NO_OWNER_NOTE]),
])
def test_text_problems(change, problems):
    assert r.text_problems(**{**GOOD, **change}) == problems


def test_explicit_consent_is_not_a_condition_offered():
    assert len(r.ART9_CONDITIONS) == 9 and "consent" not in r.ART9_CONDITIONS
    assert "consent" not in r.LEGAL_BASES


def test_legal_holds_use_the_same_lists():
    from app.core import legal_holds
    assert legal_holds.PURPOSES is r.PURPOSES and legal_holds.LEGAL_BASES is r.LEGAL_BASES
    assert legal_holds.JUSTIFICATION_MIN == r.JUSTIFICATION_MIN
    with pytest.raises(legal_holds.HoldRefused) as refused:
        legal_holds.check_case_text("internal_investigation", "legal_obligation", None, "x" * 29, "note")
    assert refused.value.reason == r.SHORT_JUSTIFICATION and refused.value.code == 422


def test_a_hold_starts_with_a_case_by_default_for_four_purposes():
    assert {p for p in r.PURPOSES if r.hold_by_default(p)} == {
        "internal_investigation", "litigation_hold", "regulator_request", "security_incident"}


def test_the_range_of_files():
    assert r.range_refusal(T0, T0) is None
    assert r.range_refusal(T0, T0 - SECOND) == r.BAD_RANGE
    assert r.range_refusal(None, T0) is None and r.range_refusal(T0, None) is None


# --------------------------------------------------------------------------- scope

A, B = uuid.uuid4(), uuid.uuid4()           # people
V1, V2, V3 = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()
FA, FB, FC = uuid.uuid4(), uuid.uuid4(), uuid.uuid4()   # folders; FB is inside FA, both in V1; FC in V2

VAULTS = {V1: r.VaultFacts(V1, A), V2: r.VaultFacts(V2, A, "zero_knowledge"), V3: r.VaultFacts(V3, B, has_password=True)}
FOLDER_VAULT = {FA: V1, FB: V1, FC: V2}
PARENT = {FA: None, FB: FA, FC: None}


def _ancestry(folder):
    chain, cur = [], PARENT.get(folder)
    while cur is not None:
        chain.append(cur)
        cur = PARENT.get(cur)
    return chain


def _resolve(raw):
    return r.resolve_scope(r.parse_scope(raw), vault=VAULTS.get, folder_vault=FOLDER_VAULT.get,
                           owned_by=lambda p: [f for f in VAULTS.values() if f.owner_id == p],
                           person_exists=lambda p: p in (A, B))


def _refusal(raw):
    with pytest.raises(r.CaseRuleRefused) as refused:
        _resolve(raw)
    return refused.value.reason


def test_a_vault_is_covered_whole():
    out = _resolve([{"kind": "vault", "target_id": str(V1)}])
    assert out.vaults == {V1: None} and out.owners() == {V1: A} and out.custodians == []


def test_folders_of_one_vault_add_up_and_a_whole_vault_wins():
    out = _resolve([{"kind": "folder", "target_id": FA}, {"kind": "folder", "target_id": FB}])
    assert out.vaults == {V1: frozenset({FA, FB})}
    out = _resolve([{"kind": "folder", "target_id": FA}, {"kind": "vault", "target_id": V1},
                    {"kind": "folder", "target_id": FB}])
    assert out.vaults == {V1: None}


def test_a_custodian_resolves_to_the_vaults_they_own_now():
    out = _resolve([{"kind": "custodian", "target_id": A}])
    assert out.vaults == {V1: None, V2: None} and out.custodians == [A]


def test_a_custodian_with_no_vault_is_still_listed():
    out = r.resolve_scope([r.ScopeItem("custodian", B)], vault=VAULTS.get, folder_vault=FOLDER_VAULT.get,
                          owned_by=lambda p: [], person_exists=lambda p: True)
    assert out.vaults == {} and out.custodians == [B]


def test_duplicates_are_dropped():
    assert r.parse_scope([{"kind": "vault", "target_id": V1}, {"kind": "vault", "target_id": str(V1)}]) \
        == [r.ScopeItem("vault", V1)]


@pytest.mark.parametrize("raw,why", [
    ([], r.NO_SCOPE),
    ([{"kind": "team", "target_id": str(V1)}], r.BAD_SCOPE_KIND),
    ([{"kind": "vault", "target_id": "nope"}], r.NO_SUCH_VAULT),
    ([{"kind": "folder", "target_id": "nope"}], r.NO_SUCH_FOLDER),
    ([{"kind": "custodian", "target_id": None}], r.NO_SUCH_PERSON),
    ([{"kind": "vault", "target_id": str(uuid.uuid4())}], r.NO_SUCH_VAULT),
    ([{"kind": "folder", "target_id": str(uuid.uuid4())}], r.NO_SUCH_FOLDER),
    ([{"kind": "custodian", "target_id": str(uuid.uuid4())}], r.NO_SUCH_PERSON),
])
def test_what_does_not_exist_is_refused(raw, why):
    assert _refusal(raw) == why


def test_persons_concerned_are_owners_custodians_and_the_people_named():
    named = uuid.uuid4()
    out = _resolve([{"kind": "vault", "target_id": V3}, {"kind": "custodian", "target_id": A}])
    assert r.persons_concerned(out, [named]) == {A: "custodian", B: "owner", named: "named"}


def test_a_person_concerned_for_two_reasons_is_listed_once_with_the_stronger():
    out = _resolve([{"kind": "vault", "target_id": V1}])
    assert r.persons_concerned(out, [A]) == {A: "owner"}
    out = _resolve([{"kind": "custodian", "target_id": A}])
    assert r.persons_concerned(out, [A]) == {A: "custodian"}


def test_an_auditor_who_is_a_person_concerned_is_refused():
    out = _resolve([{"kind": "vault", "target_id": V1}])
    concerned = r.persons_concerned(out, [])
    assert r.auditor_refusal(A, concerned) == r.AUDITOR_CONCERNED
    assert r.auditor_refusal(str(A), concerned) == r.AUDITOR_CONCERNED
    assert r.auditor_refusal(B, concerned) is None
    assert r.auditor_refusal(B, r.persons_concerned(out, [B])) == r.AUDITOR_CONCERNED


def test_what_a_vaults_scope_covers():
    assert r.in_scope(None, FC, [])
    assert r.in_scope({FA}, FA, [])
    assert r.in_scope({FA}, FB, _ancestry(FB) + [])
    assert r.in_scope({FA}, uuid.uuid4(), [FB, FA])
    assert not r.in_scope({FB}, FA, _ancestry(FA))
    assert not r.in_scope(frozenset(), FA, [])
    assert not r.in_scope(set(), uuid.uuid4(), [FA])


@pytest.mark.parametrize("old,new,why", [
    ({V1: None, V2: None}, {V1: None}, None),
    ({V1: None}, {V1: frozenset({FA})}, None),
    ({V1: frozenset({FA})}, {V1: frozenset({FB})}, None),
    ({V1: frozenset({FA})}, {V1: frozenset({FA})}, None),
    ({V1: frozenset({FA})}, {}, None),
    ({V1: None}, {V1: None, V2: None}, r.WIDENS),
    ({V1: frozenset({FA})}, {V1: None}, r.WIDENS),
    ({V1: frozenset({FB})}, {V1: frozenset({FA})}, r.WIDENS),
    ({V1: frozenset({FB})}, {V1: frozenset({FB, FA})}, r.WIDENS),
    ({V1: frozenset()}, {V1: frozenset({FA})}, r.WIDENS),
])
def test_narrowing_and_widening(old, new, why):
    assert r.narrowing_refusal(old, new, ancestry=_ancestry) == why


def test_a_vault_narrowed_out_stays_with_the_case_covering_nothing():
    assert r.narrowed({V1: None, V2: frozenset({FC})}, {V1: frozenset({FA})}) == {V1: frozenset({FA}),
                                                                               V2: frozenset()}


@pytest.mark.parametrize("old,new,why", [
    ((None, None), (T0, T0 + SECOND), None),
    ((T0, T0 + timedelta(days=9)), (T0, T0 + timedelta(days=9)), None),
    ((T0, T0 + timedelta(days=9)), (T0 + SECOND, T0 + timedelta(days=8)), None),
    ((T0, T0 + timedelta(days=9)), (T0 - SECOND, T0 + timedelta(days=9)), r.WIDENS),
    ((T0, T0 + timedelta(days=9)), (T0, T0 + timedelta(days=9) + SECOND), r.WIDENS),
    ((T0, None), (None, None), r.WIDENS),
    ((None, T0), (None, None), r.WIDENS),
    ((None, None), (T0, T0 - SECOND), r.BAD_RANGE),
])
def test_narrowing_the_time_range(old, new, why):
    assert r.time_narrowing_refusal(*old, *new) == why


# --------------------------------------------------------------------------- passwords

ORDER = (cs.REFUSE, cs.WITH_PASSWORD, cs.OVERRIDE)


@pytest.mark.parametrize("recorded", (None,) + ORDER)
@pytest.mark.parametrize("current", ORDER)
@pytest.mark.parametrize("asked", (False, True))
def test_the_stricter_password_rule(recorded, current, asked):
    got = r.password_policy(recorded, current, override_requested=asked)
    stricter = current if recorded is None else min(recorded, current, key=ORDER.index)
    expected = cs.WITH_PASSWORD if stricter == cs.OVERRIDE and not asked else stricter
    assert got == expected


def test_changing_env_to_override_never_widens_an_approved_case():
    assert r.password_policy(cs.WITH_PASSWORD, cs.OVERRIDE, override_requested=True) == cs.WITH_PASSWORD
    assert r.password_policy(cs.REFUSE, cs.OVERRIDE, override_requested=True) == cs.REFUSE
    assert r.password_policy(cs.OVERRIDE, cs.REFUSE, override_requested=True) == cs.REFUSE


def test_a_damaged_recorded_value_counts_as_the_strictest():
    assert r.password_policy("open sesame", cs.OVERRIDE, override_requested=True) == cs.REFUSE


def test_password_vaults_and_the_override():
    assert r.password_vault_refusal(cs.REFUSE, True) == r.PASSWORD_VAULT_REFUSED
    assert r.password_vault_refusal(cs.REFUSE, False) is None
    assert r.password_vault_refusal(cs.WITH_PASSWORD, True) is None
    assert r.password_vault_refusal(cs.OVERRIDE, True) is None
    assert r.override_refusal(True, cs.WITH_PASSWORD) == r.OVERRIDE_NOT_ALLOWED
    assert r.override_refusal(True, cs.REFUSE) == r.OVERRIDE_NOT_ALLOWED
    assert r.override_refusal(True, cs.OVERRIDE) is None
    assert r.override_refusal(False, cs.REFUSE) is None


def test_export_follows_the_setting():
    assert r.export_refusal(True, cs.DISABLED) == r.EXPORT_OFF
    assert r.export_refusal(True, cs.ALLOWED) is None
    assert r.export_refusal(False, cs.DISABLED) is None


# --------------------------------------------------------------------------- suspension and access

@pytest.mark.parametrize("enabled,live,expected", [
    (True, True, r.ACTIVE), (False, True, r.SUSPENDED), (True, False, r.SUSPENDED), (False, False, r.SUSPENDED)])
def test_compliance_access_off_or_an_auditor_not_in_force_suspends_an_active_case(enabled, live, expected):
    assert r.effective_status(r.ACTIVE, access_enabled=enabled, auditor_live=live) == expected


@pytest.mark.parametrize("status", [s for s in r.STATUSES if s != r.ACTIVE])
def test_only_an_active_case_is_suspended_by_the_computation(status):
    assert r.effective_status(status, access_enabled=False, auditor_live=False) == status


def test_access_and_why_not_in_order():
    start, end = r.access_window(T0, 14)
    kw = dict(access_enabled=True, auditor_live=True)
    assert r.access_refusal(r.ACTIVE, start, end, now=T0, **kw) is None
    assert r.access_refusal(r.ACTIVE, start, end, now=end - SECOND, **kw) is None
    assert r.access_refusal(r.ACTIVE, start, end, now=end, **kw) == r.ACCESS_ENDED
    assert r.access_refusal(r.ACTIVE, start, end, now=T0 - SECOND, **kw) == r.NOT_STARTED
    assert r.access_refusal(r.ACTIVE, None, None, now=T0, **kw) == r.NOT_STARTED
    assert r.access_refusal(r.ACTIVE, start, None, now=T0, **kw) == r.ACCESS_ENDED
    assert r.access_refusal(r.HOLD_ONLY, start, end, now=T0, **kw) == r.NOT_ACTIVE
    assert r.access_refusal(r.SUSPENDED, start, end, now=T0, **kw) == r.NOT_ACTIVE
    assert r.access_refusal(r.ACTIVE, start, end, now=T0, access_enabled=True, auditor_live=False) \
        == r.AUDITOR_NOT_LIVE
    # Compliance access turned off is said first, whatever else is true.
    assert r.access_refusal(r.HOLD_ONLY, start, end, now=end, access_enabled=False, auditor_live=False) == r.ACCESS_OFF
