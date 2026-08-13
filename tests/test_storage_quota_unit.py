"""Offline tests for the storage-quota arithmetic (app/core/storage_quota.py).

Pure functions, no deployment: every rule the API and the SFTP path enforce is decided here, so
this file is where the edge cases live — the boundary between "fits" and "does not", the three
meanings of an absent value (inherit / unlimited / zero), and the reclaim arithmetic that lets a
contributor take back exactly what they gave and not a byte more.
"""
import pytest

from app.core import storage_quota as sq

pytestmark = pytest.mark.unit

GIB = 1024 ** 3


# --- parsing ---------------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (5, 5.0), (5.5, 5.5), ("5", 5.0), ("5.5", 5.5), (0, 0.0), (-1, -1.0), ("-1", -1.0),
    (None, None), ("", None), ("   ", None), ("abc", None), ([], None), ({}, None),
    (True, None), (False, None),          # bool is an int subclass; must NOT read as 1 GB
])
def test_parse_gb(value, expected):
    assert sq.parse_gb(value) == expected


def test_gb_to_bytes_truncates_and_clamps():
    assert sq.gb_to_bytes(1) == GIB
    assert sq.gb_to_bytes(2.5) == int(2.5 * GIB)
    assert sq.gb_to_bytes(0) == 0
    assert sq.gb_to_bytes(-3) == 0            # negative clamps rather than producing a negative cap
    assert sq.gb_to_bytes(1e-12) == 0         # sub-byte truncates to 0, never to "unlimited"


@pytest.mark.parametrize("raw,expected", [
    (10, 10 * GIB), ("10", 10 * GIB), (0.5, GIB // 2),
    (0, None), (-5, None), (None, None), ("", None), ("nonsense", None), (True, None),
])
def test_quota_setting_bytes_treats_zero_and_junk_as_unlimited(raw, expected):
    """The per-account / per-vault quotas opt IN: absent, zero and unparseable all mean no limit,
    so a fresh deployment that never saved a quota is unbounded."""
    assert sq.quota_setting_bytes(raw) == expected


# --- the deployment ceiling ------------------------------------------------------------------

@pytest.mark.parametrize("env,expected", [
    (-1, None), (0, None), (None, None), ("", None),   # nothing configured => no ceiling
    (100, 100 * GIB), ("100", 100 * GIB), (0.5, GIB // 2),
])
def test_env_ceiling_bytes(env, expected):
    assert sq.env_ceiling_bytes(env) == expected


def test_deployment_limit_defaults_to_the_env_ceiling():
    assert sq.deployment_limit_bytes(100, None) == 100 * GIB
    assert sq.deployment_limit_bytes(100, "") == 100 * GIB
    assert sq.deployment_limit_bytes(-1, None) is None


def test_deployment_limit_admin_value_can_only_narrow():
    assert sq.deployment_limit_bytes(100, 40) == 40 * GIB     # lower than the ceiling: honoured
    assert sq.deployment_limit_bytes(100, 400) == 100 * GIB   # above it: clamped to the ceiling
    assert sq.deployment_limit_bytes(100, 100) == 100 * GIB   # exactly at it


def test_deployment_limit_zero_is_a_freeze_not_unlimited():
    """0 is the one place a zero means "accept no more bytes" — the panel offers a bounded
    0..MAX range, so it has to be able to express a stop."""
    assert sq.deployment_limit_bytes(100, 0) == 0
    assert sq.deployment_limit_bytes(-1, 0) == 0
    assert sq.would_exceed_deployment(0, 1, 0) is True


def test_deployment_limit_with_no_env_ceiling_takes_the_admin_value():
    assert sq.deployment_limit_bytes(-1, 25) == 25 * GIB


@pytest.mark.parametrize("stored,additional,limit,expected", [
    (0, 0, None, False),                       # unlimited never exceeds
    (10 ** 12, 10 ** 12, None, False),
    (0, GIB, 10 * GIB, False),
    (9 * GIB, GIB, 10 * GIB, False),           # exactly at the limit fits
    (9 * GIB, GIB + 1, 10 * GIB, True),        # one byte past does not
    (10 * GIB, 1, 10 * GIB, True),
    (0, -5, 10 * GIB, False),                  # a negative delta is treated as zero
    (None, None, 10 * GIB, False),
])
def test_would_exceed_deployment(stored, additional, limit, expected):
    assert sq.would_exceed_deployment(stored, additional, limit) is expected


# --- validating an administrator's chosen limit ----------------------------------------------

def test_validate_deployment_limit_accepts_a_value_inside_the_ceiling():
    assert sq.validate_deployment_limit(40, 100, 10 * GIB) is None
    assert sq.validate_deployment_limit(100, 100, 0) is None       # exactly the ceiling
    assert sq.validate_deployment_limit(0, 100, 0) is None         # a freeze with nothing stored


def test_validate_deployment_limit_rejects_above_the_ceiling():
    reason = sq.validate_deployment_limit(101, 100, 0)
    assert reason and "maximum" in reason and "MAX_STORAGE_GB" in reason


def test_validate_deployment_limit_rejects_below_what_is_already_stored():
    reason = sq.validate_deployment_limit(1, 100, 5 * GIB)
    assert reason and "already" in reason
    # ...and accepts exactly the stored amount, which strands nothing.
    assert sq.validate_deployment_limit(5, 100, 5 * GIB) is None


@pytest.mark.parametrize("bad", [None, "", "abc", True, [], {}])
def test_validate_deployment_limit_rejects_non_numbers(bad):
    assert sq.validate_deployment_limit(bad, 100, 0) is not None


def test_validate_deployment_limit_rejects_negative():
    assert "negative" in sq.validate_deployment_limit(-5, 100, 0)


def test_validate_deployment_limit_without_a_ceiling_only_checks_stored_bytes():
    assert sq.validate_deployment_limit(10 ** 6, -1, 0) is None
    assert sq.validate_deployment_limit(1, -1, 5 * GIB) is not None


# --- per-account budgets ---------------------------------------------------------------------

def test_account_quota_override_beats_the_default():
    assert sq.account_quota_bytes(7 * GIB, 10) == 7 * GIB
    assert sq.account_quota_bytes(None, 10) == 10 * GIB          # NULL inherits
    assert sq.account_quota_bytes(sq.UNLIMITED_QUOTA, 10) is None  # -1 exempts
    assert sq.account_quota_bytes(0, 10) == 0                    # 0 means "may allocate nothing"


def test_account_quota_inherits_an_unlimited_default():
    assert sq.account_quota_bytes(None, 0) is None
    assert sq.account_quota_bytes(None, None) is None


@pytest.mark.parametrize("value,expected", [
    (None, None), ("", None), ("inherit", None), ("INHERIT", None), ("default", None),
    ("unlimited", sq.UNLIMITED_QUOTA), ("Unlimited", sq.UNLIMITED_QUOTA),
    ("none", sq.UNLIMITED_QUOTA), ("exempt", sq.UNLIMITED_QUOTA),
    (0, 0), (5, 5 * GIB), (2.5, int(2.5 * GIB)), ("5", 5 * GIB),
])
def test_parse_account_quota_input(value, expected):
    assert sq.parse_account_quota_input(value) == expected


@pytest.mark.parametrize("bad", [-1, -0.5, "abc", True, False, [], {}])
def test_parse_account_quota_input_rejects_junk(bad):
    with pytest.raises(ValueError):
        sq.parse_account_quota_input(bad)


def test_parse_account_quota_input_rejects_an_overflowing_budget():
    with pytest.raises(ValueError):
        sq.parse_account_quota_input(10 ** 12)


def test_account_headroom():
    assert sq.account_headroom_bytes(None, 5 * GIB) is None      # unlimited stays unlimited
    assert sq.account_headroom_bytes(10 * GIB, 4 * GIB) == 6 * GIB
    assert sq.account_headroom_bytes(10 * GIB, 10 * GIB) == 0
    assert sq.account_headroom_bytes(10 * GIB, 99 * GIB) == 0    # over-spent never goes negative
    assert sq.account_headroom_bytes(10 * GIB, None) == 10 * GIB


def test_max_vault_total_takes_the_tightest_bound():
    assert sq.max_vault_total_bytes(None, None) is None                       # nothing bounds it
    assert sq.max_vault_total_bytes(5 * GIB, None) == 5 * GIB                 # ceiling only
    assert sq.max_vault_total_bytes(None, 3 * GIB) == 3 * GIB                 # budget only
    assert sq.max_vault_total_bytes(5 * GIB, 3 * GIB) == 3 * GIB              # budget is tighter
    assert sq.max_vault_total_bytes(2 * GIB, 3 * GIB) == 2 * GIB              # ceiling is tighter


def test_max_vault_total_counts_what_others_already_contributed():
    """On a shared vault your headroom sits ON TOP of everyone else's contributions, so the
    total you may set is higher than your own budget — up to the per-vault ceiling."""
    assert sq.max_vault_total_bytes(None, 3 * GIB, other_grants=4 * GIB) == 7 * GIB
    assert sq.max_vault_total_bytes(5 * GIB, 3 * GIB, other_grants=4 * GIB) == 5 * GIB


# --- the allocation check --------------------------------------------------------------------

def _check(new_grant, **kw):
    kw.setdefault("current_grant", 0)
    kw.setdefault("other_grants", 0)
    kw.setdefault("stored_bytes", 0)
    return sq.check_grant(new_grant, **kw)


def test_check_grant_allows_a_plain_increase_within_budget():
    assert _check(5 * GIB, current_grant=GIB, account_quota=10 * GIB, allocated_elsewhere=0) is None


def test_check_grant_allows_reclaiming_down_to_zero_when_others_hold_the_vault_open():
    """A contributor may withdraw everything they gave; the vault survives on the rest."""
    assert _check(0, current_grant=5 * GIB, other_grants=GIB, stored_bytes=0) is None


def test_check_grant_refuses_emptying_the_last_allocation():
    reason = _check(0, current_grant=GIB, other_grants=0)
    assert reason and "at least 1 byte" in reason


def test_check_grant_refuses_going_below_stored_bytes():
    reason = _check(GIB, current_grant=5 * GIB, stored_bytes=3 * GIB)
    assert reason and "already stores" in reason
    # exactly the stored amount is allowed — nothing is stranded
    assert _check(3 * GIB, current_grant=5 * GIB, stored_bytes=3 * GIB) is None


def test_check_grant_refuses_passing_the_per_vault_ceiling():
    assert _check(5 * GIB, per_vault_ceiling=4 * GIB) is not None
    assert _check(4 * GIB, per_vault_ceiling=4 * GIB) is None
    # the ceiling applies to the vault TOTAL, not to one person's share
    assert _check(3 * GIB, other_grants=2 * GIB, per_vault_ceiling=4 * GIB) is not None


def test_a_ceiling_lowered_after_the_fact_does_not_trap_the_storage():
    """An administrator lowering 'max vault size' below an existing vault must not strand what
    people already allocated: every reclaim would still end above the new ceiling, so a strict
    check would leave the only exit as deleting the vault."""
    # 10 GB already allocated (mine 6, others 4); the ceiling has since dropped to 2 GB.
    reclaim = _check(3 * GIB, current_grant=6 * GIB, other_grants=4 * GIB, per_vault_ceiling=2 * GIB)
    assert reclaim is None
    # ...but growing further away from the new ceiling is still refused.
    assert _check(7 * GIB, current_grant=6 * GIB, other_grants=4 * GIB,
                  per_vault_ceiling=2 * GIB) is not None


def test_an_account_quota_cut_after_the_fact_does_not_trap_the_storage():
    """Same trap, one level up: an account whose quota was cut below what it already allocated
    has to be able to give storage BACK, which is the very thing that returns it to compliance."""
    give_back = _check(2 * GIB, current_grant=5 * GIB, other_grants=GIB,
                       account_quota=1 * GIB, allocated_elsewhere=0)
    assert give_back is None
    assert _check(6 * GIB, current_grant=5 * GIB, other_grants=GIB,
                  account_quota=1 * GIB, allocated_elsewhere=0) is not None


def test_holding_an_allocation_steady_is_never_refused():
    """Re-saving the same number under a tightened bound is a no-op, not a violation."""
    assert _check(5 * GIB, current_grant=5 * GIB, other_grants=0,
                  per_vault_ceiling=GIB, account_quota=GIB) is None


def test_check_grant_refuses_passing_the_account_budget():
    reason = _check(6 * GIB, account_quota=10 * GIB, allocated_elsewhere=5 * GIB)
    assert reason and "quota" in reason
    assert _check(5 * GIB, account_quota=10 * GIB, allocated_elsewhere=5 * GIB) is None


def test_check_grant_excludes_this_vault_from_allocated_elsewhere():
    """The caller passes what they allocated to OTHER vaults, so raising a grant they already
    hold is charged only the difference — otherwise a full quota could never be re-spent here."""
    assert _check(8 * GIB, current_grant=8 * GIB, account_quota=8 * GIB,
                  allocated_elsewhere=0) is None


def test_check_grant_is_unbounded_without_a_budget():
    assert _check(10 ** 15, account_quota=None) is None


@pytest.mark.parametrize("bad", [None, True, False, "abc", [], {}])
def test_check_grant_rejects_non_numbers(bad):
    assert _check(bad) is not None


def test_check_grant_rejects_a_negative_allocation():
    assert "negative" in _check(-1)


def test_check_grant_rejects_an_overflowing_total():
    assert _check(sq.INT64_MAX, other_grants=GIB) is not None
    assert _check(sq.INT64_MAX) is None      # exactly the column's maximum still fits


def test_check_grant_reports_the_tightest_reason_first():
    """Stored bytes are reported before the ceiling: a caller who is below their own files
    should be told that, not sent chasing an administrator's per-vault setting."""
    reason = _check(0, other_grants=GIB, stored_bytes=5 * GIB, per_vault_ceiling=1)
    assert "already stores" in reason


# --- formatting ------------------------------------------------------------------------------

@pytest.mark.parametrize("value,expected", [
    (0, "0 B"), (900, "900 B"), (1024, "1.00 KB"), (1024 ** 2, "1.00 MB"),
    (GIB, "1.00 GB"), (int(2.5 * GIB), "2.50 GB"), (20 * GIB, "20 GB"), (None, "0 B"),
])
def test_format_bytes(value, expected):
    assert sq.format_bytes(value) == expected


@pytest.mark.parametrize("value,expected", [
    (GIB, "1.00 GB"), (50 * GIB, "50 GB"), (0, "0.00 GB"), (None, "0.00 GB"),
])
def test_format_gb_always_uses_gb(value, expected):
    assert sq.format_gb(value) == expected
