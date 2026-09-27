"""A vault's file expiry is at most 100 years.

The setting had no upper bound. A vault set to expire files after 999,999,999 days took the value,
and then every upload into it answered 500: the deadline, worked out at upload, does not fit a date
(OverflowError). A value past the database column's range, such as 2**40, made the settings save
itself answer 500.

Now the longest is 100 years in each unit -- 52,560,000 minutes, 876,000 hours, 36,500 days --
refused with a message fit to show wherever the setting is written: the vault settings endpoint
(through ``VaultService.set_file_expiry``), vault creation (the endpoint and ``create_vault``). An
upload link's retention, the one other writer, is already bounded at ten years
(``receiver_policy.MAX_RETENTION_DAYS``). A longer value an earlier version stored counts as 100
years when a deadline is worked out, instead of failing the upload.

These run the real functions against an in-memory session (tests/_memory_db.py) and the vault
creation handler with what comes before the check stubbed. tests/test_file_expiry_maximum_live.py
drives the endpoints on a running stack.
"""
import inspect
import uuid
from datetime import timedelta
from types import SimpleNamespace

import pytest
from fastapi import HTTPException

from _async_run import run_coroutine
from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

set_bare_api_env()

from app.core import file_expiry, receiver_policy  # noqa: E402
from app.core.models import File, Vault  # noqa: E402
from app.services.vault_service import VaultService, calculate_file_expiration  # noqa: E402

pytestmark = pytest.mark.unit

MAX = {"minutes": 52_560_000, "hours": 876_000, "days": 36_500}


def _vault(value, unit="days"):
    return SimpleNamespace(id=uuid.uuid4(), expire_files_after_days=value, expire_files_unit=unit)


def _service(db):
    svc = VaultService.__new__(VaultService)
    svc.db = db
    return svc


def test_the_maximum_is_100_years_in_each_unit():
    assert file_expiry.MAX_EXPIRY == MAX
    assert MAX["days"] == 100 * 365
    assert MAX["hours"] == MAX["days"] * 24 and MAX["minutes"] == MAX["hours"] * 60
    # Each maximum fits the database column (a 32-bit integer) and a date.
    assert max(MAX.values()) < 2**31
    for unit, value in MAX.items():
        assert calculate_file_expiration(_vault(value, unit)) is not None


# ---------------------------------------------------------------------------------------------
# Writing the setting
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("unit", sorted(MAX))
def test_the_settings_take_the_maximum_and_refuse_one_more(unit):
    vault = _vault(7)
    db = MemoryDB({Vault: [vault], File: []})
    assert _service(db).set_file_expiry(vault, expire_files_after_days=MAX[unit],
                                        expire_files_unit=unit) == 0
    assert (vault.expire_files_after_days, vault.expire_files_unit) == (MAX[unit], unit)

    vault = _vault(7)
    db = MemoryDB({Vault: [vault], File: []})
    with pytest.raises(ValueError) as refused:
        _service(db).set_file_expiry(vault, expire_files_after_days=MAX[unit] + 1,
                                     expire_files_unit=unit)
    assert str(refused.value) == f"File expiry can be at most 100 years ({MAX[unit]:,} {unit})."
    assert (vault.expire_files_after_days, vault.expire_files_unit) == (7, "days")
    assert db.log == [], "nothing may be locked or changed before the refusal"


@pytest.mark.parametrize("value", [999_999_999, 2**40, 10**30, float(10**12)])
def test_a_huge_value_is_refused(value):
    vault = _vault(None)
    db = MemoryDB({Vault: [vault], File: []})
    with pytest.raises(ValueError, match="at most 100 years"):
        _service(db).set_file_expiry(vault, expire_files_after_days=value, expire_files_unit="days")
    assert vault.expire_files_after_days is None and db.log == []


def test_the_value_alone_is_checked_against_the_unit_the_vault_has():
    vault = _vault(5, "minutes")
    db = MemoryDB({Vault: [vault], File: []})
    _service(db).set_file_expiry(vault, expire_files_after_days=MAX["minutes"])
    assert vault.expire_files_after_days == MAX["minutes"]

    vault = _vault(5, "hours")
    with pytest.raises(ValueError, match=r"876,000 hours"):
        _service(MemoryDB({Vault: [vault], File: []})).set_file_expiry(
            vault, expire_files_after_days=MAX["hours"] + 1)


def test_changing_only_the_unit_is_checked_too():
    """50,000 minutes is a month; the same number of days is 137 years."""
    vault = _vault(50_000, "minutes")
    db = MemoryDB({Vault: [vault], File: []})
    with pytest.raises(ValueError, match=r"36,500 days"):
        _service(db).set_file_expiry(vault, expire_files_unit="days")
    assert (vault.expire_files_after_days, vault.expire_files_unit) == (50_000, "minutes")

    _service(db).set_file_expiry(vault, expire_files_unit="hours")
    assert (vault.expire_files_after_days, vault.expire_files_unit) == (50_000, "hours")


def test_a_longer_value_an_earlier_version_stored_can_still_be_lowered_or_turned_off():
    vault = _vault(999_999_999)
    kept = SimpleNamespace(id=uuid.uuid4(), vault_id=vault.id, expires_at=file_expiry.utc_now(),
                           updated_at=None)
    db = MemoryDB({Vault: [vault], File: [kept]})
    with pytest.raises(ValueError):
        _service(db).set_file_expiry(vault, expire_files_unit="days")
    _service(db).set_file_expiry(vault, expire_files_after_days=30)
    assert vault.expire_files_after_days == 30

    vault.expire_files_after_days = 999_999_999
    assert _service(db).set_file_expiry(vault, expire_files_after_days=0) == 1
    assert vault.expire_files_after_days is None and kept.expires_at is None


def test_create_vault_refuses_a_longer_expiry_before_it_builds_anything():
    db = MemoryDB({Vault: []})
    with pytest.raises(ValueError, match=r"36,500 days"):
        _service(db).create_vault(name="v", owner=SimpleNamespace(id=uuid.uuid4()),
                                  expire_files_after_days=MAX["days"] + 1)
    assert db.log == [] and db.rows_of(Vault) == []


def test_an_upload_link_retention_is_already_within_the_maximum():
    assert receiver_policy.MAX_RETENTION_DAYS <= MAX["days"]


# ---------------------------------------------------------------------------------------------
# The vault creation endpoint answers 400
# ---------------------------------------------------------------------------------------------


class _Reached(Exception):
    """Raised in place of creating the vault: the endpoint got past the expiry check."""


@pytest.fixture
def create_endpoint(monkeypatch):
    import app.api.api_server as S
    import app.core.temp_scope as temp_scope

    monkeypatch.setattr(S, "PermissionService", lambda db: SimpleNamespace(
        require_permission=lambda *a, **k: None))
    monkeypatch.setattr(S, "AuditLogger", lambda db: None)
    monkeypatch.setattr(S, "_resolve_vault_type_for_create", lambda user, t, db: "standard")
    monkeypatch.setattr(temp_scope, "require_create_vault_type", lambda user, t: None)
    monkeypatch.setattr(S, "_enforce_vault_count", lambda db, user: None)
    monkeypatch.setattr(S, "_enforce_vault_size", lambda db, user, size: None)

    def reached(self, **kw):
        raise _Reached(kw["expire_files_after_days"])
    monkeypatch.setattr(S.VaultService, "create_vault", reached)

    handler = inspect.unwrap(S.create_vault)

    def call(days):
        body = S.VaultCreate(name="v", size_limit_gb=1, expire_files_after_days=days)
        return run_coroutine(handler(vault_create=body, request=None,
                                     current_user=SimpleNamespace(id=uuid.uuid4()), db=object()))
    return call


def test_the_create_endpoint_refuses_a_longer_expiry_with_400(create_endpoint):
    with pytest.raises(HTTPException) as refused:
        create_endpoint(MAX["days"] + 1)
    assert refused.value.status_code == 400
    assert refused.value.detail == "File expiry can be at most 100 years (36,500 days)."


@pytest.mark.parametrize("days", [None, 1, MAX["days"]])
def test_the_create_endpoint_goes_ahead_within_the_maximum(create_endpoint, days):
    with pytest.raises(_Reached) as reached:
        create_endpoint(days)
    assert reached.value.args == (days,)


# ---------------------------------------------------------------------------------------------
# Working out a deadline from a value stored before the maximum
# ---------------------------------------------------------------------------------------------


@pytest.mark.parametrize("unit,value", [
    ("days", 999_999_999), ("hours", 2**40), ("minutes", 2**62), (None, 10**9), ("weeks", 10**9),
])
def test_a_stored_value_over_the_maximum_counts_as_the_maximum(unit, value):
    before = file_expiry.utc_now()
    got = calculate_file_expiration(_vault(value, unit))
    span = {"minutes": timedelta(minutes=MAX["minutes"]), "hours": timedelta(hours=MAX["hours"])}.get(
        unit, timedelta(days=MAX["days"]))
    assert before + span <= got <= file_expiry.utc_now() + span


def test_a_value_within_the_maximum_is_not_changed():
    before = file_expiry.utc_now()
    got = calculate_file_expiration(_vault(MAX["days"] - 1))
    assert before + timedelta(days=MAX["days"] - 1) <= got <= file_expiry.utc_now() + timedelta(
        days=MAX["days"] - 1)
