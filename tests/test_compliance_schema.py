"""The compliance tables and case numbers, offline (app/core/models.py, app/core/case_numbers.py).

The new tables are built by create_all, so a fresh install has them and an older release ignores them. The
one change to an existing table's indexes, the partial index on audit_logs.case_id, is built in the
background after start, never in the start's own statements, so a large audit log does not block the start.
An account has at most one open auditor grant. Case numbers come from a counter per year in the approving
transaction: sequential, and a rolled-back approval leaves no gap. test_compliance_schema_live.py checks the
tables, the index and numbers taken at the same moment on Postgres.
"""
import re
import tempfile
import uuid
from datetime import datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import background_maintenance as bm  # noqa: E402
from app.core import case_numbers  # noqa: E402
from app.core import models as m  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent

TABLES = ("auditor_grants", "compliance_cases", "compliance_case_scopes", "compliance_case_vaults",
          "compliance_case_people", "compliance_case_counters", "compliance_exports", "compliance_reveals",
          "compliance_notice_outbox", "legal_hold_vaults", "held_name_history")


@pytest.fixture
def factory():
    with tempfile.TemporaryDirectory(ignore_cleanup_errors=True) as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'compliance.db'}")
        m.Base.metadata.create_all(engine, tables=[m.Base.metadata.tables[t] for t in ("users",) + TABLES])
        make = sessionmaker(bind=engine, autocommit=False, autoflush=False)
        made = []

        def session():
            made.append(make())
            return made[-1]

        yield session
        for s in made:
            s.close()
        engine.dispose()


def _columns(table):
    return {c.name: c for c in m.Base.metadata.tables[table].columns}


def test_every_compliance_table_is_in_the_model():
    for table in TABLES:
        assert table in m.Base.metadata.tables, table


def test_a_grant_is_bound_to_an_enrollment_and_keeps_its_credential_changers():
    cols = _columns("auditor_grants")
    for name in ("user_id", "username_at_grant", "proposed_by", "proposed_by_username", "proposed_at",
                 "approved_by", "approved_by_operator", "approved_at", "status", "expires_at", "suspended_at",
                 "suspend_reason", "revoked_at", "revoked_by", "second_factor_enrollment_id",
                 "credential_changers"):
        assert name in cols, name
    assert not cols["credential_changers"].nullable
    # The binding outlives a second-factor reset that deletes the enrollment: no foreign key.
    assert not cols["second_factor_enrollment_id"].foreign_keys
    assert set(m.AUDITOR_GRANT_OPEN) == {"proposed", "active", "suspended"}
    assert set(m.AUDITOR_GRANT_STATES) == {"proposed", "active", "suspended", "expired", "revoked", "rejected",
                                           "lapsed", "ended"}


def test_free_text_is_kept_only_in_sealed_columns():
    for table in TABLES:
        for name, column in _columns(table).items():
            if any(word in name for word in ("justification", "note", "objection", "reason", "address")):
                if name in ("suspend_reason", "reason_category"):
                    continue                          # a fixed category, not free text
                assert name.endswith("_enc"), (table, name)
                assert isinstance(column.type, sa.Text), (table, name)


def test_a_case_cannot_lose_its_auditor_and_its_rows_go_only_with_it():
    auditor = next(iter(_columns("compliance_cases")["auditor_id"].foreign_keys))
    assert (auditor.column.table.name, auditor.ondelete) == ("users", "RESTRICT")
    for table in ("compliance_case_scopes", "compliance_case_vaults", "compliance_case_people", "compliance_exports",
                  "legal_hold_vaults", "compliance_notice_outbox"):
        fk = next(iter(_columns(table)["case_id"].foreign_keys))
        assert (fk.column.table.name, fk.ondelete) == ("compliance_cases", "CASCADE"), table
    # A vault in a case or under a hold keeps its record after the vault is gone.
    for table in ("compliance_case_vaults", "legal_hold_vaults", "held_name_history"):
        assert not _columns(table)["vault_id"].foreign_keys, table
    assert _columns("compliance_cases")["number"].unique
    assert _columns("compliance_notice_outbox")["dedup_key"].unique
    assert not _columns("compliance_notice_outbox")["dedup_key"].nullable


def test_an_account_has_at_most_one_open_grant(factory):
    db = factory()
    user = m.User(id=uuid.uuid4(), username="ana", password_hash="x", role=m.RoleEnum.USER)
    db.add(user)
    db.commit()

    def grant(status):
        db.add(m.AuditorGrant(user_id=user.id, username_at_grant="ana", status=status, proposed_by_username="bo"))
        db.commit()

    for status in ("revoked", "expired", "rejected", "lapsed", "revoked"):
        grant(status)
    grant("proposed")
    for status in m.AUDITOR_GRANT_OPEN:
        with pytest.raises(sa.exc.IntegrityError):
            grant(status)
        db.rollback()
    row = db.query(m.AuditorGrant).filter_by(status="proposed").one()
    row.status = "active"
    db.commit()
    with pytest.raises(sa.exc.IntegrityError):
        grant("suspended")
    db.rollback()
    assert db.query(m.AuditorGrant).count() == 6


def test_the_open_grant_and_the_open_hold_indexes_are_partial():
    from sqlalchemy.dialects import postgresql
    from sqlalchemy.schema import CreateIndex
    built = {ix.name: str(CreateIndex(ix).compile(dialect=postgresql.dialect()))
             for t in ("auditor_grants", "legal_hold_vaults") for ix in m.Base.metadata.tables[t].indexes}
    assert built["uq_auditor_grant_open"] == ("CREATE UNIQUE INDEX uq_auditor_grant_open ON auditor_grants (user_id) "
                                              "WHERE status IN ('proposed', 'active', 'suspended')")
    assert built["idx_legal_hold_vault_open"] == ("CREATE INDEX idx_legal_hold_vault_open ON legal_hold_vaults "
                                                  "(vault_id) WHERE released_at IS NULL")


# --------------------------------------------------------------------------- the start

def test_the_case_index_is_built_in_the_background_and_never_at_start():
    steps = {s.name: s for s in bm.STEPS}
    step = steps["ix_audit_logs_case_id"]
    assert step.kind == bm.CREATE_INDEX
    assert step.sql == ("CREATE INDEX CONCURRENTLY IF NOT EXISTS ix_audit_logs_case_id ON audit_logs (case_id) "
                        "WHERE case_id IS NOT NULL")
    # The start's own statements add the column (nullable, no default) and build no index on it.
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    assert source.count('" ADD COLUMN IF NOT EXISTS case_id UUID"') == 1
    assert not re.search(r"CREATE (UNIQUE )?INDEX[^\"]*audit_logs[^\"]*case_id", source)
    assert not [ix for ix in m.AuditLog.__table__.indexes if "case_id" in ix.columns]
    assert not m.AuditLog.__table__.columns["case_id"].index


def test_the_new_tables_are_new_so_create_all_builds_them_and_no_start_statement_alters_them():
    source = (ROOT / "app" / "api" / "api_server.py").read_text(encoding="utf-8")
    for table in TABLES:
        assert not re.search(rf"ALTER TABLE (IF EXISTS )?{table}\b", source), table


# --------------------------------------------------------------------------- case numbers

def test_numbers_are_sequential_per_year_and_formatted(factory):
    db = factory()
    jan = datetime(2026, 1, 2)
    assert [case_numbers.allocate(db, jan) for _ in range(3)] == ["C-2026-0001", "C-2026-0002", "C-2026-0003"]
    assert case_numbers.allocate(db, datetime(2027, 1, 1)) == "C-2027-0001"
    assert case_numbers.allocate(db, datetime(2026, 12, 31, 23, 59)) == "C-2026-0004"
    db.commit()
    assert case_numbers.format_number(2026, 12345) == "C-2026-12345"
    assert case_numbers.format_number(2026, 7) == "C-2026-0007"


def test_a_rolled_back_approval_takes_its_number_back(factory):
    db = factory()
    when = datetime(2026, 5, 5)
    assert case_numbers.allocate(db, when) == "C-2026-0001"
    db.commit()
    assert case_numbers.allocate(db, when) == "C-2026-0002"
    db.rollback()
    other = factory()
    assert case_numbers.allocate(other, when) == "C-2026-0002"
    other.commit()


def test_allocate_never_commits(factory):
    db = factory()
    case_numbers.allocate(db, datetime(2026, 1, 1))
    assert factory().query(m.ComplianceCaseCounter).count() == 0
