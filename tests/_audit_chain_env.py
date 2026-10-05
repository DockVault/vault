"""A throwaway SQLite database and a chain state of its own, for the offline tests of the audit integrity
chain (app/core/audit_integrity.py)."""
import tempfile
import uuid
from datetime import datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from typing import Optional

import sqlalchemy as sa
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import audit_chain_format as fmt  # noqa: E402
from app.core import audit_integrity as ai  # noqa: E402
from app.core import retention  # noqa: E402
from app.core import setting_changes as sc  # noqa: E402
from app.core import settings_registry as reg  # noqa: E402
from app.core.models import (AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange,  # noqa: E402
                             SystemSetting, User)

KEY_TEXT = "c" * 64
ENC_KEY = "Y2hhbmdlbWVjaGFuZ2VtZWNoYW5nZW1lY2hhbmdlbWU="
T0 = datetime(2026, 10, 20, 9, 0, 0)

INPUT_ENV = ("AUDIT_LOG_MAX_MB", "AUDIT_LOG_RETENTION_DAYS", "AUDIT_MIN_RETENTION_DAYS", "AUDIT_PROTECTED_MIN_DAYS",
             "PLAN_LOG_MAX_DAYS", "PLAN_LOG_MAX_MB", "RETENTION_HOLD", "RETENTION_REDUCTION_DELAY_DAYS",
             "SECURITY_RECORD_DAYS", "SECURITY_RECORD_MAX_DAYS", "SECURITY_RECORD_MIN_DAYS")


def settings(tmp: Path, **kw):
    base = dict(settings_locked_keys="", retention_hold=False, log_prune_interval_minutes=15,
                log_prune_batch_rows=5000, retention_reduction_delay_days=7, audit_log_retention_days=0,
                audit_min_retention_days=0, audit_protected_min_days=365, audit_log_max_mb=0,
                plan_log_max_days=-1, plan_log_max_mb=-1, security_alert_retention_days=90,
                security_record_days=30, security_record_min_days=7, security_record_max_days=365,
                jwt_access_token_expire_minutes=60, audit_seal_lag_minutes=60, encryption_key=ENC_KEY,
                audit_chain_key=KEY_TEXT, audit_chain_head_file=str(tmp / "keys" / "audit-chain-head.json"))
    base.update(kw)
    return SimpleNamespace(**base)


class Clock:
    def __init__(self, at: datetime):
        self.at = at

    def __call__(self) -> datetime:
        return self.at

    def advance(self, **kw) -> datetime:
        self.at += timedelta(**kw)
        return self.at


class Env:
    """The database, the settings, the clock and the chain state of one test."""

    def __init__(self, monkeypatch, tmp: Path, **kw):
        self.tmp = tmp
        self.monkeypatch = monkeypatch
        for name in INPUT_ENV:
            monkeypatch.delenv(name, raising=False)
        self.settings = settings(tmp, **kw)
        monkeypatch.setattr(reg, "_cache", reg._Cache())
        monkeypatch.setattr(reg, "_deployment_settings", lambda: self.settings)
        monkeypatch.setattr(retention, "_settings", lambda: self.settings)
        monkeypatch.setattr(retention, "KEEP_RULES", {})
        monkeypatch.setattr(sc, "announce", lambda *a, **k: None)
        self.engine = sa.create_engine(f"sqlite:///{tmp / 'audit.db'}")
        copies = sa.MetaData()
        for model in (User, AuditLog, AuditSeal, ManagedSetting, ManagedSettingChange, SystemSetting):
            columns = []
            for column in model.__table__.columns:
                default = column.server_default
                if default is not None and "now()" in str(getattr(default, "arg", "")):
                    default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
                elif default is not None:
                    default = sa.schema.DefaultClause(default.arg)
                columns.append(sa.Column(column.name, column.type, primary_key=column.primary_key,
                                         nullable=column.nullable, server_default=default))
            sa.Table(model.__tablename__, copies, *columns)
        copies.create_all(self.engine)
        self.make = sessionmaker(bind=self.engine, autocommit=False, autoflush=False)
        self.made = []
        monkeypatch.setattr(reg, "_default_session_factory", self.session)
        self.clock = Clock(T0)
        clock = self.clock

        class _AtTheClock(datetime):
            """The audit rows the app writes itself are dated by the test's clock."""
            @classmethod
            def now(cls, tz=None):
                return clock().replace(tzinfo=tz) if tz is not None else clock()

        from app.services import audit_logger
        monkeypatch.setattr(audit_logger, "datetime", _AtTheClock)
        self.st = ai.ChainState(settings=self.settings, clock=self.clock)
        ai.set_state(self.st)
        with self.session() as db:
            db.add(SystemSetting(key=ai.NAME_PURGE_MARKER, value={"rows": 0}))
            db.commit()

    def session(self):
        self.made.append(self.make())
        return self.made[-1]

    def close(self):
        for s in self.made:
            s.close()
        ai.set_state(None)
        self.engine.dispose()

    # -- rows

    def row(self, at: datetime, action="file_uploaded", username="alice", nonce=True, **kw):
        row_id = uuid.uuid4()
        row = AuditLog(id=row_id, action=action, status="success", timestamp=at, username=username,
                       ip_address=kw.pop("ip_address", "203.0.113.9"), details=kw.pop("details", {"n": 1}),
                       seal_nonce=uuid.uuid4().bytes if nonce else None, **kw)
        with self.session() as db:
            db.add(row)
            db.commit()
        return row_id

    # -- the sealer

    def seal(self, **kw):
        return ai.seal_pass(self.session, engine=self.engine, st=self.st, now=self.clock(), **kw)

    def run_until_sealed(self, limit=200):
        for _ in range(limit):
            r = self.seal()
            if r.stopped or not r.sealed:
                return r
        return r

    def verify(self, **kw):
        from app.core import audit_chain_verify as v
        with self.session() as db:
            held = {k: c.key for k, c in self.st.keys_held().items()}
            return v.verify(db, record=self.st.head_store().load(), held=held,
                            current_key_id=self.st.current_key().key_id, now=self.clock(), **kw)

    def seals(self):
        with self.session() as db:
            return db.query(AuditSeal).order_by(AuditSeal.seq).all()

    def fresh_process(self):
        """The same database and head record, read by a process that has just started."""
        self.st = ai.ChainState(settings=self.settings, clock=self.clock)
        ai.set_state(self.st)
        return self.st


def failures(report):
    from app.core.audit_chain_verify import FAILURE
    return report.kinds(FAILURE)


CHAIN_SETTINGS = dict(encryption_key=ENC_KEY, audit_chain_key=KEY_TEXT, audit_seal_lag_minutes=60,
                      security_record_days=30, security_record_min_days=7, security_record_max_days=365,
                      audit_min_retention_days=0, audit_protected_min_days=365, audit_log_max_mb=0,
                      plan_log_max_days=-1, plan_log_max_mb=-1)


class Chain:
    """The audit chain of a test database whose tables another test module made (they must include
    audit_seals): a chain state of its own, a clock, and the rows the app writes dated by that clock."""

    def __init__(self, monkeypatch, tmp: Path, settings, factory, now: datetime):
        for name in INPUT_ENV:
            monkeypatch.delenv(name, raising=False)
        for attr, value in CHAIN_SETTINGS.items():
            if not hasattr(settings, attr):
                setattr(settings, attr, value)
        settings.audit_chain_head_file = str(tmp / "keys" / "audit-chain-head.json")
        self.monkeypatch = monkeypatch
        self.factory = factory
        self.clock = Clock(now)
        clock = self.clock

        class _AtTheClock(datetime):
            @classmethod
            def now(cls, tz=None):
                return clock().replace(tzinfo=tz) if tz is not None else clock()

        from app.services import audit_logger
        monkeypatch.setattr(audit_logger, "datetime", _AtTheClock)
        self.st = ai.ChainState(settings=settings, clock=self.clock)
        monkeypatch.setattr(ai, "_state", self.st)
        db = factory()
        if db.get(SystemSetting, ai.NAME_PURGE_MARKER) is None:
            db.add(SystemSetting(key=ai.NAME_PURGE_MARKER, value={"rows": 0}))
            db.commit()

    def setenv(self, name: str, value) -> None:
        """An .env input, as the process environment gives it (the chain reads its inputs from there)."""
        self.monkeypatch.setenv(name, str(value))

    def at(self, now: datetime) -> None:
        self.clock.at = now

    def seal_all(self, now: Optional[datetime] = None, limit: int = 400):
        if now is not None:
            self.clock.at = now
        result = None
        for _ in range(limit):
            result = ai.seal_pass(self.factory, st=self.st, now=self.clock())
            if result.stopped or not result.sealed:
                break
        return result
