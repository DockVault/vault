"""A throwaway SQLite database with a chain of its own (tests/_audit_chain_env.py), plus every table a per-person
erase reads or changes (app/core/person_erase.py STORES), for the offline tests of the erase."""
import uuid
from datetime import timedelta

import sqlalchemy as sa

from _audit_chain_env import Env
from app.core import audit_chain_policy_seals as ps
from app.core import audit_integrity as ai
from app.core import person_erase as pe
from app.core import retention
from app.core.models import (AccountInvitation, ActivitySavedSearch, AdminGrant, AuditPrivacyPolicy,  # noqa: F401
                             CredentialChange, EraseRequest, Note, Notification, RoleEnum, SecurityAlert,
                             SecurityRecord, TemporaryCredential, User, UserSSHKey)

EXTRA = (EraseRequest, TemporaryCredential, AccountInvitation, SecurityRecord, SecurityAlert, CredentialChange,
         AdminGrant, ActivitySavedSearch, Notification, Note, AuditPrivacyPolicy, UserSSHKey)


def add_tables(engine, models=EXTRA):
    """Copies of ``models``' tables (columns only, server defaults made SQLite's), as Env makes its own."""
    copies = sa.MetaData()
    for model in models:
        columns = []
        for column in model.__table__.columns:
            default = column.server_default
            if default is not None and "now()" in str(getattr(default, "arg", "")):
                default = sa.schema.DefaultClause(sa.text("CURRENT_TIMESTAMP"))
            elif default is not None:
                default = sa.schema.DefaultClause(default.arg)
            columns.append(sa.Column(column.name, column.type, primary_key=column.primary_key, nullable=True,
                                     server_default=default))
        sa.Table(model.__tablename__, copies, *columns)
    copies.create_all(engine)


class EraseEnv(Env):
    def __init__(self, monkeypatch, tmp, **kw):
        super().__init__(monkeypatch, tmp, **kw)
        add_tables(self.engine)
        self.told = []
        monkeypatch.setattr(pe, "announce", lambda event, details, by=None: self.told.append((event, dict(details))))
        monkeypatch.setattr(pe, "WAIT_RULES", [])

    def admin(self, name="ada"):
        uid = uuid.uuid4()
        with self.session() as db:
            db.add(User(id=uid, username=name, email=f"{name}@example.com", password_hash="x", role=RoleEnum.ADMIN,
                        is_active=True))
            db.commit()
        return self.session().get(User, uid)

    def ask(self, name, actor=None):
        with ps.change_transaction(self.engine) as w:
            return pe.request(w, name, actor or self.admin(f"admin{uuid.uuid4().hex[:6]}"))

    def cancel(self, request_id, actor):
        with ps.change_transaction(self.engine) as w:
            return pe.cancel(w, request_id, actor)

    def passes(self, hours, step=6):
        """The pruner every ``step`` hours for ``hours`` hours."""
        end = self.clock() + timedelta(hours=hours)
        while self.clock() < end:
            self.clock.advance(hours=step)
            retention.run_pass(self.session, now=self.clock())

    def erase_job(self):
        from app.core import audit_chain_erase
        return audit_chain_erase.run_job(retention.Pass(self.session, now=self.clock()))

    def request_row(self, request_id):
        with self.session() as db:
            return db.get(EraseRequest, uuid.UUID(str(request_id)))

    def erase_seals(self):
        return [s for s in self.seals() if s.kind == "erase"]

    def view(self):
        return ai.state().view
