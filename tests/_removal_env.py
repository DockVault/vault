"""A throwaway SQLite database with a chain of its own (tests/_erase_env.py), plus the table of removals of values
recorded under earlier levels, for the offline tests of rewriting audit rows (app/core/audit_rewrite.py,
app/core/audit_value_removal.py)."""
import uuid
from datetime import timedelta

from _erase_env import EraseEnv
from app.core import audit_chain_policy_seals as ps
from app.core import audit_privacy as ap
from app.core import audit_value_removal as vr
from app.core import retention
from app.core.models import AuditLog, AuditValueRemoval  # noqa: F401


class RemovalEnv(EraseEnv):
    def __init__(self, monkeypatch, tmp, levels=None, **kw):
        super().__init__(monkeypatch, tmp, **kw)
        self.removal_told = []
        monkeypatch.setattr(vr, "tell_administrators",
                            lambda event, facts, by=None: self.removal_told.append((event, dict(facts))))
        self.levels = dict(levels or {k: ap.FULL for k in ap.POLICY_KEYS})
        monkeypatch.setattr(vr, "in_force", lambda db: dict(self.levels))
        vr._cursors.clear()
        from app.core import audit_rewrite
        audit_rewrite._cursors.clear()

    def put(self, when, username="alice", **values):
        """An audit row at ``when``, with a full address and browser description unless told otherwise."""
        row = dict(id=uuid.uuid4(), action="file_uploaded", status="success", timestamp=when, username=username,
                   user_id=None, ip_address="203.0.113.9", user_agent="Mozilla/5.0 test",
                   endpoint="/vaults/{vault_id}/files", details={"n": 1}, seal_nonce=uuid.uuid4().bytes)
        row.update(values)
        with self.session() as db:
            db.add(AuditLog(**row))
            db.commit()
        return row["id"]

    def get(self, row_id):
        with self.session() as db:
            return db.get(AuditLog, row_id)

    def ask_removal(self, actor=None):
        with ps.change_transaction(self.engine) as w:
            return vr.request(w, actor or self.admin(f"admin{uuid.uuid4().hex[:6]}"))

    def cancel_removal(self, request_id, actor):
        with ps.change_transaction(self.engine) as w:
            return vr.cancel(w, request_id, actor)

    def removal_job(self):
        return vr.run_job(retention.Pass(self.session, now=self.clock()))

    def removal_row(self, request_id):
        with self.session() as db:
            return db.get(AuditValueRemoval, uuid.UUID(str(request_id)))

    def rewrite_seals(self):
        return [s for s in self.seals() if s.kind == "rewrite"]

    def week(self):
        """Seven days of passes and six hours: a removal's delay runs."""
        self.passes(24 * 7 + 6)


def until(env, check, step=6, hours=24 * 30):
    end = env.clock() + timedelta(hours=hours)
    while env.clock() < end and not check():
        env.clock.advance(hours=step)
        retention.run_pass(env.session, now=env.clock())
    return check()
