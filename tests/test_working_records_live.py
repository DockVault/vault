"""Working records on a running stack (app/core/working_records.py, app/core/retention.py).

A pass deletes invitations that ended 30 days ago and keeps a pending one; it deletes password reset links,
one-time codes and email-change codes used or expired 30 days ago and keeps a live one; each job records what it
deleted. Notifications run on a throwaway database of their own: with NOTIFICATION_RETENTION_DAYS in .env the
chain starts with that window, older notifications go, read or not, and a shorter window written into the
database behind the panel's back deletes none sooner (it is reported, and not acted on). The panel lists the
new settings, and giving notifications a window is a change that deletes sooner, so it waits (and is cancelled
here, so the stack's chain and database still agree). The web app's own log-access writer is sized by the cap.
test_retention.py and test_log_sink_cap.py cover the rules offline.
"""
import json
import uuid

import pytest

from _account_change_helpers import in_api_container, psql, second_admin
from _throwaway_db import PREAMBLE, run_in, throwaway_database
from test_retention_live import _cancel_waiting, _put, _row, _run_pass, _wait_for, chain_started  # noqa: F401

pytestmark = pytest.mark.integration

KEY = "notification_retention_days"


def _admin_id():
    return psql("SELECT id FROM users WHERE username = 'admin'")


def _count(table, ids):
    listed = ", ".join(f"'{i}'" for i in ids)
    return int(psql(f"SELECT count(*) FROM {table} WHERE id IN ({listed})"))


def test_a_pass_deletes_ended_invitations_and_used_or_expired_links_and_codes_and_records_it():
    admin_id = _admin_id()
    tag = uuid.uuid4().hex[:10]
    ended = {"account_invitations": [], "password_reset_tokens": [], "otp_codes": [], "email_change_codes": []}
    live = {k: [] for k in ended}

    def invitation(expires, accepted=None):
        i = str(uuid.uuid4())
        psql("INSERT INTO account_invitations (id, username, role, token_prefix, token_hash, expires_at, accepted_at, "
             f"created_at) VALUES ('{i}', 'wr-{tag}-{len(ended['account_invitations']) + len(live['account_invitations'])}'"
             f", 'user', '{uuid.uuid4().hex[:12]}', '{uuid.uuid4().hex * 2}', {expires}, {accepted or 'NULL'}, "
             "now() - interval '400 days')")
        return i

    def link(expires, consumed=None):
        i = str(uuid.uuid4())
        psql("INSERT INTO password_reset_tokens (id, user_id, token_prefix, token_hash, expires_at, consumed_at, "
             f"created_at) VALUES ('{i}', '{admin_id}', '{uuid.uuid4().hex[:12]}', '{uuid.uuid4().hex * 2}', {expires}, "
             f"{consumed or 'NULL'}, now() - interval '400 days')")
        return i

    def code(expires, consumed=None):
        i = str(uuid.uuid4())
        psql("INSERT INTO otp_codes (id, purpose, user_id, code_hash, attempts, max_attempts, expires_at, consumed_at, "
             f"created_at) VALUES ('{i}', 'wr-test', '{admin_id}', '{uuid.uuid4().hex * 2}', 0, 3, {expires}, "
             f"{consumed or 'NULL'}, now() - interval '400 days')")
        return i

    def email_code(expires):
        i = str(uuid.uuid4())
        psql("INSERT INTO email_change_codes (id, user_id, new_email, code_hash, expires_at, created_at) "
             f"VALUES ('{i}', '{admin_id}', 'wr-{tag}@example.com', '{uuid.uuid4().hex * 2}', {expires}, "
             "now() - interval '400 days')")
        return i

    long_ago, recent = "now() - interval '31 days'", "now() - interval '29 days'"
    soon = "now() + interval '1 day'"
    ended["account_invitations"] += [invitation(long_ago), invitation(soon, accepted=long_ago)]
    live["account_invitations"] += [invitation(soon), invitation(recent)]
    ended["password_reset_tokens"] += [link(long_ago), link(soon, consumed=long_ago)]
    live["password_reset_tokens"] += [link(soon), link(soon, consumed=recent)]
    ended["otp_codes"] += [code(long_ago)]
    live["otp_codes"] += [code(soon)]
    ended["email_change_codes"] += [email_code(long_ago)]
    live["email_change_codes"] += [email_code(recent)]
    try:
        # The web app's own pruner may take a pass meanwhile: what the rows became is what counts.
        _run_pass()
        for table in ended:
            assert _count(table, ended[table]) == 0, table
            assert _count(table, live[table]) == len(live[table]), table
        recorded = psql("SELECT details->>'job' || ':' || (details->>'table') FROM audit_logs WHERE action = "
                        "'retention_pruned' AND timestamp > now() - interval '5 minutes'").splitlines()
        assert {"invitations:account_invitations", "one_time_proofs:password_reset_tokens",
                "one_time_proofs:otp_codes", "one_time_proofs:email_change_codes"} <= set(recorded), recorded
    finally:
        for table in ended:
            listed = ", ".join(f"'{i}'" for i in ended[table] + live[table])
            psql(f"DELETE FROM {table} WHERE id IN ({listed})")


NOTIFICATIONS = PREAMBLE + r'''
from app.core import settings_registry as registry, working_records

def jobs():
    done = retention.run_pass(SessionLocal, engine=engine)
    return None if done is None else {n: (r.deleted if r else None) for n, r in done}

from app.core.models import Notification, RoleEnum, User

PERSON = uuid.uuid4()
db = SessionLocal()
db.add(User(id=PERSON, username="wr-person", email="wr@example.com", password_hash="x", role=RoleEnum.USER,
            is_active=True))
db.commit()
db.close()

def notification(days, read=False):
    db = SessionLocal()
    n = Notification(id=uuid.uuid4(), user_id=PERSON, type="share_received", title="t", is_read=read,
                     created_at=datetime.utcnow() - timedelta(days=days))
    db.add(n)
    db.commit()
    nid = str(n.id)
    db.close()
    return nid

def left(ids):
    with engine.begin() as c:
        return sorted(str(r[0]) for r in c.execute(text("SELECT id FROM notifications")).all() if str(r[0]) in ids)

out = {"first": jobs()}          # the chain starts here, with the .env window
kept = [notification(60), notification(60, read=True)]
gone = [notification(100), notification(100, read=True)]
out["pass"] = jobs()
out["left"] = left(kept + gone)
out["kept"] = sorted(kept)
# A shorter window written into the database without the server's key.
with engine.begin() as c:
    c.execute(text("INSERT INTO managed_settings (key, value, version, updated_at) VALUES (:k, '30', "
                   "(SELECT coalesce(max(version), 0) + 1 FROM managed_settings), now()) ON CONFLICT (key) DO "
                   "UPDATE SET value = '30', version = excluded.version"), {"k": working_records.NOTIFICATION_DAYS_KEY})
registry.refresh(SessionLocal)
older = notification(95)
out["registry"] = registry.resolve(working_records.NOTIFICATION_DAYS_KEY)
out["behind"] = jobs()
out["left_behind"] = left(kept + [older])
out["failures"] = sorted(ai.status(st)["failures"])
print(json.dumps(out))
'''


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def test_notifications_go_after_the_chains_window_and_a_window_written_behind_its_back_deletes_none_sooner(throwaway):
    out = run_in(throwaway, NOTIFICATIONS, env={"NOTIFICATION_RETENTION_DAYS": "90"})
    assert out["first"] is not None, out
    assert out["pass"]["notifications"] == 2, out
    assert out["left"] == out["kept"]
    assert out["registry"] == 30
    # The job ran on the chain's 90 days: the 95-day-old one went, the 60-day-old ones stayed.
    assert out["behind"]["notifications"] == 1, out
    assert out["left_behind"] == out["kept"]
    assert "unjustified-input" in out["failures"], out["failures"]


def test_the_panel_lists_the_working_record_settings_and_a_notification_window_waits(admin):
    rows = {r["key"]: r for r in admin.get("/settings/managed").json()["settings"]}
    assert (rows[KEY]["value"], rows[KEY]["unlimited"], rows[KEY]["min"], rows[KEY]["group"]) == (0, 0, 30, "retention")
    sink = rows["log_pull_sink_max_mb"]
    assert (sink["value"], sink["editable"], sink["env"]) == (15, "env_only", "LOG_PULL_SINK_MAX_MB")
    for fixed in ("ended_invitation_days", "ended_one_time_proof_days"):
        assert (rows[fixed]["value"], rows[fixed]["editable"]) == (30, "fixed")
    try:
        with second_admin(admin) as (account, client):
            r = _put(client, account["_password"], KEY, 90)
            assert r.status_code == 200, r.text
            body = r.json()
            assert body["status"] == "pending" and body["change"]["new"] == 90, body
            pending = [p for p in admin.get("/settings/managed").json()["pending"] if p["key"] == KEY]
            assert [p["id"] for p in pending] == [body["change"]["id"]]
            assert admin.post(f"/settings/managed/changes/{body['change']['id']}/cancel").status_code == 200
        assert _row(admin, KEY)["value"] == 0
    finally:
        _cancel_waiting(admin, KEY)


def test_the_web_apps_own_log_access_file_is_sized_by_the_cap():
    out = in_api_container(
        "import json, os\nfrom app.services import log_sink\n"
        "path = log_sink._SINK_PATH\n"
        "print(json.dumps([log_sink._SINK_MAX_BYTES, log_sink._SINK_BACKUPS, log_sink.is_active(), "
        "os.path.exists(path), len(log_sink.read_tail(path).encode()) if os.path.exists(path) else -1]))\n")
    per_file, backups, _active, exists, read = json.loads(out.stdout.strip().splitlines()[-1])
    assert (per_file, backups) == (5 * 1024 * 1024, 2)
    if exists:
        assert 0 <= read <= 5 * 1024 * 1024
