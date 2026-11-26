"""The host operator's account tool (python -m app.core.host_operator), offline: the checks it makes
before it changes anything. test_host_operator_live.py runs it inside a running stack, and
test_dockvault_accounts.py covers the dockvault.py side that drives it."""
import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

pytestmark = pytest.mark.unit


def test_the_host_tool_changes_nothing_unless_the_username_is_typed_again():
    from app.core.host_operator import confirmation_problem
    assert confirmation_problem("alice", "alice") is None
    for typed in (None, "", "Alice", "alice ", "bob"):
        assert confirmation_problem("alice", typed), typed
    assert confirmation_problem("", "")


def test_the_host_tool_temporary_password_is_strong():
    from app.core.host_operator import temporary_password
    seen = set()
    for _ in range(50):
        pw = temporary_password()
        assert len(pw) == 20
        assert any(c.islower() for c in pw) and any(c.isupper() for c in pw)
        assert any(c.isdigit() for c in pw) and any(not c.isalnum() for c in pw)
        seen.add(pw)
    assert len(seen) == 50


def _fresh_signal_worker(monkeypatch, publish):
    """Give this test its own signal queue and publisher thread, so the thread is started after the
    snapshot the tool takes, as it is in a real run (an earlier test may have started one already)."""
    import queue
    from app.core import audit_signal
    monkeypatch.setattr(audit_signal, "_queue", queue.Queue(maxsize=audit_signal.MAX_QUEUE))
    monkeypatch.setattr(audit_signal, "_worker_pid", None)
    monkeypatch.setattr(audit_signal, "_publish", publish)
    return audit_signal


def test_the_host_tool_does_not_wait_out_its_budget_for_the_signal_publisher(monkeypatch):
    # The Activity signal's publisher is a thread that runs as long as the process. The tool used to
    # join it with the rest of the threads its run started, so every change it made sat silent for the
    # whole budget (30 s) before printing its answer.
    import threading
    import time
    import uuid
    from app.core.host_operator import _wait_for_background_work
    audit_signal = _fresh_signal_worker(monkeypatch, lambda text: None)
    started_before = set(threading.enumerate())
    assert audit_signal.enqueue(str(uuid.uuid4()), "accounts") is True
    assert any(t.name == "audit-signal" and t not in started_before for t in threading.enumerate())
    began = time.monotonic()
    _wait_for_background_work(started_before, timeout=3.0)
    assert time.monotonic() - began < 1.5


def test_the_host_tool_sends_its_signals_before_it_exits(monkeypatch):
    # Skipping the publisher alone would drop the signals for the rows this run wrote, so the Activity
    # page would show the host operator's change only at its slower poll. They are flushed first.
    import threading
    import time
    import uuid
    from app.core.host_operator import _wait_for_background_work
    published = []

    def slow_publish(text):
        time.sleep(0.3)
        published.append(text)

    audit_signal = _fresh_signal_worker(monkeypatch, slow_publish)
    started_before = set(threading.enumerate())
    row_id = str(uuid.uuid4())
    assert audit_signal.enqueue(row_id, "accounts") is True
    _wait_for_background_work(started_before, timeout=3.0)
    assert len(published) == 1 and row_id in published[0]


def test_the_host_tool_lists_who_may_manage_users_without_being_an_administrator():
    # Read-only. An account demoted before 0.33.0 kept the administrator's defaults, stored with no
    # granter; a permission an administrator granted names them. Administrators themselves are not listed.
    import tempfile
    from pathlib import Path

    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker

    from app.core.host_operator import user_managers
    from app.core.models import RoleEnum, User, UserEndpointPermission

    with tempfile.TemporaryDirectory() as tmp:
        engine = sa.create_engine(f"sqlite:///{Path(tmp) / 'managers.db'}")
        for model in (User, UserEndpointPermission):
            model.__table__.create(engine)
        db = sessionmaker(bind=engine)()
        people = {}
        for name, role in (("ada", RoleEnum.ADMIN), ("bob", RoleEnum.USER), ("dana", RoleEnum.USER),
                           ("carol", RoleEnum.USER), ("xena", RoleEnum.EXTERNAL)):
            people[name] = User(username=name, email=None, password_hash="x", role=role, is_active=True,
                                is_locked=False)
            db.add(people[name])
        db.commit()
        rows = [("ada", "USER_MANAGE", None), ("ada", "USER_VIEW", None),     # an administrator's own
                ("bob", "USER_MANAGE", None), ("bob", "USER_VIEW", None),     # kept after a demotion
                ("dana", "USER_MANAGE", "ada"), ("dana", "USER_VIEW", "ada"),  # granted on purpose
                ("carol", "VAULT_VIEW", None),                                 # an ordinary default
                ("xena", "USER_VIEW", "ada")]
        for name, group, by in rows:
            db.add(UserEndpointPermission(user_id=people[name].id, endpoint_group=group,
                                          granted_by=people[by].id if by else None))
        db.commit()
        listed = {a["username"]: a for a in user_managers(db)}
        db.close()
        engine.dispose()

    assert sorted(listed) == ["bob", "dana", "xena"]
    assert [(p["group"], p["granted_by"]) for p in listed["bob"]["permissions"]] == [
        ("USER_MANAGE", None), ("USER_VIEW", None)]
    assert [(p["group"], p["granted_by"]) for p in listed["dana"]["permissions"]] == [
        ("USER_MANAGE", "ada"), ("USER_VIEW", "ada")]
    assert (listed["xena"]["role"], listed["xena"]["active"]) == ("external", True)
    assert all(p["granted_at"].endswith("Z") for p in listed["bob"]["permissions"])


def test_the_host_tool_writes_the_recording_alerts_its_rows_raised_before_it_exits(monkeypatch, tmp_path):
    # A server writes the recording levels' alerts from the thread that refreshes the levels; this tool never
    # starts it. A row it wrote while the levels could not be read raised an alert that stayed queued and was
    # lost at exit, so nobody learned that the row had been written without them.
    import threading
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from app.core import audit_privacy as ap
    from app.core.host_operator import _wait_for_background_work
    from app.core.models import SecurityAlert
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'alerts.db'}")
    SecurityAlert.__table__.create(engine)
    monkeypatch.setattr(ap, "_default_session_factory", sessionmaker(bind=engine))
    ap._reset_for_tests()
    try:
        started_before = set(threading.enumerate())
        assert ap.raise_alert(ap.FAILED, "PolicyUnavailable", "second_factor_admin_reset") is True
        _wait_for_background_work(started_before, timeout=3.0)
        assert ap.pending_alerts() == []
        db = sessionmaker(bind=engine)()
        alerts = db.query(SecurityAlert).all()
        assert [(a.event_type, a.details["action"]) for a in alerts] == [
            (ap.ALERT_EVENT, "second_factor_admin_reset")]
        db.close()
    finally:
        ap._reset_for_tests()
        engine.dispose()


STOPPED = {"ok": False, "error": "The account tool stopped before it could answer."}


class _StartUpExits:
    """An import finder that answers for the web app the way its start-up does when it refuses this
    container's configuration: a message on standard error, then SystemExit(1)."""

    def find_spec(self, name, path=None, target=None):
        if name == "app.api.api_server":
            import sys
            print("DockVault API startup failed [made-up]: refused at db.example.internal", file=sys.stderr)
            raise SystemExit(1)
        return None


WHAT_STOPPED = {"while it imports": "ModuleNotFoundError", "when its start-up exits": "SystemExit",
                "while it works": "RuntimeError"}


@pytest.mark.parametrize("where", list(WHAT_STOPPED))
def test_the_host_tool_answers_once_when_something_unexpected_stops_it(monkeypatch, capsys, where):
    # Its answer is one JSON object on standard output, which the tooling reads. Something nothing expected
    # (the database out of reach, say) used to escape, so nothing at all was printed there: the answer kept
    # for that case was never written. Now it is, with exit status 1, and what happened is on standard error.
    import json
    import sys
    from app.core import host_operator
    if where == "while it imports":
        # Importing the web app is the first thing it does; a module set to None cannot be imported.
        monkeypatch.setitem(sys.modules, "app.api.api_server", None)
    elif where == "when its start-up exits":
        monkeypatch.delitem(sys.modules, "app.api.api_server", raising=False)
        monkeypatch.setattr(sys, "meta_path", [_StartUpExits(), *sys.meta_path])
    else:
        def stops(args, api):
            raise RuntimeError("the database at db.example.internal is out of reach")
        monkeypatch.setattr(host_operator, "load_the_stored_settings", lambda: None)
        monkeypatch.setattr(host_operator, "_run", stops)
    code = host_operator.run(["zk-status"])
    out, err = capsys.readouterr()
    assert code == 1
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [STOPPED]
    assert "Traceback" in err and WHAT_STOPPED[where] in err
    assert "db.example.internal" not in out


def _settings_database(tmp_path, monkeypatch, rows=()):
    """A throwaway database holding the administrators' saved settings, as this process's database, and a copy
    of the settings that holds nothing yet (as in a process that has just started)."""
    import sqlalchemy as sa
    from sqlalchemy.orm import sessionmaker
    from app.core import database
    from app.core import settings_registry as registry
    import json
    engine = sa.create_engine(f"sqlite:///{tmp_path / 'settings.db'}")
    factory = sessionmaker(bind=engine)
    with factory() as db:
        # The table as the model reads it, without the reference to the accounts' table.
        db.execute(sa.text("CREATE TABLE managed_settings (key VARCHAR(64) PRIMARY KEY, value JSON, version BIGINT "
                           "NOT NULL, updated_by CHAR(32), updated_by_name VARCHAR(255), updated_at DATETIME NOT NULL)"))
        for version, (key, value) in enumerate(rows, start=1):
            db.execute(sa.text("INSERT INTO managed_settings (key, value, version, updated_at) "
                               "VALUES (:key, :value, :version, '2026-11-25 10:00:00')"),
                       {"key": key, "value": json.dumps(value), "version": version})
        db.commit()
    monkeypatch.setattr(database, "SessionLocal", factory)
    monkeypatch.setattr(registry, "_cache", registry._Cache())
    registry.all_specs()
    return registry


def test_the_host_tool_reads_the_settings_an_administrator_saved_before_it_acts(tmp_path, monkeypatch):
    """Passkeys are required for the role "user" in this vault. The tool starts no server, and the settings are
    answered from a copy that only a server's start filled: to the tool passkeys were "optional", whatever was
    saved. Lifting the requirement for an account whose browser cannot make a passkey (the break-glass the
    setting's own help names) was refused for every account in every vault: "there is nothing to lift"."""
    import types
    from app.core import host_operator
    from app.core import webauthn_settings as wss
    registry = _settings_database(tmp_path, monkeypatch, rows=[
        (wss.MODE, wss.REQUIRED_FOR_ROLES), (wss.REQUIRED_ROLES, ["user"])])
    alice = types.SimpleNamespace(role="user", passkey_requirement_cleared_at=None)
    # As the tool found it: nothing loaded, the defaults.
    assert registry.stamp() is None and wss.mode() == wss.OPTIONAL
    assert "there is nothing to lift" in wss.lifting_refusal(alice)
    # Read through this process's own database sessions, named: the registry's usual way in waits for a server's
    # start, which this tool never makes.
    from app.core import database
    asked, read = [], registry.refresh
    monkeypatch.setattr(registry, "refresh", lambda factory=None: (asked.append(factory), read(factory))[1])
    host_operator.load_the_stored_settings()
    assert asked == [database.SessionLocal]
    assert registry.stamp() == 2 and wss.mode() == wss.REQUIRED_FOR_ROLES and wss.required_roles() == ("user",)
    assert wss.lifting_refusal(alice) is None
    # A vault that saved nothing is read too: its settings are the defaults, and the tool goes on.
    monkeypatch.setattr(registry, "_cache", registry._Cache())
    import sqlalchemy as sa
    from app.core import database
    with database.SessionLocal() as db:
        db.execute(sa.text("DELETE FROM managed_settings"))
        db.commit()
    host_operator.load_the_stored_settings()
    assert registry.stamp() == 0 and wss.mode() == wss.OPTIONAL


def test_the_host_tool_refuses_in_words_when_the_saved_settings_cannot_be_read(tmp_path, monkeypatch, capsys):
    """The settings could not be read while the database answers (the table out of reach). The read raises
    nothing and leaves the copy empty: gone on, the tool would have acted on the defaults, which is what it did
    before. It refuses, and says why; nothing of the action runs."""
    import json
    import sys
    import types
    from app.core import host_operator
    registry = _settings_database(tmp_path, monkeypatch)
    monkeypatch.setattr(registry, "refresh", lambda factory=None: False)     # read nothing, raised nothing
    with pytest.raises(host_operator._Answer) as refused:
        host_operator.load_the_stored_settings()
    assert refused.value.code == 2 and refused.value.obj == {"ok": False, "error": host_operator.SETTINGS_NOT_READ}
    assert registry.stamp() is None
    assert "could not be read, so nothing was done" in host_operator.SETTINGS_NOT_READ
    capsys.readouterr()                # the registry's own warning, said where this test called it
    # Through the whole command: the refusal is the one answer, with the refusal's exit status, and the action
    # is never reached.
    reached = []
    monkeypatch.setitem(sys.modules, "app.api.api_server", types.ModuleType("app.api.api_server"))
    monkeypatch.setattr(host_operator, "_run", lambda args, api: reached.append(args.action))
    monkeypatch.setattr(host_operator, "_wait_for_background_work", lambda started_before: None)
    code = host_operator.run(["clear-passkey-requirement", "--username", "alice", "--confirm-username", "alice"])
    out, _err = capsys.readouterr()
    assert code == 2 and reached == []
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [
        {"ok": False, "error": host_operator.SETTINGS_NOT_READ}]
    assert "db.example.internal" not in out


def test_a_database_out_of_reach_is_answered_stopped_with_its_traceback(tmp_path, monkeypatch, capsys):
    """The database does not answer at all. The settings' read raises nothing, so the tool asks the database once
    more itself: that raises, and the tool answers as it always did when something stopped it: the one line, exit
    status 1, and the traceback on standard error. It is not told as settings that could not be read."""
    import json
    import sys
    import types
    from sqlalchemy.exc import OperationalError
    from app.core import database, host_operator
    _settings_database(tmp_path, monkeypatch)

    class Session:
        def __enter__(self):
            return self

        def __exit__(self, *exc):
            return False

        def execute(self, *a, **kw):
            raise OperationalError("SELECT 1", {}, RuntimeError("could not connect to db.example.internal"))

        def query(self, *a, **kw):
            raise OperationalError("SELECT", {}, RuntimeError("could not connect to db.example.internal"))

        def close(self):
            pass
    monkeypatch.setattr(database, "SessionLocal", Session)
    monkeypatch.setitem(sys.modules, "app.api.api_server", types.ModuleType("app.api.api_server"))
    monkeypatch.setattr(host_operator, "_wait_for_background_work", lambda started_before: None)
    code = host_operator.run(["lookup", "--username", "alice"])
    out, err = capsys.readouterr()
    assert code == 1
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [
        {"ok": False, "error": "The account tool stopped before it could answer."}]
    assert "Traceback" in err and "db.example.internal" in err


def test_the_host_tool_loads_the_settings_before_the_action_and_once(tmp_path, monkeypatch, capsys):
    import sys
    import types
    from app.core import host_operator
    order = []
    monkeypatch.setitem(sys.modules, "app.api.api_server", types.ModuleType("app.api.api_server"))
    monkeypatch.setattr(host_operator, "load_the_stored_settings", lambda: order.append("the settings"))

    def action(args, api):
        order.append("the action")
        host_operator._answer({"ok": True})
    monkeypatch.setattr(host_operator, "_run", action)
    monkeypatch.setattr(host_operator, "_wait_for_background_work", lambda started_before: None)
    assert host_operator.run(["lookup", "--username", "alice"]) == 0
    assert order == ["the settings", "the action"]
    capsys.readouterr()


class _DriverError(Exception):
    """What the database driver raises, carrying PostgreSQL's code for the error as psycopg2 does."""

    def __init__(self, pgcode):
        super().__init__("canceling statement")
        self.pgcode = pgcode


def _database_refuses(monkeypatch, pgcode):
    from sqlalchemy.exc import OperationalError
    from app.core import host_operator

    def refused(args, api):
        raise OperationalError("UPDATE users SET is_locked=false WHERE users.id = %(id)s", {},
                               _DriverError(pgcode))
    monkeypatch.setattr(host_operator, "_run", refused)
    # The stored settings are read before any action; here they read as nothing saved, so the action is reached.
    monkeypatch.setattr(host_operator, "load_the_stored_settings", lambda: None)
    return host_operator


def test_the_host_tool_answers_busy_when_it_waits_too_long_for_an_account(monkeypatch, capsys):
    # Its changes take the account's turn on the same connections as the web app, with the same lock wait
    # (5 s). When the wait ran out, the web app answered "busy" and the tool answered that it stopped, with
    # exit status 1 and a traceback. Now it is refused the way the web app is: try again in a moment.
    import json
    host_operator = _database_refuses(monkeypatch, "55P03")
    code = host_operator.run(["unlock", "--username", "alice", "--confirm-username", "alice"])
    out, err = capsys.readouterr()
    assert code == 2
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [
        {"ok": False, "busy": True, "error": "The vault is busy with this right now. Try again in a moment."}]
    assert "Traceback" not in err


def test_the_host_tool_still_stops_on_any_other_database_error(monkeypatch, capsys):
    import json
    host_operator = _database_refuses(monkeypatch, "08006")   # connection_failure
    code = host_operator.run(["unlock", "--username", "alice", "--confirm-username", "alice"])
    out, err = capsys.readouterr()
    assert code == 1
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [STOPPED]
    assert "Traceback" in err and "OperationalError" in err


def test_the_host_tool_counts_a_passkey_as_a_second_factor_as_the_web_does():
    # `dockvault.py accounts` showed the second factor from the authenticator alone, so an account that set up a
    # passkey and nothing else was shown with none. A passkey that was not retired counts, whether or not passkeys are
    # switched on (app/services/sso_sign_in.py accounts_that_set_up_a_factor); a retired one, and an authenticator
    # that is not active, do not.
    import types
    import uuid
    from datetime import datetime

    from _memory_db import MemoryDB
    from app.core.host_operator import _describe
    from app.core.models import RoleEnum, SecondFactorEnrollment, User, WebAuthnCredential

    def account(name):
        return types.SimpleNamespace(id=uuid.uuid4(), username=name, email=None, role=RoleEnum.USER, is_active=True,
                                     is_locked=False, locked_until=None, last_login=None)
    keys_only, retired_only, code_only, both, nothing = (account(n) for n in ("keys", "retired", "code", "both", "none"))
    now = datetime.utcnow()
    db = MemoryDB({User: [keys_only, retired_only, code_only, both, nothing], WebAuthnCredential: [
        types.SimpleNamespace(id=uuid.uuid4(), user_id=keys_only.id, retired_at=None),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=keys_only.id, retired_at=None),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=retired_only.id, retired_at=now),
        types.SimpleNamespace(id=uuid.uuid4(), user_id=both.id, retired_at=None)],
        SecondFactorEnrollment: [
            types.SimpleNamespace(id=uuid.uuid4(), user_id=code_only.id, status="active"),
            types.SimpleNamespace(id=uuid.uuid4(), user_id=both.id, status="active"),
            types.SimpleNamespace(id=uuid.uuid4(), user_id=nothing.id, status="pending")]})
    seen = {a.username: {k: _describe(db, a)[k] for k in ("second_factor", "authenticator", "passkeys")}
            for a in (keys_only, retired_only, code_only, both, nothing)}
    assert seen == {
        "keys": {"second_factor": True, "authenticator": False, "passkeys": 2},
        "retired": {"second_factor": False, "authenticator": False, "passkeys": 0},
        "code": {"second_factor": True, "authenticator": True, "passkeys": 0},
        "both": {"second_factor": True, "authenticator": True, "passkeys": 1},
        "none": {"second_factor": False, "authenticator": False, "passkeys": 0}}
