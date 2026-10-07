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
        monkeypatch.setattr(host_operator, "_run", stops)
    code = host_operator.run(["zk-status"])
    out, err = capsys.readouterr()
    assert code == 1
    assert [json.loads(line) for line in out.splitlines() if line.strip()] == [STOPPED]
    assert "Traceback" in err and WHAT_STOPPED[where] in err
    assert "db.example.internal" not in out
