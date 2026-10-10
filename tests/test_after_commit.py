"""The one after-commit dispatcher (app/core/after_commit.py).

A step queues what it wants done after its transaction commits; the handler of its kind receives it once the
outermost transaction commits, and nothing does when it ends any other way. Its listeners are added once, with the
models, before any session exists: a listener added to the Session class while a commit runs its listeners made
that commit raise ("deque mutated during iteration") after the rows were already in the database, which is what
happened when a module that listened on its own was first imported inside another module's notice delivery.
"""
import ast
import os
import subprocess
import sys
import textwrap
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import after_commit  # noqa: E402

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


@pytest.fixture
def db():
    session = sessionmaker(bind=create_engine("sqlite://"))()
    session.execute(text("SELECT 1"))
    yield session
    session.close()


@pytest.fixture
def got(monkeypatch):
    out = []
    monkeypatch.setitem(after_commit._HANDLERS, "test-kind", out.extend)
    return out


def test_queued_work_is_handed_over_after_the_commit_in_order(db, got):
    after_commit.later(db, "test-kind", 1)
    after_commit.later(db, "test-kind", 2)
    assert got == []
    db.commit()
    assert got == [1, 2]
    assert after_commit.pending(db, "test-kind") == []


def test_a_rollback_drops_the_work_and_a_later_commit_does_not_hand_it_over(db, got):
    after_commit.later(db, "test-kind", 1)
    db.rollback()
    db.execute(text("SELECT 1"))
    db.commit()
    assert got == []


def test_only_the_end_of_the_outermost_transaction_drops_the_work(db, got):
    after_commit.later(db, "test-kind", 1)
    after_commit._after_transaction_end(db, SimpleNamespace(parent=object()))
    assert after_commit.pending(db, "test-kind") == [1]
    after_commit._after_transaction_end(db, SimpleNamespace(parent=None))
    assert after_commit.pending(db, "test-kind") == []


def test_a_failing_handler_is_reported_and_neither_undoes_the_commit_nor_stops_the_others(db, got, monkeypatch,
                                                                                           capsys):
    def fail(items):
        raise ValueError("no")
    monkeypatch.setitem(after_commit._HANDLERS, "test-fails", fail)
    after_commit.later(db, "test-fails", 1)
    after_commit.later(db, "test-kind", 2)
    db.commit()
    assert got == [2]
    assert "test-fails: ValueError" in capsys.readouterr().out


def test_the_listeners_are_on_the_session_class_once_the_models_are_imported():
    from sqlalchemy import event
    from sqlalchemy.orm import Session
    import app.core.models  # noqa: F401
    assert event.contains(Session, "after_commit", after_commit._after_commit)
    assert event.contains(Session, "after_transaction_end", after_commit._after_transaction_end)


def test_a_module_first_imported_while_a_commit_hands_over_its_work_does_not_break_that_commit():
    """In a fresh process: an auditor right notice is committed while nothing has imported the legal holds
    module, and its delivery imports the web app (as the real delivery does), which imports it. The commit
    returns and the notice is delivered."""
    script = textwrap.dedent("""
        import sys
        from sqlalchemy import create_engine, text
        from sqlalchemy.orm import sessionmaker
        from app.core import auditor_rights
        assert "app.core.legal_holds" not in sys.modules
        assert "app.api.api_server" not in sys.modules
        delivered = []

        def deliver(notices):
            from app.api import api_server  # noqa: F401 -- as the real delivery does, first here
            delivered.extend(notices)

        auditor_rights.deliver = deliver
        db = sessionmaker(bind=create_engine("sqlite://"))()
        db.execute(text("SELECT 1"))
        auditor_rights.queue(db, {"event": "lapsed"})
        db.commit()
        assert "app.core.legal_holds" in sys.modules, "the delivery imported it"
        assert delivered == [{"event": "lapsed"}], delivered
        print("COMMITTED-AND-DELIVERED")
    """)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "tests")])
    run = subprocess.run([sys.executable, "-c", script], cwd=str(ROOT), env=env, capture_output=True, text=True,
                         timeout=300)
    assert run.returncode == 0 and "COMMITTED-AND-DELIVERED" in run.stdout, run.stdout[-2000:] + run.stderr[-4000:]
    assert "deque mutated" not in run.stderr


def test_importing_the_models_alone_installs_the_dispatcher():
    """Every session of the app uses the models, so a process that has imported them has the listeners before its
    first session: in a fresh process, nothing but the models imported."""
    script = textwrap.dedent("""
        import sys
        from sqlalchemy import event
        from sqlalchemy.orm import Session
        import app.core.models  # noqa: F401
        dispatcher = sys.modules.get("app.core.after_commit")
        assert dispatcher is not None, "the models did not import the dispatcher"
        assert event.contains(Session, "after_commit", dispatcher._after_commit)
        assert event.contains(Session, "after_transaction_end", dispatcher._after_transaction_end)
        print("INSTALLED")
    """)
    env = dict(os.environ)
    env["PYTHONPATH"] = os.pathsep.join([str(ROOT), str(ROOT / "tests")])
    run = subprocess.run([sys.executable, "-c", script], cwd=str(ROOT), env=env, capture_output=True, text=True,
                         timeout=300)
    assert run.returncode == 0 and "INSTALLED" in run.stdout, run.stdout[-1000:] + run.stderr[-3000:]


def _listens(path: Path):
    """Each (event name, line) of a call to SQLAlchemy's event.listen in ``path`` whose event is a session's
    transaction end."""
    tree = ast.parse(path.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Call) and getattr(node.func, "attr", getattr(node.func, "id", None)) == "listen":
            names = [a.value for a in node.args if isinstance(a, ast.Constant) and isinstance(a.value, str)]
            yield from ((n, node.lineno) for n in names if n in ("after_commit", "after_transaction_end",
                                                                 "after_rollback", "after_soft_rollback"))
        if isinstance(node, ast.Tuple):
            # audit_signal adds its listeners from a tuple of (name, fn) pairs.
            names = [e.value for e in node.elts if isinstance(e, ast.Constant) and isinstance(e.value, str)]
            yield from ((n, node.lineno) for n in names if n in ("after_commit", "after_transaction_end"))


def test_no_module_adds_a_transaction_end_listener_but_the_dispatcher_and_the_per_factory_audit_signal():
    """A module that needs work after a commit registers a handler; only the dispatcher (installed with the
    models) and the audit signal (installed on a session factory when the factory is made, app/core/database.py)
    add listeners for a transaction's end."""
    found = {}
    for path in sorted((ROOT / "app").rglob("*.py")):
        hits = list(_listens(path))
        if hits:
            found[path.relative_to(ROOT).as_posix()] = sorted({n for n, _ in hits})
    assert found == {"app/core/after_commit.py": ["after_commit", "after_transaction_end"],
                     "app/core/audit_signal.py": ["after_commit", "after_transaction_end"]}
