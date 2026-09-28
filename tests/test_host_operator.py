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
