"""Waiting, on a running stack, for the web process to have read the audit log's integrity chain.

The web process reads the chain at its pruner's first pass, about a minute after it starts (longer on a large
chain). Until then GET /settings/managed shows no value of a setting the chain records as in force (the row says
``chain_read`` false), and lists no change waiting (``pending_chain.read`` false). A test that reads either waits
here first, so that it holds right after the stack or its web container was started too."""
import time


def wait_for_chain_read(client, timeout=300.0, step=2.0):
    """GET /settings/managed's body once the web process has read the chain; fails the test after ``timeout``."""
    deadline = time.monotonic() + timeout
    while True:
        r = client.get("/settings/managed")
        assert r.status_code == 200, r.text
        body = r.json()
        unread = [row["key"] for row in body.get("settings") or [] if row.get("chain_read") is False]
        if (body.get("pending_chain") or {}).get("read") and not unread:
            return body
        if time.monotonic() > deadline:
            raise AssertionError(f"the web process had not read the audit log's integrity chain after {timeout:.0f} s "
                                 f"(settings not read yet: {unread})")
        time.sleep(step)
