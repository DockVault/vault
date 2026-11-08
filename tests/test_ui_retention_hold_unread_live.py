"""UI -- Settings -> Activity and records on a web process that has not read the audit log's integrity chain through,
because the chain does not check out (a seal before the head record's changed), so no seal can be written either.

The hold's row shows no value and offers "Turn it on now": pressing it, and giving the password, turns the hold on in
the real server (no answer is served by the test): the database holds it, no seal is written, and the row still says
the value in force is not known. A number the chain holds cannot be changed meanwhile: the server refuses it (409)
saying the chain has not been read through and why, never that the change deletes records sooner. Once the seal is
put right and the chain read through, the next pass seals the hold from the database.

A throwaway database (tests/_throwaway_db.py) gets a chain of its own; the web app is started in the web container
against it on a port of its own, and the browser's requests to the stack's address are carried to that process, so
the page runs on the stack's own origin. That needs the web container's address to be reachable from the host the
tests run on (Linux); where it is not (a container network of its own, as on Docker Desktop), the test is skipped.
tests/test_audit_chain_view_trust.py covers the rules offline.
"""
import json
import secrets
import socket
import subprocess
import time

import pytest
import requests
from playwright.sync_api import Browser, expect

from _account_change_helpers import API
from _settings_ui import show_advanced
from _throwaway_db import PREAMBLE, run_in, throwaway_database
from conftest import BASE_URL

pytestmark = pytest.mark.ui

KEY = "h" * 64
PORT = 18764
ADMIN = "holdadmin"

# The chain sealed, a seal before the head record's changed, and the web app started on it, on its own.
START = PREAMBLE + r'''
import subprocess
for _ in range(50):
    r = ai.seal_pass(SessionLocal, st=st, now=now)
    if r.stopped or not r.sealed:
        break
with engine.begin() as c:
    seals = c.execute(text("SELECT count(*) FROM audit_seals")).scalar()
    c.execute(text("UPDATE audit_seals SET row_bytes = row_bytes + 1 WHERE seq = 2"))
engine.dispose()
env = dict(os.environ, ADMIN_USERNAME=os.environ["HOLD_ADMIN"], ADMIN_PASSWORD=os.environ["HOLD_PASSWORD"],
           ADMIN_EMAIL="holdadmin@example.com", VAULT_LOG_SINK_OWNER="test", API_USE_HTTPS="false", ALLOWED_HOSTS="")
env.pop("ADMIN_PASSWORD_FILE", None)
log = open(f"/tmp/{name}-web.log", "w")
p = subprocess.Popen([sys.executable, "-m", "uvicorn", "app.api.api_server:app", "--host", "0.0.0.0", "--port",
                      os.environ["HOLD_PORT"]], env=env, stdin=subprocess.DEVNULL, stdout=log,
                     stderr=subprocess.STDOUT, start_new_session=True)
with open(f"/tmp/{name}-web.pid", "w") as fh:
    fh.write(str(p.pid))
print(json.dumps({"stopped": r.stopped, "seals": seals}))
'''

# After the web process stopped: what the database holds, then the seal put right and a pass.
AFTER = PREAMBLE + r'''
def q(sql):
    with engine.begin() as c:
        res = c.execute(text(sql))
        return res.fetchall() if res.returns_rows else []
out = {"seals": q("SELECT count(*) FROM audit_seals")[0][0],
       "hold": [row[0] for row in q("SELECT value FROM managed_settings WHERE key = 'logs_hold'")]}
q("UPDATE audit_seals SET row_bytes = row_bytes - 1 WHERE seq = 2")
out["read"] = ai.read_view(engine, st)
retention.apply_waiting_changes(retention.Pass(SessionLocal, now=datetime.now(timezone.utc).replace(tzinfo=None)))
last = q("SELECT seq, kind, detail FROM audit_seals ORDER BY seq DESC LIMIT 1")[0]
detail = last[2] if isinstance(last[2], dict) else json.loads(last[2])
out["last"] = {"seq": last[0], "kind": last[1], "cause": detail.get("cause"),
               "hold": ((detail.get("state") or {}).get("logs_hold") or {}).get("value")}
print(json.dumps(out))
'''

UNREAD_TEXT = ("The value in force is not known yet, so this change cannot be made: the audit log's integrity chain "
               "does not check out (head-record-mismatch), so this server has not read it through; the integrity "
               "status on the Activity page says what to do. Nothing was changed; try again later.")


@pytest.fixture
def throwaway():
    yield from throwaway_database()


def _stop(name):
    """Stop the web process on the throwaway database, and remove its files."""
    files = f"/tmp/{name}-web.pid /tmp/{name}-web.log"
    subprocess.run(["docker", "exec", API, "sh", "-c", f"kill $(cat /tmp/{name}-web.pid) 2>/dev/null; sleep 1; "
                    f"rm -f {files}"], capture_output=True, timeout=60)


def _address():
    """Where the web process on the throwaway database answers: the web container's address, the test's port. Skips
    when this host cannot reach that address (the stack's own server there, at its port in the container, is tried)."""
    r = subprocess.run(["docker", "inspect", "-f", "{{range .NetworkSettings.Networks}}{{.IPAddress}} {{end}}", API],
                       capture_output=True, text=True, timeout=30)
    ips = r.stdout.split()
    assert r.returncode == 0 and ips, r.stderr
    try:
        socket.create_connection((ips[0], 8000), timeout=5).close()
    except OSError as exc:
        pytest.skip(f"this host cannot reach the web container's address {ips[0]} ({exc})")
    return f"http://{ips[0]}:{PORT}"


def _up(name, target):
    deadline = time.monotonic() + 120
    while time.monotonic() < deadline:
        try:
            if requests.get(target + "/health", timeout=3).status_code == 200:
                return
        except requests.RequestException:
            pass
        time.sleep(1)
    log = subprocess.run(["docker", "exec", API, "tail", "-n", "40", f"/tmp/{name}-web.log"], capture_output=True,
                         text=True, timeout=30).stdout
    raise AssertionError(f"the web process on the throwaway database did not answer at {target}: {log}")


def _put(target, token, password, key, value):
    """PUT /settings/managed/<key> with its step-up (the password: this account has no second factor)."""
    auth = {"Authorization": f"Bearer {token}"}
    r = requests.post(target + "/auth/second-factor/step-up", headers=auth, timeout=30,
                      json={"action": "admin.retention.write", "method": "password", "password": password})
    assert r.status_code == 200, r.text
    return requests.put(f"{target}/settings/managed/{key}", json={"value": value}, timeout=30,
                        headers={**auth, "X-Second-Factor": r.json()["receipt"]})


def test_before_the_chain_is_read_through_the_hold_is_turned_on_in_the_server(throwaway, browser: Browser):
    password = "Hold-" + secrets.token_hex(12) + "-9a"
    target = _address()
    try:
        started = run_in(throwaway, START, env={"AUDIT_CHAIN_KEY": KEY, "HOLD_PORT": str(PORT), "HOLD_ADMIN": ADMIN,
                                                "HOLD_PASSWORD": password})
        assert started["stopped"] is None and started["seals"] >= 2, started
        _up(throwaway, target)
        r = requests.post(target + "/auth/login", json={"username": ADMIN, "password": password}, timeout=30)
        assert r.status_code == 200, r.text
        token = r.json()["access_token"]
        managed = requests.get(target + "/settings/managed", headers={"Authorization": f"Bearer {token}"},
                               timeout=30).json()
        rows = {row["key"]: row for row in managed["settings"]}
        assert rows["logs_hold"]["chain_read"] is False and rows["logs_hold"]["value"] is None, rows["logs_hold"]
        assert managed["pending_chain"] == {"read": False, "stopped": "head-record-mismatch"}, managed["pending_chain"]
        # A number the chain holds, longer or shorter, and the hold turned off: refused, saying why, not "sooner".
        for key, value in (("audit_max_days", 400), ("audit_max_days", 0), ("logs_hold", False)):
            refused = _put(target, token, password, key, value)
            assert (refused.status_code, refused.json()["detail"]) == (409, UNREAD_TEXT), (key, value, refused.text)

        context = browser.new_context(service_workers="block", viewport={"width": 1440, "height": 900})
        errors = []

        def carry(route):
            url = route.request.url
            if not url.startswith(BASE_URL + "/") and url != BASE_URL:
                return route.continue_()
            route.fulfill(response=route.fetch(url=target + url[len(BASE_URL):]))
        context.route("**/*", carry)
        try:
            page = context.new_page()
            page.on("console", lambda m: errors.append(m.text) if m.type == "error" else None)
            page.goto(BASE_URL + "/")
            expect(page.locator("#login-screen")).to_be_visible(timeout=15000)
            page.fill("#username", ADMIN)
            page.fill("#password", password)
            page.click("#login-form button[type=submit]")
            expect(page.locator("#dashboard-screen")).to_be_visible(timeout=15000)
            page.evaluate("() => document.querySelector('.sidebar-item[data-section=\"settings\"]').click()")
            expect(page.locator("#settings-section")).to_be_visible(timeout=10000)
            page.locator('#settings-section .tab-btn[data-tab="records"]').click()
            show_advanced(page, "records")
            hold = page.locator('#retention-groups .retention-row[data-key="logs_hold"]')
            expect(hold.locator(".retention-source")).to_have_text("Not read yet", timeout=10000)
            expect(hold.locator(".retention-unread")).to_contain_text("Turning it on deletes nothing")
            numbers = page.locator('#retention-groups .retention-row[data-key="audit_max_days"]')
            expect(numbers.locator("button")).to_have_count(0)
            hold.locator(".retention-on-now").click()
            expect(page.locator("#stepup-modal.active")).to_be_visible(timeout=10000)
            page.fill("#stepup-password-input", password)
            page.locator("#stepup-modal-body .btn-primary").click()
            expect(page.locator("body")).to_contain_text("is saved", timeout=15000)
            # The page read again: still not known, as the chain is not read through.
            expect(hold.locator(".retention-source")).to_have_text("Not read yet", timeout=10000)
        finally:
            context.unroute_all(behavior="ignoreErrors")
            context.close()
        # The PUT's first answer asks for the password (403), which the browser logs; the live monitor's WebSocket is
        # not carried to that process (a route carries requests only). Nothing else.
        assert not [e for e in errors if "status of 403" not in e and "/ws/monitor" not in e], errors
        managed = requests.get(target + "/settings/managed", headers={"Authorization": f"Bearer {token}"},
                               timeout=30).json()
        row = {r["key"]: r for r in managed["settings"]}["logs_hold"]
        assert (row["chain_read"], row["value"], row["database_stored"]) == (False, None, True), row
    finally:
        _stop(throwaway)
    after = run_in(throwaway, AFTER, env={"AUDIT_CHAIN_KEY": KEY})
    # Saved in the database, no seal while sealing was stopped; sealed from the database once read through.
    assert after["seals"] == started["seals"] and after["hold"] == [True], after
    assert after["read"] is True
    assert after["last"] == {"seq": started["seals"] + 1, "kind": "policy", "cause": "database", "hold": True}, after
