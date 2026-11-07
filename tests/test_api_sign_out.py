"""POST /auth/sign-out: the web app's sign-out ends the session on the server, at once.

The web app never called POST /api/logout, because its answer carries Clear-Site-Data (which a browser applies to
the whole origin, in every tab), so a session it signed out of stayed valid on the server until it expired. This
route ends the session as logout does and answers without that header. What is held here, on a running stack:

- the session ends at once: its token is refused, the row is inactive and revoked, another session of the same
  account goes on; the answer clears nothing (no Clear-Site-Data, no cookie);
- it is idempotent: a second call answers 200 again, says it ended nothing, and records nothing; of two calls at
  once, one ends the session and one sign-out is recorded; a call for a session already ended writes nothing to its
  row (a row revoked elsewhere and still listed as active is marked inactive);
- it does its work off the server's event loop: a sign-out waiting on its session's row holds up no other request;
- an expired token still ends its session (whose row stayed listed as signed in), and that session's other,
  unexpired token is then refused too;
- only a token this server signed for a session ends one: no token, a malformed one, one signed with another key
  and a second-factor pending token are refused with 401 (without Clear-Site-Data), and end nothing; nor does a
  token signed by the server that names another account than the session's;
- a token used after it is refused everywhere one is accepted: the web API, an upload (a new one, the chunks of one
  begun before, its completion, the direct upload), a download, the live-monitor socket (a new one and one already
  open), and the minting of SFTP temporary credentials; refused without Clear-Site-Data (by the denylist, by the
  session's row, for a temporary credential's session), which a token that has run out still gets;
- a temporary credential's web session ends and frees the credential's slot, as logout does;
- the token is held in the cache's denylist for the rest of its life (none for a token that has run out, none for
  a token naming another account);
- at the auth requests' limit a vault ships with, sign-outs are counted in a budget of their own, by the session
  the token names (expired or not) and by address for a token that names none: they never use up the sign-in that
  follows from the same address, nor the account's other auth requests, and the sign-outs sent with any other
  token of the account (one that has run out, one signed out, a second-factor pending token, a temporary
  credential's) never use up the sign-out of the account's live session;
- POST /api/logout keeps its answer for its callers.

tests/test_ui_sign_out_ends_session.py holds the web app's side: every sign-out path calls this route.
"""
import json
import subprocess
import threading
import time
from contextlib import contextmanager

import jwt
import pytest
import requests

from _account_change_helpers import DB, psql, signed_in
from _sign_out_helpers import claims as _claims, expired_copy as _expired_copy, signed_by_the_server as _signed
from _sign_out_helpers import redis_cli, session_digest, shipped_auth_limit
from _sign_out_helpers import session_row as _row, sign_outs_recorded as _sign_outs_recorded
from _sf_helpers import enroll_totp
from conftest import BASE_URL, unique

pytestmark = pytest.mark.integration

websocket = pytest.importorskip("websocket")  # websocket-client

OCTET = {"Content-Type": "application/octet-stream"}


def _sign_out(token=None, header=None):
    headers = {}
    if header is not None:
        headers["Authorization"] = header
    elif token is not None:
        headers["Authorization"] = f"Bearer {token}"
    return requests.post(f"{BASE_URL}/auth/sign-out", headers=headers, timeout=30)


def _clears_nothing(r):
    assert "clear-site-data" not in {k.lower() for k in r.headers}, dict(r.headers)
    assert "set-cookie" not in {k.lower() for k in r.headers}, dict(r.headers)


def _as(token, method, path, **kw):
    headers = dict(kw.pop("headers", {}) or {})
    headers["Authorization"] = f"Bearer {token}"
    return requests.request(method, f"{BASE_URL}{path}", headers=headers, timeout=60, **kw)


@pytest.fixture
def person(admin):
    user = admin.create_user()
    yield user
    admin.delete_user(user["id"])


def test_a_sign_out_ends_the_session_at_once_and_clears_nothing(person):
    one = signed_in(person)
    assert _row(one.token) == "t|f"
    other = signed_in(person)        # (a new sign-in marks the earlier one inactive; its token still works)
    assert one.get("/users/me").status_code == 200 and other.get("/users/me").status_code == 200
    assert _row(one.token).endswith("|f")
    before = _sign_outs_recorded(person["id"])

    r = _sign_out(one.token)
    assert r.status_code == 200, r.text
    assert r.json() == {"signed_out": True, "session_ended": True}
    _clears_nothing(r)
    assert one.get("/users/me").status_code == 401, "the signed-out token still works"
    assert _row(one.token) == "f|t"
    assert other.get("/users/me").status_code == 200, "another session of the account was ended too"
    assert _sign_outs_recorded(person["id"]) == before + 1

    again = _sign_out(one.token)
    assert again.status_code == 200 and again.json() == {"signed_out": True, "session_ended": False}
    _clears_nothing(again)
    assert _sign_outs_recorded(person["id"]) == before + 1, "a second sign-out of the same session was recorded"


def test_two_sign_outs_at_once_end_the_session_once(person):
    one = signed_in(person)
    before = _sign_outs_recorded(person["id"])
    gate = threading.Barrier(2)
    answers = []

    def go():
        gate.wait(timeout=30)
        answers.append(_sign_out(one.token))

    threads = [threading.Thread(target=go) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=60)
    assert sorted((a.status_code, a.json()["session_ended"]) for a in answers) == [(200, False), (200, True)]
    assert _sign_outs_recorded(person["id"]) == before + 1


def _row_version(token):
    """The version of the session row the database keeps (its xmin): every UPDATE of the row writes a new one, even
    one that sets the values the row already holds."""
    return psql(f"SELECT xmin FROM active_sessions WHERE session_token = '{session_digest(token)}'")


def test_a_sign_out_of_a_session_already_ended_writes_nothing_to_its_row(person):
    one = signed_in(person)
    assert _sign_out(one.token).json()["session_ended"] is True
    assert _row(one.token) == "f|t"
    version = _row_version(one.token)
    for _ in range(2):
        again = _sign_out(one.token)
        assert again.status_code == 200 and again.json() == {"signed_out": True, "session_ended": False}, again.text
    assert _row_version(one.token) == version, "a sign-out of a session already ended wrote its row again"


def test_a_session_revoked_elsewhere_and_still_listed_as_active_is_marked_inactive(person):
    """The control of the test above: the row is written when there is still something to write."""
    one = signed_in(person)
    psql(f"UPDATE active_sessions SET revoked = true WHERE session_token = '{session_digest(one.token)}'")
    assert _row(one.token) == "t|t"
    r = _sign_out(one.token)
    assert r.status_code == 200 and r.json() == {"signed_out": True, "session_ended": False}, r.text
    assert _row(one.token) == "f|t"


ROW_HOLDER = "sign-out-row-holder"


@contextmanager
def _row_held(token):
    """Another database session holds the lock of the session row ``token`` names until this ends."""
    holder = subprocess.Popen(
        ["docker", "exec", "-i", DB, "psql", "-U", "sftp_user", "-d", "sftp_db", "-Atc",
         f"BEGIN; SELECT 1 FROM active_sessions WHERE session_token = '{session_digest(token)}' FOR UPDATE; "
         f"SELECT pg_sleep(900); -- {ROW_HOLDER}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        _until(lambda: psql("SELECT count(*) FROM pg_stat_activity WHERE wait_event = 'PgSleep' "
                            f"AND query LIKE '%{ROW_HOLDER}%' AND pid <> pg_backend_pid()") == "1",
               30, "the row's lock to be taken")
        yield
    finally:
        # Ending the docker client does not end psql inside the container: end its session.
        psql("SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity "
             f"WHERE query LIKE '%{ROW_HOLDER}%' AND pid <> pg_backend_pid()")
        holder.kill()
        holder.wait(timeout=30)


def _until(condition, seconds, what):
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        if condition():
            return
        time.sleep(0.1)
    raise AssertionError(f"waited {seconds}s for {what}")


def test_a_sign_out_waiting_on_its_row_holds_up_no_other_request(person):
    """The sign-out's work runs off the server's event loop. Its session's row is held by another database session,
    so the sign-out waits on it; while it waits, another request (the health check) is answered at once. On the
    loop, every other request waited until the row was let go or the wait timed out (five seconds), and the
    sign-out then failed."""
    one = signed_in(person)
    answers = []
    with _row_held(one.token):
        sending = threading.Thread(target=lambda: answers.append(_sign_out(one.token)))
        sending.start()
        _until(lambda: psql("SELECT count(*) FROM pg_stat_activity WHERE wait_event_type = 'Lock' "
                            "AND query LIKE 'UPDATE active_sessions%'") != "0", 20, "the sign-out to wait on its row")
        started = time.monotonic()
        health = requests.get(f"{BASE_URL}/health", timeout=30)
        took = time.monotonic() - started
    sending.join(60)
    assert health.status_code == 200, health.text
    assert took < 2, f"another request waited {took:.1f}s behind a sign-out waiting on its row"
    assert answers and answers[0].status_code == 200, answers and (answers[0].status_code, answers[0].text[:200])
    assert answers[0].json() == {"signed_out": True, "session_ended": True}
    assert _row(one.token) == "f|t"


def test_an_expired_token_still_ends_its_session(person):
    one = signed_in(person)
    expired = _expired_copy(one.token)
    assert _as(expired, "GET", "/users/me").status_code == 401        # the instrument: it has run out
    assert _row(one.token) == "t|f", "the session is still listed as signed in"
    before = _sign_outs_recorded(person["id"])

    r = _sign_out(expired)
    assert r.status_code == 200 and r.json() == {"signed_out": True, "session_ended": True}, r.text
    _clears_nothing(r)
    assert _row(one.token) == "f|t"
    assert one.get("/users/me").status_code == 401, "the session's unexpired token still works"
    assert _sign_outs_recorded(person["id"]) == before + 1


def test_only_a_token_this_server_signed_for_a_session_ends_one(admin, person):
    one = signed_in(person)
    claims = _claims(one.token)
    forged = jwt.encode(claims, "not-this-servers-key-" + "x" * 32, algorithm="HS256")
    eve = admin.create_user()
    try:
        enroll_totp(eve, signed_in(eve))
        step = requests.post(f"{BASE_URL}/auth/login",
                             json={"username": eve["_username"], "password": eve["_password"]}, timeout=30)
        assert step.status_code == 200 and step.json().get("second_factor_required"), step.text
        pending = step.json()["pre_auth_token"]
        for r in (_sign_out(), _sign_out(header="Bearer"), _sign_out("not-a-token"), _sign_out(forged),
                  _sign_out(pending), _sign_out(header=f"Basic {one.token}")):
            assert r.status_code == 401, (r.status_code, r.text)
            _clears_nothing(r)
    finally:
        admin.delete_user(eve["id"])
    assert one.get("/users/me").status_code == 200, "a token not this server's ended the session"
    assert _row(one.token) == "t|f"


def test_a_token_naming_another_account_does_not_end_the_session(admin, person):
    """A token signed by the server whose account is not the session's (which only the server's key could make)
    ends nothing: the session's own account must be the token's."""
    one = signed_in(person)
    other = admin.create_user()
    try:
        crossed = _signed(dict(_claims(one.token), sub=other["id"]), 5)
        r = _sign_out(crossed)
        assert r.status_code == 200 and r.json() == {"signed_out": True, "session_ended": False}, r.text
        assert one.get("/users/me").status_code == 200 and _row(one.token) == "t|f"
        assert redis_cli("EXISTS", _denylisted(one.token)) == "0", "the session's token was denylisted"
    finally:
        admin.delete_user(other["id"])


def _denylisted(token):
    """The cache's denylist entry for the session a token names."""
    return f"denylist:session:{session_digest(token)}"


def test_the_sign_out_holds_the_token_in_the_denylist_for_the_rest_of_its_life(person):
    """The revoked flag on the session's row refuses the token on its own (every reader re-checks it); the denylist
    entry refuses it before the database is read, as logout's does. Written for what is left of the token's life:
    none for a token that has run out."""
    one = signed_in(person)
    key = _denylisted(one.token)
    assert redis_cli("EXISTS", key) == "0"
    left = _claims(one.token)["exp"] - time.time()
    assert _sign_out(one.token).json()["session_ended"] is True
    assert redis_cli("EXISTS", key) == "1", "the signed-out token is not in the denylist"
    ttl = int(redis_cli("TTL", key))
    assert 0 < ttl <= left + 1, (ttl, left)

    two = signed_in(person)
    assert _sign_out(_expired_copy(two.token)).json()["session_ended"] is True
    assert redis_cli("EXISTS", _denylisted(two.token)) == "0", "an entry was written for a token that had run out"


def _sign_in_status(account):
    return requests.post(f"{BASE_URL}/auth/login",
                         json={"username": account["_username"], "password": account["_password"]},
                         timeout=30).status_code


def test_the_sign_outs_of_a_session_that_ran_out_are_counted_by_that_session_in_a_budget_of_their_own(
        admin, person):
    """Every tab of a session signs out at the same moment, and a session that has run out is signed out with its
    expired token. Counted with the sign-ins by address (an expired token names no one to the other readers), ten of
    them used up the sign-in that follows; they are counted by the session the token names, in the sign-out's own
    budget: past the limit only that session's further sign-outs wait, not another account's, not the sign-in, not
    the account's other auth requests."""
    expired = _expired_copy(signed_in(person).token)
    other = admin.create_user()
    try:
        other_expired = _expired_copy(signed_in(other).token)
        with shipped_auth_limit(admin) as limit:
            answers = [_sign_out(expired).status_code for _ in range(limit + 1)]
            assert answers[-1] == 429 and answers[:-1] == [200] * limit, answers
            assert _sign_out(other_expired).status_code == 200, "another account's sign-out was refused"
            assert _sign_in_status(person) == 200, "the sign-in after the sign-outs was refused"
            again = signed_in(person)
            assert again.get("/auth/session").status_code == 200, "the account's other auth requests were refused"
    finally:
        admin.delete_user(other["id"])


def _another_token_of_the_account(kind, admin, admin_creds, person):
    """(a token the server signed for an account, of a session other than the live one, or of none; a client of
    that account's live session) for `kind`."""
    if kind == "a-temporary-credentials":
        # Its account is its owner's (here the administrator's); its session is its own.
        made = admin.post("/auth/temp-credentials", json={"note": unique("sign-out budget")})
        assert made.status_code == 200, made.text
        cred = made.json()
        holder = requests.post(f"{BASE_URL}/auth/login",
                               json={"username": cred["temp_username"], "password": cred["credential"]}, timeout=30)
        assert holder.status_code == 200, holder.text
        live = signed_in({"_username": admin_creds["username"], "_password": admin_creds["password"]})
        return holder.json()["access_token"], live
    live = signed_in(person)
    if kind == "a-second-factor-pending-token":
        enroll_totp(person, live)
        step = requests.post(f"{BASE_URL}/auth/login",
                             json={"username": person["_username"], "password": person["_password"]}, timeout=30)
        assert step.status_code == 200 and step.json().get("second_factor_required"), step.text
        return step.json()["pre_auth_token"], live
    old = signed_in(person).token
    if kind == "one-signed-out":
        assert _sign_out(old).json()["session_ended"] is True
        return old, live
    return _expired_copy(old), live                                     # one that has run out


@pytest.mark.parametrize("kind", ["one-that-has-run-out", "one-signed-out", "a-second-factor-pending-token",
                                  "a-temporary-credentials"])
def test_no_other_token_of_the_account_uses_up_the_sign_out_of_its_live_session(admin, admin_creds, person, kind):
    """Any token the server signed for an account can be sent to the sign-out: an old session's that has run out,
    one already signed out, a second-factor pending token, a temporary credential's (whose account is its owner's).
    Counted by the account, the shipped limit of them used up the sign-out of the account's live session: it was
    refused, and that session stayed valid. Counted by the session each names (or by address, for a token that names
    none), they use up only their own, and the live session's sign-out ends it."""
    spent, live = _another_token_of_the_account(kind, admin, admin_creds, person)
    assert _claims(spent)["sub"] == _claims(live.token)["sub"], "not a token of the same account"
    assert _claims(spent).get("session_token") != _claims(live.token)["session_token"]
    assert live.get("/users/me").status_code == 200
    with shipped_auth_limit(admin) as limit:
        answers = [_sign_out(spent) for _ in range(limit)]
        expected = 401 if kind == "a-second-factor-pending-token" else 200
        assert [r.status_code for r in answers] == [expected] * limit, [(r.status_code, r.text) for r in answers]
        assert answers[0].headers.get("x-ratelimit-limit") == str(limit), dict(answers[0].headers)
        r = _sign_out(live.token)
        assert r.status_code == 200 and r.json() == {"signed_out": True, "session_ended": True}, r.text
    assert live.get("/users/me").status_code == 401, "the live session was not ended"
    assert _row(live.token) == "f|t"


def test_sign_outs_with_a_token_this_server_did_not_sign_do_not_use_up_the_sign_in(admin, person):
    """Such a token names no one: its sign-outs are counted by address, in the sign-out's budget, and refused past
    it; the sign-in from that address goes on."""
    forged = jwt.encode(_claims(signed_in(person).token), "not-this-servers-key-" + "x" * 32, algorithm="HS256")
    with shipped_auth_limit(admin) as limit:
        answers = [_sign_out(forged).status_code for _ in range(limit + 1)]
        assert answers[-1] == 429 and answers[:-1] == [401] * limit, answers
        assert _sign_in_status(person) == 200, "the sign-in after the sign-outs was refused"


def _upload(client, vault_id, name, body):
    init = client.post(f"/vaults/{vault_id}/uploads", json={
        "file_name": name, "total_size": len(body), "total_chunks": 1, "chunk_size": len(body),
        "mime_type": "application/octet-stream"})
    assert init.status_code == 200, init.text
    return init.json()["session_id"]


def _ws_url():
    return BASE_URL.replace("http://", "ws://").replace("https://", "wss://") + "/ws/monitor"


def _ws_open(token):
    ws = websocket.create_connection(_ws_url(), timeout=10)
    ws.send(json.dumps({"type": "auth", "token": token}))
    ws.settimeout(10)
    return ws, json.loads(ws.recv())


def _closed_within(ws, seconds):
    deadline = time.monotonic() + seconds
    ws.settimeout(1)
    while time.monotonic() < deadline:
        try:
            frame = ws.recv()
        except websocket.WebSocketTimeoutException:
            continue
        except Exception:  # noqa: BLE001 -- closed
            return True
        if frame in ("", None):
            return True
    return False


@pytest.mark.websocket
def test_a_signed_out_token_is_refused_everywhere_a_token_is_accepted(admin):
    """An administrator's session, so that every route below accepts it before the sign-out (the controls)."""
    boss = admin.create_user(role="admin")
    client = signed_in(boss)
    token = client.token
    vault_id = client.create_vault(name=unique("signed-out"))["id"]
    try:
        body = b"kept before the sign-out"
        stored = _upload(client, vault_id, "a.bin", body)
        put = client.put(f"/vaults/{vault_id}/uploads/{stored}/chunks/0", data=body, headers=OCTET)
        assert put.status_code == 200, put.text
        done = client.post(f"/vaults/{vault_id}/uploads/{stored}/complete")
        assert done.status_code == 200, done.text
        file_id = done.json()["id"]
        begun = _upload(client, vault_id, "b.bin", body)           # an upload begun before the sign-out
        got = _as(token, "GET", f"/vaults/{vault_id}/files/{file_id}/download")
        assert got.status_code == 200 and got.content == body, got.status_code
        assert _as(token, "GET", "/api/dashboard/stats").status_code == 200
        live, first = _ws_open(token)
        assert first.get("type") == "connected", first

        assert _sign_out(token).json()["session_ended"] is True

        refused = {
            "the web API": _as(token, "GET", "/users/me"),
            "a vault listing": _as(token, "GET", f"/vaults/{vault_id}/files"),
            "an administrator's route": _as(token, "GET", "/api/dashboard/stats"),
            "a new upload": _as(token, "POST", f"/vaults/{vault_id}/uploads", json={
                "file_name": "c.bin", "total_size": 3, "total_chunks": 1, "chunk_size": 3,
                "mime_type": "application/octet-stream"}),
            "a chunk of an upload begun before": _as(token, "PUT", f"/vaults/{vault_id}/uploads/{begun}/chunks/0",
                                                     data=body, headers=OCTET),
            "its completion": _as(token, "POST", f"/vaults/{vault_id}/uploads/{begun}/complete"),
            "the direct upload": _as(token, "POST", f"/vaults/{vault_id}/files",
                                     files={"files": ("d.bin", b"abc", "application/octet-stream")}),
            "a download": _as(token, "GET", f"/vaults/{vault_id}/files/{file_id}/download"),
            "an SFTP temporary credential": _as(token, "POST", "/auth/temp-credentials",
                                                json={"note": unique("after-sign-out")}),
        }
        assert {what: r.status_code for what, r in refused.items()} == {what: 401 for what in refused}, \
            {what: (r.status_code, r.text[:120]) for what, r in refused.items()}
        assert _closed_within(live, 20), "the socket opened before the sign-out was left open"
        ws = websocket.create_connection(_ws_url(), timeout=10)
        try:
            ws.send(json.dumps({"type": "auth", "token": token}))
            ws.settimeout(8)
            frame = ws.recv()
            assert "connected" not in (frame or ""), frame
            assert _closed_within(ws, 10)
        finally:
            ws.close()
        # Nothing the signed-out token sent was stored (read as the same account, signed in again).
        again = signed_in(boss)
        listed = [it["name"] for it in again.get(f"/vaults/{vault_id}/files").json()["items"]]
        assert listed == ["a.bin"], listed
    finally:
        signed_in(boss).post(f"/vaults/{vault_id}/delete")
        admin.delete_user(boss["id"])


def test_a_temporary_credentials_web_session_ends_and_frees_its_slot(admin):
    made = admin.post("/auth/temp-credentials", json={"note": unique("sign-out")})
    assert made.status_code == 200, made.text
    cred = made.json()
    holder = requests.post(f"{BASE_URL}/auth/login",
                           json={"username": cred["temp_username"], "password": cred["credential"]}, timeout=30)
    assert holder.status_code == 200, holder.text
    token = holder.json()["access_token"]
    assert _as(token, "GET", "/users/me").status_code == 200
    assert psql(f"SELECT slot_released_at IS NULL FROM temporary_credentials "
                f"WHERE temp_username = '{cred['temp_username']}'") == "t"

    r = _sign_out(token)
    assert r.status_code == 200 and r.json()["session_ended"] is True, r.text
    _clears_nothing(r)
    assert _as(token, "GET", "/users/me").status_code == 401
    assert _row(token) == "f|t"
    assert psql(f"SELECT slot_released_at IS NOT NULL FROM temporary_credentials "
                f"WHERE temp_username = '{cred['temp_username']}'") == "t", "its slot was not freed"
    recorded = psql("SELECT temp_credential_name FROM audit_logs WHERE action = 'logout' "
                    f"AND temp_credential_name = '{cred['temp_username']}'")
    assert recorded == cred["temp_username"], "the sign-out was not recorded as the temporary credential's"


def _clears_site_data(r):
    return "clear-site-data" in {k.lower() for k in r.headers}


def test_a_session_that_has_ended_is_refused_without_clear_site_data(admin, person):
    """A request a tab sends with the token of a session ended by a sign-out (a poll on its way, a tab told late) is
    refused without Clear-Site-Data, which a browser applies to the whole origin in every tab: by the denylist, by
    the session's row when the denylist does not hold it, and for a temporary credential's session. A token that
    has run out is still refused with it (the control)."""
    one = signed_in(person)
    assert _sign_out(one.token).json()["session_ended"] is True
    refused = _as(one.token, "GET", "/users/me")
    assert refused.status_code == 401 and "terminated" in refused.text, refused.text
    assert not _clears_site_data(refused), dict(refused.headers)
    redis_cli("DEL", _denylisted(one.token))                 # the session's row refuses it now
    assert redis_cli("EXISTS", _denylisted(one.token)) == "0"
    refused = _as(one.token, "GET", "/users/me")
    assert refused.status_code == 401 and "terminated" in refused.text, refused.text
    assert not _clears_site_data(refused), dict(refused.headers)

    made = admin.post("/auth/temp-credentials", json={"note": unique("ended-session")})
    assert made.status_code == 200, made.text
    cred = made.json()
    holder = requests.post(f"{BASE_URL}/auth/login",
                           json={"username": cred["temp_username"], "password": cred["credential"]}, timeout=30)
    assert holder.status_code == 200, holder.text
    temp = holder.json()["access_token"]
    assert _sign_out(temp).json()["session_ended"] is True
    redis_cli("DEL", _denylisted(temp))
    refused = _as(temp, "GET", "/users/me")
    assert refused.status_code == 401 and "terminated" in refused.text, refused.text
    assert not _clears_site_data(refused), dict(refused.headers)

    other = signed_in(person)
    run_out = _as(_expired_copy(other.token), "GET", "/users/me")
    assert run_out.status_code == 401 and _clears_site_data(run_out), dict(run_out.headers)


def test_api_logout_keeps_its_answer_for_its_callers(person):
    one = signed_in(person)
    before = _sign_outs_recorded(person["id"])
    r = one.post("/api/logout")
    assert r.status_code == 200 and r.json() == {"message": "Logged out successfully", "session_invalidated": True}
    assert r.headers.get("Clear-Site-Data") == '"cache", "cookies", "storage"'
    assert one.get("/users/me").status_code == 401
    assert _row(one.token) == "f|t"
    assert _sign_outs_recorded(person["id"]) == before + 1
    # The web app's sign-out of the same session after it: nothing left to end.
    assert _sign_out(one.token).json() == {"signed_out": True, "session_ended": False}
