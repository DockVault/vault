"""POST /auth/sign-out: the web app's sign-out ends the session on the server, at once.

The web app never called POST /api/logout, because its answer carries Clear-Site-Data (which a browser applies to
the whole origin, in every tab), so a session it signed out of stayed valid on the server until it expired. This
route ends the session as logout does and answers without that header. What is held here, on a running stack:

- the session ends at once: its token is refused, the row is inactive and revoked, another session of the same
  account goes on; the answer clears nothing (no Clear-Site-Data, no cookie);
- it is idempotent: a second call answers 200 again, says it ended nothing, and records nothing; of two calls at
  once, one ends the session and one sign-out is recorded;
- an expired token still ends its session (whose row stayed listed as signed in), and that session's other,
  unexpired token is then refused too;
- only a token this server signed for a session ends one: no token, a malformed one, one signed with another key
  and a second-factor pending token are refused with 401 (without Clear-Site-Data), and end nothing; nor does a
  token signed by the server that names another account than the session's;
- a token used after it is refused everywhere one is accepted: the web API, an upload (a new one, the chunks of one
  begun before, its completion, the direct upload), a download, the live-monitor socket (a new one and one already
  open), and the minting of SFTP temporary credentials;
- a temporary credential's web session ends and frees the credential's slot, as logout does;
- POST /api/logout keeps its answer for its callers.

tests/test_ui_sign_out_ends_session.py holds the web app's side: every sign-out path calls this route.
"""
import json
import threading
import time

import jwt
import pytest
import requests

from _account_change_helpers import psql, signed_in
from _sign_out_helpers import claims as _claims, expired_copy as _expired_copy, signed_by_the_server as _signed
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
    finally:
        admin.delete_user(other["id"])


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
