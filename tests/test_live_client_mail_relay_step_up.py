"""The live tests' client answers the mail server settings' step-up, and nothing else, offline.

Changing or testing the mail server settings asks for the administrator's password every time. The live tests'
client (tests/conftest.py, ApiClient) answers that refusal as a person answers the page's prompt: it confirms
with its own password and sends the same request once more with the receipt; when the step-up limit answers, a
short-lived second administrator makes the request and is removed. A test send is confirmed before it is sent,
so its route's own limit counts it once. Any other refusal, and the refusal for a client that signed in with no
password, was told not to answer or sent its own receipt, reaches the test as it came. Run against a stand-in for
the HTTP session: nothing here needs a stack.
"""
import json

import pytest
import requests

import conftest
from conftest import ApiClient

pytestmark = pytest.mark.unit

STEP_UP = {"detail": {"second_factor_required": True, "action": "admin.mail_relay.write",
                      "reason": "step_up_required", "methods": ["password"]}}
OTHER_STEP_UP = {"detail": {"second_factor_required": True, "action": "admin.auth_policy.write",
                            "reason": "step_up_required", "methods": ["password"]}}


class Answer:
    def __init__(self, status, body):
        self.status_code = status
        self._body = body
        self.text = json.dumps(body)

    def json(self):
        return self._body

    def raise_for_status(self):
        if self.status_code >= 400:
            raise requests.HTTPError(self.text)


class Server:
    """Every request the stand-in sessions send, and the answers a test scripts for them."""

    def __init__(self, answer):
        self.answer = answer
        self.seen = []

    def session(self):
        server = self

        class Session:
            def __init__(self):
                self.headers = {}

            def _send(self, method, url, **kw):
                path = url.split("://", 1)[-1].split("/", 1)[-1]
                sent = {"method": method, "path": "/" + path, "json": kw.get("json"),
                        "receipt": (kw.get("headers") or {}).get("X-Second-Factor"),
                        "as": self.headers.get("Authorization")}
                server.seen.append(sent)
                return server.answer(sent)

            def get(self, url, **kw):
                return self._send("GET", url, **kw)

            def post(self, url, **kw):
                return self._send("POST", url, **kw)

            def put(self, url, **kw):
                return self._send("PUT", url, **kw)

            def patch(self, url, **kw):
                return self._send("PATCH", url, **kw)

            def delete(self, url, **kw):
                return self._send("DELETE", url, **kw)

        return Session


def _client(monkeypatch, answer, *, signed_in=True):
    server = Server(answer)
    monkeypatch.setattr(conftest.requests, "Session", server.session())
    client = ApiClient("http://vault.test")
    if signed_in:
        client.login("ada", "ada-password")
    server.seen.clear()
    return client, server


def _sign_in(sent):
    user = (sent["json"] or {}).get("username")
    return Answer(200, {"access_token": f"token-of-{user}", "user": {"username": user}})


def test_the_step_up_is_answered_with_the_clients_password_and_the_request_sent_again(monkeypatch):
    def answer(sent):
        if sent["path"] == "/auth/login":
            return _sign_in(sent)
        if sent["path"] == "/auth/second-factor/step-up":
            assert sent["json"] == {"action": "admin.mail_relay.write", "method": "password", "code": "ada-password"}
            return Answer(200, {"receipt": "r-1"})
        return Answer(201, {"id": "p-1"}) if sent["receipt"] == "r-1" else Answer(403, STEP_UP)
    client, server = _client(monkeypatch, answer)
    r = client.post("/email/profiles", json={"name": "Relay"}, headers={"X-Extra": "kept"})
    assert r.status_code == 201
    assert [(s["method"], s["path"], s["receipt"]) for s in server.seen] == [
        ("POST", "/email/profiles", None), ("POST", "/auth/second-factor/step-up", None),
        ("POST", "/email/profiles", "r-1")]
    assert server.seen[2]["json"] == {"name": "Relay"}


@pytest.mark.parametrize("refusal", [Answer(403, OTHER_STEP_UP), Answer(403, {"detail": "Admin privileges required"}),
                                     Answer(400, {"detail": {"reason": "smtp_password_required", "message": "m"}}),
                                     Answer(401, {"detail": "Session expired"})],
                         ids=["another-step-up", "plain-403", "relay-rule", "401"])
def test_any_other_answer_reaches_the_test_as_it_came(monkeypatch, refusal):
    client, server = _client(monkeypatch, lambda sent: _sign_in(sent) if sent["path"] == "/auth/login" else refusal)
    assert client.put("/settings", json={"smtp_server": "x"}) is refusal
    assert [s["path"] for s in server.seen] == ["/settings"]


def test_a_client_told_not_to_answer_or_signed_in_with_no_password_sees_the_refusal(monkeypatch):
    refusal = Answer(403, STEP_UP)
    client, server = _client(monkeypatch, lambda sent: _sign_in(sent) if sent["path"] == "/auth/login" else refusal)
    client.answers_mail_relay_step_up = False
    assert client.delete("/email/profiles/p-1") is refusal
    anonymous, other = _client(monkeypatch, lambda sent: refusal, signed_in=False)
    assert anonymous.post("/settings/test-email") is refusal
    assert [s["path"] for s in server.seen + other.seen] == ["/email/profiles/p-1", "/settings/test-email"]


def test_a_refused_password_leaves_the_first_refusal(monkeypatch):
    first = Answer(403, STEP_UP)

    def answer(sent):
        if sent["path"] == "/auth/login":
            return _sign_in(sent)
        if sent["path"] == "/auth/second-factor/step-up":
            return Answer(403, {"detail": "Your account password is required and must be correct."})
        return first
    client, server = _client(monkeypatch, answer)
    assert client.post("/email/profiles", json={}) is first
    assert [s["path"] for s in server.seen] == ["/email/profiles", "/auth/second-factor/step-up"]
    # A test send asks first; refused, the send goes as it is and its own answer stands.
    server.seen.clear()
    assert client.post("/settings/test-email") is first
    assert [s["path"] for s in server.seen] == ["/auth/second-factor/step-up", "/settings/test-email"]


@pytest.mark.parametrize("path", ["/email/profiles/test", "/settings/test-email"])
def test_a_test_send_is_confirmed_before_it_is_sent_so_its_limit_counts_it_once(monkeypatch, path):
    def answer(sent):
        if sent["path"] == "/auth/login":
            return _sign_in(sent)
        if sent["path"] == "/auth/second-factor/step-up":
            return Answer(200, {"receipt": "r-3"})
        return Answer(200, {"message": "sent"}) if sent["receipt"] == "r-3" else Answer(403, STEP_UP)
    client, server = _client(monkeypatch, answer)
    assert client.post(path, json={"to_addr": "x@example.test"}).status_code == 200
    assert [(s["path"], s["receipt"]) for s in server.seen] == [("/auth/second-factor/step-up", None), (path, "r-3")]


def test_a_request_that_carries_its_own_receipt_is_left_alone(monkeypatch):
    refusal = Answer(403, STEP_UP)
    client, server = _client(monkeypatch, lambda sent: _sign_in(sent) if sent["path"] == "/auth/login" else refusal)
    for path in ("/settings/test-email", "/email/profiles"):
        assert client.post(path, headers={"X-Second-Factor": "spent"}) is refusal
    assert [(s["path"], s["receipt"]) for s in server.seen] == [("/settings/test-email", "spent"),
                                                                ("/email/profiles", "spent")]


def test_at_the_step_up_limit_a_second_administrator_makes_the_request_and_is_removed(monkeypatch):
    def answer(sent):
        if sent["path"] == "/auth/login":
            return _sign_in(sent)
        if sent["path"] == "/users":
            return Answer(201, {"id": "u-2", "username": sent["json"]["username"]})
        if sent["path"] == "/users/u-2/delete":
            return Answer(200, {})
        if sent["path"] == "/auth/second-factor/step-up":
            return Answer(429, {"detail": "Too many"}) if sent["as"] == "Bearer token-of-ada" else \
                Answer(200, {"receipt": "r-2"})
        return Answer(200, {"ok": True}) if sent["receipt"] == "r-2" else Answer(403, STEP_UP)
    client, server = _client(monkeypatch, answer)
    assert client.put("/email/profiles/p-1", json={"name": "Renamed"}).status_code == 200
    made = next(s for s in server.seen if s["path"] == "/users")
    assert made["json"]["role"] == "admin"
    second = f"Bearer token-of-{made['json']['username']}"
    assert [(s["path"], s["as"] == second) for s in server.seen] == [
        ("/email/profiles/p-1", False), ("/auth/second-factor/step-up", False), ("/users", False),
        ("/auth/login", False), ("/email/profiles/p-1", True), ("/auth/second-factor/step-up", True),
        ("/email/profiles/p-1", True), ("/users/u-2/delete", False)]
