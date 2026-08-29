"""Self-service TOTP enrollment lifecycle: enroll -> confirm -> acknowledge -> active.

Drives the real state machine over HTTP: the first enrollment re-proves the account password, the
recovery codes are mandatory (the enrollment is not active until they are generated AND acknowledged),
and activation keeps the caller's own session while revoking the account's other sessions.
"""
import os
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from app.core import second_factor as sf   # noqa: E402  (compute a live TOTP code, as an authenticator would)


def _totp_now(secret: str) -> str:
    return sf._totp_at_step(secret, sf.current_totp_step())


def test_totp_enroll_confirm_acknowledge_lifecycle(temp_user, temp_user_client):
    # Nothing set up yet.
    assert temp_user_client.get("/users/me/second-factor").json()["status"] == "not_setup"

    # The first enrollment re-proves the account password.
    assert temp_user_client.post("/users/me/second-factor/totp/enroll",
                                 json={"current_password": "definitely-wrong"}).status_code == 400
    r = temp_user_client.post("/users/me/second-factor/totp/enroll",
                              json={"current_password": temp_user["_password"]})
    assert r.status_code == 200, r.text
    secret = r.json()["secret"]
    assert r.json()["otpauth_uri"].startswith("otpauth://totp/") and "secret=" in r.json()["otpauth_uri"]

    # A wrong code is refused; the state stays mid-enrollment (no recovery codes yet).
    assert temp_user_client.post("/users/me/second-factor/totp/confirm",
                                 json={"code": "000000"}).status_code == 400
    s = temp_user_client.get("/users/me/second-factor").json()
    assert s["status"] == "unconfirmed" and s["enrolled"] is False and s["recovery_codes_remaining"] == 0

    # A correct code generates the ten mandatory recovery codes (shown once); still not active.
    r = temp_user_client.post("/users/me/second-factor/totp/confirm", json={"code": _totp_now(secret)})
    assert r.status_code == 200, r.text
    codes = r.json()["recovery_codes"]
    assert len(codes) == 10 and len(set(codes)) == 10
    s = temp_user_client.get("/users/me/second-factor").json()
    assert s["awaiting_acknowledge"] is True and s["enrolled"] is False

    # Acknowledge activates the enrollment; the caller stays logged in (its own session survives).
    r = temp_user_client.post("/users/me/second-factor/recovery/acknowledge")
    assert r.status_code == 200 and r.json()["enrolled"] is True
    s = temp_user_client.get("/users/me/second-factor").json()
    assert s["enrolled"] is True and s["status"] == "active"
    assert s["method"] == "totp" and s["recovery_codes_remaining"] == 10


def test_enroll_refused_when_already_active(temp_user, temp_user_client):
    """A second enrollment attempt while one is active is refused (disable first) — an active method is
    never silently replaced."""
    temp_user_client.post("/users/me/second-factor/totp/enroll",
                          json={"current_password": temp_user["_password"]}).raise_for_status()
    secret = temp_user_client.post("/users/me/second-factor/totp/enroll",
                                   json={"current_password": temp_user["_password"]}).json()["secret"]
    temp_user_client.post("/users/me/second-factor/totp/confirm", json={"code": _totp_now(secret)}).raise_for_status()
    temp_user_client.post("/users/me/second-factor/recovery/acknowledge").raise_for_status()
    # Now active -> a fresh enroll is a 409.
    assert temp_user_client.post("/users/me/second-factor/totp/enroll",
                                 json={"current_password": temp_user["_password"]}).status_code == 409
