"""The long-run client renews its token before it expires — and only that client.

The access token defaults to a 30-minute life while the session-scoped `admin` client logs in once
and lives for the whole run. Any run longer than that used to fail every remaining admin call with
401, and the `finally` blocks that clean up failed too, leaking fixtures into whatever ran next and
producing a second, unrelated-looking set of failures.

The renewal is proactive, on token age. It is NOT a retry on 401, and these tests pin that
distinction: several suites assert that a client which HAS logged in then gets 401 once its session
is denylisted, durably revoked, logged out, or its account locked. Re-authenticating in response to
a 401 would turn those into 200s and mask the security regressions they exist to catch.
"""
import time

import pytest

from conftest import ApiClient

pytestmark = pytest.mark.integration


def test_a_renewing_client_gets_a_new_token_before_expiry(admin_creds):
    """Driven by making the margin enormous rather than by waiting out a real token."""
    c = ApiClient(renew_before_expiry=True)
    c.login(admin_creds["username"], admin_creds["password"])
    first = c.token
    assert c._token_expires_at() is not None, "the token's expiry must be readable to renew on it"

    # Any token is now "about to expire", so the next request must renew first.
    c.RENEW_MARGIN_SECONDS = 10 ** 9
    assert c.get("/vaults").status_code == 200
    assert c.token != first, "the client did not renew before its token expired"
    assert c.get("/vaults").status_code == 200, "the renewed token does not work"


def test_renewal_is_bounded_by_the_margin_from_both_sides(admin_creds):
    """Brackets the boundary rather than only checking the easy side.

    Asserting "a fresh token is not renewed" alone passes with the fix fully reverted, so it
    proves nothing. Setting the margin just under the remaining lifetime and then just over it
    pins that the margin is what decides.
    """
    c = ApiClient(renew_before_expiry=True)
    c.login(admin_creds["username"], admin_creds["password"])
    first = c.token
    remaining = c._token_claims()["exp"] - time.time()
    assert remaining > 60, f"token lifetime too short to bracket: {remaining}s"

    c.RENEW_MARGIN_SECONDS = remaining - 30      # not yet inside the margin
    assert c.get("/vaults").status_code == 200
    assert c.token == first, "renewed while still outside the margin"

    c.RENEW_MARGIN_SECONDS = remaining + 30      # now inside it
    assert c.get("/vaults").status_code == 200
    assert c.token != first, "did not renew once inside the margin"


def test_renewal_is_off_by_default_so_revocation_tests_stay_honest(admin_creds):
    """The property that matters most here.

    Suites elsewhere revoke a session and then assert 401. If every client silently
    re-authenticated, those would pass with 200 and stop testing anything.
    """
    c = ApiClient()
    c.login(admin_creds["username"], admin_creds["password"])
    first = c.token
    c.RENEW_MARGIN_SECONDS = 10 ** 9   # would renew on every call IF it were enabled
    assert c.get("/vaults").status_code == 200
    assert c.token == first, "a default client renewed its token; revocation tests would go blind"


def test_a_failed_renewal_does_not_raise_out_of_a_request(admin_creds):
    """A re-login can legitimately fail — a 429 from the shared per-username login budget, say.

    Raising there would replace the caller's response with an exception from inside the client
    and, worse, abort a `finally:` cleanup mid-teardown, leaking fixtures into the next test.
    That is the very failure this renewal exists to prevent, so it must not become a new way to
    cause it. The caller should simply see whatever the stale token gets.
    """
    c = ApiClient(renew_before_expiry=True)
    c.login(admin_creds["username"], admin_creds["password"])
    c.RENEW_MARGIN_SECONDS = 10 ** 9
    c._credentials = (admin_creds["username"], "definitely-not-the-password")

    r = c.get("/vaults")          # must not raise
    assert r.status_code == 200, "the stale-but-valid token should still have worked"


def test_a_revoked_session_still_reports_401_on_the_renewing_client(admin_creds):
    """End-to-end version of the same property, through a real revocation.

    Logging out revokes this client's token. A renewing client must still surface the 401 rather
    than quietly logging back in — the renewal is keyed on the clock, and the clock has not moved.
    """
    c = ApiClient(renew_before_expiry=True)
    c.login(admin_creds["username"], admin_creds["password"])
    assert c.get("/vaults").status_code == 200

    assert c.post("/api/logout").status_code < 400
    assert c.get("/vaults").status_code == 401, (
        "a revoked session was silently re-authenticated — revocation coverage would be worthless"
    )


def test_a_short_lived_token_does_not_cause_a_login_storm(admin_creds):
    """The floor that makes short-TTL deployments safe.

    If a token's whole life is shorter than the renewal margin it is stale the moment it is
    minted, so without a minimum interval every request would log in again until the shared
    per-username login budget was exhausted — turning a slow suite into a failing one.
    """
    c = ApiClient(renew_before_expiry=True)
    c.login(admin_creds["username"], admin_creds["password"])
    c.RENEW_MARGIN_SECONDS = 10 ** 9      # every token now looks about to expire
    logins = []
    real_login = c.login
    c.login = lambda u, p: (logins.append(1), real_login(u, p))[1]

    for _ in range(5):
        assert c.get("/vaults").status_code == 200
    assert len(logins) == 1, f"renewed {len(logins)} times across 5 requests; expected 1"


def test_an_unreadable_token_never_triggers_renewal(admin_creds):
    """A malformed token must not make the client re-login in a loop; several suites hand a
    deliberately broken token to a client to assert it is rejected."""
    c = ApiClient(renew_before_expiry=True)
    c.login(admin_creds["username"], admin_creds["password"])
    c.token = "not-a-jwt"
    c.session.headers["Authorization"] = "Bearer not-a-jwt"
    assert c._token_expires_at() is None
    assert c.get("/vaults").status_code == 401
    assert c.token == "not-a-jwt", "an unreadable token was silently replaced"
