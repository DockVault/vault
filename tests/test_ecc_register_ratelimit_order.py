"""POST /ecc/keys/register refuses a temp session BEFORE charging the ECC register rate budget.

The ECC `register` bucket (15/60s) keys on the user id, and a temp session is the OWNER's own User
row tagged temporary. If the refusal ran AFTER the rate charge (the pre-fix order), a leaked temp
credential could spend the owner's once-per-account register budget just by being refused — a
bounded self-DoS on precisely the operation a legitimate owner must eventually run. After the fix the
refusal short-circuits first, so refused temp registers never touch the budget.

The test is guarded for non-vacuity: it first proves the `register` limiter actually enforces in this
environment (a fresh user hammering the shared bucket must eventually 429). If the limiter is failing
open (e.g. Redis down), the "never 429" assertion would be meaningless, so we skip instead.
"""
import pytest


def _bucket_enforces(admin):
    """True if the ECC `register` bucket 429s under load here (register/challenge shares it)."""
    victim = admin.create_user(role="user")
    try:
        vc = admin.clone_anonymous()
        vc.login(victim["_username"], victim["_password"])
        # register/challenge charges the `register` bucket before its keypair check, so a fresh user
        # with no keypair still depletes it: expect 404s then a 429 once the 15/60 bucket is spent.
        codes = [vc.post("/ecc/keys/register/challenge", json={}).status_code for _ in range(20)]
        return 429 in codes
    finally:
        admin.delete_user(victim["id"])


def test_temp_session_register_is_refused_without_charging_the_budget(admin):
    if not _bucket_enforces(admin):
        pytest.skip("ECC register rate limiter is not enforcing in this environment (fail-open)")

    # A temp session for the owner. Unscoped is fine — register is refused for any temp session
    # regardless of scope, and an unrestricted mint (no scope, no selected_vaults) is allowed.
    body = admin.post("/auth/temp-credentials", json={"validity_minutes": 60}).json()
    temp = admin.clone_anonymous()
    temp.login(body["temp_username"], body["credential"])

    # Hammer register past the 15/60 bucket. Every response must be 403 (the temp refusal) and NEVER
    # 429: a refused temp request must not consume the bucket. Pre-fix, the 16th+ would 429 because
    # the charge ran first. The bogus key never reaches format validation — the refusal precedes it.
    codes = [temp.post("/ecc/keys/register", json={"public_key": "not-a-real-key"}).status_code
             for _ in range(18)]
    assert all(c == 403 for c in codes), f"temp register must always 403, never 429/other: {codes}"
