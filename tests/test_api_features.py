"""GET /features — the capability advertisement.

Two-factor auth is not implemented, so a stock deployment must not advertise it
(the flag defaults off; an operator can still opt in via BRAND_ENABLE_2FA).
"""


def test_2fa_not_advertised_by_default(anon):
    r = anon.get("/features")
    assert r.status_code == 200, r.text
    auth = r.json()["authentication"]
    assert auth["2fa_enabled"] is False
    # the flag is still part of the response contract (kept for forward-compat)
    assert "2fa_enabled" in auth
