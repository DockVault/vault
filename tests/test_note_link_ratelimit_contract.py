"""Source contract: the public note-link redeem endpoint throttles per IP AND per (IP, token).

The redeem endpoint's docstring promised "per IP AND per token", but it kept a single bucket keyed on
`{ip}:{token}` -- so hammering one link was throttled while guessing many DIFFERENT tokens from one IP
got a fresh bucket every time (token enumeration was unthrottled). This is a source contract rather
than a live 429 test: the per-IP bucket is bounded by rate_limit_api_auth, which the suite raises so
tests do not throttle themselves, so enumeration cannot be tripped at the suite's limits. It pins that
both buckets are wired and distinct, so the per-IP half cannot silently disappear again.
"""
import pathlib
import re

import pytest

pytestmark = pytest.mark.unit

_SRC = pathlib.Path(__file__).resolve().parents[1].joinpath(
    "app", "api", "api_server.py").read_text(encoding="utf-8")


def _redeem_body() -> str:
    m = re.search(r"async def redeem_note_link\(.*?(?=\n@app\.|\nasync def |\ndef )", _SRC, re.S)
    assert m, "redeem_note_link not found in api_server.py"
    return m.group(0)


def test_redeem_keeps_the_per_pair_bucket():
    assert 'identifier=f"{client_ip}:{token}"' in _redeem_body(), (
        "the per-(IP, token) bucket must remain to bound hammering a single link")


def test_redeem_adds_the_per_ip_bucket_for_enumeration():
    body = _redeem_body()
    assert "identifier=client_ip," in body, (
        "the per-IP bucket is missing -> guessing many different tokens from one IP is unthrottled")
    assert 'prefix="notelink_redeem_ip"' in body, (
        "the per-IP bucket must use its own distinct rate-limit prefix")


def test_redeem_per_ip_bucket_uses_its_own_generous_budget():
    # A note link is a broadcast artifact opened by many people at once (often one egress IP), so the
    # per-IP budget must be its OWN generous value, NOT the tight one-per-user auth budget
    # (rate_limit_api_auth defaults to 10/min, which refuses the 11th legitimate opener from an office).
    body = _redeem_body()
    assert "limit=_NOTELINK_REDEEM_IP_LIMIT" in body, (
        "the per-IP bucket must use the dedicated _NOTELINK_REDEEM_IP_LIMIT budget")
    assert "rate_limit_api_auth" not in body, (
        "the per-IP bucket must NOT borrow the auth budget -- that default refuses legitimate opens")
    # and that dedicated budget must be generous enough not to refuse a real team
    assert _SRC.count("_NOTELINK_REDEEM_IP_LIMIT = ") == 1
    m = re.search(r"_NOTELINK_REDEEM_IP_LIMIT\s*=\s*(\d+)", _SRC)
    assert m and int(m.group(1)) >= 300, "the per-IP note-link redeem budget should be >= 300/min"
