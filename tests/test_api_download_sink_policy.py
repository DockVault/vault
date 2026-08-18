"""The download-sink policy, over HTTP, against a live deployment.

The precedence rule is proven exhaustively in `test_download_sink_policy.py` without a stack. What
these add is the part that file cannot: that the setting is actually stored and refused correctly,
that the per-user preference reaches the resolver, and above all that a user preference **cannot
widen what the organisation set**.

That last one is the whole reason the policy exists. A tenant handling material that justified a
zero-knowledge vault sets `buffered` deliberately; if a user preference could override it, the
policy would not exist, and it would look exactly like a policy that did.

Every test restores the setting, because it is global and everything after it in the run inherits
whatever it leaves.
"""
from __future__ import annotations

import pytest

from conftest import unique  # noqa: F401  (kept for symmetry with the sibling suites)


def _policy(admin):
    r = admin.get("/settings")
    assert r.status_code == 200, r.text
    return r.json().get("download_sink_policy")


def _set_policy(admin, value):
    r = admin.put("/settings", json={"download_sink_policy": value})
    return r


def _sink(client):
    r = client.get("/zk-enabled")
    assert r.status_code == 200, r.text
    body = r.json()
    assert "download_sink" in body, "the resolved sink is not reported to the client"
    return body["download_sink"]


def _set_pref(client, value):
    r = client.put("/users/me/preferences", json={"download_sink": value})
    assert r.status_code == 200, r.text
    return r


@pytest.fixture
def restored_policy(admin):
    """Put the organisation setting back however the test leaves it."""
    before = _policy(admin)
    yield
    _set_policy(admin, before if before in ("buffered", "streaming", "user_choice")
                else "user_choice")


@pytest.mark.parametrize("bad", ["", "off", "Buffered", "STREAMING", "yes", "none"])
def test_an_unknown_policy_is_refused(admin, restored_policy, bad):
    """Refused on the way in, because the read path deliberately falls back on anything it cannot
    parse -- so a typo stored here would silently mean `user_choice` while an administrator
    believed they had required something."""
    r = _set_policy(admin, bad)
    assert r.status_code == 400, f"{bad!r} was accepted: {r.status_code} {r.text[:200]}"
    assert "download_sink_policy" in r.text


@pytest.mark.parametrize("value", ["buffered", "streaming", "user_choice"])
def test_each_valid_policy_is_stored_and_reported(admin, restored_policy, value):
    assert _set_policy(admin, value).status_code == 200
    assert _policy(admin) == value
    assert _sink(admin)["org_policy"] == value


def test_a_user_preference_cannot_widen_what_the_organisation_required(admin, restored_policy):
    """The direction that matters, asserted on its own rather than as a corollary."""
    _set_pref(admin, "streaming")
    assert _set_policy(admin, "buffered").status_code == 200

    resolved = _sink(admin)
    assert resolved["sink"] == "buffered", (
        "a user preference overrode a required buffered policy, so the policy does not exist")
    assert resolved["reason"] == "organisation"
    assert resolved["user_may_choose"] is False, (
        "the UI would offer a control that changes nothing")


def test_a_user_preference_cannot_narrow_it_either(admin, restored_policy):
    """The mirror case. It is not a security hole, but it is the same bug, and a policy that only
    holds in the restrictive direction is a policy that was implemented as a preference."""
    _set_pref(admin, "buffered")
    assert _set_policy(admin, "streaming").status_code == 200
    assert _sink(admin)["sink"] == "streaming"


def test_the_user_decides_when_the_organisation_delegates(admin, restored_policy):
    assert _set_policy(admin, "user_choice").status_code == 200

    _set_pref(admin, "streaming")
    resolved = _sink(admin)
    assert resolved["user_may_choose"] is True
    # Over plain HTTP a service worker cannot be registered, so the honest answer is buffered even
    # though the user asked for streaming -- and the reason must say so rather than looking like
    # the user's own choice.
    assert resolved["sink"] in ("streaming", "buffered")
    if resolved["sink"] == "buffered":
        assert resolved["reason"] == "insecure_context", (
            "a deployment that cannot stream must say that, not attribute it to the user")

    _set_pref(admin, "buffered")
    assert _sink(admin)["sink"] == "buffered"


def test_an_unset_deployment_behaves_exactly_as_before(admin, restored_policy):
    """The upgrade case. Nothing configured must mean nothing on disk early, or an upgrade
    silently changes where people's unverified plaintext lands."""
    assert _set_policy(admin, "user_choice").status_code == 200
    _set_pref(admin, "buffered")
    assert _sink(admin)["sink"] == "buffered"
