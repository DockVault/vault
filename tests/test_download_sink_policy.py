"""Who decides where a decrypted download is written.

The rule is one sentence — the organisation decides, or delegates to the user — and it is the kind
of sentence that is easy to implement backwards. So this walks the entire space rather than a
representative case: three organisation values against two user preferences against both context
kinds is twelve combinations, and all twelve are checked.

The direction that matters is that a user preference can only ever choose within what the
organisation allows. A tenant sets the restrictive value deliberately; a bug that lets a user
preference win is not a bug in a convenience feature, it is the policy not existing.
"""
from __future__ import annotations

import importlib.util
import itertools
from pathlib import Path

import pytest

pytestmark = pytest.mark.unit

_SPEC = importlib.util.spec_from_file_location(
    "download_sink_under_test",
    Path(__file__).resolve().parents[1] / "app" / "core" / "download_sink.py",
)
_SINK = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_SINK)

resolve = _SINK.resolve_download_sink
describe = _SINK.describe_download_sink
BUFFERED, STREAMING, USER_CHOICE = _SINK.BUFFERED, _SINK.STREAMING, _SINK.USER_CHOICE


def test_an_organisation_that_names_a_mode_gets_it_whatever_the_user_wants():
    """Both directions. The restrictive one is the point, but a permissive organisation being
    overridden by a user who wants buffered would be the same bug wearing a friendlier face."""
    for user in (BUFFERED, STREAMING, None, "nonsense"):
        assert resolve(BUFFERED, user) == BUFFERED, f"user {user!r} overrode a required buffered"
        assert resolve(STREAMING, user) == STREAMING, f"user {user!r} overrode a required streaming"


def test_delegation_hands_the_choice_to_the_user():
    assert resolve(USER_CHOICE, STREAMING) == STREAMING
    assert resolve(USER_CHOICE, BUFFERED) == BUFFERED


def test_the_shipped_defaults_are_todays_behaviour():
    """Nothing configured anywhere must resolve to what already ships.

    If this ever fails, an upgrade silently starts putting unverified bytes on people's disks.
    """
    assert resolve(None, None) == BUFFERED
    assert _SINK.DEFAULT_ORG_POLICY == USER_CHOICE
    assert _SINK.DEFAULT_USER_PREFERENCE == BUFFERED


def test_plain_http_cannot_stream_however_the_policy_reads():
    """A service worker needs a secure context. Promising streaming there would promise something
    the browser refuses, so it resolves to buffered — including when the organisation REQUIRED
    streaming, because a policy cannot conjure an API the page does not have."""
    assert resolve(STREAMING, STREAMING, secure_context=False) == BUFFERED
    assert resolve(USER_CHOICE, STREAMING, secure_context=False) == BUFFERED
    assert resolve(BUFFERED, BUFFERED, secure_context=False) == BUFFERED


@pytest.mark.parametrize("org,user,secure", list(itertools.product(
    (BUFFERED, STREAMING, USER_CHOICE), (BUFFERED, STREAMING), (True, False))))
def test_every_combination_resolves_to_a_real_mode(org, user, secure):
    """Twelve combinations, no gaps, and never a third value."""
    got = resolve(org, user, secure_context=secure)
    assert got in (BUFFERED, STREAMING)
    if not secure:
        assert got == BUFFERED
    elif org != USER_CHOICE:
        assert got == org
    else:
        assert got == user


@pytest.mark.parametrize("bad", [None, "", "Buffered", "STREAMING", 1, True, [], {}, "user"])
def test_an_unreadable_setting_falls_back_rather_than_failing(bad):
    """This is read on a download. A row written by an older or newer build must not stop people
    downloading; the write path validates, which is where a bad value belongs refused."""
    assert resolve(bad, bad) in (BUFFERED, STREAMING)
    assert resolve(bad, STREAMING) == STREAMING, "an unreadable org policy should still delegate"


def test_the_three_ways_of_arriving_at_buffered_are_distinguishable():
    """They look identical from outside and mean different things: the organisation required it,
    the user chose it, or the browser cannot do anything else here. A UI that cannot tell them
    apart either offers a control that does nothing or hides one that would work."""
    assert describe(BUFFERED, STREAMING)["reason"] == "organisation"
    assert describe(USER_CHOICE, BUFFERED)["reason"] == "user"
    assert describe(USER_CHOICE, STREAMING, secure_context=False)["reason"] == "insecure_context"

    required = describe(BUFFERED, BUFFERED)
    assert required["user_may_choose"] is False, "the control must not be offered when it is moot"
    assert describe(USER_CHOICE, BUFFERED)["user_may_choose"] is True
