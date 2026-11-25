"""What Your account is told of the caller's own organisation identities and of the providers they could link
(GET /users/me/identities), and what the start of a link and the owner's unlink answer to match it
(app/api/sso_router.py). Through the ASGI app against an in-memory database. Offline."""
import uuid

import pytest

from test_sso_sign_in import Harness, _call, _identity, _provider, _user

pytestmark = pytest.mark.unit


def _listed(h):
    status, out, _ = _call(h.S, "GET", "/users/me/identities")
    assert status == 200, out
    return out


def _offered(out):
    return {p["id"]: p for p in out["providers"]}


def test_a_provider_without_a_sign_in_button_is_offered_for_a_link_and_one_that_is_off_is_not(monkeypatch):
    """The sign-in page's button is about the sign-in page: a provider that is on and can serve a link is offered
    under Your account whether it shows one or not, since the texts that send people there to link it are true only
    then. A provider that is off is offered to nobody, linked or not."""
    alice = _user()
    hidden = _provider(name="hidden", label="Hidden", show_on_sign_in=False)
    off_linked = _provider(name="off-linked", label="Off", state="disabled")
    h = Harness(monkeypatch, [alice], [hidden, off_linked], identities=[_identity(alice, off_linked)])
    offered = _offered(_listed(h))
    assert str(hidden.id) in offered and offered[str(hidden.id)]["linked"] is False
    assert str(off_linked.id) not in offered
    # The identity on the provider that is off is still listed as the account's own.
    assert [i["provider_id"] for i in _listed(h)["identities"]] == [str(off_linked.id)]
    # And the link of the button-less provider starts.
    status, out = h.start_link(hidden)
    assert status == 200 and out["authorization_url"], out
