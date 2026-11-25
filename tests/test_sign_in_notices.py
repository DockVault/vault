"""What the administrators are told of a change to how people sign in (app/api/sso_providers_router.py,
app/api/sso_admin_router.py, app/api/sso_router.py): the notice and the system email about how people sign in, which
opens the Sign-in methods page, never the ones about how long records are kept, whose advice (a change that deletes
records sooner waits and can be cancelled) does not apply to a sign-in. Offline: the notices and emails observed."""
import re
import types
import uuid
from contextlib import contextmanager
from pathlib import Path

import pytest

from _bare_api_env import set_bare_api_env
from test_sso_resolution import Resolving, _sign_in
from test_sso_sign_in import _provider, _user

pytestmark = pytest.mark.unit

ROOT = Path(__file__).resolve().parent.parent


def test_a_provider_change_is_told_to_the_administrators_as_a_change_to_how_people_sign_in(monkeypatch):
    set_bare_api_env()
    import app.api.api_server as api
    import app.core.database as database
    from app.api import sso_providers_router as R
    root = types.SimpleNamespace(id=uuid.uuid4(), email="root@example.test", username="root")

    class _Query:
        def filter(self, *_a, **_k):
            return self

        def all(self):
            return [root]

    class _DB:
        def query(self, *_a):
            return _Query()

    @contextmanager
    def ctx():
        yield _DB()

    notices, emails = [], []
    monkeypatch.setattr(database, "get_db_context", ctx)
    monkeypatch.setattr(api, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, **_k:
                        notices.append((list(ids), ntype, title, body, target)))
    monkeypatch.setattr(api, "_fire_action_email_bulk", lambda db, key, recipients, ctx=None:
                        emails.append((key, list(recipients), ctx)))
    monkeypatch.setattr(api, "_change_time_text", lambda: "25 November 2026, 10:00 UTC")
    R._tell_administrators("root", "A single sign-on provider was turned off", "root turned Okta off.")
    assert notices == [([str(root.id)], "sign_in_policy_change", "A single sign-on provider was turned off",
                        "root turned Okta off.", "#settings/signin")]
    assert emails == [("sign_in_policy_change", [("root@example.test", "root")],
                       {"change": "root turned Okta off.", "by": "root", "when": "25 November 2026, 10:00 UTC"})]


def test_the_administrators_are_told_of_a_sign_in_kept_out_of_an_administrator_as_a_sign_in_change(monkeypatch):
    root, second = _user("root", role="admin"), _user("second", role="admin")
    p = _provider(policy={"sso_link_by_email": True, "sso_allowed_domains": ["example.test"]})
    h = Resolving(monkeypatch, [root, second], [p])
    told = []
    monkeypatch.setattr(h.S, "_notify_users", lambda ids, ntype, title=None, body=None, target=None, dedup_prefix=None,
                        once=False: told.append((list(ids), ntype, target)) or list(ids))
    location, _ = _sign_in(h, p, sub="s-root", email="root@example.test")
    assert location == "/#sso-error=link_from_your_account", location
    assert ([str(second.id)], "sign_in_policy_change", "#users") in told


def test_no_sign_in_notice_borrows_the_records_notice_or_its_email():
    names = sorted(ROOT.joinpath("app", "api").glob("sso_*.py")) + [ROOT / "app" / "api" / "sign_in_settings_router.py"]
    assert len(names) > 3
    for path in names:
        source = path.read_text(encoding="utf-8")
        found = re.findall(r"setting_changes\.(?:NOTICE_TYPE|EMAIL_ACTION)\b", source)
        assert found == [], f"{path.name} tells of a sign-in change as a records change: {found}"
