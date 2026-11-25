"""What an owner is told about a passkey whose signature algorithm an administrator removed from the Sign-in settings
(app/core/webauthn_settings.py: such a key is accepted for 30 more days). Told when the key is used in those days
(app/api/api_server.py, _passkey_algorithm_check): the key by its name, its algorithm, and the day it stops. Offline:
an in-memory database, the notices recorded."""
import types
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env
from _memory_db import MemoryDB

pytestmark = pytest.mark.unit


class DB(MemoryDB):
    """The in-memory session, filing an added row under its model so the next read finds it."""

    def add(self, obj):
        super().add(obj)
        self.rows_of(type(obj)).append(obj)


def _api():
    set_bare_api_env()
    import app.api.api_server as S
    from app.core import webauthn_settings
    return S, webauthn_settings


def _allowing(monkeypatch, ws, names):
    """The algorithms the Sign-in settings allow, as a list the test changes."""
    monkeypatch.setattr(ws, "allowed_alg_names", lambda: tuple(names))


def _recorder(monkeypatch, S):
    """The notices written, one per account and key as the notification table keeps them: a second notice with the
    same key is skipped."""
    written = {}

    def notify(ids, ntype, title=None, body=None, target=None, dedup_prefix=None):
        made = []
        for uid in ids:
            key = f"{dedup_prefix}:{uid}" if dedup_prefix else object()
            if key not in written:
                written[key] = {"type": ntype, "title": title, "body": body, "target": target}
                made.append(uid)
        return made
    monkeypatch.setattr(S, "_notify_users", notify)
    return written


def _key(owner, label, alg=-257):
    return types.SimpleNamespace(id=uuid.uuid4(), user_id=owner.id, label=label, cose_alg=alg, retired_at=None)


def test_a_key_used_in_its_last_days_is_named_with_its_algorithm_and_the_day_it_stops(monkeypatch):
    """Someone with two keys of a removed algorithm got two notices that read the same ("One of your passkeys needs
    replacing ... for 30 days from the change"), and could not tell which key to replace, or by when. Each key is
    told by its name, its algorithm and the day it stops, once however often it is used."""
    S, ws = _api()
    from app.core.models import SystemSetting
    db = DB({SystemSetting: []})
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice")
    laptop, unnamed = _key(alice, "laptop"), _key(alice, None)
    _allowing(monkeypatch, ws, ["ES256", "RS256"])
    removed = datetime.utcnow() - timedelta(days=2)
    ws.record_algorithm_change(db, ["ES256", "RS256"], ["ES256"], now=removed)
    _allowing(monkeypatch, ws, ["ES256"])
    written = _recorder(monkeypatch, S)
    for _ in range(2):
        S._passkey_algorithm_check(db, alice, laptop)
        S._passkey_algorithm_check(db, alice, unnamed)
    until = removed + timedelta(days=30)
    day = S._cc_date(until)
    assert day == f"{until.day} {S._MONTHS[until.month - 1]} {until.year}"
    assert written == {
        f"passkey_alg_grace:{laptop.id}:{until.date().isoformat()}:{alice.id}": {
            "type": "security", "title": 'Your passkey "laptop" needs replacing', "target": "#profile",
            "body": (f'Your passkey "laptop" uses RS256, a signature algorithm this vault no longer accepts. It still '
                     f"signs you in until {day}; add a new passkey before then, then remove this one.")},
        f"passkey_alg_grace:{unnamed.id}:{until.date().isoformat()}:{alice.id}": {
            "type": "security", "title": 'Your passkey "Passkey" needs replacing', "target": "#profile",
            "body": (f'Your passkey "Passkey" uses RS256, a signature algorithm this vault no longer accepts. It still '
                     f"signs you in until {day}; add a new passkey before then, then remove this one.")},
    }
    # A key of an algorithm the settings allow is told nothing.
    S._passkey_algorithm_check(db, alice, _key(alice, "phone", alg=-7))
    assert len(written) == 2


def test_a_second_removal_of_the_same_algorithm_is_told_again(monkeypatch):
    """The notice was kept once for the key for good, so after the algorithm came back and was removed again, the key
    told nothing of the new day it stops. It is kept once for each removal."""
    S, ws = _api()
    from app.core.models import SystemSetting
    db = DB({SystemSetting: []})
    alice = types.SimpleNamespace(id=uuid.uuid4(), username="alice")
    laptop = _key(alice, "laptop")
    written = _recorder(monkeypatch, S)
    _allowing(monkeypatch, ws, ["ES256", "RS256"])
    first = datetime.utcnow() - timedelta(days=5)
    ws.record_algorithm_change(db, ["ES256", "RS256"], ["ES256"], now=first)
    _allowing(monkeypatch, ws, ["ES256"])
    S._passkey_algorithm_check(db, alice, laptop)
    # Allowed again: the key is accepted as any other, and nothing is said.
    ws.record_algorithm_change(db, ["ES256"], ["ES256", "RS256"], now=first + timedelta(days=1))
    _allowing(monkeypatch, ws, ["ES256", "RS256"])
    S._passkey_algorithm_check(db, alice, laptop)
    assert len(written) == 1
    # Removed again: a new day, a new notice.
    second = datetime.utcnow() - timedelta(days=1)
    ws.record_algorithm_change(db, ["ES256", "RS256"], ["ES256"], now=second)
    _allowing(monkeypatch, ws, ["ES256"])
    S._passkey_algorithm_check(db, alice, laptop)
    S._passkey_algorithm_check(db, alice, laptop)
    days = [S._cc_date(when + timedelta(days=30)) for when in (first, second)]
    assert [notice["body"].split("until ")[1].split(";")[0] for notice in written.values()] == days
    assert len(written) == 2
