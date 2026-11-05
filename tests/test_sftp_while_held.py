"""The SFTP version check while legal holds keep anything, offline (app/core/legal_holds.py, sftp_while_held, and
app/core/sftp_versions.py).

A hold cannot be placed while an SFTP server of another version may run, but the SFTP container can be replaced
after: an older one deletes the bytes of a file a hold keeps. So every pass of the pruner's legal_holds job asks again
while a hold stands or what one kept waits for its purge, and tells every active administrator when one may run, once
a day while the answer stays the same. And a process killed before it could remove its row (which an older SFTP server
never writes) counts as live for about two record intervals only, not two minutes.
test_sftp_while_held_live.py runs the check on Postgres; test_sftp_versions_live.py the window on a stack.
"""
import uuid
from datetime import datetime, timedelta

import pytest

from _bare_api_env import set_bare_api_env

set_bare_api_env()

from app.core import legal_holds  # noqa: E402
from app.core import retention  # noqa: E402
from app.core import sftp_versions as SV  # noqa: E402
from app.core.models import HeldNameHistory, LegalHoldVault, SftpProcess  # noqa: E402

pytestmark = pytest.mark.unit

NOW = datetime(2026, 11, 5, 12, 0, 0)
SPLIT = {"COMPOSE_PROFILES": "split", "RUN_SFTP": ""}


@pytest.fixture
def db(monkeypatch):
    from _kept_db import kept_database
    monkeypatch.delenv(SV.COMBINED_SFTP_ENV, raising=False)
    with kept_database() as (make, _engine):
        made = []

        def session():
            made.append(make())
            return made[-1]

        s = session()
        s.factory = session
        yield s
        for one in made:
            one.close()


@pytest.fixture
def told(monkeypatch):
    out = []
    monkeypatch.setattr(legal_holds, "_tell_administrators",
                        lambda title, body, dedup: out.append((title, body, dedup)))
    return out


def _sftp(db, version, seconds_ago, pid=None):
    seen = NOW - timedelta(seconds=seconds_ago)
    db.add(SftpProcess(id=pid or str(uuid.uuid4()), version=version, host="h", started_at=seen, seen_at=seen))
    db.commit()


def _kept_name(db):
    db.add(HeldNameHistory(object_id=uuid.uuid4(), vault_id=uuid.uuid4(), kind="file", enc_name="zk2:old",
                           name_key_version=1))
    db.commit()


def _hold(db):
    db.add(LegalHoldVault(case_id=uuid.uuid4(), vault_id=uuid.uuid4(), placed_by_username="aud"))
    db.commit()


# --------------------------------------------------------------------------- the window

def test_a_killed_process_row_counts_for_about_two_record_intervals_only(db):
    """A row of this version last refreshed 70 seconds ago (its process killed before it could remove it) no longer
    proves that every SFTP server runs this version; one refreshed within two record intervals still does."""
    assert 2 * SV.RECORD_SECONDS <= SV.LIVE_WITHIN_SECONDS <= 2 * SV.RECORD_SECONDS + 10
    _sftp(db, "0.34.0", 70)
    check = SV.sftp_same_version(db, now=NOW, environ=SPLIT, version="0.34.0")
    assert (check.ok, check.reason) == (False, SV.NONE_LIVE)
    _sftp(db, "0.34.0", 2 * SV.RECORD_SECONDS - 1)
    assert SV.sftp_same_version(db, now=NOW, environ=SPLIT, version="0.34.0").reason == SV.SAME


# --------------------------------------------------------------------------- asked again while anything is held

def test_nothing_held_nothing_asked(db, told):
    _sftp(db, "0.33.5", 5)
    assert legal_holds.sftp_while_held(db, NOW) is None and told == []


@pytest.mark.parametrize("held", [_hold, _kept_name])
def test_an_sftp_server_of_another_version_while_anything_is_held_is_told_to_the_administrators(db, told, held,
                                                                                               capsys):
    held(db)
    _sftp(db, SV.code_version(), 5)
    _sftp(db, "0.33.5", 5)
    check = legal_holds.sftp_while_held(db, NOW)
    assert (check.ok, check.reason, check.versions) == (False, SV.OTHER_VERSION, ("0.33.5",))
    ((title, body, dedup),) = told
    assert title == "An SFTP server of another version may be running"
    assert body.startswith("An SFTP server of another version is running (0.33.5)")
    assert "deletes the bytes of a file a hold keeps" in body
    assert dedup == "sftp-version-other_version-0.33.5-2026-11-05"
    assert ("Warning: an SFTP server of another version may run while legal holds keep files: An SFTP server of "
            "another version is running (0.33.5)") in capsys.readouterr().out


def test_a_killed_process_row_left_alone_is_told_too(db, told):
    """The SFTP container was killed (its row stays) and one of an older release, which records nothing, may have
    taken its place: once the row is older than the window, the answer is none live, and the administrators hear."""
    _hold(db)
    _sftp(db, SV.code_version(), 70)
    check = legal_holds.sftp_while_held(db, NOW)
    assert check.reason == SV.NONE_LIVE
    ((_title, body, dedup),) = told
    assert body.startswith("No SFTP server has reported its version") and dedup.startswith("sftp-version-none_live--")


def test_every_sftp_server_on_this_version_is_quiet(db, told):
    _hold(db)
    _sftp(db, SV.code_version(), 5)
    assert legal_holds.sftp_while_held(db, NOW).ok is True and told == []


def test_the_administrators_hear_once_a_day_while_it_lasts(db, told):
    """The notice's dedup key is the answer and the day: the same answer later the same day writes no second
    notice; the next day, or another answer, does (app/api/api_server.py, _notify_users)."""
    _hold(db)
    _sftp(db, "0.33.5", 0)
    legal_holds.sftp_while_held(db, NOW)
    legal_holds.sftp_while_held(db, NOW + timedelta(seconds=30))
    _sftp(db, "0.33.5", -86400 + 5)
    legal_holds.sftp_while_held(db, NOW + timedelta(days=1))
    keys = [d for _t, _b, d in told]
    assert keys[0] == keys[1] != keys[2] and keys[2].endswith("2026-11-06")


def test_the_pruners_legal_holds_job_asks_at_every_pass(db, told, monkeypatch):
    monkeypatch.setattr(legal_holds, "purge", lambda *a, **k: None)
    _kept_name(db)
    _sftp(db, "0.33.5", 5)
    retention.run_legal_holds(retention.Pass(db.factory, now=NOW))
    assert [d for _t, _b, d in told] == ["sftp-version-other_version-0.33.5-2026-11-05"]


def test_a_check_that_fails_leaves_the_rest_of_the_pass(db, told, monkeypatch, capsys):
    """The check reads the kept tables, which a start can skip: when it fails, the lapses and the review prompts of
    the pass still commit, the purge still runs, and the next pass asks again."""
    from sqlalchemy import text
    purged = []
    monkeypatch.setattr(legal_holds, "purge", lambda *a, **k: purged.append(True))

    def lapse_due(session, now):
        session.add(LegalHoldVault(case_id=uuid.uuid4(), vault_id=uuid.uuid4(), placed_by_username="lapsed",
                                   lapsed_at=now, released_at=now))
    monkeypatch.setattr(legal_holds, "lapse_due", lapse_due)
    monkeypatch.setattr(legal_holds, "prompt_reviews", lambda session, now: None)
    _sftp(db, "0.33.5", 5)
    db.execute(text("DROP TABLE held_files"))
    db.commit()
    retention.run_legal_holds(retention.Pass(db.factory, now=NOW))
    lapsed = db.factory().query(LegalHoldVault).filter(LegalHoldVault.placed_by_username == "lapsed").count()
    assert lapsed == 1 and purged == [True] and told == []
    assert ("the SFTP servers' versions were not checked while legal holds keep files (OperationalError)"
            in capsys.readouterr().out)
